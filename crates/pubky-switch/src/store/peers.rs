//! Peers' `identity.json` copies and the floors dropped copies leave (Switch wire 7.4.5,
//! 9.1). A copy is what the account's admission and listing checks read of another
//! identity: which apps it lists, and which it lists as removed.

use pubky_switch_core::sig::SignedDoc;
use sqlx::Row;

use super::{
    AccountTxn, StoreError, from_db,
    identity::{decode_doc, encode_doc},
    to_db,
};

/// Whether the account admits `p.identity` for keeping its copy (Switch wire 7.4.5, 9.1): a
/// contact or conversation entry, and not denied. A denied identity's copy is kept exactly
/// like a stranger's. The one rule, for every copy held and every copy delivered.
const ADMITTED_FOR_KEEPING: &str = "(EXISTS (SELECT 1 FROM list_entries l \
     WHERE l.account_id = p.account_id AND l.pubky = p.identity \
     AND l.list IN ('contact', 'conversation')) \
     AND NOT EXISTS (SELECT 1 FROM list_entries d \
     WHERE d.account_id = p.account_id AND d.pubky = p.identity AND d.list = 'deny'))";

/// A peer's copy as the account holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldPeer {
    /// The signed document, as delivered.
    pub doc: SignedDoc,
    /// Its version.
    pub version: u64,
    /// Its generation.
    pub generation: u64,
    /// The hash of its body bytes.
    pub body_hash: [u8; 32],
    /// The App IDs it lists in `removed`.
    pub removed: Vec<[u8; 16]>,
}

/// What a dropped copy of an admitted identity leaves (Switch wire 7.4.5 Floors).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerFloor {
    /// The dropped copy's version.
    pub version: u64,
    /// Its generation.
    pub generation: u64,
    /// The hash of its body bytes.
    pub body_hash: [u8; 32],
}

fn hash32(bytes: &[u8], what: &'static str) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(bytes).map_err(|_| StoreError::Corrupt(what))
}

impl AccountTxn {
    /// The copy the account holds of `identity`'s `identity.json`.
    pub async fn peer_copy(&mut self, identity: &[u8; 32]) -> Result<Option<HeldPeer>, StoreError> {
        let id = self.head().id.clone();
        let Some(row) = sqlx::query(
            "SELECT doc, version, generation, body_hash, removed FROM peer_copies \
             WHERE account_id = $1 AND identity = $2",
        )
        .bind(id)
        .bind(identity.as_slice())
        .fetch_optional(self.conn())
        .await
        .map_err(StoreError::from_db)?
        else {
            return Ok(None);
        };
        let doc: Vec<u8> = row.try_get("doc")?;
        let body_hash: Vec<u8> = row.try_get("body_hash")?;
        let removed: Vec<Vec<u8>> = row.try_get("removed")?;
        Ok(Some(HeldPeer {
            doc: decode_doc(&doc, "a peer copy")?,
            version: from_db(row.try_get("version")?, "version")?,
            generation: from_db(row.try_get("generation")?, "generation")?,
            body_hash: hash32(&body_hash, "a peer copy's body hash")?,
            removed: removed
                .iter()
                .map(|app| {
                    <[u8; 16]>::try_from(app.as_slice())
                        .map_err(|_| StoreError::Corrupt("a peer copy's removed app"))
                })
                .collect::<Result<_, _>>()?,
        }))
    }

    /// The floor a dropped copy of `identity` left, while no copy is held.
    pub async fn peer_floor(
        &mut self,
        identity: &[u8; 32],
    ) -> Result<Option<PeerFloor>, StoreError> {
        let id = self.head().id.clone();
        let Some(row) = sqlx::query(
            "SELECT version, generation, body_hash FROM peer_floors \
             WHERE account_id = $1 AND identity = $2",
        )
        .bind(id)
        .bind(identity.as_slice())
        .fetch_optional(self.conn())
        .await
        .map_err(StoreError::from_db)?
        else {
            return Ok(None);
        };
        let body_hash: Vec<u8> = row.try_get("body_hash")?;
        Ok(Some(PeerFloor {
            version: from_db(row.try_get("version")?, "version")?,
            generation: from_db(row.try_get("generation")?, "generation")?,
            body_hash: hash32(&body_hash, "a peer floor's body hash")?,
        }))
    }

    /// Keep `copy` as `identity`'s, the most recently delivered, in place of any copy or
    /// floor held for it. Only for a copy that is kept: a delivery that drops itself leaves
    /// the floor, raised by [`AccountTxn::raise_peer_floor`].
    pub async fn put_peer(
        &mut self,
        identity: &[u8; 32],
        copy: &HeldPeer,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO peer_copies (account_id, identity, doc, version, generation, body_hash, \
             removed) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (account_id, identity) \
             DO UPDATE SET doc = $3, version = $4, generation = $5, body_hash = $6, \
             removed = $7, delivered = nextval('peer_delivery_order')",
        )
        .bind(&id)
        .bind(identity.as_slice())
        .bind(encode_doc(&copy.doc)?)
        .bind(to_db(copy.version, "version")?)
        .bind(to_db(copy.generation, "generation")?)
        .bind(copy.body_hash.as_slice())
        .bind(
            copy.removed
                .iter()
                .map(|app| app.to_vec())
                .collect::<Vec<_>>(),
        )
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        // Held again: the floor's place is taken by the copy, which is at or above it.
        sqlx::query("DELETE FROM peer_floors WHERE account_id = $1 AND identity = $2")
            .bind(&id)
            .bind(identity.as_slice())
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// Note that `identity`'s copy was delivered again, so it is the most recently
    /// delivered.
    pub async fn touch_peer(&mut self, identity: &[u8; 32]) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "UPDATE peer_copies SET delivered = nextval('peer_delivery_order') \
             WHERE account_id = $1 AND identity = $2",
        )
        .bind(id)
        .bind(identity.as_slice())
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// How many copies the account holds.
    pub async fn peer_count(&mut self) -> Result<u64, StoreError> {
        let id = self.head().id.clone();
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM peer_copies WHERE account_id = $1")
                .bind(id)
                .fetch_one(self.conn())
                .await
                .map_err(StoreError::from_db)?;
        from_db(count, "peer count")
    }

    /// The least recently delivered copy other than `except`'s, and its identity: among
    /// strangers' copies only (neither a contact nor a conversation entry) with
    /// `strangers_only`, else among every copy.
    pub async fn oldest_peer(
        &mut self,
        except: &[u8; 32],
        strangers_only: bool,
    ) -> Result<Option<([u8; 32], HeldPeer)>, StoreError> {
        let id = self.head().id.clone();
        let Some(row) = sqlx::query(&format!(
            "SELECT identity FROM peer_copies p WHERE account_id = $1 AND identity <> $2 \
                 AND (NOT $3 OR NOT {ADMITTED_FOR_KEEPING}) ORDER BY delivered LIMIT 1"
        ))
        .bind(id)
        .bind(except.as_slice())
        .bind(strangers_only)
        .fetch_optional(self.conn())
        .await
        .map_err(StoreError::from_db)?
        else {
            return Ok(None);
        };
        let identity: Vec<u8> = row.try_get("identity")?;
        let identity = hash32(&identity, "a peer's identity")?;
        Ok(self
            .peer_copy(&identity)
            .await?
            .map(|copy| (identity, copy)))
    }

    /// Whether the account admits `identity` for keeping its copy: a contact or
    /// conversation entry, and not denied (the rule of [`AccountTxn::oldest_peer`]).
    pub async fn peer_admitted(&mut self, identity: &[u8; 32]) -> Result<bool, StoreError> {
        let id = self.head().id.clone();
        sqlx::query_scalar(&format!(
            "SELECT {ADMITTED_FOR_KEEPING} FROM (SELECT $1::TEXT AS account_id, \
             $2::BYTEA AS identity) p"
        ))
        .bind(id)
        .bind(identity.as_slice())
        .fetch_one(self.conn())
        .await
        .map_err(StoreError::from_db)
    }

    /// Whether the copy held of `identity` lists `app` in `removed`, read without the
    /// document: the same work whether or not a copy is held.
    pub async fn peer_lists_removed(
        &mut self,
        identity: &[u8; 32],
        app: &[u8; 16],
    ) -> Result<bool, StoreError> {
        let id = self.head().id.clone();
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM peer_copies WHERE account_id = $1 AND identity = $2 \
             AND $3 = ANY(removed))",
        )
        .bind(id)
        .bind(identity.as_slice())
        .bind(app.as_slice())
        .fetch_one(self.conn())
        .await
        .map_err(StoreError::from_db)
    }

    /// Raise `identity`'s floor, if it has one, to `floor`, when `floor` is newer: a
    /// delivered copy that verified and drops itself still moves what it leaves forward, so
    /// it never goes back (Switch wire 7.4.5).
    pub async fn raise_peer_floor(
        &mut self,
        identity: &[u8; 32],
        floor: &PeerFloor,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "UPDATE peer_floors SET version = $3, generation = $4, body_hash = $5 \
             WHERE account_id = $1 AND identity = $2 AND version < $3 AND generation <= $4",
        )
        .bind(id)
        .bind(identity.as_slice())
        .bind(to_db(floor.version, "version")?)
        .bind(to_db(floor.generation, "generation")?)
        .bind(floor.body_hash.as_slice())
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// Drop `identity`'s copy, leaving `floor` in its place if given.
    pub async fn drop_peer(
        &mut self,
        identity: &[u8; 32],
        floor: Option<PeerFloor>,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query("DELETE FROM peer_copies WHERE account_id = $1 AND identity = $2")
            .bind(&id)
            .bind(identity.as_slice())
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        if let Some(floor) = floor {
            sqlx::query(
                "INSERT INTO peer_floors (account_id, identity, version, generation, body_hash) \
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (account_id, identity) DO UPDATE \
                 SET version = $3, generation = $4, body_hash = $5",
            )
            .bind(&id)
            .bind(identity.as_slice())
            .bind(to_db(floor.version, "version")?)
            .bind(to_db(floor.generation, "generation")?)
            .bind(floor.body_hash.as_slice())
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        }
        Ok(())
    }
}
