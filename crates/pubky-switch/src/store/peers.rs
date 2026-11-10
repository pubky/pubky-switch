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
            "SELECT doc, version, generation, body_hash FROM peer_copies \
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
        Ok(Some(HeldPeer {
            doc: decode_doc(&doc, "a peer copy")?,
            version: from_db(row.try_get("version")?, "version")?,
            generation: from_db(row.try_get("generation")?, "generation")?,
            body_hash: hash32(&body_hash, "a peer copy's body hash")?,
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
    /// floor held for it.
    pub async fn put_peer(
        &mut self,
        identity: &[u8; 32],
        copy: &HeldPeer,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO peer_copies (account_id, identity, doc, version, generation, body_hash) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (account_id, identity) DO UPDATE \
             SET doc = $3, version = $4, generation = $5, body_hash = $6, \
             delivered = nextval('peer_delivery_order')",
        )
        .bind(&id)
        .bind(identity.as_slice())
        .bind(encode_doc(&copy.doc)?)
        .bind(to_db(copy.version, "version")?)
        .bind(to_db(copy.generation, "generation")?)
        .bind(copy.body_hash.as_slice())
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
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
        let Some(row) = sqlx::query(
            "SELECT identity FROM peer_copies p WHERE account_id = $1 AND identity <> $2 \
             AND (NOT $3 OR NOT EXISTS (SELECT 1 FROM list_entries l \
                 WHERE l.account_id = p.account_id AND l.pubky = p.identity \
                 AND l.list IN ('contact', 'conversation'))) \
             ORDER BY delivered LIMIT 1",
        )
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
