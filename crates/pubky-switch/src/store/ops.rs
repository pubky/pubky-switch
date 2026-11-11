//! The state signed operations change (Switch wire 6.2, 6.8): apps, receive keys, key bundle
//! parts, shared records, claims and their entries, the lists, invite codes and batch
//! records. Every read and write runs in the request's transaction, under the account's
//! lock, so a batch sees one consistent state and commits all of its changes or none.
//!
//! Signed documents are stored in their carrying form, as received. Sealed values stay
//! sealed: nothing here opens or interprets them (Switch spec 1).

use pubky_switch_core::{
    claims::{Claim, ClaimTally},
    ident::Policy,
    ops::{BatchRecord, Position},
    shared::RecordState,
    sig::SignedDoc,
};
use serde_json::Value;
use sqlx::Row;

use super::{
    AccountTxn, KeptReason, StoreError, claim_codec, from_db,
    identity::{decode_doc, encode_doc},
    to_db,
};

/// An own app as stored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredApp {
    /// The App ID.
    pub app_id: [u8; 16],
    /// Its newest app record.
    pub record: Option<SignedDoc>,
    /// When the service took it.
    pub record_at_ms: Option<u64>,
    /// The renewed certificate a `cert.put` stored.
    pub renewed_cert: Option<SignedDoc>,
    /// Its current receive key record.
    pub receive_key: Option<SignedDoc>,
    /// Its cursor.
    pub cursor: Option<Position>,
    /// The `apps_version` at which it became reachable.
    pub reachable_since: Option<u64>,
    /// When a full key bundle was requested for it, while not yet covered.
    pub full_requested_ms: Option<u64>,
}

/// A key bundle part as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBundlePart {
    /// Its first data epoch.
    pub first_epoch: u64,
    /// Its last data epoch.
    pub last_epoch: u64,
    /// The `seq` of its `key_bundle.put`.
    pub seq: u64,
    /// The signed `key_bundle.put`.
    pub op: SignedDoc,
}

/// A shared record as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRecord {
    /// Its key, collection, policy, version and whether it is deleted.
    pub state: RecordState,
    /// The bytes its value counts against the storage quota.
    pub value_bytes: u64,
    /// The writing app.
    pub writer: [u8; 16],
    /// The certificate the write was checked against.
    pub cert: SignedDoc,
    /// The signed `record.put`.
    pub op: SignedDoc,
    /// Its transition proof.
    pub proof: SignedDoc,
}

/// A claim entry as stored, for `GET /claims` (Switch wire 7.4.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredClaimEntry {
    /// The claim's step before the entry.
    pub step: u64,
    /// The entry's `seq`.
    pub seq: u64,
    /// The signed `claim`.
    pub op: SignedDoc,
    /// Its transition proof.
    pub proof: SignedDoc,
}

/// A list of the allowlist or the deny list (Switch wire 7.4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListName {
    /// Contacts.
    Contact,
    /// Conversation entries.
    Conversation,
    /// The deny list.
    Deny,
}

impl ListName {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            ListName::Contact => "contact",
            ListName::Conversation => "conversation",
            ListName::Deny => "deny",
        }
    }
}

/// A list entry as stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredListEntry {
    /// The Pubky ID.
    pub pubky: [u8; 32],
    /// The writing app; `None` for a conversation entry the service wrote for a sender an
    /// invite code admitted.
    pub written_by: Option<[u8; 16]>,
    /// The service time of the write.
    pub at_ms: u64,
}

/// An invite code as stored.
#[derive(Clone, Debug, PartialEq)]
pub struct StoredInvite {
    /// `hash(code bytes)`.
    pub code_hash: [u8; 32],
    /// How many appends it admits.
    pub max_uses: u64,
    /// How many it admitted.
    pub uses: u64,
    /// The writing app.
    pub writer: [u8; 16],
    /// When it expires.
    pub expires_at_ms: u64,
    /// Its context.
    pub context: Value,
    /// The context's bytes as its writer wrote them, which a reader repeats (Switch wire
    /// 1.1). A code stored before the service kept them holds a re-serialization.
    pub context_written: Vec<u8>,
}

fn array<const N: usize>(bytes: &[u8], what: &'static str) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(bytes).map_err(|_| StoreError::Corrupt(what))
}

fn opt_u64(value: Option<i64>, what: &'static str) -> Result<Option<u64>, StoreError> {
    value.map(|v| from_db(v, what)).transpose()
}

fn opt_to_db(value: Option<u64>, what: &'static str) -> Result<Option<i64>, StoreError> {
    value.map(|v| to_db(v, what)).transpose()
}

fn opt_doc(bytes: Option<Vec<u8>>, what: &'static str) -> Result<Option<SignedDoc>, StoreError> {
    bytes.map(|b| decode_doc(&b, what)).transpose()
}

fn keys<const N: usize>(keys: &[[u8; N]]) -> Vec<Vec<u8>> {
    keys.iter().map(|key| key.to_vec()).collect()
}

fn db(error: sqlx::Error) -> StoreError {
    StoreError::from_db(error)
}

impl AccountTxn {
    /// The directory's versions: `directory_version` and `apps_version` (Switch wire 7.4.10).
    pub async fn directory_versions(&mut self) -> Result<(u64, u64), StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query("SELECT directory_version, apps_version FROM accounts WHERE id = $1")
            .bind(id)
            .fetch_one(self.conn())
            .await
            .map_err(db)?;
        Ok((
            from_db(row.try_get("directory_version")?, "directory_version")?,
            from_db(row.try_get("apps_version")?, "apps_version")?,
        ))
    }

    /// Set the directory's versions.
    pub async fn set_directory_versions(
        &mut self,
        directory_version: u64,
        apps_version: u64,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query("UPDATE accounts SET directory_version = $2, apps_version = $3 WHERE id = $1")
            .bind(id)
            .bind(to_db(directory_version, "directory_version")?)
            .bind(to_db(apps_version, "apps_version")?)
            .execute(self.conn())
            .await
            .map_err(db)?;
        Ok(())
    }

    /// Every own app the account holds, by App ID.
    pub async fn apps(&mut self) -> Result<Vec<StoredApp>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(
            "SELECT app_id, record, record_at_ms, renewed_cert, receive_key, cursor_generation, \
             cursor_seq, reachable_since, full_requested_ms FROM apps WHERE account_id = $1 \
             ORDER BY app_id",
        )
        .bind(id)
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.iter().map(app_of).collect()
    }

    /// Store an own app, replacing what the account held for it.
    pub async fn put_app(&mut self, app: &StoredApp) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        let doc = |doc: &Option<SignedDoc>| doc.as_ref().map(encode_doc).transpose();
        sqlx::query(
            "INSERT INTO apps (account_id, app_id, record, record_at_ms, renewed_cert, \
             receive_key, cursor_generation, cursor_seq, reachable_since, full_requested_ms) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (account_id, app_id) DO UPDATE SET record = $3, record_at_ms = $4, \
             renewed_cert = $5, receive_key = $6, cursor_generation = $7, cursor_seq = $8, \
             reachable_since = $9, full_requested_ms = $10",
        )
        .bind(id)
        .bind(app.app_id.as_slice())
        .bind(doc(&app.record)?)
        .bind(opt_to_db(app.record_at_ms, "record_at_ms")?)
        .bind(doc(&app.renewed_cert)?)
        .bind(doc(&app.receive_key)?)
        .bind(opt_to_db(
            app.cursor.map(|c| c.generation),
            "cursor_generation",
        )?)
        .bind(opt_to_db(app.cursor.map(|c| c.seq), "cursor_seq")?)
        .bind(opt_to_db(app.reachable_since, "reachable_since")?)
        .bind(opt_to_db(app.full_requested_ms, "full_requested_ms")?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        self.note_change();
        Ok(())
    }

    /// Which of `kids` some app of the account registered.
    pub async fn registered_kids(&mut self, kids: &[[u8; 8]]) -> Result<Vec<[u8; 8]>, StoreError> {
        let id = self.head().id.clone();
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT kid FROM receive_keys WHERE account_id = $1 AND kid = ANY($2)",
        )
        .bind(id)
        .bind(keys(kids))
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.iter().map(|kid| array(kid, "kid")).collect()
    }

    /// Keep a registered receive key record.
    pub async fn add_receive_key(
        &mut self,
        app_id: &[u8; 16],
        n: u64,
        kid: &[u8; 8],
        record: &SignedDoc,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO receive_keys (account_id, kid, app_id, n, record) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(kid.as_slice())
        .bind(app_id.as_slice())
        .bind(to_db(n, "n")?)
        .bind(encode_doc(record)?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// The key bundle parts stored for `target`, in `first_epoch` order.
    pub async fn bundle_parts(
        &mut self,
        target: &[u8; 16],
    ) -> Result<Vec<StoredBundlePart>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(
            "SELECT first_epoch, last_epoch, seq, op FROM key_bundle_parts \
             WHERE account_id = $1 AND target_app_id = $2 ORDER BY first_epoch",
        )
        .bind(id)
        .bind(target.as_slice())
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.iter()
            .map(|row| {
                let op: Vec<u8> = row.try_get("op")?;
                Ok(StoredBundlePart {
                    first_epoch: from_db(row.try_get("first_epoch")?, "first_epoch")?,
                    last_epoch: from_db(row.try_get("last_epoch")?, "last_epoch")?,
                    seq: from_db(row.try_get("seq")?, "seq")?,
                    op: decode_doc(&op, "key bundle part")?,
                })
            })
            .collect()
    }

    /// Replace the key bundle parts stored for `target` with `parts`.
    pub async fn set_bundle_parts(
        &mut self,
        target: &[u8; 16],
        parts: &[StoredBundlePart],
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query("DELETE FROM key_bundle_parts WHERE account_id = $1 AND target_app_id = $2")
            .bind(&id)
            .bind(target.as_slice())
            .execute(self.conn())
            .await
            .map_err(db)?;
        for part in parts {
            sqlx::query(
                "INSERT INTO key_bundle_parts (account_id, target_app_id, first_epoch, \
                 last_epoch, seq, op) VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&id)
            .bind(target.as_slice())
            .bind(to_db(part.first_epoch, "first_epoch")?)
            .bind(to_db(part.last_epoch, "last_epoch")?)
            .bind(to_db(part.seq, "seq")?)
            .bind(encode_doc(&part.op)?)
            .execute(self.conn())
            .await
            .map_err(db)?;
        }
        Ok(())
    }

    /// The shared records at `keys` that the account holds.
    pub async fn records(&mut self, keys_: &[[u8; 32]]) -> Result<Vec<StoredRecord>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(
            "SELECT key, collection, read_scope, write_scopes, generation, version, deleted, \
             value_bytes, writer, cert, op, proof FROM shared_records \
             WHERE account_id = $1 AND key = ANY($2)",
        )
        .bind(id)
        .bind(keys(keys_))
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.iter().map(record_of).collect()
    }

    /// Live record keys and the bytes their values count, over the records not at `excluding`.
    pub async fn record_totals(
        &mut self,
        excluding: &[[u8; 32]],
    ) -> Result<(u64, u64), StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query(
            "SELECT count(*) AS keys, coalesce(sum(value_bytes), 0)::BIGINT AS bytes \
             FROM shared_records WHERE account_id = $1 AND NOT deleted \
             AND NOT (key = ANY($2))",
        )
        .bind(id)
        .bind(keys(excluding))
        .fetch_one(self.conn())
        .await
        .map_err(db)?;
        Ok((
            from_db(row.try_get("keys")?, "record keys")?,
            from_db(row.try_get("bytes")?, "record bytes")?,
        ))
    }

    /// Store a shared record's newest write.
    pub async fn put_record(&mut self, record: &StoredRecord) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        let state = &record.state;
        sqlx::query(
            "INSERT INTO shared_records (account_id, key, collection, read_scope, write_scopes, \
             generation, version, deleted, value_bytes, writer, cert, op, proof) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
             ON CONFLICT (account_id, key) DO UPDATE SET generation = $6, version = $7, \
             deleted = $8, value_bytes = $9, writer = $10, cert = $11, op = $12, proof = $13",
        )
        .bind(id)
        .bind(state.key.as_slice())
        .bind(state.collection.as_slice())
        .bind(&state.policy.read_scope)
        .bind(&state.policy.write_scopes)
        .bind(to_db(state.version.generation, "generation")?)
        .bind(to_db(state.version.version, "version")?)
        .bind(state.deleted)
        .bind(to_db(record.value_bytes, "value_bytes")?)
        .bind(record.writer.as_slice())
        .bind(encode_doc(&record.cert)?)
        .bind(encode_doc(&record.op)?)
        .bind(encode_doc(&record.proof)?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// The claims at `claim_keys` that the account holds.
    pub async fn claims(
        &mut self,
        claim_keys: &[[u8; 32]],
    ) -> Result<Vec<([u8; 32], Claim)>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(
            "SELECT claim_key, state FROM claims WHERE account_id = $1 AND claim_key = ANY($2)",
        )
        .bind(id)
        .bind(keys(claim_keys))
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.iter()
            .map(|row| {
                let key: Vec<u8> = row.try_get("claim_key")?;
                let state: Vec<u8> = row.try_get("state")?;
                Ok((array(&key, "claim_key")?, claim_codec::decode(&state)?))
            })
            .collect()
    }

    /// What the per-app claim limits count for `writer` over the claims not at `excluding`
    /// (Switch wire 6.8 "Per app").
    pub async fn claim_tally(
        &mut self,
        writer: &[u8; 16],
        excluding: &[[u8; 32]],
    ) -> Result<ClaimTally, StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query(
            "SELECT count(*) AS claims, \
             count(*) FILTER (WHERE creator = $2) AS created, \
             coalesce(sum(cardinality(array_positions(open_owners, $2))), 0)::BIGINT AS open \
             FROM claims WHERE account_id = $1 AND NOT (claim_key = ANY($3))",
        )
        .bind(id)
        .bind(writer.as_slice())
        .bind(keys(excluding))
        .fetch_one(self.conn())
        .await
        .map_err(db)?;
        Ok(ClaimTally {
            claims: from_db(row.try_get("claims")?, "claims")?,
            created_by_writer: from_db(row.try_get("created")?, "claims created")?,
            open_attempts_of_writer: from_db(row.try_get("open")?, "open attempts")?,
        })
    }

    /// Store a claim's state, with when it may be deleted (Switch wire 6.8).
    pub async fn put_claim(
        &mut self,
        claim_key: &[u8; 32],
        claim: &Claim,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO claims (account_id, claim_key, state, creator, tombstone, open_owners, \
             delete_known, delete_after_ms, delete_after_entry_ms) \
             VALUES ($1, $2, $3, $4, $5, $6, true, $7, $8) \
             ON CONFLICT (account_id, claim_key) DO UPDATE SET state = $3, creator = $4, \
             tombstone = $5, open_owners = $6, delete_known = true, delete_after_ms = $7, \
             delete_after_entry_ms = $8",
        )
        .bind(id)
        .bind(claim_key.as_slice())
        .bind(claim_codec::encode(claim)?)
        .bind(claim.creator.map(|c| c.to_vec()))
        .bind(claim.tombstone)
        .bind(claim_codec::open_owners(claim))
        .bind(opt_to_db(
            claim_codec::deletion(claim).0,
            "delete_after_ms",
        )?)
        .bind(opt_to_db(
            claim_codec::deletion(claim).1,
            "delete_after_entry_ms",
        )?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Delete up to `bound` claims that may be deleted at `base_ms`, the time base, with
    /// their entries (Switch wire 7.3 step 4). First, up to `bound` claims written before the
    /// service kept when they may be deleted get it, from their state. Returns how many went.
    pub async fn delete_due_claims(
        &mut self,
        base_ms: u64,
        max_claim_age_ms: u64,
        bound: u64,
    ) -> Result<u64, StoreError> {
        let id = self.head().id.clone();
        let unknown = sqlx::query(
            "SELECT claim_key, state FROM claims WHERE account_id = $1 AND NOT delete_known \
             LIMIT $2",
        )
        .bind(&id)
        .bind(to_db(bound, "bound")?)
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        for row in &unknown {
            let key: Vec<u8> = row.try_get("claim_key")?;
            let state: Vec<u8> = row.try_get("state")?;
            // A state that doesn't decode is marked known with no deletion time, so it
            // blocks nothing; the log names no content.
            let (after, after_entry) = match claim_codec::decode(&state) {
                Ok(claim) => claim_codec::deletion(&claim),
                Err(error) => {
                    tracing::warn!(%error, "a stored claim doesn't decode; it isn't deleted on time");
                    (None, None)
                }
            };
            sqlx::query(
                "UPDATE claims SET delete_known = true, delete_after_ms = $3, \
                 delete_after_entry_ms = $4 WHERE account_id = $1 AND claim_key = $2",
            )
            .bind(&id)
            .bind(key)
            .bind(opt_to_db(after, "delete_after_ms")?)
            .bind(opt_to_db(after_entry, "delete_after_entry_ms")?)
            .execute(self.conn())
            .await
            .map_err(db)?;
        }
        // A last entry this long ago or more has aged out; none has before the epoch.
        let aged_before = base_ms
            .checked_sub(max_claim_age_ms)
            .map_or(Ok(-1), |at| to_db(at, "time"))?;
        let deleted = sqlx::query(
            "DELETE FROM claims WHERE account_id = $1 AND claim_key IN ( \
             SELECT claim_key FROM claims WHERE account_id = $1 AND delete_known \
             AND (delete_after_ms <= $2 OR delete_after_entry_ms <= $3) LIMIT $4)",
        )
        .bind(&id)
        .bind(to_db(base_ms, "time")?)
        .bind(aged_before)
        .bind(to_db(bound, "bound")?)
        .execute(self.conn())
        .await
        .map_err(db)?
        .rows_affected();
        if deleted > 0 {
            self.note_change();
        }
        Ok(deleted)
    }

    /// The `seq` of the entry at `step` of the claim at `claim_key`.
    pub async fn claim_entry_seq(
        &mut self,
        claim_key: &[u8; 32],
        step: u64,
    ) -> Result<Option<u64>, StoreError> {
        let id = self.head().id.clone();
        let seq: Option<i64> = sqlx::query_scalar(
            "SELECT seq FROM claim_entries WHERE account_id = $1 AND claim_key = $2 AND step = $3",
        )
        .bind(id)
        .bind(claim_key.as_slice())
        .bind(to_db(step, "step")?)
        .fetch_optional(self.conn())
        .await
        .map_err(db)?;
        seq.map(|seq| from_db(seq, "seq")).transpose()
    }

    /// Delete the claim at `claim_key`, with its entries, as step 4 would.
    pub async fn delete_claim(&mut self, claim_key: &[u8; 32]) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query("DELETE FROM claims WHERE account_id = $1 AND claim_key = $2")
            .bind(id)
            .bind(claim_key.as_slice())
            .execute(self.conn())
            .await
            .map_err(db)?;
        self.note_change();
        Ok(())
    }

    /// Keep `app_id` for good as removed for `reason`, revoked or departed, at `at_ms` and
    /// the newest document's `data_epoch`, a departure awaiting its rotation above it, and
    /// withdraw the invite codes it registered: a leave is treated exactly as a revocation
    /// (Switch spec 7, 12.2, 12.3; Switch wire 7.4.12, 9.1).
    pub async fn keep_removed(
        &mut self,
        app_id: &[u8; 16],
        reason: KeptReason,
        at_ms: u64,
        data_epoch: u64,
    ) -> Result<(), StoreError> {
        let reason = match reason {
            KeptReason::Revoked => "revoked",
            KeptReason::Departed => "departed",
            // An enrollment's App IDs are kept when it is taken, never removed here.
            KeptReason::Enrolled => return Err(StoreError::Corrupt("not a removal")),
        };
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO kept_app_ids (account_id, app_id, reason, at_ms, data_epoch) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&id)
        .bind(app_id.as_slice())
        .bind(reason)
        .bind(to_db(at_ms, "time")?)
        .bind(to_db(data_epoch, "data_epoch")?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        sqlx::query("DELETE FROM invite_codes WHERE account_id = $1 AND writer = $2")
            .bind(&id)
            .bind(app_id.as_slice())
            .execute(self.conn())
            .await
            .map_err(db)?;
        self.note_change();
        Ok(())
    }

    /// Keep a claim entry with its proof.
    pub async fn add_claim_entry(
        &mut self,
        claim_key: &[u8; 32],
        entry: &StoredClaimEntry,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO claim_entries (account_id, claim_key, step, seq, op, proof) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(id)
        .bind(claim_key.as_slice())
        .bind(to_db(entry.step, "step")?)
        .bind(to_db(entry.seq, "seq")?)
        .bind(encode_doc(&entry.op)?)
        .bind(encode_doc(&entry.proof)?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// The entries of `list` at `pubkys` that the account holds.
    pub async fn list_entries(
        &mut self,
        list: ListName,
        pubkys: &[[u8; 32]],
    ) -> Result<Vec<StoredListEntry>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(
            "SELECT pubky, written_by, at_ms FROM list_entries \
             WHERE account_id = $1 AND list = $2 AND pubky = ANY($3)",
        )
        .bind(id)
        .bind(list.as_str())
        .bind(keys(pubkys))
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.iter()
            .map(|row| {
                let pubky: Vec<u8> = row.try_get("pubky")?;
                let by: Option<Vec<u8>> = row.try_get("written_by")?;
                Ok(StoredListEntry {
                    pubky: array(&pubky, "pubky")?,
                    written_by: by.map(|by| array(&by, "written_by")).transpose()?,
                    at_ms: from_db(row.try_get("at_ms")?, "at_ms")?,
                })
            })
            .collect()
    }

    /// The entries of `list` not at `excluding`.
    pub async fn list_count(
        &mut self,
        list: ListName,
        excluding: &[[u8; 32]],
    ) -> Result<u64, StoreError> {
        let id = self.head().id.clone();
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM list_entries WHERE account_id = $1 AND list = $2 \
             AND NOT (pubky = ANY($3))",
        )
        .bind(id)
        .bind(list.as_str())
        .bind(keys(excluding))
        .fetch_one(self.conn())
        .await
        .map_err(db)?;
        from_db(count, "list entries")
    }

    /// Add an entry to `list`, or replace it.
    pub async fn put_list_entry(
        &mut self,
        list: ListName,
        entry: &StoredListEntry,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO list_entries (account_id, list, pubky, written_by, at_ms) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (account_id, list, pubky) DO UPDATE \
             SET written_by = $4, at_ms = $5",
        )
        .bind(id)
        .bind(list.as_str())
        .bind(entry.pubky.as_slice())
        .bind(entry.written_by.map(|app| app.to_vec()))
        .bind(to_db(entry.at_ms, "at_ms")?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Remove `pubky` from `list`.
    pub async fn delete_list_entry(
        &mut self,
        list: ListName,
        pubky: &[u8; 32],
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query("DELETE FROM list_entries WHERE account_id = $1 AND list = $2 AND pubky = $3")
            .bind(id)
            .bind(list.as_str())
            .bind(pubky.as_slice())
            .execute(self.conn())
            .await
            .map_err(db)?;
        Ok(())
    }

    /// The invite codes at `code_hashes` that the account holds.
    pub async fn invites(
        &mut self,
        code_hashes: &[[u8; 32]],
    ) -> Result<Vec<StoredInvite>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(
            "SELECT code_hash, max_uses, uses, writer, expires_at_ms, context FROM invite_codes \
             WHERE account_id = $1 AND code_hash = ANY($2)",
        )
        .bind(id)
        .bind(keys(code_hashes))
        .fetch_all(self.conn())
        .await
        .map_err(db)?;
        rows.iter()
            .map(|row| {
                let hash: Vec<u8> = row.try_get("code_hash")?;
                let writer: Vec<u8> = row.try_get("writer")?;
                let context: Vec<u8> = row.try_get("context")?;
                Ok(StoredInvite {
                    code_hash: array(&hash, "code_hash")?,
                    max_uses: from_db(row.try_get("max_uses")?, "max_uses")?,
                    uses: from_db(row.try_get("uses")?, "uses")?,
                    writer: array(&writer, "writer")?,
                    expires_at_ms: from_db(row.try_get("expires_at_ms")?, "expires_at_ms")?,
                    context: serde_json::from_slice(&context)
                        .map_err(|_| StoreError::Corrupt("an invite code's context"))?,
                    context_written: context,
                })
            })
            .collect()
    }

    /// Live invite codes, with uses left and unexpired at `now_ms`, not at `excluding`.
    pub async fn live_invites(
        &mut self,
        now_ms: u64,
        excluding: &[[u8; 32]],
    ) -> Result<u64, StoreError> {
        let id = self.head().id.clone();
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM invite_codes WHERE account_id = $1 AND uses < max_uses \
             AND expires_at_ms > $2 AND NOT (code_hash = ANY($3))",
        )
        .bind(id)
        .bind(to_db(now_ms, "time")?)
        .bind(keys(excluding))
        .fetch_one(self.conn())
        .await
        .map_err(db)?;
        from_db(count, "invite codes")
    }

    /// Store an invite code, replacing one at its hash.
    pub async fn put_invite(&mut self, invite: &StoredInvite) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        // The bytes as written, never a re-serialization (Switch wire 1.1).
        let context = invite.context_written.clone();
        sqlx::query(
            "INSERT INTO invite_codes (account_id, code_hash, max_uses, uses, writer, \
             expires_at_ms, context) VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (account_id, code_hash) DO UPDATE SET max_uses = $3, uses = $4, \
             writer = $5, expires_at_ms = $6, context = $7",
        )
        .bind(id)
        .bind(invite.code_hash.as_slice())
        .bind(to_db(invite.max_uses, "max_uses")?)
        .bind(to_db(invite.uses, "uses")?)
        .bind(invite.writer.as_slice())
        .bind(to_db(invite.expires_at_ms, "expires_at_ms")?)
        .bind(context)
        .execute(self.conn())
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Withdraw the invite code at `code_hash`.
    pub async fn delete_invite(&mut self, code_hash: &[u8; 32]) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query("DELETE FROM invite_codes WHERE account_id = $1 AND code_hash = $2")
            .bind(id)
            .bind(code_hash.as_slice())
            .execute(self.conn())
            .await
            .map_err(db)?;
        Ok(())
    }

    /// The batch record the account holds for `batch_id`.
    pub async fn batch_record(
        &mut self,
        batch_id: &[u8; 16],
    ) -> Result<Option<BatchRecord>, StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query(
            "SELECT ops_hash, proofs, at_ms, first_seq, last_seq FROM batches \
             WHERE account_id = $1 AND batch_id = $2",
        )
        .bind(id)
        .bind(batch_id.as_slice())
        .fetch_optional(self.conn())
        .await
        .map_err(db)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let hash: Vec<u8> = row.try_get("ops_hash")?;
        let proofs: Option<Vec<u8>> = row.try_get("proofs")?;
        Ok(Some(BatchRecord {
            ops_hash: array(&hash, "ops_hash")?,
            proofs: proofs
                .map(|bytes| {
                    serde_json::from_slice::<Vec<SignedDoc>>(&bytes)
                        .map_err(|_| StoreError::Corrupt("a batch's proofs"))
                })
                .transpose()?,
            at: from_db(row.try_get("at_ms")?, "at_ms")?,
            first_seq: from_db(row.try_get("first_seq")?, "first_seq")?,
            last_seq: from_db(row.try_get("last_seq")?, "last_seq")?,
        }))
    }

    /// Keep a batch record, for the account's current generation.
    pub async fn put_batch(
        &mut self,
        batch_id: &[u8; 16],
        record: &BatchRecord,
    ) -> Result<(), StoreError> {
        let head = self.head().clone();
        let proofs = record
            .proofs
            .as_ref()
            .map(|proofs| {
                serde_json::to_vec(proofs).map_err(|_| StoreError::Corrupt("proofs don't encode"))
            })
            .transpose()?;
        sqlx::query(
            "INSERT INTO batches (account_id, batch_id, ops_hash, proofs, at_ms, generation, \
             first_seq, last_seq) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&head.id)
        .bind(batch_id.as_slice())
        .bind(record.ops_hash.as_slice())
        .bind(proofs)
        .bind(to_db(record.at, "at_ms")?)
        .bind(to_db(head.generation, "generation")?)
        .bind(to_db(record.first_seq, "first_seq")?)
        .bind(to_db(record.last_seq, "last_seq")?)
        .execute(self.conn())
        .await
        .map_err(db)?;
        Ok(())
    }
}

fn record_of(row: &sqlx::postgres::PgRow) -> Result<StoredRecord, StoreError> {
    let key: Vec<u8> = row.try_get("key")?;
    let collection: Vec<u8> = row.try_get("collection")?;
    let writer: Vec<u8> = row.try_get("writer")?;
    let cert: Vec<u8> = row.try_get("cert")?;
    let op: Vec<u8> = row.try_get("op")?;
    let proof: Vec<u8> = row.try_get("proof")?;
    Ok(StoredRecord {
        state: RecordState {
            key: array(&key, "record key")?,
            collection: array(&collection, "collection")?,
            policy: Policy {
                read_scope: row.try_get("read_scope")?,
                write_scopes: row.try_get("write_scopes")?,
            },
            version: pubky_switch_core::ops::RecordVersion::new(
                from_db(row.try_get("generation")?, "generation")?,
                from_db(row.try_get("version")?, "version")?,
            ),
            deleted: row.try_get("deleted")?,
        },
        value_bytes: from_db(row.try_get("value_bytes")?, "value_bytes")?,
        writer: array(&writer, "writer")?,
        cert: decode_doc(&cert, "record cert")?,
        op: decode_doc(&op, "record op")?,
        proof: decode_doc(&proof, "record proof")?,
    })
}

/// The first `steps` entries of a claim, by step (Switch wire 7.4.8).
pub(super) async fn claim_entries_before(
    pool: &sqlx::PgPool,
    id: &str,
    claim_key: &[u8; 32],
    steps: u64,
) -> Result<Vec<StoredClaimEntry>, StoreError> {
    let rows = sqlx::query(
        "SELECT step, seq, op, proof FROM claim_entries \
         WHERE account_id = $1 AND claim_key = $2 AND step < $3 ORDER BY step",
    )
    .bind(id)
    .bind(claim_key.as_slice())
    .bind(to_db(steps, "steps")?)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    rows.iter()
        .map(|row| {
            let op: Vec<u8> = row.try_get("op")?;
            let proof: Vec<u8> = row.try_get("proof")?;
            Ok(StoredClaimEntry {
                step: from_db(row.try_get("step")?, "step")?,
                seq: from_db(row.try_get("seq")?, "seq")?,
                op: decode_doc(&op, "claim entry")?,
                proof: decode_doc(&proof, "claim entry proof")?,
            })
        })
        .collect()
}

/// An `apps` row as a [`StoredApp`].
fn app_of(row: &sqlx::postgres::PgRow) -> Result<StoredApp, StoreError> {
    let app_id: Vec<u8> = row.try_get("app_id")?;
    let cursor = match (
        opt_u64(row.try_get("cursor_generation")?, "cursor_generation")?,
        opt_u64(row.try_get("cursor_seq")?, "cursor_seq")?,
    ) {
        (Some(generation), Some(seq)) => Some(Position { generation, seq }),
        (None, None) => None,
        _ => return Err(StoreError::Corrupt("an app's cursor")),
    };
    Ok(StoredApp {
        app_id: array(&app_id, "app_id")?,
        record: opt_doc(row.try_get("record")?, "app record")?,
        record_at_ms: opt_u64(row.try_get("record_at_ms")?, "record_at_ms")?,
        renewed_cert: opt_doc(row.try_get("renewed_cert")?, "renewed cert")?,
        receive_key: opt_doc(row.try_get("receive_key")?, "receive key")?,
        cursor,
        reachable_since: opt_u64(row.try_get("reachable_since")?, "reachable_since")?,
        full_requested_ms: opt_u64(row.try_get("full_requested_ms")?, "full_requested_ms")?,
    })
}

/// What an own app's checks before the lock read (Switch wire 7.2 Order), in one statement
/// so they see one state: the account's newest `identity.json`, the app's row, and whether
/// its App ID is kept for good. `None` for an account that isn't there.
pub(super) async fn own_app_view(
    pool: &sqlx::PgPool,
    id: &str,
    app_id: &[u8; 16],
) -> Result<Option<(Option<SignedDoc>, Option<StoredApp>, bool)>, StoreError> {
    let row = sqlx::query(
        "SELECT a.identity_doc, p.app_id, p.record, p.record_at_ms, p.renewed_cert, \
         p.receive_key, p.cursor_generation, p.cursor_seq, p.reachable_since, \
         p.full_requested_ms, EXISTS (SELECT 1 FROM kept_app_ids k \
         WHERE k.account_id = a.id AND k.app_id = $2) AS kept \
         FROM accounts a LEFT JOIN apps p ON p.account_id = a.id AND p.app_id = $2 \
         WHERE a.id = $1",
    )
    .bind(id)
    .bind(app_id.as_slice())
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let doc = opt_doc(row.try_get("identity_doc")?, "identity_doc")?;
    let app: Option<Vec<u8>> = row.try_get("app_id")?;
    let app = app.map(|_| app_of(&row)).transpose()?;
    Ok(Some((doc, app, row.try_get("kept")?)))
}

/// The `apps` row of `app_id` at account `id`, read without the account's lock.
pub(super) async fn app_row<'c>(
    conn: impl sqlx::PgExecutor<'c>,
    id: &str,
    app_id: &[u8; 16],
) -> Result<Option<StoredApp>, StoreError> {
    let row = sqlx::query(
        "SELECT app_id, record, record_at_ms, renewed_cert, receive_key, cursor_generation, \
         cursor_seq, reachable_since, full_requested_ms FROM apps \
         WHERE account_id = $1 AND app_id = $2",
    )
    .bind(id)
    .bind(app_id.as_slice())
    .fetch_optional(conn)
    .await
    .map_err(db)?;
    row.as_ref().map(app_of).transpose()
}
