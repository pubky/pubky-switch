//! A provider loss at this service (Switch spec 12.6; Switch wire 3.3, 3.7, 7.4.2): the
//! recovery a generation begins with, the enrollments a generation change retires, and the
//! account starting afresh.

use sqlx::Row;

use super::{AccountTxn, StoreError, from_db, identity::time_to_db, to_db};
use crate::keys::KeyId;

/// The recovery the generation the account serves began with (Switch wire 7.4.12
/// `recovery`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recovery {
    /// The generation it declares lost, the one before the account's.
    pub recovery_from: u64,
    /// The `recovery` transition's service time.
    pub declared_at_ms: u64,
    /// Whether admission is staged still (Switch spec 12.6 step 2).
    pub admission_staged: bool,
}

/// The tables of an account's state for one generation at this service, which a recovery in
/// place empties (Switch wire 3.3): its chain, its own apps and what they wrote, its lists,
/// invites, batches and inbox, its flagged senders and pending connect requests, a hand-over,
/// the counterparties' copies and their floors.
const GENERATION_STATE: &[&str] = &[
    "chain_items",
    "apps",
    "receive_keys",
    "key_bundle_parts",
    "shared_records",
    "claims",
    "list_entries",
    "invite_codes",
    "batches",
    "inbox_entries",
    "sender_flags",
    "handovers",
    "app_listings",
    "peer_copies",
    "peer_floors",
    "connect_requests",
];

/// Every table with an account column that a recovery in place keeps (Switch wire 3.3,
/// 3.7): the App IDs kept for good, the enrollment answers and the retired ones' records, and
/// the keys owed deleting. The account's row stays too, its service time and the
/// directory's two versions with it.
pub const RECOVERY_KEEPS: &[&str] = &[
    "kept_app_ids",
    "enrollment_answers",
    "retired_enrollments",
    "erased_keys",
];

/// Every table with an account column that a recovery in place empties: the generation's own state,
/// `claim_entries` with their claims, `divergent_uploads` with their records, and
/// `pending_revoked_apps`, which joins `kept_app_ids`.
/// A table added later with an account column must be classed here or in
/// [`RECOVERY_KEEPS`], which a test of every such table checks.
pub fn recovery_clears() -> Vec<&'static str> {
    let mut tables = GENERATION_STATE.to_vec();
    tables.extend(["claim_entries", "pending_revoked_apps"]);
    // A record's divergent uploads (Switch wire 7.4.14) go with their record.
    tables.push("divergent_uploads");
    tables
}

impl super::Store {
    /// The generation declared lost at `id`, read without the account's lock, while it
    /// serves the generation a recovery began; `None` otherwise. A recovery upload judged
    /// with it compares it with what it reads under the lock before it takes the judgment.
    pub async fn recovery_from_of(&self, id: &str) -> Result<Option<u64>, StoreError> {
        let row = sqlx::query("SELECT recovery_from, generation FROM accounts WHERE id = $1")
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(StoreError::from_db)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let from: Option<i64> = row.try_get("recovery_from")?;
        let generation: i64 = row.try_get("generation")?;
        let Some(from) = from else {
            return Ok(None);
        };
        let from = from_db(from, "recovery_from")?;
        Ok((from.checked_add(1) == Some(from_db(generation, "generation")?)).then_some(from))
    }
}

impl AccountTxn {
    /// The recovery the generation the account serves began with, if it began with one: a
    /// recovery the account records for an earlier generation counts for nothing.
    pub async fn recovery(&mut self) -> Result<Option<Recovery>, StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query(
            "SELECT recovery_from, recovery_declared_at_ms, admission_staged FROM accounts \
             WHERE id = $1",
        )
        .bind(id)
        .fetch_one(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        let from: Option<i64> = row.try_get("recovery_from")?;
        let at: Option<i64> = row.try_get("recovery_declared_at_ms")?;
        let (Some(from), Some(at)) = (from, at) else {
            return Ok(None);
        };
        let recovery = Recovery {
            recovery_from: from_db(from, "recovery_from")?,
            declared_at_ms: from_db(at, "recovery_declared_at_ms")?,
            admission_staged: row.try_get("admission_staged")?,
        };
        Ok(
            (recovery.recovery_from.checked_add(1) == Some(self.head().generation))
                .then_some(recovery),
        )
    }

    /// Whether admission is staged at the account: after a recovery it began with, until the
    /// signer or a qualifying upload ends it (Switch spec 12.6 step 2).
    pub async fn admission_staged(&mut self) -> Result<bool, StoreError> {
        Ok(self.recovery().await?.is_some_and(|r| r.admission_staged))
    }

    /// End staged admission: whether it was staged, and is no longer. Ending it when it isn't
    /// staged writes nothing (Switch wire 7.4.14).
    pub async fn end_admission(&mut self) -> Result<bool, StoreError> {
        if !self.admission_staged().await? {
            return Ok(false);
        }
        let id = self.head().id.clone();
        sqlx::query("UPDATE accounts SET admission_staged = false WHERE id = $1")
            .bind(id)
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        Ok(true)
    }

    /// The App IDs held with the pending key, from the `revoked_apps` of the enrollments it
    /// answered (Switch wire 3.7).
    pub async fn pending_revoked_apps(&mut self) -> Result<Vec<[u8; 16]>, StoreError> {
        let id = self.head().id.clone();
        let rows: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT app_id FROM pending_revoked_apps WHERE account_id = $1")
                .bind(id)
                .fetch_all(self.conn())
                .await
                .map_err(StoreError::from_db)?;
        rows.iter()
            .map(|app| {
                <[u8; 16]>::try_from(app.as_slice())
                    .map_err(|_| StoreError::Corrupt("pending revoked app_id"))
            })
            .collect()
    }

    /// Hold `apps`, an enrollment's `revoked_apps` answered with the pending key, until the
    /// delivery naming that key starts the new generation (Switch wire 3.7).
    pub async fn hold_pending_revoked_apps(&mut self, apps: &[[u8; 16]]) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        for app in apps {
            sqlx::query(
                "INSERT INTO pending_revoked_apps (account_id, app_id) VALUES ($1, $2) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&id)
            .bind(app.as_slice())
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        }
        Ok(())
    }

    /// The generation of the key the account answered the enrollment with document hash
    /// `hash` with, if a generation change has retired that key since (Switch wire 3.7).
    pub async fn retired_enrollment(&mut self, hash: &[u8; 32]) -> Result<Option<u64>, StoreError> {
        let id = self.head().id.clone();
        let generation: Option<i64> = sqlx::query_scalar(
            "SELECT generation FROM retired_enrollments \
             WHERE account_id = $1 AND enrollment_hash = $2",
        )
        .bind(id)
        .bind(hash.as_slice())
        .fetch_optional(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        generation
            .map(|g| from_db(g, "retired generation"))
            .transpose()
    }

    /// Start the recovery of a staged account that holds no document, at the first
    /// document's `generation` (Switch wire 3.3, 7.4.2): the account takes that generation,
    /// its key stays, and its chain starts empty, for the `recovery` transition. Recorded as
    /// the recovery of `recovery_from` at `at_ms`, with admission staged when `stages` (Switch
    /// spec 12.6 step 2). The chain must be empty: a staged account holds none.
    pub async fn start_recovery(
        &mut self,
        generation: u64,
        recovery_from: u64,
        at_ms: u64,
        stages: bool,
    ) -> Result<(), StoreError> {
        if self.head().chain.is_some() {
            return Err(StoreError::Corrupt("a staged account with a chain"));
        }
        let key = self.head().service_key.clone();
        self.set_generation(generation, &key, recovery_from, at_ms, stages)
            .await
    }

    /// Start a recovery in place (Switch wire 3.3, 3.7): the account serves the next
    /// generation under its pending key, `new_key`, and starts afresh. The caller holds the
    /// account's row lock and has taken its keying lock exclusive
    /// ([`AccountTxn::exclude_signers`]), so nothing signs with the outgoing key once this
    /// commits.
    ///
    /// It keeps the account's service time, the directory's `directory_version` and
    /// `apps_version`, which are columns of its row and never restart for an account (Switch
    /// wire 7.4.10), its App IDs kept for good, joined by the `revoked_apps` held with the
    /// pending key, and the enrollments it answered: those that
    /// named the pending key now name the account's key; those that named the outgoing key
    /// are kept by hash and generation alone ([`AccountTxn::retired_enrollment`]), at most
    /// `max_enrollments`. Everything else of the generation goes (`GENERATION_STATE`),
    /// and so does the held `identity.json`, which the caller replaces in the same
    /// transaction. The outgoing key is owed deleting, retired, not erased: it goes after the
    /// commit, as an erasure's keys do, and records no erasure.
    pub async fn start_recovery_in_place(
        &mut self,
        new_key: &KeyId,
        recovery_from: u64,
        at_ms: u64,
        max_enrollments: u64,
        stages: bool,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        let old_key = self.head().service_key.clone();
        let generation = recovery_from
            .checked_add(1)
            .ok_or(StoreError::Corrupt("generation overflow"))?;
        for table in GENERATION_STATE {
            sqlx::query(&format!("DELETE FROM {table} WHERE account_id = $1"))
                .bind(&id)
                .execute(self.conn())
                .await
                .map_err(StoreError::from_db)?;
        }
        sqlx::query(
            "INSERT INTO kept_app_ids (account_id, app_id, reason, at_ms) \
             SELECT account_id, app_id, 'enrolled', $2 FROM pending_revoked_apps \
             WHERE account_id = $1 ON CONFLICT DO NOTHING",
        )
        .bind(&id)
        .bind(time_to_db(at_ms)?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        sqlx::query("DELETE FROM pending_revoked_apps WHERE account_id = $1")
            .bind(&id)
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        // The retired answers' record, then their deletion, in this one commit (wire 3.7).
        sqlx::query(
            "INSERT INTO retired_enrollments (account_id, enrollment_hash, generation) \
             SELECT account_id, enrollment_hash, $3 FROM enrollment_answers \
             WHERE account_id = $1 AND service_key = $2 ORDER BY kept_order \
             ON CONFLICT DO NOTHING",
        )
        .bind(&id)
        .bind(old_key.as_str())
        .bind(to_db(recovery_from, "generation")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        sqlx::query(
            "DELETE FROM retired_enrollments WHERE account_id = $1 AND enrollment_hash IN ( \
             SELECT enrollment_hash FROM retired_enrollments WHERE account_id = $1 \
             ORDER BY retired_order DESC OFFSET $2)",
        )
        .bind(&id)
        .bind(to_db(max_enrollments, "max_enrollments")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        sqlx::query("DELETE FROM enrollment_answers WHERE account_id = $1 AND service_key = $2")
            .bind(&id)
            .bind(old_key.as_str())
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        // The pending key's answers are the account key's now, which a rebuild at the serving
        // account wouldn't give: kept as long as the account.
        sqlx::query(
            "UPDATE enrollment_answers SET rebuildable = false \
             WHERE account_id = $1 AND service_key = $2",
        )
        .bind(&id)
        .bind(new_key.as_str())
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        sqlx::query(
            "UPDATE accounts SET pending_key = NULL, identity_doc = NULL, identity_proof = NULL \
             WHERE id = $1",
        )
        .bind(&id)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        sqlx::query(
            "INSERT INTO erased_keys (key_id, account_id, erased_at_ms, reason) \
             VALUES ($1, $2, $3, 'retired') ON CONFLICT (key_id) DO NOTHING",
        )
        .bind(old_key.as_str())
        .bind(&id)
        .bind(time_to_db(at_ms)?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        self.set_generation(generation, new_key, recovery_from, at_ms, stages)
            .await
    }

    /// Write `generation`, `key` and the recovery of `recovery_from` at `at_ms`, staging
    /// admission when `stages`, to the account's row, and take them as its position, its
    /// chain empty.
    async fn set_generation(
        &mut self,
        generation: u64,
        key: &KeyId,
        recovery_from: u64,
        at_ms: u64,
        stages: bool,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        // The check of older documents keeps its two counters (`documents_checked_seq`,
        // `documents_check_end`), so it runs on over the new generation's first seqs. That
        // is harmless: those items are all chained under the rule, and the check deletes
        // only documents no app may read in full, as the write that superseded them would
        // have (Switch wire 7.5).
        sqlx::query(
            "UPDATE accounts SET generation = $2, service_key = $3, recovery_from = $4, \
             recovery_declared_at_ms = $5, admission_staged = $6 WHERE id = $1",
        )
        .bind(&id)
        .bind(to_db(generation, "generation")?)
        .bind(key.as_str())
        .bind(to_db(recovery_from, "recovery_from")?)
        .bind(time_to_db(at_ms)?)
        .bind(stages)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        self.start_head(generation, key.clone());
        Ok(())
    }
}
