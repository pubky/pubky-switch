//! The sweeps of an account's state at a request (Switch wire 9.1, Switch spec 10.3), under
//! its lock, in the request's transaction. Each takes at most the bound it is given and
//! decides by the service time the caller passes, never a client's: a run cut short leaves
//! only rows a later run takes, so a sweep may stop or restart at any point.

use super::{AccountTxn, StoreError, to_db};

fn app_ids(apps: &[[u8; 16]]) -> Vec<Vec<u8>> {
    apps.iter().map(|app| app.to_vec()).collect()
}

impl AccountTxn {
    /// Whether a deleted key may be forgotten, cursors aside: a cheap look before the
    /// cursors are read ([`Self::forget_deleted_keys`]).
    pub async fn deleted_key_to_forget(&mut self) -> Result<bool, StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query(
            "SELECT 1 FROM shared_records s WHERE s.account_id = $1 AND s.deleted \
             AND NOT s.from_upload AND NOT EXISTS (SELECT 1 FROM divergent_uploads d \
             WHERE d.account_id = s.account_id AND d.key = s.key) LIMIT 1",
        )
        .bind(id)
        .fetch_optional(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(row.is_some())
    }

    /// Forget at most `bound` deleted keys that nothing refers to (Switch spec 10.3, wire
    /// 9.1): the record's current write is its delete, written at this service (one taken
    /// from a recovery upload has no chain item here to stand for it); the cursor of every
    /// app of `current` is at or past the delete, but for an app `lagging` holds that has a
    /// `missed` item it hasn't passed, since passing that item makes it list its
    /// collections again (Switch wire 7.4.4), so it can't keep the forgotten record; and no
    /// divergent upload names the key. The record's row goes, so its delete shows as its
    /// chain stub and a create at the key starts afresh. The oldest deletes go first. The
    /// number forgotten.
    pub async fn forget_deleted_keys(
        &mut self,
        current: &[[u8; 16]],
        lagging: &[[u8; 16]],
        bound: u64,
    ) -> Result<u64, StoreError> {
        let id = self.head().id.clone();
        let forgotten = sqlx::query(
            "DELETE FROM shared_records r WHERE r.account_id = $1 AND r.key IN ( \
                 SELECT s.key FROM shared_records s \
                 WHERE s.account_id = $1 AND s.deleted AND NOT s.from_upload \
                 AND NOT EXISTS (SELECT 1 FROM divergent_uploads d \
                                 WHERE d.account_id = s.account_id AND d.key = s.key) \
                 AND NOT EXISTS (SELECT 1 FROM apps a \
                                 WHERE a.account_id = s.account_id \
                                 AND a.app_id = ANY($2) \
                                 AND NOT (a.app_id = ANY($3) AND EXISTS ( \
                                     SELECT 1 FROM inbox_entries m \
                                     WHERE m.account_id = a.account_id \
                                     AND m.kind = 'missed' AND m.targets[1] = a.app_id \
                                     AND (a.cursor_generation IS NULL \
                                          OR (m.generation, m.seq) \
                                             > (a.cursor_generation, a.cursor_seq)))) \
                                 AND (a.cursor_generation IS NULL \
                                      OR (a.cursor_generation, a.cursor_seq) \
                                         < (s.generation, s.version))) \
                 ORDER BY s.generation, s.version, s.key LIMIT $4)",
        )
        .bind(&id)
        .bind(app_ids(current))
        .bind(app_ids(lagging))
        .bind(to_db(bound, "bound")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?
        .rows_affected();
        Ok(forgotten)
    }

    /// Whether the once-a-minute sweep is due at service time `now_ms` (Switch wire 9.1): a
    /// minute of service time since the last, or none yet. When it is, the time is noted
    /// in this transaction, so the sweep runs once in the minute whatever the instance.
    pub async fn minute_sweep_due(&mut self, now_ms: u64) -> Result<bool, StoreError> {
        let id = self.head().id.clone();
        let due = sqlx::query(
            "UPDATE accounts SET swept_at_ms = $2 WHERE id = $1 \
             AND (swept_at_ms IS NULL OR swept_at_ms <= $2 - 60000)",
        )
        .bind(&id)
        .bind(to_db(now_ms, "time")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?
        .rows_affected();
        Ok(due > 0)
    }

    /// Drop the transition proofs of at most `bound` batches past `proofs_ms` at service
    /// time `now_ms`, the oldest first (Switch wire 6.4 step 5, 9.1): their ID and operation
    /// hash stay, so a retry is still answered `409 conflict`. The number dropped.
    pub async fn drop_expired_batch_proofs(
        &mut self,
        now_ms: u64,
        proofs_ms: u64,
        bound: u64,
    ) -> Result<u64, StoreError> {
        let Some(before) = now_ms.checked_sub(proofs_ms) else {
            return Ok(0);
        };
        let id = self.head().id.clone();
        let dropped = sqlx::query(
            "UPDATE batches SET proofs = NULL WHERE account_id = $1 AND batch_id IN ( \
                 SELECT batch_id FROM batches WHERE account_id = $1 \
                 AND proofs IS NOT NULL AND at_ms <= $2 \
                 ORDER BY at_ms, batch_id LIMIT $3)",
        )
        .bind(&id)
        .bind(to_db(before, "time")?)
        .bind(to_db(bound, "bound")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?
        .rows_affected();
        Ok(dropped)
    }

    /// Delete at most `bound` invite codes that expired at service time `now_ms` or ran out
    /// (Switch wire 9.1); an entry a code admitted keeps its hash. The number deleted.
    pub async fn drop_spent_invite_codes(
        &mut self,
        now_ms: u64,
        bound: u64,
    ) -> Result<u64, StoreError> {
        let id = self.head().id.clone();
        let dropped = sqlx::query(
            "DELETE FROM invite_codes WHERE account_id = $1 AND code_hash IN ( \
                 SELECT code_hash FROM invite_codes WHERE account_id = $1 \
                 AND (expires_at_ms <= $2 OR uses >= max_uses) \
                 ORDER BY expires_at_ms, code_hash LIMIT $3)",
        )
        .bind(&id)
        .bind(to_db(now_ms, "time")?)
        .bind(to_db(bound, "bound")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?
        .rows_affected();
        Ok(dropped)
    }
}
