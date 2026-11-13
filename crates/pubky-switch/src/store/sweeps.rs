//! The sweeps of an account's state at a request (Switch wire 9.1, Switch spec 10.3), under
//! its lock, in the request's transaction. Each takes at most the bound it is given and
//! decides by the service time the caller passes, never a client's: a run cut short leaves
//! only rows a later run takes, so a sweep may stop or restart at any point.

use pubky_switch_core::ops::Position;
use sqlx::Row;

use super::{AccountTxn, StoreError, from_db, to_db};

fn app_ids(apps: &[[u8; 16]]) -> Vec<Vec<u8>> {
    apps.iter().map(|app| app.to_vec()).collect()
}

impl AccountTxn {
    /// Whether a deleted key written here is held at all: one lookup in
    /// `shared_records_deleted`, so an account with none pays nothing more
    /// ([`Self::forget_deleted_keys`]).
    pub async fn deleted_key_held(&mut self) -> Result<bool, StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query(
            "SELECT 1 FROM shared_records WHERE account_id = $1 AND deleted \
             AND NOT from_upload LIMIT 1",
        )
        .bind(id)
        .fetch_optional(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(row.is_some())
    }

    /// The cursors of `apps` that have a row here, by App ID: `None` for one with no cursor
    /// yet. An app with no row has none either; the caller holds every key for it.
    pub async fn waited_cursors(
        &mut self,
        apps: &[[u8; 16]],
    ) -> Result<Vec<([u8; 16], Option<Position>)>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(
            "SELECT app_id, cursor_generation, cursor_seq FROM apps \
             WHERE account_id = $1 AND app_id = ANY($2)",
        )
        .bind(&id)
        .bind(app_ids(apps))
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        let mut cursors = Vec::with_capacity(rows.len());
        for row in &rows {
            let app: Vec<u8> = row.try_get("app_id")?;
            let app =
                <[u8; 16]>::try_from(app.as_slice()).map_err(|_| StoreError::Corrupt("app_id"))?;
            let generation: Option<i64> = row.try_get("cursor_generation")?;
            let seq: Option<i64> = row.try_get("cursor_seq")?;
            let cursor = match (generation, seq) {
                (Some(generation), Some(seq)) => Some(Position {
                    generation: from_db(generation, "cursor_generation")?,
                    seq: from_db(seq, "cursor_seq")?,
                }),
                _ => None,
            };
            cursors.push((app, cursor));
        }
        Ok(cursors)
    }

    /// Forget at most `bound` deleted keys that nothing refers to (Switch spec 10.3, wire
    /// 9.1), the oldest deletes first: the record's current write is its delete, written at
    /// this service (one taken from a recovery upload has no chain item here to stand for
    /// it), at or before `through`, the lowest cursor the key waits for; and no divergent
    /// upload names the key. The record's row goes, so its delete shows as its chain stub and a
    /// create at the key starts afresh. A range scan of `shared_records_deleted` up to
    /// `through`. The number forgotten.
    pub async fn forget_deleted_keys(
        &mut self,
        through: Option<Position>,
        bound: u64,
    ) -> Result<u64, StoreError> {
        let id = self.head().id.clone();
        let (generation, seq) = match through {
            Some(at) => (to_db(at.generation, "generation")?, to_db(at.seq, "seq")?),
            None => (i64::MAX, i64::MAX),
        };
        let forgotten: Vec<(i64, i64)> = sqlx::query_as(
            "DELETE FROM shared_records r WHERE r.account_id = $1 AND r.key IN ( \
                 SELECT s.key FROM shared_records s \
                 WHERE s.account_id = $1 AND s.deleted AND NOT s.from_upload \
                 AND (s.generation, s.version) <= ($2, $3) \
                 AND NOT EXISTS (SELECT 1 FROM divergent_uploads d \
                                 WHERE d.account_id = s.account_id AND d.key = s.key) \
                 ORDER BY s.generation, s.version LIMIT $4) \
             RETURNING r.generation, r.version",
        )
        .bind(&id)
        .bind(generation)
        .bind(seq)
        .bind(to_db(bound, "bound")?)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        // A forgotten delete's item is no record's current write any more, so it shows as its
        // stub to every app and its document goes before the commit (Switch wire 7.5), as a
        // write that replaces a record's current write notes it. One of an earlier generation
        // has no item in the chain served.
        let served = self.head().generation;
        let mut stale = Vec::with_capacity(forgotten.len());
        for (generation, version) in &forgotten {
            if from_db(*generation, "generation")? == served {
                stale.push(from_db(*version, "version")?);
            }
        }
        self.note_superseded(stale);
        Ok(u64::try_from(forgotten.len()).unwrap_or(u64::MAX))
    }

    /// Whether the once-a-minute sweep is due at service time `now_ms` (Switch wire 9.1): a
    /// minute of service time since the last, or none yet. When it is, the time is noted
    /// in this transaction, so the sweep runs once in the minute whatever the instance. A
    /// mark ahead of `now_ms`, left by a time base that has since stepped back, is due too,
    /// so the sweeps never wait for the clock to catch up with it.
    pub async fn minute_sweep_due(&mut self, now_ms: u64) -> Result<bool, StoreError> {
        let id = self.head().id.clone();
        let due = sqlx::query(
            "UPDATE accounts SET swept_at_ms = $2 WHERE id = $1 \
             AND (swept_at_ms IS NULL OR swept_at_ms <= $2 - 60000 OR swept_at_ms > $2)",
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
    ///
    /// Not yet: wire 9.1 deletes the whole record once its proofs are gone and none of the
    /// batch's chain stubs is kept. No stub is dropped yet, so no record goes; the delete
    /// comes with chain stub retention.
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
