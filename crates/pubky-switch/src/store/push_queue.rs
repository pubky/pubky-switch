//! The push delivery queue (Switch spec 9 step 4, Switch wire 8.2): one row per webhook owed,
//! queued with its `notify` entry and sent by a background worker (`service::webhooks`).
//!
//! - **Queued** in the append's transaction, one row per handle of each target app's
//!   registration ([`AccountTxn::queue_pushes`]), so a row exists only if its entry commits,
//!   and nothing is sent during the append.
//! - **Claimed** by one instance at a time ([`Store::claim_pushes`]): `FOR UPDATE SKIP
//!   LOCKED`, then a lease, `next_attempt_ms` moved to when a retry would be due, committed
//!   before anything is sent. An attempt ends within its 5 s timeout, well inside the lease,
//!   so no two instances send one row at once; an instance that dies mid-attempt leaves the
//!   row to be retried when the lease ends.
//! - **Signed under its registration's lock** ([`Store::hold_push_registration`]): the
//!   registration must still name the row's push key and handle, and the key must not be
//!   owed deleting. The row is held `FOR SHARE` while the webhook is signed, so a removal or a
//!   replacement, which owes the key's deletion, waits for the signature; the key store
//!   deletes the key only after that commits. So no key a sweep may be deleting ever signs.
//! - **Gone** once delivered, after its last attempt (3, within 1 minute of its entry), when
//!   its registration goes (the foreign key's cascade: a removal, a recovery in place, an
//!   erasure), at a replacement, and when its handle leaves the list (`store::push`).
//!
//! A row holds the handle, which it must, and nothing of the message. Its `Debug` shows no
//! handle.

use sqlx::{Postgres, Row, Transaction};

use super::{AccountTxn, Store, StoreError, from_db, to_db};
use crate::keys::KeyId;

/// A delivery claimed for one attempt.
#[derive(Clone, PartialEq, Eq)]
pub struct QueuedPush {
    /// The row.
    pub id: i64,
    /// The account's Pubky ID.
    pub account: String,
    /// The App ID of the registration.
    pub app_id: [u8; 16],
    /// The push key the registration held when the row was queued.
    pub push_key: KeyId,
    /// The handle.
    pub handle: String,
    /// The entry's service time.
    pub entry_at_ms: u64,
    /// The attempts made, this one included.
    pub attempts: u32,
}

impl std::fmt::Debug for QueuedPush {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedPush")
            .field("id", &self.id)
            .field("attempts", &self.attempts)
            .finish_non_exhaustive()
    }
}

/// A registration held `FOR SHARE` while its webhook is signed: dropping this releases it.
pub struct HeldRegistration {
    _tx: Transaction<'static, Postgres>,
    /// The relay URL.
    pub relay_url: String,
}

impl std::fmt::Debug for HeldRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldRegistration").finish_non_exhaustive()
    }
}

fn queued_push(row: &sqlx::postgres::PgRow) -> Result<QueuedPush, StoreError> {
    let app_id: Vec<u8> = row.try_get("app_id")?;
    let push_key: String = row.try_get("push_key_id")?;
    let attempts: i32 = row.try_get("attempts")?;
    Ok(QueuedPush {
        id: row.try_get("id")?,
        account: row.try_get("account_id")?,
        app_id: <[u8; 16]>::try_from(app_id.as_slice())
            .map_err(|_| StoreError::Corrupt("push_deliveries.app_id"))?,
        push_key: KeyId::parse(&push_key)
            .map_err(|_| StoreError::Corrupt("push_deliveries.push_key_id"))?,
        handle: row.try_get("handle")?,
        entry_at_ms: from_db(row.try_get("entry_at_ms")?, "entry_at_ms")?,
        attempts: u32::try_from(attempts)
            .map_err(|_| StoreError::Corrupt("push_deliveries.attempts"))?,
    })
}

impl Store {
    /// Delete the deliveries that can't be attempted any more at `now_ms`: past their
    /// minute or their last attempt, and not leased. Returns how many went.
    pub async fn drop_stale_pushes(&self, now_ms: u64, window_ms: u64) -> Result<u64, StoreError> {
        let now = to_db(now_ms, "now_ms")?;
        let window = to_db(window_ms, "window_ms")?;
        Ok(sqlx::query(
            "DELETE FROM push_deliveries WHERE next_attempt_ms <= $1 \
             AND (attempts >= 3 OR entry_at_ms + $2 <= $1)",
        )
        .bind(now)
        .bind(window)
        .execute(self.pool())
        .await
        .map_err(StoreError::from_db)?
        .rows_affected())
    }

    /// Claim at most `limit` deliveries due at `now_ms`, leased until `lease_until_ms`, each
    /// with its attempt counted: within `window_ms` of its entry, under 3 attempts, and not
    /// claimed by another instance. The claim commits before anything is sent.
    pub async fn claim_pushes(
        &self,
        now_ms: u64,
        window_ms: u64,
        lease_until_ms: u64,
        limit: usize,
    ) -> Result<Vec<QueuedPush>, StoreError> {
        let rows = sqlx::query(
            "UPDATE push_deliveries SET attempts = attempts + 1, next_attempt_ms = $3 \
             WHERE id IN (SELECT id FROM push_deliveries WHERE next_attempt_ms <= $1 \
             AND attempts < 3 AND entry_at_ms + $2 > $1 ORDER BY next_attempt_ms LIMIT $4 \
             FOR UPDATE SKIP LOCKED) \
             RETURNING id, account_id, app_id, push_key_id, handle, entry_at_ms, attempts",
        )
        .bind(to_db(now_ms, "now_ms")?)
        .bind(to_db(window_ms, "window_ms")?)
        .bind(to_db(lease_until_ms, "lease_until_ms")?)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(self.pool())
        .await
        .map_err(StoreError::from_db)?;
        // A row that doesn't read is skipped, its lease left to run out, and goes once its
        // attempts or its minute are spent ([`Store::drop_stale_pushes`]): it holds up no
        // other.
        Ok(rows
            .iter()
            .filter_map(|row| {
                queued_push(row)
                    .inspect_err(|error| tracing::warn!(%error, "push deliveries: a row"))
                    .ok()
            })
            .collect())
    }

    /// `push`'s registration, held `FOR SHARE` until the result is dropped, if it still names
    /// the row's push key and handle and the key isn't owed deleting; `None` otherwise, when
    /// the delivery isn't sent. Waits at most `lock_timeout_ms` for a request that holds it.
    pub async fn hold_push_registration(
        &self,
        push: &QueuedPush,
    ) -> Result<Option<HeldRegistration>, StoreError> {
        let mut tx = self.pool().begin().await.map_err(StoreError::from_db)?;
        sqlx::query(&format!(
            "SET LOCAL lock_timeout = {}",
            self.lock_timeout_ms
        ))
        .execute(&mut *tx)
        .await
        .map_err(StoreError::from_db)?;
        let relay_url: Option<String> = sqlx::query_scalar(
            "SELECT r.relay_url FROM push_registrations r WHERE r.account_id = $1 \
             AND r.app_id = $2 AND r.push_key_id = $3 AND $4 = ANY(r.handles) \
             AND NOT EXISTS (SELECT 1 FROM erased_keys e WHERE e.key_id = r.push_key_id) \
             FOR SHARE OF r",
        )
        .bind(&push.account)
        .bind(push.app_id.as_slice())
        .bind(push.push_key.as_str())
        .bind(&push.handle)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::from_db)?;
        Ok(relay_url.map(|relay_url| HeldRegistration { _tx: tx, relay_url }))
    }

    /// The delivery `id` is done: delivered, failed for the last time, or not to be sent.
    pub async fn finish_push(&self, id: i64) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM push_deliveries WHERE id = $1")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// The delivery `id` failed, and is retried at `at_ms`.
    pub async fn retry_push(&self, id: i64, at_ms: u64) -> Result<(), StoreError> {
        sqlx::query("UPDATE push_deliveries SET next_attempt_ms = $2 WHERE id = $1")
            .bind(id)
            .bind(to_db(at_ms, "next_attempt_ms")?)
            .execute(self.pool())
            .await
            .map_err(StoreError::from_db)?;
        Ok(())
    }
}

impl AccountTxn {
    /// Queue a webhook to each handle of the registration of each of `targets`, an entry's
    /// target apps, for the `notify` entry accepted at `entry_at_ms` (Switch wire 8.2).
    /// Returns how many were queued.
    pub async fn queue_pushes(
        &mut self,
        targets: &[[u8; 16]],
        entry_at_ms: u64,
    ) -> Result<u64, StoreError> {
        let id = self.head().id.clone();
        let targets: Vec<Vec<u8>> = targets.iter().map(|app| app.to_vec()).collect();
        let at = to_db(entry_at_ms, "entry_at_ms")?;
        Ok(sqlx::query(
            "INSERT INTO push_deliveries (account_id, app_id, push_key_id, handle, entry_at_ms, \
             next_attempt_ms) SELECT DISTINCT r.account_id, r.app_id, r.push_key_id, h, $3, $3 \
             FROM push_registrations r CROSS JOIN LATERAL unnest(r.handles) AS h \
             WHERE r.account_id = $1 AND r.app_id = ANY($2)",
        )
        .bind(&id)
        .bind(&targets)
        .bind(at)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?
        .rows_affected())
    }

    /// Drop the queued deliveries of `app` whose handle `keep` doesn't hold, all of them when
    /// `keep` is empty: at a replacement and at a new list of handles.
    pub(super) async fn drop_pushes_except(
        &mut self,
        app: &[u8; 16],
        keep: &[String],
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "DELETE FROM push_deliveries WHERE account_id = $1 AND app_id = $2 \
             AND NOT (handle = ANY($3))",
        )
        .bind(id)
        .bind(app.as_slice())
        .bind(keep)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(())
    }
}
