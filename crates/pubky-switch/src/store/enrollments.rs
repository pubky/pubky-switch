//! The enrollments an account answered (Switch wire 3.7): the same enrollment again gets the
//! same answer, which names the key it named the first time.

use super::{AccountTxn, StoreError, identity::time_to_db, to_db};
use crate::keys::KeyId;

impl AccountTxn {
    /// The key the account answered the enrollment with document hash `hash` with, if it
    /// keeps that answer.
    pub async fn enrollment_answer(
        &mut self,
        hash: &[u8; 32],
    ) -> Result<Option<KeyId>, StoreError> {
        let id = self.head().id.clone();
        let key: Option<String> = sqlx::query_scalar(
            "SELECT service_key FROM enrollment_answers \
             WHERE account_id = $1 AND enrollment_hash = $2",
        )
        .bind(id)
        .bind(hash.as_slice())
        .fetch_optional(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        key.map(|key| KeyId::parse(&key).map_err(|_| StoreError::Corrupt("enrollment answer key")))
            .transpose()
    }

    /// Keep that the enrollment with document hash `hash` was answered with `key` at
    /// `at_ms`. With `rebuildable`, the service would build the answer again byte for byte
    /// (it names the pending key), and the oldest such answers beyond `max` drop; every
    /// other answer is kept as long as the account (Switch wire 3.7, 9.1).
    pub async fn keep_enrollment_answer(
        &mut self,
        hash: &[u8; 32],
        key: &KeyId,
        at_ms: u64,
        max: u64,
        rebuildable: bool,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        keep(self.conn(), &id, hash, key, at_ms, max, false, rebuildable).await
    }

    /// How many answers the account keeps for good: the creating enrollment's and those
    /// given while it was staged.
    pub async fn kept_enrollment_answers(&mut self) -> Result<u64, StoreError> {
        let id = self.head().id.clone();
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM enrollment_answers WHERE account_id = $1 AND NOT rebuildable",
        )
        .bind(id)
        .fetch_one(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        super::from_db(count, "enrollment answers")
    }
}

/// Keep an enrollment answer on `conn`, for account `id`; `creating` for the enrollment
/// that creates the account. Only `rebuildable` answers drop, the oldest first, beyond `max`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn keep(
    conn: &mut sqlx::PgConnection,
    id: &str,
    hash: &[u8; 32],
    key: &KeyId,
    at_ms: u64,
    max: u64,
    creating: bool,
    rebuildable: bool,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO enrollment_answers (account_id, enrollment_hash, service_key, \
         answered_at_ms, creating, rebuildable) VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(hash.as_slice())
    .bind(key.as_str())
    .bind(time_to_db(at_ms)?)
    .bind(creating)
    .bind(rebuildable)
    .execute(&mut *conn)
    .await
    .map_err(StoreError::from_db)?;
    sqlx::query(
        "DELETE FROM enrollment_answers WHERE account_id = $1 AND enrollment_hash IN ( \
         SELECT enrollment_hash FROM enrollment_answers WHERE account_id = $1 \
         AND rebuildable ORDER BY kept_order DESC OFFSET $2)",
    )
    .bind(id)
    .bind(to_db(max, "max_enrollments")?)
    .execute(&mut *conn)
    .await
    .map_err(StoreError::from_db)?;
    Ok(())
}
