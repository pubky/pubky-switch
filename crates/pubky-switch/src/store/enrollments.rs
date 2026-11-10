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
    /// `at_ms`, dropping the oldest answers beyond `max` (Switch wire 9.1).
    pub async fn keep_enrollment_answer(
        &mut self,
        hash: &[u8; 32],
        key: &KeyId,
        at_ms: u64,
        max: u64,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        keep(self.conn(), &id, hash, key, at_ms, max).await
    }
}

/// Keep an enrollment answer on `conn`, for account `id`.
pub(super) async fn keep(
    conn: &mut sqlx::PgConnection,
    id: &str,
    hash: &[u8; 32],
    key: &KeyId,
    at_ms: u64,
    max: u64,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO enrollment_answers (account_id, enrollment_hash, service_key, \
         answered_at_ms) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(hash.as_slice())
    .bind(key.as_str())
    .bind(time_to_db(at_ms)?)
    .execute(&mut *conn)
    .await
    .map_err(StoreError::from_db)?;
    sqlx::query(
        "DELETE FROM enrollment_answers WHERE account_id = $1 AND enrollment_hash IN ( \
         SELECT enrollment_hash FROM enrollment_answers WHERE account_id = $1 \
         ORDER BY answered_at_ms DESC, enrollment_hash OFFSET $2)",
    )
    .bind(id)
    .bind(to_db(max, "max_enrollments")?)
    .execute(&mut *conn)
    .await
    .map_err(StoreError::from_db)?;
    Ok(())
}
