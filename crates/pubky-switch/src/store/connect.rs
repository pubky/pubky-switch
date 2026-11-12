//! Pending connect requests (Switch spec 7, Switch wire 7.4.7), under the account's lock.
//!
//! A request holds only the sender's Pubky ID and when it asked. A list entry written for
//! the sender, a contact, a conversation entry or a deny list entry, answers it, in the
//! same transaction (`AccountTxn::put_list_entry` and the conversation entry an invite
//! code's first append writes).

use sqlx::Row;

use super::{AccountTxn, StoreError, from_db, to_db};

/// A pending connect request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectRequest {
    /// The sender identity's Pubky ID.
    pub pubky: [u8; 32],
    /// The service time it asked at.
    pub at_ms: u64,
}

impl AccountTxn {
    /// Whether `pubky` has a pending request.
    pub async fn connect_pending(&mut self, pubky: &[u8; 32]) -> Result<bool, StoreError> {
        let id = self.head().id.clone();
        let row =
            sqlx::query("SELECT 1 FROM connect_requests WHERE account_id = $1 AND pubky = $2")
                .bind(id)
                .bind(pubky.as_slice())
                .fetch_optional(self.conn())
                .await
                .map_err(StoreError::from_db)?;
        Ok(row.is_some())
    }

    /// How many requests are pending.
    pub async fn connect_count(&mut self) -> Result<u64, StoreError> {
        let id = self.head().id.clone();
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM connect_requests WHERE account_id = $1")
                .bind(id)
                .fetch_one(self.conn())
                .await
                .map_err(StoreError::from_db)?;
        from_db(count, "connect requests")
    }

    /// Keep a request from `pubky` at `at_ms`; one already pending keeps its time.
    pub async fn put_connect(&mut self, pubky: &[u8; 32], at_ms: u64) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO connect_requests (account_id, pubky, at_ms) VALUES ($1, $2, $3) \
             ON CONFLICT (account_id, pubky) DO NOTHING",
        )
        .bind(id)
        .bind(pubky.as_slice())
        .bind(to_db(at_ms, "at_ms")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// The pending requests, oldest first.
    pub async fn connect_requests(&mut self) -> Result<Vec<ConnectRequest>, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(
            "SELECT pubky, at_ms FROM connect_requests WHERE account_id = $1 \
             ORDER BY at_ms, pubky",
        )
        .bind(id)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        rows.iter()
            .map(|row| {
                let pubky: Vec<u8> = row.try_get("pubky")?;
                let at: i64 = row.try_get("at_ms")?;
                Ok(ConnectRequest {
                    pubky: <[u8; 32]>::try_from(pubky.as_slice())
                        .map_err(|_| StoreError::Corrupt("a connect request's pubky"))?,
                    at_ms: from_db(at, "at_ms")?,
                })
            })
            .collect()
    }

    /// Remove `pubky`'s request; whether one was pending.
    pub async fn delete_connect(&mut self, pubky: &[u8; 32]) -> Result<bool, StoreError> {
        let id = self.head().id.clone();
        let deleted =
            sqlx::query("DELETE FROM connect_requests WHERE account_id = $1 AND pubky = $2")
                .bind(id)
                .bind(pubky.as_slice())
                .execute(self.conn())
                .await
                .map_err(StoreError::from_db)?
                .rows_affected();
        Ok(deleted > 0)
    }
}
