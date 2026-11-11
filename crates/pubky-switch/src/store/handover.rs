//! The signer hand-over the switch holds for an account (Switch wire 7.4.17): one at most,
//! kept as the signer's `PUT` body so `GET` answers it byte for byte.
//!
//! The hand-over is sealed to the target app's bundle key; the service never opens it. It
//! holds the identity secret, so a copy must not outlive its purpose: it goes at the next
//! `identity.json` version the account takes, and with the account.

use sqlx::Row;

use super::{AccountTxn, StoreError};

/// The hand-over as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredHandover {
    /// The App ID of the app it is for.
    pub target: [u8; 16],
    /// The `PUT` body, as received.
    pub body: Vec<u8>,
}

impl AccountTxn {
    /// Keep `body`, the hand-over for `target`, replacing any the account holds (Switch wire
    /// 7.4.17).
    pub async fn put_handover(&mut self, target: &[u8; 16], body: &[u8]) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO handovers (account_id, target_app_id, body) VALUES ($1, $2, $3) \
             ON CONFLICT (account_id) DO UPDATE \
             SET target_app_id = EXCLUDED.target_app_id, body = EXCLUDED.body",
        )
        .bind(id)
        .bind(target.as_slice())
        .bind(body)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// The hand-over the account holds, if any.
    pub async fn handover(&mut self) -> Result<Option<StoredHandover>, StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query("SELECT target_app_id, body FROM handovers WHERE account_id = $1")
            .bind(id)
            .fetch_optional(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let target: Vec<u8> = row.try_get("target_app_id").map_err(StoreError::from_db)?;
        let target = <[u8; 16]>::try_from(target.as_slice())
            .map_err(|_| StoreError::Corrupt("a hand-over's target App ID"))?;
        Ok(Some(StoredHandover {
            target,
            body: row.try_get("body").map_err(StoreError::from_db)?,
        }))
    }

    /// Delete the hand-over the account holds, if any (Switch wire 7.4.17 Deletion).
    pub async fn delete_handover(&mut self) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query("DELETE FROM handovers WHERE account_id = $1")
            .bind(id)
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        Ok(())
    }
}
