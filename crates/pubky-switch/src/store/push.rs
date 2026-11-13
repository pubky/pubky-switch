//! Push registrations (Switch spec 9, Switch wire 8.1), one per own app, and the push keys
//! owed deleting.
//!
//! A registration names its push key by key store ID; the secret half stays in the key store
//! (`crate::keys`). Every push key the database lets go is owed deleting first, in
//! `erased_keys` with the reason `push`, in the transaction that lets it go, and the key store
//! deletes it after the commit ([`Store::lock_owed_key`]):
//!
//! - **A minted key** is owed before it exists ([`Store::owe_push_key`]), and the start that
//!   names it in a committed registration takes the debt back in the same transaction
//!   ([`AccountTxn::put_push_registration`]). So a start that fails, or a crash at any point,
//!   leaves the key owed, never orphaned.
//! - **A replaced or removed key** is owed in the transaction that replaces or removes its
//!   registration: a start that replaces it, the app no longer current, a recovery in place,
//!   an erasure. Until that commits the key stays, so no committed registration ever names a
//!   deleted key.
//!
//! An owed row is locked while its key is minted or deleted, so a sweep never deletes the key
//! of a start that is about to claim it, and a start never claims a key a sweep deleted.

use std::collections::HashSet;

use pubky_switch_core::net::{UrlUse, check_url};
use sqlx::{Postgres, Row, Transaction};

use super::{AccountTxn, Store, StoreError, from_db, to_db};
use crate::keys::KeyId;

/// An own app's push registration (Switch wire 8.1). Its `Debug` shows neither the relay
/// URL nor a handle.
#[derive(Clone, PartialEq, Eq)]
pub struct PushRegistration {
    /// The App ID.
    pub app_id: [u8; 16],
    /// The relay URL.
    pub relay_url: String,
    /// The push key's ID in the key store.
    pub push_key: KeyId,
    /// The push key's public half.
    pub push_public: [u8; 32],
    /// The handles, at most 8.
    pub handles: Vec<String>,
    /// When the registration or its handles were last set, in service time.
    pub set_at_ms: u64,
}

impl std::fmt::Debug for PushRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushRegistration")
            .field("handles", &self.handles.len())
            .field("set_at_ms", &self.set_at_ms)
            .finish_non_exhaustive()
    }
}

/// An owed key's row, locked until its key store work is done: [`OwedKey::forget`] drops the
/// row once the key is deleted; dropping this releases the lock and keeps the row.
pub struct OwedKey {
    tx: Transaction<'static, Postgres>,
    key: KeyId,
}

impl std::fmt::Debug for OwedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwedKey").field("key", &self.key).finish()
    }
}

impl OwedKey {
    /// The key is deleted: the row goes, and the lock with it.
    pub async fn forget(mut self) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM erased_keys WHERE key_id = $1")
            .bind(self.key.as_str())
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
        self.tx.commit().await.map_err(StoreError::from_db)
    }
}

/// Owe deleting `key`, a push key of `account`, at `at_ms`.
async fn owe(
    conn: &mut sqlx::PgConnection,
    account: &str,
    key: &KeyId,
    at_ms: u64,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO erased_keys (key_id, account_id, erased_at_ms, reason) \
         VALUES ($1, $2, $3, 'push') ON CONFLICT (key_id) DO NOTHING",
    )
    .bind(key.as_str())
    .bind(account)
    .bind(to_db(at_ms, "erased_at_ms")?)
    .execute(conn)
    .await
    .map_err(StoreError::from_db)?;
    Ok(())
}

fn registration_of(row: &sqlx::postgres::PgRow) -> Result<PushRegistration, StoreError> {
    let app_id: Vec<u8> = row.try_get("app_id")?;
    let push_key: String = row.try_get("push_key_id")?;
    let push_public: Vec<u8> = row.try_get("push_public")?;
    Ok(PushRegistration {
        app_id: <[u8; 16]>::try_from(app_id.as_slice())
            .map_err(|_| StoreError::Corrupt("push_registrations.app_id"))?,
        relay_url: row.try_get("relay_url")?,
        push_key: KeyId::parse(&push_key)
            .map_err(|_| StoreError::Corrupt("push_registrations.push_key_id"))?,
        push_public: <[u8; 32]>::try_from(push_public.as_slice())
            .map_err(|_| StoreError::Corrupt("push_registrations.push_public"))?,
        handles: row.try_get("handles")?,
        set_at_ms: from_db(row.try_get("set_at_ms")?, "set_at_ms")?,
    })
}

impl Store {
    /// The public half of the push key of `app`'s registration at `account`, read without
    /// the account's lock, for a start to judge whether it will need a new key before it
    /// takes the lock. The endpoint judges again under it.
    pub async fn push_key_of(
        &self,
        account: &str,
        app: &[u8; 16],
    ) -> Result<Option<[u8; 32]>, StoreError> {
        let key: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT push_public FROM push_registrations WHERE account_id = $1 AND app_id = $2",
        )
        .bind(account)
        .bind(app.as_slice())
        .fetch_optional(self.pool())
        .await
        .map_err(StoreError::from_db)?;
        key.map(|key| {
            <[u8; 32]>::try_from(key.as_slice())
                .map_err(|_| StoreError::Corrupt("push_registrations.push_public"))
        })
        .transpose()
    }

    /// Owe deleting `key`, a push key about to be minted for `account` at `at_ms`, durably,
    /// before it exists.
    pub async fn owe_push_key(
        &self,
        account: &str,
        key: &KeyId,
        at_ms: u64,
    ) -> Result<(), StoreError> {
        let mut conn = self.pool().acquire().await.map_err(StoreError::from_db)?;
        owe(&mut conn, account, key, at_ms).await
    }

    /// Lock `key`'s owed row, waiting at most `lock_timeout_ms` for a start or a sweep that
    /// holds it; `None` when no row owes it any more: claimed by a committed registration, or
    /// deleted by a sweep.
    pub async fn lock_owed_key(&self, key: &KeyId) -> Result<Option<OwedKey>, StoreError> {
        let mut tx = self.pool().begin().await.map_err(StoreError::from_db)?;
        sqlx::query(&format!(
            "SET LOCAL lock_timeout = {}",
            self.lock_timeout_ms
        ))
        .execute(&mut *tx)
        .await
        .map_err(StoreError::from_db)?;
        let found = sqlx::query("SELECT 1 FROM erased_keys WHERE key_id = $1 FOR UPDATE")
            .bind(key.as_str())
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::from_db)?;
        Ok(found.map(|_| OwedKey {
            tx,
            key: key.clone(),
        }))
    }
}

impl AccountTxn {
    /// `app`'s push registration, if it holds one.
    pub async fn push_registration(
        &mut self,
        app: &[u8; 16],
    ) -> Result<Option<PushRegistration>, StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query(
            "SELECT app_id, relay_url, push_key_id, push_public, handles, set_at_ms \
             FROM push_registrations WHERE account_id = $1 AND app_id = $2",
        )
        .bind(id)
        .bind(app.as_slice())
        .fetch_optional(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        row.as_ref().map(registration_of).transpose()
    }

    /// Take `registration` as its app's, with a push key minted for it: the key's debt is
    /// taken back, and the key of the registration it replaces, `replaced`, owed instead.
    ///
    /// # Errors
    ///
    /// [`StoreError::Raced`] when the minted key is no longer owed, so a sweep may have
    /// deleted it: nothing is taken.
    pub async fn put_push_registration(
        &mut self,
        registration: &PushRegistration,
        replaced: Option<&KeyId>,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        // Waits for a sweep that holds the row; one that deleted the key deleted the row.
        let claimed = sqlx::query("DELETE FROM erased_keys WHERE key_id = $1 AND reason = 'push'")
            .bind(registration.push_key.as_str())
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?
            .rows_affected();
        if claimed != 1 {
            return Err(StoreError::Raced("the minted push key is no longer owed"));
        }
        if let Some(old) = replaced {
            self.owe_push(old, registration.set_at_ms).await?;
        }
        sqlx::query(
            "INSERT INTO push_registrations (account_id, app_id, relay_url, push_key_id, \
             push_public, handles, set_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (account_id, app_id) DO UPDATE SET relay_url = $3, push_key_id = $4, \
             push_public = $5, handles = $6, set_at_ms = $7",
        )
        .bind(&id)
        .bind(registration.app_id.as_slice())
        .bind(&registration.relay_url)
        .bind(registration.push_key.as_str())
        .bind(registration.push_public.as_slice())
        .bind(&registration.handles)
        .bind(to_db(registration.set_at_ms, "set_at_ms")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        // The deliveries queued under the registration it replaces go with it (Switch wire
        // 8.2): none is sent with the new key, which has no handles yet.
        self.drop_pushes_except(&registration.app_id, &registration.handles)
            .await
    }

    /// How many handles the account's registrations other than `app`'s hold at the relay
    /// `host`, the host as `check_url` spells it: what an entry's webhooks toward that host
    /// count against [`super::PUSH_PER_HOST`] (`store::push_queue`).
    pub async fn push_handles_at_host(
        &mut self,
        host: &str,
        app: &[u8; 16],
    ) -> Result<usize, StoreError> {
        let id = self.head().id.clone();
        let rows = sqlx::query(
            "SELECT relay_url, handles FROM push_registrations \
             WHERE account_id = $1 AND app_id <> $2",
        )
        .bind(id)
        .bind(app.as_slice())
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        let mut held = 0;
        for row in &rows {
            let relay_url: String = row.try_get("relay_url")?;
            let at_host = check_url(&relay_url, &UrlUse::Relay).is_ok_and(|url| url.host == host);
            if at_host {
                let handles: Vec<String> = row.try_get("handles")?;
                held += handles.iter().collect::<HashSet<_>>().len();
            }
        }
        Ok(held)
    }

    /// Replace the handles of `app`'s registration, at `at_ms`; the deliveries queued for a
    /// handle the list no longer holds go.
    pub async fn set_push_handles(
        &mut self,
        app: &[u8; 16],
        handles: &[String],
        at_ms: u64,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "UPDATE push_registrations SET handles = $3, set_at_ms = $4 \
             WHERE account_id = $1 AND app_id = $2",
        )
        .bind(id)
        .bind(app.as_slice())
        .bind(handles)
        .bind(to_db(at_ms, "set_at_ms")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        self.drop_pushes_except(app, handles).await
    }

    /// Remove the push registrations of every app but those of `keep`, every one when
    /// `None`, owing their keys' deletion (Switch wire 8.1: the setting goes when the app
    /// stops being current), and their queued deliveries with them. Returns how many went.
    pub async fn drop_push_registrations(
        &mut self,
        keep: Option<&[[u8; 16]]>,
    ) -> Result<usize, StoreError> {
        let id = self.head().id.clone();
        let at_ms = self.head().stamped_time_ms;
        let keep: Vec<Vec<u8>> = keep
            .unwrap_or_default()
            .iter()
            .map(|app| app.to_vec())
            .collect();
        let gone: Vec<String> = sqlx::query_scalar(
            "DELETE FROM push_registrations WHERE account_id = $1 AND NOT (app_id = ANY($2)) \
             RETURNING push_key_id",
        )
        .bind(&id)
        .bind(&keep)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        for key in &gone {
            let key = KeyId::parse(key)
                .map_err(|_| StoreError::Corrupt("push_registrations.push_key_id"))?;
            self.owe_push(&key, at_ms).await?;
        }
        Ok(gone.len())
    }

    /// Owe deleting `key`, a push key this request lets go; the service deletes it once the
    /// request commits ([`AccountTxn::owed_keys`]).
    async fn owe_push(&mut self, key: &KeyId, at_ms: u64) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        owe(self.conn(), &id, key, at_ms).await?;
        self.owed.push(key.clone());
        Ok(())
    }

    /// The push keys this request owes deleting, for the service to delete once it commits.
    pub fn owed_keys(&self) -> &[KeyId] {
        &self.owed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_registration_debug_shows_no_relay_or_handle() {
        let registration = PushRegistration {
            app_id: [1; 16],
            relay_url: "https://push.example/v1/hook".into(),
            push_key: KeyId::random().expect("key id"),
            push_public: [2; 32],
            handles: vec!["handle-Kt8fSp".into()],
            set_at_ms: 5,
        };
        let shown = format!("{registration:?}");
        for hidden in [
            "push.example",
            "/v1/hook",
            "handle-Kt8fSp",
            registration.push_key.as_str(),
        ] {
            assert!(!shown.contains(hidden), "{shown}");
        }
    }
}
