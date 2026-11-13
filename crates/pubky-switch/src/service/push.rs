//! `PUT /v1/{id}/push` (Switch spec 9, Switch wire 8.1): an own app starts a push
//! registration, at most one per app, and sets its handles.
//!
//! A `notify` entry queues a webhook to each of the app's handles, sent by the delivery
//! worker (8.2, `service::webhooks`); a replacement or a new list of handles drops the ones
//! queued for what it lets go.
//!
//! - **Before the lock**, after the app's request verified: the body is read and checked
//!   (`400`): its form, at most 8 handles, none on a start, no `replaces` with `push_key`, and
//!   the relay URL, `https://` on port 443 without user info, whose host must resolve only to
//!   public addresses, the checks switch origins take (wire 7.1, 8.2). Delivery resolves and
//!   checks the host again at each connection. A service that sends no pushes
//!   (`push.enabled` off) answers every registration `400`. A start that will need a new push
//!   key, by the registration read without the lock, has its key minted here: owed deleting
//!   first, then generated in the key store under its row's lock (`store::push`).
//! - **Under the lock**, after the caller's checks (a removed or not current app is refused
//!   `403 not_current`, a staged account `503 staged`): 8.1's cases, judged on the
//!   registration held. A start is idempotent without a nonce: the same relay without
//!   `replaces` answers the registration unchanged, `replaces` naming its key replaces it with
//!   the minted one, and anything else is `409 conflict` naming the current key, or `null`.
//!   Setting handles needs the current key and relay (`409` otherwise) and replaces the list;
//!   a list that would take the account past 8 handles at one relay host, across its apps, is
//!   `400`, since an entry sends at most 8 webhooks toward one host (8.2).
//! - **After it:** a key minted but not taken, and the replaced key, are deleted from the key
//!   store; one whose deletion fails stays owed for the next sweep. A request dropped on the
//!   way (a client that hangs up) leaves neither: the mint, and the commit with the
//!   deletions it owes, run to their end in tasks of their own, and the minted key's debt
//!   deletes it as it drops.
//!
//! Nothing of the relay URL, the handles or a key is logged.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use pubky_switch_core::{
    enc::b64,
    http::{PushBody, parse_push_body},
    net::{CheckedUrl, UrlUse, check_addresses, check_url},
};
use serde_json::json;

use super::{
    Answer, Service,
    erase::{OwedKeys, to_the_end},
    store_error,
};
use crate::{
    http::error::{ApiError, ErrorCode},
    keys::{KeyId, KeyStore, ServiceKey, ServiceSigner},
    store::{AccountTxn, PUSH_PER_HOST, PushRegistration, Store, StoreError},
};

/// How long resolving a relay's host may take (Switch wire 8.2: 5 s).
const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Resolves a relay's host to its addresses.
pub type Resolver = Arc<
    dyn Fn(String) -> futures_util::future::BoxFuture<'static, std::io::Result<Vec<IpAddr>>>
        + Send
        + Sync,
>;

/// The system resolver.
pub(super) fn system_resolver() -> Resolver {
    Arc::new(|host: String| {
        Box::pin(async move {
            let found = tokio::net::lookup_host((host.as_str(), 443)).await?;
            Ok(found.map(|address| address.ip()).collect())
        })
    })
}

/// What a `PUT /push` checked before the lock.
#[derive(Debug)]
pub(super) struct PreparedPush {
    /// The body, or its `400`.
    body: Result<PushBody, ApiError>,
    /// The key owed for a start, minted or not: deleted once the request is over, or as soon
    /// as it is dropped, unless a committed registration took it.
    reserved: Option<OwedKeys>,
    /// The key minted.
    minted: Option<ServiceKey>,
}

impl PreparedPush {
    /// The request is over: the key owed for a start goes unless a committed registration
    /// took it.
    pub(super) async fn done(self) {
        if let Some(reserved) = self.reserved {
            reserved.delete().await;
        }
    }
}

/// Owe deleting a new push key of `account` at `at_ms`, then mint it under its row's lock
/// (`store::push`). Run in a task of its own ([`to_the_end`]), so a request dropped meanwhile
/// stops it neither between the debt and the key nor while the key is written: its debt, the
/// returned [`OwedKeys`], is then dropped with the task's output and deletes the key.
async fn mint_push_key(
    store: Store,
    keys: Arc<dyn KeyStore>,
    account: String,
    at_ms: u64,
) -> (Option<OwedKeys>, Option<ServiceKey>) {
    let Ok(id) = KeyId::random() else {
        return (None, None);
    };
    if let Err(error) = store.owe_push_key(&account, &id, at_ms).await {
        let _ = store_error(&error);
        return (None, None);
    }
    let minted = mint_owed(&store, keys.as_ref(), &id).await;
    let owed = OwedKeys::new(store, keys, vec![id]);
    (Some(owed), minted)
}

/// Mint push key `id` while its owed row is locked; `None` when no row owes it any more: a
/// sweep that took the row first deleted it, and a key minted after that would be owed by
/// no row.
async fn mint_owed(store: &Store, keys: &dyn KeyStore, id: &KeyId) -> Option<ServiceKey> {
    match store.lock_owed_key(id).await {
        Ok(Some(row)) => {
            let minted = keys
                .generate_as(id)
                .await
                .inspect_err(|failure| tracing::error!(%failure, "minting a push key"))
                .ok();
            drop(row);
            minted
        }
        Ok(None) => None,
        Err(error) => {
            let _ = store_error(&error);
            None
        }
    }
}

/// Whether a start needs a new push key, by `current`, the key of the registration held:
/// none held and no `replaces`, or `replaces` naming the held one (Switch wire 8.1).
fn needs_key(current: Option<[u8; 32]>, replaces: Option<[u8; 32]>) -> bool {
    match (current, replaces) {
        (None, None) => true,
        (Some(current), Some(named)) => current == named,
        _ => false,
    }
}

/// The `409 conflict` naming the current push key, or `null` (Switch wire 8.1).
fn conflict(current: Option<[u8; 32]>) -> ApiError {
    ApiError::new(
        ErrorCode::Conflict,
        "8.1: not the current push registration",
    )
    .with_current(json!({ "push_key": current.map(|key| b64(&key)) }))
}

fn temporary() -> ApiError {
    ApiError::unavailable("7.6: a temporary failure")
}

impl Service {
    /// A `PUT /push` body checked, and a push key minted when a start will need one, before
    /// the account's lock: `app` is the verified caller, `at_ms` the time its key's debt is
    /// stamped with.
    pub(super) async fn prepare_push(
        &self,
        account: &str,
        app: &[u8; 16],
        body: &[u8],
        at_ms: u64,
    ) -> PreparedPush {
        let body = self.check_push_body(body).await;
        let mut prepared = PreparedPush {
            body,
            reserved: None,
            minted: None,
        };
        let Ok(body) = &prepared.body else {
            return prepared;
        };
        if !body.is_start() {
            return prepared;
        }
        let current = match self.store.push_key_of(account, app).await {
            Ok(current) => current,
            Err(error) => {
                let _ = store_error(&error);
                return prepared;
            }
        };
        if !needs_key(current, body.replaces) {
            return prepared;
        }
        let minting = mint_push_key(
            self.store.clone(),
            self.keys.clone(),
            account.to_string(),
            at_ms,
        );
        if let Some((reserved, minted)) = to_the_end(minting).await {
            prepared.reserved = reserved;
            prepared.minted = minted;
        }
        prepared
    }

    /// The body's checks (Switch wire 8.1): the service sends pushes, the body reads, and
    /// the relay's host resolves only to public addresses (8.2).
    async fn check_push_body(&self, body: &[u8]) -> Result<PushBody, ApiError> {
        if !self.push_enabled {
            return Err(ApiError::bad_request("8.1: this service sends no pushes"));
        }
        let body = parse_push_body(body).map_err(|e| ApiError::bad_request(e.to_string()))?;
        let refused = || {
            ApiError::bad_request("8.1: the relay's host doesn't resolve only to public addresses")
        };
        let CheckedUrl { host, .. } = check_url(&body.relay_url, &UrlUse::Relay)
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
        // An address literal was judged by `check_url`.
        if host.parse::<IpAddr>().is_err() {
            let addresses = tokio::time::timeout(RESOLVE_TIMEOUT, (self.resolver)(host))
                .await
                .map_err(|_| refused())?
                .map_err(|_| refused())?;
            check_addresses(&addresses).map_err(|_| refused())?;
        }
        Ok(body)
    }

    /// `PUT /v1/{id}/push` under the account's lock, from `app`, an own app that passed its
    /// checks (Switch wire 8.1).
    ///
    /// # Errors
    ///
    /// The `400` of the checks before the lock; `409 conflict` as 8.1 gives; `503` for a
    /// start that needs a key none was minted for, or whose key a sweep took.
    pub(super) async fn put_push(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        app: [u8; 16],
        prepared: Option<&PreparedPush>,
        time_ms: u64,
    ) -> Result<Answer, ApiError> {
        let prepared = prepared.ok_or_else(temporary)?;
        let body = prepared.body.as_ref().map_err(Clone::clone)?;
        let held = txn
            .push_registration(&app)
            .await
            .map_err(|e| store_error(&e))?;
        let current = held.as_ref().map(|reg| reg.push_public);
        let registration = match (&held, body.push_key) {
            // A start (8.1 step 1).
            (_, None) => {
                if let Some(reg) = held
                    .as_ref()
                    .filter(|reg| body.replaces.is_none() && reg.relay_url == body.relay_url)
                {
                    reg.clone()
                } else if needs_key(current, body.replaces) {
                    let key = prepared.minted.as_ref().ok_or_else(temporary)?;
                    let registration = PushRegistration {
                        app_id: app,
                        relay_url: body.relay_url.clone(),
                        push_key: key.id.clone(),
                        push_public: key.public,
                        handles: Vec::new(),
                        set_at_ms: time_ms,
                    };
                    let replaced = held.as_ref().map(|reg| &reg.push_key);
                    txn.put_push_registration(&registration, replaced)
                        .await
                        .map_err(|e| match e {
                            StoreError::Raced(_) => temporary(),
                            other => store_error(&other),
                        })?;
                    registration
                } else {
                    return Err(conflict(current));
                }
            }
            // The handles (8.1 step 3).
            (Some(reg), Some(named))
                if named == reg.push_public && reg.relay_url == body.relay_url =>
            {
                // An entry sends at most 8 webhooks toward one relay host (8.2), so handles
                // past 8 there, across the account's apps, would never get one.
                let host = check_url(&body.relay_url, &UrlUse::Relay)
                    .map_err(|e| ApiError::bad_request(e.to_string()))?
                    .host;
                let others = txn
                    .push_handles_at_host(&host, &app)
                    .await
                    .map_err(|e| store_error(&e))?;
                let handles = body.handles.iter().collect::<HashSet<_>>().len();
                if others + handles > PUSH_PER_HOST {
                    return Err(ApiError::bad_request(
                        "8.1: more than 8 handles at one relay host across the account's apps",
                    ));
                }
                txn.set_push_handles(&app, &body.handles, time_ms)
                    .await
                    .map_err(|e| store_error(&e))?;
                PushRegistration {
                    handles: body.handles.clone(),
                    set_at_ms: time_ms,
                    ..reg.clone()
                }
            }
            (_, Some(_)) => return Err(conflict(current)),
        };
        let answer = json!({
            "relay_url": registration.relay_url,
            "handles": registration.handles.len(),
            "push_key": b64(&registration.push_public),
        });
        let head = self.head(txn, signer).await.ok_or_else(temporary)?;
        Ok(Answer::ok(answer.to_string().into_bytes()).with_head(Some(head)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_needs_key_cases() {
        assert!(needs_key(None, None));
        assert!(!needs_key(None, Some([1; 32])));
        assert!(needs_key(Some([1; 32]), Some([1; 32])));
        assert!(!needs_key(Some([1; 32]), Some([2; 32])));
        assert!(!needs_key(Some([1; 32]), None));
    }

    #[tokio::test]
    async fn test_push_mint_of_a_key_no_longer_owed_mints_nothing() {
        // A sweep that took the row first deleted the key: minting it anyway would leave a
        // key no row owes, which nothing would ever delete.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = crate::keys::FileKeyStore::open(dir.path()).expect("key store");
        let id = KeyId::random().expect("key id");
        assert!(mint_owed(db.store(), &keys, &id).await.is_none());
        assert!(keys.public_key(&id).await.is_err(), "nothing minted");
        // Owed, it is minted.
        db.store()
            .owe_push_key("account", &id, 1)
            .await
            .expect("owed");
        let minted = mint_owed(db.store(), &keys, &id).await.expect("minted");
        assert_eq!(keys.public_key(&id).await.expect("kept"), minted.public);
        db.drop_database().await.expect("drop");
    }

    #[test]
    fn test_push_conflict_names_the_current_key() {
        let error = conflict(None);
        assert_eq!(error.code, ErrorCode::Conflict);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&error.body()).expect("json")["current"]["push_key"],
            serde_json::Value::Null
        );
    }
}
