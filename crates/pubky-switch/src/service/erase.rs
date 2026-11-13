//! `POST /v1/{id}/erase` (Switch wire 7.4.16, spec 12.7): the signer erases the identity's
//! account at this service.
//!
//! The request passes the signer's checks like every call, and is refused, without a head,
//! for another service key or, when the body names one, another `identity.json` than the
//! account's newest (`409 conflict`), a malformed body (`400`) or an app (`403`).
//! An account behind its key's mark still takes it (7.3 step 10), since the answer carries
//! no head. Then the order is fixed:
//! 1. the answer `{ "erased": true }` is signed while the key exists;
//! 2. the account's row is deleted, and with it every row of its state; the deletion of its
//!    service key and mark, and of a pending key of the next generation, is owed in the same
//!    transaction (`erased_keys`); all of it is committed;
//! 3. the owed keys are deleted from the key store and the erasure recorded in its ledger
//!    (spec 6.5), and the account's rate-limit and failed-authentication counts forgotten;
//! 4. only then is the answer released.
//!
//! A key the key store fails to delete stays owed, durably: [`Service::sweep_erased_keys`]
//! deletes it at the next erasure and at start. Nothing names it any more, so it signs nothing
//! meanwhile.
//!
//! If the deletion can't commit, nothing is deleted and the answer is `503`, signed with the
//! account's key, without a head; the signer retries. Afterwards every request for the
//! account, the retry of a lost `200` included, finds no account: the operator's `404`.

use std::sync::Arc;

use pubky_switch_core::http::{ERASED_BODY, parse_erase_body};

use super::{Answer, Deferred, PublicKeyBytes, Service, keyed::Proof};
use crate::{
    http::{
        SwitchResponse,
        error::{ApiError, ErrorCode},
    },
    keys::{KeyId, KeyStore, ServiceSigner},
    store::{AccountTxn, Store},
};

impl Service {
    /// The checks of an erasure from the signer, under the account's lock (Switch wire
    /// 7.4.16): the body names exactly this account's service key and, when it names one,
    /// the document hash of `held`, the account's newest `identity.json`. The answer it
    /// returns erases nothing yet: [`Service::finish_erasure`] does, once it is signed.
    ///
    /// # Errors
    ///
    /// `400` for a body that isn't `{ "service_key": b64(32), "identity_hash": b64(32) }`, the
    /// hash optional; `409 conflict` for another key, so a replay can't erase a later account
    /// of the identity here; and `409 conflict` for another hash, or a hash at an account
    /// that holds no `identity.json` yet, so an erasure can't follow a delivery made after
    /// the signer's last check, such as another install's take-over.
    pub(super) fn erase_answer(
        signer: &ServiceSigner,
        body: &[u8],
        held: Option<[u8; 32]>,
    ) -> Result<Answer, ApiError> {
        let named = parse_erase_body(body).map_err(|e| ApiError::bad_request(e.to_string()))?;
        if named.service_key != signer.public_key_bytes() {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "7.4.16: not the account's service key",
            ));
        }
        if named.identity_hash.is_some_and(|hash| Some(hash) != held) {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "7.4.16: the account holds another identity.json",
            ));
        }
        let mut answer = Answer::ok(ERASED_BODY.to_vec());
        answer.deferred = Some(Deferred::Erase);
        Ok(answer)
    }

    /// Erase the account whose lock `txn` holds and answer `answer`, signed first, while
    /// the key exists (Switch wire 7.4.16 Order). `committed_ms` is the time the account
    /// last committed, for the `503` of an erasure that doesn't commit; `base_ms` the time
    /// base, for the operator's answer.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn finish_erasure(
        &self,
        mut txn: AccountTxn,
        signer: &ServiceSigner,
        signature: Option<&[u8; 64]>,
        committed_ms: u64,
        time_ms: u64,
        base_ms: u64,
        mut answer: Answer,
    ) -> SwitchResponse {
        answer.deferred = None;
        let unavailable = || ApiError::unavailable("7.6: a temporary failure");
        // No keyed section signs with the key from here on: the erasure's answer is the last
        // it signs (7.4.16, store/keying.rs). The confirmation is signed in place, under the
        // row lock this transaction holds, since it goes out only once the deletion commits;
        // a failure here may have ended the transaction, so its `503` is signed only in a
        // keyed section.
        if let Err(failure) = txn.exclude_signers().await {
            tracing::error!(%failure, "excluding an erased account's signers");
            let key = txn.head().service_key.clone();
            return self
                .sign_after_failure(
                    txn,
                    signer,
                    &key,
                    signature,
                    committed_ms,
                    Answer::error(&unavailable()),
                    base_ms,
                    true,
                )
                .await;
        }
        let signed = self
            .sign_keyed(
                Proof::Locked(&txn),
                signer,
                signature,
                time_ms,
                answer,
                base_ms,
                true,
            )
            .await;
        let account = txn.head().id.clone();
        let key = txn.head().service_key.clone();
        // The deletion, and the keys' deletion after it, run to their end in a task of their
        // own: a signer that hangs up between them leaves no key to the next sweep.
        let (store, keys) = (self.store.clone(), self.keys.clone());
        let erased = to_the_end(async move {
            txn.erase(time_ms).await?;
            Ok::<_, crate::store::StoreError>(sweep_owed(store, keys).await)
        })
        .await;
        let left = match erased {
            Some(Ok(left)) => left,
            // A task that panicked: whether the deletion committed is unknown, so the
            // operator's `503`, as for keys still owed.
            None => None,
            Some(Err(failure)) => {
                // Dropped uncommitted: nothing is deleted, and the signer retries. The lock is
                // gone, so the `503` is signed only while the account still names the key.
                tracing::error!(%failure, "an erasure");
                return self
                    .sign_keyed(
                        Proof::checked(&account, &key),
                        signer,
                        signature,
                        committed_ms,
                        Answer::error(&unavailable()),
                        base_ms,
                        true,
                    )
                    .await;
            }
        };
        // The state is gone for good, and the keys' deletion owed with it. The keys went after
        // it: a key deleted before a commit that then failed would leave an account no key
        // answers for.
        self.forget_account(&account);
        // The answer is released only once the key and its mark are deleted and the erasure
        // recorded (7.4.16 Order). Otherwise the operator's `503`, without a head: the signer
        // keeps the request in doubt and retries, and its retry gets the operator's `404`
        // once the next sweep has deleted the key.
        let done = left.is_some_and(|left| !left.iter().any(|owed| owed == &account));
        if !done {
            let error = ApiError::unavailable("7.6: a temporary failure");
            return self.operator_answer(signature, base_ms, &error).await;
        }
        signed
    }

    /// Delete every key an erasure still owes deleting, recording each erasure in the key
    /// store's ledger first (Switch wire 7.4.16, spec 6.5), every key a generation change
    /// retired, which records none (wire 3.3), and every push key owed (wire 8.1), which
    /// records none either, and drop what is done. Each row is locked while its key goes, so
    /// a start claiming the key it minted waits, then finds it gone (`store::push`). A
    /// failure leaves the key owed for the next sweep: at the next erasure, and at start. Run
    /// at start by the service's binary. The sweep runs to its end in a task of its own, so a
    /// request dropped meanwhile doesn't stop it.
    ///
    /// Returns the accounts whose keys are still owed, a key not deleted or its erasure not
    /// recorded; `None` when the owed keys can't be read.
    pub async fn sweep_erased_keys(&self) -> Option<Vec<String>> {
        to_the_end(sweep_owed(self.store.clone(), self.keys.clone()))
            .await
            .flatten()
    }

    /// Forget every count the service keeps for `account` (Switch wire 7.4.16, 9.4).
    fn forget_account(&self, account: &str) {
        self.failed_auth.forget_account(account);
        self.reads_per_source.forget(|(at, _)| at == account);
        self.reads_per_account.forget(|at| at == account);
        self.operation_rate.forget(|(at, _)| at == account);
        self.control_rate.forget(|(at, _)| at == account);
        self.invite_rate.forget(|(at, _)| at == account);
        self.stranger_rate.forget(|at| at == account);
        self.connect_rate.forget(|(at, _)| at == account);
        self.sender_rate.forget(|(at, _)| at == account);
        self.sender_app_rate.forget(|(at, _)| at == account);
        self.upload_rate.forget(|(at, _)| at == account);
        self.notify_rate.forget(|(at, _)| at == account);
    }
}

/// Run `work` to its end in a task of its own: a request dropped meanwhile (a client that
/// hangs up, whose request future goes at its next `.await`) can't stop it half-way. `None`
/// if the task panicked.
pub(super) async fn to_the_end<T: Send + 'static>(
    work: impl Future<Output = T> + Send + 'static,
) -> Option<T> {
    tokio::spawn(work).await.ok()
}

/// [`Service::sweep_erased_keys`]'s work.
pub(super) async fn sweep_owed(store: Store, keys: Arc<dyn KeyStore>) -> Option<Vec<String>> {
    let owed = match store.erased_keys().await {
        Ok(owed) => owed,
        Err(failure) => {
            tracing::error!(%failure, "reading the keys erasures owe deleting");
            return None;
        }
    };
    let mut left = Vec::new();
    for erased in owed {
        let row = match store.lock_owed_key(&erased.key).await {
            Ok(Some(row)) => row,
            // Done meanwhile: claimed by a start's commit, or deleted by another sweep.
            Ok(None) => continue,
            Err(failure) => {
                tracing::error!(%failure, "locking an owed key's row");
                left.push(erased.account);
                continue;
            }
        };
        if !erased.retired
            && let Err(failure) = keys
                .record_erasure(&erased.account, erased.erased_at_ms)
                .await
        {
            tracing::error!(%failure, "recording an erasure");
            left.push(erased.account);
            continue;
        }
        if let Err(failure) = keys.delete(&erased.key).await {
            tracing::error!(%failure, "deleting an owed key");
            left.push(erased.account);
            continue;
        }
        // The key is gone and the erasure recorded: a row left behind is deleted again,
        // which deletes nothing more.
        if let Err(failure) = row.forget().await {
            tracing::error!(%failure, "dropping a deleted key's row");
        }
    }
    Some(left)
}

/// Delete `ids`, push keys one request owed deleting, once it is over (Switch wire 8.1):
/// those still owed go, each under its row's lock; one claimed meanwhile by a committed
/// registration stays. A failure leaves the key owed for the next sweep.
pub(super) async fn delete_owed(store: Store, keys: Arc<dyn KeyStore>, ids: Vec<KeyId>) {
    for key in &ids {
        let row = match store.lock_owed_key(key).await {
            Ok(Some(row)) => row,
            Ok(None) => continue,
            Err(failure) => {
                tracing::error!(%failure, "locking an owed key's row");
                continue;
            }
        };
        if let Err(failure) = keys.delete(key).await {
            tracing::error!(%failure, "deleting an owed push key");
            continue;
        }
        if let Err(failure) = row.forget().await {
            tracing::error!(%failure, "dropping a deleted key's row");
        }
    }
}

/// Push keys a request owes deleting once it is over (Switch wire 8.1): deleted by
/// [`OwedKeys::delete`] at its end or, when the request is dropped before that (a client that
/// hangs up), by a task of their own as this drops. So no `.await` of the request leaves
/// them to a sweep.
pub(super) struct OwedKeys {
    store: Store,
    keys: Arc<dyn KeyStore>,
    ids: Vec<KeyId>,
}

impl OwedKeys {
    /// `ids`, owed in `store`'s ledger, deleted from `keys`.
    pub(super) fn new(store: Store, keys: Arc<dyn KeyStore>, ids: Vec<KeyId>) -> Self {
        Self { store, keys, ids }
    }

    /// Delete the keys still owed, waiting until it is done.
    pub(super) async fn delete(mut self) {
        let ids = std::mem::take(&mut self.ids);
        if !ids.is_empty() {
            to_the_end(delete_owed(self.store.clone(), self.keys.clone(), ids)).await;
        }
    }
}

impl Drop for OwedKeys {
    fn drop(&mut self) {
        let ids = std::mem::take(&mut self.ids);
        if ids.is_empty() {
            return;
        }
        // Without a runtime, which only a shutting-down service lacks, the keys stay owed
        // for the sweep at start.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(delete_owed(self.store.clone(), self.keys.clone(), ids));
        }
    }
}

impl std::fmt::Debug for OwedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwedKeys")
            .field("keys", &self.ids.len())
            .finish_non_exhaustive()
    }
}
