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

use pubky_switch_core::http::{ERASED_BODY, parse_erase_body};

use super::{Answer, Deferred, PublicKeyBytes, Service, keyed::Proof};
use crate::{
    http::{
        SwitchResponse,
        error::{ApiError, ErrorCode},
    },
    keys::ServiceSigner,
    store::AccountTxn,
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
        match txn.erase(time_ms).await {
            Ok(()) => {}
            Err(failure) => {
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
        // The state is gone for good, and the keys' deletion owed with it. The keys go after
        // it: a key deleted before a commit that then failed would leave an account no key
        // answers for.
        let left = self.sweep_erased_keys().await;
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
    /// store's ledger first (Switch wire 7.4.16, spec 6.5), and every key a generation change
    /// retired, which records none (wire 3.3), and drop what is done. A failure
    /// leaves the key owed for the next sweep: at the next erasure, and at start. Run at
    /// start by the service's binary.
    ///
    /// Returns the accounts whose keys are still owed, a key not deleted or its erasure not
    /// recorded; `None` when the owed keys can't be read.
    pub async fn sweep_erased_keys(&self) -> Option<Vec<String>> {
        let owed = match self.store.erased_keys().await {
            Ok(owed) => owed,
            Err(failure) => {
                tracing::error!(%failure, "reading the keys erasures owe deleting");
                return None;
            }
        };
        let mut left = Vec::new();
        for erased in owed {
            if !erased.retired
                && let Err(failure) = self
                    .keys
                    .record_erasure(&erased.account, erased.erased_at_ms)
                    .await
            {
                tracing::error!(%failure, "recording an erasure");
                left.push(erased.account);
                continue;
            }
            if let Err(failure) = self.keys.delete(&erased.key).await {
                tracing::error!(%failure, "deleting an erased account's key");
                left.push(erased.account);
                continue;
            }
            // The key is gone and the erasure recorded: a row left behind is deleted again,
            // which deletes nothing more.
            if let Err(failure) = self.store.forget_erased_key(&erased.key).await {
                tracing::error!(%failure, "dropping a deleted key's row");
            }
        }
        Some(left)
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
