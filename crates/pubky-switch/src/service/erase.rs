//! `POST /v1/{id}/erase` (Switch wire 7.4.16, spec 12.7): the signer erases the identity's
//! account at this service.
//!
//! The request passes the signer's checks like every call, and is refused, without a head,
//! for another service key (`409 conflict`), a malformed body (`400`) or an app (`403`).
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

use super::{Answer, Deferred, PublicKeyBytes, Service, sign_answer};
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
    /// 7.4.16): the body names exactly this account's service key. The answer it returns
    /// erases nothing yet: [`Service::finish_erasure`] does, once it is signed.
    ///
    /// # Errors
    ///
    /// `400` for a body that isn't `{ "service_key": b64(32) }`; `409 conflict` for another
    /// key, so a replay can't erase a later account of the identity here.
    pub(super) fn erase_answer(signer: &ServiceSigner, body: &[u8]) -> Result<Answer, ApiError> {
        let named = parse_erase_body(body).map_err(|e| ApiError::bad_request(e.to_string()))?;
        if named != signer.public_key_bytes() {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "7.4.16: not the account's service key",
            ));
        }
        let mut answer = Answer::ok(ERASED_BODY.to_vec());
        answer.deferred = Some(Deferred::Erase);
        Ok(answer)
    }

    /// Erase the account whose lock `txn` holds and answer `answer`, signed first, while
    /// the key exists (Switch wire 7.4.16 Order). `committed_ms` is the time the account
    /// last committed, for the `503` of an erasure that doesn't commit.
    pub(super) async fn finish_erasure(
        &self,
        txn: AccountTxn,
        signer: &ServiceSigner,
        signature: Option<&[u8; 64]>,
        committed_ms: u64,
        time_ms: u64,
        mut answer: Answer,
    ) -> SwitchResponse {
        answer.deferred = None;
        let signed = sign_answer(signer, signature, time_ms, answer);
        let account = txn.head().id.clone();
        match txn.erase(time_ms).await {
            Ok(()) => {}
            Err(failure) => {
                // Dropped uncommitted: nothing is deleted, and the signer retries.
                tracing::error!(%failure, "an erasure");
                let error = ApiError::unavailable("7.6: a temporary failure");
                return sign_answer(signer, signature, committed_ms, Answer::error(&error));
            }
        };
        // The state is gone for good, and the keys' deletion owed with it. The keys go after
        // it: a key deleted before a commit that then failed would leave an account no key
        // answers for.
        self.sweep_erased_keys().await;
        self.forget_account(&account);
        signed
    }

    /// Delete every key an erasure still owes deleting, recording each erasure in the key
    /// store's ledger first (Switch wire 7.4.16, spec 6.5), and drop what is done. A failure
    /// leaves the key owed for the next sweep: at the next erasure, and at start. Run at
    /// start by the service's binary.
    pub async fn sweep_erased_keys(&self) {
        let owed = match self.store.erased_keys().await {
            Ok(owed) => owed,
            Err(failure) => {
                tracing::error!(%failure, "reading the keys erasures owe deleting");
                return;
            }
        };
        for erased in owed {
            if let Err(failure) = self
                .keys
                .record_erasure(&erased.account, erased.erased_at_ms)
                .await
            {
                tracing::error!(%failure, "recording an erasure");
                continue;
            }
            if let Err(failure) = self.keys.delete(&erased.key).await {
                tracing::error!(%failure, "deleting an erased account's key");
                continue;
            }
            if let Err(failure) = self.store.forget_erased_key(&erased.key).await {
                tracing::error!(%failure, "dropping a deleted key's row");
            }
        }
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
        self.sender_rate.forget(|(at, _)| at == account);
        self.sender_app_rate.forget(|(at, _)| at == account);
        self.notify_rate.forget(|(at, _)| at == account);
    }
}
