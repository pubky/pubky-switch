//! Where every answer is signed (Switch wire 7.1, 7.4.16): with the operator key, or with an
//! account's service key only while the account provably still names that key.
//!
//! An answer of an account's key is signed by [`Service::sign_keyed`], with a [`Proof`]:
//! - [`Proof::Locked`]: the request holds the account's row lock, uncommitted, so no erasure
//!   or change of the key can commit meanwhile, and the key is the transaction's. Only for
//!   what goes out after the same transaction commits, such as the erasure's confirmation:
//!   the commit proves the lock was held all along. A statement that failed may mean the
//!   database ended the transaction and its lock with it, so an answer to a failure under the
//!   lock goes through [`Service::sign_after_failure`] instead;
//! - [`Proof::Checked`]: anything else, a commit already made included. The answer is signed
//!   inside a keyed section ([`crate::store::Store::while_keyed`]), under the account's shared
//!   keying lock, which an erasure and a key change take exclusive before they sign their own
//!   answer.
//!
//! Otherwise the operator's answer goes out instead: as for an account the service doesn't
//! host, for one erased meanwhile (Switch wire 7.3 step 2), and `503` for one whose key
//! changed, or when the keyed section fails. Nothing else in the service signs an answer or a
//! head: `sign_answer` is this module's alone.

use axum::http::{HeaderName, HeaderValue};
use pubky_switch_core::{
    chain::{ChainTip, SignedHead},
    enc::b64,
    http::{self as wire_http, header},
    time::rfc3339,
};

use super::{Answer, Service, unsigned};
use crate::{
    http::{SwitchResponse, error::ApiError},
    keys::{KeyId, Mark, ServiceSigner, sign_head},
    store::{AccountTxn, Keyed},
};

/// What shows the account still names the key an answer is signed with.
pub(super) enum Proof<'a> {
    /// The request holds the account's row lock and hasn't committed: the key is `txn`'s.
    /// The borrow keeps the transaction alive while the answer is signed; only what goes out
    /// after that transaction commits may use it (the module's doc).
    Locked(#[allow(dead_code)] &'a AccountTxn),
    /// Checked in a keyed section: `account` names `key`, or, with `pending`, has it as its
    /// pending key of the next generation.
    Checked {
        /// The account.
        account: &'a str,
        /// The key the request loaded.
        key: &'a KeyId,
        /// The key may be the account's pending key (an enrollment's answer).
        pending: bool,
    },
}

impl<'a> Proof<'a> {
    /// [`Proof::Checked`] for `account`'s service key `key`.
    pub(super) fn checked(account: &'a str, key: &'a KeyId) -> Self {
        Proof::Checked {
            account,
            key,
            pending: false,
        }
    }
}

/// Why an answer couldn't be signed with the account's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NotKeyed {
    /// The account is gone.
    Gone,
    /// It names another key, or the keyed section failed.
    Unavailable,
}

/// The signing an answer's builder may do inside its proof: a signed head.
pub(super) struct Signing<'a> {
    signer: &'a ServiceSigner,
}

impl Signing<'_> {
    /// Sign the head at `tip` for `identity`, unless it is behind `mark` (Switch spec 6.5).
    pub(super) fn head(
        &self,
        mark: Option<&Mark>,
        identity: &[u8; 32],
        tip: &ChainTip,
    ) -> Option<SignedHead> {
        sign_head(self.signer, mark, identity, tip).ok()
    }
}

/// Sign `answer` (Switch wire 7.1): the response signature over its status, the request
/// signature, `Switch-Server-Time` and the body.
fn sign_answer(
    signer: &ServiceSigner,
    request_signature: Option<&[u8; 64]>,
    time_ms: u64,
    answer: Answer,
) -> SwitchResponse {
    let server_time = rfc3339(time_ms);
    let signature = wire_http::sign_response(
        signer,
        answer.status,
        request_signature,
        &server_time,
        &answer.body,
    );
    let mut headers = Vec::new();
    let mut put = |name: &'static str, value: String| {
        if let Ok(value) = HeaderValue::try_from(value) {
            headers.push((HeaderName::from_static(name), value));
        }
    };
    put(header::SERVICE_SIGNATURE, b64(&signature));
    put(header::SERVER_TIME, server_time);
    if let Some(head) = &answer.head {
        put(header::HEAD, head.to_header());
    }
    if let Some(seconds) = answer.retry_after {
        put(header::RETRY_AFTER, seconds.to_string());
    }
    if answer.cacheable {
        put("cache-control", "public, max-age=60".into());
    }
    if answer.no_store {
        put("cache-control", "no-store".into());
    }
    SwitchResponse {
        status: answer.status,
        headers,
        body: answer.body,
    }
}

impl Service {
    /// An answer signed with the operator key, at the time base (Switch wire 7.1).
    pub(super) async fn operator_answer(
        &self,
        request_signature: Option<&[u8; 64]>,
        base_ms: u64,
        error: &ApiError,
    ) -> SwitchResponse {
        match self.keys.operator().await {
            Ok(signer) => sign_answer(&signer, request_signature, base_ms, Answer::error(error)),
            Err(failure) => {
                tracing::error!(%failure, "the operator key");
                unsigned(error)
            }
        }
    }

    /// The answer `build` makes, signed with `signer`, an account's service key, under
    /// `proof` (the module's doc). `build` runs synchronously inside the proof, and gives
    /// the answer and its service time; it may sign a head with [`Signing::head`].
    pub(super) async fn try_sign_keyed(
        &self,
        proof: Proof<'_>,
        signer: &ServiceSigner,
        request_signature: Option<&[u8; 64]>,
        build: impl FnOnce(&Signing<'_>) -> (Answer, u64),
    ) -> Result<SwitchResponse, NotKeyed> {
        let sign = || {
            let (answer, time_ms) = build(&Signing { signer });
            sign_answer(signer, request_signature, time_ms, answer)
        };
        match proof {
            Proof::Locked(_) => Ok(sign()),
            Proof::Checked {
                account,
                key,
                pending,
            } => match self.store.while_keyed(account, key, pending, sign).await {
                Ok(Keyed::Signed(signed)) => Ok(signed),
                Ok(Keyed::Gone) => Err(NotKeyed::Gone),
                Ok(Keyed::Rekeyed) => Err(NotKeyed::Unavailable),
                Err(failure) => {
                    tracing::error!(%failure, "a keyed section");
                    Err(NotKeyed::Unavailable)
                }
            },
        }
    }

    /// `answer` at `time_ms`, signed with `signer` under `proof`; otherwise the operator's
    /// answer at `base_ms`: as for an account the service doesn't host when it is gone, for
    /// its signer when `by_signer` ([`Service::no_such_account`]), else `503`.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn sign_keyed(
        &self,
        proof: Proof<'_>,
        signer: &ServiceSigner,
        request_signature: Option<&[u8; 64]>,
        time_ms: u64,
        answer: Answer,
        base_ms: u64,
        by_signer: bool,
    ) -> SwitchResponse {
        let account = match &proof {
            Proof::Checked { account, .. } => Some((*account).to_owned()),
            Proof::Locked(_) => None,
        };
        let signed = self
            .try_sign_keyed(proof, signer, request_signature, |_| (answer, time_ms))
            .await;
        match signed {
            Ok(signed) => signed,
            Err(not_keyed) => {
                self.not_keyed_answer(
                    account.as_deref(),
                    not_keyed,
                    by_signer,
                    request_signature,
                    base_ms,
                )
                .await
            }
        }
    }

    /// The answer to a request whose transaction failed under the account's lock: a database
    /// that ended the transaction released its lock, and an erasure may have committed
    /// since. So the transaction is dropped first, holding no second connection, and the
    /// answer is signed only in a keyed section (the module's doc). `key` is the key `signer`
    /// was loaded for, not the transaction's: a request that changed the account's key in
    /// it (Switch wire 3.3) holds the new one there, and a retry may have committed that
    /// change since, so the section checks the key that signs.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn sign_after_failure(
        &self,
        txn: AccountTxn,
        signer: &ServiceSigner,
        key: &KeyId,
        request_signature: Option<&[u8; 64]>,
        time_ms: u64,
        answer: Answer,
        base_ms: u64,
        by_signer: bool,
    ) -> SwitchResponse {
        let account = txn.head().id.clone();
        let key = key.clone();
        drop(txn);
        self.sign_keyed(
            Proof::checked(&account, &key),
            signer,
            request_signature,
            time_ms,
            answer,
            base_ms,
            by_signer,
        )
        .await
    }

    /// The operator's answer in place of one an account's key couldn't sign.
    pub(super) async fn not_keyed_answer(
        &self,
        account: Option<&str>,
        not_keyed: NotKeyed,
        by_signer: bool,
        request_signature: Option<&[u8; 64]>,
        base_ms: u64,
    ) -> SwitchResponse {
        let error = match (not_keyed, account) {
            (NotKeyed::Gone, Some(account)) => self.no_such_account(account, by_signer).await,
            _ => ApiError::unavailable("7.6: a temporary failure"),
        };
        self.operator_answer(request_signature, base_ms, &error)
            .await
    }

    /// Sign the head of the account's chain as it will be committed, for an answer to the
    /// signer or an own app; `None` if the key's mark refuses it. Under the account's lock,
    /// so [`Proof::Locked`] by construction: the answer that carries it is signed under its
    /// own proof.
    pub(super) async fn head(
        &self,
        txn: &AccountTxn,
        signer: &ServiceSigner,
    ) -> Option<SignedHead> {
        let head = txn.head();
        let mark = self.keys.mark(&head.service_key).await.ok()?;
        sign_head(signer, mark.as_ref(), &head.identity_key, &head.chain_tip()).ok()
    }
}

#[cfg(test)]
mod tests {
    /// Every Rust source of the service under `dir`, with its path.
    fn sources(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                out.push((path, text));
            }
        }
    }

    #[test]
    fn test_keyed_signing_happens_only_here() {
        // An answer or a head signed anywhere else in the service could be signed with a key
        // its account no longer names (Switch wire 7.4.16): this module is the only place.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/service");
        let mut found = Vec::new();
        sources(&dir, &mut found);
        assert!(found.len() > 10, "the service's sources");
        for (path, text) in found {
            if path.ends_with("keyed.rs") {
                continue;
            }
            for needle in ["sign_response(", "sign_head(", "fn sign_answer("] {
                assert!(
                    !text.contains(needle),
                    "{} signs outside keyed.rs: {needle}",
                    path.display()
                );
            }
        }
    }
}
