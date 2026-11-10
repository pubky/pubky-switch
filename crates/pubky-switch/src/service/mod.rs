//! The Switch service: the processing order of every request (Switch wire 7.3) and the
//! endpoints, as the [`Handler`] behind the HTTP transport.
//!
//! Each request to an account runs in one transaction on it ([`crate::store`]): its time is
//! stamped, its caller authenticated, the staged gate applied, then the endpoint. Every
//! answer is signed: with the account's service key, or, for an answer the service can't tie
//! to an account, with the operator key (Switch wire 7.1). An answer that carries a `seq`, a
//! proof or a head goes out only once the commit is durable and the key's mark has moved
//! (Switch wire 7.3 step 10).
//!
//! Served so far: `POST /v1/enroll`, `PUT /v1/{id}/identity` and the public
//! `GET /v1/{id}/identity`. Every other call is answered `503 unavailable`.

mod enroll;
mod identity;
pub mod rules;

use std::sync::Arc;

use axum::http::{HeaderName, HeaderValue};
use pubky_switch_core::{
    chain::SignedHead,
    enc::b64,
    http::{self as wire_http, RequestTarget, header},
    records::IdentityDoc,
    time::rfc3339,
};

use crate::{
    http::{
        Handler, HandlerFuture, Refusal, SwitchRequest, SwitchResponse,
        error::{ApiError, ErrorCode, is_failed_authentication},
        route::Call,
        source::NetworkSource,
    },
    keys::{KeyStore, MarkCheck, ServiceSigner, sign_head},
    limits::Limits,
    ratelimit::{FailedAuthentications, MinuteWindows},
    store::{AccountTxn, Store, StoreError},
    time::TrustedTime,
};

use self::rules::{Caller, Claimed, decode_claim, names_this_service, staged_gate};

/// The service.
pub struct Service {
    origin: String,
    store: Store,
    keys: Arc<dyn KeyStore>,
    time: Arc<TrustedTime>,
    limits: Limits,
    failed_auth: FailedAuthentications,
    reads_per_source: MinuteWindows<(String, NetworkSource)>,
    reads_per_account: MinuteWindows<String>,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

/// An answer before it is signed.
#[derive(Debug)]
struct Answer {
    status: u16,
    body: Vec<u8>,
    head: Option<SignedHead>,
    retry_after: Option<u64>,
    cacheable: bool,
}

impl Answer {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            body,
            head: None,
            retry_after: None,
            cacheable: false,
        }
    }

    fn error(error: &ApiError) -> Self {
        Self {
            status: error.status(),
            body: error.body(),
            head: None,
            retry_after: error.retry_after,
            cacheable: false,
        }
    }

    fn with_head(mut self, head: Option<SignedHead>) -> Self {
        self.head = head;
        self
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
    SwitchResponse {
        status: answer.status,
        headers,
        body: answer.body,
    }
}

/// An answer with no signature, when no key can sign: clients treat it as unauthenticated.
fn unsigned(error: &ApiError) -> SwitchResponse {
    SwitchResponse {
        status: error.status(),
        headers: Vec::new(),
        body: error.body(),
    }
}

/// How a store failure is answered: a temporary failure, or the account being busy.
fn store_error(error: &StoreError) -> ApiError {
    tracing::warn!(%error, "storage");
    ApiError::unavailable("7.6: a temporary failure")
}

impl Service {
    /// A service at `origin`, the switch origin `identity.json` names.
    pub fn new(
        origin: String,
        store: Store,
        keys: Arc<dyn KeyStore>,
        time: Arc<TrustedTime>,
        limits: Limits,
    ) -> Self {
        let failed_auth = FailedAuthentications::new(limits.auth_failures_per_source_per_min);
        Self {
            origin,
            store,
            keys,
            time,
            limits,
            failed_auth,
            reads_per_source: MinuteWindows::default(),
            reads_per_account: MinuteWindows::default(),
        }
    }

    /// The failed-authentication counts, for monitoring.
    pub fn failed_authentications(&self) -> &FailedAuthentications {
        &self.failed_auth
    }

    /// An answer signed with the operator key, at the time base (Switch wire 7.1).
    async fn operator_answer(
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

    async fn serve(&self, request: SwitchRequest) -> SwitchResponse {
        let base_ms = self.time.read().base_ms;
        let request_signature = wire_http::request_signature_of(
            request
                .headers
                .get(header::SIGNATURE)
                .and_then(|value| value.to_str().ok()),
        );
        if request.route.call == Call::Enroll {
            return self.enroll(&request, base_ms, request_signature).await;
        }
        let Some(account) = request.route.account.clone() else {
            let error = ApiError::not_found("no such route");
            return self
                .operator_answer(request_signature.as_ref(), base_ms, &error)
                .await;
        };
        let txn = match self.store.begin(&account).await {
            Ok(Some(txn)) => txn,
            Ok(None) => {
                let error = ApiError::not_found("no such account");
                return self
                    .operator_answer(request_signature.as_ref(), base_ms, &error)
                    .await;
            }
            Err(error) => {
                return self
                    .operator_answer(request_signature.as_ref(), base_ms, &store_error(&error))
                    .await;
            }
        };
        self.at_account(txn, &request, base_ms, request_signature)
            .await
    }

    /// The processing order at an existing account (Switch wire 7.3 steps 3 to 10).
    async fn at_account(
        &self,
        mut txn: AccountTxn,
        request: &SwitchRequest,
        base_ms: u64,
        request_signature: Option<[u8; 64]>,
    ) -> SwitchResponse {
        // The public read's answer signs the hash of the empty string as the request
        // signature, so it is the same for every reader (Switch wire 7.4.15).
        let signature = if request.route.call == Call::GetIdentity {
            None
        } else {
            request_signature.as_ref()
        };
        // Step 3: the identity's service time, which never goes back.
        let time_ms = txn.stamp(base_ms);
        let signer = match self.keys.signer(&txn.head().service_key).await {
            Ok(signer) => signer,
            Err(failure) => {
                tracing::error!(%failure, "an account's service key");
                let error = ApiError::unavailable("7.6: a temporary failure");
                return self.operator_answer(signature, base_ms, &error).await;
            }
        };
        let outcome = self
            .run_at_account(&mut txn, &signer, request, base_ms, time_ms)
            .await;
        let (answer, marked) = match outcome {
            Ok(done) => done,
            Err(error) => (Answer::error(&error), false),
        };
        // Durable, then answered (step 10). An answer is sent even when the request only
        // stamped the time, which must be durable before it is shown.
        let committed = if marked {
            txn.commit_marked(self.keys.as_ref())
                .await
                .map(|_| ())
                .map_err(|failure| {
                    tracing::error!(%failure, "commit");
                })
        } else {
            txn.commit().await.map(|_| ()).map_err(|failure| {
                tracing::error!(%failure, "commit");
            })
        };
        let answer = match committed {
            Ok(_) => answer,
            Err(()) => Answer::error(&ApiError::unavailable("7.6: a temporary failure")),
        };
        sign_answer(&signer, signature, time_ms, answer)
    }

    /// Steps 4 to 9 at an account; the answer, and whether its commit moves the key's mark.
    async fn run_at_account(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        request: &SwitchRequest,
        base_ms: u64,
        time_ms: u64,
    ) -> Result<(Answer, bool), ApiError> {
        let call = &request.route.call;
        let identity_key = txn.head().identity_key;
        let held = match txn.held_identity().await.map_err(|e| store_error(&e))? {
            Some(held) => Some(
                IdentityDoc::verify(&held.doc, &identity_key)
                    .map_err(|_| ApiError::unavailable("7.6: a temporary failure"))?,
            ),
            None => None,
        };
        let serving = names_this_service(held.as_ref(), &self.origin, &signer.public_key_bytes());

        // A serving account whose state is behind its key's mark fails stop (step 10).
        if serving {
            match txn.mark_check(self.keys.as_ref()).await {
                Ok(MarkCheck::Behind | MarkCheck::Fork) => {
                    return Err(ApiError::unavailable(
                        "7.3: the state is behind its service key's mark; a new generation is \
                         needed",
                    ));
                }
                Ok(_) => {}
                Err(failure) => {
                    tracing::error!(%failure, "the key's mark");
                    return Err(ApiError::unavailable("7.6: a temporary failure"));
                }
            }
        }

        if *call == Call::GetIdentity {
            return self
                .public_identity(txn, request, held.as_ref(), serving, time_ms)
                .map(|answer| (answer, false));
        }
        if !matches!(call, Call::PutIdentity) {
            return Err(ApiError::unavailable("7.4: this call isn't served yet"));
        }

        // Step 5: authenticate, after the network source's failed-authentication limit.
        if call.limits_failed_authentication()
            && let Err(retry_after) = self.failed_auth.check(request.source, base_ms)
        {
            return Err(ApiError::rate_limited(
                "9.4: too many failed authentications from this network source",
                retry_after,
            ));
        }
        let claimed = self
            .authenticate(&identity_key, request, base_ms)
            .inspect_err(|error| {
                if is_failed_authentication(error.code) {
                    self.record_failure(request, txn.head().id.clone());
                }
            })?;
        rules::require_signer(&claimed.caller)?;

        // Step 7: the staged gate.
        staged_gate(call, !serving)?;

        // Step 9.
        let answer = self
            .put_identity(txn, signer, request, held.as_ref(), time_ms)
            .await?;
        Ok(answer)
    }

    /// Decode and verify a request's signature (Switch wire 7.2). Only the signer is
    /// verified so far: no app is current before app records are served.
    fn authenticate(
        &self,
        account: &[u8; 32],
        request: &SwitchRequest,
        base_ms: u64,
    ) -> Result<Claimed, ApiError> {
        let claimed = decode_claim(account, &request.headers, base_ms)?;
        if claimed.caller == Caller::Signer {
            let target = RequestTarget {
                method: &request.method,
                path_and_query: &request.path_and_query,
                body: &request.body,
                origin: &self.origin,
            };
            wire_http::verify_request(
                &claimed.identity_key,
                &target,
                &claimed.headers,
                &claimed.signature,
            )
            .map_err(|_| {
                ApiError::new(
                    ErrorCode::BadSignature,
                    "7.1: the request signature doesn't verify",
                )
            })?;
        }
        Ok(claimed)
    }

    fn record_failure(&self, request: &SwitchRequest, account: String) {
        let claimed_identity = request
            .headers
            .get(header::IDENTITY)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let claimed_app = request
            .headers
            .get(header::APP)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let base_ms = self.time.peek().base_ms;
        self.failed_auth.record(
            request.source,
            (account, claimed_identity, claimed_app),
            base_ms,
        );
    }

    /// Sign the head of the account's chain as it will be committed, for an answer to the
    /// signer or an own app; `None` if the key's mark refuses it.
    async fn head(&self, txn: &AccountTxn, signer: &ServiceSigner) -> Option<SignedHead> {
        let head = txn.head();
        let mark = self.keys.mark(&head.service_key).await.ok()?;
        sign_head(signer, mark.as_ref(), &head.identity_key, &head.chain_tip()).ok()
    }
}

impl Handler for Service {
    fn handle(&self, request: SwitchRequest) -> HandlerFuture<'_> {
        Box::pin(self.serve(request))
    }

    fn refuse(&self, refusal: Refusal) -> HandlerFuture<'_> {
        Box::pin(async move {
            let base_ms = self.time.read().base_ms;
            let (headers, error) = match &refusal {
                Refusal::UnknownRoute { headers } => {
                    (headers, ApiError::not_found("no such route"))
                }
                Refusal::TooLarge { headers, cap, .. } => (headers, ApiError::body_too_large(*cap)),
            };
            let signature = wire_http::request_signature_of(
                headers
                    .get(header::SIGNATURE)
                    .and_then(|value| value.to_str().ok()),
            );
            self.operator_answer(signature.as_ref(), base_ms, &error)
                .await
        })
    }
}

/// The service key's public key, as the core's signer reports it.
trait PublicKeyBytes {
    fn public_key_bytes(&self) -> [u8; 32];
}

impl PublicKeyBytes for ServiceSigner {
    fn public_key_bytes(&self) -> [u8; 32] {
        pubky_switch_core::signing::Signs::public_key(self)
    }
}
