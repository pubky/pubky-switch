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
//! Served so far: `POST /v1/enroll`, `PUT /v1/{id}/identity`, the public
//! `GET /v1/{id}/identity`, `POST /v1/{id}/ops`, `GET /v1/{id}/feed`,
//! `PUT /v1/{id}/peers`, `GET /v1/{id}/claims/{claim_key}`, `GET /v1/{id}/apps` and
//! `POST /v1/{id}/apps/{app_id}/revoke`. Every other call is answered `503 unavailable`.

mod admission;
mod apps;
pub mod batch;
mod claims;
mod enroll;
mod feed;
mod identity;
mod peers;
pub mod rules;

pub use enroll::announced_limits;

use std::sync::Arc;

use axum::http::{HeaderName, HeaderValue};
use pubky_switch_core::{
    chain::SignedHead,
    enc::b64,
    http::{self as wire_http, RequestTarget, header},
    records::{AppCert, IdentityDoc},
    time::rfc3339,
};

use crate::{
    changes::ChangeHub,
    http::{
        Handler, HandlerFuture, Refusal, SwitchRequest, SwitchResponse,
        error::{ApiError, ErrorCode, is_failed_authentication},
        route::Call,
        source::NetworkSource,
    },
    keys::{KeyStore, MarkCheck, ServiceSigner, sign_head},
    limits::Limits,
    ratelimit::{FailedAuthentications, KeyedMinutes, MinuteWindows},
    store::{AccountTxn, Store, StoreError},
    time::TrustedTime,
};

use self::rules::{Caller, Claimed, decode_claim, names_this_service, staged_gate};

/// How many claims whose time has passed one request deletes at most (Switch wire 7.3
/// step 4); the rest go with the next requests.
const DUE_CLAIMS_PER_REQUEST: u64 = 64;

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
    operation_rate: KeyedMinutes<(String, [u8; 16])>,
    control_rate: KeyedMinutes<(String, [u8; 16])>,
    invite_rate: KeyedMinutes<(String, [u8; 32])>,
    stranger_rate: KeyedMinutes<String>,
    changes: Arc<ChangeHub>,
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
    /// Never cached: `Cache-Control: no-store`.
    no_store: bool,
    /// An answer whose body is read once the lock is gone.
    deferred: Option<Deferred>,
}

/// A read whose answer is built once the request's lock is gone.
#[derive(Debug)]
enum Deferred {
    /// A `GET /claims` answer's entries.
    Claim(claims::ClaimRead),
    /// A feed page, after its long-poll.
    Feed(Box<feed::FeedRead>),
}

impl Answer {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            body,
            head: None,
            retry_after: None,
            cacheable: false,
            no_store: false,
            deferred: None,
        }
    }

    fn error(error: &ApiError) -> Self {
        Self {
            status: error.status(),
            body: error.body(),
            head: None,
            retry_after: error.retry_after,
            cacheable: false,
            no_store: false,
            deferred: None,
        }
    }

    fn with_head(mut self, head: Option<SignedHead>) -> Self {
        self.head = head;
        self
    }
}

/// A refusal under the account's lock: the error, whether the commit moves the key's mark,
/// and whether the answer may carry the current head.
#[derive(Debug)]
struct Refused {
    error: ApiError,
    serving: bool,
    head: bool,
}

impl Refused {
    fn with_head(error: ApiError, serving: bool) -> Self {
        Self {
            error,
            serving,
            head: true,
        }
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
            operation_rate: KeyedMinutes::default(),
            control_rate: KeyedMinutes::default(),
            invite_rate: KeyedMinutes::default(),
            stranger_rate: KeyedMinutes::default(),
            changes: ChangeHub::new(),
        }
    }

    /// The hub that wakes waiting feed reads. Run a [`crate::changes::ChangeListener`]
    /// into it, so changes made by any instance wake them.
    pub fn changes(&self) -> Arc<ChangeHub> {
        self.changes.clone()
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
        // One reading gives both the time base and whether it is trusted, so nothing that
        // waits for trusted time runs on a base read without it.
        let reading = self.time.read();
        let base_ms = reading.base_ms;
        let due = reading.trusted.then_some(base_ms);
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
        // Step 2: the account, looked up without taking its lock (Switch wire 7.2 Order).
        let found = match self.store.lookup(&account).await {
            Ok(Some(found)) => found,
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
        let call = &request.route.call;
        let refused_early = |error: ApiError| {
            let signature = if *call == Call::GetIdentity {
                None
            } else {
                request_signature
            };
            async move {
                self.early_answer(&found, signature.as_ref(), base_ms, &error)
                    .await
            }
        };
        // Everything that needs no account state comes before the lock: the limits that
        // apply before authentication, the headers and the signature (Switch wire 7.2).
        let mut verified = None;
        let mut other = None;
        let caller = match call {
            Call::GetIdentity => {
                if let Err(error) = self.public_read_limits(&account, request.source, base_ms) {
                    return refused_early(error).await;
                }
                None
            }
            Call::PutIdentity => {
                match self.authenticate_signer(&account, &request, base_ms).await {
                    Ok((claimed, app)) => {
                        verified = app;
                        Some(claimed)
                    }
                    Err(error) => return refused_early(error).await,
                }
            }
            // The signer is verified here; an own app under the lock, with the key the
            // account holds for it (Switch wire 7.2).
            Call::Revoke(_) | Call::GetApps => {
                match self.authenticate_signer(&account, &request, base_ms).await {
                    Ok((claimed, app)) => {
                        verified = app;
                        Some(claimed)
                    }
                    Err(error) => return refused_early(error).await,
                }
            }
            Call::Ops | Call::GetClaim(_) | Call::Feed | Call::PutPeers => {
                let others = *call == Call::PutPeers;
                match self.authenticate_caller(&account, &request, base_ms, others) {
                    Ok(claimed) => {
                        // An own app's request is verified here too, so nothing unverified
                        // takes the lock (Switch wire 7.2 Order).
                        if let Caller::OwnApp(app) = &claimed.caller {
                            let batch = *call == Call::Ops;
                            match self
                                .verify_own_app(&account, &request, &claimed, app, batch, base_ms)
                                .await
                            {
                                Ok(app) => verified = Some(app),
                                Err(error) => {
                                    if is_failed_authentication(error.code) {
                                        self.record_failure(&request, account.clone());
                                    }
                                    return refused_early(error).await;
                                }
                            }
                        }
                        // An app of another identity, by the certificate it sends (Switch
                        // wire 7.2 checks 1, 2 and 4); check 3 comes under the lock.
                        if let Caller::OtherApp { app, .. } = &claimed.caller {
                            match self.verify_other_app(&request, &claimed, app) {
                                Ok(cert) => other = Some(cert),
                                Err(error) => {
                                    if is_failed_authentication(error.code) {
                                        self.record_failure(&request, account.clone());
                                    }
                                    return refused_early(error).await;
                                }
                            }
                        }
                        Some(claimed)
                    }
                    Err(error) => return refused_early(error).await,
                }
            }
            _ => {
                return refused_early(ApiError::unavailable("7.4: this call isn't served yet"))
                    .await;
            }
        };
        let txn = match self.store.begin(&account).await {
            Ok(Some(txn)) => txn,
            // Erased between the lookup and the lock.
            Ok(None) => {
                let error = ApiError::not_found("no such account");
                return self
                    .operator_answer(request_signature.as_ref(), base_ms, &error)
                    .await;
            }
            Err(error) => return refused_early(store_error(&error)).await,
        };
        let signature = if caller.is_some() {
            request_signature
        } else {
            // The public read's answer signs the hash of the empty string as the request
            // signature, so it is the same for every reader (Switch wire 7.4.15).
            None
        };
        self.at_account(
            txn,
            &request,
            base_ms,
            due,
            signature,
            caller.as_ref(),
            verified.as_ref(),
            other.as_ref(),
        )
        .await
    }

    /// An answer before the account's lock: signed with its service key, at the service time
    /// it last committed, which no answer it shows later is behind (Switch wire 7.3 step 3).
    async fn early_answer(
        &self,
        found: &crate::store::FoundAccount,
        request_signature: Option<&[u8; 64]>,
        base_ms: u64,
        error: &ApiError,
    ) -> SwitchResponse {
        match self.keys.signer(&found.service_key).await {
            Ok(signer) => sign_answer(
                &signer,
                request_signature,
                found.stamped_time_ms,
                Answer::error(error),
            ),
            Err(failure) => {
                tracing::error!(%failure, "an account's service key");
                self.operator_answer(request_signature, base_ms, error)
                    .await
            }
        }
    }

    /// The signer's authentication, before the account's lock (Switch wire 7.2 Order): the
    /// network source's failed-authentication limit, then the headers, the timestamp and
    /// the request signature, verified with the identity key `{id}` names. An own app's
    /// request is verified as at its own calls, then refused: `403 permission_missing`
    /// for a call only the signer makes (7.6).
    async fn authenticate_signer(
        &self,
        account: &str,
        request: &SwitchRequest,
        base_ms: u64,
    ) -> Result<(Claimed, Option<batch::VerifiedApp>), ApiError> {
        if let Err(retry_after) = self.failed_auth.check(request.source, base_ms) {
            return Err(ApiError::rate_limited(
                "9.4: too many failed authentications from this network source",
                retry_after,
            ));
        }
        let identity_key = pubky_switch_core::enc::pubky_key(account)
            .map_err(|_| ApiError::not_found("no such account"))?;
        let claimed = self
            .authenticate(&identity_key, request, base_ms)
            .inspect_err(|error| {
                if is_failed_authentication(error.code) {
                    self.record_failure(request, account.to_string());
                }
            })?;
        match &claimed.caller {
            // Verified as at its own calls, then refused under the lock, where the refusal
            // carries the head like every refusal to a verified own app (Switch wire 7.1).
            Caller::OwnApp(app) => {
                let verified = self
                    .verify_own_app(account, request, &claimed, app, false, base_ms)
                    .await
                    .inspect_err(|error| {
                        if is_failed_authentication(error.code) {
                            self.record_failure(request, account.to_string());
                        }
                    })?;
                Ok((claimed, Some(verified)))
            }
            // Its certificate first, in 7.2's order (`400`, `401`), then the refusal.
            Caller::OtherApp { app, .. } => {
                self.verify_other_app(request, &claimed, app)
                    .inspect_err(|error| {
                        if is_failed_authentication(error.code) {
                            self.record_failure(request, account.to_string());
                        }
                    })?;
                rules::require_signer(&claimed.caller)?;
                Ok((claimed, None))
            }
            Caller::Signer => Ok((claimed, None)),
        }
    }

    /// Verify an app of another identity by the certificate it sends (Switch wire 7.2):
    /// `Switch-Cert` present (`400`), verifying for `Switch-Identity` and naming
    /// `Switch-App` (`401 bad_signature`), and the request signed with its key (`401`).
    fn verify_other_app(
        &self,
        request: &SwitchRequest,
        claimed: &Claimed,
        app: &str,
    ) -> Result<AppCert, ApiError> {
        let bad = |why: &'static str| ApiError::new(ErrorCode::BadSignature, why);
        let text = claimed.headers.cert.as_deref().ok_or_else(|| {
            ApiError::bad_request("7.2: an app of another identity sends Switch-Cert")
        })?;
        let signed = pubky_switch_core::sig::SignedDoc::from_compact(text)
            .map_err(|_| bad("7.2: Switch-Cert isn't a signed certificate"))?;
        let cert = AppCert::verify(&signed, &claimed.identity_key)
            .map_err(|_| bad("7.2: Switch-Cert doesn't verify for Switch-Identity"))?;
        let named = pubky_switch_core::enc::app_id_decode(app)
            .map_err(|_| bad("7.2: Switch-Cert doesn't name Switch-App"))?;
        if cert.app_id() != named {
            return Err(bad("7.2: Switch-Cert doesn't name Switch-App"));
        }
        let target = RequestTarget {
            method: &request.method,
            path_and_query: &request.path_and_query,
            body: &request.body,
            origin: &self.origin,
        };
        wire_http::verify_request(
            &cert.signing_key(),
            &target,
            &claimed.headers,
            &claimed.signature,
        )
        .map_err(|_| bad("7.1: the request signature doesn't verify"))?;
        Ok(cert)
    }

    /// The public read's limits (Switch wire 9.4), before the account's lock: per network
    /// source per account, then the account's backstop, which a source's refused reads
    /// don't count against.
    fn public_read_limits(
        &self,
        account: &str,
        source: Option<NetworkSource>,
        base_ms: u64,
    ) -> Result<(), ApiError> {
        if let Some(source) = source
            && let Err(retry_after) = self.reads_per_source.take(
                (account.to_string(), source),
                self.limits.identity_reads_per_source_per_min,
                base_ms,
            )
        {
            return Err(ApiError::rate_limited(
                "9.4: public identity.json reads from this network source",
                retry_after,
            ));
        }
        if let Err(retry_after) = self.reads_per_account.take(
            account.to_string(),
            self.limits.identity_reads_per_min,
            base_ms,
        ) {
            return Err(ApiError::rate_limited(
                "9.4: public identity.json reads of this account",
                retry_after,
            ));
        }
        Ok(())
    }

    /// The processing order under the account's lock (Switch wire 7.3 steps 3 to 10), for a
    /// request already authenticated as the signer, or the public read.
    #[allow(clippy::too_many_arguments)]
    async fn at_account(
        &self,
        mut txn: AccountTxn,
        request: &SwitchRequest,
        base_ms: u64,
        due: Option<u64>,
        request_signature: Option<[u8; 64]>,
        caller: Option<&Claimed>,
        verified: Option<&batch::VerifiedApp>,
        other: Option<&AppCert>,
    ) -> SwitchResponse {
        let signature = request_signature.as_ref();
        // The time the account last committed, for an answer whose commit fails.
        let committed_ms = txn.head().stamped_time_ms;
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
        // Step 4, with trusted time only, for a caller that has verified: a bounded batch of
        // the claims whose time has passed goes, by the time base (Switch wire 7.3). It comes
        // before the endpoint, so a refusal doesn't undo it; an unauthenticated request, or
        // the public read, pays for none of it. A claim a request reads or writes goes when
        // it is due, whatever the batch reached.
        if let (Some(base), Some(_)) = (due, caller)
            && let Err(error) = txn
                .delete_due_claims(base, self.limits.max_claim_age_ms, DUE_CLAIMS_PER_REQUEST)
                .await
        {
            let _ = store_error(&error);
            let error = ApiError::unavailable("7.6: a temporary failure");
            return sign_answer(&signer, signature, committed_ms, Answer::error(&error));
        }
        // What the endpoint writes is undone if it is refused, whatever step refuses it: a
        // refusal commits the stamped time and nothing else, so no later request can build
        // on a write it was never answered for (step 10).
        let savepoint = match txn.savepoint().await {
            Ok(savepoint) => savepoint,
            Err(error) => {
                let _ = store_error(&error);
                let error = ApiError::unavailable("7.6: a temporary failure");
                return sign_answer(&signer, signature, committed_ms, Answer::error(&error));
            }
        };
        let (answer, marked) = match self
            .run_at_account(&mut txn, &signer, request, verified, other, due, time_ms)
            .await
        {
            Ok(done) => done,
            Err(Refused {
                error,
                serving,
                head,
            }) => {
                if let Err(failure) = txn.rollback_to(savepoint).await {
                    // Dropped uncommitted: nothing of the request stays, the stamp included.
                    tracing::error!(%failure, "rolling back a refused request");
                    let error = ApiError::unavailable("7.6: a temporary failure");
                    return sign_answer(&signer, signature, committed_ms, Answer::error(&error));
                }
                // Every 401 counts against the network source, whatever the step: a request
                // signature, an operation's, a first call's record (Switch wire 7.2, 9.4).
                if is_failed_authentication(error.code) {
                    self.record_failure(request, txn.head().id.clone());
                }
                // An error to the authenticated signer or own app carries the current head
                // (Switch wire 7.1), except where the key's mark refuses one.
                // Not to an app of another identity, which no answer shows the head.
                let own = caller.is_some_and(|c| !matches!(c.caller, Caller::OtherApp { .. }));
                let head = if own && head {
                    self.head(&txn, &signer).await
                } else {
                    None
                };
                (Answer::error(&error).with_head(head), serving)
            }
        };
        // A read answered once the lock is gone answers a refusal with the head this request
        // commits, as every refusal to a verified caller carries one (Switch wire 7.1).
        let txn_account = txn.head().id.clone();
        let fallback_head = if answer.deferred.is_some() {
            self.head(&txn, &signer).await
        } else {
            None
        };
        // Durable, then answered (step 10). An answer is sent even when the request only
        // stamped the time, which must be durable before it is shown. A serving account's
        // commit moves the key's mark to the head the answer carries.
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
        match committed {
            Ok(()) => {
                let mut answer = answer;
                match answer.deferred.take() {
                    Some(Deferred::Claim(read)) => match self.claim_body(&read).await {
                        Ok(body) => answer.body = body,
                        Err(error) => answer = Answer::error(&error).with_head(fallback_head),
                    },
                    Some(Deferred::Feed(read)) => {
                        return match self.feed_page(&read, &signer).await {
                            Ok((page, at)) => sign_answer(&signer, signature, at, page),
                            // Erased while the read waited: as an unknown account (step 2).
                            Err(feed::FeedStop::Gone) => {
                                let error = ApiError::not_found("no such account");
                                self.operator_answer(signature, base_ms, &error).await
                            }
                            // Its key retired while the read waited: never signed with it.
                            Err(feed::FeedStop::Retired) => {
                                let error = ApiError::unavailable("7.6: a temporary failure");
                                self.operator_answer(signature, base_ms, &error).await
                            }
                            Err(feed::FeedStop::Refused(refusal)) => {
                                // Every 401 counts against the network source (9.4).
                                if is_failed_authentication(refusal.error.code) {
                                    self.record_failure(request, txn_account.clone());
                                }
                                let head = if refusal.head { fallback_head } else { None };
                                sign_answer(
                                    &signer,
                                    signature,
                                    refusal.time_ms,
                                    Answer::error(&refusal.error).with_head(head),
                                )
                            }
                        };
                    }
                    None => {}
                }
                sign_answer(&signer, signature, time_ms, answer)
            }
            // Nothing committed, the stamp included: answer at the time last committed.
            Err(()) => sign_answer(
                &signer,
                signature,
                committed_ms,
                Answer::error(&ApiError::unavailable("7.6: a temporary failure")),
            ),
        }
    }

    /// Steps 4 to 9 under the lock; the answer, and whether its commit moves the key's mark:
    /// whenever the account served before the request or serves after it.
    // The request's verified callers and times, each from a different step of 7.3.
    #[allow(clippy::too_many_arguments)]
    async fn run_at_account(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        request: &SwitchRequest,
        verified: Option<&batch::VerifiedApp>,
        other: Option<&AppCert>,
        due: Option<u64>,
        time_ms: u64,
    ) -> Result<(Answer, bool), Refused> {
        let call = &request.route.call;
        let identity_key = txn.head().identity_key;
        let unavailable = |serving| {
            Refused::with_head(ApiError::unavailable("7.6: a temporary failure"), serving)
        };
        let held = match txn.held_identity().await {
            Ok(Some(held)) => Some(
                IdentityDoc::verify(&held.doc, &identity_key).map_err(|_| unavailable(false))?,
            ),
            Ok(None) => None,
            Err(error) => {
                let _ = store_error(&error);
                return Err(unavailable(false));
            }
        };
        let serving = names_this_service(held.as_ref(), &self.origin, &signer.public_key_bytes());

        // A serving account whose state is behind its key's mark fails stop, with no head
        // (step 10).
        if serving {
            match txn.mark_check(self.keys.as_ref()).await {
                Ok(MarkCheck::Behind | MarkCheck::Fork) => {
                    return Err(Refused {
                        error: ApiError::unavailable(
                            "7.3: the state is behind its service key's mark; a new \
                             generation is needed",
                        ),
                        serving: false,
                        head: false,
                    });
                }
                Ok(_) => {}
                Err(failure) => {
                    tracing::error!(%failure, "the key's mark");
                    return Err(Refused {
                        error: ApiError::unavailable("7.6: a temporary failure"),
                        serving: false,
                        head: false,
                    });
                }
            }
        }

        if *call == Call::GetIdentity {
            return self
                .public_identity(held.as_ref(), serving)
                .map(|answer| (answer, false))
                .map_err(|error| Refused::with_head(error, false));
        }

        // Step 5 comes before the staged gate: an own app is authenticated in full first.
        let stop = |stop: batch::Stop| match stop {
            batch::Stop::Refused(error) => Refused::with_head(error, serving),
            // Not authenticated: no head.
            batch::Stop::Unauthenticated(error) => Refused {
                error,
                serving,
                head: false,
            },
        };
        let writer = match self
            .own_app_writer(txn, held.as_ref(), verified, time_ms)
            .await
        {
            Ok(writer) => writer,
            Err(error) => return Err(stop(error)),
        };
        // Check 3 of an app of another identity, at the identity's service time (Switch wire
        // 7.2): its certificate hasn't expired.
        if let Some(cert) = other
            && cert.expired_at(time_ms)
        {
            return Err(Refused::with_head(
                ApiError::new(ErrorCode::CertExpired, "3.8: the certificate has expired"),
                serving,
            ));
        }
        // A call only the signer makes, from an own app that verified: refused with the head
        // (Switch wire 7.4, 7.1).
        if writer.is_some() && matches!(call, Call::PutIdentity | Call::Revoke(_) | Call::GetApps) {
            return Err(Refused::with_head(
                ApiError::new(
                    ErrorCode::PermissionMissing,
                    "7.4: a call only the signer may make",
                ),
                serving,
            ));
        }
        // Step 7: the staged gate. Step 9: the endpoint.
        staged_gate(call, !serving).map_err(|error| Refused::with_head(error, serving))?;
        if *call == Call::Ops {
            return match self
                .post_ops(
                    txn,
                    signer,
                    request,
                    held.as_ref(),
                    verified,
                    writer.as_ref(),
                    due,
                    time_ms,
                )
                .await
            {
                Ok(answer) => Ok((answer, serving)),
                Err(error) => Err(stop(error)),
            };
        }
        match call {
            Call::GetClaim(claim_key) => {
                return self
                    .get_claim(
                        txn,
                        signer,
                        held.as_ref(),
                        writer.as_ref(),
                        claim_key,
                        due,
                        time_ms,
                    )
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            Call::PutPeers => {
                let deliverer = match (writer.as_ref(), other) {
                    (Some(_), _) => peers::Deliverer::OwnApp,
                    (None, Some(cert)) => peers::Deliverer::OtherApp(cert),
                    (None, None) => {
                        return Err(Refused::with_head(
                            ApiError::new(
                                ErrorCode::PermissionMissing,
                                "7.4.5: apps deliver peers' documents",
                            ),
                            serving,
                        ));
                    }
                };
                let invite_code = request
                    .headers
                    .get(header::INVITE_CODE)
                    .and_then(|value| value.to_str().ok());
                return self
                    .put_peers(
                        txn,
                        signer,
                        held.as_ref(),
                        deliverer,
                        &request.body,
                        invite_code,
                        due.is_some(),
                        time_ms,
                    )
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            Call::GetApps => {
                return self
                    .get_apps(txn, signer, held.as_ref(), time_ms)
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            Call::Feed => {
                let head = txn.head();
                return self
                    .feed(
                        &head.id,
                        head.identity_key,
                        &head.service_key,
                        writer.as_ref(),
                        &request.route.query,
                        time_ms,
                    )
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            Call::Revoke(app_id) => {
                return self
                    .revoke(txn, signer, held.as_ref(), app_id, &request.body, time_ms)
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            _ => {}
        }
        let (answer, serves_after) = self
            .put_identity(txn, signer, request, held.as_ref(), time_ms)
            .await
            .map_err(|error| Refused::with_head(error, serving))?;
        Ok((answer, serving || serves_after))
    }

    /// Authenticate the caller of a call the signer or an own app makes, as far as needs no
    /// account state (Switch wire 7.2 Order): the network source's failed-authentication
    /// limit, the headers and the timestamp, and the signer's signature. An own app's
    /// signature is verified under the lock, with the key the account holds for it; an app
    /// of another identity is `403 not_admitted` (Switch wire 6.4 step 1), unless the call
    /// takes `others`.
    fn authenticate_caller(
        &self,
        account: &str,
        request: &SwitchRequest,
        base_ms: u64,
        others: bool,
    ) -> Result<Claimed, ApiError> {
        if let Err(retry_after) = self.failed_auth.check(request.source, base_ms) {
            return Err(ApiError::rate_limited(
                "9.4: too many failed authentications from this network source",
                retry_after,
            ));
        }
        let identity_key = pubky_switch_core::enc::pubky_key(account)
            .map_err(|_| ApiError::not_found("no such account"))?;
        let claimed = self
            .authenticate(&identity_key, request, base_ms)
            .inspect_err(|error| {
                if is_failed_authentication(error.code) {
                    self.record_failure(request, account.to_string());
                }
            })?;
        if let Caller::OtherApp { app, .. } = &claimed.caller
            && !others
        {
            // Authenticated first, by its certificate (`400`, `401`, Switch wire 7.2):
            // permissions and the endpoint's refusal come after authentication.
            self.verify_other_app(request, &claimed, app)
                .inspect_err(|error| {
                    if is_failed_authentication(error.code) {
                        self.record_failure(request, account.to_string());
                    }
                })?;
            // The feed is for own apps only (Switch wire 7.4.4).
            if request.route.call == Call::Feed {
                return Err(ApiError::new(
                    ErrorCode::PermissionMissing,
                    "7.4.4: only own apps read the feed",
                ));
            }
            return Err(ApiError::new(
                ErrorCode::NotAdmitted,
                "6.4: an app of another identity doesn't write here",
            ));
        }
        Ok(claimed)
    }

    /// Decode and verify a request's signature (Switch wire 7.2): the signer's with the
    /// identity key. An own app's is verified under the lock, by the endpoint.
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
