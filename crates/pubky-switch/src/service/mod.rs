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
//! `POST /v1/{id}/inbox`, `PUT /v1/{id}/peers`, `GET /v1/{id}/claims/{claim_key}`,
//! `GET /v1/{id}/apps`, `POST /v1/{id}/apps/{app_id}/revoke`, `GET /v1/{id}/directory`,
//! `GET` and `POST /v1/{id}/apps/{app_id}/keys`, `POST /v1/{id}/apps/{app_id}/leave`,
//! `PUT` and `GET /v1/{id}/handover`, and `POST /v1/{id}/erase`. Every other call is answered
//! `503 unavailable`.

mod admission;
mod allow;
mod app_keys;
mod apps;
pub mod batch;
mod claims;
mod connect;
mod directory;
mod enroll;
mod erase;
mod feed;
mod handover;
mod identity;
mod inbox;
mod keyed;
mod peers;
mod records;
mod recovery;
pub mod rules;
mod upload;

pub use recovery::AdmissionEnd;

pub use enroll::announced_limits;

use std::sync::Arc;

use pubky_switch_core::{
    chain::SignedHead,
    http::{self as wire_http, RequestTarget, header},
    records::{AppCert, IdentityDoc},
};

use crate::{
    changes::ChangeHub,
    http::{
        Handler, HandlerFuture, Refusal, SwitchRequest, SwitchResponse,
        error::{ApiError, ErrorCode, is_failed_authentication},
        route::Call,
        source::NetworkSource,
    },
    keys::{KeyId, KeyStore, MarkCheck, ServiceSigner},
    limits::Limits,
    ratelimit::{FailedAuthentications, KeyedWindows, MinuteWindows},
    store::{AccountTxn, Store, StoreError},
    time::TrustedTime,
};

use self::keyed::{NotKeyed, Proof};
use self::rules::{Caller, Claimed, decode_claim, names_this_service, staged_gate};

/// How many sweeps of owed keys a retried erasure of an account gone may run each minute, for
/// that account (Switch wire 7.4.16).
const ERASURE_SWEEPS_PER_MIN: u32 = 6;

/// How many claims whose time has passed one request deletes at most (Switch wire 7.3
/// step 4); the rest go with the next requests.
const DUE_CLAIMS_PER_REQUEST: u64 = 64;

/// How many of the documents chained before superseded documents were deleted one request
/// checks at most (Switch wire 7.5); the rest go with the next requests.
const OLD_DOCUMENTS_PER_REQUEST: u64 = 64;

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
    operation_rate: KeyedWindows<(String, [u8; 16])>,
    control_rate: KeyedWindows<(String, [u8; 16])>,
    invite_rate: KeyedWindows<(String, [u8; 32])>,
    stranger_rate: KeyedWindows<String>,
    /// Connect requests per sender identity, per account (Switch wire 9.4).
    connect_rate: KeyedWindows<(String, [u8; 32])>,
    sender_rate: KeyedWindows<(String, [u8; 32])>,
    sender_app_rate: KeyedWindows<(String, [u8; 16])>,
    notify_rate: KeyedWindows<(String, [u8; 32])>,
    /// Recovery uploads per app per hour (Switch wire 7.4.14).
    upload_rate: KeyedWindows<(String, [u8; 16])>,
    /// The `(account, app)` whose recovery upload's items are being judged before the lock:
    /// one at a time for each.
    upload_judging: parking_lot::Mutex<std::collections::HashSet<(String, [u8; 16])>>,
    /// Recovery uploads whose items were judged before the account's lock, and under it.
    judged_before_lock: std::sync::atomic::AtomicU64,
    judged_under_lock: std::sync::atomic::AtomicU64,
    /// The sweeps a retried erasure of an account gone may run (Switch wire 7.4.16): only
    /// the signer's, verified with the identity key, and bounded per account, since anyone
    /// who saw one can replay it within its timestamp window.
    erasure_sweeps: KeyedWindows<String>,
    changes: Arc<ChangeHub>,
    /// Where entry IDs come from: random, opaque to senders (Switch wire 1.7).
    entry_ids: EntryIds,
}

/// A source of entry IDs.
type EntryIds = Arc<dyn Fn() -> [u8; 16] + Send + Sync>;

/// A random entry ID; all zeros only if the system has no randomness, which the service's
/// own keys would have failed on first.
fn random_entry_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    let _ = getrandom::fill(&mut id);
    id
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
    /// The account's new service key, when the request changed it (Switch wire 3.3): the
    /// answer is signed with it, and the outgoing key is owed deleting.
    rekeyed: Option<KeyId>,
}

/// A read whose answer is built once the request's lock is gone.
#[derive(Debug)]
enum Deferred {
    /// A `GET /claims` answer's entries.
    Claim(claims::ClaimRead),
    /// A feed page, after its long-poll.
    Feed(Box<feed::FeedRead>),
    /// `GET /allow`'s lists, from the snapshot of the state under the lock.
    Allow(allow::AllowRead),
    /// A `GET /records` page, from the snapshot of the state under the lock.
    Records(Box<records::RecordsRead>),
    /// The account's erasure, once its answer is signed (Switch wire 7.4.16): not a read,
    /// but done in place of the commit.
    Erase,
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
            rekeyed: None,
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
            rekeyed: None,
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

/// An answer with no signature, when no key can sign: clients treat it as unauthenticated.
fn unsigned(error: &ApiError) -> SwitchResponse {
    SwitchResponse {
        status: error.status(),
        headers: Vec::new(),
        body: error.body(),
    }
}

/// How a store failure is answered: a temporary failure, or the account being busy.
/// What a request checked before the account's lock: signature work that needs no lock
/// (Switch wire 7.2 Order).
enum Prepared {
    /// A delivered `identity.json`, read and verified (Switch wire 7.4.5).
    Delivery(Box<Result<peers::Delivered, ApiError>>),
    /// A recovery upload's rate slot and its items, judged against the account as it stood
    /// before the lock (Switch wire 7.4.14).
    Upload(Box<upload::PreparedUpload>),
}

fn store_error(error: &StoreError) -> ApiError {
    tracing::warn!(%error, "storage");
    ApiError::unavailable("7.6: a temporary failure")
}

impl Service {
    /// A service at `origin`, the switch origin `identity.json` names, started: the keys an
    /// erasure left owed, by a key store failure or a crash, are deleted first (Switch wire
    /// 7.4.16). The service's binary starts it so.
    pub async fn start(
        origin: String,
        store: Store,
        keys: Arc<dyn KeyStore>,
        time: Arc<TrustedTime>,
        limits: Limits,
    ) -> Self {
        let service = Self::new(origin, store, keys, time, limits);
        let _ = service.sweep_erased_keys().await;
        service
    }

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
            operation_rate: KeyedWindows::default(),
            control_rate: KeyedWindows::default(),
            invite_rate: KeyedWindows::default(),
            stranger_rate: KeyedWindows::default(),
            connect_rate: KeyedWindows::default(),
            sender_rate: KeyedWindows::default(),
            sender_app_rate: KeyedWindows::default(),
            notify_rate: KeyedWindows::default(),
            upload_rate: KeyedWindows::hours(),
            upload_judging: parking_lot::Mutex::default(),
            judged_before_lock: std::sync::atomic::AtomicU64::new(0),
            judged_under_lock: std::sync::atomic::AtomicU64::new(0),
            erasure_sweeps: KeyedWindows::default(),
            changes: ChangeHub::new(),
            entry_ids: Arc::new(random_entry_id),
        }
    }

    /// The service with entry IDs from `ids`, for tests that replay the vectors' fixed ones.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn with_entry_ids(mut self, ids: impl Fn() -> [u8; 16] + Send + Sync + 'static) -> Self {
        self.entry_ids = Arc::new(ids);
        self
    }

    /// How many recovery uploads had their items judged before the account's lock, and how
    /// many under it, for tests of what a refused upload costs (Switch wire 7.4.14).
    #[cfg(any(test, feature = "test-util"))]
    pub fn upload_judgments(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (
            self.judged_before_lock.load(Relaxed),
            self.judged_under_lock.load(Relaxed),
        )
    }

    /// How many counts of its rate limits and of failed authentications the service keeps
    /// for `account`, for tests of what an erasure forgets (Switch wire 7.4.16, 9.4).
    #[cfg(any(test, feature = "test-util"))]
    pub fn counted_at(&self, account: &str) -> usize {
        self.failed_auth.counted_at(account)
            + self.reads_per_source.counted(|(at, _)| at == account)
            + self.reads_per_account.counted(|at| at == account)
            + self.operation_rate.counted(|(at, _)| at == account)
            + self.control_rate.counted(|(at, _)| at == account)
            + self.invite_rate.counted(|(at, _)| at == account)
            + self.stranger_rate.counted(|at| at == account)
            + self.connect_rate.counted(|(at, _)| at == account)
            + self.sender_rate.counted(|(at, _)| at == account)
            + self.sender_app_rate.counted(|(at, _)| at == account)
            + self.notify_rate.counted(|(at, _)| at == account)
            + self.upload_rate.counted(|(at, _)| at == account)
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
                // Only the identity's own signer, its request signed with the key `{id}`
                // names, waits on an erasure's keys: no one else learns anything from it. A
                // signer whose clock is off still waits, since it can't retry at the
                // service's time as it would at a hosted account (Switch wire 7.1).
                let signed = self.signed_by_identity(&account, &request, base_ms);
                let by_signer = signed.is_some();
                // A retried erasure whose `200` was withheld while its keys were owed: the
                // sweep runs again, only for a request within the time window, at most a few
                // times a minute for the account, since a verified request can be replayed
                // (Switch wire 7.4.16).
                if signed == Some(true)
                    && request.route.call == Call::Erase
                    && matches!(self.store.owes_erased_keys(&account).await, Ok(true))
                    && self
                        .erasure_sweeps
                        .take(account.clone(), ERASURE_SWEEPS_PER_MIN, base_ms)
                        .is_ok()
                {
                    let _ = self.sweep_erased_keys().await;
                }
                let error = self.no_such_account(&account, by_signer).await;
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
        let stamped_ms = found.stamped_time_ms;
        // The key the account had at the lookup, which an answer after a wait checks again.
        let looked_up_key = found.service_key.clone();
        let (account_ref, looked_up_ref, request_ref) = (&account, &looked_up_key, &request);
        let refused_early = |error: ApiError| {
            let signature = if *call == Call::GetIdentity {
                None
            } else {
                request_signature
            };
            async move {
                // A read of the account's state that finds no account: erased since the
                // lookup, its key maybe still in the store while owed. As for an account the
                // service doesn't host, never signed with that key (7.4.16).
                if error.code == ErrorCode::NotFound
                    && let Some(gone) = self
                        .no_longer_keyed(account_ref, looked_up_ref, false)
                        .await
                {
                    return self
                        .operator_answer(signature.as_ref(), base_ms, &gone)
                        .await;
                }
                self.early_answer(&found, request_ref, signature.as_ref(), base_ms, &error)
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
                match self
                    .authenticate_signer(&account, &request, base_ms, base_ms.max(stamped_ms))
                    .await
                {
                    Ok((claimed, app, cert)) => {
                        verified = app;
                        other = cert;
                        Some(claimed)
                    }
                    Err(error) => return refused_early(error).await,
                }
            }
            // The signer is verified here; an own app under the lock, with the key the
            // account holds for it (Switch wire 7.2).
            Call::Revoke(_)
            | Call::GetApps
            | Call::PutHandover
            | Call::GetHandover
            | Call::RecoveryAdmission
            | Call::Erase => {
                match self
                    .authenticate_signer(&account, &request, base_ms, base_ms.max(stamped_ms))
                    .await
                {
                    Ok((claimed, app, cert)) => {
                        verified = app;
                        other = cert;
                        Some(claimed)
                    }
                    Err(error) => return refused_early(error).await,
                }
            }
            Call::Ops
            | Call::GetClaim(_)
            | Call::Feed
            | Call::PutPeers
            | Call::Append
            | Call::Directory
            | Call::GetKeys(_)
            | Call::RequestKeys(_)
            | Call::Leave(_)
            | Call::RecoveryUpload
            | Call::GetRecord(_)
            | Call::ListRecords
            | Call::GetAllow
            | Call::PostConnect
            | Call::GetConnect
            | Call::DeleteConnect(_) => {
                match self.authenticate_caller(&account, &request, base_ms, base_ms.max(stamped_ms))
                {
                    Ok((claimed, cert)) => {
                        other = cert;
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
        // A delivered identity.json is read and verified before the lock too: signature work
        // needs no account state (Switch wire 7.2 Order). Its refusal is answered under the
        // lock, after the caller's own checks, with the head an own app's refusal carries.
        // So is a recovery upload's from an own app, which the endpoint takes under the lock
        // only if what it was judged against is unchanged (Switch wire 7.4.14).
        let prepared = match call {
            Call::PutPeers => {
                let other = match caller.as_ref().map(|claimed| &claimed.caller) {
                    Some(Caller::OtherApp { identity, .. }) => Some(*identity),
                    _ => None,
                };
                let account_key = pubky_switch_core::enc::pubky_key(&account).unwrap_or([0; 32]);
                Some(Prepared::Delivery(Box::new(peers::verify_delivery(
                    &request.body,
                    &account_key,
                    other.as_ref(),
                ))))
            }
            Call::RecoveryUpload => match verified.as_ref() {
                Some(app) => Some(Prepared::Upload(Box::new(
                    self.prepare_upload(&account, app, &request.body, base_ms.max(stamped_ms))
                        .await,
                ))),
                None => None,
            },
            _ => None,
        };
        // The reads that run after the lock on its snapshot take their account's turn and
        // their reader first, so the lock is never held waiting for one. Only an own app's
        // request whose signature verified takes them, one place per app: the signer's is
        // refused under the lock without a read, and an app of another identity's was
        // refused above. Whether the app is current and may read is judged under the lock.
        let reading_app = verified
            .as_ref()
            .filter(|_| matches!(call, Call::GetAllow | Call::ListRecords))
            .map(batch::VerifiedApp::app_id);
        let begun = if let Some(app) = reading_app {
            self.store.begin_reading(&account, app).await
        } else {
            self.store.begin(&account).await
        };
        let txn = match begun {
            Ok(Some(txn)) => txn,
            // Erased between the lookup and the lock: as for an account the service doesn't
            // host, the signer's answer held back while the erasure's keys are owed (7.4.16).
            Ok(None) => {
                let by_signer = caller.as_ref().is_some_and(|c| c.caller == Caller::Signer);
                let error = self.no_such_account(&account, by_signer).await;
                return self
                    .operator_answer(request_signature.as_ref(), base_ms, &error)
                    .await;
            }
            // The wait for the lock, or for a reader's turn, can outlast an erasure whose key
            // stays owed: never signed with the key looked up before it (7.4.16).
            Err(error) => {
                let by_signer = caller.as_ref().is_some_and(|c| c.caller == Caller::Signer);
                if let Some(error) = self
                    .no_longer_keyed(&account, &looked_up_key, by_signer)
                    .await
                {
                    return self
                        .operator_answer(request_signature.as_ref(), base_ms, &error)
                        .await;
                }
                return refused_early(store_error(&error)).await;
            }
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
            prepared.as_ref(),
        )
        .await
    }

    /// An answer before the account's lock: signed with its service key, at the service time
    /// it last committed, which no answer it shows later is behind (Switch wire 7.3 step 3),
    /// while the account still names that key; otherwise the operator's answer, for the
    /// identity's signer when the request's signature alone says so (7.4.16).
    async fn early_answer(
        &self,
        found: &crate::store::FoundAccount,
        request: &SwitchRequest,
        request_signature: Option<&[u8; 64]>,
        base_ms: u64,
        error: &ApiError,
    ) -> SwitchResponse {
        let signer = match self.keys.signer(&found.service_key).await {
            Ok(signer) => signer,
            Err(failure) => {
                tracing::error!(%failure, "an account's service key");
                return self
                    .operator_answer(request_signature, base_ms, error)
                    .await;
            }
        };
        let account = request.route.account.as_deref().unwrap_or_default();
        let proof = Proof::checked(account, &found.service_key);
        let answer = Answer::error(error);
        match self
            .try_sign_keyed(proof, &signer, request_signature, |_| {
                (answer, found.stamped_time_ms)
            })
            .await
        {
            Ok(signed) => signed,
            Err(not_keyed) => {
                let by_signer = not_keyed == NotKeyed::Gone
                    && self.signed_by_identity(account, request, base_ms).is_some();
                self.not_keyed_answer(
                    Some(account),
                    not_keyed,
                    by_signer,
                    request_signature,
                    base_ms,
                )
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
        service_time_ms: u64,
    ) -> Result<(Claimed, Option<batch::VerifiedApp>, Option<AppCert>), ApiError> {
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
                Ok((claimed, Some(verified), None))
            }
            // Its certificate first, in 7.2's order (`400`, `401`), then its expiry, then
            // the refusal (3.8).
            Caller::OtherApp { app, .. } => {
                let cert =
                    self.other_app_before_lock(account, request, &claimed, app, service_time_ms)?;
                Ok((claimed, None, Some(cert)))
            }
            Caller::Signer => Ok((claimed, None, None)),
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
        prepared: Option<&Prepared>,
    ) -> SwitchResponse {
        let signature = request_signature.as_ref();
        let by_signer = caller.is_some_and(|c| c.caller == Caller::Signer);
        // The time the account last committed, for an answer whose commit fails.
        let committed_ms = txn.head().stamped_time_ms;
        // Step 3: the identity's service time, which never goes back.
        let time_ms = txn.stamp(base_ms);
        // The key `signer` is loaded for: a request that changes the account's key answers a
        // failure with this one, whatever its transaction then holds (keyed.rs).
        let loaded_key = txn.head().service_key.clone();
        let signer = match self.keys.signer(&loaded_key).await {
            Ok(signer) => signer,
            Err(failure) => {
                tracing::error!(%failure, "an account's service key");
                let error = ApiError::unavailable("7.6: a temporary failure");
                return self.operator_answer(signature, base_ms, &error).await;
            }
        };
        // Step 4, with trusted time only, for a caller that has verified: a bounded batch of
        // the claims whose time has passed goes, by the time base (Switch wire 7.3), and a
        // bounded batch of the documents chained before superseded documents were deleted
        // is checked (Switch wire 7.5). It comes before the endpoint, so a refusal doesn't
        // undo it; an unauthenticated request, or the public read, pays for none of it. A
        // claim a request reads or writes goes when it is due, whatever the batch reached.
        if let (Some(base), Some(_)) = (due, caller)
            && let Err(error) = async {
                txn.delete_due_claims(base, self.limits.max_claim_age_ms, DUE_CLAIMS_PER_REQUEST)
                    .await?;
                txn.check_old_documents(OLD_DOCUMENTS_PER_REQUEST).await
            }
            .await
        {
            let _ = store_error(&error);
            let error = ApiError::unavailable("7.6: a temporary failure");
            return self
                .sign_after_failure(
                    txn,
                    &signer,
                    &loaded_key,
                    signature,
                    committed_ms,
                    Answer::error(&error),
                    base_ms,
                    by_signer,
                )
                .await;
        }
        // A read after the lock takes this transaction's snapshot now, outside the endpoint's
        // savepoint, which can't export one.
        if let Err(failure) = txn.prepare_snapshot().await {
            tracing::error!(%failure, "a snapshot for a read after the lock");
            let error = ApiError::unavailable("7.6: a temporary failure");
            return self
                .sign_after_failure(
                    txn,
                    &signer,
                    &loaded_key,
                    signature,
                    committed_ms,
                    Answer::error(&error),
                    base_ms,
                    by_signer,
                )
                .await;
        }
        // What the endpoint writes is undone if it is refused, whatever step refuses it: a
        // refusal commits the stamped time and nothing else, so no later request can build
        // on a write it was never answered for (step 10).
        let savepoint = match txn.savepoint().await {
            Ok(savepoint) => savepoint,
            Err(error) => {
                let _ = store_error(&error);
                let error = ApiError::unavailable("7.6: a temporary failure");
                return self
                    .sign_after_failure(
                        txn,
                        &signer,
                        &loaded_key,
                        signature,
                        committed_ms,
                        Answer::error(&error),
                        base_ms,
                        by_signer,
                    )
                    .await;
            }
        };
        let (answer, marked) = match self
            .run_at_account(
                &mut txn, &signer, request, verified, other, prepared, due, time_ms,
            )
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
                    return self
                        .sign_after_failure(
                            txn,
                            &signer,
                            &loaded_key,
                            signature,
                            committed_ms,
                            Answer::error(&error),
                            base_ms,
                            by_signer,
                        )
                        .await;
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
                // No answer to an erasure carries one, an error included (7.4.16).
                let head = if own && head && request.route.call != Call::Erase {
                    self.head(&txn, &signer).await
                } else {
                    None
                };
                // No head, so the commit moves no mark: an erasure's refusals commit only the
                // stamped time (7.4.16).
                let marked = serving && request.route.call != Call::Erase;
                (Answer::error(&error).with_head(head), marked)
            }
        };
        // A read answered once the lock is gone answers a refusal with the head this request
        // commits, as every refusal to a verified caller carries one (Switch wire 7.1).
        if matches!(answer.deferred, Some(Deferred::Erase)) {
            return self
                .finish_erasure(
                    txn,
                    &signer,
                    signature,
                    committed_ms,
                    time_ms,
                    base_ms,
                    answer,
                )
                .await;
        }
        let txn_account = txn.head().id.clone();
        let txn_key = txn.head().service_key.clone();
        // A request that changed the account's key is answered with the new one, the key the
        // account names once it commits (Switch wire 3.3).
        let rekeyed = answer.rekeyed.clone();
        let signer = match &rekeyed {
            Some(key) => match self.keys.signer(key).await {
                Ok(signer) => signer,
                Err(failure) => {
                    tracing::error!(%failure, "a new service key");
                    let error = ApiError::unavailable("7.6: a temporary failure");
                    return self.operator_answer(signature, base_ms, &error).await;
                }
            },
            None => signer,
        };
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
        // Every answer from here on is signed once the lock is gone: only inside a keyed
        // section, while the account still names the key the request loaded (keyed.rs), so
        // none is signed with it after an erasure or a change of the key (7.4.16).
        let proof = Proof::checked(&txn_account, &txn_key);
        // The outgoing key, retired by the change, goes once the change is durable.
        if rekeyed.is_some() && committed.is_ok() {
            let _ = self.sweep_erased_keys().await;
        }
        match committed {
            Ok(()) => {
                let mut answer = answer;
                match answer.deferred.take() {
                    Some(Deferred::Claim(read)) => match self.claim_body(&read).await {
                        Ok(body) => answer.body = body,
                        Err(error) => answer = Answer::error(&error).with_head(fallback_head),
                    },
                    Some(Deferred::Allow(read)) => match Self::allow_body(read).await {
                        Ok(body) => answer.body = body,
                        Err(error) => answer = Answer::error(&error).with_head(fallback_head),
                    },
                    // A page read from a snapshot taken before an erasure committed still reads
                    // its rows: its proof, not the read, keeps it from going out.
                    Some(Deferred::Records(read)) => match Self::records_body(*read).await {
                        Ok(body) => answer.body = body,
                        Err(error) => answer = Answer::error(&error).with_head(fallback_head),
                    },
                    Some(Deferred::Feed(read)) => {
                        return match self.feed_page(&read, &signer).await {
                            // The page's head is signed with its answer, inside the proof.
                            Ok(page) => match self
                                .try_sign_keyed(proof, &signer, signature, |signing| {
                                    page.answer(signing)
                                })
                                .await
                            {
                                Ok(signed) => signed,
                                Err(not_keyed) => {
                                    self.not_keyed_answer(
                                        Some(&txn_account),
                                        not_keyed,
                                        by_signer,
                                        signature,
                                        base_ms,
                                    )
                                    .await
                                }
                            },
                            // Erased while the read waited: as an unknown account (step 2).
                            Err(feed::FeedStop::Gone) => {
                                let error = self.no_such_account(&txn_account, by_signer).await;
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
                                let refusal = *refusal;
                                let signed = self
                                    .try_sign_keyed(proof, &signer, signature, |signing| {
                                        let head = match (&refusal.snapshot, refusal.head) {
                                            (Some(snapshot), _) => snapshot.sign(signing),
                                            (None, true) => fallback_head,
                                            (None, false) => None,
                                        };
                                        let answer = Answer::error(&refusal.error).with_head(head);
                                        (answer, refusal.time_ms)
                                    })
                                    .await;
                                match signed {
                                    Ok(signed) => signed,
                                    Err(not_keyed) => {
                                        self.not_keyed_answer(
                                            Some(&txn_account),
                                            not_keyed,
                                            by_signer,
                                            signature,
                                            base_ms,
                                        )
                                        .await
                                    }
                                }
                            }
                        };
                    }
                    // An erasure was answered before the commit, above.
                    Some(Deferred::Erase) | None => {}
                }
                self.sign_keyed(
                    proof, &signer, signature, time_ms, answer, base_ms, by_signer,
                )
                .await
            }
            // Nothing committed, the stamp included, or committed with the key's mark left
            // behind: answer at the time last committed, under the same proof, so a mark that
            // didn't move because an erasure deleted the key is never answered with it.
            Err(()) => {
                self.sign_keyed(
                    proof,
                    &signer,
                    signature,
                    committed_ms,
                    Answer::error(&ApiError::unavailable("7.6: a temporary failure")),
                    base_ms,
                    by_signer,
                )
                .await
            }
        }
    }

    /// Before an answer is signed, once the account's lock is gone, with `key`, the key the
    /// request loaded: `None` while `account` still names it. Otherwise the operator's answer
    /// to give instead: as for an account the service doesn't host, for one erased since
    /// (Switch wire 7.3 step 2, [`Self::no_such_account`] for the request's signer when
    /// `by_signer`), and `503` for one enrolled again under another key, or one that can't
    /// be looked up. So nothing is signed with a key after its account's erasure was
    /// answered (7.4.16).
    pub(super) async fn no_longer_keyed(
        &self,
        account: &str,
        key: &KeyId,
        by_signer: bool,
    ) -> Option<ApiError> {
        match self.store.lookup(account).await {
            Ok(Some(found)) if found.service_key == *key => None,
            Ok(None) => Some(self.no_such_account(account, by_signer).await),
            Ok(Some(_)) | Err(_) => Some(ApiError::unavailable("7.6: a temporary failure")),
        }
    }

    /// The operator's answer for an identity whose account the service doesn't host (Switch
    /// wire 7.3 step 2): `404`. To the identity's signer, `by_signer`, only once no key of an
    /// erased account of the identity is still owed; `503` while one is, or when that can't be
    /// read. The signer takes the `404` after a request in doubt as its erasure done, at a
    /// retry or at a read (7.4.16), so it waits until the erased account's key is gone. A key
    /// still owed from an earlier account of the same identity holds a later erasure's `404`
    /// back the same way. Anyone else gets the `404` at once, without the store read.
    async fn no_such_account(&self, account: &str, by_signer: bool) -> ApiError {
        if !by_signer {
            return ApiError::not_found("no such account");
        }
        match self.store.owes_erased_keys(account).await {
            Ok(false) => ApiError::not_found("no such account"),
            Ok(true) | Err(_) => ApiError::unavailable("7.6: a temporary failure"),
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
        prepared: Option<&Prepared>,
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
        // An erasure is exempt: its answer carries no head (step 10, 7.4.16). So is "the
        // `PUT /identity` that delivers the next generation naming that key", the pending key
        // an enrollment answered (step 10, 3.3), here only a provider loss's, the one
        // generation change served: the new generation is the way out, and nothing is signed
        // with the outgoing key on its path (`recover_in_place`). Every check of the delivery
        // still runs; a delivery that is refused all the same is answered as any other
        // request in this state.
        let behind_mark = || Refused {
            error: ApiError::unavailable(
                "7.3: the state is behind its service key's mark; a new generation is needed",
            ),
            serving: false,
            head: false,
        };
        let mut behind = false;
        if serving && *call != Call::Erase {
            match txn.mark_check(self.keys.as_ref()).await {
                Ok(MarkCheck::Behind | MarkCheck::Fork) => {
                    // The signer's own delivery only: an own app or another identity's has
                    // no app or certificate of its own here.
                    let by_signer = verified.is_none() && other.is_none();
                    if !(*call == Call::PutIdentity
                        && by_signer
                        && self.delivers_a_recovery(txn, request, held.as_ref()).await)
                    {
                        return Err(behind_mark());
                    }
                    behind = true;
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
        // 7.2): its certificate hasn't expired. The refusal commits this time and is signed
        // at it. Then, at a call it doesn't make, the refusal it would have got before the
        // lock (3.8: expiry first).
        if let Some(cert) = other {
            if cert.expired_at(time_ms) {
                return Err(Refused::with_head(
                    ApiError::new(ErrorCode::CertExpired, "3.8: the certificate has expired"),
                    serving,
                ));
            }
            if !rules::takes_other_apps(call) {
                return Err(Refused::with_head(rules::other_app_refusal(call), serving));
            }
        }
        // A call only the signer makes, from an own app that verified: refused with the head
        // (Switch wire 7.4, 7.1).
        if writer.is_some()
            && matches!(
                call,
                Call::PutIdentity
                    | Call::Revoke(_)
                    | Call::GetApps
                    | Call::PutHandover
                    | Call::RecoveryAdmission
                    | Call::Erase
            )
        {
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
            Call::GetAllow => {
                return self
                    .get_allow(txn, signer, writer.as_ref(), time_ms)
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            Call::GetRecord(key) => {
                return self
                    .get_record(txn, signer, writer.as_ref(), key)
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            Call::ListRecords => {
                let query = request.route.query.as_ref().map_err(|_| {
                    Refused::with_head(
                        ApiError::bad_request("7.1: the query doesn't decode"),
                        serving,
                    )
                })?;
                return self
                    .list_records(txn, signer, writer.as_ref(), query)
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
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
            Call::Append => {
                let appender = match (writer.as_ref(), other) {
                    (Some(cert), _) => inbox::Appender::OwnApp(cert),
                    (None, Some(cert)) => inbox::Appender::OtherApp(cert),
                    (None, None) => {
                        return Err(Refused::with_head(
                            ApiError::new(
                                ErrorCode::PermissionMissing,
                                "7.4.3: apps append; the signer doesn't",
                            ),
                            serving,
                        ));
                    }
                };
                let query = request.route.query.as_ref().map_err(|_| {
                    Refused::with_head(
                        ApiError::bad_request("7.1: the query doesn't decode"),
                        serving,
                    )
                })?;
                let invite_code = request
                    .headers
                    .get(header::INVITE_CODE)
                    .and_then(|value| value.to_str().ok());
                return self
                    .append(
                        txn,
                        signer,
                        held.as_ref(),
                        appender,
                        &request.body,
                        query,
                        invite_code,
                        due.is_some(),
                        time_ms,
                    )
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            Call::PostConnect => {
                // Apps of another identity ask to connect; the account's own don't.
                let Some(cert) = other.filter(|_| writer.is_none()) else {
                    return Err(Refused::with_head(
                        ApiError::new(
                            ErrorCode::PermissionMissing,
                            "7.4.7: apps of another identity ask to connect",
                        ),
                        serving,
                    ));
                };
                return self
                    .post_connect(txn, held.as_ref(), cert, time_ms)
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            Call::GetConnect => {
                return self
                    .get_connect(txn, signer, held.as_ref(), writer.as_ref())
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            Call::DeleteConnect(pubky) => {
                return self
                    .delete_connect(txn, signer, writer.as_ref(), pubky)
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            Call::Directory => {
                let reader = match (writer.as_ref(), other) {
                    (Some(_), _) => directory::Reader::OwnApp,
                    (None, Some(cert)) => directory::Reader::OtherApp(cert),
                    (None, None) => {
                        return Err(Refused::with_head(
                            ApiError::new(
                                ErrorCode::PermissionMissing,
                                "7.4.10: apps read the directory; the signer doesn't",
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
                    .directory(
                        txn,
                        signer,
                        held.as_ref(),
                        reader,
                        invite_code,
                        due.is_some(),
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
                let delivered = match prepared {
                    Some(Prepared::Delivery(delivered)) => Some(&**delivered),
                    _ => None,
                };
                let delivered = delivered
                    .ok_or_else(|| {
                        Refused::with_head(
                            ApiError::unavailable("7.6: a temporary failure"),
                            serving,
                        )
                    })?
                    .as_ref()
                    .map_err(|error| Refused::with_head(error.clone(), serving))?;
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
                        delivered,
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
                let head = txn.head().clone();
                let answer = self
                    .feed(
                        &head.id,
                        head.identity_key,
                        &head.service_key,
                        writer.as_ref(),
                        &request.route.query,
                        time_ms,
                    )
                    .map_err(|error| Refused::with_head(error, serving))?;
                // The reader's feed read ends its lagging mark (Switch wire 7.4.4).
                if let Some(reader) = writer.as_ref() {
                    txn.set_lagging(&[reader.app_id()], false)
                        .await
                        .map_err(|error| Refused::with_head(store_error(&error), serving))?;
                }
                return Ok((answer, serving));
            }
            Call::Leave(app_id) => {
                // Only the app itself leaves (Switch wire 7.4.12).
                let Some(caller) = writer.as_ref() else {
                    return Err(Refused::with_head(
                        ApiError::new(
                            ErrorCode::PermissionMissing,
                            "7.4.12: only the app itself leaves",
                        ),
                        serving,
                    ));
                };
                return self
                    .leave(
                        txn,
                        signer,
                        held.as_ref(),
                        caller,
                        app_id,
                        &request.body,
                        due.is_some(),
                        time_ms,
                    )
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            Call::RecoveryUpload => {
                // An own app uploads (Switch wire 7.4.14); a staged service's uploads, in a
                // cooperative move, aren't served yet.
                let Some(caller) = writer.as_ref() else {
                    return Err(Refused::with_head(
                        ApiError::new(ErrorCode::PermissionMissing, "7.4.14: an own app uploads"),
                        serving,
                    ));
                };
                if !serving {
                    return Err(Refused::with_head(
                        ApiError::unavailable("7.4.14: this stage isn't served yet"),
                        serving,
                    ));
                }
                let prepared = match prepared {
                    Some(Prepared::Upload(prepared)) => Some(&**prepared),
                    _ => None,
                };
                return self
                    .recovery_upload(
                        txn,
                        signer,
                        held.as_ref(),
                        caller,
                        &request.body,
                        prepared,
                        time_ms,
                    )
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            Call::GetKeys(app_id) | Call::RequestKeys(app_id) => {
                // Only the app itself; the signer stores the parts with `key_bundle.put`
                // (Switch wire 7.4.11).
                let Some(caller) = writer.as_ref() else {
                    return Err(Refused::with_head(app_keys::only_that_app(), serving));
                };
                let keys_call = if matches!(call, Call::GetKeys(_)) {
                    app_keys::KeysCall::Read
                } else {
                    app_keys::KeysCall::Request
                };
                return self
                    .app_keys(
                        txn,
                        signer,
                        caller,
                        app_id,
                        &request.body,
                        keys_call,
                        time_ms,
                    )
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            Call::Erase => {
                return Self::erase_answer(
                    signer,
                    &request.body,
                    held.as_ref().map(IdentityDoc::hash),
                )
                .map(|answer| (answer, false))
                .map_err(|error| Refused {
                    error,
                    serving,
                    head: false,
                });
            }
            Call::PutHandover => {
                return self
                    .put_handover(txn, signer, held.as_ref(), &request.body, time_ms)
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            Call::GetHandover => {
                // The signer, or the own app it is for (Switch wire 7.4.17). An app of another
                // identity was refused above; refused here too, so the read fails closed.
                let reader = match (writer.as_ref(), other) {
                    (Some(app), _) => handover::Reader::OwnApp(app),
                    (None, None) => handover::Reader::Signer,
                    (None, Some(_)) => {
                        return Err(Refused::with_head(rules::other_app_refusal(call), serving));
                    }
                };
                return self
                    .get_handover(txn, signer, reader)
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            Call::RecoveryAdmission => {
                return self
                    .recovery_admission(txn, signer, &request.body, time_ms)
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            Call::Revoke(app_id) => {
                return self
                    .revoke(
                        txn,
                        signer,
                        held.as_ref(),
                        app_id,
                        &request.body,
                        due.is_some(),
                        time_ms,
                    )
                    .await
                    .map(|answer| (answer, serving))
                    .map_err(|error| Refused::with_head(error, serving));
            }
            _ => {}
        }
        let (answer, serves_after) = self
            .put_identity(txn, signer, request, held.as_ref(), due.is_some(), time_ms)
            .await
            .map_err(|error| {
                if behind {
                    behind_mark()
                } else {
                    Refused::with_head(error, serving)
                }
            })?;
        Ok((answer, serving || serves_after))
    }

    /// Whether `request`, a `PUT /identity` at a serving account, delivers a provider loss's
    /// next generation (Switch wire 3.3, 7.3 step 10): a document the identity signed, at the
    /// held version's generation plus one, naming this service's origin and the account's
    /// pending key, with `recovery_from` the held generation. The delivery's other checks
    /// come in `put_identity`.
    async fn delivers_a_recovery(
        &self,
        txn: &mut AccountTxn,
        request: &SwitchRequest,
        held: Option<&IdentityDoc>,
    ) -> bool {
        let Some(held) = held else {
            return false;
        };
        let Ok(delivery) = pubky_switch_core::http::IdentityDelivery::parse(&request.body) else {
            return false;
        };
        let identity = txn.head().identity_key;
        let Ok(doc) = IdentityDoc::verify(&delivery.identity, &identity) else {
            return false;
        };
        let Ok(Some(pending)) = txn.pending_key().await else {
            return false;
        };
        let Ok(pending) = self.keys.public_key(&pending).await else {
            return false;
        };
        held.generation().checked_add(1) == Some(doc.generation())
            && doc.body().recovery_from == Some(held.generation())
            && doc.inbox().url == self.origin
            && doc.inbox().service_key == pending
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
        service_time_ms: u64,
    ) -> Result<(Claimed, Option<AppCert>), ApiError> {
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
        let cert = match &claimed.caller {
            Caller::OtherApp { app, .. } => Some(self.other_app_before_lock(
                account,
                request,
                &claimed,
                app,
                service_time_ms,
            )?),
            _ => None,
        };
        Ok((claimed, cert))
    }

    /// An app of another identity before the lock (Switch wire 7.2): its certificate
    /// checked (`400`, `401`, counted against the network source), then the call. A call
    /// it makes goes on, its expiry judged under the lock. At any other call it is refused
    /// here (`rules::other_app_refusal`), unless its certificate has expired by the
    /// identity's service time as far as it is known before the lock: expiry comes before
    /// that refusal (3.8), so it goes on to the lock too, where its `403 cert_expired` is
    /// judged and signed at the time the refusal commits.
    fn other_app_before_lock(
        &self,
        account: &str,
        request: &SwitchRequest,
        claimed: &Claimed,
        app: &str,
        service_time_ms: u64,
    ) -> Result<AppCert, ApiError> {
        let cert = self
            .verify_other_app(request, claimed, app)
            .inspect_err(|error| {
                if is_failed_authentication(error.code) {
                    self.record_failure(request, account.to_string());
                }
            })?;
        let call = &request.route.call;
        if rules::takes_other_apps(call) || cert.expired_at(service_time_ms) {
            return Ok(cert);
        }
        Err(rules::other_app_refusal(call))
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

    /// Whether `request` comes from the signer of the identity `account` names: `Some` when
    /// its headers and request signature verify with that identity key, without
    /// `Switch-App`, over its own `Switch-Timestamp` whatever its skew (Switch wire 7.1);
    /// `Some(true)` when that timestamp is also within 5 minutes of the service's time.
    /// Checked for an account the service doesn't host, so it records no failed
    /// authentication: the answer is the same either way.
    ///
    /// The skew doesn't count here: at a hosted account a signer whose clock is off gets a
    /// signed `stale_timestamp` and retries at the service's time, which the operator's
    /// answer can't tell it. The cost: anyone who saw one signer request can replay it, later,
    /// to learn that the identity's erased account still owes a key here.
    fn signed_by_identity(
        &self,
        account: &str,
        request: &SwitchRequest,
        base_ms: u64,
    ) -> Option<bool> {
        let identity_key = pubky_switch_core::enc::pubky_key(account).ok()?;
        let text = request.headers.get(header::TIMESTAMP)?.to_str().ok()?;
        let signed_at = pubky_switch_core::time::parse_rfc3339(text).ok()?;
        let claimed = self.authenticate(&identity_key, request, signed_at).ok()?;
        (claimed.caller == Caller::Signer).then(|| rules::check_timestamp(text, base_ms).is_ok())
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
