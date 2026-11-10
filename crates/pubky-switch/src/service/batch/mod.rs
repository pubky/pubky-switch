//! `POST /v1/{id}/ops` (Switch wire 6.4): an own app's or the signer's batch.
//!
//! The endpoint runs under the account's lock. It authenticates an own app (Switch wire 7.2),
//! verifies the batch, answers a retry from its batch record, then loads the state the batch
//! can touch into an [`OpsState`] and applies the core's rules to it ([`apply::apply`]). Only
//! a batch that passes everything is chained: one chain item and one transition proof per
//! signed operation, then every change the batch made, all in the request's transaction.
//!
//! The pure parts, callable without HTTP or PostgreSQL, are [`state::OpsState`] with
//! [`state::Needs`], and [`apply::apply`].

pub mod apply;
pub mod state;

use pubky_switch_core::{
    chain::{ItemType, ProofBody, TransitionProof},
    enc::{app_id_bytes, unb64_array, zbase32_decode},
    http::{self as wire_http, RequestTarget},
    ops::{
        BatchEffect, BatchRecord, OpKind, OpsRequest, Refusal, RetryCheck, SignedOp, batch_effect,
        check_batch, depends_on_time, ops_hash, retry_check,
    },
    records::{AppCert, AppRecord, IdentityDoc, ReceiveKeyRecord},
    sig::SignedDoc,
};
use serde_json::json;

use self::{
    apply::{Applied, Batch},
    state::{HeldApp, HeldInvite, HeldPart, HeldRecord, ListEntry, Needs, OpsState, Totals},
};
use super::{Answer, Service, rules::Claimed, store_error};
use crate::{
    http::{
        SwitchRequest,
        error::{ApiError, ErrorCode},
    },
    keys::ServiceSigner,
    store::{
        AccountTxn, ListName, NewChainItem, StoreError, StoredApp, StoredBundlePart,
        StoredClaimEntry, StoredInvite, StoredListEntry, StoredRecord,
    },
};

/// A refusal of the core's rules as the service answers it (Switch wire 7.6).
pub fn refused(refusal: Refusal) -> ApiError {
    let mut error = ApiError::new(refusal.code, refusal.reason);
    error.current = refusal.current;
    error
}

/// Why a batch stops: an answer the caller gets, after or before its authentication.
#[derive(Debug)]
pub(super) enum Stop {
    /// Before the caller is authenticated: no head, and a `401` counts as a failed
    /// authentication.
    Unauthenticated(ApiError),
    /// After it.
    Refused(ApiError),
}

impl From<ApiError> for Stop {
    fn from(error: ApiError) -> Self {
        Stop::Refused(error)
    }
}

impl From<Refusal> for Stop {
    fn from(refusal: Refusal) -> Self {
        Stop::Refused(refused(refusal))
    }
}

fn storage(error: &StoreError) -> Stop {
    Stop::Refused(store_error(error))
}

fn temporary() -> ApiError {
    ApiError::unavailable("7.6: a temporary failure")
}

fn bad_signature(why: &str) -> ApiError {
    ApiError::new(ErrorCode::BadSignature, why.to_string())
}

fn not_current(why: &str) -> ApiError {
    ApiError::new(ErrorCode::NotCurrent, why.to_string())
}

/// An own app's batch, verified before the account's lock (Switch wire 7.2 Order).
#[derive(Clone, Debug)]
pub(super) struct VerifiedApp {
    /// The calling app.
    app: [u8; 16],
    /// The signing key its request verified with.
    key: [u8; 32],
    /// A `POST /ops` body, parsed.
    parsed: Option<OpsRequest>,
}

impl VerifiedApp {
    /// An app whose request, not a batch, verified with `key`: a read, checked again later
    /// against the state it reads.
    pub(super) fn reading(app: [u8; 16], key: [u8; 32]) -> Self {
        Self {
            app,
            key,
            parsed: None,
        }
    }

    /// The App ID.
    pub(super) fn app_id(&self) -> [u8; 16] {
        self.app
    }
}

/// The checks of an own app whose request verified with `verified.key` (Switch wire 7.2 "Own
/// app", 3.8), over what the account holds: `stored`, its row, and `kept`, whether its App ID
/// is kept for good. They come in the order of 7.2: the certificate it is checked against
/// (the first call's record's, or a stored renewed one the newest `identity.json` lists, else
/// its record's), which has the key the request verified with; checks 1 to 3 on it; not
/// revoked or departed, and the certificate listed or in an open renewal (check 5); then
/// check 6 on the record it holds.
///
/// # Errors
///
/// A [`Stop`]: `401 bad_signature` before the app is known to be its key's, then `403
/// cert_expired` or `403 not_current`.
pub(super) fn check_own_app(
    identity: &[u8; 32],
    held: Option<&IdentityDoc>,
    stored: Option<&StoredApp>,
    kept: bool,
    verified: &VerifiedApp,
    time_ms: u64,
) -> Result<AppCert, Stop> {
    let app = &verified.app;
    let changed_key = || {
        Stop::Unauthenticated(bad_signature(
            "7.2: the key the request verified with isn't the app's",
        ))
    };
    let first_call = verified
        .parsed
        .as_ref()
        .and_then(|parsed| first_app_put(parsed, app));
    let (cert, record) = match first_call {
        // The first call: the record and its certificate verify.
        Some(record) => {
            let record = AppRecord::verify(&record, identity).map_err(|_| {
                Stop::Unauthenticated(bad_signature("7.2: the first call's app record"))
            })?;
            if record.cert().app_id() != *app {
                return Err(Stop::Unauthenticated(bad_signature(
                    "7.2: the record names another app",
                )));
            }
            (record.cert().clone(), None)
        }
        None => {
            let held_app = stored
                .map(|stored| held_app(stored, identity))
                .transpose()
                .map_err(|e| storage(&e))?
                .filter(|a| a.record.is_some())
                .ok_or_else(changed_key)?;
            let mut state = OpsState::new(*identity, 0, 0, time_ms);
            state.doc = held.cloned();
            state.apps.insert(*app, held_app.clone());
            let cert = state.checked_cert(app).cloned().ok_or_else(changed_key)?;
            (cert, held_app.record)
        }
    };
    if cert.signing_key() != verified.key {
        return Err(changed_key());
    }
    // Checks 1 to 3 on that certificate: it verified for the identity and names the app; it
    // hasn't expired.
    if cert.identity() != *identity || cert.app_id() != *app {
        return Err(Stop::Unauthenticated(bad_signature(
            "3.8: the certificate isn't the caller's",
        )));
    }
    if cert.expired_at(time_ms) {
        return Err(Stop::Refused(ApiError::new(
            ErrorCode::CertExpired,
            "3.8: the certificate has expired",
        )));
    }
    // Not revoked or departed, and the certificate listed or in an open renewal.
    if kept {
        return Err(Stop::Refused(not_current(
            "7.2: the app is revoked or departed",
        )));
    }
    if !held.is_some_and(|doc| doc.current_now(app, &cert.hash())) {
        return Err(Stop::Refused(not_current(
            "3.8: the newest identity.json doesn't list the certificate",
        )));
    }
    // Check 6 on the record the service holds.
    if let Some(record) = record
        && !record.carries(&cert)
    {
        return Err(Stop::Refused(not_current(
            "3.8: the held record doesn't carry the certificate",
        )));
    }
    Ok(cert)
}

/// The app record of an own app's first call (Switch wire 7.2): the batch's first `app.put`
/// naming the caller.
fn first_app_put(request: &OpsRequest, app: &[u8; 16]) -> Option<SignedDoc> {
    request
        .signed()
        .filter_map(|doc| SignedOp::peek(doc).ok())
        .find_map(|op| match (&op.body().kind, op.body().app_id) {
            (OpKind::AppPut { record }, Some(id)) if &id == app => Some(record.clone()),
            _ => None,
        })
}

/// An app record's `signing_key`, read before the record is verified (Switch wire 7.2).
fn record_signing_key(record: &SignedDoc) -> Option<[u8; 32]> {
    let body: serde_json::Value = serde_json::from_slice(&record.body_bytes().ok()?).ok()?;
    unb64_array::<32>(body.get("signing_key")?.as_str()?).ok()
}

/// Build the state a batch is checked against from what `txn` holds.
async fn load_state(
    txn: &mut AccountTxn,
    held: Option<&IdentityDoc>,
    ops: &[SignedOp],
    writer: Option<&[u8; 16]>,
    due: Option<(u64, u64)>,
    now: u64,
) -> Result<OpsState, StoreError> {
    let head = txn.head().clone();
    let identity = head.identity_key;
    let mut state = OpsState::new(identity, head.generation, head.last_seq, now);
    state.doc = held.cloned();
    for app in txn.apps().await? {
        state.apps.insert(app.app_id, held_app(&app, &identity)?);
    }
    state.kept = txn.kept_app_ids().await?.into_iter().collect();
    let needs = Needs::of(ops);
    let named_kids: Vec<[u8; 8]> = needs.kids.iter().copied().collect();
    state.kids = txn
        .registered_kids(&named_kids)
        .await?
        .into_iter()
        .collect();
    (state.directory_version, state.apps_version) = txn.directory_versions().await?;
    for target in &needs.targets {
        let parts = txn.bundle_parts(target).await?;
        state.parts.insert(
            *target,
            parts
                .into_iter()
                .map(|part| held_part(&part))
                .collect::<Result<_, _>>()?,
        );
    }
    let record_keys: Vec<[u8; 32]> = needs.records.iter().copied().collect();
    for record in txn.records(&record_keys).await? {
        state.records.insert(
            record.state.key,
            HeldRecord {
                state: record.state,
                value_bytes: record.value_bytes,
                writer: record.writer,
                cert: record.cert,
                op: record.op,
                proof: Some(record.proof),
            },
        );
    }
    let claim_keys: Vec<[u8; 32]> = needs.claims.iter().copied().collect();
    state.claims = txn.claims(&claim_keys).await?.into_iter().collect();
    // A claim the batch names that is due goes now, whatever step 4's batch reached
    // (Switch wire 7.3 step 4): `due` is the trusted time base and `max_claim_age_ms`.
    if let Some((base, max_age)) = due {
        let gone: Vec<[u8; 32]> = state
            .claims
            .iter()
            .filter(|(_, claim)| claim.deletable(Some(base), max_age))
            .map(|(key, _)| *key)
            .collect();
        for key in gone {
            txn.delete_claim(&key).await?;
            state.claims.remove(&key);
        }
    }
    let pubkys: Vec<[u8; 32]> = needs.pubkys.iter().copied().collect();
    let entries = |list: Vec<StoredListEntry>| {
        list.into_iter()
            .map(|e| {
                (
                    e.pubky,
                    ListEntry {
                        written_by: e.written_by,
                        at: e.at_ms,
                    },
                )
            })
            .collect()
    };
    state.contacts = entries(txn.list_entries(ListName::Contact, &pubkys).await?);
    state.conversations = entries(txn.list_entries(ListName::Conversation, &pubkys).await?);
    state.deny = entries(txn.list_entries(ListName::Deny, &pubkys).await?);
    let hashes: Vec<[u8; 32]> = needs.invites.iter().copied().collect();
    for invite in txn.invites(&hashes).await? {
        state.invites.insert(
            invite.code_hash,
            HeldInvite {
                max_uses: invite.max_uses,
                uses: invite.uses,
                writer: invite.writer,
                expires_at: invite.expires_at_ms,
                context: invite.context,
                context_written: invite.context_written,
            },
        );
    }
    let (live_record_keys, record_bytes) = txn.record_totals(&record_keys).await?;
    state.totals = Totals {
        live_record_keys,
        record_bytes,
        claims: match writer {
            Some(writer) => txn.claim_tally(writer, &claim_keys).await?,
            None => Default::default(),
        },
        contacts: txn.list_count(ListName::Contact, &pubkys).await?,
        conversations: txn.list_count(ListName::Conversation, &pubkys).await?,
        deny: txn.list_count(ListName::Deny, &pubkys).await?,
        live_invites: txn.live_invites(now, &hashes).await?,
    };
    Ok(state)
}

/// The account's apps and the App IDs it keeps, for judging which apps are current (Switch
/// spec 3.4) outside a batch.
pub(super) async fn load_apps(
    txn: &mut AccountTxn,
    held: Option<&IdentityDoc>,
    now: u64,
) -> Result<OpsState, StoreError> {
    let head = txn.head().clone();
    let identity = head.identity_key;
    let mut state = OpsState::new(identity, head.generation, head.last_seq, now);
    state.doc = held.cloned();
    for app in txn.apps().await? {
        state.apps.insert(app.app_id, held_app(&app, &identity)?);
    }
    state.kept = txn.kept_app_ids().await?.into_iter().collect();
    Ok(state)
}

/// Delete the inbox entries every current target has passed (Switch wire 9.1), judged by
/// the one rule for current apps ([`OpsState::is_current`]): after anything that changes
/// which apps are current outside a batch, such as a revocation or an `identity.json`
/// delivery.
pub(super) async fn release_entries(
    txn: &mut AccountTxn,
    held: Option<&IdentityDoc>,
    now: u64,
) -> Result<u64, StoreError> {
    let state = load_apps(txn, held, now).await?;
    txn.delete_passed_entries(&state.current_app_ids()).await
}

pub(crate) fn held_app(app: &StoredApp, identity: &[u8; 32]) -> Result<HeldApp, StoreError> {
    let corrupt = |_| StoreError::Corrupt("a stored app document doesn't verify");
    let record = app
        .record
        .as_ref()
        .map(|record| AppRecord::verify(record, identity))
        .transpose()
        .map_err(corrupt)?;
    let renewed = app
        .renewed_cert
        .as_ref()
        .map(|cert| AppCert::verify(cert, identity))
        .transpose()
        .map_err(corrupt)?;
    // A receive key verifies with the certificate it was registered under, which a renewal
    // keeps the keys of.
    let receive_key = match (&app.receive_key, &record) {
        (Some(key), Some(record)) => Some(
            ReceiveKeyRecord::verify(key, record.cert())
                .or_else(|e| match &renewed {
                    Some(renewed) => ReceiveKeyRecord::verify(key, renewed),
                    None => Err(e),
                })
                .map_err(corrupt)?,
        ),
        (Some(_), None) => return Err(StoreError::Corrupt("a receive key without a record")),
        (None, _) => None,
    };
    Ok(HeldApp {
        record,
        record_at: app.record_at_ms,
        renewed,
        receive_key,
        cursor: app.cursor,
        reachable_since: app.reachable_since,
        full_requested: app.full_requested_ms,
    })
}

fn held_part(part: &StoredBundlePart) -> Result<HeldPart, StoreError> {
    let op = SignedOp::peek(&part.op).map_err(|_| StoreError::Corrupt("a key bundle part"))?;
    let OpKind::KeyBundlePut(put) = &op.body().kind else {
        return Err(StoreError::Corrupt(
            "a key bundle part isn't a key_bundle.put",
        ));
    };
    Ok(HeldPart {
        put: put.clone(),
        seq: part.seq,
        op: part.op.clone(),
    })
}

impl Service {
    /// An own app's request before the account's lock (Switch wire 7.2 Order): for a `POST
    /// /ops` (`batch`), the body parsed; the key the request is checked with found, and the
    /// request verified with it.
    /// The key is the record's in the batch's first `app.put` naming the caller, for a
    /// first call, else the one of the record the account holds, read without the lock; an
    /// App ID derives from its signing key, so every record of the app has that key.
    ///
    /// # Errors
    ///
    /// `400` or `413` for the body, `401 bad_signature` (a failed authentication), or `403
    /// not_current` for an app without a record whose batch carries no `app.put`.
    pub(super) async fn verify_own_app(
        &self,
        account: &str,
        request: &SwitchRequest,
        claimed: &Claimed,
        app: &str,
        batch: bool,
        base_ms: u64,
    ) -> Result<VerifiedApp, ApiError> {
        let app = zbase32_decode::<16>(app)
            .map_err(|_| ApiError::bad_request("7.1: Switch-App isn't an App ID"))?;
        // Step 2 of Switch wire 6.4: a batch is parsed before any signature is checked. Only
        // a batch can be an app's first call.
        let parsed = batch
            .then(|| OpsRequest::parse(&request.body).map_err(refused))
            .transpose()?;
        let first_call = parsed
            .as_ref()
            .and_then(|parsed| first_app_put(parsed, &app));
        let key = match &first_call {
            Some(record) => record_signing_key(record)
                .filter(|key| app_id_bytes(key) == app)
                .ok_or_else(|| {
                    bad_signature("7.2: the app.put's record doesn't give the caller's App ID")
                })?,
            None => self
                .store
                .app_row(account, &app)
                .await
                .map_err(|e| store_error(&e))?
                .and_then(|row| row.record)
                .as_ref()
                .and_then(record_signing_key)
                .ok_or_else(|| not_current("7.2: an own app's first call carries its app.put"))?,
        };
        let target = RequestTarget {
            method: &request.method,
            path_and_query: &request.path_and_query,
            body: &request.body,
            origin: &self.origin,
        };
        wire_http::verify_request(&key, &target, &claimed.headers, &claimed.signature)
            .map_err(|_| bad_signature("7.1: the request signature doesn't verify"))?;
        // A first call's record, and the certificate it carries, verify for the identity the
        // path names: a key the identity never certified doesn't reach the lock (Switch wire
        // 7.2 "An own app's first call").
        if let Some(record) = &first_call {
            let identity = pubky_switch_core::enc::pubky_key(account)
                .map_err(|_| ApiError::not_found("no such account"))?;
            let record = AppRecord::verify(record, &identity)
                .map_err(|_| bad_signature("7.2: the first call's app record"))?;
            if record.cert().app_id() != app {
                return Err(bad_signature("7.2: the record names another app"));
            }
        }
        let verified = VerifiedApp { app, key, parsed };
        // Then the app's checks, in their order, from what the account holds read without
        // the lock, so a revoked, departed or expired app takes no lock either (Switch spec
        // 12.2). Under the lock they run again.
        let identity = pubky_switch_core::enc::pubky_key(account)
            .map_err(|_| ApiError::not_found("no such account"))?;
        // One statement, so the document, the row and the kept flag are of one state.
        let (doc, stored, kept) = self
            .store
            .own_app_view(account, &app)
            .await
            .map_err(|e| store_error(&e))?
            .ok_or_else(|| ApiError::not_found("no such account"))?;
        let held = doc.and_then(|doc| IdentityDoc::verify(&doc, &identity).ok());
        if let Err(Stop::Refused(error) | Stop::Unauthenticated(error)) = check_own_app(
            &identity,
            held.as_ref(),
            stored.as_ref(),
            kept,
            &verified,
            base_ms,
        ) {
            return Err(error);
        }
        Ok(verified)
    }

    /// The caller under the lock (Switch wire 7.2, 7.3 step 5), before the staged gate:
    /// `None` for the signer, verified before the lock, or the certificate an own app is
    /// checked against.
    pub(super) async fn own_app_writer(
        &self,
        txn: &mut AccountTxn,
        held: Option<&IdentityDoc>,
        verified: Option<&VerifiedApp>,
        time_ms: u64,
    ) -> Result<Option<AppCert>, Stop> {
        let Some(verified) = verified else {
            return Ok(None);
        };
        let cert = self.authenticate_app(txn, held, verified, time_ms).await?;
        // Step 6 of Switch wire 7.3: an authenticated own app's last-seen time, which a
        // refusal of the endpoint doesn't undo.
        txn.note_last_seen(verified.app, time_ms);
        Ok(Some(cert))
    }

    /// `POST /v1/{id}/ops` (Switch wire 6.4) for an authenticated writer, under the
    /// account's lock.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn post_ops(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        request: &SwitchRequest,
        held: Option<&IdentityDoc>,
        verified: Option<&VerifiedApp>,
        writer: Option<&AppCert>,
        due: Option<u64>,
        time_ms: u64,
    ) -> Result<Answer, Stop> {
        let identity = txn.head().identity_key;
        // The signer's body is parsed here, so its refusals carry the head like its others.
        let parsed_here;
        let parsed = match verified.and_then(|verified| verified.parsed.as_ref()) {
            Some(parsed) => parsed,
            None => {
                parsed_here = OpsRequest::parse(&request.body)?;
                &parsed_here
            }
        };
        self.run_batch(txn, signer, held, parsed, writer, identity, due, time_ms)
            .await
    }

    /// Authenticate an own app under the lock (Switch wire 7.2 "Own app"), after its request
    /// verified before the lock: the certificate its batch is checked against, the checks
    /// on it, and that it has the key the request verified with.
    async fn authenticate_app(
        &self,
        txn: &mut AccountTxn,
        held: Option<&IdentityDoc>,
        verified: &VerifiedApp,
        time_ms: u64,
    ) -> Result<AppCert, Stop> {
        let identity = txn.head().identity_key;
        let stored = txn
            .apps()
            .await
            .map_err(|e| storage(&e))?
            .into_iter()
            .find(|stored| stored.app_id == verified.app);
        let kept = txn
            .kept_app_ids()
            .await
            .map_err(|e| storage(&e))?
            .contains(&verified.app);
        check_own_app(&identity, held, stored.as_ref(), kept, verified, time_ms)
    }

    /// Steps 3 to 11 of a batch whose caller is authenticated.
    #[allow(clippy::too_many_arguments)]
    async fn run_batch(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        held: Option<&IdentityDoc>,
        parsed: &OpsRequest,
        writer: Option<&AppCert>,
        identity: [u8; 32],
        due: Option<u64>,
        time_ms: u64,
    ) -> Result<Answer, Stop> {
        let cert = writer;
        let caller_app = cert.map(AppCert::app_id);
        // Step 3: each operation's signature with the caller's key: an app's with the
        // certificate it is checked against, which binds the operation's `app_id` to it.
        let ops = parsed
            .signed()
            .map(|doc| match cert {
                Some(cert) => SignedOp::verify_with_cert(doc, cert, &identity),
                None => SignedOp::verify(doc, &identity, &identity, None),
            })
            .collect::<Result<Vec<_>, _>>()?;
        // Step 4: the batch rules, the signer's batch carrying no cursor among them.
        parsed.check_caller(cert.is_none())?;
        check_batch(&ops)?;
        // Step 5: a retry gets the original proofs while they are kept.
        let hash = match ops.first() {
            Some(first) => {
                let hash = ops_hash(&ops).map_err(|_| temporary())?;
                let mut record = txn
                    .batch_record(&first.body().batch.id)
                    .await
                    .map_err(|e| storage(&e))?;
                if let Some(record) = record.as_mut()
                    && record.proofs_expired(time_ms, self.limits.batch_proofs_ms)
                {
                    record.proofs = None;
                }
                if let RetryCheck::Retry(proofs) = retry_check(record.as_ref(), &hash)? {
                    return self.write_answer(txn, signer, &proofs).await;
                }
                Some(hash)
            }
            None => None,
        };
        // Step 6.
        let generation = txn.head().generation;
        if ops.iter().any(|op| op.body().generation != generation) {
            return Err(ApiError::new(
                ErrorCode::StaleGeneration,
                "6.4: an operation naming another generation",
            )
            .with_current(json!({ "generation": generation }))
            .into());
        }
        let before = load_state(
            txn,
            held,
            &ops,
            caller_app.as_ref(),
            due.map(|base| (base, self.limits.max_claim_age_ms)),
            time_ms,
        )
        .await
        .map_err(|e| storage(&e))?;
        // Step 7: no-ops, time and rates.
        let effect = batch_effect(&ops, &before, parsed.cursor().is_some());
        if effect == BatchEffect::NoOp {
            return self.write_answer(txn, signer, &[]).await;
        }
        let outcome_depends = |fields: &pubky_switch_core::claims::ClaimFields,
                               writer: Option<&[u8; 16]>| {
            let (Ok(entry), Some(writer)) = (fields.check(), writer) else {
                return false;
            };
            pubky_switch_core::claims::entry_depends_on_time(
                before.claims.get(&entry.claim_key),
                &entry,
                writer,
                &|app| before.current_without_expiry(app),
            )
        };
        if !self.time.read().trusted && depends_on_time(&ops, &outcome_depends) {
            return Err(ApiError::unavailable(
                "7.3: the batch depends on the service's time, and trusted time is missing",
            )
            .into());
        }
        if let (
            BatchEffect::Apply {
                operation_rate,
                control_rate,
            },
            Some(app),
        ) = (effect, caller_app)
        {
            self.batch_rates(&txn.head().id, &app, operation_rate, control_rate, time_ms)?;
        }
        // Steps 8 to 10, on a copy.
        let mut after = before.clone();
        let applied = apply::apply(
            &mut after,
            &Batch {
                ops: &ops,
                writer: cert,
                cursor: parsed.cursor(),
                first_seq: txn.head().last_seq.saturating_add(1),
                limits: &self.limits.ops_limits(),
            },
        )?;
        if effect == BatchEffect::Unchanged {
            save_apps(txn, &before, &after)
                .await
                .map_err(|e| storage(&e))?;
            return self.write_answer(txn, signer, &[]).await;
        }
        // Step 11: the chain items and their proofs, then the state, all at once.
        let first_seq = txn.head().last_seq.saturating_add(1);
        let proofs = self.chain_ops(txn, signer, &ops, &applied, time_ms).await?;
        save(txn, &before, &mut after, &ops, &proofs)
            .await
            .map_err(|e| storage(&e))?;
        if let (Some(first), Some(ops_hash)) = (ops.first(), hash) {
            txn.put_batch(
                &first.body().batch.id,
                &BatchRecord {
                    ops_hash,
                    proofs: Some(proofs.clone()),
                    at: time_ms,
                    first_seq,
                    last_seq: txn.head().last_seq,
                },
            )
            .await
            .map_err(|e| storage(&e))?;
        }
        self.write_answer(txn, signer, &proofs).await
    }

    /// The operation and control rates of an own app's batch (Switch wire 6.4, 9.4).
    fn batch_rates(
        &self,
        account: &str,
        app: &[u8; 16],
        operation: bool,
        control: bool,
        time_ms: u64,
    ) -> Result<(), Stop> {
        let key = (account.to_string(), *app);
        if control
            && let Err(retry_after) =
                self.control_rate
                    .take(key.clone(), self.limits.control_per_min, time_ms)
        {
            return Err(ApiError::rate_limited("6.4: the app's control rate", retry_after).into());
        }
        if operation
            && let Err(retry_after) =
                self.operation_rate
                    .take(key, self.limits.ops_per_min, time_ms)
        {
            return Err(
                ApiError::rate_limited("6.4: the app's operation rate", retry_after).into(),
            );
        }
        Ok(())
    }

    /// Chain each operation and sign its proof (Switch wire 6.5, 6.6).
    async fn chain_ops(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        ops: &[SignedOp],
        applied: &[Applied],
        time_ms: u64,
    ) -> Result<Vec<SignedDoc>, Stop> {
        let identity = txn.head().identity_key;
        let mut proofs = Vec::with_capacity(ops.len());
        for (op, applied) in ops.iter().zip(applied) {
            let body = op.body();
            let seq = txn.next_seq().map_err(|e| storage(&e))?;
            let item_bytes = op.doc_bytes().map_err(|_| temporary())?;
            let hash = op.item_hash().map_err(|_| temporary())?;
            let (stub, _tip) = txn
                .head()
                .chain_tip()
                .append(seq, time_ms, ItemType::Op, hash, Some(body.batch))
                .map_err(|_| temporary())?;
            let object = body
                .kind
                .proof_object(body.app_id.as_ref())
                .ok_or_else(temporary)?;
            let proof = TransitionProof::sign(
                signer,
                &identity,
                ProofBody::new(stub.clone(), object, &applied.state),
            )
            .map_err(|_| temporary())?;
            // The item keeps its proof, which the feed shows with it (Switch wire 7.5).
            txn.append_chain_item(&NewChainItem {
                seq,
                item_type: ItemType::Op,
                item_bytes: &item_bytes,
                stub: &stub,
                server_time_ms: time_ms,
                only_for: applied.only_for,
                proof: Some(proof.signed()),
            })
            .await
            .map_err(|e| storage(&e))?;
            proofs.push(proof.signed().clone());
        }
        Ok(proofs)
    }

    /// A batch's answer: `{ "proofs": [...], "head": signed head }` (Switch wire 6.4).
    async fn write_answer(
        &self,
        txn: &AccountTxn,
        signer: &ServiceSigner,
        proofs: &[SignedDoc],
    ) -> Result<Answer, Stop> {
        let head = self.head(txn, signer).await.ok_or_else(temporary)?;
        let proofs: Vec<&SignedDoc> = proofs.iter().collect();
        let body = super::identity::write_answer(&proofs, &head.to_json())?;
        Ok(Answer::ok(body).with_head(Some(head)))
    }
}

fn stored_app(app_id: [u8; 16], app: &HeldApp) -> StoredApp {
    StoredApp {
        app_id,
        record: app.record.as_ref().map(|r| r.signed().clone()),
        record_at_ms: app.record_at,
        renewed_cert: app.renewed.as_ref().map(|c| c.signed().clone()),
        receive_key: app.receive_key.as_ref().map(|k| k.signed().clone()),
        cursor: app.cursor,
        reachable_since: app.reachable_since,
        full_requested_ms: app.full_requested,
    }
}

/// Write back the apps a batch changed, and the directory's versions.
async fn save_apps(
    txn: &mut AccountTxn,
    before: &OpsState,
    after: &OpsState,
) -> Result<(), StoreError> {
    let mut cursor_moved = false;
    for (app_id, app) in &after.apps {
        if before.apps.get(app_id) != Some(app) {
            txn.put_app(&stored_app(*app_id, app)).await?;
            cursor_moved |= before.apps.get(app_id).map(|held| held.cursor) != Some(app.cursor);
        }
    }
    // An entry every current target has passed goes (Switch wire 9.1).
    if cursor_moved {
        txn.delete_passed_entries(&after.current_app_ids()).await?;
    }
    for (app_id, key) in &after.new_receive_keys {
        txn.add_receive_key(app_id, key.n(), &key.kid(), key.signed())
            .await?;
    }
    if (before.directory_version, before.apps_version)
        != (after.directory_version, after.apps_version)
    {
        txn.set_directory_versions(after.directory_version, after.apps_version)
            .await?;
    }
    Ok(())
}

/// Write back everything a chained batch changed, with the proofs its records and claim
/// entries keep.
async fn save(
    txn: &mut AccountTxn,
    before: &OpsState,
    after: &mut OpsState,
    ops: &[SignedOp],
    proofs: &[SignedDoc],
) -> Result<(), StoreError> {
    // The records and claim entries this batch wrote keep their operation's proof.
    let proof_at = |seq: u64| -> Option<SignedDoc> {
        let first = after.newest_seq.saturating_add(1);
        let index = usize::try_from(seq.checked_sub(first)?).ok()?;
        proofs.get(index).cloned()
    };
    for (op, proof) in ops.iter().zip(proofs) {
        if let OpKind::RecordPut(put) = &op.body().kind
            && let Some(record) = after.records.get_mut(&put.key)
        {
            record.proof = Some(proof.clone());
        }
    }
    save_apps(txn, before, after).await?;
    for (target, parts) in &after.parts {
        if before.parts.get(target) != Some(parts) {
            let stored: Vec<StoredBundlePart> = parts
                .iter()
                .map(|part| StoredBundlePart {
                    first_epoch: part.put.first_epoch,
                    last_epoch: part.put.last_epoch,
                    seq: part.seq,
                    op: part.op.clone(),
                })
                .collect();
            txn.set_bundle_parts(target, &stored).await?;
        }
    }
    for (key, record) in &after.records {
        if before.records.get(key) != Some(record) {
            let proof = record
                .proof
                .clone()
                .ok_or(StoreError::Corrupt("a record write without its proof"))?;
            txn.put_record(&StoredRecord {
                state: record.state.clone(),
                value_bytes: record.value_bytes,
                writer: record.writer,
                cert: record.cert.clone(),
                op: record.op.clone(),
                proof,
            })
            .await?;
        }
    }
    for (key, claim) in &after.claims {
        if before.claims.get(key) != Some(claim) {
            txn.put_claim(key, claim).await?;
        }
    }
    for entry in &after.new_entries {
        let proof =
            proof_at(entry.seq).ok_or(StoreError::Corrupt("a claim entry without its proof"))?;
        txn.add_claim_entry(
            &entry.claim_key,
            &StoredClaimEntry {
                step: entry.step,
                seq: entry.seq,
                op: entry.op.clone(),
                proof,
            },
        )
        .await?;
    }
    for (list, old, new) in [
        (ListName::Contact, &before.contacts, &after.contacts),
        (
            ListName::Conversation,
            &before.conversations,
            &after.conversations,
        ),
        (ListName::Deny, &before.deny, &after.deny),
    ] {
        for (pubky, entry) in new {
            if old.get(pubky) != Some(entry) {
                txn.put_list_entry(
                    list,
                    &StoredListEntry {
                        pubky: *pubky,
                        written_by: entry.written_by,
                        at_ms: entry.at,
                    },
                )
                .await?;
            }
        }
        for pubky in old.keys().filter(|pubky| !new.contains_key(*pubky)) {
            txn.delete_list_entry(list, pubky).await?;
        }
    }
    for (hash, invite) in &after.invites {
        if before.invites.get(hash) != Some(invite) {
            txn.put_invite(&StoredInvite {
                code_hash: *hash,
                max_uses: invite.max_uses,
                uses: invite.uses,
                writer: invite.writer,
                expires_at_ms: invite.expires_at,
                context: invite.context.clone(),
                context_written: invite.context_written.clone(),
            })
            .await?;
        }
    }
    for hash in before
        .invites
        .keys()
        .filter(|h| !after.invites.contains_key(*h))
    {
        txn.delete_invite(hash).await?;
    }
    Ok(())
}
