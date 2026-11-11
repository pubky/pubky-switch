//! The scripted switch: one account, its chain, feed and directory, answering with answers
//! signed by the account's service key, built from the core's types. Batches go through the
//! core's rules (`batch`); `FAKES.md` lists what it leaves out.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use ed25519_dalek::SigningKey;
use pubky_switch_core::chain::{
    ChainTip, ItemType, ProofBody, ProofState, ServiceTransition, SignedHead, Stub,
    TransitionProof, ZERO_HASH, item_hash,
};
use pubky_switch_core::enc::{app_id_decode, b64, pubky_id, unb64_array, zbase32_encode};
use pubky_switch_core::envelope::Recipient;
use pubky_switch_core::http::{
    ErrorCode, frozen_refuses, header, request_signature_of, sign_response,
};
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::message::{Message, MessagePlaintext, Sender};
use pubky_switch_core::ops::{
    BatchRecord, BatchRef, KeyBundlePut, OpKind, OpsRequest, Position, SignedOp, random_batch_id,
    sign_batch,
};
use pubky_switch_core::records::{AppCert, Freeze, IdentityDoc};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::signing::Signs;
use pubky_switch_core::time::rfc3339;
use serde_json::{Map, Value, json};

use super::ScriptError;
use crate::clock::{Clock, TestClock};
use crate::error::TransportError;
use crate::transport::{Header, MockTransport, Request, Response};

mod batch;
mod inbox;
mod shared;
mod signer;

pub use shared::HeldRecord;

/// The origin the scripted switch of an account is reached at, unless a test routes
/// another one to it.
pub const SWITCH_ORIGIN: &str = "https://switch.example";

/// A status and a JSON body.
pub(crate) type Answer = (u16, Value);

/// One item of the account's sequence.
#[derive(Clone, Debug)]
pub(crate) enum Item {
    Entry {
        seq: u64,
        sender: [u8; 32],
        cert: SignedDoc,
        accepted_at: u64,
        envelope: Vec<u8>,
        targets: Vec<[u8; 16]>,
        /// The context of the invite code that admitted it.
        context: Option<Value>,
    },
    Chain {
        seq: u64,
        stub: Stub,
        item_type: ItemType,
        item: SignedDoc,
        proof: Option<SignedDoc>,
        /// Shown in full only to this app (a key bundle part).
        only_for: Option<[u8; 16]>,
    },
    Unreadable {
        seq: u64,
        sender: [u8; 32],
        accepted_at: u64,
    },
    Missed {
        seq: u64,
        entries: u64,
        from: u64,
        until: u64,
    },
}

impl Item {
    fn seq(&self) -> u64 {
        match self {
            Item::Entry { seq, .. }
            | Item::Chain { seq, .. }
            | Item::Unreadable { seq, .. }
            | Item::Missed { seq, .. } => *seq,
        }
    }

    fn batch(&self) -> Option<[u8; 16]> {
        match self {
            Item::Chain { stub, .. } => stub.open().ok()?.batch.map(|b| b.id),
            _ => None,
        }
    }
}

/// A push registration the switch holds for an app (Switch wire 8.1).
#[derive(Clone, Debug)]
pub(crate) struct PushReg {
    pub(crate) relay_url: String,
    pub(crate) key: SigningKey,
    pub(crate) handles: Vec<String>,
}

/// What the switch holds for one app of the account.
#[derive(Clone, Debug, Default)]
pub struct SwitchApp {
    /// The app record it registered (signed).
    pub record: Option<SignedDoc>,
    /// When the switch took that record (`record_at`, Switch wire 7.4.12).
    pub record_at: Option<u64>,
    /// The certificate of that record, verified.
    pub cert: Option<AppCert>,
    /// The renewed certificate a `cert.put` stored, verified.
    pub renewed: Option<AppCert>,
    /// The current receive key record (signed).
    pub receive_key: Option<SignedDoc>,
    /// The current receive key's number `n`.
    pub receive_n: Option<u64>,
    /// The cursor's `seq`.
    pub cursor: u64,
    /// Whether the app left or was revoked.
    pub departed: bool,
    /// When the signer revoked it (`revoked_at`, Switch wire 7.4.12).
    pub revoked_at: Option<u64>,
    /// When it left (`departed_at`), and the newest document's data epoch then, which its
    /// rotation goes above (`awaiting_rotation`, Switch wire 7.4.12).
    pub departed_at: Option<(u64, u64)>,
    /// When the app asked for its full key bundle, until a bundle part answers it.
    pub full_requested: Option<u64>,
    /// When the switch last took a request of the app's (`last_seen`, Switch wire 7.4.12).
    pub last_seen: Option<u64>,
    /// Whether a delivered `identity.json` listed the departed app in `removed` at a higher
    /// data epoch than at its departure: its rotation is done for good (`awaiting_rotation`,
    /// Switch wire 7.4.12).
    pub rotated: bool,
}

/// The byte budget of a feed page's items and of a record page's views: 8 MiB (Switch wire
/// 9.2 `max_page_bytes`).
pub const MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;

/// A fault the switch applies to the next request whose path contains `path`.
#[derive(Clone, Debug)]
pub enum Fault {
    /// Answer this error without applying anything.
    Error {
        /// A part of the request's path and query.
        path: String,
        /// The error code answered.
        code: ErrorCode,
        /// The answer's `current`.
        current: Value,
    },
    /// Apply the request, then lose the answer: the caller sees a timeout.
    LoseAnswer {
        /// A part of the request's path and query.
        path: String,
    },
    /// Fail to connect, applying nothing, once `after` matching requests went through; the
    /// request's body is kept.
    Unreachable {
        /// A part of the request's path and query.
        path: String,
        /// How many matching requests go through first.
        after: usize,
    },
    /// Apply an own app's or the signer's request, then sign an answer that leaves out the
    /// top-level `member`, as a faulty service would.
    LeaveOut {
        /// A part of the request's path and query.
        path: String,
        /// The member left out.
        member: String,
    },
}

pub(crate) struct Inner {
    pub(crate) identity: IdentityKey,
    pub(crate) service: SigningKey,
    pub(crate) clock: Arc<TestClock>,
    pub(crate) tip: ChainTip,
    pub(crate) seq: u64,
    pub(crate) items: Vec<Item>,
    pub(crate) tips: Vec<ChainTip>,
    pub(crate) doc: Option<IdentityDoc>,
    pub(crate) apps: BTreeMap<[u8; 16], SwitchApp>,
    /// The key bundle parts stored for each app, with the `seq` of each.
    pub(crate) bundles: BTreeMap<[u8; 16], Vec<(KeyBundlePut, u64)>>,
    /// Every kid an app of the account registered (Switch spec 3.6), with the app it
    /// belongs to.
    pub(crate) kids: BTreeMap<[u8; 8], [u8; 16]>,
    /// The batch records by batch ID (Switch wire 6.4 step 5).
    pub(crate) batches: HashMap<[u8; 16], BatchRecord>,
    pub(crate) checkpoint: Option<SignedHead>,
    /// Stubs at or below this `seq` are gone (dropped behind a checkpoint).
    pub(crate) dropped_through: u64,
    pub(crate) faults: VecDeque<Fault>,
    /// Every operation applied, in order, for counting effects.
    pub(crate) applied: Vec<SignedOp>,
    /// The signed freeze while the account is frozen (Switch spec 12.5).
    pub(crate) frozen: Option<SignedDoc>,
    /// Whether a frozen account's feed pages carry the freeze.
    pub(crate) freeze_in_feed: bool,
    /// A staged account: everything but uploads answers `503 staged`.
    pub(crate) staged: bool,
    /// An erased account: every answer is the operator's `404`.
    pub(crate) erased: bool,
    /// The generation a recovery started from, at a recovering account.
    pub(crate) recovery_from: Option<u64>,
    /// The generation an imported sequence continues from, after a cooperative move.
    pub(crate) continued_from: Option<u64>,
    /// A staged account holding a cooperative move's import, not a key change in place: it
    /// refuses an erasure until the move is aborted (Switch wire 7.4.16).
    pub(crate) holds_import: bool,
    /// When the recovery was declared: its recovery record's time (Switch spec 12.6 step 1).
    pub(crate) recovery_declared_at: Option<u64>,
    /// The service keys of the earlier generations whose proofs an import carried, by
    /// generation (Switch wire 3.3 "Service keys"); a proof of another generation is this
    /// switch's own.
    pub(crate) proof_keys: BTreeMap<u64, [u8; 32]>,
    /// An app's first receive key record may carry any `n` (after a provider loss).
    pub(crate) any_first_n: bool,
    /// The recovery uploads taken: the body, and whether it came with `Switch-Cert`.
    pub(crate) uploads: Vec<(Value, bool)>,
    /// The push registrations by app.
    pub(crate) push: BTreeMap<[u8; 16], PushReg>,
    /// Push keys minted, for fresh seeds.
    pub(crate) minted: u64,
    /// The answer to `GET /allow`, when scripted.
    pub(crate) allow: Option<Value>,
    /// Shared records, claims, invite codes and connect requests.
    pub(crate) shared: shared::Shared,
    /// Feed reads answered so far.
    pub(crate) feed_reads: u64,
    /// Feed reads answered before every later one is `503 unavailable`: a bound for tests
    /// of reads that must end.
    pub(crate) feed_limit: Option<u64>,
    /// The byte budget of a feed page's items and a record page's views, [`MAX_PAGE_BYTES`]
    /// unless a test lowers it (Switch wire 7.4.4, 7.4.9).
    pub(crate) max_page_bytes: usize,
    /// The bodies of the requests an `Unreachable` fault failed.
    pub(crate) unreached: Vec<Vec<u8>>,
    /// The peer copies of other identities' `identity.json` (Switch wire 7.4.5).
    pub(crate) peers: HashMap<[u8; 32], IdentityDoc>,
    /// The answers to appends, by sender and envelope, for retries by content.
    pub(crate) appended: HashMap<([u8; 32], Vec<u8>), Value>,
    /// The `apps_version`: it moves when an app becomes reachable or stops being so.
    pub(crate) apps_version: u64,
    /// The `apps_version` at which each reachable app became reachable.
    pub(crate) reachable_since: BTreeMap<[u8; 16], u64>,
    /// Every sender is admitted, whatever the lists say.
    pub(crate) open_admission: bool,
    /// The `directory_version`: it moves whenever the directory changes.
    pub(crate) directory_version: u64,
    /// The account's enrollment: its limits, and the answer to each enrollment taken, by
    /// enrollment hash. `None` for an account that doesn't exist until it is enrolled.
    pub(crate) enrolled: Option<signer::Enrolled>,
    /// The App IDs the enrollment that made the account named, kept for good (Switch wire
    /// 3.7).
    pub(crate) kept_app_ids: Vec<[u8; 16]>,
    /// The service time of the enrollment that named `kept_app_ids`, their `revoked_at` in
    /// `GET /apps` (Switch wire 7.4.12).
    pub(crate) kept_at: u64,
    /// The transition proof of the newest `identity.json` delivery, which a retry gets again
    /// (Switch wire 7.4.2).
    pub(crate) delivery_proof: Option<SignedDoc>,
    /// The limits an enrollment announces.
    pub(crate) enroll_limits: pubky_switch_core::records::Limits,
    /// The data epoch of the first delivered `identity.json` that listed each app.
    pub(crate) listed_at_epoch: BTreeMap<[u8; 16], u64>,
    /// The identity's service time, the last the switch stamped: a request refused before
    /// the account's lock, such as a `401 stale_timestamp`, answers with it and doesn't
    /// move it (Switch wire 7.1).
    pub(crate) stamped_ms: u64,
    /// The stored signer hand-over (Switch wire 7.4.17): its target and the `PUT` body.
    pub(crate) handover: Option<([u8; 16], Value)>,
}

impl Inner {
    fn fresh(
        identity: IdentityKey,
        service: SigningKey,
        clock: Arc<TestClock>,
        tip: ChainTip,
    ) -> Self {
        let stamped_ms = clock.now_ms();
        Self {
            stamped_ms,
            identity,
            service,
            clock,
            tip,
            seq: tip.seq,
            items: Vec::new(),
            tips: vec![tip],
            doc: None,
            apps: BTreeMap::new(),
            bundles: BTreeMap::new(),
            kids: BTreeMap::new(),
            batches: HashMap::new(),
            checkpoint: None,
            dropped_through: 0,
            faults: VecDeque::new(),
            applied: Vec::new(),
            frozen: None,
            freeze_in_feed: true,
            staged: false,
            erased: false,
            recovery_from: None,
            continued_from: None,
            holds_import: false,
            recovery_declared_at: None,
            proof_keys: BTreeMap::new(),
            any_first_n: false,
            uploads: Vec::new(),
            push: BTreeMap::new(),
            minted: 0,
            allow: None,
            shared: shared::Shared::default(),
            feed_reads: 0,
            feed_limit: None,
            max_page_bytes: MAX_PAGE_BYTES,
            unreached: Vec::new(),
            peers: HashMap::new(),
            appended: HashMap::new(),
            apps_version: 1,
            reachable_since: BTreeMap::new(),
            open_admission: false,
            directory_version: 1,
            enrolled: Some(signer::Enrolled::default()),
            kept_app_ids: Vec::new(),
            kept_at: 0,
            delivery_proof: None,
            enroll_limits: pubky_switch_core::records::Limits::default(),
            listed_at_epoch: BTreeMap::new(),
            handover: None,
        }
    }
}

/// The scripted switch of one account.
///
/// It answers the app layer's calls as the switch would (Switch wire 7.4), signing every
/// answer, head and transition proof with the account's service key, and lets a test add
/// what other parties do: entries from senders, the signer's operations and documents,
/// freezes, revocations and faults.
pub struct ScriptedSwitch {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for ScriptedSwitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.lock();
        write!(
            f,
            "ScriptedSwitch(generation {}, seq {})",
            inner.tip.generation, inner.seq
        )
    }
}

pub(crate) fn bad(code: ErrorCode, message: &str, current: Value) -> Answer {
    (
        code.status(),
        json!({ "code": code.as_str(), "message": message, "current": current }),
    )
}

fn missing(what: &str) -> ScriptError {
    ScriptError::Missing(what.to_owned())
}

fn clone_key(key: &IdentityKey) -> IdentityKey {
    IdentityKey::from_secret(key.secret_bytes())
}

impl ScriptedSwitch {
    /// The switch of `identity`'s account, its service key from `service_secret`, at
    /// generation 1 with an empty sequence.
    pub fn new(
        identity: &IdentityKey,
        service_secret: [u8; 32],
        clock: Arc<TestClock>,
    ) -> Arc<Self> {
        Self::with_generation(identity, service_secret, clock, 1)
    }

    /// A switch whose sequence and chain start at `generation`.
    pub fn with_generation(
        identity: &IdentityKey,
        service_secret: [u8; 32],
        clock: Arc<TestClock>,
        generation: u64,
    ) -> Arc<Self> {
        let tip = ChainTip {
            generation,
            seq: 0,
            chain_hash: ZERO_HASH,
        };
        Arc::new(Self {
            inner: Mutex::new(Inner::fresh(
                clone_key(identity),
                SigningKey::from_bytes(&service_secret),
                clock,
                tip,
            )),
        })
    }

    /// A service recovering the account after the loss of `recovery_from`: a new sequence and
    /// chain at `generation`, starting with the recovery record (Switch spec 12.6 step 1).
    ///
    /// # Errors
    ///
    /// When the recovery record doesn't sign.
    pub fn recovering(
        identity: &IdentityKey,
        service_secret: [u8; 32],
        clock: Arc<TestClock>,
        generation: u64,
        recovery_from: u64,
    ) -> Result<Arc<Self>, ScriptError> {
        let switch = Self::with_generation(identity, service_secret, clock, generation);
        {
            let mut inner = switch.lock();
            inner.recovery_from = Some(recovery_from);
            inner.any_first_n = true;
            let at = inner.now();
            inner.recovery_declared_at = Some(at);
            inner.service_transition(ServiceTransition::Recovery { recovery_from, at })?;
        }
        Ok(switch)
    }

    /// The next service of a cooperative move, staged, with this account imported: the same
    /// sequence, chain, apps, cursors and shared state, under its own service key (Switch
    /// spec 12.5 step 3). It serves once it is delivered an `identity.json` naming its key.
    pub fn import_into(&self, service_secret: [u8; 32]) -> Arc<Self> {
        self.continue_into(service_secret, false)
    }

    /// The same account under a new service key at the next generation, a key change in
    /// place: as [`ScriptedSwitch::import_into`], but the batch records keep their proofs,
    /// so a batch sent again unchanged gets its original proofs, signed with the earlier
    /// generation's key (Switch wire 6.4 step 6).
    pub fn change_key_into(&self, service_secret: [u8; 32]) -> Arc<Self> {
        self.continue_into(service_secret, true)
    }

    fn continue_into(&self, service_secret: [u8; 32], keep_proofs: bool) -> Arc<Self> {
        let inner = self.lock();
        let mut next = Inner::fresh(
            clone_key(&inner.identity),
            SigningKey::from_bytes(&service_secret),
            Arc::clone(&inner.clock),
            inner.tip,
        );
        next.seq = inner.seq;
        next.continued_from = Some(inner.tip.generation);
        next.holds_import = !keep_proofs;
        // The proofs this switch signed travel with the records and claims, checked with its
        // key for its generation (Switch wire 3.3).
        next.proof_keys = inner.proof_keys.clone();
        next.proof_keys
            .entry(inner.tip.generation)
            .or_insert_with(|| inner.service.verifying_key().to_bytes());
        next.items = inner.items.clone();
        next.tips = inner.tips.clone();
        next.doc = inner.doc.clone();
        next.apps = inner.apps.clone();
        next.bundles = inner.bundles.clone();
        next.kids = inner.kids.clone();
        // An export carries batch records without their proofs (Switch wire 10.1); a key
        // change in place keeps them.
        next.batches = inner
            .batches
            .iter()
            .map(|(id, record)| {
                let mut record = record.clone();
                if !keep_proofs {
                    record.proofs = None;
                }
                (*id, record)
            })
            .collect();
        next.dropped_through = inner.dropped_through;
        next.staged = true;
        next.shared = inner.shared.clone();
        next.peers = inner.peers.clone();
        next.apps_version = inner.apps_version;
        next.reachable_since = inner.reachable_since.clone();
        next.open_admission = inner.open_admission;
        next.directory_version = inner.directory_version;
        Arc::new(Self {
            inner: Mutex::new(next),
        })
    }

    /// The signer's freeze (Switch wire 7.4.13): the `freeze` transition, then every write
    /// is `410 moved`.
    ///
    /// # Errors
    ///
    /// When the transition doesn't sign.
    pub fn freeze(&self, freeze: &Freeze) -> Result<(), ScriptError> {
        let mut inner = self.lock();
        let at = inner.now();
        inner.service_transition(ServiceTransition::Freeze {
            freeze_hash: freeze.hash(),
            next_generation: freeze.body().next_generation,
            inbox: freeze.next().clone(),
            at,
        })?;
        inner.frozen = Some(freeze.signed().clone());
        Ok(())
    }

    /// The signer's unfreeze at the old service (Switch wire 7.4.13).
    ///
    /// # Errors
    ///
    /// When the transition doesn't sign.
    pub fn unfreeze(&self, freeze: &Freeze) -> Result<(), ScriptError> {
        let mut inner = self.lock();
        let at = inner.now();
        inner.service_transition(ServiceTransition::Unfreeze {
            freeze_hash: freeze.hash(),
            at,
        })?;
        inner.frozen = None;
        Ok(())
    }

    /// A faulty service that lost the account's `identity.json`: it holds none from now on.
    pub fn lose_identity(&self) {
        self.lock().doc = None;
    }

    /// The signer revokes `app` (Switch spec 12.2 step 1).
    ///
    /// # Errors
    ///
    /// When the transition doesn't sign.
    pub fn revoke(&self, app: [u8; 16]) -> Result<(), ScriptError> {
        self.lock().revoke(app)?;
        Ok(())
    }

    /// `app` leaves, as its `POST /apps/{app_id}/leave` does (Switch wire 7.4.12).
    ///
    /// # Errors
    ///
    /// When the transition doesn't sign.
    pub fn leave(&self, app: [u8; 16]) -> Result<(), ScriptError> {
        self.lock().leave(app)?;
        Ok(())
    }

    /// A faulty service: `app` stays revoked or departed, but `GET /apps` shows no time for it.
    pub fn forget_removal_time(&self, app: [u8; 16]) {
        let mut inner = self.lock();
        let held = inner.apps.entry(app).or_default();
        held.revoked_at = None;
        held.departed_at = None;
    }

    /// `app` asks for its full key bundle, as its `POST /apps/{app_id}/keys` does (Switch
    /// wire 7.4.11).
    pub fn request_full_bundle(&self, app: [u8; 16]) {
        let mut inner = self.lock();
        let now = inner.now();
        inner
            .apps
            .entry(app)
            .or_default()
            .full_requested
            .get_or_insert(now);
    }

    /// The account's identity.
    pub fn identity(&self) -> [u8; 32] {
        self.lock().identity.public()
    }

    /// The public key of the service key that signs every answer.
    pub fn service_key(&self) -> [u8; 32] {
        self.lock().service.verifying_key().to_bytes()
    }

    /// The recovery uploads taken: each body, and whether it came with `Switch-Cert`.
    pub fn uploads(&self) -> Vec<(Value, bool)> {
        self.lock().uploads.clone()
    }

    /// The push registration of `app`: its relay, push key and handles.
    pub fn push_of(&self, app: &[u8; 16]) -> Option<(String, [u8; 32], Vec<String>)> {
        self.lock().push.get(app).map(|reg| {
            (
                reg.relay_url.clone(),
                reg.key.verifying_key().to_bytes(),
                reg.handles.clone(),
            )
        })
    }

    /// Another device of `app` rotates its push key: a new key for the same relay.
    #[cfg(test)]
    pub(crate) fn rotate_push_behind(&self, app: &[u8; 16]) {
        let mut inner = self.lock();
        let key = inner.mint();
        if let Some(reg) = inner.push.get_mut(app) {
            reg.key = key;
            reg.handles.clear();
        }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A transport that answers every request from this switch, and records the requests.
    pub fn transport(self: &Arc<Self>) -> Arc<MockTransport> {
        let switch = Arc::clone(self);
        Arc::new(MockTransport::with_handler(move |request| {
            switch.handle(request)
        }))
    }

    /// Apply `fault` to the next request it matches; faults apply in the order added.
    pub fn fail_next(&self, fault: Fault) {
        self.lock().faults.push_back(fault);
    }

    /// Answer one request, as the transport does.
    ///
    /// # Errors
    ///
    /// A scripted fault's connection failure or lost answer, or [`TransportError::Other`]
    /// when the switch can't build its answer.
    pub fn handle(&self, request: &Request) -> Result<Response, TransportError> {
        let mut inner = self.lock();
        let path = request.path_and_query.clone();
        let mut lose = false;
        let mut leave_out = None;
        let matching = inner.faults.iter().position(|fault| match fault {
            Fault::Error { path: p, .. }
            | Fault::LoseAnswer { path: p }
            | Fault::Unreachable { path: p, .. }
            | Fault::LeaveOut { path: p, .. } => path.contains(p.as_str()),
        });
        let passes = matching.is_some_and(|index| match inner.faults.get_mut(index) {
            Some(Fault::Unreachable { after, .. }) if *after > 0 => {
                *after -= 1;
                true
            }
            _ => false,
        });
        if let Some(index) = matching.filter(|_| !passes) {
            match inner.faults.remove(index) {
                Some(Fault::Error { code, current, .. }) => {
                    let (status, body) = bad(code, "scripted", current);
                    // Past authentication, the service saw the app (Switch wire 7.4.12).
                    if status != 401 {
                        inner.seen(request);
                    }
                    // A `401` is answered before the request verifies, so before the lock:
                    // with the last stamped time and no head (Switch wire 7.1).
                    if status == 401 {
                        let at = inner.stamped_ms;
                        return Ok(inner.respond_at(&inner.service, request, status, &body, at));
                    }
                    return Ok(inner.respond(request, status, &body));
                }
                Some(Fault::LoseAnswer { .. }) => lose = true,
                Some(Fault::LeaveOut { member, .. }) => leave_out = Some(member),
                Some(Fault::Unreachable { .. }) => {
                    inner.unreached.push(request.body.clone());
                    return Err(TransportError::Connect("scripted".into()));
                }
                None => {}
            }
        }
        if request.method == "POST" && path == "/v1/enroll" {
            let (status, body) = inner
                .enroll(request)
                .map_err(|error| TransportError::Other(format!("scripted switch: {error}")))?;
            if lose {
                return Err(TransportError::Timeout);
            }
            return Ok(inner.respond(request, status, &body));
        }
        if let Some(answer) = inner.stale_timestamp(request) {
            return Ok(answer);
        }
        if let Some((status, body)) = inner.gate(&request.method, &path) {
            // A staged account's refusal comes after authentication: the app was seen.
            inner.seen(request);
            if inner.erased || inner.enrolled.is_none() {
                // Switch wire 7.4.16: signed with the operator key.
                let operator = SigningKey::from_bytes(&[42; 32]);
                return Ok(inner.respond_with(&operator, request, status, &body));
            }
            return Ok(inner.respond(request, status, &body));
        }
        let caller = request
            .header(header::APP)
            .and_then(|text| app_id_decode(text).ok());
        let rest = path.splitn(4, '/').nth(3).unwrap_or_default().to_owned();
        let account = inner.identity.public();
        if let Some(sender) = inbox::Sender::foreign(request, &account) {
            // An app of another identity: the routes a sender calls (Switch wire 7.2).
            let (status, body) = inner
                .route_foreign(request, &sender, &rest)
                .map_err(|error| TransportError::Other(format!("scripted switch: {error}")))?;
            if lose {
                return Err(TransportError::Timeout);
            }
            return Ok(inner.respond(request, status, &body));
        }
        let answer = match inner.route_shared(request, caller, &rest) {
            Some(answer) => Ok(answer),
            None => inner.route(request, caller, &rest),
        };
        // An own app's request: its last-seen time, also for the request that registered it.
        inner.seen(request);
        let (status, mut body) =
            answer.map_err(|error| TransportError::Other(format!("scripted switch: {error}")))?;
        if lose {
            return Err(TransportError::Timeout);
        }
        if let (Some(member), Some(object)) = (leave_out, body.as_object_mut()) {
            object.remove(&member);
        }
        Ok(inner.respond(request, status, &body))
    }

    /// Deliver an own `identity.json` (the signer's `PUT /identity`): an `identity` chain
    /// item. A document naming this switch's service key makes a staged switch serve.
    ///
    /// # Errors
    ///
    /// When the document's bytes don't read or its proof doesn't sign.
    pub fn deliver_identity(&self, doc: &IdentityDoc) -> Result<(), ScriptError> {
        self.lock().chain_identity(doc).map(|_| ())
    }

    /// An entry from `from`'s app `keys` (certificate `cert`): a message of `kind` with
    /// `body`, signed and sealed to the `to` apps' current receive keys. Returns its `seq`
    /// and the message.
    ///
    /// # Errors
    ///
    /// When the message doesn't build or seal, or a target has no receive key.
    pub fn send(
        &self,
        from: &IdentityKey,
        keys: &AppKeys,
        cert: &AppCert,
        kind: &str,
        body: Value,
        to: &[[u8; 16]],
    ) -> Result<(u64, Message), ScriptError> {
        let (account, now) = {
            let inner = self.lock();
            (inner.identity.public(), inner.clock.now_ms())
        };
        let body: Map<String, Value> = body.as_object().cloned().unwrap_or_default();
        let message = Message::new(
            kind,
            Sender::of_app(from.public(), keys),
            account,
            now,
            vec![],
            body,
        )?;
        let plaintext = message.sign(keys)?;
        let seq = self.send_plaintext(from.public(), cert, &plaintext, to)?;
        Ok((seq, message))
    }

    /// An entry carrying a signed plaintext, sealed again to the `to` apps' current keys (a
    /// re-send keeps the bytes). Returns its `seq`.
    ///
    /// # Errors
    ///
    /// When a target has no receive key, or the envelope doesn't seal.
    pub fn send_plaintext(
        &self,
        sender: [u8; 32],
        cert: &AppCert,
        plaintext: &MessagePlaintext,
        to: &[[u8; 16]],
    ) -> Result<u64, ScriptError> {
        let account = self.identity();
        let recipients = {
            let inner = self.lock();
            to.iter()
                .map(|app| {
                    let record = inner
                        .apps
                        .get(app)
                        .and_then(|held| held.receive_key.as_ref())
                        .ok_or_else(|| missing("a target app without a receive key"))?;
                    let value: Value = record.peek()?;
                    let public = value["x25519"]
                        .as_str()
                        .ok_or_else(|| missing("a receive key record without x25519"))?;
                    Ok(Recipient::new(unb64_array::<32>(public)?))
                })
                .collect::<Result<Vec<_>, ScriptError>>()?
        };
        let envelope = plaintext.seal(&account, &recipients, false)?;
        Ok(self.send_envelope(sender, cert, envelope, to))
    }

    /// An entry carrying `envelope` as it is, for the `to` apps. Returns its `seq`.
    pub fn send_envelope(
        &self,
        sender: [u8; 32],
        cert: &AppCert,
        envelope: Vec<u8>,
        to: &[[u8; 16]],
    ) -> u64 {
        let mut inner = self.lock();
        let seq = inner.next_seq();
        let accepted_at = inner.clock.now_ms();
        inner.items.push(Item::Entry {
            seq,
            sender,
            cert: cert.signed().clone(),
            accepted_at,
            envelope,
            targets: to.to_vec(),
            context: None,
        });
        seq
    }

    /// An `unreadable` item: an entry a departed own app left unread (Switch wire 7.4.4).
    /// Returns its `seq`.
    pub fn push_unreadable(&self, sender: [u8; 32], accepted_at: u64) -> u64 {
        let mut inner = self.lock();
        let seq = inner.next_seq();
        inner.items.push(Item::Unreadable {
            seq,
            sender,
            accepted_at,
        });
        seq
    }

    /// A `missed` item: `entries` entries accepted from `from` until `until` were deleted
    /// while the app lagged (Switch wire 7.4.4). Returns its `seq`.
    pub fn push_missed(&self, entries: u64, from: u64, until: u64) -> u64 {
        let mut inner = self.lock();
        let seq = inner.next_seq();
        inner.items.push(Item::Missed {
            seq,
            entries,
            from,
            until,
        });
        seq
    }

    /// An operation of the signer (identity key, `app_id` null), in a batch of its own,
    /// applied as a submitted batch is. Returns the `seq` after it.
    ///
    /// # Errors
    ///
    /// [`ScriptError::Refused`] with the switch's error answer, or a batch or proof that
    /// doesn't sign.
    pub fn signer_op(&self, kind: OpKind) -> Result<u64, ScriptError> {
        self.signer_batch(vec![kind])
    }

    /// Operations of the signer in one batch, applied as a submitted batch is, all or none,
    /// such as a renewal's `cert.put` and the first `key_bundle.put` of its full bundle
    /// (Switch wire 3.8 step 1). Returns the `seq` after them.
    ///
    /// # Errors
    ///
    /// As [`ScriptedSwitch::signer_op`].
    pub fn signer_batch(&self, kinds: Vec<OpKind>) -> Result<u64, ScriptError> {
        let key = clone_key(&self.lock().identity);
        self.inject(&key, None, kinds)
    }

    /// An operation an app with `keys` signs, in a batch of its own, applied as a submitted
    /// batch is: for another device of an own app, or a copy of its key. The app must be
    /// current at the switch, as [`super::TestSigner::register_app`] makes one. Returns the
    /// `seq` after it.
    ///
    /// # Errors
    ///
    /// As [`ScriptedSwitch::signer_op`].
    pub fn app_op(&self, keys: &AppKeys, kind: OpKind) -> Result<u64, ScriptError> {
        self.inject(keys, Some(keys.app_id_bytes()), vec![kind])
    }

    fn inject(
        &self,
        writer: &impl Signs,
        app_id: Option<[u8; 16]>,
        kinds: Vec<OpKind>,
    ) -> Result<u64, ScriptError> {
        let mut inner = self.lock();
        let account = inner.identity.public();
        let path = format!("/v1/{}/ops", pubky_id(&account));
        let ops = sign_batch(
            writer,
            &account,
            app_id,
            inner.tip.generation,
            random_batch_id()?,
            kinds.into_iter().map(|kind| (vec![], kind)).collect(),
        )?;
        let signed: Vec<SignedDoc> = ops.iter().map(|op| op.signed().clone()).collect();
        let (status, body) = match inner.gate("POST", &path) {
            Some(answer) => answer,
            None => inner.submit(app_id, &signed, None)?,
        };
        if status != 200 {
            return Err(ScriptError::Refused { status, body });
        }
        Ok(inner.seq)
    }

    /// Chain an operation without checking it, as a faulty service does, and store a key
    /// bundle part it carries; nothing else is applied. For tests of what an app does with
    /// an item a compliant switch refuses.
    #[cfg(test)]
    pub(crate) fn chain_unchecked(
        &self,
        writer: &impl Signs,
        app_id: Option<[u8; 16]>,
        kind: OpKind,
    ) -> Result<u64, ScriptError> {
        let mut inner = self.lock();
        let account = inner.identity.public();
        let generation = inner.tip.generation;
        let only_for = match &kind {
            OpKind::KeyBundlePut(put) => Some(put.target_app_id),
            _ => None,
        };
        let ops = sign_batch(
            writer,
            &account,
            app_id,
            generation,
            random_batch_id()?,
            vec![(vec![], kind)],
        )?;
        for op in &ops {
            let body = op.body();
            if let OpKind::KeyBundlePut(put) = &body.kind {
                let seq = inner.seq + 1;
                let parts = inner.bundles.entry(put.target_app_id).or_default();
                parts.push((put.clone(), seq));
            }
            let object = body
                .kind
                .proof_object(body.app_id.as_ref())
                .ok_or_else(|| missing("an operation without a proof object"))?;
            inner.chain_item(
                ItemType::Op,
                op.signed().clone(),
                op.item_hash()?,
                Some(body.batch),
                &object,
                &ProofState::Deny { denied: false },
                only_for,
            )?;
        }
        Ok(inner.seq)
    }

    /// Roll the chain back to `seq`: everything after it is gone, and the tip is as it was.
    #[cfg(test)]
    pub(crate) fn roll_back_to(&self, seq: u64) {
        let mut inner = self.lock();
        inner.items.retain(|item| item.seq() <= seq);
        if let Some(tip) = inner.tips.iter().rev().find(|tip| tip.seq <= seq).copied() {
            inner.tip = tip;
        }
        inner.tips.retain(|t| t.seq <= seq);
        inner.seq = seq;
    }

    /// Every operation applied, in order.
    pub fn applied(&self) -> Vec<SignedOp> {
        self.lock().applied.clone()
    }

    /// What the switch holds for `app`; empty for an app it never saw.
    pub fn app(&self, app: &[u8; 16]) -> SwitchApp {
        self.lock().apps.get(app).cloned().unwrap_or_default()
    }

    /// The chain tip's `seq`.
    pub fn tip_seq(&self) -> u64 {
        self.lock().tip.seq
    }

    /// The last `seq` of the account's sequence.
    pub fn seq(&self) -> u64 {
        self.lock().seq
    }

    /// The newest own `identity.json` delivered.
    pub fn identity_doc(&self) -> Option<IdentityDoc> {
        self.lock().doc.clone()
    }
}

impl Inner {
    /// An own app's request passed authentication: its last-seen time (Switch wire 7.4.12).
    /// The scripted switch takes an app with a record, not revoked, departed or kept, as
    /// authenticated; the service sees no other.
    fn seen(&mut self, request: &Request) {
        let Some(app) = request
            .header(header::APP)
            .and_then(|text| app_id_decode(text).ok())
        else {
            return;
        };
        let now = self.now();
        let kept = self.kept_app_ids.contains(&app);
        if let Some(held) = self.apps.get_mut(&app)
            && held.record.is_some()
            && !held.departed
            && !kept
        {
            held.last_seen = Some(now);
        }
    }

    fn now(&self) -> u64 {
        self.clock.now_ms()
    }

    /// `app` departed: it stops being reachable (Switch wire 7.4.10).
    fn unreachable(&mut self, app: &[u8; 16]) {
        self.directory_version += 1;
        if self.reachable_since.remove(app).is_some() {
            self.apps_version += 1;
        }
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn head(&self) -> SignedHead {
        SignedHead::sign(&self.service, &self.identity.public(), &self.tip)
    }

    /// An answer under the account's key. One to an own app or the signer carries the head
    /// in `Switch-Head`, refusals included, once the request verified: never on a `401`,
    /// answered before that, nor to an enrollment or an erasure (Switch wire 7.1).
    fn respond(&self, request: &Request, status: u16, body: &Value) -> Response {
        let mut response = self.respond_with(&self.service, request, status, body);
        let own =
            request.header(header::IDENTITY) == Some(pubky_id(&self.identity.public()).as_str());
        let path = request.path_and_query.as_str();
        if own && status != 401 && !path.ends_with("/enroll") && !path.ends_with("/erase") {
            response
                .headers
                .push(Header::new(header::HEAD, &self.head().to_header()));
        }
        response
    }

    /// A `Switch-Timestamp` more than 5 minutes from the time base, at an account the switch
    /// holds, is `401 stale_timestamp` (Switch wire 7.1, 7.6): `current.server_time` is the
    /// time base, for the retry's timestamp, and `Switch-Server-Time` the last time stamped,
    /// which the refusal, answered before the account's lock, doesn't move. A request that
    /// passes stamps the time. A missing or unparsable timestamp isn't checked.
    fn stale_timestamp(&mut self, request: &Request) -> Option<Response> {
        if self.erased || self.enrolled.is_none() {
            return None;
        }
        let now = self.now();
        let stale = request
            .header(header::TIMESTAMP)
            .and_then(|text| pubky_switch_core::time::parse_rfc3339(text).ok())
            .is_some_and(|at| at.abs_diff(now) > pubky_switch_core::records::CLOCK_TOLERANCE_MS);
        if !stale {
            self.stamped_ms = self.stamped_ms.max(now);
            return None;
        }
        let (status, body) = bad(
            ErrorCode::StaleTimestamp,
            "Switch wire 7.1: the timestamp is more than 5 minutes from the service's time",
            json!({ "server_time": rfc3339(now) }),
        );
        Some(self.respond_at(&self.service, request, status, &body, self.stamped_ms))
    }

    fn respond_with(
        &self,
        key: &SigningKey,
        request: &Request,
        status: u16,
        body: &Value,
    ) -> Response {
        self.respond_at(key, request, status, body, self.now())
    }

    /// An answer whose `Switch-Server-Time` is `at`.
    fn respond_at(
        &self,
        key: &SigningKey,
        request: &Request,
        status: u16,
        body: &Value,
        at: u64,
    ) -> Response {
        let bytes = body.to_string().into_bytes();
        let server_time = rfc3339(at);
        let request_signature = request_signature_of(request.header(header::SIGNATURE));
        let signature = sign_response(
            key,
            status,
            request_signature.as_ref(),
            &server_time,
            &bytes,
        );
        Response {
            status,
            headers: vec![
                Header::new(header::SERVICE_SIGNATURE, &b64(&signature)),
                Header::new(header::SERVER_TIME, &server_time),
            ],
            body: bytes,
        }
    }

    /// Append one chain item and its proof.
    #[allow(clippy::too_many_arguments)]
    fn chain_item(
        &mut self,
        item_type: ItemType,
        item: SignedDoc,
        hash: [u8; 32],
        batch: Option<BatchRef>,
        object: &str,
        state: &ProofState,
        only_for: Option<[u8; 16]>,
    ) -> Result<SignedDoc, ScriptError> {
        let seq = self.next_seq();
        let now = self.now();
        let (stub, tip) = self.tip.append(seq, now, item_type, hash, batch)?;
        self.tip = tip;
        self.tips.push(tip);
        let proof = TransitionProof::sign(
            &self.service,
            &self.identity.public(),
            ProofBody::new(stub.clone(), object.to_owned(), state),
        )?;
        self.items.push(Item::Chain {
            seq,
            stub,
            item_type,
            item,
            proof: Some(proof.signed().clone()),
            only_for,
        });
        Ok(proof.signed().clone())
    }

    /// Revoke `app` (Switch spec 12.2 step 1): its proof, or `None` for an app revoked or
    /// departed already.
    pub(crate) fn revoke(&mut self, app: [u8; 16]) -> Result<Option<SignedDoc>, ScriptError> {
        if self.apps.get(&app).is_some_and(|a| a.departed) {
            return Ok(None);
        }
        let at = self.now();
        let held = self.apps.entry(app).or_default();
        held.departed = true;
        held.revoked_at = Some(at);
        self.unreachable(&app);
        self.push.remove(&app);
        Ok(Some(self.service_transition(
            ServiceTransition::Revoke { app_id: app, at },
        )?))
    }

    /// `app` leaves (Switch spec 12.3): the `leave` transition's proof, or `None` for an app
    /// revoked or departed already.
    pub(crate) fn leave(&mut self, app: [u8; 16]) -> Result<Option<SignedDoc>, ScriptError> {
        if self.apps.get(&app).is_some_and(|a| a.departed) {
            return Ok(None);
        }
        let at = self.now();
        let epoch = self.doc.as_ref().map_or(0, IdentityDoc::data_epoch);
        let held = self.apps.entry(app).or_default();
        held.departed = true;
        held.departed_at = Some((at, epoch));
        self.unreachable(&app);
        Ok(Some(self.service_transition(ServiceTransition::Leave {
            app_id: app,
            at,
        })?))
    }

    fn service_transition(
        &mut self,
        transition: ServiceTransition,
    ) -> Result<SignedDoc, ScriptError> {
        let signed = transition.sign(&self.service, &self.identity.public())?;
        let hash = item_hash(ItemType::Service, &signed.doc_bytes()?);
        let object = transition.proof_object().unwrap_or_default();
        let state = ProofState::Service(transition.to_value());
        self.chain_item(ItemType::Service, signed, hash, None, &object, &state, None)
    }

    /// The answer an account gives every call `method` `path` makes, before routing: an
    /// erased account's `404`, a staged account's `503 staged` (but for uploads, the
    /// delivery that makes it serve and the erasure), and a
    /// frozen account's `410 moved` for writes.
    fn gate(&self, method: &str, path: &str) -> Option<Answer> {
        if self.erased || self.enrolled.is_none() {
            return Some(bad(ErrorCode::NotFound, "no such account", json!(null)));
        }
        let upload = method == "POST" && path.contains("recovery/upload");
        // A staged account takes the delivery that makes it serve (Switch wire 7.3 step 7).
        let delivery = method == "PUT" && path.ends_with("/identity");
        // And the erasure, which a staged account holding an import refuses (7.4.16).
        let erasure = method == "POST" && path.ends_with("/erase");
        if self.staged && !upload && !delivery && !erasure {
            return Some(bad(ErrorCode::Staged, "staged", json!(null)));
        }
        if let Some(freeze) = &self.frozen
            && frozen_refuses(method, path)
        {
            return Some(bad(ErrorCode::Moved, "moved", json!({ "freeze": freeze })));
        }
        None
    }

    fn route(
        &mut self,
        request: &Request,
        caller: Option<[u8; 16]>,
        rest: &str,
    ) -> Result<Answer, ScriptError> {
        let (route, query) = rest.split_once('?').unwrap_or((rest, ""));
        let Some(app) = caller else {
            return Ok(match (request.method.as_str(), route) {
                ("PUT", "identity") => self.put_identity(&request.body)?,
                ("GET", "apps") => self.apps_answer(),
                ("PUT", "handover") => self.put_handover(&request.body),
                ("GET", "handover") => self.handover_answer(None),
                ("POST", "erase") => self.erase_answer(&request.body),
                ("POST", r) if r.starts_with("apps/") && r.ends_with("/revoke") => {
                    self.revoke_answer(r)?
                }
                ("GET", "directory") => self.directory(),
                ("GET", "identity") => self.identity_answer(),
                ("POST", "recovery/upload") => self.upload(request, None)?,
                ("POST", "ops") => self.ops(None, &request.body)?,
                ("GET", "allow") => self.allow_answer(),
                ("GET", "feed") => self.feed(None, query),
                ("PUT", "push") => self.put_push(None, &request.body),
                _ => bad(ErrorCode::NotFound, "no route", json!(null)),
            });
        };
        let me = zbase32_encode(&app);
        let own_keys = format!("apps/{me}/keys");
        let own_leave = format!("apps/{me}/leave");
        Ok(match (request.method.as_str(), route) {
            ("GET", "handover") => self.handover_answer(Some(app)),
            ("POST", "erase") => bad(
                ErrorCode::PermissionMissing,
                "the erasure is the signer's",
                json!(null),
            ),
            ("POST", "ops") => self.ops(caller, &request.body)?,
            ("POST", "inbox") => self.append(request, None, query)?,
            ("GET", "feed") => self.feed(caller, query),
            ("GET", "directory") => self.directory(),
            ("GET", "identity") => self.identity_answer(),
            ("POST", "recovery/upload") => self.upload(request, caller)?,
            ("GET", "allow") => self.allow_answer(),
            ("PUT", "push") => self.put_push(caller, &request.body),
            // Only a current app reads its parts or asks for a full bundle; the service
            // answers any other `403 not_current` (Switch wire 7.2), and keeps nothing for it.
            (_, r) if r == own_keys && !self.app_current_by(&self.apps, &app, false) => {
                bad(ErrorCode::NotCurrent, "not current", json!(null))
            }
            ("GET", r) if r == own_keys => {
                let parts = self.bundles.get(&app).cloned().unwrap_or_default();
                if parts.is_empty() {
                    return Ok(bad(ErrorCode::NotFound, "none", json!(null)));
                }
                let bundles: Vec<Value> = parts
                    .iter()
                    .map(|(part, seq)| {
                        json!({ "bundle": part.bundle, "seq": seq,
                                "first_epoch": part.first_epoch, "last_epoch": part.last_epoch })
                    })
                    .collect();
                (200, json!({ "bundles": bundles }))
            }
            ("POST", r) if r == own_keys => {
                let now = self.now();
                let Some(held) = self.apps.get_mut(&app) else {
                    return Ok(bad(ErrorCode::NotCurrent, "not current", json!(null)));
                };
                let at = *held.full_requested.get_or_insert(now);
                (200, json!({ "requested": rfc3339(at) }))
            }
            ("POST", r) if r == own_leave => match self.leave(app)? {
                Some(proof) => (
                    200,
                    json!({ "proofs": [proof], "head": self.head().to_value() }),
                ),
                None => bad(ErrorCode::NotCurrent, "departed", json!({})),
            },
            _ => bad(ErrorCode::NotFound, "no route", json!(null)),
        })
    }

    fn identity_answer(&self) -> Answer {
        let mut answer = json!({ "identity": self.doc.as_ref().map(|d| d.signed().clone()) });
        if let Some(freeze) = &self.frozen {
            answer["freeze"] = json!(freeze);
        }
        (200, answer)
    }

    fn allow_answer(&self) -> Answer {
        (
            200,
            self.allow.clone().unwrap_or_else(|| {
                json!({ "contacts": [], "conversations": [], "deny": [], "flagged": [],
                        "invite_codes": [] })
            }),
        )
    }

    /// `POST /ops` (Switch wire 6.4): the body read, then the batch handler.
    fn ops(&mut self, caller: Option<[u8; 16]>, body: &[u8]) -> Result<Answer, ScriptError> {
        let request = match OpsRequest::parse(body) {
            Ok(request) => request,
            Err(refusal) => return Ok(batch::refused(&refusal)),
        };
        let signed: Vec<SignedDoc> = request.signed().cloned().collect();
        self.submit(caller, &signed, request.cursor())
    }

    fn feed(&mut self, caller: Option<[u8; 16]>, query: &str) -> Answer {
        let Some(app) = caller else {
            return bad(ErrorCode::PermissionMissing, "own apps only", json!(null));
        };
        if let Err(refusal) = self.own_call(&app) {
            return batch::refused(&refusal);
        }
        if self
            .feed_limit
            .is_some_and(|limit| self.feed_reads >= limit)
        {
            return bad(ErrorCode::Unavailable, "feed read limit", json!(null));
        }
        self.feed_reads += 1;
        let mut after = 0;
        let mut limit = 100usize;
        for pair in query.split('&') {
            match pair.split_once('=') {
                Some(("after", value)) => match Position::parse(value) {
                    Ok(position) => after = position.seq,
                    Err(_) => return bad(ErrorCode::BadRequest, "after", json!(null)),
                },
                Some(("limit", value)) => match value.parse() {
                    Ok(value) => limit = value,
                    Err(_) => return bad(ErrorCode::BadRequest, "limit", json!(null)),
                },
                _ => {}
            }
        }
        let mut items = Vec::new();
        let mut last = after;
        let mut truncated = false;
        let mut bytes = 0usize;
        // A batch's items go together: a page never ends inside one (Switch wire 7.4.4).
        let mut groups: Vec<Vec<&Item>> = Vec::new();
        for item in self.items.iter().filter(|item| item.seq() > after) {
            match groups.last_mut() {
                Some(group)
                    if item.batch().is_some()
                        && group.last().and_then(|held| held.batch()) == item.batch() =>
                {
                    group.push(item);
                }
                _ => groups.push(vec![item]),
            }
        }
        for group in groups {
            if items.len() >= limit {
                truncated = true;
                break;
            }
            let shown: Vec<Value> = group
                .iter()
                .filter_map(|item| self.show(item, app))
                .collect();
            let size: usize = shown.iter().map(|value| value.to_string().len()).sum();
            // The byte budget ends a page before a group that would pass it, but the page's
            // first item or batch is shown whatever its size.
            if !items.is_empty() && bytes.saturating_add(size) > self.max_page_bytes {
                truncated = true;
                break;
            }
            bytes = bytes.saturating_add(size);
            if let Some(item) = group.last() {
                last = item.seq();
            }
            items.extend(shown);
        }
        if !truncated {
            last = last.max(self.seq);
        }
        let mut page = json!({
            "items": items,
            "next": format!("{}:{last}", self.tip.generation),
            "scanned_through": last,
            "more": truncated,
            "head": self.head().to_value(),
        });
        if let Some(checkpoint) = &self.checkpoint {
            page["checkpoint"] = checkpoint.to_value();
        }
        if let Some(freeze) = &self.frozen
            && self.freeze_in_feed
        {
            page["freeze"] = json!(freeze);
        }
        (200, page)
    }

    /// An entry ID for the item at `seq`: its low byte, repeated.
    fn entry_id(seq: u64) -> String {
        b64(&[seq.to_le_bytes()[0]; 16])
    }

    fn show(&self, item: &Item, app: [u8; 16]) -> Option<Value> {
        Some(match item {
            Item::Entry {
                seq,
                sender,
                cert,
                accepted_at,
                envelope,
                targets,
                context,
            } => {
                if !targets.contains(&app) {
                    return None;
                }
                let mut value = json!({ "type": "entry", "seq": seq,
                        "entry_id": Self::entry_id(*seq), "sender": pubky_id(sender),
                        "cert": cert, "accepted_at": rfc3339(*accepted_at),
                        "envelope": b64(envelope) });
                if let Some(context) = context {
                    value["context"] = context.clone();
                }
                value
            }
            Item::Chain {
                seq,
                stub,
                item_type,
                item,
                proof,
                only_for,
            } => {
                if *seq <= self.dropped_through {
                    return None;
                }
                if only_for.is_some_and(|target| target != app) {
                    return Some(json!({ "type": "stub", "seq": seq, "stub": stub.to_value() }));
                }
                let mut value = json!({ "type": "chain", "seq": seq, "stub": stub.to_value(),
                                        "item_type": item_type.as_str(), "item": item });
                if let Some(proof) = proof
                    && *item_type == ItemType::Op
                {
                    value["proof"] = json!(proof);
                }
                value
            }
            Item::Unreadable {
                seq,
                sender,
                accepted_at,
            } => json!({ "type": "unreadable", "seq": seq, "entry_id": Self::entry_id(*seq),
                         "sender": pubky_id(sender), "accepted_at": rfc3339(*accepted_at) }),
            Item::Missed {
                seq,
                entries,
                from,
                until,
            } => json!({ "type": "missed", "seq": seq, "entries": entries,
                         "accepted_from": rfc3339(*from), "accepted_until": rfc3339(*until) }),
        })
    }

    fn mint(&mut self) -> SigningKey {
        self.minted += 1;
        let seed = format!("push/{}/{}", self.minted, b64(&self.service.to_bytes()));
        SigningKey::from_bytes(blake3::hash(seed.as_bytes()).as_bytes())
    }

    /// `POST /recovery/upload` (Switch wire 7.4.14): kept, and answered as the account
    /// stands: staged, recovering, or serving after a move.
    fn upload(
        &mut self,
        request: &Request,
        caller: Option<[u8; 16]>,
    ) -> Result<Answer, ScriptError> {
        let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
            return Ok(bad(ErrorCode::BadRequest, "upload", json!(null)));
        };
        let count = |name: &str| body[name].as_array().map_or(0, Vec::len) as u64;
        let (heads, proofs) = (count("heads"), count("proofs"));
        self.uploads
            .push((body.clone(), request.header(header::CERT).is_some()));
        if self.staged {
            return Ok((200, json!({ "heads": heads, "proofs": proofs })));
        }
        let changes = json!({ "records": [], "divergent": [], "claims": [],
                              "divergent_claims": [], "unverified": 0, "distrusted": 0,
                              "refused": 0, "heads": heads,
                              "lists": body.get("lists").is_some() });
        if self.recovery_from.is_some() {
            let at = self.now();
            let proof = self.service_transition(ServiceTransition::Upload {
                by: caller.unwrap_or_default(),
                changes: changes.clone(),
                proofs,
                at,
            })?;
            return Ok((
                200,
                json!({ "result": changes, "proof": proof, "head": self.head().to_value() }),
            ));
        }
        Ok((
            200,
            json!({ "heads": heads, "proofs": proofs, "merged": changes,
                    "head": self.head().to_value() }),
        ))
    }

    /// `PUT /push` (Switch wire 8.1).
    fn put_push(&mut self, caller: Option<[u8; 16]>, body: &[u8]) -> Answer {
        let (Some(app), Ok(body)) = (caller, serde_json::from_slice::<Value>(body)) else {
            return bad(ErrorCode::BadRequest, "push", json!(null));
        };
        let key = |name: &str| -> Result<Option<[u8; 32]>, ()> {
            match body.get(name).and_then(Value::as_str) {
                Some(text) => unb64_array::<32>(text).map(Some).map_err(|_| ()),
                None => Ok(None),
            }
        };
        let (Ok(push_key), Ok(replaces)) = (key("push_key"), key("replaces")) else {
            return bad(ErrorCode::BadRequest, "push key", json!(null));
        };
        let relay_url = body["relay_url"].as_str().unwrap_or_default().to_owned();
        let handles: Vec<String> = body["handles"]
            .as_array()
            .map(|h| {
                h.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let current = self
            .push
            .get(&app)
            .map(|reg| reg.key.verifying_key().to_bytes());
        let conflict = |current: Option<[u8; 32]>| {
            bad(
                ErrorCode::Conflict,
                "push",
                json!({ "push_key": current.map(|k| b64(&k)) }),
            )
        };
        let answer = |reg: &PushReg| {
            (
                200,
                json!({ "relay_url": reg.relay_url, "handles": reg.handles.len(),
                        "push_key": b64(&reg.key.verifying_key().to_bytes()) }),
            )
        };
        match push_key {
            None => {
                if !handles.is_empty() {
                    return bad(ErrorCode::BadRequest, "handles on a start", json!(null));
                }
                let held = self.push.get(&app).cloned();
                match held {
                    None if replaces.is_some() => conflict(None),
                    Some(reg) if replaces.is_none() && reg.relay_url == relay_url => answer(&reg),
                    Some(_) if replaces.is_some() && replaces != current => conflict(current),
                    Some(_) if replaces.is_none() => conflict(current),
                    _ => {
                        let key = self.mint();
                        let reg = PushReg {
                            relay_url,
                            key,
                            handles: Vec::new(),
                        };
                        let out = answer(&reg);
                        self.push.insert(app, reg);
                        out
                    }
                }
            }
            Some(named) => {
                if replaces.is_some() || handles.len() > 8 {
                    return bad(ErrorCode::BadRequest, "push", json!(null));
                }
                match self.push.get_mut(&app) {
                    Some(reg) if Some(named) == current && reg.relay_url == relay_url => {
                        reg.handles = handles;
                        let reg = reg.clone();
                        answer(&reg)
                    }
                    _ => conflict(current),
                }
            }
        }
    }

    fn directory(&self) -> Answer {
        let apps: Vec<Value> = self
            .apps
            .iter()
            .filter(|(_, app)| !app.departed && app.record.is_some())
            .map(|(id, app)| {
                json!({ "app_id": zbase32_encode(id), "record": app.record,
                        "receive_key": app.receive_key })
            })
            .collect();
        (
            200,
            json!({ "identity": self.doc.as_ref().map(|d| d.signed().clone()),
                    "apps": apps, "directory_version": self.directory_version,
                    "apps_version": self.apps_version }),
        )
    }
}
