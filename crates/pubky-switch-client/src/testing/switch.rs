//! The scripted switch: one account, its chain, feed and directory, answering with answers
//! signed by the account's service key, built from the core's types. Batches go through the
//! core's rules (`batch`); `FAKES.md` lists what it leaves out.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use ed25519_dalek::SigningKey;
use pubky_switch_core::chain::{
    ChainEnvelope, ChainTip, ItemType, ProofBody, ProofState, ServiceTransition, SignedHead, Stub,
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
use pubky_switch_core::recovery::{UploadBody, UploadChanges, UploadContext, check_upload};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::signing::Signs;
use pubky_switch_core::time::rfc3339;
use serde_json::{Map, Value, json};

use super::ScriptError;
use crate::clock::{Clock, TestClock};
use crate::error::TransportError;
use crate::transport::{BoxFuture, Header, MockTransport, Request, Response, Transport};

mod batch;
mod inbox;
mod retention;
mod shared;
mod signer;

pub use shared::HeldRecord;

/// The time a scripted `missed` item writes as text that doesn't parse.
const UNPARSABLE_TIME: u64 = u64::MAX;

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
        /// Who may read it in full; every other app gets its stub (Switch wire 7.5).
        readers: Readers,
        /// For a conversation entry the service wrote: its invite code's context.
        context: Option<Value>,
    },
    Unreadable {
        seq: u64,
        /// The ID of the entry it stands for; one of its own for an item a test scripted.
        entry_id: String,
        sender: [u8; 32],
        accepted_at: u64,
        /// A test scripted it ([`ScriptedSwitch::push_unreadable`]): it is kept whatever
        /// the cursors.
        scripted: bool,
    },
    Missed {
        seq: u64,
        /// The lagging app it is for, which alone is shown it; `None` for an item a test
        /// scripted ([`ScriptedSwitch::push_missed`]), shown to every app and kept
        /// whatever the cursors.
        app: Option<[u8; 16]>,
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
    /// Whether the app is marked lagging: its unread entries passed its share of the inbox
    /// quota, and entries no longer wait for it (Switch wire 7.4.4).
    pub lagging: bool,
    /// Whether the app left or was revoked.
    pub departed: bool,
    /// When the signer revoked it (`revoked_at`, Switch wire 7.4.12).
    pub revoked_at: Option<u64>,
    /// When it left (`departed_at`), and the newest document's data epoch then, which its
    /// rotation goes above (`awaiting_rotation`, Switch wire 7.4.12).
    pub departed_at: Option<(u64, u64)>,
    /// When the app asked for its full key bundle, until a bundle part answers it.
    pub full_requested: Option<u64>,
    /// The `seq` of the part that completed its last full-bundle request: the request stays
    /// in force for dropping parts until its cursor has passed it (Switch wire 6.2).
    pub full_completed: Option<u64>,
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

/// How the scripted switch keeps its chain, by the service's rule (Switch wire 7.4.4, 9.1,
/// 9.2): it signs a checkpoint once `checkpoint_behind` chain items may go, and drops the
/// stubs behind it that every current app's cursor has passed or that are `cursor_hold_ms`
/// old, oldest first, never inside a batch, at most `per_request` of them at one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retention {
    /// Chain items that may go before a checkpoint is signed (`checkpoint_behind`).
    pub checkpoint_behind: u64,
    /// How long an app's cursor holds a stub back (`cursor_hold_ms`).
    pub cursor_hold_ms: u64,
    /// Sign each checkpoint at the newest chain item (`checkpoint_at_head`).
    pub at_head: bool,
    /// The most stubs looked at and dropped at one request (`retention_per_request`).
    pub per_request: usize,
}

impl Default for Retention {
    /// The service's defaults: 1,000 items, 30 days, at the newest item that may go, 1,000 a
    /// request.
    fn default() -> Self {
        Self {
            checkpoint_behind: 1_000,
            cursor_hold_ms: 30 * 24 * 60 * 60 * 1000,
            at_head: false,
            per_request: 1_000,
        }
    }
}

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
    /// [`Fault::LoseAnswer`], once `after` matching requests went through.
    LoseAnswerAfter {
        /// A part of the request's path and query.
        path: String,
        /// How many matching requests go through first.
        after: usize,
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
    /// [`Fault::LeaveOut`], with the top-level `member` replaced by `value` instead, such as
    /// `GET /apps`' `identity` by a copy that doesn't verify.
    Replace {
        /// A part of the request's path and query.
        path: String,
        /// The member replaced.
        member: String,
        /// What the answer carries instead.
        value: Value,
    },
    /// Apply an own app's or the signer's request, then sign the answer with the key
    /// `secret` makes instead of the account's, with no head, as a hostile or faulty
    /// service would. An enrollment, a staged or erased account's refusal and a `401
    /// stale_timestamp` are answered as without it, and use it up.
    SignWith {
        /// A part of the request's path and query.
        path: String,
        /// The secret of the key that signs the answer.
        secret: [u8; 32],
    },
    /// [`Fault::Error`], the answer signed with the key `secret` makes instead of the
    /// account's, with no head.
    ErrorSignedWith {
        /// A part of the request's path and query.
        path: String,
        /// The error code answered.
        code: ErrorCode,
        /// The secret of the key that signs the answer.
        secret: [u8; 32],
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
    /// How the chain is kept, as the service keeps it; `None` keeps every stub, with only
    /// the checkpoints a test scripts (Switch wire 7.4.4, 9.1).
    pub(crate) retention: Option<Retention>,
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
    /// Keep the entries every reader they wait for has passed
    /// ([`ScriptedSwitch::keep_passed_entries`]).
    keep_passed: bool,
    /// The feed reads the switch holds and hasn't woken since they last looked (Switch wire
    /// 7.4.4 `wait`), each with its waker: woken when the account's sequence grows, at the
    /// next request, at an erasure, and when a test says the clock moved.
    held: Vec<(u64, Waker)>,
    /// The number given to the last held read.
    held_ids: u64,
    /// The request being answered is a held read, seen when it arrived: it isn't seen again
    /// (Switch wire 7.4.12 `last_seen`).
    seen_at_arrival: bool,
    /// Feed reads answered before every later one is `503 unavailable`: a bound for tests
    /// of reads that must end.
    pub(crate) feed_limit: Option<u64>,
    /// The byte budget of a feed page's items and a record page's views, [`MAX_PAGE_BYTES`]
    /// unless a test lowers it (Switch wire 7.4.4, 7.4.9).
    pub(crate) max_page_bytes: usize,
    /// The most items or batches a feed page scans, shown to the reader or not, unless
    /// `None`: a lower bound gives pages of items the reader isn't shown, with `more`
    /// (Switch wire 7.4.4).
    pub(crate) max_page_scan: Option<usize>,
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
    /// Admission is staged after a provider loss (Switch spec 12.6 step 2): a sender it can't
    /// otherwise admit gets `503 staged`.
    pub(crate) admission_staged: bool,
    /// `POST /recovery/upload` calls per app per hour after a provider loss, and the most
    /// contacts and deny entries an upload adds up to (Switch wire 9.2): the wire's defaults
    /// unless a test sets them.
    pub(crate) uploads_per_app_per_hour: u32,
    pub(crate) max_contacts: u64,
    pub(crate) max_deny: u64,
    /// The uploads each app made in the hour of the switch's clock: the hour and the count.
    upload_counts: BTreeMap<[u8; 16], (u64, u32)>,
    /// The `directory_version`: it moves whenever the directory changes.
    pub(crate) directory_version: u64,
    /// The origin the switch serves at, which an enrollment names (Switch wire 3.7).
    pub(crate) origin: String,
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
    /// The pending key a serving account's enrollments were answered with, for the next
    /// generation, and the App IDs those enrollments named (Switch wire 3.7).
    pub(crate) pending: Option<(SigningKey, Vec<[u8; 16]>)>,
    /// The key the answer being built is signed with, when it isn't the account's: an
    /// enrollment answered with the pending key (Switch wire 7.4.1).
    pub(crate) answer_key: Option<SigningKey>,
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
            retention: Some(Retention::default()),
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
            keep_passed: false,
            held: Vec::new(),
            held_ids: 0,
            seen_at_arrival: false,
            feed_limit: None,
            max_page_bytes: MAX_PAGE_BYTES,
            max_page_scan: None,
            unreached: Vec::new(),
            peers: HashMap::new(),
            appended: HashMap::new(),
            apps_version: 0,
            reachable_since: BTreeMap::new(),
            open_admission: false,
            admission_staged: false,
            uploads_per_app_per_hour: 60,
            max_contacts: 100_000,
            max_deny: 100_000,
            upload_counts: BTreeMap::new(),
            directory_version: 0,
            origin: SWITCH_ORIGIN.to_owned(),
            enrolled: Some(signer::Enrolled::default()),
            kept_app_ids: Vec::new(),
            kept_at: 0,
            delivery_proof: None,
            enroll_limits: pubky_switch_core::records::Limits::default(),
            listed_at_epoch: BTreeMap::new(),
            handover: None,
            pending: None,
            answer_key: None,
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

/// The longest a feed read may ask to be held, in seconds (Switch wire 7.4.4).
const MAX_FEED_WAIT_S: u64 = 25;

/// A feed read's `wait`, if it is an integer in its range.
fn feed_wait(text: &str) -> Option<u64> {
    decimal(text).filter(|seconds| *seconds <= MAX_FEED_WAIT_S)
}

/// The scripted switch as a transport: it answers at once, but for a feed read it holds.
struct Holding(Arc<ScriptedSwitch>);

impl Transport for Holding {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        Box::pin(async move {
            let Some(held) = self.0.waiting_read(&request) else {
                return self.0.handle(&request);
            };
            let key = held.key;
            held.await;
            // A read held while the account's service key changed, as at a recovery in
            // place, is answered `503 unavailable` with the operator key and no head: the
            // key it was read under signs nothing more (Switch wire 7.4.4).
            if let Some(answer) = self.0.key_changed_since(key, &request) {
                return Ok(answer);
            }
            // Answered as the account stands now: a reader revoked or departed while its
            // read was held is refused, and an account erased meanwhile is one the switch
            // doesn't host, as at the service (Switch wire 7.4.4, 7.4.16).
            self.0.answer(&request, true)
        })
    }
}

/// A feed read the switch holds, admitted when it arrived: ready once the feed has
/// something to show its app, its wait has passed, the account is gone, or its service key
/// changed. A departure of its app shows it the departure's chain item, so it is ready then
/// too. The switch's lock is held only while it looks, never across the wait.
struct Held<'a> {
    switch: &'a ScriptedSwitch,
    /// Its number among the reads the switch held.
    id: u64,
    /// The account's service key when the read arrived.
    key: [u8; 32],
    app: [u8; 16],
    /// The certificate the app was current with when the read arrived.
    cert: AppCert,
    after: u64,
    until_ms: u64,
}

impl Future for Held<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut inner = self.switch.lock();
        if inner.now() >= self.until_ms
            || inner.erased
            || inner.enrolled.is_none()
            || inner.service.verifying_key().to_bytes() != self.key
            || inner.shows_after(self.app, &self.cert, self.after)
        {
            return Poll::Ready(());
        }
        // One waker a read, the newest.
        let (id, waker) = (self.id, cx.waker().clone());
        match inner.held.iter_mut().find(|(held, _)| *held == id) {
            Some(held) => held.1 = waker,
            None => inner.held.push((id, waker)),
        }
        Poll::Pending
    }
}

impl Drop for Held<'_> {
    /// A read that is answered, or that its caller gave up, is held no more.
    fn drop(&mut self) {
        let id = self.id;
        self.switch.lock().held.retain(|(held, _)| *held != id);
    }
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

/// An error answer (Switch wire 7.1, 7.6). `current` goes only where there is one: a writer
/// omits an absent member rather than writing `null` (Switch wire, Conventions, "Absent and
/// null"), so `Value::Null` stands for none.
pub(crate) fn bad(code: ErrorCode, message: &str, current: Value) -> Answer {
    let mut body = json!({ "code": code.as_str(), "message": message });
    if !current.is_null() {
        body["current"] = current;
    }
    // A `429` says when to try again, as the service's does: the next minute's window
    // (Switch wire 7.6).
    if code == ErrorCode::RateLimited {
        body["retry_after"] = json!(SCRIPTED_RETRY_AFTER_S);
    }
    (code.status(), body)
}

/// `name=value` pairs joined by `&`, names and values percent-decoded; `None` for a bad
/// escape, bytes that aren't UTF-8, or a name given twice, which the service answers `400`
/// before the endpoint reads its parameters (`crates/pubky-switch/src/http/route.rs`,
/// `parse_query`; Switch wire 7.1).
pub(crate) fn parse_query(query: &str) -> Option<BTreeMap<String, String>> {
    let decode = |text: &str| {
        let bytes = text.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while let Some(&byte) = bytes.get(index) {
            if byte == b'%' {
                let hex = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
                decoded.push(u8::from_str_radix(hex, 16).ok()?);
                index += 3;
            } else {
                decoded.push(byte);
                index += 1;
            }
        }
        String::from_utf8(decoded).ok()
    };
    let mut parsed = BTreeMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if parsed.insert(decode(name)?, decode(value)?).is_some() {
            return None;
        }
    }
    Some(parsed)
}

/// A decimal integer as the service reads a query's numbers: digits only, at most 16
/// (`crates/pubky-switch/src/service/feed.rs`, `FeedQuery::parse`).
pub(crate) fn decimal(text: &str) -> Option<u64> {
    (!text.is_empty() && text.len() <= 16 && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

/// The `retry_after` of the scripted switch's `429 rate_limited`, in seconds.
pub(crate) const SCRIPTED_RETRY_AFTER_S: u64 = 60;

/// Who may read a chain item in full (Switch wire 7.5, "Who may read a chain item in
/// full"); every other own app gets its stub. Taken when the item is appended; whether the
/// item's document is still the current one is judged when a page is read, from the
/// switch's state then, as the service does: a superseded document shows as a stub to
/// every app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Readers {
    /// Every own app: `identity.json` deliveries, `receive_key.put`, and service
    /// transitions other than `conversation.add`.
    Every,
    /// Apps holding this switch permission: `lists.read` for `allow.*`, `deny.*` and the
    /// service's `conversation.add`.
    Permission(Permission),
    /// Apps with `lists.read` or `conversation.add`: `invite_code.*`.
    ListsOrConversation,
    /// Apps with `claims.read`, while the entry belongs to the claim held at this key and
    /// that claim isn't a tombstone: a compacted or deleted claim's entries show as stubs
    /// to every app (Switch wire 6.8 "Tombstones").
    Claim(Vec<u8>),
    /// Apps holding the read scope of the record at this key, while the item is its
    /// current write: a `record.put`.
    Record([u8; 32]),
    /// The target app only, while the part is stored: a `key_bundle.put`.
    Bundle([u8; 16]),
    /// Every own app, while the writing app holds this record: an `app.put`. One without
    /// a writing app shows as a stub.
    AppRecord(Option<[u8; 16]>, SignedDoc),
    /// Every own app, while the target holds this renewed certificate, neither replaced nor
    /// carried by its record: a `cert.put`.
    RenewedCert([u8; 16], SignedDoc),
}

impl Readers {
    /// The readers of an operation of `kind` written by `app_id` (`None` for the signer).
    pub(crate) fn of_op(kind: &OpKind, app_id: Option<&[u8; 16]>) -> Self {
        match kind {
            OpKind::Claim(fields) => Self::Claim(fields.claim_key.clone()),
            OpKind::RecordPut(put) => Self::Record(put.key),
            OpKind::AllowPut { .. }
            | OpKind::AllowDelete { .. }
            | OpKind::DenyPut { .. }
            | OpKind::DenyDelete { .. } => Self::Permission(Permission::ListsRead),
            OpKind::InviteCodePut(_) | OpKind::InviteCodeDelete { .. } => Self::ListsOrConversation,
            OpKind::AppPut { record } => Self::AppRecord(app_id.copied(), record.clone()),
            OpKind::ReceiveKeyPut { .. } => Self::Every,
            OpKind::KeyBundlePut(put) => Self::Bundle(put.target_app_id),
            OpKind::CertPut {
                target_app_id,
                cert,
            } => Self::RenewedCert(*target_app_id, cert.clone()),
        }
    }
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
    /// spec 12.5 step 3), at the origin the freeze names, or this switch's own when it isn't
    /// frozen. It serves once it is delivered an `identity.json` naming that origin and its
    /// key.
    pub fn import_into(&self, service_secret: [u8; 32]) -> Arc<Self> {
        self.continue_into(service_secret, false, None)
    }

    /// [`ScriptedSwitch::import_into`] at `origin`, whatever the freeze names: for a move
    /// a test scripts without a freeze.
    pub fn import_into_at(&self, service_secret: [u8; 32], origin: &str) -> Arc<Self> {
        self.continue_into(service_secret, false, Some(origin))
    }

    /// The same account under a new service key at the next generation, a key change in
    /// place, at this switch's origin: as [`ScriptedSwitch::import_into`], but the batch
    /// records keep their proofs,
    /// so a batch sent again unchanged gets its original proofs, signed with the earlier
    /// generation's key (Switch wire 6.4 step 6).
    pub fn change_key_into(&self, service_secret: [u8; 32]) -> Arc<Self> {
        self.continue_into(service_secret, true, None)
    }

    fn continue_into(
        &self,
        service_secret: [u8; 32],
        keep_proofs: bool,
        origin: Option<&str>,
    ) -> Arc<Self> {
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
        next.listed_at_epoch = inner.listed_at_epoch.clone();
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
        // A key change in place serves where this switch does; the next service of a move
        // serves where the freeze names it (Switch spec 12.5).
        next.origin = match origin {
            Some(origin) => origin.to_owned(),
            None => inner
                .frozen
                .as_ref()
                .and_then(|signed| Freeze::verify(signed, &inner.identity.public()).ok())
                .map_or_else(|| inner.origin.clone(), |freeze| freeze.next().url.clone()),
        };
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

    /// The bodies of the requests a [`Fault::Unreachable`] stopped, in order.
    pub fn unreached_bodies(&self) -> Vec<Vec<u8>> {
        self.lock().unreached.clone()
    }

    /// Script an attempt `app` owns on the claim `claim_key`, open, as its `attempt` entry
    /// would leave it, but with no entry or proof held and without the permission check the
    /// service makes (`claims.write`): for what `GET /apps` lists of an app's open attempts
    /// (Switch wire 7.4.12, 6.8).
    ///
    /// # Errors
    ///
    /// [`ScriptError::Refused`], as the service refuses the entry (`409 conflict`), when the
    /// claim has an open attempt or is SETTLED.
    pub fn open_attempt(
        &self,
        claim_key: [u8; 32],
        attempt_id: [u8; 16],
        app: [u8; 16],
    ) -> Result<(), ScriptError> {
        let mut inner = self.lock();
        let now = inner.now();
        let claim = inner.shared.claims.entry(claim_key).or_default();
        if claim.settled || claim.current.is_some() {
            return Err(ScriptError::Refused {
                status: 409,
                body: json!({ "code": "conflict" }),
            });
        }
        claim.attempts.push(pubky_switch_core::claims::Attempt {
            attempt_id,
            owner: app,
            outcome: pubky_switch_core::claims::Outcome::Open,
            opened_at: now,
            orphan_after: 86_400,
            possibly_duplicate: false,
            duplicate: false,
            resolved_by: None,
            from_upload: false,
        });
        claim.current = Some(claim.attempts.len() - 1);
        Ok(())
    }

    /// Script the attempt `attempt_id` on `claim_key` resolved as `failed` by the app `by`,
    /// as its `failed` entry would leave it, without the permission and writer checks the
    /// service makes (Switch wire 6.8).
    pub fn fail_attempt(&self, claim_key: [u8; 32], attempt_id: [u8; 16], by: [u8; 16]) {
        let mut inner = self.lock();
        if let Some(claim) = inner.shared.claims.get_mut(&claim_key) {
            for attempt in &mut claim.attempts {
                if attempt.attempt_id == attempt_id {
                    attempt.outcome = pubky_switch_core::claims::Outcome::Failed;
                    attempt.resolved_by = Some(by);
                }
            }
            claim.current = None;
        }
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

    /// A service that frees a purged app's record (Switch wire 9.1): `app`, revoked or
    /// departed and purged from `removed`, keeps its App ID for good, but its record and
    /// receive key go, so every call of it but a first call meets the refusal of one, `403
    /// not_current` without the head (Switch wire 7.2 "Where an own app gets `403
    /// not_current`"). The service keeps them, and answers with the head.
    pub fn purge(&self, app: [u8; 16]) {
        let mut inner = self.lock();
        let held = inner.apps.entry(app).or_default();
        held.departed = true;
        held.record = None;
        held.cert = None;
        held.receive_key = None;
        held.receive_n = None;
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

    /// A transport that answers every request from this switch at once, and records the
    /// requests. It holds no read: a feed read with `wait` is answered as one without. For a
    /// switch that holds one, see [`ScriptedSwitch::holding_transport`].
    pub fn transport(self: &Arc<Self>) -> Arc<MockTransport> {
        let switch = Arc::clone(self);
        Arc::new(MockTransport::with_handler(move |request| {
            switch.handle(request)
        }))
    }

    /// A transport that answers every request from this switch, and holds a feed read with
    /// `wait` that has nothing to show, as the service holds it (Switch wire 7.4.4): until
    /// the account's sequence grows, or until the wait has passed by the switch's clock,
    /// which a held read notices at the next request to the switch or at
    /// [`ScriptedSwitch::release_held_reads`].
    pub fn holding_transport(self: &Arc<Self>) -> Arc<dyn Transport> {
        Arc::new(Holding(Arc::clone(self)))
    }

    /// Let the held feed reads look again: one whose wait has passed by the clock is
    /// answered. For a test that moved the clock and sends nothing else to the switch.
    pub fn release_held_reads(&self) {
        self.lock().wake_held();
    }

    /// How many feed reads the switch holds now that it hasn't woken since they last
    /// looked.
    pub fn held_reads(&self) -> usize {
        self.lock().held.len()
    }

    /// The wait of `request`, if it is a feed read with `wait` that a current own app sent:
    /// the app and its certificate, the `seq` it reads after, and when its wait ends by the
    /// switch's clock.
    fn waiting_read(&self, request: &Request) -> Option<Held<'_>> {
        if request.method != "GET" {
            return None;
        }
        let (path, query) = request.path_and_query.split_once('?')?;
        if !path.ends_with("/feed") {
            return None;
        }
        let app = request
            .header(header::APP)
            .and_then(|text| app_id_decode(text).ok())?;
        // A query the feed refuses is answered at once.
        let params = parse_query(query)?;
        let after = match params.get("after") {
            Some(value) => Position::parse(value).ok()?.seq,
            None => 0,
        };
        let wait_s = feed_wait(params.get("wait")?).filter(|seconds| *seconds > 0)?;
        // The read is admitted as it arrives, as the service admits it under its lock: an
        // account that doesn't serve it (gone, staged, or frozen for a write) or an app that
        // isn't current is answered at once, and the app is seen now, not when its read is
        // answered.
        let mut inner = self.lock();
        if inner
            .gate(&request.method, &request.path_and_query)
            .is_some()
        {
            return None;
        }
        let cert = inner.own_call(&app).ok()?;
        inner.seen_at_arrival = false;
        inner.seen(request);
        // The read ends its app's lagging mark as it arrives, before any wait (Switch wire
        // 7.4.4).
        if let Some(held) = inner.apps.get_mut(&app) {
            held.lagging = false;
        }
        let until_ms = inner.now().saturating_add(wait_s.saturating_mul(1000));
        inner.held_ids += 1;
        let id = inner.held_ids;
        let key = inner.service.verifying_key().to_bytes();
        drop(inner);
        Some(Held {
            switch: self,
            id,
            key,
            app,
            cert,
            after,
            until_ms,
        })
    }

    /// The answer to a held read whose account's service key is no longer `key`: `503
    /// unavailable` with the operator key, with no head (Switch wire 7.4.4); `None` while
    /// the key is the same.
    fn key_changed_since(&self, key: [u8; 32], request: &Request) -> Option<Response> {
        let inner = self.lock();
        if inner.service.verifying_key().to_bytes() == key {
            return None;
        }
        let (status, body) = bad(
            ErrorCode::Unavailable,
            "7.6: a temporary failure",
            Value::Null,
        );
        let operator = SigningKey::from_bytes(&[42; 32]);
        Some(inner.respond_with(&operator, request, status, &body))
    }

    /// Keep the chain by `retention`, or, with `None`, keep every stub and sign no checkpoint
    /// but those a test scripts. By the service's defaults until set.
    pub fn set_retention(&self, retention: Option<Retention>) {
        self.lock().retention = retention;
    }

    /// The latest checkpoint the switch signed, if any, and the `seq` it dropped stubs
    /// through (Switch wire 7.4.4).
    pub fn retained(&self) -> (Option<SignedHead>, u64) {
        let inner = self.lock();
        (inner.checkpoint, inner.dropped_through)
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
        self.answer(request, false)
    }

    /// [`ScriptedSwitch::handle`]; `held` for a feed read the switch held, whose app was
    /// seen when the read arrived and isn't seen again.
    fn answer(&self, request: &Request, held: bool) -> Result<Response, TransportError> {
        let mut inner = self.lock();
        inner.seen_at_arrival = held;
        // A held read whose wait has passed is answered now at the latest.
        inner.wake_held();
        let path = request.path_and_query.clone();
        let mut lose = false;
        let mut leave_out = None;
        let mut replace = None;
        let mut sign_with = None;
        let matching = inner.faults.iter().position(|fault| match fault {
            Fault::Error { path: p, .. }
            | Fault::LoseAnswer { path: p }
            | Fault::LoseAnswerAfter { path: p, .. }
            | Fault::Unreachable { path: p, .. }
            | Fault::LeaveOut { path: p, .. }
            | Fault::Replace { path: p, .. }
            | Fault::SignWith { path: p, .. }
            | Fault::ErrorSignedWith { path: p, .. } => path.contains(p.as_str()),
        });
        let passes = matching.is_some_and(|index| match inner.faults.get_mut(index) {
            Some(Fault::Unreachable { after, .. } | Fault::LoseAnswerAfter { after, .. })
                if *after > 0 =>
            {
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
                    // An enrollment's errors are the operator's (Switch wire 7.4.1).
                    if request.method == "POST" && path == "/v1/enroll" {
                        let operator = SigningKey::from_bytes(&[42; 32]);
                        return Ok(inner.respond_with(&operator, request, status, &body));
                    }
                    return Ok(inner.respond(request, status, &body));
                }
                Some(Fault::LoseAnswer { .. } | Fault::LoseAnswerAfter { .. }) => lose = true,
                Some(Fault::LeaveOut { member, .. }) => leave_out = Some(member),
                Some(Fault::Replace { member, value, .. }) => replace = Some((member, value)),
                Some(Fault::SignWith { secret, .. }) => sign_with = Some(secret),
                Some(Fault::ErrorSignedWith { code, secret, .. }) => {
                    let (status, body) = bad(code, "scripted", Value::Null);
                    // As for `Fault::Error`: past authentication, the app was seen.
                    if status != 401 {
                        inner.seen(request);
                    }
                    let key = SigningKey::from_bytes(&secret);
                    return Ok(inner.respond_with(&key, request, status, &body));
                }
                Some(Fault::Unreachable { .. }) => {
                    inner.unreached.push(request.body.clone());
                    return Err(TransportError::Connect("scripted".into()));
                }
                None => {}
            }
        }
        if request.method == "POST" && path == "/v1/enroll" {
            // Its timestamp is checked first, as every request's (Switch wire 7.1): a stale
            // enrollment is refused whatever the switch holds for it.
            if let Some(answer) = inner.stale_enrollment(request) {
                return Ok(answer);
            }
            let (status, body) = inner
                .enroll(request)
                .map_err(|error| TransportError::Other(format!("scripted switch: {error}")))?;
            // Taken whatever happens to the answer, so it never signs a later one.
            let key = inner.answer_key.take();
            if lose {
                return Err(TransportError::Timeout);
            }
            // Its errors are the operator's, as at the service (Switch wire 7.4.1).
            if status != 200 {
                let operator = SigningKey::from_bytes(&[42; 32]);
                return Ok(inner.respond_with(&operator, request, status, &body));
            }
            if let Some(key) = key {
                return Ok(inner.respond_with(&key, request, status, &body));
            }
            return Ok(inner.respond(request, status, &body));
        }
        let stamped_before = inner.stamped_ms;
        if let Some(answer) = inner.stale_timestamp(request) {
            return Ok(answer);
        }
        let caller = request
            .header(header::APP)
            .and_then(|text| app_id_decode(text).ok());
        let rest = path.splitn(4, '/').nth(3).unwrap_or_default().to_owned();
        let account = inner.identity.public();
        // An own app the switch holds no record for, at any call but a batch that carries
        // its `app.put` (or doesn't parse, which the batch's checks refuse first): no key
        // verifies the request, so authentication refuses it,
        // whatever the route and before the account's lock, the staged and frozen answers
        // included, as the service does: `403 not_current`, no head, the last committed
        // time, and the app not seen (Switch wire 7.1 "`Switch-Head` on refusals", 7.2 "An
        // own app's first call", 7.3 steps 5 to 8).
        if let Some(app) = caller
            && !(inner.erased || inner.enrolled.is_none())
            && inbox::Sender::foreign(request, &account).is_none()
            && !(request.method == "POST" && rest == "ops" && carries_app_put(&request.body, &app))
            && inner
                .apps
                .get(&app)
                .is_none_or(|held| held.record.is_none())
        {
            inner.stamped_ms = stamped_before;
            if lose {
                return Err(TransportError::Timeout);
            }
            let (status, body) = bad(
                ErrorCode::NotCurrent,
                "Switch wire 7.2: an own app's first call carries its app.put",
                json!(null),
            );
            return Ok(inner.respond_at(&inner.service, request, status, &body, stamped_before));
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
        // The account's sweep, at each request of its own apps and its signer, before the
        // request is handled, as the service sweeps at step 4 (Switch wire 7.3, 9.1).
        inner.sweep_chain();
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
        if let (Some((member, value)), Some(object)) = (replace, body.as_object_mut()) {
            object.insert(member, value);
        }
        if let Some(secret) = sign_with {
            let key = SigningKey::from_bytes(&secret);
            return Ok(inner.respond_with(&key, request, status, &body));
        }
        Ok(inner.respond(request, status, &body))
    }

    /// Deliver an own `identity.json` (the signer's `PUT /identity`): an `identity` chain
    /// item. A document naming this switch's origin and service key makes a staged switch
    /// serve.
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
        // As an append: the lagging marks are judged before it and with it in (Switch wire
        // 7.4.4).
        inner.judge_lagging();
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
        inner.judge_lagging();
        seq
    }

    /// An `unreadable` item: an entry a departed own app left unread (Switch wire 7.4.4).
    /// Returns its `seq`.
    pub fn push_unreadable(&self, sender: [u8; 32], accepted_at: u64) -> u64 {
        let mut inner = self.lock();
        let seq = inner.next_seq();
        inner.items.push(Item::Unreadable {
            seq,
            entry_id: Inner::entry_id(seq),
            sender,
            accepted_at,
            scripted: true,
        });
        seq
    }

    /// Keep the entries every reader they wait for has passed, where the switch deletes
    /// them as the service does (Switch wire 9.1): the state of an inbox whose entries
    /// another target still holds, for a test that reads an entry again from an earlier
    /// cursor, as after a restore.
    pub fn keep_passed_entries(&self) {
        self.lock().keep_passed = true;
    }

    /// Set the inbox quota (Switch wire 9.2 `quota_bytes`), which an enrollment announces
    /// and the current apps share: an app whose unread entries pass its share is marked
    /// lagging (Switch wire 7.4.4). The switch refuses no append for it.
    pub fn set_inbox_quota(&self, quota_bytes: u64) {
        self.lock().enroll_limits.quota_bytes = quota_bytes;
    }

    /// Set `uploads_per_app_per_hour` (Switch wire 9.2): the recovery uploads the switch
    /// takes from each app in an hour of its clock.
    pub fn set_uploads_per_app_per_hour(&self, uploads: u32) {
        self.lock().uploads_per_app_per_hour = uploads;
    }

    /// A `missed` item whose times don't parse, as a faulty service may write one (Switch
    /// wire 7.4.4). Returns its `seq`.
    pub fn push_missed_unparsable(&self, entries: u64) -> u64 {
        self.push_missed(entries, UNPARSABLE_TIME, UNPARSABLE_TIME)
    }

    /// A `missed` item: `entries` entries accepted from `from` until `until` were deleted
    /// while the app lagged (Switch wire 7.4.4). Returns its `seq`.
    pub fn push_missed(&self, entries: u64, from: u64, until: u64) -> u64 {
        let mut inner = self.lock();
        let seq = inner.next_seq();
        inner.items.push(Item::Missed {
            seq,
            app: None,
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

    /// Recover the account in place, as a signer that enrolled here again and was answered
    /// `pending` does by delivering `doc`, the next generation naming that key, on `prev`:
    /// through the switch's own `PUT /identity` (Switch spec 12.6 step 1, wire 3.3). For
    /// tests of what a recovery in place does to the apps.
    ///
    /// # Errors
    ///
    /// The switch's refusal of the delivery.
    #[cfg(test)]
    pub(crate) fn recover_in_place(
        &self,
        pending: SigningKey,
        doc: &IdentityDoc,
        prev: [u8; 32],
    ) -> Result<(), ScriptError> {
        let mut inner = self.lock();
        inner.pending = Some((pending, Vec::new()));
        let delivery = pubky_switch_core::http::IdentityDelivery {
            identity: doc.signed().clone(),
            prev: Some(prev),
        }
        .to_json();
        let (status, body) = inner.put_identity(&delivery)?;
        if status != 200 {
            return Err(ScriptError::Refused { status, body });
        }
        Ok(())
    }

    /// Chain an `upload` transition by `by` listing `changes` as written, merging nothing,
    /// as after an upload whose merge the test made itself (Switch wire 7.4.14). For tests
    /// of what an app does with the transition.
    ///
    /// # Errors
    ///
    /// As [`ScriptedSwitch::signer_op`].
    #[cfg(test)]
    pub(crate) fn chain_upload(&self, by: [u8; 16], changes: Value) -> Result<(), ScriptError> {
        let mut inner = self.lock();
        let at = inner.now();
        inner.service_transition(ServiceTransition::Upload {
            by,
            changes,
            proofs: 0,
            at,
        })?;
        Ok(())
    }

    /// Move `app`'s cursor to `seq`, in a batch of its own, as a submitted `cursor.set` does
    /// (Switch wire 6.2). For tests of what a cursor move changes.
    ///
    /// # Errors
    ///
    /// As [`ScriptedSwitch::signer_op`].
    #[cfg(test)]
    pub(crate) fn move_cursor(&self, app: [u8; 16], seq: u64) -> Result<(), ScriptError> {
        let mut inner = self.lock();
        let generation = inner.tip.generation;
        let (status, body) = inner.submit(Some(app), &[], Some(Position { generation, seq }))?;
        if status != 200 {
            return Err(ScriptError::Refused { status, body });
        }
        Ok(())
    }

    /// Set `app`'s cursor to `seq` directly, with none of a move's rules: the state a switch
    /// left from before it dropped parts at cursor moves. For tests.
    #[cfg(test)]
    pub(crate) fn set_cursor_unchecked(&self, app: [u8; 16], seq: u64) {
        self.lock().apps.entry(app).or_default().cursor = seq;
    }

    /// `app`'s `keys_through` as `GET /apps` shows it (Switch wire 7.4.12). For tests.
    #[cfg(test)]
    pub(crate) fn keys_through_of(&self, app: &[u8; 16]) -> Option<u64> {
        self.lock().keys_through(app)
    }

    /// The feed items `app` is shown, in order, read page by page through the feed route
    /// itself (Switch wire 3.8, 7.4.4, 7.5), so a test judges what the route shows, with the
    /// certificate the route checks the app against; the read isn't counted against a
    /// scripted feed limit. Empty for an app the route refuses. For tests of what the fake
    /// shows each app.
    #[cfg(test)]
    pub(crate) fn shown(&self, app: [u8; 16]) -> Vec<Value> {
        let mut inner = self.lock();
        let reads = inner.feed_reads;
        let mut items = Vec::new();
        let mut query = String::new();
        loop {
            let (status, page) = inner.feed(Some(app), &query);
            if status != 200 {
                break;
            }
            if let Some(shown) = page["items"].as_array() {
                items.extend(shown.iter().cloned());
            }
            match (page["more"].as_bool(), page["next"].as_str()) {
                (Some(true), Some(next)) => query = format!("after={next}"),
                _ => break,
            }
        }
        inner.feed_reads = reads;
        items
    }

    /// Chain an operation without checking it, as a faulty service does, and store a key
    /// bundle part or a renewed certificate it carries, so the feed shows that item in full
    /// to its readers; nothing else is applied, so an unchecked `record.put`, `claim` or
    /// `app.put` has no current document and shows as a stub to every app. For tests of what
    /// an app does with an item a compliant switch refuses.
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
            if let OpKind::CertPut {
                target_app_id,
                cert,
            } = &body.kind
            {
                let renewed = AppCert::verify(cert, &account)?;
                inner.apps.entry(*target_app_id).or_default().renewed = Some(renewed);
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
                Readers::of_op(&body.kind, body.app_id.as_ref()),
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

    /// Whether admission is staged after a provider loss (Switch spec 12.6 step 2).
    pub fn admission_staged(&self) -> bool {
        self.lock().admission_staged
    }

    /// The generation the switch's account serves.
    pub fn generation(&self) -> u64 {
        self.lock().tip.generation
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
        if self.seen_at_arrival {
            return;
        }
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

    /// The retention sweep (Switch wire 7.4.4, 9.1): a checkpoint signed once enough chain
    /// items may go, and the stubs behind it dropped, oldest first. A stub may go once it is
    /// `cursor_hold_ms` old, or every current app (`current_app_ids`) has moved its cursor
    /// past it; an app that hasn't moved its cursor yet holds the stubs from its
    /// registration, here from the time the switch took its first record. It never cuts
    /// inside a batch. Nothing goes while the account is frozen, staged or erased.
    fn sweep_chain(&mut self) {
        let Some(retention) = self.retention else {
            return;
        };
        if self.frozen.is_some() || self.staged || self.erased || self.enrolled.is_none() {
            return;
        }
        if self.doc.is_none() {
            return;
        }
        let now = self.now();
        // The current apps, as the inbox's retention counts them (`current_app_ids`).
        let holders: Vec<(u64, Option<u64>)> = self
            .current_app_ids()
            .iter()
            .filter_map(|app| self.apps.get(app))
            .map(|app| (app.cursor, app.record_at))
            .collect();
        let holds = |seq: u64, at: u64| {
            at.saturating_add(retention.cursor_hold_ms) > now
                && holders.iter().any(|(cursor, joined)| {
                    *cursor < seq && (*cursor > 0 || joined.is_some_and(|joined| at >= joined))
                })
        };
        // The newest chain item that may go and ends a batch, or is of none.
        let mut cut: Option<ChainTip> = None;
        let mut may_go = 0;
        let mut since_cut = 0;
        let mut left_in_batch = 0;
        let mut looked = 0;
        for item in &self.items {
            let Item::Chain { seq, stub, .. } = item else {
                continue;
            };
            if *seq <= self.dropped_through {
                continue;
            }
            looked += 1;
            if looked > retention.per_request {
                break;
            }
            let Ok(envelope) = ChainEnvelope::parse(&stub.envelope) else {
                break;
            };
            if holds(*seq, envelope.server_time) {
                break;
            }
            since_cut += 1;
            let ends = match envelope.batch {
                Some(batch) => {
                    if left_in_batch == 0 {
                        left_in_batch = batch.count;
                    }
                    left_in_batch = left_in_batch.saturating_sub(1);
                    left_in_batch == 0
                }
                None => true,
            };
            if ends {
                may_go += since_cut;
                since_cut = 0;
                cut = Some(ChainTip {
                    generation: envelope.generation,
                    seq: *seq,
                    chain_hash: stub.chain_hash,
                });
            }
        }
        let checkpointed = self.checkpoint.as_ref().map_or(0, |c| c.seq);
        if retention.at_head {
            let added = self
                .items
                .iter()
                .filter(|item| matches!(item, Item::Chain { seq, .. } if *seq > checkpointed))
                .count();
            if u64::try_from(added).unwrap_or(u64::MAX) >= retention.checkpoint_behind {
                self.checkpoint = Some(SignedHead::sign(
                    &self.service,
                    &self.identity.public(),
                    &self.tip,
                ));
            }
        } else if let Some(cut) = cut.filter(|_| may_go >= retention.checkpoint_behind) {
            self.checkpoint = Some(SignedHead::sign(
                &self.service,
                &self.identity.public(),
                &cut,
            ));
        }
        // Behind the latest checkpoint, what the rule lets go.
        let through = cut
            .map_or(0, |c| c.seq)
            .min(self.checkpoint.as_ref().map_or(0, |c| c.seq));
        self.dropped_through = self.dropped_through.max(through);
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
        // The account changes: the held reads look again.
        self.wake_held();
        self.seq
    }

    /// Wake every held feed read, to look again.
    fn wake_held(&mut self) {
        for (_, waker) in self.held.drain(..) {
            waker.wake();
        }
    }

    /// Whether the feed has an item past `after` to show own app `app`, whole or as a stub:
    /// a read with `wait` is held while it has none (Switch wire 7.4.4).
    fn shows_after(&self, app: [u8; 16], cert: &AppCert, after: u64) -> bool {
        self.items
            .iter()
            .filter(|item| item.seq() > after)
            .any(|item| self.show(item, app, Some(cert)).is_some())
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

    /// An enrollment whose `Switch-Timestamp` is more than 5 minutes from the time base is
    /// `401 stale_timestamp` (Switch wire 7.1), at an account the switch holds or not, and
    /// whatever became of the key its answer named: the refusal comes before the enrollment
    /// is looked at. It is the operator's, as an enrollment's other errors are (Switch wire
    /// 7.4.1), and stamps nothing.
    fn stale_enrollment(&self, request: &Request) -> Option<Response> {
        let now = self.now();
        let stale = request
            .header(header::TIMESTAMP)
            .and_then(|text| pubky_switch_core::time::parse_rfc3339(text).ok())
            .is_some_and(|at| at.abs_diff(now) > pubky_switch_core::records::CLOCK_TOLERANCE_MS);
        if !stale {
            return None;
        }
        let (status, body) = bad(
            ErrorCode::StaleTimestamp,
            "Switch wire 7.1: the timestamp is more than 5 minutes from the service's time",
            json!({ "server_time": rfc3339(now) }),
        );
        let operator = SigningKey::from_bytes(&[42; 32]);
        Some(self.respond_with(&operator, request, status, &body))
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
        let mut headers = vec![
            Header::new(header::SERVICE_SIGNATURE, &b64(&signature)),
            Header::new(header::SERVER_TIME, &server_time),
        ];
        // A `429` repeats its body's `retry_after` in `Retry-After` (Switch wire 7.1, 7.6).
        if let Some(seconds) = body
            .get("retry_after")
            .and_then(Value::as_u64)
            .filter(|_| status == 429)
        {
            headers.push(Header::new(header::RETRY_AFTER, &seconds.to_string()));
        }
        Response {
            status,
            headers,
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
        readers: Readers,
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
            readers,
            context: None,
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
        let was = self.current_app_ids();
        let held = self.apps.entry(app).or_default();
        held.departed = true;
        held.revoked_at = Some(at);
        self.unreachable(&app);
        self.push.remove(&app);
        let proof = self.service_transition(ServiceTransition::Revoke { app_id: app, at })?;
        // After its chain item (Switch wire 7.4.4).
        self.after_departure(was);
        Ok(Some(proof))
    }

    /// `app` leaves (Switch spec 12.3): the `leave` transition's proof, or `None` for an app
    /// revoked or departed already.
    pub(crate) fn leave(&mut self, app: [u8; 16]) -> Result<Option<SignedDoc>, ScriptError> {
        if self.apps.get(&app).is_some_and(|a| a.departed) {
            return Ok(None);
        }
        let at = self.now();
        let epoch = self.doc.as_ref().map_or(0, IdentityDoc::data_epoch);
        let was = self.current_app_ids();
        let held = self.apps.entry(app).or_default();
        held.departed = true;
        held.departed_at = Some((at, epoch));
        self.unreachable(&app);
        let proof = self.service_transition(ServiceTransition::Leave { app_id: app, at })?;
        // After its chain item (Switch wire 7.4.4).
        self.after_departure(was);
        Ok(Some(proof))
    }

    fn service_transition(
        &mut self,
        transition: ServiceTransition,
    ) -> Result<SignedDoc, ScriptError> {
        let signed = transition.sign(&self.service, &self.identity.public())?;
        let hash = item_hash(ItemType::Service, &signed.doc_bytes()?);
        let object = transition.proof_object().unwrap_or_default();
        let state = ProofState::Service(transition.to_value());
        let readers = match transition {
            ServiceTransition::ConversationAdd { .. } => Readers::Permission(Permission::ListsRead),
            ServiceTransition::Revoke { .. }
            | ServiceTransition::Leave { .. }
            | ServiceTransition::Freeze { .. }
            | ServiceTransition::Unfreeze { .. }
            | ServiceTransition::Recovery { .. }
            | ServiceTransition::Admission { .. }
            | ServiceTransition::Upload { .. } => Readers::Every,
        };
        self.chain_item(
            ItemType::Service,
            signed,
            hash,
            None,
            &object,
            &state,
            readers,
        )
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
                ("POST", "recovery/admission") => self.recovery_admission(&request.body)?,
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
            // The leave is the app's latest request past authentication (Switch wire 7.4.12
            // `last_seen`), seen before it departs the app.
            ("POST", r) if r == own_leave => {
                self.seen(request);
                match self.leave(app)? {
                    Some(proof) => (
                        200,
                        json!({ "proofs": [proof], "head": self.head().to_value() }),
                    ),
                    None => bad(ErrorCode::NotCurrent, "departed", json!(null)),
                }
            }
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
        // Visibility is judged with the certificate the app is checked against: a stored
        // renewed one once the newest `identity.json` lists it (Switch wire 3.8, 7.5).
        let cert = match self.own_call(&app) {
            Ok(cert) => cert,
            Err(refusal) => return batch::refused(&refusal),
        };
        if self
            .feed_limit
            .is_some_and(|limit| self.feed_reads >= limit)
        {
            return bad(ErrorCode::Unavailable, "feed read limit", json!(null));
        }
        self.feed_reads += 1;
        // The query as the service reads it (`crates/pubky-switch/src/service/feed.rs`,
        // `FeedQuery::parse`): decoded, `after` a position, `limit` 1 to 500 (100 by
        // default) and `wait` at most 25, each digits only. The read was held before it came
        // here, if it had nothing to show.
        let Some(params) = parse_query(query) else {
            return bad(
                ErrorCode::BadRequest,
                "the query doesn't decode",
                json!(null),
            );
        };
        let after = match params.get("after").map(|value| Position::parse(value)) {
            None => 0,
            Some(Ok(position)) => position.seq,
            Some(Err(_)) => return bad(ErrorCode::BadRequest, "after", json!(null)),
        };
        let limit = match params.get("limit").map(|value| decimal(value)) {
            None => 100usize,
            Some(Some(value @ 1..=500)) => usize::try_from(value).unwrap_or(500),
            Some(_) => return bad(ErrorCode::BadRequest, "limit", json!(null)),
        };
        if params
            .get("wait")
            .is_some_and(|value| feed_wait(value).is_none())
        {
            return bad(ErrorCode::BadRequest, "wait", json!(null));
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
        for (scanned, group) in groups.into_iter().enumerate() {
            if items.len() >= limit || self.max_page_scan.is_some_and(|max| scanned >= max) {
                truncated = true;
                break;
            }
            let shown: Vec<Value> = group
                .iter()
                .filter_map(|item| self.show(item, app, Some(&cert)))
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
        // The reader's feed read ends its lagging mark (Switch wire 7.4.4).
        if let Some(held) = self.apps.get_mut(&app) {
            held.lagging = false;
        }
        (200, page)
    }

    /// Whether own app `app`, checked against `cert`, reads chain item `seq` in full: it is
    /// among the item's `readers`, and the item's document is still the current one (Switch
    /// wire 7.5).
    fn reads_in_full(
        &self,
        readers: &Readers,
        seq: u64,
        app: [u8; 16],
        cert: Option<&AppCert>,
    ) -> bool {
        let holds = |permission| cert.is_some_and(|c| c.has_permission(permission));
        match readers {
            Readers::Every => true,
            Readers::Permission(permission) => holds(*permission),
            Readers::ListsOrConversation => {
                holds(Permission::ListsRead) || holds(Permission::ConversationAdd)
            }
            Readers::Claim(key) => {
                holds(Permission::ClaimsRead)
                    && <[u8; 32]>::try_from(key.as_slice())
                        .is_ok_and(|key| self.shared.claim_entry_current(&key, seq))
            }
            Readers::Record(key) => self.shared.records.get(key).is_some_and(|held| {
                held.seq == seq
                    && cert.is_some_and(|c| c.holds_scope(&held.state.policy.read_scope))
            }),
            Readers::Bundle(target) => {
                *target == app
                    && self
                        .bundles
                        .get(target)
                        .is_some_and(|parts| parts.iter().any(|(_, at)| *at == seq))
            }
            Readers::AppRecord(writer, record) => writer.is_some_and(|writer| {
                self.apps
                    .get(&writer)
                    .is_some_and(|held| held.record.as_ref() == Some(record))
            }),
            Readers::RenewedCert(target, renewed) => self
                .apps
                .get(target)
                .and_then(|held| held.renewed.as_ref())
                .is_some_and(|held| held.signed() == renewed),
        }
    }

    /// An entry ID for the item at `seq`: its low byte, repeated.
    fn entry_id(seq: u64) -> String {
        b64(&[seq.to_le_bytes()[0]; 16])
    }

    /// How `item` shows to own app `app`, checked against `cert` (Switch wire 7.5); `None`
    /// for an item it isn't shown at all.
    fn show(&self, item: &Item, app: [u8; 16], cert: Option<&AppCert>) -> Option<Value> {
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
                readers,
                context,
            } => {
                if *seq <= self.dropped_through {
                    return None;
                }
                if !self.reads_in_full(readers, *seq, app, cert) {
                    return Some(json!({ "type": "stub", "seq": seq, "stub": stub.to_value() }));
                }
                let mut value = json!({ "type": "chain", "seq": seq, "stub": stub.to_value(),
                                        "item_type": item_type.as_str(), "item": item });
                if let Some(proof) = proof
                    && *item_type == ItemType::Op
                {
                    value["proof"] = json!(proof);
                }
                if let Some(context) = context {
                    value["context"] = context.clone();
                }
                value
            }
            Item::Unreadable {
                seq,
                entry_id,
                sender,
                accepted_at,
                ..
            } => json!({ "type": "unreadable", "seq": seq, "entry_id": entry_id,
                         "sender": pubky_id(sender), "accepted_at": rfc3339(*accepted_at) }),
            Item::Missed {
                seq,
                app: of,
                entries,
                from,
                until,
            } => {
                // The lagging app it was made for alone is shown it (Switch wire 7.5).
                if of.is_some_and(|of| of != app) {
                    return None;
                }
                // A scripted item whose times don't parse ([`ScriptedSwitch::push_missed_unparsable`]).
                let time = |at: u64| {
                    if at == UNPARSABLE_TIME {
                        json!("not a time")
                    } else {
                        json!(rfc3339(at))
                    }
                };
                json!({ "type": "missed", "seq": seq, "entries": entries,
                        "accepted_from": time(*from), "accepted_until": time(*until) })
            }
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
        // In the service's order: the caller's own checks, then the stage, then the body
        // (Switch wire 7.2, 7.4.14). A staged service takes an app's evidence before the app
        // registers there (Switch spec 12.5 step 3).
        let Some(app) = caller else {
            return Ok(bad(
                ErrorCode::PermissionMissing,
                "an own app uploads",
                json!(null),
            ));
        };
        // An upload from an app the switch holds a record for takes its slot of the hour
        // here, before the caller's own checks and the stage, as the service takes it once
        // the request verifies: one answered `403 not_current` or `404` counts too (Switch
        // wire 7.4.14, 9.4). The `429` itself comes last in the answer order.
        let limited = match self.apps.get(&app) {
            Some(held) if held.cert.is_some() => self.take_upload_slot(app),
            _ => None,
        };
        let cert = if self.staged {
            None
        } else {
            match self.own_call(&app) {
                Ok(cert) => Some(cert),
                Err(refusal) => return Ok(batch::refused(&refusal)),
            }
        };
        // Neither after a provider loss nor in a move (Switch wire 7.4.14 "Which stage").
        if !self.staged && self.recovery_from.is_none() && self.continued_from.is_none() {
            return Ok(bad(
                ErrorCode::NotFound,
                "neither after a provider loss nor in a move",
                json!(null),
            ));
        }
        let read = serde_json::from_slice::<Value>(&request.body);
        let with_cert = request.header(header::CERT).is_some();
        // After a provider loss the upload's slot is taken before its body is read, so one
        // that doesn't read counts too (Switch wire 7.4.14, 9.4).
        if let (false, Some(recovery_from), Some(cert)) = (self.staged, self.recovery_from, cert) {
            if let Ok(body) = read {
                self.uploads.push((body, with_cert));
            }
            return self.loss_upload(&request.body, app, &cert, recovery_from, limited);
        }
        let Ok(body) = read else {
            return Ok(bad(ErrorCode::BadRequest, "upload", json!(null)));
        };
        let count = |name: &str| body[name].as_array().map_or(0, Vec::len) as u64;
        let (heads, proofs) = (count("heads"), count("proofs"));
        self.uploads.push((body.clone(), with_cert));
        if self.staged {
            return Ok((200, json!({ "heads": heads, "proofs": proofs })));
        }
        let changes = json!({ "records": [], "divergent": [], "claims": [],
                              "divergent_claims": [], "unverified": 0, "distrusted": 0,
                              "refused": 0, "heads": heads,
                              "lists": body.get("lists").is_some() });
        Ok((
            200,
            json!({ "heads": heads, "proofs": proofs, "merged": changes,
                    "head": self.head().to_value() }),
        ))
    }

    /// Take `app`'s slot of `uploads_per_app_per_hour` in the hour of the switch's clock
    /// (Switch wire 9.4): `None` when it got one, else the seconds to the next hour. An
    /// upload past the limit takes none.
    fn take_upload_slot(&mut self, app: [u8; 16]) -> Option<u64> {
        let (now, hour_ms) = (self.now(), 3_600_000);
        let hour = now / hour_ms;
        let count = self.upload_counts.entry(app).or_insert((hour, 0));
        if count.0 < hour {
            *count = (hour, 0);
        }
        if count.1 >= self.uploads_per_app_per_hour {
            let next = count.0.saturating_add(1).saturating_mul(hour_ms);
            return Some(next.saturating_sub(now).div_ceil(1000).max(1));
        }
        count.1 += 1;
        None
    }

    /// Whether `app` has taken a slot of `uploads_per_app_per_hour`, in any hour.
    #[cfg(test)]
    pub(crate) fn upload_counts_of(&self, app: &[u8; 16]) -> bool {
        self.upload_counts.contains_key(app)
    }

    /// An upload after the loss of generation `recovery_from` (Switch wire 7.4.14), checked
    /// by the core and merged as the service merges it, ending staged admission for
    /// contacts from an app holding `lists.manage`: one `upload` transition, and `{ result,
    /// proof, head }`.
    fn loss_upload(
        &mut self,
        body: &[u8],
        app: [u8; 16],
        cert: &AppCert,
        recovery_from: u64,
        limited: Option<u64>,
    ) -> Result<Answer, ScriptError> {
        // The refusals in the wire's order: the body, the caller's permission, the limit.
        let upload = match UploadBody::parse(body).and_then(|upload| {
            upload.check_permissions(cert)?;
            Ok(upload)
        }) {
            Ok(upload) => upload,
            Err(refusal) => return Ok(batch::refused(&refusal)),
        };
        if let Some(retry_after) = limited {
            let mut limited = bad(ErrorCode::RateLimited, "recovery uploads", json!(null));
            limited.1["retry_after"] = json!(retry_after);
            return Ok(limited);
        }
        let now = self.now();
        let removed = self
            .doc
            .as_ref()
            .map(|doc| doc.body().removed.clone())
            .unwrap_or_default();
        let identity = self.identity.public();
        let checked = check_upload(
            &upload,
            &UploadContext {
                identity: &identity,
                recovery_from,
                removed: &removed,
            },
        );
        let mut changes = UploadChanges {
            unverified: checked.unverified,
            distrusted: checked.distrusted,
            heads: checked.heads,
            ..UploadChanges::default()
        };
        // The transition's `seq`, the next: a record taken from the upload is at it.
        let seq = self.seq + 1;
        let caps = (self.max_contacts, self.max_deny);
        self.shared.merge_upload(
            &checked,
            upload.lists.as_ref(),
            caps,
            seq,
            now,
            &mut changes,
        );
        if upload.ends_staged_admission(cert) {
            self.admission_staged = false;
        }
        let proof = self.service_transition(ServiceTransition::Upload {
            by: app,
            changes: changes.to_value(),
            proofs: checked.proofs,
            at: now,
        })?;
        Ok((
            200,
            json!({ "result": changes.to_value(), "proof": proof,
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

    /// `GET /directory` (Switch wire 7.4.10): the current apps holding a record, in the
    /// order the newest `identity.json` lists them, as the service lists them. Current, not
    /// served: an app whose certificate has expired stays (Switch spec 3.4).
    fn directory(&self) -> Answer {
        let listed = self.doc.iter().flat_map(|doc| &doc.body().apps);
        let apps: Vec<Value> = listed
            .filter(|entry| {
                !self.kept_app_ids.contains(&entry.app_id)
                    && self.app_current_by(&self.apps, &entry.app_id, false)
            })
            .filter_map(|entry| {
                let app = self.apps.get(&entry.app_id)?;
                Some(json!({ "app_id": zbase32_encode(&entry.app_id),
                             "record": app.record.as_ref()?,
                             "receive_key": app.receive_key }))
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

/// Whether a `POST /ops` body can be an own app's first call (Switch wire 7.2): it doesn't
/// parse, which the batch's own checks refuse first (Switch wire 6.4 step 2), or an
/// `app.put` of the batch names `app`, as the service looks for it.
fn carries_app_put(body: &[u8], app: &[u8; 16]) -> bool {
    let Ok(parsed) = OpsRequest::parse(body) else {
        return true;
    };
    parsed
        .signed()
        .filter_map(|doc| SignedOp::peek(doc).ok())
        .any(|op| matches!((&op.body().kind, op.body().app_id), (OpKind::AppPut { .. }, Some(id)) if &id == app))
}
