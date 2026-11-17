//! Sending (Switch spec 7, 8.1, 8.2, 11; Switch wire 4.3, 5.1, 7.4.3, 7.4.5).
//!
//! A message is signed once and recorded in the durable outbox (`out/<msg_id>`) before
//! anything is sent, with its jobs: the conversation entry a first message to a
//! counterparty that isn't a contact needs (except the protocol's re-send kind), the
//! delivery, and the matching shared record write the protocol names. Each job is retried
//! until it completes, at the flushes of the outbox ([`App::flush_outbox`], which goes round
//! it at most [`OUTBOX_TRIES_PER_FLUSH`] messages a call); every step commits before the
//! next one acts on the network:
//!
//! 1. **The conversation entry** (`allow.put`, kept under `opq/` until answered, Switch spec
//!    7) is written before the message is sent.
//! 2. **The own `identity.json`** goes to the counterparty's switch before the first append
//!    there (Switch spec 6.1).
//! 3. **Sealing**: the signed plaintext is sealed to every recipient app the directory gives
//!    (Switch spec 8.1), and the envelope is committed with the `apps_version` it was sealed
//!    for before it is sent. Every retry sends those bytes, so a switch that took it answers
//!    the original result (Switch wire 7.4.3 step 1): a crash never sends twice.
//! 4. **The append** names the `apps_version`. `409 stale_key` has the records checked and
//!    the same signed plaintext sealed again; `409 identity_needed` has the own
//!    `identity.json` delivered and the append retried; `410 moved` has the counterparty's
//!    `identity.json` read again; `429` and `503` wait for the next flush.
//! 5. **The record job** builds the record's next value through the protocol
//!    ([`super::Protocol::sent_record`]), compare-and-swap. One still not made
//!    [`SENT_RETENTION_MS`] after the message's first acceptance, such as one whose held
//!    value waits for a key that never comes, is given up, and the protocol told
//!    ([`AppEvent::RecordJobDropped`]): the outbox doesn't keep the message for ever.
//!
//! The acceptance is committed as soon as the append is answered, before anything else is
//! done with the answer, so a crash never sends the same bytes again: with it the message
//! goes to `sent/<msg_id>`, kept 30 days from its first acceptance for re-sends (Switch spec
//! 11), which seal the same signed plaintext to the current keys ([`App::resend`]), also
//! while its record job is still owed. The message leaves the outbox once every job is done.
//!
//! Only a refusal for good marks a message failed: the Retry column of Switch spec 6.4 says
//! "No". `403 not_admitted` and `403 not_current` stay queued, as admission changes when the
//! counterparty adds a contact or an invite, and a certificate renewal makes the app current
//! again (Switch spec 7, Switch wire 3.8), but only for [`UNDELIVERABLE_MS`] from the
//! first such answer: once a try is answered so again past that time, at
//! [`UNDELIVERABLE_TRIES`] tries spread over it, the message is deleted, plaintext and all,
//! and [`AppEvent::MessageUndelivered`] tells the protocol (Switch spec 11). Whatever the
//! tries, it is deleted so at [`UNDELIVERABLE_MAX_MS`] from that first answer, at the next
//! flush, without another try: plaintext at rest has a firm bound, and a forward jump of
//! the clock shorter than that still deletes nothing. A failed message
//! is forgotten, plaintext and all, after the retention of sent messages.

use std::collections::{BTreeMap, BTreeSet};

use pubky_switch_core::enc::{serde_b64, serde_b64_vec};
use pubky_switch_core::http::{ErrorCode, Retry};
use pubky_switch_core::ident::NamingKey;
use pubky_switch_core::json::OpaqueMember;
use pubky_switch_core::message::{Message, MessagePlaintext, Sender};
use pubky_switch_core::ops::{AllowKind, OpKind};
use pubky_switch_core::records::{AppCert, CLOCK_TOLERANCE_MS, DAY_MS, IdentityDoc};
use pubky_switch_core::scopes::Permission;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::admission::allow_key;
use super::batch::OpBatch;
use super::directory::Route;
use super::error::{Refusal, WontDeliver};
use super::events::{AppEvent, Duty};
use super::records::{Collection, RecordTarget};
use super::state::key;
use super::{App, AppError};
use crate::client::answers::AppendAnswer;
use crate::error::{ClientError, StoreError};

/// How long a sent message is kept for re-sends: 30 days from its first acceptance (Switch
/// spec 11).
pub const SENT_RETENTION_MS: u64 = 30 * DAY_MS;

/// How long a message answered `403 not_admitted` or `403 not_current` stays queued, from
/// the first such answer: 30 days (Switch spec 11).
pub const UNDELIVERABLE_MS: u64 = 30 * DAY_MS;

/// How many tries answered `403 not_admitted` or `403 not_current`, each at least
/// [`UNDELIVERABLE_TRY_SPACING_MS`] after the one counted before, a message needs before it
/// is given up: the 30 days are measured on the app's clock, and spread over separate tries
/// one forward jump of it counts one try, never the whole wait.
pub const UNDELIVERABLE_TRIES: u32 = 5;

/// The least time, app clock, between two tries [`UNDELIVERABLE_TRIES`] counts.
pub const UNDELIVERABLE_TRY_SPACING_MS: u64 = UNDELIVERABLE_MS / 4;

/// The longest a message answered `403 not_admitted` or `403 not_current` stays queued, app
/// clock, from the first such answer, however few tries confirmed [`UNDELIVERABLE_MS`]: 45
/// days. Then it is deleted, plaintext and all, without another try.
pub const UNDELIVERABLE_MAX_MS: u64 = 45 * DAY_MS;

/// How many times one delivery seals again after `409 stale_key` before it waits for the
/// next flush.
const RESEALS: usize = 2;

const OUT_PREFIX: &str = "out/";
const SENT_PREFIX: &str = "sent/";
const SENT_TIME_PREFIX: &str = "sentt/";
/// A message whose delivery the app gave up, with the time until which
/// [`App::queue_stored`] refuses it (`STATE.md`).
const GIVEN_UP_PREFIX: &str = "outgone/";
/// A counterparty whose messages the app holds ([`App::hold_queued`]).
pub(crate) const HOLD_PREFIX: &str = "outhold/";

fn hold_key(pubky: &[u8; 32]) -> String {
    format!("{HOLD_PREFIX}{}", pubky_switch_core::enc::b64(pubky))
}

/// Hold `pubky`'s messages, in `tx` ([`App::hold_queued`]): a restore's commit.
pub(crate) fn put_hold(tx: &mut super::state::Tx, pubky: &[u8; 32]) -> Result<(), AppError> {
    tx.put(&hold_key(pubky), &())
}

/// A message the app holds ([`App::hold_message`]), by `msg_id`.
pub(crate) const MESSAGE_HOLD_PREFIX: &str = "outheld/";

fn message_hold_key(msg_id: &str) -> String {
    format!("{MESSAGE_HOLD_PREFIX}{msg_id}")
}

/// Hold the message `msg_id`, in `tx` ([`App::hold_message`]): a restore's commit.
pub(crate) fn put_message_hold(tx: &mut super::state::Tx, msg_id: &str) -> Result<(), AppError> {
    tx.put(&message_hold_key(msg_id), &())
}

/// End the hold of the message `msg_id`, in `tx`: in the commit that gives its delivery up.
pub(crate) fn end_message_hold(tx: &mut super::state::Tx, msg_id: &str) -> Result<(), AppError> {
    tx.delete(&message_hold_key(msg_id))
}

/// The kind of the message `msg_id` when `reader` owes its delivery at `now`: the outbox
/// holds it with a delivery owed and not refused for good, or, absent from the outbox and
/// not kept as sent, one of `kept`, the messages kept batches put there once they settle,
/// is it, its delivery not given up. What [`App::hold_message`] and
/// [`App::withdraw_message`] act on.
async fn owed_kind(
    reader: &super::state::Reader,
    msg_id: &str,
    now: u64,
    kept: &[OutboxItem],
) -> Result<Option<String>, AppError> {
    if let Some(item) = reader.get::<OutboxItem>(&out_key(msg_id)).await? {
        return Ok(item.delivery_pending().then_some(item.kind));
    }
    if !kept_message_owed(reader, msg_id, now).await? {
        return Ok(None);
    }
    Ok(kept
        .iter()
        .find(|item| item.msg_id == msg_id)
        .map(|item| item.kind.clone()))
}

/// The messages `reader` holds ([`App::hold_message`]) whose delivery it owes at `now`,
/// each with its kind, in `msg_id` order. Every commit that ends a delivery ends its hold,
/// so none is left over; one that is isn't listed or carried.
pub(crate) async fn held_messages_of(
    reader: &super::state::Reader,
    now: u64,
) -> Result<Vec<(String, String)>, AppError> {
    let marks = reader.scan::<()>(MESSAGE_HOLD_PREFIX).await?;
    if marks.is_empty() {
        return Ok(Vec::new());
    }
    let kept = super::batch::kept_queued(reader).await?;
    let mut held = Vec::new();
    for (msg_id, ()) in marks {
        if let Some(kind) = owed_kind(reader, &msg_id, now, &kept).await? {
            held.push((msg_id, kind));
        }
    }
    Ok(held)
}

pub(crate) fn out_key(msg_id: &str) -> String {
    format!("{OUT_PREFIX}{msg_id}")
}

fn sent_key(msg_id: &str) -> String {
    format!("{SENT_PREFIX}{msg_id}")
}

fn sent_time_key(at: u64, msg_id: &str) -> String {
    format!("{SENT_TIME_PREFIX}{}/{msg_id}", key::num(at))
}

fn given_up_key(msg_id: &str) -> String {
    format!("{GIVEN_UP_PREFIX}{msg_id}")
}

/// Whether the app gave up the delivery of `msg_id` and its mark still stands at `now`
/// ([`note_given_up`]). A retained outbox item or sent copy keeps the mark effective until
/// it goes too: neither may recreate an ended delivery (Switch spec 11).
pub(crate) async fn given_up(
    reader: &super::state::Reader,
    msg_id: &str,
    now: u64,
) -> Result<bool, AppError> {
    let until: Option<u64> = reader.get(&given_up_key(msg_id)).await?;
    let Some(until) = until else {
        return Ok(false);
    };
    Ok(now <= until
        || reader.exists(&out_key(msg_id)).await?
        || reader.exists(&sent_key(msg_id)).await?)
}

/// Note in `tx` that the delivery of `msg_id` was given up at `now`, in the commit that
/// gives it up and tells the protocol: [`App::queue_stored`] refuses the message from then
/// until [`SENT_RETENTION_MS`] later, and while the outbox or sent copies keep its plaintext.
/// Past that window its replay deadline refuses it anyway, so the protocol is told once.
pub(crate) fn note_given_up(
    tx: &mut super::state::Tx,
    msg_id: &str,
    now: u64,
) -> Result<(), AppError> {
    tx.put(
        &given_up_key(msg_id),
        &now.saturating_add(SENT_RETENTION_MS),
    )
}

/// The retained local origin of an outgoing message (Switch spec 11).
///
/// This is independent of prior acceptance, a re-send, and permission to deliver.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryOrigin {
    /// Work queued directly, including an intent retained in an unanswered batch.
    Original,
    /// A copy reconstructed from signed plaintext without a retained original intent.
    Reconstructed,
}

/// An authenticated outgoing message and its owning protocol's committed local state.
///
/// The plaintext retains the exact signed JSON bytes. Its hash and origin are the same
/// facts exposed by [`QueuedMessage`] (Switch spec 11).
pub struct DeliveryView<'a> {
    message: &'a Message,
    plaintext: &'a MessagePlaintext,
    origin: DeliveryOrigin,
    resend: bool,
    local: super::LocalView<'a>,
    cert: &'a AppCert,
    naming: &'a NamingKey,
    store: &'a dyn crate::store::StateStore,
    ns: &'a str,
    clock: &'a dyn crate::clock::Clock,
}

impl std::fmt::Debug for DeliveryView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeliveryView")
    }
}

impl<'a> DeliveryView<'a> {
    /// The parsed authenticated message.
    pub fn message(&self) -> &Message {
        self.message
    }

    /// The retained signed plaintext, including its original JSON bytes.
    pub fn plaintext(&self) -> &MessagePlaintext {
        self.plaintext
    }

    /// The hash of the original signed JSON (Switch wire 5.1).
    pub fn hash(&self) -> [u8; 32] {
        self.plaintext.hash()
    }

    /// The current copy's retained origin, independently of acceptance or a re-send.
    pub fn origin(&self) -> DeliveryOrigin {
        self.origin
    }

    /// Whether this delivery is a re-send of a message this app retained as accepted.
    ///
    /// An unaccepted delivery retry is not a re-send. This is the same retained attempt
    /// fact as [`QueuedMessage::resend`], independently of [`Self::origin`].
    pub fn resend(&self) -> bool {
        self.resend
    }

    /// Only the owning protocol's local state, as committed.
    pub fn local(&self) -> &super::LocalView<'a> {
        &self.local
    }

    /// The app's current certificate, as [`App::cert`] gives it.
    pub fn cert(&self) -> &AppCert {
        self.cert
    }

    /// `blind(input)` under the app's naming key (Switch wire 1.5), as [`App::blind`]
    /// gives it, without exposing the key.
    pub fn blind(&self, input: &[u8]) -> [u8; 32] {
        self.naming.blind(input)
    }

    /// The current host wall time in Unix milliseconds, sampled on each call.
    ///
    /// This is the app's [`crate::clock::Clock`], not a verified service time.
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// The current status of a known batch ID in this app, as [`App::kept_batch`] gives it.
    ///
    /// This reads app-wide metadata, without exposing the batch or another protocol's
    /// local state. An absent or expired status is not evidence that nothing was sent.
    /// No request, settlement or pruning is performed.
    ///
    /// # Errors
    ///
    /// A store failure, or a kept batch that doesn't read, as for [`App::kept_batch`].
    pub fn kept_batch(
        &self,
        batch_id: [u8; 16],
    ) -> Result<Option<super::KeptBatchStatus>, AppError> {
        super::kept::read_kept_batch(self.store, self.ns, self.clock, batch_id)
    }
}

/// A message whose delivery is owed, including intents in unanswered batches.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct QueuedMessage {
    /// The message's identifier, as the per-message hold and withdrawal calls use it.
    pub msg_id: String,
    /// The recipient identity.
    pub to: [u8; 32],
    /// The authenticated message kind.
    pub kind: String,
    /// The hash of the original signed JSON, as the delivery gate receives it.
    pub hash: [u8; 32],
    /// Its retained local origin, as every protocol delivery gate receives it.
    pub origin: DeliveryOrigin,
    /// A re-send of a message accepted before, independently of its origin.
    pub resend: bool,
    /// The earliest retained batch that will materialize it; none if already in the outbox.
    pub kept_batch: Option<[u8; 16]>,
    /// The per-message hold is set.
    pub held: bool,
    /// The recipient-wide hold is set.
    pub counterparty_held: bool,
    /// The owning protocol currently permits this delivery; true for an unowned kind.
    pub may_send: bool,
}

impl QueuedMessage {
    /// Whether a message, recipient or protocol hold prevents delivery now.
    pub fn waits(&self) -> bool {
        self.held || self.counterparty_held || !self.may_send
    }
}

struct DeliveryHolds {
    message: bool,
    counterparty: bool,
    may_send: bool,
}

impl DeliveryHolds {
    fn any(&self) -> bool {
        self.message || self.counterparty || !self.may_send
    }
}

/// The shared record a sent message is written into (Switch spec 8.2), and the protocol's
/// tag for how, such as the message's role in the record. Its `Debug` shows no key.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordJob {
    /// The record.
    pub target: RecordTarget,
    /// The protocol's opaque tag.
    pub tag: Vec<u8>,
}

impl std::fmt::Debug for RecordJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecordJob({:?})", self.target)
    }
}

/// A message to send. Its `Debug` shows only the kind.
#[derive(Clone)]
pub struct OutgoingMessage {
    /// The recipient identity.
    pub to: [u8; 32],
    /// The kind, `<prefix>.<name>`.
    pub kind: String,
    /// The hashes of the messages it refers to.
    pub refs: Vec<[u8; 32]>,
    /// The body.
    pub body: Map<String, Value>,
    /// Whether the switch pushes it (Switch spec 5.1 `notify`).
    pub notify: bool,
    /// An invite code that admits the app at the recipient's switch (Switch spec 7).
    pub invite_code: Option<String>,
    /// The shared record write that goes with it.
    pub record: Option<RecordJob>,
}

impl std::fmt::Debug for OutgoingMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OutgoingMessage({})", self.kind)
    }
}

impl OutgoingMessage {
    /// A message of `kind` to `to` with `body`, pushed, without refs, code or record.
    pub fn new(to: [u8; 32], kind: &str, body: Map<String, Value>) -> Self {
        Self {
            to,
            kind: kind.to_owned(),
            refs: Vec::new(),
            body,
            notify: true,
            invite_code: None,
            record: None,
        }
    }
}

/// A message signed once and not yet queued ([`App::sign_message`]): its signed plaintext
/// and hash are known before anything is kept, so a protocol builds from them the shared
/// record write and claim entries that go with it, in the batch that queues it
/// ([`super::OpBatch::queue`]), or queues it alone ([`App::queue_signed`]). Its `Debug`
/// shows only the kind and `msg_id`.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedMessage {
    to: [u8; 32],
    kind: String,
    msg_id: String,
    plaintext: MessagePlaintext,
    notify: bool,
    invite_code: Option<String>,
    conversation: bool,
    record: Option<RecordJob>,
}

impl std::fmt::Debug for SignedMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SignedMessage({}, {})", self.kind, self.msg_id)
    }
}

impl SignedMessage {
    /// The recipient identity.
    pub fn to(&self) -> [u8; 32] {
        self.to
    }

    /// The kind.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The message ID.
    pub fn msg_id(&self) -> &str {
        &self.msg_id
    }

    /// The signed plaintext, as it is sealed and as a record stores it (Switch spec 8.2).
    pub fn plaintext(&self) -> &MessagePlaintext {
        &self.plaintext
    }

    /// The message hash (Switch wire 4.5), which a message referring to it names.
    pub fn hash(&self) -> [u8; 32] {
        self.plaintext.hash()
    }

    /// The shared record write that goes with it once the recipient's inbox accepts it,
    /// built through [`super::Protocol::sent_record`], if any.
    pub fn record(&self) -> Option<&RecordJob> {
        self.record.as_ref()
    }

    /// The same message with the record job `job`, whose target may derive from the
    /// message's own hash: the plaintext isn't signed again.
    #[must_use]
    pub fn with_record(mut self, job: RecordJob) -> Self {
        self.record = Some(job);
        self
    }
}

/// A message the app sent, kept for re-sends. Its `Debug` shows no content.
#[derive(Clone, PartialEq, Eq)]
pub struct SentMessage {
    /// The recipient identity.
    pub to: [u8; 32],
    /// The kind.
    pub kind: String,
    /// The message ID.
    pub msg_id: String,
    /// The signed plaintext, as sent.
    pub plaintext: MessagePlaintext,
    /// When the recipient's inbox first accepted it, the recipient's service time; `None`
    /// while it is queued.
    pub accepted_at_ms: Option<u64>,
    /// When the recipient's inbox accepted each re-send of it since, ascending, in the same
    /// clock. A re-send request's times select by these as well as the first (Switch spec
    /// 11).
    pub resent_at_ms: Vec<u64>,
}

impl SentMessage {
    /// Every acceptance time of the message, ascending: the first, then each accepted
    /// re-send's.
    pub fn accepted_times_ms(&self) -> Vec<u64> {
        let mut times: Vec<u64> = self
            .accepted_at_ms
            .into_iter()
            .chain(self.resent_at_ms.iter().copied())
            .collect();
        times.sort_unstable();
        times.dedup();
        times
    }
}

impl std::fmt::Debug for SentMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SentMessage({}, {})", self.kind, self.msg_id)
    }
}

/// Where a message is (Switch spec 11).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Delivery {
    /// In the outbox, to be tried again.
    Queued {
        /// How many times it was tried.
        tries: u64,
        /// The last failure, without content.
        last_error: Option<String>,
        /// When a delivery was first answered `403 not_admitted` or `403 not_current`, app
        /// clock: the start of the time the message stays queued so before it is given up
        /// ([`UNDELIVERABLE_MS`], Switch spec 11). `None` while no delivery of it was
        /// answered so.
        undeliverable_since_ms: Option<u64>,
        /// Which of the two the last such answer was: the recipient not admitting the
        /// sender, or the sender's own certificate not current. `None` while no delivery of
        /// it was answered so.
        undeliverable_reason: Option<UndeliverableReason>,
    },
    /// The recipient's inbox accepted it: delivery is complete.
    Accepted {
        /// The acceptance time.
        accepted_at_ms: u64,
    },
    /// Refused for good, or never queued: the kept batch that would have queued it was
    /// dropped ([`super::App::kept_batch`]). Answered for [`SENT_RETENTION_MS`] from its
    /// time, then forgotten.
    Failed {
        /// Why, without content.
        reason: String,
        /// When, app clock: when it was refused, or its batch dropped.
        failed_at_ms: u64,
    },
    /// In a kept batch, not yet in the outbox: it is queued once the batch is applied, and
    /// fails with it if the batch is dropped (Switch spec 8.2, [`super::OpBatch::queue`]).
    Kept {
        /// The batch ID it is kept under ([`super::App::kept_batch`]).
        batch_id: [u8; 16],
    },
}

/// Why a delivery stays queued for a bounded time before the message is given up
/// ([`Delivery::Queued`], Switch spec 11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UndeliverableReason {
    /// `403 not_admitted`: the recipient doesn't admit the sender, until it adds a contact
    /// or an invite (Switch spec 7).
    NotAdmitted,
    /// `403 not_current`: the sender's own certificate isn't current, until a renewal makes
    /// it current again (Switch wire 3.8). Nothing about the recipient.
    NotCurrent,
}

/// The most messages one flush of the outbox tries ([`App::flush_outbox`]): the next
/// flush goes on with the rest, from where this one stopped ([`OutboxReport::more`]).
pub const OUTBOX_TRIES_PER_FLUSH: usize = 4;

/// Where flushing the outbox stands (`outnext`, `STATE.md`).
const OUT_NEXT: &str = "outnext";

/// `outnext`: where flushing the outbox stands. A flush tries messages in queue order from
/// after `last`, round the queue, so no message waits for ever behind others that keep
/// failing. A pass goes once round: while `open`, a flush its budget stopped left messages of
/// the pass untried, and the next flush tries only those, the ones after `last` and before
/// `pass_first` (every one while the pass has tried none). The flush that ends the pass says
/// no more, and the next flush starts a new one, together with a pass of the owed
/// deliveries of the own `identity.json` ([`App::deliver_to_recent_peers`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OutNext {
    /// The queue time and ID of the last message tried.
    last: (u64, String),
    /// The first message the pass under way tried; `None` while it has tried none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pass_first: Option<(u64, String)>,
    /// A pass is under way: a flush its budget stopped left messages of it untried.
    open: bool,
}

/// Whether `key` comes after `from` and before `to`, going round the queue from `from`.
fn between(from: &(u64, String), key: &(u64, String), to: &(u64, String)) -> bool {
    if from < to {
        from < key && key < to
    } else {
        key > from || key < to
    }
}

/// What a flush of the outbox did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OutboxReport {
    /// The messages whose every job completed.
    pub done: Vec<String>,
    /// The messages still queued.
    pub queued: Vec<String>,
    /// The messages refused for good.
    pub failed: Vec<String>,
    /// The messages given up after [`UNDELIVERABLE_MS`] of `403 not_admitted` or `403
    /// not_current` (Switch spec 11), or because a try's writes were too large for the
    /// store ([`StoreError::TooLarge`]).
    pub undelivered: Vec<String>,
    /// The flush stopped on its budget, [`OUTBOX_TRIES_PER_FLUSH`] messages or the call's
    /// time ([`super::AppConfig::call_budget_ms`]), with messages of its pass, or owed
    /// deliveries of the own `identity.json`, it didn't try: the host flushes again at once,
    /// and the next flush tries only those. It is `false` once the pass is over, every
    /// message queued and every owed delivery tried in it, so a host that flushes while it is
    /// `true` stops after one pass, even with messages still queued; it flushes again on its
    /// own triggers ([`App::flush_outbox`]).
    pub more: bool,
}

/// The envelope sealed for one try, and where.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Sealed {
    envelope: pubky_switch_core::envelope::SealedEnvelope,
    apps_version: u64,
    origin: String,
    generation: u64,
}

/// The record job, as kept.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KeptJob {
    collection: String,
    policy: pubky_switch_core::ident::Policy,
    #[serde(with = "serde_b64_vec")]
    natural_key: Vec<u8>,
    #[serde(with = "serde_b64_vec")]
    tag: Vec<u8>,
}

impl KeptJob {
    fn of(job: &RecordJob) -> Self {
        Self {
            collection: job.target.collection.name.clone(),
            policy: job.target.collection.policy.clone(),
            natural_key: job.target.natural_key.clone(),
            tag: job.tag.clone(),
        }
    }

    fn job(&self) -> RecordJob {
        RecordJob {
            target: RecordTarget::new(
                Collection::new(&self.collection, self.policy.clone()),
                &self.natural_key,
            ),
            tag: self.tag.clone(),
        }
    }
}

/// `out/<msg_id>`: a queued message and its jobs. Sensitive: it holds the message and any
/// invite code.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OutboxItem {
    origin: DeliveryOrigin,
    #[serde(with = "serde_b64")]
    to: [u8; 32],
    kind: String,
    msg_id: String,
    #[serde(with = "serde_b64_vec")]
    plaintext: Vec<u8>,
    notify: bool,
    invite_code: Option<String>,
    /// The conversation entry is owed.
    conversation: bool,
    sealed: Option<Sealed>,
    record: Option<KeptJob>,
    record_done: bool,
    accepted_at_ms: Option<u64>,
    /// Refused for good: why, without content, and when, app clock. It is forgotten after
    /// the retention of sent messages.
    failed: Option<(String, u64)>,
    last_error: Option<String>,
    /// Job tries begun while unheld; delivery retries share this count. A hold
    /// discovered after earlier work does not undo that work or its try.
    tries: u64,
    queued_ms: u64,
    /// An accepted message is to be sent again, sealed to the current keys (Switch spec 11).
    resend: bool,
    /// The first `403 not_admitted` or `403 not_current` answer to a delivery, app clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    undeliverable_ms: Option<u64>,
    /// Which of the two the last such answer was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    undeliverable_reason: Option<UndeliverableReason>,
    /// The last such answer counted, app clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    undeliverable_last_ms: Option<u64>,
    /// The such answers counted ([`UNDELIVERABLE_TRIES`]).
    undeliverable_tries: u32,
    /// A re-send queued from `sent/`: the recipient accepted the message before.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    resend_queued: bool,
    /// The last time a delivery may go, for a message a restore put back or
    /// [`App::queue_stored`] queued: past it, the recipient may have forgotten the processed
    /// pair of a copy another device delivered (Switch spec 11). Kept through later backups,
    /// never moved on, and carried into `sent/` at its acceptance, so a re-send of it keeps
    /// the deadline too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replay_until_ms: Option<u64>,
    /// The batch a try of the record job left kept, the latest one, in base64: named when
    /// the job is given up ([`AppEvent::RecordJobDropped`]), as it may still apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    record_batch: Option<String>,
}

impl std::fmt::Debug for OutboxItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OutboxItem({}, {})", self.kind, self.msg_id)
    }
}

impl OutboxItem {
    pub(crate) fn msg_id(&self) -> &str {
        &self.msg_id
    }

    /// The cached routing fields agree with the plaintext authenticated by this app
    /// (Switch wire 5.1). Body rules are not needed to retain an unregistered kind.
    pub(crate) fn is_own(
        &self,
        meta: &super::state::Meta,
        cert: &pubky_switch_core::records::AppCert,
    ) -> bool {
        own_message(&self.plaintext, &self.to, meta, cert)
            .is_some_and(|message| message.kind == self.kind && message.msg_id == self.msg_id)
            && self.sealed.as_ref().is_none_or(|sealed| {
                sealed
                    .envelope
                    .matches_plaintext(&self.plaintext)
                    .unwrap_or(false)
            })
    }

    fn complete(&self) -> bool {
        self.accepted_at_ms.is_some() && !self.resend && (self.record.is_none() || self.record_done)
    }

    fn is_resend(&self) -> bool {
        self.accepted_at_ms.is_some() || self.resend_queued
    }

    /// Whether a delivery is owed: never accepted, or a re-send asked since.
    pub(crate) fn delivery_owed(&self) -> bool {
        self.accepted_at_ms.is_none() || self.resend
    }

    /// Whether a delivery is owed and the message wasn't refused for good: what a hold
    /// ([`App::hold_message`]) holds.
    pub(crate) fn delivery_pending(&self) -> bool {
        self.failed.is_none() && self.delivery_owed()
    }

    /// Count a `403 not_admitted` or `403 not_current` answer at `now`, for `reason`: the
    /// first starts the wait, a later one counts once [`UNDELIVERABLE_TRY_SPACING_MS`]
    /// passed since the last counted, and a clock gone back starts the wait over. The reason
    /// is the last answer's.
    fn count_undeliverable(&mut self, now: u64, reason: UndeliverableReason) {
        self.undeliverable_reason = Some(reason);
        match (self.undeliverable_ms, self.undeliverable_last_ms) {
            (Some(since), last) if now >= since && last.is_none_or(|last| now >= last) => {
                let last = last.unwrap_or(since);
                if now.saturating_sub(last) >= UNDELIVERABLE_TRY_SPACING_MS {
                    self.undeliverable_last_ms = Some(now);
                    self.undeliverable_tries = self.undeliverable_tries.saturating_add(1);
                }
            }
            _ => {
                self.undeliverable_ms = Some(now);
                self.undeliverable_last_ms = Some(now);
                self.undeliverable_tries = 1;
            }
        }
    }

    fn clear_undeliverable(&mut self) {
        self.undeliverable_ms = None;
        self.undeliverable_reason = None;
        self.undeliverable_last_ms = None;
        self.undeliverable_tries = 0;
    }

    fn plaintext(&self) -> Result<MessagePlaintext, AppError> {
        MessagePlaintext::decode(&self.plaintext).map_err(|_| store_corrupt())
    }

    /// The item that stays once its owed delivery is given up past its replay deadline
    /// ([`OutboxItem::replay_until`]), as [`App::drop_undeliverable`] gives one up, and the
    /// duty event that tells the protocol: a message never accepted goes, plaintext and
    /// all; one accepted before stays while its record job is owed, its sealed envelope
    /// dropped. `None` for nothing left.
    pub(crate) fn give_up_delivery(mut self) -> (Option<Self>, Duty) {
        let duty = Duty::MessageUndelivered {
            msg_id: self.msg_id.clone(),
            resend: self.accepted_at_ms.is_some() || self.resend_queued,
        };
        self.resend = false;
        self.resend_queued = false;
        self.sealed = None;
        self.clear_undeliverable();
        let kept = (self.accepted_at_ms.is_some() && !self.complete()).then_some(self);
        (kept, duty)
    }

    /// The item once the acceptance first at `first_ms` that a store restored in place
    /// holds is taken into it (Switch spec 12.4 "Sent messages"), as the commit that records
    /// an acceptance takes one: no delivery owed, nor the conversation entry that goes
    /// before it, its sealed envelope, refusal and undeliverable count dropped. `None` when
    /// nothing else of it is owed.
    fn take_acceptance(mut self, first_ms: u64) -> Option<Self> {
        self.accepted_at_ms = Some(first_ms);
        self.resend = false;
        self.conversation = false;
        self.sealed = None;
        self.failed = None;
        self.last_error = None;
        self.clear_undeliverable();
        (!self.complete()).then_some(self)
    }

    /// The replay deadline a restore gives the item (Switch spec 11): the earliest of the
    /// one it carries, its first acceptance plus [`SENT_RETENTION_MS`] for a message
    /// accepted before, and `baseline` plus [`SENT_RETENTION_MS`], where `baseline` is when
    /// the backup was taken, less the clock tolerance. A recipient keeps a processed pair
    /// 30 days and the tolerance from when it processed the message, which is at or after
    /// its first acceptance; and the first acceptance of a message not accepted before the
    /// backup is at or after the backup. So a copy delivered by the deadline is one the
    /// recipient drops. The deadline only ever comes earlier.
    pub(crate) fn replay_until(&mut self, baseline: u64) {
        let deadlines = [
            self.replay_until_ms,
            self.accepted_at_ms
                .map(|at| at.saturating_add(SENT_RETENTION_MS)),
            Some(baseline.saturating_add(SENT_RETENTION_MS)),
        ];
        self.replay_until_ms = deadlines.into_iter().flatten().min();
    }

    /// The item's replay deadline, if a restore gave it one.
    #[cfg(test)]
    pub(crate) fn replay_until_ms(&self) -> Option<u64> {
        self.replay_until_ms
    }

    /// Whether the delivery notifies the recipient, and whether it owes a conversation
    /// entry.
    #[cfg(test)]
    pub(crate) fn notify_and_conversation(&self) -> (bool, bool) {
        (self.notify, self.conversation)
    }

    /// The bytes the item takes in the store.
    fn stored_bytes(&self) -> u64 {
        super::state::encode(self).map_or(u64::MAX, |bytes| {
            u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        })
    }
}

/// The most bytes of outbox records a backup carries, so the restore's one commit fits the
/// store's batch size beside the app's own state: 8 MiB.
pub const MAX_CARRIED_OUTBOX_BYTES: u64 = 8 * 1024 * 1024;

/// The outbox a backup carries (Switch spec 11, 12.4).
#[derive(Clone, Debug, Default)]
pub(crate) struct CarriedOutbox {
    /// The records, oldest queued first.
    pub(crate) items: Vec<OutboxItem>,
    /// The messages left out past [`MAX_CARRIED_OUTBOX_BYTES`], and whether each is a
    /// re-send of a message accepted before.
    pub(crate) left_out: Vec<(String, bool)>,
}

/// The queued messages a backup carries (Switch spec 11, 12.4): every record in the outbox,
/// as it stands, its signed plaintext and the envelope sealed for its last try included, so
/// a restore delivers each with the same `msg_id` and bytes; a message refused for good is
/// carried too, so the restored app still reports it failed until it is forgotten. Oldest
/// queued first, within [`MAX_CARRIED_OUTBOX_BYTES`]: the rest are named, so the restore
/// tells the protocol it won't deliver them.
pub(crate) async fn carried_outbox(
    reader: &super::state::Reader,
) -> Result<CarriedOutbox, AppError> {
    let mut items: Vec<OutboxItem> = reader
        .scan::<OutboxItem>(OUT_PREFIX)
        .await?
        .into_iter()
        .map(|(_, item)| item)
        .collect();
    items.sort_by_key(|item| item.queued_ms);
    let mut carried = CarriedOutbox::default();
    let mut bytes = 0u64;
    for item in items {
        let size = item.stored_bytes();
        match bytes.checked_add(size) {
            Some(total) if total <= MAX_CARRIED_OUTBOX_BYTES => {
                bytes = total;
                carried.items.push(item);
            }
            _ => carried.left_out.push((
                item.msg_id.clone(),
                item.accepted_at_ms.is_some() || item.resend_queued,
            )),
        }
    }
    Ok(carried)
}

/// Whether a message first accepted at `first_ms` is still kept as sent at `now`: within
/// [`SENT_RETENTION_MS`] of its first acceptance (Switch spec 11). The one rule of the
/// pruning of `sent/` and of what a backup carries of it.
fn sent_kept(first_ms: u64, now: u64) -> bool {
    first_ms > now.saturating_sub(SENT_RETENTION_MS)
}

/// The most bytes the sent messages a backup carries take in the restore's one commit,
/// every write that installs them counted as the store counts it (`Write::size`: namespace,
/// key and value), so that commit fits the store's batch size beside the outbox
/// ([`MAX_CARRIED_OUTBOX_BYTES`]) and the app's own state: 8 MiB (Switch spec 12.4 "Sent
/// messages").
pub const MAX_CARRIED_SENT_BYTES: u64 = 8 * 1024 * 1024;

/// A sent message as a backup carries it and a restore installs it: its record, and the time
/// its give-up mark stands until when the app gave a delivery of it up. A give-up stands
/// while a sent copy remains ([`given_up`]), so it goes with the record (Switch spec 11,
/// 12.4 "Sent messages").
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CarriedSent {
    #[serde(flatten)]
    record: SentStored,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    given_up_until_ms: Option<u64>,
}

impl CarriedSent {
    /// The message's `msg_id`.
    pub(crate) fn msg_id(&self) -> &str {
        &self.record.msg_id
    }

    /// The bytes it takes in a restore's commit to the namespace `ns`, every write that
    /// installs it ([`CarriedSent::put`]) counted as the store counts it, without its
    /// plaintext when `bare`. The one measure of [`MAX_CARRIED_SENT_BYTES`].
    fn commit_bytes(&self, ns: &str, bare: bool) -> u64 {
        let put = |key: String, value: Result<Vec<u8>, AppError>| {
            value.map_or(u64::MAX, |value| {
                u64::try_from(ns.len() + key.len() + value.len()).unwrap_or(u64::MAX)
            })
        };
        let record = if bare && self.record.plaintext.is_some() {
            super::state::encode(&self.record.bare())
        } else {
            super::state::encode(&self.record)
        };
        let msg_id = &self.record.msg_id;
        put(sent_key(msg_id), record)
            .saturating_add(put(
                sent_time_key(self.record.first_ms, msg_id),
                super::state::encode(&()),
            ))
            .saturating_add(self.given_up_until_ms.map_or(0, |until| {
                put(given_up_key(msg_id), super::state::encode(&until))
            }))
    }

    /// Put it in `tx`: the record, its time index (`sentt/`) and its give-up mark.
    pub(crate) fn put(&self, tx: &mut super::state::Tx) -> Result<(), AppError> {
        let msg_id = &self.record.msg_id;
        tx.put(&sent_time_key(self.record.first_ms, msg_id), &())?;
        tx.put(&sent_key(msg_id), &self.record)?;
        if let Some(until) = self.given_up_until_ms {
            tx.put(&given_up_key(msg_id), &until)?;
        }
        Ok(())
    }

    /// The copy of one message this one and `other` both hold, as a restore in place keeps
    /// it: the records merged ([`SentStored::merged`]) and the later give-up time.
    fn merged(&self, other: &Self) -> Option<Self> {
        Some(Self {
            record: self.record.merged(&other.record)?,
            given_up_until_ms: self.given_up_until_ms.max(other.given_up_until_ms),
        })
    }
}

/// The order sent messages go in within [`MAX_CARRIED_SENT_BYTES`]: the most recently
/// accepted first, then by `msg_id`.
fn fit_order(a: &CarriedSent, b: &CarriedSent) -> std::cmp::Ordering {
    b.record
        .latest_ms()
        .cmp(&a.record.latest_ms())
        .then_with(|| a.record.msg_id.cmp(&b.record.msg_id))
}

/// Sent messages fitted within [`MAX_CARRIED_SENT_BYTES`] ([`fit_sent`]).
#[derive(Clone, Default)]
pub(crate) struct SentFit {
    /// Those carried, in `msg_id` order, some without their plaintext.
    pub(crate) records: Vec<CarriedSent>,
    /// How many were left out: the oldest, each older than every one carried.
    pub(crate) left_out: u64,
}

/// `kept` within [`MAX_CARRIED_SENT_BYTES`] of a commit to `ns`, in [`fit_order`]: first
/// the acceptance of each, without its plaintext, until one doesn't fit, it and every older
/// one left out and counted; then the plaintext of each, while the whole still fits. An
/// acceptance is what keeps a restored app from telling a message undelivered, so it goes
/// before any plaintext.
fn fit_sent(mut kept: Vec<CarriedSent>, ns: &str) -> SentFit {
    kept.sort_by(fit_order);
    let mut bytes = 0u64;
    let mut fit = SentFit::default();
    for sent in kept {
        match bytes.checked_add(sent.commit_bytes(ns, true)) {
            Some(total) if total <= MAX_CARRIED_SENT_BYTES && fit.left_out == 0 => {
                bytes = total;
                fit.records.push(sent);
            }
            _ => fit.left_out = fit.left_out.saturating_add(1),
        }
    }
    for sent in &mut fit.records {
        let extra = sent
            .commit_bytes(ns, false)
            .saturating_sub(sent.commit_bytes(ns, true));
        match bytes.checked_add(extra) {
            Some(total) if total <= MAX_CARRIED_SENT_BYTES => bytes = total,
            _ => sent.record.plaintext = None,
        }
    }
    fit.records
        .sort_by(|a, b| a.record.msg_id.cmp(&b.record.msg_id));
    fit
}

/// The sent messages a backup taken at `taken_ms` of the app whose namespace is `ns`
/// carries (Switch spec 12.4 "Sent messages"): every one `reader` holds still kept then
/// ([`sent_kept`]), as stored, with its give-up mark, within [`MAX_CARRIED_SENT_BYTES`]
/// ([`fit_sent`]).
pub(crate) async fn carried_sent(
    reader: &super::state::Reader,
    taken_ms: u64,
    ns: &str,
) -> Result<SentFit, AppError> {
    let mut kept = Vec::new();
    for (_, record) in reader.scan::<SentStored>(SENT_PREFIX).await? {
        if sent_kept(record.first_ms, taken_ms) {
            let given_up_until_ms = reader.get(&given_up_key(&record.msg_id)).await?;
            kept.push(CarriedSent {
                record,
                given_up_until_ms,
            });
        }
    }
    Ok(fit_sent(kept, ns))
}

/// Check the sent messages `sent` a backup taken at `taken_ms` carries against its outbox
/// `outbox` and the messages it left out of it `left_out` (Switch spec 12.4 "Sent
/// messages"). A backup holds what one store held at one moment: each message once, still
/// kept at `taken_ms`, signed by this app, within [`MAX_CARRIED_SENT_BYTES`] of a commit
/// to `ns`, the same message as its outbox copy, origin included, and never beside an outbox
/// copy the store never saw accepted, since a message is queued alone only while it isn't
/// kept as sent and the commit that records an acceptance writes both. Anything else is
/// damage; the error says what, without content.
pub(crate) fn check_carried_sent(
    sent: &[CarriedSent],
    taken_ms: u64,
    outbox: &[OutboxItem],
    left_out: &[(String, bool)],
    ns: &str,
    meta: &super::state::Meta,
    cert: &pubky_switch_core::records::AppCert,
) -> Result<(), &'static str> {
    // The caller checked that the outbox holds each message once.
    let mut copies: BTreeMap<String, DeliveryCopy> = outbox
        .iter()
        .map(|item| (item.msg_id.clone(), DeliveryCopy::of(item)))
        .collect();
    let mut bytes = 0u64;
    let mut ids = BTreeSet::new();
    for carried in sent {
        let record = &carried.record;
        bytes = bytes.saturating_add(carried.commit_bytes(ns, false));
        if bytes > MAX_CARRIED_SENT_BYTES {
            return Err("its sent messages are over the bytes a backup carries");
        }
        if !ids.insert(record.msg_id.as_str())
            || !sent_kept(record.first_ms, taken_ms)
            || !record.is_own(meta, cert)
        {
            return Err("a sent message is repeated, past its retention or not its own");
        }
        let never_accepted = outbox.iter().any(|item| {
            item.msg_id == record.msg_id && item.accepted_at_ms.is_none() && !item.resend_queued
        }) || left_out
            .iter()
            .any(|(msg_id, resend)| *msg_id == record.msg_id && !resend);
        if never_accepted
            || DeliveryCopy::of_sent(record)
                .remember(record.msg_id.clone(), &mut copies)
                .is_err()
        {
            return Err("a sent message disagrees with its outbox copy");
        }
    }
    Ok(())
}

/// The sent messages the store `reader`, restored in place, holds as this app's, each with
/// its give-up mark, if one reads ([`store_give_ups`] counts one that doesn't): each read
/// under its own `msg_id` and signed by the app `meta` and `cert` name; and how many records
/// it holds that don't read so, which a restore leaves behind and counts, as it does a
/// damaged value of what the store owes its protocol.
pub(crate) async fn sent_of_store(
    reader: &super::state::Reader,
    meta: &super::state::Meta,
    cert: &pubky_switch_core::records::AppCert,
) -> Result<(Vec<CarriedSent>, u64), AppError> {
    let mut kept = Vec::new();
    let mut lost = 0u64;
    for (msg_id, bytes) in reader.scan_raw(SENT_PREFIX).await? {
        match super::state::decode::<SentStored>(&bytes) {
            Ok(record) if record.msg_id == msg_id && record.is_own(meta, cert) => {
                let (given_up_until_ms, _) = mark_of(reader, &msg_id).await?;
                kept.push(CarriedSent {
                    record,
                    given_up_until_ms,
                });
            }
            _ => lost = lost.saturating_add(1),
        }
    }
    Ok((kept, lost))
}

/// The give-up mark of `msg_id` that the store `reader` holds, if one reads, and how many
/// don't (0 or 1).
async fn mark_of(
    reader: &super::state::Reader,
    msg_id: &str,
) -> Result<(Option<u64>, u64), AppError> {
    Ok(
        match reader.get_raw(given_up_key(msg_id).as_bytes()).await? {
            None => (None, 0),
            Some(bytes) => match super::state::decode::<u64>(&bytes) {
                Ok(until) => (Some(until), 0),
                Err(_) => (None, 1),
            },
        },
    )
}

/// The give-ups the store `reader`, restored in place, holds of the messages `msg_ids`,
/// each named once,
/// that still stand at `now` ([`given_up`]: until the time the mark holds, and while an
/// outbox or sent copy remains), each with that time; and how many marks don't read, which
/// the restore leaves behind and counts. The store told its protocol of each give-up, so a
/// restore delivers none of those messages again and tells none of them again (Switch spec
/// 12.4 "Sent messages").
pub(crate) async fn store_give_ups<'a>(
    reader: &super::state::Reader,
    msg_ids: impl IntoIterator<Item = &'a str>,
    now: u64,
) -> Result<(BTreeMap<String, u64>, u64), AppError> {
    let mut standing = BTreeMap::new();
    let mut lost = 0u64;
    let msg_ids: BTreeSet<&str> = msg_ids.into_iter().collect();
    for msg_id in msg_ids {
        let (until, unread) = mark_of(reader, msg_id).await?;
        lost = lost.saturating_add(unread);
        if let Some(until) = until
            && (now <= until
                || reader.exists(&out_key(msg_id)).await?
                || reader.exists(&sent_key(msg_id)).await?)
        {
            standing.insert(msg_id.to_owned(), until);
        }
    }
    Ok((standing, lost))
}

/// Put the give-up mark of `msg_id`, standing until `until`, in `tx`.
pub(crate) fn put_give_up(
    tx: &mut super::state::Tx,
    msg_id: &str,
    until: u64,
) -> Result<(), AppError> {
    tx.put(&given_up_key(msg_id), &until)
}

/// The sent messages a restore installs (Switch spec 12.4 "Sent messages").
pub(crate) struct RestoredSent {
    /// Those it installs, in `msg_id` order.
    records: Vec<CarriedSent>,
    /// Those of `records` exactly as the backup carries them.
    from_backup: BTreeSet<String>,
    /// How many sent messages the restored app doesn't know were accepted, each counted
    /// once: those the backup left out, less those of them the store restored in place
    /// gives back, and those the restore leaves out past [`MAX_CARRIED_SENT_BYTES`].
    pub(crate) left_out: u64,
}

impl RestoredSent {
    /// The record of `msg_id`, if the restore installs one.
    fn get(&self, msg_id: &str) -> Option<&SentStored> {
        self.records
            .binary_search_by(|sent| sent.record.msg_id.as_str().cmp(msg_id))
            .ok()
            .and_then(|at| self.records.get(at))
            .map(|sent| &sent.record)
    }

    /// Whether the restore installs a record of `msg_id`: it reads as accepted.
    pub(crate) fn holds(&self, msg_id: &str) -> bool {
        self.get(msg_id).is_some()
    }

    /// The copies, those exactly as the backup carries them (`true`) or not.
    pub(crate) fn records(&self, from_backup: bool) -> impl Iterator<Item = &CarriedSent> {
        self.records
            .iter()
            .filter(move |sent| self.from_backup.contains(&sent.record.msg_id) == from_backup)
    }

    /// The outbox `outbox` a backup carries, as the restore puts it back: an item whose
    /// store never saw its message accepted takes the acceptance a store restored in place
    /// holds ([`OutboxItem::take_acceptance`]); an item whose delivery that store gave up
    /// since (`given_up`, [`store_give_ups`]) owes it no more, as the give-up left it: a
    /// message never accepted isn't put back, and one accepted before stays only for a
    /// record job still owed. Each goes once nothing else of it is owed.
    pub(crate) fn outbox(
        &self,
        outbox: &[OutboxItem],
        given_up: &BTreeMap<String, u64>,
    ) -> Vec<OutboxItem> {
        outbox
            .iter()
            .filter_map(|item| {
                let item = match self.get(&item.msg_id) {
                    Some(sent) if item.accepted_at_ms.is_none() && !item.resend_queued => {
                        item.clone().take_acceptance(sent.first_ms)?
                    }
                    _ => item.clone(),
                };
                if item.delivery_owed() && given_up.contains_key(&item.msg_id) {
                    item.give_up_delivery().0
                } else {
                    Some(item)
                }
            })
            .collect()
    }
}

/// What a restore of an app whose namespace is `ns` installs of the sent messages (Switch
/// spec 12.4 "Sent messages"): those the backup carries (`carried`, checked with
/// [`check_carried_sent`]), and for a restore in place those the store holds (`store`,
/// [`sent_of_store`]) beside them.
///
/// - A store's copy of a message the backup also holds, as sent or in its outbox, takes the
///   backup's origin: the backup's copy is the snapshot the restore installs, and proves how
///   the message was first queued there; two devices of one app may hold one message under
///   different origins, one queued, one queued again from its stored plaintext.
/// - It must then be the same message as the backup's, by recipient, kind and bytes: no
///   writer gives two messages one `msg_id`, so another refuses the restore.
/// - A message both hold is one copy ([`CarriedSent::merged`]); one only the store holds
///   goes as it is.
///
/// The whole goes within [`MAX_CARRIED_SENT_BYTES`], as a backup's does ([`fit_sent`]).
/// When the backup left some out (`backup_left_out`), those are the oldest, so a message
/// only the store holds that is no newer than the oldest the backup carries is taken as one
/// of them: installed, it is no longer counted, and left out again, it is counted once.
pub(crate) fn restored_sent(
    carried: &[CarriedSent],
    store: Vec<CarriedSent>,
    outbox: &[OutboxItem],
    backup_left_out: u64,
    ns: &str,
) -> Result<RestoredSent, &'static str> {
    let mut copies: BTreeMap<String, DeliveryCopy> = outbox
        .iter()
        .map(|item| (item.msg_id.clone(), DeliveryCopy::of(item)))
        .collect();
    let mut records: BTreeMap<String, CarriedSent> = carried
        .iter()
        .map(|sent| (sent.record.msg_id.clone(), sent.clone()))
        .collect();
    let oldest = carried.iter().max_by(|a, b| fit_order(a, b));
    let mut backups_left_out = BTreeSet::new();
    for mut sent in store {
        let msg_id = sent.record.msg_id.clone();
        let backup_origin = records
            .get(&msg_id)
            .map(|held| held.record.origin)
            .or_else(|| copies.get(&msg_id).map(|copy| copy.origin));
        if let Some(origin) = backup_origin {
            sent.record.origin = origin;
        }
        DeliveryCopy::of_sent(&sent.record)
            .remember(msg_id.clone(), &mut copies)
            .map_err(|_| "the store holds another message than the backup's queued one")?;
        let copy = match records.get(&msg_id) {
            Some(held) => held
                .merged(&sent)
                .ok_or("the store holds another message than the backup's sent one")?,
            None => {
                if backup_left_out > 0
                    && oldest
                        .is_none_or(|oldest| fit_order(&sent, oldest) != std::cmp::Ordering::Less)
                {
                    backups_left_out.insert(msg_id.clone());
                }
                sent
            }
        };
        records.insert(msg_id, copy);
    }
    let fit = fit_sent(records.into_values().collect(), ns);
    let given_back = u64::try_from(
        fit.records
            .iter()
            .filter(|sent| backups_left_out.contains(&sent.record.msg_id))
            .count(),
    )
    .unwrap_or(u64::MAX);
    let left_again = u64::try_from(backups_left_out.len())
        .unwrap_or(u64::MAX)
        .saturating_sub(given_back);
    // Those the backup left out the store doesn't hold, those it holds left out again,
    // and the others left out.
    let left_out = backup_left_out
        .saturating_sub(given_back.saturating_add(left_again))
        .saturating_add(fit.left_out);
    let from_backup = fit
        .records
        .iter()
        .filter(|sent| carried.contains(sent))
        .map(|sent| sent.record.msg_id.clone())
        .collect();
    Ok(RestoredSent {
        records: fit.records,
        from_backup,
        left_out,
    })
}

/// A message's signed plaintext, as a sent message keeps it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct SignedBytes(#[serde(with = "serde_b64_vec")] Vec<u8>);

/// `sent/<msg_id>`: a sent message, kept 30 days. Sensitive. A backup carries it (Switch
/// spec 12.4 "Sent messages", [`carried_sent`]).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SentStored {
    origin: DeliveryOrigin,
    #[serde(with = "serde_b64")]
    to: [u8; 32],
    kind: String,
    msg_id: String,
    /// The signed plaintext; `None` for a message a backup carried without it, past
    /// [`MAX_CARRIED_SENT_BYTES`]: it still reads as accepted, and can't be sent again.
    plaintext: Option<SignedBytes>,
    /// The first acceptance, from which retention runs.
    first_ms: u64,
    /// The acceptances of re-sends.
    resent: Vec<u64>,
    /// The last time a re-send may go, carried from the outbox item a restore put back or
    /// [`App::queue_stored`] queued ([`OutboxItem::replay_until`]): its first acceptance
    /// here may be later than the message's first acceptance anywhere, so the retention of
    /// this copy doesn't bound its re-sends (Switch spec 11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replay_until_ms: Option<u64>,
}

impl SentStored {
    /// The record's signed plaintext agrees with its routing fields and was signed by this
    /// app; one kept without it has nothing signed to check.
    fn is_own(
        &self,
        meta: &super::state::Meta,
        cert: &pubky_switch_core::records::AppCert,
    ) -> bool {
        self.plaintext.as_ref().is_none_or(|bytes| {
            own_message(&bytes.0, &self.to, meta, cert)
                .is_some_and(|message| message.kind == self.kind && message.msg_id == self.msg_id)
        })
    }

    /// The record of one message this one and `other` both hold, as a restore in place
    /// keeps it (Switch spec 12.4 "Sent messages"): every acceptance time of either, the
    /// earliest the first, the earlier replay deadline, and the plaintext either keeps.
    /// `None` when they aren't of one message ([`DeliveryCopy::remember`]).
    fn merged(&self, other: &Self) -> Option<Self> {
        let mut copies = BTreeMap::new();
        DeliveryCopy::of_sent(self)
            .remember(self.msg_id.clone(), &mut copies)
            .ok()?;
        DeliveryCopy::of_sent(other)
            .remember(self.msg_id.clone(), &mut copies)
            .ok()?;
        let mut times: Vec<u64> = [self.first_ms, other.first_ms]
            .into_iter()
            .chain(self.resent.iter().copied())
            .chain(other.resent.iter().copied())
            .collect();
        times.sort_unstable();
        times.dedup();
        let (first_ms, resent) = times.split_first()?;
        Some(Self {
            origin: self.origin,
            to: self.to,
            kind: self.kind.clone(),
            msg_id: self.msg_id.clone(),
            plaintext: self.plaintext.clone().or_else(|| other.plaintext.clone()),
            first_ms: *first_ms,
            resent: resent.to_vec(),
            replay_until_ms: [self.replay_until_ms, other.replay_until_ms]
                .into_iter()
                .flatten()
                .min(),
        })
    }

    /// The signed plaintext, if the record keeps it.
    fn plaintext(&self) -> Option<&[u8]> {
        self.plaintext.as_ref().map(|bytes| bytes.0.as_slice())
    }

    /// The latest acceptance, first or re-send.
    fn latest_ms(&self) -> u64 {
        self.resent.iter().copied().fold(self.first_ms, u64::max)
    }

    /// The record without its signed plaintext, as a backup carries it past
    /// [`MAX_CARRIED_SENT_BYTES`].
    fn bare(&self) -> Self {
        Self {
            origin: self.origin,
            to: self.to,
            kind: self.kind.clone(),
            msg_id: self.msg_id.clone(),
            plaintext: None,
            first_ms: self.first_ms,
            resent: self.resent.clone(),
            replay_until_ms: self.replay_until_ms,
        }
    }

    /// The re-sends' acceptance times, ascending.
    fn resent_ascending(&self) -> Vec<u64> {
        let mut times = self.resent.clone();
        times.sort_unstable();
        times
    }
}

impl std::fmt::Debug for SentStored {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SentStored({}, {})", self.kind, self.msg_id)
    }
}

#[cfg(test)]
impl App {
    /// The outbox record of `msg_id`.
    pub(crate) async fn outbox_record(&self, msg_id: &str) -> Option<OutboxItem> {
        self.reader().get(&out_key(msg_id)).await.ok().flatten()
    }
}

/// Put a queued message in the outbox, in `tx`.
pub(crate) fn put_outbox_item(
    tx: &mut super::state::Tx,
    item: &OutboxItem,
) -> Result<(), AppError> {
    tx.put(&out_key(&item.msg_id), item)
}

/// What one delivery try came to.
enum Tried {
    /// The current hold decision stopped the remaining delivery work, without an answer.
    Held,
    Accepted(AppendAnswer),
    Queued(String),
    /// Queued after `403 not_admitted` or `403 not_current`, for a bounded time.
    Undeliverable(String, UndeliverableReason),
    Failed(String),
}

/// Read this app's authenticated common message fields without requiring the original
/// protocol to remain registered (Switch wire 5.1).
fn own_message(
    bytes: &[u8],
    to: &[u8; 32],
    meta: &super::state::Meta,
    cert: &pubky_switch_core::records::AppCert,
) -> Option<Message> {
    let plaintext = MessagePlaintext::decode(bytes).ok()?;
    if plaintext.sender_app_id() != meta.app_id
        || plaintext.verify_signature(&cert.signing_key(), to).is_err()
    {
        return None;
    }
    // Only the common fields are read from these already-authenticated bytes.
    let message = super::protocols::kept_message(plaintext.json())?;
    (message.to == *to
        && message.from.identity == meta.identity
        && message.from.app_id == meta.app_id)
        .then_some(message)
}

fn store_corrupt() -> AppError {
    AppError::Store(crate::error::StoreError::Corrupt)
}

/// The immutable parts shared by every retained copy of one outgoing message. A sent
/// record kept without its plaintext agrees with any plaintext.
struct DeliveryCopy {
    to: [u8; 32],
    kind: String,
    plaintext: Option<Vec<u8>>,
    origin: DeliveryOrigin,
}

impl DeliveryCopy {
    fn of(item: &OutboxItem) -> Self {
        Self {
            to: item.to,
            kind: item.kind.clone(),
            plaintext: Some(item.plaintext.clone()),
            origin: item.origin,
        }
    }

    fn of_sent(sent: &SentStored) -> Self {
        Self {
            to: sent.to,
            kind: sent.kind.clone(),
            plaintext: sent.plaintext().map(<[u8]>::to_vec),
            origin: sent.origin,
        }
    }

    fn remember(self, msg_id: String, copies: &mut BTreeMap<String, Self>) -> Result<(), AppError> {
        match copies.entry(msg_id) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let held = entry.get_mut();
                let differs = matches!(
                    (&held.plaintext, &self.plaintext),
                    (Some(held), Some(this)) if held != this
                );
                if differs
                    || (held.to, &held.kind, held.origin) != (self.to, &self.kind, self.origin)
                {
                    return Err(store_corrupt());
                }
                if held.plaintext.is_none() {
                    held.plaintext = self.plaintext;
                }
                Ok(())
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(self);
                Ok(())
            }
        }
    }
}

/// Authenticate every retained copy and require overlapping copies to agree before use.
async fn retained_copies(
    reader: &super::state::Reader,
    meta: &super::state::Meta,
    cert: &pubky_switch_core::records::AppCert,
) -> Result<BTreeMap<String, DeliveryCopy>, AppError> {
    let mut copies = BTreeMap::new();
    for (msg_id, item) in reader.scan::<OutboxItem>(OUT_PREFIX).await? {
        if msg_id != item.msg_id || !item.is_own(meta, cert) {
            return Err(store_corrupt());
        }
        DeliveryCopy::of(&item).remember(msg_id, &mut copies)?;
    }
    for (msg_id, sent) in reader.scan::<SentStored>(SENT_PREFIX).await? {
        if msg_id != sent.msg_id || !sent.is_own(meta, cert) {
            return Err(store_corrupt());
        }
        DeliveryCopy::of_sent(&sent).remember(msg_id, &mut copies)?;
    }
    for item in super::batch::kept_queued(reader).await? {
        if !item.is_own(meta, cert) {
            return Err(store_corrupt());
        }
        DeliveryCopy::of(&item).remember(item.msg_id, &mut copies)?;
    }
    Ok(copies)
}

pub(crate) async fn validate_outbox(
    reader: &super::state::Reader,
    meta: &super::state::Meta,
    cert: &pubky_switch_core::records::AppCert,
) -> Result<(), AppError> {
    retained_copies(reader, meta, cert).await.map(|_| ())
}

/// The exact condition under which settlement can materialize a retained queued intent.
pub(crate) async fn kept_message_owed(
    reader: &super::state::Reader,
    msg_id: &str,
    now: u64,
) -> Result<bool, AppError> {
    Ok(!reader.exists(&out_key(msg_id)).await?
        && !reader.exists(&sent_key(msg_id)).await?
        && !given_up(reader, msg_id, now).await?)
}

impl App {
    async fn read_outbox(&self, msg_id: &str) -> Result<Option<OutboxItem>, AppError> {
        validate_outbox(&self.reader(), &self.state.meta, &self.state.cert).await?;
        let item = self.reader().get::<OutboxItem>(&out_key(msg_id)).await?;
        if item.as_ref().is_some_and(|item| {
            item.msg_id != msg_id || !item.is_own(&self.state.meta, &self.state.cert)
        }) {
            return Err(store_corrupt());
        }
        Ok(item)
    }

    async fn read_sent(&self, msg_id: &str) -> Result<Option<SentStored>, AppError> {
        validate_outbox(&self.reader(), &self.state.meta, &self.state.cert).await?;
        let sent = self.reader().get::<SentStored>(&sent_key(msg_id)).await?;
        if sent.as_ref().is_some_and(|sent| {
            sent.msg_id != msg_id || !sent.is_own(&self.state.meta, &self.state.cert)
        }) {
            return Err(store_corrupt());
        }
        Ok(sent)
    }

    fn inherit_origin(
        &self,
        item: &mut OutboxItem,
        copies: &mut BTreeMap<String, DeliveryCopy>,
    ) -> Result<(), AppError> {
        if !item.is_own(&self.state.meta, &self.state.cert) {
            return Err(Refusal::Usage("a message this app did not sign".into()).into());
        }
        if let Some(kept) = copies.get(&item.msg_id) {
            item.origin = kept.origin;
        }
        DeliveryCopy::of(item).remember(item.msg_id.clone(), copies)
    }

    pub(crate) async fn outbox_items(
        &self,
        messages: &[SignedMessage],
    ) -> Result<Vec<OutboxItem>, AppError> {
        let mut copies =
            retained_copies(&self.reader(), &self.state.meta, &self.state.cert).await?;
        let mut items = Vec::new();
        for message in messages {
            let mut item = self.outbox_item(message)?;
            self.inherit_origin(&mut item, &mut copies)?;
            items.push(item);
        }
        Ok(items)
    }

    // ---------------------------------------------------------------------------------
    // Queueing

    /// Sign `message` once, record it in the outbox with its jobs, then try them once
    /// (module docs). Returns the `msg_id` and where the message is.
    ///
    /// The try is one unit, as in [`App::flush_outbox`]: the conversation entry, one round of
    /// the delivery, and the record job, each a bounded call of its own, so the call's worst
    /// case is theirs. Each write the try makes sends one batch kept from an earlier call
    /// first, as every write does. A message returned [`Delivery::Accepted`] may still owe
    /// its record job, when that write failed: the next pass of the flushes tries it again,
    /// and the
    /// flush's report lists the message under `queued` until then.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`]; [`AppError::InvalidData`] for a message
    /// the core refuses (its kind, its size); a store failure. Failures to deliver aren't
    /// errors: the message stays queued, or is marked failed for good.
    pub async fn send(&mut self, message: OutgoingMessage) -> Result<(String, Delivery), AppError> {
        Box::pin(async move {
            let msg_id = self.queue(message).await?;
            self.flush_item(&msg_id).await?;
            let delivery = self
                .delivery(&msg_id)
                .await?
                .ok_or_else(|| AppError::InvalidData("the message left the outbox".into()))?;
            Ok((msg_id, delivery))
        })
        .await
    }

    /// Sign `message` once and record it in the outbox, sending nothing. Returns its
    /// `msg_id`.
    ///
    /// # Errors
    ///
    /// As [`App::send`].
    pub async fn queue(&mut self, message: OutgoingMessage) -> Result<String, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let signed = self.sign_message(message)?;
            self.queue_signed(signed).await
        })
        .await
    }

    /// Sign `message` once, keeping nothing and sending nothing: its plaintext and hash are
    /// known before it is queued, with [`App::queue_signed`] or in a batch
    /// ([`super::OpBatch::queue`]). A signed message that is never queued was never sent.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`]; [`AppError::InvalidData`] for a message
    /// the core refuses (its kind, its size) or an invite code that isn't one.
    pub fn sign_message(&self, message: OutgoingMessage) -> Result<SignedMessage, AppError> {
        self.refuse_when_stopped()?;
        if let Some(code) = &message.invite_code {
            pubky_switch_core::ident::invite_code_hash(code)?;
        }
        let me = self.state.meta.identity;
        let built = Message::new(
            &message.kind,
            Sender {
                identity: me,
                app_id: self.state.meta.app_id,
            },
            message.to,
            self.now(),
            message.refs,
            message.body,
        )?;
        let plaintext = built.sign(&self.state.keys)?;
        Ok(SignedMessage {
            to: message.to,
            conversation: message.to != me && self.protocols.adds_conversation(&message.kind),
            kind: message.kind,
            msg_id: built.msg_id,
            plaintext,
            notify: message.notify,
            invite_code: message.invite_code,
            record: message.record,
        })
    }

    /// Hold every message to `pubky` that isn't delivered yet, such as when the user blocks
    /// that counterparty, until [`App::release_queued`]. Local only: it sends nothing.
    /// [`App::withdraw_queued`] gives the held messages up instead, and
    /// [`App::hold_message`] holds one message alone.
    ///
    /// - **What is held:** no flush or send delivers a message to `pubky`, a first delivery
    ///   or a re-send, nor writes the conversation entry a first message to it needs. The
    ///   messages stay queued, untried, and their tries aren't counted. Those a batch kept
    ///   from an earlier call puts in the outbox once it settles are held too.
    /// - **What isn't held:** the record job of a message the counterparty's inbox already
    ///   accepted, which is the app's own record write. The own `identity.json` that a flush
    ///   delivers to the switches the app wrote to lately after an app's removal or a closed
    ///   renewal (Switch spec 12.2 step 5): it tells the counterparty's switch that a removed
    ///   app's signature no longer counts, which protects the user whatever the hold. And
    ///   the calls the host makes itself: [`App::ask_to_connect`], and the directory reads
    ///   of [`App::recipients_for`].
    /// - **The replay deadline keeps running** ([`App::queue_stored`]): a message still held
    ///   past it is given up and the protocol told ([`AppEvent::MessageUndelivered`]).
    /// - **Where it holds:** in this app's store. Another app or device of the same identity
    ///   has an outbox of its own, and keeps delivering until its host holds there too.
    /// - **A backup carries it**, so an app restored from that backup holds it too. A restore
    ///   keeps the store's holds as well as the backup's, so a release made after the backup
    ///   is undone by a restore in place: the host releases again. A backup taken before the
    ///   hold doesn't carry it: restored on another store, the message isn't held. The client
    ///   delivers nothing during [`App::restore`], [`App::load`] or [`App::receive`], only in
    ///   [`App::flush_outbox`], [`App::flush_message`], [`App::send`] and [`App::resend`], so a
    ///   host that holds again before it calls any of those leaves no window.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for the app's own identity, whose messages go to the identity's
    /// other apps; [`Refusal::Stopped`] or [`Refusal::Left`]; a store failure.
    pub async fn hold_queued(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            if *pubky == self.state.meta.identity {
                return Err(
                    Refusal::Usage("the app's own identity isn't a counterparty".into()).into(),
                );
            }
            let mut tx = self.tx()?;
            tx.put(&hold_key(pubky), &())?;
            self.commit(tx).await
        })
        .await
    }

    /// Lift [`App::hold_queued`] for `pubky`: its messages go again from the next flush.
    /// Releasing a counterparty that isn't held changes nothing.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`]; a store failure.
    pub async fn release_queued(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let mut tx = self.tx()?;
            tx.delete(&hold_key(pubky))?;
            self.commit(tx).await
        })
        .await
    }

    /// The counterparties whose messages the app holds ([`App::hold_queued`]).
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn held_counterparties(&self) -> Result<Vec<[u8; 32]>, AppError> {
        let held = self.reader().scan_raw(HOLD_PREFIX).await?;
        held.into_iter()
            .map(|(rest, _)| {
                pubky_switch_core::enc::unb64_array::<32>(&rest)
                    .map_err(|_| AppError::Store(StoreError::Corrupt))
            })
            .collect()
    }

    /// Hold the message `msg_id` of the protocol `protocol`, queued and not delivered yet,
    /// until [`App::release_message`]: for a protocol that holds some messages to a
    /// counterparty while others to it still go, such as those of one side of a flow. A
    /// protocol holds only its own messages, those of its kinds. Local only: it sends
    /// nothing. [`App::withdraw_message`] gives the message up instead. Returns whether it
    /// holds it: `false`, writing nothing, when the app owes no delivery of `msg_id`, such
    /// as for a message delivered, given up, refused for good or never queued here.
    ///
    /// It holds as [`App::hold_queued`] holds a counterparty's messages, for this message
    /// alone, whichever of the two holds:
    /// - **What is held:** no flush or send delivers it, a first delivery or a re-send, nor
    ///   writes the conversation entry it needs. It stays queued, untried, and its tries
    ///   aren't counted. A message a batch kept from an earlier call puts in the outbox once
    ///   it settles is held too, and so is the copy of it [`App::queue_signed`] or
    ///   [`App::queue_stored`] queues meanwhile.
    /// - **What isn't held:** its record job, once the counterparty's inbox accepted it, and
    ///   the app's other messages to the same counterparty.
    /// - **The replay deadline keeps running** ([`App::queue_stored`]): a message still held
    ///   past it is given up and the protocol told ([`AppEvent::MessageUndelivered`]).
    /// - **It lasts as long as the delivery:** it ends with the release, and in the commit
    ///   that ends the delivery, whatever ends it: the message delivered, refused for good,
    ///   given up or withdrawn, the kept batch that would queue it dropped (unless the
    ///   outbox or another kept batch holds it), or a restore whose outbox doesn't owe it.
    ///   Nothing else ends it, and a message queued again after its delivery ended starts
    ///   unheld.
    /// - **Where it holds:** in this app's store: another app or device of the same
    ///   identity has an outbox of its own.
    /// - **A backup carries it** for a message the backup carries in its outbox. A restore
    ///   keeps the store's holds of the messages its outbox owes as well as the backup's, so
    ///   a release made after the backup is undone by a restore in place: the protocol
    ///   releases again. A backup taken before the hold doesn't carry it, nor one taken while
    ///   the message was only in a kept batch: the client delivers nothing during
    ///   [`App::restore`], [`App::load`] or [`App::receive`], so a protocol that holds again
    ///   before the host calls [`App::flush_outbox`], [`App::flush_message`], [`App::send`]
    ///   or [`App::resend`] leaves no window.
    /// - **A try in flight:** after a crash during a delivery's try, the message may have
    ///   reached the counterparty's inbox although the outbox still owes it; a hold then
    ///   holds a re-try that the inbox drops as a duplicate.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a protocol not registered, or a message of another
    /// protocol's kind; [`Refusal::Stopped`] or [`Refusal::Left`]; a store failure.
    pub async fn hold_message(&mut self, protocol: &str, msg_id: &str) -> Result<bool, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            if self.owned_owed(protocol, msg_id).await?.is_none() {
                return Ok(false);
            }
            let mut tx = self.tx()?;
            put_message_hold(&mut tx, msg_id)?;
            self.commit(tx).await?;
            Ok(true)
        })
        .await
    }

    /// Lift [`App::hold_message`] of the protocol `protocol` for `msg_id`: it goes again
    /// from the next flush, unless its counterparty is held ([`App::hold_queued`]).
    /// Releasing a message that isn't held changes nothing.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a protocol not registered, or a message of another
    /// protocol's kind; [`Refusal::Stopped`] or [`Refusal::Left`]; a store failure.
    pub async fn release_message(&mut self, protocol: &str, msg_id: &str) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            self.owned_owed(protocol, msg_id).await?;
            let mut tx = self.tx()?;
            end_message_hold(&mut tx, msg_id)?;
            self.commit(tx).await
        })
        .await
    }

    /// The messages of the protocol `protocol` the app holds ([`App::hold_message`]) and
    /// still owes a delivery of, in `msg_id` order.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a protocol not registered; a store failure.
    pub async fn held_messages(&self, protocol: &str) -> Result<Vec<String>, AppError> {
        self.check_registered(protocol)?;
        validate_outbox(&self.reader(), &self.state.meta, &self.state.cert).await?;
        Ok(held_messages_of(&self.reader(), self.now())
            .await?
            .into_iter()
            .filter(|(_, kind)| self.owns_kind(protocol, kind))
            .map(|(msg_id, _)| msg_id)
            .collect())
    }

    /// Whether `kind` is a kind of the protocol `protocol`, or of no registered protocol,
    /// as a message a restore with another set of protocols brings back: any protocol may
    /// then act on it, so its hold can still be released.
    fn owns_kind(&self, protocol: &str, kind: &str) -> bool {
        self.protocols
            .of_kind(kind)
            .is_none_or(|owner| owner.name == protocol)
    }

    /// List every owed delivery of `protocol`, including every retained batch producer
    /// and kinds no registered protocol owns (Switch spec 11). Materialized items come
    /// first by queue time and ID, then kept intents by batch order, each message once.
    /// Holds, a protocol refusal to send, and elapsed replay deadlines do not hide work
    /// that has not yet ended. `kept_batch` names its earliest remaining producer.
    ///
    /// This reads local state only: it writes nothing, settles no batch and sends no
    /// request. The protocol decision is the same one dispatch asks. For a local cleanup
    /// based on absence, the host must resolve earlier writes and retain exclusive App
    /// namespace ownership across this read, a fresh [`App::delivery`] and
    /// [`App::protocol_commit`], with no intervening producer or restore call.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for an unregistered protocol; [`Refusal::NotNow`] while a failed
    /// commit requires reload; a store failure or inconsistent retained copies.
    pub async fn queued_messages(&self, protocol: &str) -> Result<Vec<QueuedMessage>, AppError> {
        self.check_registered(protocol)?;
        if self.reload {
            return Err(Refusal::NotNow(
                "a commit failed: reload before listing deliveries".into(),
            )
            .into());
        }
        validate_outbox(&self.reader(), &self.state.meta, &self.state.cert).await?;
        let reader = self.reader();
        let mut outbox = reader.scan::<OutboxItem>(OUT_PREFIX).await?;
        outbox.sort_by(|a, b| (a.1.queued_ms, &a.0).cmp(&(b.1.queued_ms, &b.0)));
        let mut owed: Vec<_> = outbox
            .into_iter()
            .filter(|(_, item)| item.delivery_pending())
            .map(|(_, item)| (item, None))
            .collect();
        let mut batches = self.kept_batches().await?;
        batches.sort_by_key(|(id, pending)| (pending.queued_n, *id));
        let mut listed = BTreeSet::new();
        for (batch_id, pending) in batches {
            for item in pending.queued {
                if kept_message_owed(&reader, &item.msg_id, self.now()).await?
                    && listed.insert(item.msg_id.clone())
                {
                    owed.push((item, Some(batch_id)));
                }
            }
        }
        let mut result = Vec::new();
        for (item, kept_batch) in owed {
            if !self.owns_kind(protocol, &item.kind) {
                continue;
            }
            let holds = self.delivery_holds(&item).await?;
            let hash = item.plaintext()?.hash();
            let resend = item.is_resend();
            result.push(QueuedMessage {
                msg_id: item.msg_id,
                to: item.to,
                kind: item.kind,
                hash,
                origin: item.origin,
                resend,
                kept_batch,
                held: holds.message,
                counterparty_held: holds.counterparty,
                may_send: holds.may_send,
            });
        }
        Ok(result)
    }

    /// The kind of the message `msg_id` when the app owes its delivery, checked to be a
    /// message of the protocol `protocol`: what the per-message calls act on.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a protocol not registered, or a message of another kind than
    /// its own; a store failure.
    async fn owned_owed(&self, protocol: &str, msg_id: &str) -> Result<Option<String>, AppError> {
        self.check_registered(protocol)?;
        let reader = self.reader();
        validate_outbox(&reader, &self.state.meta, &self.state.cert).await?;
        let kept = super::batch::kept_queued(&reader).await?;
        let kind = owed_kind(&reader, msg_id, self.now(), &kept).await?;
        match kind {
            Some(kind) if !self.owns_kind(protocol, &kind) => Err(Refusal::Usage(format!(
                "`{msg_id}` is a message of no kind of `{protocol}`"
            ))
            .into()),
            kind => Ok(kind),
        }
    }

    /// Give up every message to `pubky` that isn't delivered yet, held or not: each is
    /// deleted from the outbox, plaintext and all, and the protocol told once
    /// ([`AppEvent::MessageUndelivered`], a duty event, `resend: true` for a re-send of one
    /// accepted before, which keeps its record job). So is each message to `pubky` that a
    /// batch kept from an earlier call would put in the outbox once it settles: the batch's
    /// other operations still go, and the message isn't queued. A message given up so is
    /// never queued again by this store: [`App::queue_stored`] refuses it, and a re-send
    /// after the counterparty's provider loss leaves it out. [`App::resend`] refuses
    /// it too. Returns the messages given up: those of the outbox in queue order,
    /// then those of kept batches. The retained queued copies and
    /// their delivery index are removed in the same commit, leaving the batch's other
    /// operations and local writes intact. Local only: it sends nothing.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`]; a store failure, after which the messages
    /// given up before it stay given up.
    pub async fn withdraw_queued(&mut self, pubky: &[u8; 32]) -> Result<Vec<String>, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            self.withdraw_where(|item| item.to == *pubky).await
        })
        .await
    }

    /// Give up the message `msg_id` of the protocol `protocol`, held or not, as
    /// [`App::withdraw_queued`] gives up each message to a counterparty, with the same
    /// exceptions (a re-send whose record job is still owed keeps its outbox item for that
    /// job; [`App::queue_signed`] checks no give-up): its delivery ends, in the outbox or in
    /// what a batch kept from an earlier call puts there once it settles, and the protocol
    /// is told once ([`AppEvent::MessageUndelivered`]); its hold, if any, ends. Returns
    /// whether it gave it up: `false`, changing nothing, when the app owes no delivery of
    /// `msg_id`. Local only: it sends nothing.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a protocol not registered, or a message of another
    /// protocol's kind; [`Refusal::Stopped`] or [`Refusal::Left`]; a store failure.
    pub async fn withdraw_message(
        &mut self,
        protocol: &str,
        msg_id: &str,
    ) -> Result<bool, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            if self.owned_owed(protocol, msg_id).await?.is_none() {
                return Ok(false);
            }
            let withdrawn = self.withdraw_where(|item| item.msg_id == msg_id).await?;
            Ok(!withdrawn.is_empty())
        })
        .await
    }

    /// Give up every message `matches` takes whose delivery is owed, as
    /// [`App::withdraw_queued`] says: those of the outbox in queue order, each in a commit of
    /// its own, then those of kept batches.
    async fn withdraw_where(
        &mut self,
        matches: impl Fn(&OutboxItem) -> bool,
    ) -> Result<Vec<String>, AppError> {
        validate_outbox(&self.reader(), &self.state.meta, &self.state.cert).await?;
        let now = self.now();
        let mut items: Vec<OutboxItem> = self
            .reader()
            .scan::<OutboxItem>(OUT_PREFIX)
            .await?
            .into_iter()
            .map(|(_, item)| item)
            .filter(|item| matches(item) && item.failed.is_none() && item.delivery_owed())
            .collect();
        items.sort_by_key(|item| item.queued_ms);
        let mut withdrawn = Vec::new();
        for item in items {
            let msg_id = item.msg_id.clone();
            let to = self.owners_of_kind(&item.kind);
            let (kept, duty) = item.give_up_delivery();
            let mut tx = self.tx()?;
            match &kept {
                // Kept for its record job: the mark stops a re-send after a loss.
                Some(kept) => tx.put(&out_key(&msg_id), kept)?,
                None => tx.delete(&out_key(&msg_id))?,
            }
            self.end_delivery(&msg_id, &mut tx).await?;
            self.keep_duty_for(&mut tx, to, duty)?;
            self.commit(tx).await?;
            withdrawn.push(msg_id);
        }
        // The messages kept batches would queue once they settle.
        for (_, pending) in self.kept_batches().await? {
            for item in pending.queued.iter().filter(|item| matches(item)) {
                let msg_id = item.msg_id.clone();
                if self.knows_message(&msg_id).await?
                    || given_up(&self.reader(), &msg_id, now).await?
                {
                    continue;
                }
                let mut tx = self.tx()?;
                self.end_delivery(&msg_id, &mut tx).await?;
                let to = self.owners_of_kind(&item.kind);
                self.keep_duty_for(
                    &mut tx,
                    to,
                    Duty::MessageUndelivered {
                        msg_id: msg_id.clone(),
                        resend: false,
                    },
                )?;
                self.commit(tx).await?;
                withdrawn.push(msg_id);
            }
        }
        Ok(withdrawn)
    }

    /// Record a message signed by [`App::sign_message`] in the outbox, with its jobs,
    /// sending nothing. Returns its `msg_id`. A message already in the outbox, or sent, is
    /// left as it is.
    ///
    /// It is for a message just signed. It checks neither a give-up nor the message's age,
    /// so a host doesn't queue a kept [`SignedMessage`] again once its delivery was given up
    /// ([`AppEvent::MessageUndelivered`]), or 30 days after it was signed: past that a
    /// recipient that processed it may have forgotten the pair, and would process it as new
    /// (Switch spec 11). A message signed before is queued again with [`App::queue_stored`],
    /// which refuses those.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`]; [`Refusal::Usage`] for a message another
    /// app signed; a store failure.
    pub async fn queue_signed(&mut self, message: SignedMessage) -> Result<String, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let mut item = self.outbox_item(&message)?;
            let mut copies =
                retained_copies(&self.reader(), &self.state.meta, &self.state.cert).await?;
            self.inherit_origin(&mut item, &mut copies)?;
            if self.knows_message(&item.msg_id).await? {
                return Ok(item.msg_id);
            }
            let mut tx = self.tx()?;
            put_outbox_item(&mut tx, &item)?;
            self.commit(tx).await?;
            Ok(item.msg_id)
        })
        .await
    }

    /// Queue again a message this app signed itself, from its stored signed plaintext, with
    /// the same bytes and so the same `msg_id`, sending nothing (Switch spec 11 "Queued
    /// again by its signer"). Returns its `msg_id`.
    ///
    /// It is for a message no outbox holds although the protocol's records show it sent. A
    /// batch that queues a message ([`super::OpBatch::queue`]) puts it in the outbox only
    /// with the batch's answer, and a backup doesn't carry a batch kept unanswered. So
    /// after a restore from a backup taken while such a batch was kept, if the batch was
    /// applied, the record it wrote stores the message while neither the outbox nor the
    /// sent messages hold it. The protocol queues it again from that record.
    ///
    /// The plaintext must be signed with this app's key, the one its certificate names,
    /// with the App ID and `from` of this app and identity; the recipient, the kind and the
    /// `msg_id` are the message's. It is queued as [`App::queue_signed`] queues one, with
    /// the conversation entry its kind needs, and no record job, since the record holds it
    /// already. The copy carries no invite code and notifies the recipient: a first message
    /// that needed an invite code is for the host to send again with one.
    ///
    /// The call queues the message once however often it is made, while the outbox holds
    /// it or the app keeps it as sent; it then returns the `msg_id` and changes nothing.
    /// After that it is refused with [`Refusal::WontDeliver`], and queues nothing and raises
    /// no event:
    ///
    /// - [`WontDeliver::PastReplayWindow`]: past [`SENT_RETENTION_MS`] from the message's
    ///   `created_at`, less the clock tolerance, by the later of the device clock and a
    ///   service time the app verified. A recipient that processed the message drops a copy
    ///   as a duplicate only while it keeps the pair, so a copy, and any re-send of it, goes
    ///   only until then; one queued in time and still undelivered then is given up, and
    ///   [`AppEvent::MessageUndelivered`] tells the protocol, once.
    /// - [`WontDeliver::GivenUp`]: the app gave its delivery up already, and told the
    ///   protocol then.
    /// - [`WontDeliver::TooLarge`]: its outbox record is over the store's sizes.
    ///
    /// So for one message, within one store, the call never leads to a second
    /// [`AppEvent::MessageUndelivered`], nor to one with `resend: false` once this app had a
    /// copy of it accepted. A backup carries the sent messages (Switch spec 12.4 "Sent
    /// messages"), so a restored app knows a message accepted before the backup and queues
    /// nothing for it, unless the backup left it out past [`MAX_CARRIED_SENT_BYTES`]. It
    /// carries no give-up marks, so a restored app may queue again a message given up
    /// before the backup: within its window it goes again, as a first delivery.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`]; [`Refusal::WontDeliver`] as above;
    /// [`Refusal::Usage`] for a plaintext that doesn't read as a message, or that this app
    /// didn't sign; a store failure.
    pub async fn queue_stored(&mut self, plaintext: &MessagePlaintext) -> Result<String, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let mut item = self.stored_item(plaintext)?;
            let mut copies =
                retained_copies(&self.reader(), &self.state.meta, &self.state.cert).await?;
            self.inherit_origin(&mut item, &mut copies)?;
            if self.knows_message(&item.msg_id).await? {
                return Ok(item.msg_id);
            }
            let refused = |why| Err(AppError::Refused(Refusal::WontDeliver(why)));
            if given_up(&self.reader(), &item.msg_id, self.now()).await? {
                return refused(WontDeliver::GivenUp);
            }
            if let Some(until_ms) = item.replay_until_ms
                && self.kept_window_now() > until_ms
            {
                return refused(WontDeliver::PastReplayWindow { until_ms });
            }
            let written = async {
                let mut tx = self.tx()?;
                put_outbox_item(&mut tx, &item)?;
                self.commit(tx).await
            }
            .await;
            match written {
                Err(AppError::Store(StoreError::TooLarge { .. })) => {
                    self.reload_now().await?;
                    refused(WontDeliver::TooLarge)
                }
                committed => committed.map(|()| item.msg_id),
            }
        })
        .await
    }

    /// The outbox item of a message this app signed, read from its signed plaintext
    /// ([`App::queue_stored`]).
    fn stored_item(&self, plaintext: &MessagePlaintext) -> Result<OutboxItem, AppError> {
        let not_ours = || AppError::from(Refusal::Usage("a message this app didn't sign".into()));
        let me = self.state.meta.identity;
        let app_id = self.state.meta.app_id;
        if plaintext.sender_app_id() != app_id {
            return Err(not_ours());
        }
        let rules = self.protocols.opaque_of_json(plaintext.json());
        let opaque: Vec<OpaqueMember<'_>> = rules
            .iter()
            .map(|rule| OpaqueMember {
                kind: rule.kind.as_deref(),
                member: rule.member.as_str(),
            })
            .collect();
        let message = Message::parse(plaintext.json(), &opaque)
            .map_err(|_| Refusal::Usage("a stored plaintext that isn't a message".into()))?;
        if message.from.identity != me || message.from.app_id != app_id {
            return Err(not_ours());
        }
        // Switch wire 5.1 check 4, as the recipient makes it: the key the certificate names,
        // over the recipient identity and the JSON bytes.
        plaintext
            .verify_signature(&self.state.cert.signing_key(), &message.to)
            .map_err(|_| not_ours())?;
        let deadline = message
            .created_at_ms
            .saturating_sub(CLOCK_TOLERANCE_MS)
            .saturating_add(SENT_RETENTION_MS);
        Ok(OutboxItem {
            origin: DeliveryOrigin::Reconstructed,
            to: message.to,
            conversation: message.to != me && self.protocols.adds_conversation(&message.kind),
            kind: message.kind,
            msg_id: message.msg_id,
            plaintext: plaintext.encode(),
            notify: true,
            invite_code: None,
            sealed: None,
            record: None,
            record_done: false,
            accepted_at_ms: None,
            failed: None,
            last_error: None,
            tries: 0,
            queued_ms: self.now(),
            resend: false,
            undeliverable_ms: None,
            undeliverable_reason: None,
            undeliverable_last_ms: None,
            undeliverable_tries: 0,
            resend_queued: false,
            replay_until_ms: Some(deadline),
            record_batch: None,
        })
    }

    /// Whether the outbox holds the message `msg_id`, or the app keeps it as sent.
    pub(crate) async fn knows_message(&self, msg_id: &str) -> Result<bool, AppError> {
        let reader = self.reader();
        Ok(reader.exists(&out_key(msg_id)).await? || reader.exists(&sent_key(msg_id)).await?)
    }

    /// The outbox item of a signed message, its jobs owed.
    pub(crate) fn outbox_item(&self, message: &SignedMessage) -> Result<OutboxItem, AppError> {
        if message.plaintext.sender_app_id() != self.state.meta.app_id {
            return Err(Refusal::Usage("a message this app didn't sign".into()).into());
        }
        Ok(OutboxItem {
            origin: DeliveryOrigin::Original,
            to: message.to,
            kind: message.kind.clone(),
            msg_id: message.msg_id.clone(),
            plaintext: message.plaintext.encode(),
            notify: message.notify,
            invite_code: message.invite_code.clone(),
            conversation: message.conversation,
            sealed: None,
            record: message.record.as_ref().map(KeptJob::of),
            record_done: false,
            accepted_at_ms: None,
            failed: None,
            last_error: None,
            tries: 0,
            queued_ms: self.now(),
            resend: false,
            undeliverable_ms: None,
            undeliverable_reason: None,
            undeliverable_last_ms: None,
            undeliverable_tries: 0,
            resend_queued: false,
            replay_until_ms: None,
            record_batch: None,
        })
    }

    /// Try the jobs of the queued message `msg_id` once, as [`App::flush_outbox`] does for
    /// every message, and return where it is; `None` for one the app doesn't keep. The try
    /// is one unit, as [`App::send`]'s. A try whose conversation entry is owed sends one kept
    /// batch first, and the entry is written only once no batch is kept; otherwise the call
    /// sends no kept batch beyond the one each write of the try sends first. A read, a write
    /// or the flushes' passes send the rest.
    ///
    /// # Errors
    ///
    /// As [`App::flush_outbox`].
    pub async fn flush_message(&mut self, msg_id: &str) -> Result<Option<Delivery>, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            self.flush_item(msg_id).await?;
            self.delivery(msg_id).await
        })
        .await
    }

    /// Send again a message sent in the last 30 days: the same signed plaintext, and so the
    /// same `msg_id`, sealed to the recipient's current keys (Switch spec 11). It adds no
    /// conversation entry and writes no record. A re-send goes only within 30 days of the
    /// message's first acceptance, and by its replay deadline when it has one; past it the
    /// re-send is given up ([`AppEvent::MessageUndelivered`] with `resend: true`), and the
    /// call still returns the earlier acceptance ([`Delivery::Accepted`]). The try is one
    /// unit, as [`App::send`]'s. A message a backup carried without its signed plaintext
    /// (Switch spec 12.4 "Sent messages") can't go again: its re-send is given up at once,
    /// told the same way.
    ///
    /// # Errors
    ///
    /// [`Refusal::WontDeliver`] with [`WontDeliver::GivenUp`] for a delivery the app gave
    /// up, or a re-send it gives up for want of the plaintext; [`Refusal::Usage`] for a
    /// message the app doesn't keep; as [`App::send`].
    pub async fn resend(&mut self, msg_id: &str) -> Result<Delivery, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            if !self.prepare_resend(msg_id).await? {
                return Err(AppError::Refused(Refusal::WontDeliver(
                    WontDeliver::GivenUp,
                )));
            }
            self.flush_item(msg_id).await?;
            self.delivery(msg_id)
                .await?
                .ok_or_else(|| AppError::InvalidData("the message left the outbox".into()))
        })
        .await
    }

    /// Prepare either retained copy for a re-send, unless its delivery was given up.
    /// Check before changing an accepted item's jobs or queuing its sent copy, so a repeated
    /// request neither delivers it nor reports it undelivered again (Switch spec 11).
    /// A sent message a backup carried without its signed plaintext can't go again: its
    /// re-send is given up at once, and the protocol told, as for one past its replay
    /// deadline (Switch spec 12.4 "Sent messages"). Returns whether a re-send is queued.
    async fn prepare_resend(&mut self, msg_id: &str) -> Result<bool, AppError> {
        if given_up(&self.reader(), msg_id, self.now()).await? {
            return Ok(false);
        }
        if !self.ask_resend_of_queued(msg_id).await? {
            let sent = self.read_sent(msg_id).await?.ok_or_else(|| {
                AppError::Refused(Refusal::Usage("no sent message with this msg_id".into()))
            })?;
            let Some(plaintext) = sent.plaintext() else {
                let to = self.owners_of_kind(&sent.kind);
                let mut tx = self.tx()?;
                self.keep_duty_for(
                    &mut tx,
                    to,
                    Duty::MessageUndelivered {
                        msg_id: sent.msg_id.clone(),
                        resend: true,
                    },
                )?;
                self.commit(tx).await?;
                return Ok(false);
            };
            self.queue_resend(&sent, plaintext.to_vec()).await?;
        }
        Ok(true)
    }

    /// A message still in the outbox: one already accepted, whose other jobs are owed, is
    /// marked to be sealed and sent again. Returns whether it is in the outbox.
    async fn ask_resend_of_queued(&mut self, msg_id: &str) -> Result<bool, AppError> {
        let Some(mut item) = self.read_outbox(msg_id).await? else {
            return Ok(false);
        };
        if let Some(accepted) = item.accepted_at_ms
            && !item.resend
        {
            item.resend = true;
            item.sealed = None;
            // A re-send goes only while the recipient keeps the processed pair, 30 days from
            // the first acceptance (Switch spec 11).
            item.replay_until_ms = [
                item.replay_until_ms,
                Some(accepted.saturating_add(SENT_RETENTION_MS)),
            ]
            .into_iter()
            .flatten()
            .min();
            self.save_item(&item).await?;
        }
        Ok(true)
    }

    /// Queue a re-send of `sent`, whose signed plaintext is `plaintext`.
    async fn queue_resend(
        &mut self,
        sent: &SentStored,
        plaintext: Vec<u8>,
    ) -> Result<(), AppError> {
        let item = OutboxItem {
            origin: sent.origin,
            to: sent.to,
            kind: sent.kind.clone(),
            msg_id: sent.msg_id.clone(),
            plaintext,
            notify: false,
            invite_code: None,
            conversation: false,
            sealed: None,
            record: None,
            record_done: false,
            accepted_at_ms: None,
            failed: None,
            last_error: None,
            tries: 0,
            queued_ms: self.now(),
            resend: false,
            undeliverable_ms: None,
            undeliverable_reason: None,
            undeliverable_last_ms: None,
            undeliverable_tries: 0,
            resend_queued: true,
            // Only while the recipient keeps the processed pair: 30 days from the first
            // acceptance, and by the deadline the message came with (Switch spec 11).
            replay_until_ms: [
                sent.replay_until_ms,
                Some(sent.first_ms.saturating_add(SENT_RETENTION_MS)),
            ]
            .into_iter()
            .flatten()
            .min(),
            record_batch: None,
        };
        let mut tx = self.tx()?;
        tx.put(&out_key(&item.msg_id), &item)?;
        self.commit(tx).await
    }

    /// Send again what `pubky`'s old switch accepted since `since_ms` (app clock of the
    /// previous check), after a provider loss (Switch spec 8.1), but no message whose
    /// delivery the app gave up while its give-up mark stands.
    pub(crate) async fn resend_since(
        &mut self,
        pubky: &[u8; 32],
        since_ms: u64,
    ) -> Result<(), AppError> {
        let mut queued = 0u64;
        for (msg_id, sent) in self.reader().scan::<SentStored>(SENT_PREFIX).await? {
            if msg_id != sent.msg_id || !sent.is_own(&self.state.meta, &self.state.cert) {
                return Err(store_corrupt());
            }
            if sent.to != *pubky || sent.latest_ms() < since_ms {
                continue;
            }
            if self.prepare_resend(&sent.msg_id).await? {
                queued = queued.saturating_add(1);
            }
        }
        if queued > 0 {
            self.events.push(AppEvent::ResendAfterLoss {
                identity: *pubky,
                messages: queued,
            });
        }
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // State

    /// Where the message `msg_id` is: in the outbox, sent, or in a kept batch that queues it
    /// ([`Delivery::Kept`], and [`Delivery::Failed`] once that batch is dropped); `None` for
    /// one the app doesn't keep. A restore keeps the sent messages its backup carries
    /// (Switch spec 12.4 "Sent messages"), so a message accepted before the backup reads as
    /// accepted after it. `None` never says the message was never sent: one accepted or
    /// ended longer than [`SENT_RETENTION_MS`] ago, one in a batch kept before a restore,
    /// one the backup left out past [`MAX_CARRIED_SENT_BYTES`], or one the device a backup
    /// came from sent after it, isn't known here. The protocol reads its shared state then.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn delivery(&self, msg_id: &str) -> Result<Option<Delivery>, AppError> {
        if let Some(item) = self.read_outbox(msg_id).await? {
            return Ok(Some(match (&item.failed, item.accepted_at_ms) {
                (Some((reason, failed_at_ms)), _) => Delivery::Failed {
                    reason: reason.clone(),
                    failed_at_ms: *failed_at_ms,
                },
                (None, Some(accepted_at_ms)) if !item.resend => {
                    Delivery::Accepted { accepted_at_ms }
                }
                (None, _) => Delivery::Queued {
                    tries: item.tries,
                    last_error: item.last_error.clone(),
                    undeliverable_since_ms: item.undeliverable_ms,
                    undeliverable_reason: item.undeliverable_reason,
                },
            }));
        }
        if let Some(sent) = self.read_sent(msg_id).await? {
            return Ok(Some(Delivery::Accepted {
                accepted_at_ms: sent.first_ms,
            }));
        }
        self.kept_delivery(msg_id).await
    }

    /// The messages sent to `pubky` that its inbox accepted within `[from_ms, until_ms]`,
    /// first acceptances and re-sends, for the protocol's answer to a re-send request
    /// (Switch spec 11). Each carries every acceptance time the app kept
    /// ([`SentMessage::accepted_times_ms`]). A message a backup carried without its signed
    /// plaintext isn't listed: it can't be sent again (Switch spec 12.4 "Sent messages").
    ///
    /// # Errors
    ///
    /// A store failure, or a kept message that doesn't read.
    pub async fn sent_to(
        &self,
        pubky: &[u8; 32],
        from_ms: u64,
        until_ms: u64,
    ) -> Result<Vec<SentMessage>, AppError> {
        let mut out = Vec::new();
        for (msg_id, sent) in self.reader().scan::<SentStored>(SENT_PREFIX).await? {
            if msg_id != sent.msg_id || !sent.is_own(&self.state.meta, &self.state.cert) {
                return Err(store_corrupt());
            }
            let within = std::iter::once(sent.first_ms)
                .chain(sent.resent.iter().copied())
                .any(|at| at >= from_ms && at <= until_ms);
            // One kept without its plaintext can't be sent again, and isn't listed.
            if let Some(plaintext) = sent.plaintext()
                && sent.to == *pubky
                && within
            {
                out.push(SentMessage {
                    to: sent.to,
                    kind: sent.kind.clone(),
                    msg_id: sent.msg_id.clone(),
                    plaintext: MessagePlaintext::decode(plaintext).map_err(|_| store_corrupt())?,
                    accepted_at_ms: Some(sent.first_ms),
                    resent_at_ms: sent.resent_ascending(),
                });
            }
        }
        Ok(out)
    }

    // ---------------------------------------------------------------------------------
    // Flushing

    /// Try queued messages' jobs once each (Switch spec 11: on start, on returning to the
    /// foreground, when the network comes back), after the deliveries of the own
    /// `identity.json` owed, and forget sent messages past their retention, and the ends of
    /// kept batches past theirs ([`super::App::kept_batch`]).
    ///
    /// The call is bounded:
    /// - Its work goes in units: a delivery of the own `identity.json` to one switch, or
    ///   one message's try (its conversation entry, one delivery round and its record job,
    ///   each a bounded call of its own), or, at the start of a pass, one kept batch sent
    ///   again. A unit once begun goes whole. The call starts no unit once its time budget
    ///   ([`super::AppConfig::call_budget_ms`]) is spent, but its first. So its worst case is
    ///   the budget and one unit begun within it.
    /// - One unit is bounded on its own. A delivery of the own `identity.json` is one
    ///   request. A message's try is, at the default timeouts with every request waiting to
    ///   the end of its timeout:
    ///   - the service-time fetch of a message with a replay deadline, about 10 s;
    ///   - its conversation entry, a write that may send a kept batch first under the long
    ///     timeout, about 60 s;
    ///   - one delivery round: its first attempt, at most four requests with the directory
    ///     under the long timeout, and no retry once the budget has passed since the round
    ///     began, about 90 s;
    ///   - the own `identity.json` delivered after the acceptance asks for it, about 10 s;
    ///   - its record job ([`super::App::update_record`], bounded the same way), about 130 s
    ///     on a switch that answers nothing in time.
    ///
    ///   So about 5 minutes. A try against switches that answer takes seconds.
    /// - It tries at most [`OUTBOX_TRIES_PER_FLUSH`] messages. What is left stays owed, and
    ///   [`OutboxReport::more`] says so: the host flushes again at once.
    /// - It sends one batch kept from an earlier call again, oldest first, as the first unit
    ///   of each pass, and none otherwise. A message whose conversation entry is owed goes
    ///   once no batch is kept: with k kept batches, in the k-th pass, sooner when a read or
    ///   another write sends them. A batch past its answer window gets its end in the pass that sends it
    ///   ([`super::App::kept_batch`]). Reads send kept batches
    ///   too ([`super::App::receive`]), and so does each write a message's try makes, one
    ///   first, as every write does. One that keeps failing holds the others behind it until
    ///   its answer window ends, by design: no write overtakes another. A conversation
    ///   entry is written only once no batch is kept ahead of it, and the holds are read
    ///   after the kept batch its write sends: a settlement that holds the message holds
    ///   its entry too.
    /// - The next flush starts after the last message this one tried, by queue time, and
    ///   goes round, so a message that keeps failing holds up none behind it.
    /// - Flushes go in passes, each trying every queued message and every owed delivery
    ///   once. While a pass is under way, a flush tries only what it hasn't reached; the
    ///   deliveries and the messages start a pass together, and a flush that goes on with
    ///   one starts no new pass of the other. The flush that ends both says `more` false.
    ///   An owed delivery that failed goes behind those not tried yet. A held message
    ///   ([`App::hold_queued`]) makes no request for its delivery and doesn't count towards
    ///   the four.
    /// - Where a pass got is committed after each message's try, so a flush cut short goes
    ///   on from after the last try it finished. A try that a failure or a crash cut short
    ///   goes again first.
    ///
    /// After a pass, messages still queued wait for the host's next flush, on the triggers of
    /// Switch spec 11: on start, on returning to the foreground, when the network comes back,
    /// or on a timer of the host's own. A send, a resend or a read doesn't flush the others.
    ///
    /// # Errors
    ///
    /// A store failure, or an alarm. A message that can't be delivered now stays queued.
    pub async fn flush_outbox(&mut self) -> Result<OutboxReport, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            validate_outbox(&self.reader(), &self.state.meta, &self.state.cert).await?;
            let budget = self.begin_budget();
            // The units this flush started: a delivery of the own `identity.json` or a
            // message's try. Past the budget none starts but the flush's first.
            let mut units = 0usize;
            let next: Option<OutNext> = self.reader().get(OUT_NEXT).await?;
            let messages_open = next.as_ref().is_some_and(|next| next.open);
            // The two passes go together: a flush that continues one starts no new pass of
            // the other, so a loop "flush while more" tries each delivery and message once.
            let peers_open = self.peers_pass_open().await?;
            let start = !messages_open && !peers_open;
            // A pass begins with one kept batch sent again, oldest first, as before any write:
            // a message whose conversation entry is in it, or that it would queue, goes with
            // the pass that follows, and one past its answer window gets its end.
            if start && !self.kept_batches().await?.is_empty() {
                units += 1;
                match self
                    .resume_kept(super::batch::KEPT_RESENDS_PER_WRITE, None)
                    .await
                {
                    Err(error) if is_local(&error) => return Err(error),
                    _ => {}
                }
            }
            let peers_left = if peers_open || start {
                self.deliver_to_recent_peers(&budget, &mut units).await?
            } else {
                false
            };
            let mut items = self.reader().scan::<OutboxItem>(OUT_PREFIX).await?;
            items
                .sort_by(|(a_id, a), (b_id, b)| a.queued_ms.cmp(&b.queued_ms).then(a_id.cmp(b_id)));
            // From after the last message the flush before tried, round the queue.
            if let Some(OutNext { last: (at, id), .. }) = &next {
                let start = items
                    .iter()
                    .position(|(msg_id, item)| (item.queued_ms, msg_id) > (*at, id))
                    .unwrap_or(0);
                items.rotate_left(start);
            }
            let run_messages = messages_open || start;
            // A pass under way tries only the messages it hasn't reached yet.
            let in_pass = |key: &(u64, String)| match &next {
                Some(OutNext {
                    last,
                    pass_first: Some(first),
                    open: true,
                }) => between(last, key, first),
                _ => true,
            };
            let mut report = OutboxReport::default();
            let cutoff = self.now().saturating_sub(SENT_RETENTION_MS);
            let mut tried = 0usize;
            let mut messages_left = false;
            // What the store holds of it, as each try's commit changes it.
            let mut stored = next.clone();
            let mut pass = OutNext {
                last: next
                    .as_ref()
                    .map_or((0, String::new()), |next| next.last.clone()),
                pass_first: next
                    .as_ref()
                    .filter(|next| next.open)
                    .and_then(|next| next.pass_first.clone()),
                open: true,
            };
            for (msg_id, item) in items {
                if let Some((_, failed_ms)) = &item.failed {
                    // Forgotten, plaintext and all, after the retention of sent messages.
                    if *failed_ms <= cutoff {
                        let mut tx = self.tx()?;
                        tx.delete(&out_key(&msg_id))?;
                        self.commit(tx).await?;
                    } else {
                        report.failed.push(msg_id);
                    }
                    continue;
                }
                let key = (item.queued_ms, msg_id.clone());
                // Tried already in this pass, or no pass of the messages in this flush.
                if !run_messages || !in_pass(&key) {
                    report.queued.push(msg_id);
                    continue;
                }
                // At most OUTBOX_TRIES_PER_FLUSH a flush, and no unit past its time but its
                // first: the next flush goes on from here.
                if tried >= OUTBOX_TRIES_PER_FLUSH || (units > 0 && self.spent(&budget)) {
                    messages_left = true;
                    report.queued.push(msg_id);
                    continue;
                }
                // A held message makes no request for its delivery: it doesn't count towards
                // the four.
                let held = self.delivery_waits(&item).await?;
                if !held {
                    tried += 1;
                }
                units += 1;
                let undelivered = self.flush_item(&msg_id).await?;
                // Kept once the try is done, so a flush cut short goes on from after the
                // last try it finished; one a failure or a crash cut short goes again first.
                pass.pass_first.get_or_insert_with(|| key.clone());
                pass.last = key;
                let mut tx = self.tx()?;
                tx.put(OUT_NEXT, &pass)?;
                self.commit(tx).await?;
                stored = Some(pass.clone());
                if undelivered {
                    report.undelivered.push(msg_id);
                    continue;
                }
                match self.delivery(&msg_id).await? {
                    Some(Delivery::Failed { .. }) => report.failed.push(msg_id),
                    Some(Delivery::Queued { .. }) => report.queued.push(msg_id),
                    _ if self.reader().exists(&out_key(&msg_id)).await? => {
                        report.queued.push(msg_id);
                    }
                    _ => report.done.push(msg_id),
                }
            }
            // Messages of the pass left untried keep it open; otherwise it is over.
            if run_messages {
                if !messages_left {
                    pass.pass_first = None;
                    pass.open = false;
                }
                if stored.as_ref() != Some(&pass) {
                    let mut tx = self.tx()?;
                    tx.put(OUT_NEXT, &pass)?;
                    self.commit(tx).await?;
                }
            }
            report.more = peers_left || messages_left;
            self.prune_sent().await?;
            self.prune_kept_ends().await?;
            Ok(report)
        })
        .await
    }

    /// One try of each job of one message. Returns whether a delivery was given up as
    /// undeliverable.
    ///
    /// A try whose own writes are over the store's sizes ([`StoreError::TooLarge`]), the
    /// message's outbox record or its sent copy, would be refused the same way at every
    /// flush: the delivery is given up for good, as [`App::drop_undeliverable`] gives one
    /// up, and the flush goes on. A counterparty's directory too large to cache isn't one
    /// of its writes: it is read again at each send instead (`directory.rs`).
    async fn flush_item(&mut self, msg_id: &str) -> Result<bool, AppError> {
        match self.try_item(msg_id).await {
            Err(AppError::Store(StoreError::TooLarge { .. })) => {
                // The refused commit may have left memory ahead of the store: read it again
                // before going on.
                self.reload_now().await?;
                self.give_up_too_large(msg_id).await?;
                Ok(true)
            }
            tried => tried,
        }
    }

    /// Give up the delivery of a message whose try is too large for the store, in one
    /// commit with [`AppEvent::MessageUndelivered`](super::AppEvent::MessageUndelivered): a
    /// message never accepted is deleted, plaintext and all; one accepted before keeps its
    /// record while its record job is owed, and only the re-send is given up.
    async fn give_up_too_large(&mut self, msg_id: &str) -> Result<(), AppError> {
        let Some(mut item) = self.read_outbox(msg_id).await? else {
            return Ok(());
        };
        let resend =
            item.accepted_at_ms.is_some() || self.reader().exists(&sent_key(msg_id)).await?;
        item.resend = false;
        item.sealed = None;
        item.clear_undeliverable();
        let fits = u64::try_from(super::state::encode(&item)?.len())
            .is_ok_and(|size| size <= crate::store::MAX_VALUE_BYTES);
        let mut gone = item.accepted_at_ms.is_none() || item.complete() || !fits;
        loop {
            let mut tx = self.tx()?;
            if gone {
                tx.delete(&out_key(msg_id))?;
            } else {
                tx.put(&out_key(msg_id), &item)?;
            }
            self.end_delivery(msg_id, &mut tx).await?;
            let to = self.owners_of_kind(&item.kind);
            self.keep_duty_for(
                &mut tx,
                to,
                Duty::MessageUndelivered {
                    msg_id: msg_id.to_owned(),
                    resend,
                },
            )?;
            match self.commit(tx).await {
                // A record that still doesn't fit goes too, its record job with it.
                Err(AppError::Store(StoreError::TooLarge { .. })) if !gone => {
                    self.reload_now().await?;
                    gone = true;
                }
                committed => return committed,
            }
        }
    }

    /// One try of each job of one message, as one unit: the conversation entry, one round of
    /// the delivery, and the record job. Each is a bounded call of its own. A new hold
    /// stops the remaining delivery work, preserving jobs already completed and allowing
    /// an accepted message's record job to continue.
    async fn try_item(&mut self, msg_id: &str) -> Result<bool, AppError> {
        let Some(mut item) = self.read_outbox(msg_id).await? else {
            return Ok(false);
        };
        if item.failed.is_some() {
            return Ok(false);
        }
        // A delivery to a counterparty the host holds, of a message it holds, or one its
        // protocol holds back, isn't tried, a first one or a re-send ([`App::hold_queued`],
        // [`App::hold_message`], [`super::Protocol::may_send`]);
        // its replay deadline still runs, and its record job goes.
        let mut held = self.delivery_waits(&item).await?;
        // A delivery with a replay deadline, one a restore put back, one `queue_stored`
        // queued, or a re-send of either, goes only by it, judged at the later of the device
        // clock and a service time verified in this call (Switch spec 11).
        if item.delivery_owed()
            && let Some(deadline) = item.replay_until_ms
        {
            if !held && self.kept_window_now() <= deadline {
                match self.fresh_service_time().await {
                    Err(error) if is_local(&error) => return Err(error),
                    _ => {}
                }
            }
            if self.kept_window_now() > deadline {
                let to = self.owners_of_kind(&item.kind);
                let (kept, duty) = item.give_up_delivery();
                let mut tx = self.tx()?;
                match &kept {
                    Some(kept) => tx.put(&out_key(msg_id), kept)?,
                    None => {
                        tx.delete(&out_key(msg_id))?;
                    }
                }
                self.end_delivery(msg_id, &mut tx).await?;
                self.keep_duty_for(&mut tx, to, duty)?;
                self.commit(tx).await?;
                return Ok(true);
            }
        }
        // Past the firm bound, the message goes before it is tried again.
        if item
            .undeliverable_ms
            .is_some_and(|since| self.now().saturating_sub(since) >= UNDELIVERABLE_MAX_MS)
            && self.drop_undeliverable(&mut item).await?
        {
            return Ok(true);
        }
        // The conversation entry is a write, and a write first sends a batch kept from an
        // earlier call, whose settlement may commit local policy the holds read. So that
        // batch goes first and the holds are read again after it: the entry and the
        // delivery go by this one decision, with nothing kept settled after it.
        let mut settled = Ok(());
        if item.conversation && !held && self.entry_owed(&item.to).await? {
            match self
                .resume_kept(super::batch::KEPT_RESENDS_PER_WRITE, None)
                .await
            {
                Err(error) if is_local(&error) => return Err(error),
                resumed => settled = resumed.map(|_| ()),
            }
            held = self.delivery_waits(&item).await?;
        }
        if !held {
            item.tries = item.tries.saturating_add(1);
        }
        if item.conversation && !held {
            let entry = match settled {
                Ok(()) => self.conversation_entry(&item.to).await,
                Err(error) => Err(error),
            };
            match entry {
                Ok(()) => item.conversation = false,
                Err(error) if is_local(&error) => return Err(error),
                Err(error) => {
                    item.last_error = Some(error.to_string());
                    self.save_item(&item).await?;
                    return Ok(false);
                }
            }
            self.save_item(&item).await?;
        }
        if item.delivery_owed() && !held {
            match self.deliver(&mut item).await? {
                Tried::Held => self.save_item(&item).await?,
                Tried::Accepted(answer) => self.accept(&mut item, &answer).await?,
                Tried::Queued(why) => {
                    item.last_error = Some(why);
                    self.save_item(&item).await?;
                }
                Tried::Undeliverable(why, reason) => {
                    item.last_error = Some(why);
                    item.count_undeliverable(self.now(), reason);
                    self.save_item(&item).await?;
                    if self.drop_undeliverable(&mut item).await? {
                        return Ok(true);
                    }
                }
                Tried::Failed(why) => {
                    // Refused for good: the delivery ends, and its hold with it.
                    item.failed = Some((why, self.now()));
                    let mut tx = self.tx()?;
                    tx.put(&out_key(&item.msg_id), &item)?;
                    self.end_delivery(&item.msg_id, &mut tx).await?;
                    self.commit(tx).await?;
                }
            }
        }
        if let Some(accepted) = item.accepted_at_ms
            && !item.record_done
            && let Some(job) = item.record.clone()
        {
            if accepted <= self.now().saturating_sub(SENT_RETENTION_MS) {
                self.drop_record_job(item).await?;
                return Ok(false);
            }
            match self.record_job(&item, &job).await {
                Ok(()) => item.record_done = true,
                Err(error) if is_local(&error) => return Err(error),
                Err(error) => {
                    if let Some(batch_id) = error.kept_batch() {
                        item.record_batch = Some(pubky_switch_core::enc::b64(&batch_id));
                    }
                    item.last_error = Some(error.to_string());
                }
            }
            self.save_item(&item).await?;
        }
        if item.complete() {
            self.finish_item(&item).await?;
        }
        Ok(false)
    }

    /// End a delivery answered `403 not_admitted` or `403 not_current` for
    /// [`UNDELIVERABLE_MS`], at [`UNDELIVERABLE_TRIES`] spaced tries, the last one this
    /// flush's, or for [`UNDELIVERABLE_MAX_MS`] however few tries (Switch spec 11): a
    /// message never accepted is deleted, plaintext and all; a re-send is no longer owed.
    /// The protocol is told. Returns whether the delivery was given up.
    async fn drop_undeliverable(&mut self, item: &mut OutboxItem) -> Result<bool, AppError> {
        let Some(since) = item.undeliverable_ms else {
            return Ok(false);
        };
        let elapsed = self.now().saturating_sub(since);
        let confirmed =
            item.undeliverable_tries >= UNDELIVERABLE_TRIES && elapsed >= UNDELIVERABLE_MS;
        if !confirmed && elapsed < UNDELIVERABLE_MAX_MS {
            return Ok(false);
        }
        // A re-send: of an item accepted before, or queued again from `sent/`.
        let resend =
            item.accepted_at_ms.is_some() || self.reader().exists(&sent_key(&item.msg_id)).await?;
        item.resend = false;
        item.clear_undeliverable();
        let gone = item.accepted_at_ms.is_none() || item.complete();
        let mut tx = self.tx()?;
        if gone {
            tx.delete(&out_key(&item.msg_id))?;
        } else {
            tx.put(&out_key(&item.msg_id), &*item)?;
        }
        self.end_delivery(&item.msg_id, &mut tx).await?;
        // A duty event for the protocol of the message's kind, kept in the commit that
        // gives the delivery up.
        let to = self.owners_of_kind(&item.kind);
        self.keep_duty_for(
            &mut tx,
            to,
            Duty::MessageUndelivered {
                msg_id: item.msg_id.clone(),
                resend,
            },
        )?;
        self.commit(tx).await?;
        Ok(true)
    }

    async fn save_item(&mut self, item: &OutboxItem) -> Result<(), AppError> {
        let mut tx = self.tx()?;
        tx.put(&out_key(&item.msg_id), item)?;
        self.commit(tx).await
    }

    /// The counterparty's inbox accepted the message: its acceptance is committed at once,
    /// with the sent message kept for re-sends and what the answer shows of the counterparty's
    /// switch, before anything else is done (Switch spec 11). Then what the answer asks for:
    /// the directory read again, the own `identity.json` delivered.
    async fn accept(
        &mut self,
        item: &mut OutboxItem,
        answer: &AppendAnswer,
    ) -> Result<(), AppError> {
        let at = answer.accepted_at;
        let first = *item.accepted_at_ms.get_or_insert(at);
        item.resend = false;
        item.last_error = None;
        item.clear_undeliverable();
        let mut tx = self.tx()?;
        tx.put(&out_key(&item.msg_id), &*item)?;
        // No retained producer can recreate this completed delivery after retention.
        self.end_delivery(&item.msg_id, &mut tx).await?;
        let sent = match self.read_sent(&item.msg_id).await? {
            Some(mut sent) => {
                if at != sent.first_ms && !sent.resent.contains(&at) {
                    sent.resent.push(at);
                }
                sent.replay_until_ms = [sent.replay_until_ms, item.replay_until_ms]
                    .into_iter()
                    .flatten()
                    .min();
                // A record a backup carried without its plaintext takes it again.
                sent.plaintext
                    .get_or_insert_with(|| SignedBytes(item.plaintext.clone()));
                sent
            }
            None => {
                tx.put(&sent_time_key(first, &item.msg_id), &())?;
                SentStored {
                    origin: item.origin,
                    to: item.to,
                    kind: item.kind.clone(),
                    msg_id: item.msg_id.clone(),
                    plaintext: Some(SignedBytes(item.plaintext.clone())),
                    first_ms: first,
                    resent: if at == first { Vec::new() } else { vec![at] },
                    replay_until_ms: item.replay_until_ms,
                }
            }
        };
        tx.put(&sent_key(&item.msg_id), &sent)?;
        let own = item.to == self.state.meta.identity;
        if !own {
            let mut peer = self.peer_switch(&item.to).await?;
            peer.last_sent_ms = Some(self.now());
            peer.known_version = answer.known_version;
            super::directory::put_peer(&mut tx, &item.to, &peer)?;
        }
        self.commit(tx).await?;
        self.events.push(AppEvent::MessageAccepted {
            msg_id: item.msg_id.clone(),
            accepted_at_ms: at,
        });
        if !own {
            self.after_accepted(&item.to, answer).await?;
        }
        Ok(())
    }

    /// Give up the record job of `item`, still owed [`SENT_RETENTION_MS`] after its first
    /// acceptance, such as one whose held value waits for a key that never comes: in one
    /// commit with [`AppEvent::RecordJobDropped`], the item kept only while a re-send of it
    /// is owed, so its plaintext doesn't stay, nor go into every later backup, for ever.
    async fn drop_record_job(&mut self, mut item: OutboxItem) -> Result<(), AppError> {
        item.record = None;
        let mut tx = self.tx()?;
        if item.complete() {
            tx.delete(&out_key(&item.msg_id))?;
        } else {
            tx.put(&out_key(&item.msg_id), &item)?;
        }
        let to = self.owners_of_kind(&item.kind);
        self.keep_duty_for(
            &mut tx,
            to,
            Duty::RecordJobDropped {
                msg_id: item.msg_id.clone(),
                batch_id: item.record_batch.clone(),
            },
        )?;
        self.commit(tx).await
    }

    /// A complete item leaves the outbox; its sent message is kept from its acceptance.
    async fn finish_item(&mut self, item: &OutboxItem) -> Result<(), AppError> {
        let mut tx = self.tx()?;
        tx.delete(&out_key(&item.msg_id))?;
        self.commit(tx).await
    }

    /// Forget sent messages 30 days after their first acceptance, oldest first.
    async fn prune_sent(&mut self) -> Result<(), AppError> {
        let now = self.now();
        let mut tx = self.tx()?;
        for (rest, ()) in self.reader().scan::<()>(SENT_TIME_PREFIX).await? {
            let Some((at, msg_id)) = rest.split_once('/') else {
                continue;
            };
            let Ok(at) = super::state::parse_num(at) else {
                continue;
            };
            if sent_kept(at, now) {
                break;
            }
            tx.delete(&sent_key(msg_id))?;
            tx.delete(&sent_time_key(at, msg_id))?;
        }
        for (msg_id, until) in self.reader().scan::<u64>(GIVEN_UP_PREFIX).await? {
            // A retained item may still await its turn in a bounded flush. Keep its mark
            // until neither stored copy can produce a re-send, even if this commit removes
            // the sent copy: the next prune can remove the mark.
            if until < now
                && !self.reader().exists(&out_key(&msg_id)).await?
                && !self.reader().exists(&sent_key(&msg_id)).await?
            {
                tx.delete(&given_up_key(&msg_id))?;
            }
        }
        if !tx.is_empty() {
            self.commit(tx).await?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // The jobs

    /// Whether the conversation entry for `pubky` is still to be written: the app knows it
    /// holds none and no contact (Switch spec 7), and its certificate has `conversation.add`.
    async fn entry_owed(&self, pubky: &[u8; 32]) -> Result<bool, AppError> {
        let reader = self.reader();
        Ok(!(reader
            .exists(&allow_key(AllowKind::Conversation, pubky))
            .await?
            || reader.exists(&allow_key(AllowKind::Contact, pubky)).await?
            || !self.state.cert.has_permission(Permission::ConversationAdd)))
    }

    /// The conversation entry for `pubky`, unless it isn't owed ([`App::entry_owed`]). It is
    /// written only with no batch kept from an earlier call ahead of it: otherwise the call
    /// fails with [`Refusal::NotNow`] and the item is tried again once they are answered.
    /// A kept batch's settlement may close the delivery's holds, so the entry is never kept
    /// behind one, decided before that settlement ([`App::try_item`] sends one kept batch
    /// first and reads the holds after it).
    async fn conversation_entry(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        if !self.entry_owed(pubky).await? {
            return Ok(());
        }
        if self.kept_ahead().await?.is_some() {
            return Err(Refusal::NotNow(
                "the conversation entry waits for the batches kept ahead of it".into(),
            )
            .into());
        }
        self.submit_batch(OpBatch::new().op(OpKind::AllowPut {
            pubky: *pubky,
            kind: AllowKind::Conversation,
        }))
        .await?;
        Ok(())
    }

    /// One delivery try (module docs, steps 2 to 4): under the copy of the recipient's
    /// `identity.json` held ([`App::deliver_under`]), and once more after reading the newest
    /// one when an answer of its switch didn't verify with the service key that copy names
    /// and the newest names another key or switch
    /// (Switch spec 4.3: a copy is re-fetched after any failure). The reads are bounded
    /// ([`App::reread_after_unverified`]); an answer that still doesn't verify is queued as
    /// any other.
    ///
    /// The round is bounded: it reads the newest copy at most once, and it starts no retry,
    /// that reread, a reseal after `409 stale_key` or the own `identity.json` delivered again
    /// after `409 identity_needed`, once the call's time budget
    /// ([`super::AppConfig::call_budget_ms`]) has passed since the round began. Its worst case
    /// is the budget and the attempt under way when it ran out: an attempt is at most the
    /// recipient's `identity.json` from the Homeserver, the own one delivered, the
    /// directory, and the append, each under its timeout. A retry left so is recorded, the
    /// new keys taken and the envelope dropped, or the switch's copy of the own
    /// `identity.json` taken as unknown, so the next try's first attempt makes it.
    async fn deliver(&mut self, item: &mut OutboxItem) -> Result<Tried, AppError> {
        // The time of this round: it starts no retry once the call's budget has passed.
        let round = self.begin_budget();
        let mut reread = false;
        loop {
            // Conversation settlement or a prior retry may have committed new local
            // policy. Re-read the common holds before further delivery work.
            if self.delivery_waits(item).await? {
                return Ok(Tried::Held);
            }
            match Box::pin(self.deliver_under(item, &round)).await? {
                Delivered::Tried(tried) => return Ok(tried),
                // At most once a round, however long its requests take, and within its time.
                Delivered::Unverified { held, error } => {
                    if reread
                        || self.spent(&round)
                        || !Box::pin(self.reread_after_unverified(&item.to, &held)).await?
                    {
                        return queued_or(error);
                    }
                    reread = true;
                }
            }
        }
    }

    /// Read the newest `identity.json` of `to` after an answer of its switch didn't verify
    /// with the service key the copy `held` names, as after a provider loss in place, whose
    /// new key a sender within its cache of the earlier document doesn't know (Switch spec
    /// 4.3: a copy is re-fetched after any failure; 12.6). At most one such read per
    /// identity per [`super::SENDER_REREAD_MS`], kept in memory, so a switch answering under
    /// keys no document names makes the app read no more; a read whose copy failed to
    /// commit doesn't count. Returns whether the newest copy
    /// names another switch or key, under which the delivery is tried again; a newer copy
    /// has the directory read again (Switch spec 8.1).
    async fn reread_after_unverified(
        &mut self,
        to: &[u8; 32],
        held: &IdentityDoc,
    ) -> Result<bool, AppError> {
        let now = self.now();
        let lately = |at: u64| at <= now && now - at < super::SENDER_REREAD_MS;
        if self.peer_rereads.get(to).is_some_and(|at| lately(*at)) {
            return Ok(false);
        }
        let read = self.peer_identity(to, true).await;
        // The read counts once what it took is committed, an unreadable copy included. A
        // newer copy whose commit failed leaves the held one, and the next try reads again
        // rather than wait out the window under a key that no longer verifies.
        if !matches!(read, Err(AppError::Store(_))) {
            self.peer_rereads.retain(|_, at| lately(*at));
            self.peer_rereads.insert(*to, now);
        }
        let newer = match read {
            Ok(doc) => doc,
            Err(AppError::Store(error)) => return Err(error.into()),
            Err(_) => return Ok(false),
        };
        Ok(newer.inbox() != held.inbox())
    }

    /// One try of the delivery under the recipient's `identity.json` held.
    async fn deliver_under(
        &mut self,
        item: &mut OutboxItem,
        round: &super::CallBudget,
    ) -> Result<Delivered, AppError> {
        let to = item.to;
        let own = to == self.state.meta.identity;
        let invite = item.invite_code.clone();
        let doc = match self.peer_identity(&to, false).await {
            Ok(doc) => doc,
            Err(error) => return queued_or(error).map(Delivered::Tried),
        };
        // An answer of the recipient's switch that doesn't verify with the key `doc` names.
        let failed = |error: AppError| -> Result<Delivered, AppError> {
            if is_unverified(&error) {
                return Ok(Delivered::Unverified {
                    held: Box::new(doc.clone()),
                    error,
                });
            }
            queued_or(error).map(Delivered::Tried)
        };
        if let Some(sealed) = &item.sealed
            && (sealed.origin != doc.inbox().url || sealed.generation != doc.generation())
        {
            item.sealed = None;
        }
        if !own
            && let Err(error) = self
                .deliver_own_identity(&to, invite.as_deref(), false)
                .await
        {
            return failed(error);
        }
        if item.sealed.is_none()
            && let Err(error) = self.seal(item, invite.as_deref()).await
        {
            return failed(error);
        }
        let mut resealed = 0usize;
        let mut redelivered = false;
        loop {
            let Some(sealed) = item.sealed.clone() else {
                return Ok(Delivered::Tried(Tried::Queued("not sealed".into())));
            };
            // Identity delivery, sealing and retry preparation may write state. The
            // same current decision gates every actual append, own or peer, including
            // retries, with no state-changing await between this check and the call.
            if self.delivery_waits(item).await? {
                return Ok(Delivered::Tried(Tried::Held));
            }
            let peer = if own {
                None
            } else {
                Some(self.peer_client(&to, &doc)?)
            };
            let started = peer
                .as_ref()
                .unwrap_or(&self.client)
                .start_append(
                    sealed.envelope.as_bytes().to_vec(),
                    sealed.apps_version,
                    if own { None } else { invite.as_deref() },
                )
                .await;
            let started = if own {
                self.take(started).await
            } else {
                started.map_err(AppError::from)
            };
            let result = match started {
                Ok(call) => {
                    if call.needs_retry() {
                        // Keep the first authenticated response before another decision;
                        // a withheld timestamp retry is not a failed or accepted delivery.
                        if own {
                            self.keep_observations().await?;
                        }
                        if self.delivery_waits(item).await? {
                            return Ok(Delivered::Tried(Tried::Held));
                        }
                    }
                    let answer = peer
                        .as_ref()
                        .unwrap_or(&self.client)
                        .finish_append(call)
                        .await;
                    if own {
                        self.take(answer).await
                    } else {
                        answer.map_err(AppError::from)
                    }
                }
                Err(error) => Err(error),
            };
            match result {
                Ok(answer) => return Ok(Delivered::Tried(Tried::Accepted(answer))),
                Err(AppError::Switch(ClientError::Switch {
                    code: ErrorCode::StaleKey,
                    current,
                    ..
                })) if resealed < RESEALS => {
                    resealed = resealed.saturating_add(1);
                    self.take_stale_key(&to, &current).await?;
                    // Past the round's time the reseal waits for the next try, which seals
                    // to the keys just taken on its first attempt.
                    if self.spent(round) {
                        item.sealed = None;
                        return Ok(Delivered::Tried(Tried::Queued(
                            "409 stale_key: sealed again at the next try".into(),
                        )));
                    }
                    if let Err(error) = self.seal(item, invite.as_deref()).await {
                        return failed(error);
                    }
                }
                Err(AppError::Switch(ClientError::Switch {
                    code: ErrorCode::IdentityNeeded,
                    ..
                })) if !redelivered && !own => {
                    redelivered = true;
                    // Past the round's time the delivery of the own `identity.json` waits
                    // for the next try, whose first attempt makes it: the switch's copy is
                    // taken as unknown.
                    if self.spent(round) {
                        self.note_known_version(&to, None).await?;
                        return Ok(Delivered::Tried(Tried::Queued(
                            "409 identity_needed: delivered at the next try".into(),
                        )));
                    }
                    if let Err(error) = self
                        .deliver_own_identity(&to, invite.as_deref(), true)
                        .await
                    {
                        return failed(error);
                    }
                }
                Err(AppError::Switch(ClientError::Switch {
                    code: ErrorCode::Moved,
                    ..
                })) => {
                    // Sent at the new service once the recipient's identity.json names it
                    // (Switch spec 11).
                    self.peer_identity(&to, true).await.ok();
                    self.mark_directory_stale(&to).await?;
                    return Ok(Delivered::Tried(Tried::Queued("moved".into())));
                }
                Err(error) => return failed(error),
            }
        }
    }

    /// Whether the delivery of an outbox message waits: one is owed, and the host holds its
    /// counterparty ([`App::hold_queued`]) or the message itself ([`App::hold_message`]), or
    /// its protocol holds it back ([`super::Protocol::may_send`]). Every call that tries a
    /// delivery ([`App::send`], [`App::flush_message`], [`App::resend`],
    /// [`App::flush_outbox`]) goes through `try_item`, which asks this, so no call passes
    /// any of the holds.
    async fn delivery_waits(&self, item: &OutboxItem) -> Result<bool, AppError> {
        Ok(item.delivery_owed() && self.delivery_holds(item).await?.any())
    }

    async fn delivery_holds(&self, item: &OutboxItem) -> Result<DeliveryHolds, AppError> {
        let reader = self.reader();
        Ok(DeliveryHolds {
            message: reader.exists(&message_hold_key(&item.msg_id)).await?,
            counterparty: reader.exists(&hold_key(&item.to)).await?,
            may_send: self.may_send(item),
        })
    }

    /// Whether the protocol of an outbox message's kind lets it go out now
    /// ([`super::Protocol::may_send`]). A message whose kind no protocol owns goes to its
    /// try; unreadable plaintext or unavailable protocol evidence keeps the delivery held.
    fn may_send(&self, item: &OutboxItem) -> bool {
        // Retained-copy validation binds this routing kind to the authenticated JSON.
        // An absent owner supplies no body rules and imposes no protocol hold.
        let Some(owner) = self.protocols.of_kind(&item.kind) else {
            return true;
        };
        let Ok(plaintext) = item.plaintext() else {
            return false;
        };
        // A kept message is read by its common fields, so a protocol's changed body rules
        // never hold it for good; the protocol's own hook decides.
        let Some(message) = super::protocols::kept_message(plaintext.json()) else {
            return false;
        };
        let local = super::LocalView::new(
            self.state.meta.identity,
            self.state.meta.app_id,
            self.env.store.store().as_ref(),
            &self.ns,
            &owner.name,
        );
        let delivery = DeliveryView {
            message: &message,
            plaintext: &plaintext,
            origin: item.origin,
            resend: item.is_resend(),
            local,
            cert: &self.state.cert,
            naming: &self.state.naming,
            store: self.env.store.store().as_ref(),
            ns: &self.ns,
            clock: self.env.clock.as_ref(),
        };
        owner.protocol.may_send(&delivery).unwrap_or(false)
    }

    /// Seal the item's signed plaintext to the recipient apps, and commit the envelope
    /// before it is sent.
    async fn seal(&mut self, item: &mut OutboxItem, invite: Option<&str>) -> Result<(), AppError> {
        let plaintext = item.plaintext()?;
        // Read by its signed common fields, as every kept copy is ([`own_message`]): the
        // body rules judged it when it was queued, and a changed rule never stops it.
        let message = super::protocols::kept_message(plaintext.json()).ok_or_else(store_corrupt)?;
        let (routes, apps_version) = self.routes(&item.to, &message, invite).await?;
        let recipients: Vec<_> = routes.iter().map(|r: &Route| r.recipient).collect();
        let envelope = pubky_switch_core::envelope::seal_retained(
            &item.to,
            &recipients,
            &plaintext.encode(),
            item.notify,
        )?;
        let doc = self.peer_identity(&item.to, false).await?;
        item.sealed = Some(Sealed {
            envelope,
            apps_version,
            origin: doc.inbox().url.clone(),
            generation: doc.generation(),
        });
        self.save_item(item).await
    }

    /// An append the counterparty's inbox accepted, its acceptance committed: what its
    /// answer shows about the directory and the own `identity.json` there.
    async fn after_accepted(
        &mut self,
        to: &[u8; 32],
        answer: &AppendAnswer,
    ) -> Result<(), AppError> {
        if let Some(cached) = self.cached_directory(to).await?
            && answer.directory_version > cached.directory_version
        {
            self.mark_directory_stale(to).await?;
        }
        // Delivered again whenever the switch shows an older version (Switch spec 6.1); a
        // failure here leaves it to the next send.
        let _ = self.deliver_own_identity(to, None, false).await;
        Ok(())
    }

    /// The record job: the protocol builds the record's next value from what the app holds,
    /// written compare-and-swap.
    async fn record_job(&mut self, item: &OutboxItem, job: &KeptJob) -> Result<(), AppError> {
        let kept = self.read_sent(&item.msg_id).await?;
        let sent = SentMessage {
            to: item.to,
            kind: item.kind.clone(),
            msg_id: item.msg_id.clone(),
            plaintext: item.plaintext()?,
            accepted_at_ms: kept
                .as_ref()
                .map(|sent| sent.first_ms)
                .or(item.accepted_at_ms),
            resent_at_ms: kept
                .as_ref()
                .map(SentStored::resent_ascending)
                .unwrap_or_default(),
        };
        let job = job.job();
        let protocols = self.protocols.clone();
        self.update_record(&job.target, Vec::new(), |current| {
            protocols.sent_record(&job, &sent, current)
        })
        .await?;
        Ok(())
    }
}

/// What one try of a delivery came to.
enum Delivered {
    /// Held, or tried: accepted, queued, undeliverable or failed.
    Tried(Tried),
    /// An answer of the recipient's switch that didn't verify with the service key of the
    /// copy `held` of its `identity.json`.
    Unverified {
        held: Box<IdentityDoc>,
        error: AppError,
    },
}

/// Whether `error` is an answer whose service signature is missing or doesn't verify with
/// the key pinned (Switch wire 7.1).
fn is_unverified(error: &AppError) -> bool {
    matches!(
        error.unkept(),
        AppError::Switch(ClientError::BadServiceSignature { .. })
    )
}

/// Whether an error is the app's own (an alarm, the store, a refusal of the app's rules)
/// rather than the network's or the switch's, which the outbox retries.
fn is_local(error: &AppError) -> bool {
    matches!(error.unkept(), AppError::Alarm(_) | AppError::Store(_))
}

/// A failed try: failed for good only when the switch refused it for good, the Retry column
/// of Switch spec 6.4 saying "No"; queued again for everything else (the network, `429`,
/// `503`, a refusal of the app's rules that may lift). `403 not_admitted` and `403
/// not_current` stay queued for a bounded time: admission changes when the counterparty adds
/// a contact or an invite (Switch spec 7), and a renewal makes a certificate current again
/// (Switch wire 3.8).
fn queued_or(error: AppError) -> Result<Tried, AppError> {
    match &error {
        AppError::Alarm(_) | AppError::Store(_) => Err(error),
        AppError::Switch(ClientError::Switch {
            code: ErrorCode::NotAdmitted,
            ..
        }) => Ok(Tried::Undeliverable(
            error.to_string(),
            UndeliverableReason::NotAdmitted,
        )),
        AppError::Switch(ClientError::Switch {
            code: ErrorCode::NotCurrent,
            ..
        }) => Ok(Tried::Undeliverable(
            error.to_string(),
            UndeliverableReason::NotCurrent,
        )),
        AppError::Switch(ClientError::Switch { code, .. }) if code.retry() == Retry::No => {
            Ok(Tried::Failed(error.to_string()))
        }
        _ => Ok(Tried::Queued(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_failures_split_into_retry_and_refusal() {
        let switch = |code: ErrorCode| {
            AppError::Switch(ClientError::Switch {
                status: code.status(),
                code,
                message: String::new(),
                current: Value::Null,
                known_version: None,
                retry_after: None,
            })
        };
        assert!(matches!(
            queued_or(switch(ErrorCode::RateLimited)),
            Ok(Tried::Queued(_))
        ));
        assert!(matches!(
            queued_or(switch(ErrorCode::Unavailable)),
            Ok(Tried::Queued(_))
        ));
        assert!(matches!(
            queued_or(switch(ErrorCode::NotAdmitted)),
            Ok(Tried::Undeliverable(_, UndeliverableReason::NotAdmitted))
        ));
        assert!(matches!(
            queued_or(switch(ErrorCode::NotCurrent)),
            Ok(Tried::Undeliverable(_, UndeliverableReason::NotCurrent))
        ));
        assert!(matches!(
            queued_or(switch(ErrorCode::Conflict)),
            Ok(Tried::Queued(_))
        ));
        assert!(matches!(
            queued_or(switch(ErrorCode::TooLarge)),
            Ok(Tried::Failed(_))
        ));
        assert!(matches!(
            queued_or(switch(ErrorCode::PermissionMissing)),
            Ok(Tried::Failed(_))
        ));
        assert!(matches!(
            queued_or(AppError::Transport(crate::error::TransportError::Timeout)),
            Ok(Tried::Queued(_))
        ));
        assert!(queued_or(AppError::Store(crate::error::StoreError::Unavailable)).is_err());
    }

    #[test]
    fn test_send_outgoing_debug_shows_only_the_kind() {
        let mut body = Map::new();
        body.insert("text".into(), Value::String("secret".into()));
        let message = OutgoingMessage::new([1; 32], "sample.note", body);
        assert_eq!(format!("{message:?}"), "OutgoingMessage(sample.note)");
    }

    /// A queued message accepted once, with a record job owed and an envelope sealed for
    /// its re-send.
    fn accepted_item() -> OutboxItem {
        OutboxItem {
            origin: DeliveryOrigin::Original,
            to: [1; 32],
            kind: "sample.note".into(),
            msg_id: "m1".into(),
            plaintext: Vec::new(),
            notify: false,
            invite_code: None,
            conversation: false,
            sealed: Some(Sealed {
                envelope: pubky_switch_core::envelope::seal_retained(
                    &[1; 32],
                    &[pubky_switch_core::envelope::Recipient::new(
                        pubky_switch_core::keys::ReceiveKey::generate(0)
                            .unwrap()
                            .public,
                    )],
                    &[],
                    false,
                )
                .unwrap(),
                apps_version: 1,
                origin: "https://bob.example".into(),
                generation: 1,
            }),
            record: Some(KeptJob {
                collection: "sample.items".into(),
                policy: pubky_switch_core::ident::Policy::new("scope-a", &["scope-a"]),
                natural_key: b"n1".to_vec(),
                tag: Vec::new(),
            }),
            record_done: false,
            accepted_at_ms: Some(1_000),
            failed: None,
            last_error: None,
            tries: 1,
            queued_ms: 500,
            resend: true,
            undeliverable_ms: None,
            undeliverable_reason: None,
            undeliverable_last_ms: None,
            undeliverable_tries: 0,
            resend_queued: false,
            replay_until_ms: None,
            record_batch: None,
        }
    }

    #[test]
    fn test_outbox_give_up_keeps_an_owed_record_job_without_the_envelope() {
        let (kept, duty) = accepted_item().give_up_delivery();
        let kept = kept.expect("the record job is owed");
        assert!(!kept.delivery_owed());
        assert!(
            kept.sealed.is_none(),
            "the envelope sealed for the re-send goes"
        );
        assert!(!kept.record_done);
        assert!(matches!(
            duty,
            Duty::MessageUndelivered { resend: true, .. }
        ));
        // Never accepted: nothing stays.
        let mut never = accepted_item();
        never.accepted_at_ms = None;
        never.resend = false;
        let (kept, duty) = never.give_up_delivery();
        assert!(kept.is_none());
        assert!(matches!(
            duty,
            Duty::MessageUndelivered { resend: false, .. }
        ));
    }

    #[test]
    fn test_outbox_replay_deadline_only_comes_earlier() {
        let mut item = accepted_item();
        // The first acceptance's window comes before the backup's.
        item.replay_until(5_000);
        assert_eq!(item.replay_until_ms, Some(1_000 + SENT_RETENTION_MS));
        // A later baseline doesn't move it on; an earlier one brings it forward.
        item.accepted_at_ms = None;
        item.replay_until(9_000);
        assert_eq!(item.replay_until_ms, Some(1_000 + SENT_RETENTION_MS));
        item.replay_until(100);
        assert_eq!(item.replay_until_ms, Some(100 + SENT_RETENTION_MS));
    }

    #[test]
    fn test_sent_fit_carries_acceptances_first_then_the_newest_plaintexts() {
        // Every copy takes the same bytes: its time has the same number of digits.
        const AT: u64 = 1_000_000_000_000;
        let ns = crate::store::client_namespace(&[1; 16]);
        let copy = |n: u64, given_up_until_ms: Option<u64>| CarriedSent {
            record: SentStored {
                origin: DeliveryOrigin::Original,
                to: [3; 32],
                kind: "sample.note".into(),
                msg_id: format!("{n:020}"),
                plaintext: Some(SignedBytes(vec![7; 50_000])),
                first_ms: AT + n,
                resent: Vec::new(),
                replay_until_ms: None,
            },
            given_up_until_ms,
        };
        // The measure is what the restore's commit takes, give-up mark included.
        for (bare, until) in [(false, Some(AT)), (true, Some(AT)), (false, None)] {
            let mut measured = copy(0, until);
            if bare {
                measured.record.plaintext = None;
            }
            let mut tx = crate::app::state::Tx::new(&ns);
            measured.put(&mut tx).unwrap();
            assert_eq!(tx.size(), copy(0, until).commit_bytes(&ns, bare));
        }
        // At the edge: every acceptance that fits goes, and the next wouldn't.
        let each = copy(0, None).commit_bytes(&ns, true);
        let fits = MAX_CARRIED_SENT_BYTES / each;
        let fit = fit_sent((0..fits + 10).map(|n| copy(n, None)).collect(), &ns);
        assert_eq!(fit.left_out, 10);
        assert_eq!(u64::try_from(fit.records.len()).unwrap(), fits);
        let bytes: u64 = fit.records.iter().map(|c| c.commit_bytes(&ns, false)).sum();
        assert!(bytes <= MAX_CARRIED_SENT_BYTES && bytes + each > MAX_CARRIED_SENT_BYTES);
        // The oldest are left out, and no plaintext fits beside them all.
        assert!(fit.records.iter().all(|c| c.record.first_ms >= AT + 10));
        assert!(fit.records.iter().all(|c| c.record.plaintext.is_none()));
        // Within the bound, the newest keep their plaintext.
        let few = fit_sent((0..200).map(|n| copy(n, None)).collect(), &ns);
        assert_eq!(few.left_out, 0);
        let whole: Vec<u64> = few
            .records
            .iter()
            .filter(|c| c.record.plaintext.is_some())
            .map(|c| c.record.first_ms - AT)
            .collect();
        assert!(!whole.is_empty() && whole.len() < 200, "{}", whole.len());
        assert_eq!(
            whole.iter().min(),
            Some(&(200 - u64::try_from(whole.len()).unwrap()))
        );
    }
}
