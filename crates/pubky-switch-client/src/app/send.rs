//! Sending (Switch spec 7, 8.1, 8.2, 11; Switch wire 4.3, 5.1, 7.4.3, 7.4.5).
//!
//! A message is signed once and recorded in the durable outbox (`out/<msg_id>`) before
//! anything is sent, with its jobs: the conversation entry a first message to a
//! counterparty that isn't a contact needs (except the protocol's re-send kind), the
//! delivery, and the matching shared record write the protocol names. Each job is retried
//! until it completes, at every [`App::flush_outbox`]; every step commits before the next
//! one acts on the network:
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
//!    ([`super::Protocol::sent_record`]), compare-and-swap.
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

use pubky_switch_core::enc::{serde_b64, serde_b64_vec};
use pubky_switch_core::http::{ErrorCode, Retry};
use pubky_switch_core::message::{Message, MessagePlaintext, Sender};
use pubky_switch_core::ops::{AllowKind, OpKind};
use pubky_switch_core::records::DAY_MS;
use pubky_switch_core::scopes::Permission;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::admission::allow_key;
use super::batch::OpBatch;
use super::directory::Route;
use super::error::Refusal;
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

fn out_key(msg_id: &str) -> String {
    format!("{OUT_PREFIX}{msg_id}")
}

fn sent_key(msg_id: &str) -> String {
    format!("{SENT_PREFIX}{msg_id}")
}

fn sent_time_key(at: u64, msg_id: &str) -> String {
    format!("{SENT_TIME_PREFIX}{}/{msg_id}", key::num(at))
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
    /// The kind, `<protocol>.<name>`.
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
        /// When, app clock: when it was refused, or its batch dropped; when it was queued,
        /// for one an earlier build refused without keeping the time.
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

/// What a flush of the outbox did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
}

/// The envelope sealed for one try, and where.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Sealed {
    #[serde(with = "serde_b64_vec")]
    envelope: Vec<u8>,
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
    failed: Option<String>,
    last_error: Option<String>,
    tries: u64,
    queued_ms: u64,
    /// When it was refused for good, app clock: it is forgotten after the retention of sent
    /// messages.
    #[serde(default)]
    failed_ms: Option<u64>,
    /// An accepted message is to be sent again, sealed to the current keys (Switch spec 11).
    #[serde(default)]
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
    #[serde(default)]
    undeliverable_tries: u32,
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

    fn complete(&self) -> bool {
        self.accepted_at_ms.is_some() && !self.resend && (self.record.is_none() || self.record_done)
    }

    /// Whether a delivery is owed: never accepted, or a re-send asked since.
    pub(crate) fn delivery_owed(&self) -> bool {
        self.accepted_at_ms.is_none() || self.resend
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

    /// The item a restore puts back in place of this one once its backup is older than
    /// [`SENT_RETENTION_MS`]: the delivery owed is given up, as [`App::drop_undeliverable`]
    /// gives one up, and the protocol is told by the duty event returned. A message never
    /// accepted goes, plaintext and all; one accepted before stays while its record job is
    /// owed. `None` for nothing to put back.
    pub(crate) fn give_up_delivery(mut self) -> (Option<Self>, Duty) {
        let duty = Duty::MessageUndelivered {
            msg_id: self.msg_id.clone(),
            resend: self.accepted_at_ms.is_some(),
        };
        self.resend = false;
        self.sealed = None;
        self.clear_undeliverable();
        let kept = (self.accepted_at_ms.is_some() && !self.complete()).then_some(self);
        (kept, duty)
    }
}

/// The queued messages a backup carries (Switch spec 11, 12.4): every one in the outbox that
/// wasn't refused for good, as the outbox holds it, its signed plaintext and the envelope
/// sealed for its last try included, so a restore delivers it with the same `msg_id` and
/// bytes. That is a message never accepted, one with a re-send owed, and one whose record
/// job is owed. A refused one is left out: it holds nothing to deliver.
pub(crate) async fn carried_outbox(
    reader: &super::state::Reader,
) -> Result<Vec<OutboxItem>, AppError> {
    Ok(reader
        .scan::<OutboxItem>(OUT_PREFIX)
        .await?
        .into_iter()
        .map(|(_, item)| item)
        .filter(|item| item.failed.is_none())
        .collect())
}

/// `sent/<msg_id>`: a sent message, kept 30 days. Sensitive.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SentStored {
    #[serde(with = "serde_b64")]
    to: [u8; 32],
    kind: String,
    msg_id: String,
    #[serde(with = "serde_b64_vec")]
    plaintext: Vec<u8>,
    /// The first acceptance, from which retention runs.
    first_ms: u64,
    /// The acceptances of re-sends.
    resent: Vec<u64>,
}

impl SentStored {
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

/// Put a queued message in the outbox, in `tx`.
pub(crate) fn put_outbox_item(
    tx: &mut super::state::Tx,
    item: &OutboxItem,
) -> Result<(), AppError> {
    tx.put(&out_key(&item.msg_id), item)
}

/// What one delivery try came to.
enum Tried {
    Accepted(AppendAnswer),
    Queued(String),
    /// Queued after `403 not_admitted` or `403 not_current`, for a bounded time.
    Undeliverable(String, UndeliverableReason),
    Failed(String),
}

fn store_corrupt() -> AppError {
    AppError::Store(crate::error::StoreError::Corrupt)
}

impl App {
    // ---------------------------------------------------------------------------------
    // Queueing

    /// Sign `message` once, record it in the outbox with its jobs, then try them (module
    /// docs). Returns the `msg_id` and where the message is.
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
            conversation: message.to != me && self.protocol.adds_conversation(&message.kind),
            kind: message.kind,
            msg_id: built.msg_id,
            plaintext,
            notify: message.notify,
            invite_code: message.invite_code,
            record: message.record,
        })
    }

    /// Record a message signed by [`App::sign_message`] in the outbox, with its jobs,
    /// sending nothing. Returns its `msg_id`. A message already in the outbox, or sent, is
    /// left as it is.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`]; [`Refusal::Usage`] for a message another
    /// app signed; a store failure.
    pub async fn queue_signed(&mut self, message: SignedMessage) -> Result<String, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let item = self.outbox_item(&message)?;
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
            failed_ms: None,
            resend: false,
            undeliverable_ms: None,
            undeliverable_reason: None,
            undeliverable_last_ms: None,
            undeliverable_tries: 0,
        })
    }

    /// Try the jobs of the queued message `msg_id` once, as [`App::flush_outbox`] does for
    /// every message, and return where it is; `None` for one the app doesn't keep.
    ///
    /// # Errors
    ///
    /// As [`App::flush_outbox`].
    pub async fn flush_message(&mut self, msg_id: &str) -> Result<Option<Delivery>, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            match self.resume_batches().await {
                Err(error) if is_local(&error) => return Err(error),
                _ => {}
            }
            self.flush_item(msg_id).await?;
            self.delivery(msg_id).await
        })
        .await
    }

    /// Send again a message sent in the last 30 days: the same signed plaintext, and so the
    /// same `msg_id`, sealed to the recipient's current keys (Switch spec 11). It adds no
    /// conversation entry and writes no record.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a message the app doesn't keep; as [`App::send`].
    pub async fn resend(&mut self, msg_id: &str) -> Result<Delivery, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            if !self.ask_resend_of_queued(msg_id).await? {
                let sent: SentStored =
                    self.reader().get(&sent_key(msg_id)).await?.ok_or_else(|| {
                        AppError::Refused(Refusal::Usage("no sent message with this msg_id".into()))
                    })?;
                self.queue_resend(&sent).await?;
            }
            self.flush_item(msg_id).await?;
            self.delivery(msg_id)
                .await?
                .ok_or_else(|| AppError::InvalidData("the message left the outbox".into()))
        })
        .await
    }

    /// A message still in the outbox: one already accepted, whose other jobs are owed, is
    /// marked to be sealed and sent again. Returns whether it is in the outbox.
    async fn ask_resend_of_queued(&mut self, msg_id: &str) -> Result<bool, AppError> {
        let Some(mut item) = self.reader().get::<OutboxItem>(&out_key(msg_id)).await? else {
            return Ok(false);
        };
        if item.accepted_at_ms.is_some() && !item.resend {
            item.resend = true;
            item.sealed = None;
            self.save_item(&item).await?;
        }
        Ok(true)
    }

    async fn queue_resend(&mut self, sent: &SentStored) -> Result<(), AppError> {
        let item = OutboxItem {
            to: sent.to,
            kind: sent.kind.clone(),
            msg_id: sent.msg_id.clone(),
            plaintext: sent.plaintext.clone(),
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
            failed_ms: None,
            resend: false,
            undeliverable_ms: None,
            undeliverable_reason: None,
            undeliverable_last_ms: None,
            undeliverable_tries: 0,
        };
        let mut tx = self.tx()?;
        tx.put(&out_key(&item.msg_id), &item)?;
        self.commit(tx).await
    }

    /// Send again what `pubky`'s old switch accepted since `since_ms` (app clock of the
    /// previous check), after a provider loss (Switch spec 8.1).
    pub(crate) async fn resend_since(
        &mut self,
        pubky: &[u8; 32],
        since_ms: u64,
    ) -> Result<(), AppError> {
        let mut queued = 0u64;
        for (_, sent) in self.reader().scan::<SentStored>(SENT_PREFIX).await? {
            let last = sent
                .resent
                .iter()
                .copied()
                .max()
                .unwrap_or(sent.first_ms)
                .max(sent.first_ms);
            if sent.to != *pubky || last < since_ms {
                continue;
            }
            // One whose record job is still owed is in the outbox: marked to go again.
            if !self.ask_resend_of_queued(&sent.msg_id).await? {
                self.queue_resend(&sent).await?;
            }
            queued = queued.saturating_add(1);
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
    /// one the app doesn't keep.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn delivery(&self, msg_id: &str) -> Result<Option<Delivery>, AppError> {
        if let Some(item) = self.reader().get::<OutboxItem>(&out_key(msg_id)).await? {
            return Ok(Some(match (&item.failed, item.accepted_at_ms) {
                (Some(reason), _) => Delivery::Failed {
                    reason: reason.clone(),
                    failed_at_ms: item.failed_ms.unwrap_or(item.queued_ms),
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
        if let Some(sent) = self.reader().get::<SentStored>(&sent_key(msg_id)).await? {
            return Ok(Some(Delivery::Accepted {
                accepted_at_ms: sent.first_ms,
            }));
        }
        self.kept_delivery(msg_id).await
    }

    /// The messages sent to `pubky` that its inbox accepted within `[from_ms, until_ms]`,
    /// first acceptances and re-sends, for the protocol's answer to a re-send request
    /// (Switch spec 11). Each carries every acceptance time the app kept
    /// ([`SentMessage::accepted_times_ms`]).
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
        for (_, sent) in self.reader().scan::<SentStored>(SENT_PREFIX).await? {
            let within = std::iter::once(sent.first_ms)
                .chain(sent.resent.iter().copied())
                .any(|at| at >= from_ms && at <= until_ms);
            if sent.to == *pubky && within {
                out.push(SentMessage {
                    to: sent.to,
                    kind: sent.kind.clone(),
                    msg_id: sent.msg_id.clone(),
                    plaintext: MessagePlaintext::decode(&sent.plaintext)
                        .map_err(|_| store_corrupt())?,
                    accepted_at_ms: Some(sent.first_ms),
                    resent_at_ms: sent.resent_ascending(),
                });
            }
        }
        Ok(out)
    }

    // ---------------------------------------------------------------------------------
    // Flushing

    /// Try every queued message's jobs once (Switch spec 11: on start, on returning to the
    /// foreground, when the network comes back), after the batches and deliveries of the
    /// own `identity.json` owed, and forget sent messages past their retention, and the ends
    /// of kept batches past theirs ([`super::App::kept_batch`]).
    ///
    /// # Errors
    ///
    /// A store failure, or an alarm. A message that can't be delivered now stays queued.
    pub async fn flush_outbox(&mut self) -> Result<OutboxReport, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            // A kept batch that can't be sent now holds up no delivery: it is sent again by the
            // next call that writes.
            match self.resume_batches().await {
                Err(error) if is_local(&error) => return Err(error),
                _ => {}
            }
            self.deliver_to_recent_peers().await?;
            let mut items = self.reader().scan::<OutboxItem>(OUT_PREFIX).await?;
            items.sort_by_key(|(_, item)| item.queued_ms);
            let mut report = OutboxReport::default();
            let cutoff = self.now().saturating_sub(SENT_RETENTION_MS);
            for (msg_id, item) in items {
                if item.failed.is_some() {
                    // Forgotten, plaintext and all, after the retention of sent messages.
                    if item.failed_ms.unwrap_or(item.queued_ms) <= cutoff {
                        let mut tx = self.tx()?;
                        tx.delete(&out_key(&msg_id))?;
                        self.commit(tx).await?;
                    } else {
                        report.failed.push(msg_id);
                    }
                    continue;
                }
                if self.flush_item(&msg_id).await? {
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
        let Some(mut item) = self.reader().get::<OutboxItem>(&out_key(msg_id)).await? else {
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
            self.keep_duty(
                &mut tx,
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

    async fn try_item(&mut self, msg_id: &str) -> Result<bool, AppError> {
        let Some(mut item) = self.reader().get::<OutboxItem>(&out_key(msg_id)).await? else {
            return Ok(false);
        };
        if item.failed.is_some() {
            return Ok(false);
        }
        // Past the firm bound, the message goes before it is tried again.
        if item
            .undeliverable_ms
            .is_some_and(|since| self.now().saturating_sub(since) >= UNDELIVERABLE_MAX_MS)
            && self.drop_undeliverable(&mut item).await?
        {
            return Ok(true);
        }
        item.tries = item.tries.saturating_add(1);
        if item.conversation {
            match self.conversation_entry(&item.to).await {
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
        if item.delivery_owed() {
            match self.deliver(&mut item).await? {
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
                    item.failed = Some(why);
                    item.failed_ms = Some(self.now());
                    self.save_item(&item).await?;
                }
            }
        }
        if item.accepted_at_ms.is_some()
            && !item.record_done
            && let Some(job) = item.record.clone()
        {
            match self.record_job(&item, &job).await {
                Ok(()) => item.record_done = true,
                Err(error) if is_local(&error) => return Err(error),
                Err(error) => item.last_error = Some(error.to_string()),
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
        // A duty event, kept in the commit that gives the delivery up.
        self.keep_duty(
            &mut tx,
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
        let sent = match self
            .reader()
            .get::<SentStored>(&sent_key(&item.msg_id))
            .await?
        {
            Some(mut sent) => {
                if at != sent.first_ms && !sent.resent.contains(&at) {
                    sent.resent.push(at);
                }
                sent
            }
            None => {
                tx.put(&sent_time_key(first, &item.msg_id), &())?;
                SentStored {
                    to: item.to,
                    kind: item.kind.clone(),
                    msg_id: item.msg_id.clone(),
                    plaintext: item.plaintext.clone(),
                    first_ms: first,
                    resent: if at == first { Vec::new() } else { vec![at] },
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

    /// A complete item leaves the outbox; its sent message is kept from its acceptance.
    async fn finish_item(&mut self, item: &OutboxItem) -> Result<(), AppError> {
        let mut tx = self.tx()?;
        tx.delete(&out_key(&item.msg_id))?;
        self.commit(tx).await
    }

    /// Forget sent messages 30 days after their first acceptance, oldest first.
    async fn prune_sent(&mut self) -> Result<(), AppError> {
        let cutoff = self.now().saturating_sub(SENT_RETENTION_MS);
        let mut tx = self.tx()?;
        for (rest, ()) in self.reader().scan::<()>(SENT_TIME_PREFIX).await? {
            let Some((at, msg_id)) = rest.split_once('/') else {
                continue;
            };
            let Ok(at) = super::state::parse_num(at) else {
                continue;
            };
            if at > cutoff {
                break;
            }
            tx.delete(&sent_key(msg_id))?;
            tx.delete(&sent_time_key(at, msg_id))?;
        }
        if !tx.is_empty() {
            self.commit(tx).await?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // The jobs

    /// The conversation entry for `pubky`, unless the app knows it holds one, or a contact
    /// (Switch spec 7). An app whose certificate lacks `conversation.add` can't write one.
    async fn conversation_entry(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        let reader = self.reader();
        if reader
            .exists(&allow_key(AllowKind::Conversation, pubky))
            .await?
            || reader.exists(&allow_key(AllowKind::Contact, pubky)).await?
            || !self.state.cert.has_permission(Permission::ConversationAdd)
        {
            return Ok(());
        }
        self.submit_batch(OpBatch::new().op(OpKind::AllowPut {
            pubky: *pubky,
            kind: AllowKind::Conversation,
        }))
        .await?;
        Ok(())
    }

    /// One delivery try (module docs, steps 2 to 4).
    async fn deliver(&mut self, item: &mut OutboxItem) -> Result<Tried, AppError> {
        let to = item.to;
        let own = to == self.state.meta.identity;
        let invite = item.invite_code.clone();
        let doc = match self.peer_identity(&to, false).await {
            Ok(doc) => doc,
            Err(error) => return queued_or(error),
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
            return queued_or(error);
        }
        if item.sealed.is_none()
            && let Err(error) = self.seal(item, invite.as_deref()).await
        {
            return queued_or(error);
        }
        let mut resealed = 0usize;
        let mut redelivered = false;
        loop {
            let Some(sealed) = item.sealed.clone() else {
                return Ok(Tried::Queued("not sealed".into()));
            };
            let result = if own {
                let result = self
                    .client
                    .append(sealed.envelope.clone(), sealed.apps_version, None)
                    .await;
                self.take(result).await
            } else {
                let client = self.peer_client(&to, &doc)?;
                client
                    .append(
                        sealed.envelope.clone(),
                        sealed.apps_version,
                        invite.as_deref(),
                    )
                    .await
                    .map_err(AppError::from)
            };
            match result {
                Ok(answer) => return Ok(Tried::Accepted(answer)),
                Err(AppError::Switch(ClientError::Switch {
                    code: ErrorCode::StaleKey,
                    current,
                    ..
                })) if resealed < RESEALS => {
                    resealed = resealed.saturating_add(1);
                    self.take_stale_key(&to, &current).await?;
                    if let Err(error) = self.seal(item, invite.as_deref()).await {
                        return queued_or(error);
                    }
                }
                Err(AppError::Switch(ClientError::Switch {
                    code: ErrorCode::IdentityNeeded,
                    ..
                })) if !redelivered && !own => {
                    redelivered = true;
                    if let Err(error) = self
                        .deliver_own_identity(&to, invite.as_deref(), true)
                        .await
                    {
                        return queued_or(error);
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
                    return Ok(Tried::Queued("moved".into()));
                }
                Err(error) => return queued_or(error),
            }
        }
    }

    /// Seal the item's signed plaintext to the recipient apps, and commit the envelope
    /// before it is sent.
    async fn seal(&mut self, item: &mut OutboxItem, invite: Option<&str>) -> Result<(), AppError> {
        let plaintext = item.plaintext()?;
        let rules = self.protocol.opaque_members();
        let opaque: Vec<pubky_switch_core::json::OpaqueMember<'_>> = rules
            .iter()
            .map(|rule| pubky_switch_core::json::OpaqueMember {
                kind: rule.kind.as_deref(),
                member: rule.member.as_str(),
            })
            .collect();
        let message = Message::parse(plaintext.json(), &opaque)?;
        let (routes, apps_version) = self.routes(&item.to, &message, invite).await?;
        let recipients: Vec<_> = routes.iter().map(|r: &Route| r.recipient).collect();
        let envelope = plaintext.seal(&item.to, &recipients, item.notify)?;
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
        let kept = self
            .reader()
            .get::<SentStored>(&sent_key(&item.msg_id))
            .await?;
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
        let protocol = std::sync::Arc::clone(&self.protocol);
        self.update_record(&job.target, Vec::new(), |current| {
            protocol.sent_record(&job, &sent, current)
        })
        .await?;
        Ok(())
    }
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
}
