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
//! again (Switch spec 7, Switch wire 3.8). A failed message is forgotten, plaintext and all,
//! after the retention of sent messages.

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
use super::events::AppEvent;
use super::records::{Collection, RecordTarget};
use super::state::key;
use super::{App, AppError};
use crate::client::answers::AppendAnswer;
use crate::error::ClientError;

/// How long a sent message is kept for re-sends: 30 days from its first acceptance (Switch
/// spec 11).
pub const SENT_RETENTION_MS: u64 = 30 * DAY_MS;

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
}

impl std::fmt::Debug for SentMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SentMessage({}, {})", self.kind, self.msg_id)
    }
}

/// Where a message is (Switch spec 11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// In the outbox, to be tried again.
    Queued {
        /// How many times it was tried.
        tries: u64,
        /// The last failure, without content.
        last_error: Option<String>,
    },
    /// The recipient's inbox accepted it: delivery is complete.
    Accepted {
        /// The acceptance time.
        accepted_at_ms: u64,
    },
    /// Refused for good.
    Failed {
        /// Why, without content.
        reason: String,
    },
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
struct OutboxItem {
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
}

impl std::fmt::Debug for OutboxItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OutboxItem({}, {})", self.kind, self.msg_id)
    }
}

impl OutboxItem {
    fn complete(&self) -> bool {
        self.accepted_at_ms.is_some() && !self.resend && (self.record.is_none() || self.record_done)
    }

    /// Whether a delivery is owed: never accepted, or a re-send asked since.
    fn delivery_owed(&self) -> bool {
        self.accepted_at_ms.is_none() || self.resend
    }

    fn plaintext(&self) -> Result<MessagePlaintext, AppError> {
        MessagePlaintext::decode(&self.plaintext).map_err(|_| store_corrupt())
    }
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

impl std::fmt::Debug for SentStored {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SentStored({}, {})", self.kind, self.msg_id)
    }
}

/// What one delivery try came to.
enum Tried {
    Accepted(AppendAnswer),
    Queued(String),
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
        let msg_id = self.queue(message).await?;
        self.flush_item(&msg_id).await?;
        let delivery = self
            .delivery(&msg_id)
            .await?
            .ok_or_else(|| AppError::InvalidData("the message left the outbox".into()))?;
        Ok((msg_id, delivery))
    }

    /// Sign `message` once and record it in the outbox, sending nothing. Returns its
    /// `msg_id`.
    ///
    /// # Errors
    ///
    /// As [`App::send`].
    pub async fn queue(&mut self, message: OutgoingMessage) -> Result<String, AppError> {
        self.ready_local().await?;
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
        let item = OutboxItem {
            to: message.to,
            kind: message.kind.clone(),
            msg_id: built.msg_id.clone(),
            plaintext: plaintext.encode(),
            notify: message.notify,
            invite_code: message.invite_code,
            conversation: message.to != me && self.protocol.adds_conversation(&message.kind),
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
        };
        let mut tx = self.tx()?;
        tx.put(&out_key(&item.msg_id), &item)?;
        self.commit(tx).await?;
        Ok(built.msg_id)
    }

    /// Send again a message sent in the last 30 days: the same signed plaintext, and so the
    /// same `msg_id`, sealed to the recipient's current keys (Switch spec 11). It adds no
    /// conversation entry and writes no record.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a message the app doesn't keep; as [`App::send`].
    pub async fn resend(&mut self, msg_id: &str) -> Result<Delivery, AppError> {
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

    /// Where the message `msg_id` is; `None` for one the app doesn't keep.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn delivery(&self, msg_id: &str) -> Result<Option<Delivery>, AppError> {
        if let Some(item) = self.reader().get::<OutboxItem>(&out_key(msg_id)).await? {
            return Ok(Some(match (&item.failed, item.accepted_at_ms) {
                (Some(reason), _) => Delivery::Failed {
                    reason: reason.clone(),
                },
                (None, Some(accepted_at_ms)) if !item.resend => {
                    Delivery::Accepted { accepted_at_ms }
                }
                (None, _) => Delivery::Queued {
                    tries: item.tries,
                    last_error: item.last_error.clone(),
                },
            }));
        }
        Ok(self
            .reader()
            .get::<SentStored>(&sent_key(msg_id))
            .await?
            .map(|sent| Delivery::Accepted {
                accepted_at_ms: sent.first_ms,
            }))
    }

    /// The messages sent to `pubky` that its inbox accepted within `[from_ms, until_ms]`,
    /// first acceptances and re-sends, for the protocol's answer to a re-send request
    /// (Switch spec 11).
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
                });
            }
        }
        Ok(out)
    }

    // ---------------------------------------------------------------------------------
    // Flushing

    /// Try every queued message's jobs once (Switch spec 11: on start, on returning to the
    /// foreground, when the network comes back), after the batches and deliveries of the
    /// own `identity.json` owed, and forget sent messages past their retention.
    ///
    /// # Errors
    ///
    /// A store failure, or an alarm. A message that can't be delivered now stays queued.
    pub async fn flush_outbox(&mut self) -> Result<OutboxReport, AppError> {
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
            self.flush_item(&msg_id).await?;
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
        Ok(report)
    }

    /// One try of each job of one message.
    async fn flush_item(&mut self, msg_id: &str) -> Result<(), AppError> {
        let Some(mut item) = self.reader().get::<OutboxItem>(&out_key(msg_id)).await? else {
            return Ok(());
        };
        if item.failed.is_some() {
            return Ok(());
        }
        item.tries = item.tries.saturating_add(1);
        if item.conversation {
            match self.conversation_entry(&item.to).await {
                Ok(()) => item.conversation = false,
                Err(error) if is_local(&error) => return Err(error),
                Err(error) => {
                    item.last_error = Some(error.to_string());
                    return self.save_item(&item).await;
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
        Ok(())
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
        let sent = SentMessage {
            to: item.to,
            kind: item.kind.clone(),
            msg_id: item.msg_id.clone(),
            plaintext: item.plaintext()?,
            accepted_at_ms: item.accepted_at_ms,
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
    matches!(error, AppError::Alarm(_) | AppError::Store(_))
}

/// A failed try: failed for good only when the switch refused it for good, the Retry column
/// of Switch spec 6.4 saying "No"; queued again for everything else (the network, `429`,
/// `503`, a refusal of the app's rules that may lift). `403 not_admitted` and `403
/// not_current` stay queued: admission changes when the counterparty adds a contact or an
/// invite (Switch spec 7), and a renewal makes a certificate current again (Switch wire
/// 3.8).
fn queued_or(error: AppError) -> Result<Tried, AppError> {
    match &error {
        AppError::Alarm(_) | AppError::Store(_) => Err(error),
        AppError::Switch(ClientError::Switch { code, .. })
            if code.retry() == Retry::No
                && !matches!(code, ErrorCode::NotAdmitted | ErrorCode::NotCurrent) =>
        {
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
            Ok(Tried::Queued(_))
        ));
        assert!(matches!(
            queued_or(switch(ErrorCode::NotCurrent)),
            Ok(Tried::Queued(_))
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
