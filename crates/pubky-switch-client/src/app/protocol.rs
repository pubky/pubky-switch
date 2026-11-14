//! The protocol an app is built with: the [`Protocol`] trait.
//!
//! The Switch knows no protocol (Switch spec 1): scopes, message kinds and collections are
//! opaque strings to it. A protocol on the Switch supplies what the app layer can't know:
//! the opaque members of its message bodies, which of its scopes have keys, its kind rules
//! for the recipient checks 6 and 8 (Switch wire 5.1), and what a received message does.
//!
//! The trait is object-safe and takes and returns plain owned types, so a binding can
//! implement it across a language boundary.
//!
//! - **Receiving** ([`Protocol::check_body`], then [`Protocol::receive_with`], or
//!   [`Protocol::receive`] for a protocol that needs nothing of the app's state): the app
//!   hands over each message that passed checks 1 to 9. The protocol checks the body (check
//!   10) on its own, without effects, which is also what a push extension's peek runs; for a
//!   body that passes, it adds, through the [`ReceiveContext`], the shared record writes and
//!   claim entries the app builds and signs for it, all committed in the same batch as the
//!   cursor move, and the writes of its own local state to commit with the outcome (Switch
//!   spec 8.2: "writes the effect to its shared record and advances its cursor in one
//!   batch").
//! - **Re-sends** ([`Protocol::resend_needed`], [`Protocol::missed`]): the kind that asks a
//!   counterparty to send again is a protocol's (Switch spec 11), so the app hands over
//!   what it needs and the protocol queues its request with the local writes it returns.
//!   A protocol that can't read its own state for it says so with a [`StoreFailure`]: the app
//!   keeps what it handed over and hands it over again later, so nothing is lost to a
//!   default.
//! - **Deny list changes** ([`Protocol::deny_list_changed`]): each one the feed shows, in
//!   feed order, with the local writes the protocol returns to keep it, held back and
//!   handed over again as re-sends are, and in the same order (Switch spec 8.3).
//!
//! The protocol's local state lives in the app's namespace under [`LocalWrite`] keys, which
//! the app keeps apart from its own (`STATE.md`).

use pubky_switch_core::json::OpaqueMember;
use pubky_switch_core::message::{Message, MessagePlaintext};
use pubky_switch_core::ops::{Condition, OpKind, RecordVersion};
use pubky_switch_core::receive::KindRules;
use pubky_switch_core::records::{AppCert, AppRecord, Standing};
use serde_json::Value;

use super::context::{LocalView, ReceiveContext, RestoreContext};
use super::error::AppError;
use super::records::Collection;
use super::recovery::{LossActions, ProviderLoss};
use super::send::{RecordJob, SentMessage};
use crate::error::StoreError;
use crate::store::KeyValue;

/// What a newer write of a record builds on, as the reading app sees it
/// ([`Protocol::record_regression_on`], Switch spec 8.2, 10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriteBase {
    /// The version the write builds on: the `expected_version` its operation signed,
    /// `{0, 0}` for a create.
    pub expected_version: RecordVersion,
    /// Whether the app holds that version: the write it holds of the record is at
    /// `expected_version`, or, for a create (`{0, 0}`), it holds none or holds the record
    /// deleted, as a writer that holds a deleted record creates it again (Switch wire 6.2).
    /// `false` when the write builds on a version the app never took, such as one it skipped
    /// by reading the record's current view, or on a write it refused and only follows. The
    /// held version is the one the app holds, authenticated by a proof or a stub or only the
    /// record view's word, and whether its value opened doesn't count: a write held not
    /// open ([`super::RecordContent::Unreadable`]) is held at its version.
    pub held: bool,
    /// The conditions the write's operation signed (Switch wire 6.3), in its order, such as
    /// a `claim_step` on a claim its change depends on. The service checked them when it
    /// applied the write; a protocol's reader rule may require one, such as a condition on
    /// the claim of what the write drops, and flag a write without it (Switch spec 8.2).
    pub conditions: Vec<Condition>,
}

/// An opaque member of a protocol's message bodies (Switch wire 1.1): its numbers aren't
/// checked against the integer range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueRule {
    /// The kind the rule applies to, or `None` for every kind.
    pub kind: Option<String>,
    /// The member of `body`.
    pub member: String,
}

/// A message that passed the recipient checks 1 to 9 (Switch wire 5.1), handed to the
/// protocol for check 10 ([`Protocol::check_body`]) and its effect ([`Protocol::receive`]).
#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    /// The `seq` the entry was read at: in the current generation for an entry of the
    /// feed, and for one stored locally (`parked`) in the generation it was read at, which
    /// a provider change since may have left behind. A stored entry's handle is its local
    /// ID ([`super::AppEvent::Parked`]), not this `seq`.
    pub seq: u64,
    /// The sender identity.
    pub sender: [u8; 32],
    /// When the inbox accepted it, service time in Unix milliseconds.
    pub accepted_at_ms: u64,
    /// The message's common fields and body.
    pub message: Message,
    /// The signed plaintext, kept for verifiable copies (Switch spec 8.2).
    pub plaintext: MessagePlaintext,
    /// The sender's certificate, verified.
    pub cert: AppCert,
    /// The sender app's standing when the message was accepted.
    pub standing: Standing,
    /// The invite code's context, if one admitted the entry; opaque.
    pub context: Option<Value>,
    /// Whether the entry was stored locally before and the cursor is past it already.
    pub parked: bool,
    /// Whether the host released the entry ([`super::App::release_parked`]) after its
    /// effect was uncertain ([`super::AppEvent::EffectUncertain`]): the app no longer counts
    /// it processed, and builds its effect again. The host releases it only once it knows
    /// the effect wasn't applied; a protocol that may have compensated from its own state
    /// since, or can't tell, declines with [`Outcome::Drop`], which keeps the message
    /// processed.
    ///
    /// The service refuses an effect run again this way where an operation depends on what
    /// its first application changed, such as a record write's expected version or a
    /// claim's step, and it checks conditions for the whole batch (Switch spec 8.2, 10.1);
    /// otherwise its operations, and its local writes, may apply twice.
    pub released: bool,
    /// After a `409 conflict` on the effect's batch: the answer's `current`, so the
    /// protocol builds its effect again on what the service holds now.
    pub conflict: Option<Value>,
}

/// The most bytes of local writes a protocol or host hands over at once: one receive step,
/// one [`Protocol::resend_needed`], [`Protocol::missed`] or [`Protocol::deny_list_changed`]
/// answer, or one
/// [`super::OpBatch`]'s local writes ([`Protocol`], "Limits a receive step plans for").
/// 4 MiB, counted by [`local_writes_bytes`].
///
/// It is chosen so that whatever the app keeps or commits with such writes fits the store
/// ([`crate::store::MAX_VALUE_BYTES`] 16 MiB per value, [`crate::store::MAX_BATCH_BYTES`]
/// 32 MiB per commit):
///
/// - **Kept, in base64:** each write is kept as `{"Put":{"key":"…","value":"…"}},`, its
///   key and value in base64url, at most `4/3 (k + v) + 40` bytes, which is under
///   `4/3 (k + v + 64)` since 4/3 x 64 > 40. So writes at the bound keep in at most
///   4/3 x 4 MiB = 5.34 MiB.
/// - **A kept effect** (`pending/effect`) adds its batch, at most the 4 MiB `POST /ops`
///   body (Switch wire 7.1), 5.34 MiB in base64, and its entry: the plaintext (at most the
///   64 KiB envelope, 87 KiB in base64), the certificate (under 33 KiB) and a context (1
///   KiB), with under 8 KiB of other fields: under 10.9 MiB, below the 16 MiB value size.
///   A kept batch (`opq/`) carries the same body and writes, and the messages it queues.
/// - **Committed:** each write takes its key and value, the namespace (at most 33 bytes)
///   and the `p/` prefix, under `k + v + 64`: at most 4 MiB. An applied effect's outcome
///   adds at most 7 cached record writes (each under 1.2 MiB with its proof and opened
///   value), under 13 MiB in all, below the 32 MiB batch size.
pub const MAX_STEP_LOCAL_BYTES: usize = 4 * 1024 * 1024;

/// The most bytes a [`Protocol::record_seen`] mark takes: 64 KiB, 85.6 KiB as stored in
/// base64 with its key. The commits that keep marks stay within the 32 MiB batch size: a
/// feed item or a listed record caches at most one record write with its mark (1.2 MiB
/// and 85.6 KiB, within a read's 12 MiB room for one item); an applied effect's outcome at
/// most 7, with its 4 MiB of local writes and what its entry writes (256 KiB): 4 MiB + 7 x
/// (1.2 MiB + 85.6 KiB) + 256 KiB = 13.2 MiB; and a batch's answer at most 8, with what the
/// batch kept (under 12 MiB) and 1 MiB more: 12 MiB + 8 x (1.2 MiB + 85.6 KiB) + 1 MiB =
/// 23.3 MiB. The `const` assertions of `feed.rs`, `records.rs` and `batch.rs` check each.
pub const MAX_SEEN_MARK_BYTES: usize = 64 * 1024;

/// The most bytes a [`Protocol::record_regression`] rule takes: 256. A longer one is cut
/// there.
pub const MAX_REGRESSION_REASON_BYTES: usize = 256;

/// The most counterparties a [`LossActions::conversations`](super::LossActions) list takes:
/// 100,000, the `max_conversations` a service keeps at its default limits (Switch wire
/// 9.2). The app adds back the first this many, in key order, and no more.
pub const MAX_LOSS_CONVERSATIONS: usize = 100_000;

/// What each write counts against [`MAX_STEP_LOCAL_BYTES`] beside its key and value: the
/// room its stored and kept forms take around them.
pub const LOCAL_WRITE_OVERHEAD_BYTES: usize = 64;

/// The bytes `writes` count against [`MAX_STEP_LOCAL_BYTES`]: for each write, the raw
/// length of its key (a prefix for [`LocalWrite::DeletePrefix`]) and of its value, plus
/// [`LOCAL_WRITE_OVERHEAD_BYTES`].
pub fn local_writes_bytes(writes: &[LocalWrite]) -> usize {
    writes.iter().fold(0usize, |total, write| {
        let bytes = match write {
            LocalWrite::Put { key, value } => key.len().saturating_add(value.len()),
            LocalWrite::Delete { key } => key.len(),
            LocalWrite::DeletePrefix { prefix } => prefix.len(),
        };
        total.saturating_add(bytes.saturating_add(LOCAL_WRITE_OVERHEAD_BYTES))
    })
}

/// A write of the protocol's own local state, under keys the app prefixes so they never
/// meet its own (`STATE.md`).
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LocalWrite {
    /// Set `key` to `value`.
    Put {
        /// The key, in the protocol's key space.
        key: Vec<u8>,
        /// The value.
        value: Vec<u8>,
    },
    /// Remove `key`.
    Delete {
        /// The key, in the protocol's key space.
        key: Vec<u8>,
    },
    /// Remove every key starting with `prefix`.
    DeletePrefix {
        /// The prefix, in the protocol's key space.
        prefix: Vec<u8>,
    },
}

impl std::fmt::Debug for LocalWrite {
    // Values may hold message content: only sizes are shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalWrite::Put { key, value } => {
                write!(
                    f,
                    "Put({} key bytes, {} value bytes)",
                    key.len(),
                    value.len()
                )
            }
            LocalWrite::Delete { key } => write!(f, "Delete({} key bytes)", key.len()),
            LocalWrite::DeletePrefix { prefix } => {
                write!(f, "DeletePrefix({} prefix bytes)", prefix.len())
            }
        }
    }
}

/// The protocol's layer of an app backup (Switch spec 12.4): its own local state, such as
/// its journal, in a form it chooses ([`Protocol::backup_layer`]), carried in the
/// [`super::AppBackup`] ([`super::App::backup_layered`]) and installed by
/// [`super::App::restore`] in
/// the same commit as the app's own state ([`Protocol::restore_layer`]). Opaque to the app.
/// Sensitive: its `Debug` shows only the protocol's name and the data's size.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtocolLayer {
    /// The protocol that made it, as its [`Protocol::backup_name`] gives it: a restore takes
    /// the layer only with a protocol of that name.
    pub protocol: String,
    /// The protocol's data.
    pub data: Vec<u8>,
}

impl std::fmt::Debug for ProtocolLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ProtocolLayer({}, {} bytes)",
            self.protocol,
            self.data.len()
        )
    }
}

/// A protocol's local state as the default [`Protocol::backup_layer`] writes it: each key
/// and value length-prefixed, in order.
pub fn encode_local_state(state: &[KeyValue]) -> Vec<u8> {
    let parts: Vec<&[u8]> = state
        .iter()
        .flat_map(|(key, value)| [key.as_slice(), value.as_slice()])
        .collect();
    pubky_switch_core::enc::lp(&parts)
}

/// The local state [`encode_local_state`] wrote, or `None` for bytes it didn't write.
pub fn decode_local_state(bytes: &[u8]) -> Option<Vec<KeyValue>> {
    let parts = pubky_switch_core::enc::split_lp(bytes)?;
    if parts.len() % 2 != 0 {
        return None;
    }
    let mut parts = parts.into_iter();
    let mut state = Vec::new();
    while let (Some(key), Some(value)) = (parts.next(), parts.next()) {
        state.push((key, value));
    }
    Some(state)
}

/// What a received message does: the operations committed in one batch with the cursor
/// move, and the protocol's local writes committed with the outcome. The writes added
/// through the [`ReceiveContext`] come first, then these.
#[derive(Clone, Debug, Default)]
pub struct Effect {
    /// Signed by the app and sent in one batch with the cursor move, after the context's:
    /// at most 7 in all, the cursor taking the eighth entry (Switch wire 6.4). Empty, with
    /// nothing added through the context, when the message has no lasting effect, or another
    /// own app applied it already: only the cursor moves.
    pub ops: Vec<(Vec<Condition>, OpKind)>,
    /// The protocol's local writes, committed once the batch is answered, with the
    /// processed pair and the cursor.
    pub local: Vec<LocalWrite>,
}

/// The most claims the app reads from the switch for one entry's receive step
/// ([`Outcome::Need`]), over all its calls: a step that asks for more is stored locally and
/// passed ([`super::ParkReason::TooManyReads`]).
pub const MAX_CLAIM_READS: usize = 4;

/// What a receive step needs read from the switch before it can build its effect
/// ([`Outcome::Need`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Need {
    /// The claim of this key, as `GET /claims/{claim_key}` gives it (Switch wire 7.4.8),
    /// checked as [`super::App::read_claim`] checks it. Its view is kept, so the context's
    /// [`ReceiveContext::claim_view`] and [`ReceiveContext::claim_condition`] show it, and
    /// the answer itself is in [`ReceiveContext::switch_claim`].
    Claim([u8; 32]),
}

/// The reads of the feed in a row, each ending in [`Outcome::Retry`] at one held entry,
/// after which the app raises [`super::AppEvent::StoreFailing`] for it, on that read and
/// every later one until the entry is processed or stored locally.
pub const RETRY_EVENT_READS: u32 = 3;

/// The most entries stored locally that one read tries again: the next read goes on after
/// the last one tried, in `seq` order and round again, so each is reached in turn.
pub const PARKED_RETRIES_PER_READ: usize = 16;

/// A failure of the store or the host that kept a receive step from finishing
/// ([`Outcome::Retry`]). It is built only from a [`StoreError`]: what the host's
/// [`crate::store::StateStore`] answers, through the [`ReceiveContext`]'s or a
/// [`LocalView`]'s reads or a store handle of the protocol's own, or what a binding maps
/// its own host's storage failure to. A protocol never builds one for a message it can't
/// handle: that is an [`Outcome::Drop`].
///
/// It is of one of two kinds, which decide how long the entry waits:
///
/// - **The store is unavailable for now** ([`StoreFailure::unavailable`]): the entry is
///   held, up to the bounded wait an entry whose sender can't be checked gets
///   ([`super::AppConfig::park_after_ms`]), then stored locally and passed
///   ([`super::ParkReason::StoreUnavailable`]).
/// - **The store fails for this entry** ([`StoreFailure::of_entry`]), whatever the time,
///   such as a corrupt value it holds or a write it refuses: retrying on the feed can't
///   help, so the entry is stored locally and passed at once
///   ([`super::ParkReason::StoreRejected`]).
///
/// Either way the entry is never dropped: an entry stored locally is tried again at every
/// read, and processed once the store works.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreFailure {
    error: StoreError,
    of_entry: bool,
}

impl StoreFailure {
    /// The store, or the host, is unavailable for now, and may work at a later read.
    pub fn unavailable(error: StoreError) -> Self {
        Self {
            error,
            of_entry: false,
        }
    }

    /// The store fails for this entry every time, such as a corrupt value it holds or a
    /// write of the entry's state it refuses.
    pub fn of_entry(error: StoreError) -> Self {
        Self {
            error,
            of_entry: true,
        }
    }

    /// The store's error.
    pub fn error(&self) -> &StoreError {
        &self.error
    }

    /// Whether the store fails for this entry every time ([`StoreFailure::of_entry`]),
    /// rather than for now.
    pub fn is_of_entry(&self) -> bool {
        self.of_entry
    }
}

impl From<StoreError> for StoreFailure {
    /// [`StoreError::Corrupt`] and [`StoreError::TooLarge`] fail for the entry
    /// ([`StoreFailure::of_entry`]), the same every time; every other error is the store
    /// unavailable for now ([`StoreFailure::unavailable`]), bounded by the wait.
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Corrupt | StoreError::TooLarge { .. } => Self::of_entry(error),
            error => Self::unavailable(error),
        }
    }
}

impl TryFrom<AppError> for StoreFailure {
    /// Any other error, given back: it isn't a failure of the store.
    type Error = AppError;

    /// The failure of an [`AppError::Store`], such as a [`ReceiveContext::local_get`] whose
    /// store failed, of the kind [`StoreFailure::from`] gives it; any other error is given
    /// back.
    fn try_from(error: AppError) -> Result<Self, AppError> {
        match error {
            AppError::Store(error) => Ok(error.into()),
            other => Err(other),
        }
    }
}

impl std::fmt::Display for StoreFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

/// The protocol's answer for a received message. Later versions may add answers: a host
/// that matches on it keeps a catch-all arm.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Outcome {
    /// Apply the effect.
    Apply(Effect),
    /// A rule the protocol states for the kind fails (Switch wire 5.1 check 10), one that
    /// [`Protocol::check_body`] couldn't judge: the entry is dropped, kept as processed, and
    /// the cursor moves past it.
    Drop {
        /// The rule, without content.
        reason: String,
    },
    /// The step needs these read from the switch first, such as the claim a message gives
    /// evidence for when the app keeps no view of it (Switch spec 10.2). What the context
    /// added is discarded; the app reads them, then calls [`Protocol::receive_with`] again
    /// with them in the context. Reads are bounded: every call for one entry together reads
    /// at most [`MAX_CLAIM_READS`] claims, and a `Need` that names nothing new or goes past
    /// the bound stores the entry locally and passes it
    /// ([`super::ParkReason::TooManyReads`]). A read that fails for now (the network, `429`,
    /// `503`) leaves the entry waiting for the next read of the feed.
    Need(Vec<Need>),
    /// The step couldn't finish because the protocol's store or the host failed, such as a
    /// read of its own state: never for a message the protocol can't handle, which is an
    /// [`Outcome::Drop`]. A valid message is never consumed by a store failure (Switch spec
    /// 8.2): the app keeps no processed pair for the entry and commits nothing the step
    /// built (what the context added is discarded). What happens to the entry depends on
    /// the [`StoreFailure`]'s kind:
    ///
    /// - **Unavailable for now:** the entry is held, as an entry whose sender can't be
    ///   checked yet is. The cursor stays before it; the read goes on with later items, which
    ///   are processed past it and remembered; the entry comes again at the next read of the
    ///   feed, never twice in one read, and the step runs again from the start. The app
    ///   counts the reads in a row that end so, in its own store; from the
    ///   [`RETRY_EVENT_READS`]th on it raises [`super::AppEvent::StoreFailing`] on each, so
    ///   the host learns its store is failing. Once the entry has waited the bounded wait
    ///   ([`super::AppConfig::park_after_ms`]) since its first retry, it is stored locally
    ///   and the cursor passes it ([`super::ParkReason::StoreUnavailable`]), so a store
    ///   that stays down never pins the cursor.
    /// - **Of the entry:** retrying on the feed can't help, so the entry is stored locally
    ///   and the cursor passes it at once ([`super::ParkReason::StoreRejected`]).
    ///
    /// An entry stored locally is tried again at every read, and processed once its step
    /// finishes. A retry of an entry stored locally before ([`ReceivedMessage::parked`])
    /// leaves it stored, for the next read, and counts on: the count of reads in a row is
    /// kept from the feed into local storage until the entry is processed, so a store that
    /// stays down raises [`super::AppEvent::StoreFailing`] whichever way the entry waits. Claims read for the step ([`Outcome::Need`])
    /// stay kept, in their own commits. A push extension's peek runs no receive step, so a
    /// retry doesn't change what it shows.
    Retry(StoreFailure),
    /// Passed, not processed: the protocol can't take the message now, such as a reply its
    /// own store bounds out, and wants a later re-send of it delivered again. The cursor
    /// moves past the entry as past a processed one, but no processed pair is kept (Switch
    /// spec 11), so a re-send of the same `msg_id` comes to the protocol as a new entry, not
    /// as a duplicate. What the context added is discarded; nothing is stored locally and no
    /// duty event is kept. Once the service's cursor passes the entry it is gone: only a
    /// re-send brings the message back.
    ///
    /// Only an entry read from the feed is passed so. For an entry stored locally
    /// ([`ReceivedMessage::parked`], a released one included) a `Pass` changes nothing: it
    /// stays stored, with what it counts, and is tried again at a later read; a protocol done
    /// with it returns [`Outcome::Drop`]. No entry whose effect the app must keep is asked
    /// about: one whose effect was applied is a duplicate before its receive step (check
    /// 9), and a kept effect goes again before the feed is read; after `409 conflict` on the
    /// effect's batch ([`ReceivedMessage::conflict`]) nothing of it was applied, so a `Pass`
    /// then passes the entry.
    Pass,
    /// The step needs a scope key of `data_epoch` that the app doesn't hold yet (Switch
    /// spec 3.5, 8.2), such as to read a record held sealed at that epoch
    /// ([`super::Unopened::KeyNotHeld`]) or to write while the app lacks the current data
    /// epoch's key ([`ReceiveContext::holds_scope_key`], [`ReceiveContext::data_epoch`]).
    /// What the context added is discarded. When a key the app's certificate is given is
    /// missing at an epoch up to the current one, and no full bundle is asked for yet, the
    /// app fetches its key bundle once, asking for a full bundle if a key is still missing,
    /// and runs the step again if the epoch's keys came; otherwise the entry is stored
    /// locally and the cursor passes it at once ([`super::ParkReason::AwaitingKey`]), with
    /// no bounded wait and no [`super::AppEvent::StoreFailing`]. It is tried again once the
    /// app holds every key of `data_epoch` its certificate is given and a key came since
    /// the step last ran, so a key the certificate is never given runs it again only when
    /// another key comes; in the read whose
    /// fetch brought them, after the listing a read owes first, or at a later read; it is
    /// bounded with the entries whose sender couldn't be checked and dropped past the
    /// bounds ([`super::AppEvent::StoredEntryDropped`]). Each read's report names the
    /// epochs waited for ([`super::AppEvent::AwaitingKeys`]). An effect applied with a
    /// write the context refused for want of the key ([`ReceiveContext::put_record`]) ends
    /// the same way, waiting for the current data epoch.
    AwaitKey {
        /// The data epoch whose key the step waits for.
        data_epoch: u64,
    },
}

/// Entries the app can't read and whose senders it asks to send again (Switch spec 8.2):
/// the acceptance times to ask for. The app never asks for a time before its cursor's, less
/// the clock tolerance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResendNeeded {
    /// The sender to ask.
    pub sender: [u8; 32],
    /// The first acceptance time to ask for, service time in Unix milliseconds.
    pub accepted_from_ms: u64,
    /// The last acceptance time to ask for.
    pub accepted_until_ms: u64,
    /// Why: an entry wrapped to a key the app doesn't hold, or one a departed own app left
    /// unread.
    pub reason: ResendReason,
}

/// Why the app asks for a re-send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResendReason {
    /// The entry is wrapped to a key the app doesn't hold (after a restore).
    Unopenable,
    /// A departed own app left the entry unread.
    Unreadable,
}

/// Entries the service deleted while the app was lagging (Switch spec 8.2): the protocol
/// asks the counterparties of its unfinished activity to re-send what their inboxes
/// accepted from `accepted_from_ms`, through `accepted_until_ms` if it bounds its
/// re-sends, and lists its collections again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissedEntries {
    /// The item's `seq`, in the sequence of the generation the app read it at: a call made
    /// again after a provider change keeps it, as information only.
    pub seq: u64,
    /// How many entries were missed.
    pub entries: u64,
    /// The time to ask from: the later of the item's first acceptance time and the cursor's
    /// time, less the clock tolerance.
    pub accepted_from_ms: u64,
    /// The item's last acceptance time, `accepted_until` (Switch wire 7.5), raised to
    /// `accepted_from_ms` when it is earlier. The service writes it, and the app can't
    /// check it. A call kept owed by a build that didn't keep this time is made with
    /// `u64::MAX`: no end is known.
    pub accepted_until_ms: u64,
}

/// A change to the identity's deny list, as the feed shows it to an app holding `lists.read`
/// (Switch spec 8.3): a `deny.put` or a `deny.delete` whose signature the app verified, made
/// by an app of the identity whose certificate holds `lists.manage`, this one included. One
/// the app can't verify so, such as one whose writer's certificate it can't find, is neither
/// handed nor applied to the app's copy of the lists, and names nobody. The protocol gets each in feed order ([`Protocol::deny_list_changed`]),
/// so one restored from a backup rebuilds who was denied since the backup's cursor; where
/// that history has a gap, it is told so instead ([`Protocol::deny_list_gap`]).
///
/// A genuine change the service shows again reads as a new one (Switch spec 13.5): a
/// protocol takes a change as setting a state, `pubky` denied or not, rather than as a
/// count.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DenyListChange {
    /// The generation of the feed item.
    pub generation: u64,
    /// The item's `seq` in that generation.
    pub seq: u64,
    /// The pubky the change is about.
    pub pubky: [u8; 32],
    /// `true` when the pubky was added to the deny list, `false` when it was removed.
    pub added: bool,
    /// The item's service time, in Unix milliseconds.
    pub at_ms: u64,
}

/// A gap in the deny list's history (Switch spec 8.3, 12.4, 12.6): changes after
/// `generation` and `seq` may never reach the protocol, as after a restore from a backup
/// older than the retained history, or after a provider loss. `denied` is the deny list as
/// the service holds it now, read with `GET /allow` (Switch wire 7.4.11), so the protocol
/// can start again from it, or hold what the gap covers ([`Protocol::deny_list_gap`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DenyListGap {
    /// The generation of the last position the history is known complete through.
    pub generation: u64,
    /// That position's `seq`.
    pub seq: u64,
    /// The deny list now, empty when `list_read` is false.
    pub denied: Vec<[u8; 32]>,
    /// Whether the lists were read for the gap. `false` when the service's answer couldn't
    /// be read: the protocol then knows only that the history has a gap, and fails closed
    /// for it.
    pub list_read: bool,
}

/// A protocol on the Switch, as the app layer uses it. Object-safe; the app holds an
/// `Arc<dyn Protocol>`.
///
/// # Callbacks and the store
///
/// Every callback is synchronous and runs on the app's task, in the middle of one of its
/// calls. A callback may read the host's store synchronously: the receive step through its
/// [`ReceiveContext`], [`Protocol::sends_to_with`] and [`Protocol::provider_lost_with`]
/// through a [`LocalView`], any callback through a handle of its own on the host's store.
/// No callback writes the store: the app commits the protocol's local state only as the
/// [`LocalWrite`]s a callback returns, or a batch or [`super::App::protocol_commit`]
/// carries, each at the commit point its crash rules give it (`STATE.md`). A write made
/// beside them could land without the outcome it belongs to, or after a crash that
/// discards it.
///
/// # Limits a receive step plans for
///
/// - **Operations:** at most 7 beside the cursor move (Switch wire 6.4).
/// - **Local writes:** at most [`MAX_STEP_LOCAL_BYTES`], 4 MiB, counted as
///   [`local_writes_bytes`] counts them, for each set of local writes handed over at once.
///   The bound keeps every set within what the app's store keeps and commits, whatever
///   else the read holds; a protocol keeps larger state in its own store. Over it:
///   - **a receive step**, its [`ReceiveContext::local`] writes and its [`Effect`]'s
///     together: a write that would take [`ReceiveContext::local`] past it is refused
///     there, and an effect over it is stored and passed as
///     [`super::ParkReason::EffectTooLarge`], with [`super::AppEvent::EffectRefused`],
///     never applied (Switch spec 8.2);
///   - **[`Protocol::resend_needed`], [`Protocol::missed`] and
///     [`Protocol::deny_list_changed`]**, made at once or again
///     later: the writes aren't committed and the call isn't made again, since the same
///     answer would come; the item is passed, and the protocol told with
///     [`super::AppEvent::LocalWritesRefused`], a duty event;
///   - **an [`super::OpBatch`]'s local writes**: [`super::App::submit_batch`] refuses the
///     batch before it signs or keeps it ([`super::Refusal::Usage`]).
///
/// # Duty events
///
/// What the app must tell its protocol outside a callback comes as a duty event
/// ([`super::AppEvent::is_duty`]), which the host relays. Delivery is at least once: a
/// duty event comes again after any load until the host acknowledges it
/// ([`super::App::ack_events`]), so a protocol tolerates seeing one twice, and acts on it
/// by its [`super::EventId`] or by the state it names.
pub trait Protocol: Send + Sync {
    /// The opaque members of the protocol's message bodies (Switch wire 1.1). None by
    /// default.
    fn opaque_members(&self) -> Vec<OpaqueRule> {
        Vec::new()
    }

    /// Whether `scope`, a scope of a certificate (a name, or a name and a sub-scope), has
    /// Shared Data Keys (Switch spec 3.5). A sub-scope's keys are its sub-scope keys.
    fn has_keys(&self, scope: &str) -> bool;

    /// Whether the protocol sends `kind` between apps of one identity (Switch wire 5.1
    /// check 6).
    fn sent_between_own_apps(&self, kind: &str) -> bool;

    /// Check 8 (Switch wire 5.1): the sender's certificate holds a scope that sends the
    /// kind, and the own certificate one that receives it, with the protocol's narrower
    /// rules.
    ///
    /// # Errors
    ///
    /// The rule the message breaks, without content: the entry is dropped.
    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String>;

    /// The kinds the app's record lists in `accepts` for a certificate: never wider than
    /// what its scopes receive (Switch spec 3.4).
    fn accepts(&self, cert: &AppCert) -> Vec<String>;

    /// Check 10 (Switch wire 5.1) of a message that passed checks 1 to 9, with no effect:
    /// the body parses as its kind's body, the members read have their types, and the
    /// protocol's rules for the kind hold. The app runs it before [`Protocol::receive_with`],
    /// and a push extension's peek runs it alone (Switch spec 9 step 5), so it must refuse
    /// every body that the receive step would drop for its shape, and change nothing.
    ///
    /// # Errors
    ///
    /// The rule the body breaks, without content: the entry is dropped, and a peek shows a
    /// generic notification for it.
    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String>;

    /// The effect of a message whose body passed [`Protocol::check_body`], for a protocol
    /// that needs nothing of the app's state: [`Protocol::receive_with`] calls it by default.
    /// A protocol that implements [`Protocol::receive_with`] need not implement this one; by
    /// default it drops every message. A step that can't finish because the protocol's
    /// store or the host failed returns [`Outcome::Retry`], never [`Outcome::Drop`].
    fn receive(&self, message: &ReceivedMessage) -> Outcome {
        let _ = message;
        Outcome::Drop {
            reason: "the protocol takes no messages".into(),
        }
    }

    /// The effect of a message whose body passed [`Protocol::check_body`], with the app's
    /// state at hand (Switch spec 8.2): `cx` derives record keys and blinded inputs, reads
    /// the writes the app holds and the claims it keeps, and adds record writes and claim
    /// entries to the effect's batch, which carries the cursor move. What `cx` added goes
    /// only with [`Outcome::Apply`]; a [`Outcome::Drop`], an [`Outcome::Need`], an
    /// [`Outcome::Retry`], an [`Outcome::Pass`] or an [`Outcome::AwaitKey`] discards it. After an [`Outcome::Need`] the app reads what it
    /// names and calls this again, the answers in [`ReceiveContext::switch_claim`]. A read
    /// of the context, or of the protocol's own store, that fails with a store error is an
    /// [`Outcome::Retry`] ([`StoreFailure::try_from`]): the entry is held for a later read,
    /// or stored locally and tried again at a later read. After `409 conflict` on the batch the
    /// app reads the records and claims `cx` wrote again and calls this once more, with
    /// [`ReceivedMessage::conflict`] set. [`Protocol::receive`] by default.
    fn receive_with(&self, message: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        let _ = cx;
        self.receive(message)
    }

    /// Entries the app can't read: the protocol queues its re-send request and returns the
    /// local writes that queue it, committed with the cursor passing the entries.
    ///
    /// # Errors
    ///
    /// A [`StoreFailure`] when the protocol can't build its writes now, such as when its own
    /// state can't be read, of either kind. The cursor still passes the entries, and the app
    /// keeps `needed` in that same commit and calls this again with it at the start of each
    /// later read, across loads, before anything else is handed, until it returns writes;
    /// while it fails, the read hands nothing after it, of any kind (Switch spec 8.3)
    /// ([`super::App::owed_protocol_calls`]).
    fn resend_needed(&self, needed: &ResendNeeded) -> Result<Vec<LocalWrite>, StoreFailure>;

    /// Entries missed while lagging: as [`Protocol::resend_needed`], failure included.
    ///
    /// # Errors
    ///
    /// As [`Protocol::resend_needed`].
    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, StoreFailure>;

    /// A change to the deny list the feed shows (Switch spec 8.3): the protocol keeps what
    /// it needs of it and returns the local writes that keep it, committed with the cursor
    /// passing the item. Nothing by default.
    ///
    /// - **Who gets them:** an app holding `lists.read`, its own changes included, which
    ///   come back by its feed. An app without it gets none.
    /// - **Order:** feed order, across everything the app hands over. While a change is
    ///   owed, the read hands nothing after it: no later item, owed call or entry stored
    ///   locally. So an undeny is seen before the message after it. Calls owed from a
    ///   sequence a provider loss ended come before those of the current sequence, and
    ///   among themselves in the order (generation, seq): two of one lost sequence owed at
    ///   different generations, as across a key change in place, may come out of feed
    ///   order. The gap the loss leaves follows them, with the full list
    ///   ([`Protocol::deny_list_gap`]). A change owed that the app's position is already
    ///   past, as after a restore in place from a newer backup, or one of a lost sequence
    ///   once the app reads the next, isn't made: it would come after later changes, so
    ///   the protocol is told a gap at that position instead.
    /// - **Again:** a change may come twice, after a crash before its commit and after a
    ///   restore, whose feed hands it again; its writes commit once. A protocol keys what it
    ///   keeps by the change's place, or takes it as setting a state.
    /// - **Before and after:** an entry held, accepted before a change, may come again at a
    ///   later read, after the change.
    ///
    /// # Errors
    ///
    /// As [`Protocol::resend_needed`]. A failed change is owed and made again at the start
    /// of each later read, before anything else is handed; the read stops there while it
    /// fails, and after [`RETRY_EVENT_READS`] such reads the app tells the host
    /// ([`super::AppEvent::OwedCallHeld`]). Writes over [`MAX_STEP_LOCAL_BYTES`] aren't
    /// committed and the change isn't made again, with
    /// [`super::AppEvent::LocalWritesRefused`].
    fn deny_list_changed(&self, change: &DenyListChange) -> Result<Vec<LocalWrite>, StoreFailure> {
        let _ = change;
        Ok(Vec::new())
    }

    /// A gap in the deny list's history, with the list as it stands now ([`DenyListGap`]):
    /// the protocol starts again from it, or fails closed for what the gap covers. Made
    /// once the app has read the list after the gap, before any later change or item is
    /// handed, its writes committed with that copy of the lists. Nothing by default.
    ///
    /// # Errors
    ///
    /// A [`StoreFailure`]: the copy isn't taken, and the call is made again at the next
    /// read, which hands nothing else meanwhile, as for [`Protocol::deny_list_changed`].
    fn deny_list_gap(&self, gap: &DenyListGap) -> Result<Vec<LocalWrite>, StoreFailure> {
        let _ = gap;
        Ok(Vec::new())
    }

    /// A provider loss the app follows (Switch spec 12.6 steps 2 and 4): the protocol queues
    /// its re-send requests to the counterparties of its unfinished activity, for what their
    /// inboxes accepted from [`ProviderLoss::accepted_from_ms`] on, and names the
    /// counterparties whose conversation entries the app adds back, at most
    /// [`MAX_LOSS_CONVERSATIONS`]: how many past it were left out is kept with the loss
    /// ([`super::RecoveryInfo::conversations_left_out`]). The app commits the local writes
    /// once, with that step; a crash before that commit calls it again. Writes over
    /// [`MAX_STEP_LOCAL_BYTES`] aren't committed and the loss goes on, with
    /// [`super::AppEvent::LocalWritesRefused`]. Nothing by default.
    ///
    /// # Errors
    ///
    /// A [`StoreFailure`] when the protocol can't build its actions now, such as when its own
    /// state can't be read. The recovery stays at this step, which its record keeps, and the
    /// app's call fails with [`super::AppError::Protocol`], apart from the app's own store
    /// failing; the next call asks again.
    fn provider_lost(&self, loss: &ProviderLoss) -> Result<LossActions, StoreFailure> {
        let _ = loss;
        Ok(LossActions::default())
    }

    /// [`Protocol::provider_lost`], with the protocol's local state at hand, read-only
    /// (`view`), such as to find the counterparties of its unfinished activity. The app
    /// calls this one; by default it calls [`Protocol::provider_lost`].
    ///
    /// # Errors
    ///
    /// As [`Protocol::provider_lost`].
    fn provider_lost_with(
        &self,
        loss: &ProviderLoss,
        view: &LocalView<'_>,
    ) -> Result<LossActions, StoreFailure> {
        let _ = view;
        self.provider_lost(loss)
    }

    /// Whether a certificate's scopes allow its app to receive `kind`, which a sender checks
    /// before wrapping a message to the app (Switch spec 3.4). By default, whether the kinds
    /// [`Protocol::accepts`] gives for the certificate list it, which are never wider than
    /// what its scopes receive.
    fn receives(&self, kind: &str, cert: &AppCert) -> bool {
        self.accepts(cert).iter().any(|k| k == kind)
    }

    /// The protocol's narrower rule for senders (Switch spec 3.4): whether `message` goes to
    /// the app whose record is `recipient`, beyond its certificate and `accepts`. Every app
    /// by default.
    fn sends_to(&self, message: &Message, recipient: &AppRecord) -> bool {
        let _ = (message, recipient);
        true
    }

    /// [`Protocol::sends_to`], with the protocol's local state at hand, read-only (`view`).
    /// The app calls this one; by default it calls [`Protocol::sends_to`].
    fn sends_to_with(
        &self,
        message: &Message,
        recipient: &AppRecord,
        view: &LocalView<'_>,
    ) -> bool {
        let _ = view;
        self.sends_to(message, recipient)
    }

    /// Whether a first message of `kind` to a counterparty that isn't a contact adds a
    /// conversation entry before it is sent (Switch spec 7): every kind but the protocol's
    /// re-send request, which answers entries the app can't check. Every kind by default.
    fn adds_conversation(&self, kind: &str) -> bool {
        let _ = kind;
        true
    }

    /// The protocol's collections, each with its fixed policy (Switch spec 10.3). The app
    /// lists those it may read at join and after a `missed` item, and takes writes to them
    /// from the feed; writes to any other collection are left alone. None by default.
    fn collections(&self) -> Vec<Collection> {
        Vec::new()
    }

    /// What the app has seen of a record, its high water (Switch spec 8.2): the protocol's
    /// mark after `value`, from the mark held (`None` for a write of the app's own, built on
    /// what it trusts), or `None` to keep no mark. None by default. It isn't called for the
    /// app's own delete, which leaves the mark held as it is: what the app saw stays seen,
    /// and a later write by another app is checked against it.
    ///
    /// A mark is at most [`MAX_SEEN_MARK_BYTES`], 64 KiB. Past it, nothing is silent:
    ///
    /// - **The app's own write**, built through [`super::App::put_record`],
    ///   [`super::App::record_op`] or [`super::ReceiveContext::put_record`]: the write is
    ///   refused there, before anything is signed ([`super::Refusal::Usage`]), since the
    ///   protocol's own value gives a mark it can't keep.
    /// - **An own write whose mark is over it only once taken**, such as a kept batch
    ///   answered after the protocol's marks grew: the mark held goes, as for `None`, so it
    ///   never stands for the own write, and the protocol is told the record can't be
    ///   checked from that write on ([`super::AppEvent::RecordUncheckable`], a duty event).
    /// - **Another app's write:** the record keeps the mark it held, so what was seen before
    ///   is still checked against later writes, and the protocol is told the same way.
    ///
    /// It is called once more for every own write, when the write is built, to refuse one
    /// whose mark won't fit, and again when the write is taken: it has no side effects, and
    /// gives the same mark for the same arguments.
    fn record_seen(
        &self,
        collection: &str,
        seen: Option<&[u8]>,
        value: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        let _ = (collection, seen, value);
        None
    }

    /// Whether a newer write of a record goes back on what the app has seen there (Switch
    /// spec 8.2), such as dropping or replacing a message of a role it saw: the rule it
    /// breaks, without content, and the write is flagged and not acted on. `value` is
    /// `None` for a delete or an unreadable value. Never by default.
    ///
    /// The rule is at most [`MAX_REGRESSION_REASON_BYTES`], 256 bytes; a longer one is cut
    /// there, at a character boundary.
    fn record_regression(
        &self,
        collection: &str,
        seen: &[u8],
        value: Option<&[u8]>,
    ) -> Option<String> {
        let _ = (collection, seen, value);
        None
    }

    /// [`Protocol::record_regression`], told what the newer write builds on
    /// ([`WriteBase`]): its `expected_version`, whether the app holds that version, and the
    /// conditions its operation signed. A protocol whose rules hold only for a writer that
    /// built on the value the app holds, such as one that may drop only what it held itself,
    /// applies them when `base.held`; one whose rule fences a change on a condition, such as
    /// a `claim_step` on the claim of what the write drops, finds it in `base.conditions`.
    /// The app calls this one; by default it calls [`Protocol::record_regression`], so a
    /// protocol that implements only that keeps its rules as they are.
    ///
    /// The same bound on the rule applies, [`MAX_REGRESSION_REASON_BYTES`].
    fn record_regression_on(
        &self,
        collection: &str,
        seen: &[u8],
        value: Option<&[u8]>,
        base: WriteBase,
    ) -> Option<String> {
        let _ = base;
        self.record_regression(collection, seen, value)
    }

    /// The name of the layers the protocol adds to app backups ([`ProtocolLayer`]):
    /// [`super::App::restore`] takes a backup's layer only with a protocol that gives the
    /// same name, and refuses a backup whose layer another protocol, or a protocol without a
    /// name, made, rather than drop that data. `None` by default: the protocol takes no
    /// layer, and [`super::App::backup_layered`] refuses.
    fn backup_name(&self) -> Option<String> {
        None
    }

    /// The bytes of the protocol's backup layer from its local state as committed: every
    /// key and value it holds, in key order, read by [`super::App::backup_layered`] in the
    /// same call as the app's own state. [`Protocol::restore_layer`] reads them back. By
    /// default the whole state, as [`encode_local_state`] gives it.
    ///
    /// # Errors
    ///
    /// Why the state can't be backed up, without content: the backup is refused.
    fn backup_layer(&self, state: Vec<KeyValue>) -> Result<Vec<u8>, String> {
        Ok(encode_local_state(&state))
    }

    /// The writes that install a backup's protocol layer at a restore (Switch spec 12.4),
    /// or that a backup without one, `None`, needs. [`super::App::restore`] calls it once,
    /// after it checked the backup's own state and the layer's name and before it writes
    /// anything, and commits the writes in the one commit that installs its own restored
    /// state, after it cleared the app's namespace: so the protocol starts from an empty
    /// local state and its writes stay under its prefix. It checks the layer in full here;
    /// nothing is written until it returns. [`super::App::backup_layered`] calls it too,
    /// writing nothing, to check that the backup can be restored, so it has no effect of
    /// its own. By default it reads the layer as the default [`Protocol::backup_layer`]
    /// writes it ([`decode_local_state`]) and puts every key back, and needs no writes for a
    /// backup without a layer.
    ///
    /// It runs at every restore and at every [`super::App::backup_layered`], so it has no
    /// side effects: it returns the writes, and the app commits them or doesn't.
    ///
    /// `restoring` gives the identity, the App ID, the certificate and `blind` under the
    /// naming key of the backup, the ones the restored app goes on with
    /// ([`RestoreContext`]), so the protocol can check its layer and the backup against
    /// them here, rather than after the restore commits: such as that each claim key it
    /// keeps is the one its inputs blind to, or that the certificate holds the scopes and
    /// permissions the protocol requires. In [`super::App::backup_layered`]'s check it gives
    /// the app's current ones, which the backup carries. The default ignores it.
    ///
    /// # Errors
    ///
    /// Why the layer, or a backup without one, can't be installed, without content: the
    /// restore is refused and nothing is written.
    fn restore_layer(
        &self,
        layer: Option<&ProtocolLayer>,
        restoring: &RestoreContext<'_>,
    ) -> Result<Vec<LocalWrite>, String> {
        let _ = restoring;
        let Some(layer) = layer else {
            return Ok(Vec::new());
        };
        let state = decode_local_state(&layer.data)
            .ok_or_else(|| String::from("the layer doesn't read as local state"))?;
        Ok(state
            .into_iter()
            .map(|(key, value)| LocalWrite::Put { key, value })
            .collect())
    }

    /// The shared record write of a sent message (Switch spec 8.2): the record's next value
    /// from its current one (`None` for none, deleted or unreadable), or `None` when the
    /// record already reflects the message. Nothing by default.
    fn sent_record(
        &self,
        job: &RecordJob,
        sent: &SentMessage,
        current: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        let _ = (job, sent, current);
        None
    }
}

/// The protocol's kind rules as the core's recipient checks take them, with the own
/// certificate for check 8.
pub(crate) struct Rules<'a> {
    pub(crate) protocol: &'a dyn Protocol,
    pub(crate) own: &'a AppCert,
    pub(crate) opaque: Vec<OpaqueMember<'a>>,
}

impl<'a> Rules<'a> {
    pub(crate) fn new(
        protocol: &'a dyn Protocol,
        own: &'a AppCert,
        rules: &'a [OpaqueRule],
    ) -> Self {
        Self {
            protocol,
            own,
            opaque: rules
                .iter()
                .map(|rule| OpaqueMember {
                    kind: rule.kind.as_deref(),
                    member: rule.member.as_str(),
                })
                .collect(),
        }
    }
}

impl KindRules for Rules<'_> {
    fn opaque_members(&self) -> &[OpaqueMember<'_>] {
        &self.opaque
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.protocol.sent_between_own_apps(kind)
    }

    fn check_scopes(&self, message: &Message, sender: &AppCert) -> pubky_switch_core::Result<()> {
        self.protocol
            .check_scopes(message, sender, self.own)
            .map_err(pubky_switch_core::Error::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_write_debug_hides_values() {
        let write = LocalWrite::Put {
            key: b"note".to_vec(),
            value: b"secret-body".to_vec(),
        };
        let text = format!("{write:?}");
        assert!(!text.contains("secret"), "{text}");
        assert!(text.contains("11 value bytes"));
    }
}
