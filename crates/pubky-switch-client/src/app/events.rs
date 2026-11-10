//! What the app tells its host: [`AppEvent`]s, collected in each call's report. Alarms
//! (Switch spec 3.6, 4.3, 10.1) are also kept in the store until the user resolves them.
//!
//! Events carry facts, never wording, and never message content: a host words them.
//!
//! # Duty events
//!
//! Where the spec has the app tell its protocol something, the event is a duty event
//! ([`AppEvent::is_duty`]): a received message's effect refused for good, too large for one
//! batch, or of unknown fate, and its entry stored locally for good (Switch spec 8.2, 12.5
//! "Kept batches"); a kept batch dropped at a provider change and each `attempt` in it
//! (Switch spec 12.5 "Kept batches", 12.6 step 5); a kept batch refused for good, with its
//! local writes and outbox messages (Switch spec 6.4); a message deleted from the outbox
//! undelivered (Switch spec 11). Each carries a stable [`EventId`] and is kept in the
//! store (`duty/<id>`) in the same commit as the change it reports, so no crash separates
//! the two. It is reported once that commit is done, or, for a commit whose answer can't
//! tell whether it was applied, by the reload after it; again by every [`super::App::load`],
//! and listed by [`super::App::unacknowledged_events`], until the host acknowledges it with
//! [`super::App::ack_events`]: delivery is at least once. A host and its protocol must
//! therefore tolerate a duty event seen twice, and act on it only once they have kept what
//! it says, then acknowledge it.
//!
//! Every other event is informational: kept in memory only, and shown once.
//!
//! Nothing in the app bounds the stored duty events: only the host's acknowledgements
//! remove them. Each is written once, for one entry stored for good, one kept batch or
//! `attempt` dropped, or one outbox message given up, so they grow with those facts, and
//! without limit for a host that never acknowledges. The app sets no cap, since a cap would
//! have to lose a duty event or stop the work that makes them: reading the feed, which never
//! stalls (Switch spec 8.2), giving up an undeliverable message (Switch spec 11), or
//! following a provider change (Switch spec 12.5, 12.6). A host acknowledges each duty
//! event once it has handed it to its protocol and the protocol has kept what it says.

use serde::{Deserialize, Serialize};

use pubky_switch_core::enc::serde_b64;

use super::error::Alarm;
use super::feed::OwedCall;
use super::protocol::{MissedEntries, ResendNeeded, StoreFailure};
use super::recovery::ProviderLoss;

/// The stable ID of a duty event ([`AppEvent::is_duty`]): the store's epoch, and a counter.
///
/// The epoch is random, chosen once when the app's store starts empty: at the first
/// [`super::App::join`], and at a [`super::App::restore`] onto a store that holds none. A
/// restore in place keeps it. Within one store every kept event has the same epoch and the
/// counter only goes up, in the order the events were kept; a store started on another
/// device, or after a wipe, has another epoch, so its IDs never equal one from before.
///
/// IDs compare only within one store: [`EventId::cmp_same_store`] orders two of the same
/// epoch and gives `None` otherwise. There is no total order across stores. A host keeps an
/// ID as [`EventId::to_bytes`] or its string form ([`std::fmt::Display`], parsed with
/// [`std::str::FromStr`]), both stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EventId {
    epoch: [u8; EPOCH_LEN],
    counter: u64,
}

/// The length of a store's event epoch, in bytes.
pub(crate) const EPOCH_LEN: usize = 16;

/// The length of [`EventId::to_bytes`].
pub const EVENT_ID_LEN: usize = EPOCH_LEN + 8;

impl EventId {
    pub(crate) fn new(epoch: [u8; EPOCH_LEN], counter: u64) -> Self {
        Self { epoch, counter }
    }

    pub(crate) fn epoch(&self) -> [u8; EPOCH_LEN] {
        self.epoch
    }

    /// The counter: the event's place among its store's duty events.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Whether `other` comes from the same store.
    pub fn same_store(&self, other: &Self) -> bool {
        self.epoch == other.epoch
    }

    /// The order of two IDs of the same store, by counter; `None` for IDs of different
    /// stores, which have no order.
    pub fn cmp_same_store(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.same_store(other)
            .then(|| self.counter.cmp(&other.counter))
    }

    /// The ID's stable bytes: the epoch, then the counter, big-endian.
    pub fn to_bytes(&self) -> [u8; EVENT_ID_LEN] {
        let mut bytes = [0u8; EVENT_ID_LEN];
        let (epoch, counter) = bytes.split_at_mut(EPOCH_LEN);
        epoch.copy_from_slice(&self.epoch);
        counter.copy_from_slice(&self.counter.to_be_bytes());
        bytes
    }

    /// An ID from [`EventId::to_bytes`].
    ///
    /// # Errors
    ///
    /// [`EventIdError`] for bytes of another length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EventIdError> {
        if bytes.len() != EVENT_ID_LEN {
            return Err(EventIdError);
        }
        let (epoch, counter) = bytes.split_at(EPOCH_LEN);
        Ok(Self {
            epoch: epoch.try_into().map_err(|_| EventIdError)?,
            counter: u64::from_be_bytes(counter.try_into().map_err(|_| EventIdError)?),
        })
    }
}

/// The string form: the epoch in lowercase hex, a `-`, then the counter in decimal.
impl std::fmt::Display for EventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.epoch {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "-{}", self.counter)
    }
}

impl std::str::FromStr for EventId {
    type Err = EventIdError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (hex, counter) = text.split_once('-').ok_or(EventIdError)?;
        if hex.len() != EPOCH_LEN * 2 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(EventIdError);
        }
        let mut epoch = [0u8; EPOCH_LEN];
        for (index, byte) in epoch.iter_mut().enumerate() {
            let at = index.saturating_mul(2);
            let pair = hex.get(at..at.saturating_add(2)).ok_or(EventIdError)?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| EventIdError)?;
        }
        if counter.is_empty() || !counter.bytes().all(|b| b.is_ascii_digit()) {
            return Err(EventIdError);
        }
        let counter = counter.parse().map_err(|_| EventIdError)?;
        Ok(Self { epoch, counter })
    }
}

/// Bytes or a string that aren't an [`EventId`]'s stable form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("not an event ID")]
pub struct EventIdError;

/// One thing that happened, for the host to show or act on.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AppEvent {
    /// An alarm stopped the app.
    Alarm(Alarm),
    /// A message passed every check and its effect was committed with the cursor move.
    MessageReceived {
        /// The entry's `seq`.
        seq: u64,
        /// The message kind.
        kind: String,
        /// The message ID.
        msg_id: String,
        /// The sender identity.
        sender: [u8; 32],
    },
    /// A message failed a recipient check and was dropped (Switch wire 5.1).
    MessageDropped {
        /// The entry's `seq`.
        seq: u64,
        /// The check of Switch wire 5.1 that failed, 1 to 10.
        check: u8,
        /// The rule, without content.
        reason: String,
    },
    /// The same (sender, `msg_id`) again; `conflicting` when its bytes differ, which is
    /// shown as a conflict (Switch spec 11).
    Duplicate {
        /// The entry's `seq`.
        seq: u64,
        /// Whether the bytes differ from the message processed before.
        conflicting: bool,
    },
    /// An entry whose sender can't be checked yet is held; later entries go on (Switch
    /// spec 8.2).
    Held {
        /// The entry's `seq`.
        seq: u64,
    },
    /// The protocol's receive step at an entry couldn't finish, because its store or the
    /// host failed ([`super::Outcome::Retry`]), on `reads` reads in a row: raised from the
    /// [`super::RETRY_EVENT_READS`]th on, on each such read, whether the entry is held on
    /// the feed or, after the bounded wait, stored locally ([`ParkReason::StoreUnavailable`]).
    /// The entry stays unprocessed until a read processes it; the host repairs or frees its
    /// store.
    StoreFailing {
        /// The entry's `seq`.
        seq: u64,
        /// The reads in a row that ended in a retry at the entry, this one included.
        reads: u32,
        /// When the first of them was, device time in Unix milliseconds.
        since_ms: u64,
        /// The store's failure on this read.
        failure: StoreFailure,
    },
    /// A layered backup was refused ([`super::App::backup_layered`]), so the host knows it
    /// has no current backup.
    BackupRefused {
        /// Why.
        reason: BackupRefusal,
    },
    /// An entry was stored locally and the cursor moved past it (Switch spec 8.2), for
    /// `reason`. A duty event when the entry isn't tried again
    /// ([`ParkReason::tried_again`]): then nothing but the protocol brings it back.
    Parked {
        /// The duty event's ID; `None` for an entry that later reads try again.
        id: Option<EventId>,
        /// The entry's `seq`.
        seq: u64,
        /// Why.
        reason: ParkReason,
    },
    /// A received message's effect was refused for good, has more operations than one
    /// batch takes with the cursor move, or is too large for the app's store to keep or
    /// commit ([`ParkReason::EffectTooLarge`]): its entry was stored locally and passed
    /// ([`AppEvent::Parked`]), and the effect isn't sent again (Switch spec 8.2). The
    /// protocol may build it again in another form. A duty event.
    EffectRefused {
        /// The duty event's ID.
        id: EventId,
        /// The entry's `seq`.
        seq: u64,
        /// The sender identity.
        sender: [u8; 32],
        /// The message ID.
        msg_id: String,
        /// The message kind.
        kind: String,
        /// The error code of the refusal; `None` for an effect the app refused itself, over
        /// one batch or carrying an operation the app layer builds ([`ParkReason`] says
        /// which).
        code: Option<String>,
    },
    /// A received message's effect was kept unanswered across a provider change for longer
    /// than a resend's answer can tell whether it was applied (Switch spec 12.5 "Kept
    /// batches"): its entry was stored locally and passed ([`AppEvent::Parked`]), and the
    /// effect isn't sent or built again. It may have been applied: the protocol decides
    /// from the current state of what the effect writes, and treats each `attempt` the
    /// effect carried as of unknown fate (Switch spec 12.5 "Kept batches", 12.6 step 5). A
    /// duty event.
    EffectUncertain {
        /// The duty event's ID.
        id: EventId,
        /// The entry's `seq`.
        seq: u64,
        /// The sender identity.
        sender: [u8; 32],
        /// The message ID.
        msg_id: String,
        /// The message kind.
        kind: String,
        /// The effect's own `attempt`s: whether each was applied can't be known.
        attempts: Vec<ClaimAttempt>,
    },
    /// An entry stored locally was processed.
    Unparked {
        /// The entry's `seq`.
        seq: u64,
    },
    /// An entry wrapped to a key the app doesn't hold was passed with the cursor (Switch
    /// spec 8.2, 12.4); the protocol was asked to request a re-send when allowed.
    Unopenable {
        /// The entry's `seq`.
        seq: u64,
        /// Whether a re-send was asked; never for a time before the cursor's, less the
        /// clock tolerance, and not when the protocol's call failed: it is owed then, and
        /// asked by a later read ([`super::App::owed_protocol_calls`]).
        resend_asked: bool,
    },
    /// An entry left unread by a departed own app (Switch spec 8.2).
    Unreadable {
        /// The item's `seq`.
        seq: u64,
        /// Whether a re-send was asked: only for an entry accepted at or before a departure
        /// the app verified in its chain, and not when the protocol's call failed: it is
        /// owed then, and asked by a later read.
        resend_asked: bool,
    },
    /// Entries the service deleted while the app was lagging (Switch spec 8.2).
    Missed {
        /// The item's `seq`.
        seq: u64,
        /// How many.
        entries: u64,
    },
    /// A new receive key was registered (Switch spec 3.6).
    Rotated {
        /// Its `n`.
        n: u64,
    },
    /// Another device of the app registered first; this device discarded its key.
    RotationLost {
        /// The other device's key's `n`.
        n: u64,
    },
    /// Retired receive keys were deleted once the cursor passed their successors'
    /// registrations.
    KeysDeleted {
        /// How many.
        count: u64,
    },
    /// The app reads no further until device sync brings the key of a registration its
    /// other device made (Switch spec 3.6).
    AwaitingDeviceSync {
        /// The registration's `n`.
        n: u64,
    },
    /// After a restore, a registration the app can't account for: the user is asked
    /// whether the app ran on this device after the backup (Switch spec 12.4).
    RestoreQuestion {
        /// The registrations' numbers.
        n: Vec<u64>,
    },
    /// The app holds every scope key through this data epoch (Switch spec 3.5).
    KeysThrough {
        /// The epoch.
        epoch: u64,
    },
    /// A key bundle part was skipped (Switch wire 3.5 "Reading").
    BundlePartSkipped {
        /// The range it names.
        range: (u64, u64),
        /// Why, without content.
        reason: String,
        /// Whether the user is alerted: another naming key than the identity's.
        alert: bool,
    },
    /// The app asked the signer for a full key bundle (Switch spec 3.5).
    FullBundleRequested,
    /// A newer own `identity.json` was taken.
    IdentityUpdated {
        /// Its version.
        version: u64,
    },
    /// The newest own `identity.json` names another generation: the provider changed.
    /// Following it is the provider-change flow's.
    ProviderChanged {
        /// The new generation.
        generation: u64,
    },
    /// A renewed certificate was seen in the feed; it is taken once the own
    /// `identity.json` lists it (Switch spec 3.2).
    RenewalSeen,
    /// The app took its renewed certificate and delivered its record with it.
    CertificateTaken {
        /// The new certificate's `issued_at`.
        issued_at: u64,
    },
    /// The own app was revoked or recorded as departed: it is no longer current.
    Removed,
    /// Continuity since the verified position couldn't be verified: the app continued
    /// from the checkpoint as a recovery decision and is in reconcile mode (Switch spec
    /// 8.3).
    ContinuityUnverified {
        /// The last `seq` the app had verified.
        verified_seq: u64,
        /// The checkpoint's `seq`.
        checkpoint_seq: u64,
    },
    /// The account is frozen for a move: writes wait for the next service (Switch spec
    /// 12.5).
    Moved,
    /// The device clock and the service's differ by more than the clock tolerance:
    /// automatic attempts pause (Switch spec 10.1).
    ClockSkew {
        /// The difference in milliseconds.
        skew_ms: u64,
    },
    /// A sender identity's `identity.json` was seen with two bodies at one version; the app
    /// takes nothing more from that identity until resolved (Switch spec 4.3).
    PeerEquivocation {
        /// The identity.
        identity: [u8; 32],
        /// The version.
        version: u64,
    },
    /// The app left its identity (Switch spec 12.3).
    Left,
    /// The app deleted its keys after leaving.
    KeysDestroyed,
    /// The app uploaded its newest head and evidence to the next service of a move, or to
    /// the service of a recovery (Switch spec 12.5 step 3, 12.6 step 3).
    EvidenceUploaded {
        /// The heads the service counted.
        heads: u64,
        /// The proofs the service kept or checked.
        proofs: u64,
    },
    /// The service refused the app's evidence: an import conflict the signer resolves, or
    /// another refusal (Switch wire 7.4.14). The app goes on without it.
    EvidenceRefused {
        /// The error code of the refusal.
        code: String,
    },
    /// The account's freeze was cancelled: the app stays at its service (Switch spec 12.5
    /// "Abort").
    MoveCancelled,
    /// The app follows the service of this generation now, after a cooperative move or a
    /// key change in place (Switch spec 12.5).
    ProviderFollowed {
        /// The generation followed.
        generation: u64,
    },
    /// The next service shows an older receive key of the app as current: a rollback of its
    /// registrations, which the app registers again (Switch spec 12.5 step 4).
    ReceiveKeyRolledBack {
        /// The `n` the service shows.
        shown: u64,
        /// The `n` of the app's current key.
        current: u64,
    },
    /// The next service's admission lists differ from the app's copy (Switch spec 12.5 step
    /// 4): entries added back, contacts the app never saw added, invite codes withdrawn.
    ListsDiffer {
        /// Contacts and deny list entries added back.
        added: u64,
        /// Contacts the service holds that the app never saw added; shown, not removed.
        unverified_contacts: u64,
        /// Invite codes withdrawn.
        withdrawn_codes: u64,
    },
    /// The identity declared the loss of a generation: the app recovers at the new service
    /// and stays in reconcile mode until its reconciliation ends it (Switch spec 12.6).
    ProviderLost {
        /// The generation lost.
        lost_generation: u64,
        /// The generation recovered at.
        generation: u64,
    },
    /// The app finished its steps of a recovery: registered, uploaded, restored admission
    /// and asked for re-sends (Switch spec 12.6 steps 1 to 4).
    ProviderRecovered {
        /// The generation recovered at.
        generation: u64,
    },
    /// A move or a provider loss the app was following toward `generation` was given up:
    /// the newest own `identity.json` names the later generation `newer`, which the app
    /// follows instead (Switch spec 12.5 "Abort", 12.6).
    ProviderChangeSuperseded {
        /// The generation the change being followed went to.
        generation: u64,
        /// The generation the newest own `identity.json` names.
        newer: u64,
    },
    /// A batch of operations kept before a provider change, its answer lost, is in the
    /// old service's chain: it was applied, and what it settles is committed (Switch spec
    /// 13.5).
    KeptBatchApplied {
        /// The batch ID.
        batch_id: [u8; 16],
    },
    /// A kept batch the old service didn't apply was signed again for the generation the
    /// app follows now, under a new batch ID, and is sent there with the next write
    /// (Switch spec 12.5 step 2, 13.5).
    KeptBatchSignedAgain {
        /// The batch ID it had.
        batch_id: [u8; 16],
        /// The batch ID it has now.
        new_batch_id: [u8; 16],
    },
    /// A kept batch wasn't carried to the new service: one holding an `attempt` after a
    /// provider loss, since no automatic attempt is made on an obligation from before the
    /// loss (Switch spec 12.6 step 5), or one kept longer than a resend's answer can tell
    /// whether it was applied (Switch spec 12.5 "Kept batches"). Each attempt in it follows
    /// as [`AppEvent::AttemptDropped`]. The protocol decides what to write instead. A duty
    /// event.
    KeptBatchDropped {
        /// The duty event's ID.
        id: EventId,
        /// The batch ID.
        batch_id: [u8; 16],
    },
    /// An `attempt` in a kept batch that was dropped ([`AppEvent::KeptBatchDropped`]): it
    /// is never signed again, and whether it was applied can't be known, so its obligation
    /// is uncertain (Switch spec 12.5 "Kept batches", 12.6 step 5). The protocol treats it
    /// so. A duty event.
    AttemptDropped {
        /// The duty event's ID.
        id: EventId,
        /// The claim key.
        claim_key: [u8; 32],
        /// The attempt.
        attempt_id: [u8; 16],
    },
    /// A restore in place left behind kept duty events and owed protocol calls whose stored
    /// values didn't read: what they said is lost, and the protocol learns only how many
    /// (`STATE.md`, "What the app owes its protocol"). A duty event.
    RestoreLeftBehind {
        /// The duty event's ID.
        id: EventId,
        /// The duty events left behind.
        duty_events: u64,
        /// The owed protocol calls left behind.
        owed_calls: u64,
    },
    /// The account the app used is gone: the service answers as for an identity it doesn't
    /// host and the identity publishes no `identity.json` (Switch spec 12.7).
    AccountGone,
    /// An account taken as erased was seen alive again: the identity publishes an
    /// `identity.json` listing the app (Switch spec 12.7). The app reads on; its push
    /// registration, which the service dropped, is set again with
    /// [`super::App::reregister_push`].
    AccountBack,
    /// The app's push registration is set (Switch spec 9 steps 1 to 3).
    PushRegistered {
        /// The handles the service keeps.
        handles: u64,
    },
    /// The app's push registration went with the service it was made at, or because the
    /// app stopped being current; the app registers again at its current service.
    PushRemoved,
    /// The recipient's inbox accepted a message: its delivery is complete (Switch spec 11).
    MessageAccepted {
        /// The message ID.
        msg_id: String,
        /// The acceptance time, the recipient's service time.
        accepted_at_ms: u64,
    },
    /// A message answered `403 not_admitted` or `403 not_current` for
    /// [`super::UNDELIVERABLE_MS`] wasn't delivered (Switch spec 11). A message its
    /// recipient never accepted was deleted from the outbox with its plaintext; for a
    /// re-send, only the re-send was given up. Also a message whose try needed writes over
    /// the store's sizes ([`crate::error::StoreError::TooLarge`]), which no later try can
    /// make: it was deleted from the outbox at once. A duty event.
    MessageUndelivered {
        /// The duty event's ID.
        id: EventId,
        /// The message ID.
        msg_id: String,
        /// Whether it was a re-send of a message accepted before.
        resend: bool,
    },
    /// The local writes the protocol answered `call` with were over
    /// [`super::MAX_STEP_LOCAL_BYTES`]: they weren't committed, and the call isn't made
    /// again, since the same answer would come. The read went on. The protocol acts on what
    /// the call said from its own state, such as asking for the re-send with writes that
    /// fit. A duty event.
    LocalWritesRefused {
        /// The duty event's ID.
        id: EventId,
        /// The call whose writes were refused.
        call: RefusedCall,
    },
    /// An app of a counterparty has no receive key record that passes the checks, so a
    /// message went to its other apps (Switch spec 8.1).
    UnreachableApp {
        /// The counterparty.
        identity: [u8; 32],
        /// The app.
        app_id: [u8; 16],
    },
    /// After a provider loss of a counterparty, the messages its old switch accepted since
    /// the previous check were queued again for its new one (Switch spec 8.1).
    ResendAfterLoss {
        /// The counterparty.
        identity: [u8; 32],
        /// How many messages.
        messages: u64,
    },
    /// The app took a newer write of a shared record (Switch spec 10.3).
    RecordChanged {
        /// The record key.
        key: [u8; 32],
    },
    /// A shared record write failed a check, or went back on what the app had seen: it is
    /// ignored and shown with the app that signed it (Switch spec 8.2, 10.3).
    WriteFlagged {
        /// The record key.
        key: [u8; 32],
        /// The app the write names.
        writer: [u8; 16],
        /// The rule, without content.
        reason: String,
    },
    /// The protocol's mark of what the app has seen in a record after a write
    /// ([`super::Protocol::record_seen`]) was over [`super::MAX_SEEN_MARK_BYTES`], so the
    /// record's writes can't be checked against what the app has seen from that write on
    /// (Switch spec 8.2). For another app's write the record keeps the mark it held, so
    /// what was seen before is still checked; for an own write the mark held goes. A duty
    /// event, of the class of [`AppEvent::WriteFlagged`].
    RecordUncheckable {
        /// The duty event's ID.
        id: EventId,
        /// The record key.
        key: [u8; 32],
        /// The app the write names.
        writer: [u8; 16],
        /// The write's generation and `seq`.
        version: pubky_switch_core::ops::RecordVersion,
        /// The size of the mark that wasn't kept.
        mark_bytes: u64,
    },
    /// Uploads after a provider loss conflict with a record's current write (Switch spec
    /// 12.6).
    RecordDivergent {
        /// The record key.
        key: [u8; 32],
    },
    /// The app kept a newer view or proof of a claim (Switch spec 10.2).
    ClaimChanged {
        /// The claim key.
        claim_key: [u8; 32],
    },
    /// The deadline a claim pinned differs from the one the app computes for its
    /// obligation: an early pin, or "none" beside a deadline (Switch wire 6.8).
    ClaimPinDiffers {
        /// The claim key.
        claim_key: [u8; 32],
    },
    /// A batch kept from an earlier call was sent again and refused for good: it was not
    /// applied, and the app no longer keeps it, nor the local writes and outbox messages it
    /// carried (Switch spec 6.4, Switch wire 6.4). A duty event.
    BatchRefused {
        /// The duty event's ID.
        id: EventId,
        /// The batch ID.
        batch_id: [u8; 16],
        /// The error code of the refusal.
        code: String,
    },
    /// An attempt sent again from a kept batch was applied, but its proof doesn't show the
    /// app's own open attempt: the app wrote it `failed`, and the protocol doesn't carry it
    /// out (Switch wire 6.5 "Binding").
    AttemptNotHeld {
        /// The claim key.
        claim_key: [u8; 32],
        /// The attempt.
        attempt_id: [u8; 16],
    },
}

impl AppEvent {
    /// The ID of a duty event, which the store keeps until acknowledged; `None` for an
    /// informational event (module docs, "Duty events").
    pub fn id(&self) -> Option<EventId> {
        match self {
            Self::Parked { id, .. } => *id,
            Self::EffectRefused { id, .. }
            | Self::EffectUncertain { id, .. }
            | Self::KeptBatchDropped { id, .. }
            | Self::BatchRefused { id, .. }
            | Self::RestoreLeftBehind { id, .. }
            | Self::AttemptDropped { id, .. }
            | Self::MessageUndelivered { id, .. }
            | Self::RecordUncheckable { id, .. }
            | Self::LocalWritesRefused { id, .. } => Some(*id),
            _ => None,
        }
    }

    /// Whether this is a duty event: one the spec has the app tell its protocol, kept in
    /// the store and delivered until acknowledged (module docs, "Duty events").
    pub fn is_duty(&self) -> bool {
        self.id().is_some()
    }
}

/// A protocol call whose local writes were over the bound
/// ([`AppEvent::LocalWritesRefused`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefusedCall {
    /// [`super::Protocol::resend_needed`], about the feed item at `seq`.
    ResendNeeded {
        /// The feed item's `seq`.
        seq: u64,
        /// What the call asked.
        needed: ResendNeeded,
    },
    /// [`super::Protocol::missed`].
    Missed(MissedEntries),
    /// [`super::Protocol::provider_lost`], its [`super::LossActions::local`], at this loss;
    /// the loss went on without them.
    ProviderLost(ProviderLoss),
}

/// A [`RefusedCall`] as a duty event keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum KeptRefusal {
    Owed {
        seq: u64,
        call: OwedCall,
    },
    Loss {
        lost_generation: u64,
        generation: u64,
        declared_at_ms: u64,
        accepted_from_ms: u64,
        uncertain_until_ms: u64,
    },
}

impl KeptRefusal {
    fn call(self) -> RefusedCall {
        match self {
            Self::Owed { seq, call } => call.refused(seq),
            Self::Loss {
                lost_generation,
                generation,
                declared_at_ms,
                accepted_from_ms,
                uncertain_until_ms,
            } => RefusedCall::ProviderLost(ProviderLoss {
                lost_generation,
                generation,
                declared_at_ms,
                accepted_from_ms,
                uncertain_until_ms,
            }),
        }
    }
}

/// An `attempt` on a claim (Switch wire 6.8), named by its claim key and attempt ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClaimAttempt {
    /// The claim key.
    #[serde(with = "serde_b64")]
    pub claim_key: [u8; 32],
    /// The attempt.
    #[serde(with = "serde_b64")]
    pub attempt_id: [u8; 16],
}

/// `duty/<id>`: a duty event as the store keeps it, its ID in its key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Duty {
    Parked {
        seq: u64,
        reason: ParkReason,
    },
    EffectRefused {
        seq: u64,
        #[serde(with = "serde_b64")]
        sender: [u8; 32],
        msg_id: String,
        kind: String,
        code: Option<String>,
    },
    EffectUncertain {
        seq: u64,
        #[serde(with = "serde_b64")]
        sender: [u8; 32],
        msg_id: String,
        kind: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        attempts: Vec<ClaimAttempt>,
    },
    KeptBatchDropped {
        #[serde(with = "serde_b64")]
        batch_id: [u8; 16],
    },
    BatchRefused {
        #[serde(with = "serde_b64")]
        batch_id: [u8; 16],
        code: String,
    },
    AttemptDropped {
        #[serde(with = "serde_b64")]
        claim_key: [u8; 32],
        #[serde(with = "serde_b64")]
        attempt_id: [u8; 16],
    },
    MessageUndelivered {
        msg_id: String,
        resend: bool,
    },
    LocalWritesRefused {
        call: KeptRefusal,
    },
    RecordUncheckable {
        #[serde(with = "serde_b64")]
        key: [u8; 32],
        #[serde(with = "serde_b64")]
        writer: [u8; 16],
        generation: u64,
        version: u64,
        mark_bytes: u64,
    },
    RestoreLeftBehind {
        duty_events: u64,
        owed_calls: u64,
    },
}

impl Duty {
    /// The event reported for it, with its ID.
    pub(crate) fn event(self, id: EventId) -> AppEvent {
        match self {
            Self::Parked { seq, reason } => AppEvent::Parked {
                id: Some(id),
                seq,
                reason,
            },
            Self::EffectRefused {
                seq,
                sender,
                msg_id,
                kind,
                code,
            } => AppEvent::EffectRefused {
                id,
                seq,
                sender,
                msg_id,
                kind,
                code,
            },
            Self::EffectUncertain {
                seq,
                sender,
                msg_id,
                kind,
                attempts,
            } => AppEvent::EffectUncertain {
                id,
                seq,
                sender,
                msg_id,
                kind,
                attempts,
            },
            Self::KeptBatchDropped { batch_id } => AppEvent::KeptBatchDropped { id, batch_id },
            Self::BatchRefused { batch_id, code } => AppEvent::BatchRefused { id, batch_id, code },
            Self::AttemptDropped {
                claim_key,
                attempt_id,
            } => AppEvent::AttemptDropped {
                id,
                claim_key,
                attempt_id,
            },
            Self::MessageUndelivered { msg_id, resend } => {
                AppEvent::MessageUndelivered { id, msg_id, resend }
            }
            Self::LocalWritesRefused { call } => AppEvent::LocalWritesRefused {
                id,
                call: call.call(),
            },
            Self::RecordUncheckable {
                key,
                writer,
                generation,
                version,
                mark_bytes,
            } => AppEvent::RecordUncheckable {
                id,
                key,
                writer,
                version: pubky_switch_core::ops::RecordVersion::new(generation, version),
                mark_bytes,
            },
            Self::RestoreLeftBehind {
                duty_events,
                owed_calls,
            } => AppEvent::RestoreLeftBehind {
                id,
                duty_events,
                owed_calls,
            },
        }
    }
}

/// Why a backup was refused ([`AppEvent::BackupRefused`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackupRefusal {
    /// The restore's one commit wouldn't fit the store's value or batch size: the layer, or
    /// the entries stored locally and the processed pairs it carries, are too large for now.
    TooLarge,
}

/// Why an entry was stored locally (Switch spec 8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum ParkReason {
    /// Its sender couldn't be checked within the bounded wait.
    Unverifiable,
    /// Its shared record write hit a per-kind limit, the storage quota or the value size.
    Quota,
    /// Its effect's batch was refused for good (Switch spec 6.4): it is kept, not applied,
    /// and not tried again.
    Refused,
    /// Its effect has more operations than one batch takes with the cursor move (Switch
    /// wire 6.4): it is kept, not applied, and not tried again.
    TooManyOperations,
    /// Its effect is too large for the app to keep before it sends it, or to commit with
    /// its outcome: the kept effect over the store's value size
    /// ([`crate::store::MAX_VALUE_BYTES`]), or its local writes over what one commit takes
    /// ([`crate::store::MAX_BATCH_BYTES`]) (Switch spec 8.2). The same effect is refused
    /// again however often it is built: it is kept, not applied, and not tried again
    /// ([`AppEvent::EffectRefused`]).
    EffectTooLarge,
    /// Its receive step asked for more reads from the switch than one entry gets
    /// ([`super::MAX_CLAIM_READS`]), or again for what it was given: it is kept, not
    /// applied, and not tried again.
    TooManyReads,
    /// Its effect carries an operation the app layer builds itself (`app.put`,
    /// `receive_key.put`, `key_bundle.put`, `cert.put`), which a protocol may not write: it
    /// is kept, not applied, and not tried again ([`AppEvent::EffectRefused`]).
    LifecycleOperation,
    /// Its receive step was retried for want of the store ([`super::Outcome::Retry`],
    /// [`super::StoreFailure::unavailable`]) for longer than the bounded wait: it is tried
    /// again at every read.
    StoreUnavailable,
    /// The store failed for its receive step in a way that retrying can't mend
    /// ([`super::StoreFailure::of_entry`]), such as a corrupt value: it is tried again at
    /// every read, in case the host repaired it.
    StoreRejected,
    /// Its effect was kept unanswered longer than a resend's answer can tell whether it was
    /// applied (Switch spec 12.5 "Kept batches"): it is kept, and not tried again
    /// ([`AppEvent::EffectUncertain`]).
    Uncertain,
}

impl ParkReason {
    /// Whether an entry stored for this reason is processed again by a later read: one
    /// whose sender couldn't be checked, whose write hit a quota, or whose receive step
    /// the store kept from finishing. The others stay stored until the protocol acts on
    /// them.
    pub fn tried_again(self) -> bool {
        matches!(
            self,
            Self::Unverifiable | Self::Quota | Self::StoreUnavailable | Self::StoreRejected
        )
    }
}
