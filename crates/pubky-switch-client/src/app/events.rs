//! What the app tells its host: [`AppEvent`]s, collected in each call's report. Alarms
//! (Switch spec 3.6, 4.3, 10.1) are also kept in the store until the user resolves them;
//! every other event is shown once.
//!
//! Events carry facts, never wording, and never message content: a host words them.

use super::error::Alarm;

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
    /// An entry was stored locally and the cursor moved past it (Switch spec 8.2): its
    /// sender stayed unverifiable too long, or its write hit a quota.
    Parked {
        /// The entry's `seq`.
        seq: u64,
        /// Why.
        reason: ParkReason,
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
        /// clock tolerance.
        resend_asked: bool,
    },
    /// An entry left unread by a departed own app (Switch spec 8.2).
    Unreadable {
        /// The item's `seq`.
        seq: u64,
        /// Whether a re-send was asked: only for an entry accepted at or before a departure
        /// the app verified in its chain.
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
    /// A kept batch holding an `attempt` wasn't carried to the new service after a provider
    /// loss: no automatic attempt is made on an obligation from before the loss (Switch spec
    /// 12.6 step 5). The protocol decides what to write instead.
    KeptBatchDropped {
        /// The batch ID.
        batch_id: [u8; 16],
    },
    /// The account the app used is gone: the service answers as for an identity it doesn't
    /// host and the identity publishes no `identity.json` (Switch spec 12.7).
    AccountGone,
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
    /// applied, and the app no longer keeps it (Switch spec 6.4, Switch wire 6.4).
    BatchRefused {
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
    /// Its receive step asked for more reads from the switch than one entry gets
    /// ([`super::MAX_CLAIM_READS`]), or again for what it was given: it is kept, not
    /// applied, and not tried again.
    TooManyReads,
}
