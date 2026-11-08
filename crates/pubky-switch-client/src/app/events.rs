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
}

/// Why an entry was stored locally (Switch spec 8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum ParkReason {
    /// Its sender couldn't be checked within the bounded wait.
    Unverifiable,
    /// Its shared record write hit a per-kind limit, the storage quota or the value size.
    Quota,
}
