//! The signer's error type.
//!
//! Every failure has a typed variant, so a host can tell a refusal it shows the user from a
//! key or storage failure it reports. Messages name the rule that failed and never carry a
//! secret, and they don't repeat the text of a document or request that failed a check.

use pubky_switch_client::{ClientError, StoreError, TransportError};

use crate::alert::Alert;
use crate::key::KeyError;
use crate::protocol::ProtocolError;

/// A failure of the signer.
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
#[non_exhaustive]
pub enum SignerError {
    /// The identity key couldn't be loaded, stored or used.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// A rule refused what was asked: the signer shows the user why.
    #[error(transparent)]
    Refused(#[from] Refusal),
    /// A protocol the host registered is malformed, or gave the signer something the Switch's
    /// rules don't allow. This is a fault of the host's set-up, not of the request.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// Data that didn't verify or parse, such as a document from the network.
    #[error("invalid data: {0}")]
    InvalidData(#[from] pubky_switch_core::Error),
    /// A call to the switch failed. A call that may not have arrived is resent with the same
    /// bytes by [`crate::Signer::resume`].
    #[error(transparent)]
    Switch(#[from] ClientError),
    /// The identity's Homeserver couldn't be read or written.
    #[error("homeserver: {0}")]
    Homeserver(TransportError),
    /// The host's store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The signer's own records in the store don't read: they are corrupt or of another
    /// version.
    #[error("the signer's records don't read: {0}")]
    Records(String),
    /// Another install is the identity's signer, as the newest `identity.json` or the backup
    /// names it, so this one signs nothing until the user has it take over (Switch spec 4.3,
    /// 12.8).
    #[error("another install is the identity's signer")]
    NotNamed {
        /// That install's signer ID.
        install: [u8; 16],
    },
    /// A rollback or an equivocation: the signer shows it to the user instead of building on
    /// it (Switch spec 4.3, Switch wire 3.3 "Never back").
    #[error("alarm: {0:?}")]
    Alarm(Alert),
    /// The hand-over took effect: the switch holds the version after the one handed over,
    /// naming `install`, so this install deleted the identity key and its records (Switch
    /// wire 3.12, Switch spec 12.8). That install is the hand-over's target, or one that
    /// restored the target's backup in the meantime: the switch's copy can't tell them apart.
    #[error("the identity was handed over, and this install deleted its key and records")]
    HandedOver {
        /// The signer ID the switch's copy names.
        install: [u8; 16],
    },
}

/// A rule of the Switch or of a protocol said no.
///
/// The `Display` text names the rule only. The fields carry what a host shows the user, such as
/// the scopes no registered protocol owns.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The scopes break the Switch's scope rule: at most 32, each a name or `name:<sub>`, each
    /// once, and never a name beside one of its own sub-scopes (Switch spec 3.3, Switch wire
    /// 3.1). The reason is the core's, naming the part of the rule that failed.
    #[error("refused: {0}")]
    Scopes(String),
    /// Scopes whose names no registered protocol owns (Switch wire 3.9 step 1). The host tells
    /// the user which protocol support is missing.
    #[error("refused: {} scope(s) that no registered protocol owns", scopes.len())]
    UnknownScopes {
        /// The scopes, in the order they were asked for.
        scopes: Vec<String>,
    },
    /// A protocol's own rule on its scopes refused them (Switch spec 1).
    #[error("refused by the rules of protocol {protocol}: {reason}")]
    ProtocolRule {
        /// The protocol's name.
        protocol: String,
        /// The protocol's reason.
        reason: String,
    },
    /// The app request fails a check of Switch wire 3.9: the reason names the step.
    #[error("refused: {0}")]
    AppRequest(String),
    /// The app isn't listed in the newest `identity.json`, so it has no certificate to renew.
    #[error("refused: the app isn't listed")]
    NotListed,
    /// The approval's version is delivered, but its claim is held: the switch isn't confirmed
    /// to hold the signer's newest version since a rollback or an equivocation, named here
    /// when its alert is still held ([`crate::Signer::clear_alert`]).
    #[error("refused: the claim is held until the switch is confirmed")]
    ClaimHeld {
        /// The rollback or equivocation alert behind it, if still held.
        alert: Option<crate::alert::Alert>,
    },
    /// The app hasn't joined: the switch holds no record of it, so it takes no certificate or
    /// bundle for it yet (Switch wire 6.2, spec 12.1 step 2).
    #[error("refused: the app hasn't joined the switch")]
    NotJoined,
    /// The store already holds this identity's signer records, so it isn't set up again.
    #[error("refused: the signer is already set up for this identity")]
    AlreadySetUp,
    /// This install's records are behind a newer `identity.json` it signed itself, so it
    /// signs nothing until they are restored from the signer backup (Switch wire 3.13).
    #[error("refused: this install's records are behind its own version {version}")]
    RecordsBehind {
        /// The newer version.
        version: u64,
    },
    /// That App ID is revoked, being revoked, or seen departing: it gets no new certificate
    /// or key (Switch spec 12.2).
    #[error("refused: the App ID is revoked or being revoked")]
    CutOff,
    /// This install is handing the identity over to the app `to_app`: it signs nothing but
    /// the abort until the hand-over takes effect or is aborted (Switch wire 3.12).
    #[error("refused: the identity is being handed over")]
    HandingOver {
        /// The new signer's App ID.
        to_app: [u8; 16],
    },
    /// The device clock and the switch's signed time differ by more than the clock tolerance
    /// (Switch spec 10.1): a certificate would be stamped with a time the switch doesn't
    /// share, so none is issued or renewed until they agree.
    #[error("refused: the device clock is off the switch's time")]
    ClockOff {
        /// The device clock, in Unix milliseconds.
        device_ms: u64,
        /// The switch's signed time, in Unix milliseconds.
        switch_ms: u64,
    },
    /// No hand-over is in progress to abort.
    #[error("refused: no hand-over is in progress")]
    NotHandingOver,
    /// This install is taking the identity over: it signs nothing but its first delivery
    /// until that has won (Switch wire 3.12).
    #[error("refused: the identity is being taken over")]
    TakingOver,
    /// The target of a hand-over isn't current at the switch with the certificate the newest
    /// `identity.json` lists for it (Switch wire 3.12, 7.4.17).
    #[error("refused: the hand-over's target isn't current")]
    TargetNotCurrent,
    /// A revocation is asked for whose version isn't delivered yet: no hand-over until it is.
    /// The hand-over carries the records, not a revocation in progress, so one the switch
    /// hadn't taken would never be sent (Switch spec 12.2, Switch wire 3.12).
    #[error("refused: a revocation is owed")]
    RevocationOwed,
    /// A reduction's closing delivery is owed: no hand-over until it is made (Switch wire
    /// 3.12).
    #[error("refused: a closing delivery is owed")]
    ClosingOwed,
    /// The take-over's check 3 failed (Switch wire 3.12): the switch's copy of `identity.json`
    /// isn't the version handed over, or the Homeserver's is newer or another at its version.
    /// An abort that won, a newer version, or a switch that went back. Nothing was sent, and
    /// nothing received is kept.
    #[error("refused: the switch's or the Homeserver's copy isn't the version handed over")]
    StaleHandOver,
    /// The switch holds a newer version naming `install`, but the proof that it holds the
    /// identity isn't there yet: its signer backup on the Homeserver, holding a newer version
    /// naming it (Switch wire 3.12). This install signs nothing, as one that isn't named,
    /// keeps the key and the hand-over, and looks for the proof again at each run; if that
    /// install is lost, the user takes the identity back ([`crate::Signer::take_back`]).
    #[error("refused: another install's version holds no proof yet")]
    SuccessorUnproven {
        /// The signer ID the switch's copy names.
        install: [u8; 16],
    },
    /// Nothing to take back: the switch doesn't show another install's version after the one
    /// handed over, or that install's proof is there, or no hand-over is in progress (Switch
    /// wire 3.12).
    #[error("refused: nothing to take back")]
    NothingToTakeBack,
    /// The store holds no take-over in progress for this identity.
    #[error("refused: no take-over is in progress")]
    NotTakingOver,
    /// The take-over was cancelled: the switch holds a newer version that isn't this
    /// install's first delivery, as after an abort (Switch wire 3.12). What was received, the
    /// records and the take-over, are deleted.
    #[error("refused: the take-over was cancelled")]
    TakeOverCancelled,
    /// The Homeserver holds no signer backup to restore from (Switch wire 3.13).
    #[error("refused: there is no signer backup")]
    NoBackup,
    /// The signer backup is stale: the switch holds another version than the backup's or
    /// the one it builds on, or the Homeserver a newer one or another at its version (Switch
    /// wire 3.13 "Restoring").
    #[error("refused: the signer backup is stale")]
    StaleBackup,
    /// The newest `identity.json` doesn't list that App ID in `removed`.
    #[error("refused: the App ID isn't in removed")]
    NotRemoved,
    /// An alarm's alert was cleared, and the re-delivery that confirms the switch holds this
    /// signer's newest version hasn't succeeded yet: nothing new is signed until it has
    /// ([`crate::Signer::resume`] sends it).
    #[error("refused: the switch isn't confirmed since an alarm")]
    SwitchUnconfirmed,
    /// The store holds no signer records for this identity.
    #[error("refused: the signer isn't set up for this identity")]
    NotSetUp,
    /// The Homeserver holds a signer backup this install can't open, found before its first
    /// version was delivered; nothing is written or delivered until the user deals with it
    /// ([`crate::Alert::UnreadableBackupBeforeEnrollment`]).
    #[error("refused: the Homeserver holds a signer backup this install can't open")]
    UnreadableBackup,
    /// A flow is in progress: [`crate::Signer::resume`] finishes it first.
    #[error("refused: a flow is in progress")]
    FlowInProgress,
    /// The switch holds a newer `identity.json` that this install didn't sign, which it
    /// adopted; the change asked for wasn't made, and may be asked for again on top of it
    /// (Switch spec 4.3).
    #[error("refused: the switch holds a newer version, {version}, which the signer adopted")]
    Superseded {
        /// The adopted version.
        version: u64,
    },
}

/// The signer's result type.
pub type Result<T> = std::result::Result<T, SignerError>;
