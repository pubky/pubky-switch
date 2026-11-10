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
    /// The app request names an App ID listed with the same keys, which would renew its
    /// certificate (Switch wire 3.8, 3.9 step 5); renewals aren't approved through a request
    /// here.
    #[error("refused: the app is listed already")]
    AlreadyListed,
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
