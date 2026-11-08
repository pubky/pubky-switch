//! The signer's error type.
//!
//! Every failure has a typed variant, so a host can tell a refusal it shows the user from a
//! key or storage failure it reports. Messages name the rule that failed and never carry a
//! secret, and they don't repeat the text of a document or request that failed a check.

use crate::key::KeyError;
use crate::protocol::ProtocolError;

/// A failure of the signer.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
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
}

/// The signer's result type.
pub type Result<T> = std::result::Result<T, SignerError>;
