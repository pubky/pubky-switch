//! Identity management for the Pubky Switch: the side of the signer, which holds the identity
//! key.
//!
//! The signer enrolls the identity at a Switch, approves apps and signs their certificates,
//! signs `identity.json`, derives Shared Data Keys and writes key bundles, and carries out
//! revocation, key rotation, freeze, recovery and the hand-over to another signer.
//!
//! The behaviour is specified by the Pubky Switch spec and wire format, in this repository's
//! `spec/`. The design is in `docs/signer-design.md`.
//!
//! # What is here so far
//!
//! - [`key`]: the identity key interface. The host keeps the 32-byte secret in the device's
//!   secure storage behind a [`SecretVault`], and the crate does every signature and
//!   derivation itself, only over inputs it builds (Switch wire 2.1).
//! - [`protocol`]: the protocols on the Switch the host registers, which tell the signer
//!   their scopes, the switch permissions those need and which have Shared Data Keys
//!   (Switch spec 1). The signer knows no protocol of its own.
//! - [`Signer`]: enrolling the identity at a switch, and signing, delivering and publishing
//!   its `identity.json` versions with the high-water mark, the one-signer rule and the
//!   backup, each step committed to the host's store before it is sent (Switch spec 4.3, 12.8).
//! - [`homeserver`]: the identity's own Homeserver, which the host implements.
//! - [`state`]: the signer's records in the host's store.
//! - [`alert`]: what the signer tells the user.
//! - [`error`]: the typed errors.

pub mod alert;
pub mod error;
pub mod homeserver;
pub mod key;
pub mod protocol;
mod signer;
pub mod state;

pub use alert::{Alert, Source};
pub use error::{Refusal, Result, SignerError};
pub use homeserver::Homeserver;
pub use key::{
    AddOutcome, ExportReason, IdentityKeyring, IdentitySecret, KeyError, SecretVault, VaultError,
};
pub use protocol::{GrantPath, Protocol, ProtocolError, Protocols, ScopeDef, ScopeTerms};
pub use signer::{HighWater, Signer, SignerEnv, SignerStatus};
