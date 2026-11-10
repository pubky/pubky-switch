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
//! - [`error`]: the typed errors.

pub mod error;
pub mod key;
pub mod protocol;

pub use error::{Refusal, Result, SignerError};
pub use key::{
    AddOutcome, ExportReason, IdentityKeyring, IdentitySecret, KeyError, SecretVault, VaultError,
};
pub use protocol::{GrantPath, Protocol, ProtocolError, Protocols, ScopeDef, ScopeTerms};
