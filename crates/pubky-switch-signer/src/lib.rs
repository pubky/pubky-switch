//! Identity management for the Pubky Switch: the side of the signer, which holds the identity
//! key.
//!
//! The signer enrolls the identity at a Switch, approves apps and signs their certificates,
//! signs `identity.json`, derives Shared Data Keys and writes key bundles, and carries out
//! revocation, key rotation, freeze, recovery and the hand-over to another signer.
//!
//! The behaviour is specified by the Pubky Switch spec and wire format, in this repository's
//! `spec/`.
