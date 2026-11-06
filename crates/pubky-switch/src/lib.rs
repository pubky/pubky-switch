//! The Pubky Switch: an inbox and coordination service for Pubky identities.
//!
//! One Switch hosts many identities, each with its own account. For each identity it keeps:
//!
//! - a sealed inbox, where admitted senders append signed, encrypted messages that the
//!   identity's own apps read in order from their feed;
//! - the claims and shared records the identity's own apps coordinate through, changed by
//!   batches of signed operations and answered with transition proofs and signed heads;
//! - the directory: the identity's newest `identity.json`, its apps' records, receive keys
//!   and key bundles.
//!
//! This crate holds the protocol-neutral service: storage, the HTTP API and operations. The
//! rules of a particular protocol, such as its scopes, the record policies of its collections
//! and its message kinds, come from a protocol profile the service is configured with; the
//! Paykit v0.2 profile is the `pubky-switch-paykit` crate.
//!
//! The behaviour is specified by the Paykit v0.2 specification (spec 6) and its wire format
//! (wire 6 to 11), in `specs/v0.2/` of `pubky/paykit-rs`.
