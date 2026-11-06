//! The shared core of the Pubky Switch: its formats, encodings, signatures and verification.
//!
//! The service, the client and the signer all build on this crate, so that each of them
//! encodes, signs and checks every Switch document the same way: app certificates and records,
//! `identity.json`, receive key records, key bundles, envelopes, signed operations, transition
//! proofs and signed heads.
//!
//! The formats are specified by the Pubky Switch wire format, in this repository's `spec/`,
//! and checked against its test vectors.
