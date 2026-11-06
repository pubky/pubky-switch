//! The shared core of the Pubky Switch: its formats, encodings, signatures and verification.
//!
//! The service, the client and the signer all build on this crate, so that each of them
//! encodes, signs and checks every Switch document the same way: app certificates and records,
//! `identity.json`, receive key records, key bundles, envelopes, signed operations, transition
//! proofs and signed heads.
//!
//! The formats are specified by the Pubky Switch wire format, in this repository's `spec/`,
//! and checked against its test vectors.
//!
//! The crate is pure: it does no I/O and reads no clock. Every function that depends on time
//! takes it as an argument, in Unix milliseconds. Scope names, message kinds and collections
//! are a protocol's, and the crate reads them only as opaque strings (Switch spec 1).

pub mod enc;
pub mod error;
pub mod http;
pub mod ident;
pub mod json;
pub mod keys;
pub mod labels;
pub mod net;
pub mod sig;
pub mod signing;
pub mod time;

pub use error::{Error, Result};
