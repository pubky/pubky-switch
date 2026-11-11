//! The shared core of the Pubky Switch: its formats, encodings, signatures and verification.
//!
//! The service, the client and the signer all build on this crate, so that each of them
//! encodes, signs and checks every Switch document the same way: app certificates and records,
//! `identity.json`, receive key records, key bundles, envelopes, signed operations and
//! batches, claims, shared records, transition proofs, the chain and signed heads.
//!
//! The formats are specified by the Pubky Switch wire format, in this repository's `spec/`,
//! and checked against its test vectors.
//!
//! The crate is pure: it does no I/O and reads no clock. Every function that depends on time
//! takes it as an argument, in Unix milliseconds. Scope names, message kinds and collections
//! are a protocol's, and the crate reads them only as opaque strings (Switch spec 1).

pub mod chain;
pub mod claims;
pub mod enc;
pub mod envelope;
pub mod error;
pub mod export;
pub mod http;
pub mod ident;
pub mod json;
pub mod keys;
pub mod labels;
pub mod message;
pub mod net;
pub mod ops;
pub mod receive;
pub mod records;
pub mod recovery;
pub mod scopes;
pub mod sealed;
pub mod shared;
pub mod sig;
pub mod signing;
pub mod time;

pub use error::{Error, Result, SizeRefusal};

/// The folder of the spec's test vectors (`spec/vectors/`) at this crate's revision, for the
/// tests of a protocol built on the Switch, whose own vectors build on these.
///
/// Test-only: it exists only with the `test-vectors` feature, and names a path in the source
/// tree this crate was built from.
#[cfg(feature = "test-vectors")]
pub fn spec_vectors_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}
