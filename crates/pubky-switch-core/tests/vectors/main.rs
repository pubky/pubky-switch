//! The Switch's test vectors (`spec/vectors/`): one test per vector file.
//!
//! Each test reads its file from the spec, never a copy, and rebuilds every deterministic
//! value byte for byte from the fixed keys, and refuses every rejection case for its rule.
//! The scopes, message kinds and collections in the files are a protocol's sample data,
//! which these tests read from the files and treat as opaque strings.

// The helpers outside `#[test]` functions read fixed vector files, where a failure is a test
// failure: the workspace's no-panic lints don't apply to them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

mod encoding;
mod envelopes;
mod identifiers;
mod keys;
mod sealed;
mod signatures;
