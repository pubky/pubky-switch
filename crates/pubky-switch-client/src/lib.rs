//! The client side of the Pubky Switch, for apps that act for an identity.
//!
//! An app uses it to sign its requests, append messages to a counterparty's inbox, read its
//! own feed, and coordinate with the identity's other apps through claims and shared records.
//! The signer uses it for its own calls: enrollment, `identity.json` deliveries, moves and
//! erasure.
//!
//! The behaviour is specified by the Pubky Switch spec and wire format, in this repository's
//! `spec/`. Formats, signatures and verification come from `pubky-switch-core`.
//!
//! - [`store`]: the [`store::StateStore`] trait a host implements once per install, its
//!   write batches, an in-memory store and an async handle.
//! - [`clock`]: the [`clock::Clock`] the client takes every time from.
//! - [`transport`]: plain requests and responses, the [`transport::Transport`] trait and,
//!   with the `http` feature, the HTTPS transport that connects only to public addresses.
//! - [`client`]: the [`client::SwitchClient`], which signs every request, checks every
//!   answer against the pinned service key before using it, and offers a typed call for
//!   every endpoint, with batches that are signed once and resent byte for byte.
//! - [`error`]: one error type per layer.
//! - `testing` (`test-support` feature, tests only): a scripted switch and the fixtures to
//!   drive the app layer against it, for the tests of this crate and of crates built on it.
//! - [`app`]: the app layer, which runs one app of an identity on top of the Switch: its
//!   keys, its own `identity.json`, its receive keys, its key bundles and its feed, with all
//!   durable state in the [`store::StateStore`] (Switch spec 3, 8, 11, 12).
//!
//! Async is used only at the network edge; every public type is plain owned data.

pub mod app;
pub mod client;
pub mod clock;
pub mod error;
pub mod store;
#[cfg(feature = "test-support")]
pub mod testing;
pub mod transport;

pub use client::{Credentials, SwitchClient};
pub use error::{BatchError, ClientError, StoreError, TransportError};
