//! The identity's own Homeserver, as the signer reads and writes it (Switch spec 4.1).
//!
//! The signer writes two files there, which only it writes and no app's grant covers (Switch
//! spec 3.4): `identity.json` (Switch wire 3.3), public, and the signer's backup (Switch wire
//! 3.13), under `/priv`, which the Homeserver serves to the identity's own session only. It also deletes a removed app's record, which the app wrote under its own grant
//! (Switch spec 12.2 step 4), and, when the account is erased, `identity.json` and every app
//! record it knows of (Switch spec 12.7 step 5). The host implements [`Homeserver`] on its
//! Pubky client, with the identity's own session; how it signs in, and the request deadlines,
//! are the host's.

use pubky_switch_client::TransportError;
use pubky_switch_client::transport::BoxFuture;

/// The identity's Homeserver, through the host's Pubky session for the identity.
///
/// Object-safe; the signer holds an `Arc<dyn Homeserver>`. Paths are absolute, such as
/// `/pub/pubky-switch/v1/identity.json` and `/priv/pubky-switch/v1/signer-backup.json`.
pub trait Homeserver: Send + Sync {
    /// The bytes of the identity's file at `path`, `None` when there is no such file. A `/priv`
    /// path is read with the identity's own session.
    ///
    /// # Errors
    ///
    /// A [`TransportError`] when the Homeserver can't be read now.
    fn get(&self, path: &str) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>>;

    /// Write `bytes` as the identity's file at `path`, replacing what is there. `Ok` means the
    /// Homeserver took the write.
    ///
    /// # Errors
    ///
    /// A [`TransportError`] when the write failed or may not have arrived; the signer writes
    /// the same bytes again.
    fn put(&self, path: &str, bytes: Vec<u8>) -> BoxFuture<'_, Result<(), TransportError>>;

    /// Delete the identity's file at `path`. `Ok` also when there is no such file.
    ///
    /// # Errors
    ///
    /// A [`TransportError`] when the deletion failed or may not have arrived; the signer
    /// deletes again.
    fn delete(&self, path: &str) -> BoxFuture<'_, Result<(), TransportError>>;
}
