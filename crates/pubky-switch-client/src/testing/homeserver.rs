//! A Homeserver of public files, in memory, failing on demand.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use pubky_switch_core::records::{IDENTITY_PATH, IdentityDoc};
use pubky_switch_core::sig::SignedDoc;

use super::ScriptError;
use crate::app::HomeserverReader;
use crate::error::TransportError;
use crate::transport::BoxFuture;

/// Public files by identity and path.
type Files = HashMap<([u8; 32], String), Vec<u8>>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The Homeservers of every identity in a test: public files by identity and path, read
/// through [`HomeserverReader`]. While it is down, every read fails to connect. Each read is
/// counted, by identity and path, whether it reached them or not.
#[derive(Debug, Default)]
pub struct TestHomeserver {
    files: Mutex<Files>,
    down: Mutex<bool>,
    reads: Mutex<HashMap<([u8; 32], String), u64>>,
}

impl TestHomeserver {
    /// Homeservers with no files.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish `doc` at its identity's `identity.json` path, replacing what was there.
    ///
    /// # Errors
    ///
    /// When the document doesn't serialize.
    pub fn publish(&self, doc: &IdentityDoc) -> Result<(), ScriptError> {
        let bytes = serde_json::to_vec(doc.signed())?;
        self.put(doc.identity(), IDENTITY_PATH, bytes);
        Ok(())
    }

    /// Put `bytes` at `path` on `identity`'s Homeserver.
    pub fn put(&self, identity: [u8; 32], path: &str, bytes: Vec<u8>) {
        lock(&self.files).insert((identity, path.to_owned()), bytes);
    }

    /// Delete the file at `path` on `identity`'s Homeserver.
    pub fn remove(&self, identity: [u8; 32], path: &str) {
        lock(&self.files).remove(&(identity, path.to_owned()));
    }

    /// The bytes at `path` on `identity`'s Homeserver.
    pub fn file(&self, identity: [u8; 32], path: &str) -> Option<Vec<u8>> {
        lock(&self.files).get(&(identity, path.to_owned())).cloned()
    }

    /// The `identity.json` published for `identity`, verified; `None` when there is none or
    /// it doesn't verify.
    pub fn identity_doc(&self, identity: &[u8; 32]) -> Option<IdentityDoc> {
        let bytes = self.file(*identity, IDENTITY_PATH)?;
        let signed: SignedDoc = serde_json::from_slice(&bytes).ok()?;
        IdentityDoc::verify(&signed, identity).ok()
    }

    /// How many times `identity`'s `identity.json` was read, reached or not.
    pub fn identity_reads(&self, identity: &[u8; 32]) -> u64 {
        lock(&self.reads)
            .get(&(*identity, IDENTITY_PATH.to_owned()))
            .copied()
            .unwrap_or(0)
    }

    /// Take every Homeserver down, or bring them back.
    pub fn set_down(&self, down: bool) {
        *lock(&self.down) = down;
    }
}

impl HomeserverReader for TestHomeserver {
    fn get(
        &self,
        identity: [u8; 32],
        path: String,
    ) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        {
            let mut reads = lock(&self.reads);
            let count = reads.entry((identity, path.clone())).or_insert(0);
            *count = count.saturating_add(1);
        }
        let answer = if *lock(&self.down) {
            Err(TransportError::Connect("down".into()))
        } else {
            Ok(lock(&self.files).get(&(identity, path)).cloned())
        };
        Box::pin(async move { answer })
    }
}
