//! A store that can be copied as it stood earlier: for a party whose device is put back to
//! an older state, as by a device backup restored.

use std::sync::{Mutex, MutexGuard, PoisonError};

use pubky_switch_client::error::StoreError;
use pubky_switch_client::store::{KeyValue, MemoryStore, StateStore, WriteBatch};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A store in memory that keeps every batch it committed, in order.
#[derive(Debug, Default)]
pub struct KeptCommits {
    store: MemoryStore,
    committed: Mutex<Vec<WriteBatch>>,
}

impl KeptCommits {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many batches the store has committed.
    pub fn commits(&self) -> usize {
        lock(&self.committed).len()
    }

    /// A store as this one stood after its first `commits` batches: what a device put back
    /// to that moment holds.
    ///
    /// # Errors
    ///
    /// When a batch doesn't commit again.
    pub fn as_of(&self, commits: usize) -> Result<MemoryStore, StoreError> {
        let earlier = MemoryStore::new();
        for batch in lock(&self.committed).iter().take(commits) {
            earlier.commit(batch.clone())?;
        }
        Ok(earlier)
    }
}

impl StateStore for KeptCommits {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.store.get(ns, key)
    }

    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<KeyValue>, StoreError> {
        self.store.scan(ns, prefix, after, limit)
    }

    fn commit(&self, batch: WriteBatch) -> Result<(), StoreError> {
        // One lock over both, so the kept batches are in the order they were applied.
        let mut committed = lock(&self.committed);
        self.store.commit(batch.clone())?;
        committed.push(batch);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(key: &[u8], value: &[u8]) -> WriteBatch {
        let mut batch = WriteBatch::default();
        batch.put("ns", key, value).unwrap();
        batch
    }

    #[test]
    fn test_kept_commits_copy_stands_as_the_store_did_then() {
        let store = KeptCommits::new();
        store.commit(batch(b"a", b"1")).unwrap();
        store.commit(batch(b"b", b"2")).unwrap();
        store.commit(batch(b"a", b"3")).unwrap();
        assert_eq!(store.commits(), 3);
        assert_eq!(store.get("ns", b"a").unwrap(), Some(b"3".to_vec()));
        // After its first two batches: the first value of `a`, and `b`.
        let earlier = store.as_of(2).unwrap();
        assert_eq!(earlier.get("ns", b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(earlier.get("ns", b"b").unwrap(), Some(b"2".to_vec()));
        // Before any: nothing. The copy is its own store: the original isn't touched.
        assert_eq!(store.as_of(0).unwrap().get("ns", b"a").unwrap(), None);
        earlier.commit(batch(b"a", b"9")).unwrap();
        assert_eq!(store.get("ns", b"a").unwrap(), Some(b"3".to_vec()));
    }
}
