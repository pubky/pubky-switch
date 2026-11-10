//! An in-memory [`StateStore`], for tests and for hosts that keep nothing across restarts.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use super::{StateStore, StoreError, Write, WriteBatch};

type Entries = BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>;

/// A [`StateStore`] in memory.
///
/// It is atomic, ordered and consistent within the process, and refuses a batch over the
/// working sizes as a host does. It isn't durable: everything is gone when it is dropped.
#[derive(Default)]
pub struct MemoryStore {
    entries: Mutex<Entries>,
}

impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemoryStore({} namespaces)", self.lock().len())
    }
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Entries> {
        // A panic while the lock was held can't leave a batch half applied: commits apply
        // to a copy and swap it in. So a poisoned lock still guards consistent entries.
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The number of keys in `ns`.
    pub fn len(&self, ns: &str) -> usize {
        self.lock().get(ns).map_or(0, BTreeMap::len)
    }

    /// Whether `ns` holds no key.
    pub fn is_empty(&self, ns: &str) -> bool {
        self.len(ns) == 0
    }
}

impl StateStore for MemoryStore {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.lock().get(ns).and_then(|keys| keys.get(key)).cloned())
    }

    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<super::KeyValue>, StoreError> {
        let entries = self.lock();
        let Some(keys) = entries.get(ns) else {
            return Ok(Vec::new());
        };
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        Ok(keys
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .filter(|(key, _)| after.is_none_or(|after| key.as_slice() > after))
            .take(limit)
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    fn commit(&self, batch: WriteBatch) -> Result<(), StoreError> {
        batch.check_size().map_err(StoreError::from)?;
        let mut entries = self.lock();
        let mut next = entries.clone();
        for write in batch.writes {
            match write {
                Write::Put { ns, key, value } => {
                    next.entry(ns).or_default().insert(key, value);
                }
                Write::Delete { ns, key } => {
                    if let Some(keys) = next.get_mut(&ns) {
                        keys.remove(&key);
                    }
                }
                Write::DeletePrefix { ns, prefix } => {
                    if let Some(keys) = next.get_mut(&ns) {
                        keys.retain(|key, _| !key.starts_with(&prefix));
                    }
                }
            }
        }
        next.retain(|_, keys| !keys.is_empty());
        *entries = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MAX_VALUE_BYTES;

    fn batch(f: impl FnOnce(&mut WriteBatch)) -> WriteBatch {
        let mut batch = WriteBatch::new();
        f(&mut batch);
        batch
    }

    #[test]
    fn test_memory_store_applies_a_batch_in_order() {
        let store = MemoryStore::new();
        store
            .commit(batch(|b| {
                b.put("ns", b"a".to_vec(), b"1".to_vec()).unwrap();
                b.put("ns", b"a".to_vec(), b"2".to_vec()).unwrap();
                b.put("ns", b"b".to_vec(), b"3".to_vec()).unwrap();
                b.delete("ns", b"b".to_vec()).unwrap();
            }))
            .unwrap();
        assert_eq!(store.get("ns", b"a").unwrap(), Some(b"2".to_vec()));
        assert_eq!(store.get("ns", b"b").unwrap(), None);
        assert_eq!(store.get("other", b"a").unwrap(), None);
    }

    #[test]
    fn test_memory_store_refuses_an_oversized_batch_whole() {
        let store = MemoryStore::new();
        let size = usize::try_from(MAX_VALUE_BYTES).unwrap();
        let mut oversized = WriteBatch::new();
        oversized.put("ns", b"a".to_vec(), b"1".to_vec()).unwrap();
        // Built by hand, past the builder's check.
        oversized.writes.push(Write::Put {
            ns: "ns".into(),
            key: b"b".to_vec(),
            value: vec![0; size + 1],
        });
        assert!(matches!(
            store.commit(oversized),
            Err(StoreError::TooLarge { .. })
        ));
        // Atomic: nothing of it was applied.
        assert_eq!(store.get("ns", b"a").unwrap(), None);
    }

    #[test]
    fn test_memory_store_scans_by_prefix_after_and_limit() {
        let store = MemoryStore::new();
        store
            .commit(batch(|b| {
                for key in [&b"p/1"[..], b"p/2", b"p/3", b"q/1", b"p"] {
                    b.put("ns", key.to_vec(), key.to_vec()).unwrap();
                }
            }))
            .unwrap();
        let keys = |found: Vec<crate::store::KeyValue>| -> Vec<Vec<u8>> {
            found.into_iter().map(|(key, _)| key).collect()
        };
        assert_eq!(
            keys(store.scan("ns", b"p/", None, 10).unwrap()),
            vec![b"p/1".to_vec(), b"p/2".to_vec(), b"p/3".to_vec()]
        );
        assert_eq!(
            keys(store.scan("ns", b"p/", Some(b"p/1"), 1).unwrap()),
            vec![b"p/2".to_vec()]
        );
        assert!(
            store
                .scan("ns", b"p/", Some(b"p/3"), 10)
                .unwrap()
                .is_empty()
        );
        assert!(store.scan("none", b"", None, 10).unwrap().is_empty());
        assert_eq!(store.scan("ns", b"", None, 0).unwrap().len(), 0);
    }

    #[test]
    fn test_memory_store_deletes_a_prefix() {
        let store = MemoryStore::new();
        store
            .commit(batch(|b| {
                b.put("ns", b"p/1".to_vec(), b"x".to_vec()).unwrap();
                b.put("ns", b"p/2".to_vec(), b"x".to_vec()).unwrap();
                b.put("ns", b"q".to_vec(), b"x".to_vec()).unwrap();
                b.put("other", b"p/1".to_vec(), b"x".to_vec()).unwrap();
            }))
            .unwrap();
        store
            .commit(batch(|b| {
                b.delete_prefix("ns", b"p/".to_vec()).unwrap();
            }))
            .unwrap();
        assert_eq!(store.len("ns"), 1);
        assert_eq!(store.len("other"), 1);
        store
            .commit(batch(|b| {
                b.delete_prefix("ns", Vec::new()).unwrap();
            }))
            .unwrap();
        assert!(store.is_empty("ns"));
    }
}
