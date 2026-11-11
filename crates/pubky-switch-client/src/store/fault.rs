//! A fault-injecting [`StateStore`] for crash tests. Test builds only (`test-support`).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::{StateStore, StoreError, WriteBatch};

/// What a [`FaultStore`] does at its `n`th commit, counting from 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Pass every call through.
    None,
    /// The `n`th commit fails with [`StoreError::Unavailable`] and applies nothing; later
    /// calls pass through.
    FailBefore(u64),
    /// The `n`th commit is applied, then answers [`StoreError::Unknown`]; later calls pass
    /// through.
    FailAfter(u64),
    /// The process stops before the `n`th commit: it applies nothing, and it and every
    /// later call fail with [`StoreError::Unavailable`].
    StopBefore(u64),
    /// The process stops after the `n`th commit: it is applied, and it and every later call
    /// fail with [`StoreError::Unavailable`].
    StopAfter(u64),
}

/// Puts a [`FaultStore`] refuses as too large: under a key prefix, of values over a size,
/// for a number of commits or, with `None`, for every one.
type TooLarge = (Vec<u8>, usize, Option<u32>);

/// A store that wraps another and fails, or stops, before or after a chosen commit.
///
/// A stopped store refuses every call, as a process that died would make none; the test then
/// "reopens" by using the wrapped store, which holds exactly what was committed.
pub struct FaultStore {
    inner: Arc<dyn StateStore>,
    fault: Fault,
    commits: AtomicU64,
    stopped: AtomicBool,
    /// Key prefixes whose scan fails with [`StoreError::Unavailable`], once each, after
    /// as many scans of it as given pass.
    failing_scans: Mutex<Vec<(Vec<u8>, usize)>>,
    /// A key prefix whose puts of values over a size make a commit fail with
    /// [`StoreError::TooLarge`], as a write over the working sizes would.
    too_large: Mutex<Option<TooLarge>>,
}

impl std::fmt::Debug for FaultStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FaultStore")
            .field("fault", &self.fault)
            .field("commits", &self.commits())
            .field("stopped", &self.stopped())
            .finish()
    }
}

impl FaultStore {
    /// Wrap `inner` with `fault`.
    pub fn new(inner: Arc<dyn StateStore>, fault: Fault) -> Self {
        Self {
            inner,
            fault,
            commits: AtomicU64::new(0),
            stopped: AtomicBool::new(false),
            failing_scans: Mutex::new(Vec::new()),
            too_large: Mutex::new(None),
        }
    }

    /// Refuse every commit that puts a key starting with `prefix` with
    /// [`StoreError::TooLarge`], applying nothing, as for writes over the working sizes;
    /// `None` stops refusing.
    pub fn refuse_puts_as_too_large(&self, prefix: Option<&[u8]>) {
        self.refuse_puts_as_too_large_over(prefix, 0);
    }

    /// As [`FaultStore::refuse_puts_as_too_large`], for puts of values over `size` bytes
    /// only, as a store with a smaller value size would.
    pub fn refuse_puts_as_too_large_over(&self, prefix: Option<&[u8]>, size: usize) {
        if let Ok(mut too_large) = self.too_large.lock() {
            *too_large = prefix.map(|prefix| (prefix.to_vec(), size, None));
        }
    }

    /// As [`FaultStore::refuse_puts_as_too_large`], for the next commit that puts a key
    /// starting with `prefix` only; later ones pass.
    pub fn refuse_puts_as_too_large_once(&self, prefix: &[u8]) {
        if let Ok(mut too_large) = self.too_large.lock() {
            *too_large = Some((prefix.to_vec(), 0, Some(1)));
        }
    }

    /// Fail a scan of exactly `prefix` with [`StoreError::Unavailable`], once, after `after`
    /// scans of it pass; other calls pass through.
    pub fn fail_scan(&self, prefix: &[u8], after: usize) {
        if let Ok(mut failing) = self.failing_scans.lock() {
            failing.push((prefix.to_vec(), after));
        }
    }

    /// The wrapped store, as a restarted process finds it.
    pub fn inner(&self) -> Arc<dyn StateStore> {
        Arc::clone(&self.inner)
    }

    /// The commits attempted so far, the failed ones included.
    pub fn commits(&self) -> u64 {
        self.commits.load(Ordering::SeqCst)
    }

    /// Whether the store has stopped.
    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    fn check_running(&self) -> Result<(), StoreError> {
        if self.stopped() {
            Err(StoreError::Unavailable)
        } else {
            Ok(())
        }
    }
}

impl StateStore for FaultStore {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.check_running()?;
        self.inner.get(ns, key)
    }

    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<super::KeyValue>, StoreError> {
        self.check_running()?;
        if let Ok(mut failing) = self.failing_scans.lock()
            && let Some(at) = failing.iter().position(|(p, _)| p.as_slice() == prefix)
        {
            match failing.get_mut(at) {
                Some((_, after)) if *after > 0 => *after -= 1,
                _ => {
                    failing.remove(at);
                    return Err(StoreError::Unavailable);
                }
            }
        }
        self.inner.scan(ns, prefix, after, limit)
    }

    fn commit(&self, batch: WriteBatch) -> Result<(), StoreError> {
        self.check_running()?;
        if let Ok(mut too_large) = self.too_large.lock()
            && let Some((prefix, size, times)) = too_large.as_mut()
            && batch.writes.iter().any(|write| {
                matches!(write, super::Write::Put { key, value, .. }
                    if key.starts_with(prefix.as_slice()) && value.len() > *size)
            })
        {
            if let Some(times) = times {
                *times = times.saturating_sub(1);
                if *times == 0 {
                    *too_large = None;
                }
            }
            return Err(StoreError::TooLarge { size: 0, cap: 0 });
        }
        let n = self
            .commits
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        match self.fault {
            Fault::FailBefore(at) if at == n => Err(StoreError::Unavailable),
            Fault::StopBefore(at) if at == n => {
                self.stopped.store(true, Ordering::SeqCst);
                Err(StoreError::Unavailable)
            }
            Fault::FailAfter(at) if at == n => {
                self.inner.commit(batch)?;
                Err(StoreError::Unknown)
            }
            Fault::StopAfter(at) if at == n => {
                let applied = self.inner.commit(batch);
                self.stopped.store(true, Ordering::SeqCst);
                applied?;
                Err(StoreError::Unavailable)
            }
            _ => self.inner.commit(batch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    fn put(key: &str) -> WriteBatch {
        let mut batch = WriteBatch::new();
        batch
            .put("ns", key.as_bytes().to_vec(), b"v".to_vec())
            .unwrap();
        batch
    }

    fn held(store: &dyn StateStore) -> Vec<Vec<u8>> {
        store
            .scan("ns", b"", None, 100)
            .unwrap()
            .into_iter()
            .map(|(key, _)| key)
            .collect()
    }

    #[test]
    fn test_fault_store_fails_before_a_commit_applying_nothing() {
        let store = FaultStore::new(Arc::new(MemoryStore::new()), Fault::FailBefore(2));
        store.commit(put("1")).unwrap();
        assert_eq!(store.commit(put("2")), Err(StoreError::Unavailable));
        store.commit(put("3")).unwrap();
        assert_eq!(held(&store), vec![b"1".to_vec(), b"3".to_vec()]);
        assert_eq!(store.commits(), 3);
    }

    #[test]
    fn test_fault_store_fails_after_a_commit_applying_it() {
        let store = FaultStore::new(Arc::new(MemoryStore::new()), Fault::FailAfter(1));
        assert_eq!(store.commit(put("1")), Err(StoreError::Unknown));
        assert_eq!(held(&store), vec![b"1".to_vec()]);
        assert!(!store.stopped());
    }

    #[test]
    fn test_fault_store_stops_before_a_commit() {
        let store = FaultStore::new(Arc::new(MemoryStore::new()), Fault::StopBefore(2));
        store.commit(put("1")).unwrap();
        assert_eq!(store.commit(put("2")), Err(StoreError::Unavailable));
        assert!(store.stopped());
        // A stopped process makes no further call.
        assert_eq!(store.get("ns", b"1"), Err(StoreError::Unavailable));
        assert_eq!(store.commit(put("3")), Err(StoreError::Unavailable));
        // Reopened: only the first commit is there.
        assert_eq!(held(store.inner().as_ref()), vec![b"1".to_vec()]);
    }

    #[test]
    fn test_fault_store_stops_after_a_commit() {
        let store = FaultStore::new(Arc::new(MemoryStore::new()), Fault::StopAfter(2));
        store.commit(put("1")).unwrap();
        assert_eq!(store.commit(put("2")), Err(StoreError::Unavailable));
        assert!(store.stopped());
        assert!(store.scan("ns", b"", None, 10).is_err());
        assert_eq!(
            held(store.inner().as_ref()),
            vec![b"1".to_vec(), b"2".to_vec()]
        );
    }

    #[test]
    fn test_fault_store_without_a_fault_passes_through() {
        let store = FaultStore::new(Arc::new(MemoryStore::new()), Fault::None);
        for key in ["1", "2", "3"] {
            store.commit(put(key)).unwrap();
        }
        assert_eq!(held(&store).len(), 3);
    }
}
