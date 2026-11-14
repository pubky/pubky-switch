//! [`StoreHandle`]: the async face of a host's [`StateStore`].

use std::sync::Arc;

use super::{StateStore, StoreError, WriteBatch};

/// How a [`StoreHandle`] runs the store's calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// On the calling task.
    Inline,
    /// On tokio's blocking thread pool.
    #[cfg(feature = "tokio")]
    Blocking,
}

/// A shared [`StateStore`] with async methods.
///
/// By default it calls the store inline. With the `tokio` feature, [`StoreHandle::new`] runs
/// each call through `tokio::task::spawn_blocking`, so a slow host store never blocks the
/// async executor; that needs a tokio runtime.
#[derive(Clone)]
pub struct StoreHandle {
    store: Arc<dyn StateStore>,
    mode: Mode,
}

impl std::fmt::Debug for StoreHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StoreHandle({:?})", self.mode)
    }
}

impl StoreHandle {
    /// A handle on `store`: on tokio's blocking pool with the `tokio` feature, inline
    /// without it.
    pub fn new(store: Arc<dyn StateStore>) -> Self {
        #[cfg(feature = "tokio")]
        {
            Self::blocking(store)
        }
        #[cfg(not(feature = "tokio"))]
        {
            Self::inline(store)
        }
    }

    /// A handle that calls the store on the calling task.
    pub fn inline(store: Arc<dyn StateStore>) -> Self {
        Self {
            store,
            mode: Mode::Inline,
        }
    }

    /// A handle that runs each call through `tokio::task::spawn_blocking`; its methods need
    /// a tokio runtime.
    #[cfg(feature = "tokio")]
    pub fn blocking(store: Arc<dyn StateStore>) -> Self {
        Self {
            store,
            mode: Mode::Blocking,
        }
    }

    /// Whether calls run on tokio's blocking pool.
    pub fn runs_blocking(&self) -> bool {
        match self.mode {
            Mode::Inline => false,
            #[cfg(feature = "tokio")]
            Mode::Blocking => true,
        }
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn StateStore> {
        &self.store
    }

    async fn run<T: Send + 'static>(
        &self,
        call: impl FnOnce(&dyn StateStore) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        match self.mode {
            Mode::Inline => call(self.store.as_ref()),
            #[cfg(feature = "tokio")]
            Mode::Blocking => {
                let store = Arc::clone(&self.store);
                tokio::task::spawn_blocking(move || call(store.as_ref()))
                    .await
                    // The task panicked or was cancelled: nothing it returned can be used,
                    // and a commit may or may not have been applied.
                    .unwrap_or(Err(StoreError::Unknown))
            }
        }
    }

    /// [`StateStore::get`].
    ///
    /// # Errors
    ///
    /// As [`StateStore::get`].
    pub async fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let (ns, key) = (ns.to_owned(), key.to_vec());
        self.run(move |store| store.get(&ns, &key)).await
    }

    /// [`StateStore::scan`].
    ///
    /// # Errors
    ///
    /// As [`StateStore::scan`].
    pub async fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<super::KeyValue>, StoreError> {
        let (ns, prefix, after) = (ns.to_owned(), prefix.to_vec(), after.map(<[u8]>::to_vec));
        self.run(move |store| store.scan(&ns, &prefix, after.as_deref(), limit))
            .await
    }

    /// [`StateStore::commit`]. The batch is within the working sizes, which its methods
    /// keep ([`WriteBatch`]).
    ///
    /// # Errors
    ///
    /// As [`StateStore::commit`].
    pub async fn commit(&self, batch: WriteBatch) -> Result<(), StoreError> {
        self.run(move |store| store.commit(batch)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{BatchError, MAX_VALUE_BYTES, MemoryStore};

    async fn round_trip(handle: &StoreHandle) {
        let mut batch = WriteBatch::new();
        batch.put("ns", b"a".to_vec(), b"1".to_vec()).unwrap();
        batch.put("ns", b"b".to_vec(), b"2".to_vec()).unwrap();
        handle.commit(batch).await.unwrap();
        assert_eq!(handle.get("ns", b"a").await.unwrap(), Some(b"1".to_vec()));
        let found = handle.scan("ns", b"", Some(b"a"), 10).await.unwrap();
        assert_eq!(found, vec![(b"b".to_vec(), b"2".to_vec())]);
    }

    async fn keeps_an_oversized_write_out(handle: &StoreHandle) {
        let size = usize::try_from(MAX_VALUE_BYTES).unwrap();
        let mut batch = WriteBatch::new();
        batch.put("ns", b"small".to_vec(), b"1".to_vec()).unwrap();
        assert!(matches!(
            batch.put("ns", b"big".to_vec(), vec![0; size + 1]),
            Err(BatchError::ValueTooLarge { .. })
        ));
        handle.commit(batch).await.unwrap();
        assert_eq!(handle.get("ns", b"big").await.unwrap(), None);
        assert_eq!(
            handle.get("ns", b"small").await.unwrap(),
            Some(b"1".to_vec())
        );
    }

    #[tokio::test]
    async fn test_store_handle_inline_round_trips() {
        let handle = StoreHandle::inline(Arc::new(MemoryStore::new()));
        assert!(!handle.runs_blocking());
        round_trip(&handle).await;
        keeps_an_oversized_write_out(&handle).await;
    }

    #[cfg(feature = "tokio")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_store_handle_blocking_round_trips() {
        let handle = StoreHandle::blocking(Arc::new(MemoryStore::new()));
        assert!(handle.runs_blocking());
        assert!(StoreHandle::new(Arc::new(MemoryStore::new())).runs_blocking());
        round_trip(&handle).await;
        keeps_an_oversized_write_out(&handle).await;
    }

    #[cfg(not(feature = "tokio"))]
    #[test]
    fn test_store_handle_new_is_inline_without_tokio() {
        assert!(!StoreHandle::new(Arc::new(MemoryStore::new())).runs_blocking());
    }

    #[cfg(feature = "tokio")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_store_handle_blocking_reports_a_failed_store() {
        struct Broken;
        impl StateStore for Broken {
            fn get(&self, _: &str, _: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
                Err(StoreError::Corrupt)
            }
            fn scan(
                &self,
                _: &str,
                _: &[u8],
                _: Option<&[u8]>,
                _: u32,
            ) -> Result<Vec<crate::store::KeyValue>, StoreError> {
                Err(StoreError::Unavailable)
            }
            fn commit(&self, _: WriteBatch) -> Result<(), StoreError> {
                panic!("the host store crashed")
            }
        }
        let handle = StoreHandle::blocking(Arc::new(Broken));
        assert_eq!(handle.get("ns", b"k").await, Err(StoreError::Corrupt));
        assert_eq!(
            handle.scan("ns", b"", None, 1).await,
            Err(StoreError::Unavailable)
        );
        // A store that panics on the blocking pool can't say what it applied.
        assert_eq!(
            handle.commit(WriteBatch::new()).await,
            Err(StoreError::Unknown)
        );
    }
}
