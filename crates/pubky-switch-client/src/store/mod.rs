//! The host's durable store: the [`StateStore`] trait the client and the signer persist
//! through, its write batches, an in-memory implementation and an async handle.
//!
//! The trait is synchronous and takes plain bytes, so Swift and Kotlin hosts implement it
//! without async callbacks and never parse what the crates store. The crates call it off the
//! async executor through [`StoreHandle`].
//!
//! Nothing in the Switch spec fixes how a client persists its state; these are the crates'
//! own rules. They exist so that every network effect can follow one pattern: sign an
//! artifact and commit it with the next step in one atomic write, send those bytes until
//! there is an answer, then commit the outcome. A crash then resends the same bytes, and
//! nothing is signed twice (Switch wire 2.1).

#[cfg(feature = "test-support")]
mod fault;
mod handle;
mod memory;

#[cfg(feature = "test-support")]
pub use fault::{Fault, FaultStore};
pub use handle::StoreHandle;
pub use memory::MemoryStore;

use pubky_switch_core::enc::zbase32_encode;

pub use crate::error::{BatchError, StoreError};

/// The largest value a host stores: 16 MiB.
///
/// The largest values are the signer's hand-over and backup kept as signed bytes: at most
/// 128 envelopes holding at most 11,185,390 bytes of JSON (Switch wire 3.12, 3.13).
pub const MAX_VALUE_BYTES: u64 = 16 << 20;

/// The largest batch a host commits: 32 MiB, counting every write's namespace, key and
/// value, so one batch holds such a value with the rest of its writes.
pub const MAX_BATCH_BYTES: u64 = 32 << 20;

/// One entry a [`StateStore::scan`] returns: a key and its value.
pub type KeyValue = (Vec<u8>, Vec<u8>);

/// The namespace prefix the client writes under; its namespace is this prefix followed by
/// the app's App ID.
pub const CLIENT_NAMESPACE_PREFIX: &str = "client/";

/// The client's namespace for an app: `client/<app_id>`, the App ID in z-base-32. The client
/// writes no other namespace.
pub fn client_namespace(app_id: &[u8; 16]) -> String {
    format!("{CLIENT_NAMESPACE_PREFIX}{}", zbase32_encode(app_id))
}

/// A durable key-value store the host implements once per install, for example on SQLite.
///
/// Keys and values are opaque bytes in namespaces the crates name; each crate writes only its
/// own namespaces.
///
/// # Guarantees the host gives
///
/// 1. **Atomic:** a [`commit`](StateStore::commit) applies all of its writes or none, also
///    across a crash or a power loss. An `Err` other than [`StoreError::Unknown`] means none
///    were applied; a store that can't tell returns [`StoreError::Unknown`], and the crate
///    reads its state again before it goes on.
/// 2. **Durable before `Ok`:** `commit` returns `Ok` only once the writes are on stable
///    storage (for SQLite, `synchronous=FULL`). After `Ok` they survive a process kill and a
///    power loss.
/// 3. **Ordered and consistent:** commits apply in the order they are made. A read sees
///    every commit that returned before it and never part of a batch, readers in other
///    processes included.
/// 4. **One writer per namespace:** only one process at a time writes a namespace, for
///    example the main app and not a push extension. The crates serialize their own
///    commits.
/// 5. **Device-bound and encrypted at rest:** the store is excluded from device and cloud
///    backups and is encrypted at rest under a key kept like the app's keys (Switch spec
///    3.1).
/// 6. **Real deletion:** [`Write::Delete`] and [`Write::DeletePrefix`] remove the data from
///    the store's files, not only from its index (for SQLite, `secure_delete`).
/// 7. **Sizes:** a value of up to [`MAX_VALUE_BYTES`] (16 MiB) and a batch of up to
///    [`MAX_BATCH_BYTES`] (32 MiB). A hand-over or backup, the largest value, is at most
///    11,185,390 bytes of JSON (Switch wire 3.12, 3.13). [`WriteBatch`] refuses a larger
///    value or batch before the host sees it.
pub trait StateStore: Send + Sync {
    /// The value at `key` in `ns`, or `None`.
    ///
    /// # Errors
    ///
    /// A [`StoreError`] when the store can't be read.
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError>;

    /// The entries of `ns` whose keys start with `prefix`, in ascending byte order of key,
    /// starting after `after` (exclusive), at most `limit` of them.
    ///
    /// # Errors
    ///
    /// A [`StoreError`] when the store can't be read.
    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<KeyValue>, StoreError>;

    /// Apply every write of `batch`, in order, or none of them; durable before `Ok`.
    ///
    /// # Errors
    ///
    /// A [`StoreError`]: [`StoreError::Unknown`] when the store can't tell whether the
    /// writes were applied, any other variant when none were.
    fn commit(&self, batch: WriteBatch) -> Result<(), StoreError>;
}

/// One write of a [`WriteBatch`].
#[derive(Clone, PartialEq, Eq)]
pub enum Write {
    /// Set `key` in `ns` to `value`.
    Put {
        /// The namespace.
        ns: String,
        /// The key.
        key: Vec<u8>,
        /// The value.
        value: Vec<u8>,
    },
    /// Remove `key` from `ns`, if present.
    Delete {
        /// The namespace.
        ns: String,
        /// The key.
        key: Vec<u8>,
    },
    /// Remove every key of `ns` that starts with `prefix`.
    DeletePrefix {
        /// The namespace.
        ns: String,
        /// The prefix; empty for the whole namespace.
        prefix: Vec<u8>,
    },
}

impl Write {
    /// The bytes the write counts against the batch size: its namespace, key or prefix, and
    /// value.
    pub fn size(&self) -> u64 {
        let len = |bytes: usize| u64::try_from(bytes).unwrap_or(u64::MAX);
        match self {
            Write::Put { ns, key, value } => len(ns.len())
                .saturating_add(len(key.len()))
                .saturating_add(len(value.len())),
            Write::Delete { ns, key } => len(ns.len()).saturating_add(len(key.len())),
            Write::DeletePrefix { ns, prefix } => len(ns.len()).saturating_add(len(prefix.len())),
        }
    }

    /// The write's namespace.
    pub fn ns(&self) -> &str {
        match self {
            Write::Put { ns, .. } | Write::Delete { ns, .. } | Write::DeletePrefix { ns, .. } => ns,
        }
    }
}

impl std::fmt::Debug for Write {
    // Values may hold signed artifacts and private records: only their sizes are shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Write::Put { ns, key, value } => {
                write!(
                    f,
                    "Put({ns}, {} key bytes, {} value bytes)",
                    key.len(),
                    value.len()
                )
            }
            Write::Delete { ns, key } => write!(f, "Delete({ns}, {} key bytes)", key.len()),
            Write::DeletePrefix { ns, prefix } => {
                write!(f, "DeletePrefix({ns}, {} prefix bytes)", prefix.len())
            }
        }
    }
}

/// Writes applied together, all or none ([`StateStore::commit`]).
///
/// Build one with [`WriteBatch::new`] and its methods, which count the batch's size and
/// refuse a write that would take it over the working sizes, so the host never sees an
/// oversized batch: every value is at most [`MAX_VALUE_BYTES`] and the whole at most
/// [`MAX_BATCH_BYTES`]. They keep a running total, so building a batch costs time linear in
/// its writes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteBatch {
    /// The writes, in order. Only the methods add to them.
    writes: Vec<Write>,
    /// The size of `writes`, the running total the methods keep.
    size: u64,
}

impl WriteBatch {
    /// An empty batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// The batch's writes, in order.
    pub fn writes(&self) -> &[Write] {
        &self.writes
    }

    /// The batch's writes, in order, taken out of it: what a store applies at commit.
    pub fn into_writes(self) -> Vec<Write> {
        self.writes
    }

    /// The batch's size: the sum of [`Write::size`] over its writes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Whether the batch has no writes.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    fn push(&mut self, write: Write) -> Result<&mut Self, BatchError> {
        if let Write::Put { value, .. } = &write {
            let size = u64::try_from(value.len()).unwrap_or(u64::MAX);
            if size > MAX_VALUE_BYTES {
                return Err(BatchError::ValueTooLarge {
                    size,
                    cap: MAX_VALUE_BYTES,
                });
            }
        }
        let size = self.size.saturating_add(write.size());
        if size > MAX_BATCH_BYTES {
            return Err(BatchError::BatchTooLarge {
                size,
                cap: MAX_BATCH_BYTES,
            });
        }
        self.writes.push(write);
        self.size = size;
        Ok(self)
    }

    /// Add a [`Write::Put`].
    ///
    /// # Errors
    ///
    /// [`BatchError`] if the value or the batch would be over its working size; the batch is
    /// left as it was.
    pub fn put(
        &mut self,
        ns: &str,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<&mut Self, BatchError> {
        self.push(Write::Put {
            ns: ns.to_owned(),
            key: key.into(),
            value: value.into(),
        })
    }

    /// Add a [`Write::Delete`].
    ///
    /// # Errors
    ///
    /// [`BatchError::BatchTooLarge`] if the batch would be over its working size.
    pub fn delete(&mut self, ns: &str, key: impl Into<Vec<u8>>) -> Result<&mut Self, BatchError> {
        self.push(Write::Delete {
            ns: ns.to_owned(),
            key: key.into(),
        })
    }

    /// Add a [`Write::DeletePrefix`].
    ///
    /// # Errors
    ///
    /// [`BatchError::BatchTooLarge`] if the batch would be over its working size.
    pub fn delete_prefix(
        &mut self,
        ns: &str,
        prefix: impl Into<Vec<u8>>,
    ) -> Result<&mut Self, BatchError> {
        self.push(Write::DeletePrefix {
            ns: ns.to_owned(),
            prefix: prefix.into(),
        })
    }

    /// Check that every write is in `ns`, as the client checks its batches against its own
    /// namespace ([`client_namespace`]).
    ///
    /// # Errors
    ///
    /// [`BatchError::Namespace`] for a write in another namespace.
    pub fn check_namespace(&self, ns: &str) -> Result<(), BatchError> {
        if self.writes.iter().all(|write| write.ns() == ns) {
            Ok(())
        } else {
            Err(BatchError::Namespace)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_batch_counts_namespace_key_and_value() {
        let mut batch = WriteBatch::new();
        batch.put("ns", b"key".to_vec(), vec![0; 10]).unwrap();
        batch.delete("ns", b"k".to_vec()).unwrap();
        batch.delete_prefix("ns", Vec::new()).unwrap();
        assert_eq!(batch.size(), (2 + 3 + 10) + (2 + 1) + 2);
        assert_eq!(batch.writes().len(), 3);
    }

    #[test]
    fn test_write_batch_refuses_a_value_over_its_size() {
        let mut batch = WriteBatch::new();
        let size = usize::try_from(MAX_VALUE_BYTES).unwrap();
        batch.put("ns", b"k".to_vec(), vec![0; size]).unwrap();
        let error = batch
            .put("ns", b"k".to_vec(), vec![0; size + 1])
            .unwrap_err();
        assert!(matches!(error, BatchError::ValueTooLarge { .. }));
        // The refused write isn't added.
        assert_eq!(batch.writes().len(), 1);
    }

    #[test]
    fn test_write_batch_refuses_a_batch_over_its_size() {
        let mut batch = WriteBatch::new();
        let size = usize::try_from(MAX_VALUE_BYTES).unwrap();
        batch.put("a", b"1".to_vec(), vec![0; size - 2]).unwrap();
        batch.put("a", b"2".to_vec(), vec![0; size - 2]).unwrap();
        assert_eq!(batch.size(), MAX_BATCH_BYTES);
        let error = batch.delete("a", b"3".to_vec()).unwrap_err();
        assert!(matches!(error, BatchError::BatchTooLarge { .. }));
        assert_eq!(batch.writes().len(), 2);
        assert_eq!(batch.size(), MAX_BATCH_BYTES);
    }

    #[test]
    fn test_write_batch_running_total_counts_every_write() {
        let mut batch = WriteBatch::new();
        for n in 0..2_000u32 {
            batch.delete("ns", n.to_be_bytes().to_vec()).unwrap();
        }
        assert_eq!(batch.size(), 2_000 * (2 + 4));
        let size = usize::try_from(MAX_VALUE_BYTES).unwrap();
        batch.put("ns", b"k".to_vec(), vec![0; size]).unwrap();
        let error = batch.put("ns", b"k".to_vec(), vec![0; size]).unwrap_err();
        assert!(matches!(error, BatchError::BatchTooLarge { .. }));
        let counted = batch.size();
        let writes = batch.clone().into_writes();
        assert_eq!(writes.len(), 2_001);
        assert_eq!(
            counted,
            writes.iter().map(Write::size).sum::<u64>(),
            "the running total is the sum over the writes"
        );
        assert_eq!(batch.writes(), writes.as_slice());
    }

    #[test]
    fn test_client_namespace_is_the_app_ids() {
        let ns = client_namespace(&[7; 16]);
        assert!(ns.starts_with(CLIENT_NAMESPACE_PREFIX));
        let mut batch = WriteBatch::new();
        batch.put(&ns, b"k".to_vec(), b"v".to_vec()).unwrap();
        batch.check_namespace(&ns).unwrap();
        batch.put("signer", b"k".to_vec(), b"v".to_vec()).unwrap();
        assert_eq!(batch.check_namespace(&ns), Err(BatchError::Namespace));
    }

    #[test]
    fn test_write_debug_hides_values() {
        let write = Write::Put {
            ns: "ns".into(),
            key: b"key".to_vec(),
            value: b"secret-value".to_vec(),
        };
        let text = format!("{write:?}");
        assert!(!text.contains("secret"), "{text}");
        assert!(text.contains("12 value bytes"), "{text}");
    }
}
