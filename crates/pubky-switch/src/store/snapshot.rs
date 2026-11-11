//! Reads after the account's lock, of the state under it: the request's transaction exports
//! its snapshot while it holds the lock, a second transaction on the reader pool imports it
//! before the first commits, and the read runs there once the lock is gone. Every write to
//! an account's state takes its lock, so that snapshot is the state at the request's
//! stamped service time; a long read no longer holds the lock other requests wait for.

use sqlx::{Executor, Postgres, Transaction};

use super::{
    AccountTxn, StoreError, StoredApp,
    identity::read_kept_app_ids,
    ops::{read_apps, read_directory_versions},
};

/// The accounts with a read after the lock in flight in this process: at most one each,
/// so a few slow reads of one account can't hold every reader the other accounts share.
pub(super) type Reading = std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>;

/// An account's one read after the lock, held from before its reader is taken until the
/// read ends, or its request does without reading.
#[derive(Debug)]
pub(super) struct ReadSlot {
    reading: Reading,
    account: String,
}

impl ReadSlot {
    /// The account's slot, or `None` while another read of it is in flight.
    pub(super) fn claim(reading: &Reading, account: &str) -> Option<Self> {
        let mut accounts = reading.lock().ok()?;
        accounts.insert(account.to_string()).then(|| Self {
            reading: reading.clone(),
            account: account.to_string(),
        })
    }
}

impl Drop for ReadSlot {
    fn drop(&mut self) {
        if let Ok(mut accounts) = self.reading.lock() {
            accounts.remove(&self.account);
        }
    }
}

/// A read-only transaction on the reader pool, begun before the account's lock is taken,
/// that reads the state its account's locked transaction exported.
#[derive(Debug)]
pub struct SnapshotRead {
    pub(super) tx: Transaction<'static, Postgres>,
    pub(super) id: String,
    /// Released when the read ends.
    _slot: Option<ReadSlot>,
    #[cfg(any(test, feature = "test-util"))]
    pause: Option<super::testing::SnapshotPause>,
}

/// Whether `id` reads as a snapshot ID `pg_export_snapshot()` gives: hex digits and dashes.
fn is_snapshot_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

impl AccountTxn {
    /// Export this transaction's snapshot to the reader it was begun with
    /// ([`super::Store::begin_reading`]), if any: the reader's reads see exactly what this
    /// transaction sees, after it commits and releases the lock. Called right after the
    /// lock, outside any savepoint, since PostgreSQL exports no snapshot from a
    /// subtransaction; the request writes nothing it reads. A transaction without a reader
    /// does nothing.
    pub async fn prepare_snapshot(&mut self) -> Result<(), StoreError> {
        let Some(mut reader) = self.reader.take() else {
            return Ok(());
        };
        let snapshot: String = sqlx::query_scalar("SELECT pg_export_snapshot()")
            .fetch_one(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        if !is_snapshot_id(&snapshot) {
            return Err(StoreError::Corrupt("a snapshot ID"));
        }
        // Both before any query of the reader's transaction; SET takes no bind parameters,
        // and the ID is checked above.
        reader
            .execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .await
            .map_err(StoreError::from_db)?;
        reader
            .execute(format!("SET TRANSACTION SNAPSHOT '{snapshot}'").as_str())
            .await
            .map_err(StoreError::from_db)?;
        self.snapshot = Some(SnapshotRead {
            tx: reader,
            id: self.head().id.clone(),
            _slot: self.read_slot.take(),
            #[cfg(any(test, feature = "test-util"))]
            pause: self.snapshot_pause.take(),
        });
        Ok(())
    }

    /// The read of this transaction's snapshot ([`AccountTxn::prepare_snapshot`]), handed
    /// over to run once the lock is gone.
    pub fn snapshot_read(&mut self) -> Result<SnapshotRead, StoreError> {
        self.snapshot
            .take()
            .ok_or(StoreError::Corrupt("a snapshot read without a reader"))
    }
}

impl SnapshotRead {
    /// Start reading, once the lock is gone. For tests, it first waits where a test asked it
    /// to (`TestDatabase::pause_next_snapshot_read`, with `test-util`); otherwise it does
    /// nothing.
    pub async fn start(&mut self) {
        #[cfg(any(test, feature = "test-util"))]
        if let Some(pause) = self.pause.take() {
            pause.reached.notify_one();
            pause.resume.notified().await;
        }
    }

    /// The account's app rows, by App ID.
    pub async fn apps(&mut self) -> Result<Vec<StoredApp>, StoreError> {
        read_apps(&mut self.tx, &self.id).await
    }

    /// The App IDs kept for good.
    pub async fn kept_app_ids(&mut self) -> Result<Vec<[u8; 16]>, StoreError> {
        read_kept_app_ids(&mut self.tx, &self.id).await
    }

    /// The directory's versions.
    pub async fn directory_versions(&mut self) -> Result<(u64, u64), StoreError> {
        read_directory_versions(&mut self.tx, &self.id).await
    }

    /// End the read; it wrote nothing.
    pub async fn finish(self) -> Result<(), StoreError> {
        self.tx.rollback().await.map_err(StoreError::from_db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_one_read_per_account() {
        let reading = Reading::default();
        let alice = ReadSlot::claim(&reading, "alice");
        assert!(alice.is_some());
        // A second read of alice's account waits for none: it is refused.
        assert!(ReadSlot::claim(&reading, "alice").is_none());
        // Another account's read goes on.
        assert!(ReadSlot::claim(&reading, "bob").is_some());
        // Once alice's read ends, her next one goes on.
        drop(alice);
        assert!(ReadSlot::claim(&reading, "alice").is_some());
    }

    #[test]
    fn test_snapshot_id_shape() {
        assert!(is_snapshot_id("00000003-0000001B-1"));
        assert!(!is_snapshot_id(""));
        assert!(!is_snapshot_id("1'; DROP TABLE accounts; --"));
    }
}
