//! Reads after the account's lock, of the state under it: the request's transaction exports
//! its snapshot while it holds the lock, a second transaction on the reader pool imports it
//! before the first commits, and the read runs there once the lock is gone. Every write to
//! an account's state takes its lock, so that snapshot is the state at the request's
//! stamped service time; a long read no longer holds the lock other requests wait for.

use sqlx::{Executor, Postgres, Transaction};

use super::{AccountTxn, StoreError};

/// Most reads of one account that wait for their turn behind the one in flight; a read past
/// them is refused at once ([`StoreError::LockTimeout`], `503`).
pub(super) const MAX_WAITING_READS: usize = 8;

/// The turns of each account with a read after the lock in flight or waiting in this
/// process: one read of an account runs at a time and the others wait in order, so a few
/// slow reads of one account can't hold every reader the other accounts share. An account
/// is listed while any of its reads holds or waits for its turn.
pub(super) type Reading =
    std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Turns>>>;

/// An account's turns: one permit, and how many reads hold it or wait for it.
#[derive(Debug)]
pub(super) struct Turns {
    permit: std::sync::Arc<tokio::sync::Semaphore>,
    queued: usize,
}

/// The accounts' turns. A panic while the lock was held leaves the map as it was, every
/// change to it being one step, so a poisoned lock is taken as it is.
fn accounts(
    reading: &Reading,
) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, Turns>> {
    reading
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// An account's place in its queue: it counts the read from when it starts waiting until
/// its request ends.
#[derive(Debug)]
struct Queued {
    reading: Reading,
    account: String,
}

impl Drop for Queued {
    fn drop(&mut self) {
        let mut map = accounts(&self.reading);
        if let Some(turns) = map.get_mut(&self.account) {
            turns.queued = turns.queued.saturating_sub(1);
            if turns.queued == 0 {
                map.remove(&self.account);
            }
        }
    }
}

/// An account's turn to read after the lock, held from before its reader is taken until the
/// read ends, or its request does without reading.
#[derive(Debug)]
pub(super) struct ReadTurn {
    _permit: tokio::sync::OwnedSemaphorePermit,
    _queued: Queued,
}

impl ReadTurn {
    /// Wait for `account`'s turn, in order, at most `timeout`. Refused at once
    /// ([`StoreError::LockTimeout`]) when [`MAX_WAITING_READS`] reads wait already, and after
    /// `timeout` as a busy account's lock is. Waiting holds no connection.
    pub(super) async fn wait(
        reading: &Reading,
        account: &str,
        timeout: std::time::Duration,
    ) -> Result<Self, StoreError> {
        let permit = {
            let mut map = accounts(reading);
            let turns = map.entry(account.to_string()).or_insert_with(|| Turns {
                permit: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
                queued: 0,
            });
            if turns.queued > MAX_WAITING_READS {
                return Err(StoreError::LockTimeout);
            }
            turns.queued += 1;
            turns.permit.clone()
        };
        let queued = Queued {
            reading: reading.clone(),
            account: account.to_string(),
        };
        let permit = tokio::time::timeout(timeout, permit.acquire_owned())
            .await
            .map_err(|_| StoreError::LockTimeout)?
            .map_err(|_| StoreError::Corrupt("a closed read queue"))?;
        Ok(Self {
            _permit: permit,
            _queued: queued,
        })
    }
}

/// How many reads of `account` hold or wait for its turn, for tests.
#[cfg(any(test, feature = "test-util"))]
pub(super) fn queued(reading: &Reading, account: &str) -> usize {
    accounts(reading)
        .get(account)
        .map_or(0, |turns| turns.queued)
}

/// A read-only transaction on the reader pool, begun before the account's lock is taken,
/// that reads the state its account's locked transaction exported.
#[derive(Debug)]
pub struct SnapshotRead {
    pub(super) tx: Transaction<'static, Postgres>,
    pub(super) id: String,
    /// Released when the read ends.
    _turn: Option<ReadTurn>,
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
        // The import runs while this transaction holds the lock, so a reader backend that
        // stalls can't hold it longer than a lock wait: the server cancels a statement past
        // `lock_timeout_ms`, and the request stops waiting then too. The read after the
        // lock runs without that bound.
        let bound = self.import_timeout_ms;
        let import = async {
            // Each before any query of the reader's transaction; SET takes no bind
            // parameters, and the ID is checked above.
            reader
                .execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .await?;
            reader
                .execute(format!("SET LOCAL statement_timeout = {bound}").as_str())
                .await?;
            reader
                .execute(format!("SET TRANSACTION SNAPSHOT '{snapshot}'").as_str())
                .await?;
            reader
                .execute("SET LOCAL statement_timeout = DEFAULT")
                .await
                .map(|_| ())
        };
        tokio::time::timeout(std::time::Duration::from_millis(bound), import)
            .await
            .map_err(|_| StoreError::LockTimeout)?
            .map_err(StoreError::from_db)?;
        self.snapshot = Some(SnapshotRead {
            tx: reader,
            id: self.head().id.clone(),
            _turn: self.read_turn.take(),
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

    /// End the read; it wrote nothing.
    pub async fn finish(self) -> Result<(), StoreError> {
        self.tx.rollback().await.map_err(StoreError::from_db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_snapshot_reads_of_an_account_wait_in_order() {
        let reading = Reading::default();
        let long = std::time::Duration::from_secs(10);
        let first = ReadTurn::wait(&reading, "alice", long)
            .await
            .expect("first");
        // A second read of alice's account waits for the first, then goes on.
        let (second, ()) = tokio::join!(ReadTurn::wait(&reading, "alice", long), async {
            while queued(&reading, "alice") < 2 {
                tokio::task::yield_now().await;
            }
            drop(first);
        });
        let second = second.expect("the second read's turn");
        // Another account's read doesn't wait for alice's.
        let bob = ReadTurn::wait(&reading, "bob", std::time::Duration::from_millis(1))
            .await
            .expect("bob");
        drop(bob);
        assert_eq!(queued(&reading, "bob"), 0, "bob's queue is gone");
        // A wait past its timeout is refused, and leaves the queue as it was.
        let late = ReadTurn::wait(&reading, "alice", std::time::Duration::from_millis(1)).await;
        assert!(matches!(late, Err(StoreError::LockTimeout)));
        assert_eq!(queued(&reading, "alice"), 1);
        drop(second);
        assert_eq!(queued(&reading, "alice"), 0, "alice's queue is gone");
    }

    #[tokio::test]
    async fn test_snapshot_read_queue_is_bounded() {
        let reading = Reading::default();
        let first = ReadTurn::wait(&reading, "alice", std::time::Duration::from_secs(1))
            .await
            .expect("first");
        let long = std::time::Duration::from_secs(10);
        let waiting: Vec<_> = (0..MAX_WAITING_READS)
            .map(|_| Box::pin(ReadTurn::wait(&reading, "alice", long)))
            .collect();
        // Each waiter takes its place once polled.
        let mut waiting = waiting;
        for wait in &mut waiting {
            assert!(futures_poll_once(wait.as_mut()).await.is_none());
        }
        assert_eq!(queued(&reading, "alice"), MAX_WAITING_READS + 1);
        // One more is refused at once.
        let refused = ReadTurn::wait(&reading, "alice", long).await;
        assert!(matches!(refused, Err(StoreError::LockTimeout)));
        drop(waiting);
        drop(first);
        assert_eq!(queued(&reading, "alice"), 0);
    }

    /// Poll `future` once: its output if it is ready.
    async fn futures_poll_once<F: std::future::Future + Unpin>(future: F) -> Option<F::Output> {
        let mut future = future;
        std::future::poll_fn(|cx| {
            std::task::Poll::Ready(match std::pin::Pin::new(&mut future).poll(cx) {
                std::task::Poll::Ready(out) => Some(out),
                std::task::Poll::Pending => None,
            })
        })
        .await
    }

    #[test]
    fn test_snapshot_id_shape() {
        assert!(is_snapshot_id("00000003-0000001B-1"));
        assert!(!is_snapshot_id(""));
        assert!(!is_snapshot_id("1'; DROP TABLE accounts; --"));
    }
}
