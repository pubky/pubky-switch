//! One process per database (docs/configuration.md, "Topology"): the service's binary holds a
//! session-level advisory lock in the database for as long as it serves, so a second process
//! on the same database refuses to start.
//!
//! The lock lives with its connection, which the database ends at a restart or a failover:
//! [`InstanceLock::keep`] checks it, takes it again on a connection to the database as it is
//! then, and ends when another process holds it, or when the lock can't be confirmed for a
//! few checks in a row, so the binary stops serving. Every check and every new connection is
//! bounded in time: a connection that answers nothing counts as lost.

use std::time::Duration;

use sqlx::{Connection, PgConnection, postgres::PgConnectOptions};

use super::{Store, StoreError};

/// The advisory lock key of the service's one process: "pubkyswi".
const INSTANCE_LOCK_KEY: i64 = 0x7075_626b_7973_7769;

/// How many checks in a row may fail to confirm the lock before [`InstanceLock::keep`] ends.
const UNCONFIRMED_CHECKS: u32 = 3;

/// Why [`InstanceLock::keep`] ended: the process no longer holds the database alone, or
/// can't tell that it does.
#[derive(Debug, thiserror::Error)]
pub enum InstanceLockLost {
    /// Another process holds the lock.
    #[error("another process serves this database")]
    InUse,
    /// The lock couldn't be confirmed, nor taken again, for several checks in a row.
    #[error("the lock on this database couldn't be confirmed")]
    Unconfirmed,
}

/// The database held by this process alone, as long as this lives.
#[derive(Debug)]
pub struct InstanceLock {
    conn: Option<PgConnection>,
    options: PgConnectOptions,
}

impl Store {
    /// Hold the database for this process alone: a session-level advisory lock on a
    /// connection of its own, outside the pools.
    ///
    /// # Errors
    ///
    /// [`StoreError::InUse`] while another process holds it; a database error otherwise.
    pub async fn hold_instance_lock(&self) -> Result<InstanceLock, StoreError> {
        InstanceLock::take((*self.pool.connect_options()).clone()).await
    }
}

impl InstanceLock {
    async fn take(options: PgConnectOptions) -> Result<Self, StoreError> {
        let mut conn = PgConnection::connect_with(&options).await?;
        let held: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(INSTANCE_LOCK_KEY)
            .fetch_one(&mut conn)
            .await
            .map_err(StoreError::from_db)?;
        if !held {
            let _ = conn.close().await;
            return Err(StoreError::InUse);
        }
        Ok(Self {
            conn: Some(conn),
            options,
        })
    }

    /// Check the lock every `every` while the process serves. A connection the database
    /// ended, or one that doesn't answer within `every`, took the lock with it: it is taken
    /// again on a new connection, each try bounded by `every` too. Returns once another
    /// process holds it, or once the lock was neither confirmed nor taken again for
    /// [`UNCONFIRMED_CHECKS`] checks in a row, so the caller stops serving: two processes
    /// never serve the database at once for longer than those checks take.
    pub async fn keep(mut self, every: Duration) -> InstanceLockLost {
        let mut unconfirmed = 0;
        loop {
            tokio::time::sleep(every).await;
            if let Some(conn) = self.conn.as_mut()
                && matches!(
                    tokio::time::timeout(every, sqlx::query("SELECT 1").execute(&mut *conn)).await,
                    Ok(Ok(_))
                )
            {
                unconfirmed = 0;
                continue;
            }
            self.conn = None;
            match tokio::time::timeout(every, Self::take(self.options.clone())).await {
                Ok(Ok(taken)) => {
                    tracing::warn!("the instance lock's connection ended; the lock is held again");
                    self.conn = taken.conn;
                    unconfirmed = 0;
                    continue;
                }
                Ok(Err(StoreError::InUse)) => return InstanceLockLost::InUse,
                Ok(Err(failure)) => tracing::warn!(%failure, "taking the instance lock again"),
                Err(_) => tracing::warn!("taking the instance lock again: no answer in time"),
            }
            unconfirmed += 1;
            if unconfirmed >= UNCONFIRMED_CHECKS {
                return InstanceLockLost::Unconfirmed;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_instance_lock_is_held_by_one_process_at_a_time() {
        // A second hold on a held database is refused, as a second process's is; once the
        // first is dropped the database is free again.
        let Some(db) = super::super::testing::test_database().await else {
            return;
        };
        let held = db.store().hold_instance_lock().await.expect("lock");
        assert!(matches!(
            db.store().hold_instance_lock().await,
            Err(StoreError::InUse)
        ));
        drop(held);
        // The lock goes when its session ends, which the server sees after the drop.
        let mut again = None;
        for _ in 0..50 {
            match db.store().hold_instance_lock().await {
                Ok(lock) => {
                    again = Some(lock);
                    break;
                }
                Err(StoreError::InUse) => tokio::time::sleep(Duration::from_millis(50)).await,
                Err(failure) => panic!("{failure}"),
            }
        }
        assert!(again.is_some(), "free again");
        drop(again);
        db.drop_database().await.expect("drop");
    }

    /// End the session that holds `lock`, as a database restart or a failover does.
    async fn end_session(db: &super::super::testing::TestDatabase, lock: &mut InstanceLock) {
        let conn = lock.conn.as_mut().expect("held");
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *conn)
            .await
            .expect("pid");
        let mut other = PgConnection::connect_with(db.options())
            .await
            .expect("conn");
        sqlx::query("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .execute(&mut other)
            .await
            .expect("terminate");
        other.close().await.expect("close");
    }

    #[tokio::test]
    async fn test_store_instance_lock_is_taken_again_after_its_session_ends() {
        let Some(db) = super::super::testing::test_database().await else {
            return;
        };
        let mut held = db.store().hold_instance_lock().await.expect("lock");
        end_session(&db, &mut held).await;
        // The keeper takes the lock again and goes on: it is still running after several
        // checks, and no other process can take the database.
        let keeper = tokio::spawn(held.keep(Duration::from_millis(50)));
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!keeper.is_finished(), "still held");
        assert!(matches!(
            db.store().hold_instance_lock().await,
            Err(StoreError::InUse)
        ));
        keeper.abort();
        let _ = keeper.await;
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_keeper_stops_once_another_process_holds_it() {
        let Some(db) = super::super::testing::test_database().await else {
            return;
        };
        let mut first = db.store().hold_instance_lock().await.expect("lock");
        end_session(&db, &mut first).await;
        let mut second = None;
        for _ in 0..50 {
            match db.store().hold_instance_lock().await {
                Ok(lock) => {
                    second = Some(lock);
                    break;
                }
                Err(StoreError::InUse) => tokio::time::sleep(Duration::from_millis(50)).await,
                Err(failure) => panic!("{failure}"),
            }
        }
        let second = second.expect("the second process holds it");
        let lost = tokio::time::timeout(
            Duration::from_secs(10),
            first.keep(Duration::from_millis(50)),
        )
        .await
        .expect("the keeper ends");
        assert!(matches!(lost, InstanceLockLost::InUse));
        drop(second);
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_keeper_stops_when_the_lock_cant_be_confirmed() {
        // The session is gone and the database can't be reached: after a few checks the
        // keeper gives up, so the process stops serving a database it can't tell it holds.
        let Some(db) = super::super::testing::test_database().await else {
            return;
        };
        let mut held = db.store().hold_instance_lock().await.expect("lock");
        end_session(&db, &mut held).await;
        held.options = held.options.clone().host("127.0.0.1").port(1);
        let lost = tokio::time::timeout(
            Duration::from_secs(10),
            held.keep(Duration::from_millis(50)),
        )
        .await
        .expect("the keeper ends");
        assert!(matches!(lost, InstanceLockLost::Unconfirmed));
        db.drop_database().await.expect("drop");
    }
}
