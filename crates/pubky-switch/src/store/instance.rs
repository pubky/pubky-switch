//! One process per database (docs/configuration.md, "Topology"): the service's binary holds a
//! session-level advisory lock in the database for as long as it serves, so a second process
//! on the same database refuses to start.
//!
//! The lock lives with its connection, which the database ends at a restart or a failover:
//! [`InstanceLock::keep`] checks it, takes it again on a connection to the database as it is
//! then, and ends when another process holds it, so the binary stops serving.

use std::time::Duration;

use sqlx::{Connection, PgConnection, postgres::PgConnectOptions};

use super::{Store, StoreError};

/// The advisory lock key of the service's one process: "pubkyswi".
const INSTANCE_LOCK_KEY: i64 = 0x7075_626b_7973_7769;

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
    /// ended took the lock with it: it is taken again on a new connection, retried while
    /// the database can't be reached. Returns once another process holds it, so the caller
    /// stops serving: two processes never serve the database at once for longer than a
    /// check.
    pub async fn keep(mut self, every: Duration) -> StoreError {
        loop {
            tokio::time::sleep(every).await;
            if let Some(conn) = self.conn.as_mut()
                && sqlx::query("SELECT 1").execute(&mut *conn).await.is_ok()
            {
                continue;
            }
            self.conn = None;
            match Self::take(self.options.clone()).await {
                Ok(taken) => {
                    tracing::warn!("the instance lock's connection ended; the lock is held again");
                    self.conn = taken.conn;
                }
                Err(StoreError::InUse) => return StoreError::InUse,
                Err(failure) => tracing::warn!(%failure, "taking the instance lock again"),
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
}
