//! One process per database (docs/configuration.md, "Topology"): the service's binary holds a
//! session-level advisory lock in the database for as long as it serves, so a second process
//! on the same database refuses to start.
//!
//! The lock lives with its session. [`InstanceLock::keep`] checks every few seconds that its
//! session still holds it, and takes it again on a new connection when it doesn't answer, or
//! when the database ended it at a restart or a failover. A connection that stops answering
//! may leave its session alive on the server, holding the lock: every lock session of the
//! process carries the process's own `application_name`, so the process knows such a session
//! for its own, ends it and takes the lock again, never taking it for another process. It stops serving when another process
//! holds the lock, and when the lock was neither confirmed nor taken again for three checks
//! in a row. Every check and every new connection is bounded in time.

use std::time::{Duration, Instant};

use sqlx::{Connection, Executor, PgConnection, Row, postgres::PgConnectOptions};

use super::{Store, StoreError};

/// The advisory lock key of the service's one process: "pubkyswi".
const INSTANCE_LOCK_KEY: i64 = 0x7075_626b_7973_7769;

/// The key's halves, as `pg_locks` shows a `bigint` advisory lock: `classid` and `objid`.
const LOCK_CLASSID: i64 = INSTANCE_LOCK_KEY >> 32;
const LOCK_OBJID: i64 = INSTANCE_LOCK_KEY & 0xffff_ffff;

/// How many checks in a row may fail to confirm the lock before [`InstanceLock::keep`] ends.
const UNCONFIRMED_CHECKS: u32 = 3;

/// Settings of the lock's session: the server drops it within about 20 seconds once its
/// peer is gone, so a process that died, or a connection the network lost, doesn't hold the
/// database for hours; and no statement on it runs past 5 seconds.
const SESSION_SETTINGS: &str = "SET tcp_keepalives_idle = 5; SET tcp_keepalives_interval = 5; \
     SET tcp_keepalives_count = 3; SET tcp_user_timeout = 15000; SET statement_timeout = 5000";

/// The session that holds the lock, if any, among those of this key. A column the database
/// hides from this role reads as null.
const HOLDER: &str = "SELECT l.pid, a.application_name AS name, a.backend_start::TEXT AS started, \
     host(a.client_addr) AS addr \
     FROM pg_locks l LEFT JOIN pg_stat_activity a ON a.pid = l.pid \
     WHERE l.locktype = 'advisory' AND l.granted AND l.classid::BIGINT = $1 \
     AND l.objid::BIGINT = $2 AND l.objsubid = 1 \
     AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())";

/// Why [`InstanceLock::keep`] ended: the process no longer holds the database alone, or
/// can't tell that it does.
#[derive(Debug, thiserror::Error)]
pub enum InstanceLockLost {
    /// Another process holds the lock.
    #[error("another process serves this database: {0}")]
    InUse(String),
    /// The lock couldn't be confirmed, nor taken again, for several checks in a row.
    #[error("the lock on this database couldn't be confirmed")]
    Unconfirmed,
}

/// A session that holds the lock.
#[derive(Clone, Debug)]
struct Holder {
    pid: i32,
    /// Its `application_name`: every lock session of this process carries the process's own.
    name: Option<String>,
    started: Option<String>,
    addr: Option<String>,
}

impl Holder {
    /// The holder as the operator needs it to find it, or to end it with
    /// `pg_terminate_backend`.
    fn describe(&self) -> String {
        format!(
            "the session of backend pid {} from {}, connected since {}",
            self.pid,
            self.addr
                .as_deref()
                .unwrap_or("an address not shown to this role"),
            self.started
                .as_deref()
                .unwrap_or("a time not shown to this role"),
        )
    }
}

/// Why a take of the lock failed.
enum TakeError {
    /// Another process's session holds it.
    Held(Holder),
    /// The lock changed hands while it was being taken, or this process's own earlier session
    /// hasn't let go of it yet: try again.
    Busy,
    /// The database failed.
    Store(StoreError),
}

impl From<StoreError> for TakeError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// The database held by this process alone, as long as this lives.
#[derive(Debug)]
pub struct InstanceLock {
    conn: Option<PgConnection>,
    /// The backend of the session that holds the lock now.
    pid: i32,
    /// This process's `application_name` for its lock sessions, unique to the process: a
    /// session that carries it is this process's own, also one whose take of the lock was
    /// given up after the lock was granted.
    name: String,
    /// The connection settings, with `name`.
    options: PgConnectOptions,
}

impl Store {
    /// Hold the database for this process alone: a session-level advisory lock on a
    /// connection of its own, outside the pools. While another session holds it, the take
    /// is tried again for up to `wait`, so a session the server is still dropping, such as
    /// an earlier run's, doesn't stop a restart.
    ///
    /// # Errors
    ///
    /// [`StoreError::InUse`], naming the session that holds it, when another one still does
    /// after `wait`; a database error otherwise.
    pub async fn hold_instance_lock(&self, wait: Duration) -> Result<InstanceLock, StoreError> {
        let since_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let name = format!("pubky-switch {}-{since_epoch}", std::process::id());
        let options = (*self.pool.connect_options())
            .clone()
            .application_name(&name);
        let deadline = Instant::now() + wait;
        loop {
            let refused = match InstanceLock::take(&options, &name).await {
                Ok(lock) => return Ok(lock),
                Err(TakeError::Store(error)) => return Err(error),
                Err(TakeError::Held(holder)) => holder.describe(),
                Err(TakeError::Busy) => "a session that let go of it while it was read".into(),
            };
            if Instant::now() >= deadline {
                return Err(StoreError::InUse(refused));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

impl InstanceLock {
    /// Take the lock on a new connection, ending first a session of this process's own that
    /// still holds it.
    async fn take(options: &PgConnectOptions, name: &str) -> Result<Self, TakeError> {
        let mut conn = PgConnection::connect_with(options)
            .await
            .map_err(StoreError::from)?;
        match Self::take_on(&mut conn, name).await {
            Ok(pid) => Ok(Self {
                conn: Some(conn),
                pid,
                name: name.to_string(),
                options: options.clone(),
            }),
            Err(error) => {
                let _ = conn.close().await;
                Err(error)
            }
        }
    }

    async fn take_on(conn: &mut PgConnection, name: &str) -> Result<i32, TakeError> {
        conn.execute(SESSION_SETTINGS)
            .await
            .map_err(StoreError::from_db)?;
        for _ in 0..3 {
            if try_lock(conn).await? {
                return Ok(this_pid(conn).await?);
            }
            // Let go between the two reads: try the lock again.
            let Some(holder) = holder(conn).await? else {
                continue;
            };
            if holder.name.as_deref() != Some(name) {
                return Err(TakeError::Held(holder));
            }
            // This process's own earlier session, whose connection stopped answering or
            // whose take was given up: end it. Its lock goes when the server has ended it,
            // a moment later.
            sqlx::query("SELECT pg_terminate_backend($1)")
                .bind(holder.pid)
                .execute(&mut *conn)
                .await
                .map_err(StoreError::from_db)?;
            for _ in 0..20 {
                if try_lock(conn).await? {
                    return Ok(this_pid(conn).await?);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        Err(TakeError::Busy)
    }

    /// Whether this lock's session holds the lock, asked of the session itself: not only
    /// that the connection answers.
    async fn confirm(conn: &mut PgConnection) -> Result<bool, StoreError> {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted \
             AND pid = pg_backend_pid() AND classid::BIGINT = $1 AND objid::BIGINT = $2 \
             AND objsubid = 1)",
        )
        .bind(LOCK_CLASSID)
        .bind(LOCK_OBJID)
        .fetch_one(conn)
        .await
        .map_err(StoreError::from_db)
    }

    /// Check the lock every `every` while the process serves: that its session still holds
    /// it, within `every`. A session that doesn't answer in time, or no longer holds it, is
    /// given up and the lock is taken again on a new connection, also within `every`, ending
    /// first any session of this process's own that still holds it. Returns once another
    /// process's session holds the lock, or once the lock was neither confirmed nor taken
    /// again for three checks in a row, so the caller stops serving: two processes never
    /// serve the database at once for longer than those checks take.
    pub async fn keep(mut self, every: Duration) -> InstanceLockLost {
        let mut unconfirmed = 0;
        loop {
            tokio::time::sleep(every).await;
            if let Some(conn) = self.conn.as_mut()
                && matches!(
                    tokio::time::timeout(every, Self::confirm(conn)).await,
                    Ok(Ok(true))
                )
            {
                unconfirmed = 0;
                continue;
            }
            // Given up without waiting: its session may stay on the server, and a take ends
            // it while it still holds the lock.
            drop(self.conn.take());
            match tokio::time::timeout(every, Self::take(&self.options, &self.name)).await {
                Ok(Ok(taken)) => {
                    tracing::warn!("the instance lock's session was lost; the lock is held again");
                    self.conn = taken.conn;
                    self.pid = taken.pid;
                    unconfirmed = 0;
                    continue;
                }
                Ok(Err(TakeError::Held(holder))) => {
                    return InstanceLockLost::InUse(holder.describe());
                }
                Ok(Err(TakeError::Busy)) => {
                    tracing::warn!("taking the instance lock again: it changed hands meanwhile");
                }
                Ok(Err(TakeError::Store(failure))) => {
                    tracing::warn!(%failure, "taking the instance lock again");
                }
                Err(_) => tracing::warn!("taking the instance lock again: no answer in time"),
            }
            unconfirmed += 1;
            if unconfirmed >= UNCONFIRMED_CHECKS {
                return InstanceLockLost::Unconfirmed;
            }
        }
    }
}

/// Try the lock on `conn`'s session.
async fn try_lock(conn: &mut PgConnection) -> Result<bool, StoreError> {
    sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(INSTANCE_LOCK_KEY)
        .fetch_one(conn)
        .await
        .map_err(StoreError::from_db)
}

/// The backend pid of `conn`'s session.
async fn this_pid(conn: &mut PgConnection) -> Result<i32, StoreError> {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(conn)
        .await
        .map_err(StoreError::from_db)
}

/// The session that holds the lock, if one does.
async fn holder(conn: &mut PgConnection) -> Result<Option<Holder>, StoreError> {
    let row = sqlx::query(HOLDER)
        .bind(LOCK_CLASSID)
        .bind(LOCK_OBJID)
        .fetch_optional(conn)
        .await
        .map_err(StoreError::from_db)?;
    row.map(|row| {
        Ok(Holder {
            pid: row.try_get("pid")?,
            name: row.try_get("name")?,
            started: row.try_get("started")?,
            addr: row.try_get("addr")?,
        })
    })
    .transpose()
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
        let held = db
            .store()
            .hold_instance_lock(Duration::ZERO)
            .await
            .expect("lock");
        assert!(matches!(
            db.store().hold_instance_lock(Duration::ZERO).await,
            Err(StoreError::InUse(_))
        ));
        drop(held);
        // The lock goes when its session ends, which the server sees after the drop.
        let mut again = None;
        for _ in 0..50 {
            match db.store().hold_instance_lock(Duration::ZERO).await {
                Ok(lock) => {
                    again = Some(lock);
                    break;
                }
                Err(StoreError::InUse(_)) => tokio::time::sleep(Duration::from_millis(50)).await,
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
        let mut held = db
            .store()
            .hold_instance_lock(Duration::ZERO)
            .await
            .expect("lock");
        end_session(&db, &mut held).await;
        // The keeper takes the lock again and goes on: it is still running after several
        // checks, and no other process can take the database.
        let keeper = tokio::spawn(held.keep(Duration::from_millis(50)));
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!keeper.is_finished(), "still held");
        assert!(matches!(
            db.store().hold_instance_lock(Duration::ZERO).await,
            Err(StoreError::InUse(_))
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
        let mut first = db
            .store()
            .hold_instance_lock(Duration::ZERO)
            .await
            .expect("lock");
        end_session(&db, &mut first).await;
        let mut second = None;
        for _ in 0..50 {
            match db.store().hold_instance_lock(Duration::ZERO).await {
                Ok(lock) => {
                    second = Some(lock);
                    break;
                }
                Err(StoreError::InUse(_)) => tokio::time::sleep(Duration::from_millis(50)).await,
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
        assert!(matches!(lost, InstanceLockLost::InUse(_)));
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
        let mut held = db
            .store()
            .hold_instance_lock(Duration::ZERO)
            .await
            .expect("lock");
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

    /// A TCP proxy to the test database whose first connection can be frozen: it stops
    /// forwarding and keeps both its sockets open, as a network path that loses one flow
    /// does, while later connections pass.
    async fn freezing_proxy(
        db: &super::super::testing::TestDatabase,
    ) -> (
        PgConnectOptions,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let target = format!("{}:{}", db.options().get_host(), db.options().get_port());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let frozen = Arc::new(AtomicBool::new(false));
        let freeze = frozen.clone();
        tokio::spawn(async move {
            let mut first = true;
            while let Ok((client, _)) = listener.accept().await {
                let Ok(server) = tokio::net::TcpStream::connect(&target).await else {
                    continue;
                };
                let gate = first.then(|| freeze.clone());
                first = false;
                let (client_read, client_write) = client.into_split();
                let (server_read, server_write) = server.into_split();
                for (mut from, mut to, gate) in [
                    (
                        Box::new(client_read) as Box<dyn tokio::io::AsyncRead + Send + Unpin>,
                        Box::new(server_write) as Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
                        gate.clone(),
                    ),
                    (Box::new(server_read), Box::new(client_write), gate),
                ] {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 8192];
                        loop {
                            let Ok(read) = from.read(&mut buf).await else {
                                return;
                            };
                            if read == 0 {
                                return;
                            }
                            if gate
                                .as_ref()
                                .is_some_and(|gate| gate.load(Ordering::SeqCst))
                            {
                                // Frozen: hold both sockets open and forward nothing.
                                std::future::pending::<()>().await;
                            }
                            if to.write_all(&buf[..read]).await.is_err() {
                                return;
                            }
                        }
                    });
                }
            }
        });
        (db.options().clone().host("127.0.0.1").port(port), frozen)
    }

    /// The pids of the sessions that hold the lock.
    async fn holders(db: &super::super::testing::TestDatabase) -> Vec<i32> {
        let mut conn = PgConnection::connect_with(db.options())
            .await
            .expect("conn");
        let pids = sqlx::query_scalar(
            "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted \
             AND classid::BIGINT = $1 AND objid::BIGINT = $2 AND objsubid = 1 \
             AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        )
        .bind(LOCK_CLASSID)
        .bind(LOCK_OBJID)
        .fetch_all(&mut conn)
        .await
        .expect("holders");
        conn.close().await.expect("close");
        pids
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_store_instance_lock_ends_its_own_frozen_session_and_takes_the_lock_again() {
        // The lock's connection stops answering while the server keeps its session, and
        // its lock, alive. The keeper knows that session for its own: it ends it and holds
        // the lock again, and goes on serving; a restart after it takes the lock at once.
        let Some(db) = super::super::testing::test_database().await else {
            return;
        };
        let (options, frozen) = freezing_proxy(&db).await;
        let name = "pubky-switch frozen".to_string();
        let options = options.application_name(&name);
        let held = InstanceLock::take(&options, &name)
            .await
            .unwrap_or_else(|_| panic!("lock"));
        let old = held.pid;
        assert_eq!(holders(&db).await, vec![old]);
        frozen.store(true, std::sync::atomic::Ordering::SeqCst);
        let keeper = tokio::spawn(held.keep(Duration::from_millis(200)));
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut now_held = holders(&db).await;
        while now_held.first() == Some(&old) || now_held.is_empty() {
            assert!(Instant::now() < deadline, "the lock was never taken again");
            assert!(
                !keeper.is_finished(),
                "the keeper stopped: {:?}",
                keeper.await
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
            now_held = holders(&db).await;
        }
        assert_eq!(now_held.len(), 1);
        assert_ne!(now_held[0], old, "held by a new session of this process");
        // Still serving several checks later.
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert!(!keeper.is_finished(), "still serving");
        // The process stops: its live session closes, and a restart takes the lock.
        keeper.abort();
        let _ = keeper.await;
        let restarted = db
            .store()
            .hold_instance_lock(Duration::from_secs(10))
            .await
            .expect("a restart takes the lock");
        drop(restarted);
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_store_instance_lock_ends_its_own_session_from_a_take_it_gave_up() {
        // The lock's session is gone, and a take the keeper gave up after the lock was granted
        // left a session of this process holding it: the keeper knows that session for its
        // own by the process's name, ends it and holds the lock again.
        let Some(db) = super::super::testing::test_database().await else {
            return;
        };
        let mut held = db
            .store()
            .hold_instance_lock(Duration::ZERO)
            .await
            .expect("lock");
        end_session(&db, &mut held).await;
        let mut left = PgConnection::connect_with(&held.options)
            .await
            .expect("conn");
        let mut granted = false;
        for _ in 0..50 {
            granted = try_lock(&mut left).await.expect("try");
            if granted {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(granted, "the left session holds the lock");
        let left_pid = this_pid(&mut left).await.expect("pid");
        let first_pid = held.pid;
        let keeper = tokio::spawn(held.keep(Duration::from_millis(100)));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let now_held = holders(&db).await;
            if now_held.len() == 1 && now_held[0] != left_pid && now_held[0] != first_pid {
                break;
            }
            assert!(Instant::now() < deadline, "the lock was never taken again");
            assert!(
                !keeper.is_finished(),
                "the keeper stopped: {:?}",
                keeper.await
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!keeper.is_finished(), "still serving");
        keeper.abort();
        let _ = keeper.await;
        drop(left);
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_start_waits_for_a_session_that_lets_go() {
        let Some(db) = super::super::testing::test_database().await else {
            return;
        };
        let earlier = db
            .store()
            .hold_instance_lock(Duration::ZERO)
            .await
            .expect("lock");
        let letting_go = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            drop(earlier);
        });
        db.store()
            .hold_instance_lock(Duration::from_secs(10))
            .await
            .expect("taken once the earlier session let go");
        letting_go.await.expect("join");
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_start_refuses_a_lock_another_session_keeps() {
        // Another process's session holds the lock past the wait: the start is refused,
        // naming that session for the operator.
        let Some(db) = super::super::testing::test_database().await else {
            return;
        };
        let other = db
            .store()
            .hold_instance_lock(Duration::ZERO)
            .await
            .expect("lock");
        let pid = other.pid;
        let started = Instant::now();
        let refused = db
            .store()
            .hold_instance_lock(Duration::from_millis(600))
            .await;
        assert!(started.elapsed() >= Duration::from_millis(600), "waited");
        match refused {
            Err(StoreError::InUse(holder)) => {
                assert!(holder.contains(&format!("pid {pid} ")), "{holder}");
            }
            other => panic!("{other:?}"),
        }
        drop(other);
        db.drop_database().await.expect("drop");
    }
}
