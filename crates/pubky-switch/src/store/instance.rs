//! One process per database (docs/configuration.md, "Topology"): the service's binary holds a
//! session-level advisory lock in the database for as long as it serves, so a second process
//! on the same database refuses to start.
//!
//! The lock lives with its session, and the process never ends a session, its own or another's.
//! Instead the lock's session asks the server to close it soon after its client is gone: TCP
//! keepalives and a user timeout for a peer that stopped answering, and an idle timeout for
//! one that sends nothing. [`InstanceLock::keep`] asks the session every check whether it
//! still holds the lock, so a live session is never idle that long. When it can't confirm
//! the lock, it waits a bounded time on a new connection for the lock: long enough for the
//! server to close a session of its own whose connection stopped answering. If another
//! session holds the lock throughout, whoever that is, the process stops serving.

use std::time::{Duration, Instant};

use sqlx::{Connection, Executor, PgConnection, Row, postgres::PgConnectOptions};

use super::{Store, StoreError};

/// The advisory lock key of the service's one process: "pubkyswi".
const INSTANCE_LOCK_KEY: i64 = 0x7075_626b_7973_7769;

/// The key's halves, as `pg_locks` shows a `bigint` advisory lock: `classid` and `objid`.
const LOCK_CLASSID: i64 = INSTANCE_LOCK_KEY >> 32;
const LOCK_OBJID: i64 = INSTANCE_LOCK_KEY & 0xffff_ffff;

/// The session that holds the lock, if any, among those of this key. A column the database
/// hides from this role reads as null.
const HOLDER: &str = "SELECT l.pid, a.pid IS NOT NULL AS present, \
     a.backend_start::TEXT AS started, host(a.client_addr) AS addr \
     FROM pg_locks l LEFT JOIN pg_stat_activity a ON a.pid = l.pid \
     WHERE l.locktype = 'advisory' AND l.granted AND l.classid::BIGINT = $1 \
     AND l.objid::BIGINT = $2 AND l.objsubid = 1 \
     AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())";

/// The times of the database lock, all set by how often it is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockTiming {
    every: Duration,
}

impl LockTiming {
    /// The service's: a check every 5 seconds. The server closes the lock's session 15
    /// seconds after its client last sent anything, and within about 8 seconds once a TCP
    /// peer stops answering its keepalives; a start or a keeper waits up to 25 seconds for
    /// the lock (docs/configuration.md, "Topology").
    pub const SERVICE: Self = Self {
        every: Duration::from_secs(5),
    };

    /// Timing with a check every `every`, for tests.
    #[cfg(any(test, feature = "test-util"))]
    pub fn checking_every(every: Duration) -> Self {
        Self { every }
    }

    /// How long the server lets the lock's session sit idle before it closes it: three
    /// checks, so a live session, asked at every check, never comes near it.
    fn idle(self) -> Duration {
        self.every.saturating_mul(3)
    }

    /// How long a start or a keeper waits for the lock: past the idle close, with a check to
    /// spare.
    pub fn wait(self) -> Duration {
        self.every.saturating_mul(5)
    }

    /// The lock session's settings, so the server closes it once its client is gone: an
    /// idle timeout for a client that sends nothing; TCP keepalives every second after one
    /// quiet check, three unanswered ones closing it; a user timeout of two checks for data
    /// the client doesn't acknowledge; and no statement past one check.
    fn session_settings(self) -> String {
        let every_ms = self.every.as_millis().max(1);
        let keepalive_s = self.every.as_secs().max(1);
        format!(
            "SET idle_session_timeout = {idle}; SET tcp_keepalives_idle = {keepalive_s}; \
             SET tcp_keepalives_interval = 1; SET tcp_keepalives_count = 3; \
             SET tcp_user_timeout = {user}; SET statement_timeout = {every_ms}",
            idle = self.idle().as_millis().max(1),
            user = every_ms.saturating_mul(2),
        )
    }
}

/// Why [`InstanceLock::keep`] ended: the process no longer holds the database alone, or
/// can't tell that it does.
#[derive(Debug, thiserror::Error)]
pub enum InstanceLockLost {
    /// Another session held the lock throughout the wait.
    #[error("another process serves this database: {0}")]
    InUse(String),
    /// The lock couldn't be confirmed, nor taken again, within the wait.
    #[error("the lock on this database couldn't be confirmed")]
    Unconfirmed,
}

/// A session that holds the lock.
#[derive(Clone, Debug)]
struct Holder {
    pid: i32,
    /// Whether its backend still has a status entry: one that ended between the reads of
    /// the locks and of the sessions has none, and its lock is going.
    present: bool,
    started: Option<String>,
    addr: Option<String>,
}

impl Holder {
    /// The holder as the operator needs it to find it.
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

/// Why one try at the lock failed.
enum TakeError {
    /// Another session holds it.
    Held(Holder),
    /// The holder let go between the reads: try again.
    Busy,
    /// The database failed.
    Store(StoreError),
}

impl From<StoreError> for TakeError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// What a wait for the lock found when it ran out.
enum WaitError {
    Held(Holder),
    Store(StoreError),
}

/// The database held by this process alone, as long as this lives.
#[derive(Debug)]
pub struct InstanceLock {
    conn: Option<PgConnection>,
    /// The backend of the session that holds the lock.
    pid: i32,
    options: PgConnectOptions,
    timing: LockTiming,
}

impl Store {
    /// Hold the database for this process alone: a session-level advisory lock on a
    /// connection of its own, outside the pools. While another session holds it, the take
    /// is tried again for up to [`LockTiming::wait`], long enough for the server to close a
    /// session whose client is gone, such as an earlier run's.
    ///
    /// # Errors
    ///
    /// [`StoreError::InUse`], naming the session that holds it, when another one still does
    /// after the wait; a database error otherwise, also when the server refuses the lock
    /// session's settings.
    pub async fn hold_instance_lock(&self, timing: LockTiming) -> Result<InstanceLock, StoreError> {
        let options = (*self.pool.connect_options()).clone();
        match InstanceLock::wait_for(&options, timing).await {
            Ok(lock) => Ok(lock),
            Err(WaitError::Held(holder)) => Err(StoreError::InUse(holder.describe())),
            Err(WaitError::Store(error)) => Err(error),
        }
    }
}

impl InstanceLock {
    /// Try the lock on new connections until it is taken, or until [`LockTiming::wait`] has
    /// passed: then what the last try found.
    async fn wait_for(options: &PgConnectOptions, timing: LockTiming) -> Result<Self, WaitError> {
        let deadline = Instant::now() + timing.wait();
        // What the last try that got an answer found; a try cut short finds nothing new.
        let mut last = None;
        loop {
            // No try runs past the deadline.
            let left = deadline.saturating_duration_since(Instant::now());
            let bound = timing.every.min(left).max(Duration::from_millis(1));
            match tokio::time::timeout(bound, Self::take(options, timing)).await {
                Ok(Ok(lock)) => return Ok(lock),
                Ok(Err(TakeError::Held(holder))) => last = Some(WaitError::Held(holder)),
                Ok(Err(TakeError::Busy)) => {}
                Ok(Err(TakeError::Store(error))) => last = Some(WaitError::Store(error)),
                Err(_) if last.is_none() => {
                    last = Some(WaitError::Store(StoreError::LockTimeout));
                }
                Err(_) => {}
            }
            if Instant::now() >= deadline {
                return Err(last.unwrap_or(WaitError::Store(StoreError::LockTimeout)));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            tokio::time::sleep(Duration::from_millis(200).min(timing.every).min(left)).await;
        }
    }

    /// One try at the lock, on a new connection.
    async fn take(options: &PgConnectOptions, timing: LockTiming) -> Result<Self, TakeError> {
        let mut conn = PgConnection::connect_with(options)
            .await
            .map_err(StoreError::from)?;
        match Self::take_on(&mut conn, timing).await {
            Ok(pid) => Ok(Self {
                conn: Some(conn),
                pid,
                options: options.clone(),
                timing,
            }),
            Err(error) => {
                let _ = conn.close().await;
                Err(error)
            }
        }
    }

    async fn take_on(conn: &mut PgConnection, timing: LockTiming) -> Result<i32, TakeError> {
        // The settings come first: a session that holds the lock is one the server closes
        // soon after its client is gone.
        conn.execute(timing.session_settings().as_str())
            .await
            .map_err(StoreError::from_db)?;
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(INSTANCE_LOCK_KEY)
            .fetch_one(&mut *conn)
            .await
            .map_err(StoreError::from_db)?;
        if locked {
            return Ok(sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *conn)
                .await
                .map_err(StoreError::from_db)?);
        }
        match holder(conn).await? {
            Some(holder) if holder.present => Err(TakeError::Held(holder)),
            _ => Err(TakeError::Busy),
        }
    }

    /// Whether this lock's session holds the lock, asked of the session itself: not only
    /// that the connection answers. The question also keeps the session from going idle.
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

    /// Check the lock at every check of its timing: that its session still holds it, within
    /// a check. A session that doesn't answer in time, or no longer holds it, is given up,
    /// and the lock is waited for on new connections for up to [`LockTiming::wait`]: the
    /// server closes a given-up session of this process within that time, and its lock goes
    /// with it. Returns when another session holds the lock throughout the wait, whoever's
    /// it is, or when the database couldn't be reached throughout it, so the caller stops
    /// serving: once it held the lock, the process serves on without it for at most a check,
    /// its answer time and the wait (35 seconds with the service's timing).
    pub async fn keep(mut self) -> InstanceLockLost {
        let every = self.timing.every;
        loop {
            tokio::time::sleep(every).await;
            if let Some(conn) = self.conn.as_mut()
                && matches!(
                    tokio::time::timeout(every, Self::confirm(conn)).await,
                    Ok(Ok(true))
                )
            {
                continue;
            }
            // Given up without waiting: if its session is alive on the server, the server
            // closes it once it has been idle, and its lock goes.
            drop(self.conn.take());
            match Self::wait_for(&self.options, self.timing).await {
                Ok(taken) => {
                    tracing::warn!("the instance lock's session was lost; the lock is held again");
                    self.conn = taken.conn;
                    self.pid = taken.pid;
                }
                Err(WaitError::Held(holder)) => return InstanceLockLost::InUse(holder.describe()),
                Err(WaitError::Store(failure)) => {
                    tracing::warn!(%failure, "taking the instance lock again");
                    return InstanceLockLost::Unconfirmed;
                }
            }
        }
    }
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
            present: row.try_get("present")?,
            started: row.try_get("started")?,
            addr: row.try_get("addr")?,
        })
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;
    use crate::store::testing::TestDatabase;

    /// Fast timing for tests: a check every 200 ms, the idle close at 600 ms, a wait of 1 s.
    fn fast() -> LockTiming {
        LockTiming::checking_every(Duration::from_millis(200))
    }

    /// The pids of the sessions that hold the lock.
    async fn holders(db: &TestDatabase) -> Vec<i32> {
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

    /// End the session that holds `lock`, as a database restart or a failover does.
    async fn end_session(db: &TestDatabase, lock: &InstanceLock) {
        let mut other = PgConnection::connect_with(db.options())
            .await
            .expect("conn");
        sqlx::query("SELECT pg_terminate_backend($1)")
            .bind(lock.pid)
            .execute(&mut other)
            .await
            .expect("terminate");
        other.close().await.expect("close");
    }

    /// A TCP proxy to the test database whose first connection can be frozen: it stops
    /// forwarding and keeps both its sockets open, while later connections pass.
    async fn freezing_proxy(db: &TestDatabase) -> (PgConnectOptions, Arc<AtomicBool>) {
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

    #[test]
    fn test_store_instance_lock_service_timing() {
        let timing = LockTiming::SERVICE;
        assert_eq!(timing.idle(), Duration::from_secs(15));
        assert_eq!(timing.wait(), Duration::from_secs(25));
        assert_eq!(
            timing.session_settings(),
            "SET idle_session_timeout = 15000; SET tcp_keepalives_idle = 5; \
             SET tcp_keepalives_interval = 1; SET tcp_keepalives_count = 3; \
             SET tcp_user_timeout = 10000; SET statement_timeout = 5000"
        );
    }

    #[tokio::test]
    async fn test_store_instance_lock_session_has_its_settings_on_tcp() {
        // Over TCP the server takes every setting, so it closes the session itself once its
        // client is gone.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let mut held = db
            .store()
            .hold_instance_lock(LockTiming::SERVICE)
            .await
            .expect("lock");
        let conn = held.conn.as_mut().expect("held");
        let tcp: bool = sqlx::query_scalar("SELECT inet_client_addr() IS NOT NULL")
            .fetch_one(&mut *conn)
            .await
            .expect("tcp");
        assert!(tcp, "the test database is reached over TCP");
        for (name, value) in [
            ("idle_session_timeout", "15s"),
            ("tcp_keepalives_idle", "5"),
            ("tcp_keepalives_interval", "1"),
            ("tcp_keepalives_count", "3"),
            ("tcp_user_timeout", "10000"),
            ("statement_timeout", "5s"),
        ] {
            let shown: String = sqlx::query_scalar(&format!("SHOW {name}"))
                .fetch_one(&mut *conn)
                .await
                .expect("show");
            assert_eq!(shown, value, "{name}");
        }
        drop(held);
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_second_process_never_serves() {
        // A second process waits out the wait and is refused, naming the session that
        // holds the lock, which its keeper keeps live; once the first stops, a start takes it.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let held = db.store().hold_instance_lock(fast()).await.expect("lock");
        let pid = held.pid;
        let keeper = tokio::spawn(held.keep());
        let started = Instant::now();
        match db.store().hold_instance_lock(fast()).await {
            Err(StoreError::InUse(holder)) => {
                assert!(holder.contains(&format!("pid {pid} ")), "{holder}");
            }
            other => panic!("{other:?}"),
        }
        assert!(started.elapsed() >= fast().wait(), "waited");
        assert_eq!(holders(&db).await, vec![pid]);
        assert!(!keeper.is_finished(), "the first serves on");
        keeper.abort();
        let _ = keeper.await;
        db.store()
            .hold_instance_lock(fast())
            .await
            .expect("free again");
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_start_waits_for_a_session_that_lets_go() {
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let earlier = db.store().hold_instance_lock(fast()).await.expect("lock");
        let letting_go = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            drop(earlier);
        });
        db.store()
            .hold_instance_lock(fast())
            .await
            .expect("taken once the earlier session let go");
        letting_go.await.expect("join");
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_is_taken_again_after_its_session_ends() {
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let held = db.store().hold_instance_lock(fast()).await.expect("lock");
        end_session(&db, &held).await;
        // The keeper takes the lock again and goes on: it is still running after several
        // checks, and no other process can take the database.
        let keeper = tokio::spawn(held.keep());
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert!(!keeper.is_finished(), "still held");
        assert_eq!(holders(&db).await.len(), 1);
        assert!(matches!(
            db.store().hold_instance_lock(fast()).await,
            Err(StoreError::InUse(_))
        ));
        keeper.abort();
        let _ = keeper.await;
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_store_instance_lock_frozen_session_is_closed_by_the_server() {
        // The lock's connection stops answering while its socket stays open, so no TCP
        // keepalive fails: the server closes the session once it has been idle, its lock
        // goes, and the keeper holds the lock again within the wait, ending no session. A
        // restart after it takes the lock.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let (options, frozen) = freezing_proxy(&db).await;
        let held = InstanceLock::wait_for(&options, fast())
            .await
            .unwrap_or_else(|_| panic!("lock"));
        let old = held.pid;
        assert_eq!(holders(&db).await, vec![old]);
        frozen.store(true, Ordering::SeqCst);
        let keeper = tokio::spawn(held.keep());
        let started = Instant::now();
        loop {
            let now_held = holders(&db).await;
            if now_held.len() == 1 && now_held[0] != old {
                break;
            }
            assert!(
                started.elapsed() < fast().every + fast().every + fast().wait(),
                "the lock wasn't held again within the bound"
            );
            assert!(
                !keeper.is_finished(),
                "the keeper stopped: {:?}",
                keeper.await
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert!(!keeper.is_finished(), "still serving");
        keeper.abort();
        let _ = keeper.await;
        db.store()
            .hold_instance_lock(fast())
            .await
            .expect("a restart takes the lock");
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_store_instance_lock_copy_facing_a_live_original_stops() {
        // A copy of the running process has no usable connection of its own and finds the
        // lock held by the original's live session: it waits out the wait and stops, and
        // the original serves on.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let original = db.store().hold_instance_lock(fast()).await.expect("lock");
        let original_pid = original.pid;
        let copy = InstanceLock {
            conn: None,
            pid: original.pid,
            options: original.options.clone(),
            timing: original.timing,
        };
        let original_keeper = tokio::spawn(original.keep());
        let lost = tokio::time::timeout(Duration::from_secs(10), copy.keep())
            .await
            .expect("the copy stops");
        assert!(matches!(lost, InstanceLockLost::InUse(_)), "{lost:?}");
        assert!(!original_keeper.is_finished(), "the original serves on");
        assert_eq!(holders(&db).await, vec![original_pid]);
        original_keeper.abort();
        let _ = original_keeper.await;
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_keeper_stops_once_another_process_holds_it() {
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let first = db.store().hold_instance_lock(fast()).await.expect("lock");
        end_session(&db, &first).await;
        let second = db
            .store()
            .hold_instance_lock(fast())
            .await
            .expect("the second process holds it");
        let second_pid = second.pid;
        let second_keeper = tokio::spawn(second.keep());
        let lost = tokio::time::timeout(Duration::from_secs(10), first.keep())
            .await
            .expect("the keeper ends");
        assert!(matches!(lost, InstanceLockLost::InUse(_)), "{lost:?}");
        assert_eq!(holders(&db).await, vec![second_pid]);
        second_keeper.abort();
        let _ = second_keeper.await;
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_keeper_stops_when_the_lock_cant_be_confirmed() {
        // The session is gone and the database can't be reached: after the wait the keeper
        // gives up, so the process stops serving a database it can't tell it holds.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let mut held = db.store().hold_instance_lock(fast()).await.expect("lock");
        end_session(&db, &held).await;
        held.options = held.options.clone().host("127.0.0.1").port(1);
        let lost = tokio::time::timeout(Duration::from_secs(10), held.keep())
            .await
            .expect("the keeper ends");
        assert!(matches!(lost, InstanceLockLost::Unconfirmed), "{lost:?}");
        db.drop_database().await.expect("drop");
    }
}
