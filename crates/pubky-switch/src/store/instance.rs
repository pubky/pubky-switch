//! One process per database (docs/configuration.md, "Topology"): the service's binary holds a
//! session-level advisory lock in the database for as long as it serves, so a second process
//! on the same database refuses to start.
//!
//! The lock lives with its session. The process never terminates a backend, its own or
//! another's, and never tells its own sessions from others'. Instead the lock's session asks
//! the server to close it soon after its client is gone: an idle timeout for a client that
//! sends nothing, and TCP keepalives and a user timeout for a peer that stopped answering.
//! [`InstanceLock::keep`] asks the session at every check whether it still holds the lock,
//! which also keeps a live session from going idle, and stops serving at the first check
//! that can't confirm it, or that runs late: the lock may have been free in the gap, and
//! another process may have taken it. A start takes the lock afresh, waiting a bounded time
//! for the server to close an earlier run's session.

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
    /// The service's: a check every 5 seconds, each answered within 5, so the process stops
    /// at most 10 seconds after the lock was last confirmed. The server closes the lock's
    /// session 15 seconds after its last statement ended, and about 15 seconds after a TCP
    /// peer stopped answering: after the process has stopped. A start waits up to 25
    /// seconds for the lock (docs/configuration.md, "Topology").
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

    /// How long a start waits for the lock: past the idle close, with two checks to spare.
    pub fn wait(self) -> Duration {
        self.every.saturating_mul(5)
    }

    /// The longest the process serves past the last confirmed check: the next check's sleep
    /// and its answer. Nothing is answered past it, so the process has stopped before the
    /// server closes a silent session, at three checks.
    fn overdue(self) -> Duration {
        self.every.saturating_mul(2)
    }

    /// The lock session's settings, so the server closes it once its client is gone, but
    /// only after the client would have stopped: an idle timeout of three checks; TCP
    /// keepalives after one quiet check, one a second, as many as the seconds of three
    /// checks; a user timeout of three checks, which on Linux closes a peer that stopped
    /// answering, keepalives or data, after it (a server that doesn't take it closes on the
    /// keepalives, after four checks); and no statement past one check.
    fn session_settings(self) -> String {
        let every_ms = self.every.as_millis().max(1);
        let keepalive_s = self.every.as_secs().max(1);
        format!(
            "SET idle_session_timeout = {idle}; SET tcp_keepalives_idle = {keepalive_s}; \
             SET tcp_keepalives_interval = 1; SET tcp_keepalives_count = {count}; \
             SET tcp_user_timeout = {user}; SET statement_timeout = {every_ms}",
            idle = self.idle().as_millis().max(1),
            count = keepalive_s.saturating_mul(3),
            user = every_ms.saturating_mul(3),
        )
    }
}

/// Why [`InstanceLock::keep`] ended: the process can no longer tell that it holds the
/// database alone.
#[derive(Debug, thiserror::Error)]
pub enum InstanceLockLost {
    /// A check got no answer in time, or found the lock gone from the session.
    #[error("the lock on this database couldn't be confirmed")]
    Unconfirmed,
    /// A check ran later than two checks after the last confirmed one, as after a pause of
    /// the process.
    #[error("the lock on this database went unchecked for {0:?}")]
    Overdue(Duration),
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

/// A moment on two clocks: the monotonic one, which a stopped VM, a system suspend or a
/// checkpoint restore may not advance, and the wall clock, which those do advance once the
/// host has set it again.
#[derive(Clone, Copy, Debug)]
struct Stamp {
    monotonic: Instant,
    wall: std::time::SystemTime,
}

impl Stamp {
    fn now() -> Self {
        Self {
            monotonic: Instant::now(),
            wall: std::time::SystemTime::now(),
        }
    }

    /// The time from `self` to `later`, the longer of the two clocks: a gap on either one
    /// counts. A wall clock set back counts nothing; one set forward only makes the gap
    /// look longer, which stops a healthy process, never keeps a stale one serving.
    fn until(self, later: Stamp) -> Duration {
        let monotonic = later.monotonic.saturating_duration_since(self.monotonic);
        let wall = later.wall.duration_since(self.wall).unwrap_or_default();
        monotonic.max(wall)
    }
}

/// Where the keeper reads the time: the system's clocks, or a test's.
type Clock = std::sync::Arc<dyn Fn() -> Stamp + Send + Sync>;

/// The system's clocks.
fn system_clock() -> Clock {
    std::sync::Arc::new(Stamp::now)
}

/// The database held by this process alone, as long as this lives.
pub struct InstanceLock {
    conn: Option<PgConnection>,
    /// The backend of the session that holds the lock.
    pid: i32,
    timing: LockTiming,
    /// When the check that last confirmed the lock was sent, or when the take that was
    /// granted the lock asked for it: the session held the lock at least until then.
    confirmed: Stamp,
    clock: Clock,
}

impl std::fmt::Debug for InstanceLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceLock")
            .field("pid", &self.pid)
            .field("timing", &self.timing)
            .field("confirmed", &self.confirmed)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Hold the database for this process alone: a session-level advisory lock on a
    /// connection of its own, outside the pools. While another session holds it, the take
    /// is tried again for up to [`LockTiming::wait`], long enough for the server to close a
    /// session whose client is gone, such as an earlier run's.
    ///
    /// # Errors
    ///
    /// [`StoreError::InUse`], naming the session that holds it, when the last try that got
    /// an answer found another one holding it; [`StoreError::LockUnanswered`] when no try got
    /// an answer in time; a database error otherwise, also when the server refuses the lock
    /// session's settings.
    pub async fn hold_instance_lock(&self, timing: LockTiming) -> Result<InstanceLock, StoreError> {
        let options = (*self.pool.connect_options()).clone();
        let lock = InstanceLock::wait_for(&options, timing, &system_clock()).await?;
        tracing::info!(
            backend_pid = lock.pid,
            "holding the database's instance lock"
        );
        Ok(lock)
    }
}

impl InstanceLock {
    /// Try the lock on new connections until it is taken, or until [`LockTiming::wait`] has
    /// passed: then what the last try that got an answer found. No try runs past the wait.
    async fn wait_for(
        options: &PgConnectOptions,
        timing: LockTiming,
        clock: &Clock,
    ) -> Result<Self, StoreError> {
        let deadline = Instant::now() + timing.wait();
        let mut last = None;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let bound = timing.every.min(left).max(Duration::from_millis(1));
            match tokio::time::timeout(bound, Self::take(options, timing, clock)).await {
                Ok(Ok(lock)) => return Ok(lock),
                Ok(Err(TakeError::Held(holder))) => {
                    last = Some(StoreError::InUse(holder.describe()));
                }
                Ok(Err(TakeError::Busy)) | Err(_) => {}
                Ok(Err(TakeError::Store(error))) => last = Some(error),
            }
            if Instant::now() >= deadline {
                return Err(last.unwrap_or(StoreError::LockUnanswered));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            tokio::time::sleep(Duration::from_millis(200).min(timing.every).min(left)).await;
        }
    }

    /// One try at the lock, on a new connection.
    async fn take(
        options: &PgConnectOptions,
        timing: LockTiming,
        clock: &Clock,
    ) -> Result<Self, TakeError> {
        let mut conn = PgConnection::connect_with(options)
            .await
            .map_err(StoreError::from)?;
        match Self::take_on(&mut conn, timing, clock).await {
            Ok((pid, asked)) => Ok(Self {
                conn: Some(conn),
                pid,
                timing,
                confirmed: asked,
                clock: clock.clone(),
            }),
            Err(error) => {
                let _ = conn.close().await;
                Err(error)
            }
        }
    }

    /// The lock on `conn`'s session: its backend, and when the lock was asked for, which is
    /// as late as the grant is known to hold.
    async fn take_on(
        conn: &mut PgConnection,
        timing: LockTiming,
        clock: &Clock,
    ) -> Result<(i32, Stamp), TakeError> {
        // The settings come first: a session that holds the lock is one the server closes
        // soon after its client is gone.
        conn.execute(timing.session_settings().as_str())
            .await
            .map_err(StoreError::from_db)?;
        let asked = clock();
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(INSTANCE_LOCK_KEY)
            .fetch_one(&mut *conn)
            .await
            .map_err(StoreError::from_db)?;
        if locked {
            let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *conn)
                .await
                .map_err(StoreError::from_db)?;
            return Ok((pid, asked));
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

    /// Check the lock at every check of its timing, and return at the first check that
    /// can't confirm it within what is left of two checks since the last confirmed one, so
    /// the caller stops serving. Time is read on two clocks, and a gap on either counts
    /// (the monotonic one and the wall clock): a check that starts, or an answer that comes, more than two checks
    /// after the last confirmed check was sent, as after a pause of the process, stops it
    /// too, and an answer confirms the lock only as of the moment its check was sent. So
    /// the process serves on without a confirmed lock for at most two checks (10 seconds
    /// with the service's timing) while its timers run, and a pause is caught at the first
    /// timer that fires after it. It never takes the lock again: the lock may have been free
    /// in the gap, and another process may have held it and served. A start takes it
    /// afresh. The lock comes back with the reason, still held if its session lives, so the
    /// caller can stop before it lets go.
    pub async fn keep(mut self) -> (InstanceLockLost, Self) {
        let every = self.timing.every;
        let overdue = self.timing.overdue();
        loop {
            // Measured before the sleep too: a pause since the lock was asked for, or since
            // the last confirmed check was sent, stops it at once.
            let since = self.confirmed.until((self.clock)());
            if since > overdue {
                return (InstanceLockLost::Overdue(since), self);
            }
            tokio::time::sleep(every.saturating_sub(since)).await;
            let sent = (self.clock)();
            let since = self.confirmed.until(sent);
            let Some(left) = overdue.checked_sub(since) else {
                return (InstanceLockLost::Overdue(since), self);
            };
            let Some(conn) = self.conn.as_mut() else {
                return (InstanceLockLost::Unconfirmed, self);
            };
            match tokio::time::timeout(left, Self::confirm(conn)).await {
                Ok(Ok(true)) => {
                    // An answer that waited out a pause of this process says nothing about
                    // the time since it was sent.
                    let since = self.confirmed.until((self.clock)());
                    if since > overdue {
                        return (InstanceLockLost::Overdue(since), self);
                    }
                    self.confirmed = sent;
                }
                Ok(Ok(false)) | Err(_) => return (InstanceLockLost::Unconfirmed, self),
                Ok(Err(failure)) => {
                    tracing::warn!(%failure, "checking the instance lock");
                    return (InstanceLockLost::Unconfirmed, self);
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

    /// Timing for tests: a check every second, the idle close at 3 s, a start's wait of 5 s.
    fn fast() -> LockTiming {
        LockTiming::checking_every(Duration::from_secs(1))
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
        assert_eq!(timing.overdue(), Duration::from_secs(10));
        assert_eq!(
            timing.session_settings(),
            "SET idle_session_timeout = 15000; SET tcp_keepalives_idle = 5; \
             SET tcp_keepalives_interval = 1; SET tcp_keepalives_count = 15; \
             SET tcp_user_timeout = 15000; SET statement_timeout = 5000"
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
            ("tcp_keepalives_count", "15"),
            ("tcp_user_timeout", "15000"),
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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_store_instance_lock_second_process_never_serves() {
        // A second process waits out its start's wait and is refused, naming the session
        // that holds the lock, which the first's keeper keeps live; the first serves on.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let held = db.store().hold_instance_lock(fast()).await.expect("lock");
        let pid = held.pid;
        let keeper = tokio::spawn(async move { held.keep().await.0 });
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
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_start_waits_for_a_session_that_lets_go() {
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let earlier = db.store().hold_instance_lock(fast()).await.expect("lock");
        let letting_go = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            drop(earlier);
        });
        db.store()
            .hold_instance_lock(fast())
            .await
            .expect("taken once the earlier session let go");
        letting_go.await.expect("join");
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_store_instance_lock_keeper_stops_when_its_session_ends() {
        // The database ends the lock's session, as a restart or a failover does, and another
        // process takes the lock: the keeper stops at its next check, without taking the lock
        // again, and the other serves on.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let first = db.store().hold_instance_lock(fast()).await.expect("lock");
        end_session(&db, &first).await;
        let second = db
            .store()
            .hold_instance_lock(fast())
            .await
            .expect("the other process takes it");
        let second_pid = second.pid;
        let second_keeper = tokio::spawn(async move { second.keep().await.0 });
        let started = Instant::now();
        let lost = tokio::time::timeout(Duration::from_secs(20), async { first.keep().await.0 })
            .await
            .expect("the keeper stops");
        assert!(
            matches!(
                lost,
                InstanceLockLost::Unconfirmed | InstanceLockLost::Overdue(_)
            ),
            "{lost:?}"
        );
        assert!(
            started.elapsed() <= fast().overdue() + fast().every,
            "at its next check"
        );
        assert_eq!(holders(&db).await, vec![second_pid]);
        assert!(!second_keeper.is_finished(), "the other serves on");
        second_keeper.abort();
        let _ = second_keeper.await;
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_store_instance_lock_frozen_session_is_closed_by_the_server() {
        // The lock's connection stops answering while its socket stays open, so no TCP
        // keepalive fails. The keeper stops within two checks, ending no session; the
        // server closes the frozen session once it has been idle, and a restart's start
        // then takes the lock within its wait.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let (options, frozen) = freezing_proxy(&db).await;
        let held = InstanceLock::wait_for(&options, fast(), &system_clock())
            .await
            .expect("lock");
        let old = held.pid;
        frozen.store(true, Ordering::SeqCst);
        let started = Instant::now();
        let lost = tokio::time::timeout(Duration::from_secs(20), async { held.keep().await.0 })
            .await
            .expect("the keeper stops");
        assert!(matches!(lost, InstanceLockLost::Unconfirmed), "{lost:?}");
        assert!(
            started.elapsed() <= fast().overdue() + fast().every,
            "within two checks"
        );
        let restarted = db
            .store()
            .hold_instance_lock(fast())
            .await
            .expect("a restart takes the lock");
        assert_eq!(holders(&db).await, vec![restarted.pid]);
        assert_ne!(restarted.pid, old);
        db.drop_database().await.expect("drop");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_store_instance_lock_copy_facing_a_live_original_stops() {
        // A copy of the running process has no usable connection of its own: its keeper
        // stops at its first check, and its restart finds the lock held by the original's
        // live session and is refused; the original serves on.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let original = db.store().hold_instance_lock(fast()).await.expect("lock");
        let original_pid = original.pid;
        let copy = InstanceLock {
            conn: None,
            pid: original.pid,
            timing: original.timing,
            confirmed: original.confirmed,
            clock: original.clock.clone(),
        };
        let original_keeper = tokio::spawn(async move { original.keep().await.0 });
        let lost = tokio::time::timeout(Duration::from_secs(20), async { copy.keep().await.0 })
            .await
            .expect("the copy stops");
        assert!(matches!(lost, InstanceLockLost::Unconfirmed), "{lost:?}");
        assert!(matches!(
            db.store().hold_instance_lock(fast()).await,
            Err(StoreError::InUse(_))
        ));
        assert!(!original_keeper.is_finished(), "the original serves on");
        assert_eq!(holders(&db).await, vec![original_pid]);
        original_keeper.abort();
        let _ = original_keeper.await;
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_keeper_stops_after_a_pause() {
        // The process was paused longer than two checks: the server may have closed the
        // session and another process taken the lock, so the keeper stops without asking.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let mut held = db.store().hold_instance_lock(fast()).await.expect("lock");
        held.confirmed.monotonic = Instant::now() - fast().overdue() - fast().every;
        let lost = tokio::time::timeout(Duration::from_secs(20), async { held.keep().await.0 })
            .await
            .expect("the keeper stops");
        assert!(matches!(lost, InstanceLockLost::Overdue(_)), "{lost:?}");
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_start_without_an_answer_says_so() {
        // A server that takes the connection and never answers: the start gives up after
        // its wait and says that no try was answered.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = silent.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = silent.accept().await {
                held.push(socket);
            }
        });
        let options = db.options().clone().host("127.0.0.1").port(port);
        let started = Instant::now();
        assert!(matches!(
            InstanceLock::wait_for(&options, fast(), &system_clock()).await,
            Err(StoreError::LockUnanswered)
        ));
        let waited = started.elapsed();
        assert!(
            waited >= fast().wait() && waited < fast().wait() + fast().every,
            "{waited:?}"
        );
        db.drop_database().await.expect("drop");
    }

    /// A clock that jumps `monotonic` and `wall` ahead from its `from`-th reading on, as a
    /// pause of the process would.
    fn jumping(from: usize, monotonic: Duration, wall: Duration) -> Clock {
        let readings = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        Arc::new(move || {
            let now = Stamp::now();
            if readings.fetch_add(1, Ordering::SeqCst) + 1 >= from {
                Stamp {
                    monotonic: now.monotonic + monotonic,
                    wall: now.wall + wall,
                }
            } else {
                now
            }
        })
    }

    #[tokio::test]
    async fn test_store_instance_lock_keeper_stops_after_a_suspension_only_the_wall_clock_saw() {
        // The host was suspended: the monotonic clock didn't move, the wall clock did. The
        // keeper stops at its next check, without asking.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let mut held = db.store().hold_instance_lock(fast()).await.expect("lock");
        held.clock = jumping(1, Duration::ZERO, fast().overdue() + fast().every);
        let lost = tokio::time::timeout(Duration::from_secs(20), async { held.keep().await.0 })
            .await
            .expect("the keeper stops");
        assert!(matches!(lost, InstanceLockLost::Overdue(_)), "{lost:?}");
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_keeper_stops_after_a_stall_during_its_check() {
        // The process stalled while its check was in flight: the answer waiting in the
        // socket says nothing about the stall, so the keeper stops as the answer comes in,
        // not one check later.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        let mut held = db.store().hold_instance_lock(fast()).await.expect("lock");
        // The first reading is the check's sending, the second its answer.
        let stall = fast().overdue() + fast().every;
        held.clock = jumping(2, stall, stall);
        let started = Instant::now();
        let lost = tokio::time::timeout(Duration::from_secs(20), async { held.keep().await.0 })
            .await
            .expect("the keeper stops");
        assert!(matches!(lost, InstanceLockLost::Overdue(_)), "{lost:?}");
        assert!(
            started.elapsed() < fast().every * 2,
            "at the answer of its first check"
        );
        db.drop_database().await.expect("drop");
    }

    #[tokio::test]
    async fn test_store_instance_lock_keeper_stops_after_a_stall_during_the_take() {
        // The process stalled after the take asked for the lock: the grant holds only as of
        // the asking, so the keeper stops at its first step, before any sleep.
        let Some(db) = crate::store::testing::test_database().await else {
            return;
        };
        // The first reading is the take's asking, the second the keeper's first step.
        let stall = fast().overdue() + fast().every;
        let clock = jumping(2, stall, stall);
        let held =
            InstanceLock::wait_for(db.store().pool.connect_options().as_ref(), fast(), &clock)
                .await
                .expect("lock");
        let started = Instant::now();
        let lost = tokio::time::timeout(Duration::from_secs(20), async { held.keep().await.0 })
            .await
            .expect("the keeper stops");
        assert!(matches!(lost, InstanceLockLost::Overdue(_)), "{lost:?}");
        assert!(started.elapsed() < fast().every, "at its first step");
        db.drop_database().await.expect("drop");
    }

    #[test]
    fn test_store_instance_lock_gap_counts_the_longer_clock() {
        let then = Stamp::now();
        let ahead = |monotonic: u64, wall: u64| Stamp {
            monotonic: then.monotonic + Duration::from_secs(monotonic),
            wall: then.wall + Duration::from_secs(wall),
        };
        assert_eq!(then.until(ahead(3, 1)), Duration::from_secs(3));
        assert_eq!(then.until(ahead(1, 30)), Duration::from_secs(30));
        let set_back = Stamp {
            monotonic: then.monotonic + Duration::from_secs(2),
            wall: then.wall - Duration::from_secs(60),
        };
        assert_eq!(then.until(set_back), Duration::from_secs(2));
    }
}
