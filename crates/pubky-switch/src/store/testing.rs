//! A fresh database per test.
//!
//! Tests that need PostgreSQL connect with `PUBKY_SWITCH_TEST_DATABASE_URL`, a URL whose
//! user may create databases. Each test creates its own database, so tests run in parallel
//! without seeing each other. Without the variable such a test is skipped, unless
//! `PUBKY_SWITCH_REQUIRE_DB` is set, as CI sets it: then a missing database fails the test.
//!
//! A test database is dropped by [`TestDatabase::drop_database`], or, when a test panics or
//! forgets to, when the [`TestDatabase`] is dropped. Each name carries its creation time
//! (`switch_test_<unix seconds>_<random>`), and the first database a test process creates
//! sweeps away the ones left from earlier runs: older than [`STALE_AFTER_SECS`] with no
//! connection, so a parallel run's databases are never touched.

use std::str::FromStr;

use sqlx::{Connection, Executor, PgConnection, postgres::PgConnectOptions};

use super::{DatabaseConfig, Store, StoreError};

/// The environment variable with the test server's URL.
pub const TEST_DATABASE_URL_ENV: &str = "PUBKY_SWITCH_TEST_DATABASE_URL";

/// The environment variable that turns a skipped database test into a failure.
pub const REQUIRE_DB_ENV: &str = "PUBKY_SWITCH_REQUIRE_DB";

/// How old a test database with no connection must be before a test run drops it.
pub const STALE_AFTER_SECS: u64 = 30 * 60;

/// Whether this process has swept stale test databases yet.
static SWEPT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// A database created for one test, migrated, with a [`Store`] on it. Dropped with it.
#[derive(Debug)]
pub struct TestDatabase {
    admin: PgConnectOptions,
    name: String,
    options: PgConnectOptions,
    store: Store,
    /// Set once [`TestDatabase::drop_database`] has dropped it.
    dropped: bool,
}

impl Drop for TestDatabase {
    /// Drop the database when its test unwinds or didn't drop it, from a thread with a
    /// runtime of its own, since `drop` can't wait on the test's.
    fn drop(&mut self) {
        if self.dropped {
            return;
        }
        let admin = self.admin.clone();
        let name = self.name.clone();
        let dropped = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                let mut conn = PgConnection::connect_with(&admin).await?;
                conn.execute(format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)").as_str())
                    .await?;
                Ok::<(), sqlx::Error>(())
            })?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        })
        .join();
        if !matches!(dropped, Ok(Ok(()))) {
            eprintln!("a test database wasn't dropped: {}", self.name);
        }
    }
}

/// The creation time a test database's name carries, in Unix seconds.
fn created_secs(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("switch_test_")?;
    let (secs, random) = rest.split_once('_')?;
    (random.len() == 16 && random.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| secs.parse().ok())
        .flatten()
}

/// Drop the test databases left from earlier runs: older than [`STALE_AFTER_SECS`] by
/// their names, with no connection. A database a run is using has connections; one being
/// created is new. Errors are reported, not raised: a sweep never fails a test.
async fn sweep_stale(admin: &PgConnectOptions) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let result = async {
        let mut conn = PgConnection::connect_with(admin).await?;
        let names: Vec<String> = sqlx::query_scalar(
            "SELECT d.datname FROM pg_database d WHERE d.datname LIKE 'switch\\_test\\_%' \
             AND NOT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datname = d.datname)",
        )
        .fetch_all(&mut conn)
        .await?;
        for name in names {
            let stale = created_secs(&name)
                .is_some_and(|created| now.saturating_sub(created) > STALE_AFTER_SECS);
            if stale {
                // Without FORCE: a run that connected meanwhile keeps its database.
                let _ = conn
                    .execute(format!("DROP DATABASE IF EXISTS {name}").as_str())
                    .await;
            }
        }
        conn.close().await?;
        Ok::<(), sqlx::Error>(())
    }
    .await;
    if let Err(error) = result {
        eprintln!("sweeping stale test databases: {error}");
    }
}

/// Why a test database couldn't be made.
#[derive(Debug, thiserror::Error)]
pub enum TestDatabaseError {
    /// `PUBKY_SWITCH_TEST_DATABASE_URL` isn't set, and `PUBKY_SWITCH_REQUIRE_DB` isn't
    /// either: the test is skipped.
    #[error("{TEST_DATABASE_URL_ENV} is not set")]
    Skipped,
    /// `PUBKY_SWITCH_REQUIRE_DB` is set, and `PUBKY_SWITCH_TEST_DATABASE_URL` isn't.
    #[error("{REQUIRE_DB_ENV} is set, but {TEST_DATABASE_URL_ENV} is not")]
    Required,
    /// The server refused.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl TestDatabase {
    /// Create a database with `config`'s pool settings, and migrate it.
    pub async fn create(config: &DatabaseConfig) -> Result<Self, TestDatabaseError> {
        Self::create_with(config, true).await
    }

    /// Create a database with `config`'s pool settings, migrated or empty, for an upgrade
    /// test that applies the migrations itself.
    pub async fn create_with(
        config: &DatabaseConfig,
        migrate: bool,
    ) -> Result<Self, TestDatabaseError> {
        let url = match std::env::var(TEST_DATABASE_URL_ENV) {
            Ok(url) if !url.is_empty() => url,
            _ if std::env::var_os(REQUIRE_DB_ENV).is_some() => {
                return Err(TestDatabaseError::Required);
            }
            _ => return Err(TestDatabaseError::Skipped),
        };
        let admin = PgConnectOptions::from_str(&url).map_err(StoreError::Database)?;
        if !SWEPT.swap(true, std::sync::atomic::Ordering::SeqCst) {
            sweep_stale(&admin).await;
        }
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix)
            .map_err(|_| StoreError::Corrupt("no randomness for a database name"))?;
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let name = format!("switch_test_{created}_{}", hex::encode(suffix));
        let mut conn = PgConnection::connect_with(&admin)
            .await
            .map_err(StoreError::Database)?;
        conn.execute(format!("CREATE DATABASE {name}").as_str())
            .await
            .map_err(StoreError::Database)?;
        conn.close().await.map_err(StoreError::Database)?;
        let options = admin.clone().database(&name);
        let store = Store::connect_with(options.clone(), config).await?;
        if migrate {
            store
                .migrate(&crate::service::announced_limits(
                    &crate::limits::Limits::default(),
                ))
                .await?;
        }
        Ok(Self {
            admin,
            name,
            options,
            store,
            dropped: false,
        })
    }

    /// The store on the test database.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Options to open more connections to the test database.
    pub fn options(&self) -> &PgConnectOptions {
        &self.options
    }

    /// The test database's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Open a connection to the server that may manage the test database.
    pub async fn admin(&self) -> Result<PgConnection, StoreError> {
        Ok(PgConnection::connect_with(&self.admin).await?)
    }

    /// Give out account `id`'s next `seq` without a chain item, as an inbox entry takes
    /// one (Switch spec 6.3), and commit.
    pub async fn give_out_seq(&self, id: &str) -> Result<u64, StoreError> {
        let mut txn = self
            .store
            .begin(id)
            .await?
            .ok_or(StoreError::Corrupt("no such account"))?;
        let seq = txn.next_seq()?;
        txn.commit().await?;
        Ok(seq)
    }

    /// Make the next read after the lock on this database wait, once its request has
    /// committed, until the pause's `resume` is notified: for a test that writes in between.
    ///
    /// # Panics
    ///
    /// When another test thread poisoned the slot. For tests only.
    pub fn pause_next_snapshot_read(&self) -> SnapshotPause {
        let pause = SnapshotPause::default();
        #[allow(clippy::expect_used)]
        let mut slot = self.store.snapshot_pause.lock().expect("pause slot");
        *slot = Some(pause.clone());
        pause
    }

    /// Close the store and drop the database.
    pub async fn drop_database(mut self) -> Result<(), StoreError> {
        self.store.close().await;
        let mut conn = self.admin().await?;
        conn.execute(format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name).as_str())
            .await?;
        self.dropped = true;
        Ok(())
    }
}

/// Where the next read after the lock waits ([`TestDatabase::pause_next_snapshot_read`]):
/// it notifies `reached` once its request has committed, and reads once `resume` is
/// notified.
#[derive(Clone, Debug, Default)]
pub struct SnapshotPause {
    /// Notified when the read is about to start, its request committed.
    pub reached: std::sync::Arc<tokio::sync::Notify>,
    /// Notify it to let the read go on.
    pub resume: std::sync::Arc<tokio::sync::Notify>,
}

/// Create a test database, or `None` when the test is to be skipped.
///
/// # Panics
///
/// When the database can't be made, or is required and not configured. For tests only.
pub async fn test_database() -> Option<TestDatabase> {
    match TestDatabase::create(&DatabaseConfig::default()).await {
        Ok(db) => Some(db),
        Err(TestDatabaseError::Skipped) => {
            eprintln!("skipped: set {TEST_DATABASE_URL_ENV} to run this test against PostgreSQL");
            None
        }
        #[allow(clippy::panic)]
        Err(error) => panic!("test database: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_testing_names_carry_their_creation_time() {
        assert_eq!(
            created_secs("switch_test_1700000000_0123456789abcdef"),
            Some(1_700_000_000)
        );
        // An old-style name, without a time, is never swept: its age can't be told.
        assert_eq!(created_secs("switch_test_0123456789abcdef"), None);
        assert_eq!(created_secs("other_1700000000_0123456789abcdef"), None);
    }

    async fn exists(conn: &mut PgConnection, name: &str) -> bool {
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
            .bind(name)
            .fetch_one(conn)
            .await
            .unwrap_or(true)
    }

    #[tokio::test]
    async fn test_testing_drops_a_database_its_test_left() {
        let Some(db) = test_database().await else {
            return;
        };
        let name = db.name().to_string();
        let Ok(mut admin) = db.admin().await else {
            return;
        };
        // As when a test panics before drop_database.
        drop(db);
        assert!(!exists(&mut admin, &name).await, "{name} was left behind");
    }

    #[tokio::test]
    async fn test_testing_sweeps_only_stale_unconnected_databases() {
        let Some(db) = test_database().await else {
            return;
        };
        let Ok(mut admin) = db.admin().await else {
            return;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let stale = format!(
            "switch_test_{}_00000000000000aa",
            now - STALE_AFTER_SECS - 60
        );
        let recent = format!("switch_test_{now}_00000000000000bb");
        for name in [&stale, &recent] {
            let _ = admin
                .execute(format!("CREATE DATABASE {name}").as_str())
                .await;
        }
        sweep_stale(&db.admin).await;
        assert!(
            !exists(&mut admin, &stale).await,
            "the stale one is dropped"
        );
        assert!(exists(&mut admin, &recent).await, "a recent one is kept");
        // The test's own database, connected, is kept too.
        assert!(exists(&mut admin, db.name()).await);
        let _ = admin
            .execute(format!("DROP DATABASE IF EXISTS {recent}").as_str())
            .await;
        let _ = db.drop_database().await;
    }
}
