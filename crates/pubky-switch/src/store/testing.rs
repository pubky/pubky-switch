//! A fresh database per test.
//!
//! Tests that need PostgreSQL connect with `PUBKY_SWITCH_TEST_DATABASE_URL`, a URL whose
//! user may create databases. Each test creates its own database, so tests run in parallel
//! without seeing each other. Without the variable such a test is skipped, unless
//! `PUBKY_SWITCH_REQUIRE_DB` is set, as CI sets it: then a missing database fails the test.

use std::str::FromStr;

use sqlx::{Connection, Executor, PgConnection, postgres::PgConnectOptions};

use super::{DatabaseConfig, Store, StoreError};

/// The environment variable with the test server's URL.
pub const TEST_DATABASE_URL_ENV: &str = "PUBKY_SWITCH_TEST_DATABASE_URL";

/// The environment variable that turns a skipped database test into a failure.
pub const REQUIRE_DB_ENV: &str = "PUBKY_SWITCH_REQUIRE_DB";

/// A database created for one test, migrated, with a [`Store`] on it.
#[derive(Debug)]
pub struct TestDatabase {
    admin: PgConnectOptions,
    name: String,
    options: PgConnectOptions,
    store: Store,
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
        let url = match std::env::var(TEST_DATABASE_URL_ENV) {
            Ok(url) if !url.is_empty() => url,
            _ if std::env::var_os(REQUIRE_DB_ENV).is_some() => {
                return Err(TestDatabaseError::Required);
            }
            _ => return Err(TestDatabaseError::Skipped),
        };
        let admin = PgConnectOptions::from_str(&url).map_err(StoreError::Database)?;
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix)
            .map_err(|_| StoreError::Corrupt("no randomness for a database name"))?;
        let name = format!("switch_test_{}", hex::encode(suffix));
        let mut conn = PgConnection::connect_with(&admin)
            .await
            .map_err(StoreError::Database)?;
        conn.execute(format!("CREATE DATABASE {name}").as_str())
            .await
            .map_err(StoreError::Database)?;
        conn.close().await.map_err(StoreError::Database)?;
        let options = admin.clone().database(&name);
        let store = Store::connect_with(options.clone(), config).await?;
        store.migrate().await?;
        Ok(Self {
            admin,
            name,
            options,
            store,
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

    /// Close the store and drop the database.
    pub async fn drop_database(self) -> Result<(), StoreError> {
        self.store.close().await;
        let mut conn = self.admin().await?;
        conn.execute(format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name).as_str())
            .await?;
        Ok(())
    }
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
