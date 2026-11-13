//! Durable storage in PostgreSQL.
//!
//! **One account at a time.** Every request to an account runs in one database transaction
//! that first locks the account's row ([`Store::begin`]), so one account's operations are
//! serialized while other accounts proceed in parallel (Switch spec 6.5). What a request
//! changes commits all at once or not at all: a batch that fails, or a process that dies
//! before the commit, leaves no trace.
//!
//! **Durable, then answered** (Switch wire 7.3 step 10). A request's answer carries a `seq`,
//! a transition proof or a signed head only once [`AccountTxn::commit`] has returned, which
//! it does once PostgreSQL has made the commit durable. The service refuses to use a
//! database where commits may not be durable: `fsync` must be on and `synchronous_commit`
//! must not be `off`. With synchronous replicas, `synchronous_commit` should be `on` or
//! `remote_apply`, so a commit is durable on every replica that could be promoted; an
//! asynchronous replica must never be promoted to serve writes (Switch spec 6.5).
//!
//! **The key's mark** (Switch spec 6.5) lives in the key store, apart from the database and
//! its backups. [`AccountTxn::commit_marked`] moves it once the state is durable, and
//! [`AccountTxn::mark_check`] finds a state behind it, as a restored backup would leave.

mod account;
mod allow;
mod apps;
mod chain;
mod claim_codec;
mod connect;
mod documents;
mod enrollments;
mod feed;
mod handover;
mod identity;
mod inbox;
mod keying;
mod ops;
mod peers;
mod push;
mod records;
mod recovery;
mod snapshot;
mod sweeps;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;

use std::{str::FromStr, time::Duration};

use serde::{Deserialize, Serialize};
use sqlx::{
    Connection, Executor, PgConnection, PgPool, Row,
    postgres::{PgConnectOptions, PgPoolOptions},
};

pub use account::{AccountHead, AccountTxn, CommitError, Committed, NewAccount, Savepoint};
pub use allow::{AllowEntry, AllowInvite};
pub use apps::{AppsView, KeptAppId, KeptReason, OpenAttempt, PartSpan, newly_listed};
pub use chain::NewChainItem;
pub use connect::ConnectRequest;
pub use feed::{AppDocs, CurrentDocs, FeedRow, FeedSnapshot, PageReader};
pub use handover::StoredHandover;
pub use identity::HeldIdentity;
pub use inbox::{InboxItem, InboxUsage, NewEntry, StoredEntry};
pub use keying::{Keyed, keying_lock_key};
pub use ops::{
    DivergentUpload, ListName, RecordOrigin, StoredApp, StoredBundlePart, StoredClaimEntry,
    StoredInvite, StoredListEntry, StoredRecord,
};
pub use peers::{HeldPeer, PeerFloor};
pub use push::{OwedKey, PushRegistration};
pub use recovery::{RECOVERY_KEEPS, Recovery, recovery_clears};
pub use snapshot::SnapshotRead;

use crate::admin::{CheckFuture, ReadinessCheck};

/// The environment variable that overrides `database.url`.
pub const DATABASE_URL_ENV: &str = "PUBKY_SWITCH_DATABASE_URL";

/// A key store entry an erasure still owes deleting (Switch wire 7.4.16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasedKey {
    /// The key's ID in the key store.
    pub key: crate::keys::KeyId,
    /// The erased account's Pubky ID.
    pub account: String,
    /// When the account was erased, in its service time.
    pub erased_at_ms: u64,
    /// The key wasn't erased with its account, so its deletion records no erasure: a service
    /// key a generation change retired at an account that lives on (Switch wire 3.3), or a
    /// push key (Switch wire 8.1).
    pub retired: bool,
}

/// The schema migrations, applied in order.
pub static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// The database settings.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseConfig {
    /// The PostgreSQL connection URL. `PUBKY_SWITCH_DATABASE_URL` overrides it; prefer the
    /// variable, so the password stays out of the file.
    pub url: Option<String>,
    /// Most connections in the pool.
    pub max_connections: u32,
    /// How long a request waits for a free connection.
    pub acquire_timeout_ms: u64,
    /// How long a request waits for its account's lock before it gives up with
    /// `503 unavailable`.
    pub lock_timeout_ms: u64,
    /// Apply pending schema migrations at start.
    pub migrate_on_start: bool,
    /// Most reads at once that run after the account's lock on a snapshot of the state
    /// under it (`GET /allow`), each on a connection of its own, on top
    /// of `max_connections`. A request waits for one before it takes the lock.
    pub snapshot_readers: u32,
    /// How long the service keeps trying to reach the database at start, while it refuses
    /// connections or is still starting up, before it gives up and exits.
    pub connect_retry_ms: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: None,
            max_connections: 16,
            acquire_timeout_ms: 5_000,
            lock_timeout_ms: 10_000,
            migrate_on_start: true,
            snapshot_readers: 4,
            connect_retry_ms: 30_000,
        }
    }
}

impl std::fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("url", &self.url.as_ref().map(|_| "[redacted]"))
            .field("max_connections", &self.max_connections)
            .field("acquire_timeout_ms", &self.acquire_timeout_ms)
            .field("lock_timeout_ms", &self.lock_timeout_ms)
            .field("migrate_on_start", &self.migrate_on_start)
            .field("snapshot_readers", &self.snapshot_readers)
            .field("connect_retry_ms", &self.connect_retry_ms)
            .finish()
    }
}

/// A database setting that breaks a rule.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("database.{name}: {reason}")]
pub struct DatabaseConfigError {
    /// The setting's name.
    pub name: &'static str,
    /// What is wrong with it.
    pub reason: &'static str,
}

impl DatabaseConfig {
    /// Check the settings.
    pub fn validate(&self) -> Result<(), DatabaseConfigError> {
        let fail = |name, reason| Err(DatabaseConfigError { name, reason });
        if self.max_connections == 0 {
            return fail("max_connections", "must be at least 1");
        }
        if self.acquire_timeout_ms == 0 {
            return fail("acquire_timeout_ms", "must be at least 1");
        }
        if self.lock_timeout_ms == 0 {
            return fail("lock_timeout_ms", "must be at least 1");
        }
        if self.snapshot_readers == 0 {
            return fail("snapshot_readers", "must be at least 1");
        }
        if let Some(url) = &self.url
            && (!(url.starts_with("postgres://") || url.starts_with("postgresql://"))
                || PgConnectOptions::from_str(url).is_err())
        {
            return fail("url", "not a PostgreSQL connection URL");
        }
        Ok(())
    }

    /// The URL to connect to: `PUBKY_SWITCH_DATABASE_URL`, or `url`.
    pub fn effective_url(&self) -> Option<String> {
        std::env::var(DATABASE_URL_ENV)
            .ok()
            .filter(|url| !url.is_empty())
            .or_else(|| self.url.clone())
    }
}

/// What the store can fail at.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database failed, or a statement was refused.
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    /// A schema migration failed.
    #[error("migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// The database may acknowledge a commit before it is durable.
    #[error("the database doesn't make commits durable: {0}")]
    NotDurable(String),
    /// The account's lock wasn't free within `lock_timeout_ms`.
    #[error("the account is busy")]
    LockTimeout,
    /// A concurrent change took what the request relied on; a retry finds the new state.
    #[error("raced: {0}")]
    Raced(&'static str),
    /// A value doesn't fit what the database stores, or the reverse.
    #[error("value out of range: {0}")]
    OutOfRange(&'static str),
    /// A stored value breaks an invariant.
    #[error("corrupt account state: {0}")]
    Corrupt(&'static str),
    /// No database URL is configured.
    #[error("no database URL: set database.url or {DATABASE_URL_ENV}")]
    NoUrl,
}

/// PostgreSQL's code for a lock that wasn't free within `lock_timeout`.
const LOCK_NOT_AVAILABLE: &str = "55P03";

impl StoreError {
    /// Map a database error, telling a lock timeout apart.
    pub(crate) fn from_db(error: sqlx::Error) -> Self {
        match &error {
            sqlx::Error::Database(db) if db.code().as_deref() == Some(LOCK_NOT_AVAILABLE) => {
                Self::LockTimeout
            }
            _ => Self::Database(error),
        }
    }
}

/// The durability settings of a database connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurabilitySettings {
    /// `fsync`.
    pub fsync: String,
    /// `synchronous_commit`.
    pub synchronous_commit: String,
    /// `synchronous_standby_names`.
    pub synchronous_standby_names: String,
}

impl DurabilitySettings {
    /// Read the settings in force on `conn`.
    pub async fn read(conn: &mut PgConnection) -> Result<Self, sqlx::Error> {
        let row = sqlx::query(
            "SELECT current_setting('fsync'), current_setting('synchronous_commit'), \
             current_setting('synchronous_standby_names')",
        )
        .fetch_one(conn)
        .await?;
        Ok(Self {
            fsync: row.try_get(0)?,
            synchronous_commit: row.try_get(1)?,
            synchronous_standby_names: row.try_get(2)?,
        })
    }

    /// Refuse settings under which a commit can return before it is durable.
    pub fn check(&self) -> Result<(), String> {
        if self.fsync != "on" {
            return Err(format!("fsync is {}", self.fsync));
        }
        if self.synchronous_commit == "off" {
            return Err("synchronous_commit is off".into());
        }
        Ok(())
    }

    /// Settings that are durable on this server but may not be on a synchronous replica:
    /// `local` or `remote_write` with synchronous standbys configured.
    pub fn replica_warning(&self) -> Option<String> {
        let weak = matches!(self.synchronous_commit.as_str(), "local" | "remote_write");
        (weak && !self.synchronous_standby_names.is_empty()).then(|| {
            format!(
                "synchronous_commit is {} with synchronous standbys: a commit may not be \
                 durable on a replica that could be promoted",
                self.synchronous_commit
            )
        })
    }
}

/// The service's database.
#[derive(Clone, Debug)]
pub struct Store {
    pool: PgPool,
    /// The connections reads after the lock use, apart from `pool`, so a request holding
    /// an account's lock never waits for one (`snapshot_readers`).
    readers: PgPool,
    /// The accounts with a read after the lock in flight: one each.
    reading: snapshot::Reading,
    lock_timeout_ms: u64,
    /// For tests: the next read after the lock waits here ([`testing::SnapshotPause`]).
    #[cfg(any(test, feature = "test-util"))]
    pub(crate) snapshot_pause: std::sync::Arc<std::sync::Mutex<Option<testing::SnapshotPause>>>,
}

impl Store {
    /// Connect with `config`. Every connection is checked for durable commits before use.
    pub async fn connect(config: &DatabaseConfig) -> Result<Self, StoreError> {
        let url = config.effective_url().ok_or(StoreError::NoUrl)?;
        let options = PgConnectOptions::from_str(&url)?;
        Self::connect_with(options, config).await
    }

    /// Connect to `options` with the pool settings of `config`.
    pub async fn connect_with(
        options: PgConnectOptions,
        config: &DatabaseConfig,
    ) -> Result<Self, StoreError> {
        // Check once on a connection of its own, so a database that would acknowledge
        // commits before they are durable is refused at start with the reason. The pool
        // checks every later connection too, in case the settings change.
        let mut first = connect_first(&options, config.connect_retry_ms).await?;
        let settings = DurabilitySettings::read(&mut first).await?;
        settings.check().map_err(StoreError::NotDurable)?;
        if let Some(warning) = settings.replica_warning() {
            tracing::warn!(%warning, "database durability");
        }
        first.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(Duration::from_millis(config.acquire_timeout_ms))
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    let settings = DurabilitySettings::read(conn).await?;
                    settings.check().map_err(|reason| {
                        sqlx::Error::Configuration(StoreError::NotDurable(reason).into())
                    })
                })
            })
            .connect_with(options.clone())
            .await?;
        // Read only, so their commits need no durability check.
        let readers = PgPoolOptions::new()
            .max_connections(config.snapshot_readers)
            .acquire_timeout(Duration::from_millis(config.acquire_timeout_ms))
            .connect_lazy_with(options);
        Ok(Self {
            pool,
            readers,
            reading: snapshot::Reading::default(),
            lock_timeout_ms: config.lock_timeout_ms,
            #[cfg(any(test, feature = "test-util"))]
            snapshot_pause: std::sync::Arc::default(),
        })
    }

    /// Apply pending schema migrations. Safe to run from several processes at once.
    ///
    /// `announced` is what the service announces at enrollment now: an account enrolled
    /// before the schema kept its announced limits inherits these (migration 0002).
    pub async fn migrate(
        &self,
        announced: &pubky_switch_core::records::Limits,
    ) -> Result<(), StoreError> {
        let announced = serde_json::to_string(announced)
            .map_err(|_| StoreError::Corrupt("the announced limits don't encode"))?;
        let mut conn = self.pool.acquire().await.map_err(StoreError::from_db)?;
        sqlx::query("SELECT set_config('pubky_switch.announced_limits', $1, false)")
            .bind(&announced)
            .execute(&mut *conn)
            .await
            .map_err(StoreError::from_db)?;
        if let Err(error) = MIGRATIONS.run(&mut *conn).await {
            // A failed run keeps the migrator's lock on its connection: close it rather
            // than hand it back to the pool.
            let _ = conn.detach().close().await;
            return Err(error.into());
        }
        // The connection goes back to the pool without the setting.
        sqlx::query("RESET pubky_switch.announced_limits")
            .execute(&mut *conn)
            .await
            .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// Create an account. Returns `false`, changing nothing, when one exists for the
    /// identity already.
    pub async fn create_account(&self, account: &NewAccount) -> Result<bool, StoreError> {
        account::create(&self.pool, account).await
    }

    /// The key store entries erasures still owe deleting, oldest first (Switch wire 7.4.16).
    pub async fn erased_keys(&self) -> Result<Vec<ErasedKey>, StoreError> {
        let rows = sqlx::query(
            "SELECT key_id, account_id, erased_at_ms, reason FROM erased_keys \
             ORDER BY erased_at_ms, key_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::from_db)?;
        rows.iter()
            .map(|row| {
                let key: String = row.try_get("key_id")?;
                Ok(ErasedKey {
                    key: crate::keys::KeyId::parse(&key)
                        .map_err(|_| StoreError::Corrupt("erased_keys.key_id"))?,
                    account: row.try_get("account_id")?,
                    erased_at_ms: from_db(row.try_get("erased_at_ms")?, "erased_at_ms")?,
                    retired: row.try_get::<String, _>("reason")? != "erasure",
                })
            })
            .collect()
    }

    /// Whether an erased account of the identity `account` still owes the deletion of a key
    /// (Switch wire 7.4.16).
    pub async fn owes_erased_keys(&self, account: &str) -> Result<bool, StoreError> {
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM erased_keys WHERE account_id = $1)")
            .bind(account)
            .fetch_one(&self.pool)
            .await
            .map_err(StoreError::from_db)
    }

    /// Look account `id` up without taking its lock: its service key and the service time
    /// it last committed, for the checks that come before the lock (Switch wire 7.2 Order).
    pub async fn lookup(&self, id: &str) -> Result<Option<FoundAccount>, StoreError> {
        let row = sqlx::query("SELECT service_key, stamped_time_ms FROM accounts WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::from_db)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let service_key: String = row.try_get("service_key")?;
        Ok(Some(FoundAccount {
            service_key: crate::keys::KeyId::parse(&service_key)
                .map_err(|_| StoreError::Corrupt("service_key"))?,
            stamped_time_ms: from_db(row.try_get("stamped_time_ms")?, "stamped_time_ms")?,
        }))
    }

    /// The app row account `id` holds for `app_id`, read without the account's lock, for
    /// the checks of an own app's request before it (Switch wire 7.2 Order). A plain read
    /// doesn't wait for the lock; the endpoint checks again under it.
    pub async fn app_row(
        &self,
        id: &str,
        app_id: &[u8; 16],
    ) -> Result<Option<StoredApp>, StoreError> {
        ops::app_row(&self.pool, id, app_id).await
    }

    /// What an own app's checks before the lock read, in one statement: account `id`'s
    /// newest `identity.json`, the row of `app_id`, and whether it is kept for good (Switch
    /// wire 7.2 Order). `None` for an account that isn't there.
    pub async fn own_app_view(
        &self,
        id: &str,
        app_id: &[u8; 16],
    ) -> Result<
        Option<(
            Option<pubky_switch_core::sig::SignedDoc>,
            Option<StoredApp>,
            bool,
        )>,
        StoreError,
    > {
        ops::own_app_view(&self.pool, id, app_id).await
    }

    /// The first `steps` entries of claim `claim_key` at account `id`, by step, read without
    /// the account's lock (Switch wire 7.4.8): entries never change once written.
    pub async fn claim_entries_before(
        &self,
        id: &str,
        claim_key: &[u8; 32],
        steps: u64,
    ) -> Result<Vec<StoredClaimEntry>, StoreError> {
        ops::claim_entries_before(&self.pool, id, claim_key, steps).await
    }

    /// Read a feed page of account `id` from one snapshot, without the account's lock
    /// (Switch wire 7.4.4): the sequence, then the chain items after `after`, up to
    /// `positions` positions on and `batch_tail` more to finish a batch, each given to
    /// `take`, which answers whether the page wants the next. `None` for an account that
    /// isn't there.
    #[allow(clippy::too_many_arguments)]
    pub async fn read_feed(
        &self,
        id: &str,
        reader: &[u8; 16],
        after: Option<pubky_switch_core::ops::Position>,
        positions: u64,
        batch_tail: u64,
        page: &mut impl PageReader,
    ) -> Result<Option<FeedSnapshot>, StoreError> {
        feed::read_feed(&self.pool, id, reader, after, positions, batch_tail, page).await
    }

    /// Start a request to account `id`: a transaction holding the account's lock until it
    /// commits or is dropped. `None` when there is no such account. Waits at most
    /// `lock_timeout_ms` for the lock ([`StoreError::LockTimeout`]).
    pub async fn begin(&self, id: &str) -> Result<Option<AccountTxn>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::from_db)?;
        // `SET LOCAL` takes no bind parameters; the value is a number we format.
        tx.execute(format!("SET LOCAL lock_timeout = {}", self.lock_timeout_ms).as_str())
            .await
            .map_err(StoreError::from_db)?;
        AccountTxn::lock(tx, id).await
    }

    /// [`Store::begin`], with a transaction on the reader pool begun first, before the lock
    /// is waited for, so the request waits for a free reader without holding the lock;
    /// [`AccountTxn::snapshot_read`] hands it the locked transaction's snapshot.
    ///
    /// One such read of an account runs at a time in this process; the next ones wait for
    /// their turn in order, before they take a reader and holding no connection, at most
    /// `lock_timeout_ms` ([`StoreError::LockTimeout`] after it, and at once past 8
    /// waiting). So the readers every account shares can't all be held by one account's
    /// reads. The read is `app`'s, an own app whose request signature verified with the key
    /// the account holds for it; whether it may make the read is judged under the lock.
    /// Each app holds at most one place in its account's queue: a second read of the same
    /// app while its first holds or waits for one is refused at once, so no one app, however
    /// many requests it sends, can keep the other apps' reads waiting past one place.
    pub async fn begin_reading(
        &self,
        id: &str,
        app: [u8; 16],
    ) -> Result<Option<AccountTxn>, StoreError> {
        let wait = Duration::from_millis(self.lock_timeout_ms);
        let turn = snapshot::ReadTurn::wait(&self.reading, id, app, wait).await?;
        let reader = self.readers.begin().await.map_err(StoreError::from_db)?;
        let Some(mut txn) = self.begin(id).await? else {
            return Ok(None);
        };
        txn.reader = Some(reader);
        txn.read_turn = Some(turn);
        txn.import_timeout_ms = self.lock_timeout_ms;
        #[cfg(any(test, feature = "test-util"))]
        {
            txn.snapshot_pause = self
                .snapshot_pause
                .lock()
                .map_err(|_| StoreError::Corrupt("a test pause"))?
                .take();
        }
        Ok(Some(txn))
    }

    /// The connection pool, for the store's own modules.
    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Close every connection.
    pub async fn close(&self) {
        self.pool.close().await;
        self.readers.close().await;
    }
}

/// PostgreSQL's code for a server that is starting up or shutting down.
const CANNOT_CONNECT_NOW: &str = "57P03";

/// Whether a failed connection may succeed if tried again: a server not listening yet, or
/// one still starting up. Refused credentials and other errors aren't retried.
fn retryable(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut => true,
        sqlx::Error::Database(db) => db.code().as_deref() == Some(CANNOT_CONNECT_NOW),
        _ => false,
    }
}

/// Open the first connection, trying again while the database isn't up yet, for at most
/// `retry_ms`. A database started at the same time as the service, by an orchestrator or a
/// container runtime, is often not listening for its first second or two.
async fn connect_first(
    options: &PgConnectOptions,
    retry_ms: u64,
) -> Result<PgConnection, StoreError> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(retry_ms);
    let mut backoff = Duration::from_millis(100);
    loop {
        match PgConnection::connect_with(options).await {
            Ok(conn) => return Ok(conn),
            Err(error) if retryable(&error) && tokio::time::Instant::now() < deadline => {
                tracing::warn!(%error, "the database isn't reachable yet; trying again");
                let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                tokio::time::sleep(backoff.min(left)).await;
                backoff = (backoff * 2).min(Duration::from_secs(2));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// An account found by [`Store::lookup`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundAccount {
    /// Its service key.
    pub service_key: crate::keys::KeyId,
    /// The service time it last committed.
    pub stamped_time_ms: u64,
}

/// The readiness check of the database: a round trip on a pooled connection.
#[derive(Clone, Debug)]
pub struct StoreReadiness(pub Store);

impl ReadinessCheck for StoreReadiness {
    fn name(&self) -> &str {
        "database"
    }

    fn check(&self) -> CheckFuture<'_> {
        Box::pin(async move {
            let mut conn = self
                .0
                .pool()
                .acquire()
                .await
                .map_err(|_| "no database connection".to_string())?;
            conn.ping()
                .await
                .map_err(|_| "the database doesn't answer".to_string())
        })
    }
}

/// Convert a `u64` to the `BIGINT` the database stores.
pub(crate) fn to_db(value: u64, what: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::OutOfRange(what))
}

/// Convert a stored `BIGINT` back to a `u64`.
pub(crate) fn from_db(value: i64, what: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::Corrupt(what))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(fsync: &str, commit: &str, standbys: &str) -> DurabilitySettings {
        DurabilitySettings {
            fsync: fsync.into(),
            synchronous_commit: commit.into(),
            synchronous_standby_names: standbys.into(),
        }
    }

    #[test]
    fn test_durability_settings_check() {
        assert_eq!(settings("on", "on", "").check(), Ok(()));
        assert_eq!(settings("on", "remote_apply", "s1").check(), Ok(()));
        assert_eq!(settings("on", "local", "").check(), Ok(()));
        assert!(settings("off", "on", "").check().is_err());
        assert!(settings("on", "off", "").check().is_err());
    }

    #[test]
    fn test_durability_settings_replica_warning() {
        assert_eq!(settings("on", "on", "s1").replica_warning(), None);
        assert_eq!(settings("on", "remote_write", "").replica_warning(), None);
        assert!(
            settings("on", "remote_write", "s1")
                .replica_warning()
                .is_some()
        );
        assert!(
            settings("on", "local", "ANY 1 (s1)")
                .replica_warning()
                .is_some()
        );
    }

    #[test]
    fn test_database_config_validation() {
        assert_eq!(DatabaseConfig::default().validate(), Ok(()));
        let bad_url = DatabaseConfig {
            url: Some("mysql://x".into()),
            ..DatabaseConfig::default()
        };
        assert_eq!(bad_url.validate().expect_err("url").name, "url");
        let no_pool = DatabaseConfig {
            max_connections: 0,
            ..DatabaseConfig::default()
        };
        assert_eq!(
            no_pool.validate().expect_err("pool").name,
            "max_connections"
        );
    }

    #[tokio::test]
    async fn test_store_connect_retries_then_gives_up() {
        // A port nothing listens on: refused at once, so every attempt is retried until the
        // bound, and then the error is returned.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let options = PgConnectOptions::new().host("127.0.0.1").port(port);
        let started = std::time::Instant::now();
        let error = connect_first(&options, 400)
            .await
            .expect_err("nothing listens");
        let elapsed = started.elapsed();
        assert!(
            matches!(error, StoreError::Database(sqlx::Error::Io(_))),
            "{error:?}"
        );
        assert!(elapsed >= Duration::from_millis(400), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    }

    #[test]
    fn test_store_retryable_errors() {
        assert!(retryable(&sqlx::Error::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused
        ))));
        assert!(retryable(&sqlx::Error::PoolTimedOut));
        assert!(!retryable(&sqlx::Error::Configuration("bad".into())));
        assert!(!retryable(&sqlx::Error::RowNotFound));
    }

    #[test]
    fn test_database_config_debug_redacts_url() {
        let config = DatabaseConfig {
            url: Some("postgres://switch:secret@db/switch".into()),
            ..DatabaseConfig::default()
        };
        let text = format!("{config:?}");
        assert!(!text.contains("secret"), "{text}");
        assert!(text.contains("[redacted]"));
    }
}
