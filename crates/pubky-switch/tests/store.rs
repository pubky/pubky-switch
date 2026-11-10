//! The storage layer against PostgreSQL: per-account transactions, durability before the
//! answer, crashes before the commit, per-account ordering, and the key's mark.
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used)]

use std::{sync::Arc, time::Duration};

use pubky_switch::{
    keys::{FileKeyStore, KeyStore, Mark, MarkCheck},
    store::{
        CommitError, DatabaseConfig, NewAccount, Store, StoreError,
        testing::{TestDatabase, test_database},
    },
};
use sqlx::{Connection, Executor, PgConnection};

const ID_A: &str = "6frao8w9ss5cn544qd64hynikrbr97ae1s5941c7ma5e1epifhgy";
const ID_B: &str = "7p4fn44qoshcwgfndz5grt7fyyz1eycqyduxdqe8o58of1byzodo";
const T0: u64 = 1_767_225_600_000;

struct Fixture {
    db: TestDatabase,
    keys: FileKeyStore,
    _key_dir: tempfile::TempDir,
}

impl Fixture {
    fn store(&self) -> &Store {
        self.db.store()
    }

    async fn account(&self, id: &str) -> NewAccount {
        let key = self.keys.generate().await.expect("service key");
        let account = NewAccount {
            id: id.into(),
            identity_key: [7; 32],
            generation: 1,
            service_key: key.id,
            created_at_ms: T0,
            limits: pubky_switch_core::records::Limits::default(),
            identity_doc: None,
            revoked_apps: Vec::new(),
            enrollment_hash: [0; 32],
        };
        assert!(self.store().create_account(&account).await.expect("create"));
        account
    }

    async fn finish(self) {
        self.db
            .drop_database()
            .await
            .expect("drop the test database");
    }
}

async fn fixture() -> Option<Fixture> {
    let db = test_database().await?;
    let key_dir = tempfile::tempdir().expect("key dir");
    let keys = FileKeyStore::open(key_dir.path()).expect("key store");
    Some(Fixture {
        db,
        keys,
        _key_dir: key_dir,
    })
}

/// Append one chain item: a new seq, and the chain head moved to it.
fn append(txn: &mut pubky_switch::store::AccountTxn, hash: u8) -> u64 {
    let seq = txn.next_seq().expect("seq");
    txn.set_chain_head(seq, [hash; 32]).expect("chain head");
    seq
}

/// The PID of the backend serving `txn`'s connection.
async fn backend_pid(txn: &mut pubky_switch::store::AccountTxn) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(txn.conn())
        .await
        .expect("pid")
}

/// Kill a backend from outside, as a crash of the database connection would.
async fn kill_backend(db: &TestDatabase, pid: i32) {
    let mut admin = db.admin().await.expect("admin");
    let killed: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(pid)
        .fetch_one(&mut admin)
        .await
        .expect("terminate");
    assert!(killed);
}

#[tokio::test]
async fn test_store_creates_account_once() {
    let Some(fx) = fixture().await else { return };
    let account = fx.account(ID_A).await;
    assert!(!fx.store().create_account(&account).await.expect("again"));
    let txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    let head = txn.head();
    assert_eq!(head.id, ID_A);
    assert_eq!(head.generation, 1);
    assert_eq!(head.service_key, account.service_key);
    assert_eq!(head.last_seq, 0);
    assert_eq!(head.chain, None);
    assert_eq!(head.stamped_time_ms, T0);
    drop(txn);
    fx.finish().await;
}

#[tokio::test]
async fn test_store_unknown_account_is_none() {
    let Some(fx) = fixture().await else { return };
    assert!(fx.store().begin(ID_B).await.expect("begin").is_none());
    fx.finish().await;
}

#[tokio::test]
async fn test_store_commit_keeps_seq_chain_and_time() {
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert_eq!(txn.stamp(T0 + 1_000), T0 + 1_000);
    assert_eq!(txn.next_seq().expect("seq"), 1);
    assert_eq!(append(&mut txn, 0xaa), 2);
    let committed = txn.commit().await.expect("commit");
    assert_eq!(committed.head().last_seq, 2);
    let txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert_eq!(txn.head().last_seq, 2);
    assert_eq!(txn.head().chain, Some((2, [0xaa; 32])));
    assert_eq!(txn.head().stamped_time_ms, T0 + 1_000);
    drop(txn);
    fx.finish().await;
}

#[tokio::test]
async fn test_store_stamped_time_never_goes_back() {
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    txn.stamp(T0 + 60_000);
    txn.commit().await.expect("commit");
    // The time base went back, as after a wall-clock correction: the account keeps the
    // later time.
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert_eq!(txn.stamp(T0 + 1_000), T0 + 60_000);
    txn.commit().await.expect("commit");
    let txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert_eq!(txn.head().stamped_time_ms, T0 + 60_000);
    drop(txn);
    fx.finish().await;
}

#[tokio::test]
async fn test_store_chain_head_must_follow_given_seqs() {
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert!(matches!(
        txn.set_chain_head(1, [1; 32]),
        Err(StoreError::OutOfRange(_))
    ));
    let seq = txn.next_seq().expect("seq");
    txn.set_chain_head(seq, [1; 32]).expect("head");
    assert!(matches!(
        txn.set_chain_head(seq, [2; 32]),
        Err(StoreError::OutOfRange(_))
    ));
    txn.commit().await.expect("commit");
    // A later request can't move the head to a seq an earlier one gave out.
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert!(matches!(
        txn.set_chain_head(seq, [3; 32]),
        Err(StoreError::OutOfRange(_))
    ));
    drop(txn);
    fx.finish().await;
}

#[tokio::test]
async fn test_store_dropped_request_leaves_no_trace() {
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    append(&mut txn, 1);
    txn.stamp(T0 + 5_000);
    // A batch that fails part way: the request ends without a commit.
    drop(txn);
    let txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert_eq!(txn.head().last_seq, 0);
    assert_eq!(txn.head().chain, None);
    assert_eq!(txn.head().stamped_time_ms, T0);
    drop(txn);
    fx.finish().await;
}

#[tokio::test]
async fn test_store_crash_before_commit_leaves_no_trace() {
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    append(&mut txn, 1);
    // The request wrote, and its connection dies before the commit.
    sqlx::query("UPDATE accounts SET last_seq = 1 WHERE id = $1")
        .bind(ID_A)
        .execute(txn.conn())
        .await
        .expect("write");
    let pid = backend_pid(&mut txn).await;
    kill_backend(&fx.db, pid).await;
    assert!(
        txn.commit().await.is_err(),
        "a dead connection can't commit"
    );
    let txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert_eq!(txn.head().last_seq, 0);
    assert_eq!(txn.head().chain, None);
    drop(txn);
    fx.finish().await;
}

#[tokio::test]
async fn test_store_failed_commit_releases_no_answer_and_keeps_the_mark() {
    let Some(fx) = fixture().await else { return };
    let account = fx.account(ID_A).await;
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    append(&mut txn, 1);
    txn.commit_marked(&fx.keys).await.expect("first commit");
    let mark = fx.keys.mark(&account.service_key).await.expect("mark");
    assert_eq!(mark.map(|m| m.seq), Some(1));

    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    append(&mut txn, 2);
    let pid = backend_pid(&mut txn).await;
    kill_backend(&fx.db, pid).await;
    // No `Committed`, so no answer carrying the new seq or head can be built, and the
    // mark stays at the durable state.
    assert!(matches!(
        txn.commit_marked(&fx.keys).await,
        Err(CommitError::NotCommitted(_))
    ));
    assert_eq!(
        fx.keys.mark(&account.service_key).await.expect("mark"),
        mark
    );
    let txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert_eq!(txn.head().chain, Some((1, [1; 32])));
    assert_eq!(
        txn.mark_check(&fx.keys).await.expect("check"),
        MarkCheck::Current
    );
    drop(txn);
    fx.finish().await;
}

#[tokio::test]
async fn test_store_mark_follows_commits() {
    let Some(fx) = fixture().await else { return };
    let account = fx.account(ID_A).await;
    let txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert_eq!(
        txn.mark_check(&fx.keys).await.expect("check"),
        MarkCheck::Unmarked
    );
    // A request that adds no chain item leaves the key unmarked.
    txn.commit_marked(&fx.keys).await.expect("commit");
    assert_eq!(
        fx.keys.mark(&account.service_key).await.expect("mark"),
        None
    );
    for hash in 1..=3 {
        let mut txn = fx
            .store()
            .begin(ID_A)
            .await
            .expect("begin")
            .expect("account");
        append(&mut txn, hash);
        txn.commit_marked(&fx.keys).await.expect("commit");
    }
    assert_eq!(
        fx.keys.mark(&account.service_key).await.expect("mark"),
        Some(Mark {
            generation: 1,
            seq: 3,
            chain_hash: [3; 32]
        })
    );
    fx.finish().await;
}

#[tokio::test]
async fn test_store_restored_state_behind_the_mark_is_refused() {
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    for hash in 1..=3 {
        let mut txn = fx
            .store()
            .begin(ID_A)
            .await
            .expect("begin")
            .expect("account");
        append(&mut txn, hash);
        txn.commit_marked(&fx.keys).await.expect("commit");
    }
    // A backup taken at seq 2 is restored: the key's mark, kept apart, still says 3.
    let mut admin = PgConnection::connect_with(fx.db.options())
        .await
        .expect("conn");
    sqlx::query("UPDATE accounts SET last_seq = 2, chain_seq = 2, chain_hash = $2 WHERE id = $1")
        .bind(ID_A)
        .bind([2u8; 32].as_slice())
        .execute(&mut admin)
        .await
        .expect("restore");
    let txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert_eq!(
        txn.mark_check(&fx.keys).await.expect("check"),
        MarkCheck::Behind
    );
    drop(txn);
    // Another history at the mark's seq is a fork.
    sqlx::query("UPDATE accounts SET last_seq = 3, chain_seq = 3, chain_hash = $2 WHERE id = $1")
        .bind(ID_A)
        .bind([9u8; 32].as_slice())
        .execute(&mut admin)
        .await
        .expect("fork");
    let txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert_eq!(
        txn.mark_check(&fx.keys).await.expect("check"),
        MarkCheck::Fork
    );
    drop(txn);
    // A restore to before the first chain item is behind as well.
    sqlx::query(
        "UPDATE accounts SET last_seq = 0, chain_seq = NULL, chain_hash = NULL WHERE id = $1",
    )
    .bind(ID_A)
    .execute(&mut admin)
    .await
    .expect("empty");
    let txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert_eq!(
        txn.mark_check(&fx.keys).await.expect("check"),
        MarkCheck::Behind
    );
    drop(txn);
    admin.close().await.expect("close");
    fx.finish().await;
}

#[tokio::test]
async fn test_store_serializes_one_account() {
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let store = fx.store().clone();
    let keys = Arc::new(fx.keys.clone());
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let store = store.clone();
        let keys = keys.clone();
        tasks.push(tokio::spawn(async move {
            let mut txn = store.begin(ID_A).await.expect("begin").expect("account");
            let before = txn.head().last_seq;
            let seq = txn.next_seq().expect("seq");
            // Each request sees every earlier one's commit, and nothing in between.
            assert_eq!(seq, before + 1);
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&seq.to_be_bytes());
            txn.set_chain_head(seq, hash).expect("head");
            tokio::time::sleep(Duration::from_millis(5)).await;
            txn.commit_marked(keys.as_ref()).await.expect("commit");
            seq
        }));
    }
    let mut seqs = Vec::new();
    for task in tasks {
        seqs.push(task.await.expect("task"));
    }
    seqs.sort_unstable();
    assert_eq!(seqs, (1..=12).collect::<Vec<u64>>());
    let txn = store.begin(ID_A).await.expect("begin").expect("account");
    assert_eq!(txn.head().last_seq, 12);
    assert_eq!(
        txn.mark_check(keys.as_ref()).await.expect("check"),
        MarkCheck::Current
    );
    drop(txn);
    fx.finish().await;
}

#[tokio::test]
async fn test_store_other_accounts_proceed_while_one_is_locked() {
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    fx.account(ID_B).await;
    let held = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    // Account B isn't held up by A's lock.
    let mut other = tokio::time::timeout(Duration::from_secs(2), fx.store().begin(ID_B))
        .await
        .expect("B isn't blocked")
        .expect("begin")
        .expect("account");
    append(&mut other, 1);
    other.commit().await.expect("commit");
    // A second request to A waits for the first.
    let store = fx.store().clone();
    let waiting = tokio::spawn(async move {
        let txn = store.begin(ID_A).await.expect("begin").expect("account");
        txn.head().last_seq
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !waiting.is_finished(),
        "the second request waits for the lock"
    );
    let mut held = held;
    append(&mut held, 1);
    held.commit().await.expect("commit");
    let seen = tokio::time::timeout(Duration::from_secs(2), waiting)
        .await
        .expect("the lock is released")
        .expect("task");
    assert_eq!(seen, 1, "it sees the first request's commit");
    fx.finish().await;
}

#[tokio::test]
async fn test_store_lock_timeout_is_reported() {
    let Some(db) = TestDatabase::create(&DatabaseConfig {
        lock_timeout_ms: 100,
        ..DatabaseConfig::default()
    })
    .await
    .ok() else {
        eprintln!("skipped: no test database");
        return;
    };
    let key_dir = tempfile::tempdir().expect("key dir");
    let fx = Fixture {
        keys: FileKeyStore::open(key_dir.path()).expect("keys"),
        db,
        _key_dir: key_dir,
    };
    fx.account(ID_A).await;
    let held = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert!(matches!(
        fx.store().begin(ID_A).await,
        Err(StoreError::LockTimeout)
    ));
    drop(held);
    assert!(fx.store().begin(ID_A).await.expect("begin").is_some());
    fx.finish().await;
}

#[tokio::test]
async fn test_store_refuses_a_database_without_durable_commits() {
    let Some(fx) = fixture().await else { return };
    let mut admin = fx.db.admin().await.expect("admin");
    admin
        .execute(
            format!(
                "ALTER DATABASE {} SET synchronous_commit = off",
                fx.db.name()
            )
            .as_str(),
        )
        .await
        .expect("alter");
    admin.close().await.expect("close");
    let result = Store::connect_with(fx.db.options().clone(), &DatabaseConfig::default()).await;
    assert!(
        matches!(result, Err(StoreError::NotDurable(_))),
        "{result:?}"
    );
    fx.finish().await;
}

#[tokio::test]
async fn test_store_connect_waits_for_a_late_database() {
    let Some(fx) = fixture().await else { return };
    // A forwarder to the test database that opens its port only after a while, as a
    // database container does while it initializes.
    let free = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = free.local_addr().expect("addr").port();
    drop(free);
    let target = format!(
        "{}:{}",
        fx.db.options().get_host(),
        fx.db.options().get_port()
    );
    let forwarder = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("rebind");
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            let target = target.clone();
            tokio::spawn(async move {
                if let Ok(mut server) = tokio::net::TcpStream::connect(target).await {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                }
            });
        }
    });
    let options = fx.db.options().clone().host("127.0.0.1").port(port);
    let started = std::time::Instant::now();
    let store = Store::connect_with(options, &DatabaseConfig::default())
        .await
        .expect("connects once the database listens");
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert!(store.begin(ID_A).await.expect("begin").is_none());
    store.close().await;
    forwarder.abort();
    fx.finish().await;
}

/// A database holding an account from before migration 0002, migrated now.
#[tokio::test]
#[allow(clippy::panic)]
async fn test_store_upgrade_gives_existing_accounts_the_limits_in_force() {
    use pubky_switch::store::{DatabaseConfig, MIGRATIONS, testing::TestDatabase};
    let db = match TestDatabase::create_with(&DatabaseConfig::default(), false).await {
        Ok(db) => db,
        Err(pubky_switch::store::testing::TestDatabaseError::Skipped) => return,
        Err(error) => panic!("test database: {error}"),
    };
    let mut conn = PgConnection::connect_with(db.options())
        .await
        .expect("conn");
    let first = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(MIGRATIONS.iter().take(1).cloned().collect()),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    first.run(&mut conn).await.expect("migration 0001");
    sqlx::query(
        "INSERT INTO accounts (id, identity_key, generation, service_key, created_at_ms) \
         VALUES ('old', $1, 1, 'key', 1)",
    )
    .bind([7u8; 32].as_slice())
    .execute(&mut conn)
    .await
    .expect("an account under 0001");
    // Without the limits in force, the upgrade fails and applies nothing.
    assert!(MIGRATIONS.run(&mut conn).await.is_err());
    // A failed run keeps the migrator's lock on its connection.
    conn.close().await.expect("close");
    let mut conn = PgConnection::connect_with(db.options())
        .await
        .expect("conn");
    let applied: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&mut conn)
        .await
        .expect("versions");
    assert_eq!(applied, 1);
    // With them, the account inherits them.
    let limits = pubky_switch::limits::Limits {
        app_limit: 7,
        ..pubky_switch::limits::Limits::default()
    };
    let announced = pubky_switch::service::announced_limits(&limits);
    db.store().migrate(&announced).await.expect("upgrade");
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT announced_limits FROM accounts WHERE id = 'old'")
            .fetch_one(&mut conn)
            .await
            .expect("limits");
    assert_eq!(stored, serde_json::to_vec(&announced).expect("json"));
    conn.close().await.expect("close");
    db.drop_database().await.expect("drop");
}

/// Enrollment answers kept before migration 0005: the creating one is found and marked.
#[tokio::test]
#[allow(clippy::panic)]
async fn test_store_upgrade_marks_the_creating_enrollment_answer() {
    use pubky_switch::store::{DatabaseConfig, MIGRATIONS, testing::TestDatabase};
    let db = match TestDatabase::create_with(&DatabaseConfig::default(), false).await {
        Ok(db) => db,
        Err(pubky_switch::store::testing::TestDatabaseError::Skipped) => return,
        Err(error) => panic!("test database: {error}"),
    };
    let mut conn = PgConnection::connect_with(db.options())
        .await
        .expect("conn");
    let before = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(MIGRATIONS.iter().take(4).cloned().collect()),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    before
        .run(&mut conn)
        .await
        .expect("migrations 0001 to 0004");
    for statement in [
        "INSERT INTO accounts (id, identity_key, generation, service_key, created_at_ms, \
         announced_limits) VALUES ('old', '\\x0707070707070707070707070707070707070707070707070707070707070707', \
         1, 'key', 5, '\\x7b7d')",
        "INSERT INTO enrollment_answers (account_id, enrollment_hash, service_key, answered_at_ms) \
         VALUES ('old', '\\x0101010101010101010101010101010101010101010101010101010101010101', 'key', 5), \
         ('old', '\\x0202020202020202020202020202020202020202020202020202020202020202', 'pending', 9)",
    ] {
        sqlx::query(statement)
            .execute(&mut conn)
            .await
            .expect("rows under 0004");
    }
    let announced =
        pubky_switch::service::announced_limits(&pubky_switch::limits::Limits::default());
    db.store().migrate(&announced).await.expect("upgrade");
    let creating: Vec<(Vec<u8>, bool)> = sqlx::query_as(
        "SELECT enrollment_hash, creating FROM enrollment_answers ORDER BY enrollment_hash",
    )
    .fetch_all(&mut conn)
    .await
    .expect("answers");
    assert_eq!(
        creating.iter().map(|(_, c)| *c).collect::<Vec<_>>(),
        vec![true, false]
    );
    conn.close().await.expect("close");
    db.drop_database().await.expect("drop");
}
