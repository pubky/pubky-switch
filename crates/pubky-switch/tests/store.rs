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

/// A tombstone written before migration 0006: the service learns when it may go from its
/// state, and deletes it on time.
#[tokio::test]
#[allow(clippy::panic)]
async fn test_store_upgrade_deletes_claims_from_before_0006() {
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
        migrations: std::borrow::Cow::Owned(MIGRATIONS.iter().take(5).cloned().collect()),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    before
        .run(&mut conn)
        .await
        .expect("migrations 0001 to 0005");
    let deadline: u64 = 1_767_312_000_000;
    // A settled claim, compacted, pinned to `deadline`, in the service's encoding.
    let (attempt, owner) = (vec![8u8; 16], vec![5u8; 16]);
    let state = serde_json::json!({
        "step": 2,
        "attempts": [{
            "attempt_id": attempt, "owner": owner, "outcome": "done",
            "opened_at": 1_767_225_600_000u64, "orphan_after": 60,
            "possibly_duplicate": false, "duplicate": false,
            "resolved_by": owner, "from_upload": false,
        }],
        "current": null, "settled": true, "tombstone": true, "pin": deadline,
        "divergent": false, "rebuilt": false, "creator": owner,
        "last_entry": 1_767_225_600_000u64,
    });
    sqlx::query(
        "INSERT INTO accounts (id, identity_key, generation, service_key, created_at_ms, \
         announced_limits) VALUES ('old', $1, 1, '00000000000000000000000000000000', 5, \
         '\\x7b7d')",
    )
    .bind([7u8; 32].as_slice())
    .execute(&mut conn)
    .await
    .expect("account");
    sqlx::query(
        "INSERT INTO claims (account_id, claim_key, state, creator, tombstone, open_owners) \
         VALUES ('old', $1, $2, $3, true, '{}')",
    )
    .bind([9u8; 32].as_slice())
    .bind(serde_json::to_vec(&state).expect("state"))
    .bind([5u8; 16].as_slice())
    .execute(&mut conn)
    .await
    .expect("a claim under 0005");
    // A failed claim pinned to no deadline, and a row whose state doesn't decode.
    let last_entry: u64 = 1_767_225_600_000;
    let failed = serde_json::json!({
        "step": 2,
        "attempts": [{
            "attempt_id": attempt, "owner": owner, "outcome": "failed",
            "opened_at": last_entry, "orphan_after": 60,
            "possibly_duplicate": false, "duplicate": false,
            "resolved_by": owner, "from_upload": false,
        }],
        "current": null, "settled": false, "tombstone": false, "pin": "none",
        "divergent": false, "rebuilt": false, "creator": owner, "last_entry": last_entry,
    });
    for (key, state) in [
        ([10u8; 32], serde_json::to_vec(&failed).expect("state")),
        ([11u8; 32], b"not a claim".to_vec()),
    ] {
        sqlx::query(
            "INSERT INTO claims (account_id, claim_key, state, creator, tombstone, open_owners) \
             VALUES ('old', $1, $2, $3, false, '{}')",
        )
        .bind(key.as_slice())
        .bind(state)
        .bind([5u8; 16].as_slice())
        .execute(&mut conn)
        .await
        .expect("a claim under 0005");
    }
    let announced =
        pubky_switch::service::announced_limits(&pubky_switch::limits::Limits::default());
    db.store().migrate(&announced).await.expect("upgrade");
    let age = pubky_switch::limits::Limits::default().max_claim_age_ms;
    let reconciliation = pubky_switch_core::claims::RECONCILIATION_MS;
    let mut txn = db
        .store()
        .begin("old")
        .await
        .expect("begin")
        .expect("account");
    // Not yet due: it is kept, now with when it may go.
    let early = deadline + reconciliation - 1;
    assert_eq!(
        txn.delete_due_claims(early, age, 64).await.expect("delete"),
        0
    );
    // Due: it goes.
    assert_eq!(
        txn.delete_due_claims(deadline + reconciliation, age, 64)
            .await
            .expect("delete"),
        1
    );
    // The failed claim goes once its last entry is max_claim_age_ms old; the row that
    // doesn't decode blocks nothing, and stays.
    assert_eq!(
        txn.delete_due_claims(last_entry + age - 1, age, 64)
            .await
            .expect("delete"),
        0
    );
    assert_eq!(
        txn.delete_due_claims(last_entry + age, age, 64)
            .await
            .expect("delete"),
        1
    );
    assert_eq!(
        txn.delete_due_claims(u64::MAX >> 12, age, 64)
            .await
            .expect("delete"),
        0
    );
    drop(txn);
    conn.close().await.expect("close");
    db.drop_database().await.expect("drop");
}

/// Chain items written before migration 0008 take their proofs from their batch's record
/// while it keeps them, by their place in the batch; the others stay without.
#[tokio::test]
#[allow(clippy::panic)]
async fn test_store_upgrade_gives_chain_items_their_batch_proofs() {
    use pubky_switch::store::{DatabaseConfig, MIGRATIONS, testing::TestDatabase};
    use pubky_switch_core::sig::SignedDoc;
    let db = match TestDatabase::create_with(&DatabaseConfig::default(), false).await {
        Ok(db) => db,
        Err(pubky_switch::store::testing::TestDatabaseError::Skipped) => return,
        Err(error) => panic!("test database: {error}"),
    };
    let mut conn = PgConnection::connect_with(db.options())
        .await
        .expect("conn");
    let before = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(MIGRATIONS.iter().take(7).cloned().collect()),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    before
        .run(&mut conn)
        .await
        .expect("migrations 0001 to 0007");
    sqlx::query(
        "INSERT INTO accounts (id, identity_key, generation, service_key, created_at_ms, \
         announced_limits) VALUES ('old', $1, 1, '00000000000000000000000000000000', 5, \
         '\\x7b7d')",
    )
    .bind([7u8; 32].as_slice())
    .execute(&mut conn)
    .await
    .expect("account");
    let proof = |n: u8| SignedDoc::from_parts(format!("{{\"proof\":{n}}}").as_bytes(), &[n; 64]);
    // A batch of seqs 2 and 3 whose proofs are kept, and one at seq 5 whose proofs went.
    for (id, proofs, first, last) in [
        (
            [1u8; 16],
            Some(serde_json::to_vec(&[proof(2), proof(3)]).expect("proofs")),
            2i64,
            3i64,
        ),
        ([2u8; 16], None, 5, 5),
    ] {
        sqlx::query(
            "INSERT INTO batches (account_id, batch_id, ops_hash, proofs, at_ms, generation, \
             first_seq, last_seq) VALUES ('old', $1, $2, $3, 0, 1, $4, $5)",
        )
        .bind(id.as_slice())
        .bind([0u8; 32].as_slice())
        .bind(proofs)
        .bind(first)
        .bind(last)
        .execute(&mut conn)
        .await
        .expect("batch");
    }
    for (seq, item_type) in [(1i64, "identity"), (2, "op"), (3, "op"), (5, "op")] {
        sqlx::query(
            "INSERT INTO chain_items (account_id, generation, seq, item_type, item_bytes, \
             envelope, chain_hash, server_time_ms) VALUES ('old', 1, $1, $2, '\\x7b7d', \
             '\\x7b7d', $3, 0)",
        )
        .bind(seq)
        .bind(item_type)
        .bind([0u8; 32].as_slice())
        .execute(&mut conn)
        .await
        .expect("chain item");
    }
    let announced =
        pubky_switch::service::announced_limits(&pubky_switch::limits::Limits::default());
    db.store().migrate(&announced).await.expect("upgrade");
    let rows: Vec<(i64, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT seq, proof FROM chain_items WHERE account_id = 'old' ORDER BY seq")
            .fetch_all(&mut conn)
            .await
            .expect("rows");
    let proofs: Vec<(i64, Option<SignedDoc>)> = rows
        .into_iter()
        .map(|(seq, proof)| {
            (
                seq,
                proof.map(|bytes| serde_json::from_slice(&bytes).expect("a proof")),
            )
        })
        .collect();
    assert_eq!(
        proofs,
        vec![
            (1, None),
            (2, Some(proof(2))),
            (3, Some(proof(3))),
            (5, None)
        ]
    );
    drop(conn);
    db.drop_database().await.expect("drop");
}

/// A shared record at `key` of `collection` whose `read_scope` is `read_scope`, at version
/// `(1, version)`.
fn shared_record(
    key: [u8; 32],
    collection: [u8; 32],
    read_scope: &str,
    deleted: bool,
    version: u64,
) -> pubky_switch::store::StoredRecord {
    use pubky_switch_core::{
        ident::Policy, ops::RecordVersion, shared::RecordState, sig::SignedDoc,
    };
    let doc = SignedDoc::from_parts(b"{}", &[0; 64]);
    pubky_switch::store::StoredRecord {
        state: RecordState {
            key,
            collection,
            policy: Policy::new(read_scope, &["tasks"]),
            version: RecordVersion::new(1, version),
            deleted,
        },
        value_bytes: if deleted { 0 } else { 2 },
        writer: [3; 16],
        cert: doc.clone(),
        op: doc.clone(),
        origin: pubky_switch::store::RecordOrigin::Written {
            proof: doc,
            upload_base: None,
        },
        divergent: false,
    }
}

/// Every record `readable_records` gives `held` from `collection` after `after`, read 2 at a
/// time, by key.
async fn readable(
    fx: &Fixture,
    collection: &[u8; 32],
    held: &[&str],
    after: &str,
) -> Vec<[u8; 32]> {
    let held: Vec<String> = held.iter().map(|s| (*s).to_string()).collect();
    let mut txn = fx
        .store()
        .begin_reading(ID_A, [1; 16])
        .await
        .expect("begin")
        .expect("account");
    txn.prepare_snapshot().await.expect("export");
    let mut read = txn.snapshot_read().expect("snapshot");
    txn.commit().await.expect("commit");
    let mut keys = Vec::new();
    let mut after = after.to_string();
    // Bounded, so a read that doesn't move past its `after` fails the test instead of
    // hanging it: every record the tests write fits well inside it.
    for reads in 0.. {
        assert!(
            reads < 1_000,
            "the reads never reached the collection's end"
        );
        let page = read
            .readable_records(collection, &held, &after, 2)
            .await
            .expect("records");
        let Some(last) = page.last() else { break };
        after = pubky_switch_core::enc::b64(&last.state.key);
        keys.extend(page.iter().map(|record| record.state.key));
    }
    read.finish().await.expect("finish");
    keys
}

#[tokio::test]
async fn test_store_records_by_key_text_and_read_scope() {
    use pubky_switch_core::{enc::b64, scopes::holds};
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let collection = [1; 32];
    // Keys whose text sorts otherwise than their bytes: 0xF8 begins with '-', 0xD0 with
    // '0', 0x00 with 'A', 0x68 with 'a', 0xFC with '_'.
    let scopes = [
        "tasks",
        "tasks:x",
        "tasks_people",
        "tasks_people:x",
        "tasks_assign:team1",
        "tasks_assign",
    ];
    let mut written = Vec::new();
    {
        let mut txn = fx
            .store()
            .begin(ID_A)
            .await
            .expect("begin")
            .expect("account");
        for first in [0xF8u8, 0xD0, 0x00, 0x68, 0xFC, 0x30] {
            for (j, scope) in scopes.iter().enumerate() {
                let mut key = [first; 32];
                key[31] = u8::try_from(j).expect("small");
                let record = shared_record(key, collection, scope, false, 2);
                txn.put_record(&record).await.expect("put");
                written.push((key, (*scope).to_string()));
            }
        }
        // A deleted record, and one of another collection, never listed.
        let deleted = shared_record([0x40; 32], collection, "tasks", true, 3);
        txn.put_record(&deleted).await.expect("put");
        let other = shared_record([0x41; 32], [2; 32], "tasks", false, 4);
        txn.put_record(&other).await.expect("put");
        txn.commit().await.expect("commit");
    }
    written.sort_by_key(|(key, _)| b64(key));
    for held in [
        &["tasks"][..],
        &["tasks:x"],
        &["tasks_people", "tasks_assign:team1"],
        &["tasks_assign"],
        &["tasks_people:y"],
        // A prefix of a name is no parent of it.
        &["task"],
        &["tasks_peopl"],
        &["task_"],
        &[],
    ] {
        let held_owned: Vec<String> = held.iter().map(|s| (*s).to_string()).collect();
        let expected: Vec<[u8; 32]> = written
            .iter()
            .filter(|(_, scope)| holds(&held_owned, scope))
            .map(|(key, _)| *key)
            .collect();
        assert_eq!(
            readable(&fx, &collection, held, "").await,
            expected,
            "{held:?}"
        );
        // After a key: exclusive, by text.
        let middle = b64(&written[written.len() / 2].0);
        let after: Vec<[u8; 32]> = expected
            .iter()
            .copied()
            .filter(|key| b64(key) > middle)
            .collect();
        assert_eq!(
            readable(&fx, &collection, held, &middle).await,
            after,
            "{held:?} after"
        );
    }
    fx.finish().await;
}

#[tokio::test]
#[allow(clippy::panic)]
async fn test_store_upgrade_gives_records_their_key_text() {
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
        migrations: std::borrow::Cow::Owned(
            MIGRATIONS
                .iter()
                .filter(|migration| migration.version < 14)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    before.run(&mut conn).await.expect("migrations before 0014");
    sqlx::query(
        "INSERT INTO accounts (id, identity_key, generation, service_key, created_at_ms, \
         announced_limits) VALUES ('old', $1, 1, '00000000000000000000000000000000', 5, \
         '\\x7b7d')",
    )
    .bind([7u8; 32].as_slice())
    .execute(&mut conn)
    .await
    .expect("account");
    let keys = [[0xF8u8; 32], [0x00; 32], [0xD0; 32]];
    for key in &keys {
        sqlx::query(
            "INSERT INTO shared_records (account_id, key, collection, read_scope, \
             write_scopes, generation, version, deleted, value_bytes, writer, cert, op, proof) \
             VALUES ('old', $1, $2, 'tasks', '{tasks}', 1, 1, false, 0, $3, '\\x7b7d', '\\x7b7d', \
             '\\x7b7d')",
        )
        .bind(key.as_slice())
        .bind([1u8; 32].as_slice())
        .bind([3u8; 16].as_slice())
        .execute(&mut conn)
        .await
        .expect("record");
    }
    let announced =
        pubky_switch::service::announced_limits(&pubky_switch::limits::Limits::default());
    db.store().migrate(&announced).await.expect("upgrade");
    let texts: Vec<String> = sqlx::query_scalar(
        "SELECT key_text FROM shared_records WHERE account_id = 'old' ORDER BY key_text",
    )
    .fetch_all(&mut conn)
    .await
    .expect("rows");
    let mut expected: Vec<String> = keys
        .iter()
        .map(|key| pubky_switch_core::enc::b64(key))
        .collect();
    expected.sort();
    assert_eq!(texts, expected);
    assert_eq!(texts[0].as_bytes()[0], b'-', "'-' sorts first in ASCII");
    drop(conn);
    db.drop_database().await.expect("drop");
}

/// One read of `limit` records of account A's `collection` that the scopes `held` may read.
async fn read_once(
    fx: &Fixture,
    collection: &[u8; 32],
    held: &[&str],
    limit: u64,
) -> Vec<pubky_switch::store::StoredRecord> {
    let held: Vec<String> = held.iter().map(|s| (*s).to_string()).collect();
    let mut txn = fx
        .store()
        .begin_reading(ID_A, [1; 16])
        .await
        .expect("begin")
        .expect("account");
    txn.prepare_snapshot().await.expect("export");
    let mut read = txn.snapshot_read().expect("snapshot");
    txn.commit().await.expect("commit");
    let page = read
        .readable_records(collection, &held, "", limit)
        .await
        .expect("records");
    read.finish().await.expect("finish");
    page
}

#[tokio::test]
async fn test_store_records_page_rows_stay_in_their_account() {
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    fx.account(ID_B).await;
    // Two accounts can hold a record at the same key: a key comes from the collection's
    // name, the blinded natural key and the policy, not the identity.
    let key = [0x11; 32];
    for (id, record) in [
        (ID_A, shared_record(key, [1; 32], "tasks", false, 5)),
        (ID_B, shared_record(key, [2; 32], "tasks_people", false, 9)),
    ] {
        let mut txn = fx.store().begin(id).await.expect("begin").expect("account");
        txn.put_record(&record).await.expect("put");
        txn.commit().await.expect("commit");
    }
    // A's page shows A's row only, once.
    let page = read_once(&fx, &[1; 32], &["tasks"], 33).await;
    assert_eq!(page.len(), 1, "one row, A's");
    assert_eq!(page[0].state.version.version, 5);
    assert_eq!(page[0].state.collection, [1; 32]);
    fx.finish().await;
}

#[tokio::test]
async fn test_store_records_page_keeps_key_text_order_under_any_join() {
    use pubky_switch_core::enc::b64;
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    {
        let mut txn = fx
            .store()
            .begin(ID_A)
            .await
            .expect("begin")
            .expect("account");
        // Byte order differs from text order: 0xF8 begins with '-', 0xD0 with '0', 0x00
        // with 'A'.
        for first in [0x00u8, 0x30, 0x68, 0xD0, 0xF8, 0xFC] {
            for j in 0..6u8 {
                let mut key = [first; 32];
                key[31] = j;
                let record = shared_record(key, [1; 32], "tasks", false, 1);
                txn.put_record(&record).await.expect("put");
            }
        }
        // Many more records of another collection, so a page's keys are the smaller side
        // of any hash join the planner picks.
        for n in 0..3_000u32 {
            let mut key = [0x55; 32];
            key[..4].copy_from_slice(&n.to_be_bytes());
            let record = shared_record(key, [2; 32], "tasks", false, 1);
            txn.put_record(&record).await.expect("put");
        }
        txn.commit().await.expect("commit");
    }
    // The planner kept off nested loops and merge joins, which happen to keep the page's
    // order: only the query's own ordering of the rows read by key gives it. The readers
    // connect after this, so they take these settings.
    let mut conn = PgConnection::connect_with(fx.db.options())
        .await
        .expect("conn");
    let name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&mut conn)
        .await
        .expect("name");
    for setting in ["enable_nestloop = off", "enable_mergejoin = off"] {
        conn.execute(format!("ALTER DATABASE \"{name}\" SET {setting}").as_str())
            .await
            .expect("alter");
    }
    conn.execute("ANALYZE shared_records")
        .await
        .expect("analyze");
    drop(conn);
    let page = read_once(&fx, &[1; 32], &["tasks"], 33).await;
    let texts: Vec<String> = page.iter().map(|record| b64(&record.state.key)).collect();
    let mut sorted = texts.clone();
    sorted.sort();
    assert_eq!(texts.len(), 33);
    assert_eq!(texts, sorted, "key-text order");
    fx.finish().await;
}

/// A key an erasure owed before migration 0017: it stays an erasure's, whose deletion the
/// ledger records, not a retired one.
#[tokio::test]
#[allow(clippy::panic)]
async fn test_store_upgrade_keeps_owed_keys_as_erasures() {
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
        migrations: std::borrow::Cow::Owned(
            MIGRATIONS
                .iter()
                .take_while(|m| m.version < 17)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    before
        .run(&mut conn)
        .await
        .expect("migrations through 0016");
    sqlx::query(
        "INSERT INTO erased_keys (key_id, account_id, erased_at_ms) VALUES ('owed', 'gone', 5)",
    )
    .execute(&mut conn)
    .await
    .expect("an owed key under 0016");
    let announced =
        pubky_switch::service::announced_limits(&pubky_switch::limits::Limits::default());
    db.store().migrate(&announced).await.expect("upgrade");
    let reason: String = sqlx::query_scalar("SELECT reason FROM erased_keys WHERE key_id = 'owed'")
        .fetch_one(&mut conn)
        .await
        .expect("reason");
    assert_eq!(reason, "erasure");
    conn.close().await.expect("close");
    db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_store_upgrade_applies_0021_after_later_migrations() {
    // A database made by a service that already ran 0022 and 0025, but not 0021: the
    // upgrade applies 0021 then, with its column and both indexes.
    use pubky_switch::store::{DatabaseConfig, MIGRATIONS, testing::TestDatabase};
    let db = match TestDatabase::create_with(&DatabaseConfig::default(), false).await {
        Ok(db) => db,
        Err(pubky_switch::store::testing::TestDatabaseError::Skipped) => return,
        Err(error) => panic!("test database: {error}"),
    };
    let mut conn = PgConnection::connect_with(db.options())
        .await
        .expect("conn");
    let without_0021 = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATIONS
                .iter()
                .filter(|m| m.version != 21)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    without_0021
        .run(&mut conn)
        .await
        .expect("every migration but 0021");
    let applied = |version: i64| {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = $1 AND success)",
        )
        .bind(version)
    };
    assert!(applied(25).fetch_one(&mut conn).await.expect("0025"));
    assert!(!applied(21).fetch_one(&mut conn).await.expect("0021"));
    let announced =
        pubky_switch::service::announced_limits(&pubky_switch::limits::Limits::default());
    db.store().migrate(&announced).await.expect("upgrade");
    assert!(applied(21).fetch_one(&mut conn).await.expect("0021"));
    let indexes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_indexes \
         WHERE indexname IN ('shared_records_deleted', 'batches_with_proofs')",
    )
    .fetch_one(&mut conn)
    .await
    .expect("indexes");
    assert_eq!(indexes, 2);
    sqlx::query("SELECT swept_at_ms FROM accounts LIMIT 0")
        .execute(&mut conn)
        .await
        .expect("the column");
    conn.close().await.expect("close");
    db.drop_database().await.expect("drop");
}

/// A record taken from a recovery upload after a provider loss, at `version` of generation 1,
/// listed by the `upload` transition at `seq`.
fn uploaded_record(key: [u8; 32], version: u64, seq: u64) -> pubky_switch::store::StoredRecord {
    let mut record = shared_record(key, [1; 32], "tasks", false, version);
    record.origin = pubky_switch::store::RecordOrigin::Uploaded { seq, exact: false };
    record
}

async fn record_at(fx: &Fixture, key: [u8; 32]) -> pubky_switch::store::StoredRecord {
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    let mut records = txn.records(&[key]).await.expect("records");
    drop(txn);
    records.pop().expect("the record")
}

#[tokio::test]
async fn test_store_record_taken_from_an_upload_keeps_no_proof() {
    use pubky_switch::store::RecordOrigin;
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let key = [0x51; 32];
    {
        let mut txn = fx
            .store()
            .begin(ID_A)
            .await
            .expect("begin")
            .expect("account");
        txn.put_record(&uploaded_record(key, 9, 4))
            .await
            .expect("put");
        txn.commit().await.expect("commit");
    }
    let held = record_at(&fx, key).await;
    assert_eq!(
        held.origin,
        RecordOrigin::Uploaded {
            seq: 4,
            exact: false
        }
    );
    assert_eq!(held.origin.proof(), None);
    assert!(!held.divergent);
}

#[tokio::test]
async fn test_store_record_written_here_keeps_its_upload_base() {
    use pubky_switch::store::RecordOrigin;
    use pubky_switch_core::ops::RecordVersion;
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let key = [0x52; 32];
    let mut record = shared_record(key, [1; 32], "tasks", false, 12);
    let RecordOrigin::Written { proof, .. } = record.origin.clone() else {
        unreachable!("shared_record writes here");
    };
    record.origin = RecordOrigin::Written {
        proof,
        upload_base: Some(pubky_switch_core::recovery::UploadBase {
            version: RecordVersion::new(1, 9),
            op_hash: [9; 32],
        }),
    };
    {
        let mut txn = fx
            .store()
            .begin(ID_A)
            .await
            .expect("begin")
            .expect("account");
        txn.put_record(&record).await.expect("put");
        txn.commit().await.expect("commit");
    }
    assert_eq!(record_at(&fx, key).await.origin, record.origin);
}

#[tokio::test]
async fn test_store_divergent_uploads_keep_their_order_until_a_write_here() {
    use pubky_switch_core::sig::SignedDoc;
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let key = [0x53; 32];
    let first = SignedDoc::from_parts(b"{\"a\":1}", &[1; 64]);
    let second = SignedDoc::from_parts(b"{\"a\":2}", &[2; 64]);
    {
        let mut txn = fx
            .store()
            .begin(ID_A)
            .await
            .expect("begin")
            .expect("account");
        txn.put_record(&uploaded_record(key, 9, 4))
            .await
            .expect("put");
        txn.add_divergent_upload(&key, &first, &[1; 32])
            .await
            .expect("first");
        txn.add_divergent_upload(&key, &second, &[2; 32])
            .await
            .expect("second");
        // The same upload twice is refused: the caller keeps each once.
        assert!(
            txn.add_divergent_upload(&key, &first, &[1; 32])
                .await
                .is_err()
        );
        drop(txn);
    }
    {
        let mut txn = fx
            .store()
            .begin(ID_A)
            .await
            .expect("begin")
            .expect("account");
        txn.put_record(&uploaded_record(key, 9, 4))
            .await
            .expect("put");
        txn.add_divergent_upload(&key, &first, &[1; 32])
            .await
            .expect("first");
        txn.add_divergent_upload(&key, &second, &[2; 32])
            .await
            .expect("second");
        let kept = txn.divergent_uploads(&key).await.expect("kept");
        assert_eq!(
            kept.iter()
                .map(|d| (d.position, d.op_hash))
                .collect::<Vec<_>>(),
            vec![(0, [1; 32]), (1, [2; 32])]
        );
        assert_eq!(kept[1].op, second);
        // A newer upload replacing the record keeps them.
        txn.put_record(&uploaded_record(key, 11, 5))
            .await
            .expect("replace");
        assert_eq!(txn.divergent_uploads(&key).await.expect("kept").len(), 2);
        txn.commit().await.expect("commit");
    }
    assert!(record_at(&fx, key).await.divergent);
    // A write here is a newer version at this service: it clears them.
    {
        let mut txn = fx
            .store()
            .begin(ID_A)
            .await
            .expect("begin")
            .expect("account");
        txn.put_record(&shared_record(key, [1; 32], "tasks", false, 20))
            .await
            .expect("write here");
        assert!(txn.divergent_uploads(&key).await.expect("kept").is_empty());
        txn.commit().await.expect("commit");
    }
    assert!(!record_at(&fx, key).await.divergent);
}

#[tokio::test]
async fn test_store_record_origin_checks_refuse_mixed_rows() {
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let mut conn = PgConnection::connect_with(fx.db.options())
        .await
        .expect("conn");
    let insert = |columns: &str, values: &str| {
        format!(
            "INSERT INTO shared_records (account_id, key, collection, read_scope, write_scopes, \
             generation, version, deleted, value_bytes, writer, cert, op{columns}) VALUES \
             ($1, $2, $2, 'tasks', '{{tasks}}', 1, 1, false, 0, $3, '\\x7b7d', '\\x7b7d'{values})"
        )
    };
    let cases = [
        // Written here without a proof.
        (", proof", ", NULL"),
        // Uploaded with a proof, or without its seq.
        (", proof, from_upload, upload_seq", ", '\\x7b7d', true, 3"),
        (", from_upload", ", true"),
        // Written here with a lower bound, a seq, or part of an upload base.
        (", proof, version_exact", ", '\\x7b7d', false"),
        (", proof, upload_seq", ", '\\x7b7d', 3"),
        (", proof, upload_base_generation", ", '\\x7b7d', 1"),
        (
            ", proof, upload_base_generation, upload_base_version",
            ", '\\x7b7d', 1, 2",
        ),
        // Uploaded with an upload base.
        (
            ", from_upload, upload_seq, upload_base_generation, upload_base_version",
            ", true, 3, 1, 2",
        ),
    ];
    for (i, (columns, values)) in cases.iter().enumerate() {
        let key = [u8::try_from(i).expect("small"); 32];
        let result = sqlx::query(&insert(columns, values))
            .bind(ID_A)
            .bind(key.as_slice())
            .bind([3u8; 16].as_slice())
            .execute(&mut conn)
            .await;
        assert!(result.is_err(), "case {i} {columns}");
    }
    // The two shapes that hold.
    for (i, (columns, values)) in [
        (", proof", ", '\\x7b7d'"),
        (
            ", from_upload, upload_seq, version_exact",
            ", true, 3, false",
        ),
    ]
    .iter()
    .enumerate()
    {
        let key = [0x60 + u8::try_from(i).expect("small"); 32];
        sqlx::query(&insert(columns, values))
            .bind(ID_A)
            .bind(key.as_slice())
            .bind([3u8; 16].as_slice())
            .execute(&mut conn)
            .await
            .expect(columns);
    }
}

#[tokio::test]
async fn test_store_kept_proof_generations_leave_out_uploaded_records() {
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    // An uploaded record of generation 1 keeps no proof, so it names no generation.
    txn.put_record(&uploaded_record([0x54; 32], 9, 4))
        .await
        .expect("put");
    assert_eq!(
        txn.kept_proof_generations().await.expect("generations").0,
        Vec::<u64>::new()
    );
    txn.put_record(&shared_record([0x55; 32], [1; 32], "tasks", false, 3))
        .await
        .expect("put");
    assert_eq!(
        txn.kept_proof_generations().await.expect("generations").0,
        vec![1]
    );
    drop(txn);
}

#[tokio::test]
async fn test_store_sweeps_take_at_most_their_bound_and_the_rest_later() {
    // Each sweep takes at most the bound it is given, the oldest first, and leaves the rest
    // for a later run: a run stopped after any of them leaves only rows a later one takes
    // (Switch wire 9.1).
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let mut conn = PgConnection::connect_with(fx.db.options())
        .await
        .expect("conn");
    for i in 1u8..=3 {
        sqlx::query(
            "INSERT INTO shared_records (account_id, key, collection, read_scope, write_scopes, \
             generation, version, deleted, value_bytes, writer, cert, op, proof) \
             VALUES ($1, $2, $3, 'tasks', '{tasks}', 1, $4, true, 0, $5, '\\x', '\\x', '\\x')",
        )
        .bind(ID_A)
        .bind([i; 32].as_slice())
        .bind([9u8; 32].as_slice())
        .bind(i64::from(10 - i))
        .bind([5u8; 16].as_slice())
        .execute(&mut conn)
        .await
        .expect("record");
        sqlx::query(
            "INSERT INTO batches (account_id, batch_id, ops_hash, proofs, at_ms, generation, \
             first_seq, last_seq) VALUES ($1, $2, $3, '\\x5b5d', $4, 1, $5, $5)",
        )
        .bind(ID_A)
        .bind([i; 16].as_slice())
        .bind([i; 32].as_slice())
        .bind(i64::try_from(T0).expect("t0") + i64::from(i))
        .bind(i64::from(i))
        .execute(&mut conn)
        .await
        .expect("batch");
        sqlx::query(
            "INSERT INTO invite_codes (account_id, code_hash, max_uses, uses, writer, \
             expires_at_ms, context) VALUES ($1, $2, 1, 0, $3, $4, 'null')",
        )
        .bind(ID_A)
        .bind([i; 32].as_slice())
        .bind([5u8; 16].as_slice())
        .bind(i64::try_from(T0).expect("t0") + i64::from(i))
        .execute(&mut conn)
        .await
        .expect("invite");
    }
    let later = T0 + 1_000;
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    // No cursor waited for: every delete may go.
    assert_eq!(txn.forget_deleted_keys(None, 2).await.expect("forget"), 2);
    assert_eq!(
        txn.drop_expired_batch_proofs(later, 0, 2)
            .await
            .expect("proofs"),
        2
    );
    assert_eq!(
        txn.drop_spent_invite_codes(later, 2).await.expect("codes"),
        2
    );
    txn.commit().await.expect("commit");
    // The oldest went: the delete at the lowest version, the earliest batch and code.
    let mut left: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT key FROM shared_records WHERE account_id = $1 \
         UNION ALL SELECT batch_id FROM batches WHERE account_id = $1 AND proofs IS NOT NULL \
         UNION ALL SELECT code_hash FROM invite_codes WHERE account_id = $1",
    )
    .bind(ID_A)
    .fetch_all(&mut conn)
    .await
    .expect("left");
    left.sort();
    assert_eq!(
        left,
        vec![vec![1u8; 32], vec![3u8; 16], vec![3u8; 32]],
        "the newest of each"
    );
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    // Only up to the lowest cursor waited for: the last delete is past it.
    let through = pubky_switch_core::ops::Position {
        generation: 1,
        seq: 8,
    };
    assert_eq!(
        txn.forget_deleted_keys(Some(through), 2)
            .await
            .expect("forget"),
        0
    );
    assert_eq!(txn.forget_deleted_keys(None, 2).await.expect("forget"), 1);
    assert_eq!(
        txn.drop_expired_batch_proofs(later, 0, 2)
            .await
            .expect("proofs"),
        1
    );
    assert_eq!(
        txn.drop_spent_invite_codes(later, 2).await.expect("codes"),
        1
    );
    assert_eq!(txn.forget_deleted_keys(None, 2).await.expect("forget"), 0);
    txn.commit().await.expect("commit");
    conn.close().await.expect("close");
    fx.finish().await;
}

#[tokio::test]
async fn test_store_forget_compares_whole_positions() {
    // The lowest cursor waited for is a position, generation first: a delete of an earlier
    // generation is before it whatever its seq, one later in the same generation isn't
    // (Switch spec 10.3).
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let mut conn = PgConnection::connect_with(fx.db.options())
        .await
        .expect("conn");
    for (key, generation, version) in [(1u8, 0i64, 100i64), (2, 1, 11)] {
        sqlx::query(
            "INSERT INTO shared_records (account_id, key, collection, read_scope, write_scopes, \
             generation, version, deleted, value_bytes, writer, cert, op, proof) \
             VALUES ($1, $2, $3, 'tasks', '{tasks}', $4, $5, true, 0, $6, '\\x', '\\x', '\\x')",
        )
        .bind(ID_A)
        .bind([key; 32].as_slice())
        .bind([9u8; 32].as_slice())
        .bind(generation)
        .bind(version)
        .bind([5u8; 16].as_slice())
        .execute(&mut conn)
        .await
        .expect("record");
    }
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    let through = pubky_switch_core::ops::Position {
        generation: 1,
        seq: 10,
    };
    assert_eq!(
        txn.forget_deleted_keys(Some(through), 8)
            .await
            .expect("forget"),
        1
    );
    txn.commit().await.expect("commit");
    let left: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT key FROM shared_records WHERE account_id = $1")
            .bind(ID_A)
            .fetch_all(&mut conn)
            .await
            .expect("left");
    assert_eq!(left, vec![vec![2u8; 32]]);
    conn.close().await.expect("close");
    fx.finish().await;
}

#[tokio::test]
async fn test_store_creation_waiting_on_an_erasure_never_commits_before_it() {
    // An account inserted while an erasure of the same ID is still committing waits for the
    // deletion, then is created after that erasure, which the database still owes keys for;
    // with a database that gives new sessions another isolation level, it is created after
    // it or not at all (Switch spec 6.5).
    for level in ["read committed", "repeatable read", "serializable"] {
        let Some(fx) = fixture().await else { return };
        let old = fx.account(ID_A).await;
        let mut admin = fx.db.admin().await.expect("admin");
        admin
            .execute(
                format!(
                    "ALTER DATABASE {} SET default_transaction_isolation = '{level}'",
                    fx.db.name()
                )
                .as_str(),
            )
            .await
            .expect("default isolation");
        admin.close().await.expect("close");
        let store = Store::connect_with(fx.db.options().clone(), &DatabaseConfig::default())
            .await
            .expect("store");
        let erased_at = T0 + 60_000;
        let mut erasing = PgConnection::connect_with(fx.db.options())
            .await
            .expect("conn");
        erasing.execute("BEGIN").await.expect("begin");
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(ID_A)
            .execute(&mut erasing)
            .await
            .expect("delete");
        sqlx::query(
            "INSERT INTO erased_keys (key_id, account_id, erased_at_ms) VALUES ($1, $2, $3)",
        )
        .bind(old.service_key.as_str())
        .bind(ID_A)
        .bind(i64::try_from(erased_at).expect("time"))
        .execute(&mut erasing)
        .await
        .expect("owed");
        let key = fx.keys.generate().await.expect("service key");
        let account = NewAccount {
            service_key: key.id,
            created_at_ms: T0 + 1_000,
            ..old.clone()
        };
        let (created, ()) = tokio::join!(
            async {
                match store.begin_create(&account).await {
                    Ok(Some(creation)) => creation.commit(None).await.ok(),
                    _ => None,
                }
            },
            async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                erasing.execute("COMMIT").await.expect("commit");
            }
        );
        match created {
            Some(created) => assert!(created > erased_at, "{level}: created at {created}"),
            None => assert_ne!(level, "read committed", "created"),
        }
        erasing.close().await.expect("close");
        store.close().await;
        fx.finish().await;
    }
}
