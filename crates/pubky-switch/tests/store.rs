//! The storage layer against PostgreSQL: per-account transactions, durability before the
//! answer, crashes before the commit, per-account ordering, account creation after an
//! erasure, erasure, a generation started afresh, and the reads the verdict takes.
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// A test fails on any error.
#![allow(clippy::expect_used)]

use std::time::Duration;

use pubky_switch::{
    keys::KeyId,
    store::{
        DatabaseConfig, ErasedKey, HeldIdentity, NewAccount, RECOVERY_KEEPS, Recovery, Store,
        StoreError, recovery_clears,
        testing::{TestDatabase, test_database},
    },
};
use sqlx::{Connection, Executor, PgConnection};

const ID_A: &str = "6frao8w9ss5cn544qd64hynikrbr97ae1s5941c7ma5e1epifhgy";
const ID_B: &str = "7p4fn44qoshcwgfndz5grt7fyyz1eycqyduxdqe8o58of1byzodo";
const ID_C: &str = "8um71us3fyw6h8wbcxb5ar3rwusy1a6u49956ikzojg3gcwd1dty";
const ID_D: &str = "9xk3pd5ojmm4z8ckab1nrqjzo6aiu4e7fxg8b3fyeq7tts1yhcwo";
const T0: u64 = 1_767_225_600_000;

fn account_key() -> pubky_switch_core::keys::IdentityKey {
    pubky_switch_core::keys::IdentityKey::from_secret([7; 32])
}

fn identity_doc() -> pubky_switch_core::sig::SignedDoc {
    use pubky_switch_core::records::{IdentityBody, IdentityDoc, IdentityPolicy, Inbox};
    let key = account_key();
    let body = IdentityBody::first(
        key.public(),
        [8; 16],
        Inbox::new(
            "https://switch.example",
            pubky_switch_core::keys::IdentityKey::from_secret([9; 32]).public(),
        ),
        IdentityPolicy::default(),
    );
    IdentityDoc::sign(&key, body)
        .expect("identity")
        .signed()
        .clone()
}

struct Fixture {
    db: TestDatabase,
}

impl Fixture {
    fn store(&self) -> &Store {
        self.db.store()
    }

    async fn account(&self, id: &str) -> NewAccount {
        let account = new_account(id);
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

/// Account `id` at generation 1, created at `T0`, holding no `identity.json`.
fn new_account(id: &str) -> NewAccount {
    NewAccount {
        activation: pubky_switch_core::records::AccountActivation::Ordinary,
        id: id.into(),
        identity_key: account_key().public(),
        generation: 1,
        created_at_ms: T0,
        limits: pubky_switch_core::records::Limits::default(),
        identity_doc: None,
        revoked_apps: Vec::new(),
        enrollment_hash: [0; 32],
        enrollment_store_id: [1; 16],
        stamped_time_ms: T0,
        stamped_by: [2; 16],
    }
}

async fn fixture() -> Option<Fixture> {
    let db = test_database().await?;
    Some(Fixture { db })
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
    assert_eq!(head.created_at_ms, account.created_at_ms);
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
async fn test_store_kept_exclusion_schema_requires_event_provenance() {
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let mut connection = PgConnection::connect_with(fx.db.options())
        .await
        .expect("connect");
    for (reason, at, epoch, rotated) in [
        ("revoked", None, None, false),
        ("departed", None, None, false),
        ("enrolled", None, None, false),
        ("document", Some(T0 as i64), None, false),
        ("document", None, Some(1_i64), false),
        ("document", None, None, true),
    ] {
        let result = sqlx::query(
            "INSERT INTO kept_app_ids (account_id, app_id, reason, at_ms, data_epoch, rotated) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(ID_A)
        .bind([44_u8; 16].as_slice())
        .bind(reason)
        .bind(at)
        .bind(epoch)
        .bind(rotated)
        .execute(&mut connection)
        .await;
        assert!(
            matches!(result, Err(sqlx::Error::Database(ref error))
            if error.code().as_deref() == Some("23514")),
            "{reason}: {result:?}"
        );
    }
    sqlx::query(
        "INSERT INTO kept_app_ids (account_id, app_id, reason) VALUES ($1, $2, 'document')",
    )
    .bind(ID_A)
    .bind([44_u8; 16].as_slice())
    .execute(&mut connection)
    .await
    .expect("document exclusion");
    connection.close().await.expect("close");
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    let kept = txn.kept_entries().await.expect("kept entries");
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].reason, pubky_switch::store::KeptReason::Document);
    assert_eq!(kept[0].at_ms, None);
    drop(txn);
    fx.finish().await;
}

#[tokio::test]
async fn test_store_kept_exclusion_reader_rejects_unknown_event_time() {
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let mut connection = PgConnection::connect_with(fx.db.options())
        .await
        .expect("connect");
    let checks: Vec<String> = sqlx::query_scalar(
        "SELECT conname FROM pg_constraint \
         WHERE conrelid = 'kept_app_ids'::regclass AND contype = 'c'",
    )
    .fetch_all(&mut connection)
    .await
    .expect("checks");
    for check in checks {
        let quoted = check.replace('"', "\"\"");
        connection
            .execute(format!("ALTER TABLE kept_app_ids DROP CONSTRAINT \"{quoted}\"").as_str())
            .await
            .expect("allow corrupted data");
    }
    sqlx::query("INSERT INTO kept_app_ids (account_id, app_id, reason) VALUES ($1, $2, 'revoked')")
        .bind(ID_A)
        .bind([44_u8; 16].as_slice())
        .execute(&mut connection)
        .await
        .expect("corrupted event");
    connection.close().await.expect("close");
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert!(matches!(
        txn.kept_entries().await,
        Err(StoreError::Corrupt("a kept App ID's event provenance"))
    ));
    drop(txn);
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
    assert_eq!(
        txn.stamp(T0 + 1_000, pubky_switch::store::ServiceRun::start()),
        T0 + 1_000
    );
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
    txn.stamp(T0 + 60_000, pubky_switch::store::ServiceRun::start());
    txn.commit().await.expect("commit");
    // The time base went back, as after a wall-clock correction: the account keeps the
    // later time.
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert_eq!(
        txn.stamp(T0 + 1_000, pubky_switch::store::ServiceRun::start()),
        T0 + 60_000
    );
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
    txn.stamp(T0 + 5_000, pubky_switch::store::ServiceRun::start());
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
async fn test_store_serializes_one_account() {
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let store = fx.store().clone();
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let store = store.clone();
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
            txn.commit().await.expect("commit");
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
    assert_eq!(txn.head().chain.map(|(seq, _)| seq), Some(12));
    drop(txn);
    fx.finish().await;
}

#[tokio::test]
async fn test_store_serializes_one_account_under_any_default_isolation() {
    // A request waits for the one ahead of it and then sees its commit, whatever isolation
    // level the database gives new sessions: the store's connections set their own (Switch
    // spec 6.5).
    for level in ["repeatable read", "serializable"] {
        let Some(fx) = fixture().await else { return };
        fx.account(ID_A).await;
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
        let mut tasks = Vec::new();
        for _ in 0..6 {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                let mut txn = store
                    .begin(ID_A)
                    .await
                    .unwrap_or_else(|error| panic!("{level}: begin: {error}"))
                    .expect("account");
                let before = txn.head().last_seq;
                let seq = txn.next_seq().expect("seq");
                assert_eq!(seq, before + 1, "{level}");
                tokio::time::sleep(Duration::from_millis(5)).await;
                txn.commit()
                    .await
                    .unwrap_or_else(|error| panic!("{level}: commit: {error}"));
                seq
            }));
        }
        let mut seqs = Vec::new();
        for task in tasks {
            seqs.push(task.await.expect("task"));
        }
        seqs.sort_unstable();
        assert_eq!(seqs, (1..=6).collect::<Vec<u64>>(), "{level}");
        store.close().await;
        fx.finish().await;
    }
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
    let fx = Fixture { db };
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

/// The migrations a database records as applied: version, checksum, success and when.
async fn applied_migrations(db: &TestDatabase) -> Vec<(i64, Vec<u8>, bool, String)> {
    let mut conn = PgConnection::connect_with(db.options())
        .await
        .expect("conn");
    let applied = sqlx::query_as(
        "SELECT version, checksum, success, installed_on::text FROM _sqlx_migrations \
         ORDER BY version",
    )
    .fetch_all(&mut conn)
    .await
    .expect("applied migrations");
    conn.close().await.expect("close");
    applied
}

#[tokio::test]
async fn test_store_empty_database_comes_up_at_the_current_schema() {
    // The fixture's database is created empty and migrated once.
    let Some(fx) = fixture().await else { return };
    let applied = applied_migrations(&fx.db).await;
    let embedded: Vec<(i64, Vec<u8>, bool)> = pubky_switch::store::MIGRATIONS
        .iter()
        .map(|migration| (migration.version, migration.checksum.to_vec(), true))
        .collect();
    assert!(!embedded.is_empty());
    let recorded: Vec<(i64, Vec<u8>, bool)> = applied
        .iter()
        .map(|(version, checksum, success, _)| (*version, checksum.clone(), *success))
        .collect();
    assert_eq!(recorded, embedded);
    // The schema holds an account, written and read back through the store.
    let account = fx.account(ID_A).await;
    let txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    assert_eq!(
        (txn.head().id.as_str(), txn.head().generation),
        (ID_A, account.generation)
    );
    drop(txn);
    // Migrating again changes nothing: no migration runs, and the account stays.
    fx.store().migrate().await.expect("migrate again");
    assert_eq!(applied_migrations(&fx.db).await, applied);
    assert!(fx.store().begin(ID_A).await.expect("begin").is_some());
    fx.finish().await;
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
    let policy = pubky_switch_core::ident::Policy::new(read_scope, &["tasks"]);
    record_at_policy(key, collection, policy, deleted, version)
}

/// [`shared_record`] at `policy`.
fn record_at_policy(
    key: [u8; 32],
    collection: [u8; 32],
    policy: pubky_switch_core::ident::Policy,
    deleted: bool,
    version: u64,
) -> pubky_switch::store::StoredRecord {
    use pubky_switch_core::{
        chain::{ChainTip, ItemType, ProofBody, TransitionProof, ZERO_HASH},
        enc::b64,
        keys::{AppKeys, IdentityKey},
        ops::{
            BatchRef, OpBody, OpKind, RecordPut, RecordVersion, SignedOp, StateAfter, proof_state,
        },
        records::{AppCert, AppCertBody},
        sealed::SealedValue,
        shared::{ApplicationRef, RecordState},
    };
    let identity = IdentityKey::from_secret([1; 32]);
    let app = AppKeys::from_secrets([2; 32], [3; 32]);
    let read_scope = policy.read_scope.clone();
    let read_scope = read_scope.as_str();
    let put = RecordPut {
        key,
        collection,
        policy: policy.clone(),
        expected_version: RecordVersion::NONE,
        value_sealed: SealedValue::seal_with_nonce(
            &identity.scope_key(1, read_scope),
            &identity.public(),
            1,
            read_scope,
            &key,
            if deleted { b"" } else { b"{}" },
            &[4; 24],
        )
        .expect("sealed record"),
        id_inputs: pubky_switch_core::ops::IdInputs {
            collection: "tasks.items".into(),
            blinded_key: key,
        },
    };
    let op = SignedOp::sign(
        &app,
        OpBody {
            identity: identity.public(),
            app_id: Some(app.app_id_bytes()),
            generation: 1,
            batch: BatchRef {
                id: [5; 16],
                count: 1,
            },
            conditions: Vec::new(),
            kind: OpKind::RecordPut(put),
        },
    )
    .expect("signed record");
    let revision = ApplicationRef {
        generation: 1,
        seq: version,
        item_hash: op.item_hash().expect("item hash"),
    };
    let (stub, _) = ChainTip {
        generation: 1,
        seq: version - 1,
        chain_hash: ZERO_HASH,
    }
    .append(
        version,
        T0,
        ItemType::Op,
        revision.item_hash,
        Some(op.body().batch),
    )
    .expect("record stub");
    let state = proof_state(&op, &StateAfter::Record(RecordVersion::new(1, version)))
        .expect("record state");
    let proof = TransitionProof::sign(
        &ed25519_dalek::SigningKey::from_bytes(&[6; 32]),
        &identity.public(),
        ProofBody::new(stub, b64(&key), &state),
    )
    .expect("record proof");
    let cert = AppCert::issue(
        &identity,
        AppCertBody::new(
            identity.public(),
            app.signing_public(),
            app.bundle_public(),
            vec![read_scope.into()],
            &[],
            T0 - 1,
            T0 + 1_000,
        ),
    )
    .expect("certificate");
    pubky_switch::store::StoredRecord {
        state: RecordState {
            key,
            collection,
            policy,
            version: RecordVersion::new(1, version),
            deleted,
        },
        revision,
        value_bytes: if deleted { 0 } else { 2 },
        writer: app.app_id_bytes(),
        cert: cert.signed().clone(),
        op: op.signed().clone(),
        origin: pubky_switch::store::RecordOrigin::Written {
            proof: proof.signed().clone(),
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

/// A record taken from a recovery upload after a provider loss, at `version` of generation 1,
/// listed by the `upload` transition at `seq`.
fn uploaded_record(key: [u8; 32], version: u64, seq: u64) -> pubky_switch::store::StoredRecord {
    let mut record = shared_record(key, [1; 32], "tasks", false, version);
    record.origin = pubky_switch::store::RecordOrigin::Uploaded { seq, exact: false };
    record.revision.generation = 2;
    record.revision.seq = seq;
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
async fn test_store_record_write_of_another_policy_is_refused() {
    use pubky_switch::store::StoreError;
    use pubky_switch_core::ident::Policy;
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let key = [0x57; 32];
    {
        let mut txn = fx
            .store()
            .begin(ID_A)
            .await
            .expect("begin")
            .expect("account");
        txn.put_record(&shared_record(key, [1; 32], "tasks", false, 3))
            .await
            .expect("put");
        txn.put_record(&shared_record(key, [1; 32], "tasks", true, 4))
            .await
            .expect("put");
        txn.commit().await.expect("commit");
    }
    // A record's collection and policy are fixed at creation (Switch wire 6.2): a write of
    // another one, a permanent policy over the deleted ordinary record among them (Switch
    // spec 10.3.1), is refused, and the row keeps what it held.
    let ordinary = Policy::new("tasks", &["tasks"]);
    for (collection, policy) in [
        ([1; 32], ordinary.clone().with_create_scope("tasks_admin")),
        ([1; 32], ordinary.clone().permanent(None)),
        ([1; 32], ordinary.clone().permanent(Some(1))),
        ([1; 32], Policy::new("tasks", &["tasks", "tasks_people"])),
        ([2; 32], ordinary.clone()),
    ] {
        let mut txn = fx
            .store()
            .begin(ID_A)
            .await
            .expect("begin")
            .expect("account");
        let refused = txn
            .put_record(&record_at_policy(key, collection, policy.clone(), false, 5))
            .await;
        assert!(
            matches!(refused, Err(StoreError::Corrupt(_))),
            "{policy:?}: {refused:?}"
        );
        drop(txn);
        let held = record_at(&fx, key).await;
        assert!(held.state.deleted);
        assert_eq!(held.state.policy, ordinary);
        assert_eq!(held.state.collection, [1; 32]);
    }
    // The same policy is written as before.
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    txn.put_record(&shared_record(key, [1; 32], "tasks", false, 5))
        .await
        .expect("put");
    txn.commit().await.expect("commit");
    assert!(!record_at(&fx, key).await.state.deleted);
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
             permanent, generation, version, application_generation, application_seq, application_item_hash, \
             deleted, value_bytes, writer, cert, op{columns}) VALUES \
             ($1, $2, $2, 'tasks', '{{tasks}}', false, 1, 1, 1, 1, $2, false, 0, $3, '\\x7b7d', '\\x7b7d'{values})"
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
             permanent, generation, version, application_generation, application_seq, application_item_hash, \
             deleted, value_bytes, writer, cert, op, proof) \
             VALUES ($1, $2, $3, 'tasks', '{tasks}', false, 1, $4, 1, $4, $2, true, 0, $5, '\\x', '\\x', '\\x')",
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
    for (key, generation, version) in [(1u8, 1i64, 100i64), (2, 2, 11)] {
        sqlx::query(
            "INSERT INTO shared_records (account_id, key, collection, read_scope, write_scopes, \
             permanent, generation, version, application_generation, application_seq, application_item_hash, \
             deleted, value_bytes, writer, cert, op, proof) \
             VALUES ($1, $2, $3, 'tasks', '{tasks}', false, $4, $5, $4, $5, $2, true, 0, $6, '\\x', '\\x', '\\x')",
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
        generation: 2,
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

/// Wait until one session waits for an advisory lock another transaction holds.
async fn identity_lock_waits(db: &TestDatabase, context: &str) {
    let mut watcher = PgConnection::connect_with(db.options())
        .await
        .expect("conn");
    let mut waited = 0;
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() \
             AND wait_event_type = 'Lock' AND wait_event = 'advisory'",
        )
        .fetch_one(&mut watcher)
        .await
        .expect("activity");
        if waiting == 1 {
            break;
        }
        waited += 1;
        assert!(
            waited < 500,
            "{context}: the identity's lock was never waited for"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    watcher.close().await.expect("close");
}

#[tokio::test]
async fn test_store_identity_lock_holds_a_creation_until_the_erasure_commits() {
    // An erasure holds the identity's lock, then the account's, through its deletion's
    // commit; a creation of the identity takes the identity's lock first, so it waits for the
    // erasure and then finds the account gone, whatever isolation level the database gives
    // new sessions (Switch wire 7.3, Table 3).
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
        let erasing = store
            .begin(ID_A)
            .await
            .expect("begin")
            .expect("the account");
        let account = NewAccount {
            activation: pubky_switch_core::records::AccountActivation::Ordinary,
            created_at_ms: T0 + 1_000,
            ..old.clone()
        };
        let (created, ()) = tokio::join!(
            async {
                let mut lock = store.lock_identity(ID_A).await.ok()?;
                if lock.has_account().await.ok()? {
                    return None;
                }
                lock.create(&account).await.ok()??.commit().await.ok()
            },
            async {
                identity_lock_waits(&fx.db, level).await;
                erasing.erase(T0 + 500).await.expect("erase");
            }
        );
        assert!(created.is_some(), "{level}: not created");
        let found = store.lookup(ID_A).await.expect("lookup").expect("account");
        assert_eq!(found.created_at_ms, T0 + 1_000, "{level}");
        store.close().await;
        fx.finish().await;
    }
}

#[tokio::test]
async fn test_store_identity_lock_gives_up_at_the_lock_timeout() {
    // A request, an enrollment or an erasure waits for an identity's lock at most the
    // configured lock timeout, then is refused having written nothing; another identity's
    // lock is free meanwhile (Switch spec 6.5).
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    let config = DatabaseConfig {
        lock_timeout_ms: 200,
        ..DatabaseConfig::default()
    };
    let store = Store::connect_with(fx.db.options().clone(), &config)
        .await
        .expect("store");
    let held = store.lock_identity(ID_A).await.expect("lock");
    let refused = tokio::time::timeout(Duration::from_secs(5), store.lock_identity(ID_A))
        .await
        .expect("waited past the lock timeout");
    let error = refused.expect_err("taken twice");
    assert!(matches!(error, StoreError::LockTimeout), "{error:?}");
    assert!(error.is_refused(), "nothing written");
    let refused = tokio::time::timeout(Duration::from_secs(5), store.begin(ID_A))
        .await
        .expect("waited past the lock timeout");
    assert!(
        matches!(refused, Err(StoreError::LockTimeout)),
        "{refused:?}"
    );
    store.lock_identity(ID_B).await.expect("another identity's");
    drop(held);
    assert!(store.begin(ID_A).await.expect("free again").is_some());
    store.close().await;
    fx.finish().await;
}

#[tokio::test]
async fn test_store_creation_commits_at_the_time_asked_for() {
    // An account created under its identity's lock commits at the creation time the caller
    // read under that lock, its stamped time with it; one that exists already is no
    // creation, and keeps its time (Switch wire 7.3, "The mark").
    let Some(fx) = fixture().await else { return };
    for (id, at) in [(ID_A, T0), (ID_B, T0 + 5_001)] {
        let account = NewAccount {
            activation: pubky_switch_core::records::AccountActivation::Ordinary,
            created_at_ms: at,
            stamped_time_ms: at,
            ..new_account(id)
        };
        fx.store()
            .lock_identity(id)
            .await
            .expect("lock")
            .create(&account)
            .await
            .expect("insert")
            .expect("no account")
            .commit()
            .await
            .expect("commit");
        let found = fx
            .store()
            .lookup(id)
            .await
            .expect("lookup")
            .expect("account");
        assert_eq!(
            (found.created_at_ms, found.stamped_time_ms),
            (at, at),
            "{id}"
        );
    }
    assert!(
        fx.store()
            .lock_identity(ID_A)
            .await
            .expect("lock")
            .create(&new_account(ID_A))
            .await
            .expect("insert")
            .is_none()
    );
    // An account is created only under its own identity's lock.
    assert!(
        fx.store()
            .lock_identity(ID_C)
            .await
            .expect("lock")
            .create(&new_account(ID_D))
            .await
            .is_err()
    );
    fx.finish().await;
}

/// The tables with an account column.
async fn account_tables(db: &TestDatabase) -> Vec<String> {
    let mut conn = PgConnection::connect_with(db.options())
        .await
        .expect("conn");
    let mut tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.columns \
         WHERE table_schema = current_schema() AND column_name = 'account_id' \
         ORDER BY table_name",
    )
    .fetch_all(&mut conn)
    .await
    .expect("tables");
    conn.close().await.expect("close");
    tables.dedup();
    tables
}

/// The rows of `table` account `id` holds.
async fn rows_of(db: &TestDatabase, table: &str, id: &str) -> i64 {
    let mut conn = PgConnection::connect_with(db.options())
        .await
        .expect("conn");
    let count = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM {table} WHERE account_id = $1"
    ))
    .bind(id)
    .fetch_one(&mut conn)
    .await
    .expect("count");
    conn.close().await.expect("close");
    count
}

/// Give account `id` state of its generation: a chain item, a shared record, a push
/// registration, an App ID kept for good, one held for the next generation and an
/// identity.json. The push registration's key.
async fn seed_state(fx: &Fixture, id: &str) -> KeyId {
    let push_key = KeyId::random().expect("key id");
    let mut conn = PgConnection::connect_with(fx.db.options())
        .await
        .expect("conn");
    sqlx::query(
        "INSERT INTO chain_items (account_id, generation, seq, item_type, envelope, \
         chain_hash, server_time_ms) VALUES ($1, 1, 1, 'op', '\\x7b7d', $2, $3)",
    )
    .bind(id)
    .bind([1u8; 32].as_slice())
    .bind(i64::try_from(T0).expect("t0"))
    .execute(&mut conn)
    .await
    .expect("chain item");
    sqlx::query(
        "INSERT INTO push_registrations (account_id, app_id, relay_url, push_key_id, \
         push_public, handles, set_at_ms) VALUES ($1, $2, 'https://relay.example', $3, $4, \
         '{}', $5)",
    )
    .bind(id)
    .bind([5u8; 16].as_slice())
    .bind(push_key.as_str())
    .bind([6u8; 32].as_slice())
    .bind(i64::try_from(T0).expect("t0"))
    .execute(&mut conn)
    .await
    .expect("push registration");
    sqlx::query(
        "INSERT INTO kept_app_ids (account_id, app_id, reason, at_ms) \
         VALUES ($1, $2, 'revoked', $3)",
    )
    .bind(id)
    .bind([9u8; 16].as_slice())
    .bind(i64::try_from(T0).expect("t0"))
    .execute(&mut conn)
    .await
    .expect("kept app id");
    conn.close().await.expect("close");
    let mut txn = fx.store().begin(id).await.expect("begin").expect("account");
    let seq = txn.next_seq().expect("seq");
    txn.set_chain_head(seq, [1; 32]).expect("chain head");
    txn.put_record(&shared_record([0x21; 32], [1; 32], "tasks", false, 1))
        .await
        .expect("record");
    txn.hold_revoked_apps(&[[8; 16]]).await.expect("hold");
    txn.set_identity(&HeldIdentity {
        doc: identity_doc(),
        proof: None,
    })
    .await
    .expect("identity");
    txn.commit().await.expect("commit");
    push_key
}

/// The rows account `id` holds in each table with an account column.
async fn holdings_of(fx: &Fixture, id: &str) -> Vec<(String, i64)> {
    let mut held = Vec::new();
    for table in account_tables(&fx.db).await {
        let rows = rows_of(&fx.db, &table, id).await;
        held.push((table, rows));
    }
    held
}

#[tokio::test]
async fn test_store_erase_deletes_every_row_and_owes_the_push_keys() {
    // An erasure deletes the account's row and every row of its state, and owes deleting its
    // apps' push keys; another account's rows stay (Switch wire 7.4.16, 8.1).
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    fx.account(ID_B).await;
    let push_a = seed_state(&fx, ID_A).await;
    seed_state(&fx, ID_B).await;
    let before_b = holdings_of(&fx, ID_B).await;
    for table in [
        "chain_items",
        "shared_records",
        "push_registrations",
        "kept_app_ids",
        "held_revoked_apps",
        "enrollment_answers",
    ] {
        assert_eq!(rows_of(&fx.db, table, ID_A).await, 1, "{table}");
    }
    let erased_at = T0 + 9_000;
    let txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    txn.erase(erased_at).await.expect("erase");

    assert!(fx.store().lookup(ID_A).await.expect("lookup").is_none());
    assert!(fx.store().begin(ID_A).await.expect("begin").is_none());
    for (table, rows) in holdings_of(&fx, ID_A).await {
        let expected = i64::from(table == "erased_keys");
        assert_eq!(rows, expected, "{table}");
    }
    assert_eq!(
        fx.store().erased_keys().await.expect("owed"),
        vec![ErasedKey {
            key: push_a,
            account: ID_A.into(),
            erased_at_ms: erased_at,
        }]
    );
    assert_eq!(holdings_of(&fx, ID_B).await, before_b, "B's rows stay");
    fx.finish().await;
}

#[tokio::test]
async fn test_store_erase_that_fails_to_commit_keeps_the_account() {
    // An erasure whose connection dies before its commit deletes nothing and owes nothing.
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    seed_state(&fx, ID_A).await;
    let before = holdings_of(&fx, ID_A).await;
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    let pid = backend_pid(&mut txn).await;
    kill_backend(&fx.db, pid).await;
    assert!(txn.erase(T0 + 9_000).await.is_err());
    assert!(fx.store().lookup(ID_A).await.expect("lookup").is_some());
    assert_eq!(holdings_of(&fx, ID_A).await, before);
    assert!(fx.store().erased_keys().await.expect("owed").is_empty());
    fx.finish().await;
}

#[tokio::test]
async fn test_store_start_afresh_keeps_and_empties_the_right_tables() {
    // A generation started afresh empties every table of the generation's state, keeps the
    // App IDs kept for good, joined by those held for the next generation, the enrollment
    // answers and the push keys owed, the registration's key among them; the account keeps
    // its row and service time, and serves the new generation from an empty chain (Switch
    // wire 3.3, 3.7, 7.3 Table 2).
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    fx.account(ID_B).await;
    let push_a = seed_state(&fx, ID_A).await;
    seed_state(&fx, ID_B).await;
    let before_a = holdings_of(&fx, ID_A).await;
    let before_b = holdings_of(&fx, ID_B).await;
    let at = T0 + 3_000;

    // Not committed: nothing changes.
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    txn.start_afresh(2, 1, at, true).await.expect("afresh");
    drop(txn);
    assert_eq!(holdings_of(&fx, ID_A).await, before_a);

    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    let stamped = txn.head().stamped_time_ms;
    txn.start_afresh(2, 1, at, true).await.expect("afresh");
    assert_eq!(
        (txn.head().generation, txn.head().last_seq, txn.head().chain),
        (2, 0, None)
    );
    // The new generation's first chain item is seq 1.
    assert_eq!(txn.next_seq().expect("seq"), 1);
    txn.commit().await.expect("commit");

    for table in recovery_clears() {
        assert_eq!(rows_of(&fx.db, table, ID_A).await, 0, "{table} emptied");
    }
    for table in RECOVERY_KEEPS {
        assert!(rows_of(&fx.db, table, ID_A).await > 0, "{table} kept");
    }
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    let mut kept = txn.kept_app_ids().await.expect("kept");
    kept.sort_unstable();
    assert_eq!(kept, vec![[8; 16], [9; 16]], "the held App ID joins");
    assert!(txn.held_revoked_apps().await.expect("held").is_empty());
    assert_eq!(
        txn.recovery().await.expect("recovery"),
        Some(Recovery {
            recovery_from: 1,
            declared_at_ms: at,
            admission_staged: true,
        })
    );
    assert!(txn.held_identity().await.expect("identity").is_none());
    drop(txn);
    let found = fx
        .store()
        .lookup(ID_A)
        .await
        .expect("lookup")
        .expect("account");
    assert_eq!(
        (found.generation, found.chain, found.stamped_time_ms),
        (2, None, stamped)
    );
    assert!(
        fx.store()
            .erased_keys()
            .await
            .expect("owed")
            .iter()
            .any(|owed| owed.key == push_a && owed.account == ID_A),
        "the registration's key is owed"
    );
    assert_eq!(holdings_of(&fx, ID_B).await, before_b, "B's rows stay");
    fx.finish().await;
}

#[tokio::test]
async fn test_store_lookup_reads_generation_chain_and_document() {
    // The verdict's read of an account before its lock: generation, chain head, times and
    // the newest identity.json (Switch wire 7.3 step 2).
    let Some(fx) = fixture().await else { return };
    assert!(fx.store().lookup(ID_A).await.expect("lookup").is_none());
    fx.account(ID_A).await;
    let found = fx
        .store()
        .lookup(ID_A)
        .await
        .expect("lookup")
        .expect("account");
    assert_eq!(
        (
            found.generation,
            found.chain,
            found.stamped_time_ms,
            found.created_at_ms,
            found.identity_doc
        ),
        (1, None, T0, T0, None)
    );
    let doc = identity_doc();
    let mut txn = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    txn.stamp(T0 + 1_000, pubky_switch::store::ServiceRun::start());
    append(&mut txn, 0xab);
    txn.set_identity(&HeldIdentity {
        doc: doc.clone(),
        proof: None,
    })
    .await
    .expect("identity");
    txn.commit().await.expect("commit");
    // It doesn't wait for the account's lock, and reads what was committed.
    let held = fx
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    let found = tokio::time::timeout(Duration::from_secs(2), fx.store().lookup(ID_A))
        .await
        .expect("not blocked by the lock")
        .expect("lookup")
        .expect("account");
    drop(held);
    assert_eq!(
        (
            found.generation,
            found.chain,
            found.stamped_time_ms,
            found.created_at_ms,
            found.identity_doc
        ),
        (1, Some((1, [0xab; 32])), T0 + 1_000, T0, Some(doc))
    );
    fx.finish().await;
}

#[tokio::test]
async fn test_store_stub_hash_at_reads_the_held_stub() {
    // The chain hash of the stub an account holds at a generation and seq, for a fork past
    // the mark (Switch wire 7.3, Table 1); none where it holds no stub there.
    let Some(fx) = fixture().await else { return };
    fx.account(ID_A).await;
    fx.account(ID_B).await;
    let mut conn = PgConnection::connect_with(fx.db.options())
        .await
        .expect("conn");
    for (id, seq, hash) in [(ID_A, 1i64, 1u8), (ID_A, 2, 2), (ID_B, 3, 3)] {
        sqlx::query(
            "INSERT INTO chain_items (account_id, generation, seq, item_type, envelope, \
             chain_hash, server_time_ms) VALUES ($1, 1, $2, 'op', '\\x7b7d', $3, 0)",
        )
        .bind(id)
        .bind(seq)
        .bind([hash; 32].as_slice())
        .execute(&mut conn)
        .await
        .expect("chain item");
    }
    conn.close().await.expect("close");
    let store = fx.store();
    assert_eq!(
        store.stub_hash_at(ID_A, 1, 2).await.expect("stub"),
        Some([2; 32])
    );
    assert_eq!(
        store.stub_hash_at(ID_A, 1, 1).await.expect("stub"),
        Some([1; 32])
    );
    for (id, generation, seq) in [(ID_A, 1, 3), (ID_A, 2, 1), (ID_B, 1, 2), (ID_C, 1, 1)] {
        assert_eq!(
            store.stub_hash_at(id, generation, seq).await.expect("stub"),
            None,
            "{id} ({generation}, {seq})"
        );
    }
    fx.finish().await;
}
