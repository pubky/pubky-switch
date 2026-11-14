//! The operator's check of chain heads against their keys' marks, against PostgreSQL: each
//! state, reading only, and a replica's verdict (Switch spec 6.5).
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used)]

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use pubky_switch::{
    check_marks::{self, AccountReport, CheckOptions, DatabaseChoice, MarkState},
    keys::{FileKeyStore, KeyStore, KeyStoreView, Mark},
    store::{
        NewAccount,
        heads::open_read_only_with,
        testing::{TestDatabase, test_database},
    },
};
use sqlx::Connection;

use pubky_switch_core::{
    keys::IdentityKey,
    records::{IdentityBody, IdentityDoc, IdentityPolicy, Inbox},
};

const ORIGIN: &str = "https://switch.example";
const T0: u64 = 1_767_225_600_000;

struct Fixture {
    db: TestDatabase,
    keys: FileKeyStore,
    key_dir: tempfile::TempDir,
}

async fn fixture() -> Option<Fixture> {
    let db = test_database().await?;
    let key_dir = tempfile::tempdir().expect("key dir");
    let keys = FileKeyStore::open(key_dir.path()).expect("key store");
    Some(Fixture { db, keys, key_dir })
}

/// A new account `id` in `db`, under a new key of `keys`; serving when its enrollment's
/// `identity.json` names this service and the key.
async fn create(db: &TestDatabase, keys: &FileKeyStore, id: &str, serving: bool) -> NewAccount {
    let key = keys.generate().await.expect("service key");
    let account = new_account(id, key.id, key.public, serving);
    assert!(db.store().create_account(&account).await.expect("create"));
    account
}

fn new_account(
    id: &str,
    service_key: pubky_switch::keys::KeyId,
    public: [u8; 32],
    serving: bool,
) -> NewAccount {
    let identity = IdentityKey::from_secret([7; 32]);
    let doc = serving.then(|| {
        let body = IdentityBody::first(
            identity.public(),
            [4; 16],
            Inbox::new(ORIGIN, public),
            IdentityPolicy::default(),
        );
        IdentityDoc::sign(&identity, body)
            .expect("sign")
            .signed()
            .clone()
    });
    NewAccount {
        id: id.into(),
        identity_key: identity.public(),
        generation: 1,
        service_key,
        created_at_ms: T0,
        limits: pubky_switch_core::records::Limits::default(),
        identity_doc: doc,
        revoked_apps: Vec::new(),
        enrollment_hash: [0; 32],
    }
}

/// Append one chain item per hash to account `id`, moving the key's mark with each commit
/// when `marked`.
async fn append(db: &TestDatabase, keys: &FileKeyStore, id: &str, hashes: &[u8], marked: bool) {
    for hash in hashes {
        let mut txn = db.store().begin(id).await.expect("begin").expect("account");
        let seq = txn.next_seq().expect("seq");
        txn.set_chain_head(seq, [*hash; 32]).expect("head");
        if marked {
            txn.commit_marked(keys).await.expect("commit");
        } else {
            txn.commit().await.expect("commit");
        }
    }
}

/// Put a mark file in place, as a newer key store holds it.
fn write_mark(key_dir: &Path, account: &NewAccount, mark: Mark) {
    fs::write(
        key_dir.join("marks").join(account.service_key.as_str()),
        serde_json::to_vec(&mark).expect("mark"),
    )
    .expect("write mark");
}

fn options(db: &TestDatabase, key_dir: &Path, all: bool) -> CheckOptions {
    CheckOptions {
        database: db.options().clone(),
        choice: DatabaseChoice::Configured,
        key_dir: key_dir.to_path_buf(),
        origin: ORIGIN.into(),
        all,
    }
}

fn find<'a>(accounts: &'a [AccountReport], id: &str) -> &'a AccountReport {
    accounts
        .iter()
        .find(|account| account.account == id)
        .expect("a line for the account")
}

/// Every file under `dir`, with its content.
fn listing(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut all = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in fs::read_dir(&next).expect("read dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                all.push((path.clone(), Vec::new()));
                stack.push(path);
            } else {
                let bytes = fs::read(&path).expect("read");
                all.push((path, bytes));
            }
        }
    }
    all.sort();
    all
}

/// The accounts table, as text.
async fn accounts_digest(db: &TestDatabase) -> String {
    let mut conn = sqlx::PgConnection::connect_with(db.options())
        .await
        .expect("connect");
    sqlx::query_scalar(
        "SELECT coalesce(md5(string_agg(a::text, '|' ORDER BY a.id)), '') FROM accounts a",
    )
    .fetch_one(&mut conn)
    .await
    .expect("digest")
}

#[tokio::test]
async fn test_check_marks_reports_each_state() {
    let Some(fx) = fixture().await else { return };
    let (db, keys, dir) = (&fx.db, &fx.keys, fx.key_dir.path());

    let current = create(db, keys, "current", true).await;
    append(db, keys, "current", &[1, 2], true).await;

    // The database went back two positions behind the key's mark.
    let behind = create(db, keys, "behind", true).await;
    append(db, keys, "behind", &[1, 2, 3], true).await;
    write_mark(
        dir,
        &behind,
        Mark {
            generation: 1,
            seq: 5,
            chain_hash: [5; 32],
        },
    );

    let fork = create(db, keys, "fork", true).await;
    append(db, keys, "fork", &[1, 2], true).await;
    write_mark(
        dir,
        &fork,
        Mark {
            generation: 1,
            seq: 2,
            chain_hash: [9; 32],
        },
    );

    let other = create(db, keys, "othergen", true).await;
    append(db, keys, "othergen", &[1], true).await;
    write_mark(
        dir,
        &other,
        Mark {
            generation: 2,
            seq: 1,
            chain_hash: [1; 32],
        },
    );

    // A commit whose mark didn't move yet.
    create(db, keys, "ahead", true).await;
    append(db, keys, "ahead", &[1], true).await;
    append(db, keys, "ahead", &[2, 3], false).await;

    let lost = create(db, keys, "marklost", true).await;
    append(db, keys, "marklost", &[1], true).await;
    fs::remove_file(dir.join("marks").join(lost.service_key.as_str())).expect("remove mark");

    let missing = create(db, keys, "keymissing", true).await;
    append(db, keys, "keymissing", &[1], true).await;
    keys.delete(&missing.service_key).await.expect("delete key");

    create(db, keys, "erased", false).await;
    keys.record_erasure("erased", T0).await.expect("erasure");

    create(db, keys, "unmarked", true).await;

    // Behind, but not serving: the service doesn't refuse it.
    let staged = create(db, keys, "staged", false).await;
    append(db, keys, "staged", &[1], true).await;
    write_mark(
        dir,
        &staged,
        Mark {
            generation: 1,
            seq: 4,
            chain_hash: [4; 32],
        },
    );

    let report = check_marks::run(&options(db, dir, true))
        .await
        .expect("check");
    let all = &report.accounts;
    assert_eq!(all.len(), 10);
    let line = find(all, "current");
    assert_eq!(
        (line.state, line.serving, line.head_seq, line.mark_seq),
        (MarkState::Current, true, Some(2), Some(2))
    );
    assert_eq!(line.generation, current.generation);
    let line = find(all, "behind");
    assert_eq!(
        (line.state, line.head_seq, line.mark_seq, line.lost),
        (MarkState::Behind, Some(3), Some(5), Some(2))
    );
    assert_eq!(find(all, "fork").state, MarkState::Fork);
    assert_eq!(find(all, "othergen").state, MarkState::OtherGeneration);
    let line = find(all, "ahead");
    assert_eq!(
        (line.state, line.head_seq, line.mark_seq, line.ahead_by),
        (MarkState::Ahead, Some(3), Some(1), Some(2))
    );
    assert_eq!(find(all, "marklost").state, MarkState::MarkLost);
    let line = find(all, "keymissing");
    assert_eq!((line.state, line.serving), (MarkState::KeyMissing, false));
    let line = find(all, "erased");
    assert_eq!(
        (line.state, line.erased_at_ms),
        (MarkState::ErasedInLedger, Some(T0))
    );
    let line = find(all, "unmarked");
    assert_eq!(
        (line.state, line.head_seq, line.mark_seq),
        (MarkState::Unmarked, None, None)
    );
    let line = find(all, "staged");
    assert_eq!((line.state, line.serving), (MarkState::Behind, false));

    let summary = &report.summary;
    assert_eq!(summary.accounts, 10);
    assert_eq!(summary.serving, 7);
    assert_eq!(summary.needs_attention, 6);
    assert_eq!(summary.states[&MarkState::Current], 1);
    assert_eq!(summary.states[&MarkState::Behind], 2);
    assert_eq!(summary.states[&MarkState::AccountMissing], 0);
    assert!(report.missing.is_empty());
    assert!(report.needs_attention());

    // Without `all`, only the accounts that need attention, in the order of their IDs.
    let report = check_marks::run(&options(db, dir, false))
        .await
        .expect("check");
    let ids: Vec<&str> = report
        .accounts
        .iter()
        .map(|line| line.account.as_str())
        .collect();
    assert_eq!(
        ids,
        [
            "behind",
            "erased",
            "fork",
            "keymissing",
            "marklost",
            "othergen"
        ]
    );
    assert_eq!(report.summary.accounts, 10);
    fx.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_check_marks_clean_database_needs_nothing() {
    let Some(fx) = fixture().await else { return };
    let (db, keys, dir) = (&fx.db, &fx.keys, fx.key_dir.path());
    create(db, keys, "current", true).await;
    append(db, keys, "current", &[1], true).await;
    create(db, keys, "unmarked", true).await;
    let report = check_marks::run(&options(db, dir, false))
        .await
        .expect("check");
    assert!(report.accounts.is_empty());
    assert!(!report.needs_attention());
    assert_eq!(report.summary.accounts, 2);
    let text = report.to_json_lines().expect("encode");
    assert_eq!(text.lines().count(), 1);
    assert!(text.starts_with("{\"summary\":"), "{text}");
    fx.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_check_marks_reads_only() {
    let Some(fx) = fixture().await else { return };
    let (db, keys, dir) = (&fx.db, &fx.keys, fx.key_dir.path());
    let behind = create(db, keys, "behind", true).await;
    append(db, keys, "behind", &[1], true).await;
    write_mark(
        dir,
        &behind,
        Mark {
            generation: 1,
            seq: 3,
            chain_hash: [3; 32],
        },
    );
    create(db, keys, "erased", true).await;
    keys.record_erasure("erased", T0).await.expect("erasure");

    let files = listing(dir);
    let digest = accounts_digest(db).await;
    let report = check_marks::run(&options(db, dir, true))
        .await
        .expect("check");
    assert_eq!(report.summary.needs_attention, 2);
    assert_eq!(listing(dir), files, "the key store is unchanged");
    assert_eq!(
        accounts_digest(db).await,
        digest,
        "the database is unchanged"
    );

    // The check's session refuses writes.
    let mut conn = open_read_only_with(db.options()).await.expect("connect");
    let refused = sqlx::query("UPDATE accounts SET generation = generation")
        .execute(&mut conn)
        .await
        .expect_err("read only");
    let code = refused
        .as_database_error()
        .and_then(|error| error.code())
        .map(|code| code.to_string());
    assert_eq!(code.as_deref(), Some("25006"), "{refused}");

    // A key store that isn't there fails the check, and nothing is made.
    let absent = dir.join("absent");
    let error = check_marks::run(&options(db, &absent, true))
        .await
        .expect_err("no key store");
    assert!(matches!(error, check_marks::CheckError::Keys(_)), "{error}");
    assert!(!absent.exists());
    assert_eq!(listing(dir), files);
    fx.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_check_marks_replica_gives_its_own_verdict() {
    let Some(fx) = fixture().await else { return };
    let Some(replica) = test_database().await else {
        return;
    };
    let (db, keys, dir) = (&fx.db, &fx.keys, fx.key_dir.path());
    // The configured database holds three chain items the mark covers; the replica, the
    // same account with the first only, as a lagging standby would.
    let account = create(db, keys, "lagging", true).await;
    append(db, keys, "lagging", &[1, 2, 3], true).await;
    assert!(
        replica
            .store()
            .create_account(&account)
            .await
            .expect("create")
    );
    append(&replica, keys, "lagging", &[1], false).await;

    let configured = check_marks::run(&options(db, dir, true))
        .await
        .expect("check");
    assert_eq!(configured.summary.database, DatabaseChoice::Configured);
    assert_eq!(
        find(&configured.accounts, "lagging").state,
        MarkState::Current
    );
    assert!(!configured.needs_attention());

    let on_replica = check_marks::run(&CheckOptions {
        database: replica.options().clone(),
        choice: DatabaseChoice::Replica,
        ..options(db, dir, true)
    })
    .await
    .expect("check");
    assert_eq!(on_replica.summary.database, DatabaseChoice::Replica);
    let line = find(&on_replica.accounts, "lagging");
    assert_eq!(
        (line.state, line.lost, line.serving),
        (MarkState::Behind, Some(2), true)
    );
    assert!(on_replica.needs_attention());
    replica.drop_database().await.expect("drop");
    fx.db.drop_database().await.expect("drop");
}

#[test]
fn test_check_marks_options_from_config() {
    let mut config = pubky_switch::config::Config::default();
    assert!(matches!(
        CheckOptions::from_config(&config, Some("postgres://h/db"), false),
        Err(check_marks::CheckError::NoKeyStore)
    ));
    config.keys.path = Some(PathBuf::from("/nonexistent/keys"));
    // Without an origin no account reads as serving: refused, not a pass.
    assert!(matches!(
        CheckOptions::from_config(&config, Some("postgres://h/db"), false),
        Err(check_marks::CheckError::NoOrigin)
    ));
    config.server.origin = Some(ORIGIN.into());
    let options =
        CheckOptions::from_config(&config, Some("postgres://h/db"), true).expect("options");
    assert_eq!(options.choice, DatabaseChoice::Replica);
    assert_eq!(options.origin, ORIGIN);
    assert!(options.all);
    assert!(CheckOptions::from_config(&config, Some("not a url"), false).is_err());
}

/// Run `sql` on a connection that may write, as the service or a restore would.
async fn write(db: &TestDatabase, sql: &str) {
    let mut conn = sqlx::PgConnection::connect_with(db.options())
        .await
        .expect("connect");
    sqlx::raw_sql(sql).execute(&mut conn).await.expect("write");
}

#[tokio::test]
async fn test_check_marks_reports_an_account_the_database_lost() {
    let Some(fx) = fixture().await else { return };
    let (db, keys, dir) = (&fx.db, &fx.keys, fx.key_dir.path());
    create(db, keys, "kept", true).await;
    append(db, keys, "kept", &[1], true).await;
    // Enrolled and marked, then gone, as a restore from before its enrollment leaves it.
    let gone = create(db, keys, "gone", true).await;
    append(db, keys, "gone", &[1, 2], true).await;
    write(db, "DELETE FROM accounts WHERE id = 'gone'").await;

    let report = check_marks::run(&options(db, dir, false))
        .await
        .expect("check");
    assert!(report.accounts.is_empty());
    assert_eq!(report.missing.len(), 1);
    let missing = &report.missing[0];
    assert_eq!(missing.key, gone.service_key);
    assert_eq!(
        (missing.state, missing.generation, missing.mark_seq),
        (MarkState::AccountMissing, 1, 2)
    );
    assert_eq!(report.summary.accounts, 1);
    assert_eq!(report.summary.needs_attention, 1);
    assert_eq!(report.summary.states[&MarkState::AccountMissing], 1);
    assert!(report.needs_attention());
    let text = report.to_json_lines().expect("encode");
    let first: serde_json::Value =
        serde_json::from_str(text.lines().next().expect("a line")).expect("json");
    assert_eq!(
        first,
        serde_json::json!({
            "key": gone.service_key.as_str(), "state": "account_missing",
            "generation": 1, "mark_seq": 2
        })
    );
    fx.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_check_marks_keys_the_database_names_are_not_missing() {
    let Some(fx) = fixture().await else { return };
    let (db, keys, dir) = (&fx.db, &fx.keys, fx.key_dir.path());
    // An erasure under way: the account is gone, its key owed deleting, its files still
    // there.
    let erasing = create(db, keys, "erasing", true).await;
    append(db, keys, "erasing", &[1], true).await;
    write(
        db,
        &format!(
            "DELETE FROM accounts WHERE id = 'erasing'; \
             INSERT INTO erased_keys (key_id, account_id, erased_at_ms, reason) \
             VALUES ('{}', 'erasing', {T0}, 'erasure')",
            erasing.service_key
        ),
    )
    .await;
    // A pending key the account names, with a mark file, and a push key with none.
    let pending = create(db, keys, "pending", true).await;
    let next = keys.generate().await.expect("pending key");
    write_mark(
        dir,
        &NewAccount {
            service_key: next.id.clone(),
            ..pending
        },
        Mark {
            generation: 2,
            seq: 1,
            chain_hash: [1; 32],
        },
    );
    write(
        db,
        &format!(
            "UPDATE accounts SET pending_key = '{}' WHERE id = 'pending'",
            next.id
        ),
    )
    .await;
    keys.generate().await.expect("push key");

    let report = check_marks::run(&options(db, dir, true))
        .await
        .expect("check");
    assert!(report.missing.is_empty(), "{:?}", report.missing);
    assert_eq!(report.summary.states[&MarkState::AccountMissing], 0);

    // An account created after the accounts were read, before the mark files are: the
    // database names its key by the time its mark is listed.
    let view = KeyStoreView::open(dir).expect("view");
    let mut conn = open_read_only_with(db.options()).await.expect("connect");
    create(db, keys, "late", true).await;
    append(db, keys, "late", &[1], true).await;
    let missing = check_marks::missing_accounts(&mut conn, &view, &HashSet::new())
        .await
        .expect("missing");
    assert!(missing.is_empty(), "{missing:?}");
    fx.db.drop_database().await.expect("drop");
}
