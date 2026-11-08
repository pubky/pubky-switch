//! Change notifications through PostgreSQL: a committed change wakes the requests waiting
//! on its account, wherever they wait; a change that rolls back wakes nobody.
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used)]

use std::time::Duration;

use pubky_switch::{
    changes::{ChangeHub, ChangeListener},
    keys::{FileKeyStore, KeyStore},
    store::{NewAccount, testing::test_database},
};
use tokio::sync::{oneshot, watch};

const ID_A: &str = "6frao8w9ss5cn544qd64hynikrbr97ae1s5941c7ma5e1epifhgy";
const ID_B: &str = "7p4fn44qoshcwgfndz5grt7fyyz1eycqyduxdqe8o58of1byzodo";

async fn woken(receiver: &mut watch::Receiver<u64>, within: Duration) -> bool {
    tokio::time::timeout(within, receiver.changed())
        .await
        .is_ok()
}

#[tokio::test]
async fn test_changes_committed_change_wakes_its_account_only() {
    let Some(db) = test_database().await else {
        return;
    };
    let key_dir = tempfile::tempdir().expect("key dir");
    let keys = FileKeyStore::open(key_dir.path()).expect("keys");
    for id in [ID_A, ID_B] {
        let key = keys.generate().await.expect("key");
        db.store()
            .create_account(&NewAccount {
                id: id.into(),
                identity_key: [1; 32],
                generation: 1,
                service_key: key.id,
                created_at_ms: 0,
            })
            .await
            .expect("create");
    }
    let hub = ChangeHub::new();
    let listener = ChangeListener::connect(db.store()).await.expect("listen");
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(listener.run(hub.clone(), async {
        let _ = stopped.await;
    }));
    let mut waiting_a = hub.subscribe(ID_A);
    let mut waiting_b = hub.subscribe(ID_B);

    // A change to B wakes B, not A.
    let mut txn = db
        .store()
        .begin(ID_B)
        .await
        .expect("begin")
        .expect("account");
    txn.next_seq().expect("seq");
    txn.commit().await.expect("commit");
    assert!(woken(&mut waiting_b, Duration::from_secs(5)).await);
    assert!(!woken(&mut waiting_a, Duration::from_millis(200)).await);

    // A change that rolls back wakes nobody.
    let mut txn = db
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    txn.next_seq().expect("seq");
    txn.note_change();
    drop(txn);
    assert!(!woken(&mut waiting_a, Duration::from_millis(300)).await);

    // A request that changes the account's other state, without moving its position.
    let mut txn = db
        .store()
        .begin(ID_A)
        .await
        .expect("begin")
        .expect("account");
    txn.note_change();
    txn.commit().await.expect("commit");
    assert!(woken(&mut waiting_a, Duration::from_secs(5)).await);

    // A request that changes nothing, or only stamps a later time, wakes nobody.
    let begin = || async {
        db.store()
            .begin(ID_A)
            .await
            .expect("begin")
            .expect("account")
    };
    begin().await.commit().await.expect("commit");
    let mut txn = begin().await;
    txn.stamp(60_000);
    txn.commit().await.expect("commit");
    assert!(!woken(&mut waiting_a, Duration::from_millis(300)).await);
    assert_eq!(
        begin().await.head().stamped_time_ms,
        60_000,
        "the stamp itself is kept"
    );

    let _ = stop.send(());
    task.await.expect("listener stops");
    db.drop_database().await.expect("drop");
}
