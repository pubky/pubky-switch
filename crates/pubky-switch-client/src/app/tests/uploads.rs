//! What an app does with an `upload` transition in its feed (Switch wire 7.4.14): the
//! records and claims it lists are read again, and a divergent record is held so.

use std::collections::BTreeSet;
use std::sync::Arc;

use pubky_switch_core::enc::b64;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ops::{OpKind, sign_batch};
use pubky_switch_core::recovery::UploadChanges;
use pubky_switch_core::scopes::Permission;
use serde_json::{Value, json};

use super::moves::{
    ATTEMPT, CLAIM, Lost, NEXT, follow_loss, lost_world_with, third_recovering, upload_at_next,
    upload_beside,
};
use super::shared_flows::{ids, items, value};
use super::*;
use crate::app::{
    AppEvent, ClaimOp, ObligationDeadline, RECORD_REREADS_PER_READ, RecordTarget, UserConfirmed,
};
use crate::testing::Fault;

/// An app of another identity's apps, the uploader the tests name.
const PHONE: [u8; 16] = [9; 16];

fn store_of(store: &MemoryStore, key: &str) -> bool {
    let ns = crate::store::client_namespace(&app_keys("wallet").app_id_bytes());
    store.get(&ns, key.as_bytes()).unwrap().is_some()
}

fn marks(store: &MemoryStore, prefix: &str) -> usize {
    let ns = crate::store::client_namespace(&app_keys("wallet").app_id_bytes());
    store
        .scan(&ns, prefix.as_bytes(), None, 1000)
        .unwrap()
        .len()
}

fn changed(events: &[AppEvent], key: [u8; 32]) -> bool {
    events
        .iter()
        .any(|e| matches!(e, AppEvent::RecordChanged { key: k } if *k == key))
}

fn divergent(events: &[AppEvent], key: [u8; 32]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, AppEvent::RecordDivergent { key: k } if *k == key))
        .count()
}

/// The app after the provider loss, out of reconcile mode.
async fn followed(store: &Arc<MemoryStore>, record: bool) -> (Lost, App) {
    let lost = lost_world_with(
        Arc::clone(store) as Arc<dyn StateStore>,
        &Permission::ALL,
        record,
        false,
    )
    .await;
    *lost.protocol.collections.lock().unwrap() = vec![items()];
    let (mut app, _) = follow_loss(&lost, Arc::clone(store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    if app.reconcile_mode() {
        app.end_reconcile(UserConfirmed::new()).await.unwrap();
    }
    (lost, app)
}

/// A record of the lost generation the app doesn't hold, uploaded to the next switch with
/// no proof, as another device's app would (Switch wire 7.4.14): taken there. Its key.
async fn upload_unheld_record(lost: &Lost, app: &mut App) -> [u8; 32] {
    let target = RecordTarget::new(items(), b"uploaded");
    let (_, kind) = app
        .record_op(&target, Some(&value(&["u"])), vec![])
        .await
        .unwrap();
    let OpKind::RecordPut(put) = &kind else {
        unreachable!("a record op");
    };
    let key = put.key;
    let op = sign_batch(
        &app_keys("wallet"),
        &lost.w.alice.public(),
        Some(app_keys("wallet").app_id_bytes()),
        1,
        [98; 16],
        vec![(Vec::new(), kind)],
    )
    .unwrap();
    let body = json!({ "records": [{ "op": op[0].signed(), "cert": app.cert().signed() }] });
    let (status, answer) = upload_at_next(lost, &body.to_string());
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["result"]["records"], json!([b64(&key)]));
    key
}

#[tokio::test]
async fn test_upload_record_taken_is_read_from_the_transition() {
    // A record taken from an upload has no `record.put` at the next switch: the app learns of
    // it from the `upload` transition in its feed, and reads it with `GET /records`.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, false).await;
    let key = upload_unheld_record(&lost, &mut app).await;
    assert!(app.shared_record(&key).await.unwrap().is_none());
    let report = app.receive(None).await.unwrap();
    assert!(changed(&report.events, key), "{:?}", report.events);
    let record = app.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(record.content.value()), vec!["u"]);
    // No proof dates it: its version is the service's word.
    assert!(!record.authenticated);
    assert!(!record.divergent);
    // Read once: the mark went with the read.
    assert_eq!(marks(&store, "rcread/"), 0);
    let report = app.receive(None).await.unwrap();
    assert!(!changed(&report.events, key), "{:?}", report.events);
}

#[tokio::test]
async fn test_upload_record_reread_the_switch_may_answer_later_keeps_its_mark() {
    // A read again that fails for now keeps the mark, and the feed's read still succeeds;
    // the next read reads it.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, false).await;
    let key = upload_unheld_record(&lost, &mut app).await;
    lost.next.fail_next(Fault::Error {
        path: "/records/".into(),
        code: ErrorCode::Unavailable,
        current: Value::Null,
    });
    let report = app.receive(None).await.unwrap();
    assert!(!changed(&report.events, key), "{:?}", report.events);
    assert_eq!(marks(&store, "rcread/"), 1);
    let report = app.receive(None).await.unwrap();
    assert!(changed(&report.events, key), "{:?}", report.events);
    assert_eq!(marks(&store, "rcread/"), 0);
}

#[tokio::test]
async fn test_upload_record_the_switch_refuses_for_good_is_unmarked() {
    // A record the switch refuses to read for good, such as one whose read scope the app
    // lacks (`403`), is unmarked: reading it again would be refused again.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, false).await;
    let key = upload_unheld_record(&lost, &mut app).await;
    lost.next.fail_next(Fault::Error {
        path: "/records/".into(),
        code: ErrorCode::PermissionMissing,
        current: Value::Null,
    });
    let report = app.receive(None).await.unwrap();
    assert!(!changed(&report.events, key), "{:?}", report.events);
    assert_eq!(marks(&store, "rcread/"), 0);
    assert!(app.shared_record(&key).await.unwrap().is_none());
}

#[tokio::test]
async fn test_upload_records_read_again_are_bounded_per_read() {
    // At most `RECORD_REREADS_PER_READ` records are read again in one read, the oldest
    // marks first; the rest stay marked for the next. Keys the switch doesn't know (`404`)
    // are unmarked.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, false).await;
    let keys: BTreeSet<[u8; 32]> = (0..=RECORD_REREADS_PER_READ)
        .map(|i| [u8::try_from(i).unwrap() + 100; 32])
        .collect();
    let changes = UploadChanges {
        divergent: keys,
        ..UploadChanges::default()
    };
    lost.next.chain_upload(PHONE, changes.to_value()).unwrap();
    app.receive(None).await.unwrap();
    assert_eq!(marks(&store, "rcread/"), 1);
    app.receive(None).await.unwrap();
    assert_eq!(marks(&store, "rcread/"), 0);
}

#[tokio::test]
async fn test_upload_transition_that_doesnt_read_marks_nothing() {
    // Changes that don't read as the wire's (7.4.14) mark nothing, and the read goes on.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, false).await;
    lost.next
        .chain_upload(PHONE, json!({ "records": [b64(&[1; 32])] }))
        .unwrap();
    app.receive(None).await.unwrap();
    assert_eq!(marks(&store, "rcread/"), 0);
    assert!(app.alarm().is_none(), "{:?}", app.alarm());
}

/// A fork of the record the app uploaded at the loss, built on the same version in another
/// batch: kept divergent at the next switch (Switch wire 7.4.14).
fn upload_fork(lost: &Lost, batch: [u8; 16]) -> [u8; 32] {
    let next = lost.next.lock();
    let (key, taken) = next.shared.records.iter().next().expect("the record");
    let key = *key;
    let op = pubky_switch_core::ops::SignedOp::peek(&taken.op).unwrap();
    let fork = sign_batch(
        &app_keys("wallet"),
        &lost.w.alice.public(),
        Some(app_keys("wallet").app_id_bytes()),
        op.body().generation,
        batch,
        vec![(Vec::new(), op.body().kind.clone())],
    )
    .unwrap();
    let cert = taken.cert.clone().unwrap();
    drop(next);
    let body = json!({ "records": [{ "op": fork[0].signed(), "cert": cert }] });
    let (status, answer) = upload_at_next(lost, &body.to_string());
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["result"]["divergent"], json!([b64(&key)]));
    key
}

#[tokio::test]
async fn test_upload_divergent_record_is_held_divergent_until_a_newer_write() {
    // Uploads that conflict with a record's current write: the app reads the record again,
    // keeps its write, and holds it divergent, raising `RecordDivergent` once. A newer write
    // at the switch clears it (Switch wire 7.4.14).
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, true).await;
    let key = upload_fork(&lost, [99; 16]);
    let before = app.shared_record(&key).await.unwrap().unwrap();
    assert!(!before.divergent);
    let report = app.receive(None).await.unwrap();
    assert_eq!(divergent(&report.events, key), 1, "{:?}", report.events);
    let held = app.shared_record(&key).await.unwrap().unwrap();
    assert!(held.divergent);
    assert_eq!(held.content, before.content);
    // Another divergent upload: read again, still divergent, no event again.
    upload_fork(&lost, [97; 16]);
    let report = app.receive(None).await.unwrap();
    assert_eq!(divergent(&report.events, key), 0, "{:?}", report.events);
    assert!(app.shared_record(&key).await.unwrap().unwrap().divergent);
    // The app's own newer write clears it, at the switch and in the app.
    let target = RecordTarget::new(items(), b"key");
    app.put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    assert!(!lost.next.lock().shared.divergent.contains_key(&key));
    assert!(!app.shared_record(&key).await.unwrap().unwrap().divergent);
    let report = app.receive(None).await.unwrap();
    assert_eq!(divergent(&report.events, key), 0, "{:?}", report.events);
    assert!(!app.shared_record(&key).await.unwrap().unwrap().divergent);
}

#[tokio::test]
async fn test_upload_divergent_record_is_cleared_by_a_newer_write_in_the_feed() {
    // Another app's newer write at the switch, read from the feed, clears the divergent
    // uploads there, and in the app.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, true).await;
    let key = upload_fork(&lost, [99; 16]);
    app.receive(None).await.unwrap();
    assert!(app.shared_record(&key).await.unwrap().unwrap().divergent);
    // A second device of the app writes the record at the next switch.
    let target = RecordTarget::new(items(), b"key");
    let (conditions, kind) = app
        .record_op(&target, Some(&value(&["c"])), vec![])
        .await
        .unwrap();
    assert!(conditions.is_empty());
    lost.next.app_op(&app_keys("wallet"), kind).unwrap();
    assert!(!lost.next.lock().shared.divergent.contains_key(&key));
    let report = app.receive(None).await.unwrap();
    assert!(changed(&report.events, key), "{:?}", report.events);
    let held = app.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["c"]);
    assert!(!held.divergent);
}

#[tokio::test]
async fn test_upload_divergent_record_flag_goes_at_a_provider_loss() {
    // The lost service's divergent uploads aren't the next one's: the commit that starts a
    // provider loss removes the flags.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, true).await;
    let key = upload_fork(&lost, [99; 16]);
    app.receive(None).await.unwrap();
    assert!(store_of(&store, &format!("rcdiv/{}", b64(&key))));
    drop(app);
    // The signer declares generation 2 lost, at a third service.
    lost.router.remove(NEXT);
    let _third = third_recovering(&lost.w, &lost.router, 3, 2);
    let (app, _) = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert_eq!(app.cursor().generation, 3);
    assert_eq!(marks(&store, "rcdiv/"), 0);
    assert!(!app.shared_record(&key).await.unwrap().unwrap().divergent);
}

#[tokio::test]
async fn test_upload_claim_listed_is_read_again() {
    // A claim an upload changed has no entry at the switch: the app reads it again after
    // the transition, raises `ClaimChanged`, and holds it divergent, so doubtful.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, false).await;
    app.write_claim(
        ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None),
        vec![],
        ObligationDeadline::NoDeadline,
    )
    .await
    .unwrap();
    app.receive(None).await.unwrap();
    assert!(!app.claim_doubt(&CLAIM).await.unwrap().unwrap().divergent);
    upload_beside(&lost.next);
    let changes = UploadChanges {
        divergent_claims: [CLAIM].into(),
        ..UploadChanges::default()
    };
    lost.next.chain_upload(PHONE, changes.to_value()).unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::ClaimChanged { claim_key } if *claim_key == CLAIM)),
        "{:?}",
        report.events
    );
    assert!(app.claim_doubt(&CLAIM).await.unwrap().unwrap().divergent);
    assert_eq!(marks(&store, "clread/"), 0);
}

#[tokio::test]
async fn test_upload_claims_unmarked_without_claims_read() {
    // An app without `claims.read` can't read claims, and marks none an upload lists; it
    // still reads the records.
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world_with(
        Arc::clone(&store) as Arc<dyn StateStore>,
        &[Permission::ConversationAdd],
        false,
        false,
    )
    .await;
    let (mut app, _) = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap();
    let changes = UploadChanges {
        claims: [CLAIM].into(),
        records: [[7; 32]].into(),
        ..UploadChanges::default()
    };
    // The record's read again fails for now, so its mark stays to be seen beside the
    // claim's, which was never written.
    lost.next.fail_next(Fault::Error {
        path: "/records/".into(),
        code: ErrorCode::Unavailable,
        current: Value::Null,
    });
    lost.next.chain_upload(PHONE, changes.to_value()).unwrap();
    app.receive(None).await.unwrap();
    assert_eq!(marks(&store, "clread/"), 0);
    assert_eq!(marks(&store, "rcread/"), 1);
}
