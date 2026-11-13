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
    AppEvent, ClaimOp, MAX_RECORD_MARKS, ObligationDeadline, RECORD_REREADS_PER_READ, RecordTarget,
    UserConfirmed,
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
        .filter(|e| matches!(e, AppEvent::RecordDivergent { key: k, .. } if *k == key))
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
async fn test_upload_divergent_record_is_cleared_by_a_view_that_isnt() {
    // A view that shows the record no longer divergent clears the flag, with no event.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, true).await;
    let key = upload_fork(&lost, [99; 16]);
    app.receive(None).await.unwrap();
    assert!(app.shared_record(&key).await.unwrap().unwrap().divergent);
    lost.next.lock().shared.divergent.remove(&key);
    let changes = UploadChanges {
        records: [key].into(),
        ..UploadChanges::default()
    };
    lost.next.chain_upload(PHONE, changes.to_value()).unwrap();
    let report = app.receive(None).await.unwrap();
    assert_eq!(divergent(&report.events, key), 0, "{:?}", report.events);
    assert!(!app.shared_record(&key).await.unwrap().unwrap().divergent);
}

#[tokio::test]
async fn test_upload_divergent_record_stays_through_the_write_it_conflicts_with() {
    // An upload newer than the version a write at the switch built on conflicts with that
    // write. The feed then shows the write, which the app holds already from a read: it
    // clears nothing, since the uploads came after it.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, true).await;
    let (key, kind, version) = {
        let next = lost.next.lock();
        let (key, taken) = next.shared.records.iter().next().expect("the record");
        let op = pubky_switch_core::ops::SignedOp::peek(&taken.op).unwrap();
        (*key, op.body().kind.clone(), taken.state.version)
    };
    // A second device of the app writes the record at the next switch; the app reads it.
    let target = RecordTarget::new(items(), b"key");
    let (_, write) = app
        .record_op(&target, Some(&value(&["c"])), vec![])
        .await
        .unwrap();
    lost.next.app_op(&app_keys("wallet"), write).unwrap();
    let read = app.read_record_fresh(&target).await.unwrap();
    assert!(matches!(read, crate::app::RecordRead::Fresh(_)), "{read:?}");
    // The lost generation's next write, built on the version uploaded: newer than it.
    let OpKind::RecordPut(mut put) = kind else {
        unreachable!("a record op");
    };
    put.expected_version = version;
    put.id_inputs = None;
    let op = sign_batch(
        &app_keys("wallet"),
        &lost.w.alice.public(),
        Some(app_keys("wallet").app_id_bytes()),
        1,
        [96; 16],
        vec![(Vec::new(), OpKind::RecordPut(put))],
    )
    .unwrap();
    let body = json!({ "records": [{ "op": op[0].signed(), "cert": app.cert().signed() }] });
    let (status, answer) = upload_at_next(&lost, &body.to_string());
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["result"]["divergent"], json!([b64(&key)]));
    // Read before the feed shows the write: divergent, its event queued for the next read's
    // report.
    app.read_record_fresh(&target).await.unwrap();
    assert!(app.shared_record(&key).await.unwrap().unwrap().divergent);
    let report = app.receive(None).await.unwrap();
    // The fresh read's event only: the feed's write didn't clear the flag for the reread
    // to raise it again.
    assert_eq!(divergent(&report.events, key), 1, "{:?}", report.events);
    assert!(app.shared_record(&key).await.unwrap().unwrap().divergent);
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
    let third = third_recovering(&lost.w, &lost.router, 3, 2);
    // The third switch's view would clear the flag too: its read fails for now, so only the
    // loss can.
    third.fail_next(Fault::Error {
        path: "/records/".into(),
        code: ErrorCode::Unavailable,
        current: Value::Null,
    });
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

#[tokio::test]
async fn test_upload_claim_the_app_doesnt_hold_isnt_marked() {
    // A claim rebuilt at the next switch from another app's upload, which this app (with
    // `claims.read`) never held: the transition marks nothing for it, and nothing reads it
    // (Switch wire 7.4.14); the app reads it when it first attempts on it.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, false).await;
    assert!(app.claim_doubt(&CLAIM).await.unwrap().is_none());
    {
        let mut next = lost.next.lock();
        let entry = pubky_switch_core::recovery::UploadedEntry {
            entry: pubky_switch_core::claims::ClaimEntry {
                claim_key: CLAIM,
                attempt_id: [77; 16],
                expected_step: 0,
                kind: pubky_switch_core::claims::EntryKind::Attempt {
                    orphan_after: 60,
                    deadline: None,
                },
            },
            writer: PHONE,
            proof: None,
        };
        let merge =
            pubky_switch_core::recovery::merge_upload_claim(None, None, &[entry], START, 64);
        assert!(merge.changed, "{merge:?}");
        next.shared.claims.insert(CLAIM, merge.claim.unwrap());
    }
    // With it, more claims the app doesn't hold than one read reads again: a mark for any
    // of them would outlast the read.
    let claims: BTreeSet<[u8; 32]> = std::iter::once(CLAIM)
        .chain(
            (0..crate::app::CLAIM_REREADS_PER_READ).map(|i| [u8::try_from(i).unwrap() + 100; 32]),
        )
        .collect();
    let changes = UploadChanges {
        claims,
        ..UploadChanges::default()
    };
    lost.next.chain_upload(PHONE, changes.to_value()).unwrap();
    // A pending fault on the claim read shows whether the claim was asked for at all.
    lost.next.fail_next(Fault::Error {
        path: "/claims/".into(),
        code: ErrorCode::Unavailable,
        current: Value::Null,
    });
    app.receive(None).await.unwrap();
    assert_eq!(lost.next.lock().faults.len(), 1, "the claim was read");
    assert_eq!(marks(&store, "clread/"), 0);
}

#[tokio::test]
async fn test_upload_record_reread_refused_for_an_expired_certificate_keeps_its_mark() {
    // `403 cert_expired` is `Retry::No`, but a renewal ends it: the record is still owed a
    // read again, unlike one whose read scope the app lacks.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, false).await;
    upload_unheld_record(&lost, &mut app).await;
    lost.next.fail_next(Fault::Error {
        path: "/records/".into(),
        code: ErrorCode::CertExpired,
        current: Value::Null,
    });
    app.receive(None).await.unwrap();
    assert_eq!(
        marks(&store, "rcread/"),
        1,
        "the mark went at a cert_expired"
    );
}

#[tokio::test]
async fn test_upload_divergent_flag_of_a_record_the_app_doesnt_take_isnt_kept() {
    // A record the app doesn't take (a collection its protocol doesn't list), whose view
    // shows divergent: the app holds no record there, yet the read again keeps
    // `rcdiv/<key>` and raises `RecordDivergent` for it; nothing reads that key again to
    // clear it.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, false).await;
    let key = upload_unheld_record(&lost, &mut app).await;
    *lost.protocol.collections.lock().unwrap() = vec![];
    lost.next.lock().shared.divergent.insert(key, vec![[1; 32]]);
    let report = app.receive(None).await.unwrap();
    assert!(app.shared_record(&key).await.unwrap().is_none());
    assert_eq!(divergent(&report.events, key), 0, "{:?}", report.events);
    assert!(!store_of(&store, &format!("rcdiv/{}", b64(&key))));
}

#[tokio::test]
async fn test_upload_records_read_again_go_oldest_mark_first() {
    // Marks of an earlier transition go before a later one's, whatever their keys' order:
    // the later transition's one key sorts first, and is left for the next read.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, false).await;
    let first: BTreeSet<[u8; 32]> = (0..RECORD_REREADS_PER_READ)
        .map(|i| [u8::try_from(i).unwrap() + 100; 32])
        .collect();
    let changes = UploadChanges {
        records: first,
        ..UploadChanges::default()
    };
    // The first read fails for now, so all its marks stay.
    lost.next.fail_next(Fault::Error {
        path: "/records/".into(),
        code: ErrorCode::Unavailable,
        current: Value::Null,
    });
    lost.next.chain_upload(PHONE, changes.to_value()).unwrap();
    app.receive(None).await.unwrap();
    assert_eq!(marks(&store, "rcread/"), RECORD_REREADS_PER_READ);
    lost.w.clock.advance_ms(1000);
    let later = UploadChanges {
        records: [[0; 32]].into(),
        ..UploadChanges::default()
    };
    lost.next.chain_upload(PHONE, later.to_value()).unwrap();
    app.receive(None).await.unwrap();
    assert!(store_of(&store, &format!("rcread/{}", b64(&[0; 32]))));
    assert_eq!(marks(&store, "rcread/"), 1);
}

#[tokio::test]
async fn test_upload_changed_claim_listed_is_read_again() {
    // A claim the upload changed without making it divergent (`claims`, not
    // `divergent_claims`) is read again too.
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
    upload_beside(&lost.next);
    let changes = UploadChanges {
        claims: [CLAIM].into(),
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
}

#[tokio::test]
async fn test_upload_record_view_of_another_key_isnt_taken() {
    // A switch that answers `GET /records/{key}` with a view of another key: nothing is
    // taken or flagged under either key, and the mark goes.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, false).await;
    let key = upload_unheld_record(&lost, &mut app).await;
    let other = [9; 32];
    lost.next.lock().shared.divergent.insert(key, vec![[1; 32]]);
    lost.next.fail_next(Fault::Replace {
        path: "/records/".into(),
        member: "key".into(),
        value: json!(b64(&other)),
    });
    let report = app.receive(None).await.unwrap();
    assert!(app.shared_record(&key).await.unwrap().is_none());
    assert!(app.shared_record(&other).await.unwrap().is_none());
    assert!(!changed(&report.events, key) && !changed(&report.events, other));
    assert_eq!(divergent(&report.events, other), 0, "{:?}", report.events);
    assert_eq!(marks(&store, "rcdiv/"), 0);
    assert_eq!(marks(&store, "rcread/"), 0);
}

#[tokio::test]
async fn test_upload_divergent_flag_follows_the_last_note_in_one_commit() {
    // Notes in one commit read the commit's own writes: a clear then a set leaves the record
    // divergent, as the later view says, and tells the app again.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, true).await;
    let key = *lost
        .next
        .lock()
        .shared
        .records
        .keys()
        .next()
        .expect("the record");
    let mut tx = app.tx().unwrap();
    app.note_view_divergence(&key, true, &mut tx).await.unwrap();
    app.commit(tx).await.unwrap();
    assert!(app.shared_record(&key).await.unwrap().unwrap().divergent);
    let mut tx = app.tx().unwrap();
    app.note_divergent(&key, false, &mut tx).await.unwrap();
    app.note_view_divergence(&key, true, &mut tx).await.unwrap();
    app.commit(tx).await.unwrap();
    assert!(app.shared_record(&key).await.unwrap().unwrap().divergent);
    let report = app.receive(None).await.unwrap();
    assert_eq!(divergent(&report.events, key), 2, "{:?}", report.events);
}

#[tokio::test]
async fn test_upload_records_past_the_mark_cap_owe_a_listing() {
    // Uploads that would leave more than `MAX_RECORD_MARKS` records marked, counting those
    // a commit marked before, drop every record mark and owe a listing instead, which the
    // read makes before it hands any later entry over.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, false).await;
    let keys = |from: usize| -> BTreeSet<[u8; 32]> {
        (from..from + MAX_RECORD_MARKS / 2 + 1)
            .map(|i| {
                let mut key = [0; 32];
                key[..8].copy_from_slice(&u64::try_from(i).unwrap().to_be_bytes());
                key
            })
            .collect()
    };
    for from in [0, MAX_RECORD_MARKS] {
        let changes = UploadChanges {
            records: keys(from),
            ..UploadChanges::default()
        };
        lost.next.chain_upload(PHONE, changes.to_value()).unwrap();
    }
    let listings = lost.next.lock().shared.listings;
    app.receive(None).await.unwrap();
    assert_eq!(marks(&store, "rcread/"), 0);
    assert!(lost.next.lock().shared.listings > listings, "listed");
    assert!(!store_of(&store, "list_due"));
}

#[tokio::test]
async fn test_upload_records_up_to_the_mark_cap_are_marked() {
    // Up to `MAX_RECORD_MARKS`, the records are marked, and no listing is owed.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, false).await;
    let keys: BTreeSet<[u8; 32]> = (0..MAX_RECORD_MARKS)
        .map(|i| {
            let mut key = [0; 32];
            key[..8].copy_from_slice(&u64::try_from(i).unwrap().to_be_bytes());
            key
        })
        .collect();
    let changes = UploadChanges {
        records: keys,
        ..UploadChanges::default()
    };
    lost.next.chain_upload(PHONE, changes.to_value()).unwrap();
    let listings = lost.next.lock().shared.listings;
    app.receive(None).await.unwrap();
    assert_eq!(
        marks(&store, "rcread/"),
        MAX_RECORD_MARKS - RECORD_REREADS_PER_READ
    );
    assert_eq!(lost.next.lock().shared.listings, listings, "no listing");
}

#[tokio::test]
async fn test_upload_divergent_flag_reads_in_the_receive_context() {
    // The protocol's receive context reads the flag too (`ReceiveContext::record_at`).
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, true).await;
    let key = upload_fork(&lost, [99; 16]);
    app.receive(None).await.unwrap();
    let shown = |app: &App| {
        let store = Arc::clone(app.env.store.store());
        let cx = crate::app::ReceiveContext::new(
            &app.state,
            app.protocol.as_ref(),
            store.as_ref(),
            &app.ns,
            false,
            &[],
            &[],
            &[],
        );
        cx.record_at(&key).unwrap().unwrap().divergent
    };
    assert!(shown(&app));
    let target = RecordTarget::new(items(), b"key");
    app.put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    assert!(!shown(&app));
}

#[tokio::test]
async fn test_upload_record_held_is_read_again_under_its_own_collection() {
    // A record the app holds, of a collection its protocol doesn't list, is read again as
    // its own collection: a newer upload of it is taken.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, true).await;
    *lost.protocol.collections.lock().unwrap() = vec![];
    let (key, kind, version) = {
        let next = lost.next.lock();
        let (key, taken) = next.shared.records.iter().next().expect("the record");
        let op = pubky_switch_core::ops::SignedOp::peek(&taken.op).unwrap();
        (*key, op.body().kind.clone(), taken.state.version)
    };
    // The lost generation's next write, built on the version uploaded: it replaces it.
    let OpKind::RecordPut(mut put) = kind else {
        unreachable!("a record op");
    };
    put.expected_version = version;
    put.id_inputs = None;
    let op = sign_batch(
        &app_keys("wallet"),
        &lost.w.alice.public(),
        Some(app_keys("wallet").app_id_bytes()),
        1,
        [95; 16],
        vec![(Vec::new(), OpKind::RecordPut(put))],
    )
    .unwrap();
    let body = json!({ "records": [{ "op": op[0].signed(), "cert": app.cert().signed() }] });
    let (status, answer) = upload_at_next(&lost, &body.to_string());
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["result"]["records"], json!([b64(&key)]));
    let report = app.receive(None).await.unwrap();
    assert!(changed(&report.events, key), "{:?}", report.events);
}

#[tokio::test]
async fn test_record_read_answered_with_another_records_view_flags_neither() {
    // A read of one record answered with its divergent view under another key the app
    // holds: the view says nothing of either record, so neither is held divergent.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, true).await;
    let held = *lost
        .next
        .lock()
        .shared
        .records
        .keys()
        .next()
        .expect("the record");
    let key = upload_unheld_record(&lost, &mut app).await;
    lost.next.lock().shared.divergent.insert(key, vec![[1; 32]]);
    lost.next.fail_next(Fault::Replace {
        path: "/records/".into(),
        member: "key".into(),
        value: json!(b64(&held)),
    });
    // The write is judged by its own operation, whose key is the one asked for.
    let read = app
        .read_record_fresh(&RecordTarget::new(items(), b"uploaded"))
        .await
        .unwrap();
    assert!(matches!(read, crate::app::RecordRead::Fresh(ref r) if r.key == key));
    assert!(!app.shared_record(&key).await.unwrap().unwrap().divergent);
    assert!(!app.shared_record(&held).await.unwrap().unwrap().divergent);
    assert_eq!(marks(&store, "rcdiv/"), 0);
}

#[tokio::test]
async fn test_upload_feed_write_judged_by_its_view_holds_the_views_divergence() {
    // A feed write by a writer whose certificate the app can't find (it never saw the
    // phone's `app.put`, and the directory doesn't show it) is judged by the record's view:
    // the view's `divergent` is the switch's latest word, so the record is held divergent
    // although the write is newer, and the app is told once.
    let store = Arc::new(MemoryStore::new());
    let w = World::new();
    let router = super::moves::Router::of(&w);
    let phone = w.other_app("phone", &Permission::ALL);
    let protocol = Arc::new(super::moves::LossProtocol::default());
    *protocol.collections.lock().unwrap() = vec![items()];
    let mut app = super::moves::join_on(
        &w,
        &router,
        Arc::clone(&store) as Arc<dyn StateStore>,
        Arc::clone(&protocol) as Arc<dyn crate::app::Protocol>,
        &Permission::ALL,
    )
    .await;
    // The listing owed since joining goes first, before the write, so only the feed meets it.
    w.switch
        .lock()
        .apps
        .get_mut(&phone.app_id_bytes())
        .unwrap()
        .record = None;
    app.receive(None).await.unwrap();
    let listings = w.switch.lock().shared.listings;
    let target = RecordTarget::new(items(), b"the phone's");
    let (_, kind) = app
        .record_op(&target, Some(&value(&["p"])), vec![])
        .await
        .unwrap();
    let OpKind::RecordPut(put) = &kind else {
        unreachable!("a record op");
    };
    let key = put.key;
    w.switch.app_op(&phone, kind).unwrap();
    w.switch.lock().shared.divergent.insert(key, vec![[1; 32]]);
    let report = app.receive(None).await.unwrap();
    assert_eq!(w.switch.lock().shared.listings, listings, "no listing");
    let held = app.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["p"]);
    assert!(held.divergent, "the view said divergent");
    assert_eq!(divergent(&report.events, key), 1, "{:?}", report.events);
}

#[tokio::test]
async fn test_upload_records_past_the_mark_cap_still_read_a_held_record_no_listing_covers() {
    // A record the app holds of a collection its protocol doesn't list, which an upload
    // replaced: read again under its own collection when marked. Past `MAX_RECORD_MARKS`
    // the marks give way to a listing, which reads only the protocol's collections.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, true).await;
    *lost.protocol.collections.lock().unwrap() = vec![];
    let (key, kind, version) = {
        let next = lost.next.lock();
        let (key, taken) = next.shared.records.iter().next().expect("the record");
        let op = pubky_switch_core::ops::SignedOp::peek(&taken.op).unwrap();
        (*key, op.body().kind.clone(), taken.state.version)
    };
    let OpKind::RecordPut(mut put) = kind else {
        unreachable!("a record op");
    };
    put.expected_version = version;
    put.id_inputs = None;
    let op = sign_batch(
        &app_keys("wallet"),
        &lost.w.alice.public(),
        Some(app_keys("wallet").app_id_bytes()),
        1,
        [95; 16],
        vec![(Vec::new(), OpKind::RecordPut(put))],
    )
    .unwrap();
    let body = json!({ "records": [{ "op": op[0].signed(), "cert": app.cert().signed() }] });
    let (status, answer) = upload_at_next(&lost, &body.to_string());
    assert_eq!(status, 200, "{answer}");
    // Another upload, in the same read, lists more records than the marks hold.
    let many: BTreeSet<[u8; 32]> = (0..MAX_RECORD_MARKS)
        .map(|i| {
            let mut key = [1; 32];
            key[..8].copy_from_slice(&u64::try_from(i).unwrap().to_be_bytes());
            key
        })
        .collect();
    let changes = UploadChanges {
        records: many,
        ..UploadChanges::default()
    };
    lost.next.chain_upload(PHONE, changes.to_value()).unwrap();
    let first = app.receive(None).await.unwrap();
    let second = app.receive(None).await.unwrap();
    assert!(
        changed(&first.events, key) || changed(&second.events, key),
        "the held record's newer upload was never read"
    );
}

#[tokio::test]
async fn test_upload_claim_kept_earlier_in_the_same_commit_is_marked() {
    // A claim the app first keeps from an entry on the same feed page as the transition,
    // before it: held only in the open commit, it is marked and read again, so its view
    // isn't the one from before the upload.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, false).await;
    assert!(app.claim_doubt(&CLAIM).await.unwrap().is_none());
    // A second device of the app attempts at the next switch; then an upload beside it.
    let attempt = ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None);
    lost.next
        .app_op(&app_keys("wallet"), attempt.kind())
        .unwrap();
    upload_beside(&lost.next);
    let changes = UploadChanges {
        divergent_claims: [CLAIM].into(),
        ..UploadChanges::default()
    };
    lost.next.chain_upload(PHONE, changes.to_value()).unwrap();
    app.receive(None).await.unwrap();
    assert!(app.claim_doubt(&CLAIM).await.unwrap().unwrap().divergent);
    assert_eq!(marks(&store, "clread/"), 0);
}

#[tokio::test]
async fn test_upload_past_the_mark_cap_lists_before_a_later_entry() {
    // The listing an upload past the mark cap owes comes before any later entry of the read
    // is handed to the protocol, as a `missed` item's does (Switch spec 8.2): a listing that
    // fails hands nothing over, and the next read lists, then hands the entry over once.
    let store = Arc::new(MemoryStore::new());
    let (lost, mut app) = followed(&store, false).await;
    let changes = UploadChanges {
        records: (0..=MAX_RECORD_MARKS)
            .map(|i| {
                let mut key = [0; 32];
                key[..8].copy_from_slice(&u64::try_from(i).unwrap().to_be_bytes());
                key
            })
            .collect(),
        ..UploadChanges::default()
    };
    lost.next.chain_upload(PHONE, changes.to_value()).unwrap();
    let seq = super::moves::note_at(&lost.w, &lost.next, app.app_id(), "after the upload");
    let handed = |lost: &Lost| {
        lost.protocol
            .sample
            .received
            .lock()
            .unwrap()
            .iter()
            .filter(|(s, _, _)| *s == seq)
            .count()
    };
    lost.next.fail_next(Fault::Unreachable {
        path: "records?collection".into(),
        after: 0,
    });
    app.receive(None).await.unwrap_err();
    assert_eq!(handed(&lost), 0);
    assert!(store_of(&store, "list_due"));
    assert!(app.cursor().seq < seq);
    let listings = lost.next.lock().shared.listings;
    app.receive(None).await.unwrap();
    assert!(lost.next.lock().shared.listings > listings, "listed");
    assert_eq!(handed(&lost), 1);
    assert!(app.cursor().seq >= seq);
}

/// The wallet joined on `store` with the items protocol, its owed listing made, holding a
/// record it wrote; the record's key.
async fn holding_a_record(
    w: &World,
    router: &super::moves::Router,
    store: &Arc<MemoryStore>,
    protocol: &Arc<super::moves::LossProtocol>,
) -> (App, [u8; 32]) {
    *protocol.collections.lock().unwrap() = vec![items()];
    let mut app = super::moves::join_on(
        w,
        router,
        Arc::clone(store) as Arc<dyn StateStore>,
        Arc::clone(protocol) as Arc<dyn crate::app::Protocol>,
        &Permission::ALL,
    )
    .await;
    app.receive(None).await.unwrap();
    let target = RecordTarget::new(items(), b"n1");
    app.put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = app.record_key(&target).unwrap();
    app.receive(None).await.unwrap();
    (app, key)
}

fn divergent_ids(events: &[AppEvent], key: [u8; 32]) -> Vec<crate::app::EventId> {
    events
        .iter()
        .filter_map(|e| match e {
            AppEvent::RecordDivergent { id, key: k } if *k == key => Some(*id),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn test_upload_divergence_marked_and_cleared_in_one_commit_is_told_after_a_restart() {
    // The mark set and removed again in one commit, as when a newer write later in the same
    // read clears it, and the app stops before its host takes the report: the duty event
    // stays, and the next load delivers it.
    let store = Arc::new(MemoryStore::new());
    let w = World::new();
    let router = super::moves::Router::of(&w);
    let protocol = Arc::new(super::moves::LossProtocol::default());
    let (mut app, key) = holding_a_record(&w, &router, &store, &protocol).await;
    let id = app.app_id();
    let mut tx = app.tx().unwrap();
    app.note_divergent(&key, true, &mut tx).await.unwrap();
    app.note_divergent(&key, false, &mut tx).await.unwrap();
    app.commit(tx).await.unwrap();
    assert_eq!(marks(&store, "rcdiv/"), 0);
    assert!(!app.shared_record(&key).await.unwrap().unwrap().divergent);
    drop(app);
    let mut app = App::load(
        router.env(&w, Arc::clone(&store) as Arc<dyn StateStore>),
        Arc::clone(&protocol) as Arc<dyn crate::app::Protocol>,
        World::config(),
        id,
    )
    .await
    .unwrap();
    let events = app.take_events();
    assert_eq!(divergent_ids(&events, key).len(), 1, "{events:?}");
    assert!(events.iter().all(AppEvent::is_duty), "{events:?}");
}

#[tokio::test]
async fn test_upload_divergence_is_delivered_until_acknowledged_after_its_flag_clears() {
    // The scripted switch makes the held record divergent; the read raises the duty event.
    // A newer write clears the flag. The host never acknowledged: every load delivers the
    // event again, with its ID, until the host acknowledges it.
    let store = Arc::new(MemoryStore::new());
    let w = World::new();
    let router = super::moves::Router::of(&w);
    let protocol = Arc::new(super::moves::LossProtocol::default());
    let (mut app, key) = holding_a_record(&w, &router, &store, &protocol).await;
    let id = app.app_id();
    w.switch
        .make_divergent(app_keys("phone").app_id_bytes(), key, [1; 32])
        .unwrap();
    let report = app.receive(None).await.unwrap();
    let first = divergent_ids(&report.events, key);
    assert_eq!(first.len(), 1, "{:?}", report.events);
    assert!(app.shared_record(&key).await.unwrap().unwrap().divergent);
    // Once only: a read that sees it still divergent raises nothing more.
    let report = app.receive(None).await.unwrap();
    assert!(divergent_ids(&report.events, key).is_empty());
    let target = RecordTarget::new(items(), b"n1");
    app.put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    assert!(!app.shared_record(&key).await.unwrap().unwrap().divergent);
    let load = || {
        App::load(
            router.env(&w, Arc::clone(&store) as Arc<dyn StateStore>),
            Arc::clone(&protocol) as Arc<dyn crate::app::Protocol>,
            World::config(),
            id,
        )
    };
    drop(app);
    for _ in 0..2 {
        let mut app = load().await.unwrap();
        assert_eq!(divergent_ids(&app.take_events(), key), first);
    }
    let mut app = load().await.unwrap();
    assert_eq!(divergent_ids(&app.take_events(), key), first);
    app.ack_events(first[0]).await.unwrap();
    let mut app = load().await.unwrap();
    assert!(divergent_ids(&app.take_events(), key).is_empty());
}

#[tokio::test]
async fn test_upload_divergence_is_told_again_after_a_restore_from_a_backup() {
    // A backup carries neither the mark nor the duty event: the listing the restore owes
    // reads the record again, and a view still divergent raises the event again, under an
    // ID of the new store.
    let store = Arc::new(MemoryStore::new());
    let w = World::new();
    let router = super::moves::Router::of(&w);
    let protocol = Arc::new(super::moves::LossProtocol::default());
    let (mut app, key) = holding_a_record(&w, &router, &store, &protocol).await;
    w.switch
        .make_divergent(app_keys("phone").app_id_bytes(), key, [1; 32])
        .unwrap();
    let report = app.receive(None).await.unwrap();
    let first = divergent_ids(&report.events, key);
    assert_eq!(first.len(), 1, "{:?}", report.events);
    let backup = app.backup().await.unwrap();
    drop(app);
    let fresh = Arc::new(MemoryStore::new());
    let mut restored = App::restore(
        router.env(&w, Arc::clone(&fresh) as Arc<dyn StateStore>),
        Arc::clone(&protocol) as Arc<dyn crate::app::Protocol>,
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    let mut told = divergent_ids(&restored.take_events(), key);
    for _ in 0..4 {
        let report = restored.receive(None).await.unwrap();
        told.extend(divergent_ids(&report.events, key));
        if !restored.listing_owed().await.unwrap() {
            break;
        }
    }
    assert_eq!(told.len(), 1, "{told:?}");
    assert_ne!(told, first, "an ID of the new store");
    assert!(
        restored
            .shared_record(&key)
            .await
            .unwrap()
            .unwrap()
            .divergent
    );
    assert_eq!(restored.unacknowledged_events().await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_upload_divergence_is_told_to_each_app_that_holds_the_record() {
    // Two own apps hold the record, each on its own store: each keeps its own duty event,
    // and one acknowledging leaves the other's.
    let w = World::new();
    let router = super::moves::Router::of(&w);
    let protocol = Arc::new(super::moves::LossProtocol::default());
    let wallet_store = Arc::new(MemoryStore::new());
    let (mut wallet, key) = holding_a_record(&w, &router, &wallet_store, &protocol).await;
    let spec = AppSpec::new(&["scope-a"]).with_permissions(&Permission::ALL);
    let request = w.signer.approve(&app_keys("phone"), &spec).unwrap();
    let mut phone = App::join(
        router.env(&w, Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        Arc::clone(&protocol) as Arc<dyn crate::app::Protocol>,
        World::config(),
        request,
    )
    .await
    .unwrap();
    for _ in 0..3 {
        phone.receive(None).await.unwrap();
        if !phone.listing_owed().await.unwrap() {
            break;
        }
    }
    assert!(phone.shared_record(&key).await.unwrap().is_some());
    w.switch
        .make_divergent(app_keys("tablet").app_id_bytes(), key, [1; 32])
        .unwrap();
    let at_wallet = divergent_ids(&wallet.receive(None).await.unwrap().events, key);
    let at_phone = divergent_ids(&phone.receive(None).await.unwrap().events, key);
    assert_eq!((at_wallet.len(), at_phone.len()), (1, 1));
    wallet.ack_events(at_wallet[0]).await.unwrap();
    assert!(divergent_ids(&wallet.unacknowledged_events().await.unwrap(), key).is_empty());
    assert_eq!(
        divergent_ids(&phone.unacknowledged_events().await.unwrap(), key),
        at_phone
    );
}
