//! The certificates of the writers of the claim entries an app keeps (Switch wire 7.4.8,
//! 7.4.14): fetched from the own directory while it can be read, so an upload after a
//! provider loss carries the entries.

use std::sync::Arc;

use pubky_switch_core::enc::b64;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::records::{AppCert, AppRecord, RemovedApp};
use pubky_switch_core::scopes::Permission;
use serde_json::Value;

use super::moves::{ATTEMPT, CLAIM, join_on};
use super::*;
use crate::app::ClaimOp;
use crate::testing::Fault;

fn phone() -> [u8; 16] {
    app_keys("phone").app_id_bytes()
}

fn mark_of(store: &MemoryStore, app_id: &[u8; 16]) -> Option<u64> {
    let ns = crate::store::client_namespace(&app_keys("wallet").app_id_bytes());
    store
        .get(&ns, format!("clcert/{}", b64(app_id)).as_bytes())
        .unwrap()
        .map(|bytes| crate::app::state::decode::<u64>(&bytes).unwrap())
}

fn holds_cert_of(store: &MemoryStore, app_id: &[u8; 16]) -> bool {
    let ns = crate::store::client_namespace(&app_keys("wallet").app_id_bytes());
    let prefix = format!("ocert/{}/", pubky_switch_core::enc::zbase32_encode(app_id));
    !store
        .scan(&ns, prefix.as_bytes(), None, 10)
        .unwrap()
        .is_empty()
}

fn directory_fault() -> Fault {
    Fault::Error {
        path: "directory".into(),
        code: ErrorCode::Unavailable,
        current: Value::Null,
    }
}

fn pending_faults(w: &World) -> usize {
    w.switch.lock().faults.len()
}

/// The phone, registered before the wallet joins, so the wallet never sees its `app.put`;
/// then the wallet; then the phone's attempt on [`CLAIM`].
async fn joined_after_the_writer(store: &Arc<MemoryStore>) -> (World, App) {
    let (w, _, app) = joined_after_the_writer_on(store).await;
    (w, app)
}

async fn joined_after_the_writer_on(
    store: &Arc<MemoryStore>,
) -> (World, super::moves::Router, App) {
    let w = World::new();
    let router = super::moves::Router::of(&w);
    w.other_app("phone", &Permission::ALL);
    let app = join_on(
        &w,
        &router,
        Arc::clone(store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &Permission::ALL,
    )
    .await;
    let attempt = ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None);
    w.switch.app_op(&app_keys("phone"), attempt.kind()).unwrap();
    (w, router, app)
}

/// The directory shows no record of the phone, so its certificate can't be fetched.
fn hide_the_phone(w: &World) {
    w.switch.lock().apps.get_mut(&phone()).unwrap().record = None;
}

#[tokio::test]
async fn test_writer_cert_of_a_kept_entry_is_fetched_and_the_entry_uploadable() {
    // The wallet keeps the phone's entry from its feed without the phone's certificate; the
    // read's end reads the own directory once and keeps it, so the entry goes into the
    // upload's evidence.
    let store = Arc::new(MemoryStore::new());
    let (_w, mut app) = joined_after_the_writer(&store).await;
    assert!(!holds_cert_of(&store, &phone()));
    app.receive(None).await.unwrap();
    assert!(holds_cert_of(&store, &phone()));
    assert_eq!(mark_of(&store, &phone()), None);
    let evidence = app.shared_evidence().await.unwrap();
    assert_eq!(evidence.claim_entries_left_out, 0);
    assert_eq!(evidence.ops.len(), 1, "{evidence:?}");
}

#[tokio::test]
async fn test_writer_cert_directory_read_that_fails_for_now_keeps_the_mark() {
    // A directory read the switch may answer later keeps the mark due, and the feed's read
    // still succeeds; the next read fetches the certificate.
    let store = Arc::new(MemoryStore::new());
    let (w, mut app) = joined_after_the_writer(&store).await;
    w.switch.fail_next(directory_fault());
    app.receive(None).await.unwrap();
    assert_eq!(pending_faults(&w), 0, "the directory was read");
    assert_eq!(mark_of(&store, &phone()), Some(0));
    assert_eq!(
        app.shared_evidence().await.unwrap().claim_entries_left_out,
        1
    );
    app.receive(None).await.unwrap();
    assert!(holds_cert_of(&store, &phone()));
    assert_eq!(mark_of(&store, &phone()), None);
}

#[tokio::test]
async fn test_writer_cert_the_directory_doesnt_show_is_looked_for_once_per_document() {
    // A listed writer the directory doesn't show: looked for once, its mark stamped with
    // the document's version, and not looked for again at later reads, until a newer own
    // `identity.json`. Its entry is counted as left out.
    let store = Arc::new(MemoryStore::new());
    let (w, mut app) = joined_after_the_writer(&store).await;
    w.switch.lock().apps.get_mut(&phone()).unwrap().record = None;
    app.receive(None).await.unwrap();
    let version = app.own_identity().version();
    assert_eq!(mark_of(&store, &phone()), Some(version));
    assert_eq!(
        app.shared_evidence().await.unwrap().claim_entries_left_out,
        1
    );
    // Later reads don't read the directory: the fault stays pending.
    w.switch.fail_next(directory_fault());
    app.receive(None).await.unwrap();
    app.receive(None).await.unwrap();
    assert_eq!(pending_faults(&w), 1);
    // A newer own document makes it due once more.
    w.next_doc(|_| {});
    app.receive(None).await.unwrap();
    assert_eq!(pending_faults(&w), 0, "looked for again");
}

#[tokio::test]
async fn test_writer_cert_not_named_by_the_own_document_isnt_kept() {
    // A certificate the identity's key signed but the own `identity.json` doesn't name, as a
    // switch could show from an earlier issue, isn't kept: the entry stays without one.
    let store = Arc::new(MemoryStore::new());
    let (w, mut app) = joined_after_the_writer(&store).await;
    {
        let mut switch = w.switch.lock();
        let held = switch.apps.get_mut(&phone()).unwrap();
        let mut body = held.cert.clone().unwrap().body().clone();
        body.issued_at += 1;
        let planted = AppCert::issue(&w.alice, body).unwrap();
        let record = AppRecord::sign(
            &app_keys("phone"),
            pubky_switch_core::records::AppRecordBody::new(&planted, Vec::new(), START),
        )
        .unwrap();
        held.record = Some(record.signed().clone());
    }
    app.receive(None).await.unwrap();
    assert!(!holds_cert_of(&store, &phone()));
    assert_eq!(
        app.shared_evidence().await.unwrap().claim_entries_left_out,
        1
    );
}

#[tokio::test]
async fn test_writer_cert_of_a_writer_no_longer_listed_is_dropped_unread() {
    // A writer the own `identity.json` no longer lists: its mark goes without a directory
    // read, and its entry stays left out.
    let store = Arc::new(MemoryStore::new());
    let (w, mut app) = joined_after_the_writer(&store).await;
    w.next_doc(|body| {
        body.apps.retain(|entry| entry.app_id != phone());
        body.removed.push(RemovedApp {
            app_id: phone(),
            distrust_from: START,
        });
    });
    w.switch.fail_next(directory_fault());
    app.receive(None).await.unwrap();
    assert_eq!(pending_faults(&w), 1, "no directory read");
    assert_eq!(mark_of(&store, &phone()), None);
    assert_eq!(
        app.shared_evidence().await.unwrap().claim_entries_left_out,
        1
    );
}

#[tokio::test]
async fn test_writer_cert_that_doesnt_verify_the_entry_isnt_uploaded_with_it() {
    // An entry kept before its writer's certificate came, which that certificate doesn't
    // verify, as one a switch forged in the writer's name, is left out of the upload.
    let store = Arc::new(MemoryStore::new());
    let (_w, mut app) = joined_after_the_writer(&store).await;
    app.receive(None).await.unwrap();
    assert!(holds_cert_of(&store, &phone()));
    // The kept entry's signature is replaced by another valid encoding.
    let ns = crate::store::client_namespace(&app_keys("wallet").app_id_bytes());
    let (key, value) = store
        .scan(&ns, b"clent/", None, 10)
        .unwrap()
        .into_iter()
        .next()
        .expect("the kept entry");
    let mut entry: Value = serde_json::from_slice(&value).unwrap();
    let forged = b64(&[7; 64]);
    let sig = &mut entry["d"]["op"]["sig"];
    assert!(
        sig.is_string() && *sig != Value::String(forged.clone()),
        "{sig}"
    );
    *sig = Value::String(forged);
    let mut batch = crate::store::WriteBatch::new();
    batch
        .put(&ns, key, serde_json::to_vec(&entry).unwrap())
        .unwrap();
    store.commit(batch).unwrap();
    let evidence = app.shared_evidence().await.unwrap();
    assert_eq!(evidence.claim_entries_left_out, 1);
    assert!(evidence.ops.is_empty(), "{evidence:?}");
}

#[tokio::test]
async fn test_writer_cert_left_out_entries_are_in_the_recovery_report() {
    // After a provider loss, the upload leaves out the entry it holds no certificate for,
    // and the recovery report says how many.
    let store = Arc::new(MemoryStore::new());
    let (w, router, mut app) = joined_after_the_writer_on(&store).await;
    hide_the_phone(&w);
    app.receive(None).await.unwrap();
    drop(app);
    let n_key = super::moves::next_key();
    let next =
        ScriptedSwitch::recovering(&w.alice, n_key.to_bytes(), Arc::clone(&w.clock), 2, 1).unwrap();
    router.add(super::moves::NEXT, &next);
    super::moves::publish_at(
        &w,
        &next,
        pubky_switch_core::records::Inbox::new(
            super::moves::NEXT,
            n_key.verifying_key().to_bytes(),
        ),
        2,
        Some(1),
    );
    w.switch.lock().erased = true;
    let mut app = App::load(
        router.env(&w, Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    app.refresh_identity().await.unwrap();
    app.receive(None).await.unwrap();
    let info = app.recovery_info().await.unwrap().unwrap();
    assert_eq!(info.loss.generation, 2);
    assert_eq!(info.claim_entries_left_out, 1);
}

#[tokio::test]
async fn test_writer_cert_of_an_entry_kept_from_a_claim_read_is_marked() {
    // An entry kept from `GET /claims`, not the feed, marks its writer too.
    let store = Arc::new(MemoryStore::new());
    let (_w, mut app) = joined_after_the_writer(&store).await;
    app.read_claim(&CLAIM).await.unwrap();
    assert_eq!(mark_of(&store, &phone()), Some(0));
}
