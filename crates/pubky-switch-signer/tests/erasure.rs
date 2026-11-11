//! Erasing the identity's account against the scripted switch (Switch spec 12.7; Switch wire
//! 7.4.16): `identity.json` and the app records leave the Homeserver first, then the switch
//! erases the account; a lost answer, a failure and a refusal; and what the signer keeps and
//! refuses afterwards.

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::*;
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::Fault as SwitchFault;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::{IDENTITY_PATH, SIGNER_BACKUP_PATH, app_record_path};
use pubky_switch_signer::{Alert, Refusal, Signer, SignerError, SignerStatus, UserConfirmed};

fn confirmed() -> UserConfirmed {
    UserConfirmed::shown_and_confirmed()
}

fn erase_requests(world: &World) -> usize {
    world
        .transport
        .requests()
        .iter()
        .filter(|r| r.method == "POST" && r.path_and_query.ends_with("/erase"))
        .count()
}

/// An enrolled signer with one app approved, whose record the Homeserver publishes, and the
/// signer's store.
async fn with_an_app(world: &World) -> (Signer, [u8; 16], Arc<MemoryStore>) {
    let (mut signer, store) = world.enrolled().await;
    let app = App::with_keys(
        AppKeys::from_secrets([3; 32], [4; 32]),
        &["notes"],
        None,
        [9; 32],
    );
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    world
        .homeserver
        .set(&app_record_path(&id), b"the app's record".to_vec());
    (signer, id, store)
}

#[tokio::test]
async fn test_erasure_unpublishes_then_erases_the_account() {
    // `identity.json` and the app's record leave the Homeserver, the user is asked to revoke
    // the app's grant, then the switch erases the account. The records stay, the backup too,
    // and nothing more is signed (Switch spec 12.7).
    let world = World::new();
    let (mut signer, id, store) = with_an_app(&world).await;
    let newest = signer.identity_doc().unwrap().unwrap();
    signer.close_account(confirmed()).await.unwrap();
    assert!(world.switch.erased());
    assert!(world.homeserver.file(IDENTITY_PATH).is_none());
    assert!(world.homeserver.file(&app_record_path(&id)).is_none());
    assert!(world.homeserver.file(SIGNER_BACKUP_PATH).is_some());
    let reminder = Alert::GrantRevocationOwed { app_id: id };
    assert!(signer.alerts().contains(&reminder));
    assert_eq!(signer.status(), SignerStatus::Erased);
    assert_eq!(
        signer.identity_doc().unwrap().unwrap().signed(),
        newest.signed()
    );

    let erased = SignerError::Refused(Refusal::Erased);
    assert_eq!(
        signer.set_record_max_age(Some(60)).await.unwrap_err(),
        erased
    );
    assert_eq!(signer.run_due().await.unwrap_err(), erased);
    assert_eq!(signer.close_account(confirmed()).await.unwrap_err(), erased);
    // A resume, as at the next start, sends nothing and publishes nothing.
    let requests = world.transport.requests().len();
    signer.resume().await.unwrap();
    assert_eq!(world.transport.requests().len(), requests);
    assert!(world.homeserver.file(IDENTITY_PATH).is_none());
    // The reminder can still be cleared.
    signer.clear_alert(&reminder).await.unwrap();
    assert!(!signer.alerts().contains(&reminder));

    // Reopened, the records say the same.
    drop(signer);
    let reopened = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    assert_eq!(reopened.status(), SignerStatus::Erased);
}

#[tokio::test]
async fn test_erasure_answer_lost_is_taken_as_done_from_the_404() {
    // The switch erased the account, and its `200` was lost. The retry gets the operator's
    // `404` of an account it doesn't host, which the signer takes as the erasure done
    // (Switch wire 7.4.16).
    let world = World::new();
    let (mut signer, _, _) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/erase".into(),
    });
    signer.close_account(confirmed()).await.unwrap_err();
    assert!(world.switch.erased());
    assert_eq!(signer.status(), SignerStatus::Signing);
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
    assert_eq!(erase_requests(&world), 2);
}

#[tokio::test]
async fn test_erasure_retried_after_the_switch_failed() {
    // The switch couldn't commit the deletion (`503`): nothing was erased, and the erasure
    // stays in progress until a later resume sends it again; the Homeserver's files are gone
    // already and aren't deleted twice.
    let world = World::new();
    let (mut signer, _, _) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::Error {
        path: "/erase".into(),
        code: ErrorCode::Unavailable,
        current: serde_json::Value::Null,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    assert!(!world.switch.erased());
    assert!(world.homeserver.file(IDENTITY_PATH).is_none());
    // Nothing else is signed meanwhile.
    assert_eq!(
        signer.set_record_max_age(Some(60)).await.unwrap_err(),
        SignerError::Refused(Refusal::FlowInProgress)
    );
    signer.resume().await.unwrap();
    assert!(world.switch.erased());
    assert_eq!(signer.status(), SignerStatus::Erased);
}

#[tokio::test]
async fn test_erasure_waits_for_the_homeserver() {
    // The Homeserver is down: nothing goes to the switch until `identity.json` and the app
    // records are deleted, so counterparties never find an identity whose switch doesn't
    // answer (Switch spec 12.7 step 5).
    let world = World::new();
    let (mut signer, id, _) = with_an_app(&world).await;
    // Down only for writes and deletions: the checks before the erasure read it.
    *world.homeserver.failing_puts.lock().unwrap() = true;
    let error = signer.close_account(confirmed()).await.unwrap_err();
    assert!(matches!(error, SignerError::Homeserver(_)), "{error:?}");
    assert_eq!(erase_requests(&world), 0);
    assert!(!world.switch.erased());
    *world.homeserver.failing_puts.lock().unwrap() = false;
    signer.resume().await.unwrap();
    assert!(world.switch.erased());
    assert!(world.homeserver.file(&app_record_path(&id)).is_none());
}

#[tokio::test]
async fn test_erasure_refused_publishes_the_identity_again() {
    // The switch refuses the erasure (`409 conflict`), as during a move: nothing was erased,
    // the erasure ends, and the next run publishes `identity.json` again. Signing goes on.
    let world = World::new();
    let (mut signer, _, _) = with_an_app(&world).await;
    let newest = signer.identity_doc().unwrap().unwrap();
    world.switch.fail_next(SwitchFault::Error {
        path: "/erase".into(),
        code: ErrorCode::Conflict,
        current: serde_json::Value::Null,
    });
    assert_eq!(
        signer.close_account(confirmed()).await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureRefused)
    );
    assert!(!world.switch.erased());
    assert_eq!(signer.status(), SignerStatus::Signing);
    signer.resume().await.unwrap();
    assert_eq!(world.published().unwrap().signed(), newest.signed());
    signer.set_record_max_age(Some(60)).await.unwrap();
}

#[tokio::test]
async fn test_erasure_refused_by_the_gate() {
    // As every signing step: not while another install signs or an alarm is held, and
    // nothing leaves the Homeserver then.
    let world = World::new();
    let (mut signer, _, _) = with_an_app(&world).await;
    let newest = signer.identity_doc().unwrap().unwrap();
    world
        .switch
        .deliver_identity(&world.other_install_version(&newest, [7; 16]))
        .unwrap();
    assert_eq!(
        signer.close_account(confirmed()).await.unwrap_err(),
        SignerError::NotNamed { install: [7; 16] }
    );
    assert!(world.homeserver.file(IDENTITY_PATH).is_some());
    assert_eq!(erase_requests(&world), 0);
}
