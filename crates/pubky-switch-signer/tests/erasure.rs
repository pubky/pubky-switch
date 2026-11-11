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
use pubky_switch_client::transport::{MockTransport, Response};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::{IDENTITY_PATH, IdentityDoc, SIGNER_BACKUP_PATH, app_record_path};
use pubky_switch_signer::{
    Alert, Refusal, Signer, SignerEnv, SignerError, SignerStatus, UserConfirmed,
};

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
    // The switch erased the account, and its `200` was lost. The check before the retry gets
    // the operator's `404` of an account it doesn't host, and the backup and the Homeserver
    // show no other install: the signer takes it as the erasure done, as a retry's `404`
    // (Switch wire 7.4.16), and sends no other request.
    let world = World::new();
    let (mut signer, _, _) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/erase".into(),
    });
    signer.close_account(confirmed()).await.unwrap_err();
    assert!(world.switch.erased());
    assert_eq!(signer.status(), SignerStatus::Erasing);
    // It may have erased the account: it can't be aborted.
    assert_eq!(
        signer.abort_erasure().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnanswered)
    );
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
    assert_eq!(erase_requests(&world), 1);
}

#[tokio::test]
async fn test_erasure_retried_after_the_switch_failed() {
    // The switch couldn't commit the deletion (`503`): nothing was erased, and the erasure
    // stays in progress until a later resume sends it again.
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
    assert_eq!(signer.status(), SignerStatus::Erasing);
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
    // The grant reminder the erasure raised for the app, still listed, is withdrawn.
    assert!(
        !signer
            .alerts()
            .iter()
            .any(|a| matches!(a, Alert::GrantRevocationOwed { .. }))
    );
    signer.resume().await.unwrap();
    assert_eq!(world.published().unwrap().signed(), newest.signed());
    signer.set_record_max_age(Some(60)).await.unwrap();
}

#[tokio::test]
async fn test_erasure_refused_by_the_gate() {
    // As every signing step: not while another install signs or an alarm is held, and
    // nothing leaves the Homeserver then.
    for alarm in [false, true] {
        let world = World::new();
        let (mut signer, _, _) = with_an_app(&world).await;
        let newest = signer.identity_doc().unwrap().unwrap();
        let planted = if alarm {
            // Another body at the newest version on the Homeserver: equivocation.
            let mut body = newest.body().clone();
            body.record_max_age = Some(7);
            let other = IdentityDoc::sign(&world.key, body).unwrap();
            let bytes = serde_json::to_vec(other.signed()).unwrap();
            world.homeserver.set(IDENTITY_PATH, bytes.clone());
            bytes
        } else {
            world
                .switch
                .deliver_identity(&world.other_install_version(&newest, [7; 16]))
                .unwrap();
            world.homeserver.file(IDENTITY_PATH).unwrap()
        };
        let error = signer.close_account(confirmed()).await.unwrap_err();
        if alarm {
            assert!(matches!(error, SignerError::Alarm(_)), "{error:?}");
        } else {
            assert_eq!(error, SignerError::NotNamed { install: [7; 16] });
        }
        assert_eq!(world.homeserver.file(IDENTITY_PATH), Some(planted));
        assert_eq!(erase_requests(&world), 0);
    }
}

/// `world`'s env, with a transport that answers `POST /erase` with an unsigned `404`, as a
/// proxy or an unknown route could, and passes every other request to the switch.
fn unsigned_404_for_erasure(world: &World, store: Arc<MemoryStore>) -> SignerEnv {
    let switch = Arc::clone(&world.switch);
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if request.method == "POST" && request.path_and_query.ends_with("/erase") {
            Ok(Response {
                status: 404,
                headers: Vec::new(),
                body: b"{}".to_vec(),
            })
        } else {
            switch.handle(request)
        }
    }));
    let mut env = world.env(store);
    env.transport = transport;
    env
}

#[tokio::test]
async fn test_erasure_404_to_a_first_request_isnt_taken_as_done() {
    // A `404` is never a lost answer: to a request with none in doubt before, it erased
    // nothing, however often it comes, as from an intermediary that never routes the request.
    // The erasure stays in progress and the user can abort it (Switch wire 7.4.16).
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    drop(signer);
    let mut signer = Signer::open(unsigned_404_for_erasure(&world, store), world.keyring())
        .await
        .unwrap();
    let newest = signer.identity_doc().unwrap().unwrap();
    let error = signer.close_account(confirmed()).await.unwrap_err();
    assert!(matches!(error, SignerError::Switch(_)), "{error:?}");
    for _ in 0..10 {
        signer.resume().await.unwrap_err();
        assert_eq!(signer.status(), SignerStatus::Erasing);
    }
    signer.abort_erasure().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Signing);
    assert_eq!(world.published().unwrap().signed(), newest.signed());
}

#[tokio::test]
async fn test_erasure_aborted_after_a_signed_refusal() {
    // The switch answered, signed, that it couldn't commit the deletion: the account still
    // exists, so the user can abort. `identity.json` is published again, and the grant
    // reminder the erasure raised for the app, still listed, is withdrawn.
    let world = World::new();
    let (mut signer, _, _) = with_an_app(&world).await;
    let newest = signer.identity_doc().unwrap().unwrap();
    world.switch.fail_next(SwitchFault::Error {
        path: "/erase".into(),
        code: ErrorCode::Unavailable,
        current: serde_json::Value::Null,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    signer.abort_erasure().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Signing);
    assert_eq!(world.published().unwrap().signed(), newest.signed());
    assert!(
        !signer
            .alerts()
            .iter()
            .any(|a| matches!(a, Alert::GrantRevocationOwed { .. }))
    );
    assert_eq!(
        signer.abort_erasure().await.unwrap_err(),
        SignerError::Refused(Refusal::NotErasing)
    );
}

/// `world`'s env, whose transport loses the first answer to `POST /erase`, then answers the
/// next `GET /apps` with an unsigned `503`, as a proxy could, and passes everything else to the
/// switch.
fn lost_then_unsigned_503(world: &World, store: Arc<MemoryStore>) -> SignerEnv {
    let switch = Arc::clone(&world.switch);
    // 0: nothing lost yet; 1: the erasure's answer lost; 2: the `503` given.
    let stage = Arc::new(std::sync::Mutex::new(0));
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        let mut stage = stage.lock().unwrap();
        if *stage == 0 && request.method == "POST" && request.path_and_query.ends_with("/erase") {
            *stage = 1;
            let _ = switch.handle(request);
            return Err(pubky_switch_client::TransportError::Timeout);
        }
        if *stage == 1 && request.method == "GET" && request.path_and_query.ends_with("/apps") {
            *stage = 2;
            return Ok(Response {
                status: 503,
                headers: Vec::new(),
                body: b"{}".to_vec(),
            });
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport;
    env
}

#[tokio::test]
async fn test_erasure_unsigned_answer_after_a_lost_200_keeps_it_landed() {
    // The switch erased the account and its `200` was lost; a proxy answers the next check's
    // read with an unsigned `503`, which keeps the request in doubt; the next check gets the
    // operator's `404`. The unsigned answer showed nothing about the account, so the erasure
    // is done (Switch wire 7.4.16).
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    drop(signer);
    let mut signer = Signer::open(lost_then_unsigned_503(&world, store), world.keyring())
        .await
        .unwrap();
    signer.close_account(confirmed()).await.unwrap_err();
    assert!(world.switch.erased());
    signer.resume().await.unwrap_err();
    assert_eq!(
        signer.abort_erasure().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnanswered)
    );
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
}

#[tokio::test]
async fn test_erasure_reopened_mid_flow_finishes() {
    // The install stopped with the erasure's request unanswered: reopened, it shows the
    // erasure in progress, and its resume finishes it.
    let world = World::new();
    let (mut signer, _, store) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/erase".into(),
    });
    signer.close_account(confirmed()).await.unwrap_err();
    drop(signer);
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    assert_eq!(signer.status(), SignerStatus::Erasing);
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
}

#[tokio::test]
async fn test_erasure_settles_what_only_the_account_could_and_refuses_the_rest() {
    // A revocation couldn't reach the switch before the erasure. Once erased, it is dropped:
    // no run reaches the switch, a revocation and a restore are refused, and nothing is sent.
    let world = World::new();
    let (mut signer, id, _) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::Error {
        path: "/revoke".into(),
        code: ErrorCode::Unavailable,
        current: serde_json::Value::Null,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    signer.close_account(confirmed()).await.unwrap();
    assert!(
        !signer
            .alerts()
            .iter()
            .any(|a| matches!(a, Alert::RevocationPending { .. }))
    );
    let requests = world.transport.requests().len();
    let erased = SignerError::Refused(Refusal::Erased);
    assert_eq!(signer.run_due().await.unwrap_err(), erased);
    assert_eq!(
        signer.revoke(id, None, confirmed()).await.unwrap_err(),
        erased
    );
    assert_eq!(signer.restore(confirmed()).await.unwrap_err(), erased);
    assert_eq!(world.transport.requests().len(), requests);
}

#[tokio::test]
async fn test_erasure_reminds_of_removed_apps_whose_record_was_owed() {
    // The app was revoked while the Homeserver refused `identity.json`, so its record's
    // deletion, and with it its grant reminder, waited for a publication. The erasure deletes
    // the record and raises the reminder (Switch spec 12.2 step 1).
    let world = World::new();
    let (mut signer, id, _) = with_an_app(&world).await;
    *world.homeserver.failing_path.lock().unwrap() = Some(IDENTITY_PATH.to_owned());
    let _ = signer.revoke(id, None, confirmed()).await;
    let reminder = Alert::GrantRevocationOwed { app_id: id };
    assert!(!signer.alerts().contains(&reminder));
    *world.homeserver.failing_path.lock().unwrap() = None;
    signer.close_account(confirmed()).await.unwrap();
    assert!(signer.alerts().contains(&reminder));
    assert!(world.homeserver.file(&app_record_path(&id)).is_none());
}

#[tokio::test]
async fn test_erasure_ended_keeps_a_removed_apps_reminder() {
    // The app was revoked while the Homeserver refused `identity.json`, so its reminder
    // waited; the erasure raised it, then ended without erasing, by the switch's refusal or
    // the user's abort. The removed app's grant revocation is owed all the same: the reminder
    // stays (Switch spec 12.2 step 1).
    for refused in [true, false] {
        let world = World::new();
        let (mut signer, id, _) = with_an_app(&world).await;
        *world.homeserver.failing_path.lock().unwrap() = Some(IDENTITY_PATH.to_owned());
        let _ = signer.revoke(id, None, confirmed()).await;
        *world.homeserver.failing_path.lock().unwrap() = None;
        let code = if refused {
            ErrorCode::Conflict
        } else {
            ErrorCode::Unavailable
        };
        world.switch.fail_next(SwitchFault::Error {
            path: "/erase".into(),
            code,
            current: serde_json::Value::Null,
        });
        signer.close_account(confirmed()).await.unwrap_err();
        if !refused {
            signer.abort_erasure().await.unwrap();
        }
        let reminder = Alert::GrantRevocationOwed { app_id: id };
        assert!(signer.alerts().contains(&reminder), "refused: {refused}");
    }
}

#[tokio::test]
async fn test_erasure_aborted_after_a_partial_unpublish_publishes_again() {
    // `identity.json` left the Homeserver, then the app's record couldn't be deleted: the
    // erasure stopped before the switch. The user aborts, and `identity.json` is published
    // again by the abort's own resume.
    let world = World::new();
    let (mut signer, id, _) = with_an_app(&world).await;
    let newest = signer.identity_doc().unwrap().unwrap();
    *world.homeserver.failing_path.lock().unwrap() = Some(app_record_path(&id));
    signer.close_account(confirmed()).await.unwrap_err();
    assert!(world.homeserver.file(IDENTITY_PATH).is_none());
    assert_eq!(erase_requests(&world), 0);
    *world.homeserver.failing_path.lock().unwrap() = None;
    signer.abort_erasure().await.unwrap();
    assert_eq!(world.published().unwrap().signed(), newest.signed());
}

#[tokio::test]
async fn test_erasure_run_does_nothing_while_erasing_or_once_erased() {
    // Past half the app's lifetime, with the Homeserver's copy gone: while the erasure is in
    // progress, and once it is done, a run renews nothing and writes nothing to the
    // Homeserver. The run that completes the erasure returns without error.
    let world = World::new();
    let (mut signer, _, _) = with_an_app(&world).await;
    world.clock.advance_ms(200 * 86_400_000);
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/erase".into(),
    });
    signer.close_account(confirmed()).await.unwrap_err();
    let sent = world.sent_docs().len();
    let writes = world.homeserver.writes.lock().unwrap().len();
    signer.run_due().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
    assert_eq!(
        signer.run_due().await.unwrap_err(),
        SignerError::Refused(Refusal::Erased)
    );
    assert_eq!(world.sent_docs().len(), sent);
    assert_eq!(world.homeserver.writes.lock().unwrap().len(), writes);
    assert!(world.homeserver.file(IDENTITY_PATH).is_none());
}

/// Another install's version after `signer`'s newest, delivered to the switch behind its
/// back, as a restore on another device delivers.
fn another_install_delivers(world: &World, signer: &Signer) -> impl FnOnce() + Send + 'static {
    let doc = world.other_install_version(&signer.identity_doc().unwrap().unwrap(), [9; 16]);
    let switch = Arc::clone(&world.switch);
    move || switch.deliver_identity(&doc).unwrap()
}

#[tokio::test]
async fn test_erasure_resumed_after_a_restore_elsewhere_deletes_nothing_of_it() {
    // The erasure stops at a Homeserver failure after deleting `identity.json`; another device
    // restores from the backup, delivers its version as the signer and publishes it. This
    // install's resumed erasure then deletes nothing, sends no erasure, and publishes nothing
    // over the other install's version: it no longer signs (Switch spec 4.3, Switch wire
    // 3.13).
    let world = World::new();
    let (mut signer, id, _) = with_an_app(&world).await;
    *world.homeserver.failing_path.lock().unwrap() = Some(app_record_path(&id));
    let error = signer.close_account(confirmed()).await.unwrap_err();
    assert!(matches!(error, SignerError::Homeserver(_)), "{error:?}");
    *world.homeserver.failing_path.lock().unwrap() = None;
    assert_eq!(signer.status(), SignerStatus::Erasing);
    let mut other = Signer::restore_new(
        world.env(Arc::new(MemoryStore::new())),
        world.keyring(),
        confirmed(),
    )
    .await
    .unwrap();
    let theirs = other.identity_doc().unwrap().unwrap();
    assert_eq!(world.published().unwrap().signed(), theirs.signed());

    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::NotNamed {
            install: other.install_id()
        }
    );
    assert_eq!(erase_requests(&world), 0);
    assert!(!world.switch.erased());
    assert_eq!(world.published().unwrap().signed(), theirs.signed());
    assert!(world.homeserver.file(&app_record_path(&id)).is_some());
    assert!(
        matches!(signer.status(), SignerStatus::ManagedBy { .. }),
        "{:?}",
        signer.status()
    );
    // Its grant reminders for the apps still listed are withdrawn: the other install signs.
    assert!(
        !signer
            .alerts()
            .iter()
            .any(|alert| matches!(alert, Alert::GrantRevocationOwed { .. })),
        "{:?}",
        signer.alerts()
    );
    // And it stays so: the next run does nothing, publishing or deleting nothing.
    signer.resume().await.unwrap();
    assert_eq!(world.published().unwrap().signed(), theirs.signed());
    assert_eq!(erase_requests(&world), 0);
    other.set_record_max_age(Some(60)).await.unwrap();
}

#[tokio::test]
async fn test_erasure_stops_when_another_install_delivers_between_two_deletions() {
    // Each deletion comes after a fresh check: another install delivering after
    // `identity.json` went stops the erasure before the app's record goes.
    let world = World::new();
    let (mut signer, id, _) = with_an_app(&world).await;
    let delivers = another_install_delivers(&world, &signer);
    *world.homeserver.after_delete.lock().unwrap() =
        Some((IDENTITY_PATH.to_owned(), Box::new(delivers)));
    assert_eq!(
        signer.close_account(confirmed()).await.unwrap_err(),
        SignerError::NotNamed { install: [9; 16] }
    );
    assert!(world.homeserver.file(&app_record_path(&id)).is_some());
    assert_eq!(erase_requests(&world), 0);
    assert!(!world.switch.erased());
}

#[tokio::test]
async fn test_erasure_takes_no_step_while_ownership_cant_be_read() {
    // The switch, or the signer backup, can't be read: nothing is deleted and nothing is sent,
    // the erasure stays in progress, and goes on once both answer.
    let world = World::new();
    let (mut signer, id, _) = with_an_app(&world).await;
    *world.homeserver.failing_puts.lock().unwrap() = true;
    signer.close_account(confirmed()).await.unwrap_err();
    *world.homeserver.failing_puts.lock().unwrap() = false;
    let published = world.published();
    assert!(published.is_some());

    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/apps".into(),
        after: 0,
    });
    signer.resume().await.unwrap_err();
    *world.homeserver.failing_read_path.lock().unwrap() =
        Some(pubky_switch_core::records::SIGNER_BACKUP_PATH.to_owned());
    signer.resume().await.unwrap_err();
    assert_eq!(
        world.published().map(|d| d.signed().clone()),
        published.map(|d| d.signed().clone())
    );
    assert!(world.homeserver.file(&app_record_path(&id)).is_some());
    assert_eq!(erase_requests(&world), 0);
    assert_eq!(signer.status(), SignerStatus::Erasing);

    *world.homeserver.failing_read_path.lock().unwrap() = None;
    signer.resume().await.unwrap();
    assert!(world.switch.erased());
    assert!(world.homeserver.file(&app_record_path(&id)).is_none());
}

#[tokio::test]
async fn test_erasure_request_not_sent_again_once_another_install_signs() {
    // The files are gone and a request went unanswered; another install then delivers. The
    // check before the next request finds it: nothing more is sent, and the grant reminders
    // raised for apps still listed are withdrawn (Switch spec 4.3, 12.7).
    let world = World::new();
    let (mut signer, id, _) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/erase".into(),
        after: 0,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    assert!(
        signer
            .alerts()
            .contains(&Alert::GrantRevocationOwed { app_id: id })
    );
    let sent = erase_requests(&world);
    another_install_delivers(&world, &signer)();
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::NotNamed { install: [9; 16] }
    );
    assert_eq!(erase_requests(&world), sent);
    assert!(!world.switch.erased());
    assert!(
        !signer
            .alerts()
            .contains(&Alert::GrantRevocationOwed { app_id: id })
    );
}

/// `world`'s env, whose transport answers `GET /apps` with an unsigned `404` the first
/// `times` times, as an intermediary could, and passes everything else to the switch.
fn unsigned_404_for_apps(world: &World, store: Arc<MemoryStore>, times: usize) -> SignerEnv {
    let switch = Arc::clone(&world.switch);
    let left = Arc::new(std::sync::Mutex::new(times));
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if request.method == "GET" && request.path_and_query.ends_with("/apps") {
            let mut left = left.lock().unwrap();
            if *left > 0 {
                *left -= 1;
                return Ok(Response {
                    status: 404,
                    headers: Vec::new(),
                    body: b"{}".to_vec(),
                });
            }
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport;
    env
}

#[tokio::test]
async fn test_erasure_unsigned_404_with_nothing_in_doubt_takes_no_step() {
    // With no request in doubt, an unsigned `404` to the check's read is a copy that can't be
    // read: nothing is deleted (Switch wire 7.4.16).
    let world = World::new();
    let (mut signer, id, store) = with_an_app(&world).await;
    *world.homeserver.failing_puts.lock().unwrap() = true;
    signer.close_account(confirmed()).await.unwrap_err();
    *world.homeserver.failing_puts.lock().unwrap() = false;
    drop(signer);
    let mut signer = Signer::open(unsigned_404_for_apps(&world, store, 1), world.keyring())
        .await
        .unwrap();
    signer.resume().await.unwrap_err();
    assert!(world.published().is_some());
    assert!(world.homeserver.file(&app_record_path(&id)).is_some());
    assert_eq!(erase_requests(&world), 0);
    assert_eq!(signer.status(), SignerStatus::Erasing);
}

#[tokio::test]
async fn test_erasure_in_doubt_still_judges_the_backup() {
    // A request went unanswered, without landing; another device restores and takes over.
    // An unsigned `404` to the next check's switch read, which could be the operator's after
    // an erasure, still leaves the backup to judge: it names the other install, and nothing
    // is sent (Switch wire 3.13, 7.4.16).
    let world = World::new();
    let (mut signer, id, store) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/erase".into(),
        after: 0,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    assert!(
        signer
            .alerts()
            .contains(&Alert::GrantRevocationOwed { app_id: id })
    );
    drop(signer);
    let other = Signer::restore_new(
        world.env(Arc::new(MemoryStore::new())),
        world.keyring(),
        confirmed(),
    )
    .await
    .unwrap();
    let sent = erase_requests(&world);
    let mut signer = Signer::open(unsigned_404_for_apps(&world, store, 1), world.keyring())
        .await
        .unwrap();
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::NotNamed {
            install: other.install_id()
        }
    );
    assert_eq!(erase_requests(&world), sent);
    assert!(!world.switch.erased());
    // Ended in the commit that names the other install: the reminder is withdrawn.
    assert!(
        !signer
            .alerts()
            .contains(&Alert::GrantRevocationOwed { app_id: id })
    );
}

#[tokio::test]
async fn test_erasure_stops_at_another_installs_copy_on_the_homeserver() {
    // The Homeserver publishes a newer version of another install's: the full check before the
    // first deletion finds it, and nothing is deleted (Switch spec 4.3).
    let world = World::new();
    let (mut signer, id, _) = with_an_app(&world).await;
    *world.homeserver.failing_puts.lock().unwrap() = true;
    signer.close_account(confirmed()).await.unwrap_err();
    *world.homeserver.failing_puts.lock().unwrap() = false;
    let other = world.other_install_version(&signer.identity_doc().unwrap().unwrap(), [9; 16]);
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(other.signed()).unwrap());
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::NotNamed { install: [9; 16] }
    );
    assert!(world.homeserver.file(&app_record_path(&id)).is_some());
    assert!(world.homeserver.file(IDENTITY_PATH).is_some());
    assert_eq!(erase_requests(&world), 0);
}

#[tokio::test]
async fn test_erasure_kept_through_an_alarm() {
    // Another body at the mark's version on the Homeserver is the equivocation alarm: this
    // install still signs, so the erasure stays in progress, nothing is deleted meanwhile,
    // and the user can abort it.
    let world = World::new();
    let (mut signer, id, _) = with_an_app(&world).await;
    *world.homeserver.failing_puts.lock().unwrap() = true;
    signer.close_account(confirmed()).await.unwrap_err();
    *world.homeserver.failing_puts.lock().unwrap() = false;
    let mine = signer.identity_doc().unwrap().unwrap();
    let mut body = mine.body().clone();
    body.record_max_age = Some(1);
    let other = IdentityDoc::sign(&world.key, body).unwrap();
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(other.signed()).unwrap());
    assert!(matches!(
        signer.resume().await.unwrap_err(),
        SignerError::Alarm(_)
    ));
    assert_eq!(signer.status(), SignerStatus::Erasing);
    assert!(world.homeserver.file(&app_record_path(&id)).is_some());
    assert_eq!(erase_requests(&world), 0);
    // The other body leaves the Homeserver, and the user hasn't cleared the alarm: the copies
    // read clean again, but the alarm still holds every step back.
    world.homeserver.files.lock().unwrap().remove(IDENTITY_PATH);
    assert!(matches!(
        signer.resume().await.unwrap_err(),
        SignerError::Alarm(_)
    ));
    assert_eq!(signer.status(), SignerStatus::Erasing);
    assert!(world.homeserver.file(&app_record_path(&id)).is_some());
    assert_eq!(erase_requests(&world), 0);
    // The user's way out: the abort ends it without erasing.
    signer.abort_erasure().await.unwrap();
    assert_ne!(signer.status(), SignerStatus::Erasing);
    assert_eq!(erase_requests(&world), 0);
}

#[tokio::test]
async fn test_erasure_in_doubt_sends_nothing_more_on_an_unsigned_404() {
    // A request went unanswered, without landing; another install then delivers at the switch,
    // and has neither published nor written its backup yet. A proxy answers this install's
    // check with an unsigned `404`, and the other copies show nothing: it is taken as the
    // erasure done, and no other request goes out, so the other install's account stays
    // (Switch wire 7.4.16).
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    drop(signer);
    let mut signer = Signer::open(world.env(store.clone()), world.keyring())
        .await
        .unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/erase".into(),
        after: 0,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    another_install_delivers(&world, &signer)();
    drop(signer);
    let sent = erase_requests(&world);
    let mut signer = Signer::open(
        unsigned_404_for_apps(&world, store, usize::MAX),
        world.keyring(),
    )
    .await
    .unwrap();
    signer.resume().await.unwrap();
    assert_eq!(erase_requests(&world), sent);
    assert!(!world.switch.erased(), "the other install's account stays");
    assert_eq!(signer.status(), SignerStatus::Erased);
}

#[tokio::test]
async fn test_erasure_stops_at_a_copy_published_between_two_deletions() {
    // Another install's newer copy reaches the Homeserver after `identity.json` went, before
    // the switch shows it: each later deletion judges the Homeserver too, and the app's record
    // stays (Switch wire 3.13).
    let world = World::new();
    let (mut signer, id, _) = with_an_app(&world).await;
    let other = world.other_install_version(&signer.identity_doc().unwrap().unwrap(), [9; 16]);
    let homeserver = Arc::clone(&world.homeserver);
    *world.homeserver.after_delete.lock().unwrap() = Some((
        IDENTITY_PATH.to_owned(),
        Box::new(move || {
            homeserver.set(IDENTITY_PATH, serde_json::to_vec(other.signed()).unwrap());
        }),
    ));
    assert_eq!(
        signer.close_account(confirmed()).await.unwrap_err(),
        SignerError::NotNamed { install: [9; 16] }
    );
    assert!(world.homeserver.file(&app_record_path(&id)).is_some());
    assert_eq!(erase_requests(&world), 0);
}

/// An erasure with the files gone and the reminders raised, and no request in doubt: its
/// first request got a signed `503`.
async fn erasing_after_a_signed_failure(world: &World) -> (Signer, [u8; 16], Arc<MemoryStore>) {
    let (mut signer, id, store) = with_an_app(world).await;
    world.switch.fail_next(SwitchFault::Error {
        path: "/erase".into(),
        code: ErrorCode::Unavailable,
        current: serde_json::Value::Null,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    assert_eq!(signer.status(), SignerStatus::Erasing);
    assert!(
        signer
            .alerts()
            .contains(&Alert::GrantRevocationOwed { app_id: id })
    );
    (signer, id, store)
}

#[tokio::test]
async fn test_erasure_kept_when_clearing_an_alarm_raises_it_again() {
    // The switch shows a rollback during the erasure: the alarm keeps it. The user clears the
    // alert while the switch still shows it, and the read that clearing makes raises it again:
    // the erasure is still kept, in that commit. Once the switch holds the mark again and the
    // alert is cleared, the erasure goes on and erases.
    let world = World::new();
    let (mut signer, _, _) = erasing_after_a_signed_failure(&world).await;
    let mark = signer.identity_doc().unwrap().unwrap();
    world.switch.lose_identity();
    let SignerError::Alarm(alert) = signer.resume().await.unwrap_err() else {
        panic!("an alarm")
    };
    assert_eq!(signer.status(), SignerStatus::Erasing);
    assert!(matches!(
        signer.clear_alert(&alert).await.unwrap_err(),
        SignerError::Alarm(_)
    ));
    assert_eq!(signer.status(), SignerStatus::Erasing);
    world.switch.deliver_identity(&mark).unwrap();
    signer.clear_alert(&alert).await.unwrap();
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
    assert!(world.switch.erased());
    assert!(world.published().is_none(), "nothing published again");
}

#[tokio::test]
async fn test_erasure_kept_when_a_revocation_raises_an_alarm() {
    // A revocation asked for during the erasure reads the switch, which shows a rollback: the
    // alarm keeps the erasure.
    let world = World::new();
    let (mut signer, id, _) = erasing_after_a_signed_failure(&world).await;
    world.switch.lose_identity();
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert_eq!(signer.status(), SignerStatus::Erasing);
}

#[tokio::test]
async fn test_erasure_and_its_doubt_survive_a_crash_after_an_alarm() {
    // A request is in doubt; the switch then shows a rollback. The alarm is recorded with the
    // erasure in one commit: a crash right after it loses neither the erasure nor its doubt,
    // so it still can't be aborted (Switch wire 7.4.16).
    use pubky_switch_client::store::{Fault, FaultStore, StateStore};
    let world = World::new();
    let (mut signer, _, store) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/erase".into(),
        after: 0,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    drop(signer);
    world.switch.lose_identity();
    let inner: Arc<dyn StateStore> = store.clone();
    let dying = Arc::new(FaultStore::new(inner, Fault::StopAfter(1)));
    let mut signer = Signer::open(world.env(dying), world.keyring())
        .await
        .unwrap();
    signer.resume().await.unwrap_err();
    drop(signer);
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    assert_eq!(signer.status(), SignerStatus::Erasing);
    assert_eq!(
        signer.abort_erasure().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnanswered)
    );
}

#[tokio::test]
async fn test_erasure_in_doubt_ends_erased_through_a_held_alarm() {
    // The request lands and its answer is lost. The next check meets the operator's `404`,
    // and the Homeserver holds another body at the mark: the equivocation alarm, the erasure
    // kept. Once the alert is cleared, the check finds the account erased: a conclusion, not
    // a step, so the gate doesn't hold it back, and the erasure ends erased (Switch wire
    // 7.4.16).
    let world = World::new();
    let (mut signer, _, _) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/erase".into(),
    });
    signer.close_account(confirmed()).await.unwrap_err();
    assert!(world.switch.erased());
    let mine = signer.identity_doc().unwrap().unwrap();
    let mut body = mine.body().clone();
    body.record_max_age = Some(1);
    let other = IdentityDoc::sign(&world.key, body).unwrap();
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(other.signed()).unwrap());
    let SignerError::Alarm(alert) = signer.resume().await.unwrap_err() else {
        panic!("an alarm")
    };
    assert_eq!(signer.status(), SignerStatus::Erasing);
    let _ = signer.clear_alert(&alert).await;
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
    assert_eq!(erase_requests(&world), 1);
}

/// `world`'s env, whose transport forwards the first `POST /erase` to the switch, which
/// erases, and answers it with an unsigned `503`, as a gateway could, and passes everything
/// else to the switch.
fn forwarded_then_unsigned_503(world: &World, store: Arc<MemoryStore>) -> SignerEnv {
    let switch = Arc::clone(&world.switch);
    let first = Arc::new(std::sync::Mutex::new(true));
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if request.method == "POST" && request.path_and_query.ends_with("/erase") {
            let mut first = first.lock().unwrap();
            if *first {
                *first = false;
                let _ = switch.handle(request);
                return Ok(Response {
                    status: 503,
                    headers: Vec::new(),
                    body: b"{}".to_vec(),
                });
            }
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport;
    env
}

#[tokio::test]
async fn test_erasure_unsigned_503_to_its_request_keeps_it_in_doubt() {
    // A gateway's unsigned `503` can hide a request it forwarded: the request stays in doubt,
    // the erasure can't be aborted, and the next check's `404` finds it erased (Switch wire
    // 7.4.16).
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    drop(signer);
    let mut signer = Signer::open(forwarded_then_unsigned_503(&world, store), world.keyring())
        .await
        .unwrap();
    signer.close_account(confirmed()).await.unwrap_err();
    assert!(world.switch.erased());
    assert_eq!(
        signer.abort_erasure().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnanswered)
    );
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
}

#[tokio::test]
async fn test_erasure_in_doubt_judges_the_backup_alone() {
    // The other install delivered and wrote its backup, and its publication failed: the
    // Homeserver shows nothing of it. The in-doubt `404` still meets the backup, which names
    // it (Switch wire 3.13).
    let world = World::new();
    let (mut signer, _, store) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/erase".into(),
        after: 0,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    drop(signer);
    *world.homeserver.failing_path.lock().unwrap() = Some(IDENTITY_PATH.to_owned());
    let other = Signer::restore_new(
        world.env(Arc::new(MemoryStore::new())),
        world.keyring(),
        confirmed(),
    )
    .await;
    *world.homeserver.failing_path.lock().unwrap() = None;
    assert!(
        matches!(other, Err(SignerError::Homeserver(_))),
        "{other:?}"
    );
    assert!(world.homeserver.file(IDENTITY_PATH).is_none());
    let mut signer = Signer::open(unsigned_404_for_apps(&world, store, 1), world.keyring())
        .await
        .unwrap();
    let mine = signer.install_id();
    let error = signer.resume().await.unwrap_err();
    assert!(
        matches!(error, SignerError::NotNamed { install } if install != mine),
        "{error:?}"
    );
    assert_eq!(erase_requests(&world), 1);
}

#[tokio::test]
async fn test_erasure_in_doubt_judges_the_homeserver_alone() {
    // Another install's newer copy on the Homeserver, the backup still this install's own:
    // the in-doubt `404` still meets it (Switch spec 4.3).
    let world = World::new();
    let (mut signer, _, store) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/erase".into(),
        after: 0,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    let other = world.other_install_version(&signer.identity_doc().unwrap().unwrap(), [9; 16]);
    drop(signer);
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(other.signed()).unwrap());
    let mut signer = Signer::open(unsigned_404_for_apps(&world, store, 1), world.keyring())
        .await
        .unwrap();
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::NotNamed { install: [9; 16] }
    );
    assert_eq!(erase_requests(&world), 1);
}

/// `world`'s env, whose transport holds the first `POST /erase` back, answering nothing, and
/// passes everything else to the switch; `land` sends the held request on to the switch, as a
/// request delayed on the way lands late.
fn delayed_erasure(
    world: &World,
    store: Arc<MemoryStore>,
) -> (SignerEnv, impl Fn() + Send + Sync + 'static) {
    let switch = Arc::clone(&world.switch);
    let held = Arc::new(std::sync::Mutex::new(None));
    let holding = Arc::clone(&held);
    let first = Arc::new(std::sync::Mutex::new(true));
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if request.method == "POST" && request.path_and_query.ends_with("/erase") {
            let mut first = first.lock().unwrap();
            if *first {
                *first = false;
                *holding.lock().unwrap() = Some(request.clone());
                return Err(pubky_switch_client::TransportError::Timeout);
            }
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport;
    let switch = Arc::clone(&world.switch);
    let land = move || {
        let request = held.lock().unwrap().take().expect("a held request");
        let _ = switch.handle(&request);
    };
    (env, land)
}

/// A copy of `signer`'s install, as on a cloned device, delivers the next version at the switch
/// and writes the signer backup holding it: `signer`'s records are behind. Returns that version.
fn a_clone_delivers_and_backs_up(world: &World, signer: &Signer) -> IdentityDoc {
    a_clone_backs_up(world, signer, true)
}

/// As [`a_clone_delivers_and_backs_up`], the delivery made only if `delivers`: a clone writes
/// its backup first (Switch wire 3.13).
fn a_clone_backs_up(world: &World, signer: &Signer, delivers: bool) -> IdentityDoc {
    use pubky_switch_core::keys::IdentityKey;
    use pubky_switch_core::records::{SignerBackup, SignerRecords};
    let mark = signer.identity_doc().unwrap().unwrap();
    let next = world.other_install_version(&mark, signer.install_id());
    if delivers {
        world.switch.deliver_identity(&next).unwrap();
    }
    let held = world.backup();
    let records = SignerRecords::new(
        IdentityKey::from_secret(world.key.secret_bytes()),
        next.clone(),
        held.revoked_apps(),
        held.certs(),
        *held.limits(),
        held.bundle_parts(),
        Some(mark.hash()),
    )
    .unwrap();
    let backup = SignerBackup::seal(&world.key, &records).unwrap();
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, serde_json::to_vec(&backup).unwrap());
    next
}

#[tokio::test]
async fn test_erasure_records_behind_ends_once_a_new_install_takes_over() {
    // A request is in doubt; a clone of this install then delivers and backs up the next
    // version: records behind, the erasure kept, nothing sent. The user restores on a new
    // install, which takes over. This install's next run still reads the switch, finds the
    // new install signing, and ends its erasure without erasing (Switch spec 4.3, 12.7).
    let world = World::new();
    let (mut signer, id, _) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/erase".into(),
        after: 0,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    a_clone_delivers_and_backs_up(&world, &signer);
    assert!(matches!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::RecordsBehind { .. })
    ));
    assert_eq!(signer.status(), SignerStatus::Erasing);
    let sent = erase_requests(&world);
    let other = Signer::restore_new(
        world.env(Arc::new(MemoryStore::new())),
        world.keyring(),
        confirmed(),
    )
    .await
    .unwrap();
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::NotNamed {
            install: other.install_id()
        }
    );
    assert!(matches!(signer.status(), SignerStatus::ManagedBy { .. }));
    assert_eq!(erase_requests(&world), sent);
    assert!(!world.switch.erased());
    assert!(
        !signer
            .alerts()
            .contains(&Alert::GrantRevocationOwed { app_id: id })
    );
}

#[tokio::test]
async fn test_erasure_records_behind_its_own_clone_keeps_it_and_sends_nothing() {
    // The switch holds this install's own newer version, a clone's: records behind, the
    // erasure kept through every run, and nothing deleted or sent (Switch spec 4.3).
    let world = World::new();
    let (mut signer, _, _) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/erase".into(),
        after: 0,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    a_clone_delivers_and_backs_up(&world, &signer);
    let sent = erase_requests(&world);
    for _ in 0..3 {
        assert!(matches!(
            signer.resume().await.unwrap_err(),
            SignerError::Refused(Refusal::RecordsBehind { .. })
        ));
        assert_eq!(signer.status(), SignerStatus::Erasing);
    }
    assert_eq!(erase_requests(&world), sent);
    assert!(!world.switch.erased());
}

#[tokio::test]
async fn test_erasure_records_behind_in_doubt_ends_erased_on_the_404() {
    // A request is held on the way; a clone delivers: records behind, the erasure kept. The
    // held request then lands and erases the account. The next check's read gets the
    // operator's `404`, the request in doubt: erased, whatever this install's records say,
    // since no install can restore at an erased switch (Switch wire 7.4.16).
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    drop(signer);
    let (env, land) = delayed_erasure(&world, store);
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    signer.close_account(confirmed()).await.unwrap_err();
    a_clone_delivers_and_backs_up(&world, &signer);
    assert!(matches!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::RecordsBehind { .. })
    ));
    land();
    assert!(world.switch.erased());
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
}

#[tokio::test]
async fn test_erasure_records_behind_from_the_backup_alone_sends_nothing() {
    // A clone wrote the backup of its next version and hasn't delivered it yet: the switch
    // still holds the mark. Records behind from the backup alone keep the erasure, and the
    // read of the switch at the mark sends nothing either (Switch wire 3.13).
    let world = World::new();
    let (mut signer, _, _) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/erase".into(),
        after: 0,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    a_clone_backs_up(&world, &signer, false);
    let sent = erase_requests(&world);
    for _ in 0..2 {
        assert!(matches!(
            signer.resume().await.unwrap_err(),
            SignerError::Refused(Refusal::RecordsBehind { .. })
        ));
        assert_eq!(signer.status(), SignerStatus::Erasing);
    }
    assert_eq!(erase_requests(&world), sent);
}

#[tokio::test]
async fn test_erasure_records_behind_before_its_deletions_deletes_nothing() {
    // The erasure stopped before deleting anything; a clone then wrote the backup of its next
    // version. Records behind: the files stay, run after run, though the switch's read at the
    // mark passes (Switch wire 3.13).
    let world = World::new();
    let (mut signer, id, _) = with_an_app(&world).await;
    *world.homeserver.failing_puts.lock().unwrap() = true;
    signer.close_account(confirmed()).await.unwrap_err();
    *world.homeserver.failing_puts.lock().unwrap() = false;
    a_clone_backs_up(&world, &signer, false);
    for _ in 0..2 {
        assert!(matches!(
            signer.resume().await.unwrap_err(),
            SignerError::Refused(Refusal::RecordsBehind { .. })
        ));
    }
    assert!(world.published().is_some());
    assert!(world.homeserver.file(&app_record_path(&id)).is_some());
    assert_eq!(erase_requests(&world), 0);
}
