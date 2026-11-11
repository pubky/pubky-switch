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
