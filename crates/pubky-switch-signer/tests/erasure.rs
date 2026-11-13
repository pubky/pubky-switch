//! Erasing the identity's account against the scripted switch (Switch spec 12.7; Switch wire
//! 7.4.16): `identity.json` and the app records leave the Homeserver first, then the switch
//! erases the account; a lost answer, a failure and a refusal; and what the signer keeps and
//! refuses afterwards.

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use pubky_switch_client::clock::Clock;

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

/// How long every check meets the operator's `404` after a request in doubt before the
/// erasure is done (Switch wire 7.4.16, spec 12.7 step 5).
const ERASURE_CONFIRMATION_MS: u64 = 24 * 3_600_000;

/// After a request in doubt, the operator's `404`: the next run leaves the erasure erased
/// but unconfirmed, and the first run 24 hours on ends it erased (Switch wire 7.4.16).
async fn confirm_erasure(world: &World, signer: &mut Signer) {
    let error = signer.resume().await.unwrap_err();
    assert!(
        matches!(
            error,
            SignerError::Refused(Refusal::ErasureUnconfirmed { .. })
        ),
        "{error:?}"
    );
    assert!(matches!(
        signer.status(),
        SignerStatus::ErasedUnconfirmed { .. }
    ));
    world.clock.advance_ms(ERASURE_CONFIRMATION_MS);
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
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
    confirm_erasure(&world, &mut signer).await;
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
    confirm_erasure(&world, &mut signer).await;
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
    confirm_erasure(&world, &mut signer).await;
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
    // Unconfirmed for 24 hours, then the run that completes the erasure.
    assert!(matches!(
        signer.run_due().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { .. })
    ));
    world.clock.advance_ms(ERASURE_CONFIRMATION_MS);
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
    // Every check meets the intermediary's `404` for 24 hours: the erasure ends erased, the
    // stated residual, though the other install's account stays.
    let error = signer.resume().await.unwrap_err();
    assert!(
        matches!(
            error,
            SignerError::Refused(Refusal::ErasureUnconfirmed { .. })
        ),
        "{error:?}"
    );
    world.clock.advance_ms(ERASURE_CONFIRMATION_MS);
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
    confirm_erasure(&world, &mut signer).await;
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
    confirm_erasure(&world, &mut signer).await;
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

#[tokio::test]
async fn test_erasure_held_request_landing_after_a_passing_rollback_erases_with_the_alarm_held() {
    // A request is held on the way; the switch then answers, signed, that it holds no copy:
    // the rollback alarm keeps the erasure. The switch goes back to the mark it held all
    // along, and the held request, naming that mark, lands and erases. The next check meets
    // the operator's `404` after the request in doubt: erased once it has held for 24 hours,
    // the alarm still held. Clearing it then only removes it: nothing is sent, and no alert
    // is raised for an account the switch doesn't host.
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    let mark = signer.identity_doc().unwrap().unwrap();
    drop(signer);
    let switch = Arc::clone(&world.switch);
    let held = Arc::new(std::sync::Mutex::new(None));
    let holding = Arc::clone(&held);
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if request.method == "POST"
            && request.path_and_query.ends_with("/erase")
            && holding.lock().unwrap().is_none()
        {
            *holding.lock().unwrap() = Some(request.clone());
            return Err(pubky_switch_client::TransportError::Timeout);
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport.clone();
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    signer.close_account(confirmed()).await.unwrap_err();
    world.switch.lose_identity();
    let SignerError::Alarm(alert) = signer.resume().await.unwrap_err() else {
        panic!("an alarm")
    };
    assert!(
        matches!(alert, Alert::Rollback { version: None, .. }),
        "{alert:?}"
    );
    world.switch.deliver_identity(&mark).unwrap();
    let request = held.lock().unwrap().clone().expect("a held request");
    let _ = world.switch.handle(&request);
    assert!(
        world.switch.erased(),
        "the held request names the mark the switch holds"
    );
    let error = signer.resume().await.unwrap_err();
    assert!(
        matches!(
            error,
            SignerError::Refused(Refusal::ErasureUnconfirmed { .. })
        ),
        "{error:?}"
    );
    world.clock.advance_ms(ERASURE_CONFIRMATION_MS);
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
    assert!(signer.alerts().contains(&alert));
    let before = transport.requests().len();
    signer.clear_alert(&alert).await.unwrap();
    assert!(!signer.alerts().contains(&alert));
    assert!(!signer.alerts().contains(&Alert::AccountNotHosted));
    for _ in 0..3 {
        signer.resume().await.unwrap();
    }
    assert_eq!(transport.requests().len(), before, "nothing sent");
}

/// A copy of `signer`'s install, as on a cloned device, delivers the next version at the switch
/// and writes the signer backup holding it: `signer`'s records are behind. Returns that version.
fn a_clone_delivers_and_backs_up(world: &World, signer: &Signer) -> IdentityDoc {
    a_clone_backs_up(world, signer, true)
}

/// As [`a_clone_delivers_and_backs_up`], the delivery made only if `delivers`: a clone writes
/// its backup first (Switch wire 3.13).
fn a_clone_backs_up(world: &World, signer: &Signer, delivers: bool) -> IdentityDoc {
    let mark = signer.identity_doc().unwrap().unwrap();
    a_clone_signs_on(world, &mark, signer.install_id(), delivers)
}

/// A clone of `install` signs the version after `on`: its backup written, then, if `delivers`,
/// its delivery made.
fn a_clone_signs_on(
    world: &World,
    on: &IdentityDoc,
    install: [u8; 16],
    delivers: bool,
) -> IdentityDoc {
    use pubky_switch_core::keys::IdentityKey;
    use pubky_switch_core::records::{SignerBackup, SignerRecords};
    let next = world.other_install_version(on, install);
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
        Some(on.hash()),
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
async fn test_erasure_held_request_landing_after_a_clone_delivered_erases_nothing() {
    // A request is held on the way; a clone delivers: records behind, the erasure kept. The
    // held request then lands, naming the mark it followed: the switch holds the clone's
    // version, so it refuses it and erases nothing (Switch wire 7.4.16). The erasure stays
    // kept with the records behind, and the way out is a restore.
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
    assert!(!world.switch.erased());
    assert!(matches!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::RecordsBehind { .. })
    ));
    assert_eq!(signer.status(), SignerStatus::Erasing);
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

#[tokio::test]
async fn test_erasure_in_doubt_ends_erased_though_the_clone_published() {
    // A clone writes the backup of its next version and publishes it on the Homeserver
    // without delivering it: records behind. The held request lands, the switch still holding
    // the mark it names, and erases. This install's own copy on the Homeserver isn't another
    // install, and the `404` ends the erasure (Switch wire 7.4.16).
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    drop(signer);
    let (env, land) = delayed_erasure(&world, store);
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    signer.close_account(confirmed()).await.unwrap_err();
    let next = a_clone_backs_up(&world, &signer, false);
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(next.signed()).unwrap());
    assert!(matches!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::RecordsBehind { .. })
    ));
    land();
    assert!(world.switch.erased());
    confirm_erasure(&world, &mut signer).await;
}

#[tokio::test]
async fn test_erasure_in_doubt_ends_erased_though_the_clone_signed_again() {
    // The clone signs once, records behind, then again, delivering neither: its backup holds
    // a version above any this install has seen. The held request lands, the switch still
    // holding the mark, and the first run after ends the erasure on the `404` (Switch wire
    // 7.4.16).
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    drop(signer);
    let (env, land) = delayed_erasure(&world, store);
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    signer.close_account(confirmed()).await.unwrap_err();
    let next = a_clone_backs_up(&world, &signer, false);
    assert!(matches!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::RecordsBehind { .. })
    ));
    a_clone_signs_on(&world, &next, signer.install_id(), false);
    land();
    assert!(world.switch.erased());
    confirm_erasure(&world, &mut signer).await;
}

#[tokio::test]
async fn test_erasure_in_doubt_404_ends_it_only_after_24_hours() {
    // The request lands and its answer is lost. The next run meets the operator's `404`:
    // erased but unconfirmed, the time kept through a restart, the erasure still not to be
    // aborted. A run 23 hours on changes nothing; the first run 24 hours after the first
    // `404` ends it erased (Switch wire 7.4.16, spec 12.7 step 5).
    let world = World::new();
    let (mut signer, _, store) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/erase".into(),
    });
    signer.close_account(confirmed()).await.unwrap_err();
    assert!(world.switch.erased());
    let first = world.clock.now_ms();
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { since_ms: first })
    );
    assert_eq!(
        signer.status(),
        SignerStatus::ErasedUnconfirmed { since_ms: first }
    );
    assert_eq!(
        signer.abort_erasure().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnanswered)
    );
    drop(signer);
    world.clock.advance_ms(23 * 3_600_000);
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { since_ms: first })
    );
    world.clock.advance_ms(3_600_000);
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
    assert_eq!(erase_requests(&world), 1);
}

#[tokio::test]
async fn test_erasure_signed_answer_ends_the_wait_and_the_request_goes_again() {
    // The request never reached the switch, and an intermediary answers the checks `404`:
    // erased but unconfirmed. Once the switch answers again, signed, the wait ends: the
    // account is there, and the erasure goes on with its request, the same body, naming the
    // mark; it lands (Switch wire 7.4.16).
    use std::sync::atomic::{AtomicBool, Ordering};
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    let mark = signer.identity_doc().unwrap().unwrap();
    drop(signer);
    let intermediary = Arc::new(AtomicBool::new(false));
    let answering = Arc::clone(&intermediary);
    let switch = Arc::clone(&world.switch);
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if answering.load(Ordering::SeqCst)
            && request.method == "GET"
            && request.path_and_query.ends_with("/apps")
        {
            return Ok(Response {
                status: 404,
                headers: Vec::new(),
                body: b"{}".to_vec(),
            });
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport.clone();
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/erase".into(),
        after: 0,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    assert!(!world.switch.erased());
    intermediary.store(true, Ordering::SeqCst);
    assert!(matches!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { .. })
    ));
    intermediary.store(false, Ordering::SeqCst);
    // The signed check ends the wait; the request it sends again goes unanswered.
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/erase".into(),
        after: 0,
    });
    signer.resume().await.unwrap_err();
    assert_eq!(signer.status(), SignerStatus::Erasing);
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
    assert!(world.switch.erased());
    let bodies: Vec<_> = transport
        .requests()
        .into_iter()
        .filter(|r| r.method == "POST" && r.path_and_query.ends_with("/erase"))
        .map(|r| r.body)
        .collect();
    assert_eq!(bodies.len(), 3);
    assert!(bodies.iter().all(|body| *body == bodies[0]));
    let sent = pubky_switch_core::http::parse_erase_body(&bodies[0]).unwrap();
    assert_eq!(sent.identity_hash, Some(mark.hash()));
}

#[tokio::test]
async fn test_erasure_clock_set_back_starts_the_wait_again() {
    // Erased but unconfirmed since a time the device clock is then set back before: the wait
    // starts again from the clock's time, and ends 24 hours after it (Switch wire 7.4.16).
    let world = World::new();
    let (mut signer, _, _) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/erase".into(),
    });
    signer.close_account(confirmed()).await.unwrap_err();
    let first = world.clock.now_ms();
    signer.resume().await.unwrap_err();
    world.clock.set_ms(first - 3_600_000);
    let again = world.clock.now_ms();
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { since_ms: again })
    );
    world.clock.set_ms(again + ERASURE_CONFIRMATION_MS - 1);
    assert!(matches!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { .. })
    ));
    world.clock.set_ms(again + ERASURE_CONFIRMATION_MS);
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
}

#[tokio::test]
async fn test_erasure_unconfirmed_refuses_revocations() {
    // While the erasure waits for the `404` to hold, a revocation is refused, sending
    // nothing: it would need the switch, which doesn't answer (spec 12.7 step 5).
    let world = World::new();
    let (mut signer, id, _) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/erase".into(),
    });
    signer.close_account(confirmed()).await.unwrap_err();
    signer.resume().await.unwrap_err();
    let before = world.transport.requests().len();
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(
        world.transport.requests()[before..]
            .iter()
            .all(|r| r.method == "GET"),
        "nothing sent but reads"
    );
    assert!(matches!(
        signer.status(),
        SignerStatus::ErasedUnconfirmed { .. }
    ));
}

#[tokio::test]
async fn test_erasure_retry_meeting_the_404_waits_24_hours_too() {
    // The first request is held on the way; the next check is signed, so the request goes
    // again, and the held one lands just before it: the retry itself gets the operator's
    // `404`. That too is only how a landed erasure looks: erased but unconfirmed, then erased
    // 24 hours on (Switch wire 7.4.16).
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    drop(signer);
    let switch = Arc::clone(&world.switch);
    let held = Arc::new(std::sync::Mutex::new(None));
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if request.method == "POST" && request.path_and_query.ends_with("/erase") {
            let mut held = held.lock().unwrap();
            match held.take() {
                // The first: held, and its answer never comes.
                None if !switch.erased() && held.is_none() => {
                    *held = Some(request.clone());
                    return Err(pubky_switch_client::TransportError::Timeout);
                }
                // The retry: the held request lands first.
                Some(first) => {
                    let _ = switch.handle(&first);
                }
                None => {}
            }
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport;
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    signer.close_account(confirmed()).await.unwrap_err();
    assert!(!world.switch.erased());
    let error = signer.resume().await.unwrap_err();
    assert!(
        matches!(
            error,
            SignerError::Refused(Refusal::ErasureUnconfirmed { .. })
        ),
        "{error:?}"
    );
    assert!(world.switch.erased());
    world.clock.advance_ms(ERASURE_CONFIRMATION_MS);
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
}

#[tokio::test]
async fn test_erasure_unsigned_404_with_nothing_in_doubt_raises_account_not_hosted() {
    // With no erasure of its own in progress, an unsigned `404` to `GET /apps` raises the
    // alert and changes nothing else: the records, the switch's account and the Homeserver's
    // files stay, and only reads go out. The first signed answer clears it (Switch wire
    // 7.3 step 2, 7.4.16).
    let world = World::new();
    let (signer, id, store) = with_an_app(&world).await;
    let mark = signer.identity_doc().unwrap().unwrap();
    drop(signer);
    let (env, transport, unsigned) = apps_answers(&world, store);
    *unsigned.lock().unwrap() = Some(404);
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    let error = signer.run_due().await.unwrap_err();
    assert!(
        matches!(
            error,
            SignerError::Switch(pubky_switch_client::ClientError::BadServiceSignature {
                status: 404
            })
        ),
        "{error:?}"
    );
    assert!(signer.alerts().contains(&Alert::AccountNotHosted));
    assert_eq!(signer.status(), SignerStatus::Signing);
    assert_eq!(signer.identity_doc().unwrap().unwrap(), mark);
    assert!(!world.switch.erased());
    assert!(world.homeserver.file(IDENTITY_PATH).is_some());
    assert!(world.homeserver.file(&app_record_path(&id)).is_some());
    let sent = transport.requests();
    assert!(!sent.is_empty());
    assert!(sent.iter().all(|r| r.method == "GET"), "only reads");
    *unsigned.lock().unwrap() = None;
    signer.run_due().await.unwrap();
    assert!(!signer.alerts().contains(&Alert::AccountNotHosted));
}

#[tokio::test]
async fn test_erasure_in_doubt_ending_erased_raises_no_account_not_hosted() {
    // The erasure's own request in doubt: the `404` that follows ends it erased, and the
    // alert for an account the switch doesn't host isn't raised (Switch wire 7.4.16).
    let world = World::new();
    let (mut signer, _, _) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/erase".into(),
    });
    signer.close_account(confirmed()).await.unwrap_err();
    assert!(world.switch.erased());
    confirm_erasure(&world, &mut signer).await;
    assert!(!signer.alerts().contains(&Alert::AccountNotHosted));
}

/// `world`'s env, whose transport answers `GET /apps` number `nth`, counted from 1, with an
/// unsigned answer of `status`, as an intermediary could, and passes everything else to the
/// switch. Returns the env and the transport, which keeps every request.
/// An environment whose every `GET /apps` gets an unsigned answer with the status the
/// returned cell holds, while it holds one; the switch answers the rest.
fn apps_answers(
    world: &World,
    store: Arc<MemoryStore>,
) -> (
    SignerEnv,
    Arc<MockTransport>,
    Arc<std::sync::Mutex<Option<u16>>>,
) {
    let switch = Arc::clone(&world.switch);
    let unsigned = Arc::new(std::sync::Mutex::new(None));
    let status = Arc::clone(&unsigned);
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        let held = *status.lock().unwrap();
        if request.method == "GET"
            && request.path_and_query.ends_with("/apps")
            && let Some(status) = held
        {
            return Ok(Response {
                status,
                headers: Vec::new(),
                body: b"{}".to_vec(),
            });
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport.clone();
    (env, transport, unsigned)
}

fn nth_apps_answer(
    world: &World,
    store: Arc<MemoryStore>,
    nth: usize,
    status: u16,
) -> (SignerEnv, Arc<MockTransport>) {
    let switch = Arc::clone(&world.switch);
    let seen = Arc::new(std::sync::Mutex::new(0usize));
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if request.method == "GET" && request.path_and_query.ends_with("/apps") {
            let mut seen = seen.lock().unwrap();
            *seen += 1;
            if *seen == nth {
                return Ok(Response {
                    status,
                    headers: Vec::new(),
                    body: b"{}".to_vec(),
                });
            }
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport.clone();
    (env, transport)
}

#[tokio::test]
async fn test_erasure_account_not_hosted_keeps_a_delivery_in_progress() {
    // A new version's delivery is in progress; the backup is missing, so the backup write
    // reads the switch, and that read gets the unsigned `404`. The alert's commit keeps the
    // delivery, and a later run delivers the version and clears the alert.
    let world = World::new();
    let (signer, store) = world.enrolled().await;
    drop(signer);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    // `GET /apps` 1 is the change's own check, 2 the backup write's.
    let (env, _) = nth_apps_answer(&world, store.clone(), 2, 404);
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    signer.set_record_max_age(Some(60)).await.unwrap_err();
    assert!(signer.alerts().contains(&Alert::AccountNotHosted));
    drop(signer);
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    signer.resume().await.unwrap();
    assert_eq!(
        world.switch.identity_doc().unwrap().body().record_max_age,
        Some(60)
    );
    assert!(!signer.alerts().contains(&Alert::AccountNotHosted));
}

#[tokio::test]
async fn test_erasure_unsigned_503_raises_no_account_not_hosted() {
    // A gateway's unsigned `503` to `GET /apps` says nothing of the account: no alert.
    let world = World::new();
    let (signer, store) = world.enrolled().await;
    drop(signer);
    let (env, _) = nth_apps_answer(&world, store, 1, 503);
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    signer.run_due().await.unwrap_err();
    assert!(!signer.alerts().contains(&Alert::AccountNotHosted));
}

#[tokio::test]
async fn test_erasure_signed_404_raises_no_account_not_hosted() {
    // A `404` the pinned key signs is the switch's own answer, not one for an account it
    // doesn't host: no alert.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    world.switch.fail_next(SwitchFault::Error {
        path: "/apps".into(),
        code: ErrorCode::NotFound,
        current: serde_json::Value::Null,
    });
    signer.run_due().await.unwrap_err();
    assert!(!signer.alerts().contains(&Alert::AccountNotHosted));
}

#[tokio::test]
async fn test_erasure_ended_through_an_equivocation_clearing_it_delivers_nothing() {
    // The account ends erased while the Homeserver's equivocation is still held. Clearing
    // that alert only removes it: no delivery again, no republication, no read, and every
    // later run has nothing left to do (Switch spec 12.7).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/erase".into(),
    });
    signer.close_account(confirmed()).await.unwrap_err();
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
    world.homeserver.files.lock().unwrap().remove(IDENTITY_PATH);
    confirm_erasure(&world, &mut signer).await;
    let before = world.transport.requests().len();
    signer.clear_alert(&alert).await.unwrap();
    assert!(!signer.alerts().contains(&alert));
    for _ in 0..3 {
        signer.resume().await.unwrap();
    }
    assert_eq!(world.transport.requests().len(), before, "nothing sent");
    assert!(
        world.homeserver.file(IDENTITY_PATH).is_none(),
        "nothing published"
    );
}

#[tokio::test]
async fn test_erasure_held_request_landing_during_a_rollback_erases_nothing() {
    // A request is held on the way; the switch then answers, signed, that it holds no copy:
    // the rollback alarm keeps the erasure. The held request lands: it names the mark, which
    // the switch no longer holds, so it is refused and erases nothing. The erasure stays,
    // with the alarm, and no alert for an account the switch doesn't host is raised (Switch
    // wire 7.4.16, spec 4.3).
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    drop(signer);
    let (env, land) = delayed_erasure(&world, store);
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    signer.close_account(confirmed()).await.unwrap_err();
    world.switch.lose_identity();
    let SignerError::Alarm(alert) = signer.resume().await.unwrap_err() else {
        panic!("an alarm")
    };
    land();
    assert!(!world.switch.erased());
    assert!(matches!(
        signer.resume().await.unwrap_err(),
        SignerError::Alarm(_)
    ));
    assert_eq!(signer.status(), SignerStatus::Erasing);
    assert!(signer.alerts().contains(&alert));
    assert!(!signer.alerts().contains(&Alert::AccountNotHosted));
}

/// Call `$call` on an install whose store is `$store`, and check that it answers `$answer`,
/// writes nothing to the Homeserver, sends no request but reads when `$reads` (none at all
/// otherwise), and leaves no flow stored.
macro_rules! check_call {
    ($world:expr, $store:expr, $identity:expr, $reads:expr, $name:expr, $answer:pat, $call:expr) => {{
        use pubky_switch_client::store::StateStore;
        let requests = $world.transport.requests().len();
        let files = $world.homeserver.files.lock().unwrap().clone();
        let answer = $call.map(drop);
        assert!(matches!(answer, $answer), "{}: {answer:?}", $name);
        let sent = $world.transport.requests()[requests..].to_vec();
        if $reads {
            assert!(
                sent.iter().all(|r| r.method == "GET"),
                "{} wrote at the switch",
                $name
            );
        } else {
            assert!(sent.is_empty(), "{} sent", $name);
        }
        assert!(
            *$world.homeserver.files.lock().unwrap() == files,
            "{} wrote",
            $name
        );
        let ns = pubky_switch_signer::state::signer_namespace(&$identity);
        assert!(
            $store.get(&ns, b"flow").unwrap().is_none(),
            "{}: a flow stored",
            $name
        );
        answer
    }};
}

#[tokio::test]
async fn test_erasure_erased_install_sends_nothing_whatever_is_called() {
    // Every public call on an erased install: it refuses with `Erased`, refuses for a reason
    // its arguments give, or does only local work. None sends a request, writes the
    // Homeserver, or stores a flow (Switch spec 12.7).
    use pubky_switch_signer::CertChange;
    let world = World::new();
    let (mut signer, id, store) = with_an_app(&world).await;
    let removed = App::with_keys(
        AppKeys::from_secrets([5; 32], [6; 32]),
        &["notes"],
        None,
        [10; 32],
    );
    world.approve(&mut signer, &removed).await;
    let removed = removed.keys.app_id_bytes();
    signer.revoke(removed, None, confirmed()).await.unwrap();
    // An approval whose claim the app hasn't confirmed yet: still held.
    let pending = App::with_keys(
        AppKeys::from_secrets([11; 32], [12; 32]),
        &["notes"],
        None,
        [13; 32],
    );
    let review = signer.review(&pending.request, &pending.auth).unwrap();
    let held = signer.approve(review).await.unwrap().request;
    signer.close_account(confirmed()).await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
    let identity = signer.identity();
    let alert = signer.alerts().first().cloned().expect("a reminder");
    let app = App::new(&["notes"], None, [8; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let erased = |name: &str, answer: Result<(), SignerError>| {
        assert!(
            matches!(answer, Err(SignerError::Refused(Refusal::Erased))),
            "{name}: {answer:?}"
        );
    };
    macro_rules! check {
        ($name:expr, erased, $call:expr) => {
            erased(
                $name,
                check_call!(world, store, identity, false, $name, _, $call),
            )
        };
        ($name:expr, $answer:pat, $call:expr) => {
            drop(check_call!(
                world, store, identity, false, $name, $answer, $call
            ))
        };
    }
    check!("resume", Ok(()), signer.resume().await);
    check!("clear_alert", Ok(()), signer.clear_alert(&alert).await);
    check!(
        "set_record_max_age",
        erased,
        signer.set_record_max_age(Some(60)).await
    );
    check!(
        "set_connect_requests",
        erased,
        signer.set_connect_requests(Default::default()).await
    );
    check!(
        "renew",
        erased,
        signer.renew(id, CertChange::default()).await
    );
    check!(
        "complete_renewals",
        Ok(()),
        signer.complete_renewals().await
    );
    check!("run_due", erased, signer.run_due().await);
    check!("renew_expiring", erased, signer.renew_expiring().await);
    check!("restore", erased, signer.restore(confirmed()).await);
    check!(
        "hand_over_to",
        erased,
        signer.hand_over_to(id, confirmed()).await
    );
    check!(
        "abort_hand_over",
        erased,
        signer.abort_hand_over(confirmed()).await
    );
    check!("take_back", erased, signer.take_back(confirmed()).await);
    check!("revoke", erased, signer.revoke(id, None, confirmed()).await);
    check!(
        "complete_removals",
        erased,
        signer.complete_removals().await
    );
    check!("purge_removed", erased, signer.purge_removed(removed).await);
    check!(
        "purge_removed, not removed",
        Err(SignerError::Refused(Refusal::NotRemoved)),
        signer.purge_removed(id).await
    );
    check!(
        "serve_full_bundles",
        erased,
        signer.serve_full_bundles().await
    );
    check!(
        "close_account",
        erased,
        signer.close_account(confirmed()).await
    );
    check!(
        "abort_erasure",
        Err(SignerError::Refused(Refusal::NotErasing)),
        signer.abort_erasure().await
    );
    check!("approve", erased, signer.approve(review).await);
    // The one local commit: the held claim is forgotten once the app has it. The erasure
    // unpublished the version, so `approved` shows none; the stored records change.
    let stored = || {
        use pubky_switch_client::store::StateStore;
        let ns = pubky_switch_signer::state::signer_namespace(&identity);
        store.get(&ns, b"state").unwrap()
    };
    let before = stored();
    check!(
        "claim_delivered",
        Ok(()),
        signer.claim_delivered(&held).await
    );
    assert_ne!(stored(), before, "the held claim forgotten");
    let before = stored();
    check!(
        "claim_delivered, again",
        Ok(()),
        signer.claim_delivered(&held).await
    );
    assert_eq!(stored(), before, "nothing more to forget");
    assert_eq!(signer.status(), SignerStatus::Erased);
}

#[tokio::test]
async fn test_erasure_records_behind_or_another_install_named_stores_no_flow() {
    // An install whose records are behind a clone's newer version, and one another install
    // took over from: every public call refuses with that state, refuses for a reason its
    // arguments give, or only reads; none writes at the switch or the Homeserver or stores a
    // flow. Only a restore, the way out, signs again (Switch spec 4.3, wire 3.13).
    use pubky_switch_signer::CertChange;
    for behind in [true, false] {
        let world = World::new();
        let (mut signer, id, store) = with_an_app(&world).await;
        let removed = App::with_keys(
            AppKeys::from_secrets([5; 32], [6; 32]),
            &["notes"],
            None,
            [10; 32],
        );
        world.approve(&mut signer, &removed).await;
        let removed = removed.keys.app_id_bytes();
        signer.revoke(removed, None, confirmed()).await.unwrap();
        if behind {
            a_clone_delivers_and_backs_up(&world, &signer);
        } else {
            Signer::restore_new(
                world.env(Arc::new(MemoryStore::new())),
                world.keyring(),
                confirmed(),
            )
            .await
            .unwrap();
        }
        // The next check finds the state.
        signer.set_record_max_age(Some(60)).await.unwrap_err();
        if behind {
            assert!(matches!(
                signer.status(),
                SignerStatus::RecordsBehind { .. }
            ));
        } else {
            assert!(matches!(signer.status(), SignerStatus::ManagedBy { .. }));
        }
        let identity = signer.identity();
        let alert = signer.alerts().first().cloned().expect("a reminder");
        let app = App::new(&["notes"], None, [8; 32]);
        let review = signer.review(&app.request, &app.auth).unwrap();
        let refused = |name: &str, answer: Result<(), SignerError>| {
            let ok = if behind {
                matches!(
                    answer,
                    Err(SignerError::Refused(Refusal::RecordsBehind { .. }))
                )
            } else {
                matches!(answer, Err(SignerError::NotNamed { .. }))
            };
            assert!(ok, "{name}: {answer:?}");
        };
        macro_rules! check {
            ($name:expr, state, $call:expr) => {
                refused(
                    $name,
                    check_call!(world, store, identity, true, $name, _, $call),
                )
            };
            ($name:expr, $answer:pat, $call:expr) => {
                drop(check_call!(
                    world, store, identity, true, $name, $answer, $call
                ))
            };
        }
        check!("resume", Ok(()), signer.resume().await);
        check!("clear_alert", Ok(()), signer.clear_alert(&alert).await);
        check!(
            "set_record_max_age",
            state,
            signer.set_record_max_age(Some(60)).await
        );
        check!(
            "set_connect_requests",
            state,
            signer.set_connect_requests(Default::default()).await
        );
        check!(
            "renew",
            state,
            signer.renew(id, CertChange::default()).await
        );
        check!(
            "complete_renewals",
            Ok(()),
            signer.complete_renewals().await
        );
        check!("run_due", state, signer.run_due().await);
        check!("renew_expiring", state, signer.renew_expiring().await);
        check!(
            "hand_over_to",
            state,
            signer.hand_over_to(id, confirmed()).await
        );
        check!(
            "abort_hand_over",
            state,
            signer.abort_hand_over(confirmed()).await
        );
        check!("take_back", state, signer.take_back(confirmed()).await);
        check!("revoke", state, signer.revoke(id, None, confirmed()).await);
        check!("complete_removals", state, signer.complete_removals().await);
        check!("purge_removed", state, signer.purge_removed(removed).await);
        check!(
            "purge_removed, not removed",
            Err(SignerError::Refused(Refusal::NotRemoved)),
            signer.purge_removed(id).await
        );
        check!(
            "serve_full_bundles",
            state,
            signer.serve_full_bundles().await
        );
        check!(
            "close_account",
            state,
            signer.close_account(confirmed()).await
        );
        check!(
            "abort_erasure",
            Err(SignerError::Refused(Refusal::NotErasing)),
            signer.abort_erasure().await
        );
        check!("approve", state, signer.approve(review).await);
        check!(
            "claim_delivered",
            Ok(()),
            signer.claim_delivered(&[0; 32]).await
        );
        // The way out signs again.
        signer.restore(confirmed()).await.unwrap();
        assert_eq!(signer.status(), SignerStatus::Signing);
    }
}

#[tokio::test]
async fn test_erasure_records_behind_clearing_the_alarm_leaves_no_delivery() {
    // An alarm is held, then a clone delivers and backs up the next version: records behind.
    // Clearing the alarm removes it and delivers nothing, since the delivery could never go;
    // the in-place restore then takes the clone's records (Switch spec 4.3, wire 3.13).
    let world = World::new();
    let (mut signer, store, alert) = alarm_then_records_behind(&world).await;
    signer.clear_alert(&alert).await.unwrap();
    assert!(!signer.alerts().contains(&alert));
    let mut reopened = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    reopened.restore(confirmed()).await.unwrap();
    assert_eq!(reopened.status(), SignerStatus::Signing);
}

#[tokio::test]
async fn test_erasure_records_behind_after_the_clone_published_clearing_then_restore() {
    // As above, and the clone published its version over the other body, as a clone does:
    // clearing the alarm delivers nothing, and the restore then takes the clone's records.
    let world = World::new();
    let (mut signer, store, alert) = alarm_then_records_behind(&world).await;
    let v2 = world.switch.identity_doc().unwrap();
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(v2.signed()).unwrap());
    signer.clear_alert(&alert).await.unwrap();
    let mut reopened = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    reopened.run_due().await.unwrap_err();
    reopened.restore(confirmed()).await.unwrap();
    assert_eq!(reopened.status(), SignerStatus::Signing);
}

/// An install holding a Homeserver equivocation alarm, the switch unconfirmed, whose records
/// are then found behind a clone's newer version, with no flow.
async fn alarm_then_records_behind(world: &World) -> (Signer, Arc<MemoryStore>, Alert) {
    let (mut signer, store) = world.enrolled().await;
    let mine = signer.identity_doc().unwrap().unwrap();
    let mut body = mine.body().clone();
    body.record_max_age = Some(1);
    let other = IdentityDoc::sign(&world.key, body).unwrap();
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(other.signed()).unwrap());
    let SignerError::Alarm(alert) = signer.set_record_max_age(Some(5)).await.unwrap_err() else {
        panic!("an alarm")
    };
    a_clone_delivers_and_backs_up(world, &signer);
    let error = signer.set_record_max_age(Some(5)).await.unwrap_err();
    assert!(
        matches!(error, SignerError::Refused(Refusal::RecordsBehind { .. })),
        "{error:?}"
    );
    assert!(signer.alerts().contains(&alert));
    (signer, store, alert)
}

#[tokio::test]
async fn test_erasure_account_not_hosted_outlasts_an_unsigned_answer_and_clears_on_a_signed_one() {
    // Raised by an unsigned `404`, the alert outlasts an unsigned `503`, which says nothing of
    // the account. Any answer the pinned key signs clears it, a signed error included: the
    // account is hosted (Switch wire 7.3 step 2).
    let world = World::new();
    let (signer, store) = world.enrolled().await;
    drop(signer);
    let (env, _, unsigned) = apps_answers(&world, store);
    *unsigned.lock().unwrap() = Some(404);
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    signer.run_due().await.unwrap_err();
    assert!(signer.alerts().contains(&Alert::AccountNotHosted));
    *unsigned.lock().unwrap() = Some(503);
    signer.run_due().await.unwrap_err();
    assert!(
        signer.alerts().contains(&Alert::AccountNotHosted),
        "an unsigned 503 clears nothing"
    );
    *unsigned.lock().unwrap() = None;
    world.switch.fail_next(SwitchFault::Error {
        path: "/apps".into(),
        code: ErrorCode::NotFound,
        current: serde_json::Value::Null,
    });
    signer.run_due().await.unwrap_err();
    assert!(
        !signer.alerts().contains(&Alert::AccountNotHosted),
        "a signed error clears it"
    );
}

#[tokio::test]
async fn test_erasure_flow_stored_on_an_erased_install_is_never_loaded() {
    // An earlier version could store a delivery on an erased install, which could never go.
    // The flow is left out when the records load: the reopened install is erased, resumes
    // nothing, and sends nothing (Switch spec 12.7).
    use pubky_switch_client::store::{StateStore, WriteBatch};
    use pubky_switch_signer::state::signer_namespace;
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let ns = signer_namespace(&signer.identity());
    // A delivery in progress, its answer not come: its flow as stored.
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    signer.set_record_max_age(Some(60)).await.unwrap_err();
    let flow = store.get(&ns, b"flow").unwrap().expect("a delivery stored");
    signer.resume().await.unwrap();
    signer.close_account(confirmed()).await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
    drop(signer);
    let mut batch = WriteBatch::new();
    batch.put(&ns, b"flow", flow).unwrap();
    store.commit(batch).unwrap();
    let before = world.transport.requests().len();
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
    signer.resume().await.unwrap();
    assert_eq!(world.transport.requests().len(), before, "nothing sent");
}

#[tokio::test]
async fn test_erasure_after_a_take_over_between_check_and_request_erases_nothing() {
    // The signer checks the copies, then another install delivers the next version before
    // the erasure request reaches the switch. The request names the mark it followed: the
    // switch refuses it, signed, and erases nothing. The signer reads the switch's copy, finds
    // the other install named, and ends the erasure without erasing (Switch wire 7.4.16,
    // spec 4.3).
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    let mark = signer.identity_doc().unwrap().unwrap();
    drop(signer);
    let other = world.other_install_version(&mark, [9; 16]);
    let switch = Arc::clone(&world.switch);
    let first = Arc::new(std::sync::Mutex::new(true));
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if request.method == "POST" && request.path_and_query.ends_with("/erase") {
            let mut first = first.lock().unwrap();
            if *first {
                *first = false;
                switch.deliver_identity(&other).unwrap();
            }
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport;
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    let error = signer.close_account(confirmed()).await.unwrap_err();
    assert_eq!(
        error,
        SignerError::NotNamed { install: [9; 16] },
        "{error:?}"
    );
    assert!(!world.switch.erased());
    assert!(matches!(signer.status(), SignerStatus::ManagedBy { .. }));
}

#[tokio::test]
async fn test_erasure_refused_while_the_switch_holds_the_mark_ends_it() {
    // A `409` to the request while the switch still holds this install's mark: a refusal
    // signed with the account's key, so nothing landed. The copy checks out, the erasure ends
    // refused, and the user may ask again (Switch wire 7.4.16).
    let world = World::new();
    let (mut signer, _, _) = with_an_app(&world).await;
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
    signer.close_account(confirmed()).await.unwrap();
    assert!(world.switch.erased());
}

#[tokio::test]
async fn test_erasure_retry_after_doubt_names_the_mark_so_a_take_over_meanwhile_erases_nothing() {
    // The first request is lost before the switch (in doubt, not landed). The next run checks
    // the copies, then another install delivers before the retry reaches the switch. The retry
    // names the same mark: refused, signed, and the signer finds the other install named.
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    let mark = signer.identity_doc().unwrap().unwrap();
    drop(signer);
    let other = world.other_install_version(&mark, [9; 16]);
    let switch = Arc::clone(&world.switch);
    let count = Arc::new(std::sync::Mutex::new(0));
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if request.method == "POST" && request.path_and_query.ends_with("/erase") {
            let mut count = count.lock().unwrap();
            *count += 1;
            if *count == 1 {
                return Err(pubky_switch_client::TransportError::Timeout);
            }
            if *count == 2 {
                switch.deliver_identity(&other).unwrap();
            }
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport;
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    signer.close_account(confirmed()).await.unwrap_err();
    assert_eq!(signer.status(), SignerStatus::Erasing);
    let error = signer.resume().await.unwrap_err();
    assert_eq!(
        error,
        SignerError::NotNamed { install: [9; 16] },
        "{error:?}"
    );
    assert!(
        !world.switch.erased(),
        "the retry erased the take-over's account"
    );
    assert!(matches!(signer.status(), SignerStatus::ManagedBy { .. }));
}

#[tokio::test]
async fn test_erasure_unsigned_409_after_a_forwarded_request_keeps_it_in_doubt() {
    // A proxy forwards the request, which erases, and answers an unsigned `409`: that isn't
    // the switch's refusal, so the request stays in doubt, the erasure can't be aborted, and
    // the next run's `404` finds it erased once it has held for 24 hours (wire 7.4.16).
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    drop(signer);
    let switch = Arc::clone(&world.switch);
    let first = Arc::new(std::sync::Mutex::new(true));
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if request.method == "POST" && request.path_and_query.ends_with("/erase") {
            let mut first = first.lock().unwrap();
            if *first {
                *first = false;
                let _ = switch.handle(request);
                return Ok(Response {
                    status: 409,
                    headers: Vec::new(),
                    body: br#"{"code":"conflict","message":"x"}"#.to_vec(),
                });
            }
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport;
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    assert_eq!(
        signer.close_account(confirmed()).await.unwrap_err(),
        SignerError::Switch(pubky_switch_client::ClientError::BadServiceSignature { status: 409 })
    );
    assert!(world.switch.erased());
    assert_eq!(
        signer.abort_erasure().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnanswered)
    );
    confirm_erasure(&world, &mut signer).await;
}

#[tokio::test]
async fn test_erasure_signed_409_from_a_clone_delivery_keeps_the_erasure_abortable() {
    // A clone of this install delivers between the check and the request: the signed `409`
    // shows the request didn't land, the copy shows records behind, and the erasure is kept,
    // no longer in doubt, so the user may abort it (wire 7.4.16).
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    let mark = signer.identity_doc().unwrap().unwrap();
    let install = signer.install_id();
    drop(signer);
    let clone = world.other_install_version(&mark, install);
    let switch = Arc::clone(&world.switch);
    let first = Arc::new(std::sync::Mutex::new(true));
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if request.method == "POST" && request.path_and_query.ends_with("/erase") {
            let mut first = first.lock().unwrap();
            if *first {
                *first = false;
                switch.deliver_identity(&clone).unwrap();
            }
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport;
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    let error = signer.close_account(confirmed()).await.unwrap_err();
    assert!(
        matches!(error, SignerError::Refused(Refusal::RecordsBehind { .. })),
        "{error:?}"
    );
    assert!(!world.switch.erased());
    assert_eq!(signer.status(), SignerStatus::Erasing);
    // Not in doubt: the abort is taken (it then meets the records behind at the run).
    let aborted = signer.abort_erasure().await;
    assert_ne!(
        aborted,
        Err(SignerError::Refused(Refusal::ErasureUnanswered)),
        "{aborted:?}"
    );
    assert_ne!(signer.status(), SignerStatus::Erasing);
}
