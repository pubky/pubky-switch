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
    assert_eq!(signer.status(), SignerStatus::Erasing);
    // It may have erased the account: it can't be aborted.
    assert_eq!(
        signer.abort_erasure().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnanswered)
    );
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
    assert_eq!(erase_requests(&world), 2);
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
    // A `404` to the first request can't be the account erased already: the erasure stays in
    // progress. An unsigned answer doesn't show the account still exists either, so the
    // request may have landed: it can't be aborted, and a `404` to the next request is the
    // erasure done (Switch wire 7.4.16).
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    drop(signer);
    let mut signer = Signer::open(unsigned_404_for_erasure(&world, store), world.keyring())
        .await
        .unwrap();
    let error = signer.close_account(confirmed()).await.unwrap_err();
    assert!(matches!(error, SignerError::Switch(_)), "{error:?}");
    assert_eq!(signer.status(), SignerStatus::Erasing);
    assert_eq!(
        signer.abort_erasure().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnanswered)
    );
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
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

/// `world`'s env, whose transport loses the first answer to `POST /erase`, answers the second
/// with an unsigned `503`, as a proxy could, and passes everything else to the switch.
fn lost_then_unsigned_503(world: &World, store: Arc<MemoryStore>) -> SignerEnv {
    let switch = Arc::clone(&world.switch);
    let erasures = Arc::new(std::sync::Mutex::new(0));
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if request.method == "POST" && request.path_and_query.ends_with("/erase") {
            let mut count = erasures.lock().unwrap();
            *count += 1;
            match *count {
                1 => {
                    let _ = switch.handle(request);
                    return Err(pubky_switch_client::TransportError::Timeout);
                }
                2 => {
                    return Ok(Response {
                        status: 503,
                        headers: Vec::new(),
                        body: b"{}".to_vec(),
                    });
                }
                _ => {}
            }
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport;
    env
}

#[tokio::test]
async fn test_erasure_unsigned_answer_after_a_lost_200_keeps_it_landed() {
    // The switch erased the account and its `200` was lost; a proxy answers the retry with an
    // unsigned `503`; the next retry gets the operator's `404`. The unsigned answer showed
    // nothing about the account, so the erasure is done (Switch wire 7.4.16).
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
