//! Revocations, departures and full-bundle requests against the scripted switch (Switch spec
//! 12.2, 12.3; Switch wire 3.5, 7.4.11, 7.4.12): the switch revoked first, the rotation's
//! bundles for the apps that stay, the version that removes the app at the switch's time, the
//! record deleted and the App ID kept for good, a revocation or a departure completed at the
//! next run, and the parts a full-bundle request lacks.

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::*;
use pubky_switch_client::store::{Fault, FaultStore, MemoryStore, StateStore};
use pubky_switch_client::testing::{Fault as SwitchFault, SWITCH_ORIGIN};
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::ops::OpKind;
use pubky_switch_core::records::{KeyBundleContents, RemovedApp, app_record_path};
use pubky_switch_signer::Alert;
use pubky_switch_signer::{CertChange, Refusal, Signer, SignerError, UserConfirmed};

const DAY_MS: u64 = 86_400_000;

fn confirmed() -> UserConfirmed {
    UserConfirmed::shown_and_confirmed()
}

/// The bundle parts the switch holds for `app`, opened with its bundle secret.
fn opened(world: &World, app: &App) -> Vec<KeyBundleContents> {
    let id = app.keys.app_id_bytes();
    world
        .switch
        .bundle_parts_of(&id)
        .iter()
        .map(|part| {
            part.bundle
                .open(&world.key.public(), &id, &app.keys.bundle_secret())
                .unwrap()
        })
        .collect()
}

/// Whether `parts` give the identity's key of `scope` at `epoch`.
fn holds(world: &World, parts: &[KeyBundleContents], epoch: u64, scope: &str) -> bool {
    parts
        .iter()
        .any(|p| p.keys.get(epoch, scope) == Some(world.key.scope_key(epoch, scope)))
}

/// Whether `signer` refuses `app`'s request as a revoked or removed App ID (Switch wire 3.9
/// step 4), whether or not it is still listed.
fn refused_for_good(signer: &Signer, app: &App) -> bool {
    matches!(
        signer.review(&app.request, &app.auth),
        Err(SignerError::Refused(Refusal::AppRequest(ref why))) if why.contains("step 4")
    )
}

/// Two apps, `a` and `b`, approved and joined.
async fn two_joined(world: &World, signer: &mut Signer) -> (App, App) {
    let a = App::with_keys(
        AppKeys::from_secrets([3; 32], [4; 32]),
        &["notes", "notes_sync"],
        None,
        [9; 32],
    );
    let b = App::with_keys(
        AppKeys::from_secrets([5; 32], [6; 32]),
        &["notes"],
        None,
        [10; 32],
    );
    world.approve(signer, &a).await;
    world.approve(signer, &b).await;
    (a, b)
}

#[tokio::test]
async fn test_revocation_removes_the_app_at_the_switchs_time_and_rotates() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world
        .homeserver
        .set(&app_record_path(&id), b"a's record".to_vec());
    world.clock.advance_ms(DAY_MS);
    let removing = signer.revoke(id, None, confirmed()).await.unwrap();
    // Revoked at the switch first, then removed at that time with the data epoch raised
    // (Switch spec 12.2 steps 1 and 3).
    assert!(world.switch.app(&id).departed);
    assert!(removing.listed_cert(&id).is_none());
    assert_eq!(
        removing.body().removed,
        [RemovedApp {
            app_id: id,
            distrust_from: START_MS + DAY_MS,
        }]
    );
    assert_eq!(removing.data_epoch(), 2);
    assert_eq!(world.published().unwrap().signed(), removing.signed());
    // The app that stays holds the new epoch's key; the revoked one doesn't (step 2).
    assert!(holds(&world, &opened(&world, &b), 2, "notes"));
    assert!(!holds(&world, &opened(&world, &a), 2, "notes"));
    // Its record is gone, its grant is the user's to revoke, and its App ID stays refused.
    assert!(world.homeserver.file(&app_record_path(&id)).is_none());
    assert!(
        signer
            .alerts()
            .contains(&Alert::GrantRevocationOwed { app_id: id })
    );
    assert!(refused_for_good(&signer, &a));
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_revocation_takes_an_earlier_distrust_from_and_never_a_later_one() {
    for (picked, expected) in [
        (START_MS + DAY_MS - 3_600_000, START_MS + DAY_MS - 3_600_000),
        (START_MS + 2 * DAY_MS, START_MS + DAY_MS),
    ] {
        let world = World::new();
        let (mut signer, _) = world.enrolled().await;
        let (a, _) = two_joined(&world, &mut signer).await;
        world.clock.advance_ms(DAY_MS);
        let removing = signer
            .revoke(a.keys.app_id_bytes(), Some(picked), confirmed())
            .await
            .unwrap();
        assert_eq!(removing.body().removed[0].distrust_from, expected);
    }
}

#[tokio::test]
async fn test_revocation_keeps_the_app_id_before_the_switch_answers() {
    // The switch can't be reached: the revocation is kept, so the App ID is refused already,
    // and the next run sends it.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(!world.switch.app(&id).departed);
    assert!(refused_for_good(&signer, &a));
    signer.run_due().await.unwrap();
    assert!(world.switch.app(&id).departed);
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&id).is_none());
}

#[tokio::test]
async fn test_revocation_reaches_the_switch_while_an_alarm_holds_signing_back() {
    // The switch went back: an alarm. The revocation still cuts the app off at the switch,
    // which signs nothing new; the version that removes it waits for the alarm to be cleared.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    let before = signer.identity_doc().unwrap().unwrap();
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    world.switch.deliver_identity(&before).unwrap();
    let SignerError::Alarm(alarm) = signer.set_record_max_age(Some(60)).await.unwrap_err() else {
        panic!("no alarm")
    };
    let current = signer.identity_doc().unwrap().unwrap();
    world.switch.deliver_identity(&current).unwrap();
    let sent = world.sent_docs().len();
    assert_eq!(
        signer.revoke(id, None, confirmed()).await.unwrap_err(),
        SignerError::Alarm(alarm.clone())
    );
    assert!(world.switch.app(&id).departed);
    assert!(refused_for_good(&signer, &a));
    assert_eq!(world.sent_docs().len(), sent);
    // Cleared, the next run removes it.
    signer.clear_alert(&alarm).await.unwrap();
    signer.run_due().await.unwrap();
    assert!(
        signer
            .identity_doc()
            .unwrap()
            .unwrap()
            .listed_cert(&id)
            .is_none()
    );
}

#[tokio::test]
async fn test_revocation_takes_the_switchs_time_not_the_signers_clock() {
    // The signer's clock runs ten hours ahead of the switch's: `distrust_from` is the time
    // in the revocation's proof (Switch wire 7.4.12), and the backup keeps the App ID.
    let world = World::new();
    let (signer, memory) = world.enrolled().await;
    drop(signer);
    let mut env = world.env(memory);
    env.clock = Arc::new(pubky_switch_client::clock::TestClock::new(
        START_MS + 10 * 3_600_000,
    ));
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.clock.advance_ms(DAY_MS);
    let removing = signer.revoke(id, None, confirmed()).await.unwrap();
    assert_eq!(removing.body().removed[0].distrust_from, START_MS + DAY_MS);
    assert!(world.backup().revoked_apps().contains(&id));
}

#[tokio::test]
async fn test_revocation_without_a_time_is_an_error_with_an_alert() {
    // A faulty switch: the app is revoked already, so the answer carries no proof, and
    // `GET /apps` shows no time. The revocation isn't reported done, and the user is told.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.switch.revoke(id).unwrap();
    world.switch.forget_removal_time(id);
    let error = signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(matches!(error, SignerError::InvalidData(_)), "{error:?}");
    assert!(
        signer
            .alerts()
            .contains(&Alert::RevocationUnconfirmed { app_id: id })
    );
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&id).is_some());
    assert!(refused_for_good(&signer, &a));
}

#[tokio::test]
async fn test_revocation_is_kept_when_the_checks_after_it_fail() {
    // The Homeserver is down: the revocation reaches the switch and is kept, and the next
    // run removes the app once the Homeserver answers again.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    *world.homeserver.down.lock().unwrap() = true;
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(refused_for_good(&signer, &a));
    // The time was kept from the revocation's proof: it stands even if the switch's list
    // later shows none.
    world.clock.advance_ms(DAY_MS);
    world.switch.forget_removal_time(id);
    *world.homeserver.down.lock().unwrap() = false;
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&id).is_none());
    assert_eq!(doc.body().removed[0].distrust_from, START_MS);
}

#[tokio::test]
async fn test_revocation_during_a_flow_is_kept_and_completed_after_it() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert_eq!(
        signer.revoke(id, None, confirmed()).await.unwrap_err(),
        SignerError::Refused(Refusal::FlowInProgress)
    );
    assert!(refused_for_good(&signer, &a));
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&id).is_none());
    assert_eq!(doc.body().record_max_age, Some(86_400));
}

#[tokio::test]
async fn test_revoked_app_gets_no_keys_even_while_the_switch_still_serves_it() {
    // The revocation hasn't reached the switch, which still serves the app and would take
    // its part. A rotation and a full-bundle request give it nothing all the same: the
    // signer's records decide who is cut off (Switch spec 12.2).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let b_id = b.keys.app_id_bytes();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    signer.revoke(b_id, None, confirmed()).await.unwrap_err();
    assert!(!world.switch.app(&b_id).departed);
    let renewing = signer
        .renew(
            a.keys.app_id_bytes(),
            CertChange {
                scopes: Some(vec!["notes_sync".into()]),
                expires_at: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(renewing.data_epoch(), 2);
    assert!(!holds(&world, &opened(&world, &b), 2, "notes"));
    world.switch.request_full_bundle(b_id);
    assert!(signer.serve_full_bundles().await.unwrap().is_empty());
    assert!(world.switch.bundle_parts_of(&b_id).is_empty());
}

#[tokio::test]
async fn test_removal_the_switch_reports_raises_an_alert_for_a_departure() {
    // The app left: the removal takes its departure time, and the user is told an app went
    // that this signer didn't revoke.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.clock.advance_ms(DAY_MS);
    world.switch.leave(id).unwrap();
    world.clock.advance_ms(DAY_MS);
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.body().removed[0].distrust_from, START_MS + DAY_MS);
    assert!(signer.alerts().contains(&Alert::RemovedAtSwitch {
        app_id: id,
        left: true,
    }));
}

#[tokio::test]
async fn test_removal_time_never_reaches_back_past_a_version_the_switch_took_listing_it() {
    // The switch reports a departure, then takes a version that still lists the app, later.
    // The removal is distrusted only from that version's time, with an alert, so a reported
    // time can't invalidate the app's messages before it.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.switch.leave(id).unwrap();
    world.clock.advance_ms(DAY_MS);
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.body().removed[0].distrust_from, START_MS + DAY_MS);
    assert!(signer.alerts().contains(&Alert::RemovalTimeBounded {
        app_id: id,
        reported: START_MS,
        distrust_from: START_MS + DAY_MS,
    }));
}

#[tokio::test]
async fn test_full_bundle_request_refused_for_one_app_doesnt_hold_back_the_others() {
    // `a`'s renewal stored a newer certificate before it was given up, so the `cert.put` its
    // full-bundle answer needs is refused (`409`, Switch wire 6.2). `b`'s request is answered
    // all the same, and `a`'s isn't tried again until it asks anew.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let (a_id, b_id) = (a.keys.app_id_bytes(), b.keys.app_id_bytes());
    signer
        .renew(
            a_id,
            CertChange {
                scopes: None,
                expires_at: Some(START_MS + 400 * DAY_MS),
            },
        )
        .await
        .unwrap();
    world.switch.fail_next(SwitchFault::Error {
        path: "/identity".into(),
        code: pubky_switch_core::http::ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    signer
        .renew(
            a_id,
            CertChange {
                scopes: Some(vec!["notes".into()]),
                expires_at: None,
            },
        )
        .await
        .unwrap_err();
    world.switch.request_full_bundle(a_id);
    world.switch.request_full_bundle(b_id);
    signer.run_due().await.unwrap();
    assert!(world.switch.app(&b_id).full_requested.is_none());
    assert!(world.switch.app(&a_id).full_requested.is_some());
    assert!(
        signer
            .alerts()
            .contains(&Alert::FullBundleRefused { app_id: a_id })
    );
    let sent = world.switch.applied().len();
    signer.run_due().await.unwrap();
    assert_eq!(world.switch.applied().len(), sent);
}

#[tokio::test]
async fn test_revocation_refuses_an_app_that_isnt_listed() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let error = signer.revoke([1; 16], None, confirmed()).await.unwrap_err();
    assert_eq!(error, SignerError::Refused(Refusal::NotListed));
    assert!(world.switch.app(&[1; 16]).revoked_at.is_none());
}

#[tokio::test]
async fn test_revocation_cut_short_is_completed_at_the_next_run() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(world.switch.app(&id).departed);
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&id).is_none());
    assert_eq!(doc.data_epoch(), 2);
    assert!(holds(&world, &opened(&world, &b), 2, "notes"));
}

#[tokio::test]
async fn test_revocation_survives_a_crash_at_every_commit() {
    // Under each fault the revocation is asked once and the store is reopened as a restarted
    // process finds it: the app is either never revoked at the switch, or revoked and
    // removed, at the switch's time for its revocation, and nothing is signed twice.
    for n in 1..=10 {
        for fault in [Fault::StopBefore(n), Fault::StopAfter(n)] {
            let world = World::new();
            let memory = Arc::new(MemoryStore::new());
            let mut signer =
                Signer::create(world.env(memory.clone()), world.keyring(), SWITCH_ORIGIN)
                    .await
                    .unwrap();
            signer.resume().await.unwrap();
            let (a, _) = two_joined(&world, &mut signer).await;
            let id = a.keys.app_id_bytes();
            world.clock.advance_ms(DAY_MS);
            let faulty: Arc<dyn StateStore> = Arc::new(FaultStore::new(memory.clone(), fault));
            let mut signer = Signer::open(world.env(faulty), world.keyring())
                .await
                .unwrap();
            let _ = signer.revoke(id, None, confirmed()).await;
            world.clock.advance_ms(DAY_MS);
            let mut restarted = Signer::open(world.env(memory), world.keyring())
                .await
                .unwrap();
            restarted
                .run_due()
                .await
                .unwrap_or_else(|e| panic!("{fault:?}: {e:?}"));
            let doc = restarted.identity_doc().unwrap().unwrap();
            let held = world.switch.app(&id);
            // Once the revocation was kept, its App ID is refused, and it reaches the switch.
            let kept = refused_for_good(&restarted, &a);
            assert_eq!(held.departed, kept, "{fault:?}");
            if held.departed {
                assert_eq!(
                    doc.body().removed,
                    [RemovedApp {
                        app_id: id,
                        distrust_from: held.revoked_at.unwrap(),
                    }],
                    "{fault:?}"
                );
                assert!(doc.listed_cert(&id).is_none(), "{fault:?}");
            } else {
                assert!(doc.listed_cert(&id).is_some(), "{fault:?}");
            }
            assert_eq!(
                world.switch.identity_doc().unwrap().signed(),
                doc.signed(),
                "{fault:?}"
            );
            world.assert_no_version_sent_twice();
        }
    }
}

#[tokio::test]
async fn test_revocation_the_signer_didnt_ask_for_is_completed_at_the_next_run() {
    // The switch shows a revocation the records don't: the next run removes the app too,
    // and keeps its App ID.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.clock.advance_ms(DAY_MS);
    world.switch.revoke(id).unwrap();
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.body().removed[0].distrust_from, START_MS + DAY_MS);
    assert!(refused_for_good(&signer, &a));
    assert!(signer.alerts().contains(&Alert::RemovedAtSwitch {
        app_id: id,
        left: false,
    }));
}

#[tokio::test]
async fn test_departure_is_completed_at_the_next_run_from_its_time() {
    // An app leaves (Switch spec 12.3): the next run removes it with the departure time as
    // `distrust_from` and rotates, and the switch no longer shows it awaiting its rotation.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.clock.advance_ms(DAY_MS);
    world.switch.leave(id).unwrap();
    world.clock.advance_ms(DAY_MS);
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(
        doc.body().removed,
        [RemovedApp {
            app_id: id,
            distrust_from: START_MS + DAY_MS,
        }]
    );
    assert_eq!(doc.data_epoch(), 2);
    assert!(holds(&world, &opened(&world, &b), 2, "notes"));
    assert!(refused_for_good(&signer, &a));
    // Nothing more is owed: a second run delivers nothing.
    let sent = world.sent_docs().len();
    signer.run_due().await.unwrap();
    assert_eq!(world.sent_docs().len(), sent);
}

#[tokio::test]
async fn test_revocation_completes_a_given_up_epoch_first() {
    // A reduction's rotation is given up after its batches, so epoch 2's keys went out. The
    // revocation completes epoch 2 in a version of its own, then rotates to 3 (Switch spec
    // 3.2, 3.5).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    world.switch.fail_next(SwitchFault::Error {
        path: "/identity".into(),
        code: pubky_switch_core::http::ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    signer
        .renew(
            b.keys.app_id_bytes(),
            CertChange {
                scopes: Some(vec!["notes_tags".into()]),
                expires_at: None,
            },
        )
        .await
        .unwrap_err();
    let removing = signer
        .revoke(b.keys.app_id_bytes(), None, confirmed())
        .await
        .unwrap();
    assert_eq!(removing.data_epoch(), 3);
    let completed = world
        .sent_docs()
        .into_iter()
        .find(|d| d.version() + 1 == removing.version())
        .unwrap();
    assert_eq!(completed.data_epoch(), 2);
    // `a` holds epoch 1 from its approval, and epochs 2 and 3 from the stored parts.
    assert!((2..=3).all(|epoch| holds(&world, &opened(&world, &a), epoch, "notes")));
}

#[tokio::test]
async fn test_revocation_record_cleanup_waits_for_the_homeserver() {
    // The record deletion fails: the removal stands, and the deletion is done at the next
    // run.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world
        .homeserver
        .set(&app_record_path(&id), b"a's record".to_vec());
    *world.homeserver.failing_path.lock().unwrap() = Some(app_record_path(&id));
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(
        world
            .switch
            .identity_doc()
            .unwrap()
            .listed_cert(&id)
            .is_none()
    );
    assert!(world.homeserver.file(&app_record_path(&id)).is_some());
    *world.homeserver.failing_path.lock().unwrap() = None;
    signer.run_due().await.unwrap();
    assert!(world.homeserver.file(&app_record_path(&id)).is_none());
    assert_eq!(
        world.published().unwrap().signed(),
        world.switch.identity_doc().unwrap().signed()
    );
}

#[tokio::test]
async fn test_purge_removed_drops_the_entry_and_keeps_the_app_id() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    signer.revoke(id, None, confirmed()).await.unwrap();
    let purged = signer.purge_removed(id).await.unwrap();
    assert!(purged.body().removed.is_empty());
    assert!(refused_for_good(&signer, &a));
    assert_eq!(
        signer.purge_removed(id).await.unwrap_err(),
        SignerError::Refused(Refusal::NotRemoved)
    );
}

#[tokio::test]
async fn test_full_bundle_request_gets_the_missing_parts_and_the_listed_certificate() {
    // `a` is renewed, and its record still carries the earlier certificate. A later
    // rotation's prune lets the signer forget the part it stored for `a`, once `a` passed it,
    // so it can't tell what `a` holds. `a` asks for its full bundle: the signer stores the
    // listed certificate again with `cert.put`, then the parts for every epoch (Switch wire
    // 3.5 "Full bundles on request").
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    let extend = || CertChange {
        scopes: None,
        expires_at: Some(START_MS + 400 * DAY_MS),
    };
    signer.renew(id, extend()).await.unwrap();
    signer.renew(b.keys.app_id_bytes(), extend()).await.unwrap();
    let listed = signer
        .identity_doc()
        .unwrap()
        .unwrap()
        .listed_cert(&id)
        .unwrap();
    let cert_puts = |world: &World| {
        world
            .switch
            .applied()
            .iter()
            .filter(|op| {
                matches!(&op.body().kind, OpKind::CertPut { target_app_id, .. } if *target_app_id == id)
            })
            .count()
    };
    let before = cert_puts(&world);
    world.switch.request_full_bundle(id);
    signer.run_due().await.unwrap();
    assert_eq!(cert_puts(&world), before + 1);
    assert!(world.switch.app(&id).full_requested.is_none());
    let parts = opened(&world, &a);
    assert!(parts.iter().any(|p| p.cert == listed));
    assert!(holds(&world, &parts, 1, "notes"));
    // The backup lists the parts, at the same version.
    let newest = signer.identity_doc().unwrap().unwrap();
    assert_eq!(world.backup().identity_doc().signed(), newest.signed());
    // Answered, nothing more is sent.
    let sent = world.switch.applied().len();
    signer.run_due().await.unwrap();
    assert_eq!(world.switch.applied().len(), sent);
}

#[tokio::test]
async fn test_full_bundle_request_after_the_approval_stores_every_epoch() {
    // The approval's bundle came in its claim, not as stored parts, so the signer can't tell
    // what the app holds: it stores every epoch, once (Switch wire 3.5).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    assert!(world.switch.bundle_parts_of(&id).is_empty());
    world.switch.request_full_bundle(id);
    assert_eq!(signer.serve_full_bundles().await.unwrap(), [id]);
    assert!(holds(&world, &opened(&world, &a), 1, "notes"));
    assert!(world.switch.app(&id).full_requested.is_none());
    assert!(signer.serve_full_bundles().await.unwrap().is_empty());
}
