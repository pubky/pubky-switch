//! Renewals and reductions against the scripted switch (Switch spec 3.2; Switch wire 3.5,
//! 3.8): the stored certificate and key bundles, the renewing version, a reduction's closing
//! at the switch's time, a rotation's bundles for the current apps only, the epoch a given-up
//! rotation sent completed before the next, the closing owed after a crash or without a service
//! time, a cooperative renewal closed once the app's record carries the new certificate, and
//! the renewal of every certificate past half its lifetime. The clock moves between steps, so
//! every cutoff is checked against the switch's time.

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use pubky_switch_client::clock::Clock;

use common::*;
use pubky_switch_client::store::{Fault, FaultStore, MemoryStore, StateStore};
use pubky_switch_client::testing::{Fault as SwitchFault, SWITCH_ORIGIN};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::ops::OpKind;
use pubky_switch_core::records::{
    AppCert, AppRecord, AppRecordBody, CLOCK_TOLERANCE_MS, IDENTITY_PATH, IdentityDoc,
    KeyBundleContents, Limits, SIGNER_BACKUP_PATH, SignerBackup, SignerRecords,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_signer::{
    Alert, CertChange, Protocol, Protocols, Refusal, RenewalSkip, ScopeDef, Signer, SignerEnv,
    SignerError,
};

const DAY_MS: u64 = 86_400_000;

fn scopes(list: &[&str]) -> Option<Vec<String>> {
    Some(list.iter().map(|s| (*s).to_owned()).collect())
}

fn reduce(list: &[&str]) -> CertChange {
    CertChange {
        scopes: scopes(list),
        expires_at: None,
    }
}

/// The open and closed renewals of `app` in `doc`.
fn renewals(doc: &IdentityDoc, app: &[u8; 16]) -> Vec<Option<u64>> {
    doc.body()
        .renewed
        .iter()
        .filter(|r| &r.app_id == app)
        .map(|r| r.until)
        .collect()
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

/// Whether `app` holds the key of `scope` at `epoch`, and it is the identity's: from the
/// keys its approval gave it, or from `parts`, its bundle parts at the switch. An incremental
/// part starts after the epochs the app holds (`keys_through`), so it may replace a part
/// whose keys the app has from its approval (Switch wire 3.5 "Incremental bundles").
fn app_holds(
    world: &World,
    app: &App,
    parts: &[KeyBundleContents],
    epoch: u64,
    scope: &str,
) -> bool {
    let approved = world
        .approval_keys
        .lock()
        .unwrap()
        .get(&app.keys.app_id_bytes())
        .and_then(|keys| keys.get(epoch, scope))
        == Some(world.key.scope_key(epoch, scope));
    approved || holds(world, parts, epoch, scope)
}

/// Whether `parts` give the key of `scope` at `epoch`, and it is the identity's.
fn holds(world: &World, parts: &[KeyBundleContents], epoch: u64, scope: &str) -> bool {
    parts
        .iter()
        .any(|p| p.keys.get(epoch, scope) == Some(world.key.scope_key(epoch, scope)))
}

fn two_apps(scopes_a: &[&str], scopes_b: &[&str]) -> (App, App) {
    (
        App::with_keys(
            AppKeys::from_secrets([3; 32], [4; 32]),
            scopes_a,
            None,
            [9; 32],
        ),
        App::with_keys(
            AppKeys::from_secrets([5; 32], [6; 32]),
            scopes_b,
            None,
            [10; 32],
        ),
    )
}

#[tokio::test]
async fn test_renewal_extending_the_expiry_stores_the_cert_and_bundle_and_stays_open() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let approved = world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    let old = approved.listed_cert(&id).unwrap();
    world.clock.advance_ms(DAY_MS);
    let later = START_MS + 400 * DAY_MS;
    let doc = signer
        .renew(
            id,
            CertChange {
                scopes: None,
                expires_at: Some(later),
            },
        )
        .await
        .unwrap();
    // The renewing version lists the new certificate and keeps the earlier one open:
    // extending the expiry isn't a reduction.
    let new = doc.listed_cert(&id).unwrap();
    assert_ne!(new, old);
    assert_eq!(doc.body().renewed[0].cert, old);
    assert_eq!(renewals(&doc, &id), [None]);
    assert_eq!(doc.data_epoch(), 1);
    assert_eq!(world.switch.identity_doc().unwrap().signed(), doc.signed());
    // The switch holds the renewed certificate and a full bundle made for it.
    assert_eq!(world.switch.app(&id).renewed.unwrap().hash(), new);
    let parts = opened(&world, &app);
    assert!(parts.iter().all(|p| p.cert == new));
    assert!(holds(&world, &parts, 1, "notes"));
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_renewal_cooperative_closes_at_the_time_the_switch_took_the_new_record() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    world.clock.advance_ms(DAY_MS);
    let doc = signer
        .renew(
            id,
            CertChange {
                scopes: None,
                expires_at: Some(START_MS + 400 * DAY_MS),
            },
        )
        .await
        .unwrap();
    // Before the app delivers its record, nothing closes.
    assert!(signer.complete_renewals().await.unwrap().is_empty());
    // An hour later the app delivers its record carrying the new certificate (Switch wire 3.8
    // step 3), and the close is that time plus the tolerance, whatever the clock says later.
    world.clock.advance_ms(3_600_000);
    let record_at = START_MS + DAY_MS + 3_600_000;
    let new = world.switch.app(&id).renewed.unwrap();
    let record =
        AppRecord::sign(&app.keys, AppRecordBody::new(&new, Vec::new(), record_at)).unwrap();
    world
        .switch
        .app_op(
            &app.keys,
            OpKind::AppPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    world.clock.advance_ms(DAY_MS);
    assert_eq!(signer.complete_renewals().await.unwrap(), [id]);
    let closed = signer.identity_doc().unwrap().unwrap();
    assert_eq!(closed.version(), doc.version() + 1);
    assert_eq!(
        renewals(&closed, &id),
        [Some(record_at + CLOCK_TOLERANCE_MS)]
    );
}

#[tokio::test]
async fn test_renewal_a_reduction_closes_at_the_renewing_deliverys_time() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    world.clock.advance_ms(DAY_MS);
    let delivered = START_MS + DAY_MS;
    // Removing `notes_tags`, a scope without keys, is a reduction that rotates nothing.
    let renewing = signer.renew(id, reduce(&["notes"])).await.unwrap();
    assert_eq!(renewing.data_epoch(), 1);
    let closed = signer.identity_doc().unwrap().unwrap();
    assert_eq!(closed.version(), renewing.version() + 1);
    assert_eq!(
        renewals(&closed, &id),
        [Some(delivered + CLOCK_TOLERANCE_MS)]
    );
    assert_eq!(
        world.switch.identity_doc().unwrap().signed(),
        closed.signed()
    );
    assert_eq!(world.published().unwrap().signed(), closed.signed());
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_renewal_a_failing_publication_doesnt_hold_back_a_reductions_closing() {
    // The Homeserver refuses `identity.json` writes: the closing still reaches the switch,
    // which cuts the earlier certificate off; only publication waits (Switch wire 3.8).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    world.clock.advance_ms(DAY_MS);
    *world.homeserver.failing_path.lock().unwrap() = Some(IDENTITY_PATH.into());
    let error = signer.renew(id, reduce(&["notes"])).await.unwrap_err();
    assert!(matches!(error, SignerError::Homeserver(_)), "{error:?}");
    let held = world.switch.identity_doc().unwrap();
    assert_eq!(
        renewals(&held, &id),
        [Some(START_MS + DAY_MS + CLOCK_TOLERANCE_MS)]
    );
    // Once the Homeserver takes writes again, the closing version is published.
    *world.homeserver.failing_path.lock().unwrap() = None;
    signer.resume().await.unwrap();
    assert_eq!(world.published().unwrap().signed(), held.signed());
}

#[tokio::test]
async fn test_renewal_a_failing_publication_doesnt_hold_back_a_cooperative_closing() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    *world.homeserver.failing_path.lock().unwrap() = Some(IDENTITY_PATH.into());
    let change = CertChange {
        scopes: None,
        expires_at: Some(START_MS + 400 * DAY_MS),
    };
    signer.renew(id, change).await.unwrap_err();
    world.clock.advance_ms(3_600_000);
    let new = world.switch.app(&id).renewed.unwrap();
    let record_at = START_MS + 3_600_000;
    let record =
        AppRecord::sign(&app.keys, AppRecordBody::new(&new, Vec::new(), record_at)).unwrap();
    world
        .switch
        .app_op(
            &app.keys,
            OpKind::AppPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    // The renewing version still isn't published, yet the closing goes to the switch.
    let error = signer.run_due().await.unwrap_err();
    assert!(matches!(error, SignerError::Homeserver(_)), "{error:?}");
    assert_eq!(
        renewals(&world.switch.identity_doc().unwrap(), &id),
        [Some(record_at + CLOCK_TOLERANCE_MS)]
    );
}

#[tokio::test]
async fn test_renewal_removing_a_keyed_scope_rotates_and_only_keepers_get_its_new_key() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (reduced, keeper) = two_apps(&["notes", "notes_sync"], &["notes"]);
    world.approve(&mut signer, &reduced).await;
    world.approve(&mut signer, &keeper).await;
    let id = reduced.keys.app_id_bytes();
    world.clock.advance_ms(DAY_MS);
    let renewing = signer.renew(id, reduce(&["notes_sync"])).await.unwrap();
    // The renewing version raises the data epoch (Switch wire 3.8 "A removed scope's keys
    // rotate"), and the reduction closes at once.
    assert_eq!(renewing.data_epoch(), 2);
    let closed = signer.identity_doc().unwrap().unwrap();
    assert_eq!(
        renewals(&closed, &id),
        [Some(START_MS + DAY_MS + CLOCK_TOLERANCE_MS)]
    );
    // The reduced app's full bundle runs through epoch 2 with the scope it keeps, and holds
    // no key of the removed one, at any epoch.
    let parts = opened(&world, &reduced);
    assert!(holds(&world, &parts, 1, "notes_sync") && holds(&world, &parts, 2, "notes_sync"));
    assert!(parts.iter().all(|p| p.keys.max_epoch("notes").is_none()));
    // The app that keeps `notes` gets its key for epoch 2.
    let kept = opened(&world, &keeper);
    assert!(holds(&world, &kept, 2, "notes"));
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_renewal_a_given_up_rotation_is_completed_before_the_next() {
    // A rotation stores the other app's bundle for epoch 2, then its delivery is refused, so
    // epoch 2's keys went out with no version raising it. The next rotation first completes
    // epoch 2 for every app holding its scopes, the given-up one included, then rotates to 3
    // (Switch spec 3.2, 3.5).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_apps(&["notes", "notes_sync"], &["notes", "notes_sync"]);
    world.approve(&mut signer, &a).await;
    world.approve(&mut signer, &b).await;
    let a_id = a.keys.app_id_bytes();
    world.switch.fail_next(SwitchFault::Error {
        path: "/identity".into(),
        code: ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    signer
        .renew(a_id, reduce(&["notes_sync"]))
        .await
        .unwrap_err();
    let before = signer.identity_doc().unwrap().unwrap();
    let listed = before.listed_cert(&a_id).unwrap();
    assert_eq!(before.data_epoch(), 1);
    assert!(holds(&world, &opened(&world, &b), 2, "notes"));
    // The given-up renewal's full bundle, made for a certificate never listed, replaced `a`'s.
    assert!(opened(&world, &a).iter().all(|p| p.cert != listed));

    let renewing = signer
        .renew(b.keys.app_id_bytes(), reduce(&["notes_sync"]))
        .await
        .unwrap();
    assert_eq!(renewing.data_epoch(), 3);
    // The version before it raised `data_epoch` to 2 and changed nothing else.
    let completed = world
        .sent_docs()
        .into_iter()
        .find(|d| d.version() + 1 == renewing.version())
        .unwrap();
    assert_eq!(completed.data_epoch(), 2);
    assert_eq!(completed.body().apps, before.body().apps);
    assert_eq!(completed.body().renewed, before.body().renewed);
    // `a` holds `notes` through epoch 3 again, in parts made for its listed certificate.
    let parts = opened(&world, &a);
    assert!(parts.iter().all(|p| p.cert == listed));
    assert!((1..=3).all(|epoch| app_holds(&world, &a, &parts, epoch, "notes")));
}

#[tokio::test]
async fn test_renewal_full_bundle_request_replaces_a_part_for_another_certificate() {
    // A given-up renewal stored `a`'s full bundle for a certificate never listed. A range only
    // such a part covers counts as missing: asked for its full bundle, `a` gets parts for every
    // epoch, each made for its listed certificate (Switch wire 3.5 "Full bundles on request").
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_apps(&["notes", "notes_sync"], &["notes", "notes_sync"]);
    world.approve(&mut signer, &a).await;
    world.approve(&mut signer, &b).await;
    let a_id = a.keys.app_id_bytes();
    world.switch.fail_next(SwitchFault::Error {
        path: "/identity".into(),
        code: ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    signer
        .renew(a_id, reduce(&["notes_sync"]))
        .await
        .unwrap_err();
    let newest = signer.identity_doc().unwrap().unwrap();
    let listed = newest.listed_cert(&a_id).unwrap();
    assert!(opened(&world, &a).iter().all(|p| p.cert != listed));

    world.switch.request_full_bundle(a_id);
    assert_eq!(signer.serve_full_bundles().await.unwrap(), [a_id]);
    let fresh: Vec<_> = opened(&world, &a)
        .into_iter()
        .filter(|p| p.cert == listed)
        .collect();
    for epoch in 1..=newest.data_epoch() {
        assert!(holds(&world, &fresh, epoch, "notes"), "epoch {epoch}");
    }
    assert!(
        opened(&world, &a).iter().all(|p| p.cert == listed),
        "the part for the other certificate is replaced"
    );
    assert!(world.switch.app(&a_id).full_requested.is_none());
    assert!(signer.serve_full_bundles().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_renewal_a_given_up_epoch_reaches_its_app_after_a_renewal_in_between() {
    // A rotation is given up after its batches, leaving `a`'s parts made for a certificate
    // never listed. A renewal that doesn't rotate comes in between, and the switch shows
    // `keys_through(a) = 2`, counting parts `a` skipped. The part record stays, so the next
    // rotation's completion still gives `a` a full bundle for its listed certificate
    // (Switch wire 3.5).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_apps(&["notes", "notes_sync"], &["notes", "notes_sync"]);
    world.approve(&mut signer, &a).await;
    world.approve(&mut signer, &b).await;
    let (a_id, b_id) = (a.keys.app_id_bytes(), b.keys.app_id_bytes());
    let listed = signer
        .identity_doc()
        .unwrap()
        .unwrap()
        .listed_cert(&a_id)
        .unwrap();
    world.switch.fail_next(SwitchFault::Error {
        path: "/identity".into(),
        code: ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    signer
        .renew(a_id, reduce(&["notes_sync"]))
        .await
        .unwrap_err();
    signer
        .renew(
            b_id,
            CertChange {
                scopes: None,
                expires_at: Some(START_MS + 400 * DAY_MS),
            },
        )
        .await
        .unwrap();
    signer.renew(b_id, reduce(&["notes_sync"])).await.unwrap();
    let parts = opened(&world, &a);
    assert!(parts.iter().all(|p| p.cert == listed));
    assert!((1..=3).all(|epoch| app_holds(&world, &a, &parts, epoch, "notes")));
}

#[tokio::test]
async fn test_renewal_brings_back_an_app_whose_certificate_expired() {
    // The app's certificate expired, so the switch refuses its requests. The renewal's
    // batch is taken all the same; the app is refused until the renewing version is
    // delivered, then it works again (Switch wire 3.8 "An expired certificate").
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    world.clock.advance_ms(366 * DAY_MS);
    // An app request: its record, carrying the certificate the switch checks it against.
    let app_put = |cert: &pubky_switch_core::records::AppCert, at: u64| OpKind::AppPut {
        record: AppRecord::sign(&app.keys, AppRecordBody::new(cert, Vec::new(), at))
            .unwrap()
            .signed()
            .clone(),
    };
    let now = START_MS + 366 * DAY_MS;
    let old = world.switch.app(&id).cert.unwrap();
    let error = world
        .switch
        .app_op(&app.keys, app_put(&old, now))
        .unwrap_err();
    assert!(format!("{error:?}").contains("cert_expired"), "{error:?}");
    // Step 1 alone: the certificate and the bundle are stored, the delivery doesn't arrive.
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    signer.renew(id, CertChange::default()).await.unwrap_err();
    let new = world.switch.app(&id).renewed.unwrap();
    assert!(opened(&world, &app).iter().any(|p| p.cert == new.hash()));
    let error = world
        .switch
        .app_op(&app.keys, app_put(&new, now))
        .unwrap_err();
    assert!(format!("{error:?}").contains("cert_expired"), "{error:?}");
    // Delivered, the renewed certificate is the one checked: the app works again.
    signer.resume().await.unwrap();
    world.switch.app_op(&app.keys, app_put(&new, now)).unwrap();
    assert!(holds(&world, &opened(&world, &app), 1, "notes"));
}

#[tokio::test]
async fn test_renewal_a_refused_batch_keeps_the_parts_stored_before_it() {
    // A rotation in two batches: the first stores `a`'s full bundle for its new certificate,
    // and the second is refused. The signer records what the first stored, so the next
    // rotation gives `a` a full bundle for its listed certificate (Switch wire 3.5).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_apps(&["notes", "notes_sync"], &["notes", "notes_sync"]);
    world.approve(&mut signer, &a).await;
    world.approve(&mut signer, &b).await;
    // Six more apps holding `notes`: nine operations, two batches.
    for n in 0..6u8 {
        let more = App::with_keys(
            AppKeys::from_secrets([20 + 2 * n; 32], [21 + 2 * n; 32]),
            &["notes"],
            None,
            [40 + n; 32],
        );
        world.approve(&mut signer, &more).await;
    }
    let a_id = a.keys.app_id_bytes();
    let listed = signer
        .identity_doc()
        .unwrap()
        .unwrap()
        .listed_cert(&a_id)
        .unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/ops".into(),
        after: 1,
    });
    signer
        .renew(a_id, reduce(&["notes_sync"]))
        .await
        .unwrap_err();
    world.switch.fail_next(SwitchFault::Error {
        path: "/ops".into(),
        code: ErrorCode::Conflict,
        current: serde_json::Value::Null,
    });
    signer.resume().await.unwrap_err();
    assert_eq!(signer.identity_doc().unwrap().unwrap().data_epoch(), 1);
    assert!(opened(&world, &a).iter().all(|p| p.cert != listed));

    signer
        .renew(b.keys.app_id_bytes(), reduce(&["notes_sync"]))
        .await
        .unwrap();
    let parts = opened(&world, &a);
    assert!(parts.iter().all(|p| p.cert == listed));
    assert!((1..=3).all(|epoch| app_holds(&world, &a, &parts, epoch, "notes")));
}

#[tokio::test]
async fn test_renewal_of_an_app_that_hasnt_joined_is_refused_up_front() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    signer.approve(review).await.unwrap();
    let error = signer
        .renew(app.keys.app_id_bytes(), CertChange::default())
        .await
        .unwrap_err();
    assert_eq!(error, SignerError::Refused(Refusal::NotJoined));
    // Nothing is left in progress.
    signer.set_record_max_age(Some(86_400)).await.unwrap();
}

#[tokio::test]
async fn test_renewal_a_refused_batch_ends_the_renewal() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    for code in [ErrorCode::Conflict, ErrorCode::NotFound] {
        world.switch.fail_next(SwitchFault::Error {
            path: "/ops".into(),
            code,
            current: serde_json::Value::Null,
        });
        let error = signer
            .renew(app.keys.app_id_bytes(), CertChange::default())
            .await
            .unwrap_err();
        assert!(matches!(error, SignerError::Switch(_)), "{error:?}");
        // The signer isn't stuck with the renewal in progress.
        signer.set_record_max_age(Some(86_400)).await.unwrap();
    }
}

#[tokio::test]
async fn test_renewal_sends_no_batch_once_another_install_signs() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_apps(&["notes", "notes_sync"], &["notes"]);
    world.approve(&mut signer, &a).await;
    world.approve(&mut signer, &b).await;
    let before = world.switch.bundle_parts_of(&b.keys.app_id_bytes()).len();
    let newest = signer.identity_doc().unwrap().unwrap();
    world
        .switch
        .deliver_identity(&world.other_install_version(&newest, [7; 16]))
        .unwrap();
    let error = signer
        .renew(a.keys.app_id_bytes(), reduce(&["notes_sync"]))
        .await
        .unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: [7; 16] });
    assert!(world.switch.app(&a.keys.app_id_bytes()).renewed.is_none());
    assert_eq!(
        world.switch.bundle_parts_of(&b.keys.app_id_bytes()).len(),
        before
    );
}

#[tokio::test]
async fn test_renewal_a_resumed_batch_waits_for_the_signer_check() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    signer.renew(id, CertChange::default()).await.unwrap_err();
    // Meanwhile another install takes over; the resumed batch isn't sent.
    let newest = signer.identity_doc().unwrap().unwrap();
    world
        .switch
        .deliver_identity(&world.other_install_version(&newest, [7; 16]))
        .unwrap();
    let error = signer.resume().await.unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: [7; 16] });
    assert!(world.switch.app(&id).renewed.is_none());
}

#[tokio::test]
async fn test_renewal_a_resumed_batch_waits_for_the_backup_check() {
    // The switch still holds this install's version, but another install's backup on the
    // Homeserver took over: the resumed batch isn't sent (Switch wire 3.13).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    signer.renew(id, CertChange::default()).await.unwrap_err();
    let newest = signer.identity_doc().unwrap().unwrap();
    let records = SignerRecords::new(
        IdentityKey::from_secret(SECRET),
        world.other_install_version(&newest, [7; 16]),
        &[],
        &[world.switch.app(&id).cert.unwrap()],
        Limits::default(),
        &[],
        Some(newest.hash()),
    )
    .unwrap();
    let backup = SignerBackup::seal(&world.key, &records).unwrap();
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, serde_json::to_vec(&backup).unwrap());
    let error = signer.resume().await.unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: [7; 16] });
    assert!(world.switch.app(&id).renewed.is_none());
}

#[tokio::test]
async fn test_renewal_a_rotation_skips_an_app_whose_certificate_expired() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_apps(&["notes", "notes_sync"], &["notes"]);
    world.approve(&mut signer, &a).await;
    world.approve(&mut signer, &b).await;
    signer
        .renew(
            b.keys.app_id_bytes(),
            CertChange {
                scopes: None,
                expires_at: Some(START_MS + 3_600_000),
            },
        )
        .await
        .unwrap();
    world.clock.advance_ms(2 * 3_600_000);
    let renewing = signer
        .renew(a.keys.app_id_bytes(), reduce(&["notes_sync"]))
        .await
        .unwrap();
    assert_eq!(renewing.data_epoch(), 2);
    assert!(!holds(&world, &opened(&world, &b), 2, "notes"));
}

#[tokio::test]
async fn test_renewal_a_rotation_skips_apps_the_switch_doesnt_serve_and_catches_them_up() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, late) = two_apps(&["notes", "notes_sync"], &["notes"]);
    world.approve(&mut signer, &a).await;
    // `late` is approved but hasn't joined: the rotation doesn't send it a part, so its
    // `403 not_current` can't block the reduction.
    let review = signer.review(&late.request, &late.auth).unwrap();
    let approved = signer.approve(review).await.unwrap();
    signer.claim_delivered(&approved.request).await.unwrap();
    let renewing = signer
        .renew(a.keys.app_id_bytes(), reduce(&["notes_sync"]))
        .await
        .unwrap();
    assert_eq!(renewing.data_epoch(), 2);
    assert!(
        world
            .switch
            .bundle_parts_of(&late.keys.app_id_bytes())
            .is_empty()
    );
    // It joins, and the next rotation's bundle starts after what it holds: epochs 2 and 3.
    world.join(&late, &approved);
    let other = App::with_keys(
        AppKeys::from_secrets([7; 32], [8; 32]),
        &["notes", "notes_sync"],
        None,
        [11; 32],
    );
    world.approve(&mut signer, &other).await;
    signer
        .renew(other.keys.app_id_bytes(), reduce(&["notes_sync"]))
        .await
        .unwrap();
    let parts = opened(&world, &late);
    assert!(holds(&world, &parts, 2, "notes") && holds(&world, &parts, 3, "notes"));
}

/// A second protocol, `chat`, with one keyed scope.
struct Chat;

impl Protocol for Chat {
    fn name(&self) -> &str {
        "chat"
    }
    fn scopes(&self) -> Vec<ScopeDef> {
        vec![ScopeDef::keyed("chat")]
    }
    fn check_scopes(&self, _: &[&str]) -> Result<(), String> {
        Ok(())
    }
    fn permissions(&self, _: &[&str]) -> Vec<Permission> {
        Vec::new()
    }
}

/// A signer for `world` on `store` whose protocols own `notes` and `chat`, enrolled.
async fn notes_and_chat(world: &World, store: Arc<MemoryStore>) -> Signer {
    let both = Protocols::new(vec![Arc::new(Notes), Arc::new(Chat)]).unwrap();
    let mut signer = Signer::create(world.env_with(store, both), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    signer
}

#[tokio::test]
async fn test_renewal_a_rotation_skips_an_app_with_a_scope_no_protocol_owns_and_catches_it_up() {
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let mut signer = notes_and_chat(&world, store.clone()).await;
    let (a, b) = two_apps(&["notes", "notes_sync"], &["chat"]);
    world.approve(&mut signer, &a).await;
    world.approve(&mut signer, &b).await;
    drop(signer);
    // Reopened with `notes` only: the rotation can't judge `b`'s `chat` keys, so `b` gets no
    // part, with an alert naming it and the scope (design note, decision 2).
    let notes_only = Protocols::new(vec![Arc::new(Notes)]).unwrap();
    let mut signer = Signer::open(world.env_with(store.clone(), notes_only), world.keyring())
        .await
        .unwrap();
    let renewing = signer
        .renew(a.keys.app_id_bytes(), reduce(&["notes_sync"]))
        .await
        .unwrap();
    assert_eq!(renewing.data_epoch(), 2);
    assert!(signer.alerts().contains(&Alert::RotationSkipped {
        app_id: b.keys.app_id_bytes(),
        scopes: vec!["chat".into()],
    }));
    assert!(!holds(&world, &opened(&world, &b), 2, "chat"));
    drop(signer);
    // With `chat` owned again, the next rotation's bundle for `b` starts after what it
    // holds: epochs 2 and 3.
    let both = Protocols::new(vec![Arc::new(Notes), Arc::new(Chat)]).unwrap();
    let mut signer = Signer::open(world.env_with(store, both), world.keyring())
        .await
        .unwrap();
    let other = App::with_keys(
        AppKeys::from_secrets([7; 32], [8; 32]),
        &["notes", "notes_sync"],
        None,
        [11; 32],
    );
    world.approve(&mut signer, &other).await;
    signer
        .renew(other.keys.app_id_bytes(), reduce(&["notes_sync"]))
        .await
        .unwrap();
    let parts = opened(&world, &b);
    assert!(holds(&world, &parts, 2, "chat") && holds(&world, &parts, 3, "chat"));
}

#[tokio::test]
async fn test_renewal_removing_a_scope_no_protocol_owns_rotates() {
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let mut signer = notes_and_chat(&world, store.clone()).await;
    let (mixed, chatter) = two_apps(&["notes", "chat"], &["chat"]);
    world.approve(&mut signer, &mixed).await;
    world.approve(&mut signer, &chatter).await;
    drop(signer);
    // Reopened with `chat` only, `notes` has no owner: removing it rotates, as its keys can't
    // be judged, and keeping it is refused (design note, decision 2).
    let chat_only = Protocols::new(vec![Arc::new(Chat)]).unwrap();
    let mut signer = Signer::open(world.env_with(store, chat_only), world.keyring())
        .await
        .unwrap();
    let id = mixed.keys.app_id_bytes();
    let error = signer.renew(id, CertChange::default()).await.unwrap_err();
    assert_eq!(
        error,
        SignerError::Refused(Refusal::UnknownScopes {
            scopes: vec!["notes".into()]
        })
    );
    let renewing = signer.renew(id, reduce(&["chat"])).await.unwrap();
    assert_eq!(renewing.data_epoch(), 2);
    let parts = opened(&world, &mixed);
    assert!(holds(&world, &parts, 2, "chat"));
    assert!(parts.iter().all(|p| p.keys.max_epoch("notes").is_none()));
    assert!(holds(&world, &opened(&world, &chatter), 2, "chat"));
}

#[tokio::test]
async fn test_renewal_a_lost_renewing_answer_closes_at_the_switchs_time_for_it() {
    // The switch takes the renewing version and its answer is lost. A day later the signer
    // delivers it again: the retry's proof carries the first day's time, which is the cutoff
    // (Switch wire 3.8, 7.4.2).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    world.clock.advance_ms(DAY_MS);
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/identity".into(),
    });
    signer.renew(id, reduce(&["notes"])).await.unwrap_err();
    world.clock.advance_ms(DAY_MS);
    signer.resume().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(
        renewals(&doc, &id),
        [Some(START_MS + DAY_MS + CLOCK_TOLERANCE_MS)]
    );
}

#[tokio::test]
async fn test_renewal_a_closing_without_a_service_time_waits_for_the_next_delivery() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    // The renewing delivery's answer is lost, and the switch then forgets its proof, so every
    // retry answers without one (Switch wire 7.4.2).
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/identity".into(),
    });
    signer.renew(id, reduce(&["notes"])).await.unwrap_err();
    world.switch.forget_delivery_proof();
    let before = world.sent_docs().len();
    let error = signer.resume().await.unwrap_err();
    assert!(matches!(error, SignerError::InvalidData(_)), "{error:?}");
    let alert = Alert::ReductionNotClosed { apps: vec![id] };
    assert!(signer.alerts().contains(&alert));
    // A bounded number of deliveries, and later calls go on.
    assert!(world.sent_docs().len() - before <= 2);
    signer.resume().await.unwrap();
    assert!(world.sent_docs().len() - before <= 2);
    // The alert stays while the reduction is open.
    signer.clear_alert(&alert).await.unwrap();
    assert!(signer.alerts().contains(&alert));
    // The next delivery carries a service time, a day later: the reduction closes at it,
    // and the alert goes.
    world.clock.advance_ms(DAY_MS);
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(
        renewals(&doc, &id),
        [Some(START_MS + DAY_MS + CLOCK_TOLERANCE_MS)]
    );
    assert!(!signer.alerts().contains(&alert));
}

#[tokio::test]
async fn test_renewal_an_owed_closing_isnt_signed_while_the_records_are_behind() {
    // A reduction's closing is owed with no flow in progress, as after a refused closing
    // delivery. Then the switch shows a newer version of this install's own: the records are
    // behind, and the owed closing isn't signed either (Switch spec 4.3).
    let world = World::new();
    let (mut signer, memory) = world.enrolled().await;
    let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 1,
    });
    signer.renew(id, reduce(&["notes"])).await.unwrap_err();
    world.switch.fail_next(SwitchFault::Error {
        path: "/identity".into(),
        code: ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    signer.resume().await.unwrap_err();
    let renewing = world.switch.identity_doc().unwrap();
    assert_eq!(renewals(&renewing, &id), [None]);
    let mut body = renewing.body().clone();
    body.version = 9;
    world
        .switch
        .deliver_identity(&IdentityDoc::sign(&world.key, body).unwrap())
        .unwrap();
    let behind = SignerError::Refused(Refusal::RecordsBehind { version: 9 });
    assert_eq!(
        signer.set_record_max_age(Some(60)).await.unwrap_err(),
        behind
    );
    let sent = world.sent_docs().len();
    let backup = world.backup().identity_doc().signed().clone();
    assert_eq!(signer.resume().await.unwrap_err(), behind);
    assert_eq!(world.sent_docs().len(), sent);
    assert_eq!(world.backup().identity_doc().signed(), &backup);
    // No closing version was signed, nor left as a flow to deliver.
    let ns = format!(
        "signer/{}",
        pubky_switch_core::enc::zbase32_encode(&world.key.public())
    );
    assert!(memory.get(&ns, b"flow").unwrap().is_none());
    let state: serde_json::Value =
        serde_json::from_slice(&memory.get(&ns, b"state").unwrap().unwrap()).unwrap();
    assert_eq!(state["signed_through"], 9);
}

#[tokio::test]
async fn test_renewal_an_owed_closing_waits_for_a_held_alarm_to_be_cleared() {
    // A reduction's closing is owed with no flow in progress, as after a refused closing
    // delivery. The Homeserver then shows another body at the renewing version: an alarm.
    // While it is held nothing is signed, the closing included, and the user is told the
    // reduction stays open. Once the alarm is cleared, the closing goes out and is published
    // over the other body.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 1,
    });
    signer.renew(id, reduce(&["notes"])).await.unwrap_err();
    world.switch.fail_next(SwitchFault::Error {
        path: "/identity".into(),
        code: ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    signer.resume().await.unwrap_err();
    let renewing = world.switch.identity_doc().unwrap();
    let mut body = renewing.body().clone();
    body.record_max_age = Some(7);
    let other = IdentityDoc::sign(&world.key, body).unwrap();
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(other.signed()).unwrap());
    let SignerError::Alarm(alarm) = signer.set_record_max_age(Some(60)).await.unwrap_err() else {
        panic!("no alarm")
    };
    // Held: nothing new is signed or sent, however often it resumes.
    let sent = world.sent_docs().len();
    for _ in 0..2 {
        assert_eq!(
            signer.resume().await.unwrap_err(),
            SignerError::Alarm(alarm.clone())
        );
    }
    assert_eq!(world.sent_docs().len(), sent);
    assert_eq!(renewals(&world.switch.identity_doc().unwrap(), &id), [None]);
    assert_eq!(world.published().unwrap().signed(), other.signed());
    assert_eq!(signer.status(), pubky_switch_signer::SignerStatus::Alarm);
    let open = Alert::ReductionNotClosed { apps: vec![id] };
    assert!(signer.alerts().contains(&open));
    // Cleared: the switch is confirmed, the closing is delivered, and it is published.
    signer.clear_alert(&alarm).await.unwrap();
    let closed = world.switch.identity_doc().unwrap();
    assert!(renewals(&closed, &id)[0].is_some());
    assert_eq!(world.published().unwrap().signed(), closed.signed());
    assert!(!signer.alerts().contains(&open));
    assert_eq!(signer.status(), pubky_switch_signer::SignerStatus::Signing);
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_renewal_an_owed_closing_isnt_signed_through_a_rollback_alarm() {
    // A closing is owed with no flow, and the switch then goes back a version: an alarm.
    // However often it resumes, no closing is signed while the alarm is held.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    let before = signer.identity_doc().unwrap().unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 1,
    });
    signer.renew(id, reduce(&["notes"])).await.unwrap_err();
    world.switch.fail_next(SwitchFault::Error {
        path: "/identity".into(),
        code: ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    signer.resume().await.unwrap_err();
    world.switch.deliver_identity(&before).unwrap();
    let SignerError::Alarm(_) = signer.set_record_max_age(Some(60)).await.unwrap_err() else {
        panic!("no alarm")
    };
    let sent = world.sent_docs().len();
    for _ in 0..3 {
        signer.resume().await.unwrap_err();
    }
    assert_eq!(world.sent_docs().len(), sent);
    assert_eq!(signer.status(), pubky_switch_signer::SignerStatus::Alarm);
}

#[tokio::test]
async fn test_renewal_refuses_an_app_that_isnt_listed() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let error = signer
        .renew([1; 16], CertChange::default())
        .await
        .unwrap_err();
    assert_eq!(error, SignerError::Refused(Refusal::NotListed));
}

#[tokio::test]
async fn test_renewal_refuses_a_new_scope_no_protocol_owns() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let error = signer
        .renew(app.keys.app_id_bytes(), reduce(&["photos"]))
        .await
        .unwrap_err();
    assert!(
        matches!(error, SignerError::Refused(Refusal::UnknownScopes { .. })),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_renewal_a_reductions_closing_survives_a_crash_at_every_commit() {
    // Under each fault the renewal is asked once, the clock moves on, and the store is
    // reopened as a restarted process finds it: whatever it held, the reduction ends closed
    // at the switch's time for the renewing delivery, and no version goes out with two bodies
    // (Switch wire 3.8 "A closing delivery owed").
    for n in 1..=12 {
        for fault in [Fault::StopBefore(n), Fault::StopAfter(n)] {
            let world = World::new();
            let memory = Arc::new(MemoryStore::new());
            let mut signer =
                Signer::create(world.env(memory.clone()), world.keyring(), SWITCH_ORIGIN)
                    .await
                    .unwrap();
            signer.resume().await.unwrap();
            let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
            world.approve(&mut signer, &app).await;
            let id = app.keys.app_id_bytes();
            world.clock.advance_ms(DAY_MS);
            let faulty: Arc<dyn StateStore> = Arc::new(FaultStore::new(memory.clone(), fault));
            let mut signer = Signer::open(world.env(faulty), world.keyring())
                .await
                .unwrap();
            let _ = signer.renew(id, reduce(&["notes"])).await;
            // Whether the switch took the renewing version before the crash, a day in.
            let took = world
                .switch
                .identity_doc()
                .is_some_and(|d| !renewals(&d, &id).is_empty());
            world.clock.advance_ms(DAY_MS);
            let mut restarted = Signer::open(world.env(memory), world.keyring())
                .await
                .unwrap();
            restarted
                .run_due()
                .await
                .unwrap_or_else(|e| panic!("{fault:?}: {e:?}"));
            let doc = restarted.identity_doc().unwrap().unwrap();
            let state = renewals(&doc, &id);
            // The renewal closed at the switch's time for its renewing delivery: a day in when
            // the switch took it before the crash, else two days in, when the restart
            // delivered it, unless the crash came before the renewal was kept.
            let day = |days: u64| Some(START_MS + days * DAY_MS + CLOCK_TOLERANCE_MS);
            if took {
                assert_eq!(state, [day(1)], "{fault:?}");
            } else {
                assert!(
                    state.is_empty() || state == [day(2)],
                    "{fault:?}: {state:?}"
                );
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
async fn test_renewal_an_added_scope_survives_the_next_rotation_unfetched() {
    // A renewal adds `notes_sync` to `a`, storing a full bundle with its earlier keys, which
    // `a` hasn't fetched when the next rotation comes: `keys_through(a)` doesn't vouch for
    // them. The rotation's part starts after the parts stored for `a`'s listed certificate,
    // so it replaces none of them, and `a` still gets every epoch of `notes_sync` (Switch
    // wire 3.5 "Incremental bundles").
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = |n: u8| {
        App::with_keys(
            AppKeys::from_secrets([n; 32], [n + 1; 32]),
            &["notes"],
            None,
            [n + 2; 32],
        )
    };
    let (a, b, c) = (app(3), app(13), app(23));
    for each in [&a, &b, &c] {
        world.approve(&mut signer, each).await;
    }
    let a_id = a.keys.app_id_bytes();
    let confirmed = pubky_switch_signer::UserConfirmed::shown_and_confirmed;
    signer
        .revoke(b.keys.app_id_bytes(), None, confirmed())
        .await
        .unwrap();
    let widening = CertChange {
        scopes: scopes(&["notes", "notes_sync"]),
        expires_at: None,
    };
    signer.renew(a_id, widening).await.unwrap();
    signer
        .revoke(c.keys.app_id_bytes(), None, confirmed())
        .await
        .unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.data_epoch(), 3);
    let parts = opened(&world, &a);
    let mut ranges: Vec<(u64, u64)> = parts
        .iter()
        .map(|p| (p.first_epoch, p.last_epoch))
        .collect();
    ranges.sort_unstable();
    assert_eq!(ranges, [(1, 2), (3, 3)]);
    for scope in ["notes", "notes_sync"] {
        assert!(
            (1..=3).all(|epoch| app_holds(&world, &a, &parts, epoch, scope)),
            "{scope}"
        );
    }
}

#[tokio::test]
async fn test_renewal_a_part_the_switch_no_longer_holds_is_sent_again() {
    // The signer stored `a`'s part for epoch 2, which a faulty switch then lost. At the next
    // rotation that part doesn't count as stored, since `bundle_ranges` no longer shows it:
    // `a`'s part starts after `keys_through`, and `a` gets epoch 2 again.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = |n: u8| {
        App::with_keys(
            AppKeys::from_secrets([n; 32], [n + 1; 32]),
            &["notes"],
            None,
            [n + 2; 32],
        )
    };
    let (a, b, c) = (app(3), app(13), app(23));
    for each in [&a, &b, &c] {
        world.approve(&mut signer, each).await;
    }
    let a_id = a.keys.app_id_bytes();
    let confirmed = pubky_switch_signer::UserConfirmed::shown_and_confirmed;
    signer
        .revoke(b.keys.app_id_bytes(), None, confirmed())
        .await
        .unwrap();
    assert!(holds(&world, &opened(&world, &a), 2, "notes"));
    world.switch.forget_bundle_parts(&a_id);
    signer
        .revoke(c.keys.app_id_bytes(), None, confirmed())
        .await
        .unwrap();
    let parts = opened(&world, &a);
    assert!((1..=3).all(|epoch| app_holds(&world, &a, &parts, epoch, "notes")));
}

/// The certificate `doc` lists for `app`, among those the signer holds.
fn listed_cert(signer: &Signer, doc: &IdentityDoc, app: &[u8; 16]) -> AppCert {
    let hash = doc.listed_cert(app).unwrap();
    signer
        .certificates()
        .unwrap()
        .into_iter()
        .find(|c| c.hash() == hash)
        .unwrap()
}

/// The default certificate lifetime, 365 days (Switch wire 3.1).
const LIFETIME_MS: u64 = 365 * DAY_MS;

#[tokio::test]
async fn test_renewal_on_expiry_renews_each_app_past_half_its_lifetime() {
    // Both apps' certificates were issued at the start, for a year. Until half of that has
    // passed, a run renews nothing; then one run renews each, in a version of its own, with a
    // year from then, and the next run renews nothing again (Switch spec 3.2).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_apps(&["notes"], &["notes"]);
    world.approve(&mut signer, &a).await;
    world.approve(&mut signer, &b).await;
    let ids = [a.keys.app_id_bytes(), b.keys.app_id_bytes()];
    world.clock.advance_ms(LIFETIME_MS / 2 - DAY_MS);
    let before = world.sent_docs().len();
    signer.run_due().await.unwrap();
    assert_eq!(world.sent_docs().len(), before, "not due yet");

    world.clock.advance_ms(2 * DAY_MS);
    signer.run_due().await.unwrap();
    let newest = signer.identity_doc().unwrap().unwrap();
    assert_eq!(world.sent_docs().len(), before + 2, "one version for each");
    let now = world.clock.now_ms();
    for id in &ids {
        assert_eq!(renewals(&newest, id), [None], "open until the app takes it");
        let cert = listed_cert(&signer, &newest, id);
        assert_eq!(cert.expires_at(), cert.issued_at() + LIFETIME_MS);
        assert!(cert.issued_at() >= now);
    }
    let sent = world.sent_docs().len();
    signer.run_due().await.unwrap();
    assert_eq!(world.sent_docs().len(), sent, "renewed once");
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_renewal_on_expiry_brings_back_an_app_whose_certificate_lapsed() {
    // The signer was offline past the certificate's expiry. The app is still current in spec
    // 3.4's sense, so the next run renews it, and the switch takes the renewal although the
    // certificate it replaces has expired; once the app's record carries the new certificate,
    // the renewal closes (Switch wire 3.8 "An expired certificate").
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_apps(&["notes"], &["notes"]);
    world.approve(&mut signer, &a).await;
    let id = a.keys.app_id_bytes();
    world.clock.advance_ms(LIFETIME_MS + 30 * DAY_MS);
    signer.run_due().await.unwrap();
    let newest = signer.identity_doc().unwrap().unwrap();
    assert_eq!(renewals(&newest, &id), [None]);
    let cert = listed_cert(&signer, &newest, &id);
    assert!(cert.expires_at() > world.clock.now_ms());
    assert!(world.switch.applied().iter().any(|op| matches!(
        &op.body().kind,
        OpKind::CertPut { target_app_id, .. } if *target_app_id == id
    )));
    assert!(holds(&world, &opened(&world, &a), 1, "notes"));

    // The app takes it and delivers its record carrying it.
    let record = AppRecord::sign(
        &a.keys,
        AppRecordBody::new(&cert, Vec::new(), world.clock.now_ms()),
    )
    .unwrap();
    world
        .switch
        .app_op(
            &a.keys,
            OpKind::AppPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    signer.run_due().await.unwrap();
    let closed = signer.identity_doc().unwrap().unwrap();
    assert!(renewals(&closed, &id).iter().all(Option::is_some));
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_renewal_on_expiry_leaves_removed_and_unjoined_apps_and_renews_open_ones() {
    // Past half their lifetime: `a`'s revocation couldn't reach the switch yet, `c` was
    // approved but never joined, and `e` has left, its removal not done yet: none of these is
    // renewed. `b` has a renewal its app hasn't taken, and is renewed again all the same, so
    // an app that stays away never lapses (Switch spec 3.2); `d` is renewed too.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_apps(&["notes"], &["notes"]);
    let c = App::with_keys(
        AppKeys::from_secrets([7; 32], [8; 32]),
        &["notes"],
        None,
        [11; 32],
    );
    let d = App::with_keys(
        AppKeys::from_secrets([12; 32], [13; 32]),
        &["notes"],
        None,
        [14; 32],
    );
    let e = App::with_keys(
        AppKeys::from_secrets([15; 32], [16; 32]),
        &["notes"],
        None,
        [17; 32],
    );
    world.approve(&mut signer, &e).await;
    world.approve(&mut signer, &a).await;
    world.approve(&mut signer, &b).await;
    world.approve(&mut signer, &d).await;
    let review = signer.review(&c.request, &c.auth).unwrap();
    let approved = signer.approve(review).await.unwrap();
    signer.claim_delivered(&approved.request).await.unwrap();
    let [a_id, b_id, c_id, d_id] = [&a, &b, &c, &d].map(|app| app.keys.app_id_bytes());
    signer
        .renew(
            b_id,
            CertChange {
                scopes: scopes(&["notes", "notes_tags"]),
                expires_at: None,
            },
        )
        .await
        .unwrap();
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    world.switch.fail_next(SwitchFault::Error {
        path: "/revoke".into(),
        code: ErrorCode::Unavailable,
        current: serde_json::Value::Null,
    });
    signer
        .revoke(
            a_id,
            None,
            pubky_switch_signer::UserConfirmed::shown_and_confirmed(),
        )
        .await
        .unwrap_err();
    let e_id = e.keys.app_id_bytes();
    world.switch.leave(e_id).unwrap();
    let before = signer.identity_doc().unwrap().unwrap();
    assert!(before.listed_cert(&a_id).is_some(), "still listed");
    assert!(before.listed_cert(&e_id).is_some(), "still listed");
    assert_eq!(signer.renew_expiring().await.unwrap(), [b_id, d_id]);
    let newest = signer.identity_doc().unwrap().unwrap();
    assert_eq!(renewals(&newest, &a_id), Vec::<Option<u64>>::new());
    assert_eq!(
        renewals(&newest, &b_id),
        [None, None],
        "renewed again while open"
    );
    assert_eq!(renewals(&newest, &c_id), Vec::<Option<u64>>::new());
    assert_eq!(renewals(&newest, &d_id), [None]);
    assert_eq!(renewals(&newest, &e_id), Vec::<Option<u64>>::new());
}

#[tokio::test]
async fn test_renewal_on_expiry_skips_a_scope_no_protocol_owns_and_tells_the_user() {
    // `b` holds `chat`, which no protocol registered now owns, so a renewal can't keep it:
    // `b` is skipped with an alert naming it and the scope, and `a` is renewed all the same
    // (design note, decision 2).
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let mut signer = notes_and_chat(&world, store.clone()).await;
    let (a, b) = two_apps(&["notes"], &["chat"]);
    world.approve(&mut signer, &a).await;
    world.approve(&mut signer, &b).await;
    drop(signer);
    let notes_only = Protocols::new(vec![Arc::new(Notes)]).unwrap();
    let mut signer = Signer::open(world.env_with(store, notes_only), world.keyring())
        .await
        .unwrap();
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    signer.run_due().await.unwrap();
    let skipped = Alert::RenewalSkipped {
        app_id: b.keys.app_id_bytes(),
        reason: RenewalSkip::UnownedScopes {
            scopes: vec!["chat".into()],
        },
    };
    assert!(signer.alerts().contains(&skipped));
    let newest = signer.identity_doc().unwrap().unwrap();
    assert_eq!(renewals(&newest, &a.keys.app_id_bytes()), [None]);
    assert!(renewals(&newest, &b.keys.app_id_bytes()).is_empty());
    let sent = world.sent_docs().len();
    signer.run_due().await.unwrap();
    assert_eq!(world.sent_docs().len(), sent);
    assert_eq!(
        signer.alerts().iter().filter(|al| **al == skipped).count(),
        1
    );
}

#[tokio::test]
async fn test_renewal_on_expiry_cut_short_is_finished_then_the_rest_renewed() {
    // The first app's renewing version couldn't reach the switch. The next run finishes that
    // renewal, sending the same bytes, then renews the other app: each once.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_apps(&["notes"], &["notes"]);
    world.approve(&mut signer, &a).await;
    world.approve(&mut signer, &b).await;
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    signer.run_due().await.unwrap_err();
    signer.run_due().await.unwrap();
    let newest = signer.identity_doc().unwrap().unwrap();
    assert_eq!(renewals(&newest, &a.keys.app_id_bytes()), [None]);
    assert_eq!(renewals(&newest, &b.keys.app_id_bytes()), [None]);
    world.assert_no_version_sent_twice();
}

/// A signer for `world` on `store` whose device clock reads `device_ms`, while the switch keeps
/// `world`'s clock.
async fn with_device_clock(world: &World, store: Arc<MemoryStore>, device_ms: u64) -> Signer {
    let env = SignerEnv {
        store: pubky_switch_client::store::StoreHandle::inline(store),
        clock: Arc::new(pubky_switch_client::clock::TestClock::new(device_ms)),
        transport: world.transport.clone(),
        homeserver: world.homeserver.clone(),
        protocols: Protocols::new(vec![Arc::new(Notes)]).unwrap(),
    };
    Signer::open(env, world.keyring()).await.unwrap()
}

#[tokio::test]
async fn test_renewal_on_expiry_waits_while_the_device_clock_is_off() {
    // Half the lifetime is judged on the switch's signed time, and a certificate is stamped
    // with the device clock. A device clock far ahead of the switch's time, or behind it,
    // renews nothing by itself and tells the user, and the user's own renewals and approvals
    // are refused; once the clocks agree, the renewal goes out (Switch spec 3.2, 10.1).
    for ahead in [true, false] {
        let world = World::new();
        let (mut signer, store) = world.enrolled().await;
        let (a, b) = two_apps(&["notes"], &["notes"]);
        world.approve(&mut signer, &a).await;
        drop(signer);
        let id = a.keys.app_id_bytes();
        let device = if ahead {
            // Not due by the switch's time.
            world.clock.advance_ms(DAY_MS);
            world.clock.now_ms() + LIFETIME_MS / 2 + DAY_MS
        } else {
            // Due by the switch's time.
            world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
            world.clock.now_ms() - CLOCK_TOLERANCE_MS - 1
        };
        let mut signer = with_device_clock(&world, store.clone(), device).await;
        let sent = world.sent_docs().len();
        signer.run_due().await.unwrap();
        assert_eq!(world.sent_docs().len(), sent, "ahead: {ahead}");
        assert!(signer.alerts().contains(&Alert::ClockOff), "ahead: {ahead}");
        let off =
            |error: SignerError| matches!(error, SignerError::Refused(Refusal::ClockOff { .. }));
        assert!(off(signer
            .renew(id, CertChange::default())
            .await
            .unwrap_err()));
        let review = signer.review(&b.request, &b.auth).unwrap();
        assert!(off(signer.approve(review).await.unwrap_err()));
        assert_eq!(world.sent_docs().len(), sent);

        drop(signer);
        let mut signer = with_device_clock(&world, store, world.clock.now_ms()).await;
        signer.run_due().await.unwrap();
        let newest = signer.identity_doc().unwrap().unwrap();
        assert_eq!(
            renewals(&newest, &id).len(),
            usize::from(!ahead),
            "ahead: {ahead}"
        );
        // The clocks agree again: the alert clears itself.
        assert!(
            !signer.alerts().contains(&Alert::ClockOff),
            "ahead: {ahead}"
        );
    }
}

#[tokio::test]
async fn test_renewal_on_expiry_keeps_an_app_away_for_lifetimes_served() {
    // The app never takes its renewals: each half lifetime it is renewed again, its listed
    // certificate never expires, and once it comes back with the newest one, every open
    // renewal closes (Switch spec 3.2).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_apps(&["notes"], &["notes"]);
    world.approve(&mut signer, &a).await;
    let id = a.keys.app_id_bytes();
    for round in 1..=3 {
        world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
        signer.run_due().await.unwrap();
        let newest = signer.identity_doc().unwrap().unwrap();
        assert_eq!(renewals(&newest, &id), vec![None; round]);
        let cert = listed_cert(&signer, &newest, &id);
        assert!(cert.expires_at() > world.clock.now_ms());
    }
    let newest = signer.identity_doc().unwrap().unwrap();
    let cert = listed_cert(&signer, &newest, &id);
    let record = AppRecord::sign(
        &a.keys,
        AppRecordBody::new(&cert, Vec::new(), world.clock.now_ms()),
    )
    .unwrap();
    world
        .switch
        .app_op(
            &a.keys,
            OpKind::AppPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    signer.run_due().await.unwrap();
    let closed = signer.identity_doc().unwrap().unwrap();
    let entries = renewals(&closed, &id);
    assert!(
        !entries.is_empty() && entries.iter().all(Option::is_some),
        "{entries:?}"
    );
    world.assert_no_version_sent_twice();
}

/// The test protocol's scopes, `notes` giving `permissions`: as after an update of its table.
struct NotesGiving(Vec<Permission>);

impl Protocol for NotesGiving {
    fn name(&self) -> &str {
        Notes.name()
    }
    fn scopes(&self) -> Vec<ScopeDef> {
        Notes.scopes()
    }
    fn check_scopes(&self, scopes: &[&str]) -> Result<(), String> {
        Notes.check_scopes(scopes)
    }
    fn permissions(&self, scopes: &[&str]) -> Vec<Permission> {
        if scopes.contains(&"notes") {
            self.0.clone()
        } else {
            Vec::new()
        }
    }
}

#[tokio::test]
async fn test_renewal_on_expiry_never_changes_what_a_certificate_grants() {
    // The protocol's table now gives `notes` more switch permissions, or fewer. A renewal the
    // user didn't ask for never changes what the certificate grants: the app is skipped, with
    // an alert naming both sets, and the user renews it by hand.
    for now in [
        vec![Permission::ClaimsRead, Permission::ClaimsWrite],
        Vec::new(),
    ] {
        let world = World::new();
        let (mut signer, store) = world.enrolled().await;
        let (a, _) = two_apps(&["notes"], &["notes"]);
        world.approve(&mut signer, &a).await;
        drop(signer);
        let updated = Protocols::new(vec![Arc::new(NotesGiving(now.clone()))]).unwrap();
        let mut signer = Signer::open(world.env_with(store, updated), world.keyring())
            .await
            .unwrap();
        world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
        let sent = world.sent_docs().len();
        signer.run_due().await.unwrap();
        assert_eq!(world.sent_docs().len(), sent, "{now:?}");
        let skipped = Alert::RenewalSkipped {
            app_id: a.keys.app_id_bytes(),
            reason: RenewalSkip::PermissionsChanged {
                held: vec!["claims.read".into()],
                now: now.iter().map(ToString::to_string).collect(),
            },
        };
        assert!(signer.alerts().contains(&skipped), "{:?}", signer.alerts());
    }
}

#[tokio::test]
async fn test_renewal_on_expiry_judges_half_the_lifetime_on_the_switchs_time() {
    // Just past half the lifetime by the switch's time, with the device clock 4 minutes
    // behind it, within the tolerance, and so not yet past half by its own reading: the
    // certificate is renewed (Switch spec 3.2).
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let (a, _) = two_apps(&["notes"], &["notes"]);
    world.approve(&mut signer, &a).await;
    drop(signer);
    let id = a.keys.app_id_bytes();
    let newest = world.switch.identity_doc().unwrap();
    let issued = {
        let signer = with_device_clock(&world, store.clone(), world.clock.now_ms()).await;
        listed_cert(&signer, &newest, &id).issued_at()
    };
    world.clock.set_ms(issued + LIFETIME_MS / 2 + 60_000);
    let mut signer = with_device_clock(&world, store, world.clock.now_ms() - 4 * 60_000).await;
    signer.run_due().await.unwrap();
    let renewed = signer.identity_doc().unwrap().unwrap();
    assert_eq!(renewals(&renewed, &id), [None]);
}

/// The test protocol's scopes, refusing `notes` by its own rule: as after an update.
struct NotesRefusing;

impl Protocol for NotesRefusing {
    fn name(&self) -> &str {
        Notes.name()
    }
    fn scopes(&self) -> Vec<ScopeDef> {
        Notes.scopes()
    }
    fn check_scopes(&self, scopes: &[&str]) -> Result<(), String> {
        if scopes.contains(&"notes") {
            return Err("notes now needs notes_sync".into());
        }
        Ok(())
    }
    fn permissions(&self, scopes: &[&str]) -> Vec<Permission> {
        Notes.permissions(scopes)
    }
}

#[tokio::test]
async fn test_renewal_on_expiry_tells_of_scopes_a_rule_now_refuses() {
    // The protocol's own rule now refuses the certificate's scopes: a renewal keeping them
    // would be refused, so the run skips the app and says why, instead of letting it lapse
    // unnoticed.
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let (a, _) = two_apps(&["notes"], &["notes"]);
    world.approve(&mut signer, &a).await;
    drop(signer);
    let updated = Protocols::new(vec![Arc::new(NotesRefusing)]).unwrap();
    let mut signer = Signer::open(world.env_with(store, updated), world.keyring())
        .await
        .unwrap();
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    let sent = world.sent_docs().len();
    signer.run_due().await.unwrap();
    assert_eq!(world.sent_docs().len(), sent);
    assert!(
        signer.alerts().iter().any(|alert| matches!(
            alert,
            Alert::RenewalSkipped {
                app_id,
                reason: RenewalSkip::ScopesRefused { protocol, reason },
            } if *app_id == a.keys.app_id_bytes()
                && protocol.as_deref() == Some("notes")
                && reason == "notes now needs notes_sync"
        )),
        "{:?}",
        signer.alerts()
    );
}

#[tokio::test]
async fn test_renewal_by_the_user_applies_the_protocols_table_now() {
    // The user renews with the scopes unchanged after the protocol's table changed: the new
    // certificate carries the permissions the table gives now, wider or narrower. A narrower
    // one is a reduction, which closes at once (Switch wire 3.8).
    for now in [
        vec![Permission::ClaimsRead, Permission::ClaimsWrite],
        Vec::new(),
    ] {
        let world = World::new();
        let (mut signer, store) = world.enrolled().await;
        let (a, _) = two_apps(&["notes"], &["notes"]);
        world.approve(&mut signer, &a).await;
        drop(signer);
        let id = a.keys.app_id_bytes();
        let updated = Protocols::new(vec![Arc::new(NotesGiving(now.clone()))]).unwrap();
        let mut signer = Signer::open(world.env_with(store, updated), world.keyring())
            .await
            .unwrap();
        signer.renew(id, CertChange::default()).await.unwrap();
        let newest = signer.identity_doc().unwrap().unwrap();
        let cert = listed_cert(&signer, &newest, &id);
        assert_eq!(cert.permissions(), now.as_slice());
        let closed = renewals(&newest, &id).iter().all(Option::is_some);
        assert_eq!(closed, now.is_empty(), "{now:?}");
    }
}

#[tokio::test]
async fn test_renewal_each_batch_checked_against_another_install() {
    // A renewal in two batches: another install delivering right after the check before the
    // first stops the second, which this install no longer signs for (Switch spec 4.3).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_apps(&["notes", "notes_sync"], &["notes", "notes_sync"]);
    world.approve(&mut signer, &a).await;
    world.approve(&mut signer, &b).await;
    // Six more apps holding `notes`: nine operations, two batches.
    for n in 0..6u8 {
        let more = App::with_keys(
            AppKeys::from_secrets([20 + 2 * n; 32], [21 + 2 * n; 32]),
            &["notes"],
            None,
            [40 + n; 32],
        );
        world.approve(&mut signer, &more).await;
    }
    let ops = |world: &World| {
        world
            .transport
            .requests()
            .iter()
            .filter(|r| r.method == "POST" && r.path_and_query.ends_with("/ops"))
            .count()
    };
    let before = ops(&world);
    let other = world.other_install_version(&signer.identity_doc().unwrap().unwrap(), [9; 16]);
    let switch = Arc::clone(&world.switch);
    // The signer backup's second read is the check before the first batch; the first is the
    // signing gate's.
    *world.homeserver.after_get.lock().unwrap() = Some((
        pubky_switch_core::records::SIGNER_BACKUP_PATH.to_owned(),
        2,
        Box::new(move || switch.deliver_identity(&other).unwrap()),
    ));
    let error = signer
        .renew(a.keys.app_id_bytes(), reduce(&["notes_sync"]))
        .await
        .unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: [9; 16] });
    assert_eq!(ops(&world), before + 1, "the second batch isn't sent");
}

/// How many requests `world`'s switch got for `method` `path` (a suffix) so far.
fn sent(world: &World, method: &str, path: &str) -> usize {
    world
        .transport
        .requests()
        .iter()
        .filter(|r| r.method == method && r.path_and_query.ends_with(path))
        .count()
}

#[tokio::test]
async fn test_run_due_with_nothing_due_reads_the_switch_once_a_step() {
    // Nothing due: each step that checks this install still signs reads `GET /apps` once,
    // and takes the apps it goes by from that same answer; closing renewals reads nothing
    // with none open (design note, section 4.5).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let before = sent(&world, "GET", "/apps");
    signer.run_due().await.unwrap();
    // Removals, full bundles, renewals past half their lifetime, publication.
    assert_eq!(sent(&world, "GET", "/apps") - before, 4);
}

#[tokio::test]
async fn test_run_due_open_renewal_reads_the_switch_for_it() {
    // A cooperative renewal open: closing it reads the switch, once, and closes it at the
    // time the switch took the app's record (Switch wire 3.8 step 4).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    let change = CertChange {
        scopes: None,
        expires_at: Some(START_MS + 400 * DAY_MS),
    };
    signer.renew(id, change).await.unwrap();
    world.clock.advance_ms(3_600_000);
    let new = world.switch.app(&id).renewed.unwrap();
    let record_at = START_MS + 3_600_000;
    let record =
        AppRecord::sign(&app.keys, AppRecordBody::new(&new, Vec::new(), record_at)).unwrap();
    world
        .switch
        .app_op(
            &app.keys,
            OpKind::AppPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    let before = sent(&world, "GET", "/apps");
    signer.run_due().await.unwrap();
    assert_eq!(
        renewals(&signer.identity_doc().unwrap().unwrap(), &id),
        [Some(record_at + CLOCK_TOLERANCE_MS)]
    );
    // The four of a run with nothing due, the closing's read, and its delivery's check
    // before it publishes.
    assert_eq!(sent(&world, "GET", "/apps") - before, 6);
}

#[tokio::test]
async fn test_approval_reads_the_switch_once_before_its_delivery() {
    // The approval's copy check and its clock check are one read; its publication checks
    // again after the delivery (Switch spec 4.3).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let before = world.transport.requests().len();
    world
        .approve(&mut signer, &App::new(&["notes"], None, [9; 32]))
        .await;
    let sent: Vec<_> = world.transport.requests()[before..]
        .iter()
        .map(|r| {
            (
                r.method.clone(),
                r.path_and_query.ends_with("/apps"),
                r.path_and_query.ends_with("/identity"),
            )
        })
        .collect();
    let delivery = sent
        .iter()
        .position(|(method, _, identity)| method == "PUT" && *identity)
        .expect("a delivery");
    let reads = |requests: &[(String, bool, bool)]| {
        requests
            .iter()
            .filter(|(method, apps, _)| method == "GET" && *apps)
            .count()
    };
    assert_eq!(reads(&sent[..delivery]), 1);
    assert_eq!(reads(&sent[delivery..]), 1);
}

#[tokio::test]
async fn test_run_due_step_reads_the_switch_again_after_delivering_an_owed_closing() {
    // A crash leaves a reduction's closing owed with no flow in progress. The next step's
    // check delivers it first; the apps the step then goes by are read after that delivery,
    // not taken from the read before it (Switch wire 3.8 "A closing delivery owed").
    let mut found = false;
    for n in 1..=12 {
        let world = World::new();
        let memory = Arc::new(MemoryStore::new());
        let mut signer = Signer::create(world.env(memory.clone()), world.keyring(), SWITCH_ORIGIN)
            .await
            .unwrap();
        signer.resume().await.unwrap();
        let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
        world.approve(&mut signer, &app).await;
        let id = app.keys.app_id_bytes();
        world.clock.advance_ms(DAY_MS);
        let faulty: Arc<dyn StateStore> =
            Arc::new(FaultStore::new(memory.clone(), Fault::StopAfter(n)));
        let mut signer = Signer::open(world.env(faulty), world.keyring())
            .await
            .unwrap();
        let _ = signer.renew(id, reduce(&["notes"])).await;
        let mut restarted = Signer::open(world.env(memory), world.keyring())
            .await
            .unwrap();
        let open = |doc: Option<IdentityDoc>| doc.is_some_and(|d| renewals(&d, &id) == [None]);
        if !open(world.switch.identity_doc()) {
            continue;
        }
        let before = world.transport.requests().len();
        // Only where the step itself delivers the closing.
        if restarted.serve_full_bundles().await.is_err() || open(world.switch.identity_doc()) {
            continue;
        }
        found = true;
        let requests = world.transport.requests()[before..].to_vec();
        let closing = requests
            .iter()
            .rposition(|r| r.method == "PUT" && r.path_and_query.ends_with("/identity"))
            .expect("the closing's delivery");
        let reads = requests[closing..]
            .iter()
            .filter(|r| r.method == "GET" && r.path_and_query.ends_with("/apps"))
            .count();
        // The publication's check, then the step's own read.
        assert_eq!(reads, 2, "StopAfter({n})");
    }
    assert!(found, "a crash that leaves the closing owed");
}

#[tokio::test]
async fn test_renewal_clock_off_isnt_cleared_by_a_slow_backup_read() {
    // The device clock is 5.5 minutes behind the switch: the renewals are skipped with
    // `ClockOff`. At the next check the signer backup read takes 60 s; the device clock when
    // the switch's answer came is still off, so the alert stays (Switch spec 10.1).
    use pubky_switch_client::clock::TestClock;
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    world
        .approve(&mut signer, &App::new(&["notes"], None, [9; 32]))
        .await;
    drop(signer);
    let device = Arc::new(TestClock::new(world.clock.now_ms() - 330_000));
    let mut env = world.env(store);
    env.clock = device.clone();
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    signer.renew_expiring().await.unwrap();
    assert!(signer.alerts().contains(&Alert::ClockOff));
    let switch_clock = Arc::clone(&world.clock);
    let device_clock = Arc::clone(&device);
    *world.homeserver.after_get.lock().unwrap() = Some((
        SIGNER_BACKUP_PATH.to_owned(),
        1,
        Box::new(move || {
            switch_clock.advance_ms(60_000);
            device_clock.advance_ms(60_000);
        }),
    ));
    signer.renew_expiring().await.unwrap();
    assert!(signer.alerts().contains(&Alert::ClockOff));
}
