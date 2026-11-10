//! Renewals and reductions against the scripted switch (Switch spec 3.2; Switch wire 3.5,
//! 3.8): the stored certificate and key bundles, the renewing version, a reduction's closing
//! at the switch's time, a rotation's bundles for the current apps only, above every epoch
//! ever sent, the closing owed after a crash, and a cooperative renewal closed once the app's
//! record carries the new certificate. The clock moves between steps, so every cutoff is
//! checked against the switch's time.

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::*;
use pubky_switch_client::store::{Fault, FaultStore, MemoryStore, StateStore};
use pubky_switch_client::testing::{Fault as SwitchFault, SWITCH_ORIGIN};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::ops::OpKind;
use pubky_switch_core::records::{
    AppRecord, AppRecordBody, CLOCK_TOLERANCE_MS, IdentityDoc, KeyBundleContents,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_signer::{
    Alert, CertChange, Protocol, Protocols, Refusal, ScopeDef, Signer, SignerError,
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
async fn test_renewal_a_given_up_rotation_never_hands_out_the_next_epoch() {
    // A rotation stores the other app's bundle for epoch 2, then its delivery is refused. The
    // next rotation goes to epoch 3, so the key that app got early is no current epoch's
    // (Switch spec 3.2, 3.5).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_apps(&["notes", "notes_sync"], &["notes", "notes_sync"]);
    world.approve(&mut signer, &a).await;
    world.approve(&mut signer, &b).await;
    world.switch.fail_next(SwitchFault::Error {
        path: "/identity".into(),
        code: ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    signer
        .renew(a.keys.app_id_bytes(), reduce(&["notes_sync"]))
        .await
        .unwrap_err();
    assert_eq!(signer.identity_doc().unwrap().unwrap().data_epoch(), 1);
    assert!(holds(&world, &opened(&world, &b), 2, "notes"));
    let renewing = signer
        .renew(b.keys.app_id_bytes(), reduce(&["notes_sync"]))
        .await
        .unwrap();
    assert_eq!(renewing.data_epoch(), 3);
    // The app that keeps `notes` gets the key of epoch 3.
    assert!(holds(&world, &opened(&world, &a), 3, "notes"));
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

#[tokio::test]
async fn test_renewal_stops_at_a_scope_no_registered_protocol_owns() {
    let world = World::new();
    let both = || Protocols::new(vec![Arc::new(Notes), Arc::new(Chat)]).unwrap();
    let store = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(
        world.env_with(store.clone(), both()),
        world.keyring(),
        SWITCH_ORIGIN,
    )
    .await
    .unwrap();
    signer.resume().await.unwrap();
    let (a, b) = two_apps(&["notes", "notes_sync"], &["chat"]);
    world.approve(&mut signer, &a).await;
    world.approve(&mut signer, &b).await;
    drop(signer);
    // Reopened with `notes` only: the rotation needs a bundle for `b`, whose `chat` it can't
    // judge, so it stops and names the scope (design note, decision 2).
    let notes_only = Protocols::new(vec![Arc::new(Notes)]).unwrap();
    let mut signer = Signer::open(world.env_with(store.clone(), notes_only), world.keyring())
        .await
        .unwrap();
    let error = signer
        .renew(a.keys.app_id_bytes(), reduce(&["notes_sync"]))
        .await
        .unwrap_err();
    assert_eq!(
        error,
        SignerError::Refused(Refusal::UnknownScopes {
            scopes: vec!["chat".into()]
        })
    );
    // Reopened with `chat` only: removing `notes` from `a` can't be judged either.
    let chat_only = Protocols::new(vec![Arc::new(Chat)]).unwrap();
    let mut signer = Signer::open(world.env_with(store, chat_only), world.keyring())
        .await
        .unwrap();
    let error = signer
        .renew(a.keys.app_id_bytes(), reduce(&["notes_sync"]))
        .await
        .unwrap_err();
    assert!(
        matches!(error, SignerError::Refused(Refusal::UnknownScopes { .. })),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_renewal_a_closing_without_a_service_time_is_reported_not_retried() {
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
    assert!(
        signer
            .alerts()
            .contains(&Alert::ReductionNotClosed { apps: vec![id] })
    );
    // A bounded number of deliveries, and later calls go on.
    assert!(world.sent_docs().len() - before <= 2);
    signer.resume().await.unwrap();
    assert!(world.sent_docs().len() - before <= 2);
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
            // The renewal either never reached the switch, or it closed at the switch's time
            // for its renewing delivery: before the restart, a day in, or after it, two days
            // in, when the crash came before anything was sent.
            let cutoffs = [
                Some(START_MS + DAY_MS + CLOCK_TOLERANCE_MS),
                Some(START_MS + 2 * DAY_MS + CLOCK_TOLERANCE_MS),
            ];
            assert!(
                state.is_empty() || (state.len() == 1 && cutoffs.contains(&state[0])),
                "{fault:?}: {state:?}"
            );
            assert_eq!(
                world.switch.identity_doc().unwrap().signed(),
                doc.signed(),
                "{fault:?}"
            );
            world.assert_no_version_sent_twice();
        }
    }
}
