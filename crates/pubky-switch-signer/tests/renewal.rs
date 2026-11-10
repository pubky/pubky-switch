//! Renewals and reductions against the scripted switch (Switch spec 3.2; Switch wire 3.5,
//! 3.8): the stored certificate and key bundles, the renewing version, a reduction's closing
//! at once, a rotation's bundles for the other apps, the closing owed after a crash, and a
//! cooperative renewal closed once the app's record carries the new certificate.

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::*;
use pubky_switch_client::store::{Fault, FaultStore, MemoryStore, StateStore};
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::ops::OpKind;
use pubky_switch_core::records::{AppRecord, AppRecordBody, CLOCK_TOLERANCE_MS, IdentityDoc};
use pubky_switch_signer::{CertChange, Refusal, Signer, SignerError};

const DAY_MS: u64 = 86_400_000;

fn scopes(list: &[&str]) -> Option<Vec<String>> {
    Some(list.iter().map(|s| (*s).to_owned()).collect())
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

#[tokio::test]
async fn test_renewal_extending_the_expiry_stores_the_cert_and_bundle_and_stays_open() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let approved = world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    let old = approved.listed_cert(&id).unwrap();
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
    // The renewing version lists the new certificate, keeps the earlier one open, and
    // nothing follows it: extending the expiry isn't a reduction.
    let new = doc.listed_cert(&id).unwrap();
    assert_ne!(new, old);
    assert_eq!(doc.body().renewed[0].cert, old);
    assert_eq!(renewals(&doc, &id), [None]);
    assert_eq!(doc.data_epoch(), 1);
    assert_eq!(world.switch.identity_doc().unwrap().signed(), doc.signed());
    // The switch holds the renewed certificate and a full bundle made for it.
    let held = world.switch.app(&id);
    assert_eq!(held.renewed.unwrap().hash(), new);
    assert_eq!(world.backup().identity_doc().signed(), doc.signed());
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_renewal_cooperative_closes_once_the_apps_record_carries_the_new_cert() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
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
    // The app delivers its record carrying the new certificate (Switch wire 3.8 step 3).
    let new = world.switch.app(&id).renewed.unwrap();
    let record = AppRecord::sign(
        &app.keys,
        AppRecordBody::new(&new, Vec::new(), START_MS + 1),
    )
    .unwrap();
    world
        .switch
        .app_op(
            &app.keys,
            OpKind::AppPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    assert_eq!(signer.complete_renewals().await.unwrap(), [id]);
    let closed = signer.identity_doc().unwrap().unwrap();
    assert_eq!(closed.version(), doc.version() + 1);
    assert_eq!(
        renewals(&closed, &id),
        [Some(START_MS + CLOCK_TOLERANCE_MS)]
    );
}

#[tokio::test]
async fn test_renewal_a_reduction_closes_at_once() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    // Removing `notes_tags`, a scope without keys, is a reduction that rotates nothing.
    let renewing = signer
        .renew(
            id,
            CertChange {
                scopes: scopes(&["notes"]),
                expires_at: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(renewing.data_epoch(), 1);
    let closed = signer.identity_doc().unwrap().unwrap();
    assert_eq!(closed.version(), renewing.version() + 1);
    // The cutoff is the switch's time for the renewing delivery plus the tolerance.
    assert_eq!(
        renewals(&closed, &id),
        [Some(START_MS + CLOCK_TOLERANCE_MS)]
    );
    assert_eq!(
        world.switch.identity_doc().unwrap().signed(),
        closed.signed()
    );
    assert_eq!(world.published().unwrap().signed(), closed.signed());
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_renewal_removing_a_keyed_scope_rotates_the_data_epoch() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let reduced = App::with_keys(
        AppKeys::from_secrets([3; 32], [4; 32]),
        &["notes", "notes_tags"],
        None,
        [9; 32],
    );
    let other = App::with_keys(
        AppKeys::from_secrets([5; 32], [6; 32]),
        &["notes"],
        None,
        [10; 32],
    );
    world.approve(&mut signer, &reduced).await;
    world.approve(&mut signer, &other).await;
    let id = reduced.keys.app_id_bytes();
    let renewing = signer
        .renew(
            id,
            CertChange {
                scopes: scopes(&["notes_tags"]),
                expires_at: None,
            },
        )
        .await
        .unwrap();
    // The renewing version raises the data epoch (Switch wire 3.8 "A removed scope's keys
    // rotate"), and the reduction closes.
    assert_eq!(renewing.data_epoch(), 2);
    let closed = signer.identity_doc().unwrap().unwrap();
    assert_eq!(
        renewals(&closed, &id),
        [Some(START_MS + CLOCK_TOLERANCE_MS)]
    );
    // The other app got its bundle for the new epoch before the version that raised it.
    let other_id = other.keys.app_id_bytes();
    let parts = world.switch.bundles_of(&other_id);
    assert!(
        parts.iter().any(|(first, last)| *first <= 2 && *last == 2),
        "{parts:?}"
    );
    // The reduced app's full bundle runs through epoch 2.
    let reduced_parts = world.switch.bundles_of(&id);
    assert_eq!(reduced_parts, [(1, 2)]);
    world.assert_no_version_sent_twice();
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
async fn test_renewal_refuses_a_scope_no_protocol_owns() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let error = signer
        .renew(
            app.keys.app_id_bytes(),
            CertChange {
                scopes: scopes(&["photos"]),
                expires_at: None,
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, SignerError::Refused(Refusal::UnknownScopes { .. })),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_renewal_a_reductions_closing_survives_a_crash_at_every_commit() {
    // Under each fault the renewal is asked once, then the store is reopened as a restarted
    // process finds it: whatever it held, the reduction ends closed at the switch's time for
    // the renewing delivery, and no version goes out with two bodies (Switch wire 3.8 "A
    // closing delivery owed").
    for n in 1..=12 {
        for fault in [Fault::StopBefore(n), Fault::StopAfter(n)] {
            let world = World::new();
            let memory = Arc::new(MemoryStore::new());
            let mut signer = Signer::create(
                world.env(memory.clone()),
                world.keyring(),
                pubky_switch_client::testing::SWITCH_ORIGIN,
            )
            .await
            .unwrap();
            signer.resume().await.unwrap();
            let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
            world.approve(&mut signer, &app).await;
            let id = app.keys.app_id_bytes();
            let faulty: Arc<dyn StateStore> = Arc::new(FaultStore::new(memory.clone(), fault));
            let mut signer = Signer::open(world.env(faulty), world.keyring())
                .await
                .unwrap();
            let _ = signer
                .renew(
                    id,
                    CertChange {
                        scopes: scopes(&["notes"]),
                        expires_at: None,
                    },
                )
                .await;
            let mut restarted = Signer::open(world.env(memory), world.keyring())
                .await
                .unwrap();
            restarted
                .run_due()
                .await
                .unwrap_or_else(|e| panic!("{fault:?}: {e:?}"));
            let doc = restarted.identity_doc().unwrap().unwrap();
            let state = renewals(&doc, &id);
            // The renewal either never reached the switch, or it closed at the right time.
            assert!(
                state.is_empty() || state == [Some(START_MS + CLOCK_TOLERANCE_MS)],
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
