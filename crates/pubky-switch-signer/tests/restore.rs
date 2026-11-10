//! Restoring the signer from its backup against the scripted switch (Switch spec 12.8; Switch
//! wire 3.13): in place, when the records are behind, and on a new install; the version the
//! backup holds delivered first when the switch is at the one before; stale, missing and
//! unreadable backups refused; and what the backup doesn't carry rebuilt: the epoch floor, and
//! a removed app's record deletion with its grant reminder.

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::*;
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::Fault as SwitchFault;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::records::{
    IDENTITY_PATH, IdentityDoc, Limits, SIGNER_BACKUP_PATH, SignerBackup, SignerRecords,
    app_record_path,
};
use pubky_switch_signer::{
    Alert, CertChange, Refusal, Signer, SignerError, SignerStatus, UserConfirmed,
};

fn confirmed() -> UserConfirmed {
    UserConfirmed::shown_and_confirmed()
}

/// A version `version` of this install's own above `doc`, at data epoch 2, and its backup.
fn own_newer(world: &World, doc: &IdentityDoc, version: u64) -> (IdentityDoc, Vec<u8>) {
    let mut body = doc.body().clone();
    body.version = version;
    body.data_epoch = 2;
    let newer = IdentityDoc::sign(&world.key, body).unwrap();
    let records = SignerRecords::new(
        IdentityKey::from_secret(SECRET),
        newer.clone(),
        &[],
        &[],
        Limits::default(),
        &[],
        None,
    )
    .unwrap();
    let backup = SignerBackup::seal(&world.key, &records).unwrap();
    (newer, serde_json::to_vec(&backup).unwrap())
}

/// Two apps holding `notes` (and `a` also `notes_sync`), approved and joined.
async fn two_joined(world: &World, signer: &mut Signer) -> (App, App) {
    let a = App::with_keys(
        AppKeys::from_secrets([3; 32], [4; 32]),
        &["notes", "notes_sync"],
        None,
        [9; 32],
    );
    let b = App::with_keys(
        AppKeys::from_secrets([5; 32], [6; 32]),
        &["notes", "notes_sync"],
        None,
        [10; 32],
    );
    world.approve(signer, &a).await;
    world.approve(signer, &b).await;
    (a, b)
}

/// A new install on a store of its own, restored from the backup.
async fn restored(world: &World) -> Result<Signer, SignerError> {
    Signer::restore_new(
        world.env(Arc::new(MemoryStore::new())),
        world.keyring(),
        confirmed(),
    )
    .await
}

#[tokio::test]
async fn test_restore_in_place_clears_records_behind() {
    // The switch and the backup hold this install's own version 9, at data epoch 2, and the
    // records are at version 1. The restore takes the backup's records and signs version 10
    // as this install, so signing goes on.
    let world = World::new();
    let (signer, memory) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let install = signer.install_id();
    drop(signer);
    let (nine, backup) = own_newer(&world, &first, 9);
    world.switch.deliver_identity(&nine).unwrap();
    world.homeserver.set(SIGNER_BACKUP_PATH, backup);
    let mut signer = Signer::open(world.env(memory), world.keyring())
        .await
        .unwrap();
    signer.set_record_max_age(Some(60)).await.unwrap_err();
    assert_eq!(signer.status(), SignerStatus::RecordsBehind { version: 9 });
    let ten = signer.restore(confirmed()).await.unwrap();
    assert_eq!(ten.version(), 10);
    assert_eq!(ten.data_epoch(), 2);
    assert_eq!(ten.body().signer, install);
    assert_eq!(signer.status(), SignerStatus::Signing);
    assert!(
        !signer
            .alerts()
            .iter()
            .any(|a| matches!(a, Alert::RecordsBehind { .. }))
    );
    assert_eq!(world.switch.identity_doc().unwrap().signed(), ten.signed());
    assert_eq!(world.published().unwrap().signed(), ten.signed());
    assert_eq!(world.backup().identity_doc().signed(), ten.signed());
    signer.set_record_max_age(Some(60)).await.unwrap();
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_restore_on_a_new_install_takes_over() {
    // A new device restores from the backup: it delivers the next version as its own install,
    // and the old install, opened again, finds another install signing.
    let world = World::new();
    let (mut old, memory) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut old).await;
    let before = old.identity_doc().unwrap().unwrap();
    let old_install = old.install_id();
    drop(old);
    let mut signer = restored(&world).await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.version(), before.version() + 1);
    assert_ne!(doc.body().signer, old_install);
    assert_eq!(doc.body().signer, signer.install_id());
    assert_eq!(doc.body().apps, before.body().apps);
    assert_eq!(world.backup().identity_doc().signed(), doc.signed());
    // The restored install holds the certificates: it renews a listed app.
    let change = CertChange {
        scopes: None,
        expires_at: Some(START_MS + 400 * 86_400_000),
    };
    signer.renew(a.keys.app_id_bytes(), change).await.unwrap();
    let mut old = Signer::open(world.env(memory), world.keyring())
        .await
        .unwrap();
    assert_eq!(
        old.set_record_max_age(Some(60)).await.unwrap_err(),
        SignerError::NotNamed {
            install: signer.install_id()
        }
    );
}

#[tokio::test]
async fn test_restore_delivers_the_backups_version_first_when_the_switch_is_before_it() {
    // The signer wrote the backup of version 2 and stopped before delivering it: the switch
    // is at version 1, the one version 2 builds on. The restore delivers version 2 first, then
    // version 3 as its own.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    old.set_record_max_age(Some(86_400)).await.unwrap_err();
    drop(old);
    assert_eq!(world.switch.identity_doc().unwrap().version(), 1);
    assert_eq!(world.backup().identity_doc().version(), 2);
    let signer = restored(&world).await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.version(), 3);
    assert_eq!(doc.body().record_max_age, Some(86_400));
    assert!(world.sent_docs().iter().any(|d| d.version() == 2));
}

#[tokio::test]
async fn test_restore_refuses_a_stale_backup() {
    // Another install delivered a newer version since the backup: the switch is past it.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    let first = old.identity_doc().unwrap().unwrap();
    drop(old);
    let mut body = first.body().clone();
    body.version = 2;
    body.signer = [7; 16];
    world
        .switch
        .deliver_identity(&IdentityDoc::sign(&world.key, body).unwrap())
        .unwrap();
    assert_eq!(
        restored(&world).await.unwrap_err(),
        SignerError::Refused(Refusal::StaleBackup)
    );
}

#[tokio::test]
async fn test_restore_refuses_when_the_homeserver_holds_another_body() {
    let world = World::new();
    let (old, _) = world.enrolled().await;
    let first = old.identity_doc().unwrap().unwrap();
    drop(old);
    let mut body = first.body().clone();
    body.record_max_age = Some(7);
    let other = IdentityDoc::sign(&world.key, body).unwrap();
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(other.signed()).unwrap());
    assert_eq!(
        restored(&world).await.unwrap_err(),
        SignerError::Refused(Refusal::StaleBackup)
    );
}

#[tokio::test]
async fn test_restore_refuses_a_missing_or_unreadable_backup() {
    let world = World::new();
    let (old, _) = world.enrolled().await;
    drop(old);
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, b"not a backup".to_vec());
    assert_eq!(
        restored(&world).await.unwrap_err(),
        SignerError::Refused(Refusal::UnreadableBackup)
    );
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    assert_eq!(
        restored(&world).await.unwrap_err(),
        SignerError::Refused(Refusal::NoBackup)
    );
}

#[tokio::test]
async fn test_restore_rebuilds_an_owed_record_deletion_and_its_reminder() {
    // `a` was revoked and its record's deletion failed, so it is owed. The backup doesn't
    // carry that: the restored install finds the record of an app no version lists, deletes
    // it, and raises the grant reminder once more.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut old).await;
    let id = a.keys.app_id_bytes();
    world
        .homeserver
        .set(&app_record_path(&id), b"a's record".to_vec());
    *world.homeserver.failing_path.lock().unwrap() = Some(app_record_path(&id));
    old.revoke(id, None, confirmed()).await.unwrap();
    drop(old);
    *world.homeserver.failing_path.lock().unwrap() = None;
    let signer = restored(&world).await.unwrap();
    assert!(world.homeserver.file(&app_record_path(&id)).is_none());
    assert!(
        signer
            .alerts()
            .contains(&Alert::GrantRevocationOwed { app_id: id })
    );
}

#[tokio::test]
async fn test_restore_keeps_the_epoch_floor_the_switch_shows() {
    // A rotation in two batches stored epoch 2's keys in its first, and its second was
    // refused, before any backup of it was written. The backup doesn't show epoch 2, but the
    // switch does: the restored install's next rotation completes epoch 2 first, and goes to 3.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut old).await;
    for n in 0..6u8 {
        let more = App::with_keys(
            AppKeys::from_secrets([20 + 2 * n; 32], [21 + 2 * n; 32]),
            &["notes"],
            None,
            [40 + n; 32],
        );
        world.approve(&mut old, &more).await;
    }
    let reduce = || CertChange {
        scopes: Some(vec!["notes_sync".into()]),
        expires_at: None,
    };
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/ops".into(),
        after: 1,
    });
    old.renew(a.keys.app_id_bytes(), reduce())
        .await
        .unwrap_err();
    world.switch.fail_next(SwitchFault::Error {
        path: "/ops".into(),
        code: ErrorCode::Conflict,
        current: serde_json::Value::Null,
    });
    old.resume().await.unwrap_err();
    drop(old);
    assert_eq!(world.backup().identity_doc().data_epoch(), 1);
    let mut signer = restored(&world).await.unwrap();
    assert_eq!(signer.identity_doc().unwrap().unwrap().data_epoch(), 1);
    let renewing = signer.renew(b.keys.app_id_bytes(), reduce()).await.unwrap();
    assert_eq!(renewing.data_epoch(), 3);
}

#[tokio::test]
async fn test_restore_keeps_a_revocation_only_the_switch_shows() {
    // The switch revoked `a`, which the backup's records don't show: the restored install
    // keeps its App ID for good all the same.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut old).await;
    drop(old);
    world.switch.revoke(a.keys.app_id_bytes()).unwrap();
    let signer = restored(&world).await.unwrap();
    assert!(matches!(
        signer.review(&a.request, &a.auth),
        Err(SignerError::Refused(Refusal::AppRequest(ref why))) if why.contains("step 4")
    ));
}

/// A backup of `doc`, the switch's copy, written as a signer would, with these records.
fn backup_of(
    world: &World,
    doc: &IdentityDoc,
    revoked: &[[u8; 16]],
    apps: &[&App],
    parts: &[pubky_switch_core::records::StoredPart],
) -> Vec<u8> {
    let certs: Vec<_> = apps
        .iter()
        .map(|app| world.switch.app(&app.keys.app_id_bytes()).cert.unwrap())
        .collect();
    let records = SignerRecords::new(
        IdentityKey::from_secret(SECRET),
        doc.clone(),
        revoked,
        &certs,
        Limits::default(),
        parts,
        None,
    )
    .unwrap();
    serde_json::to_vec(&SignerBackup::seal(&world.key, &records).unwrap()).unwrap()
}

/// The switch, its backup and the Homeserver's `identity.json` as they are now, to put back.
fn snapshot(world: &World) -> (IdentityDoc, Vec<u8>, Vec<u8>) {
    (
        world.switch.identity_doc().unwrap(),
        world.homeserver.file(SIGNER_BACKUP_PATH).unwrap(),
        world.homeserver.file(IDENTITY_PATH).unwrap(),
    )
}

fn put_back(world: &World, (doc, backup, published): &(IdentityDoc, Vec<u8>, Vec<u8>)) {
    world.switch.deliver_identity(doc).unwrap();
    world.homeserver.set(SIGNER_BACKUP_PATH, backup.clone());
    world.homeserver.set(IDENTITY_PATH, published.clone());
}

#[tokio::test]
async fn test_restore_in_place_refuses_a_backup_below_the_mark() {
    // The install revoked `a` at version 4. The switch, the backup and the Homeserver all go
    // back to version 3: restoring over that would list `a` again, so it is refused.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let before = snapshot(&world);
    signer
        .revoke(a.keys.app_id_bytes(), None, confirmed())
        .await
        .unwrap();
    put_back(&world, &before);
    let sent = world.sent_docs().len();
    assert_eq!(
        signer.restore(confirmed()).await.unwrap_err(),
        SignerError::Refused(Refusal::StaleBackup)
    );
    assert_eq!(world.sent_docs().len(), sent);
}

#[tokio::test]
async fn test_restore_in_place_never_clears_an_alarm() {
    // The same rollback, seen first by a signing call: the alarm stands, and the restore is
    // refused while it does.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let before = snapshot(&world);
    signer
        .revoke(a.keys.app_id_bytes(), None, confirmed())
        .await
        .unwrap();
    put_back(&world, &before);
    let SignerError::Alarm(alarm) = signer.set_record_max_age(Some(60)).await.unwrap_err() else {
        panic!("no alarm")
    };
    assert_eq!(
        signer.restore(confirmed()).await.unwrap_err(),
        SignerError::Alarm(alarm.clone())
    );
    assert!(signer.alerts().contains(&alarm));
    assert_eq!(signer.status(), SignerStatus::Alarm);
}

#[tokio::test]
async fn test_restore_keeps_a_removal_time_from_before_it() {
    // The switch revoked `a` on day 1, and a new install restores on day 5: the removal is
    // distrusted from day 1, with no bound applied.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut old).await;
    drop(old);
    let id = a.keys.app_id_bytes();
    world.clock.advance_ms(86_400_000);
    world.switch.revoke(id).unwrap();
    world.clock.advance_ms(4 * 86_400_000);
    let mut signer = restored(&world).await.unwrap();
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.body().removed[0].distrust_from, START_MS + 86_400_000);
    assert!(
        !signer
            .alerts()
            .iter()
            .any(|a| matches!(a, Alert::RemovalTimeBounded { .. }))
    );
}

#[tokio::test]
async fn test_restore_in_place_keeps_a_revocation_asked_for() {
    // `a`'s revocation is kept but hasn't reached the switch. Restored in place, the install
    // still refuses `a`'s App ID, and the next run sends the revocation and removes it.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    signer.restore(confirmed()).await.unwrap();
    assert!(matches!(
        signer.review(&a.request, &a.auth),
        Err(SignerError::Refused(Refusal::AppRequest(ref why))) if why.contains("step 4")
    ));
    signer.run_due().await.unwrap();
    assert!(world.switch.app(&id).departed);
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
async fn test_restore_writes_its_backup_once_its_delivery_won() {
    // The publication fails during the restore: the backup is written all the same, holding
    // the version the switch took.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    drop(old);
    *world.homeserver.failing_path.lock().unwrap() = Some(IDENTITY_PATH.into());
    restored(&world).await.unwrap_err();
    assert_eq!(
        world.backup().identity_doc().signed(),
        world.switch.identity_doc().unwrap().signed()
    );
}

#[tokio::test]
async fn test_restore_backup_that_cant_be_written_stays_owed() {
    // The backup write fails after the restore's delivery: `BackupNotWritten` stays while it
    // is owed, and the next run writes it.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    drop(old);
    *world.homeserver.failing_path.lock().unwrap() = Some(SIGNER_BACKUP_PATH.into());
    let mut signer = restored(&world).await.unwrap();
    assert!(signer.alerts().contains(&Alert::BackupNotWritten));
    assert_ne!(
        world.backup().identity_doc().signed(),
        world.switch.identity_doc().unwrap().signed()
    );
    *world.homeserver.failing_path.lock().unwrap() = None;
    signer.run_due().await.unwrap();
    assert!(!signer.alerts().contains(&Alert::BackupNotWritten));
    assert_eq!(
        world.backup().identity_doc().signed(),
        world.switch.identity_doc().unwrap().signed()
    );
}

#[tokio::test]
async fn test_restore_keeps_the_epoch_floor_the_backup_shows() {
    // The backup's parts show epoch 2's keys sent to `b`, which the switch doesn't show: the
    // restored install's next rotation completes epoch 2 first, and goes to 3.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut old).await;
    let doc = old.identity_doc().unwrap().unwrap();
    drop(old);
    let b_id = b.keys.app_id_bytes();
    let part = pubky_switch_core::records::StoredPart {
        app_id: b_id,
        first_epoch: 2,
        last_epoch: 2,
        cert: doc.listed_cert(&b_id).unwrap(),
    };
    world.homeserver.set(
        SIGNER_BACKUP_PATH,
        backup_of(&world, &doc, &[], &[&a, &b], &[part]),
    );
    let mut signer = restored(&world).await.unwrap();
    let reduce = CertChange {
        scopes: Some(vec!["notes_sync".into()]),
        expires_at: None,
    };
    let renewing = signer.renew(a.keys.app_id_bytes(), reduce).await.unwrap();
    assert_eq!(renewing.data_epoch(), 3);
}

#[tokio::test]
async fn test_restore_bounds_an_epoch_floor_past_the_next_epoch() {
    // The backup claims epoch 41's keys sent at data epoch 1: epochs never skip, so the floor
    // is kept at 2, with an alert, and the next rotation goes to 3, not 42.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut old).await;
    let doc = old.identity_doc().unwrap().unwrap();
    drop(old);
    let b_id = b.keys.app_id_bytes();
    let part = pubky_switch_core::records::StoredPart {
        app_id: b_id,
        first_epoch: 2,
        last_epoch: 41,
        cert: doc.listed_cert(&b_id).unwrap(),
    };
    world.homeserver.set(
        SIGNER_BACKUP_PATH,
        backup_of(&world, &doc, &[], &[&a, &b], &[part]),
    );
    let mut signer = restored(&world).await.unwrap();
    assert!(signer.alerts().contains(&Alert::EpochFloorBounded {
        claimed: 41,
        kept: 2,
    }));
    let reduce = CertChange {
        scopes: Some(vec!["notes_sync".into()]),
        expires_at: None,
    };
    let renewing = signer.renew(a.keys.app_id_bytes(), reduce).await.unwrap();
    assert_eq!(renewing.data_epoch(), 3);
}

#[tokio::test]
async fn test_restore_keeps_the_versions_this_install_spent() {
    // A renewal's version was signed and its batch refused, so that version is spent though
    // nothing holds it. Restored in place, the next version goes above it.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let newest = signer.identity_doc().unwrap().unwrap();
    world.switch.fail_next(SwitchFault::Error {
        path: "/ops".into(),
        code: ErrorCode::Conflict,
        current: serde_json::Value::Null,
    });
    let change = CertChange {
        scopes: None,
        expires_at: Some(START_MS + 400 * 86_400_000),
    };
    signer
        .renew(a.keys.app_id_bytes(), change)
        .await
        .unwrap_err();
    let restored = signer.restore(confirmed()).await.unwrap();
    assert_eq!(restored.version(), newest.version() + 2);
}

#[tokio::test]
async fn test_restore_keeps_the_backups_revoked_apps() {
    // The backup names an App ID as revoked that nothing else shows: the restored install
    // refuses it for good.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut old).await;
    let doc = old.identity_doc().unwrap().unwrap();
    drop(old);
    let gone = App::with_keys(
        AppKeys::from_secrets([30; 32], [31; 32]),
        &["notes"],
        None,
        [32; 32],
    );
    world.homeserver.set(
        SIGNER_BACKUP_PATH,
        backup_of(&world, &doc, &[gone.keys.app_id_bytes()], &[&a, &b], &[]),
    );
    let signer = restored(&world).await.unwrap();
    assert!(matches!(
        signer.review(&gone.request, &gone.auth),
        Err(SignerError::Refused(Refusal::AppRequest(ref why))) if why.contains("step 4")
    ));
}

#[tokio::test]
async fn test_restore_whose_take_over_answer_is_lost_writes_its_backup_on_reopen() {
    // The take-over delivery reaches the switch and its answer is lost. Reopened, the install
    // finishes the take-over at the next run, and writes the backup it owes: the backup holds
    // the switch's version, so a later restore isn't stale.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    drop(old);
    let store = Arc::new(MemoryStore::new());
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/identity".into(),
    });
    Signer::restore_new(world.env(store.clone()), world.keyring(), confirmed())
        .await
        .unwrap_err();
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    signer.run_due().await.unwrap();
    let active = world.switch.identity_doc().unwrap();
    assert_eq!(active.version(), 2);
    assert_eq!(world.backup().identity_doc().signed(), active.signed());
    assert!(!signer.alerts().contains(&Alert::BackupNotWritten));
    restored(&world).await.unwrap();
}

#[tokio::test]
async fn test_restore_keeps_a_departure_time_from_before_it() {
    // `a` leaves on day 1, and a new install restores on day 2: the removal keeps the
    // departure's own time.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut old).await;
    drop(old);
    let id = a.keys.app_id_bytes();
    world.clock.advance_ms(86_400_000);
    world.switch.leave(id).unwrap();
    world.clock.advance_ms(86_400_000);
    let mut signer = restored(&world).await.unwrap();
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.body().removed[0].distrust_from, START_MS + 86_400_000);
}

/// Another install's records holding `doc`, as its backup.
fn others_backup(world: &World, doc: &IdentityDoc) -> Vec<u8> {
    let records = SignerRecords::new(
        IdentityKey::from_secret(SECRET),
        doc.clone(),
        &[],
        &[],
        Limits::default(),
        &[],
        None,
    )
    .unwrap();
    serde_json::to_vec(&SignerBackup::seal(&world.key, &records).unwrap()).unwrap()
}

/// `doc` as the switch's copy, the published copy and the backup's, all at once.
fn everywhere(world: &World, doc: &IdentityDoc, backup: Vec<u8>) {
    world.switch.deliver_identity(doc).unwrap();
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(doc.signed()).unwrap());
    world.homeserver.set(SIGNER_BACKUP_PATH, backup);
}

#[tokio::test]
async fn test_restore_in_place_never_goes_below_its_own_version_it_saw() {
    // The records are at version 1, and the install saw its own version 9 at the switch.
    // Then everything goes back to its own version 6: restoring that would roll versions 7 to
    // 9 back, so it is refused.
    let world = World::new();
    let (signer, memory) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    drop(signer);
    let (nine, backup) = own_newer(&world, &first, 9);
    everywhere(&world, &nine, backup);
    let mut signer = Signer::open(world.env(memory), world.keyring())
        .await
        .unwrap();
    signer.set_record_max_age(Some(60)).await.unwrap_err();
    assert_eq!(signer.status(), SignerStatus::RecordsBehind { version: 9 });
    let (six, backup) = own_newer(&world, &first, 6);
    everywhere(&world, &six, backup);
    let sent = world.sent_docs().len();
    assert_eq!(
        signer.restore(confirmed()).await.unwrap_err(),
        SignerError::Refused(Refusal::StaleBackup)
    );
    assert_eq!(world.sent_docs().len(), sent);
}

#[tokio::test]
async fn test_restore_in_place_after_an_alarm_and_a_take_over() {
    // The switch went back and the install raised the alarm; then another install took over
    // at version 3. Once the user has cleared the alert, the install restores in place from
    // that install's backup and signs again.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let two = signer.set_record_max_age(Some(86_400)).await.unwrap();
    world.switch.deliver_identity(&first).unwrap();
    let SignerError::Alarm(alarm) = signer.set_record_max_age(Some(60)).await.unwrap_err() else {
        panic!("no alarm")
    };
    let theirs = world.other_install_version(&two, [7; 16]);
    everywhere(&world, &theirs, others_backup(&world, &theirs));
    assert_eq!(
        signer.restore(confirmed()).await.unwrap_err(),
        SignerError::Alarm(alarm.clone())
    );
    signer.clear_alert(&alarm).await.unwrap_err();
    let restored = signer.restore(confirmed()).await.unwrap();
    assert_eq!(restored.version(), 4);
    assert_eq!(restored.body().signer, signer.install_id());
    assert_eq!(signer.status(), SignerStatus::Signing);
}

#[tokio::test]
async fn test_restore_in_place_refuses_a_backup_at_a_lower_generation() {
    // The install adopted another install's version 5 at generation 2. A backup, switch and
    // Homeserver at version 6 but generation 1 are below that mark by generation.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let mut body = first.body().clone();
    body.version = 5;
    body.generation = 2;
    body.signer = [7; 16];
    let five = IdentityDoc::sign(&world.key, body).unwrap();
    world.switch.deliver_identity(&five).unwrap();
    signer.set_record_max_age(Some(60)).await.unwrap_err();
    assert_eq!(signer.high_water().unwrap().generation, 2);
    let mut body = first.body().clone();
    body.version = 6;
    body.signer = [7; 16];
    let six = IdentityDoc::sign(&world.key, body).unwrap();
    everywhere(&world, &six, others_backup(&world, &six));
    assert_eq!(
        signer.restore(confirmed()).await.unwrap_err(),
        SignerError::Refused(Refusal::StaleBackup)
    );
}

#[tokio::test]
async fn test_restore_in_place_refuses_another_body_at_the_mark() {
    // The mark is this install's version 2; the backup, the switch and the Homeserver all
    // hold another body at version 2.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let two = signer.set_record_max_age(Some(86_400)).await.unwrap();
    let mut body = two.body().clone();
    body.record_max_age = Some(7);
    let other = IdentityDoc::sign(&world.key, body).unwrap();
    everywhere(&world, &other, others_backup(&world, &other));
    assert_eq!(
        signer.restore(confirmed()).await.unwrap_err(),
        SignerError::Refused(Refusal::StaleBackup)
    );
}

#[tokio::test]
async fn test_restore_in_place_keeps_an_owed_record_deletion() {
    // `a`'s record couldn't be deleted after its removal. Restored in place, the install
    // still deletes it once the Homeserver takes it.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world
        .homeserver
        .set(&app_record_path(&id), b"a's record".to_vec());
    *world.homeserver.failing_path.lock().unwrap() = Some(app_record_path(&id));
    signer.revoke(id, None, confirmed()).await.unwrap();
    signer.restore(confirmed()).await.unwrap();
    assert!(world.homeserver.file(&app_record_path(&id)).is_some());
    *world.homeserver.failing_path.lock().unwrap() = None;
    signer.run_due().await.unwrap();
    assert!(world.homeserver.file(&app_record_path(&id)).is_none());
}
