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
