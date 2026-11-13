//! The apps summary a management screen shows (`Signer::apps`): each app the newest
//! `identity.json` lists, then each it names as removed, with its certificate, its standing,
//! the protocols that own its scopes and the alerts that name it (Switch spec 3.1, 12.2).

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use pubky_switch_client::testing::Fault as SwitchFault;
use pubky_switch_core::keys::AppKeys;
use pubky_switch_signer::{Alert, AppStanding, Signer, UserConfirmed};

const DAY_MS: u64 = 86_400_000;

fn confirmed() -> UserConfirmed {
    UserConfirmed::shown_and_confirmed()
}

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
async fn test_apps_lists_none_before_an_app_is_approved() {
    let world = World::new();
    let (signer, _) = world.enrolled().await;
    assert!(signer.apps().unwrap().is_empty());
}

#[tokio::test]
async fn test_apps_lists_each_app_with_its_certificate() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let apps = signer.apps().unwrap();
    let ids: Vec<[u8; 16]> = apps.iter().map(|app| app.app_id).collect();
    assert_eq!(ids, [a.keys.app_id_bytes(), b.keys.app_id_bytes()]);
    let doc = signer.identity_doc().unwrap().unwrap();
    for (app, scopes) in apps.iter().zip([&["notes", "notes_sync"][..], &["notes"]]) {
        assert_eq!(app.standing, AppStanding::Listed);
        let cert = app.cert.as_ref().expect("a listed app's certificate");
        assert_eq!(doc.listed_cert(&app.app_id), Some(cert.hash()));
        assert_eq!(cert.scopes(), scopes);
        assert_eq!(app.protocols, ["notes"]);
        assert!(app.unowned_scopes.is_empty());
        assert!(!app.renewal_open);
        assert_eq!(app.distrust_from, None);
        assert_eq!(app.untaken_renewals, 0);
        assert!(app.alerts.is_empty());
    }
}

#[tokio::test]
async fn test_apps_shows_a_revoked_app_as_removed_with_its_alerts() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, b) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.clock.advance_ms(DAY_MS);
    let picked = START_MS + DAY_MS - 3_600_000;
    signer.revoke(id, Some(picked), confirmed()).await.unwrap();
    let apps = signer.apps().unwrap();
    // The listed app first, then the removed one.
    assert_eq!(apps.len(), 2);
    assert_eq!(apps[0].app_id, b.keys.app_id_bytes());
    assert_eq!(apps[0].standing, AppStanding::Listed);
    let removed = &apps[1];
    assert_eq!(removed.app_id, id);
    assert_eq!(removed.standing, AppStanding::Removed);
    assert!(removed.cert.is_none());
    assert_eq!(removed.distrust_from, Some(picked));
    // Its grant is the user's to revoke; the alert that says so names this app only.
    assert!(
        removed
            .alerts
            .contains(&Alert::GrantRevocationOwed { app_id: id })
    );
    assert!(
        !apps[0]
            .alerts
            .contains(&Alert::GrantRevocationOwed { app_id: id })
    );
}

#[tokio::test]
async fn test_apps_shows_a_revocation_the_switch_hasnt_answered() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    let picked = START_MS - 3_600_000;
    signer
        .revoke(id, Some(picked), confirmed())
        .await
        .unwrap_err();
    let apps = signer.apps().unwrap();
    let revoking = apps.iter().find(|app| app.app_id == id).unwrap();
    assert_eq!(
        revoking.standing,
        AppStanding::Revoking { at_switch: false }
    );
    assert!(
        revoking.cert.is_some(),
        "still listed until a version removes it"
    );
    assert_eq!(revoking.distrust_from, Some(picked));
    // The next run reaches the switch and removes it.
    signer.run_due().await.unwrap();
    let apps = signer.apps().unwrap();
    let removed = apps.iter().find(|app| app.app_id == id).unwrap();
    assert_eq!(removed.standing, AppStanding::Removed);
}
