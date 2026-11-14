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
        assert_eq!(app.listed_cert, Some(cert.hash()));
        assert_eq!(app.protocols.as_deref(), Some(&["notes".to_owned()][..]));
        assert_eq!(app.unowned_scopes.as_deref(), Some(&[][..]));
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
    assert!(removed.cert.is_none() && removed.listed_cert.is_none());
    assert!(removed.protocols.is_none() && removed.unowned_scopes.is_none());
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

/// A protocol owning one scope, `other`, none of the apps' here.
struct Other;

impl pubky_switch_signer::Protocol for Other {
    fn name(&self) -> &str {
        "other"
    }
    fn scopes(&self) -> Vec<pubky_switch_signer::ScopeDef> {
        vec![pubky_switch_signer::ScopeDef::keyed("other")]
    }
    fn check_scopes(&self, _: &[&str]) -> Result<(), String> {
        Ok(())
    }
    fn permissions(&self, _: &[&str]) -> Vec<pubky_switch_core::scopes::Permission> {
        Vec::new()
    }
}

#[tokio::test]
async fn test_apps_shows_a_revocation_the_switch_took_before_its_version() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    let id = a.keys.app_id_bytes();
    // The switch takes the revocation; the version that removes the app doesn't arrive.
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    let apps = signer.apps().unwrap();
    let revoking = apps.iter().find(|app| app.app_id == id).unwrap();
    assert_eq!(revoking.standing, AppStanding::Revoking { at_switch: true });
    assert!(revoking.cert.is_some());
    signer.run_due().await.unwrap();
    let apps = signer.apps().unwrap();
    let removed = apps.iter().find(|app| app.app_id == id).unwrap();
    assert_eq!(removed.standing, AppStanding::Removed);
}

#[tokio::test]
async fn test_apps_shows_a_renewal_open_until_the_app_takes_it() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let (_, b) = two_joined(&world, &mut signer).await;
    let id = b.keys.app_id_bytes();
    let before = signer.apps().unwrap()[1].cert.clone().unwrap();
    signer
        .renew(
            id,
            pubky_switch_signer::CertChange {
                scopes: Some(vec!["notes".into(), "notes_sync".into()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let app = signer
        .apps()
        .unwrap()
        .into_iter()
        .find(|app| app.app_id == id)
        .unwrap();
    assert!(app.renewal_open);
    let cert = app.cert.unwrap();
    assert_ne!(cert.hash(), before.hash());
    assert_eq!(cert.scopes(), ["notes", "notes_sync"]);
}

#[tokio::test]
async fn test_apps_names_the_scopes_no_registered_protocol_owns() {
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let (a, _) = two_joined(&world, &mut signer).await;
    drop(signer);
    let protocols = pubky_switch_signer::Protocols::new(vec![std::sync::Arc::new(Other)]).unwrap();
    let signer = Signer::open(world.env_with(store, protocols), world.keyring())
        .await
        .unwrap();
    let apps = signer.apps().unwrap();
    let first = apps
        .iter()
        .find(|app| app.app_id == a.keys.app_id_bytes())
        .unwrap();
    assert_eq!(first.protocols.as_deref(), Some(&[][..]));
    assert_eq!(
        first.unowned_scopes.as_deref(),
        Some(&["notes".to_owned(), "notes_sync".to_owned()][..])
    );
}

#[tokio::test]
async fn test_apps_of_an_install_another_took_over_from() {
    // Another install restores and approves an app; this one adopts that version without
    // the new app's certificate.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    two_joined(&world, &mut old).await;
    let store = std::sync::Arc::new(pubky_switch_client::store::MemoryStore::new());
    let mut new = Signer::restore_new(world.env(store), world.keyring(), confirmed())
        .await
        .unwrap();
    let c = App::with_keys(
        AppKeys::from_secrets([7; 32], [8; 32]),
        &["notes"],
        None,
        [11; 32],
    );
    world.approve(&mut new, &c).await;
    let _ = old.run_due().await;
    assert!(
        matches!(
            old.status(),
            pubky_switch_signer::SignerStatus::ManagedBy { .. }
        ),
        "{:?}",
        old.status()
    );
    let apps = old.apps().unwrap();
    let third = apps
        .iter()
        .find(|app| app.app_id == c.keys.app_id_bytes())
        .unwrap();
    assert_eq!(third.standing, AppStanding::Listed);
    // Listed with a certificate this install doesn't hold: the hash is known, the scopes
    // aren't, and nothing claims they're owned or not.
    let listed = new.identity_doc().unwrap().unwrap();
    assert_eq!(
        third.listed_cert,
        listed.listed_cert(&c.keys.app_id_bytes())
    );
    assert!(third.cert.is_none());
    assert!(third.protocols.is_none() && third.unowned_scopes.is_none());
}
