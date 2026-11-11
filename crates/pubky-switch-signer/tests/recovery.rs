//! A provider loss against scripted switches (Switch spec 12.6 steps 1 and 2; Switch wire
//! 3.3, 3.7, 7.4.2, 7.4.14): the signer enrolls at another service, delivers the next
//! generation there with `recovery_from`, and ends the staged admission it started when no
//! listed app holds `lists.manage`; who may declare it, and what the version carries.

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::*;
use pubky_switch_client::clock::Clock;
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::{Router, SWITCH_ORIGIN, ScriptedSwitch};
use pubky_switch_core::records::IDENTITY_PATH;
use pubky_switch_core::scopes::Permission;
use pubky_switch_signer::{
    Alert, Protocol, Protocols, Refusal, ScopeDef, Signer, SignerError, SignerStatus, UserConfirmed,
};

/// The service the signer recovers at.
const NEW_ORIGIN: &str = "https://recovery.example";

fn confirmed() -> UserConfirmed {
    UserConfirmed::shown_and_confirmed()
}

/// The test protocol, whose `notes` scope gives `permissions`.
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

/// The new service at [`NEW_ORIGIN`], and a router that reaches it and the lost one.
fn new_service(world: &World) -> (Arc<ScriptedSwitch>, Arc<Router>) {
    let service =
        ScriptedSwitch::unenrolled_at(&world.key, [0x5e; 32], Arc::clone(&world.clock), NEW_ORIGIN);
    let router = Arc::new(Router::new());
    router.add_switch(SWITCH_ORIGIN, &world.switch);
    router.add_switch(NEW_ORIGIN, &service);
    (service, router)
}

/// The signer of `store`, reopened on `router` with `protocols`.
async fn reopened(
    world: &World,
    store: Arc<MemoryStore>,
    router: &Arc<Router>,
    protocols: Protocols,
) -> Signer {
    let mut env = world.env_with(store, protocols);
    env.transport = router.clone();
    Signer::open(env, world.keyring()).await.unwrap()
}

/// An enrolled signer with one app approved under `protocols`, then the lost service made
/// unreachable: the signer reopened on a router to the new service.
async fn lost_with_an_app(
    world: &World,
    protocols: Protocols,
) -> (Signer, Arc<ScriptedSwitch>, Arc<Router>) {
    let store = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(
        world.env_with(store.clone(), protocols.clone()),
        world.keyring(),
        SWITCH_ORIGIN,
    )
    .await
    .unwrap();
    signer.resume().await.unwrap();
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    drop(signer);
    let (service, router) = new_service(world);
    router.remove(SWITCH_ORIGIN);
    let signer = reopened(world, store, &router, protocols).await;
    (signer, service, router)
}

fn notes() -> Protocols {
    Protocols::new(vec![Arc::new(Notes)]).unwrap()
}

#[tokio::test]
async fn test_provider_loss_recovers_at_another_service() {
    // The service is lost. The signer enrolls at another, delivers the next generation there
    // with `recovery_from` the lost one, naming it, and publishes it. No listed app holds
    // `lists.manage`, so the signer ends the staged admission the recovery started (Switch
    // spec 12.6 steps 1 and 2).
    let world = World::new();
    let (mut signer, service, router) = lost_with_an_app(&world, notes()).await;
    let lost = signer.identity_doc().unwrap().unwrap();
    let recovered = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert_eq!(recovered.generation(), lost.generation() + 1);
    assert_eq!(recovered.body().recovery_from, Some(lost.generation()));
    assert!(recovered.version() > lost.version());
    assert_eq!(recovered.data_epoch(), lost.data_epoch());
    assert_eq!(recovered.inbox().url, NEW_ORIGIN);
    assert_eq!(recovered.body().apps, lost.body().apps);
    assert_eq!(service.identity_doc().unwrap().hash(), recovered.hash());
    assert_eq!(service.generation(), recovered.generation());
    assert_eq!(world.published().unwrap().hash(), recovered.hash());
    assert_eq!(world.backup().identity_doc().hash(), recovered.hash());
    assert!(!service.admission_staged(), "ended by the signer");
    assert!(
        router
            .log()
            .iter()
            .any(|line| line.contains("POST https://recovery.example")
                && line.ends_with("/recovery/admission"))
    );
    assert_eq!(signer.status(), SignerStatus::Signing);
    // The new service is the signer's: a later change is delivered there.
    signer.set_record_max_age(Some(60)).await.unwrap();
    assert_eq!(
        service.identity_doc().unwrap().body().record_max_age,
        Some(60)
    );
}

#[tokio::test]
async fn test_provider_loss_leaves_admission_staged_for_an_app_that_manages_lists() {
    // A listed app holds `lists.manage`: its contacts upload ends the staged admission, so
    // the signer leaves it staged, until the user ends it (Switch spec 12.6 step 2).
    let world = World::new();
    let protocols = Protocols::new(vec![Arc::new(NotesGiving(vec![
        Permission::ListsRead,
        Permission::ListsManage,
    ]))])
    .unwrap();
    let (mut signer, service, _) = lost_with_an_app(&world, protocols).await;
    signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert!(service.admission_staged(), "left for the app's upload");
    signer.end_staged_admission().await.unwrap();
    assert!(!service.admission_staged());
    // Ending it again changes nothing.
    signer.end_staged_admission().await.unwrap();
}

#[tokio::test]
async fn test_provider_loss_admission_end_is_resumed_after_a_failure() {
    // The new service can't be reached for the admission's end, right after the recovery's
    // delivery: the end stays owed, and the next run sends it (Switch spec 12.6 step 2).
    let world = World::new();
    let (mut signer, service, _) = lost_with_an_app(&world, notes()).await;
    service.fail_next(pubky_switch_client::testing::Fault::Unreachable {
        path: "/recovery/admission".into(),
        after: 0,
    });
    signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap_err();
    assert!(service.identity_doc().is_some(), "delivered");
    assert!(service.admission_staged());
    signer.resume().await.unwrap();
    assert!(!service.admission_staged());
}

#[tokio::test]
async fn test_provider_loss_while_an_alarm_about_the_lost_service_is_held() {
    // The lost service answered with no copy: a rollback alarm, which holds every signing
    // step back. A provider loss is the way out of it, and the alarm goes with the recovery
    // (Switch spec 12.6 step 1).
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    world.switch.lose_identity();
    let error = signer.set_record_max_age(Some(5)).await.unwrap_err();
    assert!(
        matches!(error, SignerError::Alarm(Alert::Rollback { .. })),
        "{error:?}"
    );
    drop(signer);
    let (service, router) = new_service(&world);
    let mut signer = reopened(&world, store, &router, notes()).await;
    let recovered = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert_eq!(service.identity_doc().unwrap().hash(), recovered.hash());
    assert!(
        !signer
            .alerts()
            .iter()
            .any(|a| matches!(a, Alert::Rollback { .. }))
    );
    signer.set_record_max_age(Some(60)).await.unwrap();
}

#[tokio::test]
async fn test_provider_loss_enrolls_an_erased_account_again() {
    // An erased install declares a provider loss at another service: how an erased account
    // is enrolled again (Switch spec 12.6 step 1, 12.7 step 4). It signs there again.
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    signer.close_account(confirmed()).await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
    drop(signer);
    let (service, router) = new_service(&world);
    let mut signer = reopened(&world, store, &router, notes()).await;
    let recovered = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert_eq!(service.identity_doc().unwrap().hash(), recovered.hash());
    assert_eq!(signer.status(), SignerStatus::Signing);
    assert!(
        world.homeserver.file(IDENTITY_PATH).is_some(),
        "published again"
    );
    signer.set_record_max_age(Some(60)).await.unwrap();
}

#[tokio::test]
async fn test_provider_loss_ends_an_erasure_in_progress() {
    // An erasure whose request may have landed: the account at the lost service counts as
    // gone, and the provider loss ends the erasure, withdrawing the grant reminder it raised
    // for an app still listed (Switch spec 12.6 step 1, 12.7).
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let reminder = Alert::GrantRevocationOwed {
        app_id: app.keys.app_id_bytes(),
    };
    world
        .switch
        .fail_next(pubky_switch_client::testing::Fault::Unreachable {
            path: "/erase".into(),
            after: 0,
        });
    signer.close_account(confirmed()).await.unwrap_err();
    assert_eq!(signer.status(), SignerStatus::Erasing);
    assert!(signer.alerts().contains(&reminder));
    drop(signer);
    let (service, router) = new_service(&world);
    router.remove(SWITCH_ORIGIN);
    let mut signer = reopened(&world, store, &router, notes()).await;
    let recovered = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert_eq!(service.identity_doc().unwrap().hash(), recovered.hash());
    assert_eq!(signer.status(), SignerStatus::Signing);
    assert_eq!(world.published().unwrap().hash(), recovered.hash());
    assert!(!signer.alerts().contains(&reminder), "withdrawn");
}

#[tokio::test]
async fn test_provider_loss_names_the_revoked_apps_in_its_enrollment() {
    // The enrollment names every App ID the signer revoked, so the new service refuses them
    // from the start (Switch spec 12.6 step 1, wire 3.7).
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(world.env(store.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    signer.revoke(id, None, confirmed()).await.unwrap();
    drop(signer);
    let (service, router) = new_service(&world);
    router.remove(SWITCH_ORIGIN);
    let mut signer = reopened(&world, store, &router, notes()).await;
    signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert!(service.kept_app_ids().contains(&id));
}

#[tokio::test]
async fn test_provider_loss_refused_while_another_install_signs() {
    // Not an install another install signs for (Switch spec 12.6 step 1): nothing is sent.
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let mine = signer.identity_doc().unwrap().unwrap();
    let other = world.other_install_version(&mine, [0x77; 16]);
    world.switch.deliver_identity(&other).unwrap();
    let error = signer.set_record_max_age(Some(5)).await.unwrap_err();
    assert!(matches!(error, SignerError::NotNamed { .. }), "{error:?}");
    drop(signer);
    let (service, router) = new_service(&world);
    let mut signer = reopened(&world, store, &router, notes()).await;
    let error = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap_err();
    assert!(matches!(error, SignerError::NotNamed { .. }), "{error:?}");
    assert!(service.identity_doc().is_none(), "nothing sent");
}

#[tokio::test]
async fn test_provider_loss_refuses_an_origin_that_isnt_a_switch_origin() {
    let world = World::new();
    let (mut signer, _, _) = lost_with_an_app(&world, notes()).await;
    let error = signer
        .declare_provider_loss("http://recovery.example", confirmed())
        .await
        .unwrap_err();
    assert!(
        !matches!(error, SignerError::Refused(Refusal::FlowInProgress)),
        "{error:?}"
    );
    // Nothing was kept: a recovery at a proper origin goes through.
    signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
}

#[tokio::test]
async fn test_provider_loss_closes_an_owed_reduction_itself() {
    // A reduction's closing can't reach the lost service: the recovery's version closes it
    // itself, at the time it is signed plus the clock tolerance, so a reader takes the
    // earlier certificate's writes up to then and none after (Switch spec 12.6 step 1).
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(world.env(store.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    let app = App::new(&["notes", "notes_sync"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    // The renewing version is delivered; its closing doesn't get through.
    world
        .switch
        .fail_next(pubky_switch_client::testing::Fault::Unreachable {
            path: "/identity".into(),
            after: 1,
        });
    let change = pubky_switch_signer::CertChange {
        scopes: Some(vec!["notes_sync".into()]),
        expires_at: None,
    };
    signer.renew(id, change).await.unwrap_err();
    let renewing = signer.identity_doc().unwrap().unwrap();
    assert!(
        renewing
            .body()
            .renewed
            .iter()
            .any(|r| r.app_id == id && r.until.is_none()),
        "the closing is owed"
    );
    drop(signer);
    let (service, router) = new_service(&world);
    router.remove(SWITCH_ORIGIN);
    let mut signer = reopened(&world, store, &router, notes()).await;
    world.clock.advance_ms(60_000);
    let signed_at = world.clock.now_ms();
    let recovered = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    let closed: Vec<_> = recovered
        .body()
        .renewed
        .iter()
        .filter(|r| r.app_id == id)
        .collect();
    assert!(!closed.is_empty());
    assert!(
        closed
            .iter()
            .all(|r| r.until == Some(signed_at + pubky_switch_core::records::CLOCK_TOLERANCE_MS)),
        "{closed:?}"
    );
    assert_eq!(service.identity_doc().unwrap().hash(), recovered.hash());
    // The recovery's version itself closed it: no closing followed it, so the new service
    // chained the recovery transition, that one version, and the admission's end.
    assert_eq!(recovered.body().recovery_from, Some(renewing.generation()));
    assert_eq!(service.seq(), 3);
}
