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
use pubky_switch_client::testing::{Fault, Router, SWITCH_ORIGIN, ScriptedSwitch};
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
    // delivery: the version is published all the same, since apps find the service through
    // it, and the end stays owed, sent at the next run (Switch spec 12.6 step 2).
    let world = World::new();
    let (mut signer, service, _) = lost_with_an_app(&world, notes()).await;
    service.fail_next(Fault::Unreachable {
        path: "/recovery/admission".into(),
        after: 0,
    });
    let recovered = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert_eq!(service.identity_doc().unwrap().hash(), recovered.hash());
    assert_eq!(world.published().unwrap().hash(), recovered.hash());
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
    world.switch.fail_next(Fault::Unreachable {
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
    // The lost service takes the renewing version, and its answer is lost: the version is
    // in flight, and owes its closing.
    world.switch.fail_next(Fault::LoseAnswer {
        path: "/identity".into(),
    });
    let change = pubky_switch_signer::CertChange {
        scopes: Some(vec!["notes_sync".into()]),
        expires_at: None,
    };
    signer.renew(id, change).await.unwrap_err();
    let renewing = world.switch.identity_doc().unwrap();
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
    // Built on the renewing version the lost service took: its epoch and certificate carry
    // over, whatever the signer's records held as delivered.
    assert_eq!(recovered.data_epoch(), renewing.data_epoch());
    assert_eq!(recovered.listed_cert(&id), renewing.listed_cert(&id));
    assert!(recovered.version() > renewing.version());
}

/// Another service the signer may declare the loss at.
const THIRD_ORIGIN: &str = "https://third.example";

/// The service at `origin`, unenrolled, reached through `router`.
fn service_on(world: &World, router: &Router, origin: &str, secret: u8) -> Arc<ScriptedSwitch> {
    let service =
        ScriptedSwitch::unenrolled_at(&world.key, [secret; 32], Arc::clone(&world.clock), origin);
    router.add_switch(origin, &service);
    service
}

/// The App ID of the app [`lost_with_an_app`] approves.
fn notes_app_id() -> [u8; 16] {
    App::new(&["notes"], None, [9; 32]).keys.app_id_bytes()
}

#[tokio::test]
async fn test_provider_loss_completes_a_pending_revocation_at_the_new_service() {
    // A revocation the lost service never took: the app stays listed, so the enrollment
    // doesn't name it, and the revocation is completed at the new service right after the
    // recovery's version, a removal with its own rotation (Switch spec 12.6 step 1, 12.2).
    let world = World::new();
    let (mut signer, service, router) = lost_with_an_app(&world, notes()).await;
    let id = notes_app_id();
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    let lost = signer.identity_doc().unwrap().unwrap();
    assert!(lost.listed_cert(&id).is_some());
    let recovered = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert_eq!(recovered.generation(), lost.generation() + 1);
    assert!(
        recovered.listed_cert(&id).is_none(),
        "removed at the service"
    );
    assert!(recovered.body().removed.iter().any(|r| r.app_id == id));
    assert_eq!(recovered.data_epoch(), lost.data_epoch() + 1);
    assert_eq!(service.identity_doc().unwrap().hash(), recovered.hash());
    assert_eq!(world.published().unwrap().hash(), recovered.hash());
    assert!(
        router
            .log()
            .iter()
            .any(|line| line.contains(NEW_ORIGIN) && line.contains("/revoke")),
        "revoked there"
    );
    assert_eq!(signer.status(), SignerStatus::Signing);
    assert!(
        !signer
            .alerts()
            .iter()
            .any(|a| matches!(a, Alert::RevocationPending { .. }))
    );
}

#[tokio::test]
async fn test_provider_loss_declared_again_after_an_origin_that_never_answers() {
    // A mistyped origin never answers the enrollment: the recovery shows as in progress
    // there, signs nothing else, and declaring it again at the right origin replaces it
    // (Switch spec 12.6 step 1).
    let world = World::new();
    let (mut signer, service, _) = lost_with_an_app(&world, notes()).await;
    let typo = "https://recovery.exmaple";
    signer
        .declare_provider_loss(typo, confirmed())
        .await
        .unwrap_err();
    assert_eq!(
        signer.status(),
        SignerStatus::Recovering {
            origin: typo.into()
        }
    );
    assert_eq!(
        signer.set_record_max_age(Some(5)).await.unwrap_err(),
        Refusal::FlowInProgress.into()
    );
    signer.resume().await.unwrap_err();
    let recovered = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert_eq!(service.identity_doc().unwrap().hash(), recovered.hash());
    assert_eq!(recovered.inbox().url, NEW_ORIGIN);
    assert_eq!(signer.status(), SignerStatus::Signing);
}

#[tokio::test]
async fn test_provider_loss_declared_again_after_a_refused_version() {
    // The service refuses the recovery's version for good: nothing is sent there again, the
    // recovery waits to be declared again, refusing every other step meanwhile, and a second
    // declaration elsewhere comes out at a higher version (Switch spec 12.6 step 1).
    let world = World::new();
    let (mut signer, service, router) = lost_with_an_app(&world, notes()).await;
    service.fail_next(Fault::Error {
        path: "/identity".into(),
        code: pubky_switch_core::http::ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap_err();
    let refused = world.backup().identity_doc().clone();
    assert_eq!(refused.inbox().url, NEW_ORIGIN, "backed up, then refused");
    assert!(service.identity_doc().is_none());
    assert_eq!(
        signer.status(),
        SignerStatus::RecoveryRefused {
            origin: NEW_ORIGIN.into()
        }
    );
    assert_eq!(
        signer.set_record_max_age(Some(5)).await.unwrap_err(),
        Refusal::Recovering.into()
    );
    assert_eq!(
        signer.end_staged_admission().await.unwrap_err(),
        Refusal::Recovering.into()
    );
    let sent = router.log().len();
    signer.resume().await.unwrap();
    assert_eq!(router.log().len(), sent, "nothing sent again");
    let third = service_on(&world, &router, THIRD_ORIGIN, 0x6e);
    let recovered = signer
        .declare_provider_loss(THIRD_ORIGIN, confirmed())
        .await
        .unwrap();
    assert!(recovered.version() > refused.version());
    assert_eq!(recovered.generation(), refused.generation());
    assert_eq!(third.identity_doc().unwrap().hash(), recovered.hash());
    assert_eq!(world.published().unwrap().hash(), recovered.hash());
    assert_eq!(signer.status(), SignerStatus::Signing);
}

#[tokio::test]
async fn test_provider_loss_declared_again_while_the_version_is_in_flight() {
    // The recovery's version is signed and backed up, its delivery unanswered, when the user
    // declares again elsewhere: the new version is higher, so no version has two bodies
    // (Switch spec 4.3).
    let world = World::new();
    let (mut signer, service, router) = lost_with_an_app(&world, notes()).await;
    service.fail_next(Fault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap_err();
    let first = world.backup().identity_doc().clone();
    let third = service_on(&world, &router, THIRD_ORIGIN, 0x6e);
    let second = signer
        .declare_provider_loss(THIRD_ORIGIN, confirmed())
        .await
        .unwrap();
    assert!(second.version() > first.version());
    assert_eq!(third.identity_doc().unwrap().hash(), second.hash());
}

#[tokio::test]
async fn test_provider_loss_lost_answers_are_retried_with_the_same_bytes() {
    // The enrollment's answer and the delivery's are lost: each is sent again with its
    // bytes, and the recovery ends delivered, published and admitted (Switch spec 12.6).
    let world = World::new();
    let (mut signer, service, _) = lost_with_an_app(&world, notes()).await;
    service.fail_next(Fault::LoseAnswer {
        path: "/enroll".into(),
    });
    signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap_err();
    service.fail_next(Fault::LoseAnswer {
        path: "/identity".into(),
    });
    signer.resume().await.unwrap_err();
    signer.resume().await.unwrap();
    let held = service.identity_doc().unwrap();
    assert_eq!(held.hash(), signer.identity_doc().unwrap().unwrap().hash());
    assert_eq!(world.published().unwrap().hash(), held.hash());
    assert!(!service.admission_staged());
}

#[tokio::test]
async fn test_provider_loss_second_loss_starts_the_next_generation() {
    // The new service is lost too, before the admission's end: a second declaration
    // recovers from the first recovery's generation (Switch spec 12.6).
    let world = World::new();
    let (mut signer, service, router) = lost_with_an_app(&world, notes()).await;
    service.fail_next(Fault::Unreachable {
        path: "/recovery/admission".into(),
        after: 0,
    });
    let first = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    router.remove(NEW_ORIGIN);
    let third = service_on(&world, &router, THIRD_ORIGIN, 0x6e);
    let second = signer
        .declare_provider_loss(THIRD_ORIGIN, confirmed())
        .await
        .unwrap();
    assert_eq!(second.generation(), first.generation() + 1);
    assert_eq!(second.body().recovery_from, Some(first.generation()));
    assert!(second.version() > first.version());
    assert!(!third.admission_staged());
    assert_eq!(world.published().unwrap().hash(), second.hash());
}

#[tokio::test]
async fn test_provider_loss_refused_for_a_newer_own_version_on_the_homeserver() {
    // The Homeserver holds a newer version of this install's own, and the signer backup is
    // gone: the records are behind, which the recovery's check of the copies finds before
    // anything is signed or sent (Switch spec 12.6 step 1, 4.3).
    let world = World::new();
    let (signer, store) = world.enrolled().await;
    let mine = signer.identity_doc().unwrap().unwrap();
    let mut body = mine.body().clone();
    body.version += 1;
    body.record_max_age = Some(7);
    let own = pubky_switch_core::records::IdentityDoc::sign(&world.key, body).unwrap();
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(own.signed()).unwrap());
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(pubky_switch_core::records::SIGNER_BACKUP_PATH);
    drop(signer);
    let (service, router) = new_service(&world);
    router.remove(SWITCH_ORIGIN);
    let mut signer = reopened(&world, store, &router, notes()).await;
    let error = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap_err();
    assert_eq!(
        error,
        Refusal::RecordsBehind {
            version: own.version()
        }
        .into()
    );
    assert!(router.log().is_empty(), "nothing sent");
    assert!(service.identity_doc().is_none());
}

#[tokio::test]
async fn test_provider_loss_refused_while_the_records_are_behind() {
    // Not an install whose records are behind (Switch spec 12.6 step 1): the gate refuses it
    // before anything is sent.
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let mine = signer.identity_doc().unwrap().unwrap();
    let mut body = mine.body().clone();
    body.version += 1;
    body.record_max_age = Some(3);
    let own = pubky_switch_core::records::IdentityDoc::sign(&world.key, body).unwrap();
    world.switch.deliver_identity(&own).unwrap();
    signer.set_record_max_age(Some(5)).await.unwrap_err();
    drop(signer);
    let (_, router) = new_service(&world);
    router.remove(SWITCH_ORIGIN);
    let mut signer = reopened(&world, store, &router, notes()).await;
    let error = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap_err();
    assert_eq!(
        error,
        Refusal::RecordsBehind {
            version: own.version()
        }
        .into()
    );
    assert!(router.log().is_empty(), "nothing sent");
}

#[tokio::test]
async fn test_provider_loss_refused_during_a_hand_over() {
    // Not an install handing the identity over (Switch spec 12.6 step 1, 12.8): refused
    // before anything is sent.
    let world = World::new();
    let (mut old, store) = world.enrolled().await;
    let app = App::with_keys(
        pubky_switch_core::keys::AppKeys::from_secrets([3; 32], [4; 32]),
        &["notes"],
        None,
        [9; 32],
    );
    world.approve(&mut old, &app).await;
    old.hand_over_to(app.keys.app_id_bytes(), confirmed())
        .await
        .unwrap();
    drop(old);
    let (_, router) = new_service(&world);
    router.remove(SWITCH_ORIGIN);
    let mut signer = reopened(&world, store, &router, notes()).await;
    let error = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap_err();
    assert_eq!(
        error,
        Refusal::HandingOver {
            to_app: app.keys.app_id_bytes()
        }
        .into()
    );
    assert!(router.log().is_empty(), "nothing sent");
}

#[tokio::test]
async fn test_provider_loss_waits_for_a_homeserver_alarm_to_publish() {
    // Another body at the mark on the Homeserver: the equivocation alarm, which the recovery
    // passes and doesn't clear, since a new service doesn't resolve it. Its version is
    // delivered and waits for the user to clear the alarm before it is published (Switch
    // spec 12.6 step 1, wire 3.3).
    let world = World::new();
    let (signer, store) = world.enrolled().await;
    let mine = signer.identity_doc().unwrap().unwrap();
    let mut body = mine.body().clone();
    body.record_max_age = Some(11);
    let other = pubky_switch_core::records::IdentityDoc::sign(&world.key, body).unwrap();
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(other.signed()).unwrap());
    drop(signer);
    let (service, router) = new_service(&world);
    router.remove(SWITCH_ORIGIN);
    let mut signer = reopened(&world, store, &router, notes()).await;
    let recovered = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert_eq!(service.identity_doc().unwrap().hash(), recovered.hash());
    assert!(!service.admission_staged(), "ended while publication waits");
    let alarm = Alert::Equivocation {
        source: pubky_switch_signer::Source::Homeserver,
        version: mine.version(),
    };
    assert!(signer.alerts().contains(&alarm), "{:?}", signer.alerts());
    assert_eq!(signer.status(), SignerStatus::Alarm);
    assert_eq!(world.published().unwrap().hash(), other.hash());
    signer.clear_alert(&alarm).await.unwrap();
    signer.resume().await.unwrap();
    assert_eq!(world.published().unwrap().hash(), recovered.hash());
    assert_eq!(signer.status(), SignerStatus::Signing);
}

#[tokio::test]
async fn test_provider_loss_writes_a_missing_backup_when_the_homeserver_agrees() {
    // The backup is gone and the lost service can't be asked who signs: the Homeserver's
    // copy names this install at its mark, so the backup is written over, with the alert
    // (Switch spec 12.6 step 1, wire 3.13).
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    signer.resume().await.unwrap();
    drop(signer);
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(pubky_switch_core::records::SIGNER_BACKUP_PATH);
    let (service, router) = new_service(&world);
    router.remove(SWITCH_ORIGIN);
    let mut signer = reopened(&world, store, &router, notes()).await;
    let recovered = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert_eq!(service.identity_doc().unwrap().hash(), recovered.hash());
    assert_eq!(world.backup().identity_doc().hash(), recovered.hash());
    assert!(signer.alerts().contains(&Alert::BackupMissing));
}

#[tokio::test]
async fn test_provider_loss_stops_at_a_take_over_the_homeserver_shows() {
    // The backup is gone, and the Homeserver's copy is another install's newer version: it
    // took the identity over at the lost service, so this install signs nothing and sends
    // nothing (Switch spec 12.6 step 1, 4.3).
    let world = World::new();
    let (signer, store) = world.enrolled().await;
    let mine = signer.identity_doc().unwrap().unwrap();
    let mut body = mine.body().clone();
    body.version += 1;
    body.signer = [0x77; 16];
    let theirs = pubky_switch_core::records::IdentityDoc::sign(&world.key, body).unwrap();
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(theirs.signed()).unwrap());
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(pubky_switch_core::records::SIGNER_BACKUP_PATH);
    drop(signer);
    let (service, router) = new_service(&world);
    router.remove(SWITCH_ORIGIN);
    let mut signer = reopened(&world, store, &router, notes()).await;
    let error = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap_err();
    assert_eq!(
        error,
        SignerError::NotNamed {
            install: [0x77; 16]
        }
    );
    assert!(router.log().is_empty(), "nothing sent");
    assert!(service.identity_doc().is_none());
}

#[tokio::test]
async fn test_provider_loss_carries_an_epoch_the_lost_service_took() {
    // A reduction rotates the data epoch; the lost service takes the renewing version and
    // its answer is lost. The recovery is built on that version, so its epoch never goes
    // back, which apps that saw it would refuse (Switch spec 12.6 step 1, 4.3).
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(world.env(store.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    let app = App::new(&["notes", "notes_sync"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    let before = signer.identity_doc().unwrap().unwrap();
    world.switch.fail_next(Fault::LoseAnswer {
        path: "/identity".into(),
    });
    let change = pubky_switch_signer::CertChange {
        scopes: Some(vec!["notes".into()]),
        expires_at: None,
    };
    signer.renew(id, change).await.unwrap_err();
    let at_lost = world.switch.identity_doc().unwrap();
    assert!(
        at_lost.data_epoch() > before.data_epoch(),
        "a reduction rotates"
    );
    drop(signer);
    let (_, router) = new_service(&world);
    router.remove(SWITCH_ORIGIN);
    let mut signer = reopened(&world, store, &router, notes()).await;
    let recovered = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert_eq!(recovered.data_epoch(), at_lost.data_epoch());
    assert_eq!(recovered.listed_cert(&id), at_lost.listed_cert(&id));
}

#[tokio::test]
async fn test_provider_loss_withdraws_an_erased_accounts_grant_reminders() {
    // An erased account enrolled again lists its apps again, so the reminders to revoke
    // their grants go, as at an erasure the recovery ends (Switch spec 12.7 step 4).
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    signer.close_account(confirmed()).await.unwrap();
    let reminder = Alert::GrantRevocationOwed {
        app_id: app.keys.app_id_bytes(),
    };
    assert!(signer.alerts().contains(&reminder));
    drop(signer);
    let (_, router) = new_service(&world);
    router.remove(SWITCH_ORIGIN);
    let mut signer = reopened(&world, store, &router, notes()).await;
    let recovered = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert!(recovered.listed_cert(&app.keys.app_id_bytes()).is_some());
    assert!(!signer.alerts().contains(&reminder), "withdrawn");
    assert_eq!(signer.status(), SignerStatus::Signing);
}

#[tokio::test]
async fn test_provider_loss_end_staged_admission_without_a_recovery_sends_nothing() {
    // No recovery, so no wait: ending it sends nothing and owes nothing, and later steps go
    // on, publication included (Switch spec 12.6 step 2).
    let world = World::new();
    let (mut signer, _store) = world.enrolled().await;
    signer.end_staged_admission().await.unwrap();
    let sent = world.transport.requests().len();
    signer.resume().await.unwrap();
    assert_eq!(world.transport.requests().len(), sent, "nothing owed");
    let changed = signer.set_record_max_age(Some(5)).await.unwrap();
    assert_eq!(world.published().unwrap().hash(), changed.hash());
    assert_eq!(world.switch.identity_doc().unwrap().hash(), changed.hash());
}

#[tokio::test]
async fn test_provider_loss_admission_end_owed_after_a_restore() {
    // The admission's end failed and this install is gone: an install restored from the
    // backup finds the wait from the service's `GET /apps` and ends it (Switch spec 12.6
    // step 2, wire 7.4.12).
    let world = World::new();
    let (mut signer, service, router) = lost_with_an_app(&world, notes()).await;
    service.fail_next(Fault::Unreachable {
        path: "/recovery/admission".into(),
        after: 0,
    });
    signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert!(service.admission_staged());
    drop(signer);
    let mut env = world.env_with(Arc::new(MemoryStore::new()), notes());
    env.transport = router.clone();
    let mut restored = Signer::restore_new(env, world.keyring(), confirmed())
        .await
        .unwrap();
    restored.resume().await.unwrap();
    assert!(!service.admission_staged());
}

#[tokio::test]
async fn test_provider_loss_keeps_its_base_after_a_refused_version() {
    // The recovery builds on a renewing version the lost service took, its answer lost; the
    // first service refuses the recovery's version, and the second declaration builds on
    // the same version, its certificate kept for it (Switch spec 12.6 step 1).
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(world.env(store.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    let app = App::new(&["notes", "notes_sync"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    world.switch.fail_next(Fault::LoseAnswer {
        path: "/identity".into(),
    });
    let change = pubky_switch_signer::CertChange {
        scopes: Some(vec!["notes".into()]),
        expires_at: None,
    };
    signer.renew(id, change).await.unwrap_err();
    let at_lost = world.switch.identity_doc().unwrap();
    drop(signer);
    let (service, router) = new_service(&world);
    router.remove(SWITCH_ORIGIN);
    let mut signer = reopened(&world, store, &router, notes()).await;
    service.fail_next(Fault::Error {
        path: "/identity".into(),
        code: pubky_switch_core::http::ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap_err();
    service_on(&world, &router, THIRD_ORIGIN, 0x6e);
    let recovered = signer
        .declare_provider_loss(THIRD_ORIGIN, confirmed())
        .await
        .unwrap();
    assert_eq!(recovered.data_epoch(), at_lost.data_epoch());
    assert_eq!(recovered.listed_cert(&id), at_lost.listed_cert(&id));
}

#[tokio::test]
async fn test_provider_loss_resumed_stops_at_a_take_over_the_homeserver_shows() {
    // The declaration passed its checks; before the recovery's backup is written, another
    // install's newer version is on the Homeserver and the backup is gone. The resumed
    // recovery doesn't write over it: that install signs (Switch spec 12.6 step 1, 4.3).
    let world = World::new();
    let (mut signer, service, _) = lost_with_an_app(&world, notes()).await;
    service.fail_next(Fault::LoseAnswer {
        path: "/enroll".into(),
    });
    signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap_err();
    let mine = signer.identity_doc().unwrap().unwrap();
    let mut body = mine.body().clone();
    body.version += 1;
    body.signer = [0x77; 16];
    let theirs = pubky_switch_core::records::IdentityDoc::sign(&world.key, body).unwrap();
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(theirs.signed()).unwrap());
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(pubky_switch_core::records::SIGNER_BACKUP_PATH);
    let error = signer.resume().await.unwrap_err();
    assert_eq!(
        error,
        SignerError::NotNamed {
            install: [0x77; 16]
        }
    );
    assert!(service.identity_doc().is_none());
    assert!(
        world
            .homeserver
            .file(pubky_switch_core::records::SIGNER_BACKUP_PATH)
            .is_none()
    );
}

#[tokio::test]
async fn test_provider_loss_carries_a_removal_in_flight() {
    // The lost service took a revocation, and the version removing the app never got
    // through: the recovery is built on that version, so the app stays removed, its App ID
    // named in the enrollment, and nothing is left pending (Switch spec 12.6 step 1).
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(world.env(store.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    let before = signer.identity_doc().unwrap().unwrap();
    world.switch.fail_next(Fault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    drop(signer);
    let (service, router) = new_service(&world);
    router.remove(SWITCH_ORIGIN);
    let mut signer = reopened(&world, store, &router, notes()).await;
    let recovered = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert!(recovered.listed_cert(&id).is_none());
    assert!(recovered.body().removed.iter().any(|r| r.app_id == id));
    assert_eq!(recovered.data_epoch(), before.data_epoch() + 1);
    assert!(
        service.kept_app_ids().contains(&id),
        "named in the enrollment"
    );
    assert!(
        !signer
            .alerts()
            .iter()
            .any(|a| matches!(a, Alert::RevocationPending { .. })),
        "{:?}",
        signer.alerts()
    );
}

#[tokio::test]
async fn test_provider_loss_sends_a_revocation_the_lost_service_took_again() {
    // The lost service took a revocation, then failed before the version removing the app
    // was signed: the new service hasn't taken it, so the alert for a revocation not
    // completed there says so (Switch spec 12.6 step 1, 12.2).
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(world.env(store.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    let app = App::new(&["notes"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    // The check before the revocation and the revocation go through; the read before the
    // removal doesn't.
    world.switch.fail_next(Fault::Unreachable {
        path: "/apps".into(),
        after: 2,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    assert!(signer.alerts().contains(&Alert::RevocationPending {
        app_id: id,
        at_switch: true
    }));
    drop(signer);
    let (service, router) = new_service(&world);
    router.remove(SWITCH_ORIGIN);
    let mut signer = reopened(&world, store, &router, notes()).await;
    // Neither the revocation nor the version removing the app gets through there.
    service.fail_next(Fault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    service.fail_next(Fault::Unreachable {
        path: "/identity".into(),
        after: 1,
    });
    let recovered = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert!(recovered.listed_cert(&id).is_some(), "still listed");
    assert!(
        signer.alerts().contains(&Alert::RevocationPending {
            app_id: id,
            at_switch: false
        }),
        "{:?}",
        signer.alerts()
    );
}

#[tokio::test]
async fn test_provider_loss_stops_at_a_newer_own_backup() {
    // The backup holds a newer version of this install's own than its records, while the
    // Homeserver's copy is at the mark: the records are behind, which the recovery's check
    // of the backup finds before anything is signed or sent (Switch spec 12.6 step 1, wire
    // 3.13).
    let world = World::new();
    let (signer, store) = world.enrolled().await;
    let mine = signer.identity_doc().unwrap().unwrap();
    let mut body = mine.body().clone();
    body.version += 1;
    body.record_max_age = Some(7);
    let own = pubky_switch_core::records::IdentityDoc::sign(&world.key, body).unwrap();
    let records = pubky_switch_core::records::SignerRecords::new(
        pubky_switch_core::keys::IdentityKey::from_secret(SECRET),
        own.clone(),
        &[],
        &[],
        pubky_switch_core::records::Limits::default(),
        &[],
        Some(mine.hash()),
    )
    .unwrap();
    let backup = pubky_switch_core::records::SignerBackup::seal(&world.key, &records).unwrap();
    world.homeserver.set(
        pubky_switch_core::records::SIGNER_BACKUP_PATH,
        serde_json::to_vec(&backup).unwrap(),
    );
    drop(signer);
    let (service, router) = new_service(&world);
    router.remove(SWITCH_ORIGIN);
    let mut signer = reopened(&world, store, &router, notes()).await;
    let error = signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap_err();
    assert_eq!(
        error,
        Refusal::RecordsBehind {
            version: own.version()
        }
        .into()
    );
    assert!(router.log().is_empty(), "nothing sent");
    assert!(service.identity_doc().is_none());
}

/// A recovery whose version the new service refused for good, once its backup was written:
/// the signer, the service, the router, the lost version and the refused one.
async fn refused_after_its_backup(
    world: &World,
) -> (
    Signer,
    Arc<ScriptedSwitch>,
    Arc<Router>,
    pubky_switch_core::records::IdentityDoc,
    pubky_switch_core::records::IdentityDoc,
) {
    let (mut signer, service, router) = lost_with_an_app(world, notes()).await;
    let lost = signer.identity_doc().unwrap().unwrap();
    service.fail_next(Fault::Error {
        path: "/identity".into(),
        code: pubky_switch_core::http::ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap_err();
    let refused = world.backup().identity_doc().clone();
    assert_eq!(refused.body().recovery_from, Some(lost.generation()));
    (signer, service, router, lost, refused)
}

#[tokio::test]
async fn test_provider_loss_restored_mid_recovery_on_a_new_install_declares_again() {
    // The backup holds a recovery's version the service refused: an install restored from
    // it is recovering, refused there, and declares the loss again at another service, the
    // lost generation the same and the version higher (Switch spec 12.6 step 1, wire 3.13).
    let world = World::new();
    let (signer, service, router, lost, refused) = refused_after_its_backup(&world).await;
    drop(signer);
    service.fail_next(Fault::Error {
        path: "/identity".into(),
        code: pubky_switch_core::http::ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    let store = Arc::new(MemoryStore::new());
    let mut env = world.env_with(store.clone(), notes());
    env.transport = router.clone();
    Signer::restore_new(env, world.keyring(), confirmed())
        .await
        .unwrap_err();
    let mut restored = reopened(&world, store, &router, notes()).await;
    assert_eq!(
        restored.status(),
        SignerStatus::RecoveryRefused {
            origin: NEW_ORIGIN.into()
        }
    );
    let third = service_on(&world, &router, THIRD_ORIGIN, 0x6e);
    let recovered = restored
        .declare_provider_loss(THIRD_ORIGIN, confirmed())
        .await
        .unwrap();
    assert_eq!(recovered.generation(), lost.generation() + 1);
    assert_eq!(recovered.body().recovery_from, Some(lost.generation()));
    assert!(recovered.version() > refused.version());
    assert_eq!(third.identity_doc().unwrap().hash(), recovered.hash());
    assert_eq!(world.published().unwrap().hash(), recovered.hash());
    assert_eq!(restored.status(), SignerStatus::Signing);
}

#[tokio::test]
async fn test_provider_loss_restored_mid_recovery_in_place_declares_again() {
    // The same, restored in place: the restore delivers the backup's version again, is
    // refused, and the recovery is declared again elsewhere (Switch spec 12.6 step 1).
    let world = World::new();
    let (mut signer, service, router, lost, refused) = refused_after_its_backup(&world).await;
    service.fail_next(Fault::Error {
        path: "/identity".into(),
        code: pubky_switch_core::http::ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    signer.restore(confirmed()).await.unwrap_err();
    assert_eq!(
        signer.status(),
        SignerStatus::RecoveryRefused {
            origin: NEW_ORIGIN.into()
        }
    );
    service_on(&world, &router, THIRD_ORIGIN, 0x6e);
    let recovered = signer
        .declare_provider_loss(THIRD_ORIGIN, confirmed())
        .await
        .unwrap();
    assert_eq!(recovered.generation(), lost.generation() + 1);
    assert_eq!(recovered.body().recovery_from, Some(lost.generation()));
    assert!(recovered.version() > refused.version());
}

#[tokio::test]
async fn test_provider_loss_restored_mid_recovery_completes_it() {
    // The install stopped after the recovery's backup, its delivery never sent: an install
    // restored from that backup delivers it, and the recovery is done there, the admission
    // ended (Switch spec 12.6, wire 3.13).
    let world = World::new();
    let (mut signer, service, router) = lost_with_an_app(&world, notes()).await;
    service.fail_next(Fault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap_err();
    let backed_up = world.backup().identity_doc().clone();
    drop(signer);
    let mut env = world.env_with(Arc::new(MemoryStore::new()), notes());
    env.transport = router.clone();
    let mut restored = Signer::restore_new(env, world.keyring(), confirmed())
        .await
        .unwrap();
    restored.resume().await.unwrap();
    let held = service.identity_doc().unwrap();
    assert_eq!(held.generation(), backed_up.generation());
    assert!(
        held.version() > backed_up.version(),
        "the restore's own next version"
    );
    assert!(!service.admission_staged());
    assert_eq!(restored.status(), SignerStatus::Signing);
}

#[tokio::test]
async fn test_provider_loss_admission_end_owed_after_a_restore_in_place() {
    // As after a restore on a new install: restored in place, the install still finds the
    // wait from the service's `GET /apps`, and ends it (Switch spec 12.6 step 2).
    let world = World::new();
    let (mut signer, service, _) = lost_with_an_app(&world, notes()).await;
    service.fail_next(Fault::Unreachable {
        path: "/recovery/admission".into(),
        after: 0,
    });
    signer
        .declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap();
    assert!(service.admission_staged());
    signer.restore(confirmed()).await.unwrap();
    signer.resume().await.unwrap();
    assert!(!service.admission_staged());
}
