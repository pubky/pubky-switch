//! The signer hand-over against the scripted switch (Switch spec 12.8; Switch wire 3.12,
//! 7.4.17): the old signer seals and stores it, signs nothing routine meanwhile, and deletes
//! its key only on the switch's proof that another install holds the identity; the new signer
//! checks it, delivers its first version, and takes the secret into its vault only once that
//! has won; and the abort, which beats it when it comes first. Answers that decide nothing
//! delete nothing, on either side.

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use pubky_switch_client::StoreError;
use pubky_switch_client::store::{KeyValue, MemoryStore, StateStore, StoreHandle, WriteBatch};
use pubky_switch_client::testing::{Fault as SwitchFault, SWITCH_ORIGIN};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::records::{AppCert, IDENTITY_PATH, IdentityDoc};
use pubky_switch_signer::state::signer_namespace;
use pubky_switch_signer::{
    AbortOutcome, AddOutcome, Alert, CertChange, IdentityKeyring, IdentitySecret, KeyError,
    ReceivingApp, Refusal, SecretVault, Signer, SignerError, SignerStatus, UserConfirmed,
    VaultError,
};
use serde_json::json;

fn confirmed() -> UserConfirmed {
    UserConfirmed::shown_and_confirmed()
}

/// Approve `app` and have it join, returning its certificate.
async fn approved(world: &World, signer: &mut Signer, app: &App) -> AppCert {
    let review = signer.review(&app.request, &app.auth).unwrap();
    let approved = signer.approve(review).await.unwrap();
    signer.claim_delivered(&approved.request).await.unwrap();
    world.join(app, &approved)
}

/// An enrolled old signer, with its store, and the app it hands over to, approved and joined.
struct Setup {
    old: Signer,
    old_store: Arc<MemoryStore>,
    target: ReceivingApp,
    handed: IdentityDoc,
}

async fn setup(world: &World) -> Setup {
    let (mut old, old_store) = world.enrolled().await;
    let app = App::with_keys(
        AppKeys::from_secrets([3; 32], [4; 32]),
        &["notes"],
        None,
        [9; 32],
    );
    let cert = approved(world, &mut old, &app).await;
    let handed = old.identity_doc().unwrap().unwrap();
    let target = ReceivingApp {
        keys: app.keys,
        cert,
        origin: SWITCH_ORIGIN.to_owned(),
        service_key: world.switch.service_key(),
    };
    Setup {
        old,
        old_store,
        target,
        handed,
    }
}

impl Setup {
    fn app_id(&self) -> [u8; 16] {
        self.target.cert.app_id()
    }
}

/// An empty vault for the new signer's install.
fn empty_vault() -> Arc<Vault> {
    Arc::new(Vault(Mutex::new(None)))
}

/// Whether `store` holds signer records for the identity.
async fn holds_records(store: &Arc<MemoryStore>) -> bool {
    let handle = StoreHandle::inline(store.clone());
    let ns = signer_namespace(&IdentityKey::from_secret(SECRET).public());
    handle.get(&ns, b"state").await.unwrap().is_some()
}

fn vault_holds(vault: &Vault) -> bool {
    vault.0.lock().unwrap().is_some()
}

/// The `current` of a `409 stale_identity` carrying a copy of `doc` at its version plus `ahead`,
/// naming `install`, whose signature doesn't verify: another document's.
fn forged(world: &World, doc: &IdentityDoc, ahead: u64, install: [u8; 16]) -> serde_json::Value {
    let mut body = doc.body().clone();
    body.version += ahead;
    body.signer = install;
    let mut signed = IdentityDoc::sign(&world.key, body)
        .unwrap()
        .signed()
        .clone();
    signed.sig.clone_from(&doc.signed().sig);
    json!({ "version": doc.version() + ahead, "generation": doc.generation(), "identity": signed })
}

/// How many `PUT` requests went to a path ending with `suffix`.
fn puts(world: &World, suffix: &str) -> usize {
    world
        .transport
        .requests()
        .iter()
        .filter(|r| r.method == "PUT" && r.path_and_query.ends_with(suffix))
        .count()
}

/// The `current` of a `409 stale_identity` carrying `doc`.
fn current(doc: &IdentityDoc) -> serde_json::Value {
    json!({ "version": doc.version(), "generation": doc.generation(), "identity": doc.signed() })
}

#[tokio::test]
async fn test_hand_over_takes_effect_and_the_old_signer_deletes_its_key() {
    let world = World::new();
    let Setup {
        mut old,
        old_store,
        target,
        handed,
    } = setup(&world).await;
    let app_id = target.cert.app_id();
    old.hand_over_to(app_id, confirmed()).await.unwrap();
    assert_eq!(old.status(), SignerStatus::HandingOver { to_app: app_id });
    assert_eq!(world.switch.stored_handover(), Some(app_id));
    // Nothing routine is signed while handing over.
    assert_eq!(
        old.set_record_max_age(Some(60)).await.unwrap_err(),
        SignerError::Refused(Refusal::HandingOver { to_app: app_id })
    );

    let store = Arc::new(MemoryStore::new());
    let vault = empty_vault();
    let mut new = Signer::receive_hand_over(world.env(store.clone()), &target, vault.clone())
        .await
        .unwrap();
    assert_eq!(new.status(), SignerStatus::Signing);
    assert_eq!(*vault.0.lock().unwrap(), Some(SECRET));
    let first = new.identity_doc().unwrap().unwrap();
    assert_eq!(first.version(), handed.version() + 1);
    assert_eq!(first.body().signer, new.install_id());
    assert_eq!(first.body().apps, handed.body().apps);
    assert_eq!(
        world.switch.identity_doc().unwrap().signed(),
        first.signed()
    );
    // Its backup is written once the delivery won, then the version published.
    assert_eq!(world.backup().identity_doc().signed(), first.signed());
    assert_eq!(world.published().unwrap().signed(), first.signed());
    assert_eq!(world.switch.stored_handover(), None);

    // The old signer finds the switch's copy and deletes the key, then its records.
    assert_eq!(
        old.resume().await.unwrap_err(),
        SignerError::HandedOver {
            install: new.install_id()
        }
    );
    assert!(!vault_holds(&world.vault));
    assert!(!holds_records(&old_store).await);
    assert!(matches!(
        old.resume().await.unwrap_err(),
        SignerError::HandedOver { .. }
    ));

    // The new signer signs on.
    new.set_record_max_age(Some(60)).await.unwrap();
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_hand_over_abort_wins_and_signing_goes_on() {
    let world = World::new();
    let mut s = setup(&world).await;
    let app_id = s.app_id();
    s.old.hand_over_to(app_id, confirmed()).await.unwrap();
    let outcome = s.old.abort_hand_over(confirmed()).await.unwrap();
    let version = s.handed.version() + 2;
    assert_eq!(outcome, AbortOutcome::Aborted { version });
    assert_eq!(s.old.status(), SignerStatus::Signing);
    let abort = world.switch.identity_doc().unwrap();
    assert_eq!(abort.version(), version);
    assert_eq!(abort.body().apps, s.handed.body().apps);
    assert_eq!(world.backup().identity_doc().signed(), abort.signed());
    assert_eq!(world.published().unwrap().signed(), abort.signed());
    // The switch dropped the hand-over with the abort: the new signer finds none.
    let store = Arc::new(MemoryStore::new());
    let vault = empty_vault();
    Signer::receive_hand_over(world.env(store.clone()), &s.target, vault.clone())
        .await
        .unwrap_err();
    assert!(!holds_records(&store).await);
    assert!(!vault_holds(&vault));
    s.old.set_record_max_age(Some(60)).await.unwrap();
    assert!(vault_holds(&world.vault));
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_take_over_lost_to_an_abort_deletes_what_was_received() {
    // The new signer signed its first delivery, but couldn't send it; the abort won first. Its
    // retry is answered with the abort, a verified copy past it: the take-over is cancelled.
    let world = World::new();
    let mut s = setup(&world).await;
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    let store = Arc::new(MemoryStore::new());
    let vault = empty_vault();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    Signer::receive_hand_over(world.env(store.clone()), &s.target, vault.clone())
        .await
        .unwrap_err();
    assert!(holds_records(&store).await, "the take-over is kept");
    assert!(!vault_holds(&vault));
    let AbortOutcome::Aborted { .. } = s.old.abort_hand_over(confirmed()).await.unwrap() else {
        panic!("the abort wins");
    };
    let identity = world.key.public();
    let lost = Signer::resume_take_over(
        world.env(store.clone()),
        identity,
        &s.target.keys,
        vault.clone(),
    )
    .await
    .unwrap_err();
    assert_eq!(lost, SignerError::Refused(Refusal::TakeOverCancelled));
    assert!(!holds_records(&store).await);
    assert!(!vault_holds(&vault));
    // Nothing is left to resume.
    assert_eq!(
        Signer::resume_take_over(world.env(store), identity, &s.target.keys, vault)
            .await
            .unwrap_err(),
        SignerError::Refused(Refusal::NotSetUp)
    );
    // The old signer still holds the identity.
    assert!(vault_holds(&world.vault));
    s.old.set_record_max_age(Some(60)).await.unwrap();
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_take_over_lost_answer_then_retry_wins() {
    // The switch took the first delivery and the answer was lost. The retry, the same bytes,
    // wins: by a 2xx, and by a 409 whose copy is the delivery itself.
    for as_409 in [false, true] {
        let world = World::new();
        let mut s = setup(&world).await;
        s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
        let store = Arc::new(MemoryStore::new());
        let vault = empty_vault();
        let distinct = world.distinct_requests("PUT", "/identity");
        world.switch.fail_next(SwitchFault::LoseAnswer {
            path: "/identity".into(),
        });
        Signer::receive_hand_over(world.env(store.clone()), &s.target, vault.clone())
            .await
            .unwrap_err();
        assert!(
            !vault_holds(&vault),
            "not before the delivery is known to have won"
        );
        let own = world.switch.identity_doc().unwrap();
        assert_eq!(own.version(), s.handed.version() + 1);
        if as_409 {
            world.switch.fail_next(SwitchFault::Error {
                path: "/identity".into(),
                code: ErrorCode::StaleIdentity,
                current: current(&own),
            });
        }
        let new = Signer::resume_take_over(
            world.env(store.clone()),
            world.key.public(),
            &s.target.keys,
            vault.clone(),
        )
        .await
        .unwrap();
        assert_eq!(new.status(), SignerStatus::Signing, "as 409: {as_409}");
        assert!(vault_holds(&vault));
        assert_eq!(new.identity_doc().unwrap().unwrap().signed(), own.signed());
        assert_eq!(world.distinct_requests("PUT", "/identity"), distinct + 1);
        assert_eq!(world.backup().identity_doc().signed(), own.signed());
        assert!(matches!(
            s.old.resume().await.unwrap_err(),
            SignerError::HandedOver { .. }
        ));
        assert!(!vault_holds(&world.vault));
    }
}

#[tokio::test]
async fn test_take_over_ambiguous_answers_delete_nothing() {
    // A refusal of the caller, a rate limit, and a 409 whose copy is missing, older or forged
    // decide nothing: the take-over is kept, and the delivery sent again wins.
    let world = World::new();
    let mut s = setup(&world).await;
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    let forged = forged(&world, &s.handed, 5, [7; 16]);
    let faults = [
        (ErrorCode::BadSignature, json!(null)),
        (ErrorCode::RateLimited, json!(null)),
        (ErrorCode::StaleIdentity, json!(null)),
        (ErrorCode::StaleIdentity, current(&s.handed)),
        (ErrorCode::StaleIdentity, forged),
    ];
    let store = Arc::new(MemoryStore::new());
    let vault = empty_vault();
    let identity = world.key.public();
    let distinct = world.distinct_requests("PUT", "/identity");
    for (i, (code, current)) in faults.into_iter().enumerate() {
        world.switch.fail_next(SwitchFault::Error {
            path: "/identity".into(),
            code,
            current,
        });
        let result = if i == 0 {
            Signer::receive_hand_over(world.env(store.clone()), &s.target, vault.clone()).await
        } else {
            Signer::resume_take_over(
                world.env(store.clone()),
                identity,
                &s.target.keys,
                vault.clone(),
            )
            .await
        };
        assert!(result.is_err(), "fault {i}");
        assert!(holds_records(&store).await, "fault {i}: kept");
        assert!(!vault_holds(&vault), "fault {i}");
    }
    let new = Signer::resume_take_over(world.env(store), identity, &s.target.keys, vault.clone())
        .await
        .unwrap();
    assert_eq!(new.status(), SignerStatus::Signing);
    assert!(vault_holds(&vault));
    // Every send was the same bytes.
    assert_eq!(world.distinct_requests("PUT", "/identity"), distinct + 1);
}

#[tokio::test]
async fn test_old_signer_ambiguous_answers_and_forged_copies_delete_nothing() {
    // While handing over: a refused or failing `GET /apps`, and an abort answered with no copy
    // or a forged "newer" one, delete nothing.
    let world = World::new();
    let mut s = setup(&world).await;
    let app_id = s.app_id();
    s.old.hand_over_to(app_id, confirmed()).await.unwrap();
    for code in [
        ErrorCode::BadSignature,
        ErrorCode::RateLimited,
        ErrorCode::Unavailable,
    ] {
        world.switch.fail_next(SwitchFault::Error {
            path: "/apps".into(),
            code,
            current: json!(null),
        });
        s.old.resume().await.unwrap_err();
        assert!(vault_holds(&world.vault));
        assert!(holds_records(&s.old_store).await);
    }
    let forged = forged(&world, &s.handed, 1, [7; 16]);
    let distinct = world.distinct_requests("PUT", "/identity");
    for (code, current) in [
        (ErrorCode::BadSignature, json!(null)),
        (ErrorCode::StaleIdentity, forged.clone()),
    ] {
        world.switch.fail_next(SwitchFault::Error {
            path: "/identity".into(),
            code,
            current,
        });
        s.old.abort_hand_over(confirmed()).await.unwrap_err();
        assert!(vault_holds(&world.vault));
        assert!(holds_records(&s.old_store).await);
        assert_eq!(s.old.status(), SignerStatus::HandingOver { to_app: app_id });
    }
    // The abort, signed again, is the same bytes, and wins.
    let outcome = s.old.abort_hand_over(confirmed()).await.unwrap();
    assert!(matches!(outcome, AbortOutcome::Aborted { .. }));
    assert_eq!(world.distinct_requests("PUT", "/identity"), distinct + 1);
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_old_signer_deletes_only_at_the_version_after_the_one_handed_over() {
    // A version after the one handed over, naming another install, ends it, whoever that is:
    // the target, or an install that restored its backup. A newer copy further on is
    // adopted as any other signer's, and the key stays.
    let world = World::new();
    let mut s = setup(&world).await;
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    let two = world.other_install_version(&s.handed, [7; 16]);
    let three = world.other_install_version(&two, [7; 16]);
    world.switch.deliver_identity(&two).unwrap();
    world.switch.deliver_identity(&three).unwrap();
    assert_eq!(
        s.old.resume().await.unwrap_err(),
        SignerError::NotNamed { install: [7; 16] }
    );
    assert!(
        vault_holds(&world.vault),
        "a version further on isn't the proof"
    );
    assert_eq!(s.old.status(), SignerStatus::ManagedBy { install: [7; 16] });

    // A copy only the Homeserver shows isn't the switch's proof either: it is adopted, and
    // the key stays.
    let world = World::new();
    let mut s = setup(&world).await;
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    let next = world.other_install_version(&s.handed, [7; 16]);
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(next.signed()).unwrap());
    assert_eq!(
        s.old.set_record_max_age(Some(60)).await.unwrap_err(),
        SignerError::NotNamed { install: [7; 16] }
    );
    assert!(vault_holds(&world.vault));
    assert!(holds_records(&s.old_store).await);

    let world = World::new();
    let mut s = setup(&world).await;
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    let next = world.other_install_version(&s.handed, [7; 16]);
    world.switch.deliver_identity(&next).unwrap();
    // A copy only the Homeserver shows isn't the switch's proof.
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(next.signed()).unwrap());
    let outcome = s.old.abort_hand_over(confirmed()).await.unwrap();
    assert_eq!(outcome, AbortOutcome::SucceededBy { install: [7; 16] });
    assert!(!vault_holds(&world.vault));
    assert!(!holds_records(&s.old_store).await);
}

#[tokio::test]
async fn test_hand_over_run_due_signs_nothing_routine() {
    let world = World::new();
    let mut s = setup(&world).await;
    let app_id = s.app_id();
    s.old.hand_over_to(app_id, confirmed()).await.unwrap();
    let sent = world.sent_docs().len();
    s.old.run_due().await.unwrap();
    world.clock.advance_ms(400 * 86_400_000);
    s.old.run_due().await.unwrap();
    assert_eq!(world.sent_docs().len(), sent);
    assert_eq!(s.old.status(), SignerStatus::HandingOver { to_app: app_id });
}

#[tokio::test]
async fn test_hand_over_target_must_be_listed_and_current() {
    let world = World::new();
    let mut s = setup(&world).await;
    assert_eq!(
        s.old.hand_over_to([5; 16], confirmed()).await.unwrap_err(),
        SignerError::Refused(Refusal::NotListed)
    );
    world.switch.revoke(s.app_id()).unwrap();
    let refused = s
        .old
        .hand_over_to(s.app_id(), confirmed())
        .await
        .unwrap_err();
    assert_eq!(refused, SignerError::Refused(Refusal::TargetNotCurrent));
    assert_eq!(world.switch.stored_handover(), None);
    assert_ne!(
        s.old.status(),
        SignerStatus::HandingOver { to_app: s.app_id() }
    );
}

#[tokio::test]
async fn test_hand_over_and_revocation_wait_for_each_other() {
    // A revocation owed holds a hand-over back, and a hand-over holds a revocation back: the
    // hand-over carries the records as sealed, not a revocation in progress.
    let world = World::new();
    let mut s = setup(&world).await;
    let other = App::with_keys(
        AppKeys::from_secrets([5; 32], [6; 32]),
        &["notes"],
        None,
        [10; 32],
    );
    approved(&world, &mut s.old, &other).await;
    let other_id = other.keys.app_id_bytes();
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    assert_eq!(
        s.old.revoke(other_id, None, confirmed()).await.unwrap_err(),
        SignerError::Refused(Refusal::HandingOver { to_app: s.app_id() })
    );
    s.old.abort_hand_over(confirmed()).await.unwrap();
    world.switch.fail_next(SwitchFault::Error {
        path: "/revoke".into(),
        code: ErrorCode::Unavailable,
        current: json!(null),
    });
    s.old.revoke(other_id, None, confirmed()).await.unwrap_err();
    assert_eq!(
        s.old
            .hand_over_to(s.app_id(), confirmed())
            .await
            .unwrap_err(),
        SignerError::Refused(Refusal::RevocationOwed)
    );
}

#[tokio::test]
async fn test_hand_over_store_is_sent_again_after_a_lost_answer() {
    let world = World::new();
    let mut s = setup(&world).await;
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/handover".into(),
    });
    s.old
        .hand_over_to(s.app_id(), confirmed())
        .await
        .unwrap_err();
    assert_eq!(
        s.old.status(),
        SignerStatus::HandingOver { to_app: s.app_id() }
    );
    s.old.resume().await.unwrap();
    assert_eq!(world.distinct_requests("PUT", "/handover"), 1);
    assert_eq!(world.switch.stored_handover(), Some(s.app_id()));
}

#[tokio::test]
async fn test_hand_over_definite_refusal_is_kept_until_aborted() {
    // A refusal for good isn't sent again; an earlier send may be stored, so the hand-over
    // stays, with an alert, until the user aborts it.
    let world = World::new();
    let mut s = setup(&world).await;
    let app_id = s.app_id();
    world.switch.fail_next(SwitchFault::Error {
        path: "/handover".into(),
        code: ErrorCode::BadRequest,
        current: json!(null),
    });
    s.old.hand_over_to(app_id, confirmed()).await.unwrap_err();
    assert!(
        s.old
            .alerts()
            .contains(&Alert::HandOverRefused { to_app: app_id })
    );
    let sends = puts(&world, "/handover");
    s.old.resume().await.unwrap();
    assert_eq!(puts(&world, "/handover"), sends);
    assert_eq!(s.old.status(), SignerStatus::HandingOver { to_app: app_id });
    let outcome = s.old.abort_hand_over(confirmed()).await.unwrap();
    assert!(matches!(outcome, AbortOutcome::Aborted { .. }));
}

#[tokio::test]
async fn test_take_over_check_3_refuses_a_newer_homeserver_copy() {
    let world = World::new();
    let mut s = setup(&world).await;
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    let newer = world.other_install_version(&s.handed, [7; 16]);
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(newer.signed()).unwrap());
    let store = Arc::new(MemoryStore::new());
    let vault = empty_vault();
    let sends = puts(&world, "/identity");
    assert_eq!(
        Signer::receive_hand_over(world.env(store.clone()), &s.target, vault.clone())
            .await
            .unwrap_err(),
        SignerError::Refused(Refusal::StaleHandOver)
    );
    assert!(!holds_records(&store).await);
    assert!(!vault_holds(&vault));
    assert_eq!(puts(&world, "/identity"), sends, "nothing sent");
}

#[tokio::test]
async fn test_take_over_check_3_refuses_a_switch_without_the_version_handed_over() {
    // A switch that holds no copy went back: a delivery built on the version handed over would
    // be refused, so nothing is sent and nothing received is kept.
    let world = World::new();
    let mut s = setup(&world).await;
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    world.switch.lose_identity();
    let store = Arc::new(MemoryStore::new());
    let vault = empty_vault();
    let sends = puts(&world, "/identity");
    assert_eq!(
        Signer::receive_hand_over(world.env(store.clone()), &s.target, vault.clone())
            .await
            .unwrap_err(),
        SignerError::Refused(Refusal::StaleHandOver)
    );
    assert!(!holds_records(&store).await);
    assert!(!vault_holds(&vault));
    assert_eq!(puts(&world, "/identity"), sends, "nothing sent");
}

/// A vault whose writes fail while `failing` is set, and whose deletions fail while
/// `failing_delete` is.
struct Flaky {
    inner: Vault,
    failing: Mutex<bool>,
    failing_delete: Mutex<bool>,
}

impl SecretVault for Flaky {
    fn load(&self) -> Result<Option<IdentitySecret>, VaultError> {
        self.inner.load()
    }
    fn add(&self, secret: &IdentitySecret) -> Result<AddOutcome, VaultError> {
        if *self.failing.lock().unwrap() {
            return Err(VaultError("locked".into()));
        }
        self.inner.add(secret)
    }
    fn delete(&self) -> Result<(), VaultError> {
        if *self.failing_delete.lock().unwrap() {
            return Err(VaultError("locked".into()));
        }
        self.inner.delete()
    }
}

/// A store whose commits fail once `left` more have gone through.
struct Failing {
    inner: Arc<MemoryStore>,
    left: Mutex<Option<usize>>,
}

impl StateStore for Failing {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.get(ns, key)
    }
    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<KeyValue>, StoreError> {
        self.inner.scan(ns, prefix, after, limit)
    }
    fn commit(&self, batch: WriteBatch) -> Result<(), StoreError> {
        let mut left = self.left.lock().unwrap();
        match left.as_mut() {
            Some(0) => return Err(StoreError::Unavailable),
            Some(n) => *n -= 1,
            None => {}
        }
        self.inner.commit(batch)
    }
}

#[tokio::test]
async fn test_take_over_vault_failure_keeps_the_flow_and_sends_nothing_again() {
    let world = World::new();
    let mut s = setup(&world).await;
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    let store = Arc::new(MemoryStore::new());
    let vault = Arc::new(Flaky {
        inner: Vault(Mutex::new(None)),
        failing: Mutex::new(true),
        failing_delete: Mutex::new(false),
    });
    Signer::receive_hand_over(world.env(store.clone()), &s.target, vault.clone())
        .await
        .unwrap_err();
    assert!(holds_records(&store).await);
    assert!(new_alert_kept(&store).await);
    let sends = puts(&world, "/identity");
    *vault.failing.lock().unwrap() = false;
    let new = Signer::resume_take_over(
        world.env(store),
        world.key.public(),
        &s.target.keys,
        vault.clone(),
    )
    .await
    .unwrap();
    assert_eq!(new.status(), SignerStatus::Signing);
    assert!(!new.alerts().contains(&Alert::KeyNotInstalled));
    assert_eq!(*vault.inner.0.lock().unwrap(), Some(SECRET));
    // The delivery wasn't sent again.
    assert_eq!(puts(&world, "/identity"), sends);
}

/// Whether the records in `store` hold [`Alert::KeyNotInstalled`].
async fn new_alert_kept(store: &Arc<MemoryStore>) -> bool {
    let handle = StoreHandle::inline(store.clone());
    let ns = signer_namespace(&IdentityKey::from_secret(SECRET).public());
    let bytes = handle.get(&ns, b"state").await.unwrap().unwrap();
    String::from_utf8_lossy(&bytes).contains("KeyNotInstalled")
}

#[tokio::test]
async fn test_hand_over_refuses_a_restore_meanwhile() {
    // A restore would sign the version after the one handed over, racing the new signer at
    // its own version.
    let world = World::new();
    let mut s = setup(&world).await;
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    assert_eq!(
        s.old.restore(confirmed()).await.unwrap_err(),
        SignerError::Refused(Refusal::HandingOver { to_app: s.app_id() })
    );
    assert_eq!(
        s.old.status(),
        SignerStatus::HandingOver { to_app: s.app_id() }
    );
}

#[tokio::test]
async fn test_switch_showing_each_side_the_other_leaves_the_old_key() {
    // The abort is signed while the switch holds the version handed over, and not sent. The
    // switch then takes the new signer's version and withholds the answer, answers the abort
    // with it, and answers the new signer's retry with the abort, which it never took. The
    // new signer gives up; the old signer keeps the key, since the new signer never
    // published.
    let world = World::new();
    let mut s = setup(&world).await;
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    s.old.abort_hand_over(confirmed()).await.unwrap_err();
    let abort = world.sent_docs().into_iter().last().unwrap();
    assert_eq!(abort.version(), s.handed.version() + 2);
    let store = Arc::new(MemoryStore::new());
    let vault = empty_vault();
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/identity".into(),
    });
    Signer::receive_hand_over(world.env(store.clone()), &s.target, vault.clone())
        .await
        .unwrap_err();
    let new_version = world.switch.identity_doc().unwrap();
    assert_eq!(
        s.old.abort_hand_over(confirmed()).await.unwrap_err(),
        SignerError::Refused(Refusal::SuccessorUnpublished {
            install: new_version.body().signer
        })
    );
    assert!(vault_holds(&world.vault));
    assert!(holds_records(&s.old_store).await);
    world.switch.fail_next(SwitchFault::Error {
        path: "/identity".into(),
        code: ErrorCode::StaleIdentity,
        current: current(&abort),
    });
    let lost = Signer::resume_take_over(
        world.env(store.clone()),
        world.key.public(),
        &s.target.keys,
        vault.clone(),
    )
    .await
    .unwrap_err();
    assert_eq!(lost, SignerError::Refused(Refusal::TakeOverCancelled));
    assert!(!vault_holds(&vault));
    // The old install still holds the key, and still deletes nothing.
    assert!(s.old.resume().await.is_err());
    assert!(vault_holds(&world.vault));
    assert!(holds_records(&s.old_store).await);
}

#[tokio::test]
async fn test_abort_after_the_new_signer_moved_on_signs_nothing() {
    // The old install was away while the new signer took over and signed a version after its
    // first: an abort at the same version would be another body there.
    let world = World::new();
    let mut s = setup(&world).await;
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    let store = Arc::new(MemoryStore::new());
    let mut new = Signer::receive_hand_over(world.env(store), &s.target, empty_vault())
        .await
        .unwrap();
    new.set_record_max_age(Some(60)).await.unwrap();
    let sent = world.sent_docs().len();
    assert_eq!(
        s.old.abort_hand_over(confirmed()).await.unwrap_err(),
        SignerError::NotNamed {
            install: new.install_id()
        }
    );
    assert_eq!(world.sent_docs().len(), sent, "no abort signed");
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_hand_over_deletion_finishes_after_a_failure() {
    // The key's deletion fails: the records are marked, and the next open deletes both.
    let world = World::new();
    let vault = Arc::new(Flaky {
        inner: Vault(Mutex::new(Some(SECRET))),
        failing: Mutex::new(false),
        failing_delete: Mutex::new(true),
    });
    let (mut old, old_store) = {
        let store = Arc::new(MemoryStore::new());
        let keyring = IdentityKeyring::open(vault.clone()).unwrap();
        let mut signer = Signer::create(world.env(store.clone()), keyring, SWITCH_ORIGIN)
            .await
            .unwrap();
        signer.resume().await.unwrap();
        (signer, store)
    };
    let app = App::with_keys(
        AppKeys::from_secrets([3; 32], [4; 32]),
        &["notes"],
        None,
        [9; 32],
    );
    let cert = approved(&world, &mut old, &app).await;
    let target = ReceivingApp {
        keys: app.keys,
        cert,
        origin: SWITCH_ORIGIN.to_owned(),
        service_key: world.switch.service_key(),
    };
    old.hand_over_to(target.cert.app_id(), confirmed())
        .await
        .unwrap();
    let new = Signer::receive_hand_over(
        world.env(Arc::new(MemoryStore::new())),
        &target,
        empty_vault(),
    )
    .await
    .unwrap();
    assert!(matches!(
        old.resume().await.unwrap_err(),
        SignerError::Key(KeyError::Vault(_))
    ));
    assert!(vault.inner.0.lock().unwrap().is_some());
    drop(old);
    *vault.failing_delete.lock().unwrap() = false;
    let keyring = IdentityKeyring::open(vault.clone()).unwrap();
    assert_eq!(
        Signer::open(world.env(old_store.clone()), keyring)
            .await
            .unwrap_err(),
        SignerError::HandedOver {
            install: new.install_id()
        }
    );
    assert!(vault.inner.0.lock().unwrap().is_none());
    assert!(!holds_records(&old_store).await);

    // The records' deletion fails once the key is gone: they count as none for a new set-up.
    let world = World::new();
    let mut s = setup(&world).await;
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    Signer::receive_hand_over(
        world.env(Arc::new(MemoryStore::new())),
        &s.target,
        empty_vault(),
    )
    .await
    .unwrap();
    drop(s.old);
    let failing = Arc::new(Failing {
        inner: s.old_store.clone(),
        left: Mutex::new(Some(1)),
    });
    let mut old = Signer::open(world.env(failing), world.keyring())
        .await
        .unwrap();
    assert!(old.resume().await.is_err());
    assert!(!vault_holds(&world.vault));
    assert!(holds_records(&s.old_store).await, "left behind, marked");
    // The key comes back from elsewhere, and the install restores from the new signer's
    // backup: the marked records don't stand in the way.
    *world.vault.0.lock().unwrap() = Some(SECRET);
    let restored =
        Signer::restore_new(world.env(s.old_store.clone()), world.keyring(), confirmed())
            .await
            .unwrap();
    assert_eq!(restored.status(), SignerStatus::Signing);
}

#[tokio::test]
async fn test_hand_over_decided_before_a_failed_publication() {
    // The take-over or the abort has won, and the publication after it fails: the outcome
    // stands, and the publication is the next run's.
    let world = World::new();
    let mut s = setup(&world).await;
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    let store = Arc::new(MemoryStore::new());
    let vault = empty_vault();
    *world.homeserver.failing_puts.lock().unwrap() = true;
    Signer::receive_hand_over(world.env(store.clone()), &s.target, vault.clone())
        .await
        .unwrap_err();
    assert!(vault_holds(&vault));
    *world.homeserver.failing_puts.lock().unwrap() = false;
    let new = Signer::resume_take_over(world.env(store), world.key.public(), &s.target.keys, vault)
        .await
        .unwrap();
    let first = new.identity_doc().unwrap().unwrap();
    assert_eq!(world.published().unwrap().signed(), first.signed());

    let world = World::new();
    let mut s = setup(&world).await;
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    *world.homeserver.failing_puts.lock().unwrap() = true;
    let outcome = s.old.abort_hand_over(confirmed()).await.unwrap();
    assert_eq!(
        outcome,
        AbortOutcome::Aborted {
            version: s.handed.version() + 2
        }
    );
    *world.homeserver.failing_puts.lock().unwrap() = false;
    s.old.resume().await.unwrap();
    assert_eq!(world.published().unwrap().version(), s.handed.version() + 2);
}

#[tokio::test]
async fn test_hand_over_refused_while_a_closing_is_owed() {
    // A reduction's closing waits for a service time the switch didn't give: still owed.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/identity".into(),
    });
    let reduce = CertChange {
        scopes: Some(vec!["notes".to_owned()]),
        expires_at: None,
    };
    signer.renew(id, reduce).await.unwrap_err();
    world.switch.forget_delivery_proof();
    signer.resume().await.unwrap_err();
    assert!(
        signer
            .alerts()
            .contains(&Alert::ReductionNotClosed { apps: vec![id] })
    );
    assert_eq!(
        signer.hand_over_to(id, confirmed()).await.unwrap_err(),
        SignerError::Refused(Refusal::ClosingOwed)
    );
    assert_eq!(world.switch.stored_handover(), None);
}

#[tokio::test]
async fn test_hand_over_not_stored_again_once_it_took_effect() {
    let world = World::new();
    let mut s = setup(&world).await;
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/handover".into(),
    });
    s.old
        .hand_over_to(s.app_id(), confirmed())
        .await
        .unwrap_err();
    Signer::receive_hand_over(
        world.env(Arc::new(MemoryStore::new())),
        &s.target,
        empty_vault(),
    )
    .await
    .unwrap();
    let sends = puts(&world, "/handover");
    assert!(matches!(
        s.old.resume().await.unwrap_err(),
        SignerError::HandedOver { .. }
    ));
    assert_eq!(puts(&world, "/handover"), sends);
    assert_eq!(world.switch.stored_handover(), None);
}

#[tokio::test]
async fn test_take_over_refuses_a_vault_holding_another_secret() {
    let world = World::new();
    let mut s = setup(&world).await;
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    let store = Arc::new(MemoryStore::new());
    let vault = Arc::new(Vault(Mutex::new(Some([42; 32]))));
    let sends = puts(&world, "/identity");
    assert_eq!(
        Signer::receive_hand_over(world.env(store.clone()), &s.target, vault)
            .await
            .unwrap_err(),
        SignerError::Key(KeyError::Occupied)
    );
    assert!(!holds_records(&store).await);
    assert_eq!(puts(&world, "/identity"), sends);
}

#[tokio::test]
async fn test_hand_over_successor_lost_before_publishing_restores_from_its_backup() {
    // The new signer won, wrote its backup, and was lost before publishing. The old install
    // keeps the key and signs nothing; an install with the key restores from the new
    // signer's backup on a fresh store and signs from then on.
    let world = World::new();
    let mut s = setup(&world).await;
    s.old.hand_over_to(s.app_id(), confirmed()).await.unwrap();
    *world.homeserver.failing_path.lock().unwrap() = Some(IDENTITY_PATH.to_owned());
    let new = Signer::receive_hand_over(
        world.env(Arc::new(MemoryStore::new())),
        &s.target,
        empty_vault(),
    )
    .await;
    assert!(new.is_err(), "the publication failed");
    drop(new);
    *world.homeserver.failing_path.lock().unwrap() = None;
    let won = world.switch.identity_doc().unwrap();
    assert_eq!(world.backup().identity_doc().signed(), won.signed());
    assert_eq!(
        s.old.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::SuccessorUnpublished {
            install: won.body().signer
        })
    );
    assert_eq!(
        s.old.restore(confirmed()).await.unwrap_err(),
        SignerError::Refused(Refusal::HandingOver { to_app: s.app_id() })
    );
    assert!(vault_holds(&world.vault));
    let restored = Signer::restore_new(
        world.env(Arc::new(MemoryStore::new())),
        world.keyring(),
        confirmed(),
    )
    .await
    .unwrap();
    assert_eq!(restored.status(), SignerStatus::Signing);
    assert_eq!(
        restored.identity_doc().unwrap().unwrap().version(),
        won.version() + 1
    );
    world.assert_no_version_sent_twice();
}
