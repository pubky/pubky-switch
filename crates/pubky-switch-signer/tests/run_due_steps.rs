//! The routine run's bounds against a step that keeps failing, a restart, a crash between
//! two commits and a run dropped part way (design note, section 4.5).

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Waker};

use common::*;
use pubky_switch_client::TransportError;
use pubky_switch_client::clock::Clock;
use pubky_switch_client::store::{Fault, FaultStore, MemoryStore, StateStore, StoreHandle};
use pubky_switch_client::testing::{Fault as SwitchFault, SWITCH_ORIGIN};
use pubky_switch_client::transport::BoxFuture;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::{IDENTITY_PATH, Limits, app_record_path};
use pubky_switch_signer::{Alert, CertChange, Homeserver, Protocols, Signer, SignerEnv};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const LIFETIME_MS: u64 = 365 * DAY_MS;
const HOUR_MS: i64 = 60 * 60 * 1000;

fn apps(n: u8) -> Vec<App> {
    (0..n)
        .map(|i| {
            App::with_keys(
                AppKeys::from_secrets([i + 1; 32], [i + 101; 32]),
                &["notes"],
                None,
                [i + 1; 32],
            )
        })
        .collect()
}

fn env_for_many(world: &World, store: Arc<dyn StateStore>) -> SignerEnv {
    world.switch.set_enroll_limits(Limits {
        app_limit: 40,
        ..Limits::default()
    });
    world.env(store)
}

async fn enrolled_for_many(world: &World) -> Signer {
    let store = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(env_for_many(world, store), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    signer
}

fn renewed_since(signer: &Signer, ids: &[[u8; 16]], since: u64) -> Vec<[u8; 16]> {
    let doc = signer.identity_doc().unwrap().unwrap();
    let certs = signer.certificates().unwrap();
    ids.iter()
        .copied()
        .filter(|id| {
            let hash = doc.listed_cert(id).unwrap();
            certs
                .iter()
                .find(|c| c.hash() == hash)
                .is_some_and(|c| c.issued_at() >= since)
        })
        .collect()
}

fn clock_moves_at_the_first_read(world: &World, ms: i64) {
    let clock = Arc::clone(&world.clock);
    *world.homeserver.after_get.lock().unwrap() = Some((
        IDENTITY_PATH.to_owned(),
        1,
        Box::new(move || {
            let now = clock.now_ms();
            clock.set_ms(now.saturating_add_signed(ms));
        }),
    ));
}

/// A refusal for good of the next request whose path holds `path`.
fn refusal(path: &str) -> SwitchFault {
    SwitchFault::Error {
        path: path.into(),
        code: if path == "/ops" {
            ErrorCode::Conflict
        } else {
            ErrorCode::BadRequest
        },
        current: serde_json::Value::Null,
    }
}

/// The switch stores a renewed certificate for `app_id` issued `ahead_ms` from now, as an
/// earlier renewal cut short leaves one: every renewal of `app_id` this signer issues before
/// then is refused for good at its batch, `409 conflict` (Switch wire 3.8, 6.2), and no other
/// app's is.
fn plant_later_renewal(world: &World, signer: &Signer, app_id: [u8; 16], ahead_ms: u64) {
    use pubky_switch_core::ops::OpKind;
    use pubky_switch_core::records::{AppCert, AppCertBody};
    let doc = signer.identity_doc().unwrap().unwrap();
    let hash = doc.listed_cert(&app_id).unwrap();
    let held = signer
        .certificates()
        .unwrap()
        .into_iter()
        .find(|c| c.hash() == hash)
        .unwrap();
    let issued = world.clock.now_ms() + ahead_ms;
    let body = AppCertBody::new(
        signer.identity(),
        held.signing_key(),
        held.bundle_key(),
        held.scopes().to_vec(),
        held.permissions(),
        issued,
        issued + LIFETIME_MS,
    );
    let cert = AppCert::issue(&world.key, body).unwrap();
    world
        .switch
        .signer_op(OpKind::CertPut {
            target_app_id: app_id,
            cert: cert.signed().clone(),
        })
        .unwrap();
}

#[tokio::test]
async fn test_run_due_cursor_on_a_refused_renewal_holds_back_no_full_bundle() {
    // A run whose clock jumps answers `a`'s full-bundle request and leaves the cursor at the
    // renewals. Then `a`'s renewal is refused for good at every run, and `b` asks for its full
    // bundle: the full-bundle answers, which come before the renewals in a run from the first
    // step, must still get a turn.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let all = apps(2);
    world.approve(&mut signer, &all[0]).await;
    let a = all[0].keys.app_id_bytes();
    world.switch.request_full_bundle(a);
    clock_moves_at_the_first_read(&world, HOUR_MS);
    assert!(signer.run_due().await.unwrap().steps_left);
    assert!(world.switch.app(&a).full_requested.is_none());
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    world.approve(&mut signer, &all[1]).await;
    let b = all[1].keys.app_id_bytes();
    plant_later_renewal(&world, &signer, a, 300 * DAY_MS);
    world.switch.request_full_bundle(b);
    for _ in 0..4 {
        let _ = signer.run_due().await;
    }
    assert!(
        world.switch.app(&b).full_requested.is_none(),
        "b's full-bundle request answered within four runs"
    );
}

#[tokio::test]
async fn test_run_due_cursor_at_the_first_step_answers_the_full_bundle() {
    // The control: the same, with the cursor at the first step.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let all = apps(2);
    world.approve(&mut signer, &all[0]).await;
    let a = all[0].keys.app_id_bytes();
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    world.approve(&mut signer, &all[1]).await;
    let b = all[1].keys.app_id_bytes();
    plant_later_renewal(&world, &signer, a, 300 * DAY_MS);
    world.switch.request_full_bundle(b);
    let _ = signer.run_due().await;
    assert!(world.switch.app(&b).full_requested.is_none());
}

#[tokio::test]
async fn test_run_due_a_renewal_refused_at_every_run_holds_back_no_other_app() {
    // `b` is listed first and expires after `a`; `a`'s automatic renewal is refused for good
    // at every run (a stored renewed certificate issued later). `b`'s renewal must still be
    // made.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let all = apps(2);
    world.approve(&mut signer, &all[0]).await;
    world.clock.advance_ms(DAY_MS);
    world.approve(&mut signer, &all[1]).await;
    world.clock.advance_ms(DAY_MS);
    let (b, a) = (all[0].keys.app_id_bytes(), all[1].keys.app_id_bytes());
    signer.renew(b, CertChange::default()).await.unwrap();
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    plant_later_renewal(&world, &signer, a, 300 * DAY_MS);
    let since = world.clock.now_ms();
    let mut refused = 0;
    for _ in 0..4 {
        refused += usize::from(signer.run_due().await.is_err());
    }
    assert_eq!(refused, 4, "a's renewal refused at every run");
    assert!(renewed_since(&signer, &[a], since).is_empty(), "a refused");
    assert_eq!(renewed_since(&signer, &[b], since), [b], "b renewed");
}

#[tokio::test]
async fn test_run_due_refused_full_bundles_take_no_place_at_the_next_run() {
    // Five requests; the four oldest are refused for good in the first run. The next run
    // passes over them and answers the fifth.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let all = apps(5);
    for app in &all {
        world.approve(&mut signer, app).await;
    }
    let ids: Vec<[u8; 16]> = all.iter().map(|a| a.keys.app_id_bytes()).collect();
    for id in &ids {
        world.switch.request_full_bundle(*id);
        world.clock.advance_ms(1_000);
    }
    for _ in 0..4 {
        world.switch.fail_next(refusal("/ops"));
    }
    let report = signer.run_due().await.unwrap();
    assert!(report.full_bundles_left);
    for id in &ids[..4] {
        assert!(
            signer
                .alerts()
                .contains(&Alert::FullBundleRefused { app_id: *id })
        );
    }
    assert!(world.switch.app(&ids[4]).full_requested.is_some());
    let report = signer.run_due().await.unwrap();
    assert!(world.switch.app(&ids[4]).full_requested.is_none());
    assert!(!report.full_bundles_left);
}

#[tokio::test]
async fn test_run_due_cursor_survives_a_restart() {
    // `a` is due for renewal and `b`, approved later, asks for its full bundle. A run whose
    // clock jumps answers `b` and leaves the cursor at the renewals, then a restart. `b` asks
    // again, and the next run, its clock jumping too, starts from the renewals: it renews `a`,
    // and `b`'s request waits. A run from the first step would answer `b` and leave `a`.
    let world = World::new();
    let memory = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(
        env_for_many(&world, memory.clone()),
        world.keyring(),
        SWITCH_ORIGIN,
    )
    .await
    .unwrap();
    signer.resume().await.unwrap();
    let all = apps(2);
    world.approve(&mut signer, &all[0]).await;
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    world.approve(&mut signer, &all[1]).await;
    let (a, b) = (all[0].keys.app_id_bytes(), all[1].keys.app_id_bytes());
    world.switch.request_full_bundle(b);
    let since = world.clock.now_ms();
    clock_moves_at_the_first_read(&world, HOUR_MS);
    assert!(signer.run_due().await.unwrap().steps_left);
    assert!(world.switch.app(&b).full_requested.is_none());
    assert!(renewed_since(&signer, &[a], since).is_empty());
    drop(signer);
    let mut signer = Signer::open(world.env(memory), world.keyring())
        .await
        .unwrap();
    world.switch.request_full_bundle(b);
    clock_moves_at_the_first_read(&world, HOUR_MS);
    assert!(signer.run_due().await.unwrap().steps_left);
    assert_eq!(renewed_since(&signer, &[a], since), [a]);
    assert!(world.switch.app(&b).full_requested.is_some());
}

#[tokio::test]
async fn test_run_due_renews_an_app_once_it_joins() {
    // An app approved and not joined is past half its lifetime: not renewed. It joins: the
    // next run renews it.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let app = &apps(1)[0];
    let review = signer.review(&app.request, &app.auth).unwrap();
    let approved = signer.approve(review).await.unwrap();
    signer.claim_delivered(&approved.request).await.unwrap();
    let id = app.keys.app_id_bytes();
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    let since = world.clock.now_ms();
    signer.run_due().await.unwrap();
    assert!(renewed_since(&signer, &[id], since).is_empty());
    world.join(app, &approved);
    signer.run_due().await.unwrap();
    assert_eq!(renewed_since(&signer, &[id], since), [id]);
}

#[tokio::test]
async fn test_run_due_crash_after_a_deletion_keeps_one_reminder() {
    // The process stops right after a removed app's record is deleted, before that
    // deletion's commit: its reminder was committed before, and the next run deletes again
    // and keeps that one reminder.
    let setup = || async {
        let world = World::new();
        let (mut signer, memory) = world.enrolled().await;
        let app = App::new(&["notes"], None, [9; 32]);
        world.approve(&mut signer, &app).await;
        let id = app.keys.app_id_bytes();
        world.homeserver.set(&app_record_path(&id), b"{}".to_vec());
        drop(signer);
        (world, memory, id)
    };
    let confirmed = pubky_switch_signer::UserConfirmed::shown_and_confirmed;
    let (world, memory, id) = setup().await;
    let counting = Arc::new(FaultStore::new(memory, Fault::None));
    let store: Arc<dyn StateStore> = counting.clone();
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    signer.revoke(id, None, confirmed()).await.unwrap();
    let last = counting.commits();
    let (world, memory, id) = setup().await;
    let faulty: Arc<dyn StateStore> =
        Arc::new(FaultStore::new(memory.clone(), Fault::StopBefore(last)));
    let mut signer = Signer::open(world.env(faulty), world.keyring())
        .await
        .unwrap();
    let _ = signer.revoke(id, None, confirmed()).await;
    assert!(world.homeserver.file(&app_record_path(&id)).is_none());
    let mut signer = Signer::open(world.env(memory), world.keyring())
        .await
        .unwrap();
    let reminder = Alert::GrantRevocationOwed { app_id: id };
    let count = |signer: &Signer| signer.alerts().iter().filter(|a| **a == reminder).count();
    assert_eq!(count(&signer), 1);
    world.homeserver.deletes.lock().unwrap().clear();
    signer.run_due().await.unwrap();
    assert_eq!(count(&signer), 1);
    assert!(
        world
            .homeserver
            .deletes
            .lock()
            .unwrap()
            .contains(&app_record_path(&id)),
        "deleted again"
    );
    signer.run_due().await.unwrap();
    world.homeserver.deletes.lock().unwrap().clear();
    signer.run_due().await.unwrap();
    assert!(
        !world
            .homeserver
            .deletes
            .lock()
            .unwrap()
            .contains(&app_record_path(&id)),
        "no longer owed"
    );
}

/// A Homeserver whose writes to one path never answer, as a host's request that it gives up
/// on by dropping the call.
struct Hanging {
    inner: Arc<TestHomeserver>,
    path: Mutex<Option<String>>,
    hung: Mutex<bool>,
}

impl Homeserver for Hanging {
    fn get(&self, path: &str) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        self.inner.get(path)
    }
    fn put(&self, path: &str, bytes: Vec<u8>) -> BoxFuture<'_, Result<(), TransportError>> {
        if self.path.lock().unwrap().as_deref() == Some(path) {
            *self.hung.lock().unwrap() = true;
            return Box::pin(std::future::pending());
        }
        self.inner.put(path, bytes)
    }
    fn delete(&self, path: &str) -> BoxFuture<'_, Result<(), TransportError>> {
        self.inner.delete(path)
    }
}

#[tokio::test]
async fn test_run_due_dropped_run_leaves_each_later_call_its_own_budget() {
    // A run is dropped by the host while its first renewal's publication waits. A direct
    // `renew_expiring` afterwards, outside any run, has a budget of its own: it renews the
    // four apps still due.
    let world = World::new();
    world.switch.set_enroll_limits(Limits {
        app_limit: 40,
        ..Limits::default()
    });
    let hanging = Arc::new(Hanging {
        inner: Arc::clone(&world.homeserver),
        path: Mutex::new(None),
        hung: Mutex::new(false),
    });
    let env = SignerEnv {
        store: StoreHandle::inline(Arc::new(MemoryStore::new())),
        clock: world.clock.clone(),
        transport: world.transport.clone(),
        homeserver: hanging.clone(),
        protocols: Protocols::new(vec![Arc::new(Notes)]).unwrap(),
    };
    let mut signer = Signer::create(env, world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    let all = apps(5);
    for app in &all {
        world.approve(&mut signer, app).await;
    }
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    *hanging.path.lock().unwrap() = Some(IDENTITY_PATH.to_owned());
    {
        let mut run = std::pin::pin!(signer.run_due());
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..10_000 {
            assert!(run.as_mut().poll(&mut cx).is_pending());
            if *hanging.hung.lock().unwrap() {
                break;
            }
        }
        assert!(*hanging.hung.lock().unwrap(), "the run reached the publication");
    }
    *hanging.path.lock().unwrap() = None;
    signer.resume().await.unwrap();
    let renewed = signer.renew_expiring().await.unwrap();
    assert_eq!(renewed.len(), 4, "the four apps still due renewed");
}

#[tokio::test]
async fn test_run_due_cursor_goes_past_a_failing_step() {
    // `a`'s renewal is refused for good, so the run's renewals fail: the next run starts
    // from the step after them. Its clock jumps, and `b` asks for its full bundle: the
    // publication, with nothing to do, passes the turn on, and the full bundle is answered
    // before the renewals fail again.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let all = apps(2);
    world.approve(&mut signer, &all[0]).await;
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    world.approve(&mut signer, &all[1]).await;
    let (a, b) = (all[0].keys.app_id_bytes(), all[1].keys.app_id_bytes());
    plant_later_renewal(&world, &signer, a, 300 * DAY_MS);
    signer.run_due().await.unwrap_err();
    world.switch.request_full_bundle(b);
    clock_moves_at_the_first_read(&world, HOUR_MS);
    assert!(signer.run_due().await.unwrap().steps_left);
    assert!(world.switch.app(&b).full_requested.is_none());
}

#[tokio::test]
async fn test_run_due_refused_renewal_goes_behind_the_others() {
    // Nine apps due, the soonest to expire refused for good. The first run renews the three
    // after it all the same, and returns the refusal; the next renews the four after those,
    // the refused one behind them.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let all = apps(9);
    for app in &all {
        world.approve(&mut signer, app).await;
        world.clock.advance_ms(DAY_MS);
    }
    let ids: Vec<[u8; 16]> = all.iter().map(|a| a.keys.app_id_bytes()).collect();
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    plant_later_renewal(&world, &signer, ids[0], 300 * DAY_MS);
    let since = world.clock.now_ms();
    signer.run_due().await.unwrap_err();
    assert_eq!(renewed_since(&signer, &ids, since), ids[1..4]);
    let report = signer.run_due().await.unwrap();
    assert_eq!(renewed_since(&signer, &ids, since), ids[1..8]);
    assert!(report.renewals_left);
}
