//! How much one routine run does (design note, section 4.5): each of its steps a bounded
//! amount, and past the run's time no later step started once one has had work, the rest
//! left for the next run.

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::*;
use pubky_switch_client::clock::Clock;
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::{Fault as SwitchFault, SWITCH_ORIGIN};
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::{IDENTITY_PATH, Limits, app_record_path};
use pubky_switch_signer::{Signer, UserConfirmed};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const LIFETIME_MS: u64 = 365 * DAY_MS;

/// The `n` apps of these tests, each with keys of its own.
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

/// A signer enrolled at a switch that lets it list up to 40 apps.
async fn enrolled_for_many(world: &World) -> Signer {
    world.switch.set_enroll_limits(Limits {
        app_limit: 40,
        ..Limits::default()
    });
    let store = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(world.env(store), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    signer
}

/// The App IDs whose listed certificate in the newest version was issued at or after `since`.
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

#[tokio::test]
async fn test_run_due_renews_four_a_run_the_soonest_to_expire_first() {
    // Five apps approved a day apart, all past half their lifetime: a run renews the four
    // that expire soonest, and the next run the fifth.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let apps = apps(5);
    for app in &apps {
        world.approve(&mut signer, app).await;
        world.clock.advance_ms(DAY_MS);
    }
    let ids: Vec<[u8; 16]> = apps.iter().map(|a| a.keys.app_id_bytes()).collect();
    world.clock.advance_ms(LIFETIME_MS / 2);
    let since = world.clock.now_ms();
    let report = signer.run_due().await.unwrap();
    assert_eq!(renewed_since(&signer, &ids, since), ids[..4]);
    assert!(report.renewals_left && report.more_due());
    assert!(!report.full_bundles_left && !report.deletions_left && !report.steps_left);
    let report = signer.run_due().await.unwrap();
    assert_eq!(renewed_since(&signer, &ids, since), ids);
    assert!(!report.more_due());
}

#[tokio::test]
async fn test_run_due_answers_four_full_bundle_requests_a_run_the_oldest_first() {
    // Five apps ask for their full bundle, the last first: a run answers the four oldest
    // requests, and the next run the fifth.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let apps = apps(5);
    for app in &apps {
        world.approve(&mut signer, app).await;
    }
    let ids: Vec<[u8; 16]> = apps.iter().map(|a| a.keys.app_id_bytes()).collect();
    for id in ids.iter().rev() {
        world.switch.request_full_bundle(*id);
        world.clock.advance_ms(1_000);
    }
    let report = signer.run_due().await.unwrap();
    let pending = |id: &[u8; 16]| world.switch.app(id).full_requested.is_some();
    assert!(pending(&ids[0]), "the newest request waits");
    assert!(ids[1..].iter().all(|id| !pending(id)));
    assert!(report.full_bundles_left && report.more_due());
    assert!(!report.renewals_left && !report.deletions_left && !report.steps_left);
    let report = signer.run_due().await.unwrap();
    assert!(!pending(&ids[0]));
    assert!(!report.more_due());
}

/// `n` apps whose records are on the Homeserver leave at once: their removal owes `n` record
/// deletions. Returns how many of those records are still held.
async fn leaving_with_records(
    world: &World,
    signer: &mut Signer,
    n: u8,
) -> impl Fn() -> usize + use<> {
    let apps = apps(n);
    for app in &apps {
        world.approve(signer, app).await;
    }
    let paths: Vec<String> = apps
        .iter()
        .map(|app| {
            let id = app.keys.app_id_bytes();
            world.homeserver.set(&app_record_path(&id), b"{}".to_vec());
            world.switch.leave(id).unwrap();
            app_record_path(&id)
        })
        .collect();
    let homeserver = Arc::clone(&world.homeserver);
    move || {
        paths
            .iter()
            .filter(|p| homeserver.file(p).is_some())
            .count()
    }
}

#[tokio::test]
async fn test_run_due_deletes_32_records_a_run() {
    // Thirty-three apps leave at once: of the 33 record deletions owed, a run makes 32, and
    // the next the last.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let held = leaving_with_records(&world, &mut signer, 33).await;
    let report = signer.run_due().await.unwrap();
    assert_eq!(held(), 1);
    assert!(report.deletions_left && report.more_due());
    let report = signer.run_due().await.unwrap();
    assert_eq!(held(), 0);
    assert!(!report.more_due());
}

#[tokio::test]
async fn test_run_due_deleting_exactly_32_records_says_nothing_more_is_due() {
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let held = leaving_with_records(&world, &mut signer, 32).await;
    let report = signer.run_due().await.unwrap();
    assert_eq!(held(), 0);
    assert!(!report.deletions_left && !report.more_due());
}

#[tokio::test]
async fn test_run_due_past_its_time_takes_one_step_with_work() {
    // An earlier removal owes a record deletion that keeps failing, and its check of the
    // Homeserver's copy, before the run's removals, takes 31 seconds. The removal due still
    // runs, and so does the first later step with work, the renewal due. The step after it
    // waits for the next run.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let apps = apps(3);
    for app in &apps {
        world.approve(&mut signer, app).await;
    }
    let [stays, gone, goes] = [0, 1, 2].map(|i| apps[i].keys.app_id_bytes());
    let record = app_record_path(&gone);
    world.homeserver.set(&record, b"{}".to_vec());
    world
        .homeserver
        .failing_deletes
        .lock()
        .unwrap()
        .insert(record.clone());
    world.switch.leave(gone).unwrap();
    signer.run_due().await.unwrap();
    assert!(
        world.homeserver.file(&record).is_some(),
        "its deletion failed"
    );
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    world.switch.leave(goes).unwrap();
    clock_moves_at_the_first_read(&world, 31_000);
    let since = world.clock.now_ms();
    let report = signer.run_due().await.unwrap();
    assert!(world.clock.now_ms() >= since + 31_000);
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&goes).is_none(), "removed in this run");
    assert_eq!(renewed_since(&signer, &[stays], since), [stays]);
    assert!(report.steps_left && report.more_due());
}

#[tokio::test]
async fn test_run_due_past_its_time_passes_the_turn_to_a_step_with_work() {
    // Nothing to remove or close, and the run's first read of the Homeserver's copy takes 31
    // seconds: the closings have nothing to do, so the full-bundle request is still answered
    // in this run.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let app = &apps(1)[0];
    world.approve(&mut signer, app).await;
    let id = app.keys.app_id_bytes();
    world.switch.request_full_bundle(id);
    clock_moves_at_the_first_read(&world, 31_000);
    let report = signer.run_due().await.unwrap();
    assert!(world.switch.app(&id).full_requested.is_none());
    assert!(report.steps_left);
    let report = signer.run_due().await.unwrap();
    assert!(!report.more_due());
}

#[tokio::test]
async fn test_run_due_at_its_bounds_says_nothing_more_is_due() {
    // Exactly four renewals and four full-bundle requests due: the run does them all, and
    // says nothing more is due.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let apps = apps(4);
    for app in &apps {
        world.approve(&mut signer, app).await;
    }
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    for app in &apps {
        world.switch.request_full_bundle(app.keys.app_id_bytes());
    }
    let ids: Vec<[u8; 16]> = apps.iter().map(|a| a.keys.app_id_bytes()).collect();
    let since = world.clock.now_ms();
    let report = signer.run_due().await.unwrap();
    assert_eq!(renewed_since(&signer, &ids, since), ids);
    assert!(
        ids.iter()
            .all(|id| world.switch.app(id).full_requested.is_none())
    );
    assert_eq!(report, pubky_switch_signer::RunDue::default());
}

/// Make the run's first read of the Homeserver's copy move the device clock by `ms`, ahead
/// or, negative, back.
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

#[tokio::test]
async fn test_run_due_with_a_clock_that_jumps_every_run_takes_its_steps_in_turn() {
    // The device clock jumps an hour ahead in every run: each run takes one later step with
    // work, and the next run goes on from the step after it, so the full-bundle request is
    // answered at the first run and the renewal made at the second.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let app = &apps(1)[0];
    world.approve(&mut signer, app).await;
    let id = app.keys.app_id_bytes();
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    world.switch.request_full_bundle(id);
    let since = world.clock.now_ms();
    let hour = 60 * 60 * 1000;
    clock_moves_at_the_first_read(&world, hour);
    assert!(signer.run_due().await.unwrap().steps_left);
    assert!(world.switch.app(&id).full_requested.is_none());
    assert!(renewed_since(&signer, &[id], since).is_empty());
    clock_moves_at_the_first_read(&world, hour);
    assert!(signer.run_due().await.unwrap().steps_left);
    assert_eq!(renewed_since(&signer, &[id], since), [id]);
}

#[tokio::test]
async fn test_run_due_with_a_clock_that_goes_back_counts_its_time_passed() {
    // The device clock goes back an hour during the run: that can't be read as time spent,
    // so the run takes one later step with work only, the full-bundle request, and the next
    // run makes the renewal.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let app = &apps(1)[0];
    world.approve(&mut signer, app).await;
    let id = app.keys.app_id_bytes();
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    world.switch.request_full_bundle(id);
    let hour = 60 * 60 * 1000;
    let since = world.clock.now_ms() - hour;
    clock_moves_at_the_first_read(&world, -i64::try_from(hour).unwrap());
    let report = signer.run_due().await.unwrap();
    assert!(report.steps_left);
    assert!(world.switch.app(&id).full_requested.is_none());
    assert!(renewed_since(&signer, &[id], since).is_empty());
    let report = signer.run_due().await.unwrap();
    assert_eq!(renewed_since(&signer, &[id], since), [id]);
    assert!(!report.more_due());
}

/// A new install restored after `n` apps left, and `stays` others didn't: the records of the
/// `n` are owed checks. The restore's own run reads no record, its first check failing, so the
/// checks, in App ID order, wait for the next run. Returns the restored signer and the apps
/// that stay, then the apps that left.
async fn restored_owing_checks(world: &World, n: u8, stays: u8) -> (Signer, Vec<App>) {
    let mut signer = enrolled_for_many(world).await;
    let all = apps(stays + n);
    for app in &all {
        world.approve(&mut signer, app).await;
    }
    let apps = &all[usize::from(stays)..];
    for app in apps {
        world.switch.leave(app.keys.app_id_bytes()).unwrap();
    }
    signer.run_due().await.unwrap();
    signer.run_due().await.unwrap();
    drop(signer);
    let smallest = apps.iter().map(|a| a.keys.app_id_bytes()).min().unwrap();
    *world.homeserver.failing_read_path.lock().unwrap() = Some(app_record_path(&smallest));
    let env = world.env(Arc::new(MemoryStore::new()));
    let restored = Signer::restore_new(env, world.keyring(), UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    *world.homeserver.failing_read_path.lock().unwrap() = None;
    (restored, all)
}

#[tokio::test]
async fn test_run_due_checks_32_owed_deletions_a_run() {
    // Of 33 owed checks, a run makes 32, and says more is due.
    let world = World::new();
    let (mut restored, _) = restored_owing_checks(&world, 33, 0).await;
    let report = restored.run_due().await.unwrap();
    assert!(report.deletions_left && report.more_due());
    let report = restored.run_due().await.unwrap();
    assert!(!report.more_due());
}

#[tokio::test]
async fn test_run_due_checking_exactly_32_owed_deletions_says_nothing_more_is_due() {
    let world = World::new();
    let (mut restored, _) = restored_owing_checks(&world, 32, 0).await;
    let report = restored.run_due().await.unwrap();
    assert!(!report.deletions_left && !report.more_due());
}

#[tokio::test]
async fn test_run_due_owed_checks_share_the_runs_budget() {
    // Thirty-three owed checks and a renewal due in the same run: however many times the run
    // checks, it reads no more than 32 of the records.
    let world = World::new();
    let (mut restored, all) = restored_owing_checks(&world, 33, 1).await;
    let stays = all[0].keys.app_id_bytes();
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    let since = world.clock.now_ms();
    world.homeserver.gets.lock().unwrap().clear();
    let report = restored.run_due().await.unwrap();
    assert_eq!(renewed_since(&restored, &[stays], since), [stays]);
    let checked = checked(&world, &all[1..]);
    assert!(checked <= 32, "{checked} records read");
    assert!(report.deletions_left);
}

/// An app approved and never joined: it delivered no record.
async fn approved_unjoined(signer: &mut Signer, app: &App) {
    let review = signer.review(&app.request, &app.auth).unwrap();
    let approved = signer.approve(review).await.unwrap();
    signer.claim_delivered(&approved.request).await.unwrap();
}

#[tokio::test]
async fn test_run_due_renews_a_joined_app_behind_four_unjoined_ones() {
    // Four apps that never joined expire first; none can be renewed, so none takes a place,
    // and the fifth, which joined, is renewed in the first run.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let apps = apps(5);
    for app in &apps[..4] {
        approved_unjoined(&mut signer, app).await;
        world.clock.advance_ms(DAY_MS);
    }
    world.approve(&mut signer, &apps[4]).await;
    let joined = apps[4].keys.app_id_bytes();
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    let since = world.clock.now_ms();
    let report = signer.run_due().await.unwrap();
    assert_eq!(renewed_since(&signer, &[joined], since), [joined]);
    assert!(!report.renewals_left);
}

#[tokio::test]
async fn test_run_due_answers_a_full_bundle_behind_four_that_cant_be() {
    // Four apps that never joined asked first: none can be answered, so none takes a place,
    // and the fifth's request is answered in the first run.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let apps = apps(5);
    for app in &apps[..4] {
        approved_unjoined(&mut signer, app).await;
        world.switch.request_full_bundle(app.keys.app_id_bytes());
        world.clock.advance_ms(1_000);
    }
    world.approve(&mut signer, &apps[4]).await;
    let joined = apps[4].keys.app_id_bytes();
    world.switch.request_full_bundle(joined);
    let report = signer.run_due().await.unwrap();
    assert!(world.switch.app(&joined).full_requested.is_none());
    assert!(!report.full_bundles_left);
}

#[tokio::test]
async fn test_run_due_failing_deletions_hold_back_no_other_record() {
    // Thirty-three apps leave; every deletion fails in the first run, which tries 32 and
    // reminds of every grant. The next run tries the one left first, and it goes.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let apps = apps(33);
    for app in &apps {
        world.approve(&mut signer, app).await;
    }
    let paths: Vec<String> = apps
        .iter()
        .map(|a| app_record_path(&a.keys.app_id_bytes()))
        .collect();
    for (app, path) in apps.iter().zip(&paths) {
        world.homeserver.set(path, b"{}".to_vec());
        world.switch.leave(app.keys.app_id_bytes()).unwrap();
    }
    *world.homeserver.failing_deletes.lock().unwrap() = paths.iter().cloned().collect();
    world.homeserver.deletes.lock().unwrap().clear();
    let report = signer.run_due().await.unwrap();
    let tried: Vec<String> = world.homeserver.deletes.lock().unwrap().clone();
    assert_eq!(tried.len(), 32);
    assert!(report.deletions_left);
    for app in &apps {
        let app_id = app.keys.app_id_bytes();
        assert!(
            signer
                .alerts()
                .contains(&pubky_switch_signer::Alert::GrantRevocationOwed { app_id }),
            "every grant reminded"
        );
    }
    let untried = paths.iter().find(|p| !tried.contains(p)).unwrap().clone();
    world
        .homeserver
        .failing_deletes
        .lock()
        .unwrap()
        .remove(&untried);
    world.homeserver.deletes.lock().unwrap().clear();
    signer.run_due().await.unwrap();
    assert_eq!(world.homeserver.deletes.lock().unwrap()[0], untried);
    assert!(world.homeserver.file(&untried).is_none());
}

#[tokio::test]
async fn test_run_due_deletes_32_records_however_its_steps_nest() {
    // Thirty-three apps leave while another app's renewal is due: the renewal's own run of
    // the owed steps doesn't start a budget of its own, so the run deletes 32 records.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let apps = apps(34);
    for app in &apps {
        world.approve(&mut signer, app).await;
    }
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    for app in &apps[..33] {
        let id = app.keys.app_id_bytes();
        world.homeserver.set(&app_record_path(&id), b"{}".to_vec());
        world.switch.leave(id).unwrap();
    }
    world.homeserver.deletes.lock().unwrap().clear();
    let report = signer.run_due().await.unwrap();
    let deleted = world
        .homeserver
        .deletes
        .lock()
        .unwrap()
        .iter()
        .filter(|p| p.contains("/apps/"))
        .count();
    assert_eq!(deleted, 32);
    assert!(report.deletions_left);
}

#[tokio::test]
async fn test_run_due_a_check_that_keeps_failing_holds_back_no_other() {
    // A new install restored after 33 apps left finds their records still on the Homeserver;
    // the read of one keeps failing. It goes behind the others, so the first run checks and
    // deletes the other 32.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let apps = apps(33);
    for app in &apps {
        world.approve(&mut signer, app).await;
    }
    for app in &apps {
        world.switch.leave(app.keys.app_id_bytes()).unwrap();
    }
    signer.run_due().await.unwrap();
    signer.run_due().await.unwrap();
    drop(signer);
    let paths: Vec<String> = apps
        .iter()
        .map(|a| app_record_path(&a.keys.app_id_bytes()))
        .collect();
    for path in &paths {
        world.homeserver.set(path, b"{}".to_vec());
    }
    let smallest = apps.iter().map(|a| a.keys.app_id_bytes()).min().unwrap();
    let failing = app_record_path(&smallest);
    *world.homeserver.failing_read_path.lock().unwrap() = Some(failing.clone());
    let env = world.env(Arc::new(MemoryStore::new()));
    let mut restored = Signer::restore_new(
        env,
        world.keyring(),
        pubky_switch_signer::UserConfirmed::shown_and_confirmed(),
    )
    .await
    .unwrap();
    restored.run_due().await.unwrap();
    let held: Vec<&String> = paths
        .iter()
        .filter(|p| world.homeserver.file(p).is_some())
        .collect();
    assert_eq!(held, [&failing]);
}

#[tokio::test]
async fn test_renew_expiring_renews_a_joined_app_behind_four_being_cut_off() {
    // Four apps whose revocation hasn't reached the switch expire first: none can be renewed,
    // so none takes a place, and the fifth is renewed at the first call.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let apps = apps(5);
    for app in &apps {
        world.approve(&mut signer, app).await;
        world.clock.advance_ms(DAY_MS);
    }
    // Every revocation sent fails to reach the switch, the ones still pending included.
    let unreachable = || {
        world.switch.fail_next(SwitchFault::Unreachable {
            path: "/revoke".into(),
            after: 0,
        });
    };
    for (n, app) in apps[..4].iter().enumerate() {
        (0..=n).for_each(|_| unreachable());
        signer
            .revoke(
                app.keys.app_id_bytes(),
                None,
                UserConfirmed::shown_and_confirmed(),
            )
            .await
            .unwrap_err();
    }
    let joined = apps[4].keys.app_id_bytes();
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    (0..4).for_each(|_| unreachable());
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(
        apps.iter()
            .all(|a| doc.listed_cert(&a.keys.app_id_bytes()).is_some())
    );
    assert_eq!(signer.renew_expiring().await.unwrap(), [joined]);
}

#[tokio::test]
async fn test_renew_expiring_after_a_run_has_a_budget_of_its_own() {
    // Nine apps due: the run renews four, and a call of its own after it renews four more.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let apps = apps(9);
    for app in &apps {
        world.approve(&mut signer, app).await;
        world.clock.advance_ms(DAY_MS);
    }
    let ids: Vec<[u8; 16]> = apps.iter().map(|a| a.keys.app_id_bytes()).collect();
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    let since = world.clock.now_ms();
    assert!(signer.run_due().await.unwrap().renewals_left);
    assert_eq!(renewed_since(&signer, &ids, since), ids[..4]);
    assert_eq!(signer.renew_expiring().await.unwrap(), ids[4..8]);
}

/// The records of the apps in `left` read since the Homeserver's read log was last cleared.
fn checked(world: &World, left: &[App]) -> usize {
    let left: Vec<String> = left
        .iter()
        .map(|app| app_record_path(&app.keys.app_id_bytes()))
        .collect();
    let reads = world.homeserver.gets.lock().unwrap();
    reads.iter().filter(|path| left.contains(path)).count()
}

#[tokio::test]
async fn test_renew_expiring_outside_a_run_has_one_budget() {
    // Thirty-three owed checks and two renewals due, made by a call of its own: each renewal
    // runs the owed steps again, and the call reads no more than 32 of the records.
    let world = World::new();
    let (mut restored, all) = restored_owing_checks(&world, 33, 2).await;
    let stay: Vec<[u8; 16]> = all[..2].iter().map(|a| a.keys.app_id_bytes()).collect();
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    world.homeserver.gets.lock().unwrap().clear();
    let mut renewed = restored.renew_expiring().await.unwrap();
    renewed.sort_unstable();
    let mut expected = stay.clone();
    expected.sort_unstable();
    assert_eq!(renewed, expected);
    let checked = checked(&world, &all[2..]);
    assert!(checked <= 32, "{checked} records read");
}

#[tokio::test]
async fn test_serve_full_bundles_outside_a_run_has_one_budget() {
    // The same with two full-bundle requests, answered by a call of their own.
    let world = World::new();
    let (mut restored, all) = restored_owing_checks(&world, 33, 2).await;
    for app in &all[..2] {
        world.switch.request_full_bundle(app.keys.app_id_bytes());
    }
    world.homeserver.gets.lock().unwrap().clear();
    assert_eq!(restored.serve_full_bundles().await.unwrap().len(), 2);
    let checked = checked(&world, &all[2..]);
    assert!(checked <= 32, "{checked} records read");
}
