//! How much one routine run does (design note, section 4.5): each of its steps a bounded
//! amount, and none of its later steps started past the run's time, the rest left for the
//! next run.

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::*;
use pubky_switch_client::clock::Clock;
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::SWITCH_ORIGIN;
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::{IDENTITY_PATH, Limits, app_record_path};
use pubky_switch_signer::Signer;

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
    signer.run_due().await.unwrap();
    assert_eq!(renewed_since(&signer, &ids, since), ids[..4]);
    signer.run_due().await.unwrap();
    assert_eq!(renewed_since(&signer, &ids, since), ids);
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
    signer.run_due().await.unwrap();
    let pending = |id: &[u8; 16]| world.switch.app(id).full_requested.is_some();
    assert!(pending(&ids[0]), "the newest request waits");
    assert!(ids[1..].iter().all(|id| !pending(id)));
    signer.run_due().await.unwrap();
    assert!(!pending(&ids[0]));
}

#[tokio::test]
async fn test_run_due_deletes_32_records_a_run() {
    // Thirty-three apps leave at once: their removal owes 33 record deletions, of which a
    // run makes 32, and the next the last.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let apps = apps(33);
    for app in &apps {
        world.approve(&mut signer, app).await;
    }
    for app in &apps {
        let id = app.keys.app_id_bytes();
        world.homeserver.set(&app_record_path(&id), b"{}".to_vec());
        world.switch.leave(id).unwrap();
    }
    let held = || {
        apps.iter()
            .filter(|a| {
                world
                    .homeserver
                    .file(&app_record_path(&a.keys.app_id_bytes()))
                    .is_some()
            })
            .count()
    };
    signer.run_due().await.unwrap();
    assert_eq!(held(), 1);
    signer.run_due().await.unwrap();
    assert_eq!(held(), 0);
}

#[tokio::test]
async fn test_run_due_starts_no_later_step_past_its_time() {
    // The run's first steps take more than its time: the removal still runs, the renewal due
    // waits for the next run.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let apps = apps(2);
    for app in &apps {
        world.approve(&mut signer, app).await;
    }
    let (stays, goes) = (apps[0].keys.app_id_bytes(), apps[1].keys.app_id_bytes());
    world.clock.advance_ms(LIFETIME_MS / 2 + DAY_MS);
    world.switch.leave(goes).unwrap();
    // The run's first read of the Homeserver's copy takes 31 seconds.
    let clock = Arc::clone(&world.clock);
    *world.homeserver.after_get.lock().unwrap() = Some((
        IDENTITY_PATH.to_owned(),
        1,
        Box::new(move || clock.advance_ms(31_000)),
    ));
    let since = world.clock.now_ms();
    signer.run_due().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&goes).is_none(), "removed in this run");
    assert!(renewed_since(&signer, &[stays], since).is_empty());
    signer.run_due().await.unwrap();
    assert_eq!(renewed_since(&signer, &[stays], since), [stays]);
}

#[tokio::test]
async fn test_run_due_past_its_time_answers_no_full_bundle_request() {
    // Nothing to remove, and the run's first read of the Homeserver's copy takes 31 seconds:
    // the full-bundle request waits for the next run.
    let world = World::new();
    let mut signer = enrolled_for_many(&world).await;
    let app = &apps(1)[0];
    world.approve(&mut signer, app).await;
    let id = app.keys.app_id_bytes();
    world.switch.request_full_bundle(id);
    let clock = Arc::clone(&world.clock);
    *world.homeserver.after_get.lock().unwrap() = Some((
        IDENTITY_PATH.to_owned(),
        1,
        Box::new(move || clock.advance_ms(31_000)),
    ));
    signer.run_due().await.unwrap();
    assert!(world.switch.app(&id).full_requested.is_some());
    signer.run_due().await.unwrap();
    assert!(world.switch.app(&id).full_requested.is_none());
}
