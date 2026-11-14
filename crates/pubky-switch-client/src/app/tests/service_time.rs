//! The service time a first send is stamped with ([`App::stamp_service_time`]): none is
//! read while the app holds a recent one of the current service key, and where one is read
//! it is a feed page with no items (Switch wire 7.4.4).

use pubky_switch_core::ops::{AllowKind, OpKind};
use pubky_switch_core::scopes::Permission;

use super::moves::{Router, approve_with, join};
use super::*;
use crate::app::OpBatch;
use crate::app::provider::{FRESH_SERVICE_TIME_MS, RECENT_SERVICE_TIME_MS};
use crate::testing::Fault;

fn conversation(pubky: [u8; 32]) -> OpBatch {
    OpBatch::new().op(OpKind::AllowPut {
        pubky,
        kind: AllowKind::Conversation,
    })
}

/// The feed reads among the requests sent since `from`.
fn feed_reads(router: &Router, from: usize) -> Vec<String> {
    router.log()[from..]
        .iter()
        .filter(|line| line.contains("/feed"))
        .cloned()
        .collect()
}

/// A write whose answer is lost, so its batch stays kept: the time it was stamped at.
async fn stamp_of_a_kept_write(w: &World, app: &mut App) -> u64 {
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(
        app.submit_batch(conversation(w.bob.public()))
            .await
            .is_err()
    );
    let kept = app.kept_batches().await.unwrap();
    assert_eq!(kept.len(), 1);
    kept[0].1.kept_ms.unwrap()
}

#[tokio::test]
async fn test_service_time_recent_and_of_the_current_key_is_not_read_for_a_first_send() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    app.receive(None).await.unwrap();
    let held = app.highest_service_time().unwrap();
    // Up to a day on, a later call's first send reads no time: its batch goes alone.
    w.clock.advance_ms(RECENT_SERVICE_TIME_MS);
    let from = router.log().len();
    let stamp = stamp_of_a_kept_write(&w, &mut app).await;
    assert_eq!(feed_reads(&router, from), Vec::<String>::new());
    assert_eq!(router.log().len(), from + 1, "{:?}", router.log());
    // Stamped at the earlier of the device clock and the time held: never after the time
    // the service applied it.
    assert_eq!(stamp, held);
}

#[tokio::test]
async fn test_service_time_older_than_a_day_is_read_before_a_first_send() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    app.receive(None).await.unwrap();
    w.clock.advance_ms(RECENT_SERVICE_TIME_MS + 1);
    let from = router.log().len();
    let stamp = stamp_of_a_kept_write(&w, &mut app).await;
    // One read of a page with no items, before the batch.
    let reads = feed_reads(&router, from);
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert!(reads[0].ends_with("limit=0"), "{reads:?}");
    let log = router.log();
    assert!(log[from].contains("/feed"), "{log:?}");
    assert!(log[from + 1].contains("/ops"), "{log:?}");
    assert_eq!(stamp, w.clock.now_ms());
}

#[tokio::test]
async fn test_service_time_of_another_key_or_none_is_read_before_a_first_send() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    app.receive(None).await.unwrap();
    let key = app.state.meta.service_key;
    for held in [
        None,
        app.state
            .service_time
            .map(|time| crate::app::state::ServiceTime {
                key: [9; 32],
                ..time
            }),
    ] {
        // A later call, so no answer of this one brought a time.
        w.clock.advance_ms(FRESH_SERVICE_TIME_MS + 1);
        app.state.service_time = held;
        let from = router.log().len();
        app.submit_batch(conversation([7; 32])).await.unwrap();
        let reads = feed_reads(&router, from);
        assert_eq!(reads.len(), 1, "{held:?}: {reads:?}");
        assert!(reads[0].ends_with("limit=0"), "{reads:?}");
        assert_eq!(app.state.service_time.map(|time| time.key), Some(key));
    }
}

#[tokio::test]
async fn test_service_time_ahead_of_the_device_clock_is_not_read_and_the_device_time_stamps() {
    let w = World::new();
    let router = Router::of(&w);
    // The app's own clock, a minute behind the service's from here on.
    let clock = Arc::new(TestClock::new(w.clock.now_ms()));
    let mut env = router.env(&w, Arc::clone(&w.store) as Arc<dyn StateStore>);
    env.clock = Arc::clone(&clock) as Arc<dyn Clock>;
    let mut app = App::join(
        env,
        w.protocol.clone(),
        World::config(),
        approve_with(&w, &[Permission::ConversationAdd]),
    )
    .await
    .unwrap();
    w.clock.advance_ms(60_000);
    app.receive(None).await.unwrap();
    let held = app.highest_service_time().unwrap();
    clock.advance_ms(FRESH_SERVICE_TIME_MS + 1);
    w.clock.advance_ms(FRESH_SERVICE_TIME_MS + 1);
    assert!(clock.now_ms() < w.clock.now_ms());
    let from = router.log().len();
    let stamp = stamp_of_a_kept_write(&w, &mut app).await;
    assert_eq!(feed_reads(&router, from), Vec::<String>::new());
    // The earlier of the two: the device clock's when the held time is ahead of it, the
    // held time otherwise.
    assert_eq!(stamp, clock.now_ms().min(held));
}

#[tokio::test]
async fn test_service_time_read_for_a_kept_batch_is_a_page_with_no_items() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    app.receive(None).await.unwrap();
    stamp_of_a_kept_write(&w, &mut app).await;
    // A later call sends the kept batch again: its age is judged at a time read in that
    // call, whatever time the app holds.
    w.clock.advance_ms(FRESH_SERVICE_TIME_MS + 1);
    let from = router.log().len();
    app.submit_batch(conversation([7; 32])).await.unwrap();
    let reads = feed_reads(&router, from);
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert!(reads[0].ends_with("limit=0"), "{reads:?}");
    assert!(router.log()[from].contains("/feed"), "{:?}", router.log());
    assert!(app.kept_batches().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_service_time_brought_before_a_change_of_service_isnt_fresh_after_it() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    app.receive(None).await.unwrap();
    // A time an answer of this call brought counts for the call.
    let from = router.log().len();
    app.fresh_service_time().await.unwrap();
    assert_eq!(feed_reads(&router, from), Vec::<String>::new());
    // Once the client is built again, as for another service, it is read again.
    app.rebuild_client().unwrap();
    let from = router.log().len();
    app.fresh_service_time().await.unwrap();
    let reads = feed_reads(&router, from);
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert!(reads[0].ends_with("limit=0"), "{reads:?}");
}
