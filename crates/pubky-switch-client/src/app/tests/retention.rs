//! Apps across the checkpoints the scripted switch signs and the stubs it drops by the
//! service's rule (Switch spec 8.3, 10.1; Switch wire 7.4.4): an app whose cursor passed them
//! goes on as before, one more than 30 days behind continues only with its continuity
//! unverified, and so does one restored from an older backup.

use super::*;
use crate::app::OpBatch;
use crate::testing::Retention;

const DAY: u64 = 24 * 60 * 60 * 1000;

/// The service's rule, with a checkpoint once `behind` chain items may go.
fn retention(behind: u64) -> Option<Retention> {
    Some(Retention {
        checkpoint_behind: behind,
        ..Retention::default()
    })
}

/// An app of the account that may change its lists, so it can write chain items.
async fn writer(w: &World, name: &str) -> App {
    let spec = sample_app(&["scope-a"]).with_permissions(&[Permission::ListsManage]);
    let request = w.signer.approve(&app_keys(name), &spec).unwrap();
    App::join(w.env(), w.protocol.clone(), World::config(), request)
        .await
        .unwrap()
}

/// `n` chain items from `app`, one operation each.
async fn write(app: &mut App, n: u8) {
    for i in 0..n {
        app.submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [i + 1; 32] }))
            .await
            .unwrap();
    }
}

/// Each app reads a note sent to it, and writes once: the batch carries the cursor move the
/// read deferred, past everything before the note.
async fn read_a_note(w: &World, apps: &mut [&mut App]) {
    for app in apps.iter_mut() {
        w.note(app.app_id(), "past");
        app.receive(None).await.unwrap();
        app.submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [0xee; 32] }))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn test_retention_apps_whose_cursors_passed_go_on_across_a_checkpoint() {
    // Both apps read past five items, the switch checkpoints and drops them, and both go on
    // verifying the chain, neither in reconcile mode.
    let w = World::new();
    w.switch.set_retention(retention(3));
    let mut wallet = writer(&w, "wallet").await;
    let mut phone = writer(&w, "phone").await;
    write(&mut wallet, 5).await;
    read_a_note(&w, &mut [&mut wallet, &mut phone]).await;
    write(&mut phone, 1).await;
    let (checkpoint, dropped) = w.switch.retained();
    let checkpoint = checkpoint.expect("a checkpoint signed");
    assert!(dropped > 0 && dropped <= checkpoint.seq);
    write(&mut wallet, 2).await;
    wallet.receive(None).await.unwrap();
    phone.receive(None).await.unwrap();
    assert!(!wallet.reconcile_mode() && !phone.reconcile_mode());
}

#[tokio::test]
async fn test_retention_a_cursor_holds_stubs_back_for_30_days() {
    // The phone stops reading: its cursor holds the stubs after it, so nothing is dropped
    // past it, until they are 30 days old. Then they go, and the phone, more than 30 days
    // behind, continues from the checkpoint with its continuity unverified.
    let w = World::new();
    w.switch.set_retention(retention(3));
    let mut wallet = writer(&w, "wallet").await;
    let mut phone = writer(&w, "phone").await;
    read_a_note(&w, &mut [&mut wallet, &mut phone]).await;
    let phone_at = w.switch.lock().apps[&phone.app_id()].cursor;
    write(&mut wallet, 5).await;
    read_a_note(&w, &mut [&mut wallet]).await;
    write(&mut wallet, 1).await;
    assert!(
        w.switch.retained().1 <= phone_at,
        "held by the phone's cursor"
    );
    w.clock.advance_ms(31 * DAY);
    write(&mut wallet, 1).await;
    assert!(w.switch.retained().1 > phone_at, "dropped once 30 days old");
    phone.receive(None).await.unwrap();
    assert!(phone.reconcile_mode());
    assert!(!wallet.reconcile_mode());
}

#[tokio::test]
async fn test_retention_an_app_restored_from_before_a_checkpoint_continues_unverified() {
    // The wallet's backup is from before five items the switch then checkpoints and drops:
    // restored from it, the wallet continues from the checkpoint with its continuity
    // unverified.
    let w = World::new();
    w.switch.set_retention(retention(3));
    let mut wallet = writer(&w, "wallet").await;
    wallet.receive(None).await.unwrap();
    let backup = wallet.backup().await.unwrap();
    write(&mut wallet, 5).await;
    read_a_note(&w, &mut [&mut wallet]).await;
    write(&mut wallet, 1).await;
    assert!(w.switch.retained().0.is_some());
    drop(wallet);
    let mut restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.receive(None).await.unwrap();
    assert!(restored.reconcile_mode());
}

/// The `seq`s of the batch of three operations in the switch's chain.
fn batch_of_three(w: &World) -> Vec<u64> {
    w.switch
        .lock()
        .items
        .iter()
        .filter_map(|item| match item {
            crate::testing::Item::Chain { seq, stub, .. } => {
                let envelope =
                    pubky_switch_core::chain::ChainEnvelope::parse(&stub.envelope).ok()?;
                envelope.batch.filter(|b| b.count == 3).map(|_| *seq)
            }
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn test_retention_never_cuts_inside_a_batch() {
    // A batch of three operations, and a sweep that looks at two stubs a request: the
    // checkpoint and the drop stop before the batch, then after it, never inside.
    let w = World::new();
    w.switch.set_retention(Some(Retention {
        checkpoint_behind: 1,
        per_request: 2,
        ..Retention::default()
    }));
    let mut wallet = writer(&w, "wallet").await;
    write(&mut wallet, 1).await;
    wallet
        .submit_batch(
            OpBatch::new()
                .op(OpKind::DenyPut { pubky: [7; 32] })
                .op(OpKind::DenyPut { pubky: [8; 32] })
                .op(OpKind::DenyPut { pubky: [9; 32] }),
        )
        .await
        .unwrap();
    read_a_note(&w, &mut [&mut wallet]).await;
    let batch = batch_of_three(&w);
    assert_eq!(batch.len(), 3);
    let inside = |seq: u64| seq >= batch[0] && seq < batch[2];
    for _ in 0..4 {
        wallet.receive(None).await.unwrap();
        let (checkpoint, dropped) = w.switch.retained();
        let at = checkpoint.map_or(0, |c| c.seq);
        assert!(!inside(at), "checkpoint at {at}");
        assert!(!inside(dropped), "dropped through {dropped}");
    }
}

#[tokio::test]
async fn test_retention_drops_nothing_past_the_latest_checkpoint() {
    // A checkpoint is signed once three items may go; two more go after it, too few for the
    // next: nothing is dropped past the first.
    let w = World::new();
    w.switch.set_retention(retention(3));
    let mut wallet = writer(&w, "wallet").await;
    write(&mut wallet, 3).await;
    read_a_note(&w, &mut [&mut wallet]).await;
    wallet.receive(None).await.unwrap();
    let first = w.switch.retained().0.expect("a checkpoint signed");
    w.note(wallet.app_id(), "one more");
    wallet.receive(None).await.unwrap();
    wallet
        .submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [0xdd; 32] }))
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    let (checkpoint, dropped) = w.switch.retained();
    let checkpoint = checkpoint.unwrap();
    assert!(
        dropped <= checkpoint.seq,
        "dropped {dropped} past {}",
        checkpoint.seq
    );
    assert_eq!(checkpoint.seq, first.seq, "no new checkpoint for two items");
}

/// 1,001 chain items from another own app of the account, 31 days old by the next request.
fn a_month_of_items(w: &World) {
    let other = w.other_app("other", &[Permission::ListsManage]);
    for i in 0..1_001u32 {
        let mut pubky = [0; 32];
        pubky[..4].copy_from_slice(&i.to_be_bytes());
        w.switch.app_op(&other, OpKind::DenyPut { pubky }).unwrap();
    }
    w.clock.advance_ms(31 * DAY);
}

#[tokio::test]
async fn test_retention_by_default_follows_the_services_thresholds() {
    // Over 1,000 items, 31 days old: the switch checkpoints by its defaults.
    let w = World::new();
    let mut wallet = writer(&w, "wallet").await;
    a_month_of_items(&w);
    wallet.receive(None).await.unwrap();
    let (checkpoint, dropped) = w.switch.retained();
    assert!(checkpoint.is_some() && dropped > 0);
}

#[tokio::test]
async fn test_retention_turned_off_keeps_every_stub() {
    let w = World::new();
    w.switch.set_retention(None);
    let mut wallet = writer(&w, "wallet").await;
    a_month_of_items(&w);
    wallet.receive(None).await.unwrap();
    assert_eq!(w.switch.retained(), (None, 0));
}

#[tokio::test]
async fn test_retention_an_app_yet_to_move_its_cursor_holds_every_stub() {
    // The phone joins after the wallet's first items and never moves its cursor: what went
    // before it joined stays gone, and nothing more goes inside 30 days, as at the service,
    // which keeps no registration `seq`; once 30 days old, the rest go.
    let w = World::new();
    w.switch.set_retention(retention(2));
    let mut wallet = writer(&w, "wallet").await;
    write(&mut wallet, 3).await;
    read_a_note(&w, &mut [&mut wallet]).await;
    write(&mut wallet, 1).await;
    let before = w.switch.retained().1;
    w.clock.advance_ms(1_000);
    let phone = writer(&w, "phone").await;
    write(&mut wallet, 3).await;
    read_a_note(&w, &mut [&mut wallet]).await;
    write(&mut wallet, 1).await;
    assert_eq!(w.switch.retained().1, before, "held by the phone");
    w.clock.advance_ms(31 * DAY);
    write(&mut wallet, 1).await;
    assert!(w.switch.retained().1 > before, "30 days old");
    drop(phone);
}

#[tokio::test]
async fn test_retention_drops_a_bounded_number_at_one_request() {
    // Five items may go, and a request drops at most two of them: the rest go at the next
    // requests.
    let w = World::new();
    w.switch.set_retention(Some(Retention {
        checkpoint_behind: 1,
        per_request: 2,
        ..Retention::default()
    }));
    let mut wallet = writer(&w, "wallet").await;
    write(&mut wallet, 5).await;
    read_a_note(&w, &mut [&mut wallet]).await;
    let before = w.switch.retained().1;
    wallet.receive(None).await.unwrap();
    let after = w.switch.retained().1;
    let between = w
        .switch
        .lock()
        .items
        .iter()
        .filter(|item| {
            matches!(item, crate::testing::Item::Chain { seq, .. } if *seq > before && *seq <= after)
        })
        .count();
    assert!(between <= 2, "{between} dropped at one request");
}

#[tokio::test]
async fn test_retention_stops_while_the_account_is_frozen() {
    // Frozen for a move, the switch drops nothing and signs no checkpoint, so an export
    // carries every stub kept at the freeze.
    let w = World::new();
    w.switch.set_retention(retention(2));
    let mut wallet = writer(&w, "wallet").await;
    write(&mut wallet, 4).await;
    read_a_note(&w, &mut [&mut wallet]).await;
    let kept = w.switch.retained();
    w.switch.lock().frozen = Some(pubky_switch_core::sig::SignedDoc::from_parts(
        b"{}", &[0; 64],
    ));
    w.clock.advance_ms(31 * DAY);
    let _ = wallet.receive(None).await;
    assert_eq!(w.switch.retained(), kept);
}

#[tokio::test]
async fn test_retention_a_page_without_the_checkpoint_is_a_rollback() {
    // The phone stops reading; 31 days on, the stubs after it are dropped behind a
    // checkpoint. A switch whose pages drop the stubs and leave the checkpoint out, as
    // an instance on code from before the checkpoint member, shows the phone a broken
    // chain: it raises a rollback, where with the checkpoint it reconciles.
    let w = World::new();
    w.switch.set_retention(retention(3));
    let mut wallet = writer(&w, "wallet").await;
    let mut phone = writer(&w, "phone").await;
    read_a_note(&w, &mut [&mut wallet, &mut phone]).await;
    let phone_at = w.switch.lock().apps[&phone.app_id()].cursor;
    write(&mut wallet, 5).await;
    read_a_note(&w, &mut [&mut wallet]).await;
    write(&mut wallet, 1).await;
    w.clock.advance_ms(31 * DAY);
    write(&mut wallet, 1).await;
    assert!(w.switch.retained().1 > phone_at, "dropped once 30 days old");
    w.switch.set_retention(None);
    w.switch.lock().checkpoint = None;
    let read = phone.receive(None).await;
    assert!(read.is_err(), "the read fails");
    assert!(
        matches!(phone.alarm(), Some(crate::app::Alarm::Rollback { .. })),
        "{:?}",
        phone.alarm()
    );
}

/// The `seq`s of the switch's chain items, oldest first.
fn chain_seqs(w: &World) -> Vec<u64> {
    w.switch
        .lock()
        .items
        .iter()
        .filter_map(|item| match item {
            crate::testing::Item::Chain { seq, .. } => Some(*seq),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn test_retention_never_drops_the_head() {
    // The wallet's cursor stands at the head, every stub passed: the checkpoint and the
    // drop stop short of the head, as at the service.
    let w = World::new();
    w.switch.set_retention(retention(1));
    let mut wallet = writer(&w, "wallet").await;
    write(&mut wallet, 3).await;
    wallet.receive(None).await.unwrap();
    wallet.flush_cursor().await.unwrap();
    let head = w.switch.lock().tip.seq;
    assert_eq!(w.switch.lock().apps[&wallet.app_id()].cursor, head);
    wallet.receive(None).await.unwrap();
    let (checkpoint, dropped) = w.switch.retained();
    let at = checkpoint.expect("a checkpoint").seq;
    assert!(
        at < head && dropped < head,
        "the head {head} stays: {at}, {dropped}"
    );
}

#[tokio::test]
async fn test_retention_a_look_that_ends_inside_a_batch_still_signs() {
    // The sweep looks at as many stubs as a checkpoint waits for, and the last it looks at
    // is inside a batch of three: the stubs that may go are counted before the batch edge,
    // so the checkpoint goes at the item before the batch, as at the service. Counted only
    // at batch ends, they would stay short at every request.
    let w = World::new();
    let mut wallet = writer(&w, "wallet").await;
    write(&mut wallet, 1).await;
    wallet
        .submit_batch(
            OpBatch::new()
                .op(OpKind::DenyPut { pubky: [7; 32] })
                .op(OpKind::DenyPut { pubky: [8; 32] })
                .op(OpKind::DenyPut { pubky: [9; 32] }),
        )
        .await
        .unwrap();
    write(&mut wallet, 2).await;
    wallet.receive(None).await.unwrap();
    wallet.flush_cursor().await.unwrap();
    let seqs = chain_seqs(&w);
    let batch = batch_of_three(&w);
    let first = seqs.iter().position(|seq| *seq == batch[0]).unwrap();
    // The look ends at the batch's second item.
    let look = first + 2;
    w.switch.set_retention(Some(Retention {
        checkpoint_behind: u64::try_from(look).unwrap(),
        per_request: look,
        ..Retention::default()
    }));
    wallet.receive(None).await.unwrap();
    let (checkpoint, dropped) = w.switch.retained();
    assert_eq!(checkpoint.map(|c| c.seq), Some(seqs[first - 1]));
    assert_eq!(dropped, seqs[first - 1]);
}

/// Two devices of the wallet sharing its cursor: `a` joined, `b` its second device from
/// `a`'s backup, with `b`'s own cursor move read since, so it holds evidence as any app
/// does. `b` then stops, and `a` reads and writes on until the stubs after `b`'s position
/// are dropped behind a checkpoint, under 30 days old, which `a`'s cursor passed. `b` is
/// a device of an app whose devices share the cursor when `multi_device`.
async fn device_left_behind(multi_device: bool) -> (World, App, App) {
    let w = World::new();
    w.switch.set_retention(retention(3));
    let mut a = writer(&w, "wallet").await;
    a.set_multi_device(true).await.unwrap();
    read_a_note(&w, &mut [&mut a]).await;
    let backup = a.backup().await.unwrap();
    let mut b = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    b.end_reconcile(crate::app::UserConfirmed::new())
        .await
        .unwrap();
    b.set_multi_device(multi_device).await.unwrap();
    read_a_note(&w, &mut [&mut b]).await;
    b.receive(None).await.unwrap();
    let b_at = w.switch.lock().apps[&b.app_id()].cursor;
    write(&mut a, 5).await;
    read_a_note(&w, &mut [&mut a]).await;
    write(&mut a, 1).await;
    let (checkpoint, dropped) = w.switch.retained();
    assert!(
        checkpoint.is_some() && dropped > b_at,
        "dropped past b's position"
    );
    (w, a, b)
}

#[tokio::test]
async fn test_retention_a_device_behind_its_apps_shared_cursor_reconciles() {
    // The other device moved the shared cursor past the stubs, so their absence is no
    // evidence: the device behind continues from the checkpoint in reconcile mode, raises
    // no rollback, and catches up once reconciled (Switch wire 7.4.4).
    let (w, mut a, mut b) = device_left_behind(true).await;
    b.receive(None).await.unwrap();
    assert_eq!(b.alarm(), None);
    assert!(b.reconcile_mode());
    b.end_reconcile(crate::app::UserConfirmed::new())
        .await
        .unwrap();
    write(&mut a, 2).await;
    b.receive(None).await.unwrap();
    assert_eq!(b.alarm(), None);
    assert_eq!(
        b.cursor().seq,
        w.switch.lock().tip.seq,
        "caught up to the head"
    );
    assert!(!a.reconcile_mode());
    a.receive(None).await.unwrap();
    assert_eq!(a.alarm(), None);
}

#[tokio::test]
async fn test_retention_a_single_device_app_behind_dropped_stubs_still_raises_a_rollback() {
    // The same position for an app on one device: its cursor is its own, so the service
    // rule keeps the stubs from its position while they are under 30 days old, and their
    // absence is a rollback (Switch wire 7.4.4).
    let (_w, _a, mut b) = device_left_behind(false).await;
    assert!(b.receive(None).await.is_err());
    assert!(
        matches!(b.alarm(), Some(crate::app::Alarm::Rollback { .. })),
        "{:?}",
        b.alarm()
    );
}
