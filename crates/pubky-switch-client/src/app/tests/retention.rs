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
async fn test_retention_an_app_yet_to_move_its_cursor_holds_from_its_registration() {
    // The phone joins after the wallet's first items and never moves its cursor: what came
    // before its registration may go, nothing after it, inside 30 days.
    let w = World::new();
    w.switch.set_retention(retention(2));
    let mut wallet = writer(&w, "wallet").await;
    write(&mut wallet, 3).await;
    read_a_note(&w, &mut [&mut wallet]).await;
    w.clock.advance_ms(1_000);
    let phone = writer(&w, "phone").await;
    let joined = w.switch.lock().seq;
    write(&mut wallet, 3).await;
    read_a_note(&w, &mut [&mut wallet]).await;
    write(&mut wallet, 1).await;
    let (checkpoint, dropped) = w.switch.retained();
    assert!(checkpoint.is_some(), "what came before it went");
    assert!(
        dropped < joined,
        "dropped through {dropped}, joined at {joined}"
    );
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
