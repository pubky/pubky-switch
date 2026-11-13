//! Chain stub retention on the service (Switch wire 7.4.4 "Checkpoints", 9.1), against
//! PostgreSQL: which stubs a request's sweep drops, the checkpoint it signs, its bounds, and
//! the feed pages that carry the checkpoint.
//!
//! Each test starts from alice's account as `chain.json` builds it: `identity.json` version 3,
//! which lists the wallet, the phone and the executor, and the wallet registered. Cursors are
//! set in the database, as the apps' batches would set them. Set
//! `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::{
    http::Handler,
    keys::{KeyId, KeyStore, Mark},
    limits::Limits,
};
use pubky_switch_core::{
    chain::SignedHead,
    enc::pubky_key,
    ops::{AllowKind, Condition, OpKind, OpsRequest, SignedOp, sign_batch},
    sig::SignedDoc,
};
use serde_json::Value;
use sqlx::Connection;
use support::*;

const AT: &str = "2026-01-01T00:01:00.000Z";
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

fn alice_id() -> String {
    alice(&vectors("keys.json"))["pubky_id"]
        .as_str()
        .expect("id")
        .to_string()
}

fn alice_key() -> [u8; 32] {
    pubky_key(&alice_id()).expect("key")
}

fn after(ms_after_at: u64) -> String {
    pubky_switch_core::time::rfc3339(ms(AT) + ms_after_at)
}

/// Limits that sign a checkpoint once two stubs may go and read eight, the least, at a
/// request.
fn small() -> Limits {
    Limits {
        checkpoint_behind: 2,
        retention_per_request: 8,
        ..Limits::default()
    }
}

/// alice's account with the wallet registered, at `AT`.
async fn registered(limits: Limits, time_required: bool) -> Option<Replay> {
    let replay = replay_with_time(limits, time_required).await?;
    serve_alice(&replay).await;
    let chain = vectors("chain.json");
    let at = item_time(&chain["items"].as_array().expect("items")[2]);
    set_time(&replay.clock, &at);
    let ops: Vec<SignedOp> = [2, 3]
        .iter()
        .map(|i| {
            let signed: SignedDoc =
                serde_json::from_value(chain["items"][*i]["item"].clone()).expect("op");
            SignedOp::peek(&signed).expect("op")
        })
        .collect();
    let (status, body) = post(&replay, &ops, &at).await;
    assert_eq!(status, 200, "registered: {body}");
    set_time(&replay.clock, AT);
    Some(replay)
}

/// A batch of the wallet's, with batch ID `[id; 16]`, adding contacts `[c; 32]` for each `c`
/// in `contacts`: one chain item each.
fn batch(id: u8, contacts: &[u8]) -> Vec<SignedOp> {
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let key = ed25519_dalek::SigningKey::from_bytes(&hex32(&wallet["signing_secret_hex"]));
    let app_id: [u8; 16] = hex::decode(wallet["app_id_bytes_hex"].as_str().expect("hex"))
        .expect("hex")
        .try_into()
        .expect("16 bytes");
    let kinds: Vec<(Vec<Condition>, OpKind)> = contacts
        .iter()
        .map(|c| {
            (
                Vec::new(),
                OpKind::AllowPut {
                    pubky: [*c; 32],
                    kind: AllowKind::Contact,
                },
            )
        })
        .collect();
    sign_batch(&key, &alice_key(), Some(app_id), 1, [id; 16], kinds).expect("batch")
}

async fn post(replay: &Replay, ops: &[SignedOp], at: &str) -> (u16, Value) {
    let keys = vectors("keys.json");
    let body = OpsRequest::new(ops, None).to_json();
    let path = format!("/v1/{}/ops", alice_id());
    let request = app_request(app(&keys, "wallet"), "POST", &path, body, ms(at));
    let answer = replay.service.handle(request).await;
    let body = serde_json::from_slice(&answer.body).unwrap_or(Value::Null);
    (answer.status, body)
}

/// `n` batches of one contact each at `at`, batch IDs and contacts from `first` on.
async fn chain(replay: &Replay, first: u8, n: u8, at: &str) {
    set_time(&replay.clock, at);
    for i in first..first + n {
        let (status, body) = post(replay, &batch(i, &[i]), at).await;
        assert_eq!(status, 200, "{body}");
    }
}

/// A request of the wallet's at `at` that changes nothing but what step 4 sweeps: the
/// status.
async fn request(replay: &Replay, at: &str) -> u16 {
    set_time(&replay.clock, at);
    let keys = vectors("keys.json");
    let path = format!(
        "/v1/{}/claims/{}",
        alice_id(),
        pubky_switch_core::enc::b64(&[7; 32])
    );
    let request = app_request(app(&keys, "wallet"), "GET", &path, Vec::new(), ms(at));
    replay.service.handle(request).await.status
}

/// The feed page the wallet reads after `after_seq`, at `at`.
async fn feed(replay: &Replay, after_seq: u64, at: &str) -> Value {
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/feed?after=1:{after_seq}", alice_id());
    let request = app_request(app(&keys, "wallet"), "GET", &path, Vec::new(), ms(at));
    let answer = replay.service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    serde_json::from_slice(&answer.body).expect("json")
}

async fn conn(replay: &Replay) -> sqlx::PgConnection {
    sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn")
}

/// Set the cursor of each app `keys.json` names in `apps` to `seq`, a row made for one that
/// has none, as a registration and a `cursor.set` would.
async fn cursors(replay: &Replay, apps: &[&str], seq: u64) {
    let keys = vectors("keys.json");
    let mut conn = conn(replay).await;
    for name in apps {
        let id =
            hex::decode(app(&keys, name)["app_id_bytes_hex"].as_str().expect("hex")).expect("hex");
        sqlx::query(
            "INSERT INTO apps (account_id, app_id, cursor_generation, cursor_seq) \
             VALUES ($1, $2, 1, $3) ON CONFLICT (account_id, app_id) \
             DO UPDATE SET cursor_generation = 1, cursor_seq = $3",
        )
        .bind(alice_id())
        .bind(id)
        .bind(i64::try_from(seq).expect("seq"))
        .execute(&mut conn)
        .await
        .expect("cursor");
    }
    conn.close().await.expect("close");
}

const ALL: &[&str] = &["wallet", "phone", "executor"];

/// The `seq`s of the chain stubs kept, oldest first.
async fn kept(replay: &Replay) -> Vec<u64> {
    let mut conn = conn(replay).await;
    let seqs: Vec<i64> =
        sqlx::query_scalar("SELECT seq FROM chain_items WHERE account_id = $1 ORDER BY seq")
            .bind(alice_id())
            .fetch_all(&mut conn)
            .await
            .expect("seqs");
    conn.close().await.expect("close");
    seqs.into_iter()
        .map(|seq| u64::try_from(seq).expect("seq"))
        .collect()
}

/// The latest checkpoint's `seq` and the newest dropped stub's.
async fn retained(replay: &Replay) -> (Option<u64>, Option<u64>) {
    let mut conn = conn(replay).await;
    let row: Option<(Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT checkpoint_seq, dropped_seq FROM chain_retention WHERE account_id = $1",
    )
    .bind(alice_id())
    .fetch_optional(&mut conn)
    .await
    .expect("retention");
    conn.close().await.expect("close");
    let seq = |seq: Option<i64>| seq.map(|seq| u64::try_from(seq).expect("seq"));
    row.map_or((None, None), |(checkpoint, dropped)| {
        (seq(checkpoint), seq(dropped))
    })
}

/// The chain hash at `seq`, while its stub is kept.
async fn hash_at(replay: &Replay, seq: u64) -> Vec<u8> {
    let mut conn = conn(replay).await;
    let hash: Vec<u8> =
        sqlx::query_scalar("SELECT chain_hash FROM chain_items WHERE account_id = $1 AND seq = $2")
            .bind(alice_id())
            .bind(i64::try_from(seq).expect("seq"))
            .fetch_one(&mut conn)
            .await
            .expect("hash");
    conn.close().await.expect("close");
    hash
}

async fn service_key(replay: &Replay) -> KeyId {
    let mut conn = conn(replay).await;
    let id: String = sqlx::query_scalar("SELECT service_key FROM accounts WHERE id = $1")
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("key");
    conn.close().await.expect("close");
    KeyId::parse(&id).expect("key id")
}

async fn head_seq(replay: &Replay) -> u64 {
    let mut conn = conn(replay).await;
    let seq: i64 = sqlx::query_scalar("SELECT chain_seq FROM accounts WHERE id = $1")
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("head");
    conn.close().await.expect("close");
    u64::try_from(seq).expect("seq")
}

/// The signer's `GET /apps` at `at`, without its head: what the account's current state
/// shows.
async fn apps_state(replay: &Replay, at: &str) -> Value {
    let path = format!("/v1/{}/apps", alice_id());
    let answer = replay
        .service
        .handle(signer_request("GET", &path, Vec::new(), ms(at)))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let mut state: Value = serde_json::from_slice(&answer.body).expect("json");
    state.as_object_mut().expect("object").remove("head");
    state
}

#[tokio::test]
async fn test_retention_cursors_passed_sign_a_checkpoint_and_drop_behind_it() {
    // Every current app's cursor is at the head: a request signs a checkpoint at the
    // newest of the stubs it read that may go, short of the head, and drops them; a feed
    // page, whose own request sweeps first, carries the checkpoint kept then, signed by the
    // account's key at the chain hash there; and the current state reads the same (wire
    // 7.4.4, 9.1).
    let Some(replay) = registered(small(), false).await else {
        return;
    };
    chain(&replay, 10, 10, AT).await;
    let head = head_seq(&replay).await;
    let before = kept(&replay).await;
    let mut hashes = Vec::new();
    for seq in &before {
        hashes.push((*seq, hash_at(&replay, *seq).await));
    }
    let state = apps_state(&replay, AT).await;
    cursors(&replay, ALL, head).await;
    assert_eq!(request(&replay, AT).await, 404);
    assert_eq!(retained(&replay).await, (Some(before[7]), Some(before[7])));
    assert_eq!(kept(&replay).await, before[8..]);
    let page = feed(&replay, 0, AT).await;
    let (Some(checkpoint), Some(dropped)) = retained(&replay).await else {
        panic!("a checkpoint and a drop");
    };
    assert!(checkpoint > before[7] && dropped == checkpoint && checkpoint < head);
    let signed = SignedHead::from_value(&page["checkpoint"]).expect("checkpoint");
    assert_eq!((signed.generation, signed.seq), (1, checkpoint));
    let hash = &hashes
        .iter()
        .find(|(seq, _)| *seq == checkpoint)
        .expect("hash")
        .1;
    assert_eq!(signed.chain_hash.as_slice(), hash.as_slice());
    let key = replay
        .keys
        .public_key(&service_key(&replay).await)
        .await
        .expect("public");
    signed
        .verify(&key, &alice_key())
        .expect("signed by the account's key");
    // Read from behind the oldest kept stub: no stub before it.
    let first = page["items"].as_array().expect("items")[0]["seq"].as_u64();
    assert_eq!(first, kept(&replay).await.first().copied());
    assert_eq!(apps_state(&replay, AT).await, state);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retention_a_cursor_behind_holds_stubs_for_30_days() {
    // The phone's cursor is behind: nothing past it goes, however old the cursors passed;
    // once the stubs past it are 30 days old they go all the same (wire 7.4.4, 9.2
    // `cursor_hold_ms`).
    let Some(replay) = registered(small(), false).await else {
        return;
    };
    chain(&replay, 10, 6, AT).await;
    let before = kept(&replay).await;
    let head = head_seq(&replay).await;
    cursors(&replay, &["wallet", "executor"], head).await;
    cursors(&replay, &["phone"], before[1]).await;
    request(&replay, &after(29 * DAY_MS)).await;
    assert_eq!(retained(&replay).await, (Some(before[1]), Some(before[1])));
    request(&replay, &after(29 * DAY_MS)).await;
    assert_eq!(
        kept(&replay).await,
        before[2..],
        "held by the phone's cursor"
    );
    request(&replay, &after(30 * DAY_MS)).await;
    assert_eq!(
        kept(&replay).await,
        before[9..],
        "30 days old, the head kept"
    );
    replay.db.drop_database().await.expect("drop");
}

/// Give each app `keys.json` names in `apps` a row here with an app record and no cursor, as
/// its registration does before its first `cursor.set`. The record is the wallet's: the
/// sweep only asks whether one is stored.
async fn unmoved(replay: &Replay, apps: &[&str]) {
    let keys = vectors("keys.json");
    let mut conn = conn(replay).await;
    for name in apps {
        let id =
            hex::decode(app(&keys, name)["app_id_bytes_hex"].as_str().expect("hex")).expect("hex");
        sqlx::query(
            "INSERT INTO apps (account_id, app_id, record) SELECT $1, $2, record FROM apps \
             WHERE account_id = $1 AND record IS NOT NULL LIMIT 1",
        )
        .bind(alice_id())
        .bind(id)
        .execute(&mut conn)
        .await
        .expect("row");
    }
    conn.close().await.expect("close");
}

#[tokio::test]
async fn test_retention_an_app_yet_to_move_its_cursor_holds_every_stub() {
    // The phone and the executor are registered here and haven't moved their cursors: they
    // hold every stub, which their registration's `seq` would bound, for 30 days (wire
    // 7.4.4).
    let Some(replay) = registered(small(), false).await else {
        return;
    };
    chain(&replay, 10, 6, AT).await;
    let before = kept(&replay).await;
    cursors(&replay, &["wallet"], head_seq(&replay).await).await;
    unmoved(&replay, &["phone", "executor"]).await;
    request(&replay, &after(29 * DAY_MS)).await;
    assert_eq!(retained(&replay).await, (None, None));
    assert_eq!(kept(&replay).await, before);
    request(&replay, &after(30 * DAY_MS)).await;
    assert_eq!(kept(&replay).await, before[8..]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retention_an_app_not_registered_here_holds_nothing() {
    // The phone and the executor are listed and not registered here, as before they join
    // or after a recovery in place, whose chain starts afresh: their first read starts at
    // their registration, after every stub kept, so they hold none, and the wallet's cursor
    // at the head lets the stubs go (wire 7.4.4 "Start of a new app").
    let Some(replay) = registered(small(), false).await else {
        return;
    };
    chain(&replay, 10, 6, AT).await;
    let before = kept(&replay).await;
    cursors(&replay, &["wallet"], head_seq(&replay).await).await;
    request(&replay, AT).await;
    assert_eq!(kept(&replay).await, before[8..]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retention_a_removed_apps_cursor_holds_nothing() {
    // The phone is revoked and the executor departed, still listed until the signer's next
    // version: they aren't current, so their cursors, behind or missing, hold nothing, and
    // the wallet's at the head lets the stubs go (wire 7.4.4).
    let Some(replay) = registered(small(), false).await else {
        return;
    };
    chain(&replay, 10, 6, AT).await;
    let before = kept(&replay).await;
    cursors(&replay, &["wallet"], head_seq(&replay).await).await;
    cursors(&replay, &["phone"], before[0]).await;
    let keys = vectors("keys.json");
    let mut db = conn(&replay).await;
    for (name, reason) in [("phone", "revoked"), ("executor", "departed")] {
        let id =
            hex::decode(app(&keys, name)["app_id_bytes_hex"].as_str().expect("hex")).expect("hex");
        sqlx::query(
            "INSERT INTO kept_app_ids (account_id, app_id, reason, at_ms) VALUES ($1, $2, $3, 0)",
        )
        .bind(alice_id())
        .bind(id)
        .bind(reason)
        .execute(&mut db)
        .await
        .expect("kept");
    }
    db.close().await.expect("close");
    request(&replay, AT).await;
    assert_eq!(kept(&replay).await, before[8..]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retention_never_cuts_inside_a_batch() {
    // The cursors stop inside a batch of three: the cut, and the checkpoint, stop before
    // the batch's first item (wire 7.4.4).
    let limits = Limits {
        retention_per_request: 16,
        ..small()
    };
    let Some(replay) = registered(limits, false).await else {
        return;
    };
    chain(&replay, 10, 2, AT).await;
    let (status, body) = post(&replay, &batch(20, &[20, 21, 22]), AT).await;
    assert_eq!(status, 200, "{body}");
    chain(&replay, 30, 1, AT).await;
    let before = kept(&replay).await;
    let edge = before.len() - 4;
    cursors(&replay, ALL, before[edge + 1]).await;
    request(&replay, AT).await;
    assert_eq!(
        retained(&replay).await,
        (Some(before[edge - 1]), Some(before[edge - 1]))
    );
    assert_eq!(kept(&replay).await, before[edge..]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retention_reads_and_drops_a_bounded_number_at_one_request() {
    // Twenty-three stubs may go, eight a request: each request drops the next eight, the
    // oldest first, so the kept ones run unbroken to the head, which stays (wire 9.1, 9.2
    // `retention_per_request`).
    let Some(replay) = registered(small(), false).await else {
        return;
    };
    chain(&replay, 10, 20, AT).await;
    let before = kept(&replay).await;
    cursors(&replay, ALL, head_seq(&replay).await).await;
    for request_number in 1..=2 {
        request(&replay, AT).await;
        assert_eq!(
            kept(&replay).await,
            before[8 * request_number..],
            "request {request_number}"
        );
    }
    request(&replay, AT).await;
    assert_eq!(kept(&replay).await, before[before.len() - 1..], "the head");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retention_waits_for_trusted_time() {
    // Without trusted time nothing is signed or dropped (wire 7.3 step 4).
    let Some(replay) = registered(small(), true).await else {
        return;
    };
    chain(&replay, 10, 6, AT).await;
    let before = kept(&replay).await;
    cursors(&replay, ALL, head_seq(&replay).await).await;
    request(&replay, &after(31 * DAY_MS)).await;
    assert_eq!(retained(&replay).await, (None, None));
    assert_eq!(kept(&replay).await, before);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retention_signs_and_drops_nothing_behind_the_mark() {
    // The key signed a head beyond the state the account holds: the request is refused
    // with the mark's 503, and its step 4 signs no checkpoint and drops no stub (spec 6.5,
    // wire 7.3 step 10).
    let Some(replay) = registered(small(), false).await else {
        return;
    };
    chain(&replay, 10, 6, AT).await;
    let before = kept(&replay).await;
    cursors(&replay, ALL, head_seq(&replay).await).await;
    let mark = Mark {
        generation: 1,
        seq: 500,
        chain_hash: [0xcd; 32],
    };
    replay
        .keys
        .advance_mark(&service_key(&replay).await, mark)
        .await
        .expect("mark");
    assert_eq!(request(&replay, AT).await, 503);
    assert_eq!(retained(&replay).await, (None, None));
    assert_eq!(kept(&replay).await, before);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retention_cut_short_leaves_the_state_as_it_was() {
    // The drop fails after the checkpoint was kept: the request is `503 unavailable` and
    // its transaction rolls back whole, so no checkpoint, no drop and every stub as before;
    // the next request does it all.
    let Some(replay) = registered(small(), false).await else {
        return;
    };
    chain(&replay, 10, 6, AT).await;
    let before = kept(&replay).await;
    cursors(&replay, ALL, head_seq(&replay).await).await;
    let mut db = conn(&replay).await;
    for statement in [
        "CREATE FUNCTION refuse_drops() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'refused'; END $$",
        "CREATE TRIGGER refuse_drops BEFORE DELETE ON chain_items \
         FOR EACH ROW EXECUTE FUNCTION refuse_drops()",
    ] {
        sqlx::query(statement)
            .execute(&mut db)
            .await
            .expect("trigger");
    }
    assert_eq!(request(&replay, AT).await, 503);
    assert_eq!(retained(&replay).await, (None, None));
    assert_eq!(kept(&replay).await, before);
    sqlx::query("DROP TRIGGER refuse_drops ON chain_items")
        .execute(&mut db)
        .await
        .expect("drop trigger");
    db.close().await.expect("close");
    request(&replay, AT).await;
    assert_eq!(kept(&replay).await, before[8..]);
    replay.db.drop_database().await.expect("drop");
}

/// Whether batch `[id; 16]`'s record is held at alice's account.
async fn batch_held(replay: &Replay, id: u8) -> bool {
    let mut conn = conn(replay).await;
    let held: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM batches WHERE account_id = $1 AND batch_id = $2)",
    )
    .bind(alice_id())
    .bind([id; 16].as_slice())
    .fetch_one(&mut conn)
    .await
    .expect("batch");
    conn.close().await.expect("close");
    held
}

#[tokio::test]
async fn test_retention_a_batch_record_goes_once_its_proofs_and_stubs_are_gone() {
    // Two batches' stubs are dropped at once; their records stay while their proofs do. 30
    // days on, the minute's sweep drops the proofs and the records go with them, while a
    // batch whose stub is kept keeps its record (wire 6.4 step 5, 9.1).
    let Some(replay) = registered(small(), false).await else {
        return;
    };
    chain(&replay, 10, 6, AT).await;
    cursors(&replay, ALL, head_seq(&replay).await).await;
    request(&replay, AT).await;
    let dropped = retained(&replay).await.1.expect("dropped");
    assert!(batch_held(&replay, 10).await && batch_held(&replay, 11).await);
    // Drops at `AT + 30 days` too, up to four more, and the proofs go at that minute's
    // sweep: the records of batches wholly dropped go; the one at the head stays.
    request(&replay, &after(30 * DAY_MS)).await;
    request(&replay, &after(30 * DAY_MS)).await;
    assert!(!batch_held(&replay, 10).await && !batch_held(&replay, 11).await);
    assert!(batch_held(&replay, 15).await, "its stub is the head");
    assert!(dropped > 0);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retention_a_restarted_service_goes_on_from_the_newest_dropped() {
    // A service on the same database after a restart reads the checkpoint and the newest
    // dropped stub it kept, and goes on from there.
    let Some(replay) = registered(small(), false).await else {
        return;
    };
    chain(&replay, 10, 20, AT).await;
    let before = kept(&replay).await;
    cursors(&replay, ALL, head_seq(&replay).await).await;
    request(&replay, AT).await;
    let restarted = replay.restarted_with(small());
    let keys = vectors("keys.json");
    let path = format!(
        "/v1/{}/claims/{}",
        alice_id(),
        pubky_switch_core::enc::b64(&[7; 32])
    );
    let answer = restarted
        .handle(app_request(
            app(&keys, "wallet"),
            "GET",
            &path,
            Vec::new(),
            ms(AT),
        ))
        .await;
    assert_eq!(answer.status, 404);
    assert_eq!(kept(&replay).await, before[16..]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retention_at_head_signs_at_the_newest_item() {
    // With `checkpoint_at_head`, a checkpoint goes at the head once two chain items were
    // added since the last, whatever the cursors, as the wallet's own batches find; the drop
    // still stops at the cut, so the head stays (wire 7.4.4, 9.2).
    let Some(replay) = registered(
        Limits {
            checkpoint_at_head: true,
            ..small()
        },
        false,
    )
    .await
    else {
        return;
    };
    unmoved(&replay, &["phone", "executor"]).await;
    chain(&replay, 10, 1, AT).await;
    let first = head_seq(&replay).await;
    chain(&replay, 11, 2, AT).await;
    // The third batch's step 4 found two items added since the last checkpoint: one at the
    // head then. Nothing goes while the phone and the executor, yet to move their cursors,
    // hold every stub, but the first, which went before any app was registered.
    assert_eq!(retained(&replay).await, (Some(first + 1), Some(1)));
    let head = head_seq(&replay).await;
    cursors(&replay, ALL, head).await;
    request(&replay, AT).await;
    request(&replay, AT).await;
    assert_eq!(retained(&replay).await, (Some(first + 1), Some(first + 1)));
    assert_eq!(kept(&replay).await, vec![head]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retention_turned_off_keeps_every_stub() {
    // With `chain_retention` off nothing is signed or dropped, however old the stubs and
    // whatever the cursors, and pages carry no checkpoint.
    let Some(replay) = registered(
        Limits {
            chain_retention: false,
            ..small()
        },
        false,
    )
    .await
    else {
        return;
    };
    chain(&replay, 10, 6, AT).await;
    let before = kept(&replay).await;
    cursors(&replay, ALL, head_seq(&replay).await).await;
    request(&replay, &after(31 * DAY_MS)).await;
    assert_eq!(retained(&replay).await, (None, None));
    assert_eq!(kept(&replay).await, before);
    assert!(
        feed(&replay, 0, &after(31 * DAY_MS))
            .await
            .get("checkpoint")
            .is_none()
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retention_a_read_that_ends_inside_a_batch_still_moves_on() {
    // A checkpoint once eight stubs may go, eight a request, and the eighth stub inside a
    // batch of six: the checkpoint goes at the item before the batch, and the next request,
    // whose read holds the batch whole, drops it too. Counted after the batch edge, the
    // stubs that may go would stay short of eight at every request.
    let limits = Limits {
        checkpoint_behind: 8,
        retention_per_request: 8,
        ..Limits::default()
    };
    let Some(replay) = registered(limits, false).await else {
        return;
    };
    let base = kept(&replay).await.len();
    let (status, body) = post(&replay, &batch(20, &[20, 21, 22, 23, 24, 25]), AT).await;
    assert_eq!(status, 200, "{body}");
    chain(&replay, 30, 10, AT).await;
    let before = kept(&replay).await;
    assert!(base < 8 && base + 6 > 8, "the read ends inside the batch");
    cursors(&replay, ALL, head_seq(&replay).await).await;
    request(&replay, AT).await;
    assert_eq!(
        retained(&replay).await,
        (Some(before[base - 1]), Some(before[base - 1]))
    );
    request(&replay, AT).await;
    assert_eq!(kept(&replay).await, before[base + 8..]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retention_an_app_of_another_identity_sweeps_the_chain() {
    // An app of another identity calls alice's account: its step 4 runs, chain stub
    // retention with it, as at an own app's request.
    let Some(replay) = registered(small(), false).await else {
        return;
    };
    chain(&replay, 10, 6, AT).await;
    let before = kept(&replay).await;
    cursors(&replay, ALL, head_seq(&replay).await).await;
    set_time(&replay.clock, AT);
    let path = format!("/v1/{}/connect", alice_id());
    let answer = replay
        .service
        .handle(other_request(
            "shop",
            ORIGIN,
            "POST",
            &path,
            Vec::new(),
            None,
            ms(AT),
        ))
        .await;
    assert_eq!(
        kept(&replay).await,
        before[8..],
        "{}: {}",
        answer.status,
        String::from_utf8_lossy(&answer.body)
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_retention_behind_the_mark_keeps_the_stubs_behind_an_earlier_checkpoint() {
    // With `checkpoint_at_head`, a checkpoint at the head leaves stubs behind it that the
    // cursors held. Then the state falls behind the key's mark and every cursor passes
    // them: a request signs nothing and drops nothing behind the earlier checkpoint.
    let Some(replay) = registered(
        Limits {
            checkpoint_at_head: true,
            ..small()
        },
        false,
    )
    .await
    else {
        return;
    };
    unmoved(&replay, &["phone", "executor"]).await;
    chain(&replay, 10, 1, AT).await;
    chain(&replay, 11, 2, AT).await;
    let (checkpoint, dropped) = retained(&replay).await;
    let checkpoint = checkpoint.expect("a checkpoint at the head");
    assert!(
        dropped.expect("dropped") < checkpoint,
        "stubs kept behind it"
    );
    let before = kept(&replay).await;
    let mark = Mark {
        generation: 1,
        seq: 500,
        chain_hash: [0xcd; 32],
    };
    replay
        .keys
        .advance_mark(&service_key(&replay).await, mark)
        .await
        .expect("mark");
    cursors(&replay, ALL, head_seq(&replay).await).await;
    assert_eq!(request(&replay, AT).await, 503);
    assert_eq!(
        kept(&replay).await,
        before,
        "nothing dropped behind the mark"
    );
    assert_eq!(retained(&replay).await, (Some(checkpoint), dropped));
    replay.db.drop_database().await.expect("drop");
}

#[test]
fn test_retention_a_raised_checkpoint_behind_alone_is_refused() {
    // A configuration that raised `checkpoint_behind` above 1,000 and sets no
    // `retention_per_request` is refused once retention exists.
    let limits = Limits {
        checkpoint_behind: 5_000,
        ..Limits::default()
    };
    assert!(limits.validate().is_err());
    let limits = Limits {
        checkpoint_behind: 5_000,
        retention_per_request: 5_000,
        ..Limits::default()
    };
    assert!(limits.validate().is_ok());
}

#[tokio::test]
async fn test_retention_a_batch_ending_before_its_missed_item_still_goes() {
    // The executor is registered and marked lagging, and an entry targets it and the
    // wallet. The wallet's batch of seven moves its cursor past the entry: the entry goes,
    // and the executor's `missed` item takes the `seq` after the batch's seventh chain item,
    // inside the batch record's `first_seq..=last_seq`. Every cursor then stands at that
    // seventh item: it ends the batch, so the batch may go, as the scripted switch, which
    // ends batches by their envelopes' count, lets it.
    let Some(replay) = registered(small(), false).await else {
        return;
    };
    let keys = vectors("keys.json");
    let executor = app(&keys, "executor");
    let id_of = |name: &str| -> [u8; 16] {
        hex::decode(app(&keys, name)["app_id_bytes_hex"].as_str().expect("hex"))
            .expect("hex")
            .try_into()
            .expect("16 bytes")
    };
    let (executor_id, wallet_id) = (id_of("executor"), id_of("wallet"));
    let record: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "executor app record",
        )["signed"]
            .clone(),
    )
    .expect("record");
    let ops = sign_batch(
        &ed25519_dalek::SigningKey::from_bytes(&hex32(&executor["signing_secret_hex"])),
        &alice_key(),
        Some(executor_id),
        1,
        [76; 16],
        vec![(Vec::new(), OpKind::AppPut { record })],
    )
    .expect("batch");
    let path = format!("/v1/{}/ops", alice_id());
    let answer = replay
        .service
        .handle(app_request(
            executor,
            "POST",
            &path,
            OpsRequest::new(&ops, None).to_json(),
            ms(AT),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let mut db = conn(&replay).await;
    let last: i64 = sqlx::query_scalar("SELECT last_seq FROM accounts WHERE id = $1")
        .bind(alice_id())
        .fetch_one(&mut db)
        .await
        .expect("last");
    let entry = last + 1;
    sqlx::query("UPDATE accounts SET last_seq = $2 WHERE id = $1")
        .bind(alice_id())
        .bind(entry)
        .execute(&mut db)
        .await
        .expect("seq");
    sqlx::query(
        "INSERT INTO inbox_entries (account_id, generation, seq, entry_id, sender, sender_app, \
         cert, accepted_at_ms, envelope, envelope_hash, targets, answer, quota_bytes) \
         VALUES ($1, 1, $2, $3, $4, $5, '\\x00', $6, '\\x00', $7, $8, '\\x00', 257)",
    )
    .bind(alice_id())
    .bind(entry)
    .bind([1u8; 16].as_slice())
    .bind([2u8; 32].as_slice())
    .bind([3u8; 16].as_slice())
    .bind(i64::try_from(ms(AT)).expect("ms"))
    .bind([4u8; 32].as_slice())
    .bind(vec![wallet_id.to_vec(), executor_id.to_vec()])
    .execute(&mut db)
    .await
    .expect("entry");
    sqlx::query("UPDATE apps SET lagging = true WHERE account_id = $1 AND app_id = $2")
        .bind(alice_id())
        .bind(executor_id.as_slice())
        .execute(&mut db)
        .await
        .expect("lagging");
    let cursor = pubky_switch_core::ops::Position {
        generation: 1,
        seq: u64::try_from(entry).expect("seq"),
    };
    let ops = batch(20, &[20, 21, 22, 23, 24, 25, 26]);
    let answer = replay
        .service
        .handle(app_request(
            app(&keys, "wallet"),
            "POST",
            &path,
            OpsRequest::new(&ops, Some(cursor)).to_json(),
            ms(AT),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let (first, last): (i64, i64) = sqlx::query_as(
        "SELECT first_seq, last_seq FROM batches WHERE account_id = $1 AND batch_id = $2",
    )
    .bind(alice_id())
    .bind([20u8; 16].as_slice())
    .fetch_one(&mut db)
    .await
    .expect("batch");
    let missed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM inbox_entries WHERE account_id = $1 AND kind = 'missed' AND seq = $2",
    )
    .bind(alice_id())
    .bind(last)
    .fetch_one(&mut db)
    .await
    .expect("missed");
    db.close().await.expect("close");
    assert_eq!(
        (last - first, missed),
        (7, 1),
        "the missed item ends the batch's range"
    );
    let ends = u64::try_from(last - 1).expect("seq");
    chain(&replay, 30, 3, AT).await;
    cursors(&replay, ALL, ends).await;
    for _ in 0..3 {
        request(&replay, AT).await;
    }
    let kept = kept(&replay).await;
    assert!(
        kept[0] > ends,
        "the batch {first}..={ends} is still kept: {kept:?}, {:?}",
        retained(&replay).await
    );
    replay.db.drop_database().await.expect("drop");
}
