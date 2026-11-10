//! `POST /v1/{id}/ops` on the service (Switch wire 6.4), against PostgreSQL: the callers and
//! their authentication, retries, the generation, no-ops and unchanged batches with a cursor,
//! the operation and control rates, the per-kind limits, trusted time, and a refused batch
//! leaving nothing behind.
//!
//! Each test starts from alice's account as `chain.json` builds it: `identity.json` version 3
//! and the wallet registered. Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see
//! `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::{
    http::Handler,
    limits::Limits,
    store::{ListName, StoredApp},
};
use pubky_switch_core::{
    claims::{ClaimFields, ClaimType},
    enc::pubky_key,
    http::header,
    ops::{AllowKind, Condition, OpKind, OpsRequest, Position, SignedOp, sign_batch},
    sig::SignedDoc,
};
use serde_json::Value;
use support::*;

/// The time of the tests' batches, after the registration.
const AT: &str = "2026-01-01T00:01:00.000Z";

fn alice_id() -> String {
    alice(&vectors("keys.json"))["pubky_id"]
        .as_str()
        .expect("id")
        .to_string()
}

fn alice_key() -> [u8; 32] {
    pubky_key(&alice_id()).expect("key")
}

/// Another identity's Pubky ID, for list entries.
fn bob() -> [u8; 32] {
    let keys = vectors("keys.json");
    let bob = keys["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] != "alice")
        .expect("another identity");
    pubky_key(bob["pubky_id"].as_str().expect("id")).expect("key")
}

fn ops_path() -> String {
    format!("/v1/{}/ops", alice_id())
}

/// alice's account with the wallet registered, as `chain.json`'s seqs 1 to 4 leave it.
async fn registered(limits: Limits, time_required: bool) -> Option<Replay> {
    let replay = replay_with_time(limits, time_required).await?;
    serve_alice(&replay).await;
    let chain = vectors("chain.json");
    let item = &chain["items"].as_array().expect("items")[2];
    let at = item_time(item);
    set_time(&replay.clock, &at);
    let ops: Vec<SignedOp> = [2, 3]
        .iter()
        .map(|i| {
            let signed: SignedDoc =
                serde_json::from_value(chain["items"][*i]["item"].clone()).expect("op");
            SignedOp::peek(&signed).expect("op")
        })
        .collect();
    let (status, body) = post_app(&replay, "wallet", &ops, None, &at).await;
    assert_eq!(status, 200, "registered: {body}");
    set_time(&replay.clock, AT);
    Some(replay)
}

/// A batch of the wallet's, with batch ID `[id; 16]`, at generation `generation`.
fn wallet_batch(id: u8, generation: u64, kinds: Vec<(Vec<Condition>, OpKind)>) -> Vec<SignedOp> {
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let key = ed25519_dalek::SigningKey::from_bytes(&hex32(&wallet["signing_secret_hex"]));
    let app_id: [u8; 16] = hex::decode(wallet["app_id_bytes_hex"].as_str().expect("hex"))
        .expect("hex")
        .try_into()
        .expect("16 bytes");
    sign_batch(
        &key,
        &alice_key(),
        Some(app_id),
        generation,
        [id; 16],
        kinds,
    )
    .expect("batch")
}

fn contact(pubky: [u8; 32]) -> (Vec<Condition>, OpKind) {
    (
        Vec::new(),
        OpKind::AllowPut {
            pubky,
            kind: AllowKind::Contact,
        },
    )
}

/// Post `ops` from the app `keys.json` names `app_name` at `at`: the status and the body.
async fn post_app(
    replay: &Replay,
    app_name: &str,
    ops: &[SignedOp],
    cursor: Option<Position>,
    at: &str,
) -> (u16, Value) {
    let keys = vectors("keys.json");
    let body = OpsRequest::new(ops, cursor).to_json();
    let request = app_request(app(&keys, app_name), "POST", &ops_path(), body, ms(at));
    let answer = replay.service.handle(request).await;
    let body = serde_json::from_slice(&answer.body).unwrap_or(Value::Null);
    (answer.status, body)
}

/// The head `seq` an answer names.
fn head_seq(body: &Value) -> u64 {
    body["head"]["seq"].as_u64().expect("head seq")
}

async fn wallet_app(replay: &Replay) -> StoredApp {
    let mut txn = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    let keys = vectors("keys.json");
    let id = app(&keys, "wallet")["app_id_bytes_hex"]
        .as_str()
        .expect("hex")
        .to_string();
    txn.apps()
        .await
        .expect("apps")
        .into_iter()
        .find(|stored| hex::encode(stored.app_id) == id)
        .expect("the wallet")
}

#[tokio::test]
async fn test_ops_retry_returns_the_original_proofs() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    let ops = wallet_batch(1, 1, vec![contact(bob())]);
    let (status, first) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!(status, 200, "{first}");
    assert_eq!(first["proofs"].as_array().expect("proofs").len(), 1);
    assert_eq!(head_seq(&first), 5);
    // The same batch again: the same proofs, no new chain item.
    let (status, again) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["proofs"], first["proofs"]);
    assert_eq!(head_seq(&again), 5);
    // Its ID with other operations is a conflict.
    let reused = wallet_batch(1, 1, vec![contact(alice_key())]);
    let (status, body) = post_app(&replay, "wallet", &reused, None, AT).await;
    assert_eq!((status, body["code"].as_str()), (409, Some("conflict")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_stale_generation() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    let ops = wallet_batch(2, 2, vec![contact(bob())]);
    let (status, body) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["code"], "stale_generation");
    assert_eq!(body["current"]["generation"], 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_unchanged_batches_and_the_cursor() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    let held = wallet_app(&replay).await.record.expect("record");
    let app_put = || {
        wallet_batch(
            3,
            1,
            vec![(
                Vec::new(),
                OpKind::AppPut {
                    record: held.clone(),
                },
            )],
        )
    };
    // The held record again: a no-op, no proof and no chain item.
    let (status, body) = post_app(&replay, "wallet", &app_put(), None, AT).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["proofs"], Value::Array(Vec::new()));
    assert_eq!(head_seq(&body), 4);
    // With cursor.set: checked, the cursor moves, still no proof.
    let position = Position {
        generation: 1,
        seq: 4,
    };
    let (status, body) = post_app(&replay, "wallet", &app_put(), Some(position), AT).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["proofs"], Value::Array(Vec::new()));
    assert_eq!(wallet_app(&replay).await.cursor, Some(position));
    // A cursor past the newest seq, or at another generation, is 400.
    for bad in [
        Position {
            generation: 1,
            seq: 5,
        },
        Position {
            generation: 2,
            seq: 1,
        },
    ] {
        let (status, body) = post_app(&replay, "wallet", &app_put(), Some(bad), AT).await;
        assert_eq!(status, 400, "{body}");
    }
    assert_eq!(wallet_app(&replay).await.cursor, Some(position));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_callers_and_authentication() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    // The phone has no record: a first call without its app.put is 403 not_current.
    let keys = vectors("keys.json");
    let phone = app(&keys, "phone");
    let key = ed25519_dalek::SigningKey::from_bytes(&hex32(&phone["signing_secret_hex"]));
    let phone_id: [u8; 16] = hex::decode(phone["app_id_bytes_hex"].as_str().expect("hex"))
        .expect("hex")
        .try_into()
        .expect("16 bytes");
    let ops = sign_batch(
        &key,
        &alice_key(),
        Some(phone_id),
        1,
        [4; 16],
        vec![contact(bob())],
    )
    .expect("batch");
    let (status, body) = post_app(&replay, "phone", &ops, None, AT).await;
    assert_eq!((status, body["code"].as_str()), (403, Some("not_current")));
    assert!(body.get("head").is_none());

    // The wallet's batch, with the request signed by another key: 401 bad_signature.
    let ops = wallet_batch(5, 1, vec![contact(bob())]);
    let body = OpsRequest::new(&ops, None).to_json();
    let mut request = app_request(phone, "POST", &ops_path(), body, ms(AT));
    request.headers.insert(
        header::APP,
        app(&keys, "wallet")["app_id"]
            .as_str()
            .expect("id")
            .parse()
            .expect("header"),
    );
    let answer = replay.service.handle(request).await;
    let body: Value = serde_json::from_slice(&answer.body).expect("json");
    assert_eq!(
        (answer.status, body["code"].as_str()),
        (401, Some("bad_signature"))
    );
    assert!(header_text(&answer, header::HEAD).is_none());

    // An app of another identity: 403 not_admitted.
    let shop = app(&keys, "shop");
    let ops = OpsRequest::new(&wallet_batch(6, 1, vec![contact(bob())]), None).to_json();
    let mut request = app_request(shop, "POST", &ops_path(), ops, ms(AT));
    request.headers.insert(
        header::IDENTITY,
        shop["identity"]
            .as_str()
            .expect("identity")
            .parse()
            .expect("header"),
    );
    let answer = replay.service.handle(request).await;
    let body: Value = serde_json::from_slice(&answer.body).expect("json");
    assert_eq!(
        (answer.status, body["code"].as_str()),
        (403, Some("not_admitted"))
    );

    // The signer has no cursor.
    let request = signer_request(
        "POST",
        &ops_path(),
        OpsRequest::new(
            &[],
            Some(Position {
                generation: 1,
                seq: 1,
            }),
        )
        .to_json(),
        ms(AT),
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(answer.status, 400);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_control_rate() {
    let limits = Limits {
        control_per_min: 1,
        ..Limits::default()
    };
    let Some(replay) = registered(limits, false).await else {
        return;
    };
    // Removing what isn't there is a repeatable control mutation.
    let delete = |id| {
        wallet_batch(
            id,
            1,
            vec![(
                Vec::new(),
                OpKind::AllowDelete {
                    pubky: bob(),
                    kind: AllowKind::Contact,
                },
            )],
        )
    };
    let (status, body) = post_app(&replay, "wallet", &delete(7), None, AT).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = post_app(&replay, "wallet", &delete(8), None, AT).await;
    assert_eq!((status, body["code"].as_str()), (429, Some("rate_limited")));
    assert!(body["retry_after"].as_u64().is_some());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_list_quota() {
    let limits = Limits {
        max_contacts: 1,
        ..Limits::default()
    };
    let Some(replay) = registered(limits, false).await else {
        return;
    };
    let (status, body) = post_app(
        &replay,
        "wallet",
        &wallet_batch(9, 1, vec![contact(bob())]),
        None,
        AT,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    // The same entry again passes; a new one finds the list full.
    let (status, body) = post_app(
        &replay,
        "wallet",
        &wallet_batch(10, 1, vec![contact(bob())]),
        None,
        AT,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = post_app(
        &replay,
        "wallet",
        &wallet_batch(11, 1, vec![contact(alice_key())]),
        None,
        AT,
    )
    .await;
    assert_eq!(status, 429, "{body}");
    assert_eq!(body["code"], "quota_exceeded");
    assert_eq!(body["current"]["limit"], "contacts");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_refused_batch_leaves_nothing() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    // The contact is added, then an unknown invite code's delete refuses the whole batch.
    let ops = wallet_batch(
        12,
        1,
        vec![
            contact(bob()),
            (Vec::new(), OpKind::InviteCodeDelete { code_hash: [9; 32] }),
        ],
    );
    let (status, body) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));
    let mut txn = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    assert!(
        txn.list_entries(ListName::Contact, &[bob()])
            .await
            .expect("entries")
            .is_empty()
    );
    assert_eq!(txn.head().last_seq, 4);
    assert!(txn.batch_record(&[12; 16]).await.expect("batch").is_none());
    drop(txn);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_without_trusted_time() {
    let Some(replay) = registered(Limits::default(), true).await else {
        return;
    };
    // An attempt depends on the service's time.
    let attempt = OpKind::Claim(ClaimFields {
        claim_key: vec![7; 32],
        kind: ClaimType::Attempt,
        expected_step: 0,
        attempt_id: vec![8; 16],
        orphan_after: Some(60),
        deadline: None,
        basis: None,
        evidence_ref: None,
    });
    let (status, body) = post_app(
        &replay,
        "wallet",
        &wallet_batch(13, 1, vec![(Vec::new(), attempt)]),
        None,
        AT,
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (503, Some("unavailable")),
        "{body}"
    );
    // A list change doesn't.
    let (status, body) = post_app(
        &replay,
        "wallet",
        &wallet_batch(14, 1, vec![contact(bob())]),
        None,
        AT,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["proofs"][0]["sig"].as_str().map(str::len), Some(86));
    replay.db.drop_database().await.expect("drop");
}
