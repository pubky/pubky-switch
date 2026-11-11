//! `GET` and `POST /v1/{id}/apps/{app_id}/keys` (Switch wire 7.4.11) on `chain.json`'s
//! account: the wallet reads the key bundle parts the signer stored for it and asks for a full
//! bundle, which `GET /apps` shows until the parts cover every data epoch.
//!
//! The vectors fix the service key and the times; set `PUBKY_SWITCH_TEST_DATABASE_URL` to run
//! them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::http::{Handler, SwitchResponse};
use pubky_switch_core::{
    http::header,
    keys::IdentityKey,
    ops::{KeyBundlePut, OpKind, OpsRequest, SignedOp, sign_batch},
    records::{AppCert, AppRecord, KeyBundle},
    sig::SignedDoc,
};
use serde_json::{Value, json};
use support::*;

fn alice_id() -> String {
    alice(&vectors("keys.json"))["pubky_id"]
        .as_str()
        .expect("id")
        .to_string()
}

fn app_id(name: &str) -> String {
    app(&vectors("keys.json"), name)["app_id"]
        .as_str()
        .expect("id")
        .to_string()
}

fn revoke_time() -> String {
    item_time(chain_item(&vectors("chain.json"), 9))
}

fn body(answer: &SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body)
        .unwrap_or_else(|_| panic!("json: {}", String::from_utf8_lossy(&answer.body)))
}

fn code(answer: &SwitchResponse) -> (u16, Value) {
    (answer.status, body(answer)["code"].clone())
}

/// The wallet's certificate, from its `app.put` at `seq` 3.
fn wallet_cert() -> AppCert {
    let keys = vectors("keys.json");
    let alice_key = hex32(&alice(&keys)["public_hex"]);
    let op = SignedOp::peek(
        &serde_json::from_value::<SignedDoc>(chain_item(&vectors("chain.json"), 3)["item"].clone())
            .expect("op"),
    )
    .expect("op");
    let OpKind::AppPut { record } = &op.body().kind else {
        panic!("seq 3 is the wallet's app.put");
    };
    AppRecord::verify(record, &alice_key)
        .expect("record")
        .cert()
        .clone()
}

/// The signer stores the wallet's key bundle parts over `ranges`, in one batch at `at`;
/// returns each part's bundle.
async fn store_parts(
    replay: &Replay,
    ranges: &[(u64, u64)],
    batch: u8,
    at: &str,
) -> Vec<KeyBundle> {
    let keys = vectors("keys.json");
    let alice_key = hex32(&alice(&keys)["public_hex"]);
    let alice = IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let cert = wallet_cert();
    let mut bundles = Vec::new();
    let mut ops = Vec::new();
    for (first, last) in ranges {
        let part =
            pubky_switch_core::records::seal_bundle_parts(&alice, &cert, *first, *last, &|_| true)
                .expect("bundle")
                .remove(0);
        bundles.push(part.bundle.clone());
        ops.push((
            Vec::new(),
            OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: cert.app_id(),
                bundle: part.bundle,
                first_epoch: *first,
                last_epoch: *last,
            }),
        ));
    }
    let batch = sign_batch(&alice, &alice_key, None, 1, [batch; 16], ops).expect("batch");
    let answer = replay
        .service
        .handle(signer_request(
            "POST",
            &format!("/v1/{}/ops", alice_id()),
            OpsRequest::new(&batch, None).to_json(),
            ms(at),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    bundles
}

/// The keys call `method` on `path_app`'s keys, from `caller` (a `keys.json` app, or
/// `"signer"`), at `at`.
async fn keys_call(
    replay: &Replay,
    caller: &str,
    method: &str,
    path_app: &str,
    body: Vec<u8>,
    at: &str,
) -> SwitchResponse {
    let path = format!("/v1/{}/apps/{}/keys", alice_id(), app_id(path_app));
    let request = if caller == "signer" {
        signer_request(method, &path, body, ms(at))
    } else {
        app_request(
            app(&vectors("keys.json"), caller),
            method,
            &path,
            body,
            ms(at),
        )
    };
    replay.service.handle(request).await
}

async fn full_bundle_requested(replay: &Replay, at: &str) -> Value {
    let path = format!("/v1/{}/apps", alice_id());
    let answer = replay
        .service
        .handle(signer_request("GET", &path, Vec::new(), ms(at)))
        .await;
    let wallet = app_id("wallet");
    body(&answer)["apps"]
        .as_array()
        .expect("apps")
        .iter()
        .find(|status| status["app_id"] == wallet.as_str())
        .expect("the wallet's status")["full_bundle_requested"]
        .clone()
}

#[tokio::test]
async fn test_keys_get_answers_the_parts_in_order() {
    // Two parts, stored in one batch: the wallet reads both, ordered by `first_epoch`, each
    // its bundle, the `seq` of its `key_bundle.put` and its range, with the head (Switch wire
    // 7.4.11, 7.1).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let bundles = store_parts(&replay, &[(2, 2), (1, 1)], 41, &at).await;
    let answer = keys_call(&replay, "wallet", "GET", "wallet", Vec::new(), &at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");
    let parts = body(&answer)["bundles"]
        .as_array()
        .expect("bundles")
        .clone();
    assert_eq!(parts.len(), 2);
    assert_eq!(
        parts
            .iter()
            .map(|part| (part["first_epoch"].clone(), part["last_epoch"].clone()))
            .collect::<Vec<_>>(),
        [(json!(1), json!(1)), (json!(2), json!(2))]
    );
    // The batch's two operations follow the revoke at `seq` 9, in the batch's order.
    assert_eq!(parts[0]["seq"], 11);
    assert_eq!(parts[1]["seq"], 10);
    assert_eq!(
        parts[0]["bundle"],
        serde_json::to_value(&bundles[1]).expect("bundle")
    );
    assert_eq!(
        parts[1]["bundle"],
        serde_json::to_value(&bundles[0]).expect("bundle")
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_get_without_parts_is_not_found() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let answer = keys_call(&replay, "wallet", "GET", "wallet", Vec::new(), &at).await;
    assert_eq!(code(&answer), (404, json!("not_found")));
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_only_the_app_itself() {
    // Another own app's path, the signer and an app of another identity: `403
    // permission_missing`, with the head to the account's own callers only. The revoked phone
    // isn't current (Switch wire 7.4.11, 7.2).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    for method in ["GET", "POST"] {
        let answer = keys_call(&replay, "wallet", method, "phone", Vec::new(), &at).await;
        assert_eq!(
            code(&answer),
            (403, json!("permission_missing")),
            "{method}"
        );
        assert!(header_text(&answer, header::HEAD).is_some(), "{method}");
        let answer = keys_call(&replay, "signer", method, "wallet", Vec::new(), &at).await;
        assert_eq!(
            code(&answer),
            (403, json!("permission_missing")),
            "{method}"
        );
        assert!(header_text(&answer, header::HEAD).is_some(), "{method}");
        let path = format!("/v1/{}/apps/{}/keys", alice_id(), app_id("shop"));
        let answer = replay
            .service
            .handle(other_request(
                "shop",
                ORIGIN,
                method,
                &path,
                Vec::new(),
                None,
                ms(&at),
            ))
            .await;
        assert_eq!(
            code(&answer),
            (403, json!("permission_missing")),
            "{method}"
        );
        assert!(header_text(&answer, header::HEAD).is_none(), "{method}");
        let answer = keys_call(&replay, "phone", method, "phone", Vec::new(), &at).await;
        assert_eq!(code(&answer), (403, json!("not_current")), "{method}");
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_request_keeps_the_first_time_until_covered() {
    // The first request's service time is kept, and `GET /apps` shows it, until the stored
    // parts cover every data epoch from 1 to the current one, 2 (Switch wire 7.4.11, 3.5).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    assert_eq!(full_bundle_requested(&replay, &at).await, Value::Null);
    let answer = keys_call(&replay, "wallet", "POST", "wallet", Vec::new(), &at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");
    assert_eq!(
        answer.body,
        format!(r#"{{"requested":"{at}"}}"#).into_bytes()
    );
    assert_eq!(full_bundle_requested(&replay, &at).await, json!(at));

    let later = "2026-01-01T00:10:00.000Z";
    set_time(&replay.clock, later);
    let answer = keys_call(&replay, "wallet", "POST", "wallet", Vec::new(), later).await;
    assert_eq!(body(&answer), json!({ "requested": at }));
    assert_eq!(full_bundle_requested(&replay, later).await, json!(at));

    // A part for epoch 2 alone doesn't cover epoch 1; the second does.
    store_parts(&replay, &[(2, 2)], 41, later).await;
    assert_eq!(full_bundle_requested(&replay, later).await, json!(at));
    store_parts(&replay, &[(1, 1)], 42, later).await;
    assert_eq!(full_bundle_requested(&replay, later).await, Value::Null);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_request_has_an_empty_body() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let answer = keys_call(&replay, "wallet", "POST", "wallet", b"{}".to_vec(), &at).await;
    assert_eq!(code(&answer), (400, json!("bad_request")));
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");
    assert_eq!(full_bundle_requested(&replay, &at).await, Value::Null);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_seq_follows_the_part_stored() {
    // An identical part again is a no-op and keeps its `seq` (Switch wire 6.4); a part
    // spanning both ranges replaces them, and answers its own `seq` (6.2).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    store_parts(&replay, &[(1, 1), (2, 2)], 41, &at).await;
    let seqs = |answer: &SwitchResponse| {
        body(answer)["bundles"]
            .as_array()
            .expect("bundles")
            .iter()
            .map(|part| {
                (
                    part["first_epoch"].as_u64().expect("first"),
                    part["last_epoch"].as_u64().expect("last"),
                    part["seq"].as_u64().expect("seq"),
                )
            })
            .collect::<Vec<_>>()
    };
    let before = keys_call(&replay, "wallet", "GET", "wallet", Vec::new(), &at).await;
    assert_eq!(seqs(&before), [(1, 1, 10), (2, 2, 11)]);
    store_parts(&replay, &[(1, 2)], 42, &at).await;
    let after = keys_call(&replay, "wallet", "GET", "wallet", Vec::new(), &at).await;
    assert_eq!(seqs(&after), [(1, 2, 12)]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_request_takes_the_service_time() {
    // The request records the service's stamped time, not its own `Switch-Timestamp`
    // (Switch wire 7.4.11, 7.3).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let now = "2026-01-01T00:20:00.000Z";
    set_time(&replay.clock, now);
    let signed_at = "2026-01-01T00:18:00.000Z";
    let answer = keys_call(&replay, "wallet", "POST", "wallet", Vec::new(), signed_at).await;
    assert_eq!(body(&answer), json!({ "requested": now }));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_refused_to_an_expired_or_unregistered_app() {
    // Check 3 and the app's standing come first (Switch wire 7.2): an app that hasn't
    // delivered its record isn't current, and an expired certificate is refused.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    for method in ["GET", "POST"] {
        let answer = keys_call(&replay, "executor", method, "executor", Vec::new(), &at).await;
        assert_eq!(code(&answer), (403, json!("not_current")), "{method}");
    }
    let expired = "2026-12-01T00:00:01.000Z";
    set_time(&replay.clock, expired);
    for method in ["GET", "POST"] {
        let answer = keys_call(&replay, "wallet", method, "wallet", Vec::new(), expired).await;
        assert_eq!(code(&answer), (403, json!("cert_expired")), "{method}");
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_staged_account_is_unavailable() {
    // A version naming another switch leaves the account staged here: both calls are `503
    // staged`, after the caller's own checks, with the head (Switch wire 7.3 step 7).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let v3: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json",
        )["signed"]
            .clone(),
    )
    .expect("version 3");
    let mut moved: pubky_switch_core::records::IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("body");
    moved.version = 4;
    moved.inbox.url = "https://other.example".into();
    let key = IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]));
    let moved = pubky_switch_core::records::IdentityDoc::sign(&key, moved)
        .expect("sign")
        .signed()
        .clone();
    let delivery = pubky_switch_core::http::IdentityDelivery {
        identity: moved,
        prev: Some(v3.doc_hash().expect("hash")),
    }
    .to_json();
    let path = format!("/v1/{}/identity", alice_id());
    let delivered = replay
        .service
        .handle(signer_request("PUT", &path, delivery, ms(&at)))
        .await;
    assert_eq!(
        delivered.status,
        200,
        "{}",
        String::from_utf8_lossy(&delivered.body)
    );
    for method in ["GET", "POST"] {
        let answer = keys_call(&replay, "wallet", method, "wallet", Vec::new(), &at).await;
        assert_eq!(code(&answer), (503, json!("staged")), "{method}");
        assert!(header_text(&answer, header::HEAD).is_some(), "{method}");
    }
    replay.db.drop_database().await.expect("drop");
}
