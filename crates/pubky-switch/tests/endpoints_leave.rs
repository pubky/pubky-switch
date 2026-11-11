//! `POST /v1/{id}/apps/{app_id}/leave` (Switch wire 7.4.12, Switch spec 12.3) on `chain.json`'s
//! account: the wallet leaves, the service treats it exactly as a revocation, records the
//! departure flagged for its rotation, and answers with the `leave` transition's proof.
//!
//! The vectors fix the service key and the times; set `PUBKY_SWITCH_TEST_DATABASE_URL` to run
//! them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::http::{Handler, SwitchResponse};
use pubky_switch_core::{
    chain::{SignedHead, TransitionProof},
    enc::app_id_decode,
    http::{IdentityDelivery, header},
    keys::IdentityKey,
    records::{IdentityBody, IdentityDoc, RemovedApp},
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

/// `POST .../apps/<path_app>/leave` from `caller` (a `keys.json` app, or `"signer"`) at `at`.
async fn leave(
    replay: &Replay,
    caller: &str,
    path_app: &str,
    body: Vec<u8>,
    at: &str,
) -> SwitchResponse {
    let path = format!("/v1/{}/apps/{}/leave", alice_id(), app_id(path_app));
    let request = if caller == "signer" {
        signer_request("POST", &path, body, ms(at))
    } else {
        app_request(
            app(&vectors("keys.json"), caller),
            "POST",
            &path,
            body,
            ms(at),
        )
    };
    replay.service.handle(request).await
}

/// The wallet's status in `GET /apps`, read by the signer at `at`.
async fn wallet_status(replay: &Replay, at: &str) -> Value {
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
        .expect("the wallet's status")
        .clone()
}

fn service_key() -> [u8; 32] {
    let keys = vectors("keys.json");
    let service = keys["service_keys"]
        .as_array()
        .expect("service keys")
        .iter()
        .find(|s| s["account"] == alice_id().as_str())
        .expect("alice's service key")
        .clone();
    let public =
        pubky_switch_core::enc::unb64(service["public"].as_str().expect("public")).expect("key");
    public.try_into().expect("32 bytes")
}

#[tokio::test]
async fn test_leave_records_the_departure_and_answers_its_proof() {
    // The answer carries the `leave` transition's proof, naming the wallet, and the head;
    // `GET /apps` shows the departure at the service time, awaiting its rotation (Switch wire
    // 7.4.12, spec 12.3).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = "2026-01-01T00:05:00.000Z";
    set_time(&replay.clock, at);
    let answer = leave(&replay, "wallet", "wallet", Vec::new(), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let identity = hex32(&alice(&vectors("keys.json"))["public_hex"]);
    let answered = body(&answer);
    let proofs = answered["proofs"].as_array().expect("proofs");
    assert_eq!(proofs.len(), 1);
    let signed: SignedDoc = serde_json::from_value(proofs[0].clone()).expect("proof");
    let proof = TransitionProof::verify(&signed, &service_key(), &identity).expect("verifies");
    assert_eq!(proof.body().object, app_id("wallet"));
    let stub = std::str::from_utf8(&proof.body().chain.envelope).expect("stub");
    assert!(stub.contains(r#""item_type":"service""#), "{stub}");
    assert_eq!(proof.body().state["type"], "leave");
    assert_eq!(proof.body().state["app_id"], app_id("wallet").as_str());
    assert_eq!(proof.body().state["at"], at);
    let head = SignedHead::from_value(&answered["head"]).expect("head");
    head.verify(&service_key(), &identity)
        .expect("the head verifies");
    // After the revoke at `seq` 9.
    assert_eq!(head.seq, 10);
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");

    let status = wallet_status(&replay, at).await;
    assert_eq!(status["departed_at"], at);
    assert_eq!(status["revoked_at"], Value::Null);
    assert_eq!(status["current"], false);
    assert_eq!(status["awaiting_rotation"], true);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_leave_again_is_refused_as_not_current() {
    // A departed app is never current again: a second leave is refused when it
    // authenticates, and nothing more is chained (Switch wire 7.2, 7.4.12).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let first = leave(&replay, "wallet", "wallet", Vec::new(), &at).await;
    assert_eq!(
        first.status,
        200,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    let again = leave(&replay, "wallet", "wallet", Vec::new(), &at).await;
    assert_eq!(code(&again), (403, json!("not_current")));
    // The signer's next answer carries the head: still the leave's, at `seq` 10.
    let path = format!("/v1/{}/apps", alice_id());
    let apps = replay
        .service
        .handle(signer_request("GET", &path, Vec::new(), ms(&at)))
        .await;
    let head = SignedHead::from_header(header_text(&apps, header::HEAD).expect("Switch-Head"))
        .expect("head");
    assert_eq!(head.seq, 10);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_leave_only_the_app_itself() {
    // Another own app's path, the signer and an app of another identity: `403
    // permission_missing`, with the head to the account's own callers only; nothing departs.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let answer = leave(&replay, "wallet", "executor", Vec::new(), &at).await;
    assert_eq!(code(&answer), (403, json!("permission_missing")));
    assert!(header_text(&answer, header::HEAD).is_some());
    let answer = leave(&replay, "signer", "wallet", Vec::new(), &at).await;
    assert_eq!(code(&answer), (403, json!("permission_missing")));
    assert!(header_text(&answer, header::HEAD).is_some());
    let path = format!("/v1/{}/apps/{}/leave", alice_id(), app_id("shop"));
    let answer = replay
        .service
        .handle(other_request(
            "shop",
            ORIGIN,
            "POST",
            &path,
            Vec::new(),
            None,
            ms(&at),
        ))
        .await;
    assert_eq!(code(&answer), (403, json!("permission_missing")));
    assert!(header_text(&answer, header::HEAD).is_none());
    assert_eq!(
        wallet_status(&replay, &at).await["departed_at"],
        Value::Null
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_leave_has_an_empty_body() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let answer = leave(&replay, "wallet", "wallet", b"{}".to_vec(), &at).await;
    assert_eq!(code(&answer), (400, json!("bad_request")));
    assert_eq!(
        wallet_status(&replay, &at).await["departed_at"],
        Value::Null
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_leave_rotation_is_done_once_removed_above_its_epoch() {
    // Departed at data epoch 2: the signer's next version moves it to `removed` at data epoch
    // 3, which completes the rotation (Switch wire 7.4.12 `awaiting_rotation`).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let answer = leave(&replay, "wallet", "wallet", Vec::new(), &at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let wallet = app_id_decode(&app_id("wallet")).expect("app id");
    let keys = vectors("keys.json");
    let key = IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let v3: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json",
        )["signed"]
            .clone(),
    )
    .expect("version 3");
    let mut next: IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("identity body");
    next.version = 4;
    next.apps.retain(|listed| listed.app_id != wallet);
    next.removed.push(RemovedApp {
        app_id: wallet,
        distrust_from: ms(&at),
    });
    next.data_epoch = 3;
    let v4 = IdentityDoc::sign(&key, next).expect("sign");
    let held = IdentityDoc::verify(&v3, &key.public()).expect("version 3");
    let delivery = IdentityDelivery {
        identity: v4.signed().clone(),
        prev: Some(held.hash()),
    };
    let path = format!("/v1/{}/identity", alice_id());
    let answer = replay
        .service
        .handle(signer_request("PUT", &path, delivery.to_json(), ms(&at)))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(
        wallet_status(&replay, &at).await["awaiting_rotation"],
        false
    );
    replay.db.drop_database().await.expect("drop");
}
