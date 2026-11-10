//! `GET /v1/{id}/apps` (Switch wire 7.4.12) on `chain.json`'s account, and the kept proofs'
//! service keys a delivery must keep (3.3 "Service keys").
//!
//! The vectors fix the service key and the times; set `PUBKY_SWITCH_TEST_DATABASE_URL` to run
//! them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::http::{Handler, SwitchResponse};
use pubky_switch_core::{
    enc::b64,
    http::{IdentityDelivery, header},
    keys::IdentityKey,
    ops::{OpKind, SignedOp},
    records::{AppRecord, IdentityBody, IdentityDoc, RemovedApp},
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

fn revoke_time() -> String {
    item_time(chain_item(&vectors("chain.json"), 9))
}

async fn get_apps(replay: &Replay, caller: &str, at: &str) -> SwitchResponse {
    let path = format!("/v1/{}/apps", alice_id());
    let request = if caller == "signer" {
        signer_request("GET", &path, Vec::new(), ms(at))
    } else {
        let keys = vectors("keys.json");
        app_request(app(&keys, caller), "GET", &path, Vec::new(), ms(at))
    };
    replay.service.handle(request).await
}

fn body(answer: &SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body)
        .unwrap_or_else(|_| panic!("json: {}", String::from_utf8_lossy(&answer.body)))
}

fn status<'a>(answer: &'a Value, name: &str) -> &'a Value {
    let keys = vectors("keys.json");
    let id = app(&keys, name)["app_id"].as_str().expect("id").to_string();
    answer["apps"]
        .as_array()
        .expect("apps")
        .iter()
        .find(|status| status["app_id"] == id.as_str())
        .unwrap_or_else(|| panic!("no status for {name}"))
}

fn held_doc(name: &str) -> SignedDoc {
    serde_json::from_value(named(&vectors("documents.json")["documents"], name)["signed"].clone())
        .expect("document")
}

/// alice's version 3 with `change` applied, as version 4, signed by her identity key.
fn version_4(change: impl FnOnce(&mut IdentityBody)) -> SignedDoc {
    let mut body: IdentityBody =
        serde_json::from_slice(&held_doc("alice identity.json").body_bytes().expect("body"))
            .expect("identity body");
    body.version = 4;
    change(&mut body);
    let key = IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]));
    IdentityDoc::sign(&key, body)
        .expect("sign")
        .signed()
        .clone()
}

async fn deliver(replay: &Replay, doc: SignedDoc, at: &str) -> SwitchResponse {
    let body = IdentityDelivery {
        identity: doc,
        prev: Some(held_doc("alice identity.json").doc_hash().expect("hash")),
    }
    .to_json();
    let path = format!("/v1/{}/identity", alice_id());
    replay
        .service
        .handle(signer_request("PUT", &path, body, ms(at)))
        .await
}

#[tokio::test]
async fn test_apps_after_the_chain() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let chain = vectors("chain.json");
    let at = revoke_time();
    let answer = get_apps(&replay, "signer", &at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    // Signed at the service time, with the head, like every answer to the signer.
    assert_eq!(header_text(&answer, header::SERVER_TIME), Some(at.as_str()));
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");
    let apps = body(&answer);
    assert_eq!(
        apps["identity"],
        serde_json::to_value(held_doc("alice identity.json")).expect("doc")
    );
    assert_eq!(apps["recovery"], Value::Null);
    // The record's write and the live claim's attempt keep proofs of generation 1.
    assert_eq!(apps["proof_generations"], json!([1]));
    // The three apps version 3 lists, by App ID bytes: phone, executor, wallet.
    let order: Vec<&str> = apps["apps"]
        .as_array()
        .expect("apps")
        .iter()
        .map(|status| status["app_id"].as_str().expect("id"))
        .collect();
    let keys = vectors("keys.json");
    let id = |name: &str| app(&keys, name)["app_id"].as_str().expect("id").to_string();
    assert_eq!(order, vec![id("phone"), id("executor"), id("wallet")]);

    let wallet = status(&apps, "wallet");
    let op = SignedOp::peek(
        &serde_json::from_value::<SignedDoc>(chain_item(&chain, 3)["item"].clone()).expect("op"),
    )
    .expect("op");
    let OpKind::AppPut { record } = &op.body().kind else {
        panic!("seq 3 is the wallet's app.put");
    };
    let alice_key = hex32(&alice(&keys)["public_hex"]);
    let record = AppRecord::verify(record, &alice_key).expect("record");
    let attempt = SignedOp::peek(
        &serde_json::from_value::<SignedDoc>(chain_item(&chain, 7)["item"].clone()).expect("op"),
    )
    .expect("op");
    let attempt_body: Value =
        serde_json::from_slice(&attempt.signed().body_bytes().expect("body")).expect("json");
    assert_eq!(
        *wallet,
        json!({
            "app_id": id("wallet"),
            "current": true,
            // Its last request: the attempt's batch.
            "last_seen": item_time(chain_item(&chain, 7)),
            "revoked_at": null,
            "departed_at": null,
            "awaiting_rotation": false,
            "open_attempts": [{
                "claim_key": attempt_body["claim_key"],
                "attempt_id": attempt_body["attempt_id"],
                "outcome": "open",
            }],
            "unread_entries": 0,
            "sole_target_unread": 0,
            "record_cert": b64(&record.cert().hash()),
            "record_at": item_time(chain_item(&chain, 3)),
            "lagging": false,
            // Listed first by version 1, at data epoch 1, with no key bundle part since.
            "keys_through": 1,
            "full_bundle_requested": null,
            "bundle_ranges": [],
            "cert_expires_at": pubky_switch_core::time::rfc3339(record.cert().expires_at()),
        })
    );
    // The phone was revoked at seq 9. Only a departure awaits a rotation (Switch wire
    // 7.4.12): the signer rotates for its own revocations.
    let phone = status(&apps, "phone");
    assert_eq!(phone["current"], false);
    assert_eq!(phone["revoked_at"], json!(at));
    assert_eq!(phone["departed_at"], Value::Null);
    assert_eq!(phone["awaiting_rotation"], false);
    // The executor is listed and never registered: current, with no record.
    let executor = status(&apps, "executor");
    assert_eq!(
        (
            executor["current"].clone(),
            executor["record_cert"].clone(),
            executor["keys_through"].clone(),
            executor["last_seen"].clone(),
        ),
        (json!(true), Value::Null, json!(1), Value::Null)
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_apps_only_the_signer_reads_them() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let answer = get_apps(&replay, "wallet", &revoke_time()).await;
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("permission_missing"))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_apps_revoked_app_moved_to_removed() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let keys = vectors("keys.json");
    let phone =
        pubky_switch_core::enc::app_id_decode(app(&keys, "phone")["app_id"].as_str().expect("id"))
            .expect("app id");
    // The signer moves the revoked phone to removed: it stays revoked and known, no longer
    // current, and the document the answer carries is the new one.
    let moved = version_4(|body| {
        body.apps.retain(|listed| listed.app_id != phone);
        body.removed.push(RemovedApp {
            app_id: phone,
            distrust_from: ms(&at),
        });
        body.data_epoch += 1;
    });
    let answer = deliver(&replay, moved.clone(), &at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let apps = body(&get_apps(&replay, "signer", &at).await);
    assert_eq!(apps["identity"], serde_json::to_value(&moved).expect("doc"));
    let phone = status(&apps, "phone");
    assert_eq!(
        (
            phone["current"].clone(),
            phone["revoked_at"].clone(),
            phone["awaiting_rotation"].clone(),
        ),
        (json!(false), json!(at), json!(false))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_identity_delivery_keeps_the_kept_proofs_service_key() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    // A move to another service that leaves out generation 1's key, which the record's
    // write proof and the live claim's entry proof name: 409 conflict (Switch wire 3.3).
    let moved = version_4(|body| {
        body.inbox.url = "https://other.example".into();
        body.inbox.service_key = [9; 32];
    });
    let answer = deliver(&replay, moved, &revoke_time()).await;
    assert_eq!(
        answer.status,
        409,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let refused = body(&answer);
    assert_eq!(refused["code"], "conflict");
    assert_eq!(refused["current"]["proof_generations"], json!([1]));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_apps_keys_through_rises_once_the_cursor_passes_a_part() {
    use pubky_switch_core::ops::{KeyBundlePut, OpsRequest, Position, sign_batch};
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let keys = vectors("keys.json");
    let chain = vectors("chain.json");
    let alice_key = hex32(&alice(&keys)["public_hex"]);
    let alice = IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let op = SignedOp::peek(
        &serde_json::from_value::<SignedDoc>(chain_item(&chain, 3)["item"].clone()).expect("op"),
    )
    .expect("op");
    let OpKind::AppPut { record } = &op.body().kind else {
        panic!("seq 3 is the wallet's app.put");
    };
    let cert = AppRecord::verify(record, &alice_key)
        .expect("record")
        .cert()
        .clone();
    // The signer stores the wallet's keys of data epoch 2, as seq 10.
    let part = pubky_switch_core::records::seal_bundle_parts(&alice, &cert, 2, 2, &|_| true)
        .expect("bundle")
        .remove(0);
    let batch = sign_batch(
        &alice,
        &alice_key,
        None,
        1,
        [41; 16],
        vec![(
            Vec::new(),
            OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: cert.app_id(),
                bundle: part.bundle,
                first_epoch: 2,
                last_epoch: 2,
            }),
        )],
    )
    .expect("batch");
    let ops = format!("/v1/{}/ops", alice_id());
    let answer = replay
        .service
        .handle(signer_request(
            "POST",
            &ops,
            OpsRequest::new(&batch, None).to_json(),
            ms(&at),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let apps = body(&get_apps(&replay, "signer", &at).await);
    let wallet = status(&apps, "wallet");
    assert_eq!(wallet["bundle_ranges"], json!([[2, 2]]));
    // The wallet's cursor hasn't passed the part yet.
    assert_eq!(wallet["keys_through"], 1);
    let cursor = OpsRequest::new(
        &[],
        Some(Position {
            generation: 1,
            seq: 10,
        }),
    )
    .to_json();
    let answer = replay
        .service
        .handle(app_request(
            app(&keys, "wallet"),
            "POST",
            &ops,
            cursor,
            ms(&at),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let apps = body(&get_apps(&replay, "signer", &at).await);
    assert_eq!(status(&apps, "wallet")["keys_through"], 2);
    replay.db.drop_database().await.expect("drop");
}
