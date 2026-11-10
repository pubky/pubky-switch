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
    // Each app's own open attempts only: the wallet's attempt isn't the others'.
    assert_eq!(executor["open_attempts"], json!([]));
    assert_eq!(phone["open_attempts"], json!([]));
    // Never cached.
    assert_eq!(header_text(&answer, "cache-control"), Some("no-store"));
    // Written in the order of the wire's tables (Switch wire 7.4.12).
    let text = String::from_utf8(answer.body.clone()).expect("utf-8");
    let at = |member: &str| {
        text.find(&format!("\"{member}\":"))
            .unwrap_or_else(|| panic!("no {member}"))
    };
    let members = [
        "apps",
        "app_id",
        "current",
        "last_seen",
        "revoked_at",
        "departed_at",
        "awaiting_rotation",
        "open_attempts",
        "unread_entries",
        "sole_target_unread",
        "record_cert",
        "record_at",
        "lagging",
        "keys_through",
        "full_bundle_requested",
        "bundle_ranges",
        "cert_expires_at",
    ];
    for pair in members.windows(2) {
        assert!(at(pair[0]) < at(pair[1]), "{} before {}", pair[0], pair[1]);
    }
    assert!(text.rfind("\"cert_expires_at\":").expect("last") < at("identity"));
    assert!(at("identity") < at("recovery") && at("recovery") < at("proof_generations"));
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
    // A key change in place: generation 2 under a new key, leaving out generation 1's,
    // which the record's write proof and the live claim's entry proof name: 409 conflict
    // (Switch wire 3.3), before anything about the new generation is judged.
    let moved = version_4(|body| {
        body.generation = 2;
        body.inbox.service_key = [9; 32];
        body.service_keys.clear();
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
    // One seq before the part's still hasn't.
    let before = OpsRequest::new(
        &[],
        Some(Position {
            generation: 1,
            seq: 9,
        }),
    )
    .to_json();
    let answer = replay
        .service
        .handle(app_request(
            app(&keys, "wallet"),
            "POST",
            &ops,
            before,
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
    assert_eq!(status(&apps, "wallet")["keys_through"], 1);
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

#[tokio::test]
async fn test_identity_vector_leaving_out_a_kept_proofs_key() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    // http.json's delivery at generation 2 without generation 1's service key. The vector's
    // switch is at seq 41; here the record and claim of chain.json keep generation 1's
    // proofs, and the kept keys are checked first, so the answer is the vector's 409 with
    // its current, compared as values (its message and head are that switch's).
    let http = vectors("http.json");
    let request = named(
        &http["requests"],
        "signer: identity.json at generation 2 that leaves out generation 1's service key",
    );
    let expected = named(
        &http["responses"],
        "signer: 409 conflict, a needed service key left out, current.proof_generations",
    );
    set_time(
        &replay.clock,
        expected["headers"]["switch-server-time"]
            .as_str()
            .expect("time"),
    );
    let answer = replay.service.handle(vector_request(request)).await;
    let expected_body: Value =
        serde_json::from_str(expected["body"].as_str().expect("body")).expect("json");
    assert_eq!(
        answer.status,
        409,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let refused = body(&answer);
    assert_eq!(
        (refused["code"].clone(), refused["current"].clone()),
        (
            expected_body["code"].clone(),
            expected_body["current"].clone()
        )
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_apps_signature_covers_the_body_and_time() {
    use pubky_switch_core::enc::unb64;
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let request = signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&at),
    );
    let request_signature: [u8; 64] = unb64(
        request
            .headers
            .get(header::SIGNATURE)
            .and_then(|value| value.to_str().ok())
            .expect("signature"),
    )
    .expect("b64")
    .try_into()
    .expect("64");
    let answer = replay.service.handle(request).await;
    let signature: [u8; 64] = unb64(header_text(&answer, header::SERVICE_SIGNATURE).expect("sig"))
        .expect("b64")
        .try_into()
        .expect("64");
    let time = header_text(&answer, header::SERVER_TIME)
        .expect("time")
        .to_string();
    let keys = vectors("keys.json");
    let service = keys["service_keys"]
        .as_array()
        .expect("keys")
        .iter()
        .find(|key| key["seed_label"] == "service/alice")
        .expect("alice's service key");
    let key: [u8; 32] = unb64(service["public"].as_str().expect("public"))
        .expect("b64")
        .try_into()
        .expect("32");
    let verify = |time: &str, body: &[u8]| {
        pubky_switch_core::http::verify_response(
            &key,
            200,
            Some(&request_signature),
            time,
            body,
            &signature,
        )
    };
    assert!(verify(&time, &answer.body).is_ok());
    // Another byte of the document, or another time: it no longer verifies.
    let mut tampered = answer.body.clone();
    let at_identity = tampered
        .windows(10)
        .position(|w| w == b"\"identity\"")
        .expect("identity")
        + 14;
    tampered[at_identity] ^= 1;
    assert!(verify(&time, &tampered).is_err());
    assert!(verify("2026-01-01T00:00:00.000Z", &answer.body).is_err());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_apps_current_outlives_the_certificate() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let apps = body(&get_apps(&replay, "signer", &revoke_time()).await);
    let expires = status(&apps, "wallet")["cert_expires_at"]
        .as_str()
        .expect("expiry")
        .to_string();
    // At its certificate's expiry the wallet is still current (spec 3.4): listed and
    // neither revoked nor departed, so a renewal brings it back. `cert_expires_at` shows
    // the lapse.
    set_time(&replay.clock, &expires);
    let apps = body(&get_apps(&replay, "signer", &expires).await);
    let wallet = status(&apps, "wallet");
    assert_eq!(
        (wallet["current"].clone(), wallet["cert_expires_at"].clone()),
        (json!(true), json!(expires))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_apps_relisted_app_from_before_listings_stays_unknown() {
    use sqlx::Connection;
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let keys = vectors("keys.json");
    let wallet =
        pubky_switch_core::enc::app_id_decode(app(&keys, "wallet")["app_id"].as_str().expect("id"))
            .expect("app id");
    // As if listed before app_listings existed: no row, its first epoch unknown.
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("DELETE FROM app_listings WHERE app_id = $1")
        .bind(wallet.as_slice())
        .execute(&mut conn)
        .await
        .expect("delete");
    // Dropped from apps at epoch 3, then listed again at epoch 4: still unknown, never 4.
    let v3 = held_doc("alice identity.json");
    let v3_body: IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("identity body");
    let entry = v3_body
        .apps
        .iter()
        .find(|listed| listed.app_id == wallet)
        .copied()
        .expect("listed");
    let v4 = version_4(|body| {
        body.apps.retain(|listed| listed.app_id != wallet);
        body.data_epoch = 3;
    });
    assert_eq!(deliver(&replay, v4.clone(), &at).await.status, 200);
    let mut v5_body: IdentityBody =
        serde_json::from_slice(&v4.body_bytes().expect("body")).expect("identity body");
    v5_body.version = 5;
    v5_body.data_epoch = 4;
    v5_body.apps.push(entry);
    let key = IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let v5 = IdentityDoc::sign(&key, v5_body)
        .expect("sign")
        .signed()
        .clone();
    let delivery = IdentityDelivery {
        identity: v5,
        prev: Some(v4.doc_hash().expect("hash")),
    }
    .to_json();
    let path = format!("/v1/{}/identity", alice_id());
    let answer = replay
        .service
        .handle(signer_request("PUT", &path, delivery, ms(&at)))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let apps = body(&get_apps(&replay, "signer", &at).await);
    assert_eq!(status(&apps, "wallet")["keys_through"], Value::Null);
    replay.db.drop_database().await.expect("drop");
}

/// alice's next version over `prev`, by `change`, delivered at `at`; the new document.
async fn next_version(
    replay: &Replay,
    prev: &SignedDoc,
    at: &str,
    change: impl FnOnce(&mut IdentityBody),
) -> SignedDoc {
    let mut next: IdentityBody =
        serde_json::from_slice(&prev.body_bytes().expect("body")).expect("identity body");
    next.version += 1;
    change(&mut next);
    let key = IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]));
    let doc = IdentityDoc::sign(&key, next)
        .expect("sign")
        .signed()
        .clone();
    let delivery = IdentityDelivery {
        identity: doc.clone(),
        prev: Some(prev.doc_hash().expect("hash")),
    }
    .to_json();
    let path = format!("/v1/{}/identity", alice_id());
    let answer = replay
        .service
        .handle(signer_request("PUT", &path, delivery, ms(at)))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    doc
}

#[tokio::test]
async fn test_apps_departure_rotation_is_done_for_good() {
    use sqlx::Connection;
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let keys = vectors("keys.json");
    let executor = pubky_switch_core::enc::app_id_decode(
        app(&keys, "executor")["app_id"].as_str().expect("id"),
    )
    .expect("app id");
    // The executor departed at data epoch 2 (departures come with leave; seeded here).
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(
        "INSERT INTO kept_app_ids (account_id, app_id, reason, at_ms, data_epoch) \
         VALUES ($1, $2, 'departed', $3, 2)",
    )
    .bind(alice_id())
    .bind(executor.as_slice())
    .bind(i64::try_from(ms(&at)).expect("time"))
    .execute(&mut conn)
    .await
    .expect("departure");
    let awaiting = |apps: &Value| status(apps, "executor")["awaiting_rotation"].clone();
    assert_eq!(
        awaiting(&body(&get_apps(&replay, "signer", &at).await)),
        json!(true)
    );
    // Dropped from apps at a higher data epoch, in neither list: not a rotation.
    let v3 = held_doc("alice identity.json");
    let v4 = next_version(&replay, &v3, &at, |body| {
        body.apps.retain(|listed| listed.app_id != executor);
        body.data_epoch = 3;
    })
    .await;
    assert_eq!(
        awaiting(&body(&get_apps(&replay, "signer", &at).await)),
        json!(true)
    );
    // In removed, but at the departure's own data epoch, 2, which the service accepts
    // though it lowers data_epoch (Switch wire 3.3): not a rotation either.
    let v5 = next_version(&replay, &v4, &at, |body| {
        body.removed.push(RemovedApp {
            app_id: executor,
            distrust_from: ms(&at),
        });
        body.data_epoch = 2;
    })
    .await;
    assert_eq!(
        awaiting(&body(&get_apps(&replay, "signer", &at).await)),
        json!(true)
    );
    // In removed above it: done, and it stays done though a later version lowers
    // data_epoch again.
    let v6 = next_version(&replay, &v5, &at, |body| body.data_epoch = 3).await;
    assert_eq!(
        awaiting(&body(&get_apps(&replay, "signer", &at).await)),
        json!(false)
    );
    next_version(&replay, &v6, &at, |body| body.data_epoch = 1).await;
    assert_eq!(
        awaiting(&body(&get_apps(&replay, "signer", &at).await)),
        json!(false)
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_apps_refusals_to_other_callers() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    // An own app that verified: 403 permission_missing, with the head.
    let answer = get_apps(&replay, "wallet", &at).await;
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("permission_missing"))
    );
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");
    // An app of another identity: its certificate first, without one 400; then 403, with
    // no head.
    let keys = vectors("keys.json");
    let shop = app(&keys, "shop");
    let key = ed25519_dalek::SigningKey::from_bytes(&hex32(&shop["signing_secret_hex"]));
    let request = signed_request(
        &key,
        shop["identity"].as_str().expect("identity"),
        Some(shop["app_id"].as_str().expect("app")),
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&at),
    );
    assert_eq!(replay.service.handle(request).await.status, 400);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_apps_lists_an_enrollment_named_app_id_as_revoked() {
    use pubky_switch_core::{
        enc::unb64,
        records::{Enrollment, EnrollmentBody},
    };
    let Some(replay) = replay().await else { return };
    let enrolled_at = "2026-01-01T00:00:00.000Z";
    set_time(&replay.clock, enrolled_at);
    // The vectors' enrollment, naming one App ID in revoked_apps.
    let named_id = [0x11u8; 16];
    let http = vectors("http.json");
    let vector = named(&http["requests"], "signer: enrollment");
    let body_value: Value =
        serde_json::from_slice(&unb64(vector["body_b64"].as_str().expect("body")).expect("b64"))
            .expect("json");
    let signed: SignedDoc =
        serde_json::from_value(body_value["enrollment"].clone()).expect("enrollment");
    let mut fields: EnrollmentBody =
        serde_json::from_slice(&signed.body_bytes().expect("body")).expect("fields");
    fields.identity_doc = None;
    fields.revoked_apps = Some(vec![named_id]);
    let key = IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]));
    let enrollment = Enrollment::sign(&key, fields).expect("sign");
    let request = serde_json::to_vec(&json!({ "enrollment": enrollment.signed() })).expect("body");
    let answer = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            request,
            ms(enrolled_at),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let later = "2026-01-01T00:01:00.000Z";
    set_time(&replay.clock, later);
    let delivery = IdentityDelivery {
        identity: held_doc("alice identity.json, first delivery (version 1)"),
        prev: None,
    }
    .to_json();
    let path = format!("/v1/{}/identity", alice_id());
    let answer = replay
        .service
        .handle(signer_request("PUT", &path, delivery, ms(later)))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let apps = body(&get_apps(&replay, "signer", later).await);
    let id = pubky_switch_core::enc::zbase32_encode(&named_id);
    let named_status = apps["apps"]
        .as_array()
        .expect("apps")
        .iter()
        .find(|status| status["app_id"] == id.as_str())
        .expect("the enrollment-named App ID is listed");
    assert_eq!(
        (
            named_status["current"].clone(),
            named_status["revoked_at"].clone(),
            named_status["awaiting_rotation"].clone(),
        ),
        (json!(false), json!(enrolled_at), json!(false))
    );
    // No record or claim yet: no generation's proofs are kept.
    assert!(apps.get("proof_generations").is_none());
    replay.db.drop_database().await.expect("drop");
}
