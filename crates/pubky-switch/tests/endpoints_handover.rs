//! `PUT` and `GET /v1/{id}/handover` (Switch wire 7.4.17) on alice's account: the signer
//! stores a hand-over for a current app, the app fetches it, and the next `identity.json`
//! version drops it.
//!
//! The vectors' switch is at `seq` 41, past what `chain.json` replays here, so their answers
//! are compared byte for byte but for `Switch-Head`, which the answer's signature doesn't
//! cover: that is that switch's head. Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see
//! `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::http::{Handler, SwitchResponse};
use pubky_switch_core::{
    enc::b64,
    http::{IdentityDelivery, header},
    keys::{AppKeys, IdentityKey},
    ops::{OpKind, OpsRequest, sign_batch},
    records::{AppCert, IdentityDoc, Limits, SignerHandover, SignerRecords},
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

fn handover_path() -> String {
    format!("/v1/{}/handover", alice_id())
}

fn body(answer: &SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body)
        .unwrap_or_else(|_| panic!("json: {}", String::from_utf8_lossy(&answer.body)))
}

fn code_of(answer: &SwitchResponse) -> (u16, Value) {
    (answer.status, body(answer)["code"].clone())
}

fn http_case(list: &str, name: &str) -> Value {
    named(&vectors("http.json")[list], name).clone()
}

fn store_request() -> Value {
    http_case(
        "requests",
        "signer: store the hand-over to the phone at the switch",
    )
}

fn fetch_request() -> Value {
    http_case(
        "requests",
        "own app: the phone fetches the hand-over stored for it",
    )
}

/// The answer matches the vector byte for byte, its status, body, server time and
/// signature, but for `Switch-Head`, which is the vectors' switch's (module doc).
fn assert_matches_but_the_head(answer: &SwitchResponse, expected: &Value) {
    let name = expected["name"].as_str().expect("name");
    assert_eq!(
        u64::from(answer.status),
        expected["status"].as_u64().expect("status"),
        "{name}"
    );
    assert_eq!(
        String::from_utf8_lossy(&answer.body),
        expected["body"].as_str().expect("body"),
        "{name}"
    );
    for (name, value) in expected["headers"].as_object().expect("headers") {
        if name != header::HEAD {
            assert_eq!(header_text(answer, name), value.as_str(), "{name}");
        }
    }
    assert!(header_text(answer, header::HEAD).is_some(), "Switch-Head");
}

/// The time the vectors' requests are answered at, which this account's requests are signed
/// at too.
fn vector_time() -> String {
    http_case("responses", "signer: the hand-over stored for the phone")["headers"]
        ["switch-server-time"]
        .as_str()
        .expect("time")
        .to_string()
}

fn document(name: &str) -> SignedDoc {
    serde_json::from_value(named(&vectors("documents.json")["documents"], name)["signed"].clone())
        .expect("document")
}

fn identity_key() -> IdentityKey {
    IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]))
}

/// A batch of `ops` from alice's app `name`, signed with its keys, at `at`.
async fn app_ops(replay: &Replay, name: &str, ops: Vec<OpKind>, batch: u8, at: &str) {
    let keys = vectors("keys.json");
    let me = app(&keys, name);
    let signed = sign_batch(
        &AppKeys::from_secrets(
            hex32(&me["signing_secret_hex"]),
            hex32(&me["bundle_secret_hex"]),
        ),
        &hex32(&alice(&keys)["public_hex"]),
        Some(
            pubky_switch_core::enc::app_id_decode(me["app_id"].as_str().expect("id")).expect("id"),
        ),
        1,
        [batch; 16],
        ops.into_iter().map(|op| (Vec::new(), op)).collect(),
    )
    .expect("batch");
    let answer = replay
        .service
        .handle(app_request(
            me,
            "POST",
            &format!("/v1/{}/ops", alice_id()),
            OpsRequest::new(&signed, None).to_json(),
            ms(at),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{name}: {}",
        String::from_utf8_lossy(&answer.body)
    );
}

/// alice's account after `chain.json` up to `seq` 8, before the phone's revocation, with the
/// phone and the executor registered with the records of `http.json`'s directory: three
/// current apps. The clock is at the vectors' time.
async fn alice_with_three_apps(replay: &Replay) {
    let chain = vectors("chain.json");
    serve_alice(replay).await;
    replay_batch(replay, &chain, &[3, 4]).await;
    // `seq` 5 is the inbox entry's.
    assert_eq!(replay.db.give_out_seq(&alice_id()).await.expect("seq"), 5);
    replay_batch(replay, &chain, &[6]).await;
    replay_batch(replay, &chain, &[7, 8]).await;
    let at = item_time(chain_item(&chain, 8));
    set_time(&replay.clock, &at);
    let directory: Value = serde_json::from_str(
        http_case(
            "responses",
            "app of another identity: directory, known_version in the body",
        )["body"]
            .as_str()
            .expect("body"),
    )
    .expect("json");
    let keys = vectors("keys.json");
    for (name, batch) in [("phone", 101), ("executor", 102)] {
        let id = app(&keys, name)["app_id"].clone();
        let listed = directory["apps"]
            .as_array()
            .expect("apps")
            .iter()
            .find(|listed| listed["app_id"] == id)
            .expect("listed");
        let signed =
            |value: &Value| -> SignedDoc { serde_json::from_value(value.clone()).expect("signed") };
        app_ops(
            replay,
            name,
            vec![
                OpKind::AppPut {
                    record: signed(&listed["record"]),
                },
                OpKind::ReceiveKeyPut {
                    record: signed(&listed["receive_key"]),
                },
            ],
            batch,
            &at,
        )
        .await;
    }
    set_time(&replay.clock, &vector_time());
}

/// A `PUT /handover` from the signer with `body`, at the vectors' time.
async fn put(replay: &Replay, body: Vec<u8>) -> SwitchResponse {
    replay
        .service
        .handle(signer_request(
            "PUT",
            &handover_path(),
            body,
            ms(&vector_time()),
        ))
        .await
}

/// A `GET /handover` from `caller` (a `keys.json` app, or `"signer"`), at the vectors' time.
async fn get(replay: &Replay, caller: &str) -> SwitchResponse {
    let request = if caller == "signer" {
        signer_request("GET", &handover_path(), Vec::new(), ms(&vector_time()))
    } else {
        app_request(
            app(&vectors("keys.json"), caller),
            "GET",
            &handover_path(),
            Vec::new(),
            ms(&vector_time()),
        )
    };
    replay.service.handle(request).await
}

/// The vector's `PUT` body: the hand-over to the phone.
fn phone_body() -> Vec<u8> {
    pubky_switch_core::enc::unb64(store_request()["body_b64"].as_str().expect("body")).expect("b64")
}

/// A hand-over of alice's records, version 3, to the executor.
fn executor_body() -> Vec<u8> {
    let key = identity_key();
    let alice = key.public();
    let doc = IdentityDoc::verify(&document("alice identity.json"), &alice).expect("version 3");
    let certs: Vec<AppCert> = [
        "wallet certificate",
        "phone certificate",
        "executor certificate",
    ]
    .iter()
    .map(|name| AppCert::verify(&document(name), &alice).expect("certificate"))
    .collect();
    let executor = certs[2].clone();
    let records = SignerRecords::new(
        IdentityKey::from_secret(key.secret_bytes()),
        doc,
        &[],
        &certs,
        Limits::default(),
        &[],
        None,
    )
    .expect("records");
    let handover = SignerHandover::seal(&key, &executor, &records).expect("sealed");
    json!({
        "app_id": pubky_switch_core::enc::zbase32_encode(&executor.app_id()),
        "handover": handover,
    })
    .to_string()
    .into_bytes()
}

/// A hand-over signed for the phone, sealed to the executor's certified bundle key.
fn sealed_to_the_executor() -> Vec<u8> {
    let alice = identity_key().public();
    let executor = AppCert::verify(&document("executor certificate"), &alice).expect("certificate");
    let phone = pubky_switch_core::enc::app_id_decode(
        app(&vectors("keys.json"), "phone")["app_id"]
            .as_str()
            .expect("id"),
    )
    .expect("id");
    let handover = SignerHandover::seal_parts_with(
        &identity_key(),
        &phone,
        &executor.bundle_key(),
        &[b"a part"],
        &[pubky_switch_core::envelope::FixedRandomness {
            content_key: [1; 32],
            nonce: [2; 24],
            ikm_e: [3; 32],
        }],
    )
    .expect("sealed");
    json!({
        "app_id": pubky_switch_core::enc::zbase32_encode(&phone),
        "handover": handover,
    })
    .to_string()
    .into_bytes()
}

#[tokio::test]
async fn test_handover_vectors_store_and_fetch() {
    // http.json's store and fetch: the signer stores the hand-over to the phone, answered
    // with the target and the parts and a head; the phone fetches the body as stored
    // (Switch wire 7.4.17).
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    let stored = replay
        .service
        .handle(vector_request(&store_request()))
        .await;
    assert_matches_but_the_head(
        &stored,
        &http_case("responses", "signer: the hand-over stored for the phone"),
    );
    let expected = http_case(
        "responses",
        "own app: the hand-over the switch stores for the phone",
    );
    set_time(
        &replay.clock,
        expected["headers"]["switch-server-time"]
            .as_str()
            .expect("time"),
    );
    let fetched = replay
        .service
        .handle(vector_request(&fetch_request()))
        .await;
    assert_matches_but_the_head(&fetched, &expected);
    assert_eq!(fetched.body, phone_body());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_handover_only_the_target_and_the_signer_read_it() {
    // Another own app gets the `404` of a call when none is held, so it learns nothing of a
    // hand-over to another; an app of another identity is refused; only the signer stores
    // (Switch wire 7.4.17, 7.4).
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    assert_eq!(put(&replay, phone_body()).await.status, 200);
    let signer = get(&replay, "signer").await;
    assert_eq!(signer.status, 200);
    assert_eq!(signer.body, phone_body());
    for other in ["wallet", "executor"] {
        let answer = get(&replay, other).await;
        assert_eq!(code_of(&answer), (404, json!("not_found")), "{other}");
        assert!(header_text(&answer, header::HEAD).is_some());
    }
    let shop = replay
        .service
        .handle(other_request(
            "shop",
            ORIGIN,
            "GET",
            &handover_path(),
            Vec::new(),
            None,
            ms(&vector_time()),
        ))
        .await;
    assert_eq!(code_of(&shop), (403, json!("permission_missing")));
    let shop_put = replay
        .service
        .handle(other_request(
            "shop",
            ORIGIN,
            "PUT",
            &handover_path(),
            phone_body(),
            None,
            ms(&vector_time()),
        ))
        .await;
    assert_eq!(code_of(&shop_put), (403, json!("permission_missing")));
    let from_app = replay
        .service
        .handle(app_request(
            app(&vectors("keys.json"), "wallet"),
            "PUT",
            &handover_path(),
            phone_body(),
            ms(&vector_time()),
        ))
        .await;
    assert_eq!(code_of(&from_app), (403, json!("permission_missing")));
    assert!(header_text(&from_app, header::HEAD).is_some());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_handover_none_held_is_not_found() {
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    assert_eq!(
        code_of(&get(&replay, "signer").await),
        (404, json!("not_found"))
    );
    assert_eq!(
        code_of(&get(&replay, "phone").await),
        (404, json!("not_found"))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_handover_target_not_current_is_conflict() {
    // The phone holds a record but is revoked, so it isn't current: `409 conflict`, before
    // any check of the envelopes or the signature, and nothing kept; the hand-over held
    // for it before is refused to it as it is to every app that isn't current (Switch wire
    // 7.4.17, 7.2, spec 3.4).
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    assert_eq!(put(&replay, phone_body()).await.status, 200);
    let phone = app(&vectors("keys.json"), "phone")["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    let revoked = replay
        .service
        .handle(signer_request(
            "POST",
            &format!("/v1/{}/apps/{phone}/revoke", alice_id()),
            Vec::new(),
            ms(&vector_time()),
        ))
        .await;
    assert_eq!(
        revoked.status,
        200,
        "{}",
        String::from_utf8_lossy(&revoked.body)
    );
    assert_eq!(
        code_of(&put(&replay, phone_body()).await),
        (409, json!("conflict"))
    );
    let mut forged: Value = serde_json::from_slice(&phone_body()).expect("json");
    forged["handover"]["sig"] = json!(b64(&[1u8; 64]));
    assert_eq!(
        code_of(&put(&replay, forged.to_string().into_bytes()).await),
        (409, json!("conflict")),
        "the target first"
    );
    assert_eq!(
        code_of(&get(&replay, "phone").await),
        (403, json!("not_current"))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_handover_target_without_a_record_is_conflict() {
    // Before the executor delivers its record, `chain.json`'s account lists it but holds
    // nothing of it: not current (Switch wire 7.4.17, spec 3.4).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    set_time(&replay.clock, &vector_time());
    assert_eq!(
        code_of(&put(&replay, executor_body()).await),
        (409, json!("conflict"))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_handover_expired_target_is_stored_but_not_served_to_it() {
    // An expired certificate leaves the app current (spec 3.4, Switch wire 3.8): the
    // hand-over is stored, and the target fetches it only once renewed (7.2 check 3).
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    let expired = "2026-12-01T00:00:10.000Z";
    set_time(&replay.clock, expired);
    let stored = replay
        .service
        .handle(signer_request(
            "PUT",
            &handover_path(),
            executor_body(),
            ms(expired),
        ))
        .await;
    assert_eq!(
        stored.status,
        200,
        "{}",
        String::from_utf8_lossy(&stored.body)
    );
    let fetched = replay
        .service
        .handle(app_request(
            app(&vectors("keys.json"), "executor"),
            "GET",
            &handover_path(),
            Vec::new(),
            ms(expired),
        ))
        .await;
    assert_eq!(code_of(&fetched), (403, json!("cert_expired")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_handover_checks_the_form_and_the_signature() {
    // Without opening anything: unknown members, the count, each envelope's one recipient,
    // the target's certified bundle key, and the identity key's signature over the target,
    // the count and the bytes (Switch wire 7.4.17, 3.12). Nothing is kept for any of them.
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    let good: Value = serde_json::from_slice(&phone_body()).expect("json");
    let with = |change: &dyn Fn(&mut Value)| {
        let mut value = good.clone();
        change(&mut value);
        value.to_string().into_bytes()
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("an unknown member", with(&|v| v["x"] = json!(1))),
        (
            "an unknown member in the hand-over",
            with(&|v| v["handover"]["x"] = json!(1)),
        ),
        (
            "no envelope",
            with(&|v| v["handover"]["envelopes"] = json!([])),
        ),
        (
            "one envelope left out",
            with(&|v| {
                v["handover"]["envelopes"]
                    .as_array_mut()
                    .expect("envelopes")
                    .pop();
            }),
        ),
        (
            "another signature",
            with(&|v| v["handover"]["sig"] = json!(b64(&[1u8; 64]))),
        ),
        (
            "an envelope that isn't one, which the signature covers too",
            with(&|v| v["handover"]["envelopes"][0] = json!(b64(b"not an envelope"))),
        ),
        (
            "signed for another target",
            with(&|v| v["app_id"] = app(&vectors("keys.json"), "executor")["app_id"].clone()),
        ),
        (
            "129 envelopes",
            with(&|v| {
                let first = v["handover"]["envelopes"][0].clone();
                v["handover"]["envelopes"] = json!(vec![first; 129]);
            }),
        ),
        // Signed for the phone, but sealed to the executor's bundle key: only the kid
        // check refuses it.
        (
            "sealed to another app's bundle key",
            sealed_to_the_executor(),
        ),
    ];
    for (case, body) in cases {
        let answer = put(&replay, body).await;
        assert_eq!(code_of(&answer), (400, json!("bad_request")), "{case}");
        assert!(header_text(&answer, header::HEAD).is_some(), "{case}");
    }
    assert_eq!(
        code_of(&get(&replay, "signer").await),
        (404, json!("not_found"))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_handover_replaced_by_the_next_put() {
    // One per account: a hand-over to the executor replaces the phone's (Switch wire
    // 7.4.17).
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    assert_eq!(put(&replay, phone_body()).await.status, 200);
    let executor = executor_body();
    let stored = put(&replay, executor.clone()).await;
    assert_eq!(
        stored.status,
        200,
        "{}",
        String::from_utf8_lossy(&stored.body)
    );
    assert_eq!(
        body(&stored)["app_id"],
        app(&vectors("keys.json"), "executor")["app_id"]
    );
    assert_eq!(
        code_of(&get(&replay, "phone").await),
        (404, json!("not_found"))
    );
    assert_eq!(get(&replay, "executor").await.body, executor);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_handover_dropped_at_the_next_version_not_at_a_retry() {
    // The same delivery again takes no new version and keeps the hand-over; the next
    // version drops it, whichever signer delivered it (Switch wire 7.4.17 Deletion).
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    assert_eq!(put(&replay, phone_body()).await.status, 200);
    let alice = identity_key().public();
    let version_1 = document("alice identity.json, first delivery (version 1)");
    let version_3 = document("alice identity.json");
    let path = format!("/v1/{}/identity", alice_id());
    let again = IdentityDelivery {
        identity: version_3.clone(),
        prev: Some(version_1.doc_hash().expect("hash")),
    };
    let retried = replay
        .service
        .handle(signer_request(
            "PUT",
            &path,
            again.to_json(),
            ms(&vector_time()),
        ))
        .await;
    assert_eq!(
        retried.status,
        200,
        "{}",
        String::from_utf8_lossy(&retried.body)
    );
    assert_eq!(get(&replay, "phone").await.body, phone_body());
    let held = IdentityDoc::verify(&version_3, &alice).expect("version 3");
    let mut next = held.body().clone();
    next.version = 4;
    let next = IdentityDoc::sign(&identity_key(), next).expect("sign");
    let delivered = replay
        .service
        .handle(signer_request(
            "PUT",
            &path,
            IdentityDelivery {
                identity: next.signed().clone(),
                prev: Some(held.hash()),
            }
            .to_json(),
            ms(&vector_time()),
        ))
        .await;
    assert_eq!(
        delivered.status,
        200,
        "{}",
        String::from_utf8_lossy(&delivered.body)
    );
    assert_eq!(
        code_of(&get(&replay, "phone").await),
        (404, json!("not_found"))
    );
    assert_eq!(
        code_of(&get(&replay, "signer").await),
        (404, json!("not_found"))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_handover_staged_account_is_unavailable() {
    // An account that doesn't serve yet takes no hand-over (Switch wire 7.3 step 7).
    let Some(replay) = replay().await else { return };
    let enrolled = http_case(
        "responses",
        "signer: enrollment answer, signed with the new account's key",
    );
    set_time(
        &replay.clock,
        enrolled["headers"]["switch-server-time"]
            .as_str()
            .expect("time"),
    );
    let enrollment = vector_request(&http_case("requests", "signer: enrollment"));
    assert_eq!(replay.service.handle(enrollment).await.status, 200);
    let at = enrolled["headers"]["switch-server-time"]
        .as_str()
        .expect("time")
        .to_string();
    let answer = replay
        .service
        .handle(signer_request(
            "PUT",
            &handover_path(),
            phone_body(),
            ms(&at),
        ))
        .await;
    assert_eq!(code_of(&answer), (503, json!("staged")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_handover_fetched_as_stored_byte_for_byte() {
    // The body is kept as received, whatever its member order or whitespace: the target
    // checks the hand-over it fetches against what the signer sent (Switch wire 7.4.17).
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    let value: Value = serde_json::from_slice(&phone_body()).expect("json");
    let reordered = format!(
        "{{ \"handover\" : {} ,\n \"app_id\" : {} }}",
        value["handover"], value["app_id"]
    )
    .into_bytes();
    assert_eq!(put(&replay, reordered.clone()).await.status, 200);
    assert_eq!(get(&replay, "phone").await.body, reordered);
    replay.db.drop_database().await.expect("drop");
}
