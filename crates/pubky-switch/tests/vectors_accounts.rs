//! The account vectors of `spec/vectors`, replayed on the service, byte for byte: the
//! enrollment and its answer, the first `identity.json` delivery and version 3 as
//! `chain.json` chains them, the public `identity.json` read, and the operator-signed `404`
//! (Switch wire 7.1, 7.4.1, 7.4.2, 7.4.15).
//!
//! The vectors fix the service and operator keys and the times; the service gets them
//! through `keys::FixedKeys` and a manual clock. Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run
//! them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used)]

mod support;

use pubky_switch::http::{Handler, SwitchResponse};
use pubky_switch_core::{
    chain::{SignedHead, TransitionProof},
    enc::{b64, pubky_key, unb64},
    http::{IdentityDelivery, header},
    sig::SignedDoc,
};
use serde_json::Value;
use support::*;

/// The delivery answer's proof and head, checked against the chain item `chain.json` gives
/// for it.
fn assert_chained(
    response: &SwitchResponse,
    item: &Value,
    service_key: &[u8; 32],
    identity: &[u8; 32],
) {
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let body: Value = serde_json::from_slice(&response.body).expect("json");
    let proofs = body["proofs"].as_array().expect("proofs");
    assert_eq!(proofs.len(), 1);
    let signed: SignedDoc = serde_json::from_value(proofs[0].clone()).expect("proof");
    let proof =
        TransitionProof::verify(&signed, service_key, identity).expect("the proof verifies");
    assert_eq!(proof.body().object, "identity");
    assert_eq!(
        proof.body().chain.envelope,
        item["envelope_json"].as_str().expect("envelope").as_bytes(),
        "the stub's envelope is chain.json's"
    );
    assert_eq!(
        b64(&proof.body().chain.chain_hash),
        item["chain_hash"].as_str().expect("hash")
    );
    let head = SignedHead::from_value(&body["head"]).expect("head");
    head.verify(service_key, identity)
        .expect("the head verifies");
    assert_eq!(head.seq, item["seq"].as_u64().expect("seq"));
    assert_eq!(
        b64(&head.chain_hash),
        item["chain_hash"].as_str().expect("hash")
    );
    assert_eq!(
        header_text(response, header::HEAD),
        Some(head.to_header().as_str())
    );
}

#[tokio::test]
async fn test_vectors_accounts_replay() {
    let Some(replay) = replay().await else { return };
    let http = vectors("http.json");
    let chain = vectors("chain.json");
    let documents = vectors("documents.json");
    let keys = vectors("keys.json");
    let alice = alice(&keys);
    let alice_id = alice["pubky_id"].as_str().expect("id");
    let alice_key = pubky_key(alice_id).expect("key");
    let service_key: [u8; 32] = unb64(keys["service_keys"][0]["public"].as_str().expect("public"))
        .expect("b64")
        .try_into()
        .expect("32 bytes");

    // An unknown account, a request without a signature: the operator key's 404.
    let expected = named(
        &http["responses"],
        "no signature on the request, unknown account: operator key, BLAKE3 of the empty string",
    );
    set_time(
        &replay.clock,
        expected["headers"]["switch-server-time"]
            .as_str()
            .expect("time"),
    );
    let unknown = request("GET", &format!("/v1/{alice_id}/feed"), &[], Vec::new());
    assert_matches(&replay.service.handle(unknown).await, expected);

    // The enrollment, answered with the new account's key.
    let expected = named(
        &http["responses"],
        "signer: enrollment answer, signed with the new account's key",
    );
    set_time(
        &replay.clock,
        expected["headers"]["switch-server-time"]
            .as_str()
            .expect("time"),
    );
    let enrollment = vector_request(named(&http["requests"], "signer: enrollment"));
    assert_matches(&replay.service.handle(enrollment).await, expected);

    // The first delivery, version 1, chained at seq 1.
    let items = chain["items"].as_array().expect("items");
    let first = &items[0];
    let first_time: Value =
        serde_json::from_str(first["envelope_json"].as_str().expect("envelope")).expect("json");
    set_time(
        &replay.clock,
        first_time["server_time"].as_str().expect("time"),
    );
    let delivery = vector_request(named(&http["requests"], "signer: identity.json delivery"));
    let answer = replay.service.handle(delivery).await;
    assert_chained(&answer, first, &service_key, &alice_key);

    // Version 3, delivered on version 1, chained at seq 2. The request is signed here with
    // alice's fixed identity key, as her signer would sign it.
    let second = &items[1];
    let second_time: Value =
        serde_json::from_str(second["envelope_json"].as_str().expect("envelope")).expect("json");
    let at = second_time["server_time"].as_str().expect("time");
    set_time(&replay.clock, at);
    let version_1: SignedDoc = serde_json::from_value(
        named(
            &documents["documents"],
            "alice identity.json, first delivery (version 1)",
        )["signed"]
            .clone(),
    )
    .expect("version 1");
    let version_3: SignedDoc = serde_json::from_value(
        named(&documents["documents"], "alice identity.json")["signed"].clone(),
    )
    .expect("version 3");
    let body = IdentityDelivery {
        identity: version_3,
        prev: Some(version_1.doc_hash().expect("hash")),
    }
    .to_json();
    let path = format!("/v1/{alice_id}/identity");
    let delivery = signer_request("PUT", &path, body, ms(at));
    let answer = replay.service.handle(delivery).await;
    assert_chained(&answer, second, &service_key, &alice_key);

    // The public read of version 3: unsigned, and the same answer for every reader.
    let expected = named(
        &http["responses"],
        "anyone: the public identity.json read, unsigned, answered with no head",
    );
    set_time(
        &replay.clock,
        expected["headers"]["switch-server-time"]
            .as_str()
            .expect("time"),
    );
    let read = request("GET", &path, &[], Vec::new());
    assert_matches(&replay.service.handle(read).await, expected);

    replay.db.drop_database().await.expect("drop");
}
