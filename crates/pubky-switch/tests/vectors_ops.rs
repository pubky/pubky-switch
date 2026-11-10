//! The batches of `chain.json`, replayed on the service through `POST /ops`, byte for byte
//! (Switch wire 6.4 to 6.6): the wallet's registration batch (`app.put` and the first
//! `receive_key.put`, seqs 3 and 4), the record's create (seq 6) and the batch with a claim
//! attempt and the record's update under a condition (seqs 7 and 8). The inbox entry at seq
//! 5 takes its seq without a chain item. Each answer's proofs are `chain.json`'s transition
//! proofs, and its head the chain head there.
//!
//! The vectors fix the service key and the times; set `PUBKY_SWITCH_TEST_DATABASE_URL` to run
//! them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::http::Handler;
use pubky_switch_core::{
    ops::{OpsRequest, SignedOp},
    sig::SignedDoc,
};
use serde_json::Value;
use support::*;

#[tokio::test]
async fn test_vectors_ops_replay_chain() {
    let Some(replay) = replay().await else { return };
    let chain = vectors("chain.json");
    let keys = vectors("keys.json");
    let alice_id = alice(&keys)["pubky_id"].as_str().expect("id").to_string();
    serve_alice(&replay).await;
    replay_batch(&replay, &chain, &[3, 4]).await;
    // The inbox entry at seq 5 takes a seq and no chain item.
    assert_eq!(replay.db.give_out_seq(&alice_id).await.expect("seq"), 5);
    replay_batch(&replay, &chain, &[6]).await;
    replay_batch(&replay, &chain, &[7, 8]).await;

    // The signer revokes the phone: the revoke transition at seq 9 (Switch wire 7.4.12).
    let revoke = chain_item(&chain, 9);
    let at = item_time(revoke);
    set_time(&replay.clock, &at);
    let phone = app(&keys, "phone")["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    let path = format!("/v1/{alice_id}/apps/{phone}/revoke");
    let answer = replay
        .service
        .handle(signer_request("POST", &path, Vec::new(), ms(&at)))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let body: Value = serde_json::from_slice(&answer.body).expect("json");
    assert_eq!(
        body["proofs"],
        serde_json::json!([proof_at(&chain, 9)]),
        "the revoke proof"
    );
    assert_eq!(body["head"]["chain_hash"], revoke["chain_hash"]);
    // Again: revoked already, no proof.
    let again = replay
        .service
        .handle(signer_request("POST", &path, Vec::new(), ms(&at)))
        .await;
    let body: Value = serde_json::from_slice(&again.body).expect("json");
    assert_eq!(
        (again.status, body["proofs"].clone()),
        (200, serde_json::json!([]))
    );

    // The wallet deletes the record: seq 10, its proof showing deleted (Switch wire 6.2).
    let delete = &chain["record_delete"];
    let at = item_time(&delete["item"]);
    set_time(&replay.clock, &at);
    let signed: SignedDoc = serde_json::from_value(delete["item"]["item"].clone()).expect("op");
    let body = OpsRequest::new(&[SignedOp::peek(&signed).expect("op")], None).to_json();
    let wallet = app(&keys, "wallet");
    let request = app_request(
        wallet,
        "POST",
        &format!("/v1/{alice_id}/ops"),
        body,
        ms(&at),
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let body: Value = serde_json::from_slice(&answer.body).expect("json");
    assert_eq!(
        body["proofs"],
        serde_json::json!([delete["transition_proof"]["signed"]]),
        "the delete's proof"
    );
    assert_eq!(body["head"]["chain_hash"], delete["item"]["chain_hash"]);
    replay.db.drop_database().await.expect("drop");
}

/// Post the `POST /ops` body `body` from `writer` (`"signer"` or an app of `keys.json`) at
/// `at`: the status and the answer.
async fn post_body(replay: &Replay, writer: &str, body: Vec<u8>, at: &str) -> (u16, Value) {
    let keys = vectors("keys.json");
    let alice_id = alice(&keys)["pubky_id"].as_str().expect("id").to_string();
    let path = format!("/v1/{alice_id}/ops");
    let request = if writer == "signer" {
        signer_request("POST", &path, body, ms(at))
    } else {
        app_request(app(&keys, writer), "POST", &path, body, ms(at))
    };
    let answer = replay.service.handle(request).await;
    (
        answer.status,
        serde_json::from_slice(&answer.body).unwrap_or(Value::Null),
    )
}

/// A body of the signed operations `cases` carry in `signed`, in that order.
fn body_of(cases: &[&Value]) -> Vec<u8> {
    let mut entries = Vec::new();
    for case in cases {
        let signed = &case["signed"];
        let signed = if let Some(text) = signed.as_str() {
            serde_json::from_str(text).expect("signed")
        } else {
            signed.clone()
        };
        entries.push(signed);
    }
    serde_json::to_vec(&serde_json::json!({ "ops": entries })).expect("body")
}

fn expect_refused(case: &Value, status: u16, body: &Value) {
    let name = case["name"].as_str().expect("name");
    assert_eq!(
        u64::from(status),
        case["expect"]["status"].as_u64().expect("status"),
        "{name}: {body}"
    );
    assert_eq!(body["code"], case["expect"]["code"], "{name}");
}

#[tokio::test]
async fn test_vectors_ops_operations() {
    let Some(replay) = replay().await else { return };
    let chain = vectors("chain.json");
    let operations = vectors("operations.json");
    let keys = vectors("keys.json");
    let alice_id = alice(&keys)["pubky_id"].as_str().expect("id").to_string();
    serve_alice(&replay).await;

    // The registration batch, with its cursor: chain.json's seqs 3 and 4.
    let at = item_time(chain_item(&chain, 3));
    set_time(&replay.clock, &at);
    let request = operations["ops_request"]["body"].as_str().expect("body");
    let (status, body) = post_body(&replay, "wallet", request.as_bytes().to_vec(), &at).await;
    assert_eq!(status, 200, "{body}");
    let proofs: Vec<SignedDoc> = serde_json::from_value(body["proofs"].clone()).expect("proofs");
    assert_eq!(proofs, vec![proof_at(&chain, 3), proof_at(&chain, 4)]);

    // Members beside a batch entry's own: 400, before any signature.
    for case in operations["unknown_members"]["batch_entries"]["cases"]
        .as_array()
        .expect("cases")
    {
        let body = case["body"].as_str().expect("body").as_bytes().to_vec();
        let (status, answer) = post_body(&replay, "wallet", body, &at).await;
        expect_refused(case, status, &answer);
    }
    // Unknown members at any depth of a signed operation, and integers out of the rule.
    for case in operations["unknown_members"]["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .chain(
            operations["integer_bounds"]["cases"]
                .as_array()
                .expect("cases")
                .iter()
                .filter(|case| case["expect"]["status"].is_number()),
        )
    {
        let writer = case["writer"].as_str().expect("writer");
        let (status, answer) = post_body(&replay, writer, body_of(&[case]), &at).await;
        expect_refused(case, status, &answer);
    }

    // The largest integer is valid: the attempt goes through with chain.json's batch.
    assert_eq!(replay.db.give_out_seq(&alice_id).await.expect("seq"), 5);
    let create = named(&operations["operations"], "record.put create");
    let at = item_time(chain_item(&chain, 6));
    set_time(&replay.clock, &at);
    // Operations whose shape fails, creates whose scopes aren't scopes and key bundle parts
    // whose range is out of the rule: 400 at their shape, before anything is stored, so the
    // create's batch ID stays free for the create that follows.
    for case in operations["shape_rejections"]["cases"]
        .as_array()
        .expect("cases")
    {
        let writer = case["writer"].as_str().expect("writer");
        let (status, answer) = post_body(&replay, writer, body_of(&[case]), &at).await;
        expect_refused(case, status, &answer);
    }
    let (status, answer) = post_body(&replay, "wallet", body_of(&[create]), &at).await;
    assert_eq!(status, 200, "{answer}");
    let largest = operations["integer_bounds"]["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["expect"]["valid"] == true)
        .expect("the valid case");
    let update = named(&operations["operations"], "record.put update");
    let at = item_time(chain_item(&chain, 7));
    set_time(&replay.clock, &at);
    let (status, answer) = post_body(&replay, "wallet", body_of(&[largest, update]), &at).await;
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["proofs"].as_array().map(Vec::len), Some(2));
    replay.db.drop_database().await.expect("drop");
}
