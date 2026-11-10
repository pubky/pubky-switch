//! The account endpoints' rules on the service, against PostgreSQL: enrollment (Switch wire
//! 3.7, 7.4.1), `identity.json` delivery (7.4.2), the public read (7.4.15), authentication
//! (7.2) and the key's mark (7.3 step 10).
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used)]

mod support;

use pubky_switch::{
    http::{Handler, SwitchResponse},
    limits::Limits,
};
use pubky_switch_core::{
    enc::b64,
    http::{IdentityDelivery, header},
    keys::IdentityKey,
    records::{Enrollment, EnrollmentBody},
    sig::SignedDoc,
};
use serde_json::{Value, json};
use sqlx::Connection;
use support::*;

fn json(response: &SwitchResponse) -> Value {
    serde_json::from_slice(&response.body).expect("json body")
}

fn code(response: &SwitchResponse) -> String {
    json(response)["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn signature_key(response: &SwitchResponse) -> Option<String> {
    response
        .headers
        .iter()
        .find(|(name, _)| name.as_str() == header::SERVICE_SIGNATURE)
        .and_then(|(_, value)| value.to_str().ok())
        .map(str::to_string)
}

struct Alice {
    id: String,
    key: IdentityKey,
}

fn alice_keys() -> Alice {
    let keys = vectors("keys.json");
    let alice = alice(&keys);
    Alice {
        id: alice["pubky_id"].as_str().expect("id").into(),
        key: IdentityKey::from_secret(hex32(&alice["secret_hex"])),
    }
}

/// The vector enrollment's body, with another nonce or origin, signed by alice.
fn enrollment_body(nonce: u8, origin: &str) -> Vec<u8> {
    enrollment_with(nonce, origin, None)
}

/// The vector enrollment's body with another nonce, origin and `identity_doc`.
fn enrollment_with(nonce: u8, origin: &str, identity_doc: Option<SignedDoc>) -> Vec<u8> {
    let http = vectors("http.json");
    let vector = named(&http["requests"], "signer: enrollment");
    let body: Value = serde_json::from_slice(
        &pubky_switch_core::enc::unb64(vector["body_b64"].as_str().expect("body")).expect("b64"),
    )
    .expect("json");
    let signed: SignedDoc = serde_json::from_value(body["enrollment"].clone()).expect("signed");
    let mut fields: EnrollmentBody =
        serde_json::from_slice(&signed.body_bytes().expect("body")).expect("enrollment body");
    fields.nonce = [nonce; 16];
    fields.origin = origin.into();
    fields.identity_doc = identity_doc;
    let enrollment = Enrollment::sign(&alice_keys().key, fields).expect("sign");
    serde_json::to_vec(&json!({ "enrollment": enrollment.signed() })).expect("json")
}

const T: &str = "2026-01-01T00:00:00.000Z";

/// Enroll alice with the vectors' enrollment, then deliver her version 1 at `T`.
async fn serving(replay: &Replay) {
    let http = vectors("http.json");
    set_time(&replay.clock, "2025-12-30T00:00:00.040Z");
    let enrolled = replay
        .service
        .handle(vector_request(named(
            &http["requests"],
            "signer: enrollment",
        )))
        .await;
    assert_eq!(enrolled.status, 200);
    set_time(&replay.clock, "2025-12-30T00:00:02.000Z");
    let delivered = replay
        .service
        .handle(vector_request(named(
            &http["requests"],
            "signer: identity.json delivery",
        )))
        .await;
    assert_eq!(
        delivered.status,
        200,
        "{}",
        String::from_utf8_lossy(&delivered.body)
    );
    set_time(&replay.clock, T);
}

fn version(name: &str) -> SignedDoc {
    let documents = vectors("documents.json");
    serde_json::from_value(named(&documents["documents"], name)["signed"].clone()).expect("doc")
}

fn delivery(doc: SignedDoc, prev: Option<[u8; 32]>) -> Vec<u8> {
    IdentityDelivery {
        identity: doc,
        prev,
    }
    .to_json()
}

#[tokio::test]
async fn test_enroll_same_enrollment_same_answer() {
    let Some(replay) = replay().await else { return };
    let alice = alice_keys();
    set_time(&replay.clock, T);
    let body = enrollment_body(1, ORIGIN);
    let first = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", body.clone(), ms(T)))
        .await;
    assert_eq!(first.status, 200);
    let again = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", body, ms(T)))
        .await;
    assert_eq!(
        again.body, first.body,
        "the same enrollment, the same answer"
    );
    // Another enrollment while staged: the same key, its own nonce and hash.
    let other = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            enrollment_body(2, ORIGIN),
            ms(T),
        ))
        .await;
    assert_eq!(json(&other)["service_key"], json(&first)["service_key"]);
    assert_ne!(json(&other)["enrollment"], json(&first)["enrollment"]);
    assert_eq!(json(&first)["identity"], alice.id.as_str());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_enroll_serving_account_answers_one_pending_key() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let account_key = vectors("keys.json")["service_keys"][0]["public"].clone();
    let first = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            enrollment_body(3, ORIGIN),
            ms(T),
        ))
        .await;
    assert_eq!(first.status, 200);
    let pending = json(&first)["service_key"].clone();
    assert_ne!(
        pending, account_key,
        "a pending key for the next generation"
    );
    let again = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            enrollment_body(4, ORIGIN),
            ms(T),
        ))
        .await;
    assert_eq!(json(&again)["service_key"], pending, "the same pending key");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_enroll_refusals() {
    let Some(replay) = replay().await else { return };
    set_time(&replay.clock, T);
    // Another origin.
    let wrong_origin = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            enrollment_body(5, "https://other.example"),
            ms(T),
        ))
        .await;
    assert_eq!(
        (wrong_origin.status, code(&wrong_origin).as_str()),
        (400, "bad_request")
    );
    // A request signature over another body.
    let mut tampered = signer_request("POST", "/v1/enroll", enrollment_body(6, ORIGIN), ms(T));
    tampered.body = enrollment_body(7, ORIGIN).into();
    let refused = replay.service.handle(tampered).await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (401, "bad_signature")
    );
    assert!(
        signature_key(&refused).is_some(),
        "signed with the operator key"
    );
    // An app of the identity.
    let mut app = signer_request("POST", "/v1/enroll", enrollment_body(8, ORIGIN), ms(T));
    app.headers.insert(
        header::APP,
        "wejf37ngr7qizej3eoijn3hq4c".parse().expect("value"),
    );
    let refused = replay.service.handle(app).await;
    assert_eq!(code(&refused), "permission_missing");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_identity_retry_and_stale_prev() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    let path = format!("/v1/{}/identity", alice.id);
    let version_1 = version("alice identity.json, first delivery (version 1)");
    let version_3 = version("alice identity.json");

    // Version 1 again, whatever prev it names: the original proof, no new item.
    let retry = replay
        .service
        .handle(signer_request(
            "PUT",
            &path,
            delivery(version_1.clone(), Some([9; 32])),
            ms(T),
        ))
        .await;
    assert_eq!(retry.status, 200);
    let retried = json(&retry);
    assert_eq!(retried["proofs"].as_array().expect("proofs").len(), 1);
    assert_eq!(retried["head"]["seq"], 1, "no new chain item");

    // Version 3 on a prev that isn't the newest held: the held copy comes back.
    let stale = replay
        .service
        .handle(signer_request(
            "PUT",
            &path,
            delivery(version_3, Some([9; 32])),
            ms(T),
        ))
        .await;
    assert_eq!(
        (stale.status, code(&stale).as_str()),
        (409, "stale_identity")
    );
    let current = &json(&stale)["current"];
    assert_eq!(current["version"], 1);
    assert_eq!(current["hash"], b64(&version_1.doc_hash().expect("hash")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_identity_callers_and_timestamps() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    let path = format!("/v1/{}/identity", alice.id);
    let body = delivery(version("alice identity.json"), None);

    // An own app isn't current before app records are served.
    let mut app = signer_request("PUT", &path, body.clone(), ms(T));
    app.headers.insert(
        header::APP,
        "wejf37ngr7qizej3eoijn3hq4c".parse().expect("value"),
    );
    assert_eq!(code(&replay.service.handle(app).await), "not_current");

    // A timestamp 5 minutes and a second off: 401, counted against the network source.
    let mut stale = signer_request("PUT", &path, body, ms(T) - 301_000);
    let source = Some(pubky_switch::http::source::NetworkSource::of(
        "203.0.113.9".parse().expect("ip"),
    ));
    stale.source = source;
    let refused = replay.service.handle(stale).await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (401, "stale_timestamp")
    );
    let claimed = (alice.id.clone(), alice.id.clone(), None);
    assert_eq!(
        replay
            .service
            .failed_authentications()
            .claimed(&claimed, ms(T)),
        1
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_public_identity_staged_and_limits() {
    let Some(replay) = replay_with(Limits {
        identity_reads_per_source_per_min: 2,
        identity_reads_per_min: 3,
        ..Limits::default()
    })
    .await
    else {
        return;
    };
    let alice = alice_keys();
    let path = format!("/v1/{}/identity", alice.id);
    set_time(&replay.clock, T);
    let read = |source: &str| {
        let mut request = request("GET", &path, &[], Vec::new());
        request.source = Some(pubky_switch::http::source::NetworkSource::of(
            source.parse().expect("ip"),
        ));
        request
    };

    // Enrolled without a document: nothing to read.
    let enrolled = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            enrollment_body(1, ORIGIN),
            ms(T),
        ))
        .await;
    assert_eq!(enrolled.status, 200);
    assert_eq!(
        code(&replay.service.handle(read("203.0.113.1")).await),
        "not_found"
    );

    replay.db.drop_database().await.expect("drop");

    // Enrolled by a new provider with a document naming another service: the account
    // holds it, and stays staged until a document names it.
    let Some(replay) = replay_with(Limits::default()).await else {
        return;
    };
    set_time(&replay.clock, T);
    let elsewhere = version(
        "alice identity.json after the move to the next service (version 7, generation 2), \
         keeping generation 1's service key in service_keys",
    );
    let enrolled = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            enrollment_with(2, ORIGIN, Some(elsewhere)),
            ms(T),
        ))
        .await;
    assert_eq!(
        enrolled.status,
        200,
        "{}",
        String::from_utf8_lossy(&enrolled.body)
    );
    let staged = replay.service.handle(read("203.0.113.1")).await;
    assert_eq!((staged.status, code(&staged).as_str()), (503, "staged"));
    replay.db.drop_database().await.expect("drop");

    // The limits, on a serving account: 2 per source, a backstop of 3 for the account, and
    // a source's refused reads don't count against the backstop.
    let Some(replay) = replay_with(Limits {
        identity_reads_per_source_per_min: 2,
        identity_reads_per_min: 3,
        ..Limits::default()
    })
    .await
    else {
        return;
    };
    serving(&replay).await;
    let read = |source: &str| {
        let mut request = request("GET", &path, &[], Vec::new());
        request.source = Some(pubky_switch::http::source::NetworkSource::of(
            source.parse().expect("ip"),
        ));
        request
    };
    for _ in 0..2 {
        assert_eq!(replay.service.handle(read("203.0.113.1")).await.status, 200);
    }
    let limited = replay.service.handle(read("203.0.113.1")).await;
    assert_eq!(
        (limited.status, code(&limited).as_str()),
        (429, "rate_limited")
    );
    assert!(json(&limited)["retry_after"].is_u64());
    // The backstop has 1 read left: the refused one didn't count.
    assert_eq!(replay.service.handle(read("203.0.113.2")).await.status, 200);
    assert_eq!(
        code(&replay.service.handle(read("203.0.113.3")).await),
        "rate_limited",
        "the account's backstop"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_state_behind_the_mark_fails_stop() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    // A backup from before the first delivery is restored: the key's mark is at seq 1.
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(
        "UPDATE accounts SET last_seq = 0, chain_seq = NULL, chain_hash = NULL WHERE id = $1",
    )
    .bind(&alice.id)
    .execute(&mut conn)
    .await
    .expect("restore");
    conn.close().await.expect("close");
    let read = request(
        "GET",
        &format!("/v1/{}/identity", alice.id),
        &[],
        Vec::new(),
    );
    let refused = replay.service.handle(read).await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (503, "unavailable")
    );
    let put = replay
        .service
        .handle(signer_request(
            "PUT",
            &format!("/v1/{}/identity", alice.id),
            delivery(version("alice identity.json"), None),
            ms(T),
        ))
        .await;
    assert_eq!(code(&put), "unavailable");
    assert!(
        !put.headers
            .iter()
            .any(|(name, _)| name.as_str() == header::HEAD),
        "no head behind the mark"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_calls_not_served_yet() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    let feed = replay
        .service
        .handle(request(
            "GET",
            &format!("/v1/{}/feed", alice.id),
            &[],
            Vec::new(),
        ))
        .await;
    assert_eq!((feed.status, code(&feed).as_str()), (503, "unavailable"));
    assert!(signature_key(&feed).is_some());
    replay.db.drop_database().await.expect("drop");
}
