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

/// alice's version 1 with `change` applied, signed by her identity key.
fn alice_version(change: impl FnOnce(&mut pubky_switch_core::records::IdentityBody)) -> SignedDoc {
    let version_1 = version("alice identity.json, first delivery (version 1)");
    let mut body: pubky_switch_core::records::IdentityBody =
        serde_json::from_slice(&version_1.body_bytes().expect("body")).expect("identity body");
    change(&mut body);
    pubky_switch_core::records::IdentityDoc::sign(&alice_keys().key, body)
        .expect("sign")
        .signed()
        .clone()
}

fn header_of<'a>(response: &'a SwitchResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(header, _)| header.as_str() == name)
        .and_then(|(_, value)| value.to_str().ok())
}

/// The account's service key ID, read from the database.
async fn service_key_id(replay: &Replay, id: &str) -> pubky_switch::keys::KeyId {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let key: String = sqlx::query_scalar("SELECT service_key FROM accounts WHERE id = $1")
        .bind(id)
        .fetch_one(&mut conn)
        .await
        .expect("key");
    conn.close().await.expect("close");
    pubky_switch::keys::KeyId::parse(&key).expect("key id")
}

#[tokio::test]
async fn test_identity_first_document_of_a_recovery_isnt_served_yet() {
    let Some(replay) = replay().await else { return };
    let alice = alice_keys();
    set_time(&replay.clock, T);
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
    // A first document that starts a recovery at generation 3: the recovery transition comes
    // with recovery, so the service doesn't chain it at the account's generation 1.
    let recovery = alice_version(|body| {
        body.version = 9;
        body.generation = 3;
        body.recovery_from = Some(2);
    });
    let path = format!("/v1/{}/identity", alice.id);
    let answer = replay
        .service
        .handle(signer_request(
            "PUT",
            &path,
            delivery(recovery, None),
            ms(T),
        ))
        .await;
    assert_eq!(
        (answer.status, code(&answer).as_str()),
        (503, "unavailable"),
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let key = service_key_id(&replay, &alice.id).await;
    assert_eq!(
        pubky_switch::keys::KeyStore::mark(replay.keys.as_ref(), &key)
            .await
            .expect("mark"),
        None,
        "nothing chained"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_authentication_takes_no_account_lock() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    let path = format!("/v1/{}/identity", alice.id);
    // Another request holds the account's lock.
    let held = replay
        .db
        .store()
        .begin(&alice.id)
        .await
        .expect("begin")
        .expect("account");
    let mut garbage = signer_request(
        "PUT",
        &path,
        delivery(version("alice identity.json"), None),
        ms(T),
    );
    garbage
        .headers
        .insert(header::SIGNATURE, b64(&[7u8; 64]).parse().expect("value"));
    let refused = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        replay.service.handle(garbage),
    )
    .await
    .expect("answered without waiting for the lock");
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (401, "bad_signature")
    );
    drop(held);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_authentication_refusals_at_put_identity() {
    let Some(replay) = replay_with(Limits {
        auth_failures_per_source_per_min: 2,
        ..Limits::default()
    })
    .await
    else {
        return;
    };
    serving(&replay).await;
    let alice = alice_keys();
    let path = format!("/v1/{}/identity", alice.id);
    let body = delivery(version("alice identity.json"), None);
    let source = Some(pubky_switch::http::source::NetworkSource::of(
        "203.0.113.9".parse().expect("ip"),
    ));

    // Signed with another key than alice's identity key.
    let keys = vectors("keys.json");
    let bob = keys["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == "bob")
        .expect("bob");
    let mut wrong_key = signer_request("PUT", &path, body.clone(), ms(T));
    let bob_key = ed25519_dalek::SigningKey::from_bytes(&hex32(&bob["secret_hex"]));
    let timestamp = pubky_switch_core::time::rfc3339_seconds(ms(T));
    let forged = pubky_switch_core::http::sign_request(
        &bob_key,
        &pubky_switch_core::http::RequestTarget {
            method: "PUT",
            path_and_query: &path,
            body: &body,
            origin: ORIGIN,
        },
        &pubky_switch_core::http::RequestHeaders {
            timestamp,
            identity: alice.id.clone(),
            ..Default::default()
        },
    );
    wrong_key
        .headers
        .insert(header::SIGNATURE, b64(&forged).parse().expect("value"));
    wrong_key.source = source;
    let refused = replay.service.handle(wrong_key).await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (401, "bad_signature")
    );

    // Another identity's signer.
    let mut other = signer_request("PUT", &path, body.clone(), ms(T));
    other.headers.insert(
        header::IDENTITY,
        bob["pubky_id"]
            .as_str()
            .expect("id")
            .parse()
            .expect("value"),
    );
    assert_eq!(code(&replay.service.handle(other).await), "not_admitted");

    // The second failure from the source fills its limit of 2; the next request from it is
    // refused before any signature work, even a correctly signed one.
    let mut stale = signer_request("PUT", &path, body.clone(), ms(T) - 301_000);
    stale.source = source;
    assert_eq!(code(&replay.service.handle(stale).await), "stale_timestamp");
    let mut good = signer_request("PUT", &path, body, ms(T));
    good.source = source;
    let limited = replay.service.handle(good).await;
    assert_eq!(
        (limited.status, code(&limited).as_str()),
        (429, "rate_limited")
    );
    assert!(header_of(&limited, header::RETRY_AFTER).is_some());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_signer_error_answers_carry_the_head() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    let stale = replay
        .service
        .handle(signer_request(
            "PUT",
            &format!("/v1/{}/identity", alice.id),
            delivery(version("alice identity.json"), Some([9; 32])),
            ms(T),
        ))
        .await;
    assert_eq!(code(&stale), "stale_identity");
    let head = pubky_switch_core::chain::SignedHead::from_header(
        header_of(&stale, header::HEAD).expect("a head on the signer's error answer"),
    )
    .expect("head");
    let service_key: [u8; 32] = pubky_switch_core::enc::unb64(
        vectors("keys.json")["service_keys"][0]["public"]
            .as_str()
            .expect("public"),
    )
    .expect("b64")
    .try_into()
    .expect("32 bytes");
    head.verify(&service_key, &alice.key.public())
        .expect("the head verifies");
    assert_eq!(head.seq, 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_delivery_away_from_this_service_moves_the_mark() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    let version_1 = version("alice identity.json, first delivery (version 1)");
    let away = alice_version(|body| {
        body.version = 2;
        body.inbox.url = "https://other.example".into();
    });
    let answer = replay
        .service
        .handle(signer_request(
            "PUT",
            &format!("/v1/{}/identity", alice.id),
            delivery(away, Some(version_1.doc_hash().expect("hash"))),
            ms(T),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(json(&answer)["head"]["seq"], 2);
    let key = service_key_id(&replay, &alice.id).await;
    let mark = pubky_switch::keys::KeyStore::mark(replay.keys.as_ref(), &key)
        .await
        .expect("mark")
        .expect("marked");
    assert_eq!(mark.seq, 2, "the head the answer carried is marked");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_enrollment_answer_keeps_its_limits_after_a_config_change() {
    let Some(replay) = replay().await else { return };
    set_time(&replay.clock, T);
    let body = enrollment_body(1, ORIGIN);
    let first = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", body.clone(), ms(T)))
        .await;
    assert_eq!(first.status, 200);
    let restarted = replay.restarted_with(Limits {
        app_limit: 40,
        quota_bytes: 2 * Limits::default().quota_bytes,
        ..Limits::default()
    });
    let again = restarted
        .handle(signer_request("POST", "/v1/enroll", body, ms(T)))
        .await;
    assert_eq!(
        String::from_utf8_lossy(&again.body),
        String::from_utf8_lossy(&first.body),
        "the same enrollment, the same answer"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_commit_failure_answer_keeps_the_committed_time() {
    let Some(replay) = replay().await else { return };
    set_time(&replay.clock, T);
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
    // Every commit that changes the account now fails, at the commit itself.
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    for statement in [
        "CREATE FUNCTION refuse() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'refused at commit'; END $$",
        "CREATE CONSTRAINT TRIGGER refuse_at_commit AFTER UPDATE ON accounts \
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION refuse()",
    ] {
        sqlx::query(statement)
            .execute(&mut conn)
            .await
            .expect("trigger");
    }
    conn.close().await.expect("close");
    let later = ms(T) + 60_000;
    set_time(&replay.clock, &pubky_switch_core::time::rfc3339(later));
    let http = vectors("http.json");
    let mut put = vector_request(named(&http["requests"], "signer: identity.json delivery"));
    put = signer_request("PUT", &put.path_and_query, put.body.to_vec(), later);
    let failed = replay.service.handle(put).await;
    assert_eq!(code(&failed), "unavailable");
    assert_eq!(
        header_of(&failed, header::SERVER_TIME),
        Some(pubky_switch_core::time::rfc3339(ms(T)).as_str()),
        "the answer shows the committed time, not the stamp that didn't commit"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_concurrent_first_enrollments_share_one_account() {
    let Some(replay) = replay().await else { return };
    set_time(&replay.clock, T);
    let body = enrollment_body(1, ORIGIN);
    let (a, b) = tokio::join!(
        replay
            .service
            .handle(signer_request("POST", "/v1/enroll", body.clone(), ms(T))),
        replay
            .service
            .handle(signer_request("POST", "/v1/enroll", body, ms(T))),
    );
    assert_eq!((a.status, b.status), (200, 200));
    assert_eq!(json(&a)["service_key"], json(&b)["service_key"]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_refused_delivery_leaves_nothing_to_build_on() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    let alice = alice_keys();
    // A backup from before the first delivery is restored: no document and no chain, while
    // the key's mark is at the first delivery's seq 1.
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    for statement in [
        "UPDATE accounts SET last_seq = 0, chain_seq = NULL, chain_hash = NULL, \
         identity_doc = NULL, identity_proof = NULL WHERE id = $1",
        "DELETE FROM chain_items WHERE account_id = $1",
    ] {
        sqlx::query(statement)
            .bind(&alice.id)
            .execute(&mut conn)
            .await
            .expect("restore");
    }
    // Version 1 again, at another time: a seq 1 beside the mark, which no head may show.
    let path = format!("/v1/{}/identity", alice.id);
    let version_1 = version("alice identity.json, first delivery (version 1)");
    let refused = replay
        .service
        .handle(signer_request(
            "PUT",
            &path,
            delivery(version_1.clone(), None),
            ms(T),
        ))
        .await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (503, "unavailable")
    );
    // Nothing of the refused delivery was kept, so a later one can't extend it.
    let (last_seq, doc): (i64, Option<Vec<u8>>) =
        sqlx::query_as("SELECT last_seq, identity_doc FROM accounts WHERE id = $1")
            .bind(&alice.id)
            .fetch_one(&mut conn)
            .await
            .expect("account");
    assert_eq!((last_seq, doc), (0, None));
    let extended = replay
        .service
        .handle(signer_request(
            "PUT",
            &path,
            delivery(
                version("alice identity.json"),
                Some(version_1.doc_hash().expect("hash")),
            ),
            ms(T),
        ))
        .await;
    assert_ne!(
        extended.status,
        200,
        "{}",
        String::from_utf8_lossy(&extended.body)
    );
    assert!(header_of(&extended, header::HEAD).is_none());
    conn.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_identity_first_delivery_refuses_an_enrolled_revoked_app() {
    let Some(replay) = replay().await else { return };
    let alice = alice_keys();
    set_time(&replay.clock, T);
    // An enrollment without identity_doc whose revoked_apps names the wallet, which version 1
    // lists as current.
    let keys = vectors("keys.json");
    let wallet: [u8; 16] = hex::decode(
        keys["apps"]
            .as_array()
            .expect("apps")
            .iter()
            .find(|app| app["name"] == "wallet")
            .expect("the wallet")["app_id_bytes_hex"]
            .as_str()
            .expect("hex"),
    )
    .expect("hex")
    .try_into()
    .expect("16 bytes");
    let http = vectors("http.json");
    let vector = named(&http["requests"], "signer: enrollment");
    let body: Value = serde_json::from_slice(
        &pubky_switch_core::enc::unb64(vector["body_b64"].as_str().expect("body")).expect("b64"),
    )
    .expect("json");
    let signed: SignedDoc = serde_json::from_value(body["enrollment"].clone()).expect("signed");
    let mut fields: EnrollmentBody =
        serde_json::from_slice(&signed.body_bytes().expect("body")).expect("enrollment body");
    fields.identity_doc = None;
    fields.revoked_apps = Some(vec![wallet]);
    let enrollment = Enrollment::sign(&alice.key, fields).expect("sign");
    let body = serde_json::to_vec(&json!({ "enrollment": enrollment.signed() })).expect("json");
    let enrolled = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", body, ms(T)))
        .await;
    assert_eq!(
        enrolled.status,
        200,
        "{}",
        String::from_utf8_lossy(&enrolled.body)
    );
    let path = format!("/v1/{}/identity", alice.id);
    let delivered = replay
        .service
        .handle(signer_request(
            "PUT",
            &path,
            delivery(
                version("alice identity.json, first delivery (version 1)"),
                None,
            ),
            ms(T),
        ))
        .await;
    assert_eq!(
        (delivered.status, code(&delivered).as_str()),
        (400, "bad_request"),
        "{}",
        String::from_utf8_lossy(&delivered.body)
    );
    let read = replay
        .service
        .handle(request("GET", &path, &[], Vec::new()))
        .await;
    assert_eq!(read.status, 404, "nothing is served");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_enroll_retry_after_serving_gets_the_first_answer() {
    let Some(replay) = replay().await else { return };
    serving(&replay).await;
    // The vectors' enrollment again, under a fresh request signature, once the account
    // serves: the answer it got first, not the next generation's pending key.
    let http = vectors("http.json");
    let vector = named(&http["requests"], "signer: enrollment");
    let body =
        pubky_switch_core::enc::unb64(vector["body_b64"].as_str().expect("body")).expect("b64");
    let again = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", body, ms(T)))
        .await;
    let first = named(
        &http["responses"],
        "signer: enrollment answer, signed with the new account's key",
    );
    assert_eq!(again.status, 200);
    assert_eq!(
        String::from_utf8_lossy(&again.body),
        first["body"].as_str().expect("body"),
        "the same enrollment, the same answer"
    );
    // A new enrollment still gets the pending key.
    let other = replay
        .service
        .handle(signer_request(
            "POST",
            "/v1/enroll",
            enrollment_body(5, ORIGIN),
            ms(T),
        ))
        .await;
    assert_ne!(
        json(&other)["service_key"],
        vectors("keys.json")["service_keys"][0]["public"]
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_stale_timestamp_gives_a_time_to_retry_with() {
    let Some(replay) = replay().await else { return };
    // The account last committed on December 30, and is idle until January 1.
    serving(&replay).await;
    let alice = alice_keys();
    let path = format!("/v1/{}/identity", alice.id);
    let body = delivery(version("alice identity.json"), None);
    let last_committed = "2025-12-30T00:00:02.000Z";
    let stale = signer_request("PUT", &path, body.clone(), ms(last_committed));
    let refused = replay.service.handle(stale).await;
    assert_eq!(
        (refused.status, code(&refused).as_str()),
        (401, "stale_timestamp")
    );
    // The signed time stays the identity's service time; the body gives the time base.
    assert_eq!(
        header_of(&refused, header::SERVER_TIME),
        Some(last_committed)
    );
    let retry_at = json(&refused)["current"]["server_time"]
        .as_str()
        .expect("current.server_time")
        .to_string();
    assert_eq!(retry_at, T);
    let retried = replay
        .service
        .handle(signer_request("PUT", &path, body, ms(&retry_at)))
        .await;
    assert_ne!(code(&retried), "stale_timestamp");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_enroll_answers_keep_the_creating_one_and_drop_the_oldest() {
    let limits = Limits {
        max_enrollments: 2,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    serving(&replay).await;
    let alice = alice_keys();
    // Three more enrollments, all at one time.
    let mut newest = [0; 32];
    for nonce in 11..=13 {
        let body = enrollment_body(nonce, ORIGIN);
        let value: Value = serde_json::from_slice(&body).expect("json");
        let signed: SignedDoc = serde_json::from_value(value["enrollment"].clone()).expect("doc");
        newest = signed.doc_hash().expect("hash");
        let answer = replay
            .service
            .handle(signer_request("POST", "/v1/enroll", body, ms(T)))
            .await;
        assert_eq!(answer.status, 200);
    }
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let kept: Vec<(Vec<u8>, bool)> = sqlx::query_as(
        "SELECT enrollment_hash, creating FROM enrollment_answers WHERE account_id = $1 \
         ORDER BY kept_order",
    )
    .bind(&alice.id)
    .fetch_all(&mut conn)
    .await
    .expect("answers");
    conn.close().await.expect("close");
    assert_eq!(kept.len(), 2);
    assert!(kept[0].1, "the creating enrollment's answer stays");
    assert_eq!(kept[1].0, newest.to_vec(), "the newest of the others stays");
    // The creating enrollment again: its own answer, not the pending key.
    let http = vectors("http.json");
    let vector = named(&http["requests"], "signer: enrollment");
    let body =
        pubky_switch_core::enc::unb64(vector["body_b64"].as_str().expect("body")).expect("b64");
    let again = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", body, ms(T)))
        .await;
    let first = named(
        &http["responses"],
        "signer: enrollment answer, signed with the new account's key",
    );
    assert_eq!(
        String::from_utf8_lossy(&again.body),
        first["body"].as_str().expect("body")
    );
    replay.db.drop_database().await.expect("drop");
}
