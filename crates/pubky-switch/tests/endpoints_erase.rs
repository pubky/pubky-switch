//! `POST /v1/{id}/erase` (Switch wire 7.4.16, spec 12.7) on alice's account: the vector, what
//! is deleted and what isn't, what every later call answers, and the refusals.
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::{
    http::{Handler, SwitchResponse},
    keys::{KeyId, KeyStore},
};
use pubky_switch_core::http::{erase_body, header};
use serde_json::{Value, json};
use sqlx::Connection;
use support::*;

/// Every table holding an account's state, each with its account column. All reference
/// `accounts` with `ON DELETE CASCADE`.
const ACCOUNT_TABLES: &[(&str, &str)] = &[
    ("accounts", "id"),
    ("kept_app_ids", "account_id"),
    ("chain_items", "account_id"),
    ("enrollment_answers", "account_id"),
    ("apps", "account_id"),
    ("receive_keys", "account_id"),
    ("key_bundle_parts", "account_id"),
    ("shared_records", "account_id"),
    ("claims", "account_id"),
    ("claim_entries", "account_id"),
    ("list_entries", "account_id"),
    ("invite_codes", "account_id"),
    ("batches", "account_id"),
    ("app_listings", "account_id"),
    ("peer_copies", "account_id"),
    ("peer_floors", "account_id"),
    ("inbox_entries", "account_id"),
    ("sender_flags", "account_id"),
];

fn alice_id() -> String {
    alice(&vectors("keys.json"))["pubky_id"]
        .as_str()
        .expect("id")
        .to_string()
}

fn erase_path() -> String {
    format!("/v1/{}/erase", alice_id())
}

fn body(answer: &SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body)
        .unwrap_or_else(|_| panic!("json: {}", String::from_utf8_lossy(&answer.body)))
}

fn code_of(answer: &SwitchResponse) -> (u16, Value) {
    (answer.status, body(answer)["code"].clone())
}

fn no_head(answer: &SwitchResponse) -> bool {
    header_text(answer, header::HEAD).is_none()
}

fn revoke_time() -> String {
    item_time(chain_item(&vectors("chain.json"), 9))
}

/// alice's service key, from `keys.json`.
fn alice_service_key() -> [u8; 32] {
    let keys = vectors("keys.json");
    let service = keys["service_keys"]
        .as_array()
        .expect("service keys")
        .iter()
        .find(|s| s["account"] == alice_id().as_str())
        .expect("alice's service key")
        .clone();
    pubky_switch_core::enc::unb64(service["public"].as_str().expect("public"))
        .expect("key")
        .try_into()
        .expect("32 bytes")
}

/// The signer's erasure of alice's account, naming `key`, at `at`.
async fn erase(replay: &Replay, key: &[u8; 32], at: &str) -> SwitchResponse {
    replay
        .service
        .handle(signer_request(
            "POST",
            &erase_path(),
            erase_body(key),
            ms(at),
        ))
        .await
}

/// How many rows each account table holds for `account`.
async fn rows(replay: &Replay, account: &str) -> Vec<(&'static str, i64)> {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let mut counts = Vec::new();
    for (table, column) in ACCOUNT_TABLES {
        let count: i64 =
            sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE {column} = $1"))
                .bind(account)
                .fetch_one(&mut conn)
                .await
                .expect("count");
        counts.push((*table, count));
    }
    conn.close().await.expect("close");
    counts
}

/// The account's service key ID, read from the database.
async fn service_key_id(replay: &Replay, id: &str) -> KeyId {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let key: String = sqlx::query_scalar("SELECT service_key FROM accounts WHERE id = $1")
        .bind(id)
        .fetch_one(&mut conn)
        .await
        .expect("key");
    conn.close().await.expect("close");
    KeyId::parse(&key).expect("key id")
}

/// The answer is signed with the operator key, as for an account the service doesn't hold
/// (Switch wire 7.3 step 2).
fn operator_signed(answer: &SwitchResponse, request_signature: Option<&[u8; 64]>) -> bool {
    let signature: [u8; 64] = pubky_switch_core::enc::unb64(
        header_text(answer, header::SERVICE_SIGNATURE).expect("signature"),
    )
    .expect("b64")
    .try_into()
    .expect("64");
    pubky_switch_core::http::verify_response(
        &operator_public(),
        answer.status,
        request_signature,
        header_text(answer, header::SERVER_TIME).expect("time"),
        &answer.body,
        &signature,
    )
    .is_ok()
}

fn signature_of(request: &pubky_switch::http::SwitchRequest) -> [u8; 64] {
    pubky_switch_core::enc::unb64(
        request
            .headers
            .get(header::SIGNATURE)
            .and_then(|value| value.to_str().ok())
            .expect("signature"),
    )
    .expect("b64")
    .try_into()
    .expect("64")
}

#[tokio::test]
async fn test_erase_vector_answer() {
    // http.json's erasure and its answer: `{ "erased": true }`, signed with the account's
    // key, without a head (Switch wire 7.4.16).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let http = vectors("http.json");
    let expected = named(
        &http["responses"],
        "signer: account erasure answer, signed with the account's key, no head",
    );
    set_time(
        &replay.clock,
        expected["headers"]["switch-server-time"]
            .as_str()
            .expect("time"),
    );
    let request = vector_request(named(
        &http["requests"],
        "signer: account erasure, naming the account's service key",
    ));
    let answer = replay.service.handle(request).await;
    assert_matches(&answer, expected);
    assert!(no_head(&answer));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_deletes_the_account_and_nothing_else() {
    // Every row of alice's state goes, her service key and its mark with it, and the
    // erasure is in the key store's ledger; bob's account on the same service keeps every
    // row (Switch wire 7.4.16, spec 12.7).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let bob = serve_bob(&replay).await;
    let bob_before = rows(&replay, &bob).await;
    let alice_before = rows(&replay, &alice_id()).await;
    for table in [
        "accounts",
        "chain_items",
        "apps",
        "claims",
        "enrollment_answers",
    ] {
        assert!(
            alice_before.iter().any(|(t, n)| *t == table && *n > 0),
            "alice holds {table} rows to erase"
        );
    }
    let key = service_key_id(&replay, &alice_id()).await;
    let at = revoke_time();
    let answer = erase(&replay, &alice_service_key(), &at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    for (table, count) in rows(&replay, &alice_id()).await {
        assert_eq!(count, 0, "{table}");
    }
    assert_eq!(rows(&replay, &bob).await, bob_before);
    assert!(
        replay.keys.public_key(&key).await.is_err(),
        "the key is gone"
    );
    assert_eq!(
        replay.keys.mark(&key).await.ok().flatten(),
        None,
        "and its mark"
    );
    assert_eq!(
        replay.keys.erasure(&alice_id()).await.expect("ledger"),
        Some(ms(&at))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_then_every_call_is_the_operators_404() {
    // Afterwards the account is one the service doesn't host: the public read, the signer's
    // calls, an app's, and the erasure again (the retry of a lost `200`) get the `404`
    // signed with the operator key, without a head (Switch wire 7.4.16, 7.3 step 2).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    assert_eq!(erase(&replay, &alice_service_key(), &at).await.status, 200);
    let keys = vectors("keys.json");
    let requests = vec![
        request(
            "GET",
            &format!("/v1/{}/identity", alice_id()),
            &[],
            Vec::new(),
        ),
        signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            ms(&at),
        ),
        app_request(
            app(&keys, "wallet"),
            "GET",
            &format!("/v1/{}/feed", alice_id()),
            Vec::new(),
            ms(&at),
        ),
        signer_request(
            "POST",
            &erase_path(),
            erase_body(&alice_service_key()),
            ms(&at),
        ),
    ];
    for request in requests {
        let path = format!("{:?}", request.route.call);
        let signature = request
            .headers
            .get(header::SIGNATURE)
            .map(|_| signature_of(&request));
        let answer = replay.service.handle(request).await;
        assert_eq!(code_of(&answer), (404, json!("not_found")), "{path}");
        assert!(no_head(&answer), "{path}");
        assert!(operator_signed(&answer, signature.as_ref()), "{path}");
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_then_enrollment_starts_a_new_account() {
    // `POST /v1/enroll` after an erasure creates a new, staged account with a new key
    // (Switch wire 7.4.16 Afterwards).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let old_key = service_key_id(&replay, &alice_id()).await;
    let http = vectors("http.json");
    let enrolled = named(
        &http["responses"],
        "signer: enrollment answer, signed with the new account's key",
    );
    // Erased at the time `serve_alice` left, then enrolled again at the vector's.
    let served = item_time(&vectors("chain.json")["items"][1]);
    assert_eq!(
        erase(&replay, &alice_service_key(), &served).await.status,
        200
    );
    set_time(
        &replay.clock,
        enrolled["headers"]["switch-server-time"]
            .as_str()
            .expect("time"),
    );
    let enrollment = vector_request(named(&http["requests"], "signer: enrollment"));
    let answer = replay.service.handle(enrollment).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let new_key = service_key_id(&replay, &alice_id()).await;
    assert_ne!(new_key, old_key);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_another_key_is_conflict() {
    // Another service key is `409 conflict`, so a replay can't erase a later account of the
    // identity; without a head, and nothing deleted (Switch wire 7.4.16).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let before = rows(&replay, &alice_id()).await;
    let answer = erase(&replay, &[7; 32], &revoke_time()).await;
    assert_eq!(code_of(&answer), (409, json!("conflict")));
    assert!(no_head(&answer));
    assert_eq!(rows(&replay, &alice_id()).await, before);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_body_names_only_the_service_key() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let key = pubky_switch_core::enc::b64(&alice_service_key());
    for body in [
        format!(r#"{{"service_key":"{key}","x":1}}"#).into_bytes(),
        b"{}".to_vec(),
        Vec::new(),
    ] {
        let answer = replay
            .service
            .handle(signer_request("POST", &erase_path(), body, ms(&at)))
            .await;
        assert_eq!(code_of(&answer), (400, json!("bad_request")));
        assert!(no_head(&answer));
    }
    assert_eq!(rows(&replay, &alice_id()).await[0], ("accounts", 1));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_only_the_signer() {
    // An own app's call is `403 permission_missing`, an app of another identity's `403
    // not_admitted`; neither carries a head, and nothing is erased (Switch wire 7.4.16).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let keys = vectors("keys.json");
    let own = replay
        .service
        .handle(app_request(
            app(&keys, "wallet"),
            "POST",
            &erase_path(),
            erase_body(&alice_service_key()),
            ms(&at),
        ))
        .await;
    assert_eq!(code_of(&own), (403, json!("permission_missing")));
    assert!(no_head(&own));
    let other = replay
        .service
        .handle(other_request(
            "shop",
            ORIGIN,
            "POST",
            &erase_path(),
            erase_body(&alice_service_key()),
            None,
            ms(&at),
        ))
        .await;
    assert_eq!(code_of(&other), (403, json!("not_admitted")));
    assert!(no_head(&other));
    assert_eq!(rows(&replay, &alice_id()).await[0], ("accounts", 1));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_staged_account() {
    // An account that doesn't serve yet takes the erasure (Switch wire 7.3 step 7).
    let Some(replay) = replay().await else { return };
    let http = vectors("http.json");
    let enrolled = named(
        &http["responses"],
        "signer: enrollment answer, signed with the new account's key",
    );
    let at = enrolled["headers"]["switch-server-time"]
        .as_str()
        .expect("time")
        .to_string();
    set_time(&replay.clock, &at);
    let enrollment = vector_request(named(&http["requests"], "signer: enrollment"));
    assert_eq!(replay.service.handle(enrollment).await.status, 200);
    let answer = erase(&replay, &alice_service_key(), &at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(rows(&replay, &alice_id()).await[0], ("accounts", 0));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_account_behind_its_mark() {
    // A state behind its key's mark fails every call stop (7.3 step 10), but the erasure,
    // whose answer carries no head (Switch wire 7.4.16).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(
        "UPDATE accounts SET last_seq = 0, chain_seq = NULL, chain_hash = NULL WHERE id = $1",
    )
    .bind(alice_id())
    .execute(&mut conn)
    .await
    .expect("restore");
    conn.close().await.expect("close");
    let at = revoke_time();
    let apps = replay
        .service
        .handle(signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            ms(&at),
        ))
        .await;
    assert_eq!(
        code_of(&apps),
        (503, json!("unavailable")),
        "behind its mark"
    );
    let answer = erase(&replay, &alice_service_key(), &at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(rows(&replay, &alice_id()).await[0], ("accounts", 0));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_forgets_the_accounts_counts() {
    // The failed-authentication counts at the account go with it (Switch wire 7.4.16, 9.4).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let mut bad = signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&at),
    );
    bad.headers.insert(
        header::SIGNATURE,
        pubky_switch_core::enc::b64(&[0u8; 64])
            .parse()
            .expect("header"),
    );
    assert_eq!(code_of(&replay.service.handle(bad).await).0, 401);
    let claimed = (alice_id(), alice_id(), None);
    let base = replay.time.peek().base_ms;
    assert!(
        replay
            .service
            .failed_authentications()
            .claimed(&claimed, base)
            > 0
    );
    assert_eq!(erase(&replay, &alice_service_key(), &at).await.status, 200);
    assert_eq!(
        replay
            .service
            .failed_authentications()
            .claimed(&claimed, base),
        0
    );
    replay.db.drop_database().await.expect("drop");
}
