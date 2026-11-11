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
    ("handovers", "account_id"),
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
    // bob's account names alice: a contact, and a copy of her identity.json. They are bob's,
    // and stay (7.4.16 Not erased).
    let alice_key = hex32(&alice(&vectors("keys.json"))["public_hex"]);
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(
        "INSERT INTO list_entries (account_id, list, pubky, written_by, at_ms) \
         VALUES ($1, 'contact', $2, $3, 0)",
    )
    .bind(&bob)
    .bind(alice_key.as_slice())
    .bind([0u8; 16].as_slice())
    .execute(&mut conn)
    .await
    .expect("contact");
    let copy = serde_json::to_vec(
        &named(
            &vectors("documents.json")["documents"],
            "alice identity.json",
        )["signed"],
    )
    .expect("copy");
    sqlx::query(
        "INSERT INTO peer_copies (account_id, identity, doc, version, generation, body_hash) \
         VALUES ($1, $2, $3, 3, 1, $4)",
    )
    .bind(&bob)
    .bind(alice_key.as_slice())
    .bind(copy)
    .bind([0u8; 32].as_slice())
    .execute(&mut conn)
    .await
    .expect("peer copy");
    // A stored hand-over on each account: alice's goes, bob's stays (7.4.17).
    for account in [alice_id(), bob.clone()] {
        sqlx::query("INSERT INTO handovers (account_id, target_app_id, body) VALUES ($1, $2, $3)")
            .bind(account)
            .bind([1u8; 16].as_slice())
            .bind(b"{}".as_slice())
            .execute(&mut conn)
            .await
            .expect("a hand-over");
    }
    conn.close().await.expect("close");
    let bob_before = rows(&replay, &bob).await;
    for table in ["list_entries", "peer_copies"] {
        assert!(
            bob_before.iter().any(|(t, n)| *t == table && *n > 0),
            "bob holds {table} rows naming alice"
        );
    }
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
    assert_ne!(
        body(&answer)["service_key"],
        json!(pubky_switch_core::enc::b64(&alice_service_key()))
    );
    // Staged: it serves nothing until its first delivery (7.3 step 7).
    let apps = replay
        .service
        .handle(signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            ms(enrolled["headers"]["switch-server-time"]
                .as_str()
                .expect("time")),
        ))
        .await;
    assert_eq!(code_of(&apps), (503, json!("staged")));
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
    // An app's call is `403 permission_missing`, an own app's and one of another identity's;
    // neither carries a head, and nothing is erased (Switch wire 7.4.16, 7.6).
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
    assert_eq!(code_of(&other), (403, json!("permission_missing")));
    assert!(no_head(&other));
    let stale = erase(&replay, &alice_service_key(), "2026-01-01T00:30:00.000Z").await;
    assert_eq!(code_of(&stale), (401, json!("stale_timestamp")));
    assert!(no_head(&stale));
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
    // A public read and the replayed batches counted against the account's other limits.
    let read = replay
        .service
        .handle(request(
            "GET",
            &format!("/v1/{}/identity", alice_id()),
            &[],
            Vec::new(),
        ))
        .await;
    assert_eq!(read.status, 200);
    let failed = replay
        .service
        .failed_authentications()
        .counted_at(&alice_id());
    assert!(
        replay.service.counted_at(&alice_id()) > failed,
        "counts beyond the failures"
    );
    assert_eq!(erase(&replay, &alice_service_key(), &at).await.status, 200);
    assert_eq!(
        replay
            .service
            .failed_authentications()
            .claimed(&claimed, base),
        0
    );
    assert_eq!(
        replay.service.counted_at(&alice_id()),
        0,
        "every count of the account"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_every_account_table_cascades() {
    // Read from the schema's foreign keys, whatever their columns' names: every foreign key
    // that reaches `accounts` deletes in cascade, and every table that reaches it is in
    // `ACCOUNT_TABLES`; every other table is one the erasure leaves by design (7.4.16).
    let Some(replay) = replay().await else { return };
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    // (table, referenced table, delete rule) for every foreign key in the schema.
    let keys: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT c.conrelid::regclass::text, c.confrelid::regclass::text, c.confdeltype::text \
         FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace \
         WHERE c.contype = 'f' AND n.nspname = current_schema()",
    )
    .fetch_all(&mut conn)
    .await
    .expect("foreign keys");
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT tablename::text FROM pg_tables WHERE schemaname = current_schema()",
    )
    .fetch_all(&mut conn)
    .await
    .expect("tables");
    conn.close().await.expect("close");
    // The tables reaching `accounts` through foreign keys, transitively.
    let mut reached = vec!["accounts".to_owned()];
    loop {
        let more: Vec<String> = keys
            .iter()
            .filter(|(table, to, _)| reached.contains(to) && !reached.contains(table))
            .map(|(table, _, _)| table.clone())
            .collect();
        if more.is_empty() {
            break;
        }
        reached.extend(more);
    }
    for (table, to, rule) in &keys {
        if reached.contains(to) {
            assert_eq!(rule, "c", "{table}'s foreign key to {to} cascades");
        }
    }
    let mut listed: Vec<&str> = ACCOUNT_TABLES.iter().map(|(t, _)| *t).collect();
    listed.sort_unstable();
    let mut found: Vec<&str> = reached.iter().map(String::as_str).collect();
    found.sort_unstable();
    assert_eq!(
        found, listed,
        "ACCOUNT_TABLES names every table of an account"
    );
    for table in &tables {
        assert!(
            reached.contains(table)
                || ["erased_keys", "_sqlx_migrations"].contains(&table.as_str()),
            "{table} holds nothing of an account, or reaches accounts"
        );
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_commit_failure_deletes_nothing() {
    // The deletion doesn't commit: `503`, signed with the account's key, without a head, and
    // nothing deleted, the key, the ledger and the rows included; the retry erases (7.4.16).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    for statement in [
        "CREATE FUNCTION refuse_erasure() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'refused'; END $$",
        "CREATE CONSTRAINT TRIGGER refuse_erasure AFTER DELETE ON accounts \
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION refuse_erasure()",
    ] {
        sqlx::query(statement)
            .execute(&mut conn)
            .await
            .expect("trigger");
    }
    let before = rows(&replay, &alice_id()).await;
    let key = service_key_id(&replay, &alice_id()).await;
    let at = revoke_time();
    let request = signer_request(
        "POST",
        &erase_path(),
        erase_body(&alice_service_key()),
        ms(&at),
    );
    let request_signature = signature_of(&request);
    let answer = replay.service.handle(request).await;
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    assert!(no_head(&answer));
    let signature: [u8; 64] = pubky_switch_core::enc::unb64(
        header_text(&answer, header::SERVICE_SIGNATURE).expect("signature"),
    )
    .expect("b64")
    .try_into()
    .expect("64");
    assert!(
        pubky_switch_core::http::verify_response(
            &alice_service_key(),
            503,
            Some(&request_signature),
            header_text(&answer, header::SERVER_TIME).expect("time"),
            &answer.body,
            &signature,
        )
        .is_ok(),
        "signed with the account's key"
    );
    assert_eq!(rows(&replay, &alice_id()).await, before);
    assert!(replay.keys.public_key(&key).await.is_ok(), "the key stays");
    assert_eq!(
        replay.keys.erasure(&alice_id()).await.expect("ledger"),
        None
    );
    sqlx::query("DROP TRIGGER refuse_erasure ON accounts")
        .execute(&mut conn)
        .await
        .expect("drop trigger");
    conn.close().await.expect("close");
    assert_eq!(erase(&replay, &alice_service_key(), &at).await.status, 200);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_deletes_the_pending_key() {
    // A fresh enrollment at the serving account made a pending key of the next generation
    // (Switch wire 3.7): it goes with the account (7.4.16).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let served = item_time(&vectors("chain.json")["items"][1]);
    let again = fresh_enrollment(3);
    let answer = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", again, ms(&served)))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let pending: Option<String> =
        sqlx::query_scalar("SELECT pending_key FROM accounts WHERE id = $1")
            .bind(alice_id())
            .fetch_one(&mut conn)
            .await
            .expect("pending");
    conn.close().await.expect("close");
    let pending = KeyId::parse(&pending.expect("a pending key")).expect("key id");
    assert!(replay.keys.public_key(&pending).await.is_ok());
    assert_eq!(
        erase(&replay, &alice_service_key(), &served).await.status,
        200
    );
    assert!(
        replay.keys.public_key(&pending).await.is_err(),
        "the pending key is gone"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_owed_keys_swept_later() {
    // A key an erasure owes deleting, left by a key store failure or a crash, goes at the
    // next sweep, its erasure recorded in the ledger first (7.4.16, spec 6.5).
    let Some(replay) = replay().await else { return };
    let key = replay.keys.generate().await.expect("key");
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("INSERT INTO erased_keys (key_id, account_id, erased_at_ms) VALUES ($1, $2, 7)")
        .bind(key.id.as_str())
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("owed");
    replay.service.sweep_erased_keys().await;
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM erased_keys")
        .fetch_one(&mut conn)
        .await
        .expect("count");
    conn.close().await.expect("close");
    assert_eq!(left, 0);
    assert!(replay.keys.public_key(&key.id).await.is_err());
    assert_eq!(
        replay.keys.erasure(&alice_id()).await.expect("ledger"),
        Some(7)
    );
    replay.db.drop_database().await.expect("drop");
}

/// The vectors' enrollment with another nonce, signed by alice: a fresh one, not a retry.
fn fresh_enrollment(nonce: u8) -> Vec<u8> {
    use pubky_switch_core::{
        keys::IdentityKey,
        records::{Enrollment, EnrollmentBody},
        sig::SignedDoc,
    };
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
    let key = IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]));
    let enrollment = Enrollment::sign(&key, fields).expect("sign");
    serde_json::to_vec(&json!({ "enrollment": enrollment.signed() })).expect("json")
}

#[tokio::test]
async fn test_erase_waiting_feed_read_never_signs_with_the_erased_key() {
    // A feed read waits; the account is erased and enrolled again before the read wakes at
    // its wait's end. It finds its key gone and another account in its place: the operator's
    // temporary failure, never an answer signed with the erased key (Switch wire 7.4.16).
    use std::time::Duration;
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "GET",
        &format!("/v1/{}/feed?after=1:9&wait=2", alice_id()),
        Vec::new(),
        ms(&at),
    );
    let request_signature = signature_of(&request);
    let (answer, ()) = tokio::join!(replay.service.handle(request), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(erase(&replay, &alice_service_key(), &at).await.status, 200);
        let enrolled = replay
            .service
            .handle(signer_request(
                "POST",
                "/v1/enroll",
                fresh_enrollment(5),
                ms(&at),
            ))
            .await;
        assert_eq!(
            enrolled.status,
            200,
            "{}",
            String::from_utf8_lossy(&enrolled.body)
        );
    });
    assert_eq!(
        answer.status,
        503,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(no_head(&answer));
    assert!(operator_signed(&answer, Some(&request_signature)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_wakes_the_reads_waiting_on_the_account() {
    // The erasure's change notice wakes a feed read waiting on the account at once, not at its
    // wait's end, and it answers as for an unknown account (Switch wire 7.4.16).
    use std::time::Duration;
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let listener = pubky_switch::changes::ChangeListener::connect(replay.db.store())
        .await
        .expect("listen");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(listener.run(replay.service.changes(), async {
        let _ = stopped.await;
    }));
    let at = revoke_time();
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "GET",
        &format!("/v1/{}/feed?after=1:9&wait=20", alice_id()),
        Vec::new(),
        ms(&at),
    );
    let started = std::time::Instant::now();
    let (answer, ()) = tokio::join!(replay.service.handle(request), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(erase(&replay, &alice_service_key(), &at).await.status, 200);
    });
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "woken by the erasure"
    );
    let _ = stop.send(());
    task.await.expect("listener");
    replay.db.drop_database().await.expect("drop");
}

/// A key store that can fail the erasure ledger, and pause one `advance_mark`: the one after
/// `skip` others, before or after it moves the mark.
struct Gate {
    inner: std::sync::Arc<pubky_switch::keys::FixedKeys>,
    skip: std::sync::atomic::AtomicI64,
    after: bool,
    paused: tokio::sync::Notify,
    release: tokio::sync::Notify,
    fail_ledger: std::sync::atomic::AtomicBool,
}

impl KeyStore for Gate {
    fn generate(&self) -> pubky_switch::keys::KeyFuture<'_, pubky_switch::keys::ServiceKey> {
        self.inner.generate()
    }
    fn public_key<'a>(&'a self, id: &'a KeyId) -> pubky_switch::keys::KeyFuture<'a, [u8; 32]> {
        self.inner.public_key(id)
    }
    fn signer<'a>(
        &'a self,
        id: &'a KeyId,
    ) -> pubky_switch::keys::KeyFuture<'a, pubky_switch::keys::ServiceSigner> {
        self.inner.signer(id)
    }
    fn operator(&self) -> pubky_switch::keys::KeyFuture<'_, pubky_switch::keys::ServiceSigner> {
        self.inner.operator()
    }
    fn mark<'a>(
        &'a self,
        id: &'a KeyId,
    ) -> pubky_switch::keys::KeyFuture<'a, Option<pubky_switch::keys::Mark>> {
        self.inner.mark(id)
    }
    fn advance_mark<'a>(
        &'a self,
        id: &'a KeyId,
        head: pubky_switch::keys::Mark,
    ) -> pubky_switch::keys::KeyFuture<'a, pubky_switch::keys::MarkCheck> {
        use std::sync::atomic::Ordering;
        Box::pin(async move {
            let pause = self.skip.fetch_sub(1, Ordering::SeqCst) == 0;
            if pause && !self.after {
                self.paused.notify_one();
                self.release.notified().await;
            }
            let moved = self.inner.advance_mark(id, head).await;
            if pause && self.after {
                self.paused.notify_one();
                self.release.notified().await;
            }
            moved
        })
    }
    fn delete<'a>(&'a self, id: &'a KeyId) -> pubky_switch::keys::KeyFuture<'a, ()> {
        self.inner.delete(id)
    }
    fn record_erasure<'a>(
        &'a self,
        identity: &'a str,
        erased_at_ms: u64,
    ) -> pubky_switch::keys::KeyFuture<'a, ()> {
        if self.fail_ledger.load(std::sync::atomic::Ordering::SeqCst) {
            return Box::pin(async {
                Err(pubky_switch::keys::KeyStoreError::Io(
                    std::io::Error::other("disk full"),
                ))
            });
        }
        self.inner.record_erasure(identity, erased_at_ms)
    }
    fn erasure<'a>(&'a self, identity: &'a str) -> pubky_switch::keys::KeyFuture<'a, Option<u64>> {
        self.inner.erasure(identity)
    }
}

/// `replay`'s service on a [`Gate`] over its keys, pausing nothing until [`Gate::arm`], then
/// `after` its `advance_mark` moves the mark, or before.
fn gated(replay: &mut Replay, after: bool) -> std::sync::Arc<Gate> {
    let gate = std::sync::Arc::new(Gate {
        inner: replay.keys.clone(),
        skip: std::sync::atomic::AtomicI64::new(-1),
        after,
        paused: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        fail_ledger: std::sync::atomic::AtomicBool::new(false),
    });
    replay.service = pubky_switch::service::Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        gate.clone(),
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    );
    gate
}

impl Gate {
    /// Pause the `advance_mark` after `skip` more.
    fn arm(&self, skip: i64) {
        self.skip.store(skip, std::sync::atomic::Ordering::SeqCst);
    }
}

/// `request` answered while, once its `advance_mark` pauses, the account is erased.
async fn erased_meanwhile(
    replay: &Replay,
    gate: &Gate,
    request: pubky_switch::http::SwitchRequest,
) -> SwitchResponse {
    let at = revoke_time();
    let (answer, erased) = tokio::join!(replay.service.handle(request), async {
        gate.paused.notified().await;
        let erased = erase(replay, &alice_service_key(), &at).await;
        gate.release.notify_one();
        erased
    });
    assert_eq!(
        erased.status,
        200,
        "{}",
        String::from_utf8_lossy(&erased.body)
    );
    answer
}

#[tokio::test]
async fn test_erase_answer_withheld_until_its_key_is_gone() {
    // The key store can't record the erasure, so the key isn't deleted: the `200` isn't
    // released, the operator's `503` without a head goes out instead, and the key stays owed;
    // the next sweep deletes it, and the retry gets the operator's `404` (7.4.16 Order).
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    let key = service_key_id(&replay, &alice_id()).await;
    gate.fail_ledger
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let at = revoke_time();
    let request = signer_request(
        "POST",
        &erase_path(),
        erase_body(&alice_service_key()),
        ms(&at),
    );
    let request_signature = signature_of(&request);
    let answer = replay.service.handle(request).await;
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    assert!(no_head(&answer));
    assert!(operator_signed(&answer, Some(&request_signature)));
    assert!(
        replay.keys.public_key(&key).await.is_ok(),
        "the key is still owed"
    );
    gate.fail_ledger
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(replay.service.sweep_erased_keys().await, Some(Vec::new()));
    assert!(replay.keys.public_key(&key).await.is_err());
    assert_eq!(
        code_of(&erase(&replay, &alice_service_key(), &at).await),
        (404, json!("not_found"))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_owed_keys_swept_at_start() {
    // A key an erasure left owed goes when a service starts (7.4.16).
    let Some(replay) = replay().await else { return };
    let key = replay.keys.generate().await.expect("key");
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("INSERT INTO erased_keys (key_id, account_id, erased_at_ms) VALUES ($1, $2, 7)")
        .bind(key.id.as_str())
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("owed");
    conn.close().await.expect("close");
    let _started = pubky_switch::service::Service::start(
        ORIGIN.into(),
        replay.db.store().clone(),
        replay.keys.clone(),
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    )
    .await;
    assert!(replay.keys.public_key(&key.id).await.is_err());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_feed_page_whose_mark_moves_after_it_isnt_signed_with_its_key() {
    // A feed page read just before the erasure moves its mark just after it: the key is gone,
    // and the read answers as for an unknown account, never signed with the erased key and
    // never with its head (7.4.16).
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    // The request's own commit moves the mark first; the page's move is the second.
    gate.arm(1);
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "GET",
        &format!("/v1/{}/feed?after=1:0", alice_id()),
        Vec::new(),
        ms(&revoke_time()),
    );
    let request_signature = signature_of(&request);
    let answer = erased_meanwhile(&replay, &gate, request).await;
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    assert!(no_head(&answer));
    assert!(operator_signed(&answer, Some(&request_signature)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_write_whose_mark_moves_after_it_isnt_signed_with_its_key() {
    // A request committed just before the erasure moves its mark after the erasure deleted
    // the key: it answers as for an unknown account (7.4.16).
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    gate.arm(0);
    let request = signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&revoke_time()),
    );
    let request_signature = signature_of(&request);
    let answer = erased_meanwhile(&replay, &gate, request).await;
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    assert!(no_head(&answer));
    assert!(operator_signed(&answer, Some(&request_signature)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_deferred_claim_read_isnt_signed_with_its_key() {
    // A claim read whose entries are read once the lock is gone, after an erasure: as for an
    // unknown account, never signed with the erased key (7.4.16).
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, true);
    replay_chain_through_revoke(&replay).await;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let claim_key: Vec<u8> =
        sqlx::query_scalar("SELECT claim_key FROM claims WHERE account_id = $1 LIMIT 1")
            .bind(alice_id())
            .fetch_one(&mut conn)
            .await
            .expect("a claim");
    conn.close().await.expect("close");
    gate.arm(0);
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "GET",
        &format!(
            "/v1/{}/claims/{}",
            alice_id(),
            pubky_switch_core::enc::b64(&claim_key)
        ),
        Vec::new(),
        ms(&revoke_time()),
    );
    let request_signature = signature_of(&request);
    let answer = erased_meanwhile(&replay, &gate, request).await;
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    assert!(no_head(&answer));
    assert!(operator_signed(&answer, Some(&request_signature)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_refusal_moves_no_mark() {
    // An erasure's refusal commits only the stamped time: at an account whose state forks
    // from its key's mark, which fails every other call stop, the refusal is the erasure's
    // own `409`, not a `503` from a mark that can't move (7.4.16, 7.3 step 10).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("UPDATE accounts SET chain_hash = $2 WHERE id = $1")
        .bind(alice_id())
        .bind([9u8; 32].as_slice())
        .execute(&mut conn)
        .await
        .expect("fork");
    conn.close().await.expect("close");
    let answer = erase(&replay, &[7; 32], &revoke_time()).await;
    assert_eq!(code_of(&answer), (409, json!("conflict")));
    assert!(no_head(&answer));
    replay.db.drop_database().await.expect("drop");
}
