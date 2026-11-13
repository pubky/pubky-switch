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
    ("chain_retention", "account_id"),
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
    ("retired_enrollments", "account_id"),
    ("pending_revoked_apps", "account_id"),
    ("divergent_uploads", "account_id"),
    ("connect_requests", "account_id"),
    ("push_registrations", "account_id"),
    ("push_deliveries", "account_id"),
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
            erase_body(key, None),
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
            erase_body(&alice_service_key(), None),
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
            erase_body(&alice_service_key(), None),
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
            erase_body(&alice_service_key(), None),
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
        erase_body(&alice_service_key(), None),
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
    // wait's end, and it answers as for an account the service doesn't host (Switch wire
    // 7.4.16).
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
    // As for an account the service doesn't host: the `404`, or the `503` while the erased
    // key's deletion is still owed in the moment after the erasure's commit.
    assert!(
        matches!(code_of(&answer).0, 404 | 503),
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(no_head(&answer));
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
    fail_delete: std::sync::atomic::AtomicBool,
    fail_advance: std::sync::atomic::AtomicBool,
    /// Fails every read of the erasure ledger.
    fail_ledger_read: std::sync::atomic::AtomicBool,
    /// The erasures it was asked to record.
    recorded: std::sync::atomic::AtomicUsize,
}

impl KeyStore for Gate {
    fn generate(&self) -> pubky_switch::keys::KeyFuture<'_, pubky_switch::keys::ServiceKey> {
        self.inner.generate()
    }
    fn generate_as<'a>(
        &'a self,
        id: &'a KeyId,
    ) -> pubky_switch::keys::KeyFuture<'a, pubky_switch::keys::ServiceKey> {
        self.inner.generate_as(id)
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
            if self.fail_advance.load(Ordering::SeqCst) {
                return Err(pubky_switch::keys::KeyStoreError::Io(
                    std::io::Error::other("read-only"),
                ));
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
        if self.fail_delete.load(std::sync::atomic::Ordering::SeqCst) {
            return Box::pin(async {
                Err(pubky_switch::keys::KeyStoreError::Io(
                    std::io::Error::other("read-only"),
                ))
            });
        }
        self.inner.delete(id)
    }
    fn record_erasure<'a>(
        &'a self,
        identity: &'a str,
        erased_at_ms: u64,
    ) -> pubky_switch::keys::KeyFuture<'a, ()> {
        self.recorded
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
        if self
            .fail_ledger_read
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Box::pin(async {
                Err(pubky_switch::keys::KeyStoreError::Io(
                    std::io::Error::other("unreadable"),
                ))
            });
        }
        self.inner.erasure(identity)
    }

    fn erasures(&self) -> pubky_switch::keys::KeyFuture<'_, Vec<(String, u64)>> {
        self.inner.erasures()
    }

    fn forget_erasures_before(&self, before_ms: u64) -> pubky_switch::keys::KeyFuture<'_, usize> {
        self.inner.forget_erasures_before(before_ms)
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
        fail_delete: std::sync::atomic::AtomicBool::new(false),
        fail_advance: std::sync::atomic::AtomicBool::new(false),
        fail_ledger_read: std::sync::atomic::AtomicBool::new(false),
        recorded: std::sync::atomic::AtomicUsize::new(0),
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
    // released, the operator's `503` without a head goes out instead, and the key stays owed.
    // While it is, the account answers as gone but owed: the immediate retry and a `GET /apps`
    // get the operator's `503`, never the `404` the signer would take as done. Once the key
    // store works again, the retry's sweep deletes the key, and its answer is the `404`
    // (7.4.16 Order).
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
        erase_body(&alice_service_key(), None),
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
    let retry = erase(&replay, &alice_service_key(), &at).await;
    assert_eq!(code_of(&retry), (503, json!("unavailable")), "the retry");
    let apps = replay
        .service
        .handle(signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            ms(&at),
        ))
        .await;
    assert_eq!(code_of(&apps), (503, json!("unavailable")), "a read");
    gate.fail_ledger
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        code_of(&erase(&replay, &alice_service_key(), &at).await),
        (404, json!("not_found"))
    );
    assert!(replay.keys.public_key(&key).await.is_err());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_answer_withheld_while_its_key_cant_be_deleted() {
    // The key store can't delete the key: as for a ledger that can't be written, the
    // operator's `503`, the key owed (7.4.16 Order).
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    let key = service_key_id(&replay, &alice_id()).await;
    gate.fail_delete
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let answer = erase(&replay, &alice_service_key(), &revoke_time()).await;
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    assert!(no_head(&answer));
    assert!(replay.keys.public_key(&key).await.is_ok());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_gone_account_whose_owed_keys_cant_be_read_isnt_a_404() {
    // The owed keys can't be read: the account gone may still owe one, so the operator's
    // `503`, not the `404` (7.4.16).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    assert_eq!(erase(&replay, &alice_service_key(), &at).await.status, 200);
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("ALTER TABLE erased_keys RENAME TO erased_keys_away")
        .execute(&mut conn)
        .await
        .expect("rename");
    let apps = replay
        .service
        .handle(signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            ms(&at),
        ))
        .await;
    assert_eq!(code_of(&apps), (503, json!("unavailable")));
    sqlx::query("ALTER TABLE erased_keys_away RENAME TO erased_keys")
        .execute(&mut conn)
        .await
        .expect("rename back");
    conn.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_feed_page_after_an_erasure_whose_key_stays_isnt_signed_with_it() {
    // The erasure couldn't delete its key: a feed page read just before it, whose mark move
    // then succeeds, still answers as for an account gone, the operator's `404` to an app,
    // not signed with that key (7.4.16).
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    gate.fail_delete
        .store(true, std::sync::atomic::Ordering::SeqCst);
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
    let at = revoke_time();
    let (answer, erased) = tokio::join!(replay.service.handle(request), async {
        gate.paused.notified().await;
        let erased = erase(&replay, &alice_service_key(), &at).await;
        gate.release.notify_one();
        erased
    });
    assert_eq!(code_of(&erased), (503, json!("unavailable")));
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    assert!(no_head(&answer));
    assert!(operator_signed(&answer, Some(&request_signature)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_write_answered_after_a_new_enrollment_isnt_signed_with_the_old_key() {
    // A request committed just before the erasure moves its mark after the account was erased
    // and enrolled again: the account names another key now, and the answer is the operator's
    // `503` (7.4.16).
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    gate.arm(0);
    let at = revoke_time();
    let request = signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&at),
    );
    let request_signature = signature_of(&request);
    let (answer, ()) = tokio::join!(replay.service.handle(request), async {
        gate.paused.notified().await;
        assert_eq!(erase(&replay, &alice_service_key(), &at).await.status, 200);
        let enrolled = replay
            .service
            .handle(signer_request(
                "POST",
                "/v1/enroll",
                fresh_enrollment(6),
                ms(&at),
            ))
            .await;
        assert_eq!(enrolled.status, 200);
        gate.release.notify_one();
    });
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    assert!(no_head(&answer));
    assert!(operator_signed(&answer, Some(&request_signature)));
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

#[tokio::test]
async fn test_erase_feed_refusal_after_an_erasure_whose_key_stays_isnt_signed_with_it() {
    // The key store fails: the erasure's key isn't deleted, and a feed page's mark move then
    // fails too. The refusal goes out once the lock is gone, so as for an account gone, the
    // operator's `404` to an app, not signed with the erased key, and without its head
    // (7.4.16).
    use std::sync::atomic::Ordering;
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "GET",
        &format!("/v1/{}/feed?after=1:0", alice_id()),
        Vec::new(),
        ms(&at),
    );
    let request_signature = signature_of(&request);
    gate.arm(1);
    let (answer, erased) = tokio::join!(replay.service.handle(request), async {
        gate.paused.notified().await;
        gate.fail_ledger.store(true, Ordering::SeqCst);
        let erased = erase(&replay, &alice_service_key(), &at).await;
        gate.fail_advance.store(true, Ordering::SeqCst);
        gate.release.notify_one();
        erased
    });
    assert_eq!(code_of(&erased), (503, json!("unavailable")));
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    assert!(no_head(&answer));
    assert!(operator_signed(&answer, Some(&request_signature)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_retries_sweep_a_few_times_a_minute() {
    // A retried erasure of an account gone sweeps its owed keys at most six times a minute
    // for the account: a verified request can be replayed (7.4.16).
    use std::sync::atomic::Ordering;
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    gate.fail_ledger.store(true, Ordering::SeqCst);
    let at = revoke_time();
    assert_eq!(
        code_of(&erase(&replay, &alice_service_key(), &at).await).0,
        503
    );
    let first = gate.recorded.load(Ordering::SeqCst);
    for _ in 0..10 {
        assert_eq!(
            code_of(&erase(&replay, &alice_service_key(), &at).await).0,
            503
        );
    }
    assert_eq!(
        gate.recorded.load(Ordering::SeqCst) - first,
        6,
        "six sweeps in the minute"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_deferred_allow_read_isnt_signed_with_its_key() {
    // A `GET /allow` whose lists are read once the lock is gone, after an erasure: as for an
    // account the service doesn't host, never signed with the erased key (7.4.16).
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, true);
    replay_chain_through_revoke(&replay).await;
    gate.arm(0);
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "GET",
        &format!("/v1/{}/allow", alice_id()),
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
async fn test_erase_deferred_records_page_isnt_signed_with_its_key() {
    // A `GET /records` page read once the lock is gone, from a snapshot taken before an
    // erasure: the page reads, but as for an account the service doesn't host, it is never
    // signed with the erased key (7.4.16).
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, true);
    replay_chain_through_revoke(&replay).await;
    gate.arm(0);
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "GET",
        &format!(
            "/v1/{}/records?collection={}",
            alice_id(),
            pubky_switch_core::enc::b64(&[1; 32])
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

/// The answer is signed with alice's service key.
fn alice_signed(answer: &SwitchResponse, request_signature: Option<&[u8; 64]>) -> bool {
    let Some(text) = header_text(answer, header::SERVICE_SIGNATURE) else {
        return false;
    };
    let signature: [u8; 64] = pubky_switch_core::enc::unb64(text)
        .expect("b64")
        .try_into()
        .expect("64");
    pubky_switch_core::http::verify_response(
        &alice_service_key(),
        answer.status,
        request_signature,
        header_text(answer, header::SERVER_TIME).expect("time"),
        &answer.body,
        &signature,
    )
    .is_ok()
}

/// alice served, with the wallet's ops 3 and 4 and the phone's app record delivered, at
/// chain item 3's time, which it returns.
async fn registered(replay: &Replay) -> String {
    use pubky_switch_core::{
        keys::IdentityKey,
        ops::{OpKind, OpsRequest, SignedOp, sign_batch},
        sig::SignedDoc,
    };
    serve_alice(replay).await;
    let chain = vectors("chain.json");
    let keys = vectors("keys.json");
    let at = item_time(chain_item(&chain, 3));
    set_time(&replay.clock, &at);
    let post = |name: &'static str, ops: Vec<SignedOp>| {
        let request = app_request(
            app(&keys, name),
            "POST",
            &format!("/v1/{}/ops", alice_id()),
            OpsRequest::new(&ops, None).to_json(),
            ms(&at),
        );
        async move {
            let answer = replay.service.handle(request).await;
            assert_eq!(
                answer.status,
                200,
                "{}",
                String::from_utf8_lossy(&answer.body)
            );
        }
    };
    let ops: Vec<SignedOp> = [3, 4]
        .iter()
        .map(|seq| {
            let signed: SignedDoc =
                serde_json::from_value(chain_item(&chain, *seq)["item"].clone()).expect("op");
            SignedOp::peek(&signed).expect("op")
        })
        .collect();
    post("wallet", ops).await;
    let document = |name: &str| -> SignedDoc {
        serde_json::from_value(
            named(&vectors("documents.json")["documents"], name)["signed"].clone(),
        )
        .expect("document")
    };
    let phone = app(&keys, "phone");
    let key = ed25519_dalek::SigningKey::from_bytes(&hex32(&phone["signing_secret_hex"]));
    let app_id = pubky_switch_core::enc::app_id_decode(phone["app_id"].as_str().expect("id"))
        .expect("app id");
    let alice = IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let ops = sign_batch(
        &key,
        &alice.public(),
        Some(app_id),
        1,
        [80; 16],
        vec![
            (
                Vec::new(),
                OpKind::AppPut {
                    record: document("phone app record"),
                },
            ),
            (
                Vec::new(),
                OpKind::ReceiveKeyPut {
                    record: document("phone receive key record"),
                },
            ),
        ],
    )
    .expect("batch");
    post("phone", ops).await;
    at
}

#[tokio::test]
async fn test_erase_read_waiting_its_turn_across_an_erasure_isnt_signed_with_its_key() {
    // The phone's `GET /allow` waits for its account's turn, before the lock, behind the
    // wallet's paused page. The account is erased meanwhile and its key stays owed (the
    // ledger fails). The wait times out (`lock_timeout_ms`, 10 s): the answer is the
    // operator's `404` to an app, never signed with the erased key (7.4.16).
    use std::sync::atomic::Ordering;
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    let at = registered(&replay).await;
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/allow", alice_id());
    let first = app_request(app(&keys, "wallet"), "GET", &path, Vec::new(), ms(&at));
    let second = app_request(app(&keys, "phone"), "GET", &path, Vec::new(), ms(&at));
    let second_signature = signature_of(&second);
    let pause = replay.db.pause_next_snapshot_read();
    let (_, (second, erased)) = tokio::join!(replay.service.handle(first), async {
        tokio::time::timeout(std::time::Duration::from_secs(10), pause.reached.notified())
            .await
            .expect("the wallet's page paused after the lock");
        let (second, erased) = tokio::join!(replay.service.handle(second), async {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while replay.db.queued_reads(&alice_id()) < 2 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the phone never queued"
                );
                tokio::task::yield_now().await;
            }
            gate.fail_ledger.store(true, Ordering::SeqCst);
            erase(&replay, &alice_service_key(), &at).await
        });
        pause.resume.notify_one();
        (second, erased)
    });
    assert_eq!(code_of(&erased), (503, json!("unavailable")));
    assert_eq!(code_of(&second), (404, json!("not_found")));
    assert!(
        !alice_signed(&second, Some(&second_signature)),
        "signed with the erased account's key"
    );
    assert!(operator_signed(&second, Some(&second_signature)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_records_list_waiting_its_turn_across_an_erasure_isnt_signed_with_its_key() {
    // As for `GET /allow`: the phone's `GET /records` list waits for its account's turn,
    // before the lock, behind the wallet's paused page; the account is erased meanwhile and
    // its key stays owed. The wait's `503` is the operator's, never signed with the erased
    // key (7.4.16).
    use std::sync::atomic::Ordering;
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    let at = registered(&replay).await;
    let keys = vectors("keys.json");
    let allow = format!("/v1/{}/allow", alice_id());
    let list = format!(
        "/v1/{}/records?collection={}",
        alice_id(),
        pubky_switch_core::enc::b64(&[1; 32])
    );
    let first = app_request(app(&keys, "wallet"), "GET", &allow, Vec::new(), ms(&at));
    let second = app_request(app(&keys, "phone"), "GET", &list, Vec::new(), ms(&at));
    let second_signature = signature_of(&second);
    let pause = replay.db.pause_next_snapshot_read();
    let (_, (second, erased)) = tokio::join!(replay.service.handle(first), async {
        tokio::time::timeout(std::time::Duration::from_secs(10), pause.reached.notified())
            .await
            .expect("the wallet's page paused after the lock");
        let (second, erased) = tokio::join!(replay.service.handle(second), async {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while replay.db.queued_reads(&alice_id()) < 2 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the phone never queued"
                );
                tokio::task::yield_now().await;
            }
            gate.fail_ledger.store(true, Ordering::SeqCst);
            erase(&replay, &alice_service_key(), &at).await
        });
        pause.resume.notify_one();
        (second, erased)
    });
    assert_eq!(code_of(&erased), (503, json!("unavailable")));
    assert_eq!(code_of(&second), (404, json!("not_found")));
    assert!(
        !alice_signed(&second, Some(&second_signature)),
        "signed with the erased account's key"
    );
    assert!(operator_signed(&second, Some(&second_signature)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_lock_waiter_after_an_erasure_whose_key_stays_isnt_a_404() {
    // The signer's GET /apps looks the account up and waits for its lock behind an erasure
    // whose key then stays owed (the ledger fails). The waiter finds the account gone at the
    // lock: the operator's `503` to the signer while a key is owed (7.4.16).
    use std::sync::atomic::Ordering;
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    gate.fail_ledger.store(true, Ordering::SeqCst);
    let at = revoke_time();
    let mut holder = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("BEGIN")
        .execute(&mut holder)
        .await
        .expect("begin");
    sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(alice_id())
        .execute(&mut holder)
        .await
        .expect("lock");
    let options = replay.db.options().clone();
    let apps = signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&at),
    );
    let key = alice_service_key();
    let (erased, (answer, ())) = tokio::join!(erase(&replay, &key, &at), async {
        lock_waiters(&options, 1).await;
        tokio::join!(replay.service.handle(apps), async {
            lock_waiters(&options, 2).await;
            sqlx::query("COMMIT")
                .execute(&mut holder)
                .await
                .expect("commit");
        })
    });
    assert_eq!(code_of(&erased), (503, json!("unavailable")));
    assert_eq!(
        code_of(&answer),
        (503, json!("unavailable")),
        "a 404 while the key is owed"
    );
    replay.db.drop_database().await.expect("drop");
}

/// Wait until `n` backends of the test database wait for a lock.
async fn lock_waiters(options: &sqlx::postgres::PgConnectOptions, n: i64) {
    let mut watcher = sqlx::PgConnection::connect_with(options)
        .await
        .expect("conn");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' \
             AND datname = current_database()",
        )
        .fetch_one(&mut watcher)
        .await
        .expect("count");
        if count >= n {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{count} waiting, not {n}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// alice's erasure, its key store unable to record it: `503`, and its key stays owed.
async fn erased_owing_its_key(replay: &mut Replay) -> std::sync::Arc<Gate> {
    let gate = gated(replay, false);
    replay_chain_through_revoke(replay).await;
    gate.fail_ledger
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let erased = erase(replay, &alice_service_key(), &revoke_time()).await;
    assert_eq!(code_of(&erased), (503, json!("unavailable")));
    gate
}

/// `request` with its body changed after it was signed: its signature no longer verifies.
fn tampered(mut request: pubky_switch::http::SwitchRequest) -> pubky_switch::http::SwitchRequest {
    request.body = erase_body(&[1; 32], None).into();
    request
}

#[tokio::test]
async fn test_erase_owed_keys_hold_back_only_the_signers_404() {
    // While an erased account's key is owed, only its signer, its request verified with the
    // identity key, gets the operator's `503` in place of the `404`: the public read, an
    // app's call and a request whose signature doesn't verify get the `404` (7.4.16, 7.3
    // step 2).
    let Some(mut replay) = replay().await else {
        return;
    };
    let _gate = erased_owing_its_key(&mut replay).await;
    let at = revoke_time();
    let keys = vectors("keys.json");
    let signer = signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&at),
    );
    assert_eq!(
        code_of(&replay.service.handle(signer).await),
        (503, json!("unavailable"))
    );
    let others = vec![
        request(
            "GET",
            &format!("/v1/{}/identity", alice_id()),
            &[],
            Vec::new(),
        ),
        app_request(
            app(&keys, "wallet"),
            "GET",
            &format!("/v1/{}/feed", alice_id()),
            Vec::new(),
            ms(&at),
        ),
        tampered(signer_request(
            "POST",
            &erase_path(),
            erase_body(&alice_service_key(), None),
            ms(&at),
        )),
    ];
    for request in others {
        let path = request.path_and_query.clone();
        let request_signature = request
            .headers
            .contains_key(header::SIGNATURE)
            .then(|| signature_of(&request));
        let answer = replay.service.handle(request).await;
        assert_eq!(code_of(&answer), (404, json!("not_found")), "{path}");
        assert!(no_head(&answer), "{path}");
        assert!(
            operator_signed(&answer, request_signature.as_ref()),
            "{path}"
        );
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_retry_that_doesnt_verify_sweeps_nothing() {
    // A retried erasure sweeps the owed keys only when its signature verifies with the
    // identity key: one that doesn't verify gets the `404` and the key stays owed; the
    // signer's own retry then sweeps it (7.4.16).
    use std::sync::atomic::Ordering;
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    let key = service_key_id(&replay, &alice_id()).await;
    gate.fail_ledger.store(true, Ordering::SeqCst);
    let at = revoke_time();
    let erased = erase(&replay, &alice_service_key(), &at).await;
    assert_eq!(code_of(&erased), (503, json!("unavailable")));
    gate.fail_ledger.store(false, Ordering::SeqCst);
    let retry = || {
        signer_request(
            "POST",
            &erase_path(),
            erase_body(&alice_service_key(), None),
            ms(&at),
        )
    };
    let recorded = gate.recorded.load(Ordering::SeqCst);
    let answer = replay.service.handle(tampered(retry())).await;
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    assert_eq!(gate.recorded.load(Ordering::SeqCst), recorded, "no sweep");
    assert!(replay.keys.public_key(&key).await.is_ok(), "still owed");
    let answer = replay.service.handle(retry()).await;
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    assert!(replay.keys.public_key(&key).await.is_err(), "swept");
    replay.db.drop_database().await.expect("drop");
}

/// alice's signer request signed over `origin` instead of the service's.
fn signer_request_for(
    origin: &str,
    method: &str,
    path: &str,
    body: Vec<u8>,
    at_ms: u64,
) -> pubky_switch::http::SwitchRequest {
    use pubky_switch_core::http::{RequestHeaders, RequestTarget};
    let keys = vectors("keys.json");
    let alice = alice(&keys);
    let alice_id = alice["pubky_id"].as_str().expect("id").to_string();
    let timestamp = pubky_switch_core::time::rfc3339_seconds(at_ms);
    let signed_headers = RequestHeaders {
        timestamp: timestamp.clone(),
        identity: alice_id.clone(),
        ..RequestHeaders::default()
    };
    let secret = ed25519_dalek::SigningKey::from_bytes(&hex32(&alice["secret_hex"]));
    let signature = pubky_switch_core::enc::b64(&pubky_switch_core::http::sign_request(
        &secret,
        &RequestTarget {
            method,
            path_and_query: path,
            body: &body,
            origin,
        },
        &signed_headers,
    ));
    request(
        method,
        path,
        &[
            (header::IDENTITY, &alice_id),
            (header::TIMESTAMP, &timestamp),
            (header::SIGNATURE, &signature),
        ],
        body,
    )
}

#[tokio::test]
async fn test_erase_stale_signer_while_its_key_is_owed_isnt_a_404() {
    // The signer's clock is 10 minutes off. At a hosted account its requests get a `401
    // stale_timestamp` signed with the account's key, which the client retries once at the
    // service's time (Switch wire 7.1). Once erased with its key owed, the same signer's
    // retried erasure and its check's `GET /apps` still get the operator's `503`, not the
    // `404` the signer takes as its erasure done: the signature decides, whatever the
    // timestamp (7.4.16).
    use std::sync::atomic::Ordering;
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    let at = ms(&revoke_time());
    let skewed = at - 10 * 60_000;
    let apps = || {
        signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            skewed,
        )
    };
    let hosted = apps();
    let hosted_signature = signature_of(&hosted);
    let answer = replay.service.handle(hosted).await;
    assert_eq!(code_of(&answer), (401, json!("stale_timestamp")));
    assert!(
        alice_signed(&answer, Some(&hosted_signature)),
        "the client retries this one"
    );
    gate.fail_ledger.store(true, Ordering::SeqCst);
    let erased = erase(&replay, &alice_service_key(), &revoke_time()).await;
    assert_eq!(code_of(&erased), (503, json!("unavailable")));
    let retry = signer_request(
        "POST",
        &erase_path(),
        erase_body(&alice_service_key(), None),
        skewed,
    );
    let mut got = Vec::new();
    for request in [retry, apps()] {
        let path = request.path_and_query.clone();
        let answer = replay.service.handle(request).await;
        got.push((path, code_of(&answer)));
    }
    replay.db.drop_database().await.expect("drop");
    for (path, code) in got {
        assert_eq!(
            code,
            (503, json!("unavailable")),
            "{path}: the operator's 404 to the signer while its key is owed"
        );
    }
}

#[tokio::test]
async fn test_erase_signer_request_for_another_origin_is_the_404() {
    // A request signed with the identity key over another service's origin isn't the
    // signer's here: the `404` at once, no sweep (7.1, 7.4.16).
    use std::sync::atomic::Ordering;
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    let key = service_key_id(&replay, &alice_id()).await;
    gate.fail_ledger.store(true, Ordering::SeqCst);
    let at = revoke_time();
    let erased = erase(&replay, &alice_service_key(), &at).await;
    assert_eq!(code_of(&erased), (503, json!("unavailable")));
    gate.fail_ledger.store(false, Ordering::SeqCst);
    let recorded = gate.recorded.load(Ordering::SeqCst);
    let elsewhere = signer_request_for(
        BOB_ORIGIN,
        "POST",
        &erase_path(),
        erase_body(&alice_service_key(), None),
        ms(&at),
    );
    let signature = signature_of(&elsewhere);
    let answer = replay.service.handle(elsewhere).await;
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    assert!(operator_signed(&answer, Some(&signature)));
    assert_eq!(gate.recorded.load(Ordering::SeqCst), recorded, "no sweep");
    assert!(replay.keys.public_key(&key).await.is_ok(), "still owed");
    // The same request over this origin is the signer's: held back, then swept.
    let here = signer_request_for(
        ORIGIN,
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&at),
    );
    gate.fail_ledger.store(true, Ordering::SeqCst);
    assert_eq!(
        code_of(&replay.service.handle(here).await),
        (503, json!("unavailable"))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_signer_mark_move_failing_after_an_erasure_owing_its_key_isnt_a_404() {
    // A read-only key store: the signer's `GET /apps` commits just before the erasure, which
    // can't record or delete its key, and its mark move then fails too. The answer goes out
    // once the lock is gone (the commit-failed arm): to the signer, the operator's `503`
    // while the key is owed, never the `404` it takes as its erasure done (7.4.16).
    use std::sync::atomic::Ordering;
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    gate.arm(0);
    let at = revoke_time();
    let request = signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&at),
    );
    let request_signature = signature_of(&request);
    let (answer, erased) = tokio::join!(replay.service.handle(request), async {
        gate.paused.notified().await;
        gate.fail_ledger.store(true, Ordering::SeqCst);
        let erased = erase(&replay, &alice_service_key(), &at).await;
        gate.fail_advance.store(true, Ordering::SeqCst);
        gate.release.notify_one();
        erased
    });
    let got = (code_of(&erased), code_of(&answer), no_head(&answer));
    let operator = operator_signed(&answer, Some(&request_signature));
    replay.db.drop_database().await.expect("drop");
    assert_eq!(got.0, (503, json!("unavailable")));
    assert_eq!(
        got.1,
        (503, json!("unavailable")),
        "a 404 to the signer while its key is owed"
    );
    assert!(got.2);
    assert!(operator);
}

#[tokio::test]
async fn test_erase_app_lock_waiter_after_an_erasure_owing_its_key_is_the_404() {
    // As `test_erase_lock_waiter_after_an_erasure_whose_key_stays_isnt_a_404`, for an app's
    // call: the operator's `404` at once, the key owed or not (7.4.16).
    use std::sync::atomic::Ordering;
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    gate.fail_ledger.store(true, Ordering::SeqCst);
    let at = revoke_time();
    let mut holder = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("BEGIN")
        .execute(&mut holder)
        .await
        .expect("begin");
    sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(alice_id())
        .execute(&mut holder)
        .await
        .expect("lock");
    let options = replay.db.options().clone();
    let keys = vectors("keys.json");
    let feed = app_request(
        app(&keys, "wallet"),
        "GET",
        &format!("/v1/{}/feed", alice_id()),
        Vec::new(),
        ms(&at),
    );
    let feed_signature = signature_of(&feed);
    let key = alice_service_key();
    let (erased, (answer, ())) = tokio::join!(erase(&replay, &key, &at), async {
        lock_waiters(&options, 1).await;
        tokio::join!(replay.service.handle(feed), async {
            lock_waiters(&options, 2).await;
            sqlx::query("COMMIT")
                .execute(&mut holder)
                .await
                .expect("commit");
        })
    });
    let got = (code_of(&erased), code_of(&answer));
    let operator = operator_signed(&answer, Some(&feed_signature));
    replay.db.drop_database().await.expect("drop");
    assert_eq!(got.0, (503, json!("unavailable")));
    assert_eq!(got.1, (404, json!("not_found")));
    assert!(operator);
}

#[tokio::test]
async fn test_erase_stale_signer_retry_sweeps_nothing() {
    // A retried erasure signed by the signer, its timestamp 10 minutes off: the operator's
    // `503` while the key is owed, and no sweep, since only a request within the time window
    // starts one. The signer's retry at the service's time sweeps it (7.4.16, 7.1).
    use std::sync::atomic::Ordering;
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    let key = service_key_id(&replay, &alice_id()).await;
    gate.fail_ledger.store(true, Ordering::SeqCst);
    let at = ms(&revoke_time());
    let retry = |at_ms| {
        signer_request(
            "POST",
            &erase_path(),
            erase_body(&alice_service_key(), None),
            at_ms,
        )
    };
    assert_eq!(
        code_of(&replay.service.handle(retry(at)).await),
        (503, json!("unavailable"))
    );
    gate.fail_ledger.store(false, Ordering::SeqCst);
    let recorded = gate.recorded.load(Ordering::SeqCst);
    let answer = replay.service.handle(retry(at - 10 * 60_000)).await;
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    assert_eq!(gate.recorded.load(Ordering::SeqCst), recorded, "no sweep");
    assert!(replay.keys.public_key(&key).await.is_ok(), "still owed");
    assert_eq!(
        code_of(&replay.service.handle(retry(at)).await),
        (404, json!("not_found"))
    );
    assert!(replay.keys.public_key(&key).await.is_err(), "swept");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_own_app_view_gone_after_the_lookup_isnt_signed_with_its_key() {
    // An own app's request finds the account, then its view of the account's state, read
    // before the lock, finds none: the account was erased in between, its key owed. The
    // early `404` is the operator's, never signed with the erased key (7.4.16).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let key = service_key_id(&replay, &alice_id()).await;
    let at = revoke_time();
    let mut holder = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    // `kept_app_ids` is read by the app's view and not by the lookup: the view waits on it.
    sqlx::query("BEGIN")
        .execute(&mut holder)
        .await
        .expect("begin");
    sqlx::query("LOCK TABLE kept_app_ids IN ACCESS EXCLUSIVE MODE")
        .execute(&mut holder)
        .await
        .expect("lock");
    let options = replay.db.options().clone();
    let keys = vectors("keys.json");
    let feed = app_request(
        app(&keys, "wallet"),
        "GET",
        &format!("/v1/{}/feed", alice_id()),
        Vec::new(),
        ms(&at),
    );
    let feed_signature = signature_of(&feed);
    let (answer, ()) = tokio::join!(replay.service.handle(feed), async {
        lock_waiters(&options, 1).await;
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(alice_id())
            .execute(&mut holder)
            .await
            .expect("erase");
        sqlx::query(
            "INSERT INTO erased_keys (key_id, account_id, erased_at_ms) VALUES ($1, $2, 7)",
        )
        .bind(key.as_str())
        .bind(alice_id())
        .execute(&mut holder)
        .await
        .expect("owed");
        sqlx::query("COMMIT")
            .execute(&mut holder)
            .await
            .expect("commit");
    });
    let got = code_of(&answer);
    let erased_key = alice_signed(&answer, Some(&feed_signature));
    let operator = operator_signed(&answer, Some(&feed_signature));
    replay.db.drop_database().await.expect("drop");
    assert_eq!(got, (404, json!("not_found")));
    assert!(!erased_key, "signed with the erased account's key");
    assert!(operator);
}

#[tokio::test]
async fn test_erase_vector_naming_the_identity_json_it_follows() {
    // http.json's erasure naming the hash of alice's version 3, which her account holds, and
    // its answer: `{ "erased": true }`, signed with the account's key, without a head (Switch
    // wire 7.4.16).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let http = vectors("http.json");
    let expected = named(
        &http["responses"],
        "signer: account erasure answer to the request naming its identity.json, signed with the account's key, no head",
    );
    set_time(
        &replay.clock,
        expected["headers"]["switch-server-time"]
            .as_str()
            .expect("time"),
    );
    let request = vector_request(named(
        &http["requests"],
        "signer: account erasure, naming the account's service key and the identity.json it follows",
    ));
    let answer = replay.service.handle(request).await;
    assert_matches(&answer, expected);
    assert!(no_head(&answer));
    assert_eq!(rows(&replay, &alice_id()).await[0], ("accounts", 0));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_vector_naming_another_identity_json_is_conflict() {
    // http.json's erasure naming alice's version 1 while her account holds version 3: the
    // vector's `409 conflict`, signed with the account's key, without a head, and nothing is
    // deleted, so an erasure can't follow a delivery made after the signer's last check
    // (Switch wire 7.4.16).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let before = rows(&replay, &alice_id()).await;
    let http = vectors("http.json");
    let expected = named(
        &http["responses"],
        "signer: account erasure refused, the account holds another identity.json, 409 conflict, no head",
    );
    set_time(
        &replay.clock,
        expected["headers"]["switch-server-time"]
            .as_str()
            .expect("time"),
    );
    let request = vector_request(named(
        &http["requests"],
        "signer: account erasure naming an identity.json the account doesn't hold",
    ));
    let answer = replay.service.handle(request).await;
    assert_matches(&answer, expected);
    assert!(no_head(&answer));
    assert_eq!(rows(&replay, &alice_id()).await, before, "nothing deleted");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_naming_a_hash_at_an_account_holding_no_identity_json_is_conflict() {
    // A staged account, enrolled and not yet delivered to, holds no `identity.json`: a hash
    // can't match, `409 conflict`, nothing deleted; the key alone erases it (7.4.16).
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
    let named_hash = replay
        .service
        .handle(signer_request(
            "POST",
            &erase_path(),
            erase_body(&alice_service_key(), Some(&[9; 32])),
            ms(&at),
        ))
        .await;
    assert_eq!(code_of(&named_hash), (409, json!("conflict")));
    assert!(no_head(&named_hash));
    assert_eq!(rows(&replay, &alice_id()).await[0], ("accounts", 1));
    assert_eq!(erase(&replay, &alice_service_key(), &at).await.status, 200);
    replay.db.drop_database().await.expect("drop");
}

/// The document hash of documents.json's `name`.
fn doc_hash(name: &str) -> [u8; 32] {
    let doc: pubky_switch_core::sig::SignedDoc = serde_json::from_value(
        named(&vectors("documents.json")["documents"], name)["signed"].clone(),
    )
    .expect("signed doc");
    doc.doc_hash().expect("hash")
}

/// The time of the erasure answer naming its `identity.json` in http.json.
fn hash_vector_time() -> String {
    let http = vectors("http.json");
    named(
        &http["responses"],
        "signer: account erasure answer to the request naming its identity.json, signed with the account's key, no head",
    )["headers"]["switch-server-time"]
        .as_str()
        .expect("time")
        .to_string()
}

#[tokio::test]
async fn test_erase_malformed_identity_hash_is_bad_request_not_conflict() {
    // A malformed `identity_hash` (short, not a string, null) or an unknown member is `400`,
    // never a `409`, without a head, and nothing is deleted (wire 7.4.16, 1.1).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let at = hash_vector_time();
    set_time(&replay.clock, &at);
    let before = rows(&replay, &alice_id()).await;
    let key = pubky_switch_core::enc::b64(&alice_service_key());
    let held = pubky_switch_core::enc::b64(&doc_hash("alice identity.json"));
    for body in [
        format!(r#"{{"service_key":"{key}","identity_hash":"AA"}}"#),
        format!(r#"{{"service_key":"{key}","identity_hash":7}}"#),
        format!(r#"{{"service_key":"{key}","identity_hash":null}}"#),
        format!(r#"{{"service_key":"{key}","identity_hash":"{held}","x":1}}"#),
    ] {
        let answer = replay
            .service
            .handle(signer_request(
                "POST",
                &erase_path(),
                body.clone().into_bytes(),
                ms(&at),
            ))
            .await;
        assert_eq!(code_of(&answer), (400, json!("bad_request")), "{body}");
        assert!(no_head(&answer), "{body}");
    }
    assert_eq!(rows(&replay, &alice_id()).await, before, "nothing deleted");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_wrong_key_is_judged_before_the_hash() {
    // Another key and another hash: the key's refusal, as the wire orders them (7.4.16).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let at = hash_vector_time();
    set_time(&replay.clock, &at);
    let answer = replay
        .service
        .handle(signer_request(
            "POST",
            &erase_path(),
            erase_body(&[1; 32], Some(&[9; 32])),
            ms(&at),
        ))
        .await;
    assert_eq!(code_of(&answer), (409, json!("conflict")));
    assert_eq!(
        body(&answer)["message"],
        json!("7.4.16: not the account's service key")
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_retry_with_the_hash_after_it_landed_is_the_operators_404() {
    // The erasure naming the held version lands; a retry with the same body finds no account:
    // the operator's `404`, never a `409` (7.4.16).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let at = hash_vector_time();
    set_time(&replay.clock, &at);
    let hash = doc_hash("alice identity.json");
    let first = replay
        .service
        .handle(signer_request(
            "POST",
            &erase_path(),
            erase_body(&alice_service_key(), Some(&hash)),
            ms(&at),
        ))
        .await;
    assert_eq!(first.status, 200);
    let retry = signer_request(
        "POST",
        &erase_path(),
        erase_body(&alice_service_key(), Some(&hash)),
        ms(&at) + 1000,
    );
    let signature = signature_of(&retry);
    let answer = replay.service.handle(retry).await;
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    assert!(operator_signed(&answer, Some(&signature)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_hash_of_an_older_version_at_a_later_account_is_conflict() {
    // A hash naming version 1 while the account holds version 3, and the key right: `409`,
    // nothing deleted, and the right hash then erases (7.4.16).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let at = hash_vector_time();
    set_time(&replay.clock, &at);
    let before = rows(&replay, &alice_id()).await;
    let old = doc_hash("alice identity.json, first delivery (version 1)");
    let refused = replay
        .service
        .handle(signer_request(
            "POST",
            &erase_path(),
            erase_body(&alice_service_key(), Some(&old)),
            ms(&at),
        ))
        .await;
    assert_eq!(code_of(&refused), (409, json!("conflict")));
    assert_eq!(rows(&replay, &alice_id()).await, before, "nothing deleted");
    let hash = doc_hash("alice identity.json");
    let erased = replay
        .service
        .handle(signer_request(
            "POST",
            &erase_path(),
            erase_body(&alice_service_key(), Some(&hash)),
            ms(&at) + 1000,
        ))
        .await;
    assert_eq!(erased.status, 200);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_success_committed_before_it_isnt_signed_with_its_key() {
    // A request that committed, and moved its key's mark, just before the erasure: its
    // answer, signed once the erasure has finished, is the operator's, as for an account the
    // service doesn't host, never signed with the erased key (7.4.16).
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, true);
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
async fn test_erase_tombstone_read_committed_before_it_isnt_signed_with_its_key() {
    // A claim read of a tombstone, whose answer is built under the lock, committed just
    // before the erasure: as for an account the service doesn't host (7.4.16).
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, true);
    replay_chain_through_revoke(&replay).await;
    let claim_key = settle_the_chains_claim(&replay).await;
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

/// The wallet settles the chain's claim with `done`, its own attempt's outcome, which
/// compacts it to a tombstone (Switch wire 6.8): its claim key.
async fn settle_the_chains_claim(replay: &Replay) -> Vec<u8> {
    use pubky_switch_core::{
        claims::{Basis, ClaimFields, ClaimType},
        ops::{OpKind, OpsRequest, sign_batch},
    };
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
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let at = ms(&revoke_time());
    let path = format!(
        "/v1/{}/claims/{}",
        alice_id(),
        pubky_switch_core::enc::b64(&claim_key)
    );
    let read = replay
        .service
        .handle(app_request(wallet, "GET", &path, Vec::new(), at))
        .await;
    assert_eq!(read.status, 200, "{}", String::from_utf8_lossy(&read.body));
    let view = body(&read)["claim"].clone();
    let attempt_id = pubky_switch_core::enc::unb64(view["attempt_id"].as_str().expect("open"))
        .expect("attempt id");
    let done = ClaimFields {
        claim_key: claim_key.clone(),
        kind: ClaimType::Done,
        expected_step: view["step"].as_u64().expect("step"),
        attempt_id,
        orphan_after: None,
        deadline: None,
        basis: Some(Basis::Owner),
        evidence_ref: None,
    };
    let app_id = pubky_switch_core::enc::app_id_decode(wallet["app_id"].as_str().expect("id"))
        .expect("app id");
    let ops = sign_batch(
        &ed25519_dalek::SigningKey::from_bytes(&hex32(&wallet["signing_secret_hex"])),
        &hex32(&alice(&keys)["public_hex"]),
        Some(app_id),
        1,
        [77; 16],
        vec![(Vec::new(), OpKind::Claim(done))],
    )
    .expect("batch");
    let answer = replay
        .service
        .handle(app_request(
            wallet,
            "POST",
            &format!("/v1/{}/ops", alice_id()),
            OpsRequest::new(&ops, None).to_json(),
            at,
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    claim_key
}

/// `request` answered while the test holds alice's keying lock exclusive, as an erasure or a
/// key change does before it commits: the request parks on the lock in its keyed section
/// (seen in `pg_locks`, not granted), and `then` runs in the holder's transaction before it
/// commits. The answer, once the lock is free.
async fn parked_while<F>(
    replay: &Replay,
    request: pubky_switch::http::SwitchRequest,
    then: F,
) -> SwitchResponse
where
    F: for<'c> FnOnce(
        &'c mut sqlx::PgConnection,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'c>>,
{
    parked_at(replay, &replay.service, request, then).await
}

/// [`parked_while`], answered by `service`.
async fn parked_at<F>(
    replay: &Replay,
    service: &pubky_switch::service::Service,
    request: pubky_switch::http::SwitchRequest,
    then: F,
) -> SwitchResponse
where
    F: for<'c> FnOnce(
        &'c mut sqlx::PgConnection,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'c>>,
{
    let mut holder = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("BEGIN")
        .execute(&mut holder)
        .await
        .expect("begin");
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(pubky_switch::store::keying_lock_key(&alice_id()))
        .execute(&mut holder)
        .await
        .expect("exclusive");
    let (answer, ()) = tokio::join!(service.handle(request), async {
        let mut watcher = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        // Parked: a shared advisory lock waited for, not granted.
        let mut waited = 0;
        loop {
            let parked: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted \
                 AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
            )
            .fetch_one(&mut watcher)
            .await
            .expect("locks");
            if parked == 1 {
                break;
            }
            waited += 1;
            assert!(waited < 500, "the keyed section never parked on the lock");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        then(&mut holder).await;
        sqlx::query("COMMIT")
            .execute(&mut holder)
            .await
            .expect("commit");
    });
    answer
}

/// alice's signer's `GET /apps`.
fn signer_apps() -> pubky_switch::http::SwitchRequest {
    signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&revoke_time()),
    )
}

/// The holder's step of an erasure: the account's row deleted.
fn erase_row(
    conn: &mut sqlx::PgConnection,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
    Box::pin(async move {
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(alice_id())
            .execute(conn)
            .await
            .expect("erased");
    })
}

/// The wallet's `GET path`.
fn wallet_get(path: &str) -> pubky_switch::http::SwitchRequest {
    app_request(
        app(&vectors("keys.json"), "wallet"),
        "GET",
        &format!("/v1/{}/{path}", alice_id()),
        Vec::new(),
        ms(&revoke_time()),
    )
}

/// `request`, parked on the keying lock while the account is erased: the operator's `404`,
/// without a head, never signed with the erased key (7.4.16).
async fn assert_parked_across_an_erasure(request: pubky_switch::http::SwitchRequest) {
    let Some(replay) = replay().await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let request_signature = signature_of(&request);
    let answer = parked_while(&replay, request, erase_row).await;
    assert_eq!(
        code_of(&answer),
        (404, json!("not_found")),
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(no_head(&answer));
    assert!(operator_signed(&answer, Some(&request_signature)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_signer_parked_on_the_keying_lock_answers_as_after_the_erasure() {
    // The erasure commits while a request that committed before it waits to sign: the
    // request's key read, a statement of its own, sees the account gone, and its answer is
    // the operator's, as for an account the service doesn't host (7.4.16, store/keying.rs).
    assert_parked_across_an_erasure(signer_apps()).await;
}

#[tokio::test]
async fn test_erase_signer_parked_on_the_keying_lock_across_a_key_change_isnt_signed() {
    // The same, across a change of the account's key: the key the request loaded is no
    // longer the account's, so the operator's `503` goes out instead.
    let Some(replay) = replay().await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let request = signer_apps();
    let request_signature = signature_of(&request);
    let answer = parked_while(&replay, request, |conn| {
        Box::pin(async move {
            sqlx::query("UPDATE accounts SET service_key = $2 WHERE id = $1")
                .bind(alice_id())
                .bind("00000000000000000000000000000000")
                .execute(conn)
                .await
                .expect("rekeyed");
        })
    })
    .await;
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    assert!(no_head(&answer));
    assert!(operator_signed(&answer, Some(&request_signature)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_signer_parked_on_the_keying_lock_signs_once_it_is_free() {
    // A holder that changes nothing: the parked request signs with the account's key once
    // the lock is free, as at any time the account names it.
    let Some(replay) = replay().await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let request = signer_apps();
    let request_signature = signature_of(&request);
    let answer = parked_while(&replay, request, |_| Box::pin(async {})).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(alice_signed(&answer, Some(&request_signature)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_pre_lock_refusal_parked_on_the_keying_lock_isnt_signed() {
    // A refusal before the lock, a request signature that doesn't verify, is signed with the
    // account's key only while the account names it (7.4.16).
    assert_parked_across_an_erasure(tampered(wallet_get("feed?after=1:0"))).await;
}

#[tokio::test]
async fn test_erase_refusal_under_the_lock_parked_on_the_keying_lock_isnt_signed() {
    // A refusal under the lock, an app calling the signer's `GET /apps`, committed its
    // stamp, then parked: as for an account the service doesn't host.
    assert_parked_across_an_erasure(wallet_get("apps")).await;
}

#[tokio::test]
async fn test_erase_records_page_parked_on_the_keying_lock_isnt_signed() {
    // A `GET /records` page read after the lock, from its snapshot, then parked.
    assert_parked_across_an_erasure(wallet_get(&format!(
        "records?collection={}",
        pubky_switch_core::enc::b64(&[1; 32])
    )))
    .await;
}

#[tokio::test]
async fn test_erase_feed_page_parked_on_the_keying_lock_isnt_signed() {
    // A feed page read after the lock, whose head is signed only inside its keyed section.
    assert_parked_across_an_erasure(wallet_get("feed?after=1:0")).await;
}

#[tokio::test]
async fn test_erase_enrollment_parked_on_the_keying_lock_isnt_signed() {
    // An enrollment that created its account, then waited to sign with the account's new
    // key while the account was erased: the operator's `503`, never signed with that key,
    // and the signer enrolls again (7.4.16).
    let Some(replay) = replay().await else {
        return;
    };
    let http = vectors("http.json");
    let enrolled = named(
        &http["responses"],
        "signer: enrollment answer, signed with the new account's key",
    );
    set_time(
        &replay.clock,
        enrolled["headers"]["switch-server-time"]
            .as_str()
            .expect("time"),
    );
    let enrollment = vector_request(named(&http["requests"], "signer: enrollment"));
    let request_signature = signature_of(&enrollment);
    let answer = parked_while(&replay, enrollment, erase_row).await;
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    assert!(operator_signed(&answer, Some(&request_signature)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_waits_for_a_keyed_section_in_progress() {
    // An erasure takes the keying lock exclusive before it signs its answer, the last its
    // key signs: while a keyed section holds it shared, the erasure waits (seen in
    // `pg_locks`), and goes on once the section ends (7.4.16, store/keying.rs).
    let Some(replay) = replay().await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let mut section = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("BEGIN")
        .execute(&mut section)
        .await
        .expect("begin");
    sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
        .bind(pubky_switch::store::keying_lock_key(&alice_id()))
        .execute(&mut section)
        .await
        .expect("shared");
    let at = revoke_time();
    let key = alice_service_key();
    let (erased, ()) = tokio::join!(erase(&replay, &key, &at), async {
        let mut watcher = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        let mut waited = 0;
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted \
                 AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
            )
            .fetch_one(&mut watcher)
            .await
            .expect("locks");
            if waiting == 1 {
                break;
            }
            waited += 1;
            assert!(
                waited < 500,
                "the erasure never waited for the keyed section"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        sqlx::query("COMMIT")
            .execute(&mut section)
            .await
            .expect("commit");
    });
    assert_eq!(
        erased.status,
        200,
        "{}",
        String::from_utf8_lossy(&erased.body)
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_keyed_section_reads_committed_whatever_the_pools_default() {
    // At a database whose transactions default to REPEATABLE READ, a keyed section's key read
    // would see the snapshot its transaction took before the lock was granted: the section is
    // READ COMMITTED explicitly, so it still sees the erasure (store/keying.rs).
    let Some(replay) = replay().await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let options = replay
        .db
        .options()
        .clone()
        .options([("default_transaction_isolation", "repeatable\\ read")]);
    let store = pubky_switch::store::Store::connect_with(
        options,
        &pubky_switch::store::DatabaseConfig::default(),
    )
    .await
    .expect("store");
    let service = pubky_switch::service::Service::new(
        ORIGIN.into(),
        store,
        replay.keys.clone(),
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    );
    let request = signer_apps();
    let request_signature = signature_of(&request);
    let answer = parked_at(&replay, &service, request, erase_row).await;
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    assert!(operator_signed(&answer, Some(&request_signature)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_signer_refusal_parked_while_a_key_is_owed_isnt_a_404() {
    // A signer call refused before the lock, its timestamp an hour off, parks while the
    // account is erased and its key left owed: the signer's answer is the operator's `503`,
    // decided on its signature alone, never the `404` it would take as its erasure done
    // (7.4.16).
    let Some(replay) = replay().await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let key = service_key_id(&replay, &alice_id()).await;
    let request = signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        ms(&revoke_time()) - 3_600_000,
    );
    let request_signature = signature_of(&request);
    let answer = parked_while(&replay, request, move |conn| {
        Box::pin(async move {
            sqlx::query("DELETE FROM accounts WHERE id = $1")
                .bind(alice_id())
                .execute(&mut *conn)
                .await
                .expect("erased");
            sqlx::query(
                "INSERT INTO erased_keys (key_id, account_id, erased_at_ms) VALUES ($1, $2, 1)",
            )
            .bind(key.as_str())
            .bind(alice_id())
            .execute(&mut *conn)
            .await
            .expect("owed");
        })
    })
    .await;
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    assert!(no_head(&answer));
    assert!(operator_signed(&answer, Some(&request_signature)));
    replay.db.drop_database().await.expect("drop");
}

/// A key store that pauses once, when armed, right after `signer` returned a signer.
struct SignerPause {
    inner: std::sync::Arc<pubky_switch::keys::FixedKeys>,
    armed: std::sync::atomic::AtomicBool,
    paused: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl KeyStore for SignerPause {
    fn generate(&self) -> pubky_switch::keys::KeyFuture<'_, pubky_switch::keys::ServiceKey> {
        self.inner.generate()
    }
    fn generate_as<'a>(
        &'a self,
        id: &'a KeyId,
    ) -> pubky_switch::keys::KeyFuture<'a, pubky_switch::keys::ServiceKey> {
        self.inner.generate_as(id)
    }
    fn public_key<'a>(&'a self, id: &'a KeyId) -> pubky_switch::keys::KeyFuture<'a, [u8; 32]> {
        self.inner.public_key(id)
    }
    fn signer<'a>(
        &'a self,
        id: &'a KeyId,
    ) -> pubky_switch::keys::KeyFuture<'a, pubky_switch::keys::ServiceSigner> {
        Box::pin(async move {
            let signer = self.inner.signer(id).await;
            if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                self.paused.notify_one();
                self.release.notified().await;
            }
            signer
        })
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
        self.inner.advance_mark(id, head)
    }
    fn delete<'a>(&'a self, id: &'a KeyId) -> pubky_switch::keys::KeyFuture<'a, ()> {
        self.inner.delete(id)
    }
    fn record_erasure<'a>(
        &'a self,
        identity: &'a str,
        erased_at_ms: u64,
    ) -> pubky_switch::keys::KeyFuture<'a, ()> {
        self.inner.record_erasure(identity, erased_at_ms)
    }
    fn erasure<'a>(&'a self, identity: &'a str) -> pubky_switch::keys::KeyFuture<'a, Option<u64>> {
        self.inner.erasure(identity)
    }

    fn erasures(&self) -> pubky_switch::keys::KeyFuture<'_, Vec<(String, u64)>> {
        self.inner.erasures()
    }

    fn forget_erasures_before(&self, before_ms: u64) -> pubky_switch::keys::KeyFuture<'_, usize> {
        self.inner.forget_erasures_before(before_ms)
    }
}

#[tokio::test]
async fn test_erase_failure_under_a_lost_lock_isnt_signed_with_the_erased_key() {
    // A failure under the lock can be the database ending the transaction (a terminated
    // backend, `idle_in_transaction_session_timeout`, a failover), the row lock with it: an
    // erasure may then run to completion. The request's `503` is signed only in a keyed
    // section, so never with the erased key (service/keyed.rs).
    let Some(mut replay) = replay().await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let pause = std::sync::Arc::new(SignerPause {
        inner: replay.keys.clone(),
        armed: std::sync::atomic::AtomicBool::new(false),
        paused: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    replay.service = pubky_switch::service::Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        pause.clone(),
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    );
    pause.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let request = signer_apps();
    let request_signature = signature_of(&request);
    let (answer, erased) = tokio::join!(replay.service.handle(request), async {
        pause.paused.notified().await;
        let mut admin = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        let killed: i64 = sqlx::query_scalar(
            "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity \
             WHERE datname = current_database() AND state = 'idle in transaction' \
             AND query LIKE '%FOR UPDATE%'",
        )
        .fetch_one(&mut admin)
        .await
        .expect("terminate");
        assert_eq!(killed, 1, "the request's locked transaction");
        let erased = erase(&replay, &alice_service_key(), &revoke_time()).await;
        pause.release.notify_one();
        erased
    });
    assert_eq!(
        erased.status,
        200,
        "{}",
        String::from_utf8_lossy(&erased.body)
    );
    assert!(
        !alice_signed(&answer, Some(&request_signature)),
        "signed with the erased key after the erasure's 200: {} {}",
        answer.status,
        String::from_utf8_lossy(&answer.body)
    );
    replay.db.drop_database().await.expect("drop");
}

/// One signature made with a service key, in the order they were made.
type SignLog = std::sync::Arc<std::sync::Mutex<Vec<([u8; 32], [u8; 64])>>>;

/// A signer that logs every signature, taken in order under the log's lock.
struct Recording {
    inner: pubky_switch::keys::ServiceSigner,
    log: SignLog,
}

impl pubky_switch_core::signing::Signs for Recording {
    fn public_key(&self) -> [u8; 32] {
        pubky_switch_core::signing::Signs::public_key(&self.inner)
    }
    fn sign_fields(&self, label: &str, fields: &[&[u8]]) -> [u8; 64] {
        let mut log = self.log.lock().expect("log");
        let signature = pubky_switch_core::signing::Signs::sign_fields(&self.inner, label, fields);
        log.push((self.public_key(), signature));
        signature
    }
}

/// Keys whose signers log every signature.
struct Recorder {
    inner: std::sync::Arc<pubky_switch::keys::FixedKeys>,
    log: SignLog,
}

impl KeyStore for Recorder {
    fn generate(&self) -> pubky_switch::keys::KeyFuture<'_, pubky_switch::keys::ServiceKey> {
        self.inner.generate()
    }
    fn generate_as<'a>(
        &'a self,
        id: &'a KeyId,
    ) -> pubky_switch::keys::KeyFuture<'a, pubky_switch::keys::ServiceKey> {
        self.inner.generate_as(id)
    }
    fn public_key<'a>(&'a self, id: &'a KeyId) -> pubky_switch::keys::KeyFuture<'a, [u8; 32]> {
        self.inner.public_key(id)
    }
    fn signer<'a>(
        &'a self,
        id: &'a KeyId,
    ) -> pubky_switch::keys::KeyFuture<'a, pubky_switch::keys::ServiceSigner> {
        Box::pin(async move {
            let inner = self.inner.signer(id).await?;
            Ok(pubky_switch::keys::ServiceSigner::new(std::sync::Arc::new(
                Recording {
                    inner,
                    log: self.log.clone(),
                },
            )))
        })
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
        self.inner.advance_mark(id, head)
    }
    fn delete<'a>(&'a self, id: &'a KeyId) -> pubky_switch::keys::KeyFuture<'a, ()> {
        self.inner.delete(id)
    }
    fn record_erasure<'a>(
        &'a self,
        identity: &'a str,
        erased_at_ms: u64,
    ) -> pubky_switch::keys::KeyFuture<'a, ()> {
        self.inner.record_erasure(identity, erased_at_ms)
    }
    fn erasure<'a>(&'a self, identity: &'a str) -> pubky_switch::keys::KeyFuture<'a, Option<u64>> {
        self.inner.erasure(identity)
    }

    fn erasures(&self) -> pubky_switch::keys::KeyFuture<'_, Vec<(String, u64)>> {
        self.inner.erasures()
    }

    fn forget_erasures_before(&self, before_ms: u64) -> pubky_switch::keys::KeyFuture<'_, usize> {
        self.inner.forget_erasures_before(before_ms)
    }
}

/// alice's keying lock waited for and not granted, in `pg_locks`, until `count` are seen.
async fn advisory_waiters(replay: &Replay, count: i64) {
    let mut watcher = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let mut waited = 0;
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted \
             AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        )
        .fetch_one(&mut watcher)
        .await
        .expect("locks");
        if waiting == count {
            return;
        }
        waited += 1;
        assert!(waited < 500, "never {count} waiting on the keying lock");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn test_erase_signs_its_confirmation_only_once_the_sections_are_done() {
    // While a keyed section holds the lock shared, the erasure waits, and it hasn't signed
    // its confirmation yet: it signs it only once it holds the lock exclusive.
    let Some(replay) = replay().await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let log: SignLog = std::sync::Arc::default();
    let service = pubky_switch::service::Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        std::sync::Arc::new(Recorder {
            inner: replay.keys.clone(),
            log: log.clone(),
        }),
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    );
    let mut section = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("BEGIN")
        .execute(&mut section)
        .await
        .expect("begin");
    sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
        .bind(pubky_switch::store::keying_lock_key(&alice_id()))
        .execute(&mut section)
        .await
        .expect("shared");
    let request = signer_request(
        "POST",
        &erase_path(),
        erase_body(&alice_service_key(), None),
        ms(&revoke_time()),
    );
    let (erased, signed_while_waiting) = tokio::join!(service.handle(request), async {
        advisory_waiters(&replay, 1).await;
        let signed = log.lock().expect("log").len();
        sqlx::query("COMMIT")
            .execute(&mut section)
            .await
            .expect("commit");
        signed
    });
    assert_eq!(erased.status, 200);
    let confirmation: [u8; 64] = pubky_switch_core::enc::unb64(
        header_text(&erased, header::SERVICE_SIGNATURE).expect("signature"),
    )
    .expect("b64")
    .try_into()
    .expect("64");
    let at = log
        .lock()
        .expect("log")
        .iter()
        .position(|(_, signature)| *signature == confirmation)
        .expect("logged");
    assert!(
        at >= signed_while_waiting,
        "the confirmation was signed before the erasure held the lock: {at} < {signed_while_waiting}"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_keyed_section_during_the_deletion_waits_for_its_commit() {
    // The erasure has signed its confirmation and is deleting (its cascade held up on a row
    // of alice's chain): a pre-lock refusal's keyed section waits for the erasure's commit,
    // then sees the account gone. The exclusive lock is held from before the confirmation to
    // the commit, not only waited for.
    let Some(replay) = replay().await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let mut blocker = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("BEGIN")
        .execute(&mut blocker)
        .await
        .expect("begin");
    sqlx::query("SELECT 1 FROM chain_items WHERE account_id = $1 LIMIT 1 FOR UPDATE")
        .bind(alice_id())
        .execute(&mut blocker)
        .await
        .expect("a chain row");
    let erasure = signer_request(
        "POST",
        &erase_path(),
        erase_body(&alice_service_key(), None),
        ms(&revoke_time()),
    );
    let refused = tampered(wallet_get("feed?after=1:0"));
    let refused_signature = signature_of(&refused);
    let (erased, answer) = tokio::join!(replay.service.handle(erasure), async {
        let mut watcher = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        let mut waited = 0;
        loop {
            let deleting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() \
                 AND wait_event_type = 'Lock' AND query LIKE 'DELETE FROM accounts%'",
            )
            .fetch_one(&mut watcher)
            .await
            .expect("activity");
            if deleting == 1 {
                break;
            }
            waited += 1;
            assert!(waited < 500, "the erasure's deletion never waited");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let (answer, ()) = tokio::join!(replay.service.handle(refused), async {
            advisory_waiters(&replay, 1).await;
            sqlx::query("ROLLBACK")
                .execute(&mut blocker)
                .await
                .expect("rollback");
        });
        answer
    });
    assert_eq!(
        erased.status,
        200,
        "{}",
        String::from_utf8_lossy(&erased.body)
    );
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    assert!(operator_signed(&answer, Some(&refused_signature)));
    replay.db.drop_database().await.expect("drop");
}

/// A signer `GET /apps` paused under the lock after its signer is loaded, its transaction
/// ended by the database, the account erased meanwhile (with `owed`, a key of it then left
/// owed), then resumed: its answer, and its request's signature.
async fn lost_lock_answer(owed: bool) -> (SwitchResponse, [u8; 64]) {
    let mut replay = replay().await.expect("database");
    replay_chain_through_revoke(&replay).await;
    let key = service_key_id(&replay, &alice_id()).await;
    let pause = std::sync::Arc::new(SignerPause {
        inner: replay.keys.clone(),
        armed: std::sync::atomic::AtomicBool::new(false),
        paused: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    replay.service = pubky_switch::service::Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        pause.clone(),
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    );
    pause.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let request = signer_apps();
    let request_signature = signature_of(&request);
    let (answer, ()) = tokio::join!(replay.service.handle(request), async {
        pause.paused.notified().await;
        let mut admin = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        let killed: i64 = sqlx::query_scalar(
            "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity \
             WHERE datname = current_database() AND state = 'idle in transaction' \
             AND query LIKE '%FOR UPDATE%'",
        )
        .fetch_one(&mut admin)
        .await
        .expect("terminate");
        assert_eq!(killed, 1);
        assert_eq!(
            erase(&replay, &alice_service_key(), &revoke_time())
                .await
                .status,
            200
        );
        if owed {
            sqlx::query(
                "INSERT INTO erased_keys (key_id, account_id, erased_at_ms) VALUES ($1, $2, 1)",
            )
            .bind(key.as_str())
            .bind(alice_id())
            .execute(&mut admin)
            .await
            .expect("owed");
        }
        pause.release.notify_one();
    });
    replay.db.drop_database().await.expect("drop");
    (answer, request_signature)
}

#[tokio::test]
async fn test_erase_lost_lock_failure_is_the_operators_404() {
    // A request whose transaction the database ended under the lock, the account erased
    // since: the operator's answer for an account the service doesn't host.
    let (answer, signature) = lost_lock_answer(false).await;
    assert_eq!(
        code_of(&answer),
        (404, json!("not_found")),
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(no_head(&answer));
    assert!(operator_signed(&answer, Some(&signature)));
}

#[tokio::test]
async fn test_erase_lost_lock_failure_to_the_signer_while_a_key_is_owed_is_the_503() {
    // The same, to the signer while a key of the erased account is still owed: the
    // operator's `503`, as `no_such_account` answers the signer then.
    let (answer, signature) = lost_lock_answer(true).await;
    assert_eq!(
        code_of(&answer),
        (503, json!("unavailable")),
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(no_head(&answer));
    assert!(operator_signed(&answer, Some(&signature)));
}

/// `first`, then `second`, queued in that order behind a hold on alice's account row, and
/// answered once the hold ends: so they run one after the other, as two requests that come
/// at the same moment do.
async fn queued(
    replay: &Replay,
    first: impl std::future::Future<Output = SwitchResponse>,
    second: impl std::future::Future<Output = SwitchResponse>,
) -> (SwitchResponse, SwitchResponse) {
    let mut holder = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("BEGIN")
        .execute(&mut holder)
        .await
        .expect("begin");
    sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(alice_id())
        .execute(&mut holder)
        .await
        .expect("lock");
    let options = replay.db.options().clone();
    let (first, (second, ())) = tokio::join!(first, async {
        lock_waiters(&options, 1).await;
        tokio::join!(second, async {
            lock_waiters(&options, 2).await;
            sqlx::query("COMMIT")
                .execute(&mut holder)
                .await
                .expect("commit");
        })
    });
    (first, second)
}

/// An invite code that expired at `at`, for the minute's sweep to drop, and the sweep due
/// at the next request.
async fn expired_invite(replay: &Replay, at: &str) {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("UPDATE accounts SET swept_at_ms = NULL WHERE id = $1")
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("due");
    sqlx::query(
        "INSERT INTO invite_codes (account_id, code_hash, max_uses, writer, expires_at_ms, \
         context) VALUES ($1, decode(repeat('ab', 32), 'hex'), 1, \
         decode(repeat('cd', 16), 'hex'), $2, 'null')",
    )
    .bind(alice_id())
    .bind(i64::try_from(ms(at)).expect("ms"))
    .execute(&mut conn)
    .await
    .expect("invite");
    conn.close().await.expect("close");
}

#[tokio::test]
async fn test_erase_and_a_sweep_at_the_same_moment_run_one_after_the_other() {
    // A request that sweeps and the erasure, at the same moment, in either order: each
    // takes the account's lock, so one runs after the other. A sweep before the erasure is
    // answered, and the erasure then deletes everything; a sweep after it finds no account
    // and gets the operator's answer (Switch wire 7.3 step 4, 7.4.16).
    for sweep_first in [true, false] {
        let Some(replay) = replay().await else { return };
        replay_chain_through_revoke(&replay).await;
        let at = revoke_time();
        expired_invite(&replay, &at).await;
        log_swept_invite_codes(&replay).await;
        let apps = || {
            replay.service.handle(signer_request(
                "GET",
                &format!("/v1/{}/apps", alice_id()),
                Vec::new(),
                ms(&at),
            ))
        };
        let key = alice_service_key();
        let (swept, erased) = if sweep_first {
            queued(&replay, apps(), erase(&replay, &key, &at)).await
        } else {
            let (erased, swept) = queued(&replay, erase(&replay, &key, &at), apps()).await;
            (swept, erased)
        };
        assert_eq!(
            erased.status,
            200,
            "{}",
            String::from_utf8_lossy(&erased.body)
        );
        if sweep_first {
            assert_eq!(
                swept.status,
                200,
                "{}",
                String::from_utf8_lossy(&swept.body)
            );
        } else {
            // The operator's answer: `404`, or `503` while the erased key is still being
            // deleted (7.4.16); never one of the account's.
            assert!(
                matches!(swept.status, 404 | 503) && no_head(&swept),
                "{}",
                String::from_utf8_lossy(&swept.body)
            );
        }
        assert!(
            rows(&replay, &alice_id())
                .await
                .iter()
                .all(|(_, count)| *count == 0),
            "sweep first: {sweep_first}"
        );
        // A sweep ran before the erasure took the account: whichever request came first
        // swept the expired code at its step 4.
        assert_eq!(
            swept_invite_codes(&replay).await,
            1,
            "sweep first: {sweep_first}"
        );
        replay.db.drop_database().await.expect("drop");
    }
}

#[tokio::test]
async fn test_erase_after_a_purge() {
    // The wallet revoked and purged (Switch wire 9.1): the erasure deletes every row as
    // before, the purged App ID's included.
    let Some(replay) = replay().await else { return };
    let (_, at) = purge_wallet(&replay).await;
    let answer = erase(
        &replay,
        &alice_service_key(),
        &pubky_switch_core::time::rfc3339(at),
    )
    .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    for (table, count) in rows(&replay, &alice_id()).await {
        assert_eq!(count, 0, "{table}");
    }
    let answer = replay
        .service
        .handle(signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            at,
        ))
        .await;
    assert_eq!(answer.status, 404);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_of_an_account_holding_an_older_item_that_doesnt_read() {
    // An older chain item whose stored document doesn't read, left for the check of older
    // documents (Switch wire 7.5): the signer can still erase the account, as step 4's check
    // passes over the item.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    sql_on(
        &replay,
        &alice_id(),
        "UPDATE chain_items SET item_bytes = '\\x00'::BYTEA WHERE account_id = $1 AND seq = 3",
    )
    .await;
    sql_on(
        &replay,
        &alice_id(),
        "UPDATE accounts SET documents_checked_seq = 0, documents_check_end = last_seq \
         WHERE id = $1",
    )
    .await;
    let answer = erase(&replay, &alice_service_key(), &revoke_time()).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    replay.db.drop_database().await.expect("drop");
}

/// alice's account as a database restored from a backup taken before its erasure holds it
/// (Switch spec 6.5): the database as it was, and `keys` as the erasure left the key store,
/// the erasure recorded in the ledger a minute after the account was created and her service
/// key, with its mark, deleted. The time recorded.
async fn restored_after_erasure(replay: &Replay, keys: &dyn KeyStore) -> u64 {
    let key = service_key_id(replay, &alice_id()).await;
    let created = created_at(replay).await.expect("the account");
    let erased_at = created + 60_000;
    keys.record_erasure(&alice_id(), erased_at)
        .await
        .expect("ledger");
    keys.delete(&key).await.expect("delete");
    erased_at
}

/// When alice's account was created, if it is there.
async fn created_at(replay: &Replay) -> Option<u64> {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let at: Option<i64> = sqlx::query_scalar("SELECT created_at_ms FROM accounts WHERE id = $1")
        .bind(alice_id())
        .fetch_optional(&mut conn)
        .await
        .expect("created");
    conn.close().await.expect("close");
    at.map(|at| u64::try_from(at).expect("time"))
}

/// Whether no account table holds a row of alice's account.
async fn all_gone(replay: &Replay) -> bool {
    rows(replay, &alice_id())
        .await
        .iter()
        .all(|(_, count)| *count == 0)
}

/// A service on `replay`'s database and clock over `keys`, made as the binary makes it at
/// start, with `retention_days` of backups.
async fn started(
    replay: &Replay,
    keys: std::sync::Arc<dyn KeyStore>,
    retention_days: Option<u64>,
) -> pubky_switch::service::Service {
    pubky_switch::service::Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        keys,
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    )
    .with_backup_retention_days(retention_days)
    .started()
    .await
}

/// A call, made at a service time.
type CallAt<'a> = dyn Fn(&str) -> pubky_switch::http::SwitchRequest + 'a;

#[tokio::test]
async fn test_erase_restored_account_is_erased_again_before_any_call_is_served() {
    // A database restored from before an erasure brings the account back; the first call to
    // it, whatever it is, erases it again before anything is served or signed, and is
    // answered as for an account the service doesn't host (Switch spec 6.5, wire 7.3 step 2).
    // Each call on a restore of its own, so every path's check is tried.
    let keys = vectors("keys.json");
    let id = alice_id();
    let calls: Vec<(&str, Box<CallAt>)> = vec![
        (
            "public read",
            Box::new(|_| {
                request(
                    "GET",
                    &format!("/v1/{}/identity", alice_id()),
                    &[],
                    Vec::new(),
                )
            }),
        ),
        (
            "signer read",
            Box::new(|at| {
                signer_request(
                    "GET",
                    &format!("/v1/{}/apps", alice_id()),
                    Vec::new(),
                    ms(at),
                )
            }),
        ),
        (
            "signer delivery",
            Box::new(|at| {
                signer_request(
                    "PUT",
                    &format!("/v1/{}/identity", alice_id()),
                    b"{}".to_vec(),
                    ms(at),
                )
            }),
        ),
        (
            "own app feed",
            Box::new(|at| {
                app_request(
                    app(&keys, "wallet"),
                    "GET",
                    &format!("/v1/{}/feed?wait=25", alice_id()),
                    Vec::new(),
                    ms(at),
                )
            }),
        ),
        (
            "own app batch",
            Box::new(|at| {
                let body = pubky_switch_core::ops::OpsRequest::new(
                    &[],
                    Some(pubky_switch_core::ops::Position {
                        generation: 1,
                        seq: 4,
                    }),
                )
                .to_json();
                app_request(
                    app(&keys, "wallet"),
                    "POST",
                    &format!("/v1/{}/ops", alice_id()),
                    body,
                    ms(at),
                )
            }),
        ),
        (
            "own app push",
            Box::new(|at| {
                app_request(
                    app(&keys, "wallet"),
                    "PUT",
                    &format!("/v1/{}/push", alice_id()),
                    b"{}".to_vec(),
                    ms(at),
                )
            }),
        ),
        (
            "inbox append from another identity",
            Box::new(|at| {
                other_request(
                    "shop",
                    ORIGIN,
                    "POST",
                    &format!("/v1/{}/inbox", alice_id()),
                    b"{}".to_vec(),
                    None,
                    ms(at),
                )
            }),
        ),
        (
            "directory read from another identity",
            Box::new(|at| {
                other_request(
                    "shop",
                    ORIGIN,
                    "GET",
                    &format!("/v1/{}/directory", alice_id()),
                    Vec::new(),
                    None,
                    ms(at),
                )
            }),
        ),
        (
            "connect request from another identity",
            Box::new(|at| {
                other_request(
                    "shop",
                    ORIGIN,
                    "POST",
                    &format!("/v1/{}/connect", alice_id()),
                    b"{}".to_vec(),
                    None,
                    ms(at),
                )
            }),
        ),
    ];
    for (name, call) in &calls {
        let Some(replay) = replay().await else { return };
        replay_chain_through_revoke(&replay).await;
        let erased_at = restored_after_erasure(&replay, replay.keys.as_ref()).await;
        let at = revoke_time();
        let request = call(&at);
        let signature = request
            .headers
            .get(header::SIGNATURE)
            .map(|_| signature_of(&request));
        let answer = replay.service.handle(request).await;
        assert_eq!(code_of(&answer), (404, json!("not_found")), "{name}");
        assert!(no_head(&answer), "{name}");
        assert!(operator_signed(&answer, signature.as_ref()), "{name}");
        assert!(all_gone(&replay).await, "{name}: the state is erased again");
        // The ledger keeps the erasure, so a later restore is erased again too.
        assert_eq!(
            replay.keys.erasure(&id).await.expect("ledger"),
            Some(erased_at),
            "{name}"
        );
        replay.db.drop_database().await.expect("drop");
    }
}

#[tokio::test]
async fn test_erase_restored_account_is_erased_again_at_start() {
    // The service the binary starts erases every restored account the ledger names before
    // it takes a request (Switch spec 6.5).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    restored_after_erasure(&replay, replay.keys.as_ref()).await;
    assert!(!all_gone(&replay).await, "restored");
    let service = started(&replay, replay.keys.clone(), None).await;
    assert!(all_gone(&replay).await, "erased before any request");
    let answer = service
        .handle(signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            ms(&revoke_time()),
        ))
        .await;
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_restored_account_then_enrollment_starts_a_new_account() {
    // An enrollment of a restored account's identity erases the old account first and makes
    // a new one, created after the ledger's erasure time, which no later check takes for a
    // restored one (Switch spec 6.5, wire 3.7).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let old_key = service_key_id(&replay, &alice_id()).await;
    let erased_at = restored_after_erasure(&replay, replay.keys.as_ref()).await;
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
    let answer = replay.service.handle(enrollment).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_ne!(service_key_id(&replay, &alice_id()).await, old_key);
    let created = created_at(&replay).await.expect("the new account");
    assert!(created > erased_at, "created after the erasure");
    // Nothing of the old account: only the new account's row and its enrollment answer.
    let held: Vec<_> = rows(&replay, &alice_id())
        .await
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(table, _)| table)
        .collect();
    assert_eq!(held, ["accounts", "enrollment_answers"]);
    // A start and a call later, it is still there: staged, as a new account is.
    let service = started(&replay, replay.keys.clone(), None).await;
    let apps = service
        .handle(signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            ms(&at),
        ))
        .await;
    assert_eq!(code_of(&apps), (503, json!("staged")));
    assert_eq!(created_at(&replay).await, Some(created));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_account_enrolled_after_its_erasure_is_kept() {
    // An erasure, then an enrollment of the identity at an earlier service time than the
    // erasure's (the erased account's time ran ahead): the new account is created after the
    // ledger's time, so neither a start nor a call erases it (Switch spec 6.5).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let ahead = "2026-01-01T00:04:00.000Z";
    set_time(&replay.clock, ahead);
    assert_eq!(
        erase(&replay, &alice_service_key(), ahead).await.status,
        200
    );
    let erased_at = replay
        .keys
        .erasure(&alice_id())
        .await
        .expect("ledger")
        .expect("recorded");
    let http = vectors("http.json");
    let enrolled = named(
        &http["responses"],
        "signer: enrollment answer, signed with the new account's key",
    );
    let at = enrolled["headers"]["switch-server-time"]
        .as_str()
        .expect("time")
        .to_string();
    assert!(ms(&at) < erased_at, "enrolled at an earlier time");
    set_time(&replay.clock, &at);
    let enrollment = vector_request(named(&http["requests"], "signer: enrollment"));
    assert_eq!(replay.service.handle(enrollment).await.status, 200);
    let created = created_at(&replay).await.expect("the new account");
    assert_eq!(created, erased_at + 1);
    let service = started(&replay, replay.keys.clone(), None).await;
    let apps = service
        .handle(signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            ms(&at),
        ))
        .await;
    assert_eq!(code_of(&apps), (503, json!("staged")));
    assert_eq!(created_at(&replay).await, Some(created), "kept");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_restored_account_whose_keys_cant_go_stays_erased_and_owed() {
    // The erasure again commits, then the key store can't delete the keys it owes: as after
    // a crash between the two steps, the account is gone, its keys owed, and the signer's call
    // gets the operator's `503` until a start deletes them; then the `404` (Switch spec 6.5,
    // wire 7.4.16).
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    restored_after_erasure(&replay, replay.keys.as_ref()).await;
    gate.fail_delete
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let at = revoke_time();
    let apps = || {
        signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            ms(&at),
        )
    };
    let answer = replay.service.handle(apps()).await;
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    assert!(all_gone(&replay).await, "erased again");
    assert!(
        replay
            .db
            .store()
            .owes_erased_keys(&alice_id())
            .await
            .expect("owed")
    );
    gate.fail_delete
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let service = started(&replay, gate.clone(), None).await;
    assert!(
        !replay
            .db
            .store()
            .owes_erased_keys(&alice_id())
            .await
            .expect("owed")
    );
    assert_eq!(
        code_of(&service.handle(apps()).await),
        (404, json!("not_found"))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_restored_account_is_never_served_while_the_ledger_cant_be_read() {
    // Without the ledger the service can't tell a restored account: every call is the
    // operator's `503` and nothing is erased; once it reads again, the account is erased
    // (Switch spec 6.5).
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    replay_chain_through_revoke(&replay).await;
    restored_after_erasure(&replay, replay.keys.as_ref()).await;
    gate.fail_ledger_read
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let keys = vectors("keys.json");
    let at = revoke_time();
    let feed = || {
        app_request(
            app(&keys, "wallet"),
            "GET",
            &format!("/v1/{}/feed", alice_id()),
            Vec::new(),
            ms(&at),
        )
    };
    let request = feed();
    let signature = signature_of(&request);
    let answer = replay.service.handle(request).await;
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    assert!(no_head(&answer));
    assert!(operator_signed(&answer, Some(&signature)));
    assert!(!all_gone(&replay).await, "nothing erased yet");
    gate.fail_ledger_read
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        code_of(&replay.service.handle(feed()).await),
        (404, json!("not_found"))
    );
    assert!(all_gone(&replay).await);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_ledger_forgets_an_erasure_once_its_backups_aged_out() {
    // With `keys.backup_retention_days`, a start forgets the erasures older than that by
    // trusted time and keeps the younger; without the setting, or without trusted time, it
    // forgets none (Switch spec 6.5).
    let Some(replay) = replay().await else { return };
    let day = 24 * 60 * 60 * 1000;
    let now = "2026-03-01T00:00:00.000Z";
    set_time(&replay.clock, now);
    for (identity, age) in [("aaa", 3 * day), ("bbb", day / 2)] {
        replay
            .keys
            .record_erasure(identity, ms(now) - age)
            .await
            .expect("record");
    }
    let held = || async {
        replay
            .keys
            .erasures()
            .await
            .expect("ledger")
            .into_iter()
            .map(|(identity, _)| identity)
            .collect::<Vec<_>>()
    };
    let _ = started(&replay, replay.keys.clone(), None).await;
    assert_eq!(
        held().await,
        ["aaa", "bbb"],
        "kept for good without the setting"
    );
    let untrusted = std::sync::Arc::new(pubky_switch::time::TrustedTime::new(
        pubky_switch::time::TrustedTimeConfig {
            required: true,
            ..pubky_switch::time::TrustedTimeConfig::default()
        },
        replay.clock.clone(),
    ));
    let _ = pubky_switch::service::Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        replay.keys.clone(),
        untrusted,
        pubky_switch::limits::Limits::default(),
    )
    .with_backup_retention_days(Some(1))
    .started()
    .await;
    assert_eq!(held().await, ["aaa", "bbb"], "kept without trusted time");
    let _ = started(&replay, replay.keys.clone(), Some(1)).await;
    assert_eq!(held().await, ["bbb"], "the erasure older than a day goes");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_account_enrolled_while_its_erasure_is_unrecorded_is_kept() {
    // An erasure whose ledger record fails commits and stays owed; an enrollment of the
    // identity meanwhile, at an earlier service time than the erasure's (the erased account's
    // time ran ahead), makes a new account. Once a start records the owed erasure, neither
    // the start nor a call may take that new account for a restored one (Switch spec 6.5).
    use std::sync::atomic::Ordering;
    let Some(mut replay) = replay().await else {
        return;
    };
    let gate = gated(&mut replay, false);
    serve_alice(&replay).await;
    let ahead = "2026-01-01T00:04:00.000Z";
    set_time(&replay.clock, ahead);
    gate.fail_ledger.store(true, Ordering::SeqCst);
    assert_eq!(
        code_of(&erase(&replay, &alice_service_key(), ahead).await),
        (503, json!("unavailable"))
    );
    gate.fail_ledger.store(false, Ordering::SeqCst);
    assert_eq!(
        replay.keys.erasure(&alice_id()).await.expect("ledger"),
        None,
        "not recorded yet"
    );
    let http = vectors("http.json");
    let enrolled = named(
        &http["responses"],
        "signer: enrollment answer, signed with the new account's key",
    );
    let at = enrolled["headers"]["switch-server-time"]
        .as_str()
        .expect("time")
        .to_string();
    assert!(ms(&at) < ms(ahead), "enrolled at an earlier time");
    set_time(&replay.clock, &at);
    let enrollment = vector_request(named(&http["requests"], "signer: enrollment"));
    assert_eq!(replay.service.handle(enrollment).await.status, 200);
    let created = created_at(&replay).await.expect("the new account");
    let service = started(&replay, gate.clone(), None).await;
    assert!(
        replay
            .keys
            .erasure(&alice_id())
            .await
            .expect("ledger")
            .is_some(),
        "the start recorded the owed erasure"
    );
    assert_eq!(
        created_at(&replay).await,
        Some(created),
        "the new account is kept through a start"
    );
    let apps = service
        .handle(signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            ms(&at),
        ))
        .await;
    assert_eq!(code_of(&apps), (503, json!("staged")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_restored_account_whose_key_is_still_held_signs_nothing() {
    // A database restored from before an erasure while the key store still holds the
    // account's service key and its mark (a deletion that failed, or a key store brought back
    // from its own backup): only the ledger tells. The first call erases the account again,
    // the operator answers it, and the key goes (Switch spec 6.5).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let key = service_key_id(&replay, &alice_id()).await;
    let created = created_at(&replay).await.expect("the account");
    replay
        .keys
        .record_erasure(&alice_id(), created + 60_000)
        .await
        .expect("ledger");
    assert!(replay.keys.public_key(&key).await.is_ok(), "still held");
    let answer = replay
        .service
        .handle(request(
            "GET",
            &format!("/v1/{}/identity", alice_id()),
            &[],
            Vec::new(),
        ))
        .await;
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    assert!(no_head(&answer));
    assert!(operator_signed(&answer, None));
    assert!(all_gone(&replay).await, "erased again");
    assert!(
        replay.keys.public_key(&key).await.is_err(),
        "the key is deleted"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_erase_account_enrolled_while_its_erasure_commits_is_kept() {
    // An enrollment whose lookup still finds the account while an erasure of it commits, at
    // a later service time than the enrollment's: its insert waits for the deletion, and the
    // new account is created after the erasure, which the database holds before the ledger
    // does. A start that then records the erasure keeps the new account (Switch spec 6.5).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let key = service_key_id(&replay, &alice_id()).await;
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
    let erased_at = ms(&at) + 60_000;
    // The erasure's transaction, as `AccountTxn::erase` writes it, held open.
    let mut erasing = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("BEGIN")
        .execute(&mut erasing)
        .await
        .expect("begin");
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(alice_id())
        .execute(&mut erasing)
        .await
        .expect("delete");
    sqlx::query("INSERT INTO erased_keys (key_id, account_id, erased_at_ms) VALUES ($1, $2, $3)")
        .bind(key.as_str())
        .bind(alice_id())
        .bind(i64::try_from(erased_at).expect("time"))
        .execute(&mut erasing)
        .await
        .expect("owed");
    let enrollment = vector_request(named(&http["requests"], "signer: enrollment"));
    let (answer, ()) = tokio::join!(replay.service.handle(enrollment), async {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        sqlx::query("COMMIT")
            .execute(&mut erasing)
            .await
            .expect("commit");
    });
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_ne!(
        service_key_id(&replay, &alice_id()).await,
        key,
        "a new account"
    );
    let created = created_at(&replay).await.expect("the new account");
    assert_eq!(created, erased_at + 1, "created after the erasure");
    assert_eq!(
        replay.keys.erasure(&alice_id()).await.expect("ledger"),
        None,
        "not recorded yet"
    );
    let _ = started(&replay, replay.keys.clone(), None).await;
    assert_eq!(
        replay.keys.erasure(&alice_id()).await.expect("ledger"),
        Some(erased_at),
        "the start recorded it"
    );
    assert_eq!(created_at(&replay).await, Some(created), "kept");
    erasing.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
}
