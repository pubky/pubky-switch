//! A provider loss at the service, against PostgreSQL (Switch spec 12.6; Switch wire 3.3,
//! 3.7, 7.4.2, 7.4.12): the first document of a recovery at a new account, a recovery in
//! place under the pending key, what the account keeps and drops, the enrollments it
//! retires, and the outgoing key's last answer.
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used)]

mod support;

use pubky_switch::http::{Handler, SwitchResponse};
use pubky_switch::keys::{KeyId, KeyStore};
use pubky_switch::time::Clock;
use pubky_switch_core::{
    claims::{ClaimFields, ClaimType},
    http::{IdentityDelivery, header},
    keys::IdentityKey,
    ops::{OpKind, RecordPut, RecordVersion, SignedOp},
    records::{Enrollment, EnrollmentBody, IdentityBody, IdentityDoc},
    sig::SignedDoc,
    time::rfc3339,
};
use serde_json::{Value, json};
use sqlx::Connection;
use support::*;

/// An App ID an enrollment answered with the pending key names in its `revoked_apps`.
const HELD_REVOKED: [u8; 16] = [7; 16];

fn alice_id() -> String {
    alice(&vectors("keys.json"))["pubky_id"]
        .as_str()
        .expect("id")
        .into()
}

fn alice_key() -> IdentityKey {
    IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]))
}

fn json_of(response: &SwitchResponse) -> Value {
    serde_json::from_slice(&response.body).expect("json body")
}

fn code(response: &SwitchResponse) -> (u16, String) {
    (
        response.status,
        json_of(response)["code"]
            .as_str()
            .unwrap_or_default()
            .into(),
    )
}

/// Whether `response` is signed with `key` (Switch wire 7.1).
fn signed_by(response: &SwitchResponse, key: &[u8; 32], request_signature: &[u8; 64]) -> bool {
    let signature: [u8; 64] = pubky_switch_core::enc::unb64(
        header_text(response, header::SERVICE_SIGNATURE).expect("signature"),
    )
    .expect("b64")
    .try_into()
    .expect("64");
    pubky_switch_core::http::verify_response(
        key,
        response.status,
        Some(request_signature),
        header_text(response, header::SERVER_TIME).expect("time"),
        &response.body,
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

/// The vectors' enrollment with another nonce and `revoked_apps`.
fn enrollment(nonce: u8, revoked: Option<Vec<[u8; 16]>>) -> Vec<u8> {
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
    fields.origin = ORIGIN.into();
    fields.identity_doc = None;
    fields.revoked_apps = revoked;
    let enrollment = Enrollment::sign(&alice_key(), fields).expect("sign");
    serde_json::to_vec(&json!({ "enrollment": enrollment.signed() })).expect("json")
}

async fn enroll(replay: &Replay, body: Vec<u8>, at_ms: u64) -> SwitchResponse {
    replay
        .service
        .handle(signer_request("POST", "/v1/enroll", body, at_ms))
        .await
}

/// The service key an enrollment answer names.
fn answered_key(response: &SwitchResponse) -> [u8; 32] {
    let text = json_of(response)["service_key"]
        .as_str()
        .expect("service_key")
        .to_string();
    pubky_switch_core::enc::unb64(&text)
        .expect("b64")
        .try_into()
        .expect("32")
}

/// The newest `identity.json` the account holds, read from the database.
async fn held(replay: &Replay) -> IdentityDoc {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let bytes: Vec<u8> = sqlx::query_scalar("SELECT identity_doc FROM accounts WHERE id = $1")
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("doc");
    conn.close().await.expect("close");
    let signed: SignedDoc = serde_json::from_slice(&bytes).expect("signed");
    IdentityDoc::verify(&signed, &alice_key().public()).expect("verify")
}

async fn scalar_i64(replay: &Replay, query: &str) -> i64 {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let value: i64 = sqlx::query_scalar(query)
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("query");
    conn.close().await.expect("close");
    value
}

async fn service_key_id(replay: &Replay) -> KeyId {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let key: String = sqlx::query_scalar("SELECT service_key FROM accounts WHERE id = $1")
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("key");
    conn.close().await.expect("close");
    KeyId::parse(&key).expect("key id")
}

/// The account's chain items, as (generation, seq, item type).
async fn chain(replay: &Replay) -> Vec<(i64, i64, String)> {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let rows: Vec<(i64, i64, String)> = sqlx::query_as(
        "SELECT generation, seq, item_type FROM chain_items WHERE account_id = $1 \
         ORDER BY generation, seq",
    )
    .bind(alice_id())
    .fetch_all(&mut conn)
    .await
    .expect("chain");
    conn.close().await.expect("close");
    rows
}

/// A version after `on`, at `on`'s generation plus one, naming `key` and `recovery_from`.
fn next_generation(on: &IdentityDoc, key: [u8; 32], recovery_from: Option<u64>) -> SignedDoc {
    let mut body: IdentityBody = on.body().clone();
    body.version += 1;
    body.generation += 1;
    body.inbox.service_key = key;
    body.recovery_from = recovery_from;
    IdentityDoc::sign(&alice_key(), body)
        .expect("sign")
        .signed()
        .clone()
}

async fn deliver(
    replay: &Replay,
    doc: SignedDoc,
    prev: Option<[u8; 32]>,
    at_ms: u64,
) -> (SwitchResponse, [u8; 64]) {
    let path = format!("/v1/{}/identity", alice_id());
    let request = signer_request(
        "PUT",
        &path,
        IdentityDelivery {
            identity: doc,
            prev,
        }
        .to_json(),
        at_ms,
    );
    let signature = signature_of(&request);
    (replay.service.handle(request).await, signature)
}

/// alice serving at generation 1 with the vectors' chain through the phone's revocation,
/// then an enrollment answered with the pending key, naming [`HELD_REVOKED`]: the pending
/// key's public key, and the time after.
async fn serving_with_a_pending_key(replay: &Replay) -> ([u8; 32], u64) {
    replay_chain_through_revoke(replay).await;
    let at = replay.clock.now_ms() + 60_000;
    set_time(&replay.clock, &rfc3339(at));
    let answer = enroll(replay, enrollment(3, Some(vec![HELD_REVOKED])), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    (answered_key(&answer), at)
}

#[tokio::test]
async fn test_recovery_first_document_takes_its_generation() {
    // A new account after a provider loss: the first document is at generation 3, declaring
    // generation 2 lost. The account takes generation 3, and its chain starts with the
    // `recovery` transition at seq 1, then the delivery; `GET /apps` reports the recovery.
    let Some(replay) = replay().await else { return };
    let at = ms("2026-01-01T00:00:00.000Z");
    set_time(&replay.clock, "2026-01-01T00:00:00.000Z");
    let enrolled = enroll(&replay, enrollment(1, None), at).await;
    assert_eq!(enrolled.status, 200);
    let key = answered_key(&enrolled);
    let version_1 = IdentityDoc::verify(
        &serde_json::from_value(
            named(
                &vectors("documents.json")["documents"],
                "alice identity.json, first delivery (version 1)",
            )["signed"]
                .clone(),
        )
        .expect("doc"),
        &alice_key().public(),
    )
    .expect("verify");
    let mut body = version_1.body().clone();
    body.version = 9;
    body.generation = 3;
    body.recovery_from = Some(2);
    body.inbox.service_key = key;
    let first = IdentityDoc::sign(&alice_key(), body).expect("sign");
    let (answer, signature) = deliver(&replay, first.signed().clone(), None, at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(signed_by(&answer, &key, &signature));
    assert_eq!(
        chain(&replay).await,
        [(3, 1, "service".into()), (3, 2, "identity".into())]
    );
    let request = signer_request("GET", &format!("/v1/{}/apps", alice_id()), Vec::new(), at);
    let apps = replay.service.handle(request).await;
    assert_eq!(apps.status, 200);
    assert_eq!(
        json_of(&apps)["recovery"],
        json!({
            "recovery_from": 2,
            "declared_at": "2026-01-01T00:00:00.000Z",
            // The document lists apps: admission is staged.
            "admission_staged": true,
        })
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_first_document_needs_the_generation_less_one() {
    // A first document's `recovery_from` is its generation less one, and one above generation
    // 1 carries it (Switch wire 3.3): otherwise `400`, and nothing is chained.
    let Some(replay) = replay().await else { return };
    let at = ms("2026-01-01T00:00:00.000Z");
    set_time(&replay.clock, "2026-01-01T00:00:00.000Z");
    let enrolled = enroll(&replay, enrollment(1, None), at).await;
    let key = answered_key(&enrolled);
    let version_1: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json, first delivery (version 1)",
        )["signed"]
            .clone(),
    )
    .expect("doc");
    let version_1 = IdentityDoc::verify(&version_1, &alice_key().public()).expect("verify");
    for (generation, recovery_from) in [(3, Some(1)), (3, None), (1, Some(1))] {
        let mut body = version_1.body().clone();
        body.version = 9;
        body.generation = generation;
        body.recovery_from = recovery_from;
        body.inbox.service_key = key;
        let doc = IdentityDoc::sign(&alice_key(), body).expect("sign");
        let (answer, _) = deliver(&replay, doc.signed().clone(), None, at).await;
        assert_eq!(
            code(&answer),
            (400, "bad_request".into()),
            "generation {generation}, recovery_from {recovery_from:?}"
        );
    }
    assert!(chain(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_in_place_starts_afresh_under_the_pending_key() {
    // alice's provider loss at this same service: the next generation names the pending key
    // and declares generation 1 lost. The account starts afresh under that key: none of
    // generation 1's state stays, its tombstones and the held revoked App ID do, the chain
    // starts with the `recovery` transition, and the answer and every later one are the new
    // key's. The outgoing key is deleted, with no erasure recorded.
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let old_key = service_key_id(&replay).await;
    let tombstones_before = scalar_i64(
        &replay,
        "SELECT count(*) FROM kept_app_ids WHERE account_id = $1",
    )
    .await;
    let before = held(&replay).await;
    // A pending connect request, which doesn't outlive the recovery (wire 7.4.7).
    {
        let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        sqlx::query("INSERT INTO connect_requests (account_id, pubky, at_ms) VALUES ($1, $2, 0)")
            .bind(alice_id())
            .bind([4u8; 32].as_slice())
            .execute(&mut conn)
            .await
            .expect("a pending request");
    }
    let recovery = next_generation(&before, pending, Some(1));
    let (answer, signature) = deliver(&replay, recovery, Some(before.hash()), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(
        signed_by(&answer, &pending, &signature),
        "the new key's answer"
    );
    let new_key = service_key_id(&replay).await;
    assert_ne!(new_key, old_key);
    assert_eq!(
        replay.keys.public_key(&new_key).await.expect("key"),
        pending
    );
    assert!(
        replay.keys.public_key(&old_key).await.is_err(),
        "the outgoing key is deleted"
    );
    assert_eq!(
        replay.keys.erasure(&alice_id()).await.expect("ledger"),
        None,
        "no erasure recorded"
    );
    assert_eq!(
        scalar_i64(
            &replay,
            "SELECT count(*) FROM erased_keys WHERE account_id = $1"
        )
        .await,
        0
    );
    assert_eq!(
        chain(&replay).await,
        [(2, 1, "service".into()), (2, 2, "identity".into())]
    );
    // The new document's apps are listed afresh, in the new generation.
    assert_eq!(
        scalar_i64(
            &replay,
            "SELECT count(*) FROM app_listings WHERE account_id = $1"
        )
        .await,
        i64::try_from(before.body().apps.len()).expect("apps")
    );
    for table in pubky_switch::store::recovery_clears()
        .into_iter()
        .filter(|t| !matches!(*t, "chain_items" | "app_listings"))
    {
        let count = scalar_i64(
            &replay,
            &format!("SELECT count(*) FROM {table} WHERE account_id = $1"),
        )
        .await;
        assert_eq!(count, 0, "{table}");
    }
    assert_eq!(
        scalar_i64(
            &replay,
            "SELECT count(*) FROM kept_app_ids WHERE account_id = $1"
        )
        .await,
        tombstones_before + 1,
        "the tombstones, and the App ID held with the pending key"
    );
    assert_eq!(
        scalar_i64(
            &replay,
            "SELECT generation FROM accounts WHERE id = $1 AND pending_key IS NULL"
        )
        .await,
        2
    );
    let request = signer_request("GET", &format!("/v1/{}/apps", alice_id()), Vec::new(), at);
    let read_signature = signature_of(&request);
    let apps = replay.service.handle(request).await;
    assert_eq!(apps.status, 200);
    assert!(signed_by(&apps, &pending, &read_signature));
    assert_eq!(json_of(&apps)["recovery"]["recovery_from"], 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_in_place_answers_a_held_feed_read_503_as_the_operator() {
    // A feed read held when the account recovers in place: the recovery's commit wakes it,
    // and it is answered `503 unavailable` with the operator key, with no head: the
    // outgoing key signs nothing more, and the new generation's state isn't the read's
    // (Switch wire 7.4.4, spec 12.6 step 1).
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let tip = chain(&replay).await.last().map_or(0, |(_, seq, _)| *seq);
    let before = held(&replay).await;
    let (stop, task) = listen(&replay).await;
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/feed?after=1:{tip}&wait=10", alice_id());
    let request = app_request(app(&keys, "wallet"), "GET", &path, Vec::new(), at);
    let request_signature = signature_of(&request);
    let started = std::time::Instant::now();
    let waiting = replay.service.handle(request);
    let (answer, delivered) = tokio::join!(waiting, async {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        deliver(
            &replay,
            next_generation(&before, pending, Some(1)),
            Some(before.hash()),
            at,
        )
        .await
    });
    assert_eq!(delivered.0.status, 200, "the recovery");
    // Exactly these members, and the two headers every answer carries: the scripted
    // switch's answer is held to the same (the client's `held_reads` test).
    assert_eq!(answer.status, 503);
    assert_eq!(
        json_of(&answer),
        json!({ "code": "unavailable", "message": "7.6: a temporary failure" })
    );
    let mut names: Vec<&str> = answer
        .headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["switch-server-time", "switch-service-signature"]);
    // Woken by the recovery, not by the end of its wait.
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    // Neither generation's key signs it: the operator's does.
    assert!(signed_by(&answer, &operator_public(), &request_signature));
    assert!(!signed_by(&answer, &pending, &request_signature));
    let _ = stop.send(());
    task.await.expect("listener");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_in_place_retires_the_outgoing_keys_enrollments() {
    // After the change, the enrollment the outgoing key answered is `409 conflict`, signed
    // with the operator key, so its signer enrolls anew; the one the pending key answered
    // gets its answer again, the account's key now (Switch wire 3.7).
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let before = held(&replay).await;
    let recovery = next_generation(&before, pending, Some(1));
    let (answer, _) = deliver(&replay, recovery, Some(before.hash()), at).await;
    assert_eq!(answer.status, 200);
    let http = vectors("http.json");
    // The enrollment that created the account, its same bytes again, at the time now.
    let body = pubky_switch_core::enc::unb64(
        named(&http["requests"], "signer: enrollment")["body_b64"]
            .as_str()
            .expect("body"),
    )
    .expect("b64");
    let creating = signer_request("POST", "/v1/enroll", body, at);
    let creating_signature = signature_of(&creating);
    let retired = replay.service.handle(creating).await;
    assert_eq!(code(&retired), (409, "conflict".into()));
    assert!(signed_by(&retired, &operator_public(), &creating_signature));
    let again = enroll(&replay, enrollment(3, Some(vec![HELD_REVOKED])), at).await;
    assert_eq!(again.status, 200);
    assert_eq!(answered_key(&again), pending);
    // A new enrollment at the serving account gets a pending key of the next generation.
    let fresh = enroll(&replay, enrollment(5, None), at).await;
    assert_eq!(fresh.status, 200);
    assert_ne!(answered_key(&fresh), pending);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_key_rotation_isnt_served() {
    // The next generation under the pending key without `recovery_from`, keeping the
    // outgoing generation's key for its kept proofs, is a key rotation, which isn't served:
    // `503`, and nothing changes.
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let old_key = service_key_id(&replay).await;
    let old_public = replay.keys.public_key(&old_key).await.expect("key");
    let before = held(&replay).await;
    let mut body: IdentityBody = before.body().clone();
    body.version += 1;
    body.generation += 1;
    body.inbox.service_key = pending;
    body.service_keys
        .push(pubky_switch_core::records::ServiceKeyEntry {
            generation: 1,
            key: old_public,
        });
    let rotation = IdentityDoc::sign(&alice_key(), body)
        .expect("sign")
        .signed()
        .clone();
    let (answer, _) = deliver(&replay, rotation, Some(before.hash()), at).await;
    assert_eq!(code(&answer), (503, "unavailable".into()));
    assert_eq!(service_key_id(&replay).await, old_key);
    assert_eq!(held(&replay).await.hash(), before.hash());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_in_place_a_signer_of_the_outgoing_key_waiting_signs_nothing() {
    // A request that loaded the outgoing key comes to sign its answer while the change holds
    // the keying lock: it waits, and once the change commits it signs nothing with that key
    // (Switch wire 3.3, 7.4.16).
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let old_key = service_key_id(&replay).await;
    let store = replay.db.store().clone();
    let mut txn = store
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    let new_key = txn
        .pending_key()
        .await
        .expect("pending")
        .expect("a pending key");
    txn.exclude_signers().await.expect("exclude");
    txn.start_recovery_in_place(&new_key, 1, at, 8, true)
        .await
        .expect("start");
    let waiting = {
        let store = store.clone();
        let key = old_key.clone();
        tokio::spawn(async move { store.while_keyed(&alice_id(), &key, false, || ()).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(!waiting.is_finished(), "parked on the keying lock");
    txn.commit().await.expect("commit");
    let keyed = waiting.await.expect("join").expect("keyed");
    assert!(
        matches!(keyed, pubky_switch::store::Keyed::Rekeyed),
        "nothing signed with the outgoing key"
    );
    assert_eq!(
        replay.keys.public_key(&new_key).await.expect("key"),
        pending
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_in_place_waits_for_a_signer_of_the_outgoing_key() {
    // A request of the outgoing key is signing its answer, under the account's shared keying
    // lock, when the recovery comes: the recovery takes that lock exclusive before it switches
    // the key, so it waits until the signing is done, the outgoing key's last (Switch wire
    // 3.3). The shared lock is held here on a connection of its own, as a keyed section holds
    // it.
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let before = held(&replay).await;
    let mut signing = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("BEGIN")
        .execute(&mut signing)
        .await
        .expect("begin");
    sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
        .bind(pubky_switch::store::keying_lock_key(&alice_id()))
        .execute(&mut signing)
        .await
        .expect("shared lock");
    let recovery = next_generation(&before, pending, Some(1));
    let replay = std::sync::Arc::new(replay);
    let delivering = {
        let replay = replay.clone();
        tokio::spawn(async move { deliver(&replay, recovery, Some(before.hash()), at).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(
        !delivering.is_finished(),
        "the recovery waits for the signing"
    );
    sqlx::query("COMMIT")
        .execute(&mut signing)
        .await
        .expect("commit");
    let (answer, _) = delivering.await.expect("join");
    assert_eq!(answer.status, 200);
    signing.close().await.expect("close");
    let replay = std::sync::Arc::into_inner(replay).expect("one owner");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_classes_every_account_table() {
    // Every table with an account column is either kept or emptied by a recovery in place,
    // so a table added later fails here until it is classed (Switch wire 3.3).
    let Some(replay) = replay().await else { return };
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let mut tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.columns \
         WHERE table_schema = current_schema() AND column_name = 'account_id' \
         ORDER BY table_name",
    )
    .fetch_all(&mut conn)
    .await
    .expect("tables");
    conn.close().await.expect("close");
    tables.dedup();
    let keeps = pubky_switch::store::RECOVERY_KEEPS;
    let clears = pubky_switch::store::recovery_clears();
    for table in &tables {
        let kept = keeps.contains(&table.as_str());
        let cleared = clears.contains(&table.as_str());
        assert!(kept != cleared, "{table}: kept {kept}, cleared {cleared}");
    }
    let mut classed: Vec<&str> = keeps.iter().copied().chain(clears).collect();
    classed.sort_unstable();
    assert_eq!(classed, tables, "every class names a table");
    replay.db.drop_database().await.expect("drop");
}

/// The account's state restored from before its key's newest head: its chain gone, the
/// chain head and every `seq` back to none, while the key's mark stays where it was (Switch
/// wire 7.3 step 10).
async fn restored_behind_the_mark(replay: &Replay) {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("DELETE FROM chain_items WHERE account_id = $1")
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("chain");
    sqlx::query(
        "UPDATE accounts SET last_seq = 0, chain_seq = NULL, chain_hash = NULL WHERE id = $1",
    )
    .bind(alice_id())
    .execute(&mut conn)
    .await
    .expect("restore");
    conn.close().await.expect("close");
}

#[tokio::test]
async fn test_recovery_in_place_gets_past_a_state_behind_the_mark() {
    // The service's state was restored from before what the account's key signed: every
    // request is `503`, a new generation needed. The recovery delivering it, naming the
    // pending key, is exempt (Switch wire 7.3 step 10): it is answered with the new key, the
    // outgoing key retired and the account started afresh.
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let old_key = service_key_id(&replay).await;
    let before = held(&replay).await;
    restored_behind_the_mark(&replay).await;
    let recovery = next_generation(&before, pending, Some(1));
    let (answer, signature) = deliver(&replay, recovery, Some(before.hash()), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(signed_by(&answer, &pending, &signature));
    assert!(replay.keys.public_key(&old_key).await.is_err(), "retired");
    assert_eq!(
        chain(&replay).await,
        [(2, 1, "service".into()), (2, 2, "identity".into())]
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_exemption_from_the_mark_is_only_for_a_recovery() {
    // Behind the mark, only the recovery under the pending key gets through (Switch wire 7.3
    // step 10): an ordinary next version, a rotation without `recovery_from` and a recovery
    // naming another key all get the `503` a new generation is needed, with no head; so does the signer's `GET /apps`, which is how it
    // learns. The signer's enrollment is exempt: it gets the pending key.
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let old_key = service_key_id(&replay).await;
    let old_public = replay.keys.public_key(&old_key).await.expect("key");
    let before = held(&replay).await;
    restored_behind_the_mark(&replay).await;
    let behind = |answer: &SwitchResponse| {
        code(answer) == (503, "unavailable".into())
            && json_of(answer)["message"]
                .as_str()
                .is_some_and(|m| m.contains("a new generation is needed"))
            && header_text(answer, header::HEAD).is_none()
    };
    let sign = |change: &dyn Fn(&mut IdentityBody)| {
        let mut body: IdentityBody = before.body().clone();
        body.version += 1;
        change(&mut body);
        IdentityDoc::sign(&alice_key(), body)
            .expect("sign")
            .signed()
            .clone()
    };
    let ordinary = sign(&|body| body.record_max_age = Some(60));
    let rotation = sign(&|body| {
        body.generation += 1;
        body.inbox.service_key = pending;
        body.service_keys
            .push(pubky_switch_core::records::ServiceKeyEntry {
                generation: 1,
                key: old_public,
            });
    });
    let another_key = sign(&|body| {
        body.generation += 1;
        body.inbox.service_key = [9; 32];
        body.recovery_from = Some(1);
    });
    for (what, doc, prev) in [
        ("an ordinary version", ordinary, Some(before.hash())),
        ("a rotation", rotation, Some(before.hash())),
        (
            "a recovery naming another key",
            another_key,
            Some(before.hash()),
        ),
    ] {
        let (answer, _) = deliver(&replay, doc, prev, at).await;
        assert!(
            behind(&answer),
            "{what}: {}",
            String::from_utf8_lossy(&answer.body)
        );
    }
    let request = signer_request("GET", &format!("/v1/{}/apps", alice_id()), Vec::new(), at);
    assert!(behind(&replay.service.handle(request).await));
    let enrolled = enroll(&replay, enrollment(3, Some(vec![HELD_REVOKED])), at).await;
    assert_eq!(enrolled.status, 200);
    assert_eq!(answered_key(&enrolled), pending);
    assert_eq!(service_key_id(&replay).await, old_key, "nothing changed");
    replay.db.drop_database().await.expect("drop");
}

/// The wallet's batch with batch ID `[id; 16]` at `generation`.
fn wallet_batch(
    id: u8,
    generation: u64,
    kinds: Vec<(
        Vec<pubky_switch_core::ops::Condition>,
        pubky_switch_core::ops::OpKind,
    )>,
) -> Vec<pubky_switch_core::ops::SignedOp> {
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let key = ed25519_dalek::SigningKey::from_bytes(&hex32(&wallet["signing_secret_hex"]));
    let app_id: [u8; 16] = hex::decode(wallet["app_id_bytes_hex"].as_str().expect("hex"))
        .expect("hex")
        .try_into()
        .expect("16 bytes");
    pubky_switch_core::ops::sign_batch(
        &key,
        &alice_key().public(),
        Some(app_id),
        generation,
        [id; 16],
        kinds,
    )
    .expect("batch")
}

/// The wallet's app record from `chain.json` seq 3, and its keys and certificate.
#[allow(clippy::panic)]
fn wallet() -> (
    SignedDoc,
    pubky_switch_core::keys::AppKeys,
    pubky_switch_core::records::AppCert,
) {
    let chain = vectors("chain.json");
    let signed: SignedDoc = serde_json::from_value(chain["items"][2]["item"].clone()).expect("op");
    let op = pubky_switch_core::ops::SignedOp::peek(&signed).expect("op");
    let pubky_switch_core::ops::OpKind::AppPut { record } = op.body().kind.clone() else {
        panic!("the wallet's app.put");
    };
    let cert = pubky_switch_core::records::AppRecord::verify(&record, &alice_key().public())
        .expect("record")
        .cert()
        .clone();
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let app_keys = pubky_switch_core::keys::AppKeys::from_secrets(
        hex32(&wallet["signing_secret_hex"]),
        hex32(&wallet["bundle_secret_hex"]),
    );
    (record, app_keys, cert)
}

/// The wallet registers a receive key with `n` at `generation`, in the batch `[id; 16]`,
/// with its app record first when `with_record`: the answer's status and body.
async fn wallet_registers(
    replay: &Replay,
    id: u8,
    generation: u64,
    n: u64,
    with_record: bool,
    at: u64,
) -> (u16, Value) {
    use pubky_switch_core::ops::OpKind;
    let (record, keys, cert) = wallet();
    let key = pubky_switch_core::keys::ReceiveKey::from_secret(n, [40 + id; 32]);
    let receive = pubky_switch_core::records::ReceiveKeyRecord::sign(
        &keys,
        &cert,
        pubky_switch_core::records::ReceiveKeyBody::new(&cert, &key),
    )
    .expect("record");
    let mut ops = Vec::new();
    if with_record {
        ops.push((Vec::new(), OpKind::AppPut { record }));
    }
    ops.push((
        Vec::new(),
        OpKind::ReceiveKeyPut {
            record: receive.signed().clone(),
        },
    ));
    let batch = wallet_batch(id, generation, ops);
    let keys_json = vectors("keys.json");
    let body = pubky_switch_core::ops::OpsRequest::new(&batch, None).to_json();
    let request = app_request(
        app(&keys_json, "wallet"),
        "POST",
        &format!("/v1/{}/ops", alice_id()),
        body,
        at,
    );
    let answer = replay.service.handle(request).await;
    (
        answer.status,
        serde_json::from_slice(&answer.body).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn test_recovery_in_place_takes_a_first_receive_key_above_zero() {
    // After a provider loss an app registers a receive key one higher than every `n` it
    // registered (Switch spec 3.6, 12.6 step 1): its first record in the recovered generation
    // may carry any `n`, and each later one is one higher again.
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let before = held(&replay).await;
    let recovery = next_generation(&before, pending, Some(1));
    let (answer, _) = deliver(&replay, recovery, Some(before.hash()), at).await;
    assert_eq!(answer.status, 200);
    let (status, body) = wallet_registers(&replay, 77, 2, 3, true, at).await;
    assert_eq!(status, 200, "{body}");
    let (status, _) = wallet_registers(&replay, 78, 2, 5, false, at).await;
    assert_eq!(status, 409, "not the next one");
    let (status, body) = wallet_registers(&replay, 79, 2, 4, false, at).await;
    assert_eq!(status, 200, "{body}");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_in_place_refuses_an_app_the_pending_enrollment_revoked() {
    // The pending key's enrollments' `revoked_apps` are kept from the new generation's start,
    // as at a new account that "never serves or lists them, also after a provider loss"
    // (Switch wire 3.7): a recovery document that lists one is `400`, and nothing changes.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = replay.clock.now_ms() + 60_000;
    set_time(&replay.clock, &rfc3339(at));
    let keys = vectors("keys.json");
    let wallet_id: [u8; 16] = hex::decode(
        app(&keys, "wallet")["app_id_bytes_hex"]
            .as_str()
            .expect("hex"),
    )
    .expect("hex")
    .try_into()
    .expect("16");
    let answer = enroll(&replay, enrollment(3, Some(vec![wallet_id])), at).await;
    assert_eq!(answer.status, 200);
    let pending = answered_key(&answer);
    let old_key = service_key_id(&replay).await;
    let before = held(&replay).await;
    assert!(before.body().apps.iter().any(|a| a.app_id == wallet_id));
    let recovery = next_generation(&before, pending, Some(1));
    let (answer, _) = deliver(&replay, recovery, Some(before.hash()), at).await;
    assert_eq!(code(&answer), (400, "bad_request".into()));
    assert_eq!(service_key_id(&replay).await, old_key);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_first_document_names_this_service() {
    // A recovery's first document names this service, its origin and the account's key
    // (Switch wire 7.4.2): one naming another is `400`, and nothing is chained.
    let Some(replay) = replay().await else { return };
    let at = ms("2026-01-01T00:00:00.000Z");
    set_time(&replay.clock, "2026-01-01T00:00:00.000Z");
    let enrolled = enroll(&replay, enrollment(1, None), at).await;
    let key = answered_key(&enrolled);
    let version_1: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json, first delivery (version 1)",
        )["signed"]
            .clone(),
    )
    .expect("doc");
    let version_1 = IdentityDoc::verify(&version_1, &alice_key().public()).expect("verify");
    for (url, service_key) in [("https://elsewhere.example", key), (ORIGIN, [9; 32])] {
        let mut body = version_1.body().clone();
        body.version = 9;
        body.generation = 3;
        body.recovery_from = Some(2);
        body.inbox.url = url.into();
        body.inbox.service_key = service_key;
        let doc = IdentityDoc::sign(&alice_key(), body).expect("sign");
        let (answer, _) = deliver(&replay, doc.signed().clone(), None, at).await;
        assert_eq!(code(&answer), (400, "bad_request".into()), "{url}");
    }
    assert!(chain(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_in_place_drops_the_oldest_retired_enrollment() {
    // At most `max_enrollments` retired enrollments are kept, the oldest dropping; the same
    // enrollment again after its record dropped is answered as a new one (Switch wire 3.7).
    // With a bound of 2: two staged enrollments retire at the first change, the pending one
    // at the second, and the creating enrollment's record drops.
    let limits = pubky_switch::limits::Limits {
        max_enrollments: 2,
        ..pubky_switch::limits::Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    let at = ms("2026-01-01T00:00:00.000Z");
    set_time(&replay.clock, "2026-01-01T00:00:00.000Z");
    let first = enroll(&replay, enrollment(1, None), at).await;
    assert_eq!(first.status, 200);
    assert_eq!(enroll(&replay, enrollment(2, None), at).await.status, 200);
    let key = answered_key(&first);
    let version_1: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json, first delivery (version 1)",
        )["signed"]
            .clone(),
    )
    .expect("doc");
    let version_1 = IdentityDoc::verify(&version_1, &alice_key().public()).expect("verify");
    let mut body = version_1.body().clone();
    body.inbox.service_key = key;
    body.inbox.url = ORIGIN.into();
    let v1 = IdentityDoc::sign(&alice_key(), body).expect("sign");
    let (answer, _) = deliver(&replay, v1.signed().clone(), None, at).await;
    assert_eq!(answer.status, 200);
    let p1 = enroll(&replay, enrollment(3, None), at).await;
    let pending = answered_key(&p1);
    let (answer, _) = deliver(
        &replay,
        next_generation(&v1, pending, Some(1)),
        Some(v1.hash()),
        at,
    )
    .await;
    assert_eq!(answer.status, 200);
    for nonce in [1, 2] {
        let again = enroll(&replay, enrollment(nonce, None), at).await;
        assert_eq!(code(&again), (409, "conflict".into()), "nonce {nonce}");
    }
    let p2 = enroll(&replay, enrollment(4, None), at).await;
    let pending_2 = answered_key(&p2);
    let generation_2 = held(&replay).await;
    let (answer, _) = deliver(
        &replay,
        next_generation(&generation_2, pending_2, Some(2)),
        Some(generation_2.hash()),
        at,
    )
    .await;
    assert_eq!(answer.status, 200);
    assert_eq!(
        scalar_i64(
            &replay,
            "SELECT count(*) FROM retired_enrollments WHERE account_id = $1"
        )
        .await,
        2
    );
    let dropped = enroll(&replay, enrollment(1, None), at).await;
    assert_eq!(dropped.status, 200, "answered as a new enrollment");
    let fresh = answered_key(&dropped);
    assert!(fresh != pending_2 && fresh != pending && fresh != key);
    for nonce in [2, 3] {
        let again = enroll(&replay, enrollment(nonce, None), at).await;
        assert_eq!(code(&again), (409, "conflict".into()), "nonce {nonce}");
    }
    assert_eq!(
        answered_key(&enroll(&replay, enrollment(4, None), at).await),
        pending_2
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_in_place_keeps_the_pending_keys_answers_for_good() {
    // The answers the pending key gave name the account's key once it serves, which a
    // rebuild wouldn't give: kept for good, they never drop for newer enrollments' answers
    // (Switch wire 3.7, 9.1).
    let limits = pubky_switch::limits::Limits {
        max_enrollments: 2,
        ..pubky_switch::limits::Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let before = held(&replay).await;
    let (answer, _) = deliver(
        &replay,
        next_generation(&before, pending, Some(1)),
        Some(before.hash()),
        at,
    )
    .await;
    assert_eq!(answer.status, 200);
    for nonce in 10..14 {
        assert_eq!(
            enroll(&replay, enrollment(nonce, None), at).await.status,
            200
        );
    }
    let again = enroll(&replay, enrollment(3, Some(vec![HELD_REVOKED])), at).await;
    assert_eq!(answered_key(&again), pending);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_rotation_after_a_recovery_isnt_served() {
    // A later document keeps the earlier loss's `recovery_from` (spec 4.3), which doesn't
    // name the generation that ends: the next generation under a new pending key is then a
    // rotation, `503`, and nothing changes.
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let before = held(&replay).await;
    let (answer, _) = deliver(
        &replay,
        next_generation(&before, pending, Some(1)),
        Some(before.hash()),
        at,
    )
    .await;
    assert_eq!(answer.status, 200);
    let fresh = enroll(&replay, enrollment(9, None), at).await;
    let pending_2 = answered_key(&fresh);
    let generation_2 = held(&replay).await;
    let key_2 = service_key_id(&replay).await;
    let rotation = next_generation(&generation_2, pending_2, Some(1));
    let (answer, _) = deliver(&replay, rotation, Some(generation_2.hash()), at).await;
    assert_eq!(code(&answer), (503, "unavailable".into()));
    assert_eq!(service_key_id(&replay).await, key_2);
    assert_eq!(held(&replay).await.hash(), generation_2.hash());
    replay.db.drop_database().await.expect("drop");
}

/// alice serving with the vectors' chain, restored: her key's mark three `seq`s past her
/// state, or, with `fork`, her head at the mark's `seq` with another chain hash. The
/// outgoing key and the time.
async fn restored(replay: &Replay, fork: bool) -> (KeyId, u64) {
    replay_chain_through_revoke(replay).await;
    let at = replay.clock.now_ms() + 60_000;
    set_time(&replay.clock, &rfc3339(at));
    let old_key = service_key_id(replay).await;
    let mark = replay
        .keys
        .mark(&old_key)
        .await
        .expect("mark")
        .expect("a mark");
    if fork {
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
    } else {
        replay
            .keys
            .advance_mark(
                &old_key,
                pubky_switch::keys::Mark {
                    generation: mark.generation,
                    seq: mark.seq + 3,
                    chain_hash: [9; 32],
                },
            )
            .await
            .expect("advance");
    }
    (old_key, at)
}

/// At a serving account behind its key's mark, or beside it, every request is `503` with no
/// head, but the signer's enrollment, the recovery delivering the next generation under the
/// pending key, and an erasure (Switch wire 7.3 step 10).
async fn only_the_recovery_gets_past_the_mark(fork: bool) {
    let Some(replay) = replay().await else { return };
    let (old_key, at) = restored(&replay, fork).await;
    let old_public = replay.keys.public_key(&old_key).await.expect("key");
    let apps = replay
        .service
        .handle(signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            at,
        ))
        .await;
    assert_eq!(code(&apps), (503, "unavailable".into()), "fails stop");
    let enrolled = enroll(&replay, enrollment(3, Some(vec![HELD_REVOKED])), at).await;
    assert_eq!(enrolled.status, 200);
    let pending = answered_key(&enrolled);
    let before = held(&replay).await;
    let mut ordinary = before.body().clone();
    ordinary.version += 1;
    let ordinary = IdentityDoc::sign(&alice_key(), ordinary)
        .expect("sign")
        .signed()
        .clone();
    for (what, doc) in [
        ("an ordinary version", ordinary),
        ("a rotation", next_generation(&before, pending, None)),
        ("another key", next_generation(&before, old_public, Some(1))),
    ] {
        let (answer, _) = deliver(&replay, doc, Some(before.hash()), at).await;
        assert_eq!(code(&answer), (503, "unavailable".into()), "{what}");
        assert!(
            header_text(&answer, header::HEAD).is_none(),
            "{what}: no head"
        );
    }
    assert_eq!(service_key_id(&replay).await, old_key);
    assert_eq!(held(&replay).await.hash(), before.hash());
    let recovery = next_generation(&before, pending, Some(1));
    let (answer, signature) = deliver(&replay, recovery, Some(before.hash()), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(signed_by(&answer, &pending, &signature));
    assert!(!signed_by(&answer, &old_public, &signature));
    let request = signer_request("GET", &format!("/v1/{}/apps", alice_id()), Vec::new(), at);
    let read_signature = signature_of(&request);
    let apps = replay.service.handle(request).await;
    assert_eq!(apps.status, 200);
    assert!(signed_by(&apps, &pending, &read_signature));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_gets_past_a_state_behind_its_mark_alone() {
    only_the_recovery_gets_past_the_mark(false).await;
}

#[tokio::test]
async fn test_recovery_gets_past_a_state_beside_its_mark_alone() {
    only_the_recovery_gets_past_the_mark(true).await;
}

#[tokio::test]
async fn test_recovery_in_place_after_its_version_was_lost_too() {
    // The restore lost the newest `identity.json` too: the service holds an older version,
    // and the signer's recovery builds on the one it lost. A provider loss in place takes it
    // whatever its `prev` names, at a higher version than the one held (Switch wire 3.3);
    // the account fails stop otherwise, and could never learn the version held.
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let newest = held(&replay).await;
    let version_1: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json, first delivery (version 1)",
        )["signed"]
            .clone(),
    )
    .expect("doc");
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("UPDATE accounts SET identity_doc = $2, identity_proof = NULL WHERE id = $1")
        .bind(alice_id())
        .bind(serde_json::to_vec(&version_1).expect("json"))
        .execute(&mut conn)
        .await
        .expect("older version");
    conn.close().await.expect("close");
    restored_behind_the_mark(&replay).await;
    let recovery = next_generation(&newest, pending, Some(1));
    let (answer, signature) = deliver(&replay, recovery, Some(newest.hash()), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(signed_by(&answer, &pending, &signature));
    replay.db.drop_database().await.expect("drop");
}

/// The wallet's App ID, from the vectors.
fn wallet_app_id() -> [u8; 16] {
    let keys = vectors("keys.json");
    hex::decode(
        app(&keys, "wallet")["app_id_bytes_hex"]
            .as_str()
            .expect("hex"),
    )
    .expect("hex")
    .try_into()
    .expect("16")
}

/// A recovery after `on` naming `key`, at `version`.
fn recovery_at(on: &IdentityDoc, key: [u8; 32], version: u64) -> SignedDoc {
    let mut body: IdentityBody = on.body().clone();
    body.version = version;
    body.generation += 1;
    body.inbox.service_key = key;
    body.recovery_from = Some(on.generation());
    IdentityDoc::sign(&alice_key(), body)
        .expect("sign")
        .signed()
        .clone()
}

/// Whether `answer` is the 503 of a state behind its key's mark: no head.
fn is_behind_the_mark(answer: &SwitchResponse) -> bool {
    code(answer) == (503, "unavailable".into())
        && json_of(answer)["message"]
            .as_str()
            .is_some_and(|m| m.contains("a new generation is needed"))
        && header_text(answer, header::HEAD).is_none()
}

async fn snapshot(replay: &Replay) -> (KeyId, [u8; 32], usize, i64, i64) {
    let key = service_key_id(replay).await;
    let held = held(replay).await.hash();
    let chain = chain(replay).await.len();
    let seq = scalar_i64(replay, "SELECT last_seq FROM accounts WHERE id = $1").await;
    let recovery = scalar_i64(
        replay,
        "SELECT COALESCE(recovery_from, -1) FROM accounts WHERE id = $1",
    )
    .await;
    (key, held, chain, seq, recovery)
}

async fn exempt_delivery_refused_deeper(fork: bool) {
    // Behind (or beside) the mark, a delivery exempt from the mark check (the signer's,
    // at the next generation, naming the pending key, `recovery_from` the held generation)
    // that put_identity refuses all the same: a version not higher than the one held (409
    // stale_identity), or one listing an App ID the pending enrollment revoked (400). Each
    // gets the behind 503 with no head, signed with the outgoing key as every request in
    // that state is, and nothing commits: the key, the held version, the chain, the
    // stamped seq, the recovery columns and the outgoing key's mark all stay.
    let Some(replay) = replay().await else { return };
    let (old_key, at) = restored(&replay, fork).await;
    let old_public = replay.keys.public_key(&old_key).await.expect("key");
    let wallet = wallet_app_id();
    let enrolled = enroll(&replay, enrollment(3, Some(vec![wallet])), at).await;
    assert_eq!(enrolled.status, 200);
    let pending = answered_key(&enrolled);
    let before = held(&replay).await;
    assert!(before.body().apps.iter().any(|a| a.app_id == wallet));
    let mark_before = replay.keys.mark(&old_key).await.expect("mark");
    let state_before = snapshot(&replay).await;
    let mut without_wallet: IdentityBody = before.body().clone();
    without_wallet.apps.retain(|a| a.app_id != wallet);
    let without_wallet = IdentityDoc::sign(&alice_key(), without_wallet).expect("sign");
    for (what, doc) in [
        (
            "not a higher version",
            recovery_at(&without_wallet, pending, before.version()),
        ),
        (
            "lists the revoked wallet",
            next_generation(&before, pending, Some(before.generation())),
        ),
    ] {
        let (answer, signature) = deliver(&replay, doc, Some(before.hash()), at).await;
        assert!(
            is_behind_the_mark(&answer),
            "{what}: {} {}",
            answer.status,
            String::from_utf8_lossy(&answer.body)
        );
        assert!(
            signed_by(&answer, &old_public, &signature),
            "{what}: old key"
        );
        assert_eq!(snapshot(&replay).await, state_before, "{what}: nothing");
        assert_eq!(
            replay.keys.mark(&old_key).await.expect("mark"),
            mark_before,
            "{what}: mark"
        );
        assert!(
            replay.keys.public_key(&old_key).await.is_ok(),
            "not retired"
        );
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_behind_the_mark_an_exempt_delivery_refused_deeper_is_the_503() {
    exempt_delivery_refused_deeper(false).await;
}

#[tokio::test]
async fn test_recovery_beside_the_mark_an_exempt_delivery_refused_deeper_is_the_503() {
    exempt_delivery_refused_deeper(true).await;
}

#[tokio::test]
async fn test_recovery_without_prev_still_needs_a_higher_version_and_only_for_a_recovery() {
    // Wire 3.3: a recovery in place is exempt from comparing `prev`, but needs a
    // higher version than the one held: one at or below it, whatever its `prev`, is `409
    // stale_identity` with the held copy. A rotation and an ordinary version with a stale
    // `prev` aren't exempt: `409 stale_identity`, not the rotation's `503`.
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let before = held(&replay).await;
    let state_before = snapshot(&replay).await;
    for version in [before.version(), before.version() - 1] {
        let (answer, _) = deliver(
            &replay,
            recovery_at(&before, pending, version),
            Some([3; 32]),
            at,
        )
        .await;
        assert_eq!(code(&answer), (409, "stale_identity".into()), "v{version}");
        assert_eq!(
            json_of(&answer)["current"]["hash"],
            json!(pubky_switch_core::enc::b64(&before.hash()))
        );
    }
    let mut ordinary: IdentityBody = before.body().clone();
    ordinary.version += 1;
    let ordinary = IdentityDoc::sign(&alice_key(), ordinary)
        .expect("sign")
        .signed()
        .clone();
    let old_public = replay
        .keys
        .public_key(&service_key_id(&replay).await)
        .await
        .expect("key");
    let mut rotation: IdentityBody = before.body().clone();
    rotation.version += 1;
    rotation.generation += 1;
    rotation.inbox.service_key = pending;
    rotation
        .service_keys
        .push(pubky_switch_core::records::ServiceKeyEntry {
            generation: 1,
            key: old_public,
        });
    let rotation = IdentityDoc::sign(&alice_key(), rotation)
        .expect("sign")
        .signed()
        .clone();
    // With the right prev, the rotation is the 503 of a change not served.
    let (answer, _) = deliver(&replay, rotation.clone(), Some(before.hash()), at).await;
    assert_eq!(
        code(&answer),
        (503, "unavailable".into()),
        "rotation, right prev"
    );
    for (what, doc) in [
        ("a rotation", rotation),
        ("an ordinary version", ordinary),
        (
            "a recovery naming another key",
            next_generation(&before, [9; 32], Some(1)),
        ),
    ] {
        let (answer, _) = deliver(&replay, doc, Some([3; 32]), at).await;
        assert_eq!(code(&answer), (409, "stale_identity".into()), "{what}");
    }
    assert_eq!(snapshot(&replay).await.0, state_before.0);
    assert_eq!(snapshot(&replay).await.1, state_before.1);
    // `prev` null at an account holding a version: taken too (the rule's "whatever").
    let (answer, _) = deliver(
        &replay,
        recovery_at(&before, pending, before.version() + 1),
        None,
        at,
    )
    .await;
    assert_eq!(answer.status, 200, "prev null, a higher version");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_document_replayed_later_is_refused() {
    // A recovery document delivered before, at a generation the account has since served
    // past (a later version, then a second loss), never takes the exemption again: its
    // generation is not the held one plus one.
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let before = held(&replay).await;
    let r1 = next_generation(&before, pending, Some(1));
    let (answer, _) = deliver(&replay, r1.clone(), Some(before.hash()), at).await;
    assert_eq!(answer.status, 200);
    let g2 = held(&replay).await;
    let mut later: IdentityBody = g2.body().clone();
    later.version += 1;
    let later = IdentityDoc::sign(&alice_key(), later).expect("sign");
    let (answer, _) = deliver(&replay, later.signed().clone(), Some(g2.hash()), at).await;
    assert_eq!(answer.status, 200);
    let (answer, _) = deliver(&replay, r1.clone(), Some([3; 32]), at).await;
    assert_eq!(
        code(&answer),
        (409, "stale_identity".into()),
        "after a later version"
    );
    let (answer, _) = deliver(&replay, r1.clone(), Some(later.hash()), at).await;
    assert_eq!(
        code(&answer),
        (409, "stale_identity".into()),
        "older, prev right"
    );
    let p2 = answered_key(&enroll(&replay, enrollment(9, None), at).await);
    let r2 = recovery_at(&later, p2, later.version() + 1);
    let (answer, _) = deliver(&replay, r2, Some([4; 32]), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let key_3 = service_key_id(&replay).await;
    for prev in [Some([3; 32]), Some(later.hash()), None] {
        let (answer, _) = deliver(&replay, r1.clone(), prev, at).await;
        assert_eq!(code(&answer), (409, "stale_identity".into()), "{prev:?}");
    }
    assert_eq!(service_key_id(&replay).await, key_3);
    replay.db.drop_database().await.expect("drop");
}

async fn admission(replay: &Replay, body: Vec<u8>, at_ms: u64) -> SwitchResponse {
    let path = format!("/v1/{}/recovery/admission", alice_id());
    replay
        .service
        .handle(signer_request("POST", &path, body, at_ms))
        .await
}

async fn admission_staged(replay: &Replay, at_ms: u64) -> Value {
    let request = signer_request(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        at_ms,
    );
    let apps = replay.service.handle(request).await;
    assert_eq!(apps.status, 200);
    json_of(&apps)["recovery"]["admission_staged"].clone()
}

/// bob's shop delivers bob's document to alice's account, and appends to her inbox.
async fn from_shop(replay: &Replay, at_ms: u64) -> (SwitchResponse, SwitchResponse) {
    let bob: SignedDoc = serde_json::from_value(
        named(&vectors("documents.json")["documents"], "bob identity.json")["signed"].clone(),
    )
    .expect("bob");
    let peers = other_request(
        "shop",
        ORIGIN,
        "PUT",
        &format!("/v1/{}/peers", alice_id()),
        serde_json::to_vec(&bob).expect("json"),
        None,
        at_ms,
    );
    let version = scalar_i64(replay, "SELECT apps_version FROM accounts WHERE id = $1").await;
    let inbox = other_request(
        "shop",
        ORIGIN,
        "POST",
        &format!("/v1/{}/inbox?apps_version={version}", alice_id()),
        vec![7; 200],
        None,
        at_ms,
    );
    (
        replay.service.handle(peers).await,
        replay.service.handle(inbox).await,
    )
}

#[tokio::test]
async fn test_admission_staged_until_the_signer_ends_it() {
    // A recovery whose document lists apps stages admission: a sender alice can't otherwise
    // admit gets `503 staged` at `PUT /peers` and at the inbox, and retries. The signer ends
    // it with `POST /recovery/admission`, which chains the `admission` transition; the sender
    // is then refused as any sender not admitted. Ended, a second call chains nothing and
    // answers no proof (Switch spec 12.6 step 2; wire 7.4.14).
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let before = held(&replay).await;
    let recovery = next_generation(&before, pending, Some(1));
    let (answer, _) = deliver(&replay, recovery, Some(before.hash()), at).await;
    assert_eq!(answer.status, 200);
    assert_eq!(admission_staged(&replay, at).await, json!(true));
    let (peers, inbox) = from_shop(&replay, at).await;
    assert_eq!(code(&peers), (503, "staged".into()));
    assert_eq!(code(&inbox), (503, "staged".into()));
    let ended = admission(&replay, Vec::new(), at).await;
    assert_eq!(
        ended.status,
        200,
        "{}",
        String::from_utf8_lossy(&ended.body)
    );
    assert_eq!(
        json_of(&ended)["proofs"].as_array().expect("proofs").len(),
        1
    );
    assert_eq!(
        chain(&replay).await,
        [
            (2, 1, "service".into()),
            (2, 2, "identity".into()),
            (2, 3, "service".into())
        ]
    );
    assert_eq!(admission_staged(&replay, at).await, json!(false));
    let (peers, inbox) = from_shop(&replay, at).await;
    assert_eq!(code(&peers), (403, "not_admitted".into()));
    assert_eq!(code(&inbox), (403, "not_admitted".into()));
    let again = admission(&replay, Vec::new(), at).await;
    assert_eq!(again.status, 200);
    assert_eq!(json_of(&again)["proofs"], json!([]));
    assert_eq!(chain(&replay).await.len(), 3, "nothing chained");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_admission_isnt_staged_by_a_recovery_listing_no_app() {
    // A recovery document that lists no app stages nothing: senders aren't held back, and
    // the signer's call chains nothing (Switch spec 12.6 step 2; wire 7.4.14).
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let before = held(&replay).await;
    let mut body: IdentityBody = before.body().clone();
    body.version += 1;
    body.generation += 1;
    body.inbox.service_key = pending;
    body.recovery_from = Some(1);
    body.apps.clear();
    body.renewed.clear();
    let recovery = IdentityDoc::sign(&alice_key(), body)
        .expect("sign")
        .signed()
        .clone();
    let (answer, _) = deliver(&replay, recovery, Some(before.hash()), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(admission_staged(&replay, at).await, json!(false));
    let (peers, _) = from_shop(&replay, at).await;
    assert_eq!(code(&peers), (403, "not_admitted".into()));
    let ended = admission(&replay, Vec::new(), at).await;
    assert_eq!(ended.status, 200);
    assert_eq!(json_of(&ended)["proofs"], json!([]));
    assert_eq!(chain(&replay).await.len(), 2);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_admission_needs_a_recovery_and_an_empty_body() {
    // `404` at an account whose generation began with no recovery; `400` for a body (Switch
    // wire 7.4.14).
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    assert_eq!(
        code(&admission(&replay, Vec::new(), at).await),
        (404, "not_found".into())
    );
    let before = held(&replay).await;
    let recovery = next_generation(&before, pending, Some(1));
    let (answer, _) = deliver(&replay, recovery, Some(before.hash()), at).await;
    assert_eq!(answer.status, 200);
    assert_eq!(
        code(&admission(&replay, b"{}".to_vec(), at).await),
        (400, "bad_request".into())
    );
    assert_eq!(admission_staged(&replay, at).await, json!(true));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_admission_staged_holds_back_connect_requests_too() {
    // alice takes connect requests, so a stranger may deliver its document and ask to
    // connect. While admission is staged the deny list isn't back yet and a denied sender
    // would pass for a stranger, so a stranger gets `503 staged` too, at both calls; once it
    // ends, its delivery is taken and its request kept (Switch spec 12.6 step 2).
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let before = held(&replay).await;
    let mut body: IdentityBody = before.body().clone();
    body.version += 1;
    body.generation += 1;
    body.inbox.service_key = pending;
    body.recovery_from = Some(1);
    body.policy.connect_requests.enabled = true;
    let recovery = IdentityDoc::sign(&alice_key(), body)
        .expect("sign")
        .signed()
        .clone();
    let (answer, _) = deliver(&replay, recovery, Some(before.hash()), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let ask = || {
        other_request(
            "shop",
            ORIGIN,
            "POST",
            &format!("/v1/{}/connect", alice_id()),
            Vec::new(),
            None,
            at,
        )
    };
    let (peers, _) = from_shop(&replay, at).await;
    assert_eq!(code(&peers), (503, "staged".into()));
    assert_eq!(
        code(&replay.service.handle(ask()).await),
        (503, "staged".into())
    );
    assert_eq!(admission(&replay, Vec::new(), at).await.status, 200);
    let (peers, _) = from_shop(&replay, at).await;
    assert_eq!(
        peers.status,
        200,
        "{}",
        String::from_utf8_lossy(&peers.body)
    );
    let asked = replay.service.handle(ask()).await;
    assert_eq!(
        asked.status,
        200,
        "{}",
        String::from_utf8_lossy(&asked.body)
    );
    replay.db.drop_database().await.expect("drop");
}

fn wallet_keys() -> Value {
    app(&vectors("keys.json"), "wallet").clone()
}

async fn recovered_staged(replay: &Replay) -> u64 {
    let (pending, at) = serving_with_a_pending_key(replay).await;
    let before = held(replay).await;
    let recovery = next_generation(&before, pending, Some(1));
    let (answer, _) = deliver(replay, recovery, Some(before.hash()), at).await;
    assert_eq!(answer.status, 200);
    assert_eq!(admission_staged(replay, at).await, json!(true));
    at
}

#[tokio::test]
async fn test_admission_an_own_app_cant_end_it() {
    // POST /recovery/admission is the signer's: an own app, current at the recovered
    // account, gets 403 permission_missing, and admission stays staged, nothing chained.
    let Some(replay) = replay().await else { return };
    let at = recovered_staged(&replay).await;
    let (status, body) = wallet_registers(&replay, 77, 2, 3, true, at).await;
    assert_eq!(status, 200, "{body}");
    let length = chain(&replay).await.len();
    let path = format!("/v1/{}/recovery/admission", alice_id());
    let answer = replay
        .service
        .handle(app_request(&wallet_keys(), "POST", &path, Vec::new(), at))
        .await;
    assert_eq!(code(&answer), (403, "permission_missing".into()));
    assert_eq!(admission_staged(&replay, at).await, json!(true));
    assert_eq!(chain(&replay).await.len(), length);
    // And an app of another identity, as at every call only the signer makes.
    let other = other_request("shop", ORIGIN, "POST", &path, Vec::new(), None, at);
    let answer = replay.service.handle(other).await;
    assert_eq!(code(&answer), (403, "permission_missing".into()));
    assert_eq!(admission_staged(&replay, at).await, json!(true));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_admission_two_calls_at_once_chain_one_transition() {
    // Two signer calls at once serialize on the account's lock: one chains the admission
    // transition and answers its proof, the other chains nothing and answers none.
    let Some(replay) = replay().await else { return };
    let at = recovered_staged(&replay).await;
    let (a, b) = tokio::join!(
        admission(&replay, Vec::new(), at),
        admission(&replay, Vec::new(), at + 1)
    );
    assert_eq!((a.status, b.status), (200, 200));
    let mut lengths = [
        json_of(&a)["proofs"].as_array().expect("a").len(),
        json_of(&b)["proofs"].as_array().expect("b").len(),
    ];
    lengths.sort_unstable();
    assert_eq!(lengths, [0, 1]);
    let kinds: Vec<String> = chain(&replay).await.into_iter().map(|c| c.2).collect();
    assert_eq!(kinds, ["service", "identity", "service"]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_admission_a_second_recovery_stages_again() {
    // Staging is per generation: a second provider loss whose document lists apps stages
    // admission again, though the first ended; one listing none doesn't.
    let Some(replay) = replay().await else { return };
    let at = recovered_staged(&replay).await;
    assert_eq!(admission(&replay, Vec::new(), at).await.status, 200);
    assert_eq!(admission_staged(&replay, at).await, json!(false));
    let p2 = answered_key(&enroll(&replay, enrollment(9, None), at).await);
    let g2 = held(&replay).await;
    let (answer, _) = deliver(
        &replay,
        next_generation(&g2, p2, Some(2)),
        Some(g2.hash()),
        at,
    )
    .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(
        admission_staged(&replay, at).await,
        json!(true),
        "staged again"
    );
    let (peers, inbox) = from_shop(&replay, at).await;
    assert_eq!(code(&peers), (503, "staged".into()));
    assert_eq!(code(&inbox), (503, "staged".into()));
    let ended = admission(&replay, Vec::new(), at).await;
    assert_eq!(
        json_of(&ended)["proofs"].as_array().expect("proofs").len(),
        1
    );
    // A third, listing no app: not staged.
    let p3 = answered_key(&enroll(&replay, enrollment(10, None), at).await);
    let g3 = held(&replay).await;
    let mut body: IdentityBody = g3.body().clone();
    body.version += 1;
    body.generation += 1;
    body.inbox.service_key = p3;
    body.recovery_from = Some(3);
    body.apps.clear();
    body.renewed.clear();
    let doc = IdentityDoc::sign(&alice_key(), body).expect("sign");
    let (answer, _) = deliver(&replay, doc.signed().clone(), Some(g3.hash()), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(admission_staged(&replay, at).await, json!(false));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_admission_staged_holds_back_a_directory_read() {
    // An app of another identity reading the directory while admission is staged gets
    // `503 staged`, as at the inbox and `PUT /peers`, so it retries rather than gives up
    // (Switch spec 12.6 step 2; wire 7.4.10); once ended, `403 not_admitted`.
    let Some(replay) = replay().await else { return };
    let at = recovered_staged(&replay).await;
    let read = || {
        other_request(
            "shop",
            ORIGIN,
            "GET",
            &format!("/v1/{}/directory", alice_id()),
            Vec::new(),
            None,
            at,
        )
    };
    let answer = replay.service.handle(read()).await;
    assert_eq!(code(&answer), (503, "staged".into()));
    assert_eq!(admission(&replay, Vec::new(), at).await.status, 200);
    let answer = replay.service.handle(read()).await;
    assert_eq!(code(&answer), (403, "not_admitted".into()));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_admission_ends_with_a_proof_under_the_current_key() {
    // The admission transition's proof (wire 6.5): a service stub, object "admission", the
    // body `by: "signer"`; signed with the recovered generation's key, as is the answer.
    let Some(replay) = replay().await else { return };
    let at = recovered_staged(&replay).await;
    let key = replay
        .keys
        .public_key(&service_key_id(&replay).await)
        .await
        .expect("key");
    let request = signer_request(
        "POST",
        &format!("/v1/{}/recovery/admission", alice_id()),
        Vec::new(),
        at,
    );
    let signature = signature_of(&request);
    let answer = replay.service.handle(request).await;
    assert_eq!(answer.status, 200);
    assert!(signed_by(&answer, &key, &signature));
    let proof: SignedDoc =
        serde_json::from_value(json_of(&answer)["proofs"][0].clone()).expect("proof");
    let body: Value = serde_json::from_slice(&proof.body_bytes().expect("body")).expect("json");
    assert_eq!(body["object"], json!("admission"));
    replay.db.drop_database().await.expect("drop");
}

// POST /recovery/upload after a provider loss (Switch wire 7.4.14).

/// The vectors' transition proof named `name`, of the lost generation 1.
fn lost_proof(name: &str) -> Value {
    named(&vectors("chain.json")["transition_proofs"], name)["signed"].clone()
}

/// The wallet's operation at `seq` of the vectors' chain, uploaded with its certificate and,
/// when `proof` names one, the lost service's proof of it.
fn uploaded_op(seq: u64, proof: Option<&str>) -> Value {
    let mut op = json!({
        "op": chain_item(&vectors("chain.json"), seq)["item"].clone(),
        "cert": wallet().2.signed(),
    });
    if let Some(name) = proof {
        op["proof"] = lost_proof(name);
    }
    op
}

const CREATED: &str = "record.put create (seq 6): the record's first version is (1, 6)";
const UPDATED: &str = "record.put update (seq 8): the new version is (1, 8)";
const ATTEMPTED: &str = "claim attempt (seq 7)";

/// alice recovered in place from the loss of generation 1, admission staged, with the
/// wallet current again at generation 2: the lost generation's `identity.json` and the time.
async fn recovered_with_the_wallet(replay: &Replay) -> (IdentityDoc, u64) {
    let (pending, at) = serving_with_a_pending_key(replay).await;
    let before = held(replay).await;
    let recovery = next_generation(&before, pending, Some(1));
    let (answer, _) = deliver(replay, recovery, Some(before.hash()), at).await;
    assert_eq!(answer.status, 200);
    let (status, body) = wallet_registers(replay, 77, 2, 3, true, at).await;
    assert_eq!(status, 200, "{body}");
    (before, at)
}

async fn upload(replay: &Replay, body: &Value, at_ms: u64) -> SwitchResponse {
    upload_as(replay, &wallet_keys(), body, at_ms).await
}

async fn upload_as(replay: &Replay, keys: &Value, body: &Value, at_ms: u64) -> SwitchResponse {
    let path = format!("/v1/{}/recovery/upload", alice_id());
    let body = serde_json::to_vec(body).expect("json");
    replay
        .service
        .handle(app_request(keys, "POST", &path, body, at_ms))
        .await
}

async fn wallet_get(replay: &Replay, path: &str, at_ms: u64) -> Value {
    let path = format!("/v1/{}/{path}", alice_id());
    let answer = replay
        .service
        .handle(app_request(&wallet_keys(), "GET", &path, Vec::new(), at_ms))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{path}: {}",
        String::from_utf8_lossy(&answer.body)
    );
    json_of(&answer)
}

/// The record key and the claim key the vectors' chain writes.
fn record_and_claim_keys() -> (String, String) {
    let state = |name: &str| -> Value {
        let body = lost_proof(name)["body"].as_str().expect("body").to_owned();
        let bytes = pubky_switch_core::enc::unb64(&body).expect("b64");
        serde_json::from_slice(&bytes).expect("json")
    };
    (
        state(CREATED)["object"].as_str().expect("key").to_owned(),
        state(ATTEMPTED)["object"].as_str().expect("key").to_owned(),
    )
}

#[tokio::test]
async fn test_upload_fills_in_what_the_lost_generation_held() {
    // The wallet uploads its record's two writes and its attempt, each with the lost
    // service's proof, and the lost service's head: the record is taken at the proved (1, 8),
    // at the upload transition's seq and with no proof; the claim is rebuilt with the
    // attempt; one `upload` transition lists both (Switch wire 7.4.14).
    let Some(replay) = replay().await else { return };
    let (lost, at) = recovered_with_the_wallet(&replay).await;
    let head = vectors("chain.json")["signed_heads"][0]["head"].clone();
    let body = json!({
        "lost_identity": lost.signed(),
        "records": [uploaded_op(6, Some(CREATED)), uploaded_op(8, Some(UPDATED))],
        "claims": [uploaded_op(7, Some(ATTEMPTED))],
        "heads": [head],
    });
    let length = chain(&replay).await.len();
    let answer = upload(&replay, &body, at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let (record, claim) = record_and_claim_keys();
    let answered = json_of(&answer);
    assert_eq!(
        answered["result"],
        json!({ "records": [record], "divergent": [], "claims": [claim],
                "divergent_claims": [], "unverified": 0, "distrusted": 0, "refused": 0,
                "heads": 1, "lists": false })
    );
    assert!(answered["proof"].is_object() && answered["head"].is_object());
    assert!(header_text(&answer, "switch-head").is_some());
    let items = chain(&replay).await;
    assert_eq!(items.len(), length + 1, "one transition");
    let (_, upload_seq, kind) = items.last().expect("item").clone();
    assert_eq!(kind, "service");
    let view = wallet_get(&replay, &format!("records/{record}"), at).await;
    assert_eq!(
        (view["generation"].clone(), view["version"].clone()),
        (json!(1), json!(8))
    );
    assert_eq!(view["seq"], json!(upload_seq));
    assert!(view.get("proof").is_none(), "{view}");
    assert_eq!(view["divergent"], json!(false));
    let claimed = wallet_get(&replay, &format!("claims/{claim}"), at).await;
    assert_eq!(
        claimed["claim"]["attempts"].as_array().map(Vec::len),
        Some(1),
        "{claimed}"
    );
    // The same upload again merges nothing new, and still chains a transition of its own.
    let again = upload(&replay, &body, at).await;
    assert_eq!(again.status, 200);
    assert_eq!(json_of(&again)["result"]["records"], json!([]));
    assert_eq!(json_of(&again)["result"]["claims"], json!([]));
    assert_eq!(chain(&replay).await.len(), length + 2);
    // A fork of the update, built on the same (1, 6) in another batch, is kept divergent:
    // the record stays at (1, 8), its view `divergent`.
    let update: SignedDoc =
        serde_json::from_value(chain_item(&vectors("chain.json"), 8)["item"].clone()).expect("op");
    let update = pubky_switch_core::ops::SignedOp::peek(&update).expect("op");
    let fork = wallet_batch(90, 1, vec![(Vec::new(), update.body().kind.clone())]);
    let forked = json!({
        "lost_identity": lost.signed(),
        "records": [{ "op": fork[0].signed(), "cert": wallet().2.signed() }],
    });
    let answer = upload(&replay, &forked, at).await;
    assert_eq!(json_of(&answer)["result"]["divergent"], json!([record]));
    let view = wallet_get(&replay, &format!("records/{record}"), at).await;
    assert_eq!(
        (view["version"].clone(), view["divergent"].clone()),
        (json!(8), json!(true))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_upload_without_the_lost_identity_checks_no_proof() {
    // Without `lost_identity` the proofs and heads count for nothing: the update is taken at
    // its lower bound, (1, 7) above the (1, 6) it built on, and the head is unverified.
    let Some(replay) = replay().await else { return };
    let (lost, at) = recovered_with_the_wallet(&replay).await;
    let head = vectors("chain.json")["signed_heads"][0]["head"].clone();
    let body = json!({ "records": [uploaded_op(8, Some(UPDATED))], "heads": [head] });
    let answer = upload(&replay, &body, at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let result = &json_of(&answer)["result"];
    assert_eq!(
        (result["unverified"].clone(), result["heads"].clone()),
        (json!(1), json!(0))
    );
    let (record, _) = record_and_claim_keys();
    let view = wallet_get(&replay, &format!("records/{record}"), at).await;
    assert_eq!(
        (view["generation"].clone(), view["version"].clone()),
        (json!(1), json!(7))
    );
    // The proved write, uploaded later, makes the same operation's version exact.
    let body = json!({
        "lost_identity": lost.signed(),
        "records": [uploaded_op(8, Some(UPDATED))],
    });
    let answer = upload(&replay, &body, at).await;
    assert_eq!(json_of(&answer)["result"]["records"], json!([record]));
    let view = wallet_get(&replay, &format!("records/{record}"), at).await;
    assert_eq!(view["version"], json!(8));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_upload_contacts_end_staged_admission_and_lists_only_add() {
    // A deny-only upload leaves admission staged; one carrying contacts from an app holding
    // `lists.manage` ends it in the same transaction, with no `admission` transition: the
    // upload's own records it (Switch spec 12.6 step 2).
    let Some(replay) = replay().await else { return };
    let (_, at) = recovered_with_the_wallet(&replay).await;
    let bob = pubky_switch_core::enc::pubky_id(&[40; 32]);
    let denied = upload(&replay, &json!({ "lists": { "deny": [bob] } }), at).await;
    assert_eq!(denied.status, 200);
    assert_eq!(json_of(&denied)["result"]["lists"], json!(true));
    assert_eq!(admission_staged(&replay, at).await, json!(true));
    let length = chain(&replay).await.len();
    let contacts = json!({ "lists": { "contacts": [bob, bob], "deny": [bob] } });
    let ended = upload(&replay, &contacts, at).await;
    assert_eq!(ended.status, 200);
    assert_eq!(
        json_of(&ended)["result"]["lists"],
        json!(true),
        "the contact is new"
    );
    assert_eq!(admission_staged(&replay, at).await, json!(false));
    assert_eq!(
        chain(&replay).await.len(),
        length + 1,
        "the upload's transition only"
    );
    let again = upload(&replay, &contacts, at).await;
    assert_eq!(
        json_of(&again)["result"]["lists"],
        json!(false),
        "nothing added"
    );
    let allow = wallet_get(&replay, "allow", at).await;
    assert_eq!(
        allow["contacts"].as_array().map(Vec::len),
        Some(1),
        "{allow}"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_upload_contact_also_denied_is_denied() {
    // An upload may carry one pubky in both lists, as a live `deny.put` leaves a contact in
    // place: the deny list overrides the contact at admission (Switch spec 7), so bob's shop
    // is refused once the upload ends staged admission.
    let Some(replay) = replay().await else { return };
    let (_, at) = recovered_with_the_wallet(&replay).await;
    let bob = named(&vectors("keys.json")["identities"], "bob")["pubky_id"].clone();
    let lists = json!({ "lists": { "contacts": [bob], "deny": [bob] } });
    assert_eq!(upload(&replay, &lists, at).await.status, 200);
    assert_eq!(admission_staged(&replay, at).await, json!(false));
    let (peers, inbox) = from_shop(&replay, at).await;
    assert_eq!(code(&peers), (403, "not_admitted".into()));
    assert_eq!(code(&inbox), (403, "not_admitted".into()));
    replay.db.drop_database().await.expect("drop");
}

/// The executor, listed in alice's document, current again at generation 2 with its
/// record: its keys.
async fn executor_registers(replay: &Replay, at: u64) -> Value {
    let keys = vectors("keys.json");
    let executor = app(&keys, "executor").clone();
    let record: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "executor app record",
        )["signed"]
            .clone(),
    )
    .expect("record");
    let secret = ed25519_dalek::SigningKey::from_bytes(&hex32(&executor["signing_secret_hex"]));
    let app_id: [u8; 16] = hex::decode(executor["app_id_bytes_hex"].as_str().expect("hex"))
        .expect("hex")
        .try_into()
        .expect("16 bytes");
    let batch = pubky_switch_core::ops::sign_batch(
        &secret,
        &alice_key().public(),
        Some(app_id),
        2,
        [78; 16],
        vec![(
            Vec::new(),
            pubky_switch_core::ops::OpKind::AppPut { record },
        )],
    )
    .expect("batch");
    let body = pubky_switch_core::ops::OpsRequest::new(&batch, None).to_json();
    let path = format!("/v1/{}/ops", alice_id());
    let put = replay
        .service
        .handle(app_request(&executor, "POST", &path, body, at))
        .await;
    assert_eq!(put.status, 200, "{}", String::from_utf8_lossy(&put.body));
    executor
}

#[tokio::test]
async fn test_upload_lists_need_the_callers_permission() {
    // The executor, current again, holds no list permission: contacts or deny entries from
    // it are `403 permission_missing` for the whole upload, which merges and chains nothing,
    // and admission stays staged (Switch wire 7.4.14).
    let Some(replay) = replay().await else { return };
    let (_, at) = recovered_with_the_wallet(&replay).await;
    let executor = executor_registers(&replay, at).await;
    let length = chain(&replay).await.len();
    let bob = pubky_switch_core::enc::pubky_id(&[40; 32]);
    let before = replay.service.upload_judgments();
    for lists in [json!({ "contacts": [] }), json!({ "deny": [bob] })] {
        let refused = upload_as(&replay, &executor, &json!({ "lists": lists }), at).await;
        assert_eq!(
            code(&refused),
            (403, "permission_missing".into()),
            "{lists}"
        );
    }
    // Refused for its lists, an upload's items are judged nowhere.
    assert_eq!(replay.service.upload_judgments(), before);
    assert_eq!(chain(&replay).await.len(), length);
    assert_eq!(admission_staged(&replay, at).await, json!(true));
    // Without lists it uploads as any own app.
    assert_eq!(
        upload_as(&replay, &executor, &json!({}), at).await.status,
        200
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_upload_refusals() {
    // `404` at an account in neither stage; after the loss, `400` for a body that doesn't
    // read and `429` past `uploads_per_app_per_hour`, with what to wait. A refusal merges
    // and chains nothing.
    let limits = pubky_switch::limits::Limits {
        uploads_per_app_per_hour: 5,
        max_contacts: 1,
        ..pubky_switch::limits::Limits::default()
    };
    let Some(replay) = replay_with(limits.clone()).await else {
        return;
    };
    let (_, at) = serving_with_a_pending_key(&replay).await;
    let (status, body) = wallet_registers(&replay, 76, 1, 1, false, at).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        code(&upload(&replay, &json!({}), at).await),
        (404, "not_found".into())
    );
    let replay = {
        replay.db.drop_database().await.expect("drop");
        let Some(replay) = replay_with(limits).await else {
            return;
        };
        replay
    };
    let (_, at) = recovered_with_the_wallet(&replay).await;
    let length = chain(&replay).await.len();
    let bad = upload(&replay, &json!({ "records": {} }), at).await;
    assert_eq!(code(&bad), (400, "bad_request".into()));
    assert_eq!(upload(&replay, &json!({}), at).await.status, 200);
    assert_eq!(upload(&replay, &json!({}), at).await.status, 200);
    // Entries past `max_contacts` are dropped, not refused.
    let two = [[40; 32], [41; 32]].map(|k| pubky_switch_core::enc::pubky_id(&k));
    let capped = upload(&replay, &json!({ "lists": { "contacts": two } }), at).await;
    assert_eq!(capped.status, 200);
    let allow = wallet_get(&replay, "allow", at).await;
    assert_eq!(
        allow["contacts"].as_array().map(Vec::len),
        Some(1),
        "{allow}"
    );
    // The limit counts the entries held already: a new contact is dropped too.
    let third = pubky_switch_core::enc::pubky_id(&[42; 32]);
    let full = upload(&replay, &json!({ "lists": { "contacts": [third] } }), at).await;
    assert_eq!(json_of(&full)["result"]["lists"], json!(false));
    let allow = wallet_get(&replay, "allow", at).await;
    assert_eq!(
        allow["contacts"].as_array().map(Vec::len),
        Some(1),
        "{allow}"
    );
    let limited = upload(&replay, &json!({}), at).await;
    assert_eq!(code(&limited), (429, "rate_limited".into()));
    assert!(header_text(&limited, "retry-after").is_some());
    assert_eq!(chain(&replay).await.len(), length + 4);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_upload_judged_before_the_lock_is_judged_again_when_its_state_changed() {
    // The upload's items are judged before the account's lock. A document listing the phone
    // as removed commits while the upload waits for the lock: the judgment made before is
    // dropped, and the phone's proofless operation is distrusted (Switch wire 7.4.14).
    let Some(replay) = replay().await else { return };
    let (_, at) = recovered_with_the_wallet(&replay).await;
    let mut txn = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    let held = held(&replay).await;
    let keys = vectors("keys.json");
    let phone = app(&keys, "phone").clone();
    let phone_id: [u8; 16] = hex::decode(phone["app_id_bytes_hex"].as_str().expect("hex"))
        .expect("hex")
        .try_into()
        .expect("16 bytes");
    let record: SignedDoc = serde_json::from_value(
        named(&vectors("documents.json")["documents"], "phone app record")["signed"].clone(),
    )
    .expect("record");
    let cert = pubky_switch_core::records::AppRecord::verify(&record, &alice_key().public())
        .expect("record")
        .cert()
        .clone();
    let update: SignedDoc =
        serde_json::from_value(chain_item(&vectors("chain.json"), 8)["item"].clone()).expect("op");
    let update = pubky_switch_core::ops::SignedOp::peek(&update).expect("op");
    let secret = ed25519_dalek::SigningKey::from_bytes(&hex32(&phone["signing_secret_hex"]));
    let ops = pubky_switch_core::ops::sign_batch(
        &secret,
        &alice_key().public(),
        Some(phone_id),
        1,
        [79; 16],
        vec![(Vec::new(), update.body().kind.clone())],
    )
    .expect("batch");
    let mut body: IdentityBody = held.body().clone();
    body.version += 1;
    body.apps.retain(|listed| listed.app_id != phone_id);
    body.removed.push(pubky_switch_core::records::RemovedApp {
        app_id: phone_id,
        distrust_from: 0,
    });
    let removing = IdentityDoc::sign(&alice_key(), body).expect("sign");
    let uploaded = json!({ "records": [{ "op": ops[0].signed(), "cert": cert.signed() }] });
    let before = replay.service.upload_judgments();
    let (answer, ()) = tokio::join!(upload(&replay, &uploaded, at), async {
        let options = replay.db.options();
        let mut watcher = sqlx::PgConnection::connect_with(options)
            .await
            .expect("conn");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' \
                 AND datname = current_database()",
            )
            .fetch_one(&mut watcher)
            .await
            .expect("count");
            if waiting > 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the upload never waited"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        txn.set_identity(&pubky_switch::store::HeldIdentity {
            doc: removing.signed().clone(),
            proof: None,
        })
        .await
        .expect("identity");
        txn.commit().await.expect("commit");
    });
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let result = &json_of(&answer)["result"];
    assert_eq!(
        (result["records"].clone(), result["distrusted"].clone()),
        (json!([]), json!(1))
    );
    // Judged before the lock, and again under it.
    assert_eq!(
        replay.service.upload_judgments(),
        (before.0 + 1, before.1 + 1)
    );
    replay.db.drop_database().await.expect("drop");
}

/// The operation at `seq` of the vectors' chain.
fn vector_op(seq: u64) -> SignedOp {
    let signed: SignedDoc =
        serde_json::from_value(chain_item(&vectors("chain.json"), seq)["item"].clone())
            .expect("op");
    SignedOp::peek(&signed).expect("op")
}

/// The members of the vectors' claim attempt (seq 7).
#[allow(clippy::panic)]
fn vector_claim_fields() -> ClaimFields {
    let OpKind::Claim(fields) = vector_op(7).body().kind.clone() else {
        panic!("a claim")
    };
    fields
}

/// The members of the vectors' record update (seq 8).
#[allow(clippy::panic)]
fn vector_record_put() -> RecordPut {
    let OpKind::RecordPut(put) = vector_op(8).body().kind.clone() else {
        panic!("a record.put")
    };
    put
}

async fn wallet_ops(replay: &Replay, batch: &[SignedOp], at: u64) -> SwitchResponse {
    let body = pubky_switch_core::ops::OpsRequest::new(batch, None).to_json();
    let path = format!("/v1/{}/ops", alice_id());
    replay
        .service
        .handle(app_request(&wallet_keys(), "POST", &path, body, at))
        .await
}

/// `op` uploaded with the wallet's certificate and no proof.
fn proofless(op: &SignedOp) -> Value {
    json!({ "op": op.signed(), "cert": wallet().2.signed() })
}

/// The wallet's live attempt `[9; 16]` at the vectors' claim key, orphaned only after
/// 1,000,000 s: the claim's key.
async fn live_attempt(replay: &Replay, at: u64) -> (ClaimFields, String) {
    let mut fields = vector_claim_fields();
    fields.attempt_id = vec![9; 16];
    fields.expected_step = 0;
    fields.deadline = None;
    fields.orphan_after = Some(1_000_000);
    let batch = wallet_batch(91, 2, vec![(Vec::new(), OpKind::Claim(fields.clone()))]);
    let written = wallet_ops(replay, &batch, at).await;
    assert_eq!(
        written.status,
        200,
        "{}",
        String::from_utf8_lossy(&written.body)
    );
    let key = pubky_switch_core::enc::b64(&fields.claim_key);
    (fields, key)
}

#[tokio::test]
async fn test_upload_claim_changed_last_by_an_upload_lists_a_gap_at_its_end() {
    // The wallet writes an attempt here for a claim the service held nothing for (step 0 to
    // 1); an upload then adds another attempt beside it (divergent, step 1 to 2). GET /claims
    // lists the one entry, at step 0, and the claim at step 2: the upload's step has no
    // entry (Switch wire 7.4.8).
    let Some(replay) = replay().await else { return };
    let (_, at) = recovered_with_the_wallet(&replay).await;
    let (fields, key) = live_attempt(&replay, at).await;
    let mut uploaded = fields;
    uploaded.attempt_id = vec![10; 16];
    let lost_op = wallet_batch(92, 1, vec![(Vec::new(), OpKind::Claim(uploaded))]);
    let answer = upload(&replay, &json!({ "claims": [proofless(&lost_op[0])] }), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(json_of(&answer)["result"]["divergent_claims"], json!([key]));
    let read = wallet_get(&replay, &format!("claims/{key}"), at).await;
    let entries = read["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 1, "{read}");
    let last = entries[0]["step"].as_u64().expect("step");
    assert_eq!(
        (last, read["claim"]["step"].as_u64()),
        (0, Some(2)),
        "{read}"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_upload_known_limit_an_inflated_bound_replaces_a_proved_record() {
    // A known limit (Switch spec 19): a proofless operation built on (1, 1,000,000), never
    // applied anywhere, replaces the record held at the proved (1, 8), which is kept
    // nowhere; the proved upload again then changes nothing.
    let Some(replay) = replay().await else { return };
    let (lost, at) = recovered_with_the_wallet(&replay).await;
    let honest = json!({
        "lost_identity": lost.signed(),
        "records": [uploaded_op(6, Some(CREATED)), uploaded_op(8, Some(UPDATED))],
    });
    assert_eq!(upload(&replay, &honest, at).await.status, 200);
    let (record, _) = record_and_claim_keys();
    let mut put = vector_record_put();
    put.expected_version = RecordVersion::new(1, 1_000_000);
    let forged = wallet_batch(93, 1, vec![(Vec::new(), OpKind::RecordPut(put))]);
    let answer = upload(&replay, &json!({ "records": [proofless(&forged[0])] }), at).await;
    let result = json_of(&answer)["result"].clone();
    assert_eq!(
        (result["records"].clone(), result["divergent"].clone()),
        (json!([record]), json!([]))
    );
    let view = wallet_get(&replay, &format!("records/{record}"), at).await;
    assert_eq!(
        (view["version"].clone(), view["divergent"].clone()),
        (json!(1_000_001), json!(false))
    );
    let again = json_of(&upload(&replay, &honest, at).await)["result"].clone();
    assert_eq!(
        (again["records"].clone(), again["divergent"].clone()),
        (json!([]), json!([]))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_upload_known_limit_another_policy_uploaded_first_holds_the_key() {
    // A known limit (Switch spec 19): at a key the service lacks, a proofless operation with
    // another policy the uploader's certificate satisfies (an extra write scope; not a create,
    // so no key derivation binds it) fills the record. The honest proved writes are then
    // divergent, and a live write with the record's real policy is refused.
    let Some(replay) = replay().await else { return };
    let (lost, at) = recovered_with_the_wallet(&replay).await;
    let (record, _) = record_and_claim_keys();
    let mut put = vector_record_put();
    let real_policy = put.policy.clone();
    let mut scopes = put.policy.write_scopes.clone();
    scopes.push("zzz".into());
    scopes.sort();
    put.policy.write_scopes = scopes;
    let forged = wallet_batch(94, 1, vec![(Vec::new(), OpKind::RecordPut(put))]);
    let answer = upload(&replay, &json!({ "records": [proofless(&forged[0])] }), at).await;
    assert_eq!(
        json_of(&answer)["result"]["records"],
        json!([record]),
        "{}",
        json_of(&answer)
    );
    let honest = json!({
        "lost_identity": lost.signed(),
        "records": [uploaded_op(6, Some(CREATED)), uploaded_op(8, Some(UPDATED))],
    });
    let answer = upload(&replay, &honest, at).await;
    assert_eq!(
        json_of(&answer)["result"]["divergent"],
        json!([record]),
        "{}",
        json_of(&answer)
    );
    let view = wallet_get(&replay, &format!("records/{record}"), at).await;
    let mut write = vector_record_put();
    write.policy = real_policy;
    write.expected_version = RecordVersion::new(
        view["generation"].as_u64().expect("generation"),
        view["version"].as_u64().expect("version"),
    );
    let batch = |id: u8, write: &RecordPut| {
        wallet_batch(id, 2, vec![(Vec::new(), OpKind::RecordPut(write.clone()))])
    };
    let mut answer = wallet_ops(&replay, &batch(95, &write), at).await;
    if code(&answer).1 == "stale_epoch" {
        let epoch = json_of(&answer)["current"]["data_epoch"]
            .as_u64()
            .expect("epoch");
        write.value_sealed.data_epoch = epoch;
        answer = wallet_ops(&replay, &batch(96, &write), at).await;
    }
    assert_eq!(
        code(&answer),
        (400, "bad_request".into()),
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_upload_known_limit_a_proofless_unknown_applies_to_a_live_attempt() {
    // A known limit (Switch spec 19): the wallet's live attempt, orphaned only in
    // 1,000,000 s, refuses a live `unknown`; the same `unknown`, uploaded as an operation of
    // the lost generation without a proof, applies: the attempt is `unknown`, the claim FREE.
    let Some(replay) = replay().await else { return };
    let (_, at) = recovered_with_the_wallet(&replay).await;
    let (fields, key) = live_attempt(&replay, at).await;
    let mut unknown = fields;
    unknown.kind = ClaimType::Unknown;
    unknown.expected_step = 1;
    unknown.orphan_after = None;
    let live_batch = wallet_batch(92, 2, vec![(Vec::new(), OpKind::Claim(unknown.clone()))]);
    let live = wallet_ops(&replay, &live_batch, at).await;
    assert_eq!(
        code(&live),
        (409, "conflict".into()),
        "{}",
        String::from_utf8_lossy(&live.body)
    );
    let lost_op = wallet_batch(93, 1, vec![(Vec::new(), OpKind::Claim(unknown))]);
    let answer = upload(&replay, &json!({ "claims": [proofless(&lost_op[0])] }), at).await;
    assert_eq!(
        json_of(&answer)["result"]["claims"],
        json!([key]),
        "{}",
        json_of(&answer)
    );
    let read = wallet_get(&replay, &format!("claims/{key}"), at).await;
    assert_eq!(read["claim"]["state"], json!("FREE"), "{read}");
    assert_eq!(
        read["claim"]["attempts"][0]["outcome"],
        json!("unknown"),
        "{read}"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_upload_bound_past_the_integer_range_is_unverified() {
    // A proofless operation built on (1, 2^53 - 1): its bound would be past what a record
    // view carries (Switch wire 1.1), so it is unverified and the service holds no record.
    let Some(replay) = replay().await else { return };
    let (_, at) = recovered_with_the_wallet(&replay).await;
    let mut put = vector_record_put();
    put.expected_version = RecordVersion::new(1, (1u64 << 53) - 1);
    let key = pubky_switch_core::enc::b64(&put.key);
    let forged = wallet_batch(97, 1, vec![(Vec::new(), OpKind::RecordPut(put))]);
    let answer = upload(&replay, &json!({ "records": [proofless(&forged[0])] }), at).await;
    assert_eq!(answer.status, 200);
    let result = &json_of(&answer)["result"];
    assert_eq!(
        (result["records"].clone(), result["unverified"].clone()),
        (json!([]), json!(1))
    );
    let path = format!("/v1/{}/records/{key}", alice_id());
    let read = replay
        .service
        .handle(app_request(&wallet_keys(), "GET", &path, Vec::new(), at))
        .await;
    assert_eq!(code(&read), (404, "not_found".into()));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_upload_refusals_order_and_the_rate_slot() {
    // `404` before `400` at an account in neither stage; after the loss, a body that doesn't
    // read is `400` whatever the rate, but it takes the one slot of
    // `uploads_per_app_per_hour`, a refused upload counting (Switch wire 7.4.14), so the
    // upload that reads after it is `429`. An app not current here is `403 not_current`, an
    // app of another identity `403 permission_missing`.
    let limits = pubky_switch::limits::Limits {
        uploads_per_app_per_hour: 1,
        ..pubky_switch::limits::Limits::default()
    };
    let Some(replay) = replay_with(limits.clone()).await else {
        return;
    };
    let (_, at) = serving_with_a_pending_key(&replay).await;
    let (status, body) = wallet_registers(&replay, 76, 1, 1, false, at).await;
    assert_eq!(status, 200, "{body}");
    let path = format!("/v1/{}/recovery/upload", alice_id());
    let raw = |bytes: &[u8], at| app_request(&wallet_keys(), "POST", &path, bytes.to_vec(), at);
    assert_eq!(
        code(&replay.service.handle(raw(b"not json", at)).await),
        (404, "not_found".into())
    );
    replay.db.drop_database().await.expect("drop");
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    let (_, at) = recovered_with_the_wallet(&replay).await;
    for _ in 0..2 {
        let refused = replay.service.handle(raw(b"not json", at)).await;
        assert_eq!(code(&refused), (400, "bad_request".into()));
    }
    let keys = vectors("keys.json");
    let executor = app(&keys, "executor").clone();
    let not_current = upload_as(&replay, &executor, &json!({}), at).await;
    assert_eq!(code(&not_current), (403, "not_current".into()));
    // An app of another identity: a call only own apps make (Switch wire 7.6).
    let other = other_request("shop", ORIGIN, "POST", &path, b"{}".to_vec(), None, at);
    let refused = replay.service.handle(other).await;
    assert_eq!(code(&refused), (403, "permission_missing".into()));
    assert_eq!(
        code(&upload(&replay, &json!({}), at).await),
        (429, "rate_limited".into())
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_upload_large_body_is_judged_before_the_lock() {
    // An upload of about 15 MiB of heads, all verified with the lost key: its items are
    // judged once, before the account's lock, never under it, so the lock is held only for
    // the merge (Switch wire 7.4.14).
    let Some(replay) = replay().await else { return };
    let (lost, at) = recovered_with_the_wallet(&replay).await;
    let head = vectors("chain.json")["signed_heads"][0]["head"].clone();
    let one_head = serde_json::to_vec(&head).expect("json").len();
    let count = 15 * 1024 * 1024 / (one_head + 1);
    let before = replay.service.upload_judgments();
    let answer = upload(&replay, &many_heads(&lost, count), at).await;
    assert_eq!(answer.status, 200);
    assert_eq!(json_of(&answer)["result"]["heads"], json!(count));
    assert_eq!(replay.service.upload_judgments(), (before.0 + 1, before.1));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_upload_rate_is_per_app_and_forgotten_on_erasure() {
    // `uploads_per_app_per_hour` counts each app of each account apart, and an erasure
    // forgets the account's counts (Switch wire 9.4, 7.4.16).
    let limits = pubky_switch::limits::Limits {
        uploads_per_app_per_hour: 1,
        ..pubky_switch::limits::Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    let (_, at) = recovered_with_the_wallet(&replay).await;
    assert_eq!(upload(&replay, &json!({}), at).await.status, 200);
    assert_eq!(
        code(&upload(&replay, &json!({}), at).await),
        (429, "rate_limited".into())
    );
    let executor = executor_registers(&replay, at).await;
    assert_eq!(
        upload_as(&replay, &executor, &json!({}), at).await.status,
        200
    );
    let key = replay
        .keys
        .public_key(&service_key_id(&replay).await)
        .await
        .expect("key");
    let path = format!("/v1/{}/erase", alice_id());
    let erase = signer_request(
        "POST",
        &path,
        pubky_switch_core::http::erase_body(&key, None),
        at,
    );
    assert_eq!(replay.service.handle(erase).await.status, 200);
    assert_eq!(
        replay.service.counted_at(&alice_id()),
        0,
        "every count of the account"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_claim_that_isnt_rebuilt_and_lost_an_entry_is_unavailable() {
    // Only a claim rebuilt from uploads may hold fewer entries than its step: one that isn't
    // and lost an entry is a temporary failure, never a view with the entries missing.
    let Some(replay) = replay().await else { return };
    let (_, at) = recovered_with_the_wallet(&replay).await;
    let (_, key) = live_attempt(&replay, at).await;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("DELETE FROM claim_entries WHERE account_id = $1")
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("delete");
    let path = format!("/v1/{}/claims/{key}", alice_id());
    let read = replay
        .service
        .handle(app_request(&wallet_keys(), "GET", &path, Vec::new(), at))
        .await;
    assert_eq!(code(&read), (503, "unavailable".into()));
    replay.db.drop_database().await.expect("drop");
}

/// An upload from the wallet with `count` heads that verify with the lost key.
fn many_heads(lost: &IdentityDoc, count: usize) -> Value {
    let head = vectors("chain.json")["signed_heads"][0]["head"].clone();
    let heads: Vec<Value> = (0..count).map(|_| head.clone()).collect();
    json!({ "lost_identity": lost.signed(), "heads": heads })
}

#[tokio::test]
async fn test_upload_past_the_limit_is_refused_without_its_judgment() {
    // The slot of `uploads_per_app_per_hour` is taken before an upload's items are judged:
    // past the limit, a body of 20,000 heads that verify is `429`, its items judged neither
    // before the account's lock nor under it (Switch wire 7.4.14).
    let limits = pubky_switch::limits::Limits {
        uploads_per_app_per_hour: 1,
        ..pubky_switch::limits::Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    let (lost, at) = recovered_with_the_wallet(&replay).await;
    assert_eq!(upload(&replay, &json!({}), at).await.status, 200);
    let before = replay.service.upload_judgments();
    let limited = upload(&replay, &many_heads(&lost, 20_000), at).await;
    assert_eq!(code(&limited), (429, "rate_limited".into()));
    assert_eq!(
        replay.service.upload_judgments(),
        before,
        "no judgment for a refused upload"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_upload_while_another_of_the_app_is_judged_is_429() {
    // One upload of each app of an account is judged at a time: a second sent while the
    // first is judged is `429` with a second to wait, judged nowhere, and once the first is
    // answered the app uploads again.
    let Some(replay) = replay().await else { return };
    let (lost, at) = recovered_with_the_wallet(&replay).await;
    let replay = std::sync::Arc::new(replay);
    let before = replay.service.upload_judgments();
    let body = many_heads(&lost, 20_000);
    let first = {
        let replay = std::sync::Arc::clone(&replay);
        tokio::spawn(async move { upload(&replay, &body, at).await })
    };
    // Until the first is being judged.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while replay.service.upload_judgments().0 == before.0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the first upload was never judged"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    // Judging 20,000 heads takes at least half a second even in a release build, so the
    // second, sent as soon as the first is being judged, arrives while it still is.
    let second = upload(&replay, &json!({}), at).await;
    let first = first.await.expect("first");
    assert_eq!(first.status, 200);
    assert_eq!(code(&second), (429, "rate_limited".into()));
    assert_eq!(json_of(&second)["retry_after"], json!(1));
    assert_eq!(replay.service.upload_judgments(), (before.0 + 1, before.1));
    assert_eq!(upload(&replay, &json!({}), at).await.status, 200);
    let replay = std::sync::Arc::try_unwrap(replay).ok().expect("one owner");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_upload_from_a_revoked_app_is_refused_without_its_judgment() {
    // An app whose record remains but that isn't current any more is `403 not_current`, and
    // its upload's items are judged neither before the lock nor under it.
    let Some(replay) = replay().await else { return };
    let (lost, at) = recovered_with_the_wallet(&replay).await;
    let wallet = app(&vectors("keys.json"), "wallet")["app_id"]
        .as_str()
        .expect("id")
        .to_owned();
    let path = format!("/v1/{}/apps/{wallet}/revoke", alice_id());
    let revoked = replay
        .service
        .handle(signer_request("POST", &path, Vec::new(), at))
        .await;
    assert_eq!(
        revoked.status,
        200,
        "{}",
        String::from_utf8_lossy(&revoked.body)
    );
    let before = replay.service.upload_judgments();
    let refused = upload(&replay, &many_heads(&lost, 20_000), at).await;
    assert_eq!(code(&refused), (403, "not_current".into()));
    assert_eq!(
        replay.service.upload_judgments(),
        before,
        "no judgment for a refused upload"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_admission_staged_holds_back_connect_requests_whatever_the_policy() {
    // The recovery document takes no connect requests: while admission is staged a
    // stranger's `POST /connect` is still `503 staged` (decision: "whatever the policy"),
    // and `403 not_admitted` once it ends.
    let Some(replay) = replay().await else { return };
    let (pending, at) = serving_with_a_pending_key(&replay).await;
    let before = held(&replay).await;
    let mut body: IdentityBody = before.body().clone();
    body.version += 1;
    body.generation += 1;
    body.inbox.service_key = pending;
    body.recovery_from = Some(1);
    body.policy.connect_requests.enabled = false;
    let recovery = IdentityDoc::sign(&alice_key(), body)
        .expect("sign")
        .signed()
        .clone();
    let (answer, _) = deliver(&replay, recovery, Some(before.hash()), at).await;
    assert_eq!(answer.status, 200);
    let ask = || {
        other_request(
            "shop",
            ORIGIN,
            "POST",
            &format!("/v1/{}/connect", alice_id()),
            Vec::new(),
            None,
            at,
        )
    };
    assert_eq!(
        code(&replay.service.handle(ask()).await),
        (503, "staged".into())
    );
    assert_eq!(admission(&replay, Vec::new(), at).await.status, 200);
    assert_eq!(
        code(&replay.service.handle(ask()).await),
        (403, "not_admitted".into())
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_in_place_after_a_purge() {
    // The wallet revoked and purged (Switch wire 9.1): a provider loss in place keeps its
    // App ID as before, so the recovery's document can't list it again, and `GET /apps`
    // still shows it revoked.
    let Some(replay) = replay().await else { return };
    let (_, revoked_at) = purge_wallet(&replay).await;
    let at = revoked_at + 60_000;
    set_time(&replay.clock, &rfc3339(at));
    let answer = enroll(&replay, enrollment(3, None), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let pending = answered_key(&answer);
    let before = held(&replay).await;
    let wallet = app_id_of("wallet");
    let mut listing: IdentityBody = before.body().clone();
    listing.version += 1;
    listing.generation += 1;
    listing.inbox.service_key = pending;
    listing.recovery_from = Some(1);
    listing.apps.push(pubky_switch_core::records::ListedApp {
        app_id: wallet,
        cert: [1; 32],
    });
    let listing = IdentityDoc::sign(&alice_key(), listing).expect("sign");
    let (answer, _) = deliver(&replay, listing.signed().clone(), Some(before.hash()), at).await;
    assert_eq!(code(&answer), (400, "bad_request".into()));
    let recovery = next_generation(&before, pending, Some(1));
    let (answer, _) = deliver(&replay, recovery, Some(before.hash()), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(
        rows_naming(&replay, "kept_app_ids", "app_id", &wallet).await,
        1
    );
    let request = signer_request("GET", &format!("/v1/{}/apps", alice_id()), Vec::new(), at);
    let apps = json_of(&replay.service.handle(request).await);
    let status = apps["apps"]
        .as_array()
        .expect("apps")
        .iter()
        .find(|s| s["app_id"] == pubky_switch_core::enc::zbase32_encode(&wallet).as_str())
        .expect("the wallet's kept App ID")
        .clone();
    assert_eq!(
        (status["current"].clone(), status["revoked_at"].clone()),
        (json!(false), json!(rfc3339(revoked_at)))
    );
    replay.db.drop_database().await.expect("drop");
}
