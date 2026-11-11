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
    http::{IdentityDelivery, header},
    keys::IdentityKey,
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
    // would pass for a stranger, so a stranger gets `503 staged` too; once it ends, its
    // delivery is taken (Switch spec 12.6 step 2).
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
    let (peers, _) = from_shop(&replay, at).await;
    assert_eq!(code(&peers), (503, "staged".into()));
    assert_eq!(admission(&replay, Vec::new(), at).await.status, 200);
    let (peers, _) = from_shop(&replay, at).await;
    assert_eq!(
        peers.status,
        200,
        "{}",
        String::from_utf8_lossy(&peers.body)
    );
    replay.db.drop_database().await.expect("drop");
}
