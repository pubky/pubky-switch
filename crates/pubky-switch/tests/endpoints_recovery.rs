//! A provider loss at the service, against PostgreSQL (Switch spec 12.6; Switch wire 3.3,
//! 3.7, 7.3, 7.4.2, 7.4.12): the first document of a recovery at a new account, a recovery in
//! place under the service key, what the account keeps and drops, the App IDs its
//! enrollments hold for the next generation, the account's mark at a generation start, and
//! the start a failing account takes.
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used)]

mod support;

use pubky_switch::http::{Handler, SwitchResponse};
use pubky_switch::marks::{AccountMark, MarkRead};
use pubky_switch::time::Clock;
use pubky_switch_core::{
    chain::{ChainTip, SignedHead},
    claims::{ClaimFields, ClaimType},
    http::{IdentityDelivery, header},
    keys::IdentityKey,
    ops::{OpKind, OpsRequest, Position, RecordPut, RecordVersion, SignedOp},
    records::{Enrollment, EnrollmentBody, IdentityBody, IdentityDoc},
    sig::SignedDoc,
    time::rfc3339,
};
use serde_json::{Value, json};
use sqlx::Connection;
use support::*;

/// An App ID an enrollment at the serving account names in its `revoked_apps`.
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
fn signed_by(response: &SwitchResponse, key: &[u8; 32], sent: &Sent) -> bool {
    signed_with(response, key, sent)
}

/// `request` as sent, which an answer to it binds (Switch wire 7.1); it carries a signature.
fn signed_sent(request: &pubky_switch::http::SwitchRequest) -> Sent {
    let sent = Sent::of(request);
    assert!(sent.signed(), "signature");
    sent
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
    let wrapper: Value = serde_json::from_slice(&body).expect("enrollment wrapper");
    let signed: SignedDoc =
        serde_json::from_value(wrapper["enrollment"].clone()).expect("enrollment");
    let mut fields = Enrollment::verify(&signed, &alice_key().public(), ORIGIN)
        .expect("enrollment template")
        .body()
        .clone();
    fields.intent = new_alice_enrollment_intent(replay, at_ms).await;
    let body = Enrollment::sign(&alice_key(), fields)
        .expect("enrollment")
        .to_request_json()
        .expect("request");
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

/// A current signed document restored beside an earlier chain, whose mark is lost
/// (Switch wire 7.3, Tables 1 and 2).
async fn recovery_with_newer_document(candidate_generation: u64) {
    let Some(replay) = replay().await else { return };
    let (key, at) = serving_with_a_held_app(&replay).await;
    let original = held(&replay).await;
    let mut newer = original.body().clone();
    newer.version += 1;
    newer.generation = 3;
    newer.recovery_from = Some(2);
    let newer = IdentityDoc::sign(&alice_key(), newer).expect("signed document");
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("UPDATE accounts SET identity_doc = $2 WHERE id = $1")
        .bind(alice_id())
        .bind(serde_json::to_vec(newer.signed()).expect("document"))
        .execute(&mut conn)
        .await
        .expect("restore newer document beside earlier chain");
    conn.close().await.expect("close");
    replay.marks.delete(&alice_id()).await.expect("mark lost");
    let before_chain = chain(&replay).await;
    let mut candidate = newer.body().clone();
    candidate.version += 1;
    candidate.generation = candidate_generation;
    candidate.recovery_from = Some(candidate_generation - 1);
    let candidate = IdentityDoc::sign(&alice_key(), candidate).expect("signed candidate");
    replay.clock.set_wall_ms(at + 1_000);
    let (answer, signature) = deliver(&replay, candidate.signed().clone(), None, at + 1_000).await;
    assert!(signed_by(&answer, &key, &signature));
    if candidate_generation <= newer.generation() {
        assert!(
            is_notice(&answer, 1, "mark_lost"),
            "{}",
            String::from_utf8_lossy(&answer.body)
        );
        assert_eq!(held(&replay).await.hash(), newer.hash());
        assert_eq!(chain(&replay).await, before_chain);
        assert_eq!(
            replay.marks.read(&alice_id()).await.expect("mark"),
            MarkRead::Missing
        );
    } else {
        assert_eq!(
            answer.status,
            200,
            "{}",
            String::from_utf8_lossy(&answer.body)
        );
        assert_eq!(held(&replay).await.hash(), candidate.hash());
        let mark = mark_of(&replay).await;
        assert_eq!((mark.generation, mark.seq), (4, 2));
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_start_below_held_document_gets_notice() {
    Box::pin(recovery_with_newer_document(2)).await;
}

#[tokio::test]
async fn test_recovery_start_equal_to_held_document_gets_notice() {
    Box::pin(recovery_with_newer_document(3)).await;
}

#[tokio::test]
async fn test_recovery_start_above_held_document_remains_available() {
    Box::pin(recovery_with_newer_document(4)).await;
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

/// alice's mark, which must read as one.
#[allow(clippy::panic)]
async fn mark_of(replay: &Replay) -> AccountMark {
    match replay
        .marks
        .read(&alice_id())
        .await
        .expect("the mark store")
    {
        MarkRead::Mark(mark) => mark,
        other => panic!("no mark: {other:?}"),
    }
}

/// The account's creation time, read from the database.
async fn created_at(replay: &Replay) -> u64 {
    u64::try_from(scalar_i64(replay, "SELECT created_at_ms FROM accounts WHERE id = $1").await)
        .expect("a time")
}

/// The head an answer carries in its body.
fn head_of(response: &SwitchResponse) -> SignedHead {
    SignedHead::from_value(&json_of(response)["head"]).expect("head")
}

/// The notice `503 recovery_required` at `generation` with `reason`, not permanent, without
/// a head (Switch wire 7.3, Table 2; 7.6).
fn is_notice(response: &SwitchResponse, generation: u64, reason: &str) -> bool {
    code(response) == (503, "recovery_required".into())
        && json_of(response)["current"]
            == json!({ "generation": generation, "reason": reason, "permanent": false })
        && header_text(response, header::HEAD).is_none()
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

/// A service key change after `on`: the next generation without `recovery_from`, naming
/// `key` and keeping `on`'s generation's key for the proofs the account keeps (Switch wire
/// 3.3).
fn key_change(on: &IdentityDoc, key: [u8; 32]) -> SignedDoc {
    let mut body: IdentityBody = on.body().clone();
    body.version += 1;
    body.generation += 1;
    body.inbox.service_key = key;
    body.service_keys
        .push(pubky_switch_core::records::ServiceKeyEntry {
            generation: on.generation(),
            key,
        });
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
) -> (SwitchResponse, Sent) {
    let path = format!("/v1/{}/identity", alice_id());
    let request = signer_request_at_creation(
        "PUT",
        &path,
        IdentityDelivery {
            identity: doc,
            prev,
        }
        .to_json(),
        at_ms,
        Some(created_at(replay).await),
    );
    let signature = signed_sent(&request);
    (replay.service.handle(request).await, signature)
}

/// Run the minute's maintenance before comparing the marks of two requests at this time.
async fn sweep_before_delivery(replay: &Replay, at: u64) {
    let answer = replay
        .service
        .handle(signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            at,
        ))
        .await;
    assert_eq!(answer.status, 200);
}

/// alice serving at generation 1 with the vectors' chain through the phone's revocation,
/// then an enrollment at the serving account naming [`HELD_REVOKED`]: the key the answer
/// names, the service key, and the time after.
async fn serving_with_a_held_app(replay: &Replay) -> ([u8; 32], u64) {
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
    let key = answered_key(&answer);
    assert_eq!(key, service_public(replay), "the current key");
    (key, at)
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
    let request = signer_request_at_creation(
        "GET",
        &format!("/v1/{}/apps", alice_id()),
        Vec::new(),
        at,
        Some(created_at(&replay).await),
    );
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
async fn test_recovery_in_place_starts_afresh_under_the_service_key() {
    // alice's provider loss at this same service: the next generation names the service key,
    // the key its enrollments answer, and declares generation 1 lost. The account starts
    // afresh: none of generation 1's state stays, its tombstones and the held App ID do, the
    // chain starts with the `recovery` transition, and the answer and every later one are
    // the service key's. No erasure is recorded (Switch wire 3.3, 3.7, 7.4.2).
    let Some(replay) = replay().await else { return };
    let (key, at) = serving_with_a_held_app(&replay).await;
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
    let recovery = next_generation(&before, key, Some(1));
    let (answer, signature) = deliver(&replay, recovery, Some(before.hash()), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(
        signed_by(&answer, &key, &signature),
        "the service key's answer"
    );
    assert_eq!(
        replay.marks.erasure(&alice_id()).await.expect("ledger"),
        None,
        "no erasure recorded"
    );
    assert_eq!(
        chain(&replay).await,
        [(2, 1, "service".into()), (2, 2, "identity".into())]
    );
    // The new sequence's items keep their documents: what the recovery superseded at the
    // generation it left touches none of them (Switch wire 7.5).
    for seq in [1, 2] {
        assert_eq!(
            chain_document_kept(&replay, &alice_id(), seq).await,
            (true, false)
        );
    }
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
        "the tombstones, and the App ID the enrollment held"
    );
    assert_eq!(
        scalar_i64(&replay, "SELECT generation FROM accounts WHERE id = $1").await,
        2
    );
    let request = signer_request("GET", &format!("/v1/{}/apps", alice_id()), Vec::new(), at);
    let read_signature = signed_sent(&request);
    let apps = replay.service.handle(request).await;
    assert_eq!(apps.status, 200);
    assert!(signed_by(&apps, &key, &read_signature));
    assert_eq!(json_of(&apps)["recovery"]["recovery_from"], 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_in_place_moves_the_mark_to_the_new_generations_first_head() {
    // A delivery that starts a generation moves the account's mark to the new generation's
    // first head, the one its answer carries, with the key the document names; the
    // creation time stays (Switch wire 7.3, Table 3). An ordinary version before it moves
    // the mark within generation 1.
    let Some(replay) = replay().await else { return };
    let (key, at) = serving_with_a_held_app(&replay).await;
    let mark_before = mark_of(&replay).await;
    assert_eq!(mark_before.generation, 1);
    assert!(
        mark_before
            .creation_anchor
            .for_creation(mark_before.created_at_ms)
            .is_some()
    );
    let before = held(&replay).await;
    let mut ordinary: IdentityBody = before.body().clone();
    ordinary.version += 1;
    let ordinary = IdentityDoc::sign(&alice_key(), ordinary).expect("sign");
    let (answer, _) = deliver(&replay, ordinary.signed().clone(), Some(before.hash()), at).await;
    assert_eq!(answer.status, 200);
    let moved = mark_of(&replay).await;
    assert_eq!(moved.creation_anchor, mark_before.creation_anchor);
    assert_eq!(
        (moved.generation, moved.seq),
        (1, mark_before.seq + 1),
        "within the generation"
    );
    let (answer, _) = deliver(
        &replay,
        next_generation(&ordinary, key, Some(1)),
        Some(ordinary.hash()),
        at,
    )
    .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let head = head_of(&answer);
    assert_eq!((head.generation, head.seq), (2, 2));
    let held = mark_of(&replay).await;
    assert_eq!(
        held,
        AccountMark {
            state_tag: state_tag_of(&replay, &alice_id()).await,
            generation: 2,
            seq: 2,
            chain_hash: head.chain_hash,
            creation_anchor: mark_before.creation_anchor,
            state_version: state_version_of(&replay, &alice_id()).await,
            time_floor_ms: held.time_floor_ms,
            key,
            created_at_ms: mark_before.created_at_ms,
        }
    );
    assert_floor_covers(&held, &answer);
    replay.db.drop_database().await.expect("drop");
}

/// These generation starts commit at the request's selected time. Their marks cover that
/// stamp within one reservation step (Switch wire 7.3, "Time base").
fn assert_floor_covers(mark: &AccountMark, answer: &SwitchResponse) {
    let shown = ms(header_text(answer, header::SERVER_TIME).expect("server time"));
    assert!(
        (shown..=shown + pubky_switch::marks::TIME_FLOOR_STEP_MS).contains(&mark.time_floor_ms),
        "floor {} against {shown}",
        mark.time_floor_ms
    );
}

/// The App IDs alice's account holds for the next generation, and whether [`HELD_REVOKED`]
/// is among its tombstones.
async fn held_and_kept(replay: &Replay) -> (i64, i64) {
    (
        scalar_i64(
            replay,
            "SELECT count(*) FROM held_revoked_apps WHERE account_id = $1",
        )
        .await,
        scalar_i64(
            replay,
            "SELECT count(*) FROM kept_app_ids WHERE account_id = $1 \
             AND app_id = '\\x07070707070707070707070707070707'",
        )
        .await,
    )
}

#[tokio::test]
async fn test_recovery_held_revoked_apps_lost_to_a_restore_are_behind_the_mark() {
    // An enrollment at a serving account holds its `revoked_apps` for the next generation:
    // a counted write, which the mark covers before the answer goes out (Switch wire 7.3,
    // "Moving it", Table 3).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let count = state_version_of(&replay, &alice_id()).await;
    assert_eq!(mark_of(&replay).await.state_version, count);
    let at = replay.clock.now_ms() + 60_000;
    set_time(&replay.clock, &rfc3339(at));
    let answer = enroll(&replay, enrollment(3, Some(vec![HELD_REVOKED])), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(held_and_kept(&replay).await, (1, 0));
    assert_eq!(state_version_of(&replay, &alice_id()).await, count + 1);
    assert_eq!(mark_of(&replay).await.state_version, count + 1);
    // A restore that loses only that enrollment: the account is behind its mark, and no
    // start of a later generation can then miss the held App ID unnoticed.
    sql_on(
        &replay,
        &alice_id(),
        &format!(
            "WITH gone AS (DELETE FROM held_revoked_apps WHERE account_id = $1) \
             UPDATE accounts SET state_version = {count} WHERE id = $1"
        ),
    )
    .await;
    let read = replay
        .service
        .handle(signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            at,
        ))
        .await;
    assert_eq!(code(&read), (503, "recovery_required".to_string()));
    assert_eq!(json_of(&read)["current"]["reason"], "behind");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_in_place_held_revoked_apps_join_the_tombstones_at_the_start() {
    // At a serving account, the `revoked_apps` of every enrollment answered since its
    // generation began are held with the account, and join its tombstones when a delivery
    // starts the next generation; a delivery within the generation leaves them held (Switch
    // wire 3.3, 3.7).
    let Some(replay) = replay().await else { return };
    let (key, at) = serving_with_a_held_app(&replay).await;
    assert_eq!(
        held_and_kept(&replay).await,
        (1, 0),
        "held, not a tombstone yet"
    );
    let before = held(&replay).await;
    let mut ordinary: IdentityBody = before.body().clone();
    ordinary.version += 1;
    let ordinary = IdentityDoc::sign(&alice_key(), ordinary).expect("sign");
    let (answer, _) = deliver(&replay, ordinary.signed().clone(), Some(before.hash()), at).await;
    assert_eq!(answer.status, 200);
    assert_eq!(held_and_kept(&replay).await, (1, 0), "still held");
    let (answer, _) = deliver(
        &replay,
        next_generation(&ordinary, key, Some(1)),
        Some(ordinary.hash()),
        at,
    )
    .await;
    assert_eq!(answer.status, 200);
    assert_eq!(held_and_kept(&replay).await, (0, 1), "a tombstone now");
    // An enrollment at a staged account holds nothing: the account keeps its first
    // enrollment's `revoked_apps`.
    replay.db.drop_database().await.expect("drop");
    let Some(replay) = support::replay().await else {
        return;
    };
    let at = ms("2026-01-01T00:00:00.000Z");
    set_time(&replay.clock, "2026-01-01T00:00:00.000Z");
    assert_eq!(enroll(&replay, enrollment(1, None), at).await.status, 200);
    assert_eq!(
        enroll(&replay, enrollment(2, Some(vec![HELD_REVOKED])), at)
            .await
            .status,
        200
    );
    assert_eq!(held_and_kept(&replay).await, (0, 0));
    replay.db.drop_database().await.expect("drop");
}

/// The `cursor` the wallet's feed page after `after` reports, at `at`.
async fn wallet_cursor(replay: &Replay, after: &str, at: u64) -> Value {
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/feed?after={after}", alice_id());
    let answer = replay
        .service
        .handle(app_request(
            app(&keys, "wallet"),
            "GET",
            &path,
            Vec::new(),
            at,
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    json_of(&answer)["cursor"].clone()
}

#[tokio::test]
async fn test_recovery_in_place_counts_the_loss_of_reachable_apps_once() {
    async fn versions(replay: &Replay) -> (u64, u64) {
        let mut txn = replay
            .db
            .store()
            .begin(&alice_id())
            .await
            .expect("begin")
            .expect("account");
        txn.directory_versions().await.expect("directory versions")
    }

    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    replay_batch(&replay, &vectors("chain.json"), &[3, 4]).await;
    let key = service_public(&replay);
    let at = replay.clock.now_ms();
    let (directory, apps) = versions(&replay).await;
    assert!(apps > 0, "the wallet has a receive key");
    // The wallet becomes unreachable on the first recovery. Nothing registered again
    // before the second recovery (Switch wire 7.4.10).
    for step in 1..=2 {
        let previous = held(&replay).await;
        let recovery = next_generation(&previous, key, Some(previous.generation()));
        let (answer, sent) = deliver(&replay, recovery, Some(previous.hash()), at).await;
        assert_eq!(answer.status, 200, "{}", json_of(&answer));
        assert!(signed_by(&answer, &key, &sent));
        assert_eq!(versions(&replay).await, (directory + step, apps + 1));
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_in_place_holds_no_cursor_of_the_lost_sequence() {
    // A provider loss starts the account's apps afresh: the new sequence holds no cursor
    // from the lost one, so the wallet's first page there reports 0, before any move of its
    // own, whatever it held at generation 1 (Switch spec 8.3, 12.6 step 1).
    let Some(replay) = replay().await else { return };
    let (key, at) = serving_with_a_held_app(&replay).await;
    let keys = vectors("keys.json");
    let body = OpsRequest::new(
        &[],
        Some(Position {
            generation: 1,
            seq: 8,
        }),
    )
    .to_json();
    let path = format!("/v1/{}/ops", alice_id());
    let moved = replay
        .service
        .handle(app_request(app(&keys, "wallet"), "POST", &path, body, at))
        .await;
    assert_eq!(
        moved.status,
        200,
        "{}",
        String::from_utf8_lossy(&moved.body)
    );
    assert_eq!(wallet_cursor(&replay, "1:9", at).await, json!(8));
    let before = held(&replay).await;
    let (answer, _) = deliver(
        &replay,
        next_generation(&before, key, Some(1)),
        Some(before.hash()),
        at,
    )
    .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    // Its first call at the new generation registers it again, and moves no cursor.
    let (status, body) = wallet_registers(&replay, 77, 2, 3, true, at).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(wallet_cursor(&replay, "1:9", at).await, json!(0));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_in_place_answers_a_held_feed_read_from_the_new_generation() {
    // A feed read held when the account recovers in place: the recovery's commit wakes it,
    // and it is answered from the account as it then is, at the new generation, which holds
    // no record of the app yet: `403 not_current`, signed with the service key, with no
    // head (Switch wire 7.4.4 "Long-poll", spec 12.6 step 1).
    let Some(replay) = replay().await else { return };
    let (key, at) = serving_with_a_held_app(&replay).await;
    let tip = chain(&replay).await.last().map_or(0, |(_, seq, _)| *seq);
    let before = held(&replay).await;
    let (stop, task) = listen(&replay).await;
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/feed?after=1:{tip}&wait=10", alice_id());
    let request = app_request(app(&keys, "wallet"), "GET", &path, Vec::new(), at);
    let sent = signed_sent(&request);
    let started = std::time::Instant::now();
    let waiting = replay.service.handle(request);
    let (answer, delivered) = tokio::join!(waiting, async {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        deliver(
            &replay,
            next_generation(&before, key, Some(1)),
            Some(before.hash()),
            at,
        )
        .await
    });
    assert_eq!(delivered.0.status, 200, "the recovery");
    assert_eq!(
        code(&answer),
        (403, "not_current".into()),
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let mut members: Vec<String> = json_of(&answer)
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect();
    members.sort_unstable();
    assert_eq!(members, ["code", "message"]);
    // The two headers every answer carries, and no head.
    let mut names: Vec<&str> = answer
        .headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["switch-server-time", "switch-service-signature"]);
    // Woken by the recovery, not by the end of its wait.
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert!(signed_by(&answer, &key, &sent));
    let _ = stop.send(());
    task.await.expect("listener");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_key_change_naming_the_same_key_is_400() {
    // The next generation without `recovery_from` is a service key change: the key it
    // names must be another than the ending generation's, else `400 bad_request`, and
    // nothing changes, the mark included (Switch wire 3.3).
    let Some(replay) = replay().await else { return };
    let (key, at) = serving_with_a_held_app(&replay).await;
    let before = held(&replay).await;
    sweep_before_delivery(&replay, at).await;
    let mark_before = mark_of(&replay).await;
    let change = key_change(&before, key);
    let (answer, _) = deliver(&replay, change, Some(before.hash()), at).await;
    assert_eq!(
        code(&answer),
        (400, "bad_request".into()),
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(held(&replay).await.hash(), before.hash());
    assert_eq!(mark_of(&replay).await, mark_before);
    assert_eq!(
        scalar_i64(&replay, "SELECT generation FROM accounts WHERE id = $1").await,
        1
    );
    // With `recovery_from` the generation that ends, the same key starts it: a provider
    // loss in place.
    let (answer, _) = deliver(
        &replay,
        next_generation(&before, key, Some(1)),
        Some(before.hash()),
        at,
    )
    .await;
    assert_eq!(answer.status, 200);
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

/// The account's state restored from before its newest head: its chain gone, the chain
/// head and every `seq` back to none, while its mark stays where it was (Switch wire 7.3,
/// Table 3: a restore of the state leaves the mark).
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
    // The service's state was restored from before what it signed for the account: the
    // account fails stop, `behind`. The start of the next generation, naming the service
    // key and `recovery_from` the generation less one, is the one delivery taken: the
    // account starts afresh, whatever its `prev` names (Switch wire 3.3, 7.3 Table 2). Its
    // document still lists the phone, revoked but not removed yet, as the version held
    // does: taken, as at a provider loss in place (Switch wire 3.3, 3.7).
    let Some(replay) = replay().await else { return };
    let (key, at) = serving_with_a_held_app(&replay).await;
    let before = held(&replay).await;
    restored_behind_the_mark(&replay).await;
    let request = signer_request("GET", &format!("/v1/{}/apps", alice_id()), Vec::new(), at);
    assert!(is_notice(
        &replay.service.handle(request).await,
        1,
        "behind"
    ));
    let recovery = next_generation(&before, key, Some(1));
    let (answer, signature) = deliver(&replay, recovery, Some([3; 32]), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(signed_by(&answer, &key, &signature));
    assert_eq!(
        chain(&replay).await,
        [(2, 1, "service".into()), (2, 2, "identity".into())]
    );
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
    let (key, at) = serving_with_a_held_app(&replay).await;
    let before = held(&replay).await;
    let recovery = next_generation(&before, key, Some(1));
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
async fn test_recovery_in_place_refuses_an_app_an_enrollment_held() {
    // The `revoked_apps` a serving account's enrollments named are kept from the new
    // generation's start, as at a new account that "never serves or lists them, also after
    // a provider loss" (Switch wire 3.7): a recovery document that lists one is `400`, and
    // nothing changes.
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
    let key = answered_key(&answer);
    let before = held(&replay).await;
    sweep_before_delivery(&replay, at).await;
    let mark_before = mark_of(&replay).await;
    assert!(before.body().apps.iter().any(|a| a.app_id == wallet_id));
    let recovery = next_generation(&before, key, Some(1));
    let (answer, _) = deliver(&replay, recovery, Some(before.hash()), at).await;
    assert_eq!(code(&answer), (400, "bad_request".into()));
    assert_eq!(held(&replay).await.hash(), before.hash());
    assert_eq!(mark_of(&replay).await, mark_before);
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
async fn test_recovery_key_change_after_a_recovery_naming_the_same_key_is_400() {
    // A later document keeps the earlier loss's `recovery_from` (spec 4.3), which doesn't
    // name the generation that ends: the next generation is then a service key change, and
    // one naming the same key as the ending generation's is `400`; nothing changes (Switch
    // wire 3.3).
    let Some(replay) = replay().await else { return };
    let (key, at) = serving_with_a_held_app(&replay).await;
    let before = held(&replay).await;
    let (answer, _) = deliver(
        &replay,
        next_generation(&before, key, Some(1)),
        Some(before.hash()),
        at,
    )
    .await;
    assert_eq!(answer.status, 200);
    assert_eq!(
        answered_key(&enroll(&replay, enrollment(9, None), at).await),
        key
    );
    let generation_2 = held(&replay).await;
    let mark_2 = mark_of(&replay).await;
    let mut change: IdentityBody = generation_2.body().clone();
    change.version += 1;
    change.generation += 1;
    change.inbox.service_key = key;
    change
        .service_keys
        .push(pubky_switch_core::records::ServiceKeyEntry { generation: 2, key });
    let change = IdentityDoc::sign(&alice_key(), change)
        .expect("sign")
        .signed()
        .clone();
    let (answer, _) = deliver(&replay, change, Some(generation_2.hash()), at).await;
    assert_eq!(
        code(&answer),
        (400, "bad_request".into()),
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(held(&replay).await.hash(), generation_2.hash());
    assert_eq!(mark_of(&replay).await, mark_2);
    replay.db.drop_database().await.expect("drop");
}

/// alice serving with `identity.json` version 3 at seq 2, restored: her mark three `seq`s
/// past her state, or, with `fork`, at her state's pair with another chain hash. The time
/// after.
async fn restored(replay: &Replay, fork: bool) -> u64 {
    serve_alice(replay).await;
    let at = replay.clock.now_ms() + 60_000;
    set_time(&replay.clock, &rfc3339(at));
    let mark = mark_of(replay).await;
    if fork {
        replay.marks.delete(&alice_id()).await.expect("delete");
        let beside = ChainTip {
            chain_hash: [9; 32],
            ..mark.head()
        };
        replay
            .marks
            .write_anew(&alice_id(), at_head(beside), mark.key, mark.created_at_ms)
            .await
            .expect("a mark beside the state");
    } else {
        let ahead = ChainTip {
            generation: mark.generation,
            seq: mark.seq + 3,
            chain_hash: [9; 32],
        };
        replay
            .marks
            .advance(
                &alice_id(),
                keeping_count(&replay.marks, &alice_id(), ahead).await,
                mark.key,
                mark.created_at_ms,
            )
            .await
            .expect("a mark ahead of the state");
    }
    at
}

/// The account's key, held document, chain length, stamped `seq` and recovery column.
async fn snapshot(replay: &Replay) -> ([u8; 32], usize, i64, i64) {
    let held = held(replay).await.hash();
    let chain = chain(replay).await.len();
    let seq = scalar_i64(replay, "SELECT last_seq FROM accounts WHERE id = $1").await;
    let recovery = scalar_i64(
        replay,
        "SELECT COALESCE(recovery_from, -1) FROM accounts WHERE id = $1",
    )
    .await;
    (held, chain, seq, recovery)
}

/// At a serving account that fails stop, behind its mark or beside it, every request gets
/// the notice, but the signer's enrollment and the start above both the held document's and
/// the mark's generation with `recovery_from` its generation less one, which starts the
/// account afresh, its `prev` not compared (Switch wire 3.3, 7.3 Tables 1 and 2).
async fn only_the_start_gets_past_the_mark(fork: bool) {
    let Some(replay) = replay().await else { return };
    let at = restored(&replay, fork).await;
    let reason = if fork { "fork" } else { "behind" };
    let key = service_public(&replay);
    let request = signer_request("GET", &format!("/v1/{}/apps", alice_id()), Vec::new(), at);
    let sent = signed_sent(&request);
    let apps = replay.service.handle(request).await;
    assert!(
        is_notice(&apps, 1, reason),
        "{}",
        String::from_utf8_lossy(&apps.body)
    );
    assert!(signed_by(&apps, &key, &sent), "the key in the mark");
    let enrolled = enroll(&replay, enrollment(3, Some(vec![HELD_REVOKED])), at).await;
    assert_eq!(enrolled.status, 200);
    assert_eq!(answered_key(&enrolled), key);
    let before = held(&replay).await;
    let state_before = snapshot(&replay).await;
    let mark_before = mark_of(&replay).await;
    let mut ordinary = before.body().clone();
    ordinary.version += 1;
    let ordinary = IdentityDoc::sign(&alice_key(), ordinary)
        .expect("sign")
        .signed()
        .clone();
    let mut same_generation = before.body().clone();
    same_generation.version += 1;
    same_generation.recovery_from = Some(1);
    let same_generation = IdentityDoc::sign(&alice_key(), same_generation)
        .expect("sign")
        .signed()
        .clone();
    let mut skipping = before.body().clone();
    skipping.version += 1;
    skipping.generation += 2;
    skipping.recovery_from = Some(1);
    let skipping = IdentityDoc::sign(&alice_key(), skipping)
        .expect("sign")
        .signed()
        .clone();
    for (what, doc) in [
        ("an ordinary version", ordinary),
        ("a key change", next_generation(&before, key, None)),
        ("a start not above the generation", same_generation),
        ("recovery_from not the generation less one", skipping),
    ] {
        let (answer, _) = deliver(&replay, doc, Some(before.hash()), at).await;
        assert!(
            is_notice(&answer, 1, reason),
            "{what}: {}",
            String::from_utf8_lossy(&answer.body)
        );
        assert_eq!(snapshot(&replay).await, state_before, "{what}: nothing");
        assert_eq!(mark_of(&replay).await, mark_before, "{what}: the mark");
    }
    let start = next_generation(&before, key, Some(1));
    let (answer, signature) = deliver(&replay, start, Some([3; 32]), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(signed_by(&answer, &key, &signature));
    assert_eq!(
        chain(&replay).await,
        [(2, 1, "service".into()), (2, 2, "identity".into())],
        "afresh"
    );
    let head = head_of(&answer);
    let mark = mark_of(&replay).await;
    assert_eq!(
        (
            mark.generation,
            mark.seq,
            mark.chain_hash,
            mark.created_at_ms
        ),
        (2, 2, head.chain_hash, mark_before.created_at_ms)
    );
    let request = signer_request("GET", &format!("/v1/{}/apps", alice_id()), Vec::new(), at);
    let read_signature = signed_sent(&request);
    let apps = replay.service.handle(request).await;
    assert_eq!(apps.status, 200);
    assert!(signed_by(&apps, &key, &read_signature));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_failing_behind_its_mark_takes_only_the_start() {
    only_the_start_gets_past_the_mark(false).await;
}

#[tokio::test]
async fn test_recovery_failing_beside_its_mark_takes_only_the_start() {
    only_the_start_gets_past_the_mark(true).await;
}

#[tokio::test]
async fn test_recovery_failing_start_is_above_the_marks_generation() {
    // The mark records a head at generation 3, above the held document's generation 1: the
    // notice names generation 3, and only a start above it, with `recovery_from` its
    // generation less one, goes through (Switch wire 7.3, Table 2; 7.6).
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let at = replay.clock.now_ms() + 60_000;
    set_time(&replay.clock, &rfc3339(at));
    let key = service_public(&replay);
    let ahead = ChainTip {
        generation: 3,
        seq: 1,
        chain_hash: [9; 32],
    };
    replay
        .marks
        .advance(
            &alice_id(),
            keeping_count(&replay.marks, &alice_id(), ahead).await,
            key,
            mark_created_at(&replay, &alice_id()).await,
        )
        .await
        .expect("a mark ahead");
    let before = held(&replay).await;
    let (answer, _) = deliver(
        &replay,
        next_generation(&before, key, Some(1)),
        Some(before.hash()),
        at,
    )
    .await;
    assert!(
        is_notice(&answer, 3, "behind"),
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let mut above: IdentityBody = before.body().clone();
    above.version += 1;
    above.generation = 4;
    above.recovery_from = Some(3);
    let above = IdentityDoc::sign(&alice_key(), above)
        .expect("sign")
        .signed()
        .clone();
    let (answer, _) = deliver(&replay, above, None, at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let mark = mark_of(&replay).await;
    assert_eq!((mark.generation, mark.seq), (4, 2));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_failing_mark_lost_start_writes_the_mark_anew() {
    // A serving account whose mark is lost fails stop, `mark_lost`. The start writes the
    // mark anew at the new generation's first head, with the account's creation time
    // (Switch wire 7.3, Table 3); any other delivery gets the notice and writes none.
    let Some(replay) = replay().await else { return };
    serve_alice(&replay).await;
    let at = replay.clock.now_ms() + 60_000;
    set_time(&replay.clock, &rfc3339(at));
    let key = service_public(&replay);
    let created = created_at(&replay).await;
    replay.marks.delete(&alice_id()).await.expect("lost");
    let request = signer_request("GET", &format!("/v1/{}/apps", alice_id()), Vec::new(), at);
    assert!(is_notice(
        &replay.service.handle(request).await,
        1,
        "mark_lost"
    ));
    let before = held(&replay).await;
    let mut ordinary = before.body().clone();
    ordinary.version += 1;
    let ordinary = IdentityDoc::sign(&alice_key(), ordinary)
        .expect("sign")
        .signed()
        .clone();
    let (answer, _) = deliver(&replay, ordinary, Some(before.hash()), at).await;
    assert!(is_notice(&answer, 1, "mark_lost"));
    assert_eq!(
        replay.marks.read(&alice_id()).await.expect("read"),
        MarkRead::Missing
    );
    let (answer, signature) = deliver(
        &replay,
        next_generation(&before, key, Some(1)),
        Some([3; 32]),
        at,
    )
    .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(signed_by(&answer, &key, &signature));
    let head = head_of(&answer);
    let held = mark_of(&replay).await;
    assert_eq!(
        held,
        AccountMark {
            state_tag: state_tag_of(&replay, &alice_id()).await,
            generation: 2,
            seq: 2,
            chain_hash: head.chain_hash,
            creation_anchor: Default::default(),
            state_version: state_version_of(&replay, &alice_id()).await,
            time_floor_ms: held.time_floor_ms,
            key,
            created_at_ms: created,
        }
    );
    assert_floor_covers(&held, &answer);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_in_place_after_its_version_was_lost_too() {
    // The restore lost the newest `identity.json` too: the service holds an older version,
    // and the signer's recovery builds on the one it lost. At the account, which fails stop,
    // the start is taken whatever its `prev` names (Switch wire 3.3, 7.3 Table 2), the
    // revoked phone it still lists included, as the version held lists it (Switch wire 3.3).
    let Some(replay) = replay().await else { return };
    let (key, at) = serving_with_a_held_app(&replay).await;
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
    let recovery = next_generation(&newest, key, Some(1));
    let (answer, signature) = deliver(&replay, recovery, Some(newest.hash()), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(signed_by(&answer, &key, &signature));
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

/// At a serving account that fails stop, behind its mark or beside it, a start of the next
/// generation that 3.3 doesn't take all the same: one listing an App ID an enrollment held
/// for the next generation, or one naming a key the service doesn't hold. Each is refused
/// without a head, and nothing commits: the held version, the chain, the stamped `seq`, the
/// recovery column and the mark all stay (Switch wire 3.3, 3.7, 7.3 Table 2).
async fn start_refused_deeper_changes_nothing(fork: bool) {
    let Some(replay) = replay().await else { return };
    let at = restored(&replay, fork).await;
    let key = service_public(&replay);
    let wallet = wallet_app_id();
    let enrolled = enroll(&replay, enrollment(3, Some(vec![wallet])), at).await;
    assert_eq!(enrolled.status, 200);
    let before = held(&replay).await;
    assert!(before.body().apps.iter().any(|a| a.app_id == wallet));
    let mark_before = mark_of(&replay).await;
    let state_before = snapshot(&replay).await;
    for (what, doc) in [
        (
            "lists the held wallet",
            next_generation(&before, key, Some(before.generation())),
        ),
        (
            "names another key",
            next_generation(&before, [9; 32], Some(before.generation())),
        ),
    ] {
        let (answer, signature) = deliver(&replay, doc, Some(before.hash()), at).await;
        assert_eq!(
            code(&answer),
            (400, "bad_request".into()),
            "{what}: {}",
            String::from_utf8_lossy(&answer.body)
        );
        assert!(
            header_text(&answer, header::HEAD).is_none(),
            "{what}: no head"
        );
        assert!(signed_by(&answer, &key, &signature), "{what}: signed");
        assert_eq!(snapshot(&replay).await, state_before, "{what}: nothing");
        assert_eq!(mark_of(&replay).await, mark_before, "{what}: mark");
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_recovery_behind_the_mark_a_start_refused_deeper_changes_nothing() {
    start_refused_deeper_changes_nothing(false).await;
}

#[tokio::test]
async fn test_recovery_beside_the_mark_a_start_refused_deeper_changes_nothing() {
    start_refused_deeper_changes_nothing(true).await;
}

#[tokio::test]
async fn test_recovery_without_prev_still_needs_a_higher_version_and_only_for_a_recovery() {
    // Wire 3.3: a provider loss in place is exempt from comparing `prev`, but needs a
    // higher version than the one held: one at or below it, whatever its `prev`, is `409
    // stale_identity` with the held copy. A key change and an ordinary version with a stale
    // `prev` aren't exempt: `409 stale_identity`, not the key change's `400`.
    let Some(replay) = replay().await else { return };
    let (key, at) = serving_with_a_held_app(&replay).await;
    let before = held(&replay).await;
    let state_before = snapshot(&replay).await;
    for version in [before.version(), before.version() - 1] {
        let (answer, _) = deliver(
            &replay,
            recovery_at(&before, key, version),
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
    let change = key_change(&before, key);
    // With the right prev, the key change naming the same key is `400`.
    let (answer, _) = deliver(&replay, change.clone(), Some(before.hash()), at).await;
    assert_eq!(
        code(&answer),
        (400, "bad_request".into()),
        "key change, right prev"
    );
    for (what, doc) in [
        ("a key change", change),
        ("an ordinary version", ordinary),
        (
            "a recovery naming another key",
            next_generation(&before, [9; 32], Some(1)),
        ),
    ] {
        let (answer, _) = deliver(&replay, doc, Some([3; 32]), at).await;
        assert_eq!(code(&answer), (409, "stale_identity".into()), "{what}");
    }
    assert_eq!(snapshot(&replay).await, state_before);
    // `prev` null at an account holding a version: taken too (the rule's "whatever").
    let (answer, _) = deliver(
        &replay,
        recovery_at(&before, key, before.version() + 1),
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
    let (key, at) = serving_with_a_held_app(&replay).await;
    let before = held(&replay).await;
    let r1 = next_generation(&before, key, Some(1));
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
    assert_eq!(
        answered_key(&enroll(&replay, enrollment(9, None), at).await),
        key
    );
    let r2 = recovery_at(&later, key, later.version() + 1);
    let (answer, _) = deliver(&replay, r2, Some([4; 32]), at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let generation_3 = held(&replay).await.hash();
    for prev in [Some([3; 32]), Some(later.hash()), None] {
        let (answer, _) = deliver(&replay, r1.clone(), prev, at).await;
        assert_eq!(code(&answer), (409, "stale_identity".into()), "{prev:?}");
    }
    assert_eq!(held(&replay).await.hash(), generation_3);
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
    let (service_key, at) = serving_with_a_held_app(&replay).await;
    let before = held(&replay).await;
    let recovery = next_generation(&before, service_key, Some(1));
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
    let (service_key, at) = serving_with_a_held_app(&replay).await;
    let before = held(&replay).await;
    let mut body: IdentityBody = before.body().clone();
    body.version += 1;
    body.generation += 1;
    body.inbox.service_key = service_key;
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
    let (service_key, at) = serving_with_a_held_app(&replay).await;
    assert_eq!(
        code(&admission(&replay, Vec::new(), at).await),
        (404, "not_found".into())
    );
    let before = held(&replay).await;
    let recovery = next_generation(&before, service_key, Some(1));
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
    let (service_key, at) = serving_with_a_held_app(&replay).await;
    let before = held(&replay).await;
    let mut body: IdentityBody = before.body().clone();
    body.version += 1;
    body.generation += 1;
    body.inbox.service_key = service_key;
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
    let (service_key, at) = serving_with_a_held_app(replay).await;
    let before = held(replay).await;
    let recovery = next_generation(&before, service_key, Some(1));
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
    let key = service_public(&replay);
    let request = signer_request(
        "POST",
        &format!("/v1/{}/recovery/admission", alice_id()),
        Vec::new(),
        at,
    );
    let signature = signed_sent(&request);
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
    let (service_key, at) = serving_with_a_held_app(replay).await;
    let before = held(replay).await;
    let recovery = next_generation(&before, service_key, Some(1));
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

/// The executor's app record from the vectors.
fn executor_record() -> SignedDoc {
    serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "executor app record",
        )["signed"]
            .clone(),
    )
    .expect("record")
}

/// The executor, listed in alice's document, current again at generation 2 with its
/// record: its keys.
async fn executor_registers(replay: &Replay, at: u64) -> Value {
    let keys = vectors("keys.json");
    let executor = app(&keys, "executor").clone();
    let record = executor_record();
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
    let (_, at) = serving_with_a_held_app(&replay).await;
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
async fn test_upload_preserves_the_named_policy_at_an_empty_key() {
    let Some(replay) = replay().await else { return };
    let (lost, at) = recovered_with_the_wallet(&replay).await;
    let (record, _) = record_and_claim_keys();
    let mut put = vector_record_put();
    let mut scopes = put.policy.write_scopes.clone();
    scopes.push("zzz".into());
    scopes.sort();
    put.policy.write_scopes = scopes;
    let forged = wallet_batch(94, 1, vec![(Vec::new(), OpKind::RecordPut(put))]);
    let answer = upload(&replay, &json!({ "records": [proofless(&forged[0])] }), at).await;
    let result = &json_of(&answer)["result"];
    assert_eq!(result["records"], json!([]));
    assert_eq!(result["unverified"], json!(1));
    let honest = json!({
        "lost_identity": lost.signed(),
        "records": [uploaded_op(6, Some(CREATED)), uploaded_op(8, Some(UPDATED))],
    });
    let answer = upload(&replay, &honest, at).await;
    let result = &json_of(&answer)["result"];
    assert_eq!(result["records"], json!([record]));
    assert_eq!(result["divergent"], json!([]));
    let view = wallet_get(&replay, &format!("records/{record}"), at).await;
    assert_eq!(view["op"], json!(vector_op(8).signed()));
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

/// The executor's claim entry `fields`, an operation of the lost generation 1 in the batch
/// `[id; 16]`, uploaded with its certificate and no proof.
fn executor_proofless(id: u8, fields: ClaimFields) -> Value {
    let keys = vectors("keys.json");
    let secret = ed25519_dalek::SigningKey::from_bytes(&hex32(
        &app(&keys, "executor")["signing_secret_hex"],
    ));
    let batch = pubky_switch_core::ops::sign_batch(
        &secret,
        &alice_key().public(),
        Some(app_id_of("executor")),
        1,
        [id; 16],
        vec![(Vec::new(), OpKind::Claim(fields))],
    )
    .expect("batch");
    let cert =
        pubky_switch_core::records::AppRecord::verify(&executor_record(), &alice_key().public())
            .expect("record")
            .cert()
            .clone();
    json!({ "op": batch[0].signed(), "cert": cert.signed() })
}

#[tokio::test]
async fn test_purge_at_the_recovery_upload_that_resolves_the_apps_last_attempt() {
    // The wallet's live attempt keeps it, revoked and in neither list, while the attempt is
    // open and then `unknown`; the executor's upload of evidence that settles it purges the
    // wallet, down to its App ID (Switch wire 9.1 "Sweeps", 7.4.14).
    let Some(replay) = replay().await else { return };
    let (_, at) = recovered_with_the_wallet(&replay).await;
    let executor = executor_registers(&replay, at).await;
    let (fields, key) = live_attempt(&replay, at).await;
    let wallet = wallet_app_id();
    let keys = vectors("keys.json");
    let revoke = format!(
        "/v1/{}/apps/{}/revoke",
        alice_id(),
        app(&keys, "wallet")["app_id"].as_str().expect("id")
    );
    let revoked = replay
        .service
        .handle(signer_request("POST", &revoke, Vec::new(), at))
        .await;
    assert_eq!(
        revoked.status,
        200,
        "{}",
        String::from_utf8_lossy(&revoked.body)
    );
    let removing = deliver_next(&replay, held(&replay).await.signed(), at, |body| {
        body.apps.retain(|listed| listed.app_id != wallet);
        body.removed.push(pubky_switch_core::records::RemovedApp {
            app_id: wallet,
            distrust_from: at,
        });
        body.data_epoch += 1;
    })
    .await;
    deliver_next(&replay, &removing, at, |body| {
        body.removed.retain(|removed| removed.app_id != wallet);
    })
    .await;
    // In neither list, but its attempt is open: it keeps everything.
    assert_eq!(holdings(&replay, &wallet).await, [1, 1, 0, 1]);
    // An upload that leaves the attempt unresolved, `unknown`, purges nothing.
    let mut unknown = fields.clone();
    unknown.kind = ClaimType::Unknown;
    unknown.expected_step = 1;
    unknown.orphan_after = None;
    let body = json!({ "claims": [executor_proofless(93, unknown)] });
    let answer = upload_as(&replay, &executor, &body, at).await;
    assert_eq!(
        json_of(&answer)["result"]["claims"],
        json!([key]),
        "{}",
        json_of(&answer)
    );
    assert_eq!(holdings(&replay, &wallet).await, [1, 1, 0, 1]);
    let kept = app_status(&replay, "wallet", at).await;
    assert_eq!(kept["open_attempts"][0]["outcome"], "unknown", "{kept}");
    assert!(!kept["record_cert"].is_null(), "{kept}");
    // The upload of the evidence that settles it purges the wallet.
    let mut done = fields;
    done.kind = ClaimType::Done;
    done.expected_step = 2;
    done.orphan_after = None;
    done.basis = Some(pubky_switch_core::claims::Basis::Evidence);
    done.evidence_ref = Some(vec![5; 32]);
    let body = json!({ "claims": [executor_proofless(94, done)] });
    let answer = upload_as(&replay, &executor, &body, at).await;
    assert_eq!(
        json_of(&answer)["result"]["claims"],
        json!([key]),
        "{}",
        json_of(&answer)
    );
    assert_eq!(holdings(&replay, &wallet).await, [0, 0, 0, 0]);
    let purged = app_status(&replay, "wallet", at).await;
    assert_eq!(
        (
            purged["record_cert"].clone(),
            purged["open_attempts"].clone(),
            purged["revoked_at"].clone(),
        ),
        (Value::Null, json!([]), json!(rfc3339(at)))
    );
    // Its App ID stays, and so does the claim it created.
    assert_eq!(
        (
            rows_naming(&replay, "kept_app_ids", "app_id", &wallet).await,
            rows_naming(&replay, "claims", "creator", &wallet).await,
        ),
        (1, 1)
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
    let (_, at) = serving_with_a_held_app(&replay).await;
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
    let hash = held(&replay).await.hash();
    let erase = erasure_of(&replay, &alice_id(), Some(&hash), at).await;
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

#[tokio::test]
async fn test_recovery_in_place_and_a_sweep_at_the_same_moment_run_one_after_the_other() {
    // A request that sweeps and a recovery in place, at the same moment, in either order:
    // each takes the account's lock, so one runs after the other, and both are answered.
    // The recovery starts the account afresh either way: a sweep before it dropped what it
    // could from the old state, one after it sweeps the fresh state and takes nothing of
    // it (Switch wire 7.3 step 4, 3.3).
    for sweep_first in [true, false] {
        let Some(replay) = replay().await else { return };
        let (service_key, at) = serving_with_a_held_app(&replay).await;
        let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        sqlx::query(
            "INSERT INTO invite_codes (account_id, code_hash, max_uses, writer, \
             expires_at_ms, context) VALUES ($1, decode(repeat('ab', 32), 'hex'), 1, \
             decode(repeat('cd', 16), 'hex'), $2, 'null')",
        )
        .bind(alice_id())
        .bind(i64::try_from(at).expect("ms"))
        .execute(&mut conn)
        .await
        .expect("invite");
        // Due now: the minute's mark cleared, and each sweep's deletes logged.
        sqlx::query("UPDATE accounts SET swept_at_ms = NULL WHERE id = $1")
            .bind(alice_id())
            .execute(&mut conn)
            .await
            .expect("due");
        log_swept_invite_codes(&replay).await;
        let before = held(&replay).await;
        let recovery = next_generation(&before, service_key, Some(1));
        let apps = || {
            replay.service.handle(signer_request(
                "GET",
                &format!("/v1/{}/apps", alice_id()),
                Vec::new(),
                at,
            ))
        };
        let deliver = async { deliver(&replay, recovery, Some(before.hash()), at).await.0 };
        let (swept, recovered) = if sweep_first {
            queued(&replay, apps(), deliver).await
        } else {
            let (recovered, swept) = queued(&replay, deliver, apps()).await;
            (swept, recovered)
        };
        assert_eq!(
            recovered.status,
            200,
            "{}",
            String::from_utf8_lossy(&recovered.body)
        );
        assert_eq!(
            swept.status,
            200,
            "{}",
            String::from_utf8_lossy(&swept.body)
        );
        assert_eq!(
            chain(&replay).await,
            [(2, 1, "service".into()), (2, 2, "identity".into())],
            "sweep first: {sweep_first}"
        );
        assert_eq!(
            scalar_i64(
                &replay,
                "SELECT count(*) FROM invite_codes WHERE account_id = $1"
            )
            .await,
            0
        );
        // A sweep ran: whichever request came first swept the expired code at its step 4.
        assert_eq!(
            swept_invite_codes(&replay).await,
            1,
            "sweep first: {sweep_first}"
        );
        conn.close().await.expect("close");
        replay.db.drop_database().await.expect("drop");
    }
}

#[tokio::test]
async fn test_admission_staged_holds_back_connect_requests_whatever_the_policy() {
    // The recovery document takes no connect requests: while admission is staged a
    // stranger's `POST /connect` is still `503 staged` (decision: "whatever the policy"),
    // and `403 not_admitted` once it ends.
    let Some(replay) = replay().await else { return };
    let (service_key, at) = serving_with_a_held_app(&replay).await;
    let before = held(&replay).await;
    let mut body: IdentityBody = before.body().clone();
    body.version += 1;
    body.generation += 1;
    body.inbox.service_key = service_key;
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
    let service_key = answered_key(&answer);
    let before = held(&replay).await;
    let wallet = app_id_of("wallet");
    let mut listing: IdentityBody = before.body().clone();
    listing.version += 1;
    listing.generation += 1;
    listing.inbox.service_key = service_key;
    listing.recovery_from = Some(1);
    listing.apps.push(pubky_switch_core::records::ListedApp {
        app_id: wallet,
        cert: [1; 32],
    });
    let listing = IdentityDoc::sign(&alice_key(), listing).expect("sign");
    let (answer, _) = deliver(&replay, listing.signed().clone(), Some(before.hash()), at).await;
    assert_eq!(code(&answer), (400, "bad_request".into()));
    let recovery = next_generation(&before, service_key, Some(1));
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

#[tokio::test]
async fn test_upload_after_the_lost_generation_deleted_a_superseded_document() {
    // At generation 1 the record's update (seq 8) deleted its create's document (seq 6).
    // After the loss of generation 1 the wallet uploads both writes, with the lost service's
    // proofs, from what it holds: the service takes the record at (1, 8), as it would with
    // the create's document kept, since an upload reads nothing the chain kept.
    let Some(replay) = replay().await else { return };
    let (service_key, at) = serving_with_a_held_app(&replay).await;
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), 6).await,
        (false, false)
    );
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), 8).await,
        (true, true)
    );
    let before = held(&replay).await;
    let recovery = next_generation(&before, service_key, Some(1));
    let (answer, _) = deliver(&replay, recovery, Some(before.hash()), at).await;
    assert_eq!(answer.status, 200);
    let (status, body) = wallet_registers(&replay, 77, 2, 3, true, at).await;
    assert_eq!(status, 200, "{body}");
    let body = json!({
        "lost_identity": before.signed(),
        "records": [uploaded_op(6, Some(CREATED)), uploaded_op(8, Some(UPDATED))],
    });
    let answer = upload(&replay, &body, at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let (record, _) = record_and_claim_keys();
    let view = wallet_get(&replay, &format!("records/{record}"), at).await;
    assert_eq!(
        (view["generation"].clone(), view["version"].clone()),
        (json!(1), json!(8))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_upload_reopened_tombstone_shows_its_earlier_entries_as_stubs() {
    // The wallet's attempt and its `done` compact the claim to a tombstone, which keeps no
    // entries (Switch wire 7.4.8). An upload then adds an attempt of the lost generation and
    // reopens it: the claim reads as the upload left it, at step 3 with no entry from before,
    // and the feed shows the two earlier entries as their stubs (Switch wire 10.5).
    let Some(replay) = replay().await else { return };
    let (_, at) = recovered_with_the_wallet(&replay).await;
    let (fields, key) = live_attempt(&replay, at).await;
    let attempt = scalar_i64(&replay, "SELECT last_seq FROM accounts WHERE id = $1").await;
    let mut done = fields.clone();
    done.kind = ClaimType::Done;
    done.expected_step = 1;
    done.orphan_after = None;
    done.basis = Some(pubky_switch_core::claims::Basis::Owner);
    let batch = wallet_batch(92, 2, vec![(Vec::new(), OpKind::Claim(done))]);
    let written = wallet_ops(&replay, &batch, at).await;
    assert_eq!(
        written.status,
        200,
        "{}",
        String::from_utf8_lossy(&written.body)
    );
    let settled = scalar_i64(&replay, "SELECT last_seq FROM accounts WHERE id = $1").await;
    let rows = "SELECT count(*) FROM claim_entries WHERE account_id = $1";
    assert_eq!(scalar_i64(&replay, rows).await, 0, "a tombstone keeps none");
    let read = wallet_get(&replay, &format!("claims/{key}"), at).await;
    assert_eq!(read["claim"]["tombstone"], json!(true), "{read}");
    assert_eq!(read["entries"], json!([]), "{read}");
    let mut uploaded = fields;
    uploaded.attempt_id = vec![10; 16];
    let lost_op = wallet_batch(93, 1, vec![(Vec::new(), OpKind::Claim(uploaded))]);
    let answer = upload(&replay, &json!({ "claims": [proofless(&lost_op[0])] }), at).await;
    assert_eq!(
        json_of(&answer)["result"]["claims"],
        json!([key]),
        "{}",
        json_of(&answer)
    );
    let read = wallet_get(&replay, &format!("claims/{key}"), at).await;
    assert_eq!(read["claim"]["tombstone"], json!(false), "{read}");
    assert_eq!(read["claim"]["step"], json!(3), "{read}");
    assert_eq!(read["entries"], json!([]), "{read}");
    let feed = wallet_get(&replay, "feed?limit=500", at).await;
    for seq in [attempt, settled] {
        let item = feed["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| item["seq"] == json!(seq))
            .cloned()
            .expect("the entry");
        assert_eq!(item["type"], json!("stub"), "{item}");
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_record_current_uploaded_reference_survives_restart_and_refused_generation() {
    let Some(replay) = replay().await else { return };
    let (lost, at) = recovered_with_the_wallet(&replay).await;
    let upload_body =
        json!({"lost_identity": lost.signed(), "records": [uploaded_op(8, Some(UPDATED))]});
    let answer = upload(&replay, &upload_body, at).await;
    assert_eq!(answer.status, 200, "{}", json_of(&answer));
    let (key, _) = record_and_claim_keys();
    let path = format!("/v1/{}/records/{key}", alice_id());
    let before = wallet_get(&replay, &format!("records/{key}"), at).await;
    let op =
        SignedOp::peek(&serde_json::from_value(before["op"].clone()).expect("op")).expect("op");
    assert_eq!(
        before["revision"],
        json!({"generation": 2, "seq": json_of(&answer)["head"]["seq"], "item_hash": pubky_switch_core::enc::b64(&op.item_hash().expect("item"))})
    );
    assert_eq!(
        (before["generation"].clone(), before["version"].clone()),
        (json!(1), json!(8))
    );
    let restarted = replay.restarted_with(pubky_switch::limits::Limits::default());
    let read = restarted
        .handle(app_request(&wallet_keys(), "GET", &path, Vec::new(), at))
        .await;
    assert_eq!(read.status, 200, "{}", json_of(&read));
    assert_eq!(json_of(&read), before);
    // The record's application stays put when a generation change is refused.
    let held = held(&replay).await;
    let mut next = held.body().clone();
    next.version += 1;
    next.generation += 1;
    next.inbox.service_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32])
        .verifying_key()
        .to_bytes();
    next.service_keys
        .push(pubky_switch_core::records::ServiceKeyEntry {
            generation: held.generation(),
            key: held.inbox().service_key,
        });
    let next = IdentityDoc::sign(&alice_key(), next).expect("signed generation");
    let request = signer_request(
        "PUT",
        &format!("/v1/{}/identity", alice_id()),
        IdentityDelivery {
            identity: next.signed().clone(),
            prev: Some(held.hash()),
        }
        .to_json(),
        at,
    );
    let sent = signed_sent(&request);
    let refused = restarted.handle(request).await;
    assert_eq!(
        code(&refused),
        (400, "bad_request".into()),
        "{}",
        json_of(&refused)
    );
    assert!(signed_by(&refused, &held.inbox().service_key, &sent));
    assert_eq!(held.hash(), self::held(&replay).await.hash());
    let read = restarted
        .handle(app_request(&wallet_keys(), "GET", &path, Vec::new(), at))
        .await;
    assert_eq!(read.status, 200);
    assert_eq!(json_of(&read), before);
    replay.db.drop_database().await.expect("drop");
}

/// alice's account's count and its tag, and her mark's.
async fn count_and_mark(replay: &Replay) -> ((u64, [u8; 16]), (u64, [u8; 16])) {
    let mark = mark_of(replay).await;
    (
        (
            state_version_of(replay, &alice_id()).await,
            state_tag_of(replay, &alice_id()).await,
        ),
        (mark.state_version, mark.state_tag),
    )
}

#[tokio::test]
async fn test_recovery_enrollment_retry_after_a_failed_mark_move_moves_the_mark() {
    // A re-enrollment at a healthy account holds its `revoked_apps`, a counted write. Its
    // mark can't move after the commit: `503`. The exact retry finds the receipt, and its
    // `200` goes out only once the mark covers the account's count, so a restore that
    // loses the held App ID is behind, never healthy (Switch wire 7.3, "Moving it").
    use std::os::unix::fs::PermissionsExt;
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let count = state_version_of(&replay, &alice_id()).await;
    assert_eq!(mark_of(&replay).await.state_version, count);
    let at = replay.clock.now_ms() + 60_000;
    set_time(&replay.clock, &rfc3339(at));
    let body = alice_enrollment_body(&replay, 3, Some(vec![HELD_REVOKED]), None, at).await;
    // Reserve the enrollment's time so only the mark move after its commit can fail.
    let read = request(
        "GET",
        &format!("/v1/{}/identity", alice_id()),
        &[],
        Vec::new(),
    );
    assert_eq!(replay.service.handle(read).await.status, 200);
    let reserved = mark_of(&replay).await;
    assert!(reserved.time_floor_ms >= at);
    assert_eq!(reserved.state_version, count);
    let marks_dir = replay.key_dir().join("accounts").join("marks");
    std::fs::set_permissions(&marks_dir, std::fs::Permissions::from_mode(0o500))
        .expect("read-only");
    let failed = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", body.clone(), at))
        .await;
    std::fs::set_permissions(&marks_dir, std::fs::Permissions::from_mode(0o700)).expect("writable");
    assert_eq!(code(&failed), (503, "unavailable".into()));
    assert_eq!(held_and_kept(&replay).await, (1, 0), "the commit held");
    let ((state, _), (marked, _)) = count_and_mark(&replay).await;
    assert_eq!((state, marked), (count + 1, count));
    let retry = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", body, at))
        .await;
    assert_eq!(
        retry.status,
        200,
        "{}",
        String::from_utf8_lossy(&retry.body)
    );
    let (state, mark) = count_and_mark(&replay).await;
    assert_eq!(mark, state, "the mark at the account's count and tag");
    assert_eq!(state.0, count + 1, "the retry applied nothing again");
    // A restore to the count before the enrollment loses the held App ID: behind.
    sql_on(
        &replay,
        &alice_id(),
        &format!(
            "WITH gone AS (DELETE FROM held_revoked_apps WHERE account_id = $1) \
             UPDATE accounts SET state_version = {count} WHERE id = $1"
        ),
    )
    .await;
    let read = replay
        .service
        .handle(signer_request(
            "GET",
            &format!("/v1/{}/apps", alice_id()),
            Vec::new(),
            at,
        ))
        .await;
    assert_eq!(code(&read), (503, "recovery_required".to_string()));
    assert_eq!(json_of(&read)["current"]["reason"], "behind");
    replay.db.drop_database().await.expect("drop");
}

/// The key store of a service whose key changed (Switch spec 12.5): it signs every new
/// answer with `new`, and still holds the old key, which the accounts no generation start
/// has moved yet are answered with.
struct ChangedKey {
    old: std::sync::Arc<pubky_switch::keys::FileKeyStore>,
    new: pubky_switch::keys::ServiceSigner,
}

impl pubky_switch::keys::KeyStore for ChangedKey {
    fn current(&self) -> pubky_switch::keys::ServiceSigner {
        self.new.clone()
    }

    fn signer_for(&self, public: &[u8; 32]) -> Option<pubky_switch::keys::ServiceSigner> {
        use pubky_switch_core::signing::Signs;
        if *public == self.new.public_key() {
            Some(self.new.clone())
        } else {
            self.old.signer_for(public)
        }
    }

    fn generate_as<'a>(
        &'a self,
        id: &'a pubky_switch::keys::KeyId,
    ) -> pubky_switch::keys::KeyFuture<'a, pubky_switch::keys::ServiceKey> {
        self.old.generate_as(id)
    }

    fn public_key<'a>(
        &'a self,
        id: &'a pubky_switch::keys::KeyId,
    ) -> pubky_switch::keys::KeyFuture<'a, [u8; 32]> {
        self.old.public_key(id)
    }

    fn signer<'a>(
        &'a self,
        id: &'a pubky_switch::keys::KeyId,
    ) -> pubky_switch::keys::KeyFuture<'a, pubky_switch::keys::ServiceSigner> {
        self.old.signer(id)
    }

    fn delete<'a>(
        &'a self,
        id: &'a pubky_switch::keys::KeyId,
    ) -> pubky_switch::keys::KeyFuture<'a, ()> {
        self.old.delete(id)
    }
}

#[tokio::test]
async fn test_recovery_enrollment_after_a_service_key_change_keeps_the_marks_key() {
    // After a service key change, an enrollment's answer names the new key, but the
    // account is still answered with the key its document names: its mark moves to the
    // enrollment's count and keeps that key until a generation start names the new one
    // (Switch wire 7.3, Table 3).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let old_key = service_public(&replay);
    assert_eq!(mark_of(&replay).await.key, old_key);
    let new = pubky_switch::keys::ServiceSigner::new(std::sync::Arc::new(
        IdentityKey::from_secret([0x42; 32]),
    ));
    let new_key = {
        use pubky_switch_core::signing::Signs;
        new.public_key()
    };
    let service = pubky_switch::service::Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        std::sync::Arc::new(ChangedKey {
            old: replay.keys.clone(),
            new,
        }),
        replay.marks.clone(),
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    );
    let at = replay.clock.now_ms() + 60_000;
    set_time(&replay.clock, &rfc3339(at));
    let body = alice_enrollment_body(&replay, 3, Some(vec![HELD_REVOKED]), None, at).await;
    let answer = service
        .handle(signer_request("POST", "/v1/enroll", body, at))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(
        answered_key(&answer),
        new_key,
        "the answer names the new key"
    );
    let (state, marked) = count_and_mark(&replay).await;
    assert_eq!(marked, state, "the mark moved to the enrollment's count");
    assert_eq!(mark_of(&replay).await.key, old_key, "and kept its key");
    replay.db.drop_database().await.expect("drop");
}
