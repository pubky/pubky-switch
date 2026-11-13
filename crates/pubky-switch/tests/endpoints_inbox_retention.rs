//! `POST /inbox`'s retention, check order and flags, from #52's review: entries go once
//! every current target has passed them, whichever way a target stops being current; the
//! retry comes before any other check; `stale_key` only after admission; one app wrapped to
//! twice; flag hits only for other identities, at most `max_flags` kept.
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::{
    http::{Handler, SwitchResponse},
    limits::Limits,
};
use pubky_switch_core::{
    enc::unb64,
    envelope::{Recipient, seal},
    keys::AppKeys,
    ops::{AllowKind, OpKind, OpsRequest, Position, sign_batch},
    sig::SignedDoc,
};
use serde_json::{Value, json};
use sqlx::Connection;
use support::*;

fn alice_id() -> String {
    alice(&vectors("keys.json"))["pubky_id"]
        .as_str()
        .expect("id")
        .to_string()
}

fn at() -> String {
    item_time(chain_item(&vectors("chain.json"), 9))
}

fn body(answer: &SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body)
        .unwrap_or_else(|_| panic!("json: {}", String::from_utf8_lossy(&answer.body)))
}

fn code_of(answer: &SwitchResponse) -> (u16, Value) {
    (answer.status, body(answer)["code"].clone())
}

fn doc(name: &str) -> SignedDoc {
    serde_json::from_value(named(&vectors("documents.json")["documents"], name)["signed"].clone())
        .expect("document")
}

fn receive_public(name: &str) -> [u8; 32] {
    let keys = vectors("keys.json");
    unb64(
        app(&keys, name)["receive_key"]["public"]
            .as_str()
            .expect("public"),
    )
    .expect("b64")
    .try_into()
    .expect("32")
}

fn app_id_of(name: &str) -> [u8; 16] {
    pubky_switch_core::enc::app_id_decode(
        app(&vectors("keys.json"), name)["app_id"]
            .as_str()
            .expect("id"),
    )
    .expect("app id")
}

fn sealed_to(publics: &[[u8; 32]], byte: u8) -> Vec<u8> {
    let keys = vectors("keys.json");
    let recipients: Vec<Recipient> = publics.iter().map(|p| Recipient::new(*p)).collect();
    seal(
        &hex32(&alice(&keys)["public_hex"]),
        &recipients,
        &[byte; 100],
        false,
    )
    .expect("seal")
}

async fn sql_value(replay: &Replay, query: &str) -> i64 {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query_scalar(query)
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("value")
}

async fn apps_version(replay: &Replay) -> i64 {
    sql_value(replay, "SELECT apps_version FROM accounts WHERE id = $1").await
}

async fn from_shop(
    replay: &Replay,
    envelope: Vec<u8>,
    apps_version: Option<i64>,
    code: Option<&str>,
) -> SwitchResponse {
    let query = apps_version.map_or(String::new(), |v| format!("?apps_version={v}"));
    let path = format!("/v1/{}/inbox{query}", alice_id());
    let request = other_request("shop", ORIGIN, "POST", &path, envelope, code, ms(&at()));
    replay.service.handle(request).await
}

async fn from_wallet(replay: &Replay, envelope: Vec<u8>, apps_version: i64) -> SwitchResponse {
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/inbox?apps_version={apps_version}", alice_id());
    replay
        .service
        .handle(app_request(
            app(&keys, "wallet"),
            "POST",
            &path,
            envelope,
            ms(&at()),
        ))
        .await
}

async fn wallet_op(replay: &Replay, op: OpKind, batch: u8) {
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let ops = sign_batch(
        &AppKeys::from_secrets(
            hex32(&wallet["signing_secret_hex"]),
            hex32(&wallet["bundle_secret_hex"]),
        ),
        &hex32(&alice(&keys)["public_hex"]),
        Some(app_id_of("wallet")),
        1,
        [batch; 16],
        vec![(Vec::new(), op)],
    )
    .expect("batch");
    let path = format!("/v1/{}/ops", alice_id());
    let answer = replay
        .service
        .handle(app_request(
            wallet,
            "POST",
            &path,
            OpsRequest::new(&ops, None).to_json(),
            ms(&at()),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

async fn move_cursor(replay: &Replay, name: &str, seq: u64) {
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/ops", alice_id());
    let cursor = OpsRequest::new(&[], Some(Position { generation: 1, seq })).to_json();
    let answer = replay
        .service
        .handle(app_request(
            app(&keys, name),
            "POST",
            &path,
            cursor,
            ms(&at()),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

fn bob() -> Value {
    vectors("keys.json")["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == "bob")
        .cloned()
        .expect("bob")
}

async fn deliver_bob(replay: &Replay) {
    let path = format!("/v1/{}/peers", alice_id());
    let body = serde_json::to_vec(&doc("bob identity.json")).expect("body");
    let request = other_request("shop", ORIGIN, "PUT", &path, body, None, ms(&at()));
    let answer = replay.service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

async fn with_bob(replay: &Replay) {
    replay_chain_through_revoke(replay).await;
    wallet_op(
        replay,
        OpKind::AllowPut {
            pubky: hex32(&bob()["public_hex"]),
            kind: AllowKind::Contact,
        },
        61,
    )
    .await;
    deliver_bob(replay).await;
}

/// The executor registers its app record and receive key, so it can be a target.
async fn register_executor(replay: &Replay) {
    let keys = vectors("keys.json");
    let executor = app(&keys, "executor");
    let ops = sign_batch(
        &ed25519_dalek::SigningKey::from_bytes(&hex32(&executor["signing_secret_hex"])),
        &hex32(&alice(&keys)["public_hex"]),
        Some(app_id_of("executor")),
        1,
        [92; 16],
        vec![
            (
                Vec::new(),
                OpKind::AppPut {
                    record: doc("executor app record"),
                },
            ),
            (
                Vec::new(),
                OpKind::ReceiveKeyPut {
                    record: doc("executor receive key record"),
                },
            ),
        ],
    )
    .expect("batch");
    let path = format!("/v1/{}/ops", alice_id());
    let answer = replay
        .service
        .handle(app_request(
            executor,
            "POST",
            &path,
            OpsRequest::new(&ops, None).to_json(),
            ms(&at()),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

/// alice's signer delivers v4, v3 with `change`.
async fn deliver_alice_v4(
    replay: &Replay,
    change: impl FnOnce(&mut pubky_switch_core::records::IdentityBody),
) {
    let v3 = doc("alice identity.json");
    let mut body: pubky_switch_core::records::IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("body");
    body.version = 4;
    change(&mut body);
    let key = pubky_switch_core::keys::IdentityKey::from_secret(hex32(
        &alice(&vectors("keys.json"))["secret_hex"],
    ));
    let v4 = pubky_switch_core::records::IdentityDoc::sign(&key, body)
        .expect("sign")
        .signed()
        .clone();
    let delivery = pubky_switch_core::http::IdentityDelivery {
        identity: v4,
        prev: Some(v3.doc_hash().expect("hash")),
    }
    .to_json();
    let path = format!("/v1/{}/identity", alice_id());
    let answer = replay
        .service
        .handle(signer_request("PUT", &path, delivery, ms(&at())))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

async fn entries(replay: &Replay) -> i64 {
    sql_value(
        replay,
        "SELECT count(*) FROM inbox_entries WHERE account_id = $1",
    )
    .await
}

async fn entry_seq(replay: &Replay) -> u64 {
    u64::try_from(
        sql_value(
            replay,
            "SELECT max(seq) FROM inbox_entries WHERE account_id = $1",
        )
        .await,
    )
    .expect("seq")
}

async fn apps_status(replay: &Replay) -> Value {
    let path = format!("/v1/{}/apps", alice_id());
    body(
        &replay
            .service
            .handle(signer_request("GET", &path, Vec::new(), ms(&at())))
            .await,
    )
}

fn status_of<'a>(status: &'a Value, name: &str) -> &'a Value {
    status["apps"]
        .as_array()
        .expect("apps")
        .iter()
        .find(|s| s["app_id"] == app(&vectors("keys.json"), name)["app_id"])
        .expect("status")
}

/// The executor dropped from `apps` into `removed` by alice's version 4, never revoked.
async fn drop_executor(replay: &Replay) {
    let executor = app_id_of("executor");
    deliver_alice_v4(replay, |body| {
        body.apps.retain(|listed| listed.app_id != executor);
        body.removed.push(pubky_switch_core::records::RemovedApp {
            app_id: executor,
            distrust_from: 0,
        });
    })
    .await;
}

#[tokio::test]
async fn test_inbox_entries_released_when_a_target_is_dropped_by_delivery() {
    let Some(replay) = replay().await else { return };
    with_bob(&replay).await;
    register_executor(&replay).await;
    let version = apps_version(&replay).await;
    let both = [receive_public("wallet"), receive_public("executor")];
    // Entry A, which the wallet reads past: the executor holds it, its only unread target.
    let answer = from_shop(&replay, sealed_to(&both, 1), Some(version), None).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let a = entry_seq(&replay).await;
    move_cursor(&replay, "wallet", a).await;
    assert_eq!(entries(&replay).await, 1);
    let status = apps_status(&replay).await;
    assert_eq!(status_of(&status, "executor")["unread_entries"], 1);
    assert_eq!(status_of(&status, "executor")["sole_target_unread"], 0);
    // Entry B, which neither has read.
    let answer = from_shop(&replay, sealed_to(&both, 2), Some(version), None).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let b = entry_seq(&replay).await;
    // The signer drops the executor, with no revocation: it stops being current at once
    // (Switch wire 7.4.2), and A, which every current target has passed, goes at the
    // delivery itself.
    drop_executor(&replay).await;
    let status = apps_status(&replay).await;
    assert_eq!(status_of(&status, "executor")["current"], json!(false));
    assert_eq!(entries(&replay).await, 1);
    // B is the wallet's alone among current targets. It still targets the executor, which
    // hasn't read it: unread for both (Switch wire 7.4.12), and sole for the wallet only.
    assert_eq!(status_of(&status, "wallet")["unread_entries"], 1);
    assert_eq!(status_of(&status, "wallet")["sole_target_unread"], 1);
    assert_eq!(status_of(&status, "executor")["unread_entries"], 1);
    assert_eq!(status_of(&status, "executor")["sole_target_unread"], 0);
    // The wallet reads past B: it goes.
    move_cursor(&replay, "wallet", b).await;
    assert_eq!(entries(&replay).await, 0);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_revocation_releases_entries() {
    let Some(replay) = replay().await else { return };
    with_bob(&replay).await;
    register_executor(&replay).await;
    let version = apps_version(&replay).await;
    let answer = from_shop(
        &replay,
        sealed_to(&[receive_public("wallet"), receive_public("executor")], 7),
        Some(version),
        None,
    )
    .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let seq = entry_seq(&replay).await;
    move_cursor(&replay, "wallet", seq).await;
    assert_eq!(entries(&replay).await, 1, "the executor hasn't read it");
    let executor = app(&vectors("keys.json"), "executor")["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    let path = format!("/v1/{}/apps/{executor}/revoke", alice_id());
    let answer = replay
        .service
        .handle(signer_request("POST", &path, Vec::new(), ms(&at())))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(entries(&replay).await, 0);
    replay.db.drop_database().await.expect("drop");
}

/// The wallet's feed after `after`.
async fn wallet_feed(replay: &Replay, after: u64) -> Value {
    let request = app_request(
        app(&vectors("keys.json"), "wallet"),
        "GET",
        &format!("/v1/{}/feed?after=1:{after}", alice_id()),
        Vec::new(),
        ms(&at()),
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    body(&answer)
}

#[tokio::test]
async fn test_inbox_an_entry_with_no_current_target_becomes_unreadable() {
    let Some(replay) = replay().await else { return };
    with_bob(&replay).await;
    register_executor(&replay).await;
    let version = apps_version(&replay).await;
    let answer = from_shop(
        &replay,
        sealed_to(&[receive_public("executor")], 8),
        Some(version),
        None,
    )
    .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let entry_id = body(&answer)["entry_id"].clone();
    let entry = entry_seq(&replay).await;
    // Its only target stops being current through a delivery: in that request, after its
    // chain item, the entry becomes an unreadable item at a new seq, without its envelope,
    // with the entry's ID, sender and acceptance time (Switch wire 7.4.4).
    drop_executor(&replay).await;
    let unreadable = entry_seq(&replay).await;
    assert!(unreadable > entry, "a new seq");
    assert_eq!(
        sql_value(
            &replay,
            "SELECT count(*) FROM inbox_entries WHERE account_id = $1 \
             AND kind = 'unreadable' AND octet_length(envelope) = 0",
        )
        .await,
        1
    );
    // Shown to every current app: the wallet, which it never targeted.
    let feed = wallet_feed(&replay, entry).await;
    let item = feed["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["seq"] == unreadable)
        .cloned()
        .expect("the unreadable item");
    assert_eq!(item["type"], "unreadable");
    assert_eq!(item["entry_id"], entry_id);
    assert_eq!(item["sender"], bob()["pubky_id"]);
    assert!(item.get("envelope").is_none());
    // The wallet's cursor passing the entry's old seq keeps it; passing its own releases it.
    move_cursor(&replay, "wallet", entry).await;
    assert_eq!(entries(&replay).await, 1);
    move_cursor(&replay, "wallet", unreadable).await;
    assert_eq!(entries(&replay).await, 0);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_retry_comes_before_the_query() {
    let Some(replay) = replay().await else { return };
    with_bob(&replay).await;
    let version = apps_version(&replay).await;
    let envelope = sealed_to(&[receive_public("wallet")], 9);
    let first = from_shop(&replay, envelope.clone(), Some(version), None).await;
    assert_eq!(
        first.status,
        200,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    // The same envelope without apps_version: the stored answer, not 400.
    let retry = from_shop(&replay, envelope, None, None).await;
    assert_eq!(retry.status, 200);
    assert_eq!(retry.body, first.body);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_own_app_rate_refusal_flags_nobody() {
    let limits = Limits {
        sender_per_min: 0,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let version = apps_version(&replay).await;
    let answer = from_wallet(&replay, sealed_to(&[receive_public("wallet")], 3), version).await;
    assert_eq!(code_of(&answer), (429, json!("rate_limited")));
    assert_eq!(
        sql_value(
            &replay,
            "SELECT count(*) FROM sender_flags WHERE account_id = $1"
        )
        .await,
        0
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_dedupe_is_per_sender_identity() {
    let Some(replay) = replay().await else { return };
    with_bob(&replay).await;
    let version = apps_version(&replay).await;
    let envelope = sealed_to(&[receive_public("wallet")], 4);
    let own = from_wallet(&replay, envelope.clone(), version).await;
    assert_eq!(own.status, 200, "{}", String::from_utf8_lossy(&own.body));
    // The same bytes from bob: a new entry, with bob's own answer.
    let other = from_shop(&replay, envelope, Some(version), None).await;
    assert_eq!(
        other.status,
        200,
        "{}",
        String::from_utf8_lossy(&other.body)
    );
    assert_eq!(body(&other)["known_version"], 1);
    assert_ne!(body(&other)["entry_id"], body(&own)["entry_id"]);
    assert_eq!(entries(&replay).await, 2);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_stale_key_only_after_admission() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let version = apps_version(&replay).await;
    // Not admitted, with an unknown kid and an old apps_version: 403, and nothing of the
    // account's apps.
    let answer = from_shop(&replay, sealed_to(&[[9; 32]], 5), Some(version - 1), None).await;
    assert_eq!(code_of(&answer), (403, json!("not_admitted")));
    assert!(body(&answer).get("current").is_none());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_no_flag_or_rate_before_admission() {
    let limits = Limits {
        sender_per_min: 0,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let version = apps_version(&replay).await;
    let answer = from_shop(
        &replay,
        sealed_to(&[receive_public("wallet")], 6),
        Some(version),
        None,
    )
    .await;
    assert_eq!(code_of(&answer), (403, json!("not_admitted")));
    assert_eq!(
        sql_value(
            &replay,
            "SELECT count(*) FROM sender_flags WHERE account_id = $1"
        )
        .await,
        0
    );
    replay.db.drop_database().await.expect("drop");
}

/// A flag row for `pubky`, with `hits` and `last_hit_ms`.
async fn insert_flag(replay: &Replay, pubky: [u8; 32], hits: i64, last_hit_ms: i64) {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(
        "INSERT INTO sender_flags (account_id, pubky, hits, last_hit_ms) VALUES ($1, $2, $3, $4)",
    )
    .bind(alice_id())
    .bind(pubky.as_slice())
    .bind(hits)
    .bind(last_hit_ms)
    .execute(&mut conn)
    .await
    .expect("flag");
}

async fn flag_hits(replay: &Replay, pubky: [u8; 32]) -> i64 {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query_scalar(
        "SELECT coalesce(max(hits), 0)::BIGINT FROM sender_flags \
         WHERE account_id = $1 AND pubky = $2",
    )
    .bind(alice_id())
    .bind(pubky.as_slice())
    .fetch_one(&mut conn)
    .await
    .expect("hits")
}

#[tokio::test]
async fn test_inbox_flags_keep_the_most_frequent() {
    let limits = Limits {
        sender_per_min: 0,
        max_flags: 2,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    with_bob(&replay).await;
    let version = apps_version(&replay).await;
    let bob = hex32(&bob()["public_hex"]);
    // Two flagged senders: one frequent, one hit once, long ago.
    insert_flag(&replay, [1; 32], 5, 0).await;
    insert_flag(&replay, [2; 32], 1, 0).await;
    // bob's refusal is his first hit: as frequent as [2; 32], and later, so [2; 32] drops.
    let answer = from_shop(
        &replay,
        sealed_to(&[receive_public("wallet")], 10),
        Some(version),
        None,
    )
    .await;
    assert_eq!(code_of(&answer), (429, json!("rate_limited")));
    assert_eq!(flag_hits(&replay, bob).await, 1);
    assert_eq!(flag_hits(&replay, [1; 32]).await, 5);
    assert_eq!(flag_hits(&replay, [2; 32]).await, 0);
    // Two senders more frequent than bob: his next hit is his second, and he drops
    // himself, the least frequent.
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("DELETE FROM sender_flags WHERE account_id = $1")
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("clear");
    insert_flag(&replay, [1; 32], 5, 0).await;
    insert_flag(&replay, [3; 32], 4, 0).await;
    let answer = from_shop(
        &replay,
        sealed_to(&[receive_public("wallet")], 11),
        Some(version),
        None,
    )
    .await;
    assert_eq!(code_of(&answer), (429, json!("rate_limited")));
    assert_eq!(flag_hits(&replay, bob).await, 0);
    assert_eq!(
        sql_value(
            &replay,
            "SELECT count(*) FROM sender_flags WHERE account_id = $1"
        )
        .await,
        2
    );
    replay.db.drop_database().await.expect("drop");
}

/// The phone registers its app record and receive key, so it can be a target.
async fn register_phone(replay: &Replay, at_ms: u64) {
    let keys = vectors("keys.json");
    let phone = app(&keys, "phone");
    let ops = sign_batch(
        &ed25519_dalek::SigningKey::from_bytes(&hex32(&phone["signing_secret_hex"])),
        &hex32(&alice(&keys)["public_hex"]),
        Some(app_id_of("phone")),
        1,
        [93; 16],
        vec![
            (
                Vec::new(),
                OpKind::AppPut {
                    record: doc("phone app record"),
                },
            ),
            (
                Vec::new(),
                OpKind::ReceiveKeyPut {
                    record: doc("phone receive key record"),
                },
            ),
        ],
    )
    .expect("batch");
    let path = format!("/v1/{}/ops", alice_id());
    let answer = replay
        .service
        .handle(app_request(
            phone,
            "POST",
            &path,
            OpsRequest::new(&ops, None).to_json(),
            at_ms,
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

/// The signer renews the wallet's certificate, as a lapsed one is renewed (Switch spec 3.2):
/// `cert.put` with a key bundle part made for it, then version 4 of alice's `identity.json`
/// listing the new certificate, the earlier one renewed and open.
async fn renew_wallet(replay: &Replay, at: &str) {
    use pubky_switch_core::keys::IdentityKey;
    use pubky_switch_core::records::{AppCert, AppCertBody};
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let app_keys = AppKeys::from_secrets(
        hex32(&wallet["signing_secret_hex"]),
        hex32(&wallet["bundle_secret_hex"]),
    );
    let alice_key: [u8; 32] = hex32(&alice(&keys)["public_hex"]);
    let old = AppCert::verify(&doc("wallet certificate"), &alice_key).expect("old");
    let identity = IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let issued = ms(at) - 1_000;
    let renewed = AppCert::issue(
        &identity,
        AppCertBody::new(
            alice_key,
            app_keys.signing_public(),
            app_keys.bundle_public(),
            old.scopes().to_vec(),
            old.permissions(),
            issued,
            issued + 180 * 86_400_000,
        ),
    )
    .expect("cert");
    let part = pubky_switch_core::records::seal_bundle_parts(&identity, &renewed, 1, 1, &|_| true)
        .expect("bundle")
        .remove(0);
    let renewal = sign_batch(
        &identity,
        &alice_key,
        None,
        1,
        [94; 16],
        vec![
            (
                Vec::new(),
                OpKind::CertPut {
                    target_app_id: renewed.app_id(),
                    cert: renewed.signed().clone(),
                },
            ),
            (
                Vec::new(),
                OpKind::KeyBundlePut(pubky_switch_core::ops::KeyBundlePut {
                    target_app_id: renewed.app_id(),
                    bundle: part.bundle,
                    first_epoch: part.first_epoch,
                    last_epoch: part.last_epoch,
                }),
            ),
        ],
    )
    .expect("batch");
    let path = format!("/v1/{}/ops", alice_id());
    let answer = replay
        .service
        .handle(signer_request(
            "POST",
            &path,
            OpsRequest::new(&renewal, None).to_json(),
            ms(at),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let wallet_id = app_id_of("wallet");
    let new_hash = renewed.hash();
    let old_hash = old.hash();
    let v3 = doc("alice identity.json");
    let mut body: pubky_switch_core::records::IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("body");
    body.version = 4;
    if let Some(listed) = body
        .apps
        .iter_mut()
        .find(|listed| listed.app_id == wallet_id)
    {
        listed.cert = new_hash;
    }
    body.renewed.push(pubky_switch_core::records::RenewedCert {
        app_id: wallet_id,
        cert: old_hash,
        until: None,
    });
    let v4 = pubky_switch_core::records::IdentityDoc::sign(&identity, body)
        .expect("sign")
        .signed()
        .clone();
    let delivery = pubky_switch_core::http::IdentityDelivery {
        identity: v4,
        prev: Some(v3.doc_hash().expect("hash")),
    }
    .to_json();
    let answer = replay
        .service
        .handle(signer_request(
            "PUT",
            &format!("/v1/{}/identity", alice_id()),
            delivery,
            ms(at),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

#[tokio::test]
async fn test_inbox_entry_waits_for_a_target_whose_certificate_lapsed() {
    let Some(replay) = replay().await else { return };
    let chain = vectors("chain.json");
    serve_alice(&replay).await;
    replay_batch(&replay, &chain, &[3, 4]).await;
    assert_eq!(replay.db.give_out_seq(&alice_id()).await.expect("seq"), 5);
    replay_batch(&replay, &chain, &[6]).await;
    replay_batch(&replay, &chain, &[7, 8]).await;
    set_time(&replay.clock, &at());
    register_phone(&replay, ms(&at())).await;
    wallet_op(
        &replay,
        OpKind::AllowPut {
            pubky: hex32(&bob()["public_hex"]),
            kind: AllowKind::Contact,
        },
        61,
    )
    .await;
    deliver_bob(&replay).await;
    let version = apps_version(&replay).await;
    let answer = from_shop(
        &replay,
        sealed_to(&[receive_public("wallet"), receive_public("phone")], 12),
        Some(version),
        None,
    )
    .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let seq = entry_seq(&replay).await;
    // The wallet's certificate lapses (2026-12-01); the phone's runs to 2027-01-01.
    let later = "2026-12-01T00:00:10.000Z";
    set_time(&replay.clock, later);
    let status = body(
        &replay
            .service
            .handle(signer_request(
                "GET",
                &format!("/v1/{}/apps", alice_id()),
                Vec::new(),
                ms(later),
            ))
            .await,
    );
    // Lapsed, but still current: the entry it hasn't read counts for it, and
    // `cert_expires_at` shows the lapse.
    assert_eq!(status_of(&status, "wallet")["current"], json!(true));
    assert_eq!(
        status_of(&status, "wallet")["cert_expires_at"],
        "2026-12-01T00:00:00.000Z"
    );
    assert_eq!(status_of(&status, "wallet")["unread_entries"], 1);
    // The phone reads past the entry: it stays, waiting for the wallet.
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/ops", alice_id());
    let cursor = OpsRequest::new(&[], Some(Position { generation: 1, seq })).to_json();
    let answer = replay
        .service
        .handle(app_request(
            app(&keys, "phone"),
            "POST",
            &path,
            cursor,
            ms(later),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(entries(&replay).await, 1);
    // Still current, the wallet is a target: the phone's append wrapped to it is taken and
    // held for it too, and one that leaves it out, sealed before it was reachable, is stale
    // with the wallet among added_apps. Its expiry is the sender's own check.
    let from_phone = |envelope: Vec<u8>, apps_version: i64| {
        app_request(
            app(&keys, "phone"),
            "POST",
            &format!("/v1/{}/inbox?apps_version={apps_version}", alice_id()),
            envelope,
            ms(later),
        )
    };
    let answer = replay
        .service
        .handle(from_phone(sealed_to(&[receive_public("phone")], 14), 0))
        .await;
    assert_eq!(code_of(&answer), (409, json!("stale_key")));
    assert_eq!(
        body(&answer)["current"]["added_apps"][0]["app_id"],
        app(&keys, "wallet")["app_id"]
    );
    let answer = replay
        .service
        .handle(from_phone(
            sealed_to(&[receive_public("wallet"), receive_public("phone")], 13),
            version,
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let second = entry_seq(&replay).await;
    move_cursor_at(&replay, "phone", second, later).await;
    assert_eq!(entries(&replay).await, 2);
    // Renewed, the wallet reads it in its feed, then moves past it, and it goes.
    renew_wallet(&replay, later).await;
    let feed = body(
        &replay
            .service
            .handle(app_request(
                app(&keys, "wallet"),
                "GET",
                &format!("/v1/{}/feed?after=1:{}", alice_id(), seq - 1),
                Vec::new(),
                ms(later),
            ))
            .await,
    );
    assert!(
        feed["items"]
            .as_array()
            .expect("items")
            .iter()
            .any(|item| item["type"] == "entry" && item["seq"] == seq),
        "{feed}"
    );
    move_cursor_at(&replay, "wallet", second, later).await;
    assert_eq!(entries(&replay).await, 0);
    replay.db.drop_database().await.expect("drop");
}

async fn move_cursor_at(replay: &Replay, name: &str, seq: u64, at: &str) {
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/ops", alice_id());
    let cursor = OpsRequest::new(&[], Some(Position { generation: 1, seq })).to_json();
    let answer = replay
        .service
        .handle(app_request(app(&keys, name), "POST", &path, cursor, ms(at)))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

/// What one entry of the tests' envelopes counts against the inbox quota.
fn entry_bytes() -> u64 {
    u64::try_from(sealed_to(&[receive_public("executor")], 1).len()).expect("len")
        + Limits::default().entry_overhead_bytes
}

/// An inbox quota of four entries, and no sender share.
fn lagging_limits() -> Limits {
    Limits {
        quota_bytes: 4 * entry_bytes(),
        sender_share_percent: 100,
        ..Limits::default()
    }
}

/// alice's account with the wallet and the executor current, at an inbox quota of four
/// entries: each app's share is two (Switch wire 7.4.4). No sender share, so bob's shop
/// alone may fill it.
async fn lagging_replay() -> Option<Replay> {
    let replay = replay_with(lagging_limits()).await?;
    with_bob(&replay).await;
    register_executor(&replay).await;
    Some(replay)
}

/// bob's shop appends an envelope wrapped to the apps `names`.
async fn append_to(replay: &Replay, names: &[&str], byte: u8) {
    let publics: Vec<[u8; 32]> = names.iter().map(|name| receive_public(name)).collect();
    let version = apps_version(replay).await;
    let answer = from_shop(replay, sealed_to(&publics, byte), Some(version), None).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

async fn lagging(replay: &Replay, name: &str) -> bool {
    status_of(&apps_status(replay).await, name)["lagging"]
        .as_bool()
        .expect("lagging")
}

async fn count(replay: &Replay, kind: &str) -> i64 {
    sql_value(
        replay,
        &format!("SELECT count(*) FROM inbox_entries WHERE account_id = $1 AND kind = '{kind}'"),
    )
    .await
}

/// `name`'s feed after `after`.
async fn feed_of(replay: &Replay, name: &str, after: u64) -> Value {
    let request = app_request(
        app(&vectors("keys.json"), name),
        "GET",
        &format!("/v1/{}/feed?after=1:{after}", alice_id()),
        Vec::new(),
        ms(&at()),
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    body(&answer)
}

fn items_of<'a>(feed: &'a Value, kind: &str) -> Vec<&'a Value> {
    feed["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter(|item| item["type"] == kind)
        .collect()
}

#[tokio::test]
async fn test_inbox_a13_a_lagging_app_is_told_what_it_missed() {
    let Some(replay) = lagging_replay().await else {
        return;
    };
    let start = entry_seq_or(&replay, 0).await;
    // Two entries for the executor alone: within its share, it isn't marked.
    append_to(&replay, &["executor"], 1).await;
    append_to(&replay, &["executor"], 2).await;
    assert!(!lagging(&replay, "executor").await);
    assert_eq!(count(&replay, "entry").await, 2);
    // A third takes it past its share while the wallet is within its own: it is marked at
    // that append, and the entries only it held go, counted in its missed item.
    append_to(&replay, &["executor"], 3).await;
    assert!(lagging(&replay, "executor").await);
    assert!(!lagging(&replay, "wallet").await);
    assert_eq!(count(&replay, "entry").await, 0);
    assert_eq!(count(&replay, "missed").await, 1);
    // A missed item is no entry it hasn't read.
    let status = apps_status(&replay).await;
    assert_eq!(status_of(&status, "executor")["unread_entries"], 0);
    let first = entry_seq_or(&replay, 0).await;
    // A later miss before the executor passes its item replaces it, at a new seq, covering
    // both.
    append_to(&replay, &["executor"], 4).await;
    assert_eq!(count(&replay, "entry").await, 0);
    assert_eq!(count(&replay, "missed").await, 1);
    let second = entry_seq_or(&replay, 0).await;
    assert!(second > first, "a new seq");
    // The executor reads its feed: the item tells it what it missed, and its mark ends.
    let feed = feed_of(&replay, "executor", start).await;
    let missed = items_of(&feed, "missed");
    assert_eq!(missed.len(), 1, "{feed}");
    assert_eq!(missed[0]["seq"], second);
    assert_eq!(missed[0]["entries"], 4);
    assert_eq!(missed[0]["accepted_from"], at());
    assert_eq!(missed[0]["accepted_until"], at());
    assert!(items_of(&feed, "entry").is_empty());
    assert!(!lagging(&replay, "executor").await);
    // A13: the item waits for its app, marked or not: the wallet passing it changes
    // nothing, and it goes once the executor's cursor passes it.
    move_cursor(&replay, "wallet", second).await;
    assert_eq!(count(&replay, "missed").await, 1);
    assert!(items_of(&feed_of(&replay, "wallet", start).await, "missed").is_empty());
    move_cursor(&replay, "executor", second).await;
    assert_eq!(count(&replay, "missed").await, 0);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_a_lagging_apps_held_cursor_stays_while_its_entries_go() {
    // The entries a lagging app hasn't read go without its cursor moving (Switch spec 6.3):
    // its page reports the same `cursor` as before they came, equal to its position, and
    // only the `missed` item shows that they are gone (Switch spec 8.2, 8.3).
    let Some(replay) = lagging_replay().await else {
        return;
    };
    let position = chain_seq(&replay).await;
    move_cursor(&replay, "executor", position).await;
    let before = feed_of(&replay, "executor", position).await;
    assert_eq!(before["cursor"], position);
    for byte in 1..=3 {
        append_to(&replay, &["executor"], byte).await;
    }
    assert!(lagging(&replay, "executor").await);
    assert_eq!(count(&replay, "entry").await, 0);
    let after = feed_of(&replay, "executor", position).await;
    assert_eq!(after["cursor"], position, "the held cursor didn't move");
    assert!(items_of(&after, "entry").is_empty(), "{after}");
    let missed = items_of(&after, "missed");
    assert_eq!(missed.len(), 1, "{after}");
    assert_eq!(missed[0]["entries"], 3);
    replay.db.drop_database().await.expect("drop");
}

/// The newest seq the inbox holds, or `or` when it holds nothing.
async fn entry_seq_or(replay: &Replay, or: u64) -> u64 {
    let seq = sql_value(
        replay,
        "SELECT coalesce(max(seq), 0) FROM inbox_entries WHERE account_id = $1",
    )
    .await;
    u64::try_from(seq).ok().filter(|seq| *seq > 0).unwrap_or(or)
}

#[tokio::test]
async fn test_inbox_a14_no_app_is_marked_while_none_is_within_its_share() {
    let Some(replay) = lagging_replay().await else {
        return;
    };
    // The executor marked first.
    for byte in 1..=3 {
        append_to(&replay, &["executor"], byte).await;
    }
    assert!(lagging(&replay, "executor").await);
    // Entries for both apps until each is past its share: no current app is within it, so
    // none is marked and the executor's mark ends; the entries wait for both.
    for byte in 4..=6 {
        append_to(&replay, &["executor", "wallet"], byte).await;
    }
    assert!(!lagging(&replay, "executor").await);
    assert!(!lagging(&replay, "wallet").await);
    assert_eq!(count(&replay, "entry").await, 3);
    let newest = entry_seq(&replay).await;
    move_cursor(&replay, "wallet", newest).await;
    assert_eq!(
        count(&replay, "entry").await,
        3,
        "they wait for the executor too"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_without_trusted_time_entries_wait_for_lagging_apps() {
    let Some(replay) = lagging_replay().await else {
        return;
    };
    for byte in 1..=3 {
        append_to(&replay, &["executor"], byte).await;
    }
    assert!(lagging(&replay, "executor").await);
    // A fourth append, for both apps, then the wallet passes it at a service without
    // trusted time: the entry waits for the lagging executor, and no missed item is
    // written.
    append_to(&replay, &["executor", "wallet"], 4).await;
    let entry = entry_seq(&replay).await;
    let missed_before = count(&replay, "missed").await;
    let untrusted = replay.without_trusted_time();
    let request = app_request(
        app(&vectors("keys.json"), "wallet"),
        "POST",
        &format!("/v1/{}/ops", alice_id()),
        OpsRequest::new(
            &[],
            Some(Position {
                generation: 1,
                seq: entry,
            }),
        )
        .to_json(),
        ms(&at()),
    );
    let answer = untrusted.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(count(&replay, "entry").await, 1, "it waits");
    assert_eq!(count(&replay, "missed").await, missed_before);
    // With trusted time, the next release, at an append, lets it go into the executor's
    // missed item.
    append_to(&replay, &["wallet"], 5).await;
    assert_eq!(
        sql_value(
            &replay,
            &format!("SELECT count(*) FROM inbox_entries WHERE account_id = $1 AND seq = {entry}"),
        )
        .await,
        0
    );
    let missed = sql_value(
        &replay,
        "SELECT missed_entries FROM inbox_entries WHERE account_id = $1 AND kind = 'missed'",
    )
    .await;
    assert_eq!(missed, 4);
    replay.db.drop_database().await.expect("drop");
}

/// The newest chain item's seq.
async fn chain_seq(replay: &Replay) -> u64 {
    u64::try_from(sql_value(replay, "SELECT chain_seq FROM accounts WHERE id = $1").await)
        .expect("seq")
}

#[tokio::test]
async fn test_inbox_a_revocation_turns_entries_unread_by_others_unreadable() {
    let Some(replay) = replay().await else { return };
    with_bob(&replay).await;
    register_executor(&replay).await;
    append_to(&replay, &["executor"], 1).await;
    let entry = entry_seq(&replay).await;
    let executor = app(&vectors("keys.json"), "executor")["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    let answer = replay
        .service
        .handle(signer_request(
            "POST",
            &format!("/v1/{}/apps/{executor}/revoke", alice_id()),
            Vec::new(),
            ms(&at()),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    // After the revocation's chain item, in its request.
    let revoke = chain_seq(&replay).await;
    let unreadable = entry_seq(&replay).await;
    assert!(
        revoke > entry && unreadable > revoke,
        "{entry} {revoke} {unreadable}"
    );
    let feed = feed_of(&replay, "wallet", entry).await;
    let items = items_of(&feed, "unreadable");
    assert_eq!(items.len(), 1, "{feed}");
    assert_eq!(items[0]["seq"], unreadable);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_a_leave_turns_entries_unread_by_others_unreadable() {
    let Some(replay) = replay().await else { return };
    with_bob(&replay).await;
    register_executor(&replay).await;
    append_to(&replay, &["executor"], 1).await;
    let entry = entry_seq(&replay).await;
    let keys = vectors("keys.json");
    let executor = app(&keys, "executor");
    let path = format!(
        "/v1/{}/apps/{}/leave",
        alice_id(),
        executor["app_id"].as_str().expect("id")
    );
    let answer = replay
        .service
        .handle(app_request(executor, "POST", &path, Vec::new(), ms(&at())))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let leave = chain_seq(&replay).await;
    let unreadable = entry_seq(&replay).await;
    assert!(
        leave > entry && unreadable > leave,
        "{entry} {leave} {unreadable}"
    );
    assert_eq!(count(&replay, "unreadable").await, 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_an_earlier_entry_with_no_current_target_is_converted_once_found() {
    let Some(replay) = replay().await else { return };
    with_bob(&replay).await;
    register_executor(&replay).await;
    append_to(&replay, &["executor"], 1).await;
    // An entry left with no current target before departures converted them: wrapped to
    // the revoked phone alone.
    let phone = hex::encode(app_id_of("phone"));
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(&format!(
        "UPDATE inbox_entries SET targets = ARRAY[decode('{phone}', 'hex')] WHERE account_id = $1"
    ))
    .bind(alice_id())
    .execute(&mut conn)
    .await
    .expect("legacy");
    drop(conn);
    // Found at the next cursor move with trusted time: it becomes an unreadable item.
    let entry = entry_seq(&replay).await;
    move_cursor(&replay, "executor", entry).await;
    assert_eq!(count(&replay, "entry").await, 0);
    assert_eq!(count(&replay, "unreadable").await, 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_unreadable_items_count_for_no_senders_share() {
    // A sender's share of one entry exactly.
    let Some(replay) = replay_with(Limits {
        quota_bytes: 4 * entry_bytes(),
        sender_share_percent: 25,
        ..Limits::default()
    })
    .await
    else {
        return;
    };
    with_bob(&replay).await;
    register_executor(&replay).await;
    append_to(&replay, &["executor"], 1).await;
    let executor = app(&vectors("keys.json"), "executor")["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    let answer = replay
        .service
        .handle(signer_request(
            "POST",
            &format!("/v1/{}/apps/{executor}/revoke", alice_id()),
            Vec::new(),
            ms(&at()),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(count(&replay, "unreadable").await, 1);
    // bob's unreadable item counts against the inbox quota but not his share: his next
    // entry still fits it.
    append_to(&replay, &["wallet"], 2).await;
    replay.db.drop_database().await.expect("drop");
}

async fn revoke(replay: &Replay, name: &str) {
    let id = app(&vectors("keys.json"), name)["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    let answer = replay
        .service
        .handle(signer_request(
            "POST",
            &format!("/v1/{}/apps/{id}/revoke", alice_id()),
            Vec::new(),
            ms(&at()),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

/// bob's shop appends an envelope wrapped to `names`; the answer as it is.
async fn try_append(replay: &Replay, names: &[&str], byte: u8) -> SwitchResponse {
    let publics: Vec<[u8; 32]> = names.iter().map(|name| receive_public(name)).collect();
    let version = apps_version(replay).await;
    from_shop(replay, sealed_to(&publics, byte), Some(version), None).await
}

/// The reader departs while the other app is marked: a single current app is never marked
/// (Switch wire 7.4.4, spec 6.3), and the entries it alone holds wait for it.
#[tokio::test]
async fn test_inbox_a_lone_current_app_is_never_lagging() {
    let Some(replay) = lagging_replay().await else {
        return;
    };
    for byte in 1..=3 {
        append_to(&replay, &["executor"], byte).await;
    }
    assert!(lagging(&replay, "executor").await);
    // An entry for both, which waits for the wallet.
    append_to(&replay, &["executor", "wallet"], 4).await;
    assert_eq!(count(&replay, "entry").await, 1);
    let missed_before = sql_value(
        &replay,
        "SELECT coalesce(sum(missed_entries), 0)::BIGINT FROM inbox_entries \
         WHERE account_id = $1 AND kind = 'missed'",
    )
    .await;
    // The wallet is revoked: the executor is the only current app.
    revoke(&replay, "wallet").await;
    let missed_after = sql_value(
        &replay,
        "SELECT coalesce(sum(missed_entries), 0)::BIGINT FROM inbox_entries \
         WHERE account_id = $1 AND kind = 'missed'",
    )
    .await;
    let still_marked = lagging(&replay, "executor").await;
    let entries_left = count(&replay, "entry").await;
    // A new entry for the lone executor.
    append_to(&replay, &["executor"], 5).await;
    let entries_after_append = count(&replay, "entry").await;
    assert_eq!(
        (
            still_marked,
            entries_left,
            missed_after - missed_before,
            entries_after_append
        ),
        (false, 1, 0, 2),
        "(marked, entries after the revocation, entries missed at it, entries after an append)"
    );
    replay.db.drop_database().await.expect("drop");
}

/// A14, then the reader's return: with no app reading the inbox fills and senders get 429;
/// once the wallet reads everything, the next append judges the marks before its quota check
/// (Switch wire 7.4.4), marks the executor, and its entries stop holding the quota.
#[tokio::test]
async fn test_inbox_the_readers_return_frees_a_full_inbox() {
    let Some(replay) = lagging_replay().await else {
        return;
    };
    for byte in 1..=4 {
        append_to(&replay, &["executor", "wallet"], byte).await;
    }
    assert!(!lagging(&replay, "executor").await);
    assert_eq!(count(&replay, "entry").await, 4);
    // Full, nobody reading: 429 (A14).
    let (status, code) = code_of(&try_append(&replay, &["executor", "wallet"], 5).await);
    assert_eq!((status, code), (429, json!("quota_exceeded")));
    // The wallet reads everything and moves its cursor: the entries wait for the executor,
    // not marked, as before.
    let newest = entry_seq(&replay).await;
    move_cursor(&replay, "wallet", newest).await;
    assert_eq!(count(&replay, "entry").await, 4);
    // A reader is present now: the next append marks the executor (4 entries over a share
    // of 2), its entries go into its missed item, and the append fits.
    let answer = try_append(&replay, &["executor", "wallet"], 6).await;
    assert_eq!(
        answer.status,
        200,
        "{} (executor lagging: {})",
        String::from_utf8_lossy(&answer.body),
        lagging(&replay, "executor").await
    );
    replay.db.drop_database().await.expect("drop");
}

/// A delivery that leaves the set of current apps as it was judges no marks (Switch wire
/// 7.4.4): an app over its share that a reader's cursor moves left holding entries isn't
/// marked by it.
#[tokio::test]
async fn test_inbox_a_delivery_that_changes_no_current_app_sets_no_mark() {
    let Some(replay) = lagging_replay().await else {
        return;
    };
    for byte in 1..=3 {
        append_to(&replay, &["executor", "wallet"], byte).await;
    }
    // Both past their share: none marked (A14).
    assert!(!lagging(&replay, "executor").await);
    let newest = entry_seq(&replay).await;
    move_cursor(&replay, "wallet", newest).await;
    assert_eq!(count(&replay, "entry").await, 3);
    // The signer delivers version 4, its apps unchanged.
    deliver_alice_v4(&replay, |_| {}).await;
    assert_eq!(
        (
            lagging(&replay, "executor").await,
            count(&replay, "entry").await,
            count(&replay, "missed").await
        ),
        (false, 3, 0),
        "(executor marked, entries, missed items) after a delivery changing no current app"
    );
    replay.db.drop_database().await.expect("drop");
}

/// A marked app within its share isn't reading (Switch wire 7.4.4): the executor marked,
/// then the wallet past its share while the executor is within its own leaves no current app
/// reading, so no app is marked and the entries wait.
#[tokio::test]
async fn test_inbox_no_state_has_every_current_app_marked() {
    let Some(replay) = lagging_replay().await else {
        return;
    };
    append_to(&replay, &["executor", "wallet"], 1).await;
    let first = entry_seq(&replay).await;
    move_cursor(&replay, "executor", first).await;
    for byte in 2..=4 {
        append_to(&replay, &["executor"], byte).await;
    }
    assert!(lagging(&replay, "executor").await);
    assert_eq!(
        count(&replay, "entry").await,
        1,
        "the first waits for the wallet"
    );
    append_to(&replay, &["executor", "wallet"], 5).await;
    append_to(&replay, &["executor", "wallet"], 6).await;
    let both = lagging(&replay, "executor").await && lagging(&replay, "wallet").await;
    let left = count(&replay, "entry").await;
    assert_eq!(
        (both, left),
        (false, 3),
        "(both marked, entries after the 6th)"
    );
    replay.db.drop_database().await.expect("drop");
}

/// An unreadable item waits for every current app, a lagging one included (wire 9.1), and
/// counts the overhead only.
#[tokio::test]
async fn test_inbox_an_unreadable_item_waits_for_a_lagging_app() {
    let Some(replay) = lagging_replay().await else {
        return;
    };
    for byte in 1..=3 {
        append_to(&replay, &["executor"], byte).await;
    }
    assert!(lagging(&replay, "executor").await);
    append_to(&replay, &["wallet"], 4).await;
    let entry = entry_seq(&replay).await;
    // Left with no current target before this service converted such entries.
    let phone = hex::encode(app_id_of("phone"));
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(&format!(
        "UPDATE inbox_entries SET targets = ARRAY[decode('{phone}', 'hex')] \
         WHERE account_id = $1 AND kind = 'entry'"
    ))
    .bind(alice_id())
    .execute(&mut conn)
    .await
    .expect("legacy");
    drop(conn);
    move_cursor(&replay, "wallet", entry).await;
    assert_eq!(count(&replay, "unreadable").await, 1);
    let unreadable = u64::try_from(
        sql_value(
            &replay,
            "SELECT seq FROM inbox_entries WHERE account_id = $1 AND kind = 'unreadable'",
        )
        .await,
    )
    .expect("seq");
    assert!(unreadable > entry);
    assert_eq!(
        u64::try_from(
            sql_value(
                &replay,
                "SELECT quota_bytes FROM inbox_entries WHERE account_id = $1 \
                 AND kind = 'unreadable'",
            )
            .await
        )
        .expect("bytes"),
        Limits::default().entry_overhead_bytes
    );
    // The wallet passes it; the lagging executor hasn't: it stays.
    move_cursor(&replay, "wallet", unreadable).await;
    assert_eq!(
        count(&replay, "unreadable").await,
        1,
        "it waits for the executor"
    );
    // The executor's feed shows it, and once its cursor passes, it goes.
    let feed = feed_of(&replay, "executor", 0).await;
    assert_eq!(items_of(&feed, "unreadable").len(), 1, "{feed}");
    move_cursor(&replay, "executor", unreadable).await;
    assert_eq!(count(&replay, "unreadable").await, 0);
    replay.db.drop_database().await.expect("drop");
}

/// A departed app's mark ends with its departure (Switch wire 7.4.4).
#[tokio::test]
async fn test_inbox_a_departed_apps_mark_ends() {
    let Some(replay) = lagging_replay().await else {
        return;
    };
    for byte in 1..=3 {
        append_to(&replay, &["executor"], byte).await;
    }
    assert!(lagging(&replay, "executor").await);
    revoke(&replay, "executor").await;
    let status = apps_status(&replay).await;
    let executor = status_of(&status, "executor");
    assert_eq!(executor["current"], false);
    // Its missed item goes with it.
    assert_eq!(count(&replay, "missed").await, 0);
    assert_eq!(executor["lagging"], false, "{executor}");
    replay.db.drop_database().await.expect("drop");
}

/// A departed app's `missed` item goes with it.
#[tokio::test]
async fn test_inbox_a_departed_apps_missed_item_goes() {
    let Some(replay) = lagging_replay().await else {
        return;
    };
    for byte in 1..=3 {
        append_to(&replay, &["executor"], byte).await;
    }
    assert_eq!(count(&replay, "missed").await, 1);
    revoke(&replay, "executor").await;
    assert_eq!(count(&replay, "missed").await, 0);
    replay.db.drop_database().await.expect("drop");
}

/// An entry left with no current target before departures converted them waits for a
/// cursor move with trusted time: one without it converts nothing (wire 7.4.4).
#[tokio::test]
async fn test_inbox_an_old_ownerless_entry_is_converted_only_with_trusted_time() {
    let Some(replay) = replay().await else { return };
    with_bob(&replay).await;
    register_executor(&replay).await;
    append_to(&replay, &["executor"], 1).await;
    let phone = hex::encode(app_id_of("phone"));
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(&format!(
        "UPDATE inbox_entries SET targets = ARRAY[decode('{phone}', 'hex')] WHERE account_id = $1"
    ))
    .bind(alice_id())
    .execute(&mut conn)
    .await
    .expect("legacy");
    drop(conn);
    let entry = entry_seq(&replay).await;
    let untrusted = replay.without_trusted_time();
    let request = app_request(
        app(&vectors("keys.json"), "executor"),
        "POST",
        &format!("/v1/{}/ops", alice_id()),
        OpsRequest::new(
            &[],
            Some(Position {
                generation: 1,
                seq: entry,
            }),
        )
        .to_json(),
        ms(&at()),
    );
    let answer = untrusted.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(count(&replay, "entry").await, 1);
    assert_eq!(count(&replay, "unreadable").await, 0);
    replay.db.drop_database().await.expect("drop");
}

/// Unreadable items the app hasn't passed count in its unread bytes, overhead each (wire
/// 7.4.4): enough of them take the executor past its share, and it is marked.
#[tokio::test]
async fn test_inbox_unreadable_items_count_in_unread_bytes() {
    let Some(replay) = lagging_replay().await else {
        return;
    };
    let n = 2 * entry_bytes() / Limits::default().entry_overhead_bytes + 1;
    let phone = hex::encode(app_id_of("phone"));
    for i in 0..n {
        append_to(&replay, &["wallet"], u8::try_from(i + 1).expect("byte")).await;
        let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        sqlx::query(&format!(
            "UPDATE inbox_entries SET targets = ARRAY[decode('{phone}', 'hex')] \
             WHERE account_id = $1 AND kind = 'entry'"
        ))
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("legacy");
        drop(conn);
        let newest = entry_seq(&replay).await;
        move_cursor(&replay, "wallet", newest).await;
    }
    assert_eq!(
        count(&replay, "unreadable").await,
        i64::try_from(n).expect("n")
    );
    let newest = entry_seq(&replay).await;
    move_cursor(&replay, "wallet", newest).await;
    append_to(&replay, &["wallet"], 200).await;
    assert!(
        lagging(&replay, "executor").await,
        "over its share by unreadable items alone"
    );
    assert!(!lagging(&replay, "wallet").await);
    replay.db.drop_database().await.expect("drop");
}

/// An entry a lagging app has passed is no miss of its when it goes.
#[tokio::test]
async fn test_inbox_an_entry_a_lagging_app_passed_is_no_miss() {
    let Some(replay) = lagging_replay().await else {
        return;
    };
    append_to(&replay, &["executor", "wallet"], 1).await;
    let first = entry_seq(&replay).await;
    move_cursor(&replay, "executor", first).await;
    for byte in 2..=4 {
        append_to(&replay, &["executor"], byte).await;
    }
    assert!(lagging(&replay, "executor").await);
    move_cursor(&replay, "wallet", first).await;
    assert_eq!(count(&replay, "entry").await, 0);
    let missed = sql_value(
        &replay,
        "SELECT missed_entries FROM inbox_entries WHERE account_id = $1 AND kind = 'missed'",
    )
    .await;
    assert_eq!(missed, 3);
    replay.db.drop_database().await.expect("drop");
}

/// A later miss replaces the item with one from the earliest to the latest acceptance time.
#[tokio::test]
async fn test_inbox_a_merged_miss_spans_both_times() {
    let Some(replay) = lagging_replay().await else {
        return;
    };
    for byte in 1..=3 {
        append_to(&replay, &["executor"], byte).await;
    }
    assert!(lagging(&replay, "executor").await);
    let first = ms(&at());
    let later = first + 60_000;
    set_time(&replay.clock, &pubky_switch_core::time::rfc3339(later));
    let version = apps_version(&replay).await;
    let path = format!("/v1/{}/inbox?apps_version={version}", alice_id());
    let request = other_request(
        "shop",
        ORIGIN,
        "POST",
        &path,
        sealed_to(&[receive_public("executor")], 9),
        None,
        later,
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let row = |column: &str| {
        format!("SELECT {column} FROM inbox_entries WHERE account_id = $1 AND kind = 'missed'")
    };
    assert_eq!(sql_value(&replay, &row("missed_entries")).await, 4);
    assert_eq!(
        sql_value(&replay, &row("missed_from_ms")).await,
        i64::try_from(first).expect("ms")
    );
    assert_eq!(
        sql_value(&replay, &row("missed_until_ms")).await,
        i64::try_from(later).expect("ms")
    );
    replay.db.drop_database().await.expect("drop");
}

/// bob's shop appends an envelope wrapped to `names` at `service`.
async fn append_at(
    replay: &Replay,
    service: &pubky_switch::service::Service,
    names: &[&str],
    byte: u8,
) {
    let publics: Vec<[u8; 32]> = names.iter().map(|name| receive_public(name)).collect();
    let version = apps_version(replay).await;
    let path = format!("/v1/{}/inbox?apps_version={version}", alice_id());
    let request = other_request(
        "shop",
        ORIGIN,
        "POST",
        &path,
        sealed_to(&publics, byte),
        None,
        ms(&at()),
    );
    let answer = service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

/// The signer revokes `name` at `service`.
async fn revoke_at(service: &pubky_switch::service::Service, name: &str) {
    let id = app(&vectors("keys.json"), name)["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    let answer = service
        .handle(signer_request(
            "POST",
            &format!("/v1/{}/apps/{id}/revoke", alice_id()),
            Vec::new(),
            ms(&at()),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

/// Three current apps, and three entries for the executor alone appended at a service that
/// marks no app, so the executor is over its share and unmarked.
async fn three_apps_with_a_backlog() -> Option<Replay> {
    let replay = replay_with(lagging_limits()).await?;
    // The chain before the phone's revocation, so the wallet, the phone and the executor
    // are current.
    let chain = vectors("chain.json");
    serve_alice(&replay).await;
    replay_batch(&replay, &chain, &[3, 4]).await;
    // Seq 5 is the chain's inbox entry.
    replay.db.give_out_seq(&alice_id()).await.expect("seq");
    replay_batch(&replay, &chain, &[6]).await;
    replay_batch(&replay, &chain, &[7, 8]).await;
    set_time(&replay.clock, &at());
    register_phone(&replay, ms(&at())).await;
    register_executor(&replay).await;
    wallet_op(
        &replay,
        OpKind::AllowPut {
            pubky: hex32(&bob()["public_hex"]),
            kind: AllowKind::Contact,
        },
        61,
    )
    .await;
    deliver_bob(&replay).await;
    let quiet = replay.restarted_with(Limits {
        mark_lagging: false,
        ..lagging_limits()
    });
    for byte in 1..=3 {
        append_at(&replay, &quiet, &["executor"], byte).await;
    }
    assert!(!lagging(&replay, "executor").await);
    Some(replay)
}

/// A revocation that changes the set of current apps judges the marks for the new shares
/// (Switch wire 7.4.4): the executor, over its share with the wallet reading, is marked, and
/// the entries only it held go into its `missed` item.
#[tokio::test]
async fn test_inbox_a_departure_judges_the_marks() {
    let Some(replay) = three_apps_with_a_backlog().await else {
        return;
    };
    revoke_at(&replay.service, "phone").await;
    assert!(lagging(&replay, "executor").await);
    assert_eq!(count(&replay, "entry").await, 0);
    assert_eq!(count(&replay, "missed").await, 1);
    replay.db.drop_database().await.expect("drop");
}

/// The same revocation without trusted time sets no mark, and the entries wait (Switch wire
/// 7.4.4).
#[tokio::test]
async fn test_inbox_a_departure_without_trusted_time_sets_no_marks() {
    let Some(replay) = three_apps_with_a_backlog().await else {
        return;
    };
    revoke_at(&replay.without_trusted_time_with(lagging_limits()), "phone").await;
    assert!(!lagging(&replay, "executor").await);
    assert_eq!(count(&replay, "entry").await, 3);
    assert_eq!(count(&replay, "missed").await, 0);
    replay.db.drop_database().await.expect("drop");
}

/// An own app's append on `service`.
async fn own_append_at(
    replay: &Replay,
    service: &pubky_switch::service::Service,
    name: &str,
    names: &[&str],
    byte: u8,
) -> SwitchResponse {
    let publics: Vec<[u8; 32]> = names.iter().map(|name| receive_public(name)).collect();
    let version = apps_version(replay).await;
    service
        .handle(app_request(
            app(&vectors("keys.json"), name),
            "POST",
            &format!("/v1/{}/inbox?apps_version={version}", alice_id()),
            sealed_to(&publics, byte),
            ms(&at()),
        ))
        .await
}

/// The judgement an append makes before its quota check is undone with the append when a
/// later check refuses it: no mark, no `missed` item, no deletion stays.
#[tokio::test]
async fn test_inbox_a_refused_append_keeps_nothing_of_its_judgement() {
    let limits = Limits {
        quota_bytes: 4 * entry_bytes(),
        sender_share_percent: 50,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits.clone()).await else {
        return;
    };
    with_bob(&replay).await;
    register_executor(&replay).await;
    let quiet = replay.restarted_with(Limits {
        mark_lagging: false,
        ..limits
    });
    // bob holds his share: two entries for both apps, which wait for the wallet.
    append_at(&replay, &quiet, &["executor", "wallet"], 1).await;
    append_at(&replay, &quiet, &["executor", "wallet"], 2).await;
    // The wallet's own two entries for the executor: the executor is over its share,
    // unmarked; the wallet is within its own, reading.
    for byte in 3..=4 {
        let answer = own_append_at(&replay, &quiet, "wallet", &["executor"], byte).await;
        assert_eq!(
            answer.status,
            200,
            "{}",
            String::from_utf8_lossy(&answer.body)
        );
    }
    assert!(!lagging(&replay, "executor").await);
    assert_eq!(count(&replay, "entry").await, 4);
    // bob again: the judgement before the quota check would mark the executor and let the
    // wallet's two entries go; then bob's share refuses him, and all of it is undone.
    let publics = [receive_public("executor"), receive_public("wallet")];
    let version = apps_version(&replay).await;
    let answer = from_shop(&replay, sealed_to(&publics, 5), Some(version), None).await;
    let (status, code) = code_of(&answer);
    assert_eq!((status, code), (429, json!("quota_exceeded")));
    assert_eq!(body(&answer)["current"]["limit"], json!("sender_share"));
    assert_eq!(
        (
            lagging(&replay, "executor").await,
            count(&replay, "entry").await,
            count(&replay, "missed").await
        ),
        (false, 4, 0)
    );
    // Control: an append the same judgement lets through (alice's own share is freed by
    // the deletions it makes) keeps what it deleted: the wallet's two entries are in the
    // executor's missed item. The judgement after the add finds the wallet past its share
    // with the executor marked, so no app reads and the mark ends in the same request.
    let answer = own_append_at(&replay, &replay.service, "executor", &["wallet"], 6).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(count(&replay, "missed").await, 1);
    assert_eq!(count(&replay, "entry").await, 3);
    assert!(!lagging(&replay, "executor").await);
    replay.db.drop_database().await.expect("drop");
}

/// An append without trusted time judges no marks, before its quota check or after its add
/// (Switch wire 7.4.4).
#[tokio::test]
async fn test_inbox_an_append_without_trusted_time_sets_no_marks() {
    let Some(replay) = lagging_replay().await else {
        return;
    };
    let untrusted = replay.without_trusted_time_with(lagging_limits());
    for byte in 1..=4 {
        append_at(&replay, &untrusted, &["executor"], byte).await;
    }
    assert!(!lagging(&replay, "executor").await);
    assert_eq!(count(&replay, "entry").await, 4);
    assert_eq!(count(&replay, "missed").await, 0);
    replay.db.drop_database().await.expect("drop");
}

/// alice's signer delivers `version`, `prev` with `change`, at `service`: the document.
async fn deliver_alice_at(
    service: &pubky_switch::service::Service,
    prev: &SignedDoc,
    version: u64,
    change: impl FnOnce(&mut pubky_switch_core::records::IdentityBody),
) -> SignedDoc {
    let mut body: pubky_switch_core::records::IdentityBody =
        serde_json::from_slice(&prev.body_bytes().expect("body")).expect("body");
    body.version = version;
    change(&mut body);
    let key = pubky_switch_core::keys::IdentityKey::from_secret(hex32(
        &alice(&vectors("keys.json"))["secret_hex"],
    ));
    let next = pubky_switch_core::records::IdentityDoc::sign(&key, body)
        .expect("sign")
        .signed()
        .clone();
    let delivery = pubky_switch_core::http::IdentityDelivery {
        identity: next.clone(),
        prev: Some(prev.doc_hash().expect("hash")),
    }
    .to_json();
    let path = format!("/v1/{}/identity", alice_id());
    let answer = service
        .handle(signer_request("PUT", &path, delivery, ms(&at())))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    next
}

/// A delivery that swaps one current app for another changes the set of current apps,
/// whatever their number: its marks are judged (Switch wire 7.4.4). The phone leaves at a
/// service that marks no app; then a delivery lists it again in the wallet's place, two
/// current apps before and after, and the executor, over its share with the phone reading,
/// is marked.
#[tokio::test]
async fn test_inbox_a_delivery_swapping_current_apps_judges_the_marks() {
    let Some(replay) = three_apps_with_a_backlog().await else {
        return;
    };
    let quiet = replay.restarted_with(Limits {
        mark_lagging: false,
        ..lagging_limits()
    });
    let id = |name: &str| app_id_of(name);
    let v3 = doc("alice identity.json");
    let phone = v3_entry(&v3, id("phone"));
    let v4 = deliver_alice_at(&quiet, &v3, 4, |body| {
        body.apps.retain(|listed| listed.app_id != id("phone"));
    })
    .await;
    assert!(!lagging(&replay, "executor").await);
    deliver_alice_at(&replay.service, &v4, 5, |body| {
        body.apps.retain(|listed| listed.app_id != id("wallet"));
        body.apps.push(phone);
    })
    .await;
    assert!(lagging(&replay, "executor").await);
    replay.db.drop_database().await.expect("drop");
}

/// `app`'s entry in the `apps` of `doc`.
fn v3_entry(doc: &SignedDoc, app: [u8; 16]) -> pubky_switch_core::records::ListedApp {
    let body: pubky_switch_core::records::IdentityBody =
        serde_json::from_slice(&doc.body_bytes().expect("body")).expect("body");
    body.apps
        .into_iter()
        .find(|listed| listed.app_id == app)
        .expect("listed")
}
