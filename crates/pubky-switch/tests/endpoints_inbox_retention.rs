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

#[tokio::test]
async fn test_inbox_an_entry_with_no_current_target_stays() {
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
    // Its only target stops being current: it stays, for the unreadable item that
    // replaces it, and the wallet's cursor moving changes nothing.
    drop_executor(&replay).await;
    move_cursor(&replay, "wallet", entry_seq(&replay).await).await;
    assert_eq!(entries(&replay).await, 1);
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
    // Not served, but still current: the entry it hasn't read counts for it.
    assert_eq!(status_of(&status, "wallet")["current"], json!(false));
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
