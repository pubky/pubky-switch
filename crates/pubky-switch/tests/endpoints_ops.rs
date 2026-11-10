//! `POST /v1/{id}/ops` on the service (Switch wire 6.4), against PostgreSQL: the callers and
//! their authentication, retries, the generation, no-ops and unchanged batches with a cursor,
//! the operation and control rates, the per-kind limits, trusted time, and a refused batch
//! leaving nothing behind.
//!
//! Each test starts from alice's account as `chain.json` builds it: `identity.json` version 3
//! and the wallet registered. Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see
//! `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::{
    http::Handler,
    limits::Limits,
    store::{ListName, StoredApp},
};
use pubky_switch_core::{
    claims::{ClaimFields, ClaimType},
    enc::pubky_key,
    http::header,
    keys::{AppKeys, IdentityKey, ReceiveKey},
    ops::{AllowKind, Condition, OpKind, OpsRequest, Position, SignedOp, sign_batch},
    records::{AppCert, AppCertBody, AppRecord, AppRecordBody, ReceiveKeyBody, ReceiveKeyRecord},
    sig::SignedDoc,
};
use serde_json::Value;
use sqlx::Connection;
use support::*;

/// The time of the tests' batches, after the registration.
const AT: &str = "2026-01-01T00:01:00.000Z";

fn alice_id() -> String {
    alice(&vectors("keys.json"))["pubky_id"]
        .as_str()
        .expect("id")
        .to_string()
}

fn alice_key() -> [u8; 32] {
    pubky_key(&alice_id()).expect("key")
}

/// Another identity's Pubky ID, for list entries.
fn bob() -> [u8; 32] {
    let keys = vectors("keys.json");
    let bob = keys["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] != "alice")
        .expect("another identity");
    pubky_key(bob["pubky_id"].as_str().expect("id")).expect("key")
}

fn ops_path() -> String {
    format!("/v1/{}/ops", alice_id())
}

/// alice's account with the wallet registered, as `chain.json`'s seqs 1 to 4 leave it.
async fn registered(limits: Limits, time_required: bool) -> Option<Replay> {
    let replay = replay_with_time(limits, time_required).await?;
    serve_alice(&replay).await;
    let chain = vectors("chain.json");
    let item = &chain["items"].as_array().expect("items")[2];
    let at = item_time(item);
    set_time(&replay.clock, &at);
    let ops: Vec<SignedOp> = [2, 3]
        .iter()
        .map(|i| {
            let signed: SignedDoc =
                serde_json::from_value(chain["items"][*i]["item"].clone()).expect("op");
            SignedOp::peek(&signed).expect("op")
        })
        .collect();
    let (status, body) = post_app(&replay, "wallet", &ops, None, &at).await;
    assert_eq!(status, 200, "registered: {body}");
    set_time(&replay.clock, AT);
    Some(replay)
}

/// A batch of the wallet's, with batch ID `[id; 16]`, at generation `generation`.
fn wallet_batch(id: u8, generation: u64, kinds: Vec<(Vec<Condition>, OpKind)>) -> Vec<SignedOp> {
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let key = ed25519_dalek::SigningKey::from_bytes(&hex32(&wallet["signing_secret_hex"]));
    let app_id: [u8; 16] = hex::decode(wallet["app_id_bytes_hex"].as_str().expect("hex"))
        .expect("hex")
        .try_into()
        .expect("16 bytes");
    sign_batch(
        &key,
        &alice_key(),
        Some(app_id),
        generation,
        [id; 16],
        kinds,
    )
    .expect("batch")
}

fn contact(pubky: [u8; 32]) -> (Vec<Condition>, OpKind) {
    (
        Vec::new(),
        OpKind::AllowPut {
            pubky,
            kind: AllowKind::Contact,
        },
    )
}

/// Post `ops` from the app `keys.json` names `app_name` at `at`: the status and the body.
async fn post_app(
    replay: &Replay,
    app_name: &str,
    ops: &[SignedOp],
    cursor: Option<Position>,
    at: &str,
) -> (u16, Value) {
    let (status, body, _) = post_app_with_head(replay, app_name, ops, cursor, at).await;
    (status, body)
}

/// [`post_app`], with the answer's `Switch-Head`.
async fn post_app_with_head(
    replay: &Replay,
    app_name: &str,
    ops: &[SignedOp],
    cursor: Option<Position>,
    at: &str,
) -> (u16, Value, Option<String>) {
    let keys = vectors("keys.json");
    let body = OpsRequest::new(ops, cursor).to_json();
    let request = app_request(app(&keys, app_name), "POST", &ops_path(), body, ms(at));
    answer_of(replay.service.handle(request).await)
}

fn answer_of(answer: pubky_switch::http::SwitchResponse) -> (u16, Value, Option<String>) {
    let head = header_text(&answer, header::HEAD).map(str::to_string);
    let body = serde_json::from_slice(&answer.body).unwrap_or(Value::Null);
    (answer.status, body, head)
}

/// The head `seq` an answer names.
fn head_seq(body: &Value) -> u64 {
    body["head"]["seq"].as_u64().expect("head seq")
}

async fn wallet_app(replay: &Replay) -> StoredApp {
    let mut txn = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    let keys = vectors("keys.json");
    let id = app(&keys, "wallet")["app_id_bytes_hex"]
        .as_str()
        .expect("hex")
        .to_string();
    txn.apps()
        .await
        .expect("apps")
        .into_iter()
        .find(|stored| hex::encode(stored.app_id) == id)
        .expect("the wallet")
}

#[tokio::test]
async fn test_ops_retry_returns_the_original_proofs() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    let ops = wallet_batch(1, 1, vec![contact(bob())]);
    let (status, first) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!(status, 200, "{first}");
    assert_eq!(first["proofs"].as_array().expect("proofs").len(), 1);
    assert_eq!(head_seq(&first), 5);
    // The same batch again: the same proofs, no new chain item.
    let (status, again) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["proofs"], first["proofs"]);
    assert_eq!(head_seq(&again), 5);
    // Its ID with other operations is a conflict.
    let reused = wallet_batch(1, 1, vec![contact(alice_key())]);
    let (status, body) = post_app(&replay, "wallet", &reused, None, AT).await;
    assert_eq!((status, body["code"].as_str()), (409, Some("conflict")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_stale_generation() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    let ops = wallet_batch(2, 2, vec![contact(bob())]);
    let (status, body) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["code"], "stale_generation");
    assert_eq!(body["current"]["generation"], 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_unchanged_batches_and_the_cursor() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    let held = wallet_app(&replay).await.record.expect("record");
    let app_put = || {
        wallet_batch(
            3,
            1,
            vec![(
                Vec::new(),
                OpKind::AppPut {
                    record: held.clone(),
                },
            )],
        )
    };
    // The held record again: a no-op, no proof and no chain item.
    let (status, body) = post_app(&replay, "wallet", &app_put(), None, AT).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["proofs"], Value::Array(Vec::new()));
    assert_eq!(head_seq(&body), 4);
    // With cursor.set: checked, the cursor moves, still no proof.
    let position = Position {
        generation: 1,
        seq: 4,
    };
    let (status, body) = post_app(&replay, "wallet", &app_put(), Some(position), AT).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["proofs"], Value::Array(Vec::new()));
    assert_eq!(wallet_app(&replay).await.cursor, Some(position));
    // A cursor past the newest seq, or at another generation, is 400.
    for bad in [
        Position {
            generation: 1,
            seq: 5,
        },
        Position {
            generation: 2,
            seq: 1,
        },
    ] {
        let (status, body) = post_app(&replay, "wallet", &app_put(), Some(bad), AT).await;
        assert_eq!(status, 400, "{body}");
    }
    assert_eq!(wallet_app(&replay).await.cursor, Some(position));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_callers_and_authentication() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    // The phone has no record: a first call without its app.put is 403 not_current.
    let keys = vectors("keys.json");
    let phone = app(&keys, "phone");
    let key = ed25519_dalek::SigningKey::from_bytes(&hex32(&phone["signing_secret_hex"]));
    let phone_id: [u8; 16] = hex::decode(phone["app_id_bytes_hex"].as_str().expect("hex"))
        .expect("hex")
        .try_into()
        .expect("16 bytes");
    let ops = sign_batch(
        &key,
        &alice_key(),
        Some(phone_id),
        1,
        [4; 16],
        vec![contact(bob())],
    )
    .expect("batch");
    let (status, body, head) = post_app_with_head(&replay, "phone", &ops, None, AT).await;
    assert_eq!((status, body["code"].as_str()), (403, Some("not_current")));
    assert!(head.is_none(), "nothing verified the request");

    // The wallet's batch, with the request signed by another key: 401 bad_signature.
    let ops = wallet_batch(5, 1, vec![contact(bob())]);
    let body = OpsRequest::new(&ops, None).to_json();
    let mut request = app_request(phone, "POST", &ops_path(), body, ms(AT));
    request.headers.insert(
        header::APP,
        app(&keys, "wallet")["app_id"]
            .as_str()
            .expect("id")
            .parse()
            .expect("header"),
    );
    let answer = replay.service.handle(request).await;
    let body: Value = serde_json::from_slice(&answer.body).expect("json");
    assert_eq!(
        (answer.status, body["code"].as_str()),
        (401, Some("bad_signature"))
    );
    assert!(header_text(&answer, header::HEAD).is_none());

    // An app of another identity: 403 not_admitted.
    let shop = app(&keys, "shop");
    let ops = OpsRequest::new(&wallet_batch(6, 1, vec![contact(bob())]), None).to_json();
    let mut request = app_request(shop, "POST", &ops_path(), ops, ms(AT));
    request.headers.insert(
        header::IDENTITY,
        shop["identity"]
            .as_str()
            .expect("identity")
            .parse()
            .expect("header"),
    );
    let answer = replay.service.handle(request).await;
    let body: Value = serde_json::from_slice(&answer.body).expect("json");
    assert_eq!(
        (answer.status, body["code"].as_str()),
        (403, Some("not_admitted"))
    );

    // The signer has no cursor.
    let request = signer_request(
        "POST",
        &ops_path(),
        OpsRequest::new(
            &[],
            Some(Position {
                generation: 1,
                seq: 1,
            }),
        )
        .to_json(),
        ms(AT),
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(answer.status, 400);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_control_rate() {
    let limits = Limits {
        control_per_min: 1,
        ..Limits::default()
    };
    let Some(replay) = registered(limits, false).await else {
        return;
    };
    // Removing what isn't there is a repeatable control mutation.
    let delete = |id| {
        wallet_batch(
            id,
            1,
            vec![(
                Vec::new(),
                OpKind::AllowDelete {
                    pubky: bob(),
                    kind: AllowKind::Contact,
                },
            )],
        )
    };
    let (status, body) = post_app(&replay, "wallet", &delete(7), None, AT).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = post_app(&replay, "wallet", &delete(8), None, AT).await;
    assert_eq!((status, body["code"].as_str()), (429, Some("rate_limited")));
    assert!(body["retry_after"].as_u64().is_some());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_list_quota() {
    let limits = Limits {
        max_contacts: 1,
        ..Limits::default()
    };
    let Some(replay) = registered(limits, false).await else {
        return;
    };
    let (status, body) = post_app(
        &replay,
        "wallet",
        &wallet_batch(9, 1, vec![contact(bob())]),
        None,
        AT,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    // The same entry again passes; a new one finds the list full.
    let (status, body) = post_app(
        &replay,
        "wallet",
        &wallet_batch(10, 1, vec![contact(bob())]),
        None,
        AT,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = post_app(
        &replay,
        "wallet",
        &wallet_batch(11, 1, vec![contact(alice_key())]),
        None,
        AT,
    )
    .await;
    assert_eq!(status, 429, "{body}");
    assert_eq!(body["code"], "quota_exceeded");
    assert_eq!(body["current"]["limit"], "contacts");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_refused_batch_leaves_nothing() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    // The contact is added, then an unknown invite code's delete refuses the whole batch.
    let ops = wallet_batch(
        12,
        1,
        vec![
            contact(bob()),
            (Vec::new(), OpKind::InviteCodeDelete { code_hash: [9; 32] }),
        ],
    );
    let (status, body) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));
    let mut txn = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    assert!(
        txn.list_entries(ListName::Contact, &[bob()])
            .await
            .expect("entries")
            .is_empty()
    );
    assert_eq!(txn.head().last_seq, 4);
    assert!(txn.batch_record(&[12; 16]).await.expect("batch").is_none());
    drop(txn);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_without_trusted_time() {
    let Some(replay) = registered(Limits::default(), true).await else {
        return;
    };
    // An attempt depends on the service's time.
    let attempt = OpKind::Claim(ClaimFields {
        claim_key: vec![7; 32],
        kind: ClaimType::Attempt,
        expected_step: 0,
        attempt_id: vec![8; 16],
        orphan_after: Some(60),
        deadline: None,
        basis: None,
        evidence_ref: None,
    });
    let (status, body) = post_app(
        &replay,
        "wallet",
        &wallet_batch(13, 1, vec![(Vec::new(), attempt)]),
        None,
        AT,
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (503, Some("unavailable")),
        "{body}"
    );
    // A list change doesn't.
    let (status, body) = post_app(
        &replay,
        "wallet",
        &wallet_batch(14, 1, vec![contact(bob())]),
        None,
        AT,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["proofs"][0]["sig"].as_str().map(str::len), Some(86));
    replay.db.drop_database().await.expect("drop");
}

/// The wallet's keys and the certificate its record carries.
async fn wallet_keys(replay: &Replay) -> (AppKeys, AppCert) {
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let app_keys = AppKeys::from_secrets(
        hex32(&wallet["signing_secret_hex"]),
        hex32(&wallet["bundle_secret_hex"]),
    );
    let record = wallet_app(replay).await.record.expect("record");
    let cert = AppRecord::verify(&record, &alice_key())
        .expect("record")
        .cert()
        .clone();
    (app_keys, cert)
}

fn receive_key_put(keys: &AppKeys, cert: &AppCert, n: u64, seed: u8) -> (Vec<Condition>, OpKind) {
    let key = ReceiveKey::from_secret(n, [seed; 32]);
    let record =
        ReceiveKeyRecord::sign(keys, cert, ReceiveKeyBody::new(cert, &key)).expect("record");
    (
        Vec::new(),
        OpKind::ReceiveKeyPut {
            record: record.signed().clone(),
        },
    )
}

/// A request claiming to be the wallet's, with a signature nobody made.
fn forged(at: &str) -> pubky_switch::http::SwitchRequest {
    let keys = vectors("keys.json");
    let body = OpsRequest::new(
        &[],
        Some(Position {
            generation: 1,
            seq: 0,
        }),
    )
    .to_json();
    let mut request = app_request(app(&keys, "wallet"), "POST", &ops_path(), body, ms(at));
    request.headers.insert(
        header::SIGNATURE,
        pubky_switch_core::enc::b64(&[7; 64])
            .parse()
            .expect("header"),
    );
    request
}

async fn stamped_time(replay: &Replay) -> i64 {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let at: i64 = sqlx::query_scalar("SELECT stamped_time_ms FROM accounts WHERE id = $1")
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("account");
    conn.close().await.expect("close");
    at
}

#[tokio::test]
async fn test_ops_unverified_app_takes_no_lock_and_changes_nothing() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    let before = stamped_time(&replay).await;
    // The account's lock is held: an unverified request is answered without it.
    let held = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        replay.service.handle(forged(AT)),
    )
    .await
    .expect("answered without waiting for the lock");
    drop(held);
    let (status, body, head) = answer_of(answer);
    assert_eq!(
        (status, body["code"].as_str()),
        (401, Some("bad_signature"))
    );
    assert!(head.is_none());
    assert_eq!(stamped_time(&replay).await, before, "nothing was stamped");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_unverified_app_at_a_staged_account_gets_no_head() {
    let Some(replay) = replay().await else { return };
    // Enrolled, with no identity.json yet: staged.
    let http = vectors("http.json");
    set_time(&replay.clock, AT);
    let enrollment = vector_request(named(&http["requests"], "signer: enrollment"));
    let mut enrollment = enrollment;
    let body = enrollment.body.clone();
    enrollment = signer_request("POST", "/v1/enroll", body.to_vec(), ms(AT));
    assert_eq!(replay.service.handle(enrollment).await.status, 200);
    let (status, body, head) = answer_of(replay.service.handle(forged(AT)).await);
    assert_ne!(status, 503, "{body}");
    assert!(head.is_none(), "no head before the caller verifies");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_every_kid_a_batch_registers_is_kept() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    let (keys, cert) = wallet_keys(&replay).await;
    let two = wallet_batch(
        15,
        1,
        vec![
            receive_key_put(&keys, &cert, 1, 41),
            receive_key_put(&keys, &cert, 2, 42),
        ],
    );
    let (status, body) = post_app(&replay, "wallet", &two, None, AT).await;
    assert_eq!(status, 200, "{body}");
    // The first key's kid again, under the next n: registered already.
    let again = wallet_batch(16, 1, vec![receive_key_put(&keys, &cert, 3, 41)]);
    let (status, body) = post_app(&replay, "wallet", &again, None, AT).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("bad_request")),
        "{body}"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_revoked_expired_and_unpermitted_apps() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    // A signer-only operation from an app: 403 permission_missing, with the head.
    let (_, cert) = wallet_keys(&replay).await;
    let cert_put = wallet_batch(
        17,
        1,
        vec![(
            Vec::new(),
            OpKind::CertPut {
                target_app_id: cert.app_id(),
                cert: cert.signed().clone(),
            },
        )],
    );
    let (status, body, head) = post_app_with_head(&replay, "wallet", &cert_put, None, AT).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (403, Some("permission_missing"))
    );
    assert!(head.is_some(), "the caller verified");
    // Revoked: 403 not_current.
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(
        "INSERT INTO kept_app_ids (account_id, app_id, reason, at_ms) VALUES ($1, $2, 'revoked', 0)",
    )
    .bind(alice_id())
    .bind(cert.app_id().as_slice())
    .execute(&mut conn)
    .await
    .expect("revoke");
    conn.close().await.expect("close");
    let ops = wallet_batch(19, 1, vec![contact(bob())]);
    let (status, body) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!((status, body["code"].as_str()), (403, Some("not_current")));
    // Expired too: 403 cert_expired, which comes before the standing. Last, as the stamped
    // time never goes back.
    let expired = "2026-12-01T00:00:00.000Z";
    set_time(&replay.clock, expired);
    let ops = wallet_batch(18, 1, vec![contact(bob())]);
    let (status, body) = post_app(&replay, "wallet", &ops, None, expired).await;
    assert_eq!((status, body["code"].as_str()), (403, Some("cert_expired")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_first_call_with_an_unlisted_certificate() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    // A certificate alice issued for an app her identity.json doesn't list.
    let keys = AppKeys::from_secrets([21; 32], [22; 32]);
    let alice = IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]));
    let cert = AppCert::issue(
        &alice,
        AppCertBody::new(
            alice_key(),
            keys.signing_public(),
            keys.bundle_public(),
            vec!["neutral".into()],
            &[],
            ms("2025-12-01T00:00:00.000Z"),
            ms("2026-06-01T00:00:00.000Z"),
        ),
    )
    .expect("cert");
    let record =
        AppRecord::sign(&keys, AppRecordBody::new(&cert, Vec::new(), ms(AT))).expect("record");
    let ops = sign_batch(
        &keys,
        &alice_key(),
        Some(cert.app_id()),
        1,
        [20; 16],
        vec![(
            Vec::new(),
            OpKind::AppPut {
                record: record.signed().clone(),
            },
        )],
    )
    .expect("batch");
    let caller = serde_json::json!({
        "app_id": pubky_switch_core::enc::zbase32_encode(&cert.app_id()),
        "signing_secret_hex": hex::encode([21u8; 32]),
    });
    let body = OpsRequest::new(&ops, None).to_json();
    let request = app_request(&caller, "POST", &ops_path(), body, ms(AT));
    let (status, body, _) = answer_of(replay.service.handle(request).await);
    assert_eq!(
        (status, body["code"].as_str()),
        (403, Some("not_current")),
        "{body}"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_operation_signature_failures_count_against_the_source() {
    let limits = Limits {
        auth_failures_per_source_per_min: 2,
        ..Limits::default()
    };
    let Some(replay) = registered(limits, false).await else {
        return;
    };
    // A request the wallet signed, carrying an operation whose signature doesn't verify.
    let keys = vectors("keys.json");
    let ops = wallet_batch(21, 1, vec![contact(bob())]);
    let mut entry = serde_json::to_value(ops[0].signed()).expect("op");
    entry["sig"] = Value::String(pubky_switch_core::enc::b64(&[9; 64]));
    let body = serde_json::to_vec(&serde_json::json!({ "ops": [entry] })).expect("body");
    let send = || {
        let mut request = app_request(
            app(&keys, "wallet"),
            "POST",
            &ops_path(),
            body.clone(),
            ms(AT),
        );
        request.source = Some(pubky_switch::http::source::NetworkSource::of(
            "203.0.113.7".parse().expect("ip"),
        ));
        request
    };
    let (status, body, _) = answer_of(replay.service.handle(send()).await);
    assert_eq!(
        (status, body["code"].as_str()),
        (401, Some("bad_signature"))
    );
    // One bad request counts once.
    let claimed = (
        alice_id(),
        alice_id(),
        Some(
            app(&keys, "wallet")["app_id"]
                .as_str()
                .expect("id")
                .to_string(),
        ),
    );
    assert_eq!(
        replay
            .service
            .failed_authentications()
            .claimed(&claimed, ms(AT)),
        1
    );
    let (status, _, _) = answer_of(replay.service.handle(send()).await);
    assert_eq!(status, 401, "the second of two");
    let (status, body, _) = answer_of(replay.service.handle(send()).await);
    assert_eq!(
        (status, body["code"].as_str()),
        (429, Some("rate_limited")),
        "{body}"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_refusal_after_writing_leaves_nothing_but_the_stamp() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    // The batch is chained, then keeping its claim entry fails.
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    for statement in [
        "CREATE FUNCTION refuse() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$ \
         LANGUAGE plpgsql",
        "CREATE TRIGGER refuse BEFORE INSERT ON claim_entries FOR EACH ROW EXECUTE FUNCTION refuse()",
    ] {
        sqlx::query(statement)
            .execute(&mut conn)
            .await
            .expect("trigger");
    }
    let attempt = OpKind::Claim(ClaimFields {
        claim_key: vec![7; 32],
        kind: ClaimType::Attempt,
        expected_step: 0,
        attempt_id: vec![8; 16],
        orphan_after: Some(60),
        deadline: None,
        basis: None,
        evidence_ref: None,
    });
    let ops = wallet_batch(22, 1, vec![contact(bob()), (Vec::new(), attempt)]);
    let (status, body) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (503, Some("unavailable")),
        "{body}"
    );
    let (last_seq, items, entries, claims, last_seen): (i64, i64, i64, i64, Option<i64>) =
        sqlx::query_as(
            "SELECT a.last_seq, \
             (SELECT count(*) FROM chain_items c WHERE c.account_id = a.id), \
             (SELECT count(*) FROM list_entries l WHERE l.account_id = a.id), \
             (SELECT count(*) FROM claims k WHERE k.account_id = a.id), \
             (SELECT max(last_seen_ms) FROM apps p WHERE p.account_id = a.id) \
             FROM accounts a WHERE a.id = $1",
        )
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("account");
    assert_eq!(
        (last_seq, items, entries, claims),
        (4, 4, 0, 0),
        "nothing kept"
    );
    assert_eq!(
        last_seen,
        Some(i64::try_from(ms(AT)).expect("time")),
        "the app was seen"
    );
    conn.close().await.expect("close");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_cursor_never_moves_back() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    let at = |seq| Position { generation: 1, seq };
    let (status, body) = post_app(&replay, "wallet", &[], Some(at(4)), AT).await;
    assert_eq!(status, 200, "{body}");
    // Behind the cursor: no error, and the cursor stays.
    let (status, body) = post_app(&replay, "wallet", &[], Some(at(2)), AT).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(wallet_app(&replay).await.cursor, Some(at(4)));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_ops_self_made_key_takes_no_lock() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    // A key of the caller's own, named by a record whose certificate alice never signed.
    let keys = AppKeys::from_secrets([31; 32], [32; 32]);
    let stranger = IdentityKey::from_secret([33; 32]);
    let cert = AppCert::issue(
        &stranger,
        AppCertBody::new(
            pubky_switch_core::signing::Signs::public_key(&stranger),
            keys.signing_public(),
            keys.bundle_public(),
            vec!["neutral".into()],
            &[],
            ms("2025-12-01T00:00:00.000Z"),
            ms("2026-06-01T00:00:00.000Z"),
        ),
    )
    .expect("cert");
    let record =
        AppRecord::sign(&keys, AppRecordBody::new(&cert, Vec::new(), ms(AT))).expect("record");
    let ops = sign_batch(
        &keys,
        &alice_key(),
        Some(cert.app_id()),
        1,
        [23; 16],
        vec![(
            Vec::new(),
            OpKind::AppPut {
                record: record.signed().clone(),
            },
        )],
    )
    .expect("batch");
    let caller = serde_json::json!({
        "app_id": pubky_switch_core::enc::zbase32_encode(&cert.app_id()),
        "signing_secret_hex": hex::encode([31u8; 32]),
    });
    let body = OpsRequest::new(&ops, None).to_json();
    let request = app_request(&caller, "POST", &ops_path(), body, ms(AT));
    let before = stamped_time(&replay).await;
    let held = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        replay.service.handle(request),
    )
    .await
    .expect("answered without waiting for the lock");
    drop(held);
    let (status, body, head) = answer_of(answer);
    assert_eq!(
        (status, body["code"].as_str()),
        (401, Some("bad_signature")),
        "{body}"
    );
    assert!(head.is_none());
    assert_eq!(stamped_time(&replay).await, before, "nothing was stamped");
    replay.db.drop_database().await.expect("drop");
}
