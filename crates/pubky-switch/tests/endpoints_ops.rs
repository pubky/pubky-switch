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

    // An app of another identity: authenticated by its certificate first (Switch wire
    // 7.2), so 400 without one, then 403 not_admitted.
    let shop = app(&keys, "shop");
    let ops = OpsRequest::new(&wallet_batch(6, 1, vec![contact(bob())]), None).to_json();
    let mut request = app_request(shop, "POST", &ops_path(), ops.clone(), ms(AT));
    request.headers.insert(
        header::IDENTITY,
        shop["identity"]
            .as_str()
            .expect("identity")
            .parse()
            .expect("header"),
    );
    assert_eq!(replay.service.handle(request).await.status, 400);
    let request = other_request("shop", ORIGIN, "POST", &ops_path(), ops, None, ms(AT));
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
async fn test_ops_signer_renews_an_app_whose_certificate_expired() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    let (app_keys, old) = wallet_keys(&replay).await;
    // The wallet's certificate has expired: it is refused.
    let expired = "2026-12-01T00:00:00.000Z";
    set_time(&replay.clock, expired);
    let ops = wallet_batch(30, 1, vec![contact(bob())]);
    let (status, body) = post_app(&replay, "wallet", &ops, None, expired).await;
    assert_eq!((status, body["code"].as_str()), (403, Some("cert_expired")));
    // The signer's renewal, a cert.put and the first part of a full bundle made for it, in
    // one batch: taken although identity.json still lists the expired certificate (Switch
    // wire 3.8 step 1, 6.2).
    let alice = IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]));
    let issued = ms(expired) - 1_000;
    let renewed = AppCert::issue(
        &alice,
        AppCertBody::new(
            alice_key(),
            app_keys.signing_public(),
            app_keys.bundle_public(),
            old.scopes().to_vec(),
            old.permissions(),
            issued,
            issued + 180 * 86_400_000,
        ),
    )
    .expect("cert");
    let part = pubky_switch_core::records::seal_bundle_parts(&alice, &renewed, 1, 1, &|_| true)
        .expect("bundle")
        .remove(0);
    let renewal = sign_batch(
        &alice,
        &alice_key(),
        None,
        1,
        [31; 16],
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
    let request = signer_request(
        "POST",
        &ops_path(),
        OpsRequest::new(&renewal, None).to_json(),
        ms(expired),
    );
    let (status, body, _) = answer_of(replay.service.handle(request).await);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["proofs"].as_array().map(Vec::len), Some(2));
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

fn claim(kind: ClaimType, expected_step: u64, deadline: Option<u64>) -> (Vec<Condition>, OpKind) {
    claim_at(7, kind, expected_step, deadline)
}

/// A claim entry of the claim key `[key; 32]`.
fn claim_at(
    key: u8,
    kind: ClaimType,
    expected_step: u64,
    deadline: Option<u64>,
) -> (Vec<Condition>, OpKind) {
    (
        Vec::new(),
        OpKind::Claim(ClaimFields {
            claim_key: vec![key; 32],
            kind,
            expected_step,
            attempt_id: vec![8; 16],
            orphan_after: (kind == ClaimType::Attempt).then_some(60),
            deadline,
            basis: (kind == ClaimType::Done).then_some(pubky_switch_core::claims::Basis::Owner),
            evidence_ref: None,
        }),
    )
}

/// `GET /claims` of the tests' claim key, as the wallet at `at`.
async fn read_claim(replay: &Replay, at: &str) -> (u16, Value) {
    let keys = vectors("keys.json");
    let path = format!(
        "/v1/{}/claims/{}",
        alice_id(),
        pubky_switch_core::enc::b64(&[7; 32])
    );
    let request = app_request(app(&keys, "wallet"), "GET", &path, Vec::new(), ms(at));
    let (status, body, _) = answer_of(replay.service.handle(request).await);
    (status, body)
}

#[tokio::test]
async fn test_claims_deletion_waits_for_trusted_time() {
    let Some(replay) = registered(Limits::default(), true).await else {
        return;
    };
    let sample = |replay: &Replay| {
        use pubky_switch::time::Clock;
        replay.time.note(
            pubky_switch::time::TimeSample {
                utc_ms: replay.clock.now_ms(),
                uncertainty_ms: 0,
            },
            replay.clock.monotonic_ms(),
        );
    };
    sample(&replay);
    // An attempt pinned to a deadline a minute away, then done: a tombstone, deletable 30
    // days after the deadline.
    let deadline = ms(AT) + 60_000;
    let ops = wallet_batch(30, 1, vec![claim(ClaimType::Attempt, 0, Some(deadline))]);
    let (status, body) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!(status, 200, "{body}");
    let ops = wallet_batch(31, 1, vec![claim(ClaimType::Done, 1, None)]);
    let (status, body) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(read_claim(&replay, AT).await.1["claim"]["tombstone"], true);
    // 31 days on, the sample is too old: no trusted time, so nothing is deleted.
    replay.clock.advance_ms(31 * 86_400_000);
    let later = pubky_switch_core::time::rfc3339(ms(AT) + 31 * 86_400_000);
    let (status, body) = read_claim(&replay, &later).await;
    assert_eq!(status, 200, "kept without trusted time: {body}");
    // With a fresh sample, it goes.
    sample(&replay);
    let (status, body) = read_claim(&replay, &later).await;
    assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_claims_read_refusals() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    // The signer holds no claims.read.
    let path = format!(
        "/v1/{}/claims/{}",
        alice_id(),
        pubky_switch_core::enc::b64(&[7; 32])
    );
    let answer = replay
        .service
        .handle(signer_request("GET", &path, Vec::new(), ms(AT)))
        .await;
    let (status, body, _) = answer_of(answer);
    assert_eq!(
        (status, body["code"].as_str()),
        (403, Some("permission_missing"))
    );
    // A claim key that isn't 32 bytes, and an unknown one.
    let keys = vectors("keys.json");
    let bad = format!("/v1/{}/claims/AAAA", alice_id());
    let request = app_request(app(&keys, "wallet"), "GET", &bad, Vec::new(), ms(AT));
    assert_eq!(answer_of(replay.service.handle(request).await).0, 400);
    let (status, body) = read_claim(&replay, AT).await;
    assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));
    // An app of another identity: only own apps read claims, answered before the lock,
    // with no head (Switch wire 7.6).
    let request = other_request("shop", ORIGIN, "GET", &path, Vec::new(), None, ms(AT));
    let (status, body, head) = answer_of(replay.service.handle(request).await);
    assert_eq!(
        (status, body["code"].as_str()),
        (403, Some("permission_missing"))
    );
    assert!(head.is_none(), "no head");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_revoke_rules() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet")["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    let revoke = |app: &str, body: Vec<u8>| {
        signer_request(
            "POST",
            &format!("/v1/{}/apps/{app}/revoke", alice_id()),
            body,
            ms(AT),
        )
    };
    // The wallet registers an invite code, which its revocation withdraws.
    let invite = OpKind::InviteCodePut(pubky_switch_core::ops::InviteCodePut {
        code_hash: [5; 32],
        expires_at: ms(AT) + 86_400_000,
        max_uses: 1,
        context: pubky_switch_core::ops::InviteContext::new(Value::Null),
    });
    let ops = wallet_batch(32, 1, vec![(Vec::new(), invite)]);
    let (status, body) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!(status, 200, "{body}");
    // An unknown app is 404; a body is 400; an app may not revoke.
    let unknown = pubky_switch_core::enc::zbase32_encode(&[3; 16]);
    assert_eq!(
        answer_of(replay.service.handle(revoke(&unknown, Vec::new())).await).0,
        404
    );
    assert_eq!(
        answer_of(replay.service.handle(revoke(&wallet, b"{}".to_vec())).await).0,
        400
    );
    let by_app = app_request(
        app(&keys, "wallet"),
        "POST",
        &format!("/v1/{}/apps/{wallet}/revoke", alice_id()),
        Vec::new(),
        ms(AT),
    );
    let (status, body, _) = answer_of(replay.service.handle(by_app).await);
    assert_eq!(
        (status, body["code"].as_str()),
        (403, Some("permission_missing"))
    );
    // The revocation: one proof, the code withdrawn, the app no longer current.
    let (status, body, head) = answer_of(replay.service.handle(revoke(&wallet, Vec::new())).await);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["proofs"].as_array().map(Vec::len), Some(1));
    assert!(head.is_some());
    let mut txn = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    assert!(txn.invites(&[[5; 32]]).await.expect("invites").is_empty());
    drop(txn);
    let ops = wallet_batch(33, 1, vec![contact(bob())]);
    let (status, body) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!((status, body["code"].as_str()), (403, Some("not_current")));
    replay.db.drop_database().await.expect("drop");
}

const DAY_MS: u64 = 86_400_000;

async fn claim_count(replay: &Replay) -> i64 {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE account_id = $1")
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("count");
    conn.close().await.expect("close");
    count
}

/// The public read of alice's `identity.json` at `at`: it authenticates nothing.
async fn public_read(replay: &Replay, at: &str) {
    set_time(&replay.clock, at);
    let read = pubky_switch::http::SwitchRequest {
        ..request(
            "GET",
            &format!("/v1/{}/identity", alice_id()),
            &[],
            Vec::new(),
        )
    };
    assert_eq!(replay.service.handle(read).await.status, 200);
}

#[tokio::test]
async fn test_claims_deletion_goes_by_the_time_base() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    let deadline = ms(AT) + 60_000;
    let ops = wallet_batch(
        40,
        1,
        vec![
            claim(ClaimType::Attempt, 0, Some(deadline)),
            claim(ClaimType::Done, 1, None),
        ],
    );
    let (status, body) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!(status, 200, "{body}");
    // The wall clock runs past the deadline plus 30 days; the public read stamps that time.
    let ahead = pubky_switch_core::time::rfc3339(deadline + 31 * DAY_MS);
    public_read(&replay, &ahead).await;
    // It steps back: the stamped time stays ahead, the time base doesn't.
    let back = pubky_switch_core::time::rfc3339(ms(AT) + 120_000);
    set_time(&replay.clock, &back);
    let (status, body) = read_claim(&replay, &back).await;
    assert_eq!(status, 200, "not due by the time base: {body}");
    set_time(&replay.clock, &ahead);
    let (status, _) = read_claim(&replay, &ahead).await;
    assert_eq!(status, 404, "due by the time base");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_claims_open_attempts_and_no_deadline_pins() {
    // A short claim age, so the wallet's certificate is still current when it passes.
    let limits = Limits {
        max_claim_age_ms: 10 * DAY_MS,
        ..Limits::default()
    };
    let Some(replay) = registered(limits.clone(), false).await else {
        return;
    };
    // Claim 7: an attempt pinned to a deadline, left open. Claim 9: pinned to no deadline,
    // then failed by its owner.
    let deadline = ms(AT) + 60_000;
    let ops = wallet_batch(
        41,
        1,
        vec![
            claim(ClaimType::Attempt, 0, Some(deadline)),
            claim_at(9, ClaimType::Attempt, 0, None),
            claim_at(9, ClaimType::Failed, 1, None),
        ],
    );
    let (status, body) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!(status, 200, "{body}");
    let read = |key: u8, at: String| {
        let keys = vectors("keys.json");
        let path = format!(
            "/v1/{}/claims/{}",
            alice_id(),
            pubky_switch_core::enc::b64(&[key; 32])
        );
        app_request(app(&keys, "wallet"), "GET", &path, Vec::new(), ms(&at))
    };
    // 31 days on, past the deadline plus the reconciliation window: the open attempt stays.
    let at = pubky_switch_core::time::rfc3339(ms(AT) + 31 * DAY_MS);
    set_time(&replay.clock, &at);
    // An operator raised max_claim_age_ms to 40 days: the failed claim stays too.
    let raised = replay.restarted_with(Limits {
        max_claim_age_ms: 40 * DAY_MS,
        ..limits
    });
    assert_eq!(raised.handle(read(7, at.clone())).await.status, 200, "open");
    assert_eq!(
        raised.handle(read(9, at.clone())).await.status,
        200,
        "under the raised age"
    );
    // At 10 days, it goes.
    assert_eq!(replay.service.handle(read(9, at.clone())).await.status, 404);
    assert_eq!(replay.service.handle(read(7, at)).await.status, 200);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_claims_deletion_is_bounded_and_kept() {
    let limits = Limits {
        max_claims: 1_000,
        claim_share_percent: 100,
        open_attempts_per_app: 1_000,
        ..Limits::default()
    };
    let Some(replay) = registered(limits, false).await else {
        return;
    };
    // 68 tombstones pinned to one deadline, four a batch.
    let deadline = ms(AT) + 60_000;
    for batch in 0..17u8 {
        let mut entries = Vec::new();
        for claim in 0..4u8 {
            let key = 100 + batch * 4 + claim;
            entries.push(claim_at(key, ClaimType::Attempt, 0, Some(deadline)));
            entries.push(claim_at(key, ClaimType::Done, 1, None));
        }
        let (status, body) = post_app(
            &replay,
            "wallet",
            &wallet_batch(50 + batch, 1, entries),
            None,
            AT,
        )
        .await;
        assert_eq!(status, 200, "{body}");
    }
    assert_eq!(claim_count(&replay).await, 68);
    // All are due. The public read deletes none.
    let due = pubky_switch_core::time::rfc3339(deadline + 31 * DAY_MS);
    public_read(&replay, &due).await;
    assert_eq!(claim_count(&replay).await, 68);
    // A refused request of a verified caller deletes a bounded batch, which its refusal
    // doesn't undo.
    let stale = wallet_batch(90, 2, vec![contact(bob())]);
    let (status, _) = post_app(&replay, "wallet", &stale, None, &due).await;
    assert_eq!(status, 409);
    assert_eq!(claim_count(&replay).await, 4);
    let (status, _) = post_app(&replay, "wallet", &stale, None, &due).await;
    assert_eq!(status, 409);
    assert_eq!(claim_count(&replay).await, 0);
    replay.db.drop_database().await.expect("drop");
}

async fn revoke_wallet(replay: &Replay) {
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet")["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    let path = format!("/v1/{}/apps/{wallet}/revoke", alice_id());
    let answer = replay
        .service
        .handle(signer_request("POST", &path, Vec::new(), ms(AT)))
        .await;
    assert_eq!(answer.status, 200);
}

#[tokio::test]
async fn test_revoked_app_is_refused_under_the_lock_with_the_head() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    revoke_wallet(&replay).await;
    let before = stamped_time(&replay).await;
    let held = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    let keys = vectors("keys.json");
    let body = OpsRequest::new(&wallet_batch(60, 1, vec![contact(bob())]), None).to_json();
    let later = pubky_switch_core::time::rfc3339(ms(AT) + 60_000);
    set_time(&replay.clock, &later);
    let request = app_request(app(&keys, "wallet"), "POST", &ops_path(), body, ms(&later));
    // The request verified, so its refusal waits for the lock (Switch wire 7.1: it carries
    // the head): it is answered only once the lock is released.
    let started = std::time::Instant::now();
    let hold = std::time::Duration::from_millis(300);
    let (answer, ()) = tokio::join!(replay.service.handle(request), async {
        tokio::time::sleep(hold).await;
        drop(held);
    });
    assert!(
        started.elapsed() >= hold,
        "a verified app's refusal takes the lock"
    );
    let (status, body, head) = answer_of(answer);
    assert_eq!((status, body["code"].as_str()), (403, Some("not_current")));
    assert!(head.is_some(), "the refusal carries the head");
    // Signed at the service time the refusal commits.
    let later_ms = i64::try_from(ms(&later)).expect("time");
    assert_eq!(stamped_time(&replay).await, later_ms);
    assert_ne!(before, later_ms);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_app_at_a_signer_call_keeps_the_check_order() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    let keys = vectors("keys.json");
    let identity = format!("/v1/{}/identity", alice_id());
    let put = |at: &str| {
        app_request(
            app(&keys, "wallet"),
            "PUT",
            &identity,
            b"{}".to_vec(),
            ms(at),
        )
    };
    // A current app: refused as a caller the call isn't for.
    let (status, body, _) = answer_of(replay.service.handle(put(AT)).await);
    assert_eq!(
        (status, body["code"].as_str()),
        (403, Some("permission_missing"))
    );
    // Revoked: not_current, with the head.
    revoke_wallet(&replay).await;
    let (status, body, head) = answer_of(replay.service.handle(put(AT)).await);
    assert_eq!((status, body["code"].as_str()), (403, Some("not_current")));
    assert!(head.is_some());
    // Its certificate expired too: cert_expired comes first (Switch wire 3.8, check 3
    // before the standing). Last, as the service time never goes back.
    let expired = "2026-12-01T00:00:00.000Z";
    set_time(&replay.clock, expired);
    let (status, body, head) = answer_of(replay.service.handle(put(expired)).await);
    assert_eq!((status, body["code"].as_str()), (403, Some("cert_expired")));
    assert!(head.is_some());
    replay.db.drop_database().await.expect("drop");
}

/// A batch of the phone's, with batch ID `[id; 16]`.
fn phone_batch(id: u8, kinds: Vec<(Vec<Condition>, OpKind)>) -> Vec<SignedOp> {
    let keys = vectors("keys.json");
    let phone = app(&keys, "phone");
    let key = ed25519_dalek::SigningKey::from_bytes(&hex32(&phone["signing_secret_hex"]));
    let app_id = pubky_switch_core::enc::app_id_decode(phone["app_id"].as_str().expect("id"))
        .expect("app id");
    sign_batch(&key, &alice_key(), Some(app_id), 1, [id; 16], kinds).expect("batch")
}

fn document(name: &str) -> SignedDoc {
    serde_json::from_value(named(&vectors("documents.json")["documents"], name)["signed"].clone())
        .expect("document")
}

#[tokio::test]
async fn test_claims_expired_owner_is_not_current_for_the_claim_rules() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    // The phone registers; its certificate runs to 2027-01-01, the wallet's to 2026-12-01.
    let register = phone_batch(
        40,
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
    );
    let (status, body) = post_app(&replay, "phone", &register, None, AT).await;
    assert_eq!(status, 200, "{body}");
    // The wallet opens an attempt that its age won't orphan.
    let attempt = (
        Vec::new(),
        OpKind::Claim(ClaimFields {
            claim_key: vec![9; 32],
            kind: ClaimType::Attempt,
            expected_step: 0,
            attempt_id: vec![8; 16],
            orphan_after: Some(1_000_000_000),
            deadline: None,
            basis: None,
            evidence_ref: None,
        }),
    );
    let (status, body) = post_app(
        &replay,
        "wallet",
        &wallet_batch(41, 1, vec![attempt]),
        None,
        AT,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let failed = |id: u8| {
        phone_batch(
            id,
            vec![(
                Vec::new(),
                OpKind::Claim(ClaimFields {
                    claim_key: vec![9; 32],
                    kind: ClaimType::Failed,
                    expected_step: 1,
                    attempt_id: vec![8; 16],
                    orphan_after: None,
                    deadline: None,
                    basis: None,
                    evidence_ref: None,
                }),
            )],
        )
    };
    let view = |at: &'static str| {
        let keys = vectors("keys.json");
        let path = format!(
            "/v1/{}/claims/{}",
            alice_id(),
            pubky_switch_core::enc::b64(&[9; 32])
        );
        app_request(app(&keys, "phone"), "GET", &path, Vec::new(), ms(at))
    };
    // While the owner is served, the attempt isn't orphaned, and another app can't fail it.
    let (_, read, _) = answer_of(replay.service.handle(view(AT)).await);
    assert_eq!(read["claim"]["attempts"][0]["orphaned"], false, "{read}");
    let (status, body) = post_app(&replay, "phone", &failed(42), None, AT).await;
    assert_eq!(status, 409, "{body}");
    // Once the owner's certificate has expired it counts as not current for the claim rules
    // (Switch spec 3.2, 10.2), though it is still current for retention: orphaned, and
    // another app may fail it.
    let later = "2026-12-01T00:00:10.000Z";
    set_time(&replay.clock, later);
    let (_, read, _) = answer_of(replay.service.handle(view(later)).await);
    assert_eq!(read["claim"]["attempts"][0]["orphaned"], true, "{read}");
    // So does the claim view a batch's unmet step condition answers with.
    let unmet = phone_batch(
        44,
        vec![(
            vec![Condition::ClaimStep {
                claim_key: [9; 32],
                step: 7,
            }],
            OpKind::AllowPut {
                pubky: bob(),
                kind: AllowKind::Contact,
            },
        )],
    );
    let (status, body) = post_app(&replay, "phone", &unmet, None, later).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(
        body["current"]["claim"]["attempts"][0]["orphaned"], true,
        "{body}"
    );
    // Without trusted time that outcome waits for it: only the owner's expiry allows it, and
    // expiry can't be judged without trusted time (Switch wire 7.3). The owner is current
    // for that test, its expiry apart.
    let keys = vectors("keys.json");
    let untrusted = replay.without_trusted_time();
    let request = app_request(
        app(&keys, "phone"),
        "POST",
        &ops_path(),
        OpsRequest::new(&failed(45), None).to_json(),
        ms(later),
    );
    let (status, body, _) = answer_of(untrusted.handle(request).await);
    assert_eq!(
        (status, body["code"].as_str()),
        (503, Some("unavailable")),
        "{body}"
    );
    let (status, body) = post_app(&replay, "phone", &failed(43), None, later).await;
    assert_eq!(status, 200, "{body}");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_own_app_refusals_carry_the_head_at_every_call() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet")["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    let calls = [
        ("GET", format!("/v1/{}/feed", alice_id()), Vec::new()),
        (
            "GET",
            format!(
                "/v1/{}/claims/{}",
                alice_id(),
                pubky_switch_core::enc::b64(&[7; 32])
            ),
            Vec::new(),
        ),
        (
            "POST",
            ops_path(),
            OpsRequest::new(&wallet_batch(70, 1, vec![contact(bob())]), None).to_json(),
        ),
        (
            "GET",
            format!("/v1/{}/apps/{wallet}/keys", alice_id()),
            Vec::new(),
        ),
        (
            "POST",
            format!("/v1/{}/apps/{wallet}/leave", alice_id()),
            Vec::new(),
        ),
    ];
    let check = |code: &'static str, at: String| {
        let calls = &calls;
        let keys = &keys;
        let replay = &replay;
        async move {
            for (method, path, body) in calls {
                let request = app_request(app(keys, "wallet"), method, path, body.clone(), ms(&at));
                let (status, answer, head) = answer_of(replay.service.handle(request).await);
                assert_eq!(
                    (status, answer["code"].as_str()),
                    (403, Some(code)),
                    "{method} {path}: {answer}"
                );
                // The request verified: the refusal carries the head (Switch wire 7.1).
                assert!(head.is_some(), "{method} {path}");
            }
        }
    };
    // Revoked: not_current at every call.
    revoke_wallet(&replay).await;
    check("not_current", AT.to_string()).await;
    // Expired as well: cert_expired, the earlier check (Switch wire 3.8).
    let expired = "2026-12-01T00:00:00.000Z";
    set_time(&replay.clock, expired);
    check("cert_expired", expired.to_string()).await;
    replay.db.drop_database().await.expect("drop");
}

/// The phone registers, with the records of `documents.json`.
async fn register_phone(replay: &Replay) {
    let register = phone_batch(
        80,
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
    );
    let (status, body) = post_app(replay, "phone", &register, None, AT).await;
    assert_eq!(status, 200, "{body}");
}

/// The wallet's renewal expiring at `expires_ms`, stored by the signer with a key bundle
/// part, then listed by version 4 of alice's `identity.json` with the earlier certificate
/// renewed and still open (its closing pending).
async fn renew_wallet_open(replay: &Replay, expires_ms: u64) {
    let (app_keys, old) = wallet_keys(replay).await;
    let alice = IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]));
    let issued = ms(AT) - 1_000;
    let renewed = AppCert::issue(
        &alice,
        AppCertBody::new(
            alice_key(),
            app_keys.signing_public(),
            app_keys.bundle_public(),
            old.scopes().to_vec(),
            old.permissions(),
            issued,
            expires_ms,
        ),
    )
    .expect("cert");
    let part = pubky_switch_core::records::seal_bundle_parts(&alice, &renewed, 1, 1, &|_| true)
        .expect("bundle")
        .remove(0);
    let ops = sign_batch(
        &alice,
        &alice_key(),
        None,
        1,
        [81; 16],
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
    let request = signer_request(
        "POST",
        &ops_path(),
        OpsRequest::new(&ops, None).to_json(),
        ms(AT),
    );
    let (status, body, _) = answer_of(replay.service.handle(request).await);
    assert_eq!(status, 200, "{body}");
    let v3 = document("alice identity.json");
    let mut doc: pubky_switch_core::records::IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("body");
    doc.version = 4;
    let wallet = renewed.app_id();
    if let Some(entry) = doc.apps.iter_mut().find(|entry| entry.app_id == wallet) {
        entry.cert = renewed.hash();
    }
    doc.renewed.push(pubky_switch_core::records::RenewedCert {
        app_id: wallet,
        cert: old.hash(),
        until: None,
    });
    let v4 = pubky_switch_core::records::IdentityDoc::sign(&alice, doc)
        .expect("sign")
        .signed()
        .clone();
    let delivery = pubky_switch_core::http::IdentityDelivery {
        identity: v4,
        prev: Some(v3.doc_hash().expect("hash")),
    }
    .to_json();
    let request = signer_request(
        "PUT",
        &format!("/v1/{}/identity", alice_id()),
        delivery,
        ms(AT),
    );
    let (status, body, _) = answer_of(replay.service.handle(request).await);
    assert_eq!(status, 200, "{body}");
}

/// The wallet opens an attempt its age won't orphan, on claim key `[10; 32]`.
async fn wallet_attempt(replay: &Replay) {
    let attempt = (
        Vec::new(),
        OpKind::Claim(ClaimFields {
            claim_key: vec![10; 32],
            kind: ClaimType::Attempt,
            expected_step: 0,
            attempt_id: vec![8; 16],
            orphan_after: Some(1_000_000_000),
            deadline: None,
            basis: None,
            evidence_ref: None,
        }),
    );
    let (status, body) = post_app(
        replay,
        "wallet",
        &wallet_batch(82, 1, vec![attempt]),
        None,
        AT,
    )
    .await;
    assert_eq!(status, 200, "{body}");
}

/// The attempt's `orphaned` as the phone reads it in `GET /claims` and in a conflict's
/// claim view at `at`, and the status of the phone's `failed` on it (batch `id`).
async fn served_as_the_phone_sees_it(replay: &Replay, at: &str, id: u8) -> (Value, Value, u16) {
    let keys = vectors("keys.json");
    let path = format!(
        "/v1/{}/claims/{}",
        alice_id(),
        pubky_switch_core::enc::b64(&[10; 32])
    );
    let (_, read, _) = answer_of(
        replay
            .service
            .handle(app_request(
                app(&keys, "phone"),
                "GET",
                &path,
                Vec::new(),
                ms(at),
            ))
            .await,
    );
    let unmet = phone_batch(
        id,
        vec![(
            vec![Condition::ClaimStep {
                claim_key: [10; 32],
                step: 7,
            }],
            OpKind::AllowPut {
                pubky: bob(),
                kind: AllowKind::Contact,
            },
        )],
    );
    let (_, conflict) = post_app(replay, "phone", &unmet, None, at).await;
    let failed = phone_batch(
        id.wrapping_add(1),
        vec![(
            Vec::new(),
            OpKind::Claim(ClaimFields {
                claim_key: vec![10; 32],
                kind: ClaimType::Failed,
                expected_step: 1,
                attempt_id: vec![8; 16],
                orphan_after: None,
                deadline: None,
                basis: None,
                evidence_ref: None,
            }),
        )],
    );
    let (status, _) = post_app(replay, "phone", &failed, None, at).await;
    (
        read["claim"]["attempts"][0]["orphaned"].clone(),
        conflict["current"]["claim"]["attempts"][0]["orphaned"].clone(),
        status,
    )
}

#[tokio::test]
async fn test_claims_served_judges_the_certificate_authentication_uses() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    register_phone(&replay).await;
    wallet_attempt(&replay).await;
    // A shorter renewal, listed, its closing pending: the earlier certificate is still
    // open and unexpired when the renewal expires.
    renew_wallet_open(&replay, ms(AT) + 30 * 86_400_000).await;
    let lapsed = pubky_switch_core::time::rfc3339(ms(AT) + 40 * 86_400_000);
    set_time(&replay.clock, &lapsed);
    // The owner is refused: it is checked against the listed renewal, which has expired.
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/feed", alice_id());
    let (status, body, _) = answer_of(
        replay
            .service
            .handle(app_request(
                app(&keys, "wallet"),
                "GET",
                &path,
                Vec::new(),
                ms(&lapsed),
            ))
            .await,
    );
    assert_eq!((status, body["code"].as_str()), (403, Some("cert_expired")));
    // So the claim rules count it as not served: orphaned in both views, and another
    // app's failed is taken.
    assert_eq!(
        served_as_the_phone_sees_it(&replay, &lapsed, 83).await,
        (Value::Bool(true), Value::Bool(true), 200)
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_claims_served_through_a_longer_renewal_past_the_earlier_expiry() {
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    register_phone(&replay).await;
    wallet_attempt(&replay).await;
    // A renewal that outlives the earlier certificate (2026-12-01), listed, the earlier
    // one still open.
    renew_wallet_open(&replay, ms("2027-06-01T00:00:00.000Z")).await;
    let after = "2026-12-15T00:00:00.000Z";
    set_time(&replay.clock, after);
    // The owner is served through the renewal: the attempt isn't orphaned, and another
    // app's failed is refused while the owner is current.
    assert_eq!(
        served_as_the_phone_sees_it(&replay, after, 85).await,
        (Value::Bool(false), Value::Bool(false), 409)
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_claims_compacted_or_deleted_entries_lose_their_documents() {
    // A live claim's entry keeps its document. The `done` that settles it compacts it to a
    // tombstone, whose entries show as stubs: their documents and proofs go in that same
    // transaction (Switch wire 6.8, 7.5). A failed claim's entries keep theirs until the
    // claim is deleted, at a request past its deadline and the reconciliation window.
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    let ops = wallet_batch(60, 1, vec![claim(ClaimType::Attempt, 0, None)]);
    let (status, body) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!(status, 200, "{body}");
    let attempt = head_seq(&body);
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), attempt).await,
        (true, true)
    );
    let ops = wallet_batch(61, 1, vec![claim(ClaimType::Done, 1, None)]);
    let (status, body) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!(status, 200, "{body}");
    let done = head_seq(&body);
    for seq in [attempt, done] {
        assert_eq!(
            chain_document_kept(&replay, &alice_id(), seq).await,
            (false, false),
            "seq {seq}"
        );
    }
    let deadline = ms(AT) + 60_000;
    let ops = wallet_batch(
        62,
        1,
        vec![
            claim_at(9, ClaimType::Attempt, 0, Some(deadline)),
            claim_at(9, ClaimType::Failed, 1, None),
        ],
    );
    let (status, body) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!(status, 200, "{body}");
    let failed = head_seq(&body);
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), failed).await,
        (true, true)
    );
    // A request past the deadline and the reconciliation window: step 4 deletes the claim.
    let late = pubky_switch_core::time::rfc3339(deadline + 31 * DAY_MS);
    set_time(&replay.clock, &late);
    read_claim(&replay, &late).await;
    for seq in [failed - 1, failed] {
        assert_eq!(
            chain_document_kept(&replay, &alice_id(), seq).await,
            (false, false),
            "seq {seq}"
        );
    }
    replay.db.drop_database().await.expect("drop");
}

/// The `seq`s of the chain items whose kept document concerns app `app`.
async fn app_documents(replay: &Replay, app: &[u8; 16]) -> Vec<i64> {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let seqs = sqlx::query_scalar(
        "SELECT seq FROM chain_items WHERE account_id = $1 AND doc_app = $2 \
         AND item_bytes IS NOT NULL ORDER BY seq",
    )
    .bind(alice_id())
    .bind(app.as_slice())
    .fetch_all(&mut conn)
    .await
    .expect("seqs");
    conn.close().await.expect("close");
    seqs
}

#[tokio::test]
async fn test_ops_replaced_app_record_loses_its_document() {
    // The wallet's app record replaced by a newer one: the earlier `app.put` shows as its
    // stub from then on, and its document and proof go in the same transaction; the new
    // one keeps both (Switch wire 7.5).
    let Some(replay) = registered(Limits::default(), false).await else {
        return;
    };
    let (keys, cert) = wallet_keys(&replay).await;
    let earlier = app_documents(&replay, &cert.app_id()).await;
    assert_eq!(earlier.len(), 1, "the registration's app.put");
    let earlier = u64::try_from(earlier[0]).expect("seq");
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), earlier).await,
        (true, true)
    );
    let record = AppRecord::sign(&keys, AppRecordBody::new(&cert, Vec::new(), ms(AT) + 1_000))
        .expect("record");
    let ops = wallet_batch(
        63,
        1,
        vec![(
            Vec::new(),
            OpKind::AppPut {
                record: record.signed().clone(),
            },
        )],
    );
    let (status, body) = post_app(&replay, "wallet", &ops, None, AT).await;
    assert_eq!(status, 200, "{body}");
    let newer = head_seq(&body);
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), earlier).await,
        (false, false)
    );
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), newer).await,
        (true, true)
    );
    assert_eq!(
        app_documents(&replay, &cert.app_id()).await,
        vec![i64::try_from(newer).expect("seq")]
    );
    replay.db.drop_database().await.expect("drop");
}
