//! `GET` and `POST /v1/{id}/apps/{app_id}/keys` (Switch wire 7.4.11) on `chain.json`'s
//! account: the wallet reads the key bundle parts the signer stored for it and asks for a full
//! bundle, which `GET /apps` shows until the parts cover every data epoch.
//!
//! The vectors fix the service key and the times; set `PUBKY_SWITCH_TEST_DATABASE_URL` to run
//! them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::http::{Handler, SwitchResponse};
use pubky_switch_core::{
    http::header,
    keys::IdentityKey,
    ops::{KeyBundlePut, OpKind, OpsRequest, SignedOp, sign_batch},
    records::{AppCert, AppRecord, KeyBundle},
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

fn app_id(name: &str) -> String {
    app(&vectors("keys.json"), name)["app_id"]
        .as_str()
        .expect("id")
        .to_string()
}

fn revoke_time() -> String {
    item_time(chain_item(&vectors("chain.json"), 9))
}

fn body(answer: &SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body)
        .unwrap_or_else(|_| panic!("json: {}", String::from_utf8_lossy(&answer.body)))
}

fn code(answer: &SwitchResponse) -> (u16, Value) {
    (answer.status, body(answer)["code"].clone())
}

/// The wallet's certificate, from its `app.put` at `seq` 3.
fn wallet_cert() -> AppCert {
    let keys = vectors("keys.json");
    let alice_key = hex32(&alice(&keys)["public_hex"]);
    let op = SignedOp::peek(
        &serde_json::from_value::<SignedDoc>(chain_item(&vectors("chain.json"), 3)["item"].clone())
            .expect("op"),
    )
    .expect("op");
    let OpKind::AppPut { record } = &op.body().kind else {
        panic!("seq 3 is the wallet's app.put");
    };
    AppRecord::verify(record, &alice_key)
        .expect("record")
        .cert()
        .clone()
}

/// The signer stores the wallet's key bundle parts over `ranges`, in one batch at `at`;
/// returns each part's bundle.
async fn store_parts(
    replay: &Replay,
    ranges: &[(u64, u64)],
    batch: u8,
    at: &str,
) -> Vec<KeyBundle> {
    let keys = vectors("keys.json");
    let alice_key = hex32(&alice(&keys)["public_hex"]);
    let alice = IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let cert = wallet_cert();
    let mut bundles = Vec::new();
    let mut ops = Vec::new();
    for (first, last) in ranges {
        let part =
            pubky_switch_core::records::seal_bundle_parts(&alice, &cert, *first, *last, &|_| true)
                .expect("bundle")
                .remove(0);
        bundles.push(part.bundle.clone());
        ops.push((
            Vec::new(),
            OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: cert.app_id(),
                bundle: part.bundle,
                first_epoch: *first,
                last_epoch: *last,
            }),
        ));
    }
    let batch = sign_batch(&alice, &alice_key, None, 1, [batch; 16], ops).expect("batch");
    let answer = replay
        .service
        .handle(signer_request(
            "POST",
            &format!("/v1/{}/ops", alice_id()),
            OpsRequest::new(&batch, None).to_json(),
            ms(at),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    bundles
}

/// The keys call `method` on `path_app`'s keys, from `caller` (a `keys.json` app, or
/// `"signer"`), at `at`.
async fn keys_call(
    replay: &Replay,
    caller: &str,
    method: &str,
    path_app: &str,
    body: Vec<u8>,
    at: &str,
) -> SwitchResponse {
    let path = format!("/v1/{}/apps/{}/keys", alice_id(), app_id(path_app));
    let request = if caller == "signer" {
        signer_request(method, &path, body, ms(at))
    } else {
        app_request(
            app(&vectors("keys.json"), caller),
            method,
            &path,
            body,
            ms(at),
        )
    };
    replay.service.handle(request).await
}

async fn full_bundle_requested(replay: &Replay, at: &str) -> Value {
    let path = format!("/v1/{}/apps", alice_id());
    let answer = replay
        .service
        .handle(signer_request("GET", &path, Vec::new(), ms(at)))
        .await;
    let wallet = app_id("wallet");
    body(&answer)["apps"]
        .as_array()
        .expect("apps")
        .iter()
        .find(|status| status["app_id"] == wallet.as_str())
        .expect("the wallet's status")["full_bundle_requested"]
        .clone()
}

#[tokio::test]
async fn test_keys_get_answers_the_parts_in_order() {
    // Two parts, stored in one batch: the wallet reads both, ordered by `first_epoch`, each
    // its bundle, the `seq` of its `key_bundle.put` and its range, with the head (Switch wire
    // 7.4.11, 7.1).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let bundles = store_parts(&replay, &[(2, 2), (1, 1)], 41, &at).await;
    let answer = keys_call(&replay, "wallet", "GET", "wallet", Vec::new(), &at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");
    let parts = body(&answer)["bundles"]
        .as_array()
        .expect("bundles")
        .clone();
    assert_eq!(parts.len(), 2);
    assert_eq!(
        parts
            .iter()
            .map(|part| (part["first_epoch"].clone(), part["last_epoch"].clone()))
            .collect::<Vec<_>>(),
        [(json!(1), json!(1)), (json!(2), json!(2))]
    );
    // The batch's two operations follow the revoke at `seq` 9, in the batch's order.
    assert_eq!(parts[0]["seq"], 11);
    assert_eq!(parts[1]["seq"], 10);
    assert_eq!(
        parts[0]["bundle"],
        serde_json::to_value(&bundles[1]).expect("bundle")
    );
    assert_eq!(
        parts[1]["bundle"],
        serde_json::to_value(&bundles[0]).expect("bundle")
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_get_without_parts_is_not_found() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let answer = keys_call(&replay, "wallet", "GET", "wallet", Vec::new(), &at).await;
    assert_eq!(code(&answer), (404, json!("not_found")));
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_only_the_app_itself() {
    // Another own app's path, the signer and an app of another identity: `403
    // permission_missing`, with the head to the account's own callers only. The revoked phone
    // isn't current (Switch wire 7.4.11, 7.2).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    for method in ["GET", "POST"] {
        let answer = keys_call(&replay, "wallet", method, "phone", Vec::new(), &at).await;
        assert_eq!(
            code(&answer),
            (403, json!("permission_missing")),
            "{method}"
        );
        assert!(header_text(&answer, header::HEAD).is_some(), "{method}");
        let answer = keys_call(&replay, "signer", method, "wallet", Vec::new(), &at).await;
        assert_eq!(
            code(&answer),
            (403, json!("permission_missing")),
            "{method}"
        );
        assert!(header_text(&answer, header::HEAD).is_some(), "{method}");
        let path = format!("/v1/{}/apps/{}/keys", alice_id(), app_id("shop"));
        let answer = replay
            .service
            .handle(other_request(
                "shop",
                ORIGIN,
                method,
                &path,
                Vec::new(),
                None,
                ms(&at),
            ))
            .await;
        assert_eq!(
            code(&answer),
            (403, json!("permission_missing")),
            "{method}"
        );
        assert!(header_text(&answer, header::HEAD).is_none(), "{method}");
        let answer = keys_call(&replay, "phone", method, "phone", Vec::new(), &at).await;
        assert_eq!(code(&answer), (403, json!("not_current")), "{method}");
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_request_keeps_the_first_time_until_covered() {
    // The first request's service time is kept, and `GET /apps` shows it, until the stored
    // parts cover every data epoch from 1 to the current one, 2 (Switch wire 7.4.11, 3.5).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    assert_eq!(full_bundle_requested(&replay, &at).await, Value::Null);
    let answer = keys_call(&replay, "wallet", "POST", "wallet", Vec::new(), &at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");
    assert_eq!(
        answer.body,
        format!(r#"{{"requested":"{at}"}}"#).into_bytes()
    );
    assert_eq!(full_bundle_requested(&replay, &at).await, json!(at));

    let later = "2026-01-01T00:10:00.000Z";
    set_time(&replay.clock, later);
    let answer = keys_call(&replay, "wallet", "POST", "wallet", Vec::new(), later).await;
    assert_eq!(body(&answer), json!({ "requested": at }));
    assert_eq!(full_bundle_requested(&replay, later).await, json!(at));

    // A part for epoch 2 alone doesn't cover epoch 1; the second does.
    store_parts(&replay, &[(2, 2)], 41, later).await;
    assert_eq!(full_bundle_requested(&replay, later).await, json!(at));
    store_parts(&replay, &[(1, 1)], 42, later).await;
    assert_eq!(full_bundle_requested(&replay, later).await, Value::Null);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_request_has_an_empty_body() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let answer = keys_call(&replay, "wallet", "POST", "wallet", b"{}".to_vec(), &at).await;
    assert_eq!(code(&answer), (400, json!("bad_request")));
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");
    assert_eq!(full_bundle_requested(&replay, &at).await, Value::Null);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_seq_follows_the_part_stored() {
    // An identical part again is a no-op and keeps its `seq` (Switch wire 6.4); a part
    // spanning both ranges replaces them, and answers its own `seq` (6.2).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    store_parts(&replay, &[(1, 1), (2, 2)], 41, &at).await;
    let seqs = |answer: &SwitchResponse| {
        body(answer)["bundles"]
            .as_array()
            .expect("bundles")
            .iter()
            .map(|part| {
                (
                    part["first_epoch"].as_u64().expect("first"),
                    part["last_epoch"].as_u64().expect("last"),
                    part["seq"].as_u64().expect("seq"),
                )
            })
            .collect::<Vec<_>>()
    };
    let before = keys_call(&replay, "wallet", "GET", "wallet", Vec::new(), &at).await;
    assert_eq!(seqs(&before), [(1, 1, 10), (2, 2, 11)]);
    store_parts(&replay, &[(1, 2)], 42, &at).await;
    let after = keys_call(&replay, "wallet", "GET", "wallet", Vec::new(), &at).await;
    assert_eq!(seqs(&after), [(1, 2, 12)]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_request_takes_the_service_time() {
    // The request records the service's stamped time, not its own `Switch-Timestamp`
    // (Switch wire 7.4.11, 7.3).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let now = "2026-01-01T00:20:00.000Z";
    set_time(&replay.clock, now);
    let signed_at = "2026-01-01T00:18:00.000Z";
    let answer = keys_call(&replay, "wallet", "POST", "wallet", Vec::new(), signed_at).await;
    assert_eq!(body(&answer), json!({ "requested": now }));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_refused_to_an_expired_or_unregistered_app() {
    // Check 3 and the app's standing come first (Switch wire 7.2): an app that hasn't
    // delivered its record isn't current, and an expired certificate is refused.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    for method in ["GET", "POST"] {
        let answer = keys_call(&replay, "executor", method, "executor", Vec::new(), &at).await;
        assert_eq!(code(&answer), (403, json!("not_current")), "{method}");
    }
    let expired = "2026-12-01T00:00:01.000Z";
    set_time(&replay.clock, expired);
    for method in ["GET", "POST"] {
        let answer = keys_call(&replay, "wallet", method, "wallet", Vec::new(), expired).await;
        assert_eq!(code(&answer), (403, json!("cert_expired")), "{method}");
    }
    replay.db.drop_database().await.expect("drop");
}

/// The signer renews the wallet at `at`: `cert.put` with a full key bundle made for the new
/// certificate (data epochs 1 to 2), then version 4, which lists the new certificate and keeps
/// the earlier one open in `renewed` (Switch wire 3.8). Returns the stored parts' bundles.
async fn renew_wallet(replay: &Replay, at: &str) -> Vec<KeyBundle> {
    use pubky_switch_core::{
        http::IdentityDelivery,
        keys::AppKeys,
        records::{AppCertBody, IdentityBody, IdentityDoc, RenewedCert, seal_bundle_parts},
    };
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let wallet_keys = AppKeys::from_secrets(
        hex32(&wallet["signing_secret_hex"]),
        hex32(&wallet["bundle_secret_hex"]),
    );
    let alice_key: [u8; 32] = hex32(&alice(&keys)["public_hex"]);
    let identity = IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let earlier = wallet_cert();
    let issued = ms(at) - 1_000;
    let renewed = AppCert::issue(
        &identity,
        AppCertBody::new(
            alice_key,
            wallet_keys.signing_public(),
            wallet_keys.bundle_public(),
            earlier.scopes().to_vec(),
            earlier.permissions(),
            issued,
            issued + 180 * 86_400_000,
        ),
    )
    .expect("certificate");
    let parts = seal_bundle_parts(&identity, &renewed, 1, 2, &|_| true).expect("bundle");
    let mut ops = vec![(
        Vec::new(),
        OpKind::CertPut {
            target_app_id: renewed.app_id(),
            cert: renewed.signed().clone(),
        },
    )];
    let mut bundles = Vec::new();
    for part in parts {
        bundles.push(part.bundle.clone());
        ops.push((
            Vec::new(),
            OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: renewed.app_id(),
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }),
        ));
    }
    let renewal = sign_batch(&identity, &alice_key, None, 1, [94; 16], ops).expect("batch");
    let answer = replay
        .service
        .handle(signer_request(
            "POST",
            &format!("/v1/{}/ops", alice_id()),
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
    let v3: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json",
        )["signed"]
            .clone(),
    )
    .expect("version 3");
    let mut next: IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("identity body");
    next.version = 4;
    let listed = next
        .apps
        .iter_mut()
        .find(|listed| listed.app_id == renewed.app_id())
        .expect("the wallet is listed");
    listed.cert = renewed.hash();
    next.renewed.push(RenewedCert {
        app_id: renewed.app_id(),
        cert: earlier.hash(),
        until: None,
    });
    let v4 = IdentityDoc::sign(&identity, next).expect("sign");
    let held = IdentityDoc::verify(&v3, &identity.public()).expect("version 3");
    let delivery = IdentityDelivery {
        identity: v4.signed().clone(),
        prev: Some(held.hash()),
    };
    let answer = replay
        .service
        .handle(signer_request(
            "PUT",
            &format!("/v1/{}/identity", alice_id()),
            delivery.to_json(),
            ms(at),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    bundles
}

#[tokio::test]
async fn test_keys_lapsed_app_reads_its_parts_once_renewed() {
    // The wallet's certificate lapses and it is refused; the signer renews it (Switch wire
    // 3.8 "An expired certificate"); the same `GET` then answers exactly the parts made for
    // the renewed certificate, and a request for a full bundle is taken (7.4.11).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let lapsed = "2026-12-01T00:00:10.000Z";
    set_time(&replay.clock, lapsed);
    let refused = keys_call(&replay, "wallet", "GET", "wallet", Vec::new(), lapsed).await;
    assert_eq!(code(&refused), (403, json!("cert_expired")));
    let bundles = renew_wallet(&replay, lapsed).await;
    let answer = keys_call(&replay, "wallet", "GET", "wallet", Vec::new(), lapsed).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let parts = body(&answer)["bundles"]
        .as_array()
        .expect("bundles")
        .clone();
    assert_eq!(parts.len(), bundles.len());
    for (part, bundle) in parts.iter().zip(&bundles) {
        assert_eq!(
            part["bundle"],
            serde_json::to_value(bundle).expect("bundle")
        );
    }
    let answer = keys_call(&replay, "wallet", "POST", "wallet", Vec::new(), lapsed).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_staged_account_is_unavailable() {
    // A version naming another switch leaves the account staged here: both calls are `503
    // staged`, after the caller's own checks, with the head (Switch wire 7.3 step 7).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let v3: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json",
        )["signed"]
            .clone(),
    )
    .expect("version 3");
    let mut moved: pubky_switch_core::records::IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("body");
    moved.version = 4;
    moved.inbox.url = "https://other.example".into();
    let key = IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]));
    let moved = pubky_switch_core::records::IdentityDoc::sign(&key, moved)
        .expect("sign")
        .signed()
        .clone();
    let delivery = pubky_switch_core::http::IdentityDelivery {
        identity: moved,
        prev: Some(v3.doc_hash().expect("hash")),
    }
    .to_json();
    let path = format!("/v1/{}/identity", alice_id());
    let delivered = replay
        .service
        .handle(signer_request("PUT", &path, delivery, ms(&at)))
        .await;
    assert_eq!(
        delivered.status,
        200,
        "{}",
        String::from_utf8_lossy(&delivered.body)
    );
    for method in ["GET", "POST"] {
        let answer = keys_call(&replay, "wallet", method, "wallet", Vec::new(), &at).await;
        assert_eq!(code(&answer), (503, json!("staged")), "{method}");
        assert!(header_text(&answer, header::HEAD).is_some(), "{method}");
    }
    replay.db.drop_database().await.expect("drop");
}

/// The wallet moves its cursor to `seq` at `at`.
async fn wallet_cursor(replay: &Replay, seq: u64, at: &str) {
    let request = app_request(
        app(&vectors("keys.json"), "wallet"),
        "POST",
        &format!("/v1/{}/ops", alice_id()),
        OpsRequest::new(
            &[],
            Some(pubky_switch_core::ops::Position { generation: 1, seq }),
        )
        .to_json(),
        ms(at),
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

/// The wallet's `bundle_ranges` in `GET /apps`.
async fn bundle_ranges(replay: &Replay, at: &str) -> Value {
    let path = format!("/v1/{}/apps", alice_id());
    let answer = replay
        .service
        .handle(signer_request("GET", &path, Vec::new(), ms(at)))
        .await;
    let wallet = app_id("wallet");
    body(&answer)["apps"]
        .as_array()
        .expect("apps")
        .iter()
        .find(|status| status["app_id"] == wallet.as_str())
        .expect("the wallet's status")["bundle_ranges"]
        .clone()
}

#[tokio::test]
async fn test_keys_passed_parts_go_when_the_next_part_is_stored() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    // Epoch 1's part, passed before the service dropped parts at cursor moves: the wallet's
    // cursor set past it directly.
    store_parts(&replay, &[(1, 1)], 60, &at).await;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query("UPDATE apps SET cursor_generation = 1, cursor_seq = 10 WHERE account_id = $1")
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("cursor");
    drop(conn);
    assert_eq!(bundle_ranges(&replay, &at).await, json!([[1, 1]]));
    // The next part stored: the passed part goes there, and only the new one is read.
    let bundles = store_parts(&replay, &[(2, 2)], 61, &at).await;
    assert_eq!(bundle_ranges(&replay, &at).await, json!([[2, 2]]));
    let answer = keys_call(&replay, "wallet", "GET", "wallet", Vec::new(), &at).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let parts = body(&answer)["bundles"].as_array().expect("bundles").len();
    assert_eq!((parts, bundles.len()), (1, 1));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_unpassed_parts_stay() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    // A part the wallet's cursor hasn't passed stays when the next one is stored.
    store_parts(&replay, &[(1, 1)], 60, &at).await;
    store_parts(&replay, &[(2, 2)], 61, &at).await;
    assert_eq!(bundle_ranges(&replay, &at).await, json!([[1, 1], [2, 2]]));
    replay.db.drop_database().await.expect("drop");
}

/// The wallet's feed item at `seq`, read after `after`.
async fn wallet_item(replay: &Replay, after: u64, seq: u64, at: &str) -> Value {
    let request = app_request(
        app(&vectors("keys.json"), "wallet"),
        "GET",
        &format!("/v1/{}/feed?after=1:{after}", alice_id()),
        Vec::new(),
        ms(at),
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    body(&answer)["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["seq"] == seq)
        .cloned()
        .unwrap_or_else(|| panic!("no item at {seq}"))
}

#[tokio::test]
async fn test_keys_a_cursor_move_drops_the_parts_it_passes() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    store_parts(&replay, &[(1, 1)], 60, &at).await;
    // Before the wallet passes it, its feed shows the part in full.
    assert_eq!(wallet_item(&replay, 9, 10, &at).await["type"], "chain");
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), 10).await,
        (true, true)
    );
    // Its cursor passes the part, which its keys_through covers: the part goes, and its
    // item is a stub, to the wallet too; its document and proof are deleted with it
    // (Switch wire 7.5).
    wallet_cursor(&replay, 10, &at).await;
    assert_eq!(bundle_ranges(&replay, &at).await, json!([]));
    assert_eq!(wallet_item(&replay, 9, 10, &at).await["type"], "stub");
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), 10).await,
        (false, false)
    );
    let answer = keys_call(&replay, "wallet", "GET", "wallet", Vec::new(), &at).await;
    assert_eq!(code(&answer), (404, json!("not_found")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_a_part_passed_before_its_gap_goes_once_the_gap_is_filled() {
    // The wallet is listed at data epoch 1, where its keys_through starts; the signer moves
    // the data epoch on to 3 and stores epoch 3's part alone: a gap at epoch 2 below a part
    // the wallet passes.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    deliver_next(&replay, &alice_version_3(), ms(&at), |body| {
        body.data_epoch = 3
    })
    .await;
    // Epoch 3's part (seq 11, after the delivery's), passed: not covered while epoch 2's
    // keys are missing, so it stays.
    store_parts(&replay, &[(3, 3)], 60, &at).await;
    wallet_cursor(&replay, 11, &at).await;
    assert_eq!(bundle_ranges(&replay, &at).await, json!([[3, 3]]));
    assert_eq!(keys_through(&replay, &at).await, 1);
    // Epoch 2's part fills the gap; once the wallet passes it too, both go.
    store_parts(&replay, &[(2, 2)], 61, &at).await;
    assert_eq!(bundle_ranges(&replay, &at).await, json!([[2, 2], [3, 3]]));
    wallet_cursor(&replay, 12, &at).await;
    assert_eq!(bundle_ranges(&replay, &at).await, json!([]));
    assert_eq!(keys_through(&replay, &at).await, 3);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_a_cursor_move_keeps_parts_while_a_full_bundle_is_requested() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    store_parts(&replay, &[(1, 1)], 60, &at).await;
    let asked = keys_call(&replay, "wallet", "POST", "wallet", Vec::new(), &at).await;
    assert_eq!(
        asked.status,
        200,
        "{}",
        String::from_utf8_lossy(&asked.body)
    );
    wallet_cursor(&replay, 10, &at).await;
    assert_eq!(bundle_ranges(&replay, &at).await, json!([[1, 1]]));
    replay.db.drop_database().await.expect("drop");
}

/// The wallet's `keys_through` in `GET /apps`.
async fn keys_through(replay: &Replay, at: &str) -> Value {
    let path = format!("/v1/{}/apps", alice_id());
    let answer = replay
        .service
        .handle(signer_request("GET", &path, Vec::new(), ms(at)))
        .await;
    let wallet = app_id("wallet");
    body(&answer)["apps"]
        .as_array()
        .expect("apps")
        .iter()
        .find(|status| status["app_id"] == wallet.as_str())
        .expect("the wallet's status")["keys_through"]
        .clone()
}

#[tokio::test]
async fn test_keys_through_keeps_its_height_once_passed_parts_go() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    // Epoch 2's part, passed: keys_through rises from 1 to 2.
    store_parts(&replay, &[(2, 2)], 60, &at).await;
    wallet_cursor(&replay, 10, &at).await;
    assert_eq!(keys_through(&replay, &at).await, 2);
    // The part goes when the next one is stored; keys_through stays at 2 without it.
    store_parts(&replay, &[(1, 1)], 61, &at).await;
    assert_eq!(bundle_ranges(&replay, &at).await, json!([[1, 1]]));
    assert_eq!(keys_through(&replay, &at).await, 2);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_a_request_stays_in_force_until_the_completing_part_is_passed() {
    // The wallet asks for a full bundle; its cursor passing epoch 1's part keeps it. The
    // signer stores what isn't stored yet: epoch 3's part, then epoch 2's, which completes
    // the request with epoch 1's part.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let asked = keys_call(&replay, "wallet", "POST", "wallet", Vec::new(), &at).await;
    assert_eq!(
        asked.status,
        200,
        "{}",
        String::from_utf8_lossy(&asked.body)
    );
    store_parts(&replay, &[(1, 1)], 60, &at).await;
    wallet_cursor(&replay, 10, &at).await;
    store_parts(&replay, &[(3, 3)], 61, &at).await;
    store_parts(&replay, &[(2, 2)], 62, &at).await;
    assert_eq!(
        full_bundle_requested(&replay, &at).await,
        Value::Null,
        "covered"
    );
    // The next put comes before the wallet's cursor passes the part that completed it (seq
    // 12): the request is still in force, and nothing the wallet asked for goes.
    store_parts(&replay, &[(4, 4)], 63, &at).await;
    let all = json!([[1, 1], [2, 2], [3, 3], [4, 4]]);
    assert_eq!(bundle_ranges(&replay, &at).await, all);
    // A move short of it keeps them too.
    wallet_cursor(&replay, 11, &at).await;
    assert_eq!(bundle_ranges(&replay, &at).await, all);
    // The move that passes it ends the request's force, and drops the parts it passed and
    // holds at once.
    wallet_cursor(&replay, 12, &at).await;
    assert_eq!(bundle_ranges(&replay, &at).await, json!([[4, 4]]));
    assert_eq!(keys_through(&replay, &at).await, 3);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_a_request_stays_in_force_for_the_rest_of_the_completing_batch() {
    // As above, with the completing part and the next one in one batch: the second put
    // keeps the parts the wallet asked for too.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let asked = keys_call(&replay, "wallet", "POST", "wallet", Vec::new(), &at).await;
    assert_eq!(
        asked.status,
        200,
        "{}",
        String::from_utf8_lossy(&asked.body)
    );
    store_parts(&replay, &[(1, 1)], 60, &at).await;
    wallet_cursor(&replay, 10, &at).await;
    store_parts(&replay, &[(2, 2), (3, 3)], 61, &at).await;
    assert_eq!(
        bundle_ranges(&replay, &at).await,
        json!([[1, 1], [2, 2], [3, 3]])
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_keys_a_part_replacing_the_completing_one_carries_the_force() {
    // The wallet asks; epoch 2's part (seq 11) completes the request with epoch 1's (seq 10).
    // Before the wallet reads it, a part over epochs 2 and 3 (seq 12) replaces it while the
    // request is in force.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let asked = keys_call(&replay, "wallet", "POST", "wallet", Vec::new(), &at).await;
    assert_eq!(
        asked.status,
        200,
        "{}",
        String::from_utf8_lossy(&asked.body)
    );
    store_parts(&replay, &[(1, 1)], 60, &at).await;
    wallet_cursor(&replay, 10, &at).await;
    store_parts(&replay, &[(2, 2)], 61, &at).await;
    store_parts(&replay, &[(2, 3)], 62, &at).await;
    assert_eq!(bundle_ranges(&replay, &at).await, json!([[1, 1], [2, 3]]));
    // The completing item is now a stub, which the wallet passes without fetching: the force
    // runs on to the part that replaced it, so passing the stub drops nothing.
    assert_eq!(wallet_item(&replay, 10, 11, &at).await["type"], "stub");
    wallet_cursor(&replay, 11, &at).await;
    assert_eq!(bundle_ranges(&replay, &at).await, json!([[1, 1], [2, 3]]));
    store_parts(&replay, &[(4, 4)], 63, &at).await;
    assert_eq!(
        bundle_ranges(&replay, &at).await,
        json!([[1, 1], [2, 3], [4, 4]])
    );
    // Passing the replacing part ends the force.
    wallet_cursor(&replay, 12, &at).await;
    assert_eq!(bundle_ranges(&replay, &at).await, json!([[4, 4]]));
    assert_eq!(keys_through(&replay, &at).await, 3);
    replay.db.drop_database().await.expect("drop");
}

/// The wallet's `app.put` of the record the service holds (chain.json seq 3), alone in a
/// batch with ID `[id; 16]`: an unchanged batch (Switch wire 6.4 "No-ops").
fn wallet_unchanged_app_put(id: u8) -> Vec<SignedOp> {
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let key = ed25519_dalek::SigningKey::from_bytes(&hex32(&wallet["signing_secret_hex"]));
    let alice_key = hex32(&alice(&keys)["public_hex"]);
    let op = SignedOp::peek(
        &serde_json::from_value::<SignedDoc>(chain_item(&vectors("chain.json"), 3)["item"].clone())
            .expect("op"),
    )
    .expect("op");
    let OpKind::AppPut { record } = &op.body().kind else {
        panic!("seq 3 is the wallet's app.put");
    };
    sign_batch(
        &key,
        &alice_key,
        Some(wallet_cert().app_id()),
        1,
        [id; 16],
        vec![(
            Vec::new(),
            OpKind::AppPut {
                record: record.clone(),
            },
        )],
    )
    .expect("batch")
}

#[tokio::test]
async fn test_keys_an_unchanged_batch_with_a_cursor_move_drops_too() {
    // A batch whose operations are all unchanged but that moves the cursor isn't a no-op
    // (Switch wire 6.4 step 10): its move drops the parts it passes, as any move does (6.2).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    store_parts(&replay, &[(1, 1)], 60, &at).await; // seq 10
    let request = app_request(
        app(&vectors("keys.json"), "wallet"),
        "POST",
        &format!("/v1/{}/ops", alice_id()),
        OpsRequest::new(
            &wallet_unchanged_app_put(70),
            Some(pubky_switch_core::ops::Position {
                generation: 1,
                seq: 10,
            }),
        )
        .to_json(),
        ms(&at),
    );
    let answer = replay.service.handle(request).await;
    let answered = body(&answer);
    let ranges = bundle_ranges(&replay, &at).await;
    let through = keys_through(&replay, &at).await;
    replay.db.drop_database().await.expect("drop");
    assert_eq!(answer.status, 200, "{answered}");
    assert_eq!(answered["proofs"], json!([]), "an unchanged batch");
    assert_eq!(
        ranges,
        json!([]),
        "the move passed epoch 1's part, which keys_through ({through}) covers"
    );
}

#[tokio::test]
async fn test_keys_replacing_another_part_while_in_force_keeps_the_force_where_it_is() {
    // In force by the completing part (seq 11); a put replaces epoch 1's part (seq 10), not
    // the completing one: the force stays at 11, so the move to 11 drops the passed,
    // covered completing part, and epoch 1's new part (seq 12, unpassed) stays.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let asked = keys_call(&replay, "wallet", "POST", "wallet", Vec::new(), &at).await;
    assert_eq!(
        asked.status,
        200,
        "{}",
        String::from_utf8_lossy(&asked.body)
    );
    store_parts(&replay, &[(1, 1)], 60, &at).await; // seq 10
    wallet_cursor(&replay, 10, &at).await;
    store_parts(&replay, &[(2, 2)], 61, &at).await; // seq 11, completes
    store_parts(&replay, &[(1, 1)], 62, &at).await; // seq 12, replaces 10
    wallet_cursor(&replay, 11, &at).await;
    let at_11 = (
        bundle_ranges(&replay, &at).await,
        keys_through(&replay, &at).await,
    );
    replay.db.drop_database().await.expect("drop");
    assert_eq!(at_11, (json!([[1, 1]]), json!(2)));
}

#[tokio::test]
async fn test_keys_a_replacement_after_the_force_ended_doesnt_restart_it() {
    // The wallet is listed at data epoch 1, where its keys_through starts; the signer moves
    // the data epoch on to 3 (seq 10). The request completes at seq 13 (epoch 3); epoch 2's
    // part is replaced at seq 14 while in force. The move to 13 ends the force and drops
    // epoch 1's part; epoch 3's stays, passed above a gap at epoch 2, whose part is unpassed.
    // Replacing epoch 3's part now (seq 15) doesn't put the request back in force: the move
    // to 14 drops epoch 2's new part.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    deliver_next(&replay, &alice_version_3(), ms(&at), |body| {
        body.data_epoch = 3
    })
    .await;
    let asked = keys_call(&replay, "wallet", "POST", "wallet", Vec::new(), &at).await;
    assert_eq!(
        asked.status,
        200,
        "{}",
        String::from_utf8_lossy(&asked.body)
    );
    store_parts(&replay, &[(1, 1)], 60, &at).await; // seq 11
    store_parts(&replay, &[(2, 2)], 61, &at).await; // seq 12
    store_parts(&replay, &[(3, 3)], 62, &at).await; // seq 13, completes
    store_parts(&replay, &[(2, 2)], 63, &at).await; // seq 14, replaces 12
    wallet_cursor(&replay, 13, &at).await;
    let at_13 = (
        bundle_ranges(&replay, &at).await,
        keys_through(&replay, &at).await,
    );
    store_parts(&replay, &[(3, 4)], 64, &at).await; // seq 15, replaces 13
    wallet_cursor(&replay, 14, &at).await;
    let at_14 = (
        bundle_ranges(&replay, &at).await,
        keys_through(&replay, &at).await,
    );
    replay.db.drop_database().await.expect("drop");
    assert_eq!(at_13, (json!([[2, 2], [3, 3]]), json!(1)));
    assert_eq!(at_14, (json!([[3, 4]]), json!(2)));
}
