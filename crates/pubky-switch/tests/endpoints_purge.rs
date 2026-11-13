//! The purge of removed apps (Switch wire 9.1 "Departure, revoked app"): a revoked or
//! departed app's record, receive key records, key bundle parts, cursor, last-seen time and
//! listing go at the request that leaves the newest `identity.json` listing it in neither
//! `apps` nor `removed`, with its rotation done and no attempt open or `unknown` it owns;
//! its App ID stays for good (7.4.12, 7.6 `not_current`).
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::http::{Handler, SwitchResponse};
use pubky_switch_core::{
    claims::{Basis, ClaimType},
    enc::zbase32_encode,
    http::header,
    keys::IdentityKey,
    ops::{KeyBundlePut, OpKind, OpsRequest, sign_batch},
    records::{AppRecord, RemovedApp},
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

fn revoke_time() -> u64 {
    ms(&item_time(chain_item(&vectors("chain.json"), 9)))
}

fn json_of(answer: &SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body)
        .unwrap_or_else(|_| panic!("json: {}", String::from_utf8_lossy(&answer.body)))
}

/// Whether the service still holds the wallet's record: its status names its certificate.
async fn wallet_held(replay: &Replay, at_ms: u64) -> bool {
    !app_status(replay, "wallet", at_ms).await["record_cert"].is_null()
}

/// The signer stores the wallet's keys of data epoch 2 (Switch wire 6.2).
async fn store_wallet_part(replay: &Replay, at_ms: u64) {
    let keys = vectors("keys.json");
    let alice_key = hex32(&alice(&keys)["public_hex"]);
    let alice = IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let record: SignedDoc = serde_json::from_value(
        named(&vectors("documents.json")["documents"], "wallet app record")["signed"].clone(),
    )
    .expect("record");
    let cert = AppRecord::verify(&record, &alice_key)
        .expect("record")
        .cert()
        .clone();
    let part = pubky_switch_core::records::seal_bundle_parts(&alice, &cert, 2, 2, &|_| true)
        .expect("bundle")
        .remove(0);
    let batch = sign_batch(
        &alice,
        &alice_key,
        None,
        1,
        [41; 16],
        vec![(
            Vec::new(),
            OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: cert.app_id(),
                bundle: part.bundle,
                first_epoch: 2,
                last_epoch: 2,
            }),
        )],
    )
    .expect("batch");
    let answer = replay
        .service
        .handle(signer_request(
            "POST",
            &format!("/v1/{}/ops", alice_id()),
            OpsRequest::new(&batch, None).to_json(),
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

async fn revoke(replay: &Replay, name: &str, at_ms: u64) -> SwitchResponse {
    let keys = vectors("keys.json");
    let path = format!(
        "/v1/{}/apps/{}/revoke",
        alice_id(),
        app(&keys, name)["app_id"].as_str().expect("id")
    );
    replay
        .service
        .handle(signer_request("POST", &path, Vec::new(), at_ms))
        .await
}

/// alice's version 3 with the wallet moved to `removed` at a higher data epoch.
async fn wallet_removed(replay: &Replay, at_ms: u64) -> SignedDoc {
    let wallet = app_id_of("wallet");
    deliver_next(replay, &alice_version_3(), at_ms, |body| {
        body.apps.retain(|listed| listed.app_id != wallet);
        body.removed.push(RemovedApp {
            app_id: wallet,
            distrust_from: at_ms,
        });
        body.data_epoch += 1;
    })
    .await
}

#[tokio::test]
async fn test_purge_at_the_delivery_that_drops_a_revoked_app() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let wallet = app_id_of("wallet");
    store_wallet_part(&replay, at).await;
    let failed = app_batch(
        &replay,
        "wallet",
        90,
        vec![on_wallet_attempt(ClaimType::Failed, 1, None)],
        at,
    )
    .await;
    assert_eq!(
        failed.status,
        200,
        "{}",
        String::from_utf8_lossy(&failed.body)
    );
    assert_eq!(revoke(&replay, "wallet", at).await.status, 200);
    // Revoked, and listed: nothing goes.
    assert_eq!(holdings(&replay, &wallet).await, [1, 1, 1, 1]);
    let removing = wallet_removed(&replay, at).await;
    // In `removed`: still nothing goes.
    assert_eq!(holdings(&replay, &wallet).await, [1, 1, 1, 1]);
    assert!(wallet_held(&replay, at).await);
    let records = rows_naming(&replay, "shared_records", "writer", &wallet).await;
    let claims = rows_naming(&replay, "claims", "creator", &wallet).await;
    let kept = rows_naming(&replay, "kept_app_ids", "app_id", &wallet).await;
    assert_eq!((records, claims, kept), (1, 1, 1));
    let chain_items = {
        let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM chain_items WHERE account_id = $1")
                .bind(alice_id())
                .fetch_one(&mut conn)
                .await
                .expect("count");
        count
    };
    // The delivery that purges it from `removed` purges it here too.
    let wallet_id = zbase32_encode(&wallet);
    deliver_next(&replay, &removing, at, |body| {
        body.removed.retain(|removed| removed.app_id != wallet);
    })
    .await;
    assert_eq!(holdings(&replay, &wallet).await, [0, 0, 0, 0]);
    // Its App ID stays, with its revocation time; the records and claims it wrote stay, and
    // the chain gains only the delivery.
    assert_eq!(
        app_status(&replay, "wallet", at).await,
        json!({
            "app_id": wallet_id,
            "current": false,
            "last_seen": null,
            "revoked_at": pubky_switch_core::time::rfc3339(at),
            "departed_at": null,
            "awaiting_rotation": false,
            "open_attempts": [],
            "unread_entries": 0,
            "sole_target_unread": 0,
            "record_cert": null,
            "record_at": null,
            "lagging": false,
            "keys_through": null,
            "full_bundle_requested": null,
            "bundle_ranges": [],
            "cert_expires_at": null,
        })
    );
    assert_eq!(
        (
            rows_naming(&replay, "shared_records", "writer", &wallet).await,
            rows_naming(&replay, "claims", "creator", &wallet).await,
            rows_naming(&replay, "kept_app_ids", "app_id", &wallet).await,
        ),
        (records, claims, kept)
    );
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM chain_items WHERE account_id = $1")
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("count");
    assert_eq!(after, chain_items + 1);
    // Its cursor is gone with it: an entry naming it never counts as unread for it.
    sqlx::query(
        "INSERT INTO inbox_entries (account_id, generation, seq, entry_id, sender, sender_app, \
         cert, accepted_at_ms, envelope, envelope_hash, targets, answer, quota_bytes) \
         VALUES ($1, 1, 900, $2, $3, $4, '\\x00', 0, '\\x00', $5, $6, '\\x00', 257)",
    )
    .bind(alice_id())
    .bind([1u8; 16].as_slice())
    .bind([2u8; 32].as_slice())
    .bind([3u8; 16].as_slice())
    .bind([4u8; 32].as_slice())
    .bind(vec![wallet.to_vec()])
    .execute(&mut conn)
    .await
    .expect("an entry naming the wallet");
    assert_eq!(app_status(&replay, "wallet", at).await["unread_entries"], 0);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_purge_purged_app_is_refused_not_current() {
    let Some(replay) = replay().await else { return };
    let (_, at) = purge_wallet(&replay).await;
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    // Without its record, its requests can't be checked: 403 not_current before anything
    // verified, without the head (Switch wire 7.2).
    for (method, path) in [
        ("GET", format!("/v1/{}/feed", alice_id())),
        (
            "GET",
            format!(
                "/v1/{}/apps/{}/keys",
                alice_id(),
                wallet["app_id"].as_str().expect("id")
            ),
        ),
    ] {
        let answer = replay
            .service
            .handle(app_request(wallet, method, &path, Vec::new(), at))
            .await;
        assert_eq!(
            (answer.status, json_of(&answer)["code"].clone()),
            (403, json!("not_current")),
            "{path}"
        );
        assert!(header_text(&answer, header::HEAD).is_none(), "{path}");
    }
    // A first call with its record verifies, and is refused with the head: its App ID is
    // kept for good.
    let record: SignedDoc = serde_json::from_value(
        named(&vectors("documents.json")["documents"], "wallet app record")["signed"].clone(),
    )
    .expect("record");
    let answer = app_batch(&replay, "wallet", 91, vec![OpKind::AppPut { record }], at).await;
    assert_eq!(
        (answer.status, json_of(&answer)["code"].clone()),
        (403, json!("not_current"))
    );
    assert!(header_text(&answer, header::HEAD).is_some());
    // Revoking it again changes nothing.
    let again = revoke(&replay, "wallet", at).await;
    assert_eq!(again.status, 200);
    assert_eq!(json_of(&again)["proofs"], json!([]));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_purge_waits_for_the_apps_last_open_attempt() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let wallet = app_id_of("wallet");
    assert_eq!(revoke(&replay, "wallet", at).await.status, 200);
    let removing = wallet_removed(&replay, at).await;
    deliver_next(&replay, &removing, at, |body| {
        body.removed.retain(|removed| removed.app_id != wallet);
    })
    .await;
    // In neither list, but its attempt is open: it keeps everything.
    assert!(wallet_held(&replay, at).await);
    assert_eq!(holdings(&replay, &wallet).await, [1, 1, 0, 1]);
    // The executor registers and marks the orphaned attempt `unknown`: still unresolved.
    let record: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "executor app record",
        )["signed"]
            .clone(),
    )
    .expect("record");
    let unknown = app_batch(
        &replay,
        "executor",
        92,
        vec![
            OpKind::AppPut { record },
            on_wallet_attempt(ClaimType::Unknown, 1, None),
        ],
        at,
    )
    .await;
    assert_eq!(
        unknown.status,
        200,
        "{}",
        String::from_utf8_lossy(&unknown.body)
    );
    let held = app_status(&replay, "wallet", at).await;
    assert_eq!(held["open_attempts"][0]["outcome"], "unknown");
    assert!(!held["record_cert"].is_null());
    // Its evidence resolves it: the batch that does purges the wallet.
    let done = app_batch(
        &replay,
        "executor",
        93,
        vec![on_wallet_attempt(ClaimType::Done, 2, Some(Basis::Evidence))],
        at,
    )
    .await;
    assert_eq!(done.status, 200, "{}", String::from_utf8_lossy(&done.body));
    assert_eq!(holdings(&replay, &wallet).await, [0, 0, 0, 0]);
    let purged = app_status(&replay, "wallet", at).await;
    assert_eq!(
        (
            purged["record_cert"].clone(),
            purged["open_attempts"].clone()
        ),
        (Value::Null, json!([]))
    );
    // The claim stays, with the wallet's attempt.
    assert_eq!(rows_naming(&replay, "claims", "creator", &wallet).await, 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_purge_waits_for_a_departures_rotation() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let wallet = app_id_of("wallet");
    let failed = app_batch(
        &replay,
        "wallet",
        90,
        vec![on_wallet_attempt(ClaimType::Failed, 1, None)],
        at,
    )
    .await;
    assert_eq!(failed.status, 200);
    let keys = vectors("keys.json");
    let left = replay
        .service
        .handle(app_request(
            app(&keys, "wallet"),
            "POST",
            &format!("/v1/{}/apps/{}/leave", alice_id(), zbase32_encode(&wallet)),
            Vec::new(),
            at,
        ))
        .await;
    assert_eq!(left.status, 200, "{}", String::from_utf8_lossy(&left.body));
    // Dropped from apps at a higher data epoch, in neither list: no rotation, so it stays.
    let v3 = alice_version_3();
    let epoch =
        pubky_switch_core::records::IdentityDoc::verify(&v3, &hex32(&alice(&keys)["public_hex"]))
            .expect("verify")
            .data_epoch();
    let dropped = deliver_next(&replay, &v3, at, |body| {
        body.apps.retain(|listed| listed.app_id != wallet);
        body.data_epoch = epoch + 1;
    })
    .await;
    assert_eq!(
        app_status(&replay, "wallet", at).await["awaiting_rotation"],
        true
    );
    assert!(wallet_held(&replay, at).await);
    // In removed above the departure's epoch: rotated, and still kept while listed there.
    let rotated = deliver_next(&replay, &dropped, at, |body| {
        body.removed.push(RemovedApp {
            app_id: wallet,
            distrust_from: at,
        });
    })
    .await;
    assert_eq!(
        app_status(&replay, "wallet", at).await["awaiting_rotation"],
        false
    );
    assert!(wallet_held(&replay, at).await);
    deliver_next(&replay, &rotated, at, |body| body.removed.clear()).await;
    let purged = app_status(&replay, "wallet", at).await;
    assert_eq!(
        (
            purged["record_cert"].clone(),
            purged["departed_at"].clone(),
            purged["awaiting_rotation"].clone(),
            purged["current"].clone(),
        ),
        (
            Value::Null,
            json!(pubky_switch_core::time::rfc3339(at)),
            json!(false),
            json!(false)
        )
    );
    assert_eq!(holdings(&replay, &wallet).await, [0, 0, 0, 0]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_purge_at_the_revocation_of_an_app_in_neither_list() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let wallet = app_id_of("wallet");
    let failed = app_batch(
        &replay,
        "wallet",
        90,
        vec![on_wallet_attempt(ClaimType::Failed, 1, None)],
        at,
    )
    .await;
    assert_eq!(failed.status, 200);
    // Dropped from both lists unrevoked: it isn't kept, so nothing goes.
    deliver_next(&replay, &alice_version_3(), at, |body| {
        body.apps.retain(|listed| listed.app_id != wallet);
    })
    .await;
    assert_eq!(holdings(&replay, &wallet).await, [1, 1, 0, 1]);
    // Its revocation keeps it for good, and purges it at once.
    assert_eq!(revoke(&replay, "wallet", at).await.status, 200);
    assert_eq!(holdings(&replay, &wallet).await, [0, 0, 0, 0]);
    assert_eq!(
        rows_naming(&replay, "kept_app_ids", "app_id", &wallet).await,
        1
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_purge_deletes_the_documents_of_its_record_and_parts() {
    // Before the purge the wallet's `app.put` and its stored part's `key_bundle.put` keep
    // their documents; the purge's transaction deletes them, as no app may read them in
    // full any more (Switch wire 7.5), and keeps their stubs.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let wallet = app_id_of("wallet");
    store_wallet_part(&replay, at).await;
    let failed = app_batch(
        &replay,
        "wallet",
        90,
        vec![on_wallet_attempt(ClaimType::Failed, 1, None)],
        at,
    )
    .await;
    assert_eq!(failed.status, 200);
    assert_eq!(revoke(&replay, "wallet", at).await.status, 200);
    let removing = wallet_removed(&replay, at).await;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let mut seqs: Vec<i64> = sqlx::query_scalar(
        "SELECT seq FROM chain_items WHERE account_id = $1 AND doc_app = $2 \
         AND item_bytes IS NOT NULL",
    )
    .bind(alice_id())
    .bind(wallet.as_slice())
    .fetch_all(&mut conn)
    .await
    .expect("its app.put");
    assert!(!seqs.is_empty(), "its app.put keeps its document");
    let part: i64 = sqlx::query_scalar(
        "SELECT seq FROM key_bundle_parts WHERE account_id = $1 AND target_app_id = $2",
    )
    .bind(alice_id())
    .bind(wallet.as_slice())
    .fetch_one(&mut conn)
    .await
    .expect("its part");
    seqs.push(part);
    for seq in &seqs {
        let seq = u64::try_from(*seq).expect("seq");
        assert_eq!(
            chain_document_kept(&replay, &alice_id(), seq).await,
            (true, true),
            "seq {seq} before the purge"
        );
    }
    deliver_next(&replay, &removing, at, |body| {
        body.removed.retain(|removed| removed.app_id != wallet);
    })
    .await;
    assert_eq!(holdings(&replay, &wallet).await, [0, 0, 0, 0]);
    for seq in &seqs {
        let seq = u64::try_from(*seq).expect("seq");
        assert_eq!(
            chain_document_kept(&replay, &alice_id(), seq).await,
            (false, false),
            "seq {seq} after the purge"
        );
    }
    replay.db.drop_database().await.expect("drop");
}
