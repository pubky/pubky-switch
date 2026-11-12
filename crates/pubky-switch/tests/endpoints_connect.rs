//! Connect requests (Switch spec 7, Switch wire 7.4.7): bob's shop, a stranger at alice's
//! switch, asks to be invited where alice's `identity.json` turns connect requests on.
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::http::{Handler, SwitchResponse};
use pubky_switch::limits::Limits;
use pubky_switch_core::enc::pubky_id;
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::ops::{AllowKind, OpKind, sign_batch};
use pubky_switch_core::records::{IdentityBody, IdentityDoc};
use pubky_switch_core::sig::SignedDoc;
use serde_json::{Value, json};
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

fn code(answer: &SwitchResponse) -> (u16, Value) {
    (answer.status, body(answer)["code"].clone())
}

fn doc(name: &str) -> SignedDoc {
    serde_json::from_value(named(&vectors("documents.json")["documents"], name)["signed"].clone())
        .expect("document")
}

fn bob() -> [u8; 32] {
    let keys = vectors("keys.json");
    let bob = keys["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == "bob")
        .cloned()
        .expect("bob");
    hex32(&bob["public_hex"])
}

/// alice's version 4, turning connect requests on with `max_pending`, delivered.
async fn take_connect_requests(replay: &Replay, max_pending: u64) {
    let v3 = doc("alice identity.json");
    let mut body: IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("body");
    body.version = 4;
    body.policy.connect_requests.enabled = true;
    body.policy.connect_requests.max_pending = max_pending;
    let key = IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]));
    let v4 = IdentityDoc::sign(&key, body)
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

/// bob's shop delivers bob's `identity.json`, as a stranger may where connect requests
/// are on.
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

/// alice's switch serving, taking connect requests up to `max_pending`, and holding bob's
/// document.
async fn serving(limits: Limits, max_pending: u64) -> Option<Replay> {
    let replay = replay_with(limits).await?;
    replay_chain_through_revoke(&replay).await;
    take_connect_requests(&replay, max_pending).await;
    deliver_bob(&replay).await;
    Some(replay)
}

/// bob's shop asks to connect.
async fn ask(replay: &Replay) -> SwitchResponse {
    let path = format!("/v1/{}/connect", alice_id());
    let request = other_request("shop", ORIGIN, "POST", &path, Vec::new(), None, ms(&at()));
    replay.service.handle(request).await
}

/// alice's own app `name` reads the pending requests.
async fn list(replay: &Replay, name: &str) -> SwitchResponse {
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/connect", alice_id());
    let request = app_request(app(&keys, name), "GET", &path, Vec::new(), ms(&at()));
    replay.service.handle(request).await
}

/// alice's wallet declines `pubky`'s request.
async fn decline(replay: &Replay, pubky: &str) -> SwitchResponse {
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/connect/{pubky}", alice_id());
    let request = app_request(app(&keys, "wallet"), "DELETE", &path, Vec::new(), ms(&at()));
    replay.service.handle(request).await
}

/// A batch of `op` from alice's wallet, applied.
async fn wallet_op(replay: &Replay, op: OpKind, batch: u8) {
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let ops = sign_batch(
        &AppKeys::from_secrets(
            hex32(&wallet["signing_secret_hex"]),
            hex32(&wallet["bundle_secret_hex"]),
        ),
        &hex32(&alice(&keys)["public_hex"]),
        Some(
            pubky_switch_core::enc::app_id_decode(wallet["app_id"].as_str().expect("id"))
                .expect("app id"),
        ),
        1,
        [batch; 16],
        vec![(Vec::new(), op)],
    )
    .expect("batch");
    let signed: Vec<SignedDoc> = ops.iter().map(|op| op.signed().clone()).collect();
    let path = format!("/v1/{}/ops", alice_id());
    let request = app_request(
        wallet,
        "POST",
        &path,
        serde_json::to_vec(&json!({ "ops": signed })).expect("body"),
        ms(&at()),
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

async fn sqlx_scalar(replay: &Replay, query: &str) -> i64 {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query_scalar(query)
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("value")
}

fn pending(answer: &SwitchResponse) -> bool {
    answer.status == 200 && body(answer)["pending"] == json!(true)
}

fn requested(listed: &SwitchResponse) -> Vec<String> {
    body(listed)["requests"]
        .as_array()
        .expect("requests")
        .iter()
        .map(|request| request["pubky"].as_str().expect("pubky").to_string())
        .collect()
}

#[tokio::test]
async fn test_connect_request_is_pending_once_and_listed() {
    // A stranger asks: pending, with the version of its document the switch holds. Asking
    // again keeps one request, and its first time. The list shows it, the cap and that the
    // list isn't full.
    let Some(replay) = serving(Limits::default(), 50).await else {
        return;
    };
    let asked = ask(&replay).await;
    assert!(pending(&asked), "{}", String::from_utf8_lossy(&asked.body));
    assert!(body(&asked)["known_version"].is_u64(), "{}", body(&asked));
    let first = list(&replay, "wallet").await;
    assert_eq!(
        first.status,
        200,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    assert!(pending(&ask(&replay).await));
    let listed = list(&replay, "wallet").await;
    assert_eq!(requested(&listed), [pubky_id(&bob())]);
    assert_eq!(
        body(&listed)["requests"][0]["at"],
        body(&first)["requests"][0]["at"]
    );
    assert_eq!(body(&listed)["max_pending"], json!(50));
    assert_eq!(body(&listed)["full"], json!(false));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_request_where_the_policy_is_off_is_not_admitted() {
    // alice's version 3 takes no connect requests: `403 not_admitted`, and nothing kept.
    // An own app asking is `403 permission_missing`: only apps of another identity ask.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    assert_eq!(code(&ask(&replay).await), (403, json!("not_admitted")));
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/connect", alice_id());
    let own = replay
        .service
        .handle(app_request(
            app(&keys, "wallet"),
            "POST",
            &path,
            Vec::new(),
            ms(&at()),
        ))
        .await;
    assert_eq!(code(&own), (403, json!("permission_missing")));
    assert!(requested(&list(&replay, "wallet").await).is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_request_needs_the_senders_document() {
    // No copy of bob's document lists the shop: `409 identity_needed`, nothing kept.
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    take_connect_requests(&replay, 50).await;
    let asked = ask(&replay).await;
    assert_eq!(code(&asked), (409, json!("identity_needed")));
    assert!(requested(&list(&replay, "wallet").await).is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_request_of_a_denied_sender_is_answered_alike_and_not_kept() {
    // A denied sender gets the very answer a stranger gets, and its request isn't kept.
    let Some(replay) = serving(Limits::default(), 50).await else {
        return;
    };
    wallet_op(&replay, OpKind::DenyPut { pubky: bob() }, 70).await;
    let asked = ask(&replay).await;
    assert!(pending(&asked), "{}", String::from_utf8_lossy(&asked.body));
    assert!(requested(&list(&replay, "wallet").await).is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_requests_full_refuse_a_new_sender_before_the_deny_list() {
    // At `max_pending` 0 the list is always full: a new sender gets `429 quota_exceeded`
    // naming connect requests, and a denied one gets the same.
    let Some(replay) = serving(Limits::default(), 0).await else {
        return;
    };
    let asked = ask(&replay).await;
    assert_eq!(code(&asked), (429, json!("quota_exceeded")));
    assert_eq!(body(&asked)["current"]["limit"], json!("connect_requests"));
    wallet_op(&replay, OpKind::DenyPut { pubky: bob() }, 71).await;
    let denied = ask(&replay).await;
    assert_eq!((denied.status, body(&denied)), (asked.status, body(&asked)));
    let listed = list(&replay, "wallet").await;
    assert_eq!(
        (
            body(&listed)["max_pending"].clone(),
            body(&listed)["full"].clone()
        ),
        (json!(0), json!(true))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_requests_full_keep_the_one_waiting_and_answer_it_pending() {
    // At `max_pending` 1, the one waiting fills the list: it stays, and asking again is
    // still answered pending.
    let Some(replay) = serving(Limits::default(), 1).await else {
        return;
    };
    assert!(pending(&ask(&replay).await));
    let listed = list(&replay, "wallet").await;
    assert_eq!(body(&listed)["full"], json!(true));
    assert!(pending(&ask(&replay).await));
    assert_eq!(
        requested(&list(&replay, "wallet").await),
        [pubky_id(&bob())]
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_requests_cap_is_the_operators_at_most() {
    // A policy's `max_pending` above the operator's `max_connect_pending` is capped there.
    let limits = Limits {
        max_connect_pending: 3,
        ..Limits::default()
    };
    let Some(replay) = serving(limits, 50).await else {
        return;
    };
    assert_eq!(
        body(&list(&replay, "wallet").await)["max_pending"],
        json!(3)
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_request_rates_per_sender_and_with_strangers_deliveries() {
    // Per sender, `connect_per_min`; each refusal is a hit on its flag.
    let limits = Limits {
        connect_per_min: 1,
        ..Limits::default()
    };
    let Some(replay) = serving(limits, 50).await else {
        return;
    };
    assert!(pending(&ask(&replay).await));
    let limited = ask(&replay).await;
    assert_eq!(code(&limited), (429, json!("rate_limited")));
    let hits: i64 = sqlx_scalar(
        &replay,
        "SELECT coalesce(sum(hits), 0)::bigint FROM sender_flags WHERE account_id = $1",
    )
    .await;
    assert_eq!(hits, 1);
    replay.db.drop_database().await.expect("drop");

    // Per account, `stranger_per_min`, shared with strangers' `PUT /peers`: the delivery
    // took the minute's one.
    let limits = Limits {
        stranger_per_min: 1,
        ..Limits::default()
    };
    let Some(replay) = serving(limits, 50).await else {
        return;
    };
    assert_eq!(code(&ask(&replay).await), (429, json!("rate_limited")));
    assert!(requested(&list(&replay, "wallet").await).is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_request_is_answered_by_a_list_entry_or_declined() {
    // Declining removes it, and a second decline is `404`; a conversation entry, a contact
    // and a deny list entry for the sender each answer it too.
    let Some(replay) = serving(Limits::default(), 50).await else {
        return;
    };
    let bob_id = pubky_id(&bob());
    assert!(pending(&ask(&replay).await));
    let declined = decline(&replay, &bob_id).await;
    assert_eq!(
        declined.status,
        200,
        "{}",
        String::from_utf8_lossy(&declined.body)
    );
    assert_eq!(body(&declined), json!({ "declined": bob_id }));
    assert!(requested(&list(&replay, "wallet").await).is_empty());
    assert_eq!(
        code(&decline(&replay, &bob_id).await),
        (404, json!("not_found"))
    );
    for (batch, op) in [
        (
            72,
            OpKind::AllowPut {
                pubky: bob(),
                kind: AllowKind::Conversation,
            },
        ),
        (
            73,
            OpKind::AllowPut {
                pubky: bob(),
                kind: AllowKind::Contact,
            },
        ),
        (74, OpKind::DenyPut { pubky: bob() }),
    ] {
        // A sender the lists admit may still ask; the entry written after answers it.
        assert!(pending(&ask(&replay).await), "{op:?}");
        assert_eq!(requested(&list(&replay, "wallet").await), vec![bob_id.clone()]);
        wallet_op(&replay, op, batch).await;
        assert!(
            requested(&list(&replay, "wallet").await).is_empty(),
            "{batch}"
        );
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_requests_read_needs_lists_read() {
    // alice's executor holds no `lists.read`: `403 permission_missing`.
    let Some(replay) = serving(Limits::default(), 50).await else {
        return;
    };
    let record: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "executor app record",
        )["signed"]
            .clone(),
    )
    .expect("record");
    let keys = vectors("keys.json");
    let executor = app(&keys, "executor");
    let ops = sign_batch(
        &AppKeys::from_secrets(
            hex32(&executor["signing_secret_hex"]),
            hex32(&executor["bundle_secret_hex"]),
        ),
        &hex32(&alice(&keys)["public_hex"]),
        Some(
            pubky_switch_core::enc::app_id_decode(executor["app_id"].as_str().expect("id"))
                .expect("app id"),
        ),
        1,
        [75; 16],
        vec![(Vec::new(), OpKind::AppPut { record })],
    )
    .expect("batch");
    let signed: Vec<SignedDoc> = ops.iter().map(|op| op.signed().clone()).collect();
    let path = format!("/v1/{}/ops", alice_id());
    let registered = replay
        .service
        .handle(app_request(
            executor,
            "POST",
            &path,
            serde_json::to_vec(&json!({ "ops": signed })).expect("body"),
            ms(&at()),
        ))
        .await;
    assert_eq!(
        registered.status,
        200,
        "{}",
        String::from_utf8_lossy(&registered.body)
    );
    assert_eq!(
        code(&list(&replay, "executor").await),
        (403, json!("permission_missing"))
    );
    assert_eq!(list(&replay, "wallet").await.status, 200);
    replay.db.drop_database().await.expect("drop");
}
