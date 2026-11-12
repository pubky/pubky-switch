//! Connect requests (Switch spec 7, Switch wire 7.4.7): bob's shop, a stranger at alice's
//! switch, asks to be invited where alice's `identity.json` turns connect requests on.
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::http::{Handler, SwitchRequest, SwitchResponse};
use pubky_switch::limits::Limits;
use pubky_switch_core::enc::pubky_id;
use pubky_switch_core::http::{self as wire_http, RequestHeaders, RequestTarget, header};
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::ops::{AllowKind, OpKind, sign_batch};
use pubky_switch_core::records::{
    AppCert, AppCertBody, IdentityBody, IdentityDoc, ListedApp, RenewedCert,
};
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
    // An own app's answers carry the newest signed head (Switch wire 7.1).
    assert!(header_text(&listed, header::HEAD).is_some());
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
    assert_eq!(body(&declined)["declined"], json!(bob_id));
    assert!(header_text(&declined, header::HEAD).is_some());
    assert!(requested(&list(&replay, "wallet").await).is_empty());
    assert_eq!(
        code(&decline(&replay, &bob_id).await),
        (404, json!("not_found"))
    );
    // Each entry kind answers a pending request in the commit that writes it; the entry
    // goes again before the next kind, so the sender asks as a stranger each time.
    let kinds = [
        (
            OpKind::AllowPut {
                pubky: bob(),
                kind: AllowKind::Conversation,
            },
            Some(OpKind::AllowDelete {
                pubky: bob(),
                kind: AllowKind::Conversation,
            }),
        ),
        (
            OpKind::AllowPut {
                pubky: bob(),
                kind: AllowKind::Contact,
            },
            Some(OpKind::AllowDelete {
                pubky: bob(),
                kind: AllowKind::Contact,
            }),
        ),
        (OpKind::DenyPut { pubky: bob() }, None),
    ];
    for (batch, (put, delete)) in (72u8..).step_by(2).zip(kinds) {
        assert!(pending(&ask(&replay).await), "{put:?}");
        assert_eq!(
            requested(&list(&replay, "wallet").await),
            vec![bob_id.clone()]
        );
        wallet_op(&replay, put, batch).await;
        assert!(
            requested(&list(&replay, "wallet").await).is_empty(),
            "{batch}"
        );
        if let Some(delete) = delete {
            wallet_op(&replay, delete, batch + 1).await;
        }
    }
    replay.db.drop_database().await.expect("drop");
}

/// alice's executor registers its app record.
async fn register_executor(replay: &Replay) {
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
}

#[tokio::test]
async fn test_connect_requests_read_needs_lists_read() {
    // alice's executor holds no `lists.read`: `403 permission_missing`.
    let Some(replay) = serving(Limits::default(), 50).await else {
        return;
    };
    register_executor(&replay).await;
    assert_eq!(
        code(&list(&replay, "executor").await),
        (403, json!("permission_missing"))
    );
    assert_eq!(list(&replay, "wallet").await.status, 200);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_request_of_a_sender_the_lists_admit_is_pending_and_not_kept() {
    // A contact or a conversation entry already admits the sender: it is answered pending,
    // as anyone is, and nothing is kept, even while the list is full.
    let Some(replay) = serving(Limits::default(), 0).await else {
        return;
    };
    for (batch, kind) in [(80, AllowKind::Contact), (82, AllowKind::Conversation)] {
        wallet_op(&replay, OpKind::AllowPut { pubky: bob(), kind }, batch).await;
        let asked = ask(&replay).await;
        assert!(pending(&asked), "{}", String::from_utf8_lossy(&asked.body));
        assert!(requested(&list(&replay, "wallet").await).is_empty());
        wallet_op(
            &replay,
            OpKind::AllowDelete { pubky: bob(), kind },
            batch + 1,
        )
        .await;
    }
    replay.db.drop_database().await.expect("drop");
}

/// Who asks: bob's shop as a stranger, bob denied, or the shop removed in the copy of bob's
/// `identity.json` the switch holds.
#[derive(Clone, Copy, Debug)]
enum Asker {
    Stranger,
    Denied,
    Removed,
}

/// bob's version 2, which removes the shop: delivered by the shop itself, which a stranger
/// may do where connect requests are on, and kept, as from a stranger.
async fn deliver_bob_removing_the_shop(replay: &Replay) {
    let keys = vectors("keys.json");
    let bob_keys = keys["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == "bob")
        .cloned()
        .expect("bob");
    let v1 = doc("bob identity.json");
    let mut body: IdentityBody =
        serde_json::from_slice(&v1.body_bytes().expect("body")).expect("body");
    let shop = body.apps[0].app_id;
    body.version += 1;
    body.apps.clear();
    body.removed.push(pubky_switch_core::records::RemovedApp {
        app_id: shop,
        distrust_from: 0,
    });
    let key = IdentityKey::from_secret(hex32(&bob_keys["secret_hex"]));
    let v2 = IdentityDoc::sign(&key, body)
        .expect("sign")
        .signed()
        .clone();
    let path = format!("/v1/{}/peers", alice_id());
    let request = other_request(
        "shop",
        ORIGIN,
        "PUT",
        &path,
        serde_json::to_vec(&v2).expect("body"),
        None,
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

/// The status and body bytes `asker` gets at a fresh switch: connect requests off (`None`)
/// or on up to `max_pending`, with or without a copy of bob's document held.
async fn answer_to(asker: Asker, max_pending: Option<u64>, copy: bool) -> Option<(u16, Vec<u8>)> {
    let replay = replay().await?;
    replay_chain_through_revoke(&replay).await;
    if let Some(max_pending) = max_pending {
        take_connect_requests(&replay, max_pending).await;
        if copy {
            deliver_bob(&replay).await;
        }
        if matches!(asker, Asker::Removed) {
            deliver_bob_removing_the_shop(&replay).await;
        }
    }
    if matches!(asker, Asker::Denied) {
        wallet_op(&replay, OpKind::DenyPut { pubky: bob() }, 90).await;
    }
    let asked = ask(&replay).await;
    replay.db.drop_database().await.expect("drop");
    Some((asked.status, asked.body.to_vec()))
}

#[tokio::test]
async fn test_connect_answers_dont_show_the_deny_list_or_a_removal() {
    // At each step the spec names, a denied sender gets the stranger's very bytes, and a
    // removed app the bytes of a stranger whose document the switch doesn't hold: the
    // policy off; on without a copy held; on with one; full; not full.
    let cases: [(Option<u64>, bool, u16); 4] = [
        (None, false, 403),
        (Some(50), false, 409),
        (Some(50), true, 200),
        (Some(0), true, 429),
    ];
    for (max_pending, copy, status) in cases {
        let Some(stranger) = answer_to(Asker::Stranger, max_pending, copy).await else {
            return;
        };
        assert_eq!(
            stranger.0,
            status,
            "{}",
            String::from_utf8_lossy(&stranger.1)
        );
        let denied = answer_to(Asker::Denied, max_pending, copy)
            .await
            .expect("db");
        assert_eq!(denied, stranger, "denied, {max_pending:?} {copy}");
    }
    // A removed app: as a stranger with no copy held, whatever the switch holds.
    let Some(no_copy) = answer_to(Asker::Stranger, Some(50), false).await else {
        return;
    };
    for (max_pending, copy) in [(Some(50), true), (Some(0), true), (Some(50), false)] {
        let removed = answer_to(Asker::Removed, max_pending, copy)
            .await
            .expect("db");
        assert_eq!(removed, no_copy, "removed, {max_pending:?} {copy}");
    }
    let off = answer_to(Asker::Stranger, None, false).await.expect("db");
    let removed_off = answer_to(Asker::Removed, None, false).await.expect("db");
    assert_eq!(removed_off, off, "removed, off");
}

const DAY: u64 = 86_400_000;

/// A fresh sender identity with one app, its certificate valid at `at()`.
struct Fresh {
    identity: IdentityKey,
    secret: [u8; 32],
    cert: AppCert,
}

fn fresh(n: u8) -> Fresh {
    let identity = IdentityKey::from_secret([n; 32]);
    let secret = [n.wrapping_add(100); 32];
    let keys = AppKeys::from_secrets(secret, [n.wrapping_add(150); 32]);
    let now = ms(&at());
    let cert = AppCert::issue(
        &identity,
        AppCertBody::new(
            identity.public(),
            keys.signing_public(),
            keys.bundle_public(),
            vec!["request".into()],
            &[],
            now - DAY,
            now + 30 * DAY,
        ),
    )
    .expect("cert");
    Fresh {
        identity,
        secret,
        cert,
    }
}

impl Fresh {
    fn pubky(&self) -> [u8; 32] {
        self.identity.public()
    }

    /// Its `identity.json` at `version`, listing its app with its certificate, then `edit`.
    fn doc(&self, version: u64, edit: impl FnOnce(&mut IdentityBody)) -> SignedDoc {
        let bob = doc("bob identity.json");
        let mut body: IdentityBody =
            serde_json::from_slice(&bob.body_bytes().expect("body")).expect("body");
        body.identity = self.pubky();
        body.version = version;
        body.apps = vec![ListedApp {
            app_id: self.cert.app_id(),
            cert: self.cert.hash(),
        }];
        body.removed.clear();
        body.renewed.clear();
        edit(&mut body);
        IdentityDoc::sign(&self.identity, body)
            .expect("sign")
            .signed()
            .clone()
    }

    fn request(&self, method: &str, path: &str, body: Vec<u8>) -> SwitchRequest {
        let at_ms = ms(&at());
        let identity = pubky_id(&self.pubky());
        let app_id = pubky_switch_core::enc::zbase32_encode(&self.cert.app_id());
        let timestamp = pubky_switch_core::time::rfc3339_seconds(at_ms);
        let compact = self.cert.signed().compact();
        let signed_headers = RequestHeaders {
            timestamp: timestamp.clone(),
            identity: identity.clone(),
            app: Some(app_id.clone()),
            cert: Some(compact.clone()),
            invite_code: None,
        };
        let secret = ed25519_dalek::SigningKey::from_bytes(&self.secret);
        let signature = pubky_switch_core::enc::b64(&wire_http::sign_request(
            &secret,
            &RequestTarget {
                method,
                path_and_query: path,
                body: &body,
                origin: ORIGIN,
            },
            &signed_headers,
        ));
        request(
            method,
            path,
            &[
                (header::IDENTITY, identity.as_str()),
                (header::APP, app_id.as_str()),
                (header::CERT, compact.as_str()),
                (header::TIMESTAMP, timestamp.as_str()),
                (header::SIGNATURE, signature.as_str()),
            ],
            body,
        )
    }

    async fn deliver(&self, replay: &Replay, doc: &SignedDoc) -> SwitchResponse {
        let path = format!("/v1/{}/peers", alice_id());
        let body = serde_json::to_vec(doc).expect("body");
        replay
            .service
            .handle(self.request("PUT", &path, body))
            .await
    }

    async fn ask(&self, replay: &Replay) -> SwitchResponse {
        let path = format!("/v1/{}/connect", alice_id());
        replay
            .service
            .handle(self.request("POST", &path, Vec::new()))
            .await
    }
}

/// alice's policy at `version`, built on `prev` (her version 3 when `None`), delivered.
async fn alice_policy(
    replay: &Replay,
    prev: Option<&SignedDoc>,
    version: u64,
    enabled: bool,
    max_pending: u64,
) -> SignedDoc {
    let v3 = doc("alice identity.json");
    let mut body: IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("body");
    body.version = version;
    body.policy.connect_requests.enabled = enabled;
    body.policy.connect_requests.max_pending = max_pending;
    let key = IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]));
    let next = IdentityDoc::sign(&key, body)
        .expect("sign")
        .signed()
        .clone();
    let delivery = pubky_switch_core::http::IdentityDelivery {
        identity: next.clone(),
        prev: Some(prev.unwrap_or(&v3).doc_hash().expect("hash")),
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
    next
}

fn status_body(answer: &SwitchResponse) -> (u16, Vec<u8>) {
    (answer.status, answer.body.to_vec())
}

#[tokio::test]
async fn test_connect_lowering_the_cap_and_the_policy_off_drop_none() {
    // Decisions 4 and 5: two kept at cap 2, a third refused; the cap lowered to 1 drops
    // none (GET: both, max_pending 1, full); the policy off refuses POST but GET and
    // DELETE serve; on again shows what stayed, with its first `at`.
    let Some(replay) = replay_with(Limits::default()).await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let v4 = alice_policy(&replay, None, 4, true, 2).await;
    let (f1, f2, f3) = (fresh(11), fresh(12), fresh(13));
    for f in [&f1, &f2, &f3] {
        assert_eq!(f.deliver(&replay, &f.doc(1, |_| {})).await.status, 200);
    }
    assert!(pending(&f1.ask(&replay).await));
    assert!(pending(&f2.ask(&replay).await));
    let third = f3.ask(&replay).await;
    assert_eq!(code(&third), (429, json!("quota_exceeded")));
    let first_list = body(&list(&replay, "wallet").await);
    assert_eq!(
        (
            first_list["max_pending"].clone(),
            first_list["full"].clone()
        ),
        (json!(2), json!(true))
    );
    let v5 = alice_policy(&replay, Some(&v4), 5, true, 1).await;
    let lowered = body(&list(&replay, "wallet").await);
    assert_eq!(lowered["requests"].as_array().expect("requests").len(), 2);
    assert_eq!(
        (lowered["max_pending"].clone(), lowered["full"].clone()),
        (json!(1), json!(true))
    );
    assert!(pending(&f1.ask(&replay).await), "already pending");
    assert_eq!(code(&f3.ask(&replay).await), (429, json!("quota_exceeded")));
    let v6 = alice_policy(&replay, Some(&v5), 6, false, 1).await;
    assert_eq!(code(&f3.ask(&replay).await), (403, json!("not_admitted")));
    assert_eq!(code(&f1.ask(&replay).await), (403, json!("not_admitted")));
    assert_eq!(requested(&list(&replay, "wallet").await).len(), 2);
    assert_eq!(decline(&replay, &pubky_id(&f1.pubky())).await.status, 200);
    alice_policy(&replay, Some(&v6), 7, true, 50).await;
    let on_again = body(&list(&replay, "wallet").await);
    assert_eq!(
        on_again["requests"],
        json!([first_list["requests"]
            .as_array()
            .expect("requests")
            .iter()
            .find(|r| r["pubky"] == json!(pubky_id(&f2.pubky())))
            .expect("f2")])
    );
    assert!(pending(&f3.ask(&replay).await));
    assert_eq!(requested(&list(&replay, "wallet").await).len(), 2);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_two_senders_at_once_take_the_last_slot_once() {
    // Two new senders at once, one slot left: one kept, the other `429`, one row.
    let Some(replay) = replay_with(Limits::default()).await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    alice_policy(&replay, None, 4, true, 1).await;
    let (f1, f2) = (fresh(21), fresh(22));
    for f in [&f1, &f2] {
        assert_eq!(f.deliver(&replay, &f.doc(1, |_| {})).await.status, 200);
    }
    let (a, b) = tokio::join!(f1.ask(&replay), f2.ask(&replay));
    let mut statuses = [a.status, b.status];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 429]);
    assert_eq!(
        sqlx_scalar(
            &replay,
            "SELECT count(*) FROM connect_requests WHERE account_id = $1"
        )
        .await,
        1
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_check_five_by_certificate() {
    // Check 5 against the certificate: listed with another certificate is `409
    // identity_needed` naming the held version; renewed and closed `403 not_current`;
    // renewed and open, pending.
    let Some(replay) = replay_with(Limits::default()).await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    alice_policy(&replay, None, 4, true, 50).await;
    let f = fresh(31);
    let app_id = f.cert.app_id();
    let other_cert = [9u8; 32];
    let held_cert = f.cert.hash();
    let renewed = |until: Option<u64>| {
        move |body: &mut IdentityBody| {
            body.apps[0].cert = other_cert;
            body.renewed = vec![RenewedCert {
                app_id,
                cert: held_cert,
                until,
            }];
        }
    };
    let another = f.doc(1, |body| body.apps[0].cert = other_cert);
    assert_eq!(f.deliver(&replay, &another).await.status, 200);
    let asked = f.ask(&replay).await;
    assert_eq!(code(&asked), (409, json!("identity_needed")));
    assert_eq!(body(&asked)["current"], json!({ "version": 1 }));
    assert_eq!(body(&asked)["known_version"], json!(1));
    let closed = f.doc(2, renewed(Some(ms(&at()) - DAY)));
    assert_eq!(f.deliver(&replay, &closed).await.status, 200);
    assert_eq!(code(&f.ask(&replay).await), (403, json!("not_current")));
    let open = f.doc(3, renewed(None));
    assert_eq!(f.deliver(&replay, &open).await.status, 200);
    assert!(pending(&f.ask(&replay).await));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_denied_before_it_delivers_reads_like_a_stranger() {
    // Denied before its first delivery: its delivery and its asks read byte for byte as a
    // stranger's at the same switch, and only the stranger's request is kept.
    let Some(replay) = replay_with(Limits::default()).await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    alice_policy(&replay, None, 4, true, 50).await;
    let (denied, stranger) = (fresh(41), fresh(42));
    wallet_op(
        &replay,
        OpKind::DenyPut {
            pubky: denied.pubky(),
        },
        60,
    )
    .await;
    let d1 = denied.deliver(&replay, &denied.doc(1, |_| {})).await;
    let s1 = stranger.deliver(&replay, &stranger.doc(1, |_| {})).await;
    assert_eq!(status_body(&d1), status_body(&s1));
    for _ in 0..2 {
        let d = denied.ask(&replay).await;
        let s = stranger.ask(&replay).await;
        assert_eq!(status_body(&d), status_body(&s));
        assert!(header_text(&d, header::HEAD).is_none());
    }
    assert_eq!(
        requested(&list(&replay, "wallet").await),
        [pubky_id(&stranger.pubky())]
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_strangers_flood_flags_no_admitted_sender() {
    // `stranger_per_min` 3, spent by fresh identities (bob's delivery in `serving` took
    // one). Then bob, a contact by now, asks three times: each a `429`, but the strangers'
    // rate belongs to the account, so none is a hit on his flag and `GET /allow` shows
    // nobody flagged (Switch wire 7.4.7, 9.4). His delivery still passes (no stranger rate
    // for an admitted sender), and own apps read on.
    let limits = Limits {
        stranger_per_min: 3,
        ..Limits::default()
    };
    let Some(replay) = serving(limits, 50).await else {
        return;
    };
    let f1 = fresh(51);
    assert_eq!(f1.deliver(&replay, &f1.doc(1, |_| {})).await.status, 200);
    assert!(pending(&f1.ask(&replay).await));
    let f2 = fresh(52);
    assert_eq!(
        code(&f2.deliver(&replay, &f2.doc(1, |_| {})).await),
        (429, json!("rate_limited"))
    );
    wallet_op(
        &replay,
        OpKind::AllowPut {
            pubky: bob(),
            kind: AllowKind::Contact,
        },
        61,
    )
    .await;
    deliver_bob(&replay).await;
    for _ in 0..3 {
        assert_eq!(code(&ask(&replay).await), (429, json!("rate_limited")));
    }
    let keys = vectors("keys.json");
    let allow = replay
        .service
        .handle(app_request(
            app(&keys, "wallet"),
            "GET",
            &format!("/v1/{}/allow", alice_id()),
            Vec::new(),
            ms(&at()),
        ))
        .await;
    assert_eq!(allow.status, 200);
    assert_eq!(body(&allow)["flagged"], json!([]));
    assert_eq!(list(&replay, "wallet").await.status, 200);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_flag_rows_stay_bounded_under_fresh_identities() {
    // `max_flags` 2: four fresh identities each refused once by `connect_per_min` 1.
    let limits = Limits {
        connect_per_min: 1,
        max_flags: 2,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    alice_policy(&replay, None, 4, true, 50).await;
    for n in 61..65 {
        let f = fresh(n);
        assert_eq!(f.deliver(&replay, &f.doc(1, |_| {})).await.status, 200);
        assert!(pending(&f.ask(&replay).await));
        assert_eq!(code(&f.ask(&replay).await), (429, json!("rate_limited")));
    }
    assert_eq!(
        sqlx_scalar(
            &replay,
            "SELECT count(*) FROM sender_flags WHERE account_id = $1"
        )
        .await,
        2
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_get_and_delete_edges() {
    // A malformed pubky is `404`; the signer's GET and DELETE `403 permission_missing`; an
    // app of another identity's GET and DELETE `403 permission_missing`, as at every
    // own-app call (rules.rs); the signer's POST `403 permission_missing`.
    let Some(replay) = serving(Limits::default(), 50).await else {
        return;
    };
    assert_eq!(
        code(&decline(&replay, "not-a-pubky").await),
        (404, json!("not_found"))
    );
    let connect = format!("/v1/{}/connect", alice_id());
    let one = format!("/v1/{}/connect/{}", alice_id(), pubky_id(&bob()));
    for (method, path) in [("GET", &connect), ("DELETE", &one), ("POST", &connect)] {
        let signer = replay
            .service
            .handle(signer_request(method, path, Vec::new(), ms(&at())))
            .await;
        assert_eq!(
            code(&signer),
            (403, json!("permission_missing")),
            "signer {method}"
        );
    }
    for (method, path) in [("GET", &connect), ("DELETE", &one)] {
        let other = replay
            .service
            .handle(other_request(
                "shop",
                ORIGIN,
                method,
                path,
                Vec::new(),
                None,
                ms(&at()),
            ))
            .await;
        assert_eq!(
            code(&other),
            (403, json!("permission_missing")),
            "other {method}"
        );
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_cap_is_clamped_at_post_too() {
    // `max_connect_pending` 1 under a policy of 50: the second new sender is refused.
    let limits = Limits {
        max_connect_pending: 1,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    alice_policy(&replay, None, 4, true, 50).await;
    let (f1, f2) = (fresh(71), fresh(72));
    for f in [&f1, &f2] {
        assert_eq!(f.deliver(&replay, &f.doc(1, |_| {})).await.status, 200);
    }
    assert!(pending(&f1.ask(&replay).await));
    assert_eq!(code(&f2.ask(&replay).await), (429, json!("quota_exceeded")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_denied_contact_at_a_full_list_reads_like_a_stranger() {
    // A contact the deny list overrides isn't admitted: at a full list it gets the
    // stranger's `429`, not `pending`.
    let Some(replay) = serving(Limits::default(), 0).await else {
        return;
    };
    let stranger = ask(&replay).await;
    assert_eq!(code(&stranger), (429, json!("quota_exceeded")));
    wallet_op(
        &replay,
        OpKind::AllowPut {
            pubky: bob(),
            kind: AllowKind::Contact,
        },
        62,
    )
    .await;
    wallet_op(&replay, OpKind::DenyPut { pubky: bob() }, 63).await;
    assert_eq!(status_body(&ask(&replay).await), status_body(&stranger));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_request_kept_at_the_service_time() {
    // A request is kept with the service time of its commit, here the time base the
    // requests come at, and a repeat keeps it.
    let Some(replay) = serving(Limits::default(), 50).await else {
        return;
    };
    assert!(pending(&ask(&replay).await));
    let listed = list(&replay, "wallet").await;
    let kept = body(&listed)["requests"][0]["at"].clone();
    assert_eq!(kept, json!(pubky_switch_core::time::rfc3339(ms(&at()))));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_request_decline_needs_conversation_add() {
    // An own app whose certificate holds `lists.read` but not `conversation.add` reads the
    // requests, but its decline is `403 permission_missing`, and the request stays until
    // the wallet declines it.
    let Some(replay) = serving(Limits::default(), 50).await else {
        return;
    };
    assert!(pending(&ask(&replay).await));
    let keys = vectors("keys.json");
    let alice_identity = IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let secret = [91; 32];
    let app_keys = AppKeys::from_secrets(secret, [92; 32]);
    let now = ms(&at());
    let cert = AppCert::issue(
        &alice_identity,
        AppCertBody::new(
            alice_identity.public(),
            app_keys.signing_public(),
            app_keys.bundle_public(),
            vec!["pay".into()],
            &[pubky_switch_core::scopes::Permission::ListsRead],
            now - DAY,
            now + 30 * DAY,
        ),
    )
    .expect("cert");
    let reader = Fresh {
        identity: alice_identity.clone(),
        secret,
        cert: cert.clone(),
    };
    let held: SignedDoc = serde_json::from_value(
        body(
            &replay
                .service
                .handle(request(
                    "GET",
                    &format!("/v1/{}/identity", alice_id()),
                    &[],
                    Vec::new(),
                ))
                .await,
        )["identity"]
            .clone(),
    )
    .expect("held");
    let mut next: IdentityBody =
        serde_json::from_slice(&held.body_bytes().expect("body")).expect("body");
    next.version += 1;
    next.apps.push(ListedApp {
        app_id: cert.app_id(),
        cert: cert.hash(),
    });
    let next = IdentityDoc::sign(&alice_identity, next)
        .expect("sign")
        .signed()
        .clone();
    let delivery = pubky_switch_core::http::IdentityDelivery {
        identity: next,
        prev: Some(held.doc_hash().expect("hash")),
    }
    .to_json();
    let delivered = replay
        .service
        .handle(signer_request(
            "PUT",
            &format!("/v1/{}/identity", alice_id()),
            delivery,
            now,
        ))
        .await;
    assert_eq!(
        delivered.status,
        200,
        "{}",
        String::from_utf8_lossy(&delivered.body)
    );
    // Its first call carries its app record.
    let record = pubky_switch_core::records::AppRecord::sign(
        &app_keys,
        pubky_switch_core::records::AppRecordBody::new(&cert, Vec::new(), now),
    )
    .expect("record");
    let ops = sign_batch(
        &app_keys,
        &alice_identity.public(),
        Some(cert.app_id()),
        1,
        [96; 16],
        vec![(
            Vec::new(),
            OpKind::AppPut {
                record: record.signed().clone(),
            },
        )],
    )
    .expect("batch");
    let signed: Vec<SignedDoc> = ops.iter().map(|op| op.signed().clone()).collect();
    let registered = replay
        .service
        .handle(reader.request(
            "POST",
            &format!("/v1/{}/ops", alice_id()),
            serde_json::to_vec(&json!({ "ops": signed })).expect("body"),
        ))
        .await;
    assert_eq!(
        registered.status,
        200,
        "{}",
        String::from_utf8_lossy(&registered.body)
    );
    let read = replay
        .service
        .handle(reader.request("GET", &format!("/v1/{}/connect", alice_id()), Vec::new()))
        .await;
    assert_eq!(read.status, 200, "{}", String::from_utf8_lossy(&read.body));
    let declined = replay
        .service
        .handle(reader.request(
            "DELETE",
            &format!("/v1/{}/connect/{}", alice_id(), pubky_id(&bob())),
            Vec::new(),
        ))
        .await;
    assert_eq!(code(&declined), (403, json!("permission_missing")));
    assert_eq!(
        requested(&list(&replay, "wallet").await),
        [pubky_id(&bob())]
    );
    assert_eq!(decline(&replay, &pubky_id(&bob())).await.status, 200);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_connect_erasure_forgets_the_connect_counts() {
    // A request counts against the sender's and the strangers' rates; the erasure forgets
    // every count of the account, these included (Switch wire 7.4.16).
    let Some(replay) = serving(Limits::default(), 50).await else {
        return;
    };
    assert!(pending(&ask(&replay).await));
    let before = replay.service.counted_at(&alice_id());
    assert!(before > 0);
    let keys = vectors("keys.json");
    let service_key: [u8; 32] = pubky_switch_core::enc::unb64(
        keys["service_keys"]
            .as_array()
            .expect("service keys")
            .iter()
            .find(|s| s["account"] == alice_id().as_str())
            .expect("alice's service key")["public"]
            .as_str()
            .expect("public"),
    )
    .expect("key")
    .try_into()
    .expect("32 bytes");
    let erase = signer_request(
        "POST",
        &format!("/v1/{}/erase", alice_id()),
        pubky_switch_core::http::erase_body(&service_key, None),
        ms(&at()),
    );
    let erased = replay.service.handle(erase).await;
    assert_eq!(
        erased.status,
        200,
        "{}",
        String::from_utf8_lossy(&erased.body)
    );
    assert_eq!(replay.service.counted_at(&alice_id()), 0);
    replay.db.drop_database().await.expect("drop");
}
