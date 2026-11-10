//! `GET /v1/{id}/directory` (Switch wire 7.4.10): the vector, who may read it, what it
//! lists, and the refusals.
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::http::{Handler, SwitchResponse};
use pubky_switch_core::{
    keys::AppKeys,
    ops::{AllowKind, OpKind, OpsRequest, sign_batch},
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

fn directory_path() -> String {
    format!("/v1/{}/directory", alice_id())
}

fn body(answer: &SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body)
        .unwrap_or_else(|_| panic!("json: {}", String::from_utf8_lossy(&answer.body)))
}

fn code_of(answer: &SwitchResponse) -> (u16, Value) {
    (answer.status, body(answer)["code"].clone())
}

/// The directory `http.json` signs for bob's shop.
fn vector_answer() -> Value {
    named(
        &vectors("http.json")["responses"],
        "app of another identity: directory, known_version in the body",
    )
    .clone()
}

/// The time of the vector's answer.
fn vector_time() -> String {
    vector_answer()["headers"]["switch-server-time"]
        .as_str()
        .expect("time")
        .to_string()
}

/// The time the setup's requests are signed at, before the vector's.
fn setup_time() -> String {
    item_time(chain_item(&vectors("chain.json"), 8))
}

async fn sql(replay: &Replay, query: &str) {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(query)
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("sql");
}

/// A batch of `ops` from alice's app `name`, signed with its keys.
async fn app_ops(replay: &Replay, name: &str, ops: Vec<OpKind>, batch: u8) {
    let keys = vectors("keys.json");
    let me = app(&keys, name);
    let signed = sign_batch(
        &AppKeys::from_secrets(
            hex32(&me["signing_secret_hex"]),
            hex32(&me["bundle_secret_hex"]),
        ),
        &hex32(&alice(&keys)["public_hex"]),
        Some(
            pubky_switch_core::enc::app_id_decode(me["app_id"].as_str().expect("id")).expect("id"),
        ),
        1,
        [batch; 16],
        ops.into_iter().map(|op| (Vec::new(), op)).collect(),
    )
    .expect("batch");
    let answer = replay
        .service
        .handle(app_request(
            me,
            "POST",
            &format!("/v1/{}/ops", alice_id()),
            OpsRequest::new(&signed, None).to_json(),
            ms(&setup_time()),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{name}: {}",
        String::from_utf8_lossy(&answer.body)
    );
}

fn signed(value: &Value) -> SignedDoc {
    serde_json::from_value(value.clone()).expect("signed")
}

fn bob_public() -> [u8; 32] {
    hex32(
        &vectors("keys.json")["identities"]
            .as_array()
            .expect("identities")
            .iter()
            .find(|identity| identity["name"] == "bob")
            .expect("bob")["public_hex"],
    )
}

/// alice's account after `chain.json` up to seq 8, before the phone's revocation, with the
/// phone and the executor registered with the records of `http.json`'s directory.
async fn alice_with_three_apps(replay: &Replay) {
    let chain = vectors("chain.json");
    serve_alice(replay).await;
    replay_batch(replay, &chain, &[3, 4]).await;
    assert_eq!(replay.db.give_out_seq(&alice_id()).await.expect("seq"), 5);
    replay_batch(replay, &chain, &[6]).await;
    replay_batch(replay, &chain, &[7, 8]).await;
    set_time(&replay.clock, &setup_time());
    let expected: Value =
        serde_json::from_str(vector_answer()["body"].as_str().expect("body")).expect("json");
    let keys = vectors("keys.json");
    for (name, batch) in [("phone", 101), ("executor", 102)] {
        let id = app(&keys, name)["app_id"].clone();
        let listed = expected["apps"]
            .as_array()
            .expect("apps")
            .iter()
            .find(|listed| listed["app_id"] == id)
            .expect("listed");
        app_ops(
            replay,
            name,
            vec![
                OpKind::AppPut {
                    record: signed(&listed["record"]),
                },
                OpKind::ReceiveKeyPut {
                    record: signed(&listed["receive_key"]),
                },
            ],
            batch,
        )
        .await;
    }
}

/// bob a contact of alice's, his `identity.json` version 1 held, delivered by his shop.
async fn with_bob(replay: &Replay) {
    app_ops(
        replay,
        "wallet",
        vec![OpKind::AllowPut {
            pubky: bob_public(),
            kind: AllowKind::Contact,
        }],
        103,
    )
    .await;
    let doc: SignedDoc =
        signed(&named(&vectors("documents.json")["documents"], "bob identity.json")["signed"]);
    let request = other_request(
        "shop",
        ORIGIN,
        "PUT",
        &format!("/v1/{}/peers", alice_id()),
        serde_json::to_vec(&doc).expect("body"),
        None,
        ms(&setup_time()),
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

fn from_shop(code: Option<&str>, at: &str) -> pubky_switch::http::SwitchRequest {
    other_request(
        "shop",
        ORIGIN,
        "GET",
        &directory_path(),
        Vec::new(),
        code,
        ms(at),
    )
}

#[tokio::test]
async fn test_directory_vector() {
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    with_bob(&replay).await;
    // The counters the generator's history reached, which this replay's shorter one
    // doesn't: they count changes, and every other member comes from the state above.
    sql(
        &replay,
        "UPDATE accounts SET directory_version = 7, apps_version = 4 WHERE id = $1",
    )
    .await;
    set_time(&replay.clock, &vector_time());
    // bob's shop reads it, its request rebuilt from keys.json: the signature is the
    // vector's, so the answer matches byte for byte, signature included.
    let request = from_shop(None, "2026-01-01T00:05:00Z");
    assert_eq!(
        request
            .headers
            .get("switch-signature")
            .and_then(|value| value.to_str().ok()),
        vector_answer()["request_signature"].as_str()
    );
    assert_matches(&replay.service.handle(request).await, &vector_answer());
    replay.db.drop_database().await.expect("drop");
}

const CODE: &str = "IRrC78oNIjZ4hcet2fYnJQ";

/// alice's wallet puts the invite code `CODE`, live for an hour, with one use.
async fn put_code(replay: &Replay, batch: u8) {
    app_ops(
        replay,
        "wallet",
        vec![OpKind::InviteCodePut(
            pubky_switch_core::ops::InviteCodePut {
                code_hash: pubky_switch_core::ident::invite_code_hash(CODE).expect("hash"),
                expires_at: ms(&setup_time()) + 3_600_000,
                max_uses: 1,
                context: pubky_switch_core::ops::InviteContext::new(json!(null)),
            },
        )],
        batch,
    )
    .await;
}

/// bob's `identity.json` version 2, changed by `change`, delivered by alice's wallet: an
/// own app delivers counterparties' documents without admission.
async fn deliver_bob_version(
    replay: &Replay,
    change: impl FnOnce(&mut pubky_switch_core::records::IdentityBody),
) {
    let v1 = signed(&named(&vectors("documents.json")["documents"], "bob identity.json")["signed"]);
    let mut body: pubky_switch_core::records::IdentityBody =
        serde_json::from_slice(&v1.body_bytes().expect("body")).expect("body");
    body.version = 2;
    change(&mut body);
    let bob_secret = vectors("keys.json")["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == "bob")
        .expect("bob")["secret_hex"]
        .clone();
    let key = pubky_switch_core::keys::IdentityKey::from_secret(hex32(&bob_secret));
    let v2 = pubky_switch_core::records::IdentityDoc::sign(&key, body)
        .expect("sign")
        .signed()
        .clone();
    let keys = vectors("keys.json");
    let answer = replay
        .service
        .handle(app_request(
            app(&keys, "wallet"),
            "PUT",
            &format!("/v1/{}/peers", alice_id()),
            serde_json::to_vec(&v2).expect("body"),
            ms(&setup_time()),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

fn shop_app_id() -> [u8; 16] {
    pubky_switch_core::enc::app_id_decode(
        app(&vectors("keys.json"), "shop")["app_id"]
            .as_str()
            .expect("id"),
    )
    .expect("app id")
}

fn app_ids(answer: &SwitchResponse) -> Vec<Value> {
    body(answer)["apps"]
        .as_array()
        .expect("apps")
        .iter()
        .map(|listed| listed["app_id"].clone())
        .collect()
}

#[tokio::test]
async fn test_directory_own_apps_and_the_signer() {
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    let keys = vectors("keys.json");
    let at = setup_time();
    // An own app: the directory with the head, and no known_version.
    let answer = replay
        .service
        .handle(app_request(
            app(&keys, "phone"),
            "GET",
            &directory_path(),
            Vec::new(),
            ms(&at),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(header_text(&answer, "switch-head").is_some());
    let read = body(&answer);
    assert!(read.get("known_version").is_none());
    assert_eq!(
        app_ids(&answer),
        ["wallet", "phone", "executor"]
            .map(|name| app(&keys, name)["app_id"].clone())
            .to_vec()
    );
    assert_eq!(
        read["identity"],
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json"
        )["signed"]
    );
    // The signer reads its apps with GET /apps, not the directory.
    let answer = replay
        .service
        .handle(signer_request(
            "GET",
            &directory_path(),
            Vec::new(),
            ms(&at),
        ))
        .await;
    assert_eq!(code_of(&answer), (403, json!("permission_missing")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_directory_lists_current_apps_only() {
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    let keys = vectors("keys.json");
    let at = setup_time();
    let read = |at: String| {
        let request = app_request(
            app(&keys, "wallet"),
            "GET",
            &directory_path(),
            Vec::new(),
            ms(&at),
        );
        async { replay.service.handle(request).await }
    };
    let before = body(&read(at.clone()).await)["apps_version"].clone();
    // The signer revokes the phone: it's no longer current, and leaves the directory.
    let phone = app(&keys, "phone")["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    let path = format!("/v1/{}/apps/{phone}/revoke", alice_id());
    let answer = replay
        .service
        .handle(signer_request("POST", &path, Vec::new(), ms(&at)))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let answer = read(at.clone()).await;
    assert_eq!(
        app_ids(&answer),
        ["wallet", "executor"]
            .map(|name| app(&keys, name)["app_id"].clone())
            .to_vec()
    );
    assert_ne!(body(&answer)["apps_version"], before);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_directory_leaves_out_expired_certificates() {
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    // The wallet's and the executor's certificates expire on 2026-12-01, the phone's a
    // month later: in between, only the phone is current.
    let between = "2026-12-15T00:00:00.000Z";
    set_time(&replay.clock, between);
    let keys = vectors("keys.json");
    let answer = replay
        .service
        .handle(app_request(
            app(&keys, "phone"),
            "GET",
            &directory_path(),
            Vec::new(),
            ms(between),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(
        app_ids(&answer),
        vec![app(&keys, "phone")["app_id"].clone()]
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_directory_admission() {
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    let at = setup_time();
    // Not a contact: 403 not_admitted.
    let answer = replay.service.handle(from_shop(None, &at)).await;
    assert_eq!(code_of(&answer), (403, json!("not_admitted")));
    assert_eq!(body(&answer)["message"], "7: sender not admitted");
    assert!(header_text(&answer, "switch-head").is_none());
    // A contact: the directory, with known_version, and no head. bob's copy isn't held
    // yet: null.
    app_ops(
        &replay,
        "wallet",
        vec![OpKind::AllowPut {
            pubky: bob_public(),
            kind: AllowKind::Contact,
        }],
        110,
    )
    .await;
    let answer = replay.service.handle(from_shop(None, &at)).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(header_text(&answer, "switch-head").is_none());
    assert_eq!(body(&answer)["known_version"], Value::Null);
    assert_eq!(app_ids(&answer).len(), 3);
    // Denied, though a contact: refused.
    app_ops(
        &replay,
        "wallet",
        vec![OpKind::DenyPut {
            pubky: bob_public(),
        }],
        111,
    )
    .await;
    let answer = replay.service.handle(from_shop(None, &at)).await;
    assert_eq!(code_of(&answer), (403, json!("not_admitted")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_directory_known_version_is_the_copy_held() {
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    with_bob(&replay).await;
    let answer = replay.service.handle(from_shop(None, &setup_time())).await;
    assert_eq!(body(&answer)["known_version"], 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_directory_no_stranger_reads_it_where_connect_requests_are_on() {
    // bob's switch takes connect requests; alice's wallet is a stranger there.
    let Some(bob_switch) = replay_at(
        BOB_ORIGIN,
        "service/bob",
        pubky_switch::limits::Limits::default(),
        false,
    )
    .await
    else {
        return;
    };
    let bob = serve_bob(&bob_switch).await;
    let at = "2026-01-01T00:09:00.000Z";
    set_time(&bob_switch.clock, at);
    let request = other_request(
        "wallet",
        BOB_ORIGIN,
        "GET",
        &format!("/v1/{bob}/directory"),
        Vec::new(),
        None,
        ms(at),
    );
    let answer = bob_switch.service.handle(request).await;
    assert_eq!(code_of(&answer), (403, json!("not_admitted")));
    bob_switch.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_directory_invite_code_admits_without_use_at_its_rate() {
    let limits = pubky_switch::limits::Limits {
        invite_reads_per_min: 2,
        ..pubky_switch::limits::Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    alice_with_three_apps(&replay).await;
    put_code(&replay, 120).await;
    let at = setup_time();
    // A live code admits a stranger's read, and isn't used.
    let answer = replay.service.handle(from_shop(Some(CODE), &at)).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let uses: i64 = sqlx::query_scalar("SELECT uses FROM invite_codes WHERE account_id = $1")
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("uses");
    assert_eq!(uses, 0);
    // The code's rate is shared with PUT /peers: one delivery, then the next read is
    // refused.
    let doc =
        signed(&named(&vectors("documents.json")["documents"], "bob identity.json")["signed"]);
    let delivery = other_request(
        "shop",
        ORIGIN,
        "PUT",
        &format!("/v1/{}/peers", alice_id()),
        serde_json::to_vec(&doc).expect("body"),
        Some(CODE),
        ms(&at),
    );
    assert_eq!(replay.service.handle(delivery).await.status, 200);
    let answer = replay.service.handle(from_shop(Some(CODE), &at)).await;
    assert_eq!(code_of(&answer), (429, json!("rate_limited")));
    // A wrong code admits nobody.
    let answer = replay
        .service
        .handle(from_shop(Some("AAAAAAAAAAAAAAAAAAAAAA"), &at))
        .await;
    assert_eq!(code_of(&answer), (403, json!("not_admitted")));
    // Without trusted time, a read only a code admits waits for it (Switch wire 7.3).
    let untrusted = replay.without_trusted_time();
    let answer = untrusted.handle(from_shop(Some(CODE), &at)).await;
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_directory_removed_app_counts_only_a_code() {
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    with_bob(&replay).await;
    put_code(&replay, 121).await;
    let shop = shop_app_id();
    deliver_bob_version(&replay, |body| {
        body.apps.retain(|listed| listed.app_id != shop);
        body.removed.push(pubky_switch_core::records::RemovedApp {
            app_id: shop,
            distrust_from: 0,
        });
    })
    .await;
    let at = setup_time();
    // bob is a contact, but that doesn't count for a removed app.
    let answer = replay.service.handle(from_shop(None, &at)).await;
    assert_eq!(code_of(&answer), (403, json!("not_admitted")));
    // A code admits it, and its known_version is null, as a stranger's would be, though
    // version 2 is held.
    let answer = replay.service.handle(from_shop(Some(CODE), &at)).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(body(&answer)["known_version"], Value::Null);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_directory_expired_certificate_of_another_identity() {
    let Some(replay) = replay().await else { return };
    alice_with_three_apps(&replay).await;
    with_bob(&replay).await;
    let expired = "2026-12-01T00:00:00.000Z";
    set_time(&replay.clock, expired);
    let answer = replay.service.handle(from_shop(None, expired)).await;
    assert_eq!(code_of(&answer), (403, json!("cert_expired")));
    assert_eq!(header_text(&answer, "switch-server-time"), Some(expired));
    replay.db.drop_database().await.expect("drop");
}
