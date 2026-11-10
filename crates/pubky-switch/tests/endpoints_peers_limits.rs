//! `PUT /v1/{id}/peers` (Switch wire 7.4.5, 9.1) at the peer limit: floors that never go
//! back, removed apps and denied senders kept as strangers, and the refusals each rule
//! needs an endpoint test for.
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
    ident::invite_code_hash,
    keys::IdentityKey,
    ops::{AllowKind, InviteCodePut, InviteContext, OpKind, OpsRequest, sign_batch},
    records::{IdentityBody, IdentityDoc, IdentityPolicy, Inbox, RemovedApp},
    sig::SignedDoc,
};
use serde_json::{Value, json};
use sqlx::Connection;
use support::*;

fn doc(name: &str) -> SignedDoc {
    serde_json::from_value(named(&vectors("documents.json")["documents"], name)["signed"].clone())
        .expect("document")
}

fn identity(name: &str) -> Value {
    vectors("keys.json")["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == name)
        .cloned()
        .expect("identity")
}

fn body(answer: &SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body)
        .unwrap_or_else(|_| panic!("json: {}", String::from_utf8_lossy(&answer.body)))
}

fn delivery(doc: &SignedDoc) -> Vec<u8> {
    serde_json::to_vec(doc).expect("body")
}

fn changed(name: &str, base: &SignedDoc, change: impl FnOnce(&mut IdentityBody)) -> SignedDoc {
    let mut body: IdentityBody =
        serde_json::from_slice(&base.body_bytes().expect("body")).expect("identity body");
    change(&mut body);
    let key = IdentityKey::from_secret(hex32(&identity(name)["secret_hex"]));
    IdentityDoc::sign(&key, body)
        .expect("sign")
        .signed()
        .clone()
}

async fn wallet_op(replay: &Replay, op: OpKind, batch: u8, at: &str) {
    let alice = identity("alice");
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let wallet_keys = pubky_switch_core::keys::AppKeys::from_secrets(
        hex32(&wallet["signing_secret_hex"]),
        hex32(&wallet["bundle_secret_hex"]),
    );
    let app_id = pubky_switch_core::enc::app_id_decode(wallet["app_id"].as_str().expect("id"))
        .expect("app id");
    let ops = sign_batch(
        &wallet_keys,
        &hex32(&alice["public_hex"]),
        Some(app_id),
        1,
        [batch; 16],
        vec![(Vec::new(), op)],
    )
    .expect("batch");
    let path = format!("/v1/{}/ops", alice["pubky_id"].as_str().expect("id"));
    let answer = replay
        .service
        .handle(app_request(
            wallet,
            "POST",
            &path,
            OpsRequest::new(&ops, None).to_json(),
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

async fn contact(replay: &Replay, pubky: [u8; 32], add: bool, batch: u8, at: &str) {
    let op = if add {
        OpKind::AllowPut {
            pubky,
            kind: AllowKind::Contact,
        }
    } else {
        OpKind::AllowDelete {
            pubky,
            kind: AllowKind::Contact,
        }
    };
    wallet_op(replay, op, batch, at).await;
}

fn alice_path() -> String {
    format!(
        "/v1/{}/peers",
        identity("alice")["pubky_id"].as_str().expect("id")
    )
}

async fn from_wallet(replay: &Replay, doc: &SignedDoc, at: &str) -> SwitchResponse {
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "PUT",
        &alice_path(),
        delivery(doc),
        ms(at),
    );
    replay.service.handle(request).await
}

async fn from_shop(
    replay: &Replay,
    doc: &SignedDoc,
    code: Option<&str>,
    at: &str,
) -> SwitchResponse {
    let request = other_request(
        "shop",
        ORIGIN,
        "PUT",
        &alice_path(),
        delivery(doc),
        code,
        ms(at),
    );
    replay.service.handle(request).await
}

fn stranger_doc(seed: u8) -> ([u8; 32], SignedDoc) {
    let key = IdentityKey::from_secret([seed; 32]);
    let body = IdentityBody::first(
        key.public(),
        [seed; 16],
        Inbox {
            url: "https://inbox.other.example".into(),
            service_key: [seed; 32],
        },
        IdentityPolicy::default(),
    );
    (
        key.public(),
        IdentityDoc::sign(&key, body)
            .expect("sign")
            .signed()
            .clone(),
    )
}

async fn table(replay: &Replay, sql: &str) -> Vec<(Vec<u8>, i64)> {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query_as(sql)
        .fetch_all(&mut conn)
        .await
        .expect("rows")
}

/// A floor stays when a delivered copy drops itself, raised to it, so a lower version is
/// refused once the identity is admitted again.
#[tokio::test]
async fn test_peers_floor_stays_when_a_copy_drops_itself() {
    let Some(replay) = replay_with(Limits {
        max_peers: 1,
        ..Limits::default()
    })
    .await
    else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let bob = hex32(&identity("bob")["public_hex"]);
    let bob_v1 = doc("bob identity.json");
    let bob_v2 = changed("bob", &bob_v1, |b| b.version = 2);
    let bob_v3 = changed("bob", &bob_v1, |b| b.version = 3);
    contact(&replay, bob, true, 61, &at).await;
    assert_eq!(from_wallet(&replay, &bob_v2, &at).await.status, 200);
    let (carol, carol_v1) = stranger_doc(77);
    contact(&replay, carol, true, 62, &at).await;
    assert_eq!(from_wallet(&replay, &carol_v1, &at).await.status, 200);
    let floors = table(&replay, "SELECT identity, version FROM peer_floors").await;
    assert_eq!(
        floors,
        vec![(bob.to_vec(), 2)],
        "bob's dropped copy left a floor at 2"
    );
    // bob leaves the contacts; a delivery of his version 3 is answered as taken and drops
    // itself (no stranger's copy to drop instead).
    contact(&replay, bob, false, 63, &at).await;
    let answer = from_wallet(&replay, &bob_v3, &at).await;
    assert_eq!(
        (answer.status, body(&answer)),
        (200, json!({ "version": 3 }))
    );
    let copies = table(&replay, "SELECT identity, version FROM peer_copies").await;
    assert_eq!(copies, vec![(carol.to_vec(), 1)], "bob's v3 dropped itself");
    // Not kept: its floor stays, raised to the version it delivered.
    let floors = table(&replay, "SELECT identity, version FROM peer_floors").await;
    assert_eq!(
        floors,
        vec![(bob.to_vec(), 3)],
        "the floor stays, raised to 3"
    );
    // bob is a contact again; his version 1 is below both the floor (2) and the version the
    // service answered as taken (3).
    contact(&replay, bob, true, 64, &at).await;
    let answer = from_wallet(&replay, &bob_v1, &at).await;
    assert_eq!(
        answer.status, 409,
        "a lower version than a floor must stay refused"
    );
    replay.db.drop_database().await.expect("drop");
}

/// The same, driven by a removed app itself: the shop, removed by bob's version 2, can't
/// erase bob's floor with an invite code while bob isn't a contact, so bob's version 1
/// (listing it as current) isn't held once bob is a contact again.
#[tokio::test]
async fn test_peers_removed_app_gets_no_older_document_held() {
    let Some(replay) = replay_with(Limits {
        max_peers: 1,
        ..Limits::default()
    })
    .await
    else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let bob = hex32(&identity("bob")["public_hex"]);
    let bob_v1 = doc("bob identity.json");
    let removed = changed("bob", &bob_v1, |b| {
        let app = b.apps.remove(0);
        b.removed.push(RemovedApp {
            app_id: app.app_id,
            distrust_from: ms(&at),
        });
        b.version = 2;
    });
    // bob is a contact; an own app delivers his revocation (version 2); carol's copy then
    // pushes it out, leaving a floor at 2.
    contact(&replay, bob, true, 71, &at).await;
    assert_eq!(from_wallet(&replay, &removed, &at).await.status, 200);
    let (carol, carol_v1) = stranger_doc(78);
    contact(&replay, carol, true, 72, &at).await;
    assert_eq!(from_wallet(&replay, &carol_v1, &at).await.status, 200);
    // Before anything: the shop's version 1 is below the floor.
    // bob leaves the contacts (pruned, say). The shop holds a live invite code (an order).
    contact(&replay, bob, false, 73, &at).await;
    let code = "IRrC78oNIjZ4hcet2fYnJQ";
    wallet_op(
        &replay,
        OpKind::InviteCodePut(InviteCodePut {
            code_hash: invite_code_hash(code).expect("hash"),
            expires_at: ms(&at) + 3_600_000,
            max_uses: 1,
            context: InviteContext::new(json!({ "order": 7 })),
        }),
        74,
        &at,
    )
    .await;
    // The removed shop delivers the floor's own document: same body, so "kept", then dropped
    // as a stranger's, taking the floor with it.
    let answer = from_shop(&replay, &removed, Some(code), &at).await;
    assert_eq!(body(&answer), json!({ "known_version": 2, "version": 2 }));
    // bob is a contact again (the user writes to him); the shop delivers version 1, which
    // lists it as current, with no code.
    contact(&replay, bob, true, 75, &at).await;
    let answer = from_shop(&replay, &bob_v1, None, &at).await;
    assert_eq!(answer.status, 409, "bob's floor at 2 must refuse version 1");
    replay.db.drop_database().await.expect("drop");
}

/// A removed app of a contact identity, with connect requests off and no code, must be
/// refused like a stranger (a contact doesn't count for it).
#[tokio::test]
async fn test_peers_removed_app_of_a_contact_counts_no_contact() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let bob = hex32(&identity("bob")["public_hex"]);
    let bob_v1 = doc("bob identity.json");
    let removed = changed("bob", &bob_v1, |b| {
        let app = b.apps.remove(0);
        b.removed.push(RemovedApp {
            app_id: app.app_id,
            distrust_from: ms(&at),
        });
        b.version = 2;
    });
    contact(&replay, bob, true, 81, &at).await;
    // Listed only in the delivered document.
    let answer = from_shop(&replay, &removed, None, &at).await;
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("not_admitted"))
    );
    // Listed in the held copy.
    assert_eq!(from_wallet(&replay, &removed, &at).await.status, 200);
    let answer = from_shop(&replay, &bob_v1, None, &at).await;
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("not_admitted"))
    );
    replay.db.drop_database().await.expect("drop");
}

/// A 401 at PUT /peers counts against the network source.
#[tokio::test]
async fn test_peers_401_counts_against_the_source() {
    let Some(replay) = replay_with(Limits {
        auth_failures_per_source_per_min: 1,
        ..Limits::default()
    })
    .await
    else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let send = || {
        let mut request = other_request_as(
            "shop",
            "shop certificate",
            "cap",
            ORIGIN,
            "PUT",
            &alice_path(),
            delivery(&doc("bob identity.json")),
            None,
            ms(&at),
        );
        request.source = Some(pubky_switch::http::source::NetworkSource::of(
            "203.0.113.9".parse().expect("ip"),
        ));
        request
    };
    assert_eq!(replay.service.handle(send()).await.status, 401);
    assert_eq!(replay.service.handle(send()).await.status, 429);
    replay.db.drop_database().await.expect("drop");
}

/// A denied contact's copy is kept exactly like a stranger's (7.4.5): it drops first.
#[tokio::test]
async fn test_peers_denied_contacts_copy_drops_first() {
    let Some(replay) = replay_with(Limits {
        max_peers: 2,
        ..Limits::default()
    })
    .await
    else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let bob = hex32(&identity("bob")["public_hex"]);
    contact(&replay, bob, true, 91, &at).await;
    assert_eq!(
        from_wallet(&replay, &doc("bob identity.json"), &at)
            .await
            .status,
        200
    );
    wallet_op(&replay, OpKind::DenyPut { pubky: bob }, 92, &at).await;
    let (carol, carol_v1) = stranger_doc(79);
    assert_eq!(from_wallet(&replay, &carol_v1, &at).await.status, 200);
    let (dave, dave_v1) = stranger_doc(80);
    contact(&replay, dave, true, 93, &at).await;
    assert_eq!(from_wallet(&replay, &dave_v1, &at).await.status, 200);
    let copies = table(&replay, "SELECT identity, version FROM peer_copies").await;
    assert!(
        copies.iter().any(|(id, _)| *id == carol.to_vec()),
        "the denied bob's older copy should drop before carol's"
    );
    replay.db.drop_database().await.expect("drop");
}

/// A removed app's delivery, with no copy held, is kept as from a stranger (7.4.5): it never
/// pushes out an admitted identity's copy, though its identity is a contact.
#[tokio::test]
async fn test_peers_removed_apps_copy_never_pushes_out_an_admitted_one() {
    let Some(replay) = replay_with(Limits {
        max_peers: 1,
        ..Limits::default()
    })
    .await
    else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let bob = hex32(&identity("bob")["public_hex"]);
    let bob_v1 = doc("bob identity.json");
    let removed = changed("bob", &bob_v1, |b| {
        let app = b.apps.remove(0);
        b.removed.push(RemovedApp {
            app_id: app.app_id,
            distrust_from: ms(&at),
        });
        b.version = 2;
    });
    let (carol, carol_v1) = stranger_doc(70);
    contact(&replay, carol, true, 41, &at).await;
    assert_eq!(from_wallet(&replay, &carol_v1, &at).await.status, 200);
    contact(&replay, bob, true, 42, &at).await;
    let code = "IRrC78oNIjZ4hcet2fYnJQ";
    wallet_op(
        &replay,
        OpKind::InviteCodePut(InviteCodePut {
            code_hash: invite_code_hash(code).expect("hash"),
            expires_at: ms(&at) + 3_600_000,
            max_uses: 1,
            context: InviteContext::new(json!({ "order": 7 })),
        }),
        43,
        &at,
    )
    .await;
    let answer = from_shop(&replay, &removed, Some(code), &at).await;
    assert_eq!(body(&answer), json!({ "known_version": 2, "version": 2 }));
    let copies = table(&replay, "SELECT identity, version FROM peer_copies").await;
    assert_eq!(
        copies,
        vec![(carol.to_vec(), 1)],
        "a removed app's copy, kept as from a stranger, drops itself"
    );
    replay.db.drop_database().await.expect("drop");
}

/// A removed app is charged the invite code's rate like any delivery a code admits.
#[tokio::test]
async fn test_peers_removed_app_is_charged_the_invite_codes_rate() {
    let Some(replay) = replay_with(Limits {
        invite_reads_per_min: 1,
        ..Limits::default()
    })
    .await
    else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let bob_v1 = doc("bob identity.json");
    let removed = changed("bob", &bob_v1, |b| {
        let app = b.apps.remove(0);
        b.removed.push(RemovedApp {
            app_id: app.app_id,
            distrust_from: ms(&at),
        });
        b.version = 2;
    });
    let code = "IRrC78oNIjZ4hcet2fYnJQ";
    wallet_op(
        &replay,
        OpKind::InviteCodePut(InviteCodePut {
            code_hash: invite_code_hash(code).expect("hash"),
            expires_at: ms(&at) + 3_600_000,
            max_uses: 1,
            context: InviteContext::new(json!({ "order": 7 })),
        }),
        44,
        &at,
    )
    .await;
    assert_eq!(
        from_shop(&replay, &removed, Some(code), &at).await.status,
        200
    );
    let answer = from_shop(&replay, &removed, Some(code), &at).await;
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (429, json!("rate_limited"))
    );
    replay.db.drop_database().await.expect("drop");
}

/// The deny list is read: a denied contact is refused where connect requests are off.
#[tokio::test]
async fn test_peers_denied_contact_is_refused() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    let bob = hex32(&identity("bob")["public_hex"]);
    contact(&replay, bob, true, 45, &at).await;
    wallet_op(&replay, OpKind::DenyPut { pubky: bob }, 46, &at).await;
    let answer = from_shop(&replay, &doc("bob identity.json"), None, &at).await;
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("not_admitted"))
    );
    assert_eq!(body(&answer)["message"], "7: sender not admitted");
    replay.db.drop_database().await.expect("drop");
}

/// Another identity's expired certificate is 403 cert_expired at the feed and POST /ops,
/// before any permission (Switch wire 3.8).
#[tokio::test]
async fn test_peers_expired_certificate_comes_before_permissions_elsewhere() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let alice = identity("alice")["pubky_id"]
        .as_str()
        .expect("id")
        .to_string();
    let phone = vectors("keys.json")["apps"]
        .as_array()
        .expect("apps")
        .iter()
        .find(|app| app["name"] == "phone")
        .and_then(|app| app["app_id"].as_str())
        .expect("phone")
        .to_string();
    let calls = [
        ("GET", format!("/v1/{alice}/feed"), "permission_missing"),
        ("POST", format!("/v1/{alice}/ops"), "not_admitted"),
        ("PUT", format!("/v1/{alice}/identity"), "permission_missing"),
        (
            "POST",
            format!("/v1/{alice}/apps/{phone}/revoke"),
            "permission_missing",
        ),
        ("GET", format!("/v1/{alice}/apps"), "permission_missing"),
    ];
    let call = |method: &str, path: &str, at: &str| {
        other_request("shop", ORIGIN, method, path, b"{}".to_vec(), None, ms(at))
    };
    // Unexpired, the shop gets each call's own refusal.
    let at = item_time(chain_item(&vectors("chain.json"), 9));
    for (method, path, code) in &calls {
        let answer = replay.service.handle(call(method, path, &at)).await;
        assert_eq!(
            (answer.status, body(&answer)["code"].clone()),
            (403, json!(code)),
            "{method} {path}"
        );
    }
    // Expired, `cert_expired` comes first.
    let expired = "2026-12-01T00:00:00.000Z";
    set_time(&replay.clock, expired);
    for (method, path, _) in &calls {
        let answer = replay.service.handle(call(method, path, expired)).await;
        assert_eq!(
            (answer.status, body(&answer)["code"].clone()),
            (403, json!("cert_expired")),
            "{method} {path}"
        );
        assert!(header_text(&answer, "switch-head").is_none());
    }
    replay.db.drop_database().await.expect("drop");
}
