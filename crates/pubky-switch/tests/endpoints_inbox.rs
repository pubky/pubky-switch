//! `POST /v1/{id}/inbox` (Switch wire 7.4.3) on `chain.json`'s account: an append from bob's
//! shop, admitted, listed in the switch's copy of bob's `identity.json`, its entry in the
//! wallet's feed; the checks in their order, the rates and flags, the quotas, an invite
//! code's use, and an own app's append.
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
    ops::{AllowKind, InviteCodePut, InviteContext, OpKind, OpsRequest, Position, sign_batch},
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

/// An envelope for alice's wallet's receive key, of `byte` repeated.
fn to_wallet(byte: u8, notify: bool) -> Vec<u8> {
    let keys = vectors("keys.json");
    let public: [u8; 32] = unb64(
        app(&keys, "wallet")["receive_key"]["public"]
            .as_str()
            .expect("public"),
    )
    .expect("b64")
    .try_into()
    .expect("32");
    seal(
        &hex32(&alice(&keys)["public_hex"]),
        &[Recipient::new(public)],
        &[byte; 100],
        notify,
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

/// An append from bob's shop, with the invite code `code` if given.
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

/// A batch of `op` from alice's wallet.
async fn wallet_op(replay: &Replay, op: OpKind, batch: u8, cursor: Option<Position>) {
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let ops = match op {
        OpKind::ReceiveKeyPut { .. } => unreachable!(),
        op => sign_batch(
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
        .expect("batch"),
    };
    let path = format!("/v1/{}/ops", alice_id());
    let answer = replay
        .service
        .handle(app_request(
            wallet,
            "POST",
            &path,
            OpsRequest::new(&ops, cursor).to_json(),
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

async fn move_wallet_cursor(replay: &Replay, seq: u64) {
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/ops", alice_id());
    let cursor = OpsRequest::new(&[], Some(Position { generation: 1, seq })).to_json();
    let answer = replay
        .service
        .handle(app_request(
            app(&keys, "wallet"),
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

/// alice's account after `chain.json`, with bob a contact and his `identity.json` version 1
/// held, delivered by his shop.
async fn with_bob(replay: &Replay) {
    replay_chain_through_revoke(replay).await;
    wallet_op(
        replay,
        OpKind::AllowPut {
            pubky: hex32(&bob()["public_hex"]),
            kind: AllowKind::Contact,
        },
        61,
        None,
    )
    .await;
    deliver_bob(replay).await;
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

fn bob() -> Value {
    vectors("keys.json")["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == "bob")
        .cloned()
        .expect("bob")
}

async fn feed(replay: &Replay, after: &str) -> Value {
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/feed?after={after}", alice_id());
    body(
        &replay
            .service
            .handle(app_request(
                app(&keys, "wallet"),
                "GET",
                &path,
                Vec::new(),
                ms(&at()),
            ))
            .await,
    )
}

#[tokio::test]
async fn test_inbox_append_reaches_its_target_and_goes_once_read() {
    let Some(replay) = replay().await else { return };
    with_bob(&replay).await;
    let version = apps_version(&replay).await;
    let envelope = to_wallet(1, false);
    let answer = from_shop(&replay, envelope.clone(), Some(version), None).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    // No head to another identity's app; its identity's held version as known_version.
    assert!(header_text(&answer, "switch-head").is_none());
    let appended = body(&answer);
    assert_eq!(appended["known_version"], 1);
    let text = String::from_utf8(answer.body.clone()).expect("utf-8");
    assert!(
        text.starts_with("{\"entry_id\":"),
        "the table's order: {text}"
    );
    // A retry by content gets the same answer.
    let again = from_shop(&replay, envelope.clone(), Some(version), None).await;
    assert_eq!(again.body, answer.body);
    // The wallet reads it: the entry with the sender, its certificate and the envelope.
    let page = feed(&replay, "1:9").await;
    let entry = page["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["type"] == "entry")
        .cloned()
        .expect("the entry");
    assert_eq!(entry["entry_id"], appended["entry_id"]);
    assert_eq!(entry["sender"], bob()["pubky_id"]);
    assert_eq!(
        entry["cert"],
        serde_json::to_value(doc("shop certificate")).expect("cert")
    );
    assert_eq!(entry["accepted_at"], appended["accepted_at"]);
    assert_eq!(
        unb64(entry["envelope"].as_str().expect("envelope")).expect("b64"),
        envelope
    );
    assert!(entry.get("context").is_none());
    let seq = entry["seq"].as_u64().expect("seq");
    let unread = || async {
        sql_value(
            &replay,
            "SELECT count(*) FROM inbox_entries WHERE account_id = $1",
        )
        .await
    };
    assert_eq!(unread().await, 1);
    // Its cursor past the entry, the only target's: the entry goes.
    move_wallet_cursor(&replay, seq).await;
    assert_eq!(unread().await, 0);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_checks_in_order() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let version = apps_version(&replay).await;
    // Not admitted: bob isn't a contact.
    let answer = from_shop(&replay, to_wallet(2, false), Some(version), None).await;
    assert_eq!(code_of(&answer), (403, json!("not_admitted")));
    assert_eq!(body(&answer)["message"], "7: sender not admitted");
    // Admitted, with no copy of bob's identity.json: 409 identity_needed, version null.
    wallet_op(
        &replay,
        OpKind::AllowPut {
            pubky: hex32(&bob()["public_hex"]),
            kind: AllowKind::Contact,
        },
        62,
        None,
    )
    .await;
    let answer = from_shop(&replay, to_wallet(2, false), Some(version), None).await;
    assert_eq!(code_of(&answer), (409, json!("identity_needed")));
    assert_eq!(body(&answer)["current"], json!({ "version": null }));
    assert_eq!(body(&answer)["known_version"], Value::Null);
    deliver_bob(&replay).await;
    // No apps_version: 400.
    assert_eq!(
        from_shop(&replay, to_wallet(2, false), None, None)
            .await
            .status,
        400
    );
    // A body that isn't an envelope: 400; over 64 KiB: 413, at the body cap.
    assert_eq!(
        from_shop(&replay, vec![0; 100], Some(version), None)
            .await
            .status,
        400
    );
    // A kid the account never registered: 409 stale_key, with unknown_kids.
    let stranger_key = seal(
        &hex32(&alice(&vectors("keys.json"))["public_hex"]),
        &[Recipient::new([9; 32])],
        &[0; 10],
        false,
    )
    .expect("seal");
    let answer = from_shop(&replay, stranger_key, Some(version), None).await;
    assert_eq!(code_of(&answer), (409, json!("stale_key")));
    assert_eq!(
        body(&answer)["current"]["unknown_kids"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(body(&answer)["current"]["apps_version"], version);
    // An apps_version older than the wallet's reachability: the wallet is added since and
    // must be a target; here it is, so the append goes through.
    let answer = from_shop(&replay, to_wallet(3, false), Some(version), None).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    // The signer doesn't append.
    let path = format!("/v1/{}/inbox?apps_version={version}", alice_id());
    let answer = replay
        .service
        .handle(signer_request(
            "POST",
            &path,
            to_wallet(4, false),
            ms(&at()),
        ))
        .await;
    assert_eq!(code_of(&answer), (403, json!("permission_missing")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_stale_key_names_apps_added_since() {
    let Some(replay) = replay().await else { return };
    with_bob(&replay).await;
    let version = apps_version(&replay).await;
    assert!(version >= 1);
    // Sealed for an older apps_version without a target: the wallet, added since, is named
    // with its app record and receive key record.
    let stranger_key = seal(
        &hex32(&alice(&vectors("keys.json"))["public_hex"]),
        &[Recipient::new([9; 32])],
        &[0; 10],
        false,
    )
    .expect("seal");
    let answer = from_shop(&replay, stranger_key, Some(version - 1), None).await;
    assert_eq!(code_of(&answer), (409, json!("stale_key")));
    let added = &body(&answer)["current"]["added_apps"];
    let keys = vectors("keys.json");
    assert_eq!(added[0]["app_id"], app(&keys, "wallet")["app_id"]);
    assert!(added[0]["app_record"].is_object() && added[0]["record"].is_object());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_stale_key_names_each_app_once() {
    let Some(replay) = replay().await else { return };
    with_bob(&replay).await;
    let version = apps_version(&replay).await;
    // A retired receive key of the wallet's, and one of no app's.
    let keys = vectors("keys.json");
    let wallet = pubky_switch_core::enc::app_id_decode(
        app(&keys, "wallet")["app_id"].as_str().expect("app id"),
    )
    .expect("app id");
    let retired = [9u8; 32];
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(
        "INSERT INTO receive_keys (account_id, kid, app_id, n, record) \
         VALUES ($1, $2, $3, 100, '\\x00')",
    )
    .bind(alice_id())
    .bind(pubky_switch_core::enc::kid(&retired).as_slice())
    .bind(wallet.as_slice())
    .execute(&mut conn)
    .await
    .expect("retired key");
    // Wrapped to the retired key, sealed for an apps_version before the wallet's: the
    // wallet is stale and added since, and is named once, in receive_keys.
    let seal_to = |publics: &[[u8; 32]]| {
        seal(
            &hex32(&alice(&keys)["public_hex"]),
            &publics
                .iter()
                .map(|public| Recipient::new(*public))
                .collect::<Vec<_>>(),
            &[0; 10],
            false,
        )
        .expect("seal")
    };
    let answer = from_shop(&replay, seal_to(&[retired]), Some(version - 1), None).await;
    assert_eq!(code_of(&answer), (409, json!("stale_key")));
    let current = &body(&answer)["current"];
    assert_eq!(current["receive_keys"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        current["receive_keys"][0]["app_id"],
        app(&keys, "wallet")["app_id"]
    );
    assert_eq!(current["added_apps"], json!([]));
    // Wrapped to the wallet twice, with its current key and the retired one: one app
    // wrapped to twice is 400 (Switch wire 4.4), found as the kids resolve.
    let current_key: [u8; 32] = unb64(
        app(&keys, "wallet")["receive_key"]["public"]
            .as_str()
            .expect("public"),
    )
    .expect("b64")
    .try_into()
    .expect("32");
    let answer = from_shop(
        &replay,
        seal_to(&[current_key, retired]),
        Some(version),
        None,
    )
    .await;
    assert_eq!(code_of(&answer), (400, json!("bad_request")));
    assert_eq!(body(&answer)["message"], "4.4: one app wrapped to twice");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_rates_and_flags() {
    let limits = Limits {
        sender_per_min: 1,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    with_bob(&replay).await;
    let version = apps_version(&replay).await;
    assert_eq!(
        from_shop(&replay, to_wallet(5, false), Some(version), None)
            .await
            .status,
        200
    );
    let answer = from_shop(&replay, to_wallet(6, false), Some(version), None).await;
    assert_eq!(code_of(&answer), (429, json!("rate_limited")));
    // The refusal counts a hit for bob, though the append was rolled back.
    assert_eq!(
        sql_value(
            &replay,
            "SELECT hits FROM sender_flags WHERE account_id = $1"
        )
        .await,
        1
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_notify_and_app_rates() {
    for (limits, notify) in [
        (
            Limits {
                notify_per_min: 1,
                ..Limits::default()
            },
            true,
        ),
        (
            Limits {
                sender_app_per_min: 1,
                ..Limits::default()
            },
            false,
        ),
    ] {
        let Some(replay) = replay_with(limits).await else {
            return;
        };
        with_bob(&replay).await;
        let version = apps_version(&replay).await;
        assert_eq!(
            from_shop(&replay, to_wallet(7, notify), Some(version), None)
                .await
                .status,
            200
        );
        let answer = from_shop(&replay, to_wallet(8, notify), Some(version), None).await;
        assert_eq!(code_of(&answer), (429, json!("rate_limited")));
        replay.db.drop_database().await.expect("drop");
    }
}

#[tokio::test]
async fn test_inbox_quota_then_the_senders_share() {
    let envelope = to_wallet(9, false);
    let entry = i64::try_from(envelope.len()).expect("len") + 256;
    let entry = u64::try_from(entry).expect("size");
    // Room for one entry: the second is refused for the inbox.
    let limits = Limits {
        quota_bytes: entry,
        sender_share_percent: 100,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    with_bob(&replay).await;
    let version = apps_version(&replay).await;
    assert_eq!(
        from_shop(&replay, envelope, Some(version), None)
            .await
            .status,
        200
    );
    let answer = from_shop(&replay, to_wallet(10, false), Some(version), None).await;
    assert_eq!(code_of(&answer), (429, json!("quota_exceeded")));
    assert_eq!(body(&answer)["current"]["limit"], "inbox");
    replay.db.drop_database().await.expect("drop");
    // Room for two, with a share of half: bob's second is refused for his share.
    let limits = Limits {
        quota_bytes: entry * 2,
        sender_share_percent: 50,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    with_bob(&replay).await;
    let version = apps_version(&replay).await;
    assert_eq!(
        from_shop(&replay, to_wallet(9, false), Some(version), None)
            .await
            .status,
        200
    );
    let answer = from_shop(&replay, to_wallet(10, false), Some(version), None).await;
    assert_eq!(body(&answer)["current"]["limit"], "sender_share");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_invite_code_admits_once_and_adds_a_conversation() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    deliver_bob_with_code(&replay).await;
    let version = apps_version(&replay).await;
    let code = "IRrC78oNIjZ4hcet2fYnJQ";
    let answer = from_shop(&replay, to_wallet(11, false), Some(version), Some(code)).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    // The code is used, and the service wrote bob's conversation entry naming it: a second
    // append needs no code.
    assert_eq!(
        sql_value(
            &replay,
            "SELECT uses FROM invite_codes WHERE account_id = $1"
        )
        .await,
        1
    );
    assert_eq!(
        sql_value(
            &replay,
            "SELECT count(*) FROM list_entries WHERE account_id = $1 AND list = 'conversation' \
             AND written_by IS NULL AND code_hash IS NOT NULL"
        )
        .await,
        1
    );
    let answer = from_shop(&replay, to_wallet(12, false), Some(version), None).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    // The feed shows the entry with the code's context, and the conversation.add item.
    let page = feed(&replay, "1:9").await;
    let items = page["items"].as_array().expect("items");
    assert!(
        items
            .iter()
            .any(|item| item["type"] == "chain" && item["context"] == json!({ "order": 7 }))
    );
    let first = items
        .iter()
        .find(|item| item["type"] == "entry")
        .expect("entry");
    assert_eq!(first["context"], json!({ "order": 7 }));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_invite_code_conversation_answers_the_senders_connect_request() {
    // The conversation entry the service writes at a code's first admitted append answers
    // the sender's pending connect request (Switch wire 7.4.7).
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    deliver_bob_with_code(&replay).await;
    let bob_hex = bob()["public_hex"].as_str().expect("hex").to_string();
    let pending = format!(
        "SELECT count(*) FROM connect_requests WHERE account_id = $1 \
         AND pubky = decode('{bob_hex}', 'hex')"
    );
    {
        use sqlx::Connection;
        let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        sqlx::query(&format!(
            "INSERT INTO connect_requests (account_id, pubky, at_ms) \
             VALUES ($1, decode('{bob_hex}', 'hex'), 0)"
        ))
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("a pending request");
    }
    assert_eq!(sql_value(&replay, &pending).await, 1);
    let version = apps_version(&replay).await;
    let code = "IRrC78oNIjZ4hcet2fYnJQ";
    let answer = from_shop(&replay, to_wallet(14, false), Some(version), Some(code)).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(sql_value(&replay, &pending).await, 0);
    replay.db.drop_database().await.expect("drop");
}

/// bob's shop delivers his identity.json with an invite code alice's wallet registered.
async fn deliver_bob_with_code(replay: &Replay) {
    let code = "IRrC78oNIjZ4hcet2fYnJQ";
    wallet_op(
        replay,
        OpKind::InviteCodePut(InviteCodePut {
            code_hash: pubky_switch_core::ident::invite_code_hash(code).expect("hash"),
            expires_at: ms(&at()) + 3_600_000,
            max_uses: 1,
            context: InviteContext::new(json!({ "order": 7 })),
        }),
        71,
        None,
    )
    .await;
    let path = format!("/v1/{}/peers", alice_id());
    let body = serde_json::to_vec(&doc("bob identity.json")).expect("body");
    let request = other_request("shop", ORIGIN, "PUT", &path, body, Some(code), ms(&at()));
    let answer = replay.service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

#[tokio::test]
async fn test_inbox_own_app_appends_without_admission() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let version = apps_version(&replay).await;
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/inbox?apps_version={version}", alice_id());
    let answer = replay
        .service
        .handle(app_request(
            app(&keys, "wallet"),
            "POST",
            &path,
            to_wallet(13, false),
            ms(&at()),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    // With the head, and no known_version.
    assert!(header_text(&answer, "switch-head").is_some());
    assert!(body(&answer).get("known_version").is_none());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_invite_context_reaches_the_feed_as_written() {
    use pubky_switch_core::{labels::sig::OP, ops::SignedOp};
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    // An invite_code.put whose context holds numbers a re-serialization would change.
    let code = "IRrC78oNIjZ4hcet2fYnJQ";
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let app_keys = AppKeys::from_secrets(
        hex32(&wallet["signing_secret_hex"]),
        hex32(&wallet["bundle_secret_hex"]),
    );
    let alice_key = hex32(&alice(&keys)["public_hex"]);
    let app_id = pubky_switch_core::enc::app_id_decode(wallet["app_id"].as_str().expect("id"))
        .expect("app id");
    let ops = sign_batch(
        &app_keys,
        &alice_key,
        Some(app_id),
        1,
        [91; 16],
        vec![(
            Vec::new(),
            OpKind::InviteCodePut(InviteCodePut {
                code_hash: pubky_switch_core::ident::invite_code_hash(code).expect("hash"),
                expires_at: ms(&at()) + 3_600_000,
                max_uses: 1,
                context: InviteContext::new(json!({ "order": 7 })),
            }),
        )],
    )
    .expect("batch");
    let written = r#"{"n":12345678901234567890123,"r":1.50}"#;
    let body_text = String::from_utf8(ops[0].signed().body_bytes().expect("body"))
        .expect("utf-8")
        .replace(
            r#""context":{"order":7}"#,
            &format!(r#""context":{written}"#),
        );
    assert!(body_text.contains(written));
    let signing = ed25519_dalek::SigningKey::from_bytes(&hex32(&wallet["signing_secret_hex"]));
    let signed = SignedDoc::sign_bytes(&signing, OP, &[&alice_key], body_text.into_bytes());
    let op = SignedOp::peek(&signed).expect("op");
    let path = format!("/v1/{}/ops", alice_id());
    let answer = replay
        .service
        .handle(app_request(
            wallet,
            "POST",
            &path,
            OpsRequest::new(&[op], None).to_json(),
            ms(&at()),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    // Stored as written.
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT context FROM invite_codes WHERE account_id = $1")
            .bind(alice_id())
            .fetch_one(&mut conn)
            .await
            .expect("context");
    assert_eq!(stored, written.as_bytes());
    // The shop, admitted by the code, appends: its entry shows the context as written.
    let path = format!("/v1/{}/peers", alice_id());
    let peer = serde_json::to_vec(&doc("bob identity.json")).expect("body");
    let request = other_request("shop", ORIGIN, "PUT", &path, peer, Some(code), ms(&at()));
    assert_eq!(replay.service.handle(request).await.status, 200);
    let version = apps_version(&replay).await;
    let answer = from_shop(&replay, to_wallet(21, false), Some(version), Some(code)).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let path = format!("/v1/{}/feed?after=1:9", alice_id());
    let page = replay
        .service
        .handle(app_request(
            app(&keys, "wallet"),
            "GET",
            &path,
            Vec::new(),
            ms(&at()),
        ))
        .await;
    let text = String::from_utf8(page.body).expect("utf-8");
    assert!(
        text.contains(&format!(r#""context":{written},"envelope""#)),
        "{text}"
    );
    replay.db.drop_database().await.expect("drop");
}

/// bob's version 2, by `change` over version 1, signed by his key, delivered by alice's
/// wallet.
async fn deliver_bob_version(
    replay: &Replay,
    change: impl FnOnce(&mut pubky_switch_core::records::IdentityBody),
) {
    let v1 = doc("bob identity.json");
    let mut body: pubky_switch_core::records::IdentityBody =
        serde_json::from_slice(&v1.body_bytes().expect("body")).expect("body");
    body.version = 2;
    change(&mut body);
    let key = pubky_switch_core::keys::IdentityKey::from_secret(hex32(&bob()["secret_hex"]));
    let v2 = pubky_switch_core::records::IdentityDoc::sign(&key, body)
        .expect("sign")
        .signed()
        .clone();
    // Delivered by alice's wallet: an own app delivers counterparties' documents without
    // admission, and a version listing the shop as removed can't come from the shop.
    let path = format!("/v1/{}/peers", alice_id());
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "PUT",
        &path,
        serde_json::to_vec(&v2).expect("body"),
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

fn shop_app_id() -> [u8; 16] {
    pubky_switch_core::enc::app_id_decode(
        app(&vectors("keys.json"), "shop")["app_id"]
            .as_str()
            .expect("id"),
    )
    .expect("app id")
}

#[tokio::test]
async fn test_inbox_removed_app_and_closed_renewal() {
    let Some(replay) = replay().await else { return };
    with_bob(&replay).await;
    let version = apps_version(&replay).await;
    // bob renews the shop to another certificate and closes the old one's renewal: the
    // shop, still on the old one, is no longer current.
    let shop = shop_app_id();
    let old = doc("shop certificate").doc_hash().expect("hash");
    deliver_bob_version(&replay, |body| {
        let listed = body
            .apps
            .iter_mut()
            .find(|listed| listed.app_id == shop)
            .expect("listed");
        listed.cert = [7; 32];
        body.renewed.push(pubky_switch_core::records::RenewedCert {
            app_id: shop,
            cert: old,
            until: Some(0),
        });
    })
    .await;
    let answer = from_shop(&replay, to_wallet(30, false), Some(version), None).await;
    assert_eq!(code_of(&answer), (403, json!("not_current")));
    replay.db.drop_database().await.expect("drop");

    // A copy listing the shop as removed: bob's contact entry doesn't count for it, so it's
    // refused like a stranger.
    let Some(replay) = support::replay().await else {
        return;
    };
    with_bob(&replay).await;
    let version = apps_version(&replay).await;
    deliver_bob_version(&replay, |body| {
        body.apps.retain(|listed| listed.app_id != shop);
        body.removed.push(pubky_switch_core::records::RemovedApp {
            app_id: shop,
            distrust_from: 0,
        });
    })
    .await;
    let answer = from_shop(&replay, to_wallet(31, false), Some(version), None).await;
    assert_eq!(code_of(&answer), (403, json!("not_admitted")));
    // Admitted by an invite code, it's answered like a stranger with no copy held: 409
    // identity_needed with version null, though a copy of version 2 is held.
    let code = "IRrC78oNIjZ4hcet2fYnJQ";
    wallet_op(
        &replay,
        OpKind::InviteCodePut(InviteCodePut {
            code_hash: pubky_switch_core::ident::invite_code_hash(code).expect("hash"),
            expires_at: ms(&at()) + 3_600_000,
            max_uses: 1,
            context: InviteContext::new(json!(null)),
        }),
        72,
        None,
    )
    .await;
    let answer = from_shop(&replay, to_wallet(32, false), Some(version), Some(code)).await;
    assert_eq!(code_of(&answer), (409, json!("identity_needed")));
    assert_eq!(body(&answer)["current"], json!({ "version": null }));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_retry_gets_the_original_answer() {
    let Some(replay) = replay().await else { return };
    with_bob(&replay).await;
    let version = apps_version(&replay).await;
    let envelope = to_wallet(33, false);
    let first = from_shop(&replay, envelope.clone(), Some(version), None).await;
    assert_eq!(
        first.status,
        200,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    assert_eq!(body(&first)["known_version"], 1);
    // bob's version 2 lists the shop as removed. The shop's retry still gets the original
    // answer, byte for byte, and so learns nothing of the version held now.
    let shop = shop_app_id();
    deliver_bob_version(&replay, |body| {
        body.apps.retain(|listed| listed.app_id != shop);
        body.removed.push(pubky_switch_core::records::RemovedApp {
            app_id: shop,
            distrust_from: 0,
        });
    })
    .await;
    let retry = from_shop(&replay, envelope, Some(version), None).await;
    assert_eq!(retry.status, 200);
    assert_eq!(retry.body, first.body);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_code_only_append_needs_trusted_time() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    // bob's copy, delivered by alice's wallet, and a live code he holds.
    deliver_bob_version(&replay, |_| {}).await;
    let code = "IRrC78oNIjZ4hcet2fYnJQ";
    wallet_op(
        &replay,
        OpKind::InviteCodePut(InviteCodePut {
            code_hash: pubky_switch_core::ident::invite_code_hash(code).expect("hash"),
            expires_at: ms(&at()) + 3_600_000,
            max_uses: 1,
            context: InviteContext::new(json!(null)),
        }),
        71,
        None,
    )
    .await;
    let version = apps_version(&replay).await;
    // At a service with no trusted time, only the code admits bob, and its expiry can't be
    // judged: 503, and the code unused.
    let untrusted = replay.without_trusted_time();
    let append = |code: Option<&str>| {
        other_request(
            "shop",
            ORIGIN,
            "POST",
            &format!("/v1/{}/inbox?apps_version={version}", alice_id()),
            to_wallet(40, false),
            code,
            ms(&at()),
        )
    };
    let answer = untrusted.handle(append(Some(code))).await;
    assert_eq!(code_of(&answer), (503, json!("unavailable")));
    assert_eq!(untrusted.time_refusals(), 1);
    assert_eq!(
        sql_value(
            &replay,
            "SELECT uses FROM invite_codes WHERE account_id = $1"
        )
        .await,
        0
    );
    // A contact needs no time: the same append is taken.
    wallet_op(
        &replay,
        OpKind::AllowPut {
            pubky: hex32(&bob()["public_hex"]),
            kind: AllowKind::Contact,
        },
        72,
        None,
    )
    .await;
    let answer = untrusted.handle(append(Some(code))).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_deny_list_and_connect_policy_admit_no_append() {
    let Some(replay) = replay().await else { return };
    with_bob(&replay).await;
    let version = apps_version(&replay).await;
    // Denied, though a contact.
    wallet_op(
        &replay,
        OpKind::DenyPut {
            pubky: hex32(&bob()["public_hex"]),
        },
        63,
        None,
    )
    .await;
    let answer = from_shop(&replay, to_wallet(32, false), Some(version), None).await;
    assert_eq!(code_of(&answer), (403, json!("not_admitted")));
    replay.db.drop_database().await.expect("drop");

    // alice's policy takes connect requests: a stranger may deliver its document, but not
    // append (Switch spec 7: a stranger can't write at all).
    let Some(replay) = support::replay().await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let v3 = doc("alice identity.json");
    let mut body: pubky_switch_core::records::IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("body");
    body.version = 4;
    body.policy.connect_requests.enabled = true;
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
    deliver_bob(&replay).await;
    let version = apps_version(&replay).await;
    let answer = from_shop(&replay, to_wallet(33, false), Some(version), None).await;
    assert_eq!(code_of(&answer), (403, json!("not_admitted")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_refused_append_uses_no_invite_code() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    deliver_bob_with_code(&replay).await;
    let version = apps_version(&replay).await;
    let code = "IRrC78oNIjZ4hcet2fYnJQ";
    // Admitted by the code, then refused at its targets: the code stays unused and no
    // conversation entry is written, all in the append's one transaction.
    let stranger_key = seal(
        &hex32(&alice(&vectors("keys.json"))["public_hex"]),
        &[Recipient::new([9; 32])],
        &[0; 10],
        false,
    )
    .expect("seal");
    let answer = from_shop(&replay, stranger_key, Some(version), Some(code)).await;
    assert_eq!(code_of(&answer), (409, json!("stale_key")));
    assert_eq!(
        sql_value(
            &replay,
            "SELECT uses FROM invite_codes WHERE account_id = $1"
        )
        .await,
        0
    );
    assert_eq!(
        sql_value(
            &replay,
            "SELECT count(*) FROM list_entries WHERE account_id = $1 AND list = 'conversation'"
        )
        .await,
        0
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_conversations_limit_refuses_a_code_admitted_append() {
    let limits = Limits {
        max_conversations: 0,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    deliver_bob_with_code(&replay).await;
    let version = apps_version(&replay).await;
    let answer = from_shop(
        &replay,
        to_wallet(34, false),
        Some(version),
        Some("IRrC78oNIjZ4hcet2fYnJQ"),
    )
    .await;
    assert_eq!(code_of(&answer), (429, json!("quota_exceeded")));
    assert_eq!(body(&answer)["current"]["limit"], "conversations");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_flags_only_rate_refusals_of_authenticated_senders() {
    let limits = Limits {
        sender_per_min: 0,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    with_bob(&replay).await;
    let version = apps_version(&replay).await;
    let flags = || async {
        sql_value(
            &replay,
            "SELECT coalesce(sum(hits), 0)::BIGINT FROM sender_flags WHERE account_id = $1",
        )
        .await
    };
    // A certificate that doesn't verify: 401, before any rate, and no hit.
    let path = format!("/v1/{}/inbox?apps_version={version}", alice_id());
    let request = other_request_as(
        "shop",
        "shop certificate",
        "cap",
        ORIGIN,
        "POST",
        &path,
        to_wallet(35, false),
        None,
        ms(&at()),
    );
    assert_eq!(replay.service.handle(request).await.status, 401);
    // A refusal other than a rate's: 400, and no hit.
    assert_eq!(
        from_shop(&replay, vec![0; 10], Some(version), None)
            .await
            .status,
        400
    );
    assert_eq!(flags().await, 0);
    // The rate: a hit.
    let answer = from_shop(&replay, to_wallet(36, false), Some(version), None).await;
    assert_eq!(code_of(&answer), (429, json!("rate_limited")));
    assert_eq!(flags().await, 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_inbox_entry_hidden_from_other_apps_and_counted_for_its_target() {
    let Some(replay) = replay().await else { return };
    with_bob(&replay).await;
    let version = apps_version(&replay).await;
    // The executor registers, so a second own app reads the feed.
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
        &ed25519_dalek::SigningKey::from_bytes(&hex32(&executor["signing_secret_hex"])),
        &hex32(&alice(&keys)["public_hex"]),
        Some(
            pubky_switch_core::enc::app_id_decode(executor["app_id"].as_str().expect("id"))
                .expect("app id"),
        ),
        1,
        [92; 16],
        vec![(Vec::new(), OpKind::AppPut { record })],
    )
    .expect("batch");
    let ops_path = format!("/v1/{}/ops", alice_id());
    let answer = replay
        .service
        .handle(app_request(
            executor,
            "POST",
            &ops_path,
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
    let appended = from_shop(&replay, to_wallet(37, false), Some(version), None).await;
    assert_eq!(appended.status, 200);
    let head: u64 =
        u64::try_from(sql_value(&replay, "SELECT last_seq FROM accounts WHERE id = $1").await)
            .expect("seq");
    // The executor isn't a target: no item for the entry, and its page passes the entry's
    // position like any other, so the gap in seqs is all it shows.
    let path = format!("/v1/{}/feed?after=1:9", alice_id());
    let page = body(
        &replay
            .service
            .handle(app_request(executor, "GET", &path, Vec::new(), ms(&at())))
            .await,
    );
    assert!(
        page["items"]
            .as_array()
            .expect("items")
            .iter()
            .all(|item| item["type"] != "entry")
    );
    assert_eq!(page["scanned_through"], head);
    assert_eq!(page["next"], format!("1:{head}"));
    // GET /apps counts it for the wallet, its only current target.
    let apps_path = format!("/v1/{}/apps", alice_id());
    let apps = body(
        &replay
            .service
            .handle(signer_request("GET", &apps_path, Vec::new(), ms(&at())))
            .await,
    );
    let wallet = apps["apps"]
        .as_array()
        .expect("apps")
        .iter()
        .find(|status| status["app_id"] == app(&keys, "wallet")["app_id"])
        .cloned()
        .expect("wallet");
    assert_eq!(
        (
            wallet["unread_entries"].clone(),
            wallet["sole_target_unread"].clone()
        ),
        (json!(1), json!(1))
    );
    replay.db.drop_database().await.expect("drop");
}
