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
    assert_eq!(body(&answer)["message"], "7: the sender isn't admitted");
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
