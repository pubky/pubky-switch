//! `GET /v1/{id}/allow` (Switch wire 7.4.6) on `chain.json`'s account: every list present,
//! each whole; a service-written conversation entry with its code, context and last use;
//! flagged senders from `flag_after`; live invite codes only; who may read it; and the
//! answer's service time as the time of the state it shows.
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::http::{Handler, SwitchResponse};
use pubky_switch_core::{
    enc::unb64,
    envelope::{Recipient, seal},
    keys::AppKeys,
    ops::{AllowKind, InviteCodePut, InviteContext, OpKind, OpsRequest, sign_batch},
    sig::SignedDoc,
};
use serde_json::{Value, json};
use sqlx::Connection;
use support::*;

const CODE: &str = "IRrC78oNIjZ4hcet2fYnJQ";

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

fn identity_named(name: &str) -> Value {
    vectors("keys.json")["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == name)
        .cloned()
        .expect("identity")
}

fn bob_public() -> [u8; 32] {
    hex32(&identity_named("bob")["public_hex"])
}

fn allow_path() -> String {
    format!("/v1/{}/allow", alice_id())
}

/// `GET /allow` as alice's app `name` at `at`.
async fn read_as(replay: &Replay, name: &str, at: &str) -> SwitchResponse {
    let keys = vectors("keys.json");
    replay
        .service
        .handle(app_request(
            app(&keys, name),
            "GET",
            &allow_path(),
            Vec::new(),
            ms(at),
        ))
        .await
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

/// A batch of `op` from alice's wallet.
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
    let answer = replay
        .service
        .handle(app_request(
            wallet,
            "POST",
            &format!("/v1/{}/ops", alice_id()),
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
}

fn put_code(code: &str, expires_at: u64, max_uses: u64) -> OpKind {
    OpKind::InviteCodePut(InviteCodePut {
        code_hash: pubky_switch_core::ident::invite_code_hash(code).expect("hash"),
        expires_at,
        max_uses,
        context: InviteContext::new(json!({ "order": 7 })),
    })
}

/// An envelope for alice's wallet's receive key.
fn to_wallet(byte: u8) -> Vec<u8> {
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
        false,
    )
    .expect("seal")
}

async fn from_shop(
    replay: &Replay,
    method: &str,
    path: &str,
    body: Vec<u8>,
    code: Option<&str>,
) -> SwitchResponse {
    let request = other_request("shop", ORIGIN, method, path, body, code, ms(&at()));
    replay.service.handle(request).await
}

#[tokio::test]
async fn test_allow_every_list_present_and_empty() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let answer = read_as(&replay, "wallet", &at()).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    // All five, in the table's order, even when empty.
    assert_eq!(
        String::from_utf8_lossy(&answer.body),
        "{\"contacts\":[],\"conversations\":[],\"deny\":[],\"flagged\":[],\"invite_codes\":[]}"
    );
    assert!(header_text(&answer, "switch-head").is_some());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_allow_shows_each_list_whole() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let keys = vectors("keys.json");
    let wallet_id = app(&keys, "wallet")["app_id"].clone();
    // A contact, a deny entry, and three invite codes: one live, one expired, one used up.
    let stranger = [7u8; 32];
    wallet_op(
        &replay,
        OpKind::AllowPut {
            pubky: bob_public(),
            kind: AllowKind::Contact,
        },
        60,
    )
    .await;
    wallet_op(&replay, OpKind::DenyPut { pubky: stranger }, 61).await;
    wallet_op(&replay, put_code(CODE, ms(&at()) + 3_600_000, 2), 62).await;
    wallet_op(
        &replay,
        put_code("AAAAAAAAAAAAAAAAAAAAAA", ms(&at()) + 1, 1),
        63,
    )
    .await;
    wallet_op(
        &replay,
        put_code("BBBBBBBBBBBBBBBBBBBBBA", ms(&at()) + 3_600_000, 1),
        64,
    )
    .await;
    // The second expired, the third used up.
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    for (code, change) in [
        ("AAAAAAAAAAAAAAAAAAAAAA", "expires_at_ms = 0"),
        ("BBBBBBBBBBBBBBBBBBBBBA", "uses = max_uses"),
    ] {
        sqlx::query(&format!(
            "UPDATE invite_codes SET {change} WHERE account_id = $1 AND code_hash = $2"
        ))
        .bind(alice_id())
        .bind(
            pubky_switch_core::ident::invite_code_hash(code)
                .expect("hash")
                .as_slice(),
        )
        .execute(&mut conn)
        .await
        .expect("code");
    }
    // A conversation entry the service writes when the code admits bob's shop, then used
    // by a second append: it carries the code's hash and context, and its last use.
    wallet_op(
        &replay,
        OpKind::AllowDelete {
            pubky: bob_public(),
            kind: AllowKind::Contact,
        },
        65,
    )
    .await;
    let peers = format!("/v1/{}/peers", alice_id());
    let delivery = serde_json::to_vec(&doc("bob identity.json")).expect("body");
    assert_eq!(
        from_shop(&replay, "PUT", &peers, delivery, Some(CODE))
            .await
            .status,
        200
    );
    let version: i64 = {
        let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        sqlx::query_scalar("SELECT apps_version FROM accounts WHERE id = $1")
            .bind(alice_id())
            .fetch_one(&mut conn)
            .await
            .expect("version")
    };
    let inbox = format!("/v1/{}/inbox?apps_version={version}", alice_id());
    let first = from_shop(&replay, "POST", &inbox, to_wallet(1), Some(CODE)).await;
    assert_eq!(
        first.status,
        200,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    let second = from_shop(&replay, "POST", &inbox, to_wallet(2), None).await;
    assert_eq!(
        second.status,
        200,
        "{}",
        String::from_utf8_lossy(&second.body)
    );
    // Two senders flagged, one below flag_after.
    sql(
        &replay,
        "INSERT INTO sender_flags (account_id, pubky, hits, last_hit_ms) VALUES \
         ($1, decode(repeat('11', 32), 'hex'), 3, 0), ($1, decode(repeat('22', 32), 'hex'), 2, 0)",
    )
    .await;

    let answer = read_as(&replay, "wallet", &at()).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let lists = body(&answer);
    let bob_id = identity_named("bob")["pubky_id"].clone();
    assert_eq!(lists["contacts"], json!([]));
    assert_eq!(
        lists["deny"],
        json!([pubky_switch_core::enc::pubky_id(&stranger)])
    );
    let conversation = &lists["conversations"][0];
    assert_eq!(conversation["pubky"], bob_id);
    assert_eq!(conversation["written_by"], "service");
    assert_eq!(
        conversation["code_hash"],
        pubky_switch_core::enc::b64(
            &pubky_switch_core::ident::invite_code_hash(CODE).expect("hash")
        )
    );
    assert_eq!(conversation["context"], json!({ "order": 7 }));
    assert_eq!(conversation["at"], at());
    assert_eq!(conversation["last_used"], at());
    assert_eq!(lists["conversations"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        lists["flagged"],
        json!([{ "pubky": pubky_switch_core::enc::pubky_id(&[0x11; 32]), "hits": 3 }])
    );
    // Only the live code, used once by the append it admitted, without its context.
    let codes = lists["invite_codes"].as_array().expect("codes");
    assert_eq!(codes.len(), 1, "{codes:?}");
    assert_eq!(
        codes[0],
        json!({
            "code_hash": pubky_switch_core::enc::b64(
                &pubky_switch_core::ident::invite_code_hash(CODE).expect("hash")
            ),
            "expires_at": pubky_switch_core::time::rfc3339(ms(&at()) + 3_600_000),
            "max_uses": 2,
            "uses": 1,
            "written_by": wallet_id,
        })
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_allow_repeats_a_context_as_written() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    // A service-written conversation entry whose context holds numbers a re-serialization
    // would change.
    sql(
        &replay,
        "INSERT INTO list_entries (account_id, list, pubky, written_by, at_ms, code_hash, \
         context) VALUES ($1, 'conversation', decode(repeat('33', 32), 'hex'), NULL, 0, \
         decode(repeat('44', 32), 'hex'), convert_to('{\"n\":12345678901234567890123,\"r\":1.50}', 'UTF8'))",
    )
    .await;
    let answer = read_as(&replay, "wallet", &at()).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(
        String::from_utf8_lossy(&answer.body)
            .contains("\"context\":{\"n\":12345678901234567890123,\"r\":1.50}"),
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_allow_answer_time_is_the_state_read() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    // Read a minute later: the answer is signed at that service time, and shows the state
    // committed by then.
    let later = pubky_switch_core::time::rfc3339(ms(&at()) + 60_000);
    set_time(&replay.clock, &later);
    let answer = read_as(&replay, "wallet", &later).await;
    assert_eq!(answer.status, 200);
    assert_eq!(
        header_text(&answer, "switch-server-time"),
        Some(later.as_str())
    );
    // An expiry is judged at that time too: a code is live until the instant it expires,
    // and not at it.
    let expires = ms(&later) + 30_000;
    wallet_op(&replay, put_code(CODE, expires, 1), 70).await;
    let just_before = pubky_switch_core::time::rfc3339(expires - 1);
    set_time(&replay.clock, &just_before);
    let answer = read_as(&replay, "wallet", &just_before).await;
    assert_eq!(
        body(&answer)["invite_codes"].as_array().map(Vec::len),
        Some(1)
    );
    let at_expiry = pubky_switch_core::time::rfc3339(expires);
    set_time(&replay.clock, &at_expiry);
    let answer = read_as(&replay, "wallet", &at_expiry).await;
    assert_eq!(
        header_text(&answer, "switch-server-time"),
        Some(at_expiry.as_str())
    );
    assert_eq!(body(&answer)["invite_codes"], json!([]));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_allow_needs_lists_read() {
    let Some(replay) = replay().await else { return };
    let chain = vectors("chain.json");
    serve_alice(&replay).await;
    replay_batch(&replay, &chain, &[3, 4]).await;
    assert_eq!(replay.db.give_out_seq(&alice_id()).await.expect("seq"), 5);
    replay_batch(&replay, &chain, &[6]).await;
    replay_batch(&replay, &chain, &[7, 8]).await;
    set_time(&replay.clock, &at());
    // The executor registers; its certificate has no lists.read.
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
        [80; 16],
        vec![(
            Vec::new(),
            OpKind::AppPut {
                record: doc("executor app record"),
            },
        )],
    )
    .expect("batch");
    let answer = replay
        .service
        .handle(app_request(
            executor,
            "POST",
            &format!("/v1/{}/ops", alice_id()),
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
    let answer = read_as(&replay, "executor", &at()).await;
    assert_eq!(code_of(&answer), (403, json!("permission_missing")));
    assert!(
        header_text(&answer, "switch-head").is_some(),
        "a verified own app"
    );
    // The signer reads its own lists through its apps, not here.
    let answer = replay
        .service
        .handle(signer_request("GET", &allow_path(), Vec::new(), ms(&at())))
        .await;
    assert_eq!(code_of(&answer), (403, json!("permission_missing")));
    // An app of another identity: refused, with no head.
    let answer = from_shop(&replay, "GET", &allow_path(), Vec::new(), None).await;
    assert_eq!(code_of(&answer), (403, json!("not_admitted")));
    assert!(header_text(&answer, "switch-head").is_none());
    replay.db.drop_database().await.expect("drop");
}
