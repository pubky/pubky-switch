//! `GET /v1/{id}/feed` (Switch wire 7.4.4, 7.5) on `chain.json`'s account: the page
//! `http.json` shows, who may read what, paging, the refusals and the long-poll.
//!
//! The vectors fix the service key and the times; set `PUBKY_SWITCH_TEST_DATABASE_URL` to run
//! them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use std::time::Duration;

use pubky_switch::{
    changes::ChangeListener,
    http::Handler,
    http::SwitchResponse,
    keys::{KeyId, KeyStore, Mark},
    limits::Limits,
};
use pubky_switch_core::{
    claims::{ClaimFields, ClaimType},
    enc::pubky_key,
    http::header,
    ops::{Condition, OpKind, OpsRequest, SignedOp, sign_batch},
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

/// The service time of `chain.json`'s revoke at seq 9, which the reads below are sent at.
fn revoke_time() -> String {
    item_time(chain_item(&vectors("chain.json"), 9))
}

/// `app`'s feed read with `query`, at `at`.
async fn read(replay: &Replay, app_name: &str, query: &str, at: &str) -> SwitchResponse {
    let keys = vectors("keys.json");
    let path = format!("/v1/{}/feed{query}", alice_id());
    let request = if app_name == "signer" {
        signer_request("GET", &path, Vec::new(), ms(at))
    } else {
        app_request(app(&keys, app_name), "GET", &path, Vec::new(), ms(at))
    };
    replay.service.handle(request).await
}

fn body(answer: &SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body)
        .unwrap_or_else(|_| panic!("json: {}", String::from_utf8_lossy(&answer.body)))
}

fn seqs(page: &Value) -> Vec<u64> {
    page["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["seq"].as_u64().expect("seq"))
        .collect()
}

#[tokio::test]
async fn test_feed_vectors_page_after_the_registration() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let http = vectors("http.json");
    let expected = named(
        &http["responses"],
        "own app: feed page with an entry and chain items",
    );
    let page_text = expected["body"].as_str().expect("body");
    let expected_page: Value = serde_json::from_str(page_text).expect("page");
    let answer = read(&replay, "wallet", "?after=1:4", &revoke_time()).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let page = body(&answer);
    let item_at = |page: &Value, seq: u64| -> Value {
        page["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| item["seq"] == seq)
            .cloned()
            .unwrap_or_else(|| panic!("no item {seq}"))
    };
    // The entry at seq 5 comes with the inbox; the rest as http.json has it, but for seq 6.
    assert_eq!(seqs(&page), vec![6, 7, 8, 9]);
    // The record's create at seq 6, superseded by the update at seq 8, shows as its stub
    // (Switch wire 7.5, 9.1). http.json's page shows it in full, against that text, and is
    // to be corrected; then this page is compared whole.
    assert_eq!(
        item_at(&page, 6),
        json!({ "type": "stub", "seq": 6, "stub": item_at(&expected_page, 6)["stub"] })
    );
    for seq in [7, 8, 9] {
        assert_eq!(
            item_at(&page, seq),
            item_at(&expected_page, seq),
            "seq {seq}"
        );
    }
    for member in ["next", "scanned_through", "more", "head"] {
        assert_eq!(page[member], expected_page[member], "{member}");
    }
    assert_eq!(
        header_text(&answer, header::HEAD),
        expected["headers"]["switch-head"].as_str(),
        "Switch-Head"
    );
    // As bytes too, in the member order of the vector: each of seqs 7, 8 and 9, and the
    // members after the items, appear in the vector's body exactly as this page writes
    // them. The whole body differs only by the entry at seq 5 and the stub at seq 6.
    let text = String::from_utf8(answer.body.clone()).expect("utf-8");
    for seq in [7, 8, 9] {
        let start = text
            .find(&format!("{{\"type\":\"chain\",\"seq\":{seq},"))
            .unwrap_or_else(|| panic!("seq {seq}"));
        let end = text[start..]
            .find(",{\"type\":")
            .or_else(|| text[start..].find("],\"next\""))
            .expect("end")
            + start;
        assert!(page_text.contains(&text[start..end]), "seq {seq} as bytes");
    }
    let tail = &text[text.find("],\"next\"").expect("tail")..];
    assert!(
        page_text.ends_with(tail),
        "the members after the items as bytes"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_pages_from_the_start_by_limit() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    // From the start: both identity.json deliveries, then the registration batch whole.
    let page = body(&read(&replay, "wallet", "?limit=3", &at).await);
    assert_eq!(seqs(&page), vec![1, 2, 3, 4]);
    assert_eq!(
        (page["next"].clone(), page["more"].clone()),
        (json!("1:4"), json!(true))
    );
    let page = body(&read(&replay, "wallet", "?after=1:4&limit=1", &at).await);
    assert_eq!(seqs(&page), vec![6]);
    assert_eq!(page["scanned_through"], 6);
    let page = body(&read(&replay, "wallet", "?after=1:6&limit=1", &at).await);
    assert_eq!(seqs(&page), vec![7, 8]);
    let page = body(&read(&replay, "wallet", "?after=1:8", &at).await);
    assert_eq!(seqs(&page), vec![9]);
    assert_eq!(
        (page["next"].clone(), page["more"].clone()),
        (json!("1:9"), json!(false))
    );
    // At the head: an empty page that keeps the position.
    let page = body(&read(&replay, "wallet", "?after=1:9", &at).await);
    assert_eq!((seqs(&page), page["next"].clone()), (vec![], json!("1:9")));
    // A position of another sequence reads from the start of this one.
    let page = body(&read(&replay, "wallet", "?after=2:7&limit=1", &at).await);
    assert_eq!(seqs(&page), vec![1]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_page_ends_at_the_byte_budget() {
    let limits = Limits {
        max_page_bytes: 1,
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    // Its first item or batch is shown whatever its size, and nothing more.
    let page = body(&read(&replay, "wallet", "", &at).await);
    assert_eq!((seqs(&page), page["more"].clone()), (vec![1], json!(true)));
    let page = body(&read(&replay, "wallet", "?after=1:2", &at).await);
    assert_eq!(
        (seqs(&page), page["next"].clone()),
        (vec![3, 4], json!("1:4"))
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_refusals() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    // Only own apps read the feed: the signer gets 403 permission_missing, with the head.
    let answer = read(&replay, "signer", "", &at).await;
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("permission_missing"))
    );
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");
    // A revoked app is no longer current.
    let answer = read(&replay, "phone", "", &at).await;
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("not_current"))
    );
    for query in [
        "?after=9",
        "?after=1:x",
        "?limit=0",
        "?limit=501",
        "?wait=26",
    ] {
        let answer = read(&replay, "wallet", query, &at).await;
        assert_eq!(answer.status, 400, "{query}");
    }
    replay.db.drop_database().await.expect("drop");
}

/// The wallet's delete of the record at seq 10 (`chain.json`'s `record_delete`).
async fn delete_record(replay: &Replay) {
    let chain = vectors("chain.json");
    let delete = &chain["record_delete"];
    let at = item_time(&delete["item"]);
    let signed: SignedDoc = serde_json::from_value(delete["item"]["item"].clone()).expect("op");
    let body = OpsRequest::new(&[SignedOp::peek(&signed).expect("op")], None).to_json();
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "POST",
        &format!("/v1/{}/ops", alice_id()),
        body,
        ms(&at),
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

#[tokio::test]
async fn test_feed_long_poll_wakes_at_a_change() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let listener = ChangeListener::connect(replay.db.store())
        .await
        .expect("listen");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(listener.run(replay.service.changes(), async {
        let _ = stopped.await;
    }));
    let chain = vectors("chain.json");
    let delete_at = item_time(&chain["record_delete"]["item"]);
    set_time(&replay.clock, &delete_at);
    let started = std::time::Instant::now();
    let (answer, ()) = tokio::join!(
        read(&replay, "wallet", "?after=1:9&wait=25", &delete_at),
        async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            delete_record(&replay).await;
        }
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "woken by the change"
    );
    let page = body(&answer);
    assert_eq!(seqs(&page), vec![10]);
    assert_eq!(page["items"][0]["type"], "chain");
    assert_eq!(
        page["items"][0]["proof"],
        chain["record_delete"]["transition_proof"]["signed"]
    );
    assert_eq!(
        page["head"]["chain_hash"],
        chain["record_delete"]["item"]["chain_hash"]
    );
    // The delete superseded the update at seq 8: a stub now.
    let page = body(&read(&replay, "wallet", "?after=1:7", &delete_at).await);
    assert_eq!(page["items"][0]["seq"], 8);
    assert_eq!(page["items"][0]["type"], "stub");
    let _ = stop.send(());
    task.await.expect("listener");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_long_poll_answers_when_the_wait_ends() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let started = std::time::Instant::now();
    let answer = read(&replay, "wallet", "?after=1:9&wait=1", &revoke_time()).await;
    assert!(started.elapsed() >= Duration::from_secs(1), "waited");
    let page = body(&answer);
    assert_eq!((seqs(&page), page["more"].clone()), (vec![], json!(false)));
    // A page with something to read is answered at once, whatever the wait.
    let started = std::time::Instant::now();
    let page = body(&read(&replay, "wallet", "?after=1:8&wait=25", &revoke_time()).await);
    assert!(started.elapsed() < Duration::from_secs(5), "at once");
    assert_eq!(seqs(&page), vec![9]);
    replay.db.drop_database().await.expect("drop");
}

fn app_batch(name: &str, id: u8, kinds: Vec<(Vec<Condition>, OpKind)>) -> Vec<SignedOp> {
    let keys = vectors("keys.json");
    let entry = app(&keys, name);
    let key = ed25519_dalek::SigningKey::from_bytes(&hex32(&entry["signing_secret_hex"]));
    let app_id: [u8; 16] = hex::decode(entry["app_id_bytes_hex"].as_str().expect("hex"))
        .expect("hex")
        .try_into()
        .expect("16");
    sign_batch(
        &key,
        &pubky_key(&alice_id()).expect("key"),
        Some(app_id),
        1,
        [id; 16],
        kinds,
    )
    .expect("batch")
}

async fn post(replay: &Replay, name: &str, ops: &[SignedOp], at_ms: u64) -> SwitchResponse {
    let keys = vectors("keys.json");
    let body = OpsRequest::new(ops, None).to_json();
    let path = format!("/v1/{}/ops", alice_id());
    replay
        .service
        .handle(app_request(app(&keys, name), "POST", &path, body, at_ms))
        .await
}

fn attempt(key: u8) -> (Vec<Condition>, OpKind) {
    (
        Vec::new(),
        OpKind::Claim(ClaimFields {
            claim_key: vec![key; 32],
            kind: ClaimType::Attempt,
            expected_step: 0,
            attempt_id: vec![8; 16],
            orphan_after: Some(60),
            deadline: None,
            basis: None,
            evidence_ref: None,
        }),
    )
}

async fn listen(
    replay: &Replay,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = ChangeListener::connect(replay.db.store())
        .await
        .expect("listen");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(listener.run(replay.service.changes(), async {
        let _ = stopped.await;
    }));
    (stop, task)
}

#[tokio::test]
async fn test_feed_long_poll_of_an_app_revoked_meanwhile_is_refused() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let record: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "executor app record",
        )["signed"]
            .clone(),
    )
    .expect("record");
    let at = "2026-01-01T00:00:10.000Z";
    set_time(&replay.clock, at);
    // The executor registers: seq 10.
    let answer = post(
        &replay,
        "executor",
        &app_batch(
            "executor",
            40,
            vec![(Vec::new(), OpKind::AppPut { record })],
        ),
        ms(at),
    )
    .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let (stop, task) = listen(&replay).await;
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet")["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    // The wallet waits after seq 11, its revocation's; the executor's attempt after the
    // revocation (seq 12) wakes the poll.
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:11&wait=10", at), async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let path = format!("/v1/{}/apps/{wallet}/revoke", alice_id());
        let revoked = replay
            .service
            .handle(signer_request("POST", &path, Vec::new(), ms(at)))
            .await;
        assert_eq!(revoked.status, 200, "revoked");
        tokio::time::sleep(Duration::from_millis(300)).await;
        let written = post(
            &replay,
            "executor",
            &app_batch("executor", 41, vec![attempt(9)]),
            ms(at),
        )
        .await;
        assert_eq!(
            written.status,
            200,
            "{}",
            String::from_utf8_lossy(&written.body)
        );
    });
    // Refused as a fresh request is, with the head: nothing of seq 12 reaches it.
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("not_current"))
    );
    // Its head is the one the request committed, which the key's mark covers: never the
    // newer head the page was read at.
    let key = service_key(&replay).await;
    let mark = replay.keys.mark(&key).await.expect("mark").expect("a mark");
    assert_eq!(head_seq(&answer), Some(10));
    assert!(mark.seq >= 10);
    let fresh = read(&replay, "wallet", "?after=1:11", at).await;
    assert_eq!(fresh.status, 403);
    let _ = stop.send(());
    task.await.expect("listener");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_long_poll_answers_at_the_time_it_reads() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let (stop, task) = listen(&replay).await;
    let early = "2026-01-01T00:00:04.000Z";
    set_time(&replay.clock, early);
    let chain = vectors("chain.json");
    let late = item_time(&chain["record_delete"]["item"]);
    let mut write_time = None;
    let (answer, ()) = tokio::join!(
        read(&replay, "wallet", "?after=1:9&wait=10", early),
        async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            set_time(&replay.clock, &late);
            delete_record(&replay).await;
            write_time = Some(rfc3339_of(&late));
        }
    );
    assert_eq!(seqs(&body(&answer)), vec![10]);
    // Signed at the time the page was read, never behind what it shows or an answer sent
    // before it (Switch spec 10.1).
    assert_eq!(
        header_text(&answer, header::SERVER_TIME).map(str::to_string),
        write_time
    );
    let _ = stop.send(());
    task.await.expect("listener");
    replay.db.drop_database().await.expect("drop");
}

fn rfc3339_of(text: &str) -> String {
    pubky_switch_core::time::rfc3339(ms(text))
}

#[tokio::test]
async fn test_feed_refuses_an_app_of_another_identity() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let keys = vectors("keys.json");
    let shop = app(&keys, "shop");
    let key = ed25519_dalek::SigningKey::from_bytes(&hex32(&shop["signing_secret_hex"]));
    let request = signed_request(
        &key,
        shop["identity"].as_str().expect("identity"),
        Some(shop["app_id"].as_str().expect("app")),
        "GET",
        &format!("/v1/{}/feed", alice_id()),
        Vec::new(),
        ms(&revoke_time()),
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("permission_missing"))
    );
    replay.db.drop_database().await.expect("drop");
}

async fn service_key(replay: &Replay) -> KeyId {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let id: String = sqlx::query_scalar("SELECT service_key FROM accounts WHERE id = $1")
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("key");
    KeyId::parse(&id).expect("key id")
}

async fn sql(replay: &Replay, statement: &str) {
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(statement)
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("statement");
}

#[tokio::test]
async fn test_feed_moves_the_mark_to_the_head_it_shows() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let key = service_key(&replay).await;
    // A head committed meanwhile by a request that hasn't moved the mark yet: the page
    // shows it, so the mark moves to it before the answer goes out.
    let at = revoke_time();
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:9&wait=1", &at), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        sql(
                &replay,
                "UPDATE accounts SET last_seq = 10, chain_seq = 10, chain_hash = decode(repeat('ab', 32), 'hex') \
                 WHERE id = $1",
            )
            .await;
    });
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(body(&answer)["head"]["seq"], 10);
    assert_eq!(
        replay.keys.mark(&key).await.expect("mark"),
        Some(Mark {
            generation: 1,
            seq: 10,
            chain_hash: [0xab; 32],
        })
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_refuses_a_head_behind_the_mark() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let key = service_key(&replay).await;
    // The key signed a head beyond the state the page reads: the page is refused with the
    // mark's 503, which carries no head.
    let at = revoke_time();
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:9&wait=1", &at), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mark = Mark {
            generation: 1,
            seq: 50,
            chain_hash: [0xcd; 32],
        };
        replay.keys.advance_mark(&key, mark).await.expect("mark");
    });
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (503, json!("unavailable"))
    );
    assert!(header_text(&answer, header::HEAD).is_none());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_of_an_account_erased_meanwhile_is_unknown() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, "wallet"),
        "GET",
        &format!("/v1/{}/feed?after=1:9&wait=1", alice_id()),
        Vec::new(),
        ms(&at),
    );
    let request_signature: [u8; 64] = pubky_switch_core::enc::unb64(
        request
            .headers
            .get(header::SIGNATURE)
            .and_then(|value| value.to_str().ok())
            .expect("signature"),
    )
    .expect("b64")
    .try_into()
    .expect("64");
    let (answer, ()) = tokio::join!(replay.service.handle(request), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        sql(&replay, "DELETE FROM accounts WHERE id = $1").await;
    });
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (404, json!("not_found"))
    );
    assert!(header_text(&answer, header::HEAD).is_none());
    // Signed with the operator key, as for an account the service doesn't hold.
    let signature: [u8; 64] = pubky_switch_core::enc::unb64(
        header_text(&answer, header::SERVICE_SIGNATURE).expect("signature"),
    )
    .expect("b64")
    .try_into()
    .expect("64");
    assert!(
        pubky_switch_core::http::verify_response(
            &operator_public(),
            404,
            Some(&request_signature),
            header_text(&answer, header::SERVER_TIME).expect("time"),
            &answer.body,
            &signature,
        )
        .is_ok()
    );
    replay.db.drop_database().await.expect("drop");
}

fn head_seq(answer: &SwitchResponse) -> Option<u64> {
    let text = header_text(answer, header::HEAD)?;
    let head = pubky_switch_core::chain::SignedHead::from_header(text).ok()?;
    head.to_value()["seq"].as_u64()
}

#[tokio::test]
async fn test_feed_expiry_is_judged_at_the_snapshots_time() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let key = service_key(&replay).await;
    let at = revoke_time();
    // A commit during the wait stamps a time past the wallet's certificate: the page read
    // after it refuses the wallet, by the snapshot's time, not the request's.
    let expired = ms("2026-12-01T00:00:01.000Z");
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:9&wait=1", &at), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        sql(
            &replay,
            &format!(
                "UPDATE accounts SET last_seq = 10, chain_seq = 10, \
                 chain_hash = decode(repeat('ab', 32), 'hex'), stamped_time_ms = {expired} \
                 WHERE id = $1"
            ),
        )
        .await;
    });
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (403, json!("cert_expired"))
    );
    // The request's own head, at 9, which the mark covers; not the snapshot's 10.
    let mark = replay.keys.mark(&key).await.expect("mark").expect("a mark");
    assert_eq!(head_seq(&answer), Some(9));
    assert!(mark.seq >= 9);
    assert_eq!(
        header_text(&answer, header::SERVER_TIME),
        Some(pubky_switch_core::time::rfc3339(expired).as_str())
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_store_failure_carries_the_requests_head() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:9&wait=1", &at), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        // A seq given out, so the page reads the chain, which then fails.
        sql(&replay, "UPDATE accounts SET last_seq = 10 WHERE id = $1").await;
        sql(
            &replay,
            "ALTER TABLE chain_items RENAME TO chain_items_gone",
        )
        .await;
    });
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (503, json!("unavailable"))
    );
    assert_eq!(head_seq(&answer), Some(9));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_of_an_account_moved_away_meanwhile_is_staged() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    // A version naming another switch arrives during the wait: the page is refused with
    // 503 staged, as a fresh request would be (Switch wire 7.3 step 7).
    let v3: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json",
        )["signed"]
            .clone(),
    )
    .expect("v3");
    let mut moved: pubky_switch_core::records::IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("body");
    moved.version = 4;
    moved.inbox.url = "https://other.example".into();
    let key = pubky_switch_core::keys::IdentityKey::from_secret(hex32(
        &alice(&vectors("keys.json"))["secret_hex"],
    ));
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
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:9&wait=1", &at), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
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
    });
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (503, json!("staged"))
    );
    assert!(head_seq(&answer).is_some());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_feed_401_from_the_page_check_counts_as_a_failed_authentication() {
    let Some(replay) = replay().await else { return };
    replay_chain_through_revoke(&replay).await;
    let at = revoke_time();
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet")["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    let wallet_bytes = hex::decode(
        app(&keys, "wallet")["app_id_bytes_hex"]
            .as_str()
            .expect("hex"),
    )
    .expect("hex");
    // The key the request verified with is no longer the app's by the next snapshot: its
    // record is gone. The page is refused 401, without a head, and the 401 counts.
    let (answer, ()) = tokio::join!(read(&replay, "wallet", "?after=1:9&wait=1", &at), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        sqlx::query("UPDATE apps SET record = NULL, receive_key = NULL WHERE app_id = $1")
            .bind(wallet_bytes.as_slice())
            .execute(&mut conn)
            .await
            .expect("update");
    });
    assert_eq!(
        (answer.status, body(&answer)["code"].clone()),
        (401, json!("bad_signature"))
    );
    assert!(header_text(&answer, header::HEAD).is_none());
    let claimed = (alice_id(), alice_id(), Some(wallet));
    assert_eq!(
        replay
            .service
            .failed_authentications()
            .claimed(&claimed, ms(&at)),
        1
    );
    replay.db.drop_database().await.expect("drop");
}
