//! `GET /v1/{id}/feed` (Switch wire 7.4.4, 7.5) on `chain.json`'s account: the page
//! `http.json` shows, who may read what, paging, the refusals and the long-poll.
//!
//! The vectors fix the service key and the times; set `PUBKY_SWITCH_TEST_DATABASE_URL` to run
//! them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use std::time::Duration;

use pubky_switch::{changes::ChangeListener, http::Handler, http::SwitchResponse, limits::Limits};
use pubky_switch_core::{
    http::header,
    ops::{OpsRequest, SignedOp},
    sig::SignedDoc,
};
use serde_json::{Value, json};
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
    // The entry at seq 5 comes with the inbox. The record's create at seq 6, superseded by
    // the update at seq 8, shows as its stub (Switch wire 7.5); the rest as http.json has it.
    assert_eq!(seqs(&page), vec![6, 7, 8, 9]);
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
