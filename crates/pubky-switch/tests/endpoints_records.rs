//! `GET /v1/{id}/records/{key}` and `GET /v1/{id}/records` (Switch wire 7.4.9) on alice's
//! account with the wallet and the phone registered: the record view, who may read which
//! record by its `read_scope`, the list's order, paging by `limit` and by the byte budget,
//! and a page as the state under the lock, read after it.
//!
//! The wallet holds `pay`, `contacts` and `manage_contacts`; the phone `pay` and
//! `allowance`. Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use pubky_switch::{
    http::{Handler, SwitchResponse},
    limits::Limits,
};
use pubky_switch_core::{
    enc::b64,
    ident::{NamingKey, Policy, collection_id, record_key_from_blinded},
    keys::IdentityKey,
    ops::{IdInputs, OpKind, OpsRequest, RecordPut, RecordVersion, SignedOp, sign_batch},
    sealed::SealedValue,
    sig::SignedDoc,
};
use serde_json::{Value, json};
use support::*;

/// The time of the tests' writes and reads, after the registration.
const AT: &str = "2026-01-01T00:01:00.000Z";

const PAYMENTS: &str = "payments";

/// alice's current data epoch, at which the service takes sealed values (wire 6.2).
const DATA_EPOCH: u64 = 2;

fn alice_id() -> String {
    alice(&vectors("keys.json"))["pubky_id"]
        .as_str()
        .expect("id")
        .to_string()
}

fn alice_key() -> IdentityKey {
    IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]))
}

fn body(answer: &SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body)
        .unwrap_or_else(|_| panic!("json: {}", String::from_utf8_lossy(&answer.body)))
}

fn code_of(answer: &SwitchResponse) -> (u16, Value) {
    (answer.status, body(answer)["code"].clone())
}

fn document(name: &str) -> SignedDoc {
    serde_json::from_value(named(&vectors("documents.json")["documents"], name)["signed"].clone())
        .expect("document")
}

/// A batch of `app_name`'s (a `keys.json` app of alice's), with batch ID `[id; 16]`.
fn batch(app_name: &str, id: u8, kinds: Vec<OpKind>) -> Vec<SignedOp> {
    let keys = vectors("keys.json");
    let app = app(&keys, app_name);
    let key = ed25519_dalek::SigningKey::from_bytes(&hex32(&app["signing_secret_hex"]));
    let app_id =
        pubky_switch_core::enc::app_id_decode(app["app_id"].as_str().expect("id")).expect("app id");
    let kinds = kinds.into_iter().map(|kind| (Vec::new(), kind)).collect();
    sign_batch(
        &key,
        &alice_key().public(),
        Some(app_id),
        1,
        [id; 16],
        kinds,
    )
    .expect("batch")
}

/// Post `ops` from `app_name` at `at`; the answer's proofs.
async fn post(replay: &Replay, app_name: &str, ops: &[SignedOp], at: &str) -> Vec<SignedDoc> {
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, app_name),
        "POST",
        &format!("/v1/{}/ops", alice_id()),
        OpsRequest::new(ops, None).to_json(),
        ms(at),
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    serde_json::from_value(body(&answer)["proofs"].clone()).expect("proofs")
}

/// alice's account with the wallet and the phone registered.
async fn registered(limits: Limits) -> Option<Replay> {
    let replay = replay_with(limits).await?;
    serve_alice(&replay).await;
    let chain = vectors("chain.json");
    let at = item_time(chain_item(&chain, 3));
    set_time(&replay.clock, &at);
    let ops: Vec<SignedOp> = [3, 4]
        .iter()
        .map(|seq| {
            let signed: SignedDoc =
                serde_json::from_value(chain_item(&chain, *seq)["item"].clone()).expect("op");
            SignedOp::peek(&signed).expect("op")
        })
        .collect();
    post(&replay, "wallet", &ops, &at).await;
    set_time(&replay.clock, AT);
    let phone = batch(
        "phone",
        80,
        vec![
            OpKind::AppPut {
                record: document("phone app record"),
            },
            OpKind::ReceiveKeyPut {
                record: document("phone receive key record"),
            },
        ],
    );
    post(&replay, "phone", &phone, AT).await;
    Some(replay)
}

/// A record of `collection` at the natural key `natural`, read under `read_scope` and
/// written under `pay`, created with the value `value` (an empty one deletes).
fn record_put(
    collection: &str,
    natural: &[u8],
    read_scope: &str,
    expected: RecordVersion,
    value: &[u8],
) -> RecordPut {
    let alice = alice_key();
    let naming = NamingKey::from_root(&alice.switch_root());
    let policy = Policy::new(read_scope, &["pay"]);
    let blinded = naming.blind(natural);
    let key = record_key_from_blinded(collection, &blinded, &policy.hash().expect("policy"));
    let value_sealed = SealedValue::seal(
        &alice.scope_key(DATA_EPOCH, read_scope),
        &alice.public(),
        DATA_EPOCH,
        read_scope,
        &key,
        value,
    )
    .expect("sealed");
    let create = expected == RecordVersion::NONE;
    RecordPut {
        key,
        collection: collection_id(collection, &alice.public()),
        policy,
        expected_version: expected,
        value_sealed,
        id_inputs: create.then(|| IdInputs {
            collection: collection.to_string(),
            blinded_key: blinded,
        }),
    }
}

/// The wallet creates a record of [`PAYMENTS`] at `natural` read under `read_scope`, in
/// batch `id`: its key, the signed op and its proof.
async fn create(
    replay: &Replay,
    id: u8,
    natural: &[u8],
    read_scope: &str,
) -> ([u8; 32], SignedOp, SignedDoc) {
    let put = record_put(
        PAYMENTS,
        natural,
        read_scope,
        RecordVersion::NONE,
        b"{\"n\":1}",
    );
    let key = put.key;
    let ops = batch("wallet", id, vec![OpKind::RecordPut(put)]);
    let proofs = post(replay, "wallet", &ops, AT).await;
    (key, ops[0].clone(), proofs[0].clone())
}

/// `GET path` as alice's app `name`.
async fn get_as(replay: &Replay, name: &str, path: &str) -> SwitchResponse {
    let keys = vectors("keys.json");
    replay
        .service
        .handle(app_request(
            app(&keys, name),
            "GET",
            &format!("/v1/{}/{path}", alice_id()),
            Vec::new(),
            ms(AT),
        ))
        .await
}

fn list_path(collection: &[u8; 32], extra: &str) -> String {
    format!("records?collection={}{extra}", b64(collection))
}

fn payments() -> [u8; 32] {
    collection_id(PAYMENTS, &alice_key().public())
}

/// The keys of a page's records, as text.
fn keys_of(page: &Value) -> Vec<String> {
    page["records"]
        .as_array()
        .expect("records")
        .iter()
        .map(|view| view["key"].as_str().expect("key").to_string())
        .collect()
}

/// The last `seq` alice's account gave out.
async fn last_seq(replay: &Replay) -> u64 {
    let txn = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    let seq = txn.head().last_seq;
    txn.commit().await.expect("commit");
    seq
}

#[tokio::test]
async fn test_records_get_shows_the_view_to_a_reader_of_its_scope() {
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let (contacts, op, proof) = create(&replay, 1, b"contacts", "contacts").await;
    let (pay_sub, ..) = create(&replay, 2, b"sub", "pay:x").await;
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    // The wallet holds contacts: the whole view, with the head.
    let answer = get_as(&replay, "wallet", &format!("records/{}", b64(&contacts))).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(header_text(&answer, "switch-head").is_some(), "the head");
    let view = body(&answer);
    let proof_value = serde_json::to_value(&proof).expect("proof");
    let seq = view["version"].as_u64().expect("version");
    assert_eq!(
        view,
        json!({
            "key": b64(&contacts),
            "collection": b64(&payments()),
            "read_scope": "contacts",
            "write_scopes": ["pay"],
            "generation": 1,
            "version": seq,
            "seq": seq,
            "deleted": false,
            "writer": wallet["app_id"],
            "op": serde_json::to_value(op.signed()).expect("op"),
            "divergent": false,
            "proof": proof_value,
            "cert": serde_json::to_value(document("wallet certificate")).expect("cert"),
        })
    );
    // The phone doesn't hold contacts: refused, with the head.
    let answer = get_as(&replay, "phone", &format!("records/{}", b64(&contacts))).await;
    assert_eq!(code_of(&answer), (403, json!("permission_missing")));
    assert!(header_text(&answer, "switch-head").is_some(), "the head");
    // It holds pay, which covers pay:x.
    let answer = get_as(&replay, "phone", &format!("records/{}", b64(&pay_sub))).await;
    assert_eq!(answer.status, 200);
    assert_eq!(body(&answer)["read_scope"], "pay:x");
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_records_get_refusals_and_deleted_records() {
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let (gone, ..) = create(&replay, 1, b"gone", "pay").await;
    let version =
        body(&get_as(&replay, "wallet", &format!("records/{}", b64(&gone))).await)["version"]
            .as_u64()
            .expect("version");
    let delete = record_put(
        PAYMENTS,
        b"gone",
        "pay",
        RecordVersion::new(1, version),
        b"",
    );
    post(
        &replay,
        "wallet",
        &batch("wallet", 2, vec![OpKind::RecordPut(delete)]),
        AT,
    )
    .await;
    // A deleted record is shown, deleted.
    let answer = get_as(&replay, "phone", &format!("records/{}", b64(&gone))).await;
    assert_eq!(answer.status, 200);
    assert_eq!(body(&answer)["deleted"], true);
    // An unknown key is 404 with the head; a key that isn't b64(32) is 400.
    let answer = get_as(&replay, "phone", &format!("records/{}", b64(&[9; 32]))).await;
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    assert!(header_text(&answer, "switch-head").is_some(), "the head");
    let answer = get_as(&replay, "phone", "records/abc").await;
    assert_eq!(code_of(&answer), (400, json!("bad_request")));
    // The signer reads no records.
    let path = format!("/v1/{}/records/{}", alice_id(), b64(&gone));
    let answer = replay
        .service
        .handle(signer_request("GET", &path, Vec::new(), ms(AT)))
        .await;
    assert_eq!(code_of(&answer), (403, json!("permission_missing")));
    let list = format!("/v1/{}/{}", alice_id(), list_path(&payments(), ""));
    let answer = replay
        .service
        .handle(signer_request("GET", &list, Vec::new(), ms(AT)))
        .await;
    assert_eq!(code_of(&answer), (403, json!("permission_missing")));
    // Nor does an app of another identity, refused before the lock with no head.
    for path in [&path, &list] {
        let request = other_request("shop", ORIGIN, "GET", path, Vec::new(), None, ms(AT));
        let answer = replay.service.handle(request).await;
        assert_eq!(
            code_of(&answer),
            (403, json!("permission_missing")),
            "{path}"
        );
        assert!(header_text(&answer, "switch-head").is_none());
    }
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_records_list_shows_what_the_reader_may_read_by_key_text() {
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let mut readable_by_phone = Vec::new();
    let mut all = Vec::new();
    for (i, scope) in ["pay", "contacts", "pay:x", "pay", "contacts:y", "pay"]
        .iter()
        .enumerate()
    {
        let id = u8::try_from(i).expect("small") + 1;
        let (key, ..) = create(&replay, id, &[id], scope).await;
        all.push(b64(&key));
        if scope.starts_with("pay") {
            readable_by_phone.push(b64(&key));
        }
    }
    // A deleted record and another collection's are never listed.
    let (gone, ..) = create(&replay, 20, b"gone", "pay").await;
    let version =
        body(&get_as(&replay, "wallet", &format!("records/{}", b64(&gone))).await)["version"]
            .as_u64()
            .expect("version");
    let delete = record_put(
        PAYMENTS,
        b"gone",
        "pay",
        RecordVersion::new(1, version),
        b"",
    );
    let other = record_put("other", b"x", "pay", RecordVersion::NONE, b"{}");
    post(
        &replay,
        "wallet",
        &batch(
            "wallet",
            21,
            vec![OpKind::RecordPut(delete), OpKind::RecordPut(other)],
        ),
        AT,
    )
    .await;
    all.sort();
    readable_by_phone.sort();
    let seq = last_seq(&replay).await;
    let answer = get_as(&replay, "wallet", &list_path(&payments(), "")).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(header_text(&answer, "switch-head").is_some(), "the head");
    let page = body(&answer);
    assert_eq!(keys_of(&page), all);
    assert_eq!(page["seq"], seq);
    assert_eq!(page["next"], Value::Null);
    assert!(page["records"][0]["proof"].is_object(), "a view's proof");
    let page = body(&get_as(&replay, "phone", &list_path(&payments(), "")).await);
    assert_eq!(keys_of(&page), readable_by_phone);
    // `after` is exclusive.
    let after = format!("&after={}", readable_by_phone[0]);
    let page = body(&get_as(&replay, "phone", &list_path(&payments(), &after)).await);
    assert_eq!(keys_of(&page), readable_by_phone[1..].to_vec());
    // The query's refusals.
    for path in [
        "records".to_string(),
        "records?after=x".to_string(),
        list_path(&payments(), "&limit=0"),
        list_path(&payments(), "&limit=1001"),
        list_path(&payments(), "&after=abc"),
    ] {
        let answer = get_as(&replay, "phone", &path).await;
        assert_eq!(code_of(&answer), (400, json!("bad_request")), "{path}");
        assert!(header_text(&answer, "switch-head").is_some(), "the head");
    }
    replay.db.drop_database().await.expect("drop");
}

/// Every key a reader gets listing [`payments`] with `extra`, following `next`, and the
/// number of pages.
async fn follow(replay: &Replay, name: &str, extra: &str) -> (Vec<String>, usize) {
    let mut keys = Vec::new();
    let mut after = String::new();
    for pages in 1..=50 {
        let page = body(
            &get_as(
                replay,
                name,
                &list_path(&payments(), &format!("{extra}{after}")),
            )
            .await,
        );
        keys.extend(keys_of(&page));
        match page["next"].as_str() {
            Some(next) => {
                assert_eq!(
                    keys.last().map(String::as_str),
                    Some(next),
                    "next is the last key"
                );
                after = format!("&after={next}");
            }
            None => return (keys, pages),
        }
    }
    panic!("no last page");
}

#[tokio::test]
async fn test_records_list_pages_by_limit() {
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let mut all = Vec::new();
    for id in 1..=5u8 {
        all.push(b64(&create(&replay, id, &[id], "pay").await.0));
    }
    all.sort();
    assert_eq!(follow(&replay, "phone", "&limit=2").await, (all.clone(), 3));
    // A page that ends at the last record says so: no next, though it is full.
    let (keys, pages) = follow(&replay, "phone", "&limit=5").await;
    assert_eq!((keys, pages), (all, 1));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_records_list_pages_by_budget_with_its_first_view_whole() {
    // A budget smaller than any view: each page holds its first view, whatever its size.
    let limits = Limits {
        max_page_bytes: 1,
        ..Limits::default()
    };
    let Some(replay) = registered(limits).await else {
        return;
    };
    let mut all = Vec::new();
    for id in 1..=3u8 {
        all.push(b64(&create(&replay, id, &[id], "pay").await.0));
    }
    all.sort();
    assert_eq!(follow(&replay, "phone", "").await, (all, 3));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_records_list_reads_the_state_under_the_lock_not_after() {
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let (first, ..) = create(&replay, 1, b"first", "pay").await;
    let seq = last_seq(&replay).await;
    let list = list_path(&payments(), "");
    let pause = replay.db.pause_next_snapshot_read();
    let (answer, ()) = tokio::join!(get_as(&replay, "phone", &list), async {
        tokio::time::timeout(std::time::Duration::from_secs(10), pause.reached.notified())
            .await
            .expect("the read reached its pause once its request committed");
        // The read holds no lock: a write to the account goes on while it waits, and isn't
        // in its page.
        let write = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            create(&replay, 2, b"second", "pay"),
        )
        .await
        .expect("a write while the read waits");
        pause.resume.notify_one();
        let _ = write;
    });
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let page = body(&answer);
    assert_eq!(keys_of(&page), vec![b64(&first)]);
    assert_eq!(page["seq"], seq);
    // A read after it sees the write.
    let page = body(&get_as(&replay, "phone", &list_path(&payments(), "")).await);
    assert_eq!(keys_of(&page).len(), 2);
    assert!(page["seq"].as_u64().expect("seq") > seq);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_records_lists_of_an_account_wait_their_turn() {
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let (key, ..) = create(&replay, 1, b"first", "pay").await;
    let list = list_path(&payments(), "");
    let pause = replay.db.pause_next_snapshot_read();
    let exchange = async {
        tokio::join!(
            get_as(&replay, "phone", &list),
            async {
                tokio::time::timeout(std::time::Duration::from_secs(10), pause.reached.notified())
                    .await
                    .expect("the first list reached its pause");
                // Another list of the account waits its turn.
                get_as(&replay, "wallet", &list).await
            },
            async {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while replay.db.queued_reads(&alice_id()) != 2 {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the second list never queued"
                    );
                    tokio::task::yield_now().await;
                }
                // The phone holds its one place, whichever call it makes: its second list and
                // its GET /allow are refused at once, so no app takes two places by mixing
                // the calls.
                let again = get_as(&replay, "phone", &list).await;
                assert_eq!(code_of(&again), (503, json!("unavailable")));
                let allow = get_as(&replay, "phone", "allow").await;
                assert_eq!(code_of(&allow), (503, json!("unavailable")));
                // A read by key, under the lock, takes no turn and goes on.
                let by_key = get_as(&replay, "wallet", &format!("records/{}", b64(&key))).await;
                assert_eq!(by_key.status, 200);
                assert_eq!(replay.db.queued_reads(&alice_id()), 2);
                pause.resume.notify_one();
            }
        )
    };
    let (first, second, ()) = tokio::time::timeout(std::time::Duration::from_secs(30), exchange)
        .await
        .expect("both lists ended");
    assert_eq!(first.status, 200);
    assert_eq!(
        second.status,
        200,
        "{}",
        String::from_utf8_lossy(&second.body)
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_records_list_reads_past_one_read_of_the_snapshot() {
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    // More records than one read of the snapshot takes (32), in batches of 8.
    let mut all = Vec::new();
    for id in 1..=5u8 {
        let puts: Vec<OpKind> = (0..8u8)
            .map(|i| {
                let put = record_put(PAYMENTS, &[id, i], "pay", RecordVersion::NONE, b"{}");
                all.push(b64(&put.key));
                OpKind::RecordPut(put)
            })
            .collect();
        post(&replay, "wallet", &batch("wallet", id, puts), AT).await;
    }
    all.sort();
    assert_eq!(follow(&replay, "phone", "").await, (all.clone(), 1));
    // A limit past one read ends the page there, with the next.
    let page = body(&get_as(&replay, "phone", &list_path(&payments(), "&limit=35")).await);
    assert_eq!(keys_of(&page), all[..35].to_vec());
    assert_eq!(page["next"], json!(all[34]));
    replay.db.drop_database().await.expect("drop");
}

/// Turn the record at `key` into one taken from a recovery upload (Switch wire 7.4.14), as
/// the upload will: no proof, listed by the `upload` transition at `upload_seq`, its version
/// a lower bound; with one divergent upload kept when `divergent`.
async fn as_uploaded(replay: &Replay, key: &[u8; 32], upload_seq: u64, divergent: bool) {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(
        "UPDATE shared_records SET from_upload = true, proof = NULL, upload_seq = $3, \
         version_exact = false WHERE account_id = $1 AND key = $2",
    )
    .bind(alice_id())
    .bind(key.as_slice())
    .bind(i64::try_from(upload_seq).expect("seq"))
    .execute(&mut conn)
    .await
    .expect("uploaded");
    if divergent {
        sqlx::query(
            "INSERT INTO divergent_uploads (account_id, key, position, op, op_hash) \
             VALUES ($1, $2, 0, '\\x7b7d', $3)",
        )
        .bind(alice_id())
        .bind(key.as_slice())
        .bind([9u8; 32].as_slice())
        .execute(&mut conn)
        .await
        .expect("divergent");
    }
}

#[tokio::test]
async fn test_records_view_of_a_record_taken_from_an_upload() {
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let (key, ..) = create(&replay, 1, b"uploaded", "pay").await;
    let (plain, ..) = create(&replay, 2, b"plain", "pay").await;
    as_uploaded(&replay, &key, 40, true).await;
    // No proof, the upload transition's seq, and divergent (Switch wire 7.4.9).
    let view = body(&get_as(&replay, "wallet", &format!("records/{}", b64(&key))).await);
    assert!(view.get("proof").is_none(), "{view}");
    assert_eq!(view["seq"], 40);
    assert_eq!(view["divergent"], true);
    assert_ne!(view["version"], 40);
    // A list page shows the same.
    let page = body(&get_as(&replay, "wallet", &list_path(&payments(), "")).await);
    let views = page["records"].as_array().expect("records");
    let listed = views
        .iter()
        .find(|v| v["key"] == b64(&key))
        .expect("listed");
    assert_eq!(listed, &view);
    let other = views
        .iter()
        .find(|v| v["key"] == b64(&plain))
        .expect("listed");
    assert!(other.get("proof").is_some());
    assert_eq!(other["divergent"], false);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_records_write_here_on_an_uploaded_record_keeps_its_base() {
    use sqlx::Connection;
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let (key, ..) = create(&replay, 1, b"uploaded", "pay").await;
    as_uploaded(&replay, &key, 40, true).await;
    let view = body(&get_as(&replay, "wallet", &format!("records/{}", b64(&key))).await);
    let uploaded = RecordVersion::new(
        view["generation"].as_u64().expect("generation"),
        view["version"].as_u64().expect("version"),
    );
    let uploaded_op = serde_json::from_value::<SignedDoc>(view["op"].clone())
        .expect("op")
        .doc_hash()
        .expect("hash");
    let base_of = || async {
        let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        let row: (bool, Option<i64>, Option<i64>, i64, Option<Vec<u8>>) = sqlx::query_as(
            "SELECT from_upload, upload_base_generation, upload_base_version, \
             (SELECT count(*) FROM divergent_uploads d WHERE d.account_id = $1 \
             AND d.key = $2), upload_base_op_hash FROM shared_records \
             WHERE account_id = $1 AND key = $2",
        )
        .bind(alice_id())
        .bind(key.as_slice())
        .fetch_one(&mut conn)
        .await
        .expect("row");
        row
    };
    // Two writes here: the first builds on the uploaded version, the second on the first.
    let mut expected_version = uploaded;
    for id in [2u8, 3] {
        let mut put = record_put(PAYMENTS, b"uploaded", "pay", expected_version, b"{\"n\":2}");
        put.id_inputs = None;
        let ops = batch("wallet", id, vec![OpKind::RecordPut(put)]);
        post(&replay, "wallet", &ops, AT).await;
        // Written here, the divergent uploads gone, and the base the first write built on
        // kept by the second.
        let (from_upload, generation, version, divergent, base_op) = base_of().await;
        assert!(!from_upload);
        // With the operation it built on, which an upload of it again leaves alone.
        assert_eq!(base_op, Some(uploaded_op.to_vec()));
        assert_eq!(
            (generation, version),
            (
                Some(i64::try_from(uploaded.generation).expect("generation")),
                Some(i64::try_from(uploaded.version).expect("version"))
            )
        );
        assert_eq!(divergent, 0);
        let view = body(&get_as(&replay, "wallet", &format!("records/{}", b64(&key))).await);
        assert_eq!(view["divergent"], false);
        assert!(view.get("proof").is_some());
        expected_version = RecordVersion::new(
            view["generation"].as_u64().expect("generation"),
            view["version"].as_u64().expect("version"),
        );
    }
    replay.db.drop_database().await.expect("drop");
}

/// Post `ops` from `app_name` at `at`; the whole answer.
async fn post_answer(
    replay: &Replay,
    app_name: &str,
    ops: &[SignedOp],
    at: &str,
) -> SwitchResponse {
    let keys = vectors("keys.json");
    let request = app_request(
        app(&keys, app_name),
        "POST",
        &format!("/v1/{}/ops", alice_id()),
        OpsRequest::new(ops, None).to_json(),
        ms(at),
    );
    replay.service.handle(request).await
}

async fn divergent_count(replay: &Replay, key: &[u8; 32]) -> (bool, i64) {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query_as(
        "SELECT from_upload, (SELECT count(*) FROM divergent_uploads d WHERE d.account_id = $1 \
         AND d.key = $2) FROM shared_records WHERE account_id = $1 AND key = $2",
    )
    .bind(alice_id())
    .bind(key.as_slice())
    .fetch_one(&mut conn)
    .await
    .expect("row")
}

/// A stale write on an uploaded record: `409 conflict` whose `record_view` is the uploaded
/// record's (no proof, the upload's seq, divergent), and nothing changes: the record stays
/// uploaded with its divergent upload.
#[tokio::test]
async fn test_records_conflict_on_an_uploaded_record_shows_its_view() {
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let (key, ..) = create(&replay, 1, b"uploaded", "pay").await;
    as_uploaded(&replay, &key, 40, true).await;
    let view = body(&get_as(&replay, "wallet", &format!("records/{}", b64(&key))).await);
    let held = RecordVersion::new(
        view["generation"].as_u64().expect("generation"),
        view["version"].as_u64().expect("version"),
    );
    let stale = RecordVersion::new(held.generation, held.version + 1);
    let mut put = record_put(PAYMENTS, b"uploaded", "pay", stale, b"{\"n\":2}");
    put.id_inputs = None;
    let ops = batch("wallet", 2, vec![OpKind::RecordPut(put)]);
    let answer = post_answer(&replay, "wallet", &ops, AT).await;
    let (status, code) = code_of(&answer);
    assert_eq!((status, code), (409, json!("conflict")));
    let current = &body(&answer)["current"];
    assert_eq!(current["record_view"], view, "{current}");
    assert!(current["record_view"].get("proof").is_none());
    assert_eq!(current["record_view"]["seq"], 40);
    assert_eq!(current["record_view"]["divergent"], true);
    assert_eq!(divergent_count(&replay, &key).await, (true, 1));
    replay.db.drop_database().await.expect("drop");
}

/// A deleted record taken from an upload, created again here with `{0, 0}`: the write here
/// builds on the uploaded delete, so its version is the upload base, and the divergent
/// upload goes.
#[tokio::test]
async fn test_records_create_over_an_uploaded_delete_keeps_its_base() {
    use sqlx::Connection;
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let (key, ..) = create(&replay, 1, b"gone", "pay").await;
    let view = body(&get_as(&replay, "wallet", &format!("records/{}", b64(&key))).await);
    let v1 = RecordVersion::new(
        view["generation"].as_u64().expect("generation"),
        view["version"].as_u64().expect("version"),
    );
    let mut del = record_put(PAYMENTS, b"gone", "pay", v1, b"");
    del.id_inputs = None;
    post(
        &replay,
        "wallet",
        &batch("wallet", 2, vec![OpKind::RecordPut(del)]),
        AT,
    )
    .await;
    as_uploaded(&replay, &key, 41, true).await;
    let view = body(&get_as(&replay, "wallet", &format!("records/{}", b64(&key))).await);
    assert_eq!(view["deleted"], true);
    let uploaded = RecordVersion::new(
        view["generation"].as_u64().expect("generation"),
        view["version"].as_u64().expect("version"),
    );
    let again = record_put(PAYMENTS, b"gone", "pay", RecordVersion::NONE, b"{\"n\":3}");
    post(
        &replay,
        "wallet",
        &batch("wallet", 3, vec![OpKind::RecordPut(again)]),
        AT,
    )
    .await;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    let base: (Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT upload_base_generation, upload_base_version FROM shared_records \
         WHERE account_id = $1 AND key = $2",
    )
    .bind(alice_id())
    .bind(key.as_slice())
    .fetch_one(&mut conn)
    .await
    .expect("row");
    assert_eq!(
        base,
        (
            Some(i64::try_from(uploaded.generation).expect("g")),
            Some(i64::try_from(uploaded.version).expect("v"))
        )
    );
    assert_eq!(divergent_count(&replay, &key).await, (false, 0));
    replay.db.drop_database().await.expect("drop");
}

/// Move app `name`'s cursor to `seq` at `at`, in a request of its own.
async fn move_cursor(replay: &Replay, name: &str, seq: u64, at: &str) {
    let keys = vectors("keys.json");
    let cursor = pubky_switch_core::ops::Position { generation: 1, seq };
    let request = app_request(
        app(&keys, name),
        "POST",
        &format!("/v1/{}/ops", alice_id()),
        OpsRequest::new(&[], Some(cursor)).to_json(),
        ms(at),
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

/// A minute on: the next request runs the minute's sweep (Switch wire 9.1).
fn next_minute(replay: &Replay) {
    use pubky_switch::time::Clock;
    let at = replay.clock.now_ms() + 61_000;
    set_time(&replay.clock, &pubky_switch_core::time::rfc3339(at));
}

/// alice's executor, which her `identity.json` lists beside the wallet and the phone,
/// registers its app record.
async fn register_executor(replay: &Replay) {
    let keys = vectors("keys.json");
    let executor = app(&keys, "executor");
    let record = document("executor app record");
    let ops = sign_batch(
        &ed25519_dalek::SigningKey::from_bytes(&hex32(&executor["signing_secret_hex"])),
        &alice_key().public(),
        Some(
            pubky_switch_core::enc::app_id_decode(executor["app_id"].as_str().expect("id"))
                .expect("app id"),
        ),
        1,
        [76; 16],
        vec![(Vec::new(), OpKind::AppPut { record })],
    )
    .expect("batch");
    post(replay, "executor", &ops, AT).await;
}

/// Every app alice's `identity.json` lists moves its cursor to `seq`.
async fn all_past(replay: &Replay, seq: u64) {
    for name in ["wallet", "phone", "executor"] {
        move_cursor(replay, name, seq, AT).await;
    }
}

/// A record the wallet creates at `natural`, then deletes: its key and the delete's `seq`.
async fn created_and_deleted(replay: &Replay, id: u8, natural: &[u8]) -> ([u8; 32], u64) {
    let (key, ..) = create(replay, id, natural, "pay").await;
    let version =
        body(&get_as(replay, "wallet", &format!("records/{}", b64(&key))).await)["version"]
            .as_u64()
            .expect("version");
    let delete = record_put(
        PAYMENTS,
        natural,
        "pay",
        RecordVersion::new(1, version),
        b"",
    );
    post(
        replay,
        "wallet",
        &batch("wallet", id + 1, vec![OpKind::RecordPut(delete)]),
        AT,
    )
    .await;
    (key, last_seq(replay).await)
}

async fn record_rows(replay: &Replay, key: &[u8; 32]) -> i64 {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query_scalar("SELECT count(*) FROM shared_records WHERE account_id = $1 AND key = $2")
        .bind(alice_id())
        .bind(key.as_slice())
        .fetch_one(&mut conn)
        .await
        .expect("count")
}

async fn execute(replay: &Replay, sql: &str, key: &[u8; 32]) {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(sql)
        .bind(alice_id())
        .bind(key.as_slice())
        .execute(&mut conn)
        .await
        .expect("sql");
}

#[tokio::test]
async fn test_records_deleted_key_every_reader_passed_is_forgotten() {
    // Once the cursor of every app the held `identity.json` lists is past the delete, the
    // minute's sweep at a later request forgets the key: its view is `404`, and a create at it starts again, at a newer
    // version (Switch spec 10.3, wire 9.1).
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let (live, ..) = create(&replay, 7, b"live", "pay").await;
    let (key, deleted_at) = created_and_deleted(&replay, 1, b"gone").await;
    move_cursor(&replay, "wallet", deleted_at, AT).await;
    move_cursor(&replay, "phone", deleted_at, AT).await;
    // The executor, listed but not registered here yet, holds the key: it may still read
    // the delete or, after a provider loss, upload its copy of the record.
    next_minute(&replay);
    let answer = get_as(&replay, "phone", &format!("records/{}", b64(&key))).await;
    assert_eq!(
        body(&answer)["deleted"],
        true,
        "the executor hasn't read it"
    );
    register_executor(&replay).await;
    move_cursor(&replay, "executor", deleted_at, AT).await;
    assert_eq!(
        record_rows(&replay, &key).await,
        1,
        "not before the minute's sweep"
    );
    // A request in the same minute as the last sweep sweeps nothing.
    let answer = get_as(&replay, "phone", &format!("records/{}", b64(&key))).await;
    assert_eq!(body(&answer)["deleted"], true, "once a minute");
    // The held delete is the record's current write: its document and proof stay.
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), deleted_at).await,
        (true, true)
    );
    next_minute(&replay);
    let answer = get_as(&replay, "phone", &format!("records/{}", b64(&key))).await;
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    assert_eq!(record_rows(&replay, &key).await, 0);
    // Forgotten, it is no record's current write: its document goes with the key, and the
    // feed shows its stub (Switch wire 7.5).
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), deleted_at).await,
        (false, false)
    );
    assert_eq!(record_rows(&replay, &live).await, 1, "a live record stays");
    // A write naming the forgotten delete's own version is refused for good; a writer that
    // held or followed the delete names `{0, 0}` instead (Switch spec 8.2, 10.3).
    let on_the_delete = record_put(
        PAYMENTS,
        b"gone",
        "pay",
        RecordVersion::new(1, deleted_at),
        b"{\"n\":2}",
    );
    let refused = post_answer(
        &replay,
        "wallet",
        &batch("wallet", 9, vec![OpKind::RecordPut(on_the_delete)]),
        AT,
    )
    .await;
    assert_eq!(code_of(&refused), (409, json!("conflict")));
    let (again, ..) = create(&replay, 3, b"gone", "pay").await;
    assert_eq!(again, key);
    let view = body(&get_as(&replay, "wallet", &format!("records/{}", b64(&key))).await);
    assert!(
        view["version"].as_u64().expect("version") > deleted_at,
        "{view}"
    );
    replay.db.drop_database().await.expect("drop");
}

/// The App ID of alice's app `name`.
fn app_id(name: &str) -> Vec<u8> {
    pubky_switch_core::enc::app_id_decode(
        app(&vectors("keys.json"), name)["app_id"]
            .as_str()
            .expect("id"),
    )
    .expect("app id")
    .to_vec()
}

async fn sql_account(replay: &Replay, sql: &str) {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(sql)
        .bind(alice_id())
        .execute(&mut conn)
        .await
        .expect("sql");
}

async fn sql_app(replay: &Replay, sql: &str, name: &str) {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query(sql)
        .bind(alice_id())
        .bind(app_id(name))
        .execute(&mut conn)
        .await
        .expect("sql");
}

#[tokio::test]
async fn test_records_deleted_key_waits_for_a_reader_short_of_it() {
    // An app whose cursor is short of the delete holds the key, sweep after sweep, lagging
    // or not, with a `missed` item to pass or not: a listing doesn't show a key the service
    // forgot, so an app that missed the delete would keep the record (Switch spec 10.3).
    // Once it reads past the delete, the key goes.
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    register_executor(&replay).await;
    let (key, deleted_at) = created_and_deleted(&replay, 1, b"gone").await;
    move_cursor(&replay, "wallet", deleted_at, AT).await;
    move_cursor(&replay, "executor", deleted_at, AT).await;
    move_cursor(&replay, "phone", deleted_at - 1, AT).await;
    next_minute(&replay);
    let answer = get_as(&replay, "wallet", &format!("records/{}", b64(&key))).await;
    assert_eq!(body(&answer)["deleted"], true, "the phone hasn't passed it");
    // Marked lagging, with a `missed` item ahead of its cursor: still waited for.
    sql_app(
        &replay,
        "UPDATE apps SET lagging = true WHERE account_id = $1 AND app_id = $2",
        "phone",
    )
    .await;
    let missed_at = deleted_at + 1;
    sql_account(
        &replay,
        &format!("UPDATE accounts SET last_seq = {missed_at} WHERE id = $1"),
    )
    .await;
    sql_app(
        &replay,
        &format!(
            "INSERT INTO inbox_entries (account_id, generation, seq, kind, accepted_at_ms, \
             envelope, targets, quota_bytes, missed_entries, missed_from_ms, missed_until_ms) \
             VALUES ($1, 1, {missed_at}, 'missed', {at}, '\\x', ARRAY[$2::BYTEA], 0, 1, {at}, {at})",
            at = ms(AT)
        ),
        "phone",
    )
    .await;
    next_minute(&replay);
    let answer = get_as(&replay, "wallet", &format!("records/{}", b64(&key))).await;
    assert_eq!(
        body(&answer)["deleted"],
        true,
        "a lagging app is waited for"
    );
    assert_eq!(record_rows(&replay, &key).await, 1);
    // The phone reads past it: the next minute's sweep forgets it.
    move_cursor(&replay, "phone", missed_at, AT).await;
    next_minute(&replay);
    let answer = get_as(&replay, "wallet", &format!("records/{}", b64(&key))).await;
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_records_deleted_key_doesnt_wait_for_a_revoked_app() {
    // A revoked app, kept for good, no longer reads or uploads: the keys it hadn't passed
    // go once every other listed app has (Switch spec 10.3). Removing the app is what frees
    // a key a silent app holds.
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    register_executor(&replay).await;
    let (key, deleted_at) = created_and_deleted(&replay, 1, b"gone").await;
    move_cursor(&replay, "wallet", deleted_at, AT).await;
    move_cursor(&replay, "phone", deleted_at, AT).await;
    next_minute(&replay);
    let answer = get_as(&replay, "wallet", &format!("records/{}", b64(&key))).await;
    assert_eq!(
        body(&answer)["deleted"],
        true,
        "the executor hasn't passed it"
    );
    sql_app(
        &replay,
        &format!(
            "INSERT INTO kept_app_ids (account_id, app_id, reason, at_ms, data_epoch) \
             VALUES ($1, $2, 'revoked', {at}, 1)",
            at = ms(AT)
        ),
        "executor",
    )
    .await;
    next_minute(&replay);
    let answer = get_as(&replay, "wallet", &format!("records/{}", b64(&key))).await;
    assert_eq!(code_of(&answer), (404, json!("not_found")));
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_records_deleted_key_a_divergent_upload_names_is_kept() {
    // A divergent upload names the key: it stays, every reader past it or not.
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    register_executor(&replay).await;
    let (key, deleted_at) = created_and_deleted(&replay, 1, b"gone").await;
    all_past(&replay, deleted_at).await;
    execute(
        &replay,
        "INSERT INTO divergent_uploads (account_id, key, position, op, op_hash) \
         VALUES ($1, $2, 0, '\\x00', decode(repeat('11', 32), 'hex'))",
        &key,
    )
    .await;
    next_minute(&replay);
    let answer = get_as(&replay, "wallet", &format!("records/{}", b64(&key))).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(record_rows(&replay, &key).await, 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_records_deleted_key_taken_from_an_upload_is_kept() {
    // A delete taken from a recovery upload has no chain item here to stand for it: its
    // key stays, every reader past it or not (Switch spec 10.3, wire 7.4.14).
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let (key, uploaded_at) = created_and_deleted(&replay, 1, b"gone").await;
    as_uploaded(&replay, &key, uploaded_at, false).await;
    // A delete written here beside it, which the same sweep forgets.
    let (here, deleted_at) = created_and_deleted(&replay, 3, b"here").await;
    register_executor(&replay).await;
    all_past(&replay, deleted_at).await;
    next_minute(&replay);
    let answer = get_as(&replay, "wallet", &format!("records/{}", b64(&key))).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(record_rows(&replay, &key).await, 1);
    assert_eq!(
        record_rows(&replay, &here).await,
        0,
        "the one written here goes"
    );
    replay.db.drop_database().await.expect("drop");
}

/// A batch of the wallet's with batch ID `[id; 16]`: a create at `natural` under the
/// condition that the record at `key` is at `version`.
fn conditioned(id: u8, key: [u8; 32], version: RecordVersion, natural: &[u8]) -> Vec<SignedOp> {
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let signing = ed25519_dalek::SigningKey::from_bytes(&hex32(&wallet["signing_secret_hex"]));
    let app_id = pubky_switch_core::enc::app_id_decode(wallet["app_id"].as_str().expect("id"))
        .expect("app id");
    let put = record_put(PAYMENTS, natural, "pay", RecordVersion::NONE, b"{\"n\":1}");
    sign_batch(
        &signing,
        &alice_key().public(),
        Some(app_id),
        1,
        [id; 16],
        vec![(
            vec![pubky_switch_core::ops::Condition::RecordVersion { key, version }],
            OpKind::RecordPut(put),
        )],
    )
    .expect("batch")
}

#[tokio::test]
async fn test_records_condition_zero_matches_a_held_delete_and_a_forgotten_key() {
    // A `record_version` condition of `{0, 0}` holds for a record that is absent,
    // forgotten or deleted, as `expected_version` `{0, 0}` does: a writer holding a delete
    // names it the same way before the key is forgotten and after (Switch wire 6.3). A live
    // record fails it, `409 conflict`.
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    register_executor(&replay).await;
    let (live, ..) = create(&replay, 1, b"live", "pay").await;
    let keys = vectors("keys.json");
    let refused = replay
        .service
        .handle(app_request(
            app(&keys, "wallet"),
            "POST",
            &format!("/v1/{}/ops", alice_id()),
            OpsRequest::new(&conditioned(2, live, RecordVersion::NONE, b"c1"), None).to_json(),
            ms(AT),
        ))
        .await;
    assert_eq!(code_of(&refused), (409, json!("conflict")));
    let (key, deleted_at) = created_and_deleted(&replay, 3, b"gone").await;
    post(
        &replay,
        "wallet",
        &conditioned(5, key, RecordVersion::NONE, b"c2"),
        AT,
    )
    .await;
    // The delete's own version holds too, while the service keeps it.
    post(
        &replay,
        "wallet",
        &conditioned(6, key, RecordVersion::new(1, deleted_at), b"c3"),
        AT,
    )
    .await;
    all_past(&replay, last_seq(&replay).await).await;
    next_minute(&replay);
    get_as(&replay, "wallet", &format!("records/{}", b64(&key))).await;
    assert_eq!(record_rows(&replay, &key).await, 0, "forgotten");
    post(
        &replay,
        "wallet",
        &conditioned(7, key, RecordVersion::NONE, b"c4"),
        AT,
    )
    .await;
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_records_superseded_write_loses_its_document() {
    // A record's write keeps its document and proof while it is the record's current one;
    // the write that supersedes it deletes both in its own transaction, so only the stub is
    // left (Switch wire 7.5). The phone, which hasn't read past either, sees the first as a
    // stub and the second in full, as before; the delete later does the same to the update.
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let before = last_seq(&replay).await;
    let (key, ..) = create(&replay, 1, b"n1", "pay").await;
    let created = last_seq(&replay).await;
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), created).await,
        (true, true)
    );
    let update = record_put(
        PAYMENTS,
        b"n1",
        "pay",
        RecordVersion::new(1, created),
        b"{\"n\":2}",
    );
    post(
        &replay,
        "wallet",
        &batch("wallet", 2, vec![OpKind::RecordPut(update)]),
        AT,
    )
    .await;
    let updated = last_seq(&replay).await;
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), created).await,
        (false, false)
    );
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), updated).await,
        (true, true)
    );
    let feed = body(&get_as(&replay, "phone", &format!("feed?after=1:{before}")).await);
    let shown = |seq: u64| {
        feed["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| item["seq"] == seq)
            .expect("item")["type"]
            .clone()
    };
    assert_eq!(shown(created), json!("stub"));
    assert_eq!(shown(updated), json!("chain"));
    let delete = record_put(PAYMENTS, b"n1", "pay", RecordVersion::new(1, updated), b"");
    post(
        &replay,
        "wallet",
        &batch("wallet", 3, vec![OpKind::RecordPut(delete)]),
        AT,
    )
    .await;
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), updated).await,
        (false, false)
    );
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), last_seq(&replay).await).await,
        (true, true),
        "the delete is the record's current write"
    );
    assert_eq!(record_rows(&replay, &key).await, 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_records_documents_chained_before_the_rule_are_checked_a_bounded_number_at_a_time() {
    // Documents from before superseded ones were deleted: a superseded write's document is
    // put back, as an earlier service left it, and the account's items marked unchecked.
    // The next requests check 64 a request, oldest first, and delete it; a current write
    // keeps its document.
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    create(&replay, 1, b"n1", "pay").await;
    let created = last_seq(&replay).await;
    let update = record_put(
        PAYMENTS,
        b"n1",
        "pay",
        RecordVersion::new(1, created),
        b"{\"n\":2}",
    );
    post(
        &replay,
        "wallet",
        &batch("wallet", 2, vec![OpKind::RecordPut(update)]),
        AT,
    )
    .await;
    let updated = last_seq(&replay).await;
    for n in 0..70u8 {
        create(&replay, n.wrapping_add(10), &[b'k', n], "pay").await;
    }
    let end = last_seq(&replay).await;
    assert!(end > 64 + updated, "more than one request's bound");
    sql_account(
        &replay,
        &format!(
            "UPDATE chain_items SET item_bytes = (SELECT item_bytes FROM chain_items \
             WHERE account_id = $1 AND seq = {updated}), proof = (SELECT proof FROM \
             chain_items WHERE account_id = $1 AND seq = {updated}) \
             WHERE account_id = $1 AND seq = {created}"
        ),
    )
    .await;
    sql_account(
        &replay,
        &format!(
            "UPDATE accounts SET documents_checked_seq = 0, documents_check_end = {end} \
             WHERE id = $1"
        ),
    )
    .await;
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), created).await,
        (true, true)
    );
    get_as(&replay, "wallet", &list_path(&payments(), "")).await;
    assert_eq!(checked(&replay).await, 64);
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), created).await,
        (false, false)
    );
    assert_eq!(
        chain_document_kept(&replay, &alice_id(), updated).await,
        (true, true)
    );
    get_as(&replay, "wallet", &list_path(&payments(), "")).await;
    assert_eq!(checked(&replay).await, i64::try_from(end).expect("end"));
    get_as(&replay, "wallet", &list_path(&payments(), "")).await;
    assert_eq!(
        checked(&replay).await,
        i64::try_from(end).expect("end"),
        "done"
    );
    replay.db.drop_database().await.expect("drop");
}

async fn checked(replay: &Replay) -> i64 {
    use sqlx::Connection;
    let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    sqlx::query_scalar("SELECT documents_checked_seq FROM accounts WHERE id = $1")
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("checked")
}

/// The items of `name`'s feed read at `query`, in one page.
async fn feed_items(replay: &Replay, name: &str, query: &str) -> Vec<Value> {
    let answer = get_as(replay, name, &format!("feed?limit=500{query}")).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let page = body(&answer);
    assert_eq!(page["more"], json!(false), "one page");
    page["items"].as_array().expect("items").clone()
}

/// Update the wallet's record at `natural` read under `read_scope` from `version`, in
/// batch `id`; the new version.
async fn update(
    replay: &Replay,
    id: u8,
    natural: &[u8],
    read_scope: &str,
    version: u64,
    value: &[u8],
) -> u64 {
    let put = record_put(
        PAYMENTS,
        natural,
        read_scope,
        RecordVersion::new(1, version),
        value,
    );
    post(
        replay,
        "wallet",
        &batch("wallet", id, vec![OpKind::RecordPut(put)]),
        AT,
    )
    .await;
    last_seq(replay).await
}

#[tokio::test]
async fn test_records_feed_is_the_same_with_deleted_documents_put_back() {
    // Every read of the feed, by either app and from any position (none, behind every
    // write, between them), answers the same whether the superseded documents are deleted
    // or put back as an earlier service kept them.
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let mut docs = std::collections::BTreeMap::new();
    let id = alice_id();
    capture_documents(&replay, &id, &mut docs).await;
    let before = last_seq(&replay).await;
    create(&replay, 1, b"a1", "pay").await;
    let v1 = last_seq(&replay).await;
    capture_documents(&replay, &id, &mut docs).await;
    let v2 = update(&replay, 2, b"a1", "pay", v1, b"{\"n\":2}").await;
    capture_documents(&replay, &id, &mut docs).await;
    let v3 = update(&replay, 3, b"a1", "pay", v2, b"{\"n\":3}").await;
    capture_documents(&replay, &id, &mut docs).await;
    create(&replay, 4, b"c1", "contacts").await;
    let c1 = last_seq(&replay).await;
    capture_documents(&replay, &id, &mut docs).await;
    let c2 = update(&replay, 5, b"c1", "contacts", c1, b"{\"n\":2}").await;
    capture_documents(&replay, &id, &mut docs).await;
    let deleted = update(&replay, 6, b"a1", "pay", v3, b"").await;
    capture_documents(&replay, &id, &mut docs).await;
    for seq in [v1, v2, v3, c1] {
        assert_eq!(
            chain_document_kept(&replay, &id, seq).await,
            (false, false),
            "seq {seq}"
        );
    }
    for seq in [c2, deleted] {
        assert_eq!(
            chain_document_kept(&replay, &id, seq).await,
            (true, true),
            "seq {seq}"
        );
    }
    let queries = [
        String::new(),
        format!("&after=1:{before}"),
        format!("&after=1:{v2}"),
        format!("&after=1:{c1}"),
    ];
    let mut gone = Vec::new();
    for name in ["phone", "wallet"] {
        for query in &queries {
            gone.push(feed_items(&replay, name, query).await);
        }
    }
    assert_eq!(restore_documents(&replay, &id, &docs).await, 4);
    assert_eq!(
        chain_document_kept(&replay, &id, v1).await,
        (true, true),
        "put back"
    );
    let mut kept = Vec::new();
    for name in ["phone", "wallet"] {
        for query in &queries {
            kept.push(feed_items(&replay, name, query).await);
        }
    }
    assert_eq!(gone, kept);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_records_old_documents_check_takes_every_stale_one_over_several_requests() {
    // 150 superseded writes of one record, their documents put back as an earlier service
    // kept them, and the account marked unchecked: each request checks the next 64, the
    // stale ones go and the current write, the app records and receive keys stay, and no
    // feed read changes.
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let id = alice_id();
    let mut docs = std::collections::BTreeMap::new();
    create(&replay, 99, b"n1", "pay").await;
    let mut version = last_seq(&replay).await;
    let mut stale = vec![version];
    capture_documents(&replay, &id, &mut docs).await;
    for n in 0..150u8 {
        version = update(
            &replay,
            100 + n,
            b"n1",
            "pay",
            version,
            format!("{{\"n\":{n}}}").as_bytes(),
        )
        .await;
        stale.push(version);
        capture_documents(&replay, &id, &mut docs).await;
    }
    let current = stale.pop().expect("current");
    let end = last_seq(&replay).await;
    assert!(end > 2 * 64, "more than two requests' bound");
    let feed_before = feed_items(&replay, "phone", "").await;
    assert_eq!(
        restore_documents(&replay, &id, &docs).await,
        u64::try_from(stale.len()).expect("len")
    );
    sql_on(
        &replay,
        &id,
        "UPDATE chain_items SET doc_app = NULL WHERE account_id = $1",
    )
    .await;
    sql_on(
        &replay,
        &id,
        &format!(
            "UPDATE accounts SET documents_checked_seq = 0, documents_check_end = {end} \
             WHERE id = $1"
        ),
    )
    .await;
    let end = i64::try_from(end).expect("end");
    let mut requests = 0;
    loop {
        let (checked, _) = documents_check(&replay, &id).await;
        assert_eq!(checked, (64 * requests).min(end), "request {requests}");
        if checked == end {
            break;
        }
        get_as(&replay, "wallet", &list_path(&payments(), "")).await;
        requests += 1;
    }
    assert_eq!(requests, (end + 63) / 64);
    for seq in &stale {
        assert_eq!(
            chain_document_kept(&replay, &id, *seq).await,
            (false, false),
            "seq {seq}"
        );
    }
    assert_eq!(
        chain_document_kept(&replay, &id, current).await,
        (true, true)
    );
    // Every other item keeps its document: the registrations, deliveries and transitions.
    let mut left = std::collections::BTreeMap::new();
    capture_documents(&replay, &id, &mut left).await;
    let expected: Vec<i64> = docs
        .keys()
        .copied()
        .filter(|seq| !stale.contains(&u64::try_from(*seq).expect("seq")))
        .collect();
    assert_eq!(left.keys().copied().collect::<Vec<_>>(), expected);
    // The app records the check went past name their app again.
    let named: i64 = {
        use sqlx::Connection;
        let mut conn = sqlx::PgConnection::connect_with(replay.db.options())
            .await
            .expect("conn");
        sqlx::query_scalar(
            "SELECT count(*) FROM chain_items WHERE account_id = $1 AND doc_app IS NOT NULL",
        )
        .bind(&id)
        .fetch_one(&mut conn)
        .await
        .expect("count")
    };
    assert_eq!(named, 2, "the wallet's and the phone's app.put");
    assert_eq!(feed_items(&replay, "phone", "").await, feed_before);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_records_migration_marks_older_documents_and_holds_feed_reads() {
    // The account as a service from before migration 0022 left it: a superseded write
    // keeps its document, and the schema has none of 0022's columns, nor 0025's index on
    // one of them. The migration, run as one transaction, holds a read of `chain_items` until
    // it commits, as its `ALTER TABLE` locks the table for the whole transaction; 0025's
    // index build, in a transaction of its own, holds no read. Then the account's items are
    // marked for the check, and the next request deletes the stale document.
    use sqlx::{Connection, Executor};
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let id = alice_id();
    let mut docs = std::collections::BTreeMap::new();
    create(&replay, 1, b"n1", "pay").await;
    let created = last_seq(&replay).await;
    capture_documents(&replay, &id, &mut docs).await;
    update(&replay, 2, b"n1", "pay", created, b"{\"n\":2}").await;
    assert_eq!(restore_documents(&replay, &id, &docs).await, 1);
    let mut admin = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    admin
        .execute(sqlx::raw_sql(
            "ALTER TABLE chain_items DROP COLUMN doc_app; \
             ALTER TABLE accounts DROP COLUMN documents_checked_seq, \
             DROP COLUMN documents_check_end",
        ))
        .await
        .expect("as before 0022");
    let mut migration = admin.begin().await.expect("begin");
    migration
        .execute(sqlx::raw_sql(include_str!(
            "../migrations/0022_superseded_documents.sql"
        )))
        .await
        .expect("0022");
    let mut reader = sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn");
    reader
        .execute("SET lock_timeout = '500ms'")
        .await
        .expect("timeout");
    let read =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM chain_items WHERE account_id = $1")
            .bind(&id)
            .fetch_one(&mut reader)
            .await;
    let code = read
        .as_ref()
        .err()
        .and_then(|error| error.as_database_error())
        .and_then(|error| error.code().map(|code| code.into_owned()));
    assert_eq!(
        code.as_deref(),
        Some("55P03"),
        "a feed read waits for the migration: {read:?}"
    );
    migration.commit().await.expect("commit");
    let mut index = admin.begin().await.expect("begin");
    index
        .execute(sqlx::raw_sql(include_str!(
            "../migrations/0025_chain_items_by_doc_app.sql"
        )))
        .await
        .expect("0025");
    let read =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM chain_items WHERE account_id = $1")
            .bind(&id)
            .fetch_one(&mut reader)
            .await;
    assert!(
        read.is_ok(),
        "a feed read goes on during the build: {read:?}"
    );
    index.commit().await.expect("commit");
    reader.close().await.expect("close");
    admin.close().await.expect("close");
    let end = i64::try_from(last_seq(&replay).await).expect("end");
    assert_eq!(documents_check(&replay, &id).await, (0, end));
    assert_eq!(
        chain_document_kept(&replay, &id, created).await,
        (true, true)
    );
    get_as(&replay, "wallet", &list_path(&payments(), "")).await;
    assert_eq!(documents_check(&replay, &id).await, (end, end));
    assert_eq!(
        chain_document_kept(&replay, &id, created).await,
        (false, false)
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_records_old_documents_check_past_an_item_that_doesnt_read() {
    // An older chain item whose stored document doesn't read, left for the check of older
    // documents: the account's other requests go on answering, as they did before the
    // check existed (only a feed page over that item fails), and the check moves past it.
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let id = alice_id();
    create(&replay, 1, b"n1", "pay").await;
    let created = last_seq(&replay).await;
    sql_on(
        &replay,
        &id,
        &format!(
            "UPDATE chain_items SET item_bytes = '\\x00'::BYTEA \
             WHERE account_id = $1 AND seq = {created}"
        ),
    )
    .await;
    let end = last_seq(&replay).await;
    sql_on(
        &replay,
        &id,
        &format!(
            "UPDATE accounts SET documents_checked_seq = 0, documents_check_end = {end} \
             WHERE id = $1"
        ),
    )
    .await;
    for _ in 0..2 {
        let answer = get_as(&replay, "wallet", &list_path(&payments(), "")).await;
        assert_eq!(
            answer.status,
            200,
            "the wallet's list: {}",
            String::from_utf8_lossy(&answer.body)
        );
        let apps = replay
            .service
            .handle(signer_request(
                "GET",
                &format!("/v1/{id}/apps"),
                Vec::new(),
                ms(AT),
            ))
            .await;
        assert_eq!(
            apps.status,
            200,
            "the signer's GET /apps: {}",
            String::from_utf8_lossy(&apps.body)
        );
    }
    assert_eq!(
        documents_check(&replay, &id).await,
        (
            i64::try_from(end).expect("end"),
            i64::try_from(end).expect("end")
        )
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_records_write_superseding_an_item_that_doesnt_read_still_commits() {
    // The record's create, whose stored document doesn't read: the update that supersedes
    // it commits, and the create keeps what it holds, while a readable superseded write loses
    // its document as before.
    let Some(replay) = registered(Limits::default()).await else {
        return;
    };
    let id = alice_id();
    create(&replay, 1, b"n1", "pay").await;
    let created = last_seq(&replay).await;
    create(&replay, 2, b"n2", "pay").await;
    let other = last_seq(&replay).await;
    sql_on(
        &replay,
        &id,
        &format!(
            "UPDATE chain_items SET item_bytes = '\\x00'::BYTEA \
             WHERE account_id = $1 AND seq = {created}"
        ),
    )
    .await;
    let updated = update(&replay, 3, b"n1", "pay", created, b"{\"n\":2}").await;
    assert!(updated > created, "the update committed");
    assert_eq!(
        chain_document_kept(&replay, &id, created).await,
        (true, true),
        "kept"
    );
    let replaced = update(&replay, 4, b"n2", "pay", other, b"{\"n\":2}").await;
    assert!(replaced > updated);
    assert_eq!(
        chain_document_kept(&replay, &id, other).await,
        (false, false)
    );
    replay.db.drop_database().await.expect("drop");
}
