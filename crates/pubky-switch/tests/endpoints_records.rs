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
