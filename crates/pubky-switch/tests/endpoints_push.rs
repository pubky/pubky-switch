//! `PUT /v1/{id}/push` (Switch wire 8.1, spec 9) on `chain.json`'s account: the wallet's
//! push registration, its cases and refusals, one registration per app, its push key kept in
//! the key store and deleted through the owed-deletion ledger when the registration is
//! replaced or removed, its queued deliveries going with it, and both sides of a crash
//! around a key's commit.
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use std::{
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use pubky_switch::{
    http::{Handler, SwitchResponse},
    keys::{KeyFuture, KeyId, KeyStore, KeyStoreError, Mark, MarkCheck, ServiceKey, ServiceSigner},
    service::{Resolver, Service},
    store::{PushRegistration, StoreError},
};
use pubky_switch_core::{
    enc::{app_id_decode, b64, unb64},
    http::{IdentityDelivery, erase_body, header},
    keys::IdentityKey,
    records::{IdentityBody, IdentityDoc, RemovedApp},
    sig::SignedDoc,
};
use serde_json::{Value, json};
use sqlx::Connection;
use support::*;

const RELAY: &str = "https://push.example/v1/hook";
const OTHER_RELAY: &str = "https://push.other.example/hook";

fn alice_id() -> String {
    alice(&vectors("keys.json"))["pubky_id"]
        .as_str()
        .expect("id")
        .to_string()
}

fn app_id(name: &str) -> String {
    app(&vectors("keys.json"), name)["app_id"]
        .as_str()
        .expect("id")
        .to_string()
}

fn wallet() -> [u8; 16] {
    app_id_decode(&app_id("wallet")).expect("app id")
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

fn key_of(text: &Value) -> [u8; 32] {
    unb64(text.as_str().expect("b64"))
        .expect("b64")
        .try_into()
        .expect("32 bytes")
}

/// A key store over the replay's that records the push keys it mints and can fail their
/// deletion.
struct Recording {
    inner: Arc<pubky_switch::keys::FixedKeys>,
    minted: Mutex<Vec<KeyId>>,
    fail_delete: AtomicBool,
}

impl KeyStore for Recording {
    fn generate(&self) -> KeyFuture<'_, ServiceKey> {
        self.inner.generate()
    }
    fn generate_as<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ServiceKey> {
        self.minted.lock().expect("lock").push(id.clone());
        self.inner.generate_as(id)
    }
    fn public_key<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, [u8; 32]> {
        self.inner.public_key(id)
    }
    fn signer<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ServiceSigner> {
        self.inner.signer(id)
    }
    fn operator(&self) -> KeyFuture<'_, ServiceSigner> {
        self.inner.operator()
    }
    fn mark<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, Option<Mark>> {
        self.inner.mark(id)
    }
    fn advance_mark<'a>(&'a self, id: &'a KeyId, head: Mark) -> KeyFuture<'a, MarkCheck> {
        self.inner.advance_mark(id, head)
    }
    fn delete<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ()> {
        // Only push keys: the service key's deletion still works.
        if self.fail_delete.load(Ordering::SeqCst) && self.minted().contains(id) {
            return Box::pin(async { Err(KeyStoreError::Io(std::io::Error::other("read-only"))) });
        }
        self.inner.delete(id)
    }
    fn record_erasure<'a>(&'a self, identity: &'a str, erased_at_ms: u64) -> KeyFuture<'a, ()> {
        self.inner.record_erasure(identity, erased_at_ms)
    }
    fn erasure<'a>(&'a self, identity: &'a str) -> KeyFuture<'a, Option<u64>> {
        self.inner.erasure(identity)
    }
}

impl Recording {
    fn minted(&self) -> Vec<KeyId> {
        self.minted.lock().expect("lock").clone()
    }
}

/// Relay hosts by name: `push.example` and `push.other.example` public, `private.example`
/// a private address, `mixed.example` a public and a loopback one, `silent.example` never
/// answered; any other doesn't resolve.
fn resolver() -> Resolver {
    Arc::new(|host: String| {
        Box::pin(async move {
            let found: Vec<IpAddr> = match host.as_str() {
                "push.example" | "push.other.example" => {
                    vec!["93.184.216.34".parse().expect("address")]
                }
                "private.example" => vec!["10.1.2.3".parse().expect("address")],
                "mixed.example" => vec![
                    "93.184.216.34".parse().expect("address"),
                    "127.0.0.1".parse().expect("address"),
                ],
                "silent.example" => std::future::pending().await,
                _ => return Err(std::io::Error::other("no such host")),
            };
            Ok(found)
        })
    })
}

fn recording(replay: &Replay) -> Arc<Recording> {
    Arc::new(Recording {
        inner: replay.keys.clone(),
        minted: Mutex::default(),
        fail_delete: AtomicBool::new(false),
    })
}

fn service_on(replay: &Replay, keys: Arc<Recording>) -> Service {
    Service::new(
        ORIGIN.into(),
        replay.db.store().clone(),
        keys,
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    )
    .with_push(true)
    .with_resolver(resolver())
}

/// The replay's service on a [`Recording`] key store, with alice served through the
/// phone's revocation: the wallet is current.
async fn pushing() -> Option<(Replay, Arc<Recording>)> {
    let mut replay = replay().await?;
    let keys = recording(&replay);
    replay.service = service_on(&replay, keys.clone());
    replay_chain_through_revoke(&replay).await;
    Some((replay, keys))
}

/// `PUT /push` from `caller` (a `keys.json` app, or `"signer"`) with `body`.
async fn put(replay: &Replay, caller: &str, body: &Value) -> SwitchResponse {
    let path = format!("/v1/{}/push", alice_id());
    let bytes = body.to_string().into_bytes();
    let request = if caller == "signer" {
        signer_request("PUT", &path, bytes, ms(&at()))
    } else {
        app_request(
            app(&vectors("keys.json"), caller),
            "PUT",
            &path,
            bytes,
            ms(&at()),
        )
    };
    replay.service.handle(request).await
}

fn start(relay: &str, replaces: Option<[u8; 32]>) -> Value {
    let mut body = json!({ "relay_url": relay, "handles": [] });
    if let Some(key) = replaces {
        body["replaces"] = json!(b64(&key));
    }
    body
}

fn set(relay: &str, handles: &[&str], key: [u8; 32]) -> Value {
    json!({ "relay_url": relay, "handles": handles, "push_key": b64(&key) })
}

/// A start from the wallet that must succeed: its push key.
async fn started(replay: &Replay, relay: &str, replaces: Option<[u8; 32]>) -> [u8; 32] {
    let answer = put(replay, "wallet", &start(relay, replaces)).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    key_of(&body(&answer)["push_key"])
}

async fn conn(replay: &Replay) -> sqlx::PgConnection {
    sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn")
}

/// The wallet's registration as stored: relay, key ID, public key, handles.
async fn stored(replay: &Replay) -> Option<(String, KeyId, [u8; 32], Vec<String>)> {
    let mut conn = conn(replay).await;
    let row: Option<(String, String, Vec<u8>, Vec<String>)> = sqlx::query_as(
        "SELECT relay_url, push_key_id, push_public, handles FROM push_registrations \
         WHERE account_id = $1 AND app_id = $2",
    )
    .bind(alice_id())
    .bind(wallet().as_slice())
    .fetch_optional(&mut conn)
    .await
    .expect("row");
    conn.close().await.expect("close");
    row.map(|(relay, id, public, handles)| {
        (
            relay,
            KeyId::parse(&id).expect("key id"),
            public.try_into().expect("32"),
            handles,
        )
    })
}

/// The push keys owed deleting, by ID.
async fn owed(replay: &Replay) -> Vec<String> {
    let mut conn = conn(replay).await;
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT key_id FROM erased_keys WHERE reason = 'push' ORDER BY key_id")
            .fetch_all(&mut conn)
            .await
            .expect("owed");
    conn.close().await.expect("close");
    rows
}

async fn registrations(replay: &Replay) -> i64 {
    let mut conn = conn(replay).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM push_registrations")
        .fetch_one(&mut conn)
        .await
        .expect("count");
    conn.close().await.expect("close");
    count
}

/// Queue a webhook for the wallet's registration, as a `notify` entry would (wire 8.2).
async fn queue_one(replay: &Replay) {
    let mut conn = conn(replay).await;
    sqlx::query(
        "INSERT INTO push_deliveries (account_id, app_id, push_key_id, handle, entry_at_ms, \
         next_attempt_ms) SELECT account_id, app_id, push_key_id, 'handle', 0, 0 \
         FROM push_registrations",
    )
    .execute(&mut conn)
    .await
    .expect("queued");
    conn.close().await.expect("close");
}

async fn deliveries(replay: &Replay) -> i64 {
    let mut conn = conn(replay).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM push_deliveries")
        .fetch_one(&mut conn)
        .await
        .expect("count");
    conn.close().await.expect("close");
    count
}

async fn exists(keys: &Recording, id: &KeyId) -> bool {
    keys.public_key(id).await.is_ok()
}

#[tokio::test]
async fn test_push_start_mints_a_key_held_in_the_key_store() {
    // No registration held: the service mints a push key, keeps its secret in the key
    // store and its public half with the registration, and answers it with no handles and
    // the head (8.1 step 1, first case).
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    let answer = put(&replay, "wallet", &start(RELAY, None)).await;
    assert_eq!(answer.status, 200);
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");
    let answered = body(&answer);
    assert_eq!(answered["relay_url"], RELAY);
    assert_eq!(answered["handles"], 0);
    let (relay, id, public, handles) = stored(&replay).await.expect("a registration");
    assert_eq!((relay.as_str(), handles.len()), (RELAY, 0));
    assert_eq!(public, key_of(&answered["push_key"]));
    assert_eq!(
        keys.public_key(&id).await.expect("in the key store"),
        public
    );
    assert_eq!(keys.minted(), vec![id]);
    assert!(
        owed(&replay).await.is_empty(),
        "the key's debt was taken back"
    );
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_start_again_answers_the_registration_unchanged() {
    // The same relay without `replaces`: the current registration, handles kept, and no key
    // minted, so a retried or replayed start changes nothing (8.1 step 1, second case).
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    let key = started(&replay, RELAY, None).await;
    let answer = put(&replay, "wallet", &set(RELAY, &["a", "b"], key)).await;
    assert_eq!(body(&answer)["handles"], 2);
    let again = put(&replay, "wallet", &start(RELAY, None)).await;
    assert_eq!(again.status, 200);
    assert_eq!(key_of(&body(&again)["push_key"]), key);
    assert_eq!(body(&again)["handles"], 2);
    assert_eq!(keys.minted().len(), 1);
    assert_eq!(stored(&replay).await.expect("held").3, ["a", "b"]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_start_replacing_the_current_key_deletes_the_old_one() {
    // `replaces` naming the current key: a new key, the handles reset, another relay taken,
    // and the old key deleted from the key store through the ledger (8.1 step 1, third case).
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    let old = started(&replay, RELAY, None).await;
    let old_id = stored(&replay).await.expect("held").1;
    put(&replay, "wallet", &set(RELAY, &["a"], old)).await;
    let new = started(&replay, OTHER_RELAY, Some(old)).await;
    assert_ne!(new, old);
    let (relay, new_id, public, handles) = stored(&replay).await.expect("held");
    assert_eq!(
        (relay.as_str(), public, handles.len()),
        (OTHER_RELAY, new, 0)
    );
    assert!(!exists(&keys, &old_id).await, "the replaced key is gone");
    assert!(exists(&keys, &new_id).await);
    assert!(owed(&replay).await.is_empty());
    // One registration per app, so one key.
    assert_eq!(registrations(&replay).await, 1);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_start_conflicts_name_the_current_key() {
    // `replaces` with none held is `409` naming `null`; another relay without `replaces`,
    // and `replaces` naming another key, are `409` naming the current key; none of them
    // mints or changes anything (8.1 step 1, the other cases).
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    let none = put(&replay, "wallet", &start(RELAY, Some([9; 32]))).await;
    assert_eq!(code(&none), (409, json!("conflict")));
    assert_eq!(body(&none)["current"]["push_key"], Value::Null);
    assert!(header_text(&none, header::HEAD).is_some());
    let key = started(&replay, RELAY, None).await;
    for conflicting in [start(OTHER_RELAY, None), start(RELAY, Some([9; 32]))] {
        let answer = put(&replay, "wallet", &conflicting).await;
        assert_eq!(code(&answer), (409, json!("conflict")), "{conflicting}");
        assert_eq!(key_of(&body(&answer)["current"]["push_key"]), key);
    }
    assert_eq!(keys.minted().len(), 1);
    assert_eq!(stored(&replay).await.expect("held").2, key);
    assert!(owed(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_set_handles_needs_the_current_key_and_relay() {
    // The handles replace the list with the current key and relay; another key, another
    // relay, or none held is `409` naming the current key or `null` (8.1 step 3).
    let Some((replay, _keys)) = pushing().await else {
        return;
    };
    let none = put(&replay, "wallet", &set(RELAY, &["a"], [9; 32])).await;
    assert_eq!(code(&none), (409, json!("conflict")));
    assert_eq!(body(&none)["current"]["push_key"], Value::Null);
    let key = started(&replay, RELAY, None).await;
    let first = put(&replay, "wallet", &set(RELAY, &["a", "b", "c"], key)).await;
    assert_eq!(first.status, 200);
    assert_eq!(body(&first)["handles"], 3);
    let second = put(&replay, "wallet", &set(RELAY, &["d"], key)).await;
    assert_eq!(body(&second)["handles"], 1);
    assert_eq!(key_of(&body(&second)["push_key"]), key);
    assert_eq!(stored(&replay).await.expect("held").3, ["d"]);
    for conflicting in [set(RELAY, &["x"], [9; 32]), set(OTHER_RELAY, &["x"], key)] {
        let answer = put(&replay, "wallet", &conflicting).await;
        assert_eq!(code(&answer), (409, json!("conflict")));
        assert_eq!(key_of(&body(&answer)["current"]["push_key"]), key);
    }
    assert_eq!(stored(&replay).await.expect("held").3, ["d"]);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_bad_bodies_and_relay_urls_are_bad_request() {
    // More than 8 handles, handles on a start, `replaces` with `push_key`, and a relay URL
    // that fails the checks of switch origins, its host's resolved addresses included, are
    // `400`, and nothing is minted or kept (8.1, 8.2). A public address literal passes.
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    let key = [9; 32];
    let nine: Vec<String> = (0..9).map(|n| format!("h{n}")).collect();
    let bodies = [
        json!({ "relay_url": RELAY, "handles": ["a"] }),
        json!({ "relay_url": RELAY, "handles": [], "push_key": b64(&key), "replaces": b64(&key) }),
        json!({ "relay_url": RELAY, "handles": nine, "push_key": b64(&key) }),
        json!({ "handles": [] }),
        start("http://push.example/hook", None),
        start("https://push.example:8443/hook", None),
        start("https://user@push.example/hook", None),
        start("https://10.0.0.1/hook", None),
        start("https://private.example/hook", None),
        start("https://mixed.example/hook", None),
        start("https://unknown.example/hook", None),
    ];
    for bad in &bodies {
        let answer = put(&replay, "wallet", bad).await;
        assert_eq!(code(&answer), (400, json!("bad_request")), "{bad}");
        assert!(header_text(&answer, header::HEAD).is_some());
    }
    assert!(keys.minted().is_empty());
    assert_eq!(registrations(&replay).await, 0);
    started(&replay, "https://93.184.216.34/hook", None).await;
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_service_that_sends_no_pushes_is_bad_request() {
    // `push.enabled` off: every registration is `400`, nothing minted (8.1).
    let Some((mut replay, keys)) = pushing().await else {
        return;
    };
    replay.service = service_on(&replay, keys.clone()).with_push(false);
    let answer = put(&replay, "wallet", &start(RELAY, None)).await;
    assert_eq!(code(&answer), (400, json!("bad_request")));
    assert!(keys.minted().is_empty());
    assert_eq!(registrations(&replay).await, 0);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_only_a_current_own_app() {
    // The signer and an app of another identity are `403 permission_missing`; a revoked app
    // `403 not_current` (7.2, 7.4); at a staged account an app is refused before anything
    // is kept. Nothing is minted for any of them.
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    let signer = put(&replay, "signer", &start(RELAY, None)).await;
    assert_eq!(code(&signer), (403, json!("permission_missing")));
    let path = format!("/v1/{}/push", alice_id());
    let other = replay
        .service
        .handle(other_request(
            "shop",
            ORIGIN,
            "PUT",
            &path,
            start(RELAY, None).to_string().into_bytes(),
            None,
            ms(&at()),
        ))
        .await;
    assert_eq!(code(&other), (403, json!("permission_missing")));
    // The phone was revoked at seq 9.
    let revoked = put(&replay, "phone", &start(RELAY, None)).await;
    assert_eq!(code(&revoked), (403, json!("not_current")));
    assert_eq!(registrations(&replay).await, 0);
    assert!(keys.minted().is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_staged_account_keeps_nothing() {
    // Enrolled only, so staged: `PUT /push` isn't among the calls a staged account takes
    // (7.3 step 7), and its app, which holds no record there yet, is refused before anything
    // is kept or minted.
    let Some(mut replay) = replay().await else {
        return;
    };
    let keys = recording(&replay);
    replay.service = service_on(&replay, keys.clone());
    let http = vectors("http.json");
    let answered = named(
        &http["responses"],
        "signer: enrollment answer, signed with the new account's key",
    );
    let enrolled_at = answered["headers"]["switch-server-time"]
        .as_str()
        .expect("time")
        .to_string();
    set_time(&replay.clock, &enrolled_at);
    let enrolled = replay
        .service
        .handle(vector_request(named(
            &http["requests"],
            "signer: enrollment",
        )))
        .await;
    assert_eq!(enrolled.status, 200);
    let path = format!("/v1/{}/push", alice_id());
    let request = app_request(
        app(&vectors("keys.json"), "wallet"),
        "PUT",
        &path,
        start(RELAY, None).to_string().into_bytes(),
        ms(&enrolled_at),
    );
    let answer = replay.service.handle(request).await;
    assert_eq!(code(&answer), (403, json!("not_current")));
    assert_eq!(registrations(&replay).await, 0);
    assert!(keys.minted().is_empty());
    assert!(owed(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_revocation_removes_the_registration_and_its_key() {
    // The app stops being current: its registration goes and its key is deleted, through
    // the ledger (8.1).
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    started(&replay, RELAY, None).await;
    let id = stored(&replay).await.expect("held").1;
    let path = format!("/v1/{}/apps/{}/revoke", alice_id(), app_id("wallet"));
    let answer = replay
        .service
        .handle(signer_request("POST", &path, Vec::new(), ms(&at())))
        .await;
    assert_eq!(answer.status, 200);
    assert!(stored(&replay).await.is_none());
    assert!(!exists(&keys, &id).await);
    assert!(owed(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_departure_removes_the_registration_and_its_key() {
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    started(&replay, RELAY, None).await;
    let id = stored(&replay).await.expect("held").1;
    let path = format!("/v1/{}/apps/{}/leave", alice_id(), app_id("wallet"));
    let answer = replay
        .service
        .handle(app_request(
            app(&vectors("keys.json"), "wallet"),
            "POST",
            &path,
            Vec::new(),
            ms(&at()),
        ))
        .await;
    assert_eq!(answer.status, 200);
    assert!(stored(&replay).await.is_none());
    assert!(!exists(&keys, &id).await);
    assert!(owed(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}

/// alice's version 3, with the wallet moved to `removed` as version 4.
fn without_the_wallet() -> IdentityDelivery {
    let keys = vectors("keys.json");
    let key = IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let v3: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json",
        )["signed"]
            .clone(),
    )
    .expect("version 3");
    let mut next: IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("identity body");
    next.version = 4;
    next.apps.retain(|listed| listed.app_id != wallet());
    next.removed.push(RemovedApp {
        app_id: wallet(),
        distrust_from: ms(&at()),
    });
    next.data_epoch = 3;
    let v4 = IdentityDoc::sign(&key, next).expect("sign");
    let held = IdentityDoc::verify(&v3, &key.public()).expect("version 3");
    IdentityDelivery {
        identity: v4.signed().clone(),
        prev: Some(held.hash()),
    }
}

#[tokio::test]
async fn test_push_delivery_that_ends_the_apps_currency_removes_it() {
    // An `identity.json` that no longer lists the wallet: it isn't current, so its
    // registration goes and its key is deleted, with no revocation at the service (8.1).
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    started(&replay, RELAY, None).await;
    let id = stored(&replay).await.expect("held").1;
    let path = format!("/v1/{}/identity", alice_id());
    let answer = replay
        .service
        .handle(signer_request(
            "PUT",
            &path,
            without_the_wallet().to_json(),
            ms(&at()),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(stored(&replay).await.is_none());
    assert!(!exists(&keys, &id).await);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_recovery_in_place_removes_every_registration() {
    // A provider loss at this service starts the account afresh: the registration is
    // generation state, so it goes, and its key is deleted (8.1, spec 12.6).
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    started(&replay, RELAY, None).await;
    let id = stored(&replay).await.expect("held").1;
    queue_one(&replay).await;
    assert_eq!(deliveries(&replay).await, 1);
    // An enrollment at the serving account: its pending key starts the next generation.
    let enrollment = {
        use pubky_switch_core::records::{Enrollment, EnrollmentBody};
        let http = vectors("http.json");
        let vector = named(&http["requests"], "signer: enrollment");
        let request: Value = serde_json::from_slice(
            &unb64(vector["body_b64"].as_str().expect("body")).expect("b64"),
        )
        .expect("json");
        let signed: SignedDoc =
            serde_json::from_value(request["enrollment"].clone()).expect("signed");
        let mut fields: EnrollmentBody =
            serde_json::from_slice(&signed.body_bytes().expect("body")).expect("fields");
        fields.nonce = [3; 16];
        fields.identity_doc = None;
        let key = IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]));
        let enrollment = Enrollment::sign(&key, fields).expect("sign");
        serde_json::to_vec(&json!({ "enrollment": enrollment.signed() })).expect("json")
    };
    let answer = replay
        .service
        .handle(signer_request("POST", "/v1/enroll", enrollment, ms(&at())))
        .await;
    assert_eq!(answer.status, 200);
    let pending = key_of(&body(&answer)["service_key"]);
    let key = IdentityKey::from_secret(hex32(&alice(&vectors("keys.json"))["secret_hex"]));
    let v3: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json",
        )["signed"]
            .clone(),
    )
    .expect("version 3");
    let held = IdentityDoc::verify(&v3, &key.public()).expect("version 3");
    let mut next: IdentityBody = held.body().clone();
    next.version += 1;
    next.generation += 1;
    next.inbox.service_key = pending;
    next.recovery_from = Some(held.generation());
    let next = IdentityDoc::sign(&key, next).expect("sign");
    let delivery = IdentityDelivery {
        identity: next.signed().clone(),
        prev: Some(held.hash()),
    };
    let path = format!("/v1/{}/identity", alice_id());
    let answer = replay
        .service
        .handle(signer_request("PUT", &path, delivery.to_json(), ms(&at())))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert_eq!(registrations(&replay).await, 0);
    assert_eq!(deliveries(&replay).await, 0);
    assert!(!exists(&keys, &id).await);
    assert!(owed(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}

/// alice's service key, from `keys.json`.
fn alice_service_key() -> [u8; 32] {
    let keys = vectors("keys.json");
    let service = keys["service_keys"]
        .as_array()
        .expect("service keys")
        .iter()
        .find(|s| s["account"] == alice_id().as_str())
        .expect("alice's service key")
        .clone();
    key_of(&service["public"])
}

async fn erase(replay: &Replay) -> SwitchResponse {
    let path = format!("/v1/{}/erase", alice_id());
    replay
        .service
        .handle(signer_request(
            "POST",
            &path,
            erase_body(&alice_service_key(), None),
            ms(&at()),
        ))
        .await
}

#[tokio::test]
async fn test_push_erasure_deletes_the_push_keys() {
    // The erasure owes the push key with the service key, and releases its `200` once both
    // are gone (7.4.16, 8.1).
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    started(&replay, RELAY, None).await;
    let id = stored(&replay).await.expect("held").1;
    queue_one(&replay).await;
    assert_eq!(erase(&replay).await.status, 200);
    assert_eq!(deliveries(&replay).await, 0);
    assert!(!exists(&keys, &id).await);
    assert!(owed(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_erasure_withheld_while_a_push_key_stays() {
    // The push key can't be deleted, the service key can: the erasure's answer is withheld
    // all the same, the push key owed, until the retry's sweep deletes it (7.4.16 Order).
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    started(&replay, RELAY, None).await;
    let id = stored(&replay).await.expect("held").1;
    keys.fail_delete.store(true, Ordering::SeqCst);
    assert_eq!(code(&erase(&replay).await), (503, json!("unavailable")));
    assert!(exists(&keys, &id).await);
    keys.fail_delete.store(false, Ordering::SeqCst);
    assert_eq!(code(&erase(&replay).await), (404, json!("not_found")));
    assert!(!exists(&keys, &id).await);
    assert!(owed(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_minted_key_of_a_start_that_doesnt_commit_is_deleted() {
    // Between the key's creation and the commit: the start's transaction fails, so no
    // registration names the minted key, which is deleted once the request is over; its
    // answer is `503`.
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    let mut conn = conn(&replay).await;
    for statement in [
        "CREATE FUNCTION refuse_push() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'refused'; END $$",
        "CREATE CONSTRAINT TRIGGER refuse_push AFTER INSERT ON push_registrations \
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION refuse_push()",
    ] {
        sqlx::query(statement)
            .execute(&mut conn)
            .await
            .expect("trigger");
    }
    let answer = put(&replay, "wallet", &start(RELAY, None)).await;
    assert_eq!(code(&answer), (503, json!("unavailable")));
    let minted = keys.minted();
    assert_eq!(minted.len(), 1);
    assert!(!exists(&keys, &minted[0]).await, "no orphan key");
    assert!(owed(&replay).await.is_empty());
    assert_eq!(registrations(&replay).await, 0);
    sqlx::query("DROP TRIGGER refuse_push ON push_registrations")
        .execute(&mut conn)
        .await
        .expect("drop trigger");
    conn.close().await.expect("close");
    started(&replay, RELAY, None).await;
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_minted_key_left_by_a_crash_is_swept_at_start() {
    // A crash after the key was minted and before anything else: its debt was written
    // first, so the next service's start deletes it, while a committed registration's key
    // stays.
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    let kept = started(&replay, RELAY, None).await;
    let kept_id = stored(&replay).await.expect("held").1;
    let crashed = KeyId::random().expect("id");
    replay
        .db
        .store()
        .owe_push_key(&alice_id(), &crashed, ms(&at()))
        .await
        .expect("owed");
    keys.generate_as(&crashed).await.expect("minted");
    let _started = Service::start(
        ORIGIN.into(),
        replay.db.store().clone(),
        keys.clone(),
        replay.time.clone(),
        pubky_switch::limits::Limits::default(),
    )
    .await;
    assert!(!exists(&keys, &crashed).await);
    assert!(exists(&keys, &kept_id).await);
    assert_eq!(keys.public_key(&kept_id).await.expect("kept"), kept);
    assert!(owed(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_claim_of_a_key_no_longer_owed_is_refused() {
    // A sweep that took a minted key's row deleted the key: the start can't name it, so no
    // registration ever names a key that is gone.
    let Some((replay, _keys)) = pushing().await else {
        return;
    };
    let mut txn = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    let registration = PushRegistration {
        app_id: wallet(),
        relay_url: RELAY.into(),
        push_key: KeyId::random().expect("id"),
        push_public: [1; 32],
        handles: Vec::new(),
        set_at_ms: ms(&at()),
    };
    let refused = txn.put_push_registration(&registration, None).await;
    assert!(matches!(refused, Err(StoreError::Raced(_))), "{refused:?}");
    drop(txn);
    assert_eq!(registrations(&replay).await, 0);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_minted_key_of_a_cancelled_start_is_deleted() {
    // The request is dropped (a client that hangs up) while the start waits for the
    // account's lock, after its key was minted: the key and its debt go with it, with no
    // sweep.
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    let held = replay
        .db
        .store()
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    let answered = tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        put(&replay, "wallet", &start(RELAY, None)),
    )
    .await;
    assert!(answered.is_err(), "the start waits for the lock");
    let minted = keys.minted();
    assert_eq!(minted.len(), 1);
    drop(held);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while exists(&keys, &minted[0]).await && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(!exists(&keys, &minted[0]).await, "no key left to a sweep");
    assert!(owed(&replay).await.is_empty());
    assert_eq!(registrations(&replay).await, 0);
    started(&replay, RELAY, None).await;
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_replaced_key_of_a_start_dropped_during_its_commit_is_deleted() {
    // The request is dropped while its commit, which owes the replaced key's deletion, is
    // under way: the commit lands and the replaced key goes all the same, with no sweep.
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    let old = started(&replay, RELAY, None).await;
    let old_id = stored(&replay).await.expect("held").1;
    let mut conn = conn(&replay).await;
    for statement in [
        format!(
            "CREATE FUNCTION slow_commit() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN IF NEW.key_id = '{}' THEN PERFORM pg_sleep(2); END IF; \
             RETURN NULL; END $$",
            old_id.as_str()
        ),
        "CREATE CONSTRAINT TRIGGER slow_commit AFTER INSERT ON erased_keys \
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION slow_commit()"
            .to_string(),
    ] {
        sqlx::query(&statement)
            .execute(&mut conn)
            .await
            .expect("trigger");
    }
    conn.close().await.expect("close");
    let answered = tokio::time::timeout(
        std::time::Duration::from_millis(1000),
        put(&replay, "wallet", &start(RELAY, Some(old))),
    )
    .await;
    assert!(answered.is_err(), "dropped during the commit");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    while (exists(&keys, &old_id).await || !owed(&replay).await.is_empty())
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let new_id = stored(&replay).await.expect("held").1;
    assert_ne!(new_id, old_id, "the replacement committed");
    assert!(!exists(&keys, &old_id).await, "no key left to a sweep");
    assert!(owed(&replay).await.is_empty());
    assert!(exists(&keys, &new_id).await);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_relay_host_that_never_resolves_is_bad_request() {
    // A resolver that never answers: the start is `400` once 5 seconds have passed (8.2),
    // and nothing is minted or kept.
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    let began = std::time::Instant::now();
    let answer = put(&replay, "wallet", &start("https://silent.example/hook", None)).await;
    let took = began.elapsed();
    assert_eq!(code(&answer), (400, json!("bad_request")));
    assert!(
        took >= std::time::Duration::from_secs(5) && took < std::time::Duration::from_secs(8),
        "{took:?}"
    );
    assert!(keys.minted().is_empty());
    assert_eq!(registrations(&replay).await, 0);
    replay.db.drop_database().await.expect("drop");
}

/// alice's version 3 as version 4, naming another switch: the account no longer serves
/// here, and the wallet stays current.
fn moved_away() -> IdentityDelivery {
    let keys = vectors("keys.json");
    let key = IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let v3: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json",
        )["signed"]
            .clone(),
    )
    .expect("version 3");
    let mut next: IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("identity body");
    next.version = 4;
    next.inbox.url = "https://other.example".into();
    IdentityDelivery {
        identity: IdentityDoc::sign(&key, next).expect("sign").signed().clone(),
        prev: Some(v3.doc_hash().expect("hash")),
    }
}

#[tokio::test]
async fn test_push_account_moved_away_is_staged() {
    // An `identity.json` naming another switch: the account is staged (7.3 step 7), so a
    // current own app's registration is `503 staged`, and nothing is kept: the key minted
    // before the lock goes with the request.
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    let path = format!("/v1/{}/identity", alice_id());
    let delivered = replay
        .service
        .handle(signer_request("PUT", &path, moved_away().to_json(), ms(&at())))
        .await;
    assert_eq!(
        delivered.status,
        200,
        "{}",
        String::from_utf8_lossy(&delivered.body)
    );
    let answer = put(&replay, "wallet", &start(RELAY, None)).await;
    assert_eq!(code(&answer), (503, json!("staged")));
    for minted in keys.minted() {
        assert!(!exists(&keys, &minted).await);
    }
    assert!(owed(&replay).await.is_empty());
    assert_eq!(registrations(&replay).await, 0);
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_replaced_key_whose_deletion_failed_is_swept_later() {
    // Between the commit and the key's deletion: the replaced key stays owed when the key
    // store can't delete it, the answer naming the new key, and a later sweep deletes it.
    let Some((replay, keys)) = pushing().await else {
        return;
    };
    let old = started(&replay, RELAY, None).await;
    let old_id = stored(&replay).await.expect("held").1;
    keys.fail_delete.store(true, Ordering::SeqCst);
    let new = started(&replay, RELAY, Some(old)).await;
    let new_id = stored(&replay).await.expect("held").1;
    assert!(exists(&keys, &old_id).await, "still owed");
    assert_eq!(owed(&replay).await, vec![old_id.as_str().to_string()]);
    keys.fail_delete.store(false, Ordering::SeqCst);
    replay.service.sweep_erased_keys().await;
    assert!(!exists(&keys, &old_id).await);
    // A push key's deletion records no erasure: the account lives on.
    assert_eq!(keys.erasure(&alice_id()).await.expect("ledger"), None);
    assert_eq!(keys.public_key(&new_id).await.expect("current"), new);
    assert!(owed(&replay).await.is_empty());
    replay.db.drop_database().await.expect("drop");
}
