//! Push delivery (Switch spec 9 step 4, Switch wire 8.2) on `chain.json`'s account: a
//! `notify` append from bob's shop to alice's wallet queues one webhook per handle of the
//! wallet's registration, and the worker sends each, signed with the push key, to an
//! in-process relay behind the test-only route; its retries, the address check at each
//! connection, a registration that changed, two workers, and what the logs hold.
//!
//! Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use pubky_switch::{
    http::{Handler, SwitchResponse},
    keys::{KeyFuture, KeyId, KeyStore, Mark, MarkCheck, ServiceKey, ServiceSigner},
    limits::Limits,
    service::{PushRound, RelayRoute, Resolver, Service},
};
use pubky_switch_core::{
    enc::{b64, unb64},
    envelope::{Recipient, seal},
    http::verify_webhook,
    keys::AppKeys,
    ops::{AllowKind, OpKind, OpsRequest, sign_batch},
    sig::SignedDoc,
    time::parse_rfc3339,
};
use serde_json::{Value, json};
use sqlx::Connection;
use support::*;

const RELAY: &str = "https://push.example/v1/hook";
const H1: &str = "handle-one-Kt8fSp";
const H2: &str = "handle-two-tnjGPM";

fn public_ip() -> IpAddr {
    "93.184.216.34".parse().expect("address")
}

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

/// What the relay answers.
#[derive(Clone, Copy, Debug)]
enum Mode {
    Ok,
    Status(u16),
    Redirect,
    /// Answers only after the webhook's timeout.
    Hang,
    /// Answers `200` after a second.
    Slow,
}

/// One webhook the relay received.
#[derive(Clone, Debug)]
struct Seen {
    path: String,
    content_type: Option<String>,
    signature: String,
    body: Vec<u8>,
}

/// An in-process relay: it records each webhook and answers as its mode says.
struct Relay {
    addr: SocketAddr,
    mode: Mutex<Mode>,
    seen: Mutex<Vec<Seen>>,
}

impl Relay {
    fn set(&self, mode: Mode) {
        *self.mode.lock().expect("lock") = mode;
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("lock").clone()
    }
}

async fn answer(relay: Arc<Relay>, request: axum::extract::Request) -> Response {
    let seen = {
        let text = |name: &str| {
            request
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        };
        Seen {
            path: request.uri().path().to_string(),
            content_type: text("content-type"),
            signature: text("switch-signature").unwrap_or_default(),
            body: Vec::new(),
        }
    };
    let bytes = axum::body::to_bytes(request.into_body(), 1 << 16)
        .await
        .expect("body");
    relay.seen.lock().expect("lock").push(Seen {
        body: bytes.to_vec(),
        ..seen
    });
    let mode = *relay.mode.lock().expect("lock");
    match mode {
        Mode::Ok => StatusCode::OK.into_response(),
        Mode::Status(code) => StatusCode::from_u16(code).expect("status").into_response(),
        Mode::Redirect => (
            StatusCode::FOUND,
            [(
                axum::http::header::LOCATION,
                "https://push.example/v1/elsewhere",
            )],
        )
            .into_response(),
        Mode::Hang => {
            tokio::time::sleep(Duration::from_secs(30)).await;
            StatusCode::OK.into_response()
        }
        Mode::Slow => {
            tokio::time::sleep(Duration::from_secs(1)).await;
            StatusCode::OK.into_response()
        }
    }
}

async fn relay() -> Arc<Relay> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let relay = Arc::new(Relay {
        addr: listener.local_addr().expect("addr"),
        mode: Mutex::new(Mode::Ok),
        seen: Mutex::default(),
    });
    let state = relay.clone();
    let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
        let state = state.clone();
        async move { answer(state, request).await }
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    relay
}

/// `push.example` resolves to a public address, or to a private one once `private` is set.
fn resolver(private: Arc<AtomicBool>) -> Resolver {
    Arc::new(move |host: String| {
        let private = private.load(Ordering::SeqCst);
        Box::pin(async move {
            match host.as_str() {
                "push.example" if private => Ok(vec!["10.1.2.3".parse().expect("address")]),
                "push.example" => Ok(vec![public_ip()]),
                _ => Err(std::io::Error::other("no such host")),
            }
        })
    })
}

/// The relay listens behind the public address only.
fn route(addr: SocketAddr) -> RelayRoute {
    Arc::new(move |ip: IpAddr| (ip == public_ip()).then_some(addr))
}

struct Setup {
    replay: Replay,
    relay: Arc<Relay>,
    private: Arc<AtomicBool>,
}

impl Setup {
    /// Another service on the same database, as another instance.
    fn instance(&self) -> Service {
        self.replay
            .restarted_with(Limits::default())
            .with_push(true)
            .with_resolver(resolver(self.private.clone()))
            .with_relay_route(route(self.relay.addr))
    }
}

/// alice served through the phone's revocation, bob a contact whose `identity.json` the
/// switch holds, and a relay; no registration yet.
async fn setup() -> Option<Setup> {
    let replay = replay().await?;
    let mut setup = Setup {
        replay,
        relay: relay().await,
        private: Arc::new(AtomicBool::new(false)),
    };
    setup.replay.service = setup.instance();
    with_bob(&setup.replay).await;
    Some(setup)
}

/// [`setup`], with the wallet registered with `handles`: its push key.
async fn registered(handles: &[&str]) -> Option<(Setup, [u8; 32])> {
    let setup = setup().await?;
    let key = register(&setup.replay, handles, None).await;
    Some((setup, key))
}

async fn put_push(replay: &Replay, push: &Value) -> Value {
    let path = format!("/v1/{}/push", alice_id());
    let answer = replay
        .service
        .handle(app_request(
            app(&vectors("keys.json"), "wallet"),
            "PUT",
            &path,
            push.to_string().into_bytes(),
            ms(&at()),
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    body(&answer)
}

fn key_of(text: &Value) -> [u8; 32] {
    unb64(text.as_str().expect("b64"))
        .expect("b64")
        .try_into()
        .expect("32 bytes")
}

/// A start, replacing `replaces` if given, then `handles` set: the push key.
async fn register(replay: &Replay, handles: &[&str], replaces: Option<[u8; 32]>) -> [u8; 32] {
    let mut start = json!({ "relay_url": RELAY, "handles": [] });
    if let Some(key) = replaces {
        start["replaces"] = json!(b64(&key));
    }
    let key = key_of(&put_push(replay, &start).await["push_key"]);
    if !handles.is_empty() {
        set_handles(replay, handles, key).await;
    }
    key
}

async fn set_handles(replay: &Replay, handles: &[&str], key: [u8; 32]) {
    let set = json!({ "relay_url": RELAY, "handles": handles, "push_key": b64(&key) });
    put_push(replay, &set).await;
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

async fn conn(replay: &Replay) -> sqlx::PgConnection {
    sqlx::PgConnection::connect_with(replay.db.options())
        .await
        .expect("conn")
}

async fn sql(replay: &Replay, query: &str) {
    let mut conn = conn(replay).await;
    sqlx::query(query).execute(&mut conn).await.expect("sql");
    conn.close().await.expect("close");
}

/// The queued deliveries: handle, attempts, entry time, next attempt, oldest first.
async fn queued(replay: &Replay) -> Vec<(String, i32, i64, i64)> {
    let mut conn = conn(replay).await;
    let rows = sqlx::query_as(
        "SELECT handle, attempts, entry_at_ms, next_attempt_ms FROM push_deliveries ORDER BY id",
    )
    .fetch_all(&mut conn)
    .await
    .expect("rows");
    conn.close().await.expect("close");
    rows
}

/// A `notify` (or not) append from bob's shop to the wallet, accepted.
async fn append(replay: &Replay, byte: u8, notify: bool) {
    append_to(replay, &replay.service, byte, notify).await;
}

/// [`append`], at `service`.
async fn append_to(replay: &Replay, service: &Service, byte: u8, notify: bool) {
    append_envelope(replay, service, to_wallet(byte, notify)).await;
}

/// An append of `envelope` from bob's shop to the wallet at `service`, accepted.
async fn append_envelope(replay: &Replay, service: &Service, envelope: Vec<u8>) {
    let mut conn = conn(replay).await;
    let version: i64 = sqlx::query_scalar("SELECT apps_version FROM accounts WHERE id = $1")
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("apps_version");
    conn.close().await.expect("close");
    let path = format!("/v1/{}/inbox?apps_version={version}", alice_id());
    let request = other_request("shop", ORIGIN, "POST", &path, envelope, None, ms(&at()));
    let answer = service.handle(request).await;
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
}

/// The clock at the newest queued entry's time plus `after_ms`.
async fn clock_at_entry(replay: &Replay, after_ms: u64) {
    let entry = queued(replay)
        .await
        .iter()
        .map(|row| row.2)
        .max()
        .expect("a queued delivery");
    replay
        .clock
        .set_wall_ms(u64::try_from(entry).expect("time") + after_ms);
}

async fn with_bob(replay: &Replay) {
    replay_chain_through_revoke(replay).await;
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let bob = keys["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == "bob")
        .expect("bob")
        .clone();
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
        [61; 16],
        vec![(
            Vec::new(),
            OpKind::AllowPut {
                pubky: hex32(&bob["public_hex"]),
                kind: AllowKind::Contact,
            },
        )],
    )
    .expect("batch");
    let path = format!("/v1/{}/ops", alice_id());
    let answer = replay
        .service
        .handle(app_request(
            wallet,
            "POST",
            &path,
            OpsRequest::new(&ops, None).to_json(),
            ms(&at()),
        ))
        .await;
    assert_eq!(answer.status, 200);
    let doc: SignedDoc = serde_json::from_value(
        named(&vectors("documents.json")["documents"], "bob identity.json")["signed"].clone(),
    )
    .expect("document");
    let path = format!("/v1/{}/peers", alice_id());
    let body = serde_json::to_vec(&doc).expect("body");
    let request = other_request("shop", ORIGIN, "PUT", &path, body, None, ms(&at()));
    assert_eq!(replay.service.handle(request).await.status, 200);
}

/// The webhook passes 8.3's checks, by a relay that bound `handles` to `push_key`, at
/// `now_ms`: its handle.
fn relay_checks(seen: &Seen, push_key: &[u8; 32], handles: &[&str], now_ms: u64) -> String {
    assert_eq!(seen.path, "/v1/hook");
    assert_eq!(seen.content_type.as_deref(), Some("application/json"));
    let webhook: Value = serde_json::from_slice(&seen.body).expect("json");
    let members: Vec<&String> = webhook.as_object().expect("object").keys().collect();
    assert_eq!(members, ["handle", "nonce", "ts", "v"]);
    assert_eq!(webhook["v"], json!(1));
    let handle = webhook["handle"].as_str().expect("handle");
    assert!(handles.contains(&handle));
    let signature: [u8; 64] = unb64(&seen.signature)
        .expect("b64")
        .try_into()
        .expect("64 bytes");
    verify_webhook(push_key, RELAY, &seen.body, &signature).expect("signature");
    let ts = parse_rfc3339(webhook["ts"].as_str().expect("ts")).expect("time");
    assert!(ts.abs_diff(now_ms) <= 5 * 60 * 1000);
    assert_eq!(
        unb64(webhook["nonce"].as_str().expect("nonce"))
            .expect("b64")
            .len(),
        16
    );
    handle.to_string()
}

/// alice's service key.
async fn service_key(replay: &Replay) -> [u8; 32] {
    let mut conn = conn(replay).await;
    let id: String = sqlx::query_scalar("SELECT service_key FROM accounts WHERE id = $1")
        .bind(alice_id())
        .fetch_one(&mut conn)
        .await
        .expect("service key");
    conn.close().await.expect("close");
    replay
        .keys
        .public_key(&KeyId::parse(&id).expect("key id"))
        .await
        .expect("public")
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

fn nonce(seen: &Seen) -> String {
    let webhook: Value = serde_json::from_slice(&seen.body).expect("json");
    webhook["nonce"].as_str().expect("nonce").to_string()
}

#[tokio::test]
async fn test_push_delivery_notify_append_queues_one_per_handle() {
    let Some(setup) = setup().await else {
        return;
    };
    let replay = &setup.replay;
    // No registration: a `notify` append queues nothing.
    append(replay, 1, true).await;
    assert!(queued(replay).await.is_empty());
    register(replay, &[H1, H2], None).await;
    // Without `notify`, nothing is queued.
    append(replay, 2, false).await;
    assert!(queued(replay).await.is_empty());
    // With it, one row per handle, due at once, and nothing sent during the append.
    append(replay, 3, true).await;
    let rows = queued(replay).await;
    let mut handles: Vec<&str> = rows.iter().map(|row| row.0.as_str()).collect();
    handles.sort_unstable();
    assert_eq!(handles, [H1, H2]);
    assert!(rows.iter().all(|row| row.1 == 0 && row.2 == row.3));
    assert!(setup.relay.seen().is_empty());
    // An append sent again, a retry by its content, queues nothing again.
    let envelope = to_wallet(5, true);
    append_envelope(replay, &replay.service, envelope.clone()).await;
    assert_eq!(queued(replay).await.len(), 4);
    append_envelope(replay, &replay.service, envelope).await;
    assert_eq!(queued(replay).await.len(), 4);
    // Without trusted time, nothing is queued: no webhook could go before its minute ends.
    let untrusted = replay.without_trusted_time().with_push(true);
    append_to(replay, &untrusted, 6, true).await;
    assert_eq!(queued(replay).await.len(), 4);
    // A service with `push.enabled` off queues nothing, the registration kept.
    let off = setup.instance().with_push(false);
    append_to(replay, &off, 4, true).await;
    assert_eq!(queued(replay).await.len(), 4);
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_sends_signed_webhooks_and_drops_the_rows() {
    let Some((setup, key)) = registered(&[H1, H2]).await else {
        return;
    };
    let replay = &setup.replay;
    append(replay, 1, true).await;
    clock_at_entry(replay, 0).await;
    let round = replay.service.deliver_pushes().await;
    assert_eq!(
        round,
        PushRound {
            delivered: 2,
            ..PushRound::default()
        }
    );
    assert!(queued(replay).await.is_empty());
    let seen = setup.relay.seen();
    let now = replay.time.read().base_ms;
    let mut handles: Vec<String> = seen
        .iter()
        .map(|seen| relay_checks(seen, &key, &[H1, H2], now))
        .collect();
    handles.sort_unstable();
    assert_eq!(handles, [H1, H2]);
    assert_ne!(nonce(&seen[0]), nonce(&seen[1]));
    // The signature covers the relay's origin: another relay, or another key, refuses it.
    let signature: [u8; 64] = unb64(&seen[0].signature)
        .expect("b64")
        .try_into()
        .expect("64");
    assert!(
        verify_webhook(
            &key,
            "https://push.other.example/v1/hook",
            &seen[0].body,
            &signature
        )
        .is_err()
    );
    assert!(verify_webhook(&[7; 32], RELAY, &seen[0].body, &signature).is_err());
    // Never signed with the account's service key.
    assert!(verify_webhook(&service_key(replay).await, RELAY, &seen[0].body, &signature).is_err());
    // Nothing more is due.
    assert_eq!(replay.service.deliver_pushes().await, PushRound::default());
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_failures_retried_20s_later_3_times() {
    for mode in [Mode::Status(500), Mode::Redirect] {
        let Some((setup, key)) = registered(&[H1]).await else {
            return;
        };
        let replay = &setup.replay;
        setup.relay.set(mode);
        append(replay, 1, true).await;
        let failed = PushRound {
            failed: 1,
            ..PushRound::default()
        };
        for attempt in 1..=3_i32 {
            clock_at_entry(replay, 20_000 * u64::try_from(attempt - 1).expect("n")).await;
            assert_eq!(replay.service.deliver_pushes().await, failed, "{mode:?}");
            assert_eq!(
                setup.relay.seen().len(),
                usize::try_from(attempt).expect("n")
            );
            let rows = queued(replay).await;
            if attempt < 3 {
                // Retried 20 s after the failure, and not before.
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].1, attempt);
                assert_eq!(rows[0].3, rows[0].2 + 20_000 * i64::from(attempt));
                assert_eq!(replay.service.deliver_pushes().await, PushRound::default());
            } else {
                // The third attempt is the last: the row goes.
                assert!(rows.is_empty(), "{mode:?}");
            }
        }
        // Each attempt is a webhook of its own: its time and nonce fresh.
        let seen = setup.relay.seen();
        let now = replay.time.read().base_ms;
        for one in &seen {
            relay_checks(one, &key, &[H1], now);
        }
        assert_ne!(nonce(&seen[0]), nonce(&seen[1]));
        assert_ne!(nonce(&seen[1]), nonce(&seen[2]));
        setup.replay.db.drop_database().await.expect("drop");
    }
}

#[tokio::test]
async fn test_push_delivery_timeout_is_a_failure_retried() {
    let Some((setup, _)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    setup.relay.set(Mode::Hang);
    append(replay, 1, true).await;
    clock_at_entry(replay, 0).await;
    let started = std::time::Instant::now();
    let round = replay.service.deliver_pushes().await;
    assert_eq!(round.failed, 1);
    let took = started.elapsed();
    assert!(took >= Duration::from_secs(5) && took < Duration::from_secs(10));
    let rows = queued(replay).await;
    assert_eq!((rows[0].1, rows[0].3), (1, rows[0].2 + 20_000));
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_not_attempted_within_a_minute_goes_unsent() {
    let Some((setup, _)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    append(replay, 1, true).await;
    // At the end of its minute, a row goes without a send.
    clock_at_entry(replay, 60_000).await;
    let round = replay.service.deliver_pushes().await;
    assert_eq!(
        round,
        PushRound {
            dropped: 1,
            ..PushRound::default()
        }
    );
    assert!(setup.relay.seen().is_empty());
    assert!(queued(replay).await.is_empty());
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_refuses_a_host_no_longer_public() {
    let Some((setup, key)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    append(replay, 1, true).await;
    clock_at_entry(replay, 0).await;
    // The host passed at registration; it resolves to a private address now.
    setup.private.store(true, Ordering::SeqCst);
    let round = replay.service.deliver_pushes().await;
    assert_eq!(round.failed, 1);
    assert!(setup.relay.seen().is_empty());
    assert_eq!(queued(replay).await[0].1, 1);
    // Public again at the retry: delivered.
    setup.private.store(false, Ordering::SeqCst);
    clock_at_entry(replay, 20_000).await;
    assert_eq!(replay.service.deliver_pushes().await.delivered, 1);
    let now = replay.time.read().base_ms;
    relay_checks(&setup.relay.seen()[0], &key, &[H1], now);
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_of_a_changed_registration_goes_with_it() {
    let Some((setup, key)) = registered(&[H1, H2]).await else {
        return;
    };
    let replay = &setup.replay;
    // A handle dropped from the list takes its deliveries; the other's stay.
    append(replay, 1, true).await;
    set_handles(replay, &[H2], key).await;
    let rows = queued(replay).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, H2);
    // A replacement takes every delivery queued under the old key.
    let new_key = register(replay, &[], Some(key)).await;
    assert!(queued(replay).await.is_empty());
    // A revocation takes the registration, and its deliveries with it.
    set_handles(replay, &[H1], new_key).await;
    append(replay, 2, true).await;
    assert_eq!(queued(replay).await.len(), 1);
    let path = format!(
        "/v1/{}/apps/{}/revoke",
        alice_id(),
        app(&vectors("keys.json"), "wallet")["app_id"]
            .as_str()
            .expect("id")
    );
    let answer = replay
        .service
        .handle(signer_request("POST", &path, Vec::new(), ms(&at())))
        .await;
    assert_eq!(answer.status, 200);
    assert!(queued(replay).await.is_empty());
    assert!(setup.relay.seen().is_empty());
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_not_sent_unless_the_registration_names_it() {
    // Rows the registration no longer names, whatever left them: another push key, a handle
    // not in the list, a key owed deleting. None is signed or sent.
    let another_key = KeyId::random().expect("key id");
    for change in [
        format!(
            "UPDATE push_deliveries SET push_key_id = '{}'",
            another_key.as_str()
        ),
        "UPDATE push_deliveries SET handle = 'another-handle'".to_string(),
        "INSERT INTO erased_keys (key_id, account_id, erased_at_ms, reason) \
         SELECT push_key_id, account_id, 0, 'push' FROM push_registrations"
            .to_string(),
    ] {
        let Some((setup, _)) = registered(&[H1]).await else {
            return;
        };
        let replay = &setup.replay;
        append(replay, 1, true).await;
        sql(replay, &change).await;
        clock_at_entry(replay, 0).await;
        let round = replay.service.deliver_pushes().await;
        assert_eq!(
            round,
            PushRound {
                dropped: 1,
                ..PushRound::default()
            },
            "{change}"
        );
        assert!(setup.relay.seen().is_empty(), "{change}");
        assert!(queued(replay).await.is_empty(), "{change}");
        setup.replay.db.drop_database().await.expect("drop");
    }
}

#[tokio::test]
async fn test_push_delivery_of_a_crashed_attempt_retried_when_its_lease_ends() {
    // An instance that dies mid-attempt leaves its row leased: no other instance sends it
    // until the lease ends, 20 s after the claim, and then it is retried. The lost attempt
    // counts among the 3: each claim is one.
    let Some((setup, key)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    setup.relay.set(Mode::Hang);
    append(replay, 1, true).await;
    clock_at_entry(replay, 0).await;
    let crashed = Arc::new(setup.instance());
    let running = tokio::spawn({
        let crashed = crashed.clone();
        async move { crashed.deliver_pushes().await }
    });
    while setup.relay.seen().is_empty() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    running.abort();
    assert!(running.await.is_err(), "the round died");
    setup.relay.set(Mode::Ok);
    let other = setup.instance();
    clock_at_entry(replay, 19_999).await;
    assert_eq!(other.deliver_pushes().await, PushRound::default());
    let rows = queued(replay).await;
    assert_eq!((rows[0].1, rows[0].3), (1, rows[0].2 + 20_000));
    clock_at_entry(replay, 20_000).await;
    assert_eq!(
        other.deliver_pushes().await,
        PushRound {
            delivered: 1,
            ..PushRound::default()
        }
    );
    let seen = setup.relay.seen();
    assert_eq!(seen.len(), 2);
    relay_checks(&seen[1], &key, &[H1], replay.time.read().base_ms);
    assert!(queued(replay).await.is_empty());
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_with_push_off_sends_nothing() {
    // A service with `push.enabled` off claims and sends nothing: the row waits, and goes
    // unsent once its minute has passed, at the first round of a service that sends pushes.
    let Some((setup, _)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    append(replay, 1, true).await;
    let off = setup.instance().with_push(false);
    for after_ms in [0, 60_000] {
        clock_at_entry(replay, after_ms).await;
        assert_eq!(off.deliver_pushes().await, PushRound::default());
        assert_eq!(queued(replay).await[0].1, 0, "not claimed");
    }
    assert_eq!(
        replay.service.deliver_pushes().await,
        PushRound {
            dropped: 1,
            ..PushRound::default()
        }
    );
    assert!(setup.relay.seen().is_empty());
    assert!(queued(replay).await.is_empty());
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_of_an_account_moved_away_sends_nothing() {
    // An `identity.json` naming another switch: the account no longer serves here, so its
    // queued webhook goes unsent, and its registration stays.
    let Some((setup, _)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    append(replay, 1, true).await;
    let keys = vectors("keys.json");
    let key = pubky_switch_core::keys::IdentityKey::from_secret(hex32(&alice(&keys)["secret_hex"]));
    let v3: SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            "alice identity.json",
        )["signed"]
            .clone(),
    )
    .expect("version 3");
    let mut moved: pubky_switch_core::records::IdentityBody =
        serde_json::from_slice(&v3.body_bytes().expect("body")).expect("identity body");
    moved.version = 4;
    moved.inbox.url = "https://other.example".into();
    let delivery = pubky_switch_core::http::IdentityDelivery {
        identity: pubky_switch_core::records::IdentityDoc::sign(&key, moved)
            .expect("sign")
            .signed()
            .clone(),
        prev: Some(v3.doc_hash().expect("hash")),
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
    clock_at_entry(replay, 0).await;
    assert_eq!(
        replay.service.deliver_pushes().await,
        PushRound {
            dropped: 1,
            ..PushRound::default()
        }
    );
    assert!(setup.relay.seen().is_empty());
    assert!(queued(replay).await.is_empty());
    assert_eq!(registrations(replay).await, 1);
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_two_workers_never_send_one_twice() {
    let Some((setup, _)) = registered(&[H1, H2]).await else {
        return;
    };
    let replay = &setup.replay;
    setup.relay.set(Mode::Slow);
    append(replay, 1, true).await;
    clock_at_entry(replay, 0).await;
    let first = Arc::new(setup.instance());
    let second = setup.instance();
    let running = tokio::spawn({
        let first = first.clone();
        async move { first.deliver_pushes().await }
    });
    // While the first instance's webhooks are in flight, the second finds nothing to send.
    while setup.relay.seen().len() < 2 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(second.deliver_pushes().await, PushRound::default());
    assert_eq!(running.await.expect("round").delivered, 2);
    assert_eq!(setup.relay.seen().len(), 2);
    assert!(queued(replay).await.is_empty());
    setup.replay.db.drop_database().await.expect("drop");
}

/// A key store over the replay's whose next `signer` call, once armed, waits for a release.
struct Gate {
    inner: Arc<pubky_switch::keys::FixedKeys>,
    armed: AtomicBool,
    paused: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl KeyStore for Gate {
    fn generate(&self) -> KeyFuture<'_, ServiceKey> {
        self.inner.generate()
    }
    fn generate_as<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ServiceKey> {
        self.inner.generate_as(id)
    }
    fn public_key<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, [u8; 32]> {
        self.inner.public_key(id)
    }
    fn signer<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ServiceSigner> {
        Box::pin(async move {
            if self.armed.swap(false, Ordering::SeqCst) {
                self.paused.notify_one();
                self.release.notified().await;
            }
            self.inner.signer(id).await
        })
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
        self.inner.delete(id)
    }
    fn record_erasure<'a>(&'a self, identity: &'a str, erased_at_ms: u64) -> KeyFuture<'a, ()> {
        self.inner.record_erasure(identity, erased_at_ms)
    }
    fn erasure<'a>(&'a self, identity: &'a str) -> KeyFuture<'a, Option<u64>> {
        self.inner.erasure(identity)
    }
}

#[tokio::test]
async fn test_push_delivery_removal_waits_for_the_signature() {
    // A revocation owes the push key's deletion: it waits while a webhook is being signed
    // with that key, so the key store deletes no key that is signing.
    let Some(mut setup) = setup().await else {
        return;
    };
    let gate = Arc::new(Gate {
        inner: setup.replay.keys.clone(),
        armed: AtomicBool::new(false),
        paused: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let service = Arc::new(
        Service::new(
            ORIGIN.into(),
            setup.replay.db.store().clone(),
            gate.clone(),
            setup.replay.time.clone(),
            Limits::default(),
        )
        .with_push(true)
        .with_resolver(resolver(setup.private.clone()))
        .with_relay_route(route(setup.relay.addr)),
    );
    setup.replay.service = setup.instance();
    register(&setup.replay, &[H1], None).await;
    append(&setup.replay, 1, true).await;
    clock_at_entry(&setup.replay, 0).await;
    let mut conn = conn(&setup.replay).await;
    let key_id: String = sqlx::query_scalar("SELECT push_key_id FROM push_registrations")
        .fetch_one(&mut conn)
        .await
        .expect("key id");
    conn.close().await.expect("close");
    let key_id = KeyId::parse(&key_id).expect("key id");
    gate.armed.store(true, Ordering::SeqCst);
    let round = tokio::spawn({
        let service = service.clone();
        async move { service.deliver_pushes().await }
    });
    gate.paused.notified().await;
    let path = format!(
        "/v1/{}/apps/{}/revoke",
        alice_id(),
        app(&vectors("keys.json"), "wallet")["app_id"]
            .as_str()
            .expect("id")
    );
    let revoke = tokio::spawn({
        let service = service.clone();
        async move {
            service
                .handle(signer_request("POST", &path, Vec::new(), ms(&at())))
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !revoke.is_finished(),
        "the revocation waits for the signature"
    );
    assert!(gate.public_key(&key_id).await.is_ok());
    gate.release.notify_one();
    assert_eq!(round.await.expect("round").delivered, 1);
    assert_eq!(revoke.await.expect("revoke").status, 200);
    assert!(gate.public_key(&key_id).await.is_err());
    assert!(queued(&setup.replay).await.is_empty());
    setup.replay.db.drop_database().await.expect("drop");
}

/// A writer the log capture appends to.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn test_push_delivery_logs_no_handle_relay_or_key() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "info,sqlx::postgres::notice=warn,pubky_switch=trace",
        ))
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let _logging = tracing::subscriber::set_default(subscriber);
    let Some((setup, key)) = registered(&[H1, H2]).await else {
        return;
    };
    let replay = &setup.replay;
    // A failure, a retry delivered, and a host refused.
    setup.relay.set(Mode::Status(503));
    append(replay, 1, true).await;
    clock_at_entry(replay, 0).await;
    assert_eq!(replay.service.deliver_pushes().await.failed, 2);
    setup.relay.set(Mode::Ok);
    clock_at_entry(replay, 20_000).await;
    assert_eq!(replay.service.deliver_pushes().await.delivered, 2);
    setup.private.store(true, Ordering::SeqCst);
    append(replay, 2, true).await;
    clock_at_entry(replay, 0).await;
    assert_eq!(replay.service.deliver_pushes().await.failed, 2);
    let mut conn = conn(replay).await;
    let key_id: String = sqlx::query_scalar("SELECT push_key_id FROM push_registrations")
        .fetch_one(&mut conn)
        .await
        .expect("key id");
    conn.close().await.expect("close");
    let logs = String::from_utf8(captured.0.lock().expect("lock").clone()).expect("utf-8");
    // The capture holds the failures, by kind only.
    assert!(logs.contains("a webhook failed"), "{logs}");
    assert!(logs.contains("kind=\"status\""), "{logs}");
    for secret in [H1, H2, "push.example", "/v1/hook", &b64(&key), &key_id] {
        assert!(!logs.contains(secret), "the logs hold {secret}");
    }
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_connects_to_no_proxy_from_the_environment() {
    // A proxy named in the environment: the webhook still goes to the address checked, never
    // to the proxy, which would resolve the host itself (Switch wire 8.2). The proxy
    // variables are set only for a run of this test in a process of its own: it runs itself
    // again with them, and the proxy is a listener here that must see no connection.
    const CHILD: &str = "PUBKY_SWITCH_PROXY_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let Some((setup, _)) = registered(&[H1]).await else {
            return;
        };
        let replay = &setup.replay;
        append(replay, 1, true).await;
        clock_at_entry(replay, 0).await;
        let round = replay.service.deliver_pushes().await;
        let to_relay = setup.relay.seen().len();
        setup.replay.db.drop_database().await.expect("drop");
        assert_eq!(to_relay, 1, "the relay, not the proxy: {round:?}");
        return;
    }
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", proxy.local_addr().expect("addr"));
    let reached = Arc::new(AtomicBool::new(false));
    tokio::spawn({
        let reached = reached.clone();
        async move {
            while let Ok((mut socket, _)) = proxy.accept().await {
                reached.store(true, Ordering::SeqCst);
                use tokio::io::AsyncWriteExt;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                    .await;
            }
        }
    });
    let mut child = std::process::Command::new(std::env::current_exe().expect("exe"));
    child
        .args([
            "--exact",
            "test_push_delivery_connects_to_no_proxy_from_the_environment",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy");
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        child.env(name, &url);
    }
    // Run off this runtime's thread, so the proxy above can take a connection meanwhile.
    let output = tokio::task::spawn_blocking(move || child.output())
        .await
        .expect("join")
        .expect("the run with a proxy");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(!reached.load(Ordering::SeqCst), "the proxy was reached");
}
