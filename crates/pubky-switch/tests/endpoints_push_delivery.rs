//! Push delivery (Switch spec 9 step 4, Switch wire 8.2) on `chain.json`'s account: a
//! `notify` append from bob's shop to alice's wallet queues one webhook per handle of the
//! wallet's registration, and the worker sends each, signed with the push key, to an
//! in-process relay behind the test-only route; its retries, the address check at each
//! connection, a registration that changed, two workers, fairness across accounts, the
//! database's clock, an attempt's deadline, an outage of trusted time, and what the logs
//! hold.
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
    time::{ManualClock, TrustedTime, TrustedTimeConfig},
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

/// Where `fast.example`, another account's relay, resolves.
fn fast_ip() -> IpAddr {
    "93.184.216.35".parse().expect("address")
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
                "fast.example" => Ok(vec![fast_ip()]),
                _ => Err(std::io::Error::other("no such host")),
            }
        })
    })
}

struct Setup {
    replay: Replay,
    /// `push.example`, alice's wallet's relay.
    relay: Arc<Relay>,
    /// `fast.example`, the relay of [`other_account`].
    fast: Arc<Relay>,
    private: Arc<AtomicBool>,
}

impl Setup {
    /// Each relay listens behind its public address only.
    fn route(&self) -> RelayRoute {
        let (relay, fast) = (self.relay.addr, self.fast.addr);
        Arc::new(move |ip: IpAddr| {
            if ip == public_ip() {
                Some(relay)
            } else {
                (ip == fast_ip()).then_some(fast)
            }
        })
    }

    /// `service` connecting to the setup's relays.
    fn connected(&self, service: Service) -> Service {
        service
            .with_push(true)
            .with_resolver(resolver(self.private.clone()))
            .with_relay_route(self.route())
    }

    /// Another service on the same database, as another instance.
    fn instance(&self) -> Service {
        self.connected(self.replay.restarted_with(Limits::default()))
    }

    /// [`Setup::instance`], whose clock reads `wall_ms`.
    fn instance_at(&self, wall_ms: u64) -> Service {
        let time = TrustedTime::new(
            TrustedTimeConfig {
                required: false,
                ..TrustedTimeConfig::default()
            },
            Arc::new(ManualClock::new(wall_ms)),
        );
        self.connected(Service::new(
            ORIGIN.into(),
            self.replay.db.store().clone(),
            self.replay.keys.clone(),
            Arc::new(time),
            Limits::default(),
        ))
    }
}

/// alice served through the phone's revocation, bob a contact whose `identity.json` the
/// switch holds, and a relay; no registration yet.
async fn setup() -> Option<Setup> {
    let replay = replay().await?;
    let mut setup = Setup {
        replay,
        relay: relay().await,
        fast: relay().await,
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

/// The newest queued entry's time, by the database's clock.
async fn entry_time(replay: &Replay) -> u64 {
    let entry = queued(replay)
        .await
        .iter()
        .map(|row| row.2)
        .max()
        .expect("a queued delivery");
    u64::try_from(entry).expect("time")
}

/// `ms` pass for the queue: every row was queued, and is due, that much earlier by the
/// database's clock, which a test can't move.
async fn elapse(replay: &Replay, ms: i64) {
    sql(
        replay,
        &format!(
            "UPDATE push_deliveries SET entry_at_ms = entry_at_ms - {ms}, \
             next_attempt_ms = next_attempt_ms - {ms}"
        ),
    )
    .await;
}

/// `count` deliveries due now for the first handle of `account`'s registration.
async fn queue_rows(replay: &Replay, account: &str, count: u32) {
    let mut conn = conn(replay).await;
    sqlx::query(
        "INSERT INTO push_deliveries (account_id, app_id, push_key_id, handle, entry_at_ms, \
         next_attempt_ms) SELECT r.account_id, r.app_id, r.push_key_id, r.handles[1], t, t \
         FROM push_registrations r, generate_series(1, $2), \
         (SELECT (extract(epoch FROM statement_timestamp()) * 1000)::bigint AS t) now \
         WHERE r.account_id = $1",
    )
    .bind(account)
    .bind(i32::try_from(count).expect("count"))
    .execute(&mut conn)
    .await
    .expect("rows");
    conn.close().await.expect("close");
}

/// A second account at the switch, a copy of alice's, its wallet registered at
/// `fast.example` with a push key of its own and `H1`: its ID.
async fn other_account(setup: &Setup) -> String {
    let replay = &setup.replay;
    let key = replay.keys.generate().await.expect("push key");
    let other = "other-account".to_string();
    let mut conn = conn(replay).await;
    sqlx::query(
        "INSERT INTO accounts SELECT (jsonb_populate_record(NULL::accounts, \
         to_jsonb(a) || jsonb_build_object('id', $2::text))).* FROM accounts a WHERE a.id = $1",
    )
    .bind(alice_id())
    .bind(&other)
    .execute(&mut conn)
    .await
    .expect("account");
    sqlx::query(
        "INSERT INTO push_registrations (account_id, app_id, relay_url, push_key_id, \
         push_public, handles, set_at_ms) SELECT $2, app_id, 'https://fast.example/v1/hook', \
         $3, $4, ARRAY[$5], set_at_ms FROM push_registrations WHERE account_id = $1",
    )
    .bind(alice_id())
    .bind(&other)
    .bind(key.id.as_str())
    .bind(key.public.as_slice())
    .bind(H1)
    .execute(&mut conn)
    .await
    .expect("registration");
    conn.close().await.expect("close");
    other
}

/// A copy of alice's account at the switch, `id`, its wallet registered at alice's relay
/// with a push key of its own and `H1`: its ID.
async fn silent_account(setup: &Setup, id: &str) -> String {
    let replay = &setup.replay;
    let key = replay.keys.generate().await.expect("push key");
    let mut conn = conn(replay).await;
    sqlx::query(
        "INSERT INTO accounts SELECT (jsonb_populate_record(NULL::accounts, \
         to_jsonb(a) || jsonb_build_object('id', $2::text))).* FROM accounts a WHERE a.id = $1",
    )
    .bind(alice_id())
    .bind(id)
    .execute(&mut conn)
    .await
    .expect("account");
    sqlx::query(
        "INSERT INTO push_registrations (account_id, app_id, relay_url, push_key_id, \
         push_public, handles, set_at_ms) SELECT $2, app_id, relay_url, $3, $4, ARRAY[$5], \
         set_at_ms FROM push_registrations WHERE account_id = $1",
    )
    .bind(alice_id())
    .bind(id)
    .bind(key.id.as_str())
    .bind(key.public.as_slice())
    .bind(H1)
    .execute(&mut conn)
    .await
    .expect("registration");
    conn.close().await.expect("close");
    id.to_string()
}

/// Wait, at most 10 s, until `check` holds.
async fn until(what: &str, check: impl Fn() -> bool) {
    let started = std::time::Instant::now();
    while !check() {
        assert!(started.elapsed() < Duration::from_secs(10), "never: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// How many rows are claimed: in flight, or waiting for their retry.
async fn claimed(replay: &Replay) -> usize {
    queued(replay).await.iter().filter(|row| row.1 > 0).count()
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
            if attempt > 1 {
                elapse(replay, 20_000).await;
            }
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
                let after_entry = rows[0].3 - rows[0].2;
                let retry = 20_000 * i64::from(attempt);
                assert!(
                    (retry..retry + 5_000).contains(&after_entry),
                    "{after_entry}"
                );
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
    let started = std::time::Instant::now();
    let round = replay.service.deliver_pushes().await;
    assert_eq!(round.failed, 1);
    let took = started.elapsed();
    assert!(took >= Duration::from_secs(5) && took < Duration::from_secs(10));
    // Retried 20 s after the failure, itself 5 s after the claim.
    let rows = queued(replay).await;
    assert_eq!(rows[0].1, 1);
    assert!((25_000..30_000).contains(&(rows[0].3 - rows[0].2)));
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
    elapse(replay, 60_000).await;
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
    // The host passed at registration; it resolves to a private address now.
    setup.private.store(true, Ordering::SeqCst);
    let round = replay.service.deliver_pushes().await;
    assert_eq!(round.failed, 1);
    assert!(setup.relay.seen().is_empty());
    assert_eq!(queued(replay).await[0].1, 1);
    // Public again at the retry: delivered.
    setup.private.store(false, Ordering::SeqCst);
    elapse(replay, 20_000).await;
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
    // until the lease ends, 30 s after the claim, and then it is retried. The lost attempt
    // counts among the 3: each claim is one.
    let Some((setup, key)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    setup.relay.set(Mode::Hang);
    append(replay, 1, true).await;
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
    let rows = queued(replay).await;
    assert_eq!(rows[0].1, 1);
    assert!((30_000..35_000).contains(&(rows[0].3 - rows[0].2)));
    elapse(replay, 25_000).await;
    assert_eq!(other.deliver_pushes().await, PushRound::default());
    elapse(replay, 5_000).await;
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
        elapse(replay, after_ms).await;
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

/// A service whose key store is a [`Gate`] over the setup's.
fn gated(setup: &Setup) -> (Arc<Gate>, Arc<Service>) {
    let gate = Arc::new(Gate {
        inner: setup.replay.keys.clone(),
        armed: AtomicBool::new(false),
        paused: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let service = setup.connected(Service::new(
        ORIGIN.into(),
        setup.replay.db.store().clone(),
        gate.clone(),
        setup.replay.time.clone(),
        Limits::default(),
    ));
    (gate, Arc::new(service))
}

#[tokio::test]
async fn test_push_delivery_removal_waits_for_the_signature() {
    // A revocation owes the push key's deletion: it waits while a webhook is being signed
    // with that key, so the key store deletes no key that is signing.
    let Some(mut setup) = setup().await else {
        return;
    };
    let (gate, service) = gated(&setup);
    setup.replay.service = setup.instance();
    register(&setup.replay, &[H1], None).await;
    append(&setup.replay, 1, true).await;
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
    assert_eq!(replay.service.deliver_pushes().await.failed, 2);
    setup.relay.set(Mode::Ok);
    elapse(replay, 20_000).await;
    assert_eq!(replay.service.deliver_pushes().await.delivered, 2);
    setup.private.store(true, Ordering::SeqCst);
    append(replay, 2, true).await;
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
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    // The run ran this test, not none: a renamed test would pass it vacuously.
    assert!(stdout.contains("1 passed"), "{stdout}");
    assert!(!reached.load(Ordering::SeqCst), "the proxy was reached");
}

#[tokio::test]
async fn test_push_delivery_slow_relay_of_one_account_holds_up_no_other() {
    // alice's relay never answers, and she has more due webhooks than an instance sends at
    // once. Another account's webhook, queued while hers hang, still goes within about a
    // second: her rows take at most 8 of the 16 slots, and a free slot claims the next due
    // row without waiting for her attempts to end.
    let Some((setup, _)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    setup.relay.set(Mode::Hang);
    let other = other_account(&setup).await;
    queue_rows(replay, &alice_id(), 20).await;
    let service = Arc::new(setup.instance());
    let running = tokio::spawn({
        let service = service.clone();
        async move { service.deliver_pushes().await }
    });
    until("8 of alice's webhooks in flight", || {
        setup.relay.seen().len() >= 8
    })
    .await;
    let queued_at = std::time::Instant::now();
    queue_rows(replay, &other, 1).await;
    while setup.fast.seen().is_empty() {
        assert!(
            queued_at.elapsed() < Duration::from_millis(2_500),
            "the other account's webhook waits for alice's"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    running.abort();
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_silent_relays_of_two_accounts_hold_up_no_third() {
    // Two accounts whose relays never answer hold every slot of an instance between them,
    // with more of their webhooks due. A third account's webhook, queued after theirs,
    // takes the first slot that frees: a free slot goes to the least loaded account, not to
    // the oldest row.
    let Some((setup, _)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    setup.relay.set(Mode::Hang);
    let second = silent_account(&setup, "second-account").await;
    let other = other_account(&setup).await;
    queue_rows(replay, &alice_id(), 40).await;
    queue_rows(replay, &second, 40).await;
    let service = Arc::new(setup.instance());
    let running = tokio::spawn({
        let service = service.clone();
        async move { service.deliver_pushes().await }
    });
    until("every slot held by the silent relays", || {
        setup.relay.seen().len() >= 16
    })
    .await;
    let queued_at = std::time::Instant::now();
    queue_rows(replay, &other, 1).await;
    // The first slots free once the first hung attempts end, about 5 s after their claim;
    // oldest first, the silent accounts' rows would take them, wave after wave.
    while setup.fast.seen().is_empty() {
        assert!(
            queued_at.elapsed() < Duration::from_secs(8),
            "the third account's webhook waits behind the silent ones"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    running.abort();
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_claims_at_most_8_of_an_account_across_instances() {
    // Two instances, 20 of alice's webhooks due, her relay never answering: 8 are in flight,
    // whichever instance claimed them, and the rest wait.
    let Some((setup, _)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    setup.relay.set(Mode::Hang);
    queue_rows(replay, &alice_id(), 20).await;
    let first = Arc::new(setup.instance());
    let second = Arc::new(setup.instance());
    let running: Vec<_> = [first, second]
        .into_iter()
        .map(|service| tokio::spawn(async move { service.deliver_pushes().await }))
        .collect();
    until("8 of alice's webhooks in flight", || {
        setup.relay.seen().len() >= 8
    })
    .await;
    // Long enough for each instance to look for due rows again.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(setup.relay.seen().len(), 8);
    assert_eq!(claimed(replay).await, 8);
    for one in running {
        one.abort();
    }
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_instances_whose_clocks_differ_send_one_at_a_time() {
    // Two instances whose clocks are 30 s apart, more than a lease: while the first sends a
    // webhook, the second neither sends it again nor drops it, since the queue is timed by
    // the database's clock.
    let Some((setup, key)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    setup.relay.set(Mode::Slow);
    append(replay, 1, true).await;
    let entry = entry_time(replay).await;
    replay.clock.set_wall_ms(entry);
    let first = Arc::new(setup.instance());
    let ahead = setup.instance_at(entry + 30_000);
    let running = tokio::spawn({
        let first = first.clone();
        async move { first.deliver_pushes().await }
    });
    until("the first instance sends", || {
        !setup.relay.seen().is_empty()
    })
    .await;
    assert_eq!(ahead.deliver_pushes().await, PushRound::default());
    assert_eq!(running.await.expect("run").delivered, 1);
    let seen = setup.relay.seen();
    assert_eq!(seen.len(), 1);
    relay_checks(&seen[0], &key, &[H1], entry);
    assert!(queued(replay).await.is_empty());
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_past_its_time_to_send_sends_nothing() {
    // The push key loads slowly: past 5 s after the claim, the attempt fails without a send,
    // so its connection ends within 10 s of the claim, well inside the lease.
    let Some(mut setup) = setup().await else {
        return;
    };
    let (gate, service) = gated(&setup);
    setup.replay.service = setup.instance();
    register(&setup.replay, &[H1], None).await;
    append(&setup.replay, 1, true).await;
    gate.armed.store(true, Ordering::SeqCst);
    let started = std::time::Instant::now();
    let round = tokio::spawn({
        let service = service.clone();
        async move { service.deliver_pushes().await }
    });
    gate.paused.notified().await;
    // The key loads after 9 s.
    tokio::spawn({
        let gate = gate.clone();
        async move {
            tokio::time::sleep(Duration::from_secs(9)).await;
            gate.release.notify_one();
        }
    });
    let round = round.await.expect("run");
    assert_eq!(
        round,
        PushRound {
            failed: 1,
            ..PushRound::default()
        }
    );
    // Failed at 5 s, before the key loads at 9 s, with room for a loaded runner.
    assert!(started.elapsed() < Duration::from_secs(8));
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert!(setup.relay.seen().is_empty(), "sent past its time");
    assert_eq!(queued(&setup.replay).await[0].1, 1);
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_without_trusted_time_waits_then_goes_or_expires() {
    // Without trusted time a `notify` entry still queues its webhook, and nothing is sent; once
    // trusted time is back inside the entry's minute, it goes. A row past its minute is
    // dropped by a service without trusted time too, so the queue stays bounded.
    let Some((setup, key)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    let untrusted = setup.connected(replay.without_trusted_time());
    append_to(replay, &untrusted, 1, true).await;
    assert_eq!(queued(replay).await.len(), 1);
    assert_eq!(untrusted.deliver_pushes().await, PushRound::default());
    assert!(setup.relay.seen().is_empty());
    assert_eq!(queued(replay).await[0].1, 0, "not claimed");
    assert_eq!(replay.service.deliver_pushes().await.delivered, 1);
    relay_checks(
        &setup.relay.seen()[0],
        &key,
        &[H1],
        replay.time.read().base_ms,
    );
    append_to(replay, &untrusted, 2, true).await;
    elapse(replay, 60_000).await;
    assert_eq!(
        untrusted.deliver_pushes().await,
        PushRound {
            dropped: 1,
            ..PushRound::default()
        }
    );
    assert!(queued(replay).await.is_empty());
    assert_eq!(setup.relay.seen().len(), 1);
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_one_entry_queues_at_most_8_toward_a_host() {
    // Two target apps, 8 handles each, at one relay host spelt two ways: one entry queues 8
    // webhooks toward it, not 16. A host of its own gets its own 8.
    let Some(setup) = setup().await else {
        return;
    };
    let replay = &setup.replay;
    let handles: Vec<String> = (0..8).map(|n| format!("wallet-handle-{n}")).collect();
    let listed: Vec<&str> = handles.iter().map(String::as_str).collect();
    register(replay, &listed, None).await;
    let keys = vectors("keys.json");
    let wallet =
        pubky_switch_core::enc::app_id_decode(app(&keys, "wallet")["app_id"].as_str().expect("id"))
            .expect("app id");
    let mut targets = vec![wallet];
    for (name, relay) in [
        ("executor", "https://PUSH.example/v1/other"),
        ("phone", "https://fast.example/v1/hook"),
    ] {
        let app_id =
            pubky_switch_core::enc::app_id_decode(app(&keys, name)["app_id"].as_str().expect("id"))
                .expect("app id");
        targets.push(app_id);
        let key = replay.keys.generate().await.expect("push key");
        let handles: Vec<String> = (0..8).map(|n| format!("{name}-handle-{n}")).collect();
        let mut conn = conn(replay).await;
        sqlx::query(
            "INSERT INTO push_registrations (account_id, app_id, relay_url, push_key_id, \
             push_public, handles, set_at_ms) VALUES ($1, $2, $3, $4, $5, $6, 0)",
        )
        .bind(alice_id())
        .bind(app_id.as_slice())
        .bind(relay)
        .bind(key.id.as_str())
        .bind(key.public.as_slice())
        .bind(&handles)
        .execute(&mut conn)
        .await
        .expect("registration");
        conn.close().await.expect("close");
    }
    let store = replay.db.store();
    let mut txn = store
        .begin(&alice_id())
        .await
        .expect("begin")
        .expect("account");
    assert_eq!(txn.queue_pushes(&targets).await.expect("queued"), 16);
    txn.commit().await.expect("commit");
    let rows = queued(replay).await;
    let toward = |prefix: &str| rows.iter().filter(|row| row.0.starts_with(prefix)).count();
    assert_eq!(toward("wallet-") + toward("executor-"), 8);
    assert_eq!(toward("phone-"), 8);
    setup.replay.db.drop_database().await.expect("drop");
}

/// alice's apps have queued `rows` webhooks, 8 of them in flight; 500 other accounts have 8
/// due each, queued a second earlier, as on a service with many accounts.
async fn large_queue(setup: &Setup, rows: u32) {
    let replay = &setup.replay;
    queue_rows(replay, &alice_id(), rows).await;
    let alice = alice_id();
    for statement in [
        "UPDATE push_deliveries SET attempts = 1, next_attempt_ms = \
         (extract(epoch FROM statement_timestamp()) * 1000)::bigint + 28000 \
         WHERE id IN (SELECT id FROM push_deliveries ORDER BY id LIMIT 8)"
            .to_string(),
        format!(
            "INSERT INTO accounts SELECT (jsonb_populate_record(NULL::accounts, to_jsonb(a) \
             || jsonb_build_object('id', 'many-' || g))).* FROM accounts a, \
             generate_series(1, 500) g WHERE a.id = '{alice}'"
        ),
        format!(
            "INSERT INTO push_registrations (account_id, app_id, relay_url, push_key_id, \
             push_public, handles, set_at_ms) SELECT 'many-' || g, app_id, relay_url, \
             'many-key-' || g, push_public, handles, set_at_ms FROM push_registrations, \
             generate_series(1, 500) g WHERE account_id = '{alice}'"
        ),
        "INSERT INTO push_deliveries (account_id, app_id, push_key_id, handle, \
         entry_at_ms, next_attempt_ms) SELECT r.account_id, r.app_id, r.push_key_id, \
         r.handles[1], t - 1000, t - 1000 FROM push_registrations r, \
         generate_series(1, 8), \
         (SELECT (extract(epoch FROM statement_timestamp()) * 1000)::bigint AS t) now \
         WHERE r.account_id LIKE 'many-%'"
            .to_string(),
        "ANALYZE push_deliveries".to_string(),
    ] {
        sql(replay, &statement).await;
    }
}

#[tokio::test]
async fn test_push_delivery_claim_stays_quick_with_a_large_queue_of_one_account() {
    // A claim, which every instance's claims wait for in turn, stays well inside the 5 s an
    // attempt has from just before its claim, however many rows one account has queued.
    let Some((setup, _)) = registered(&[H1]).await else {
        return;
    };
    large_queue(&setup, 25_000).await;
    let store = setup.replay.db.store();
    let mut took = Vec::new();
    for _ in 0..3 {
        let started = std::time::Instant::now();
        let claimed = store.claim_pushes(16).await.expect("claim");
        took.push((started.elapsed(), claimed.len()));
    }
    setup.replay.db.drop_database().await.expect("drop");
    assert!(
        took.iter().all(|(took, _)| *took < Duration::from_secs(1)),
        "claims took {took:?}"
    );
}

#[tokio::test]
async fn test_push_delivery_large_queue_of_one_account_holds_up_no_other() {
    // Another account's webhook, due before every other row, still goes within about a
    // second while alice has 35,000 queued.
    let Some((setup, _)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    let other = other_account(&setup).await;
    large_queue(&setup, 35_000).await;
    queue_rows(replay, &other, 1).await;
    sql(
        replay,
        &format!(
            "UPDATE push_deliveries SET entry_at_ms = entry_at_ms - 2000, \
             next_attempt_ms = next_attempt_ms - 2000 WHERE account_id = '{other}'"
        ),
    )
    .await;
    let service = Arc::new(setup.instance());
    let running = tokio::spawn({
        let service = service.clone();
        async move { service.deliver_pushes().await }
    });
    let started = std::time::Instant::now();
    while setup.fast.seen().is_empty() && started.elapsed() < Duration::from_secs(12) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let waited = started.elapsed();
    running.abort();
    let rows: Vec<(i32,)> = {
        let mut conn = conn(replay).await;
        let rows = sqlx::query_as("SELECT attempts FROM push_deliveries WHERE account_id = $1")
            .bind(&other)
            .fetch_all(&mut conn)
            .await
            .expect("rows");
        conn.close().await.expect("close");
        rows
    };
    setup.replay.db.drop_database().await.expect("drop");
    assert!(
        waited < Duration::from_secs(3),
        "the other account's webhook unsent after {waited:?}, its row's attempts {rows:?}"
    );
}

#[tokio::test]
async fn test_push_delivery_concurrent_claims_never_claim_a_row_twice() {
    // Eight claimers at once over 40 accounts' due rows: no row is claimed twice, and no
    // account has more than 8 claimed.
    let Some((setup, _)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    let mut accounts = vec![alice_id()];
    for n in 0..39 {
        accounts.push(silent_account(&setup, &format!("account-{n}")).await);
    }
    for account in &accounts {
        queue_rows(replay, account, 20).await;
    }
    let store = replay.db.store().clone();
    let claimers: Vec<_> = (0..8)
        .map(|_| {
            let store = store.clone();
            tokio::spawn(async move {
                let mut mine = Vec::new();
                let mut errors = 0;
                loop {
                    match store.claim_pushes(3).await {
                        Ok(claimed) if claimed.is_empty() => break,
                        Ok(claimed) => {
                            mine.extend(claimed.into_iter().map(|push| (push.id, push.account)));
                        }
                        Err(_) => errors += 1,
                    }
                }
                (mine, errors)
            })
        })
        .collect();
    let mut all = Vec::new();
    let mut errors = 0;
    for claimer in claimers {
        let (mine, failed) = claimer.await.expect("claimer");
        all.extend(mine);
        errors += failed;
    }
    setup.replay.db.drop_database().await.expect("drop");
    let mut ids: Vec<i64> = all.iter().map(|claim| claim.0).collect();
    ids.sort_unstable();
    let claims = ids.len();
    ids.dedup();
    let mut per_account: std::collections::BTreeMap<String, usize> = Default::default();
    for (_, account) in &all {
        *per_account.entry(account.clone()).or_default() += 1;
    }
    assert_eq!(
        ids.len(),
        claims,
        "a row claimed twice ({errors} claims failed)"
    );
    assert!(
        per_account.values().all(|n| *n == 8),
        "{per_account:?} ({errors} claims failed)"
    );
}

#[tokio::test]
async fn test_push_delivery_rows_waiting_for_a_retry_count_against_no_cap() {
    // 8 of alice's rows failed a second ago and wait for their retry, 8 are due: the 8 due
    // are claimed, since a row waiting for its retry isn't in flight. Rows in flight do
    // count: with 8 leased, none is.
    let Some((setup, _)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    queue_rows(replay, &alice_id(), 16).await;
    let first_8 = |next_ms: i64| {
        format!(
            "UPDATE push_deliveries SET attempts = 1, next_attempt_ms = \
             (extract(epoch FROM statement_timestamp()) * 1000)::bigint + {next_ms} \
             WHERE id IN (SELECT id FROM push_deliveries ORDER BY id LIMIT 8)"
        )
    };
    sql(replay, &first_8(19_000)).await;
    let store = replay.db.store();
    assert_eq!(store.claim_pushes(16).await.expect("claim").len(), 8);
    sql(
        replay,
        "UPDATE push_deliveries SET attempts = 0, next_attempt_ms = 0",
    )
    .await;
    sql(replay, &first_8(28_000)).await;
    assert_eq!(store.claim_pushes(16).await.expect("claim").len(), 0);
    setup.replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_push_delivery_hold_waits_at_most_a_second_for_a_locked_registration() {
    // A request holds the registration's row: the attempt's hold gives up after about a
    // second instead of sitting on a connection behind it.
    let Some((setup, _)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    queue_rows(replay, &alice_id(), 1).await;
    let store = replay.db.store();
    let push = store.claim_pushes(1).await.expect("claim").remove(0);
    let mut locker = conn(replay).await;
    sql_on(&mut locker, "BEGIN").await;
    sql_on(&mut locker, "SELECT 1 FROM push_registrations FOR UPDATE").await;
    let started = std::time::Instant::now();
    let held = store.hold_push_registration(&push).await;
    let waited = started.elapsed();
    sql_on(&mut locker, "ROLLBACK").await;
    locker.close().await.expect("close");
    assert!(
        store
            .hold_push_registration(&push)
            .await
            .expect("held")
            .is_some()
    );
    setup.replay.db.drop_database().await.expect("drop");
    assert!(held.is_err(), "held behind the lock");
    assert!(waited < Duration::from_secs(3), "waited {waited:?}");
}

async fn sql_on(conn: &mut sqlx::PgConnection, query: &str) {
    sqlx::query(query).execute(&mut *conn).await.expect("sql");
}

#[tokio::test]
async fn test_push_delivery_holds_take_at_most_a_quarter_of_the_pool() {
    // 16 attempts of two accounts wait for their registrations, which a request holds: at
    // most a quarter of the request pool's connections wait at once, the rest of the pool
    // left to requests.
    let Some((setup, _)) = registered(&[H1]).await else {
        return;
    };
    let replay = &setup.replay;
    let second = silent_account(&setup, "second-account").await;
    queue_rows(replay, &alice_id(), 8).await;
    queue_rows(replay, &second, 8).await;
    let pool = replay.db.store().max_connections();
    let holds = (pool / 4).max(1);
    let mut locker = conn(replay).await;
    sql_on(&mut locker, "BEGIN").await;
    sql_on(&mut locker, "SELECT 1 FROM push_registrations FOR UPDATE").await;
    let service = Arc::new(setup.instance());
    let running = tokio::spawn({
        let service = service.clone();
        async move { service.deliver_pushes().await }
    });
    let mut watcher = conn(replay).await;
    let mut most = 0;
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(3) {
        let (waiting,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() \
             AND wait_event_type = 'Lock' AND query LIKE '%FOR SHARE OF r%'",
        )
        .fetch_one(&mut watcher)
        .await
        .expect("activity");
        most = most.max(waiting);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    watcher.close().await.expect("close");
    sql_on(&mut locker, "ROLLBACK").await;
    locker.close().await.expect("close");
    running.abort();
    setup.replay.db.drop_database().await.expect("drop");
    assert!(most >= 1, "no hold seen waiting");
    assert!(
        most <= i64::from(holds),
        "{most} holds at once, of a pool of {pool}"
    );
}

#[tokio::test]
async fn test_push_handles_past_8_at_one_relay_host_are_refused() {
    // The executor holds 5 handles at the wallet's relay host, spelt otherwise: the wallet
    // may set 3 there, not 4, since an entry sends at most 8 webhooks toward one host. At
    // another host the executor's handles don't count.
    let Some((setup, key)) = registered(&[]).await else {
        return;
    };
    let replay = &setup.replay;
    let keys = vectors("keys.json");
    let executor = pubky_switch_core::enc::app_id_decode(
        app(&keys, "executor")["app_id"].as_str().expect("id"),
    )
    .expect("app id");
    let executor_key = replay.keys.generate().await.expect("push key");
    let mut conn = conn(replay).await;
    sqlx::query(
        "INSERT INTO push_registrations (account_id, app_id, relay_url, push_key_id, \
         push_public, handles, set_at_ms) VALUES ($1, $2, 'https://PUSH.example/v1/other', \
         $3, $4, $5, 0)",
    )
    .bind(alice_id())
    .bind(executor.as_slice())
    .bind(executor_key.id.as_str())
    .bind(executor_key.public.as_slice())
    .bind((0..5).map(|n| format!("executor-{n}")).collect::<Vec<_>>())
    .execute(&mut conn)
    .await
    .expect("registration");
    let set = |count: usize| {
        let handles: Vec<String> = (0..count).map(|n| format!("wallet-{n}")).collect();
        json!({ "relay_url": RELAY, "handles": handles, "push_key": b64(&key) })
    };
    let status = move |push: Value| async move {
        replay
            .service
            .handle(app_request(
                app(&vectors("keys.json"), "wallet"),
                "PUT",
                &format!("/v1/{}/push", alice_id()),
                push.to_string().into_bytes(),
                ms(&at()),
            ))
            .await
            .status
    };
    assert_eq!(status(set(4)).await, 400);
    assert_eq!(status(set(3)).await, 200);
    sqlx::query("UPDATE push_registrations SET relay_url = 'https://fast.example/v1/hook' WHERE app_id = $1")
        .bind(executor.as_slice())
        .execute(&mut conn)
        .await
        .expect("moved");
    conn.close().await.expect("close");
    assert_eq!(status(set(8)).await, 200);
    setup.replay.db.drop_database().await.expect("drop");
}
