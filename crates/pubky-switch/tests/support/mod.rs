//! Shared setup for the service's tests: the vectors, a service on a test database with the
//! vectors' fixed keys and a manual clock, and signed requests.

// Test helpers fail the test on any error; not every test file uses every helper.
#![allow(clippy::expect_used, clippy::panic, dead_code)]

use std::{path::PathBuf, sync::Arc};

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use pubky_switch::{
    http::Handler,
    http::{SwitchRequest, SwitchResponse, route::route},
    keys::{FileKeyStore, FixedKeys},
    limits::Limits,
    service::Service,
    store::testing::{TestDatabase, test_database},
    time::{ManualClock, TrustedTime, TrustedTimeConfig},
};
use pubky_switch_core::{
    enc::{b64, unb64},
    http::{self as wire_http, RequestHeaders, RequestTarget, header},
    time::{parse_rfc3339, rfc3339_seconds},
};
use serde_json::Value;

/// The seed of the vectors' operator key.
const OPERATOR_SEED_HEX: &str = "a7ded4a83952cd27b38c2535a2b439e7fff263ae42740790f69e5bc4a1364c8c";

pub const ORIGIN: &str = "https://inbox.example";

pub fn vectors(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors")
        .join(name);
    serde_json::from_slice(&std::fs::read(&path).expect("vector file")).expect("json")
}

pub fn named<'a>(list: &'a Value, name: &str) -> &'a Value {
    list.as_array()
        .expect("list")
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))
}

pub fn hex32(text: &Value) -> [u8; 32] {
    hex::decode(text.as_str().expect("hex"))
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

pub struct Replay {
    pub db: TestDatabase,
    pub clock: Arc<ManualClock>,
    pub service: Service,
    pub keys: Arc<FixedKeys>,
    pub time: Arc<TrustedTime>,
    _key_dir: tempfile::TempDir,
}

impl Replay {
    /// Another service on the same database, keys and clock, with `limits`, as after the
    /// operator changes its configuration.
    pub fn restarted_with(&self, limits: Limits) -> Service {
        Service::new(
            ORIGIN.into(),
            self.db.store().clone(),
            self.keys.clone(),
            self.time.clone(),
            limits,
        )
    }
}

pub async fn replay() -> Option<Replay> {
    replay_with(Limits::default()).await
}

/// A service with `limits`, on a fresh test database.
pub async fn replay_with(limits: Limits) -> Option<Replay> {
    replay_with_time(limits, false).await
}

/// A service with `limits`, on a fresh test database; with `time_required`, it needs
/// trusted time, and has no sample.
pub async fn replay_with_time(limits: Limits, time_required: bool) -> Option<Replay> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let db = test_database().await?;
    let keys = vectors("keys.json");
    let alice_service = keys["service_keys"]
        .as_array()
        .expect("service keys")
        .iter()
        .find(|key| key["seed_label"] == "service/alice")
        .expect("alice's service key");
    // The vectors' operator key: the seed of label `service/operator`, by the seed rule of
    // `spec/vectors/README.md`.
    let operator = hex32(&Value::String(OPERATOR_SEED_HEX.into()));
    let key_dir = tempfile::tempdir().expect("key dir");
    let store = FileKeyStore::open(key_dir.path()).expect("key store");
    let keys = Arc::new(FixedKeys::new(
        store,
        vec![hex32(&alice_service["secret_hex"])],
        Some(operator),
    ));
    let clock = Arc::new(ManualClock::new(0));
    let time = Arc::new(TrustedTime::new(
        TrustedTimeConfig {
            required: time_required,
            ..TrustedTimeConfig::default()
        },
        clock.clone(),
    ));
    let service = Service::new(
        ORIGIN.into(),
        db.store().clone(),
        keys.clone(),
        time.clone(),
        limits,
    );
    Some(Replay {
        db,
        clock,
        service,
        keys,
        time,
        _key_dir: key_dir,
    })
}

pub fn request(method: &str, path: &str, headers: &[(&str, &str)], body: Vec<u8>) -> SwitchRequest {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.insert(
            HeaderName::from_bytes(name.as_bytes()).expect("name"),
            HeaderValue::from_str(value).expect("value"),
        );
    }
    SwitchRequest {
        route: route(method, path).expect("route"),
        method: method.into(),
        path_and_query: path.into(),
        headers: map,
        body: body.into(),
        source: None,
    }
}

pub fn vector_request(case: &Value) -> SwitchRequest {
    let headers: Vec<(String, String)> = case["headers"]
        .as_object()
        .expect("headers")
        .iter()
        .map(|(name, value)| (name.clone(), value.as_str().expect("text").to_string()))
        .collect();
    let refs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let body = unb64(case["body_b64"].as_str().unwrap_or_default()).expect("body");
    request(
        case["method"].as_str().expect("method"),
        case["path"].as_str().expect("path"),
        &refs,
        body,
    )
}

pub fn header_text<'a>(response: &'a SwitchResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(header, _)| header.as_str() == name)
        .and_then(|(_, value)| value.to_str().ok())
}

/// The response matches the vector byte for byte: status, body, server time and signature.
pub fn assert_matches(response: &SwitchResponse, expected: &Value) {
    let name = expected["name"].as_str().expect("name");
    assert_eq!(
        u64::from(response.status),
        expected["status"].as_u64().expect("status"),
        "{name}: status"
    );
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        expected["body"].as_str().expect("body"),
        "{name}: body"
    );
    for (header, value) in expected["headers"].as_object().expect("headers") {
        assert_eq!(
            header_text(response, header),
            value.as_str(),
            "{name}: header {header}"
        );
    }
}

pub fn set_time(clock: &ManualClock, text: &str) {
    clock.set_wall_ms(parse_rfc3339(text).expect("time"));
}

/// A request from alice's signer, signed with her fixed identity key at `at_ms`.
pub fn signer_request(method: &str, path: &str, body: Vec<u8>, at_ms: u64) -> SwitchRequest {
    let keys = vectors("keys.json");
    let alice = alice(&keys);
    let alice_id = alice["pubky_id"].as_str().expect("id").to_string();
    let timestamp = rfc3339_seconds(at_ms);
    let signed_headers = RequestHeaders {
        timestamp: timestamp.clone(),
        identity: alice_id.clone(),
        ..RequestHeaders::default()
    };
    let secret = ed25519_dalek::SigningKey::from_bytes(&hex32(&alice["secret_hex"]));
    let signature = b64(&wire_http::sign_request(
        &secret,
        &RequestTarget {
            method,
            path_and_query: path,
            body: &body,
            origin: ORIGIN,
        },
        &signed_headers,
    ));
    request(
        method,
        path,
        &[
            (header::IDENTITY, &alice_id),
            (header::TIMESTAMP, &timestamp),
            (header::SIGNATURE, &signature),
        ],
        body,
    )
}

/// alice's entry in `keys.json`.
pub fn alice(keys: &Value) -> &Value {
    keys["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == "alice")
        .expect("alice")
}

/// The time `text` names, in Unix milliseconds.
pub fn ms(text: &str) -> u64 {
    parse_rfc3339(text).expect("time")
}

/// The app of `keys.json` named `name`.
pub fn app<'a>(keys: &'a Value, name: &str) -> &'a Value {
    keys["apps"]
        .as_array()
        .expect("apps")
        .iter()
        .find(|app| app["name"] == name)
        .unwrap_or_else(|| panic!("no app {name}"))
}

/// A request from alice's own app `app` (a `keys.json` entry), signed with its fixed
/// signing key at `at_ms`.
pub fn app_request(
    app: &Value,
    method: &str,
    path: &str,
    body: Vec<u8>,
    at_ms: u64,
) -> SwitchRequest {
    let keys = vectors("keys.json");
    let alice_id = alice(&keys)["pubky_id"].as_str().expect("id").to_string();
    let app_id = app["app_id"].as_str().expect("app id").to_string();
    let timestamp = rfc3339_seconds(at_ms);
    let signed_headers = RequestHeaders {
        timestamp: timestamp.clone(),
        identity: alice_id.clone(),
        app: Some(app_id.clone()),
        ..RequestHeaders::default()
    };
    let secret = ed25519_dalek::SigningKey::from_bytes(&hex32(&app["signing_secret_hex"]));
    let signature = b64(&wire_http::sign_request(
        &secret,
        &RequestTarget {
            method,
            path_and_query: path,
            body: &body,
            origin: ORIGIN,
        },
        &signed_headers,
    ));
    request(
        method,
        path,
        &[
            (header::IDENTITY, &alice_id),
            (header::APP, &app_id),
            (header::TIMESTAMP, &timestamp),
            (header::SIGNATURE, &signature),
        ],
        body,
    )
}

/// The `server_time` of a `chain.json` item's envelope.
pub fn item_time(item: &Value) -> String {
    let envelope: Value =
        serde_json::from_str(item["envelope_json"].as_str().expect("envelope")).expect("json");
    envelope["server_time"].as_str().expect("time").to_string()
}

/// alice's account as `chain.json` starts it: enrolled, then given `identity.json` version
/// 1 at seq 1 and version 3 at seq 2, at the items' times.
pub async fn serve_alice(replay: &Replay) {
    let http = vectors("http.json");
    let chain = vectors("chain.json");
    let documents = vectors("documents.json");
    let keys = vectors("keys.json");
    let alice_id = alice(&keys)["pubky_id"].as_str().expect("id").to_string();
    let enrolled = named(
        &http["responses"],
        "signer: enrollment answer, signed with the new account's key",
    );
    set_time(
        &replay.clock,
        enrolled["headers"]["switch-server-time"]
            .as_str()
            .expect("time"),
    );
    let enrollment = vector_request(named(&http["requests"], "signer: enrollment"));
    assert_eq!(
        replay.service.handle(enrollment).await.status,
        200,
        "enrolled"
    );
    let items = chain["items"].as_array().expect("items");
    set_time(&replay.clock, &item_time(&items[0]));
    let delivery = vector_request(named(&http["requests"], "signer: identity.json delivery"));
    assert_eq!(
        replay.service.handle(delivery).await.status,
        200,
        "version 1"
    );
    let at = item_time(&items[1]);
    set_time(&replay.clock, &at);
    let doc = |name: &str| -> pubky_switch_core::sig::SignedDoc {
        serde_json::from_value(named(&documents["documents"], name)["signed"].clone())
            .expect("document")
    };
    let version_1 = doc("alice identity.json, first delivery (version 1)");
    let body = pubky_switch_core::http::IdentityDelivery {
        identity: doc("alice identity.json"),
        prev: Some(version_1.doc_hash().expect("hash")),
    }
    .to_json();
    let path = format!("/v1/{alice_id}/identity");
    let delivery = signer_request("PUT", &path, body, ms(&at));
    assert_eq!(
        replay.service.handle(delivery).await.status,
        200,
        "version 3"
    );
}

/// A request signed at `at_ms` by `key`, for the identity `identity` (a Pubky ID) and, with
/// `app`, one of its apps (an App ID).
pub fn signed_request(
    key: &ed25519_dalek::SigningKey,
    identity: &str,
    app: Option<&str>,
    method: &str,
    path: &str,
    body: Vec<u8>,
    at_ms: u64,
) -> SwitchRequest {
    let timestamp = rfc3339_seconds(at_ms);
    let signed_headers = RequestHeaders {
        timestamp: timestamp.clone(),
        identity: identity.to_string(),
        app: app.map(str::to_string),
        ..RequestHeaders::default()
    };
    let signature = b64(&wire_http::sign_request(
        key,
        &RequestTarget {
            method,
            path_and_query: path,
            body: &body,
            origin: ORIGIN,
        },
        &signed_headers,
    ));
    let mut headers = vec![
        (header::IDENTITY, identity),
        (header::TIMESTAMP, timestamp.as_str()),
        (header::SIGNATURE, signature.as_str()),
    ];
    if let Some(app) = app {
        headers.push((header::APP, app));
    }
    request(method, path, &headers, body)
}

/// The fixed secret of a vectors' seed label, by the seed rule `spec/vectors/README.md`
/// states, read from there.
pub fn seed(label: &str) -> [u8; 32] {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/README.md");
    let readme = std::fs::read_to_string(&path).expect("README");
    let start = readme
        .find("BLAKE3(\"")
        .expect("the README states the seed rule")
        + 8;
    let end = start + readme[start..].find('"').expect("the rule's prefix");
    *blake3::hash(format!("{}{label}", &readme[start..end]).as_bytes()).as_bytes()
}
