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
    ops::{OpsRequest, SignedOp},
    sig::SignedDoc,
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
    replay_at(ORIGIN, "service/alice", limits, time_required).await
}

/// bob's switch origin in the vectors.
pub const BOB_ORIGIN: &str = "https://inbox.bob.example";

/// A service at `origin` whose new accounts take the vectors' service key of
/// `service_label`, on a fresh test database.
pub async fn replay_at(
    origin: &str,
    service_label: &str,
    limits: Limits,
    time_required: bool,
) -> Option<Replay> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let db = test_database().await?;
    let keys = vectors("keys.json");
    let service = keys["service_keys"]
        .as_array()
        .expect("service keys")
        .iter()
        .find(|key| key["seed_label"] == service_label)
        .expect("the service key");
    // The vectors' operator key: the seed of label `service/operator`, by the seed rule of
    // `spec/vectors/README.md`.
    let operator = hex32(&Value::String(OPERATOR_SEED_HEX.into()));
    let key_dir = tempfile::tempdir().expect("key dir");
    let store = FileKeyStore::open(key_dir.path()).expect("key store");
    let keys = Arc::new(FixedKeys::new(
        store,
        vec![hex32(&service["secret_hex"])],
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
        origin.into(),
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

/// bob's account at a switch made by `replay_at(BOB_ORIGIN, "service/bob", ..)`, serving,
/// with his `identity.json` version 1 (`documents.json` "bob identity.json"): his Pubky ID.
pub async fn serve_bob(replay: &Replay) -> String {
    use pubky_switch::keys::KeyStore;
    let keys = vectors("keys.json");
    let bob = keys["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .find(|identity| identity["name"] == "bob")
        .expect("bob");
    let id = bob["pubky_id"].as_str().expect("id").to_string();
    let key = replay.keys.generate().await.expect("key");
    let doc: pubky_switch_core::sig::SignedDoc = serde_json::from_value(
        named(&vectors("documents.json")["documents"], "bob identity.json")["signed"].clone(),
    )
    .expect("document");
    replay
        .db
        .store()
        .create_account(&pubky_switch::store::NewAccount {
            id: id.clone(),
            identity_key: hex32(&bob["public_hex"]),
            generation: 1,
            service_key: key.id,
            created_at_ms: 0,
            limits: pubky_switch_core::records::Limits::default(),
            identity_doc: Some(doc),
            revoked_apps: Vec::new(),
            enrollment_hash: [0; 32],
        })
        .await
        .expect("bob's account");
    id
}

/// A request from `app` (a `keys.json` app) to another identity's switch at `origin`,
/// carrying its certificate (`documents.json` "<app> certificate") in `Switch-Cert` and,
/// if given, an invite code, signed at `at_ms`.
#[allow(clippy::too_many_arguments)]
pub fn other_request(
    app_name: &str,
    origin: &str,
    method: &str,
    path: &str,
    body: Vec<u8>,
    invite_code: Option<&str>,
    at_ms: u64,
) -> SwitchRequest {
    let keys = vectors("keys.json");
    let app = app(&keys, app_name);
    let cert: pubky_switch_core::sig::SignedDoc = serde_json::from_value(
        named(
            &vectors("documents.json")["documents"],
            &format!("{app_name} certificate"),
        )["signed"]
            .clone(),
    )
    .expect("certificate");
    let identity = app["identity"].as_str().expect("identity").to_string();
    let app_id = app["app_id"].as_str().expect("app id").to_string();
    let timestamp = rfc3339_seconds(at_ms);
    let signed_headers = RequestHeaders {
        timestamp: timestamp.clone(),
        identity: identity.clone(),
        app: Some(app_id.clone()),
        cert: Some(cert.compact()),
        invite_code: invite_code.map(str::to_string),
    };
    let secret = ed25519_dalek::SigningKey::from_bytes(&hex32(&app["signing_secret_hex"]));
    let signature = b64(&wire_http::sign_request(
        &secret,
        &RequestTarget {
            method,
            path_and_query: path,
            body: &body,
            origin,
        },
        &signed_headers,
    ));
    let compact = cert.compact();
    let mut headers = vec![
        (header::IDENTITY, identity.as_str()),
        (header::APP, app_id.as_str()),
        (header::CERT, compact.as_str()),
        (header::TIMESTAMP, timestamp.as_str()),
        (header::SIGNATURE, signature.as_str()),
    ];
    if let Some(code) = invite_code {
        headers.push((header::INVITE_CODE, code));
    }
    request(method, path, &headers, body)
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

/// The signed operations of `chain.json`'s items at `seqs`.
pub fn ops_at(chain: &Value, seqs: &[u64]) -> Vec<SignedOp> {
    seqs.iter()
        .map(|seq| {
            let item = chain_item(chain, *seq);
            let signed: SignedDoc = serde_json::from_value(item["item"].clone()).expect("op");
            SignedOp::peek(&signed).expect("op")
        })
        .collect()
}

pub fn chain_item(chain: &Value, seq: u64) -> &Value {
    chain["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["seq"].as_u64() == Some(seq))
        .unwrap_or_else(|| panic!("no item {seq}"))
}

/// The transition proof `chain.json` gives the item at `seq`.
pub fn proof_at(chain: &Value, seq: u64) -> SignedDoc {
    let prefix = format!("(seq {seq})");
    let proof = chain["transition_proofs"]
        .as_array()
        .expect("proofs")
        .iter()
        .find(|proof| proof["name"].as_str().is_some_and(|n| n.contains(&prefix)))
        .unwrap_or_else(|| panic!("no proof for seq {seq}"));
    serde_json::from_value(proof["signed"].clone()).expect("proof")
}

/// Send the batch of the items at `seqs` from the wallet at the first item's time, and check
/// its answer: one proof per item, `chain.json`'s, and the head at the last item.
pub async fn replay_batch(replay: &Replay, chain: &Value, seqs: &[u64]) {
    let keys = vectors("keys.json");
    let wallet = app(&keys, "wallet");
    let alice_id = alice(&keys)["pubky_id"].as_str().expect("id").to_string();
    let at = item_time(chain_item(chain, seqs[0]));
    set_time(&replay.clock, &at);
    let body = OpsRequest::new(&ops_at(chain, seqs), None).to_json();
    let request = app_request(
        wallet,
        "POST",
        &format!("/v1/{alice_id}/ops"),
        body,
        ms(&at),
    );
    let answer = replay.service.handle(request).await;
    let text = String::from_utf8_lossy(&answer.body).into_owned();
    assert_eq!(answer.status, 200, "seqs {seqs:?}: {text}");
    let body: Value = serde_json::from_slice(&answer.body).expect("json");
    let proofs: Vec<SignedDoc> = serde_json::from_value(body["proofs"].clone()).expect("proofs");
    let expected: Vec<SignedDoc> = seqs.iter().map(|seq| proof_at(chain, *seq)).collect();
    assert_eq!(proofs, expected, "seqs {seqs:?}: the proofs");
    let last = chain_item(chain, *seqs.last().expect("seq"));
    assert_eq!(
        body["head"]["seq"], last["seq"],
        "seqs {seqs:?}: the head's seq"
    );
    assert_eq!(
        body["head"]["chain_hash"], last["chain_hash"],
        "seqs {seqs:?}: the head's chain hash"
    );
    assert!(header_text(&answer, header::HEAD).is_some(), "Switch-Head");
}

/// `chain.json` through the revoke at seq 9 (Switch wire 7.4.12): alice served, the
/// wallet's registration batch (seqs 3 and 4), the inbox entry's seq 5, the record's create
/// (seq 6), the batch of the attempt and the record's update (seqs 7 and 8), and the
/// signer's revoke of the phone.
pub async fn replay_chain_through_revoke(replay: &Replay) {
    let chain = vectors("chain.json");
    let keys = vectors("keys.json");
    let alice_id = alice(&keys)["pubky_id"].as_str().expect("id").to_string();
    serve_alice(replay).await;
    replay_batch(replay, &chain, &[3, 4]).await;
    assert_eq!(replay.db.give_out_seq(&alice_id).await.expect("seq"), 5);
    replay_batch(replay, &chain, &[6]).await;
    replay_batch(replay, &chain, &[7, 8]).await;
    let at = item_time(chain_item(&chain, 9));
    set_time(&replay.clock, &at);
    let phone = app(&keys, "phone")["app_id"]
        .as_str()
        .expect("id")
        .to_string();
    let path = format!("/v1/{alice_id}/apps/{phone}/revoke");
    let answer = replay
        .service
        .handle(signer_request("POST", &path, Vec::new(), ms(&at)))
        .await;
    assert_eq!(answer.status, 200, "revoked");
}

/// The public key of the vectors' operator key, which signs answers the service can't tie
/// to an account.
pub fn operator_public() -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&hex32(&Value::String(OPERATOR_SEED_HEX.into())))
        .verifying_key()
        .to_bytes()
}
