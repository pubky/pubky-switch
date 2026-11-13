//! `spec/vectors/http.json` through the client: every request is rebuilt byte for byte by
//! the typed call that makes it, from the fixed keys and the vector's time, and every
//! response is checked as the client checks answers (Switch wire 7.1, 7.2, 7.4).
//!
//! The scopes and other protocol values in the files are sample data, read from the files
//! and treated as opaque strings.

// Helpers read fixed vector files, where a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use pubky_switch_client::client::answers::{FeedItem, FeedQuery, StoredHandover};
use pubky_switch_client::client::check_response;
use pubky_switch_client::clock::TestClock;
use pubky_switch_client::transport::{Header, MockTransport, Request, Response, Transport};
use pubky_switch_client::{ClientError, Credentials, SwitchClient, TransportError};
use pubky_switch_core::enc::{app_id_decode, pubky_id, pubky_key, unb64, unb64_array};
use pubky_switch_core::http::{ErrorCode, IdentityDelivery, header};
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::ops::Position;
use pubky_switch_core::records::{AppCert, Enrollment, ExportTransfer, SignerHandover};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::parse_rfc3339;
use serde_json::Value;

fn spec_file(name: &str) -> String {
    format!("{}/../../spec/vectors/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn load(name: &str) -> Value {
    let path = spec_file(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The seed prefix of the vectors' README ("Seeds"): every fixed secret is
/// `BLAKE3(prefix + label)`. It is read from the README, the convention's one source.
fn seed_prefix() -> String {
    let path = spec_file("README.md");
    let readme = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let start = readme
        .find("BLAKE3(\"")
        .expect("the README names the seed rule")
        + 8;
    let len = readme[start..].find('"').expect("a closing quote");
    readme[start..start + len].to_owned()
}

fn seed(label: &str) -> [u8; 32] {
    *blake3::hash(format!("{}{label}", seed_prefix()).as_bytes()).as_bytes()
}

fn st<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("{k} isn't a string"))
}

fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array()
        .unwrap_or_else(|| panic!("{k} isn't an array"))
}

fn b64(text: &str) -> Vec<u8> {
    unb64(text).unwrap()
}

fn b32(text: &str) -> [u8; 32] {
    unb64_array::<32>(text).unwrap()
}

fn hex32(text: &str) -> [u8; 32] {
    hex::decode(text).unwrap().try_into().unwrap()
}

/// The fixed keys of `keys.json`, each derived from its seed label and checked against the
/// file.
struct Keys {
    identities: BTreeMap<String, IdentityKey>,
    apps: BTreeMap<String, (String, AppKeys)>,
    /// Account Pubky ID to its service key.
    services: BTreeMap<String, SigningKey>,
    next_service: SigningKey,
}

fn keyed(entry: &Value, label: &str, secret: &str) -> [u8; 32] {
    let derived = seed(st(entry, label));
    assert_eq!(
        derived,
        hex32(st(entry, secret)),
        "{}: the seed rule",
        st(entry, label)
    );
    derived
}

fn keys() -> Keys {
    let k = load("keys.json");
    let identities = arr(&k, "identities")
        .iter()
        .map(|i| {
            let key = IdentityKey::from_secret(keyed(i, "seed_label", "secret_hex"));
            assert_eq!(key.id(), st(i, "pubky_id"));
            (st(i, "name").to_owned(), key)
        })
        .collect();
    let apps = arr(&k, "apps")
        .iter()
        .map(|a| {
            let keys = AppKeys::from_secrets(
                keyed(a, "signing_seed_label", "signing_secret_hex"),
                hex32(st(a, "bundle_secret_hex")),
            );
            assert_eq!(keys.app_id(), st(a, "app_id"));
            assert_eq!(keys.bundle_public(), b32(st(a, "bundle_public")));
            (
                st(a, "name").to_owned(),
                (st(a, "identity").to_owned(), keys),
            )
        })
        .collect();
    let services = arr(&k, "service_keys")
        .iter()
        .map(|s| {
            let key = SigningKey::from_bytes(&keyed(s, "seed_label", "secret_hex"));
            assert_eq!(key.verifying_key().to_bytes(), b32(st(s, "public")));
            (st(s, "account").to_owned(), key)
        })
        .collect();
    let next = &k["next_service_key"];
    let next_service = SigningKey::from_bytes(&keyed(next, "seed_label", "secret_hex"));
    Keys {
        identities,
        apps,
        services,
        next_service,
    }
}

impl Keys {
    fn identity(&self, name: &str) -> &IdentityKey {
        &self.identities[name]
    }

    fn app_by_signing(&self, public: &[u8; 32]) -> Option<(&str, &str, &AppKeys)> {
        self.apps
            .iter()
            .find(|(_, (_, keys))| keys.signing_public() == *public)
            .map(|(name, (identity, keys))| (name.as_str(), identity.as_str(), keys))
    }
}

/// A document of `documents.json` by name.
fn document(name: &str) -> SignedDoc {
    let v = load("documents.json");
    let entry = arr(&v, "documents")
        .iter()
        .find(|d| st(d, "name") == name)
        .unwrap_or_else(|| panic!("no document {name}"));
    serde_json::from_value(entry["signed"].clone()).unwrap()
}

fn header_of<'a>(v: &'a Value, name: &str) -> Option<&'a str> {
    v["headers"].get(name).and_then(Value::as_str)
}

/// A vector response as the transport hands it over.
fn response_of(r: &Value) -> Response {
    let headers = r["headers"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| Header::new(name, value.as_str().unwrap()))
        .collect();
    Response {
        status: u16::try_from(r["status"].as_u64().unwrap()).unwrap(),
        headers,
        body: st(r, "body").as_bytes().to_vec(),
    }
}

/// The `Switch-*` headers of a request, by name.
fn switch_headers(request: &Request) -> BTreeMap<String, String> {
    request
        .headers
        .iter()
        .filter(|h| h.name.starts_with("switch-"))
        .map(|h| (h.name.clone(), h.value.clone()))
        .collect()
}

fn vector_headers(r: &Value) -> BTreeMap<String, String> {
    r["headers"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| (name.clone(), value.as_str().unwrap().to_owned()))
        .collect()
}

/// The credentials that signed a vector request, from its public key and headers.
fn credentials(keys: &Keys, r: &Value) -> Credentials {
    let public = b32(st(r, "public_key"));
    if let Some(transfer) = header_of(r, header::TRANSFER) {
        let alice = keys.identity("alice").public();
        assert_eq!(public, keys.next_service.verifying_key().to_bytes());
        return Credentials::NextService {
            identity: alice,
            key: Arc::new(keys.next_service.clone()),
            transfer: ExportTransfer::verify(&SignedDoc::from_compact(transfer).unwrap(), &alice)
                .unwrap(),
        };
    }
    if let Some((name, identity_id, app)) = keys.app_by_signing(&public) {
        let identity = pubky_key(identity_id).unwrap();
        let cert = match header_of(r, header::CERT) {
            Some(compact) => SignedDoc::from_compact(compact).unwrap(),
            None => document(&format!("{name} certificate")),
        };
        return Credentials::App {
            identity,
            keys: app.clone(),
            cert: AppCert::verify(&cert, &identity).unwrap(),
        };
    }
    let (_, key) = keys
        .identities
        .iter()
        .find(|(_, key)| key.public() == public)
        .expect("a fixed key signs every request");
    Credentials::Signer {
        identity: key.public(),
        key: Arc::new(key.clone()),
    }
}

/// The account a request's path names.
fn account_of(path: &str) -> [u8; 32] {
    let id = path.split('/').nth(2).unwrap().split('?').next().unwrap();
    pubky_key(id).unwrap()
}

/// What a typed call returned, reduced to compare with the vectors.
#[derive(Debug, PartialEq)]
enum Outcome {
    Ok,
    Err(ClientError),
}

fn outcome<T>(result: Result<T, ClientError>) -> Outcome {
    match result {
        Ok(_) => Outcome::Ok,
        Err(error) => Outcome::Err(error),
    }
}

/// Make the typed call of a vector request.
async fn call(client: &SwitchClient, r: &Value) -> Outcome {
    let name = st(r, "name");
    let body = b64(st(r, "body_b64"));
    let path = st(r, "path");
    let call = path.split('?').next().unwrap();
    let method = st(r, "method");
    match (method, call.rsplit('/').next().unwrap()) {
        ("GET", "feed") => {
            let query = FeedQuery {
                after: Some(Position {
                    generation: 1,
                    seq: 41,
                }),
                limit: Some(100),
                wait: Some(25),
            };
            outcome(client.feed(query).await)
        }
        ("POST", "inbox") => {
            let apps_version = path.split("apps_version=").nth(1).unwrap().parse().unwrap();
            let code = header_of(r, header::INVITE_CODE);
            outcome(client.append(body, apps_version, code).await)
        }
        ("POST", "enroll") => {
            let value: Value = serde_json::from_slice(&body).unwrap();
            let signed: SignedDoc = serde_json::from_value(value["enrollment"].clone()).unwrap();
            let enrollment =
                Enrollment::verify(&signed, &client.account(), st(r, "origin")).unwrap();
            outcome(client.enroll(&enrollment).await)
        }
        ("PUT", "identity") => {
            let delivery = IdentityDelivery::parse(&body).unwrap();
            outcome(client.put_identity(&delivery).await)
        }
        ("GET", chunk) if call.contains("/export/chunks/") => {
            outcome(client.export_chunk(chunk).await)
        }
        ("POST", "erase") => {
            // The `identity.json` the erasure follows, when it names one (Switch wire 7.4.16).
            let named = pubky_switch_core::http::parse_erase_body(&body).unwrap();
            outcome(client.erase(named.identity_hash).await)
        }
        ("PUT", "peers") => {
            let doc: SignedDoc = serde_json::from_slice(&body).unwrap();
            outcome(client.put_peers(&doc, None).await)
        }
        ("PUT", "handover") => {
            let value: Value = serde_json::from_slice(&body).unwrap();
            let handover: SignerHandover =
                serde_json::from_value(value["handover"].clone()).unwrap();
            let stored = StoredHandover {
                app_id: app_id_decode(st(&value, "app_id")).unwrap(),
                handover,
            };
            outcome(client.put_handover(&stored).await)
        }
        ("GET", "handover") => outcome(client.get_handover().await),
        _ => panic!("{name}: no typed call for {method} {call}"),
    }
}

#[tokio::test]
async fn test_vectors_http_requests_reproduced_by_the_typed_calls() {
    let keys = keys();
    let v = load("http.json");
    let responses = arr(&v, "responses");
    for r in arr(&v, "requests") {
        let name = st(r, "name");
        let signature = st(r, "signature");
        // The answers to this request, in the file's order.
        let answers: Vec<&Value> = responses
            .iter()
            .filter(|resp| resp["request_signature"].as_str() == Some(signature))
            .collect();
        let path = st(r, "path");
        let account = if path == "/v1/enroll" {
            keys.identity("alice").public()
        } else {
            account_of(path)
        };
        // The key the answers verify with, or the account's own service key.
        let pinned = answers
            .first()
            .map(|resp| b32(st(resp, "public_key")))
            .or_else(|| {
                keys.services
                    .get(&pubky_id(&account))
                    .map(|key| key.verifying_key().to_bytes())
            });
        let is_enrollment = path == "/v1/enroll";
        let now = parse_rfc3339(header_of(r, header::TIMESTAMP).unwrap()).unwrap();
        for round in 0..answers.len().max(1) {
            let transport = Arc::new(MockTransport::new());
            match answers.get(round) {
                Some(answer) => transport.push_response(response_of(answer)),
                None => transport.push_error(TransportError::Timeout),
            }
            let client = SwitchClient::new(
                st(r, "origin"),
                account,
                credentials(&keys, r),
                if is_enrollment { None } else { pinned },
                Arc::clone(&transport) as Arc<dyn Transport>,
                Arc::new(TestClock::new(now)),
            )
            .unwrap_or_else(|e| panic!("{name}: {e}"));
            let result = call(&client, r).await;

            let sent = transport.last_request().expect("the call went out");
            assert_eq!(sent.method, st(r, "method"), "{name}");
            assert_eq!(sent.origin, st(r, "origin"), "{name}");
            assert_eq!(sent.path_and_query, path, "{name}");
            assert_eq!(sent.body, b64(st(r, "body_b64")), "{name}: body bytes");
            assert_eq!(switch_headers(&sent), vector_headers(r), "{name}: headers");

            // The answer, checked with the pinned key, is what the vector says it is.
            match answers.get(round) {
                None => assert_eq!(
                    result,
                    Outcome::Err(ClientError::Transport(TransportError::Timeout)),
                    "{name}"
                ),
                Some(answer) => {
                    let status = answer["status"].as_u64().unwrap();
                    match result {
                        Outcome::Ok => assert_eq!(status, 200, "{name}"),
                        Outcome::Err(ClientError::Switch {
                            status: got, code, ..
                        }) => {
                            let body: Value = serde_json::from_str(st(answer, "body")).unwrap();
                            assert_eq!(u64::from(got), status, "{name}");
                            assert_eq!(code.as_str(), st(&body, "code"), "{name}");
                        }
                        Outcome::Err(error) => panic!("{name}: {error}"),
                    }
                }
            }
            if is_enrollment && !answers.is_empty() {
                assert_eq!(
                    client.pinned_key(),
                    pinned,
                    "{name}: the answer's key pinned"
                );
            }
        }
    }
}

/// The account whose service signed a response: the account of its key in `keys.json`.
fn account_of_key(keys: &Keys, public: &[u8; 32]) -> Option<[u8; 32]> {
    keys.services
        .iter()
        .find(|(_, key)| key.verifying_key().to_bytes() == *public)
        .map(|(account, _)| pubky_key(account).unwrap())
}

#[test]
fn test_vectors_http_responses_checked_with_the_pinned_key() {
    let keys = keys();
    let v = load("http.json");
    for r in arr(&v, "responses") {
        let name = st(r, "name");
        let response = response_of(r);
        let public = b32(st(r, "public_key"));
        let request_signature = r["request_signature"].as_str().map(|s| {
            let bytes: [u8; 64] = b64(s).try_into().unwrap();
            bytes
        });
        let Some(account) = account_of_key(&keys, &public) else {
            // The operator's key, which no client knows: unauthenticated with any account
            // key a client pins.
            assert_eq!(response.status, 404, "{name}");
            for (account, key) in &keys.services {
                assert_eq!(
                    check_response(
                        &key.verifying_key().to_bytes(),
                        &pubky_key(account).unwrap(),
                        request_signature.as_ref(),
                        &response,
                    )
                    .unwrap_err(),
                    ClientError::BadServiceSignature { status: 404 },
                    "{name}"
                );
            }
            continue;
        };
        let checked = check_response(&public, &account, request_signature.as_ref(), &response);
        if response.status < 300 {
            let checked = checked.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(
                checked.head.is_some(),
                header_of(r, header::HEAD).is_some(),
                "{name}: the head verified"
            );
            assert_eq!(
                checked.server_time_ms,
                parse_rfc3339(header_of(r, header::SERVER_TIME).unwrap()).unwrap()
            );
        } else {
            let error = checked.unwrap_err();
            let body: Value = serde_json::from_str(st(r, "body")).unwrap();
            let code = ErrorCode::parse(st(&body, "code")).unwrap();
            assert_eq!(error.code(), Some(code), "{name}");
            assert_eq!(error.retry(), Some(code.retry()), "{name}");
            if let ClientError::Switch {
                retry_after,
                known_version,
                current,
                ..
            } = &error
            {
                assert_eq!(*retry_after, body["retry_after"].as_u64(), "{name}");
                assert_eq!(*known_version, body["known_version"].as_u64(), "{name}");
                assert_eq!(*current, body["current"], "{name}");
            }
        }
        // Another pinned key, another body or another request signature: refused.
        let wrong_key = keys.next_service.verifying_key().to_bytes();
        assert_eq!(
            check_response(&wrong_key, &account, request_signature.as_ref(), &response)
                .unwrap_err(),
            ClientError::BadServiceSignature {
                status: response.status
            },
            "{name}"
        );
        let mut tampered = response.clone();
        tampered.body.push(b' ');
        assert!(matches!(
            check_response(&public, &account, request_signature.as_ref(), &tampered),
            Err(ClientError::BadServiceSignature { .. })
        ));
        assert!(matches!(
            check_response(&public, &account, Some(&[0; 64]), &response),
            Err(ClientError::BadServiceSignature { .. })
        ));
        // A head is checked for the account it names; one that doesn't verify is ignored,
        // as the response signature doesn't cover it (wire 7.1).
        if header_of(r, header::HEAD).is_some() {
            let other = keys.identity("bob").public();
            let account = if other == account {
                keys.identity("alice").public()
            } else {
                other
            };
            let checked = check_response(&public, &account, request_signature.as_ref(), &response);
            assert!(
                matches!(&checked, Ok(c) if c.head.is_none())
                    || matches!(&checked, Err(ClientError::Switch { .. })),
                "{name}: {checked:?}"
            );
        }
    }
}

/// A switch that answers with a vector response's status, server time and body, signed
/// again with `key` for the request it gets, as the service would answer it.
fn replaying(key: SigningKey, r: &Value) -> Arc<MockTransport> {
    let template = response_of(r);
    Arc::new(MockTransport::with_handler(move |request| {
        let server_time = template.header(header::SERVER_TIME).unwrap().to_owned();
        let request_signature =
            pubky_switch_core::http::request_signature_of(request.header(header::SIGNATURE));
        let signature = pubky_switch_core::http::sign_response(
            &key,
            template.status,
            request_signature.as_ref(),
            &server_time,
            &template.body,
        );
        let mut headers: Vec<Header> = template
            .headers
            .iter()
            .filter(|h| h.name != header::SERVICE_SIGNATURE)
            .cloned()
            .collect();
        headers.push(Header::new(
            header::SERVICE_SIGNATURE,
            &pubky_switch_core::enc::b64(&signature),
        ));
        Ok(Response {
            status: template.status,
            headers,
            body: template.body.clone(),
        })
    }))
}

fn response_named<'a>(v: &'a Value, prefix: &str) -> &'a Value {
    arr(v, "responses")
        .iter()
        .find(|r| st(r, "name").starts_with(prefix))
        .unwrap_or_else(|| panic!("no response {prefix}"))
}

#[tokio::test]
async fn test_vectors_http_answers_read_by_the_typed_calls() {
    let keys = keys();
    let v = load("http.json");
    let alice = keys.identity("alice").public();
    let alice_key = keys.services[&pubky_id(&alice)].clone();
    let pinned = Some(alice_key.verifying_key().to_bytes());
    let clock = || Arc::new(TestClock::new(1_767_225_900_000));
    let wallet = Credentials::App {
        identity: alice,
        keys: keys.apps["wallet"].1.clone(),
        cert: AppCert::verify(&document("wallet certificate"), &alice).unwrap(),
    };

    // The feed page with an entry and chain items, read by alice's wallet: its opaque
    // contexts read, its head verifies, and the superseded create at seq 6 reads as a stub.
    let page = response_named(&v, "own app: feed page with an entry");
    let client = SwitchClient::new(
        "https://inbox.example",
        alice,
        wallet.clone(),
        pinned,
        replaying(alice_key.clone(), page),
        clock(),
    )
    .unwrap();
    let read = client.feed(FeedQuery::default()).await.unwrap();
    assert!(matches!(read.items.first(), Some(FeedItem::Entry(_))));
    assert!(read.items.iter().any(|i| matches!(i, FeedItem::Chain(_))));
    assert!(
        read.items
            .iter()
            .any(|i| matches!(i, FeedItem::Stub { .. }) && i.seq() == 6)
    );
    assert!(read.items.windows(2).all(|w| w[0].seq() < w[1].seq()));

    // The directory, read by bob's shop: the documents verify for alice.
    let bob = keys.identity("bob").public();
    let shop = Credentials::App {
        identity: bob,
        keys: keys.apps["shop"].1.clone(),
        cert: AppCert::verify(&document("shop certificate"), &bob).unwrap(),
    };
    let directory = response_named(&v, "app of another identity: directory");
    let client = SwitchClient::new(
        "https://inbox.example",
        alice,
        shop,
        pinned,
        replaying(alice_key.clone(), directory),
        clock(),
    )
    .unwrap();
    let read = client.directory(None).await.unwrap();
    assert_eq!(read.identity.identity(), alice);
    assert!(!read.apps.is_empty());
    assert!(read.known_version.is_some());

    // The public reads carry no request signature, so the vector answers verify as they are.
    for prefix in ["anyone: the public", "anyone: a frozen"] {
        let answer = response_named(&v, prefix);
        let transport = Arc::new(MockTransport::new());
        transport.push_response(response_of(answer));
        let client = SwitchClient::new(
            "https://inbox.example",
            alice,
            wallet.clone(),
            pinned,
            transport,
            clock(),
        )
        .unwrap();
        let read = client.public_identity().await.unwrap();
        assert_eq!(read.identity.identity(), alice);
        assert_eq!(read.freeze.is_some(), prefix == "anyone: a frozen");
    }

    // The batch answer's proofs and head verify with the account's key.
    let ops = response_named(&v, "own app: POST /ops answer");
    let body: Value = serde_json::from_str(st(ops, "body")).unwrap();
    let key = alice_key.verifying_key().to_bytes();
    for proof in arr(&body, "proofs") {
        let signed: SignedDoc = serde_json::from_value(proof.clone()).unwrap();
        pubky_switch_core::chain::TransitionProof::verify(&signed, &key, &alice).unwrap();
    }

    // The stored hand-over the phone fetches verifies for the phone.
    let stored = response_named(&v, "own app: the hand-over the switch stores");
    let body: Value = serde_json::from_str(st(stored, "body")).unwrap();
    let handover: SignerHandover = serde_json::from_value(body["handover"].clone()).unwrap();
    let phone = app_id_decode(&keys.apps["phone"].1.app_id()).unwrap();
    handover.verify(&alice, &phone).unwrap();
}

#[test]
fn test_vectors_next_service_fetches_only_from_the_transfers_old_service() {
    let keys = keys();
    let v = load("http.json");
    let fetch = arr(&v, "requests")
        .iter()
        .find(|r| header_of(r, header::TRANSFER).is_some())
        .unwrap();
    let alice = keys.identity("alice").public();
    let new = |origin: &str, account: [u8; 32]| {
        SwitchClient::new(
            origin,
            account,
            credentials(&keys, fetch),
            None,
            Arc::new(MockTransport::new()),
            Arc::new(TestClock::new(0)),
        )
    };
    assert!(new(st(fetch, "origin"), alice).is_ok());
    assert!(matches!(
        new("https://elsewhere.example", alice),
        Err(ClientError::Usage(_))
    ));
    assert!(matches!(
        new(st(fetch, "origin"), keys.identity("bob").public()),
        Err(ClientError::Usage(_))
    ));
}
