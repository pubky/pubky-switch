//! The signer's cases of the Switch vector set (`spec/vectors/`), through its public API.

// The helpers outside `#[test]` functions read fixed vector files, where a failure is a test
// failure: the workspace's no-panic lints don't apply to them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::{Arc, Mutex};

use common::{TestHomeserver, Vault};
use pubky_switch_client::clock::TestClock;
use pubky_switch_client::store::{MemoryStore, StoreHandle};
use pubky_switch_client::testing::{Fault, ScriptedSwitch};
use pubky_switch_client::transport::MockTransport;
use pubky_switch_core::enc::{b64, unb64};
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::ops::OpKind;
use pubky_switch_core::records::{AppCert, IdentityDoc, SIGNER_BACKUP_PATH, SignerBackup};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_signer::state::signer_namespace;
use pubky_switch_signer::{
    GrantPath, IdentityKeyring, IdentitySecret, Protocol, Protocols, ReceivingApp, Refusal,
    ScopeDef, Signer, SignerEnv, SignerError, SignerStatus, UserConfirmed,
};
use serde_json::Value;

/// The vectors' start time, `2026-01-01T00:00:00.000Z` (vectors README, "Times").
const VECTOR_START_MS: u64 = 1_767_225_600_000;

fn load(name: &str) -> Value {
    let path = format!("{}/../../spec/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn text<'a>(value: &'a Value, member: &str) -> &'a str {
    value[member]
        .as_str()
        .unwrap_or_else(|| panic!("{member} isn't a string"))
}

fn hex32(text: &str) -> [u8; 32] {
    hex::decode(text).unwrap().try_into().unwrap()
}

fn named<'a>(list: &'a Value, name: &str) -> &'a Value {
    list.as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("no {name}"))
}

/// A signed document of `documents.json`.
fn document(name: &str) -> SignedDoc {
    serde_json::from_value(named(&load("documents.json")["documents"], name)["signed"].clone())
        .unwrap()
}

/// The body's bytes of a request or answer of `http.json`.
fn http_body(list: &str, name: &str) -> Vec<u8> {
    let entry = named(&load("http.json")[list], name).clone();
    match (entry.get("body_b64"), entry.get("body")) {
        (Some(Value::String(b)), _) => unb64(b).unwrap(),
        (_, Some(Value::String(b))) => b.as_bytes().to_vec(),
        _ => panic!("{name} has no body"),
    }
}

/// The vectors' protocol, as the files give it: its name, the one member of the wallet app
/// record's `protocols`, and its scope roots, the names of every scope the vector certificates
/// hold.
fn vector_protocol() -> (String, Vec<String>) {
    let documents = load("documents.json");
    let documents = documents["documents"].as_array().unwrap();
    let body = |name: &str| -> Vec<Value> {
        documents
            .iter()
            .filter(|d| text(d, "name").contains(name))
            .map(|d| serde_json::from_str(text(d, "body")).unwrap())
            .collect()
    };
    let record = body("wallet app record").remove(0);
    let protocols = record["protocols"].as_object().unwrap();
    assert_eq!(
        protocols.len(),
        1,
        "the vectors' apps belong to one protocol"
    );
    let name = protocols.keys().next().unwrap().clone();
    let mut roots: Vec<String> = body("certificate")
        .iter()
        .flat_map(|cert| cert["scopes"].as_array().unwrap().clone())
        .map(|scope| {
            let scope = scope.as_str().unwrap();
            scope
                .split_once(':')
                .map_or(scope, |(root, _)| root)
                .to_owned()
        })
        .collect();
    roots.sort();
    roots.dedup();
    (name, roots)
}

/// The protocol of the vectors' apps, with the name and scope roots the files give it
/// (`vector_protocol`); keyed are the scopes the vectors give keys for (scope keys, sub-scope keys,
/// the key bundles' keys and the reduction's removed scope). Read from the spec's files, so
/// the test names no protocol of its own.
struct VectorScopes {
    name: String,
    roots: Vec<String>,
    keyed: Vec<String>,
}

impl VectorScopes {
    fn new() -> Self {
        let (name, roots) = vector_protocol();
        let keys = load("keys.json");
        let envelopes = load("envelopes.json");
        let mut keyed: Vec<String> = keys["scope_keys"]
            .as_array()
            .unwrap()
            .iter()
            .chain(keys["sub_scope_keys"]["keys"].as_array().unwrap())
            .map(|k| text(k, "scope").to_owned())
            .collect();
        for member in ["key_bundle", "reduction_key_bundle"] {
            let plaintext: Value =
                serde_json::from_str(text(&envelopes[member], "plaintext_json")).unwrap();
            for key in plaintext["keys"].as_array().unwrap() {
                keyed.push(text(key, "scope").to_owned());
            }
        }
        keyed.push(text(&envelopes["reduction_key_bundle"], "removed_scope").to_owned());
        Self { name, roots, keyed }
    }
}

impl Protocol for VectorScopes {
    fn name(&self) -> &str {
        &self.name
    }
    fn scopes(&self) -> Vec<ScopeDef> {
        self.roots
            .iter()
            .map(|root| {
                if self.keyed.contains(root) {
                    ScopeDef::keyed(root)
                } else {
                    ScopeDef::unkeyed(root)
                }
            })
            .collect()
    }
    fn check_scopes(&self, _: &[&str]) -> Result<(), String> {
        Ok(())
    }
    fn permissions(&self, _: &[&str]) -> Vec<Permission> {
        Vec::new()
    }
    fn grant_paths(&self, _: &[u8; 16], _: &[&str]) -> Vec<GrantPath> {
        Vec::new()
    }
}

/// alice's account as the vectors have it: her switch at `inbox.example` under `keys.json`'s
/// service key, holding the versions given, and her Homeserver.
struct Alice {
    key: IdentityKey,
    switch: Arc<ScriptedSwitch>,
    transport: Arc<MockTransport>,
    homeserver: Arc<TestHomeserver>,
    clock: Arc<TestClock>,
}

impl Alice {
    fn new(versions: &[&str]) -> Self {
        let keys = load("keys.json");
        let identity = named(&keys["identities"], "alice");
        let key = IdentityKey::from_secret(hex32(text(identity, "secret_hex")));
        let service = keys["service_keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["account"] == text(identity, "pubky_id"))
            .unwrap()
            .clone();
        let clock = Arc::new(TestClock::new(VECTOR_START_MS));
        let switch = ScriptedSwitch::new(
            &key,
            hex32(text(&service, "secret_hex")),
            Arc::clone(&clock),
        );
        for name in versions {
            let doc = IdentityDoc::verify(&document(name), &key.public()).unwrap();
            switch.deliver_identity(&doc).unwrap();
        }
        // The phone registered with its record: a switch serves a hand-over only to a current
        // app (Switch wire 7.2, 7.4.17).
        if !versions.is_empty() {
            let phone = named(&keys["apps"], "phone");
            let phone = AppKeys::from_secrets(
                hex32(text(phone, "signing_secret_hex")),
                hex32(text(phone, "bundle_secret_hex")),
            );
            switch
                .app_op(
                    &phone,
                    OpKind::AppPut {
                        record: document("phone app record"),
                    },
                )
                .unwrap();
        }
        Self {
            transport: switch.transport(),
            switch,
            homeserver: Arc::new(TestHomeserver::default()),
            clock,
            key,
        }
    }

    fn env(&self, store: Arc<MemoryStore>) -> SignerEnv {
        SignerEnv {
            store: StoreHandle::inline(store),
            clock: self.clock.clone(),
            transport: self.transport.clone(),
            homeserver: self.homeserver.clone(),
            protocols: Protocols::new(vec![Arc::new(VectorScopes::new())]).unwrap(),
        }
    }

    /// A vault holding alice's secret.
    fn vault(&self) -> Arc<Vault> {
        Arc::new(Vault(Mutex::new(Some(self.key.secret_bytes()))))
    }

    /// The phone, `envelopes.json` `signer_handover`'s new signer.
    fn phone(&self) -> ReceivingApp {
        let keys = load("keys.json");
        let app = named(&keys["apps"], "phone");
        let cert = AppCert::verify(&document("phone certificate"), &self.key.public()).unwrap();
        let v3 = IdentityDoc::verify(&document("alice identity.json"), &self.key.public()).unwrap();
        ReceivingApp {
            keys: AppKeys::from_secrets(
                hex32(text(app, "signing_secret_hex")),
                hex32(text(app, "bundle_secret_hex")),
            ),
            cert,
            origin: v3.inbox().url.clone(),
            service_key: v3.inbox().service_key,
        }
    }
}

fn empty_vault() -> Arc<Vault> {
    Arc::new(Vault(Mutex::new(None)))
}

/// `keys.json` identities (Switch wire 1.3, 1.5, 3.13): a vault holding the fixed secret gives
/// the identity's public key, its Pubky ID, and the backup key the signer's backup is sealed
/// to, with its kid.
#[test]
fn test_vectors_keys_identities_through_the_vault() {
    let v = load("keys.json");
    let identities = v["identities"].as_array().expect("identities");
    assert!(!identities.is_empty());
    for identity in identities {
        let secret =
            IdentitySecret::from_slice(&hex::decode(text(identity, "secret_hex")).unwrap())
                .unwrap();
        let vault = Arc::new(Vault(Mutex::new(Some(*secret.as_bytes()))));
        let keyring = IdentityKeyring::open(vault).unwrap();
        let name = text(identity, "name");
        assert_eq!(
            hex::encode(keyring.public_key()),
            text(identity, "public_hex"),
            "{name}"
        );
        assert_eq!(keyring.pubky_id(), text(identity, "pubky_id"), "{name}");
        let (backup_public, backup_kid) = keyring.backup_public().unwrap();
        assert_eq!(
            b64(&backup_public),
            text(identity, "backup_public"),
            "{name}"
        );
        assert_eq!(b64(&backup_kid), text(identity, "backup_kid"), "{name}");
    }
}

/// The records `envelopes.json` `signer_handover` seals, as JSON bytes, with `doc` in place of
/// version 3 and, for a backup, `prev`: the records a signer holding `doc` seals, when it holds
/// the vector's other records (Switch wire 3.12, 3.13).
fn vector_records(doc: &SignedDoc, prev: Option<[u8; 32]>) -> Vec<u8> {
    let plaintext = text(&load("envelopes.json")["signer_handover"], "plaintext_json").to_owned();
    let v3 = document("alice identity.json");
    let mut records = plaintext
        .replace(&v3.body, &doc.body)
        .replace(&v3.sig, &doc.sig);
    if let Some(prev) = prev {
        assert_eq!(records.pop(), Some('}'));
        records.push_str(&format!(",\"prev\":\"{}\"}}", b64(&prev)));
    }
    records.into_bytes()
}

/// The decoded `identity.json` body of an `identity.json` delivery, and its `prev`.
fn delivery(body: &[u8]) -> (Vec<u8>, Option<[u8; 32]>) {
    let value: Value = serde_json::from_slice(body).unwrap();
    let doc: SignedDoc = serde_json::from_value(value["identity"].clone()).unwrap();
    let prev = value["prev"]
        .as_str()
        .map(|p| unb64(p).unwrap().try_into().unwrap());
    (unb64(&doc.body).unwrap(), prev)
}

/// The signer ID a document body names.
fn signer_of(body: &[u8]) -> [u8; 16] {
    let value: Value = serde_json::from_slice(body).unwrap();
    unb64(text(&value, "signer")).unwrap().try_into().unwrap()
}

/// `body`, a document body, with its signer ID `from` replaced by `to`.
fn with_signer(body: &[u8], from: [u8; 16], to: [u8; 16]) -> Vec<u8> {
    let from = format!("\"signer\":\"{}\"", b64(&from));
    let to = format!("\"signer\":\"{}\"", b64(&to));
    let text = std::str::from_utf8(body).unwrap();
    assert_eq!(text.matches(&from).count(), 1);
    text.replace(&from, &to).into_bytes()
}

impl Alice {
    /// The `identity.json` deliveries sent, in order: each body decoded, with its `prev`.
    fn deliveries(&self) -> Vec<(Vec<u8>, Option<[u8; 32]>)> {
        self.transport
            .requests()
            .into_iter()
            .filter(|r| r.method == "PUT" && r.path_and_query.ends_with("/identity"))
            .map(|r| delivery(&r.body))
            .collect()
    }

    /// The backup on the Homeserver, opened, as JSON bytes.
    fn backup_records(&self) -> Vec<u8> {
        let bytes = self.homeserver.file(SIGNER_BACKUP_PATH).expect("a backup");
        let backup: SignerBackup = serde_json::from_slice(&bytes).unwrap();
        backup.open(&self.key).unwrap().to_json().unwrap().to_vec()
    }

    fn doc(&self, name: &str) -> IdentityDoc {
        IdentityDoc::verify(&document(name), &self.key.public()).unwrap()
    }

    /// Have the switch hold `envelopes.json` `signer_handover`, or `handover` in its place,
    /// for the phone, as its signer stored it (`http.json`).
    fn store_handover(&self, handover: Option<&Value>) {
        let mut body: Value =
            serde_json::from_slice(&http_body("requests", STORE_HANDOVER)).unwrap();
        if let Some(handover) = handover {
            body["handover"] = handover.clone();
        }
        let phone = self.phone().cert.app_id();
        self.switch.store_handover_again((phone, body));
    }
}

const V1: &str = "alice identity.json, first delivery (version 1)";
const V3: &str = "alice identity.json";
const ABORT: &str = "alice identity.json, hand-over abort (version 5)";
const STORE_HANDOVER: &str = "signer: store the hand-over to the phone at the switch";
const TAKE_OVER: &str = "signer: hand-over delivery after an abort won";

/// The expected records the tests build: `signer_handover`'s with version 3 and version 1's
/// hash as `prev` are `signer_backup`'s, as the vectors README says (Switch wire 3.13).
#[test]
fn test_vectors_backup_records_are_the_handovers_with_prev() {
    let alice = hex32(text(
        named(&load("keys.json")["identities"], "alice"),
        "public_hex",
    ));
    let v1 = IdentityDoc::verify(&document(V1), &alice).unwrap();
    let expected = vector_records(&document(V3), Some(v1.hash()));
    assert_eq!(
        expected,
        text(&load("envelopes.json")["signer_backup"], "plaintext_json").as_bytes()
    );
}

/// `envelopes.json` `signer_handover` and `http.json`'s take-over delivery (Switch wire 3.12,
/// 3.3): the phone opens alice's hand-over, delivers version 4 built on version 3, the body of
/// `http.json`'s delivery but for its own signer ID, and once that has won, holds the identity
/// secret and backs up the vector's records with version 4.
#[tokio::test]
async fn test_vectors_new_signer_takes_over_from_the_vectors_handover() {
    let alice = Alice::new(&[V1, V3]);
    alice.store_handover(None);
    let vault = empty_vault();
    let store = Arc::new(MemoryStore::new());
    let signer = Signer::receive_hand_over(alice.env(store), &alice.phone(), vault.clone())
        .await
        .unwrap();
    let install = signer.install_id();
    assert_eq!(signer.status(), SignerStatus::Signing);

    let (vector_body, vector_prev) = delivery(&http_body("requests", TAKE_OVER));
    let vector_install = signer_of(&vector_body);
    let deliveries = alice.deliveries();
    assert_eq!(deliveries.len(), 1, "one delivery");
    let (body, prev) = &deliveries[0];
    assert_eq!(*prev, Some(alice.doc(V3).hash()));
    assert_eq!(*prev, vector_prev);
    assert_eq!(
        *body,
        with_signer(&vector_body, vector_install, install),
        "http.json's version 4 but for the signer ID"
    );

    let v4 = signer.identity_doc().unwrap().unwrap();
    assert_eq!(v4.version(), 4);
    assert_eq!(*vault.0.lock().unwrap(), Some(alice.key.secret_bytes()));
    assert_eq!(
        alice.backup_records(),
        vector_records(v4.signed(), Some(alice.doc(V3).hash())),
        "the vector's records, with version 4 built on version 3"
    );
}

/// `envelopes.json` `signer_handover_rejections` (Switch wire 3.12 check 1): the phone refuses
/// each hand-over at its signature, before it keeps or sends anything. The switch serves each
/// as a faulty switch could: an honest one would have refused to store it (Switch wire
/// 7.4.17).
#[tokio::test]
async fn test_vectors_new_signer_refuses_the_vectors_rejections() {
    let rejections = load("envelopes.json")["signer_handover_rejections"]["cases"].clone();
    let cases = rejections.as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let name = text(case, "name");
        let alice = Alice::new(&[V1, V3]);
        alice.store_handover(Some(&case["handover"]));
        let vault = empty_vault();
        let store = Arc::new(MemoryStore::new());
        let error =
            Signer::receive_hand_over(alice.env(store.clone()), &alice.phone(), vault.clone())
                .await
                .unwrap_err();
        let SignerError::InvalidData(core) = &error else {
            panic!("{name}: {error:?}");
        };
        assert!(core.to_string().contains("check 1"), "{name}: {core}");
        assert!(alice.deliveries().is_empty(), "{name}: nothing sent");
        assert!(vault.0.lock().unwrap().is_none(), "{name}");
        let identity = alice.key.public();
        let ns = signer_namespace(&identity);
        assert!(
            StoreHandle::inline(store)
                .get(&ns, b"state")
                .await
                .unwrap()
                .is_none(),
            "{name}: nothing kept"
        );
    }
}

/// `http.json`'s take-over delivery after an abort won, and its `409 stale_identity` (Switch
/// wire 3.12, 7.4.2): the phone's version 4 couldn't reach the switch before alice's abort,
/// `documents.json`'s version 5, won. Sent again, the same bytes, it is answered with that
/// abort as `current`, which names another install: the take-over is cancelled, and nothing
/// it received is kept.
#[tokio::test]
async fn test_vectors_take_over_answered_with_the_vectors_abort_is_cancelled() {
    let alice = Alice::new(&[V1, V3]);
    alice.store_handover(None);
    let vault = empty_vault();
    let store = Arc::new(MemoryStore::new());
    alice.switch.fail_next(Fault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    Signer::receive_hand_over(alice.env(store.clone()), &alice.phone(), vault.clone())
        .await
        .unwrap_err();
    alice.switch.deliver_identity(&alice.doc(ABORT)).unwrap();
    let phone = alice.phone();
    let lost = Signer::resume_take_over(
        alice.env(store.clone()),
        alice.key.public(),
        &phone.keys,
        vault.clone(),
    )
    .await
    .unwrap_err();
    assert_eq!(lost, SignerError::Refused(Refusal::TakeOverCancelled));
    assert!(vault.0.lock().unwrap().is_none());
    let identity = alice.key.public();
    assert!(
        StoreHandle::inline(store)
            .get(&signer_namespace(&identity), b"state")
            .await
            .unwrap()
            .is_none()
    );

    // The same bytes both times; the switch's answer to them is the vector's.
    let puts: Vec<_> = alice
        .transport
        .requests()
        .into_iter()
        .filter(|r| r.method == "PUT" && r.path_and_query.ends_with("/identity"))
        .collect();
    assert_eq!(puts.len(), 2);
    assert_eq!(puts[0].body, puts[1].body);
    let answer = alice.switch.handle(&puts[1]).unwrap();
    assert_eq!(answer.status, 409);
    let answer: Value = serde_json::from_slice(&answer.body).unwrap();
    let vector: Value = serde_json::from_slice(&http_body(
        "responses",
        "signer: 409 stale_identity to a hand-over delivery after an abort won",
    ))
    .unwrap();
    assert_eq!(answer["code"], vector["code"]);
    assert_eq!(answer["current"], vector["current"]);
}

/// `envelopes.json` `signer_backup` (Switch wire 3.13 "Restoring"): a new install restores
/// alice from her backup. With the switch at version 3 it delivers its own version 4 next,
/// built on version 3; with the switch at version 1, the backup's version 3 goes first, its
/// bytes, then version 4. Either way its backup then holds the vector's records with version
/// 4. A switch at the abort, past the backup, refuses the restore before anything is sent.
#[tokio::test]
async fn test_vectors_restore_from_the_vectors_backup() {
    for (versions, first) in [(&[V1, V3][..], false), (&[V1][..], true)] {
        let alice = Alice::new(versions);
        let backup = load("envelopes.json")["signer_backup"].clone();
        alice.homeserver.set(
            text(&backup, "path"),
            serde_json::to_vec(&backup["backup"]).unwrap(),
        );
        let signer = Signer::restore_new(
            alice.env(Arc::new(MemoryStore::new())),
            IdentityKeyring::open(alice.vault()).unwrap(),
            UserConfirmed::shown_and_confirmed(),
        )
        .await
        .unwrap();
        let v3 = alice.doc(V3);
        let v4 = signer.identity_doc().unwrap().unwrap();
        let mut expected = Vec::new();
        if first {
            expected.push((
                unb64(&v3.signed().body).unwrap(),
                Some(alice.doc(V1).hash()),
            ));
        }
        // Version 4 built on version 3 is `http.json`'s take-over delivery but for the signer
        // ID: this install's.
        let (take_over, _) = delivery(&http_body("requests", TAKE_OVER));
        expected.push((
            with_signer(&take_over, signer_of(&take_over), signer.install_id()),
            Some(v3.hash()),
        ));
        assert_eq!(alice.deliveries(), expected, "first: {first}");
        assert_eq!(v4.version(), 4);
        assert_eq!(
            alice.backup_records(),
            vector_records(v4.signed(), Some(v3.hash())),
            "first: {first}"
        );
    }

    let alice = Alice::new(&[V1, V3, ABORT]);
    let backup = load("envelopes.json")["signer_backup"].clone();
    alice.homeserver.set(
        text(&backup, "path"),
        serde_json::to_vec(&backup["backup"]).unwrap(),
    );
    let refused = Signer::restore_new(
        alice.env(Arc::new(MemoryStore::new())),
        IdentityKeyring::open(alice.vault()).unwrap(),
        UserConfirmed::shown_and_confirmed(),
    )
    .await
    .unwrap_err();
    assert_eq!(refused, SignerError::Refused(Refusal::StaleBackup));
    assert!(alice.deliveries().is_empty());
}
