//! The old signer's cases of the Switch vector set (`spec/vectors/`): the hand-over to the
//! phone (`envelopes.json` `signer_handover`), the abort and the version after it, and the
//! wallet's renewal (`documents.json`, `envelopes.json` `reduction_key_bundle`), and the
//! account's erasure (`http.json`).
//!
//! Those vectors are alice's signer at her version 3, under the signer ID her documents name.
//! A signer draws its own ID at random, so this module, alone, writes that signer's records
//! into the store, taken from the records the vector's hand-over seals; every step after that
//! goes through the public API. The new signer's and the restore's cases, which need no such
//! set-up, are in `tests/vectors.rs`.

// Test code reading fixed vector files: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use pubky_switch_client::TransportError;
use pubky_switch_client::clock::TestClock;
use pubky_switch_client::store::{MemoryStore, StoreHandle};
use pubky_switch_client::testing::{Fault, ScriptedSwitch};
use pubky_switch_client::transport::{BoxFuture, Header, MockTransport, Response};
use pubky_switch_core::enc::{app_id_decode, unb64, unb64_array};
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::ops::OpKind;
use pubky_switch_core::records::{
    AppCert, IDENTITY_PATH, IdentityDoc, Limits, RenewedCert, SIGNER_BACKUP_PATH, SignerBackup,
    SignerHandover, StoredPart,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use serde_json::Value;

use super::{AbortOutcome, CertChange, Signer, SignerEnv, UserConfirmed};
use crate::alert::Alert;
use crate::error::{Refusal, SignerError, SizedBody};
use crate::homeserver::Homeserver;
use crate::key::{AddOutcome, IdentityKeyring, IdentitySecret, SecretVault, VaultError};
use crate::protocol::{Protocol, Protocols, ScopeDef};
use crate::state::{self, Newest, Service, SignerState};

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

fn document(name: &str) -> SignedDoc {
    serde_json::from_value(named(&load("documents.json")["documents"], name)["signed"].clone())
        .unwrap()
}

/// The vectors' protocol, read from the spec's files so the tests name none: its name and
/// roots as the files give them (`vector_protocol`); keyed are the scopes the vectors give keys for (scope
/// keys, sub-scope keys, the key bundles' keys and the reduction's removed scope); and the
/// switch permissions of a set of scopes are those of the vector certificate with exactly those
/// scopes.
struct VectorScopes {
    name: String,
    roots: Vec<String>,
    keyed: Vec<String>,
    permissions: Vec<(Vec<String>, Vec<Permission>)>,
}

impl VectorScopes {
    fn new() -> Self {
        let (name, roots) = super::vector_protocol::vector_protocol(&load("documents.json"));
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
        let permissions = load("documents.json")["documents"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|d| text(d, "name").contains("certificate"))
            .map(|d| {
                let body: Value = serde_json::from_str(text(d, "body")).unwrap();
                (
                    serde_json::from_value(body["scopes"].clone()).unwrap(),
                    body["permissions"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|p| Permission::from_name(p.as_str().unwrap()).unwrap())
                        .collect(),
                )
            })
            .collect();
        Self {
            name,
            roots,
            keyed,
            permissions,
        }
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
    fn permissions(&self, scopes: &[&str]) -> Vec<Permission> {
        self.permissions
            .iter()
            .find(|(of, _)| of.iter().map(String::as_str).eq(scopes.iter().copied()))
            .map(|(_, permissions)| permissions.clone())
            .unwrap_or_default()
    }
}

struct Vault(Mutex<Option<[u8; 32]>>);

impl SecretVault for Vault {
    fn load(&self) -> Result<Option<IdentitySecret>, VaultError> {
        Ok(self.0.lock().unwrap().map(IdentitySecret::from_bytes))
    }
    fn add(&self, secret: &IdentitySecret) -> Result<AddOutcome, VaultError> {
        let mut held = self.0.lock().unwrap();
        if held.is_some() {
            return Ok(AddOutcome::Occupied);
        }
        *held = Some(*secret.as_bytes());
        Ok(AddOutcome::Stored)
    }
    fn delete(&self) -> Result<(), VaultError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

#[derive(Default)]
struct Files(Mutex<HashMap<String, Vec<u8>>>);

impl Homeserver for Files {
    fn get(&self, path: &str) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        let found = self.0.lock().unwrap().get(path).cloned();
        Box::pin(async move { Ok(found) })
    }
    fn put(&self, path: &str, bytes: Vec<u8>) -> BoxFuture<'_, Result<(), TransportError>> {
        self.0.lock().unwrap().insert(path.to_owned(), bytes);
        Box::pin(async { Ok(()) })
    }
    fn delete(&self, path: &str) -> BoxFuture<'_, Result<(), TransportError>> {
        self.0.lock().unwrap().remove(path);
        Box::pin(async { Ok(()) })
    }
}

/// alice's old signer as the vectors have it: at her version 3, built on version 1, under
/// the signer ID her documents name, with her switch holding both versions, and her
/// Homeserver publishing version 3 beside the vector backup.
struct OldSigner {
    key: IdentityKey,
    signer: Signer,
    switch: Arc<ScriptedSwitch>,
    transport: Arc<MockTransport>,
    homeserver: Arc<Files>,
    clock: Arc<TestClock>,
    phone: [u8; 16],
    /// `signer_handover`'s plaintext, the records the old signer holds at version 3.
    plaintext: Vec<u8>,
}

async fn old_signer() -> OldSigner {
    old_signer_answering(None).await
}

/// [`old_signer`], whose switch gives `erasure` as its answer to `POST /erase`, when given.
async fn old_signer_answering(erasure: Option<Response>) -> OldSigner {
    let keys = load("keys.json");
    let identity = named(&keys["identities"], "alice");
    let key = IdentityKey::from_secret(hex32(text(identity, "secret_hex")));
    let alice = key.public();
    let service = keys["service_keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["account"] == text(identity, "pubky_id"))
        .unwrap()
        .clone();
    let clock = Arc::new(TestClock::new(VECTOR_START_MS));
    let switch = ScriptedSwitch::new(&key, hex32(text(&service, "secret_hex")), clock.clone());
    let v1 = IdentityDoc::verify(
        &document("alice identity.json, first delivery (version 1)"),
        &alice,
    )
    .unwrap();
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &alice).unwrap();
    switch.deliver_identity(&v1).unwrap();
    switch.deliver_identity(&v3).unwrap();
    // The phone and the wallet registered with their records: the hand-over's target, and
    // the app renewed, must have.
    for app in ["phone", "wallet"] {
        switch
            .app_op(
                &app_keys(&keys, app),
                OpKind::AppPut {
                    record: document(&format!("{app} app record")),
                },
            )
            .unwrap();
    }
    let envelopes = load("envelopes.json");
    let handover = &envelopes["signer_handover"];
    let plaintext = text(handover, "plaintext_json").as_bytes().to_vec();
    let records: Value = serde_json::from_slice(&plaintext).unwrap();
    let homeserver = Arc::new(Files::default());
    homeserver
        .put(IDENTITY_PATH, serde_json::to_vec(v3.signed()).unwrap())
        .await
        .unwrap();
    homeserver
        .put(
            SIGNER_BACKUP_PATH,
            serde_json::to_vec(&envelopes["signer_backup"]["backup"]).unwrap(),
        )
        .await
        .unwrap();

    // The records of the signer that signed version 3, as its sealed records list them.
    let mut state = SignerState::new(alice, v3.body().signer);
    state.service = Some(Service {
        origin: v3.inbox().url.clone(),
        service_key: v3.inbox().service_key,
        limits: serde_json::from_value::<Limits>(records["limits"].clone()).unwrap(),
    });
    state.newest = Some(Newest {
        doc: v3.signed().clone(),
        prev: Some(v1.hash()),
        published: true,
        delivered_at: Some(VECTOR_START_MS),
    });
    state.signed_through = v3.version();
    state.tombstones = records["revoked_apps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| app_id_decode(id.as_str().unwrap()).unwrap())
        .collect();
    state.certs = serde_json::from_value(records["certs"].clone()).unwrap();
    state.bundle_parts =
        serde_json::from_value::<Vec<StoredPart>>(records["bundle_parts"].clone()).unwrap();
    state.listed_at = v3.body().apps.iter().map(|a| (a.app_id, 0)).collect();
    state.epoch_through = v3.data_epoch();

    let store = Arc::new(MemoryStore::new());
    let transport = match erasure {
        None => switch.transport(),
        Some(answer) => {
            let scripted = Arc::clone(&switch);
            Arc::new(MockTransport::with_handler(move |request| {
                if request.method == "POST" && request.path_and_query.ends_with("/erase") {
                    Ok(answer.clone())
                } else {
                    scripted.handle(request)
                }
            }))
        }
    };
    let env = SignerEnv {
        store: StoreHandle::inline(store),
        clock: clock.clone(),
        transport: transport.clone(),
        homeserver: homeserver.clone(),
        protocols: Protocols::new(vec![Arc::new(VectorScopes::new())]).unwrap(),
    };
    state::save(&env.store, &state, None).await.unwrap();
    let vault = Arc::new(Vault(Mutex::new(Some(key.secret_bytes()))));
    let mut signer = Signer::open(env, IdentityKeyring::open(vault).unwrap())
        .await
        .unwrap();
    signer.resume().await.unwrap();
    assert!(signer.alerts().is_empty(), "{:?}", signer.alerts());
    let phone = app_id_decode(text(handover, "app_id")).unwrap();
    OldSigner {
        key,
        signer,
        switch,
        transport,
        homeserver,
        clock: Arc::clone(&clock),
        phone,
        plaintext,
    }
}

/// The signing and bundle keys of `keys.json`'s app `name`.
fn app_keys(keys: &Value, name: &str) -> AppKeys {
    let app = named(&keys["apps"], name);
    AppKeys::from_secrets(
        hex32(text(app, "signing_secret_hex")),
        hex32(text(app, "bundle_secret_hex")),
    )
}

/// `signer_handover`'s records with `doc` in place of version 3, and `prev`, as a backup's
/// plaintext in JSON bytes: its own `kind` and no `identity_secret` (Switch wire 3.13).
fn records_with(plaintext: &[u8], doc: &SignedDoc, prev: [u8; 32]) -> Vec<u8> {
    let v3 = document("alice identity.json");
    let handover: Value = serde_json::from_slice(plaintext).unwrap();
    let secret = format!(
        ",\"identity_secret\":\"{}\"",
        text(&handover, "identity_secret")
    );
    let mut records = std::str::from_utf8(plaintext)
        .unwrap()
        .replace(
            "\"kind\":\"pubky-switch.signer_handover\"",
            "\"kind\":\"pubky-switch.signer_backup\"",
        )
        .replace(&secret, "")
        .replace(&v3.body, &doc.body)
        .replace(&v3.sig, &doc.sig);
    assert_eq!(records.pop(), Some('}'));
    records.push_str(&format!(
        ",\"prev\":\"{}\"}}",
        pubky_switch_core::enc::b64(&prev)
    ));
    records.into_bytes()
}

/// `envelopes.json` `signer_handover` (Switch wire 3.12): the hand-over alice's signer stores
/// for her phone holds exactly the vector's records, and opens only with the phone's bundle
/// secret; its `PUT /handover` body has `http.json`'s members.
#[tokio::test]
async fn test_vectors_old_signer_hands_over_the_vectors_records() {
    let mut old = old_signer().await;
    old.signer
        .hand_over_to(old.phone, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    let (target, body) = old.switch.stored_handover_body().unwrap();
    assert_eq!(target, old.phone);
    let http = load("http.json");
    let request = named(
        &http["requests"],
        "signer: store the hand-over to the phone at the switch",
    );
    let vector: Value = serde_json::from_slice(&unb64(text(request, "body_b64")).unwrap()).unwrap();
    let members = |v: &Value| -> Vec<String> { v.as_object().unwrap().keys().cloned().collect() };
    assert_eq!(members(&body), members(&vector));
    assert_eq!(body["app_id"], vector["app_id"]);
    let handover: SignerHandover = serde_json::from_value(body["handover"].clone()).unwrap();
    let keys = load("keys.json");
    let phone = named(&keys["apps"], "phone");
    let records = handover
        .open(
            &old.key.public(),
            &old.phone,
            &hex32(text(phone, "bundle_secret_hex")),
        )
        .unwrap();
    assert!(
        *records.to_json().unwrap() == *old.plaintext,
        "the records the vector hands over"
    );
    let wallet = named(&keys["apps"], "wallet");
    assert!(
        handover
            .open(
                &old.key.public(),
                &app_id_decode(text(wallet, "app_id")).unwrap(),
                &hex32(text(wallet, "bundle_secret_hex")),
            )
            .is_err()
    );
}

/// `documents.json`'s hand-over abort (Switch wire 3.12): the abort alice's signer delivers is
/// the vector's version 5, byte for byte, built on version 3; once it has won, the backup
/// holds it, and alice's signer signs again: its next change is `documents.json`'s version 6
/// with a 30-day record age limit, byte for byte.
#[tokio::test]
async fn test_vectors_old_signer_abort_is_the_vectors_version_5() {
    let mut old = old_signer().await;
    old.signer
        .hand_over_to(old.phone, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    let outcome = old
        .signer
        .abort_hand_over(UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    let AbortOutcome::Aborted { .. } = outcome else {
        panic!("the abort wins: {outcome:?}");
    };
    let abort = document("alice identity.json, hand-over abort (version 5)");
    let held = old.switch.identity_doc().unwrap();
    assert_eq!(held.signed(), &abort, "the vector's abort");
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &old.key.public()).unwrap();
    let delivery = old
        .transport
        .requests()
        .into_iter()
        .rfind(|r| r.method == "PUT" && r.path_and_query.ends_with("/identity"))
        .unwrap();
    let body: Value = serde_json::from_slice(&delivery.body).unwrap();
    assert_eq!(
        unb64_array::<32>(body["prev"].as_str().unwrap()).unwrap(),
        v3.hash(),
        "built on version 3"
    );
    assert_eq!(old.signer.identity_doc().unwrap().unwrap().signed(), &abort);
    let backup: SignerBackup =
        serde_json::from_slice(&old.homeserver.0.lock().unwrap()[SIGNER_BACKUP_PATH]).unwrap();
    assert_eq!(
        *backup.open(&old.key).unwrap().to_backup_json().unwrap(),
        *records_with(&old.plaintext, &abort, v3.hash()),
        "the vector's records, with the abort built on version 3"
    );
    let six = old
        .signer
        .set_record_max_age(Some(2_592_000))
        .await
        .unwrap();
    assert_eq!(
        six.signed(),
        &document("alice identity.json, record age limit (version 6)")
    );
}

/// `documents.json`'s wallet renewal (Switch spec 3.2; Switch wire 3.8 Reductions): alice's
/// signer renews the wallet without `tasks_people_admin`, a scope with keys, and expiring earlier,
/// at 00:02. The switch takes the renewing version at 00:03. The renewed certificate, the
/// renewing version 4 at data epoch 3, and the closing version 5 with `until` 00:08 are the
/// vectors' byte for byte, and the full bundle stored for the wallet holds the keys of
/// `reduction_key_bundle`.
#[tokio::test]
async fn test_vectors_old_signer_renews_the_wallet_as_the_vectors_do() {
    let mut old = old_signer().await;
    let keys = load("keys.json");
    let wallet = app_keys(&keys, "wallet");
    let wallet_id = wallet.app_id_bytes();
    let renewed =
        AppCert::verify(&document("wallet certificate, renewed"), &old.key.public()).unwrap();
    const MINUTE_MS: u64 = 60_000;
    old.clock.set_ms(VECTOR_START_MS + 2 * MINUTE_MS);
    old.switch.fail_next(Fault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    let change = CertChange {
        scopes: Some(renewed.scopes().to_vec()),
        expires_at: Some(renewed.expires_at()),
    };
    old.signer.renew(wallet_id, change).await.unwrap_err();
    old.clock.set_ms(VECTOR_START_MS + 3 * MINUTE_MS);
    old.signer.resume().await.unwrap();

    assert!(
        old.signer
            .certificates()
            .unwrap()
            .iter()
            .any(|c| c.signed() == renewed.signed()),
        "the renewed certificate"
    );
    let delivered: Vec<SignedDoc> = old
        .transport
        .requests()
        .into_iter()
        .filter(|r| r.method == "PUT" && r.path_and_query.ends_with("/identity"))
        .map(|r| {
            let body: Value = serde_json::from_slice(&r.body).unwrap();
            serde_json::from_value(body["identity"].clone()).unwrap()
        })
        .collect();
    let renewing = document("alice identity.json, wallet renewal in progress");
    let closed = document("alice identity.json, wallet renewal closed");
    assert!(delivered.contains(&renewing), "the renewing version 4");
    assert_eq!(delivered.last(), Some(&closed), "the closing version 5");
    assert_eq!(old.switch.identity_doc().unwrap().signed(), &closed);

    let vector = load("envelopes.json");
    let reduction = &vector["reduction_key_bundle"];
    let parts = old.switch.bundle_parts_of(&wallet_id);
    assert_eq!(parts.len(), 1);
    let contents = parts[0]
        .bundle
        .open(&old.key.public(), &wallet_id, &wallet.bundle_secret())
        .unwrap();
    assert_eq!(
        *contents.to_json().unwrap(),
        *text(reduction, "plaintext_json").as_bytes(),
        "the reduction's full bundle"
    );
}

/// `http.json`'s account erasure naming the `identity.json` it follows, and its answer (Switch
/// wire 7.4.16): at the vector's time, the erasure alice's signer sends is the vector's
/// request, its body naming her account's service key and the hash of her version 3, its
/// mark, its headers and signature byte for byte; the vector's answer, signed with that
/// key and carrying no head, confirms it, and the signer then signs nothing more.
#[tokio::test]
async fn test_vectors_old_signer_erases_the_account_as_the_vectors_do() {
    let http = load("http.json");
    let request = http["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            text(r, "name")
                == "signer: account erasure, naming the account's service key and the identity.json it follows"
        })
        .unwrap();
    let answer = http["responses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["request_signature"] == request["signature"])
        .unwrap();
    let response = Response {
        status: u16::try_from(answer["status"].as_u64().unwrap()).unwrap(),
        headers: answer["headers"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, value)| Header::new(name, value.as_str().unwrap()))
            .collect(),
        body: text(answer, "body").as_bytes().to_vec(),
    };
    let mut old = old_signer_answering(Some(response)).await;
    let timestamp = text(&request["headers"], "switch-timestamp");
    old.clock
        .set_ms(pubky_switch_core::time::parse_rfc3339(timestamp).unwrap());
    old.signer
        .close_account(UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    let sent = old
        .transport
        .requests()
        .into_iter()
        .find(|r| r.method == "POST" && r.path_and_query.ends_with("/erase"))
        .unwrap();
    assert_eq!(sent.path_and_query, text(request, "path"));
    assert_eq!(sent.body, unb64(text(request, "body_b64")).unwrap());
    for (name, value) in request["headers"].as_object().unwrap() {
        assert_eq!(
            sent.header(name),
            Some(value.as_str().unwrap()),
            "the {name} header"
        );
    }
    assert_eq!(old.signer.status(), super::SignerStatus::Erased);
    assert!(!old.homeserver.0.lock().unwrap().contains_key(IDENTITY_PATH));
}

/// The size check on a delivered version (Switch wire 3.7, 7.1): alice's version 3 with about
/// 1,200 `renewed` entries passes three quarters of the cap a delivery and a move's enrollment
/// share, and the user is told; a smaller version after it clears the alert.
#[tokio::test]
async fn test_vectors_old_signer_tells_of_an_identity_near_the_limit() {
    let mut old = old_signer().await;
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &old.key.public()).unwrap();
    let mut body = v3.body().clone();
    body.version = 4;
    let app_id = body.apps[0].app_id;
    body.renewed = (0..1_200u32)
        .map(|n| {
            let mut cert = [0u8; 32];
            cert[..4].copy_from_slice(&n.to_be_bytes());
            RenewedCert {
                app_id,
                cert,
                until: Some(VECTOR_START_MS),
            }
        })
        .collect();
    let large = IdentityDoc::sign(&old.key, body).unwrap();
    old.signer
        .delivered(large.signed().clone(), Some(v3.hash()), None)
        .await
        .unwrap();
    assert!(
        old.signer
            .alerts()
            .iter()
            .any(|alert| matches!(alert, Alert::IdentityNearLimit { .. })),
        "{:?}",
        old.signer.alerts()
    );
    let mut small = v3.body().clone();
    small.version = 5;
    let small = IdentityDoc::sign(&old.key, small).unwrap();
    old.signer
        .delivered(small.signed().clone(), Some(large.hash()), None)
        .await
        .unwrap();
    assert!(
        !old.signer
            .alerts()
            .iter()
            .any(|alert| matches!(alert, Alert::IdentityNearLimit { .. }))
    );
}

/// alice's version 3 as version 4, with `entries` `renewed` entries of the wallet, closed
/// at `until` or open, held by the switch and taken by the old signer as delivered. Each entry
/// names a certificate the signer issued and holds, as a hand-over carries them all (wire
/// 3.12).
async fn with_renewed(old: &mut OldSigner, entries: u32, until: Option<u64>) -> IdentityDoc {
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &old.key.public()).unwrap();
    let mut body = v3.body().clone();
    body.version = 4;
    let listed = body.apps[0].cert;
    let listed = old
        .signer
        .state
        .certs
        .iter()
        .map(|cert| AppCert::verify(cert, &old.key.public()).unwrap())
        .find(|cert| cert.hash() == listed)
        .unwrap();
    body.renewed = (0..entries)
        .map(|n| {
            let mut earlier = listed.body().clone();
            earlier.issued_at -= u64::from(n) + 1;
            let cert = AppCert::issue(&old.key, earlier).unwrap();
            old.signer.state.certs.push(cert.signed().clone());
            RenewedCert {
                app_id: cert.app_id(),
                cert: cert.hash(),
                until,
            }
        })
        .collect();
    let large = IdentityDoc::sign(&old.key, body).unwrap();
    old.switch.deliver_identity(&large).unwrap();
    old.signer
        .delivered(large.signed().clone(), Some(v3.hash()), None)
        .await
        .unwrap();
    large
}

fn near_limit(signer: &Signer) -> bool {
    signer
        .alerts()
        .iter()
        .any(|alert| matches!(alert, Alert::IdentityNearLimit { .. }))
}

/// About 900 `renewed` entries: a delivery carrying the version stays under three quarters of
/// the cap, but a move's enrollment, which carries it encoded twice, is past it, and the user
/// is told (Switch wire 3.7, 7.1).
#[tokio::test]
async fn test_vectors_old_signer_measures_the_enrollment_form_too() {
    let mut old = old_signer().await;
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &old.key.public()).unwrap();
    let large = with_renewed(&mut old, 900, Some(VECTOR_START_MS)).await;
    let delivery = pubky_switch_core::http::IdentityDelivery {
        identity: large.signed().clone(),
        prev: Some(v3.hash()),
    };
    let limit = super::identity_limit().unwrap();
    assert!(
        delivery.to_json().len() * 4 <= limit * 3,
        "the delivery alone is under"
    );
    assert!(near_limit(&old.signer));
}

/// An identity whose delivery fits but whose move's enrollment, which carries it encoded
/// twice, wouldn't: a change that keeps it there is refused before anything is signed, as one
/// over the delivery's cap is, since the identity could never move (Switch wire 3.7, 7.1).
#[tokio::test]
async fn test_vectors_old_signer_signs_no_version_that_cant_move() {
    let mut old = old_signer().await;
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &old.key.public()).unwrap();
    let large = with_renewed(&mut old, 1_300, Some(VECTOR_START_MS)).await;
    let delivery = pubky_switch_core::http::IdentityDelivery {
        identity: large.signed().clone(),
        prev: Some(v3.hash()),
    };
    let limit = super::identity_limit().unwrap();
    assert!(
        delivery.to_json().len() + 1_000 < limit,
        "the delivery alone fits: {}",
        delivery.to_json().len()
    );
    let refused = old.signer.set_record_max_age(Some(60)).await.unwrap_err();
    assert!(
        matches!(
            refused,
            SignerError::Refused(Refusal::IdentityTooLarge { .. })
        ),
        "{refused:?}"
    );
    assert_eq!(
        old.signer.identity_doc().unwrap().unwrap().hash(),
        large.hash()
    );
}

/// An identity over the size a delivery may carry: a change that keeps it there is refused
/// before anything is signed, and so is the automatic renewal, which the run skips with the
/// near-limit alert; a revocation, which drops the app's `renewed` entries, goes through
/// (Switch wire 7.1, 3.3).
#[tokio::test]
async fn test_vectors_old_signer_signs_nothing_over_the_cap_but_a_removal() {
    let mut old = old_signer().await;
    with_renewed(&mut old, 1_560, Some(VECTOR_START_MS)).await;
    let puts = |old: &OldSigner| {
        old.transport
            .requests()
            .iter()
            .filter(|r| r.method == "PUT" && r.path_and_query.ends_with("/identity"))
            .count()
    };
    let sent = puts(&old);
    let refused = old.signer.set_record_max_age(Some(60)).await.unwrap_err();
    assert!(
        matches!(
            refused,
            SignerError::Refused(Refusal::IdentityTooLarge { .. })
        ),
        "{refused:?}"
    );
    // Past half the certificates' lifetimes: a renewal is refused, so the run renews nothing,
    // and says why.
    old.clock.set_ms(VECTOR_START_MS + 200 * 86_400_000);
    let keys = load("keys.json");
    let phone = app_keys(&keys, "phone").app_id_bytes();
    let refused = old
        .signer
        .renew(phone, CertChange::default())
        .await
        .unwrap_err();
    assert!(
        matches!(
            refused,
            SignerError::Refused(Refusal::IdentityTooLarge { .. })
        ),
        "{refused:?}"
    );
    old.signer.run_due().await.unwrap();
    assert_eq!(puts(&old), sent);
    assert!(near_limit(&old.signer));

    let wallet = app_keys(&keys, "wallet").app_id_bytes();
    let removed = old
        .signer
        .revoke(wallet, None, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    assert!(removed.body().renewed.is_empty());
    assert!(puts(&old) > sent);
    assert!(!near_limit(&old.signer));
}

/// A new signer taking over an identity near the size a delivery may carry is told at its
/// take-over, not only at its own next delivery (Switch wire 3.7, 3.12, 7.1).
#[tokio::test]
async fn test_vectors_new_signer_is_told_of_a_large_identity_at_its_take_over() {
    let mut old = old_signer().await;
    with_renewed(&mut old, 1_200, Some(VECTOR_START_MS)).await;
    old.signer
        .hand_over_to(old.phone, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    let keys = load("keys.json");
    let alice = old.key.public();
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &alice).unwrap();
    let phone = super::ReceivingApp {
        keys: app_keys(&keys, "phone"),
        cert: AppCert::verify(&document("phone certificate"), &alice).unwrap(),
        origin: v3.inbox().url.clone(),
        service_key: v3.inbox().service_key,
    };
    let env = SignerEnv {
        store: StoreHandle::inline(Arc::new(MemoryStore::new())),
        clock: old.clock.clone(),
        transport: old.transport.clone(),
        homeserver: old.homeserver.clone(),
        protocols: Protocols::new(vec![Arc::new(VectorScopes::new())]).unwrap(),
    };
    let new = Signer::receive_hand_over(env, &phone, Arc::new(Vault(Mutex::new(None))))
        .await
        .unwrap();
    assert!(near_limit(&new));
}

/// Open `renewed` entries under the cap that their closings would take over it: a change is
/// refused, since a closing owed past the cap could never be delivered and would stop every
/// later step; the revocation of their app goes through (Switch wire 3.3, 3.8, 7.1).
#[tokio::test]
async fn test_vectors_old_signer_counts_the_closings_its_open_renewals_owe() {
    let mut old = old_signer().await;
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &old.key.public()).unwrap();
    let large = with_renewed(&mut old, 1_700, None).await;
    let delivery = pubky_switch_core::http::IdentityDelivery {
        identity: large.signed().clone(),
        prev: Some(v3.hash()),
    };
    let limit = super::identity_limit().unwrap();
    assert!(delivery.to_json().len() < limit, "the open entries fit");
    let refused = old.signer.set_record_max_age(Some(60)).await.unwrap_err();
    assert!(
        matches!(
            refused,
            SignerError::Refused(Refusal::IdentityTooLarge { .. })
        ),
        "{refused:?}"
    );
    let keys = load("keys.json");
    let wallet = app_keys(&keys, "wallet").app_id_bytes();
    let removed = old
        .signer
        .revoke(wallet, None, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    assert!(removed.body().renewed.is_empty());
}

/// A version whose delivery would land within the headroom kept under the cap is refused,
/// not only one over it: a later version adds a digit or two, and its closing must still be
/// deliverable (Switch wire 7.1).
#[tokio::test]
async fn test_vectors_old_signer_keeps_headroom_under_the_cap() {
    let mut old = old_signer().await;
    // About as many closed entries as fill the cap that binds, a move's enrollment's; then
    // version 5, the inbox's host padded so that version 6, the change below, lands a few
    // bytes under it.
    let entries = entries_near_the_cap(&old.signer, 2_000);
    let large = with_renewed(&mut old, entries, Some(VECTOR_START_MS)).await;
    let prev = Some(large.hash());
    let size = |body: &pubky_switch_core::records::IdentityBody| binding(&old.signer, body, prev);
    let padded = |pad: usize| {
        let mut body = large.body().clone();
        body.version = 5;
        body.inbox.url = format!("https://{}.switch.example", "a".repeat(pad));
        body
    };
    let next = |body: &pubky_switch_core::records::IdentityBody| {
        let mut next = body.clone();
        next.version = 6;
        next.record_max_age = Some(60);
        next
    };
    let pad = (0..3_000)
        .find(|pad| {
            let measure = size(&next(&padded(*pad)));
            measure.bytes <= measure.limit && measure.bytes + 8 > measure.limit
        })
        .expect("a padding that lands within the headroom");
    let five = IdentityDoc::sign(&old.key, padded(pad)).unwrap();
    old.switch.deliver_identity(&five).unwrap();
    old.signer
        .delivered(five.signed().clone(), Some(large.hash()), None)
        .await
        .unwrap();
    let refused = old.signer.set_record_max_age(Some(60)).await.unwrap_err();
    assert!(
        matches!(
            refused,
            SignerError::Refused(Refusal::IdentityTooLarge {
                body: SizedBody::Enrollment,
                bytes,
                limit,
            }) if bytes <= limit
        ),
        "{refused:?}"
    );
}

/// A reduction's renewing version signed within the cap's headroom of the cap: its closing,
/// which only closes what is signed already, may use the headroom, and is delivered, not
/// refused; refused, it would block every signing step (Switch wire 3.8, 7.1).
#[tokio::test]
async fn test_vectors_old_signer_closes_a_reduction_within_the_headroom() {
    use pubky_switch_core::records::IdentityBody;
    let mut old = old_signer().await;
    let alice = old.key.public();
    let renewed = AppCert::verify(&document("wallet certificate, renewed"), &alice).unwrap();
    old.signer.state.certs.push(renewed.signed().clone());
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &alice).unwrap();
    let renewing = IdentityDoc::verify(
        &document("alice identity.json, wallet renewal in progress"),
        &alice,
    )
    .unwrap();
    // Closed entries enough to come near the cap, as the wallet's earlier certificates.
    let listed = AppCert::verify(&document("wallet certificate"), &alice).unwrap();
    let filler: Vec<RenewedCert> = (0..entries_near_the_cap(&old.signer, 2_000))
        .map(|n| {
            let mut earlier = listed.body().clone();
            earlier.issued_at -= u64::from(n) + 1;
            let cert = AppCert::issue(&old.key, earlier).unwrap();
            old.signer.state.certs.push(cert.signed().clone());
            RenewedCert {
                app_id: cert.app_id(),
                cert: cert.hash(),
                until: Some(VECTOR_START_MS),
            }
        })
        .collect();
    let size = |body: &IdentityBody| binding(&old.signer, body, Some(renewing.hash()));
    let padded = |pad: usize| {
        let mut body = renewing.body().clone();
        body.renewed.extend(filler.iter().copied());
        body.inbox.url = format!("https://{}.switch.example", "a".repeat(pad));
        body
    };
    let closing = |body: &IdentityBody| {
        let mut next = body.clone();
        next.version += 1;
        for entry in &mut next.renewed {
            entry.until.get_or_insert(VECTOR_START_MS);
        }
        next
    };
    // The closing lands within the headroom, under the cap that binds.
    let pad = (0..3_000)
        .find(|pad| {
            let measure = size(&closing(&padded(*pad)));
            measure.bytes <= measure.limit && measure.bytes + 8 > measure.limit
        })
        .expect("a padding that lands the closing within the headroom");
    let four = IdentityDoc::sign(&old.key, padded(pad)).unwrap();
    old.switch.deliver_identity(&four).unwrap();
    old.signer
        .delivered(
            four.signed().clone(),
            Some(v3.hash()),
            Some(VECTOR_START_MS),
        )
        .await
        .unwrap();
    assert!(!old.signer.owed().unwrap().is_empty(), "a closing is owed");
    old.signer.resume().await.unwrap();
    assert!(
        old.signer.owed().unwrap().is_empty(),
        "the closing was delivered"
    );
    let closed = old.signer.identity_doc().unwrap().unwrap();
    assert_eq!(closed.version(), 5);
    // The closed version still fits every body, its delivery and a move's enrollment.
    for measure in super::measures(&old.signer.state, closed.body(), Some(four.hash())).unwrap() {
        assert!(measure.bytes <= measure.limit, "{measure:?}");
    }
}

/// The measure of `body`, built on `prev`, that comes nearest its cap, as the signer judges
/// it.
fn binding(
    signer: &Signer,
    body: &pubky_switch_core::records::IdentityBody,
    prev: Option<[u8; 32]>,
) -> super::Measure {
    super::measures(&signer.state, body, prev)
        .unwrap()
        .into_iter()
        .max_by(|a, b| (a.bytes * b.limit).cmp(&(b.bytes * a.limit)))
        .unwrap()
}

/// How many closed `renewed` entries alice's version 3 can take with the body that binds,
/// a move's enrollment, at least `margin` bytes under its cap, and as few as possible more.
fn entries_near_the_cap(signer: &Signer, margin: usize) -> u32 {
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &signer.state.identity).unwrap();
    let with = |entries: u32| {
        let mut body = v3.body().clone();
        body.version = 6;
        body.renewed = (0..entries)
            .map(|n| {
                let mut cert = [0u8; 32];
                cert[..4].copy_from_slice(&n.to_be_bytes());
                RenewedCert {
                    app_id: body.apps[0].app_id,
                    cert,
                    until: Some(VECTOR_START_MS),
                }
            })
            .collect();
        let measure = binding(signer, &body, Some(v3.hash()));
        assert_eq!(measure.body, SizedBody::Enrollment);
        measure.bytes + margin <= measure.limit
    };
    (0..2_000).take_while(|n| with(*n)).last().unwrap()
}

/// The body a real move sends for `doc`, built as `SwitchClient::enroll` builds it, at the
/// longest origin a switch may have, naming every App ID the records revoked and `doc`'s
/// `removed`: its length.
fn real_move_request(old: &OldSigner, doc: &IdentityDoc) -> usize {
    let host = format!(
        "{}.example",
        "a".repeat(pubky_switch_core::net::MAX_DOMAIN_LEN - 8)
    );
    let origin = format!("https://{host}:65535");
    assert_eq!(origin.len(), pubky_switch_core::net::MAX_ORIGIN_LEN);
    let mut revoked = old.signer.state.tombstones.clone();
    revoked.extend(doc.body().removed.iter().map(|r| r.app_id));
    let enrollment = pubky_switch_core::records::Enrollment::sign(
        &old.key,
        pubky_switch_core::records::EnrollmentBody {
            identity: old.key.public(),
            origin,
            nonce: [7; 16],
            policy: doc.body().policy,
            identity_doc: Some(doc.signed().clone()),
            revoked_apps: Some(revoked),
        },
    )
    .unwrap();
    serde_json::json!({ "enrollment": enrollment.signed() })
        .to_string()
        .len()
}

/// The signer's measure of a move's enrollment carrying `body`, built on `prev`.
fn enrollment_measure(
    old: &OldSigner,
    body: &pubky_switch_core::records::IdentityBody,
    prev: [u8; 32],
) -> super::Measure {
    super::measures(&old.signer.state, body, Some(prev))
        .unwrap()
        .into_iter()
        .find(|m| m.body == SizedBody::Enrollment)
        .unwrap()
}

/// alice at version 5, padded so that the signer's own version 6 (`record_max_age`) lands
/// `lo..=hi` bytes under the enrollment cap, then version 6 signed by the signer. Returns
/// version 6 and the cap.
async fn at_the_edge(old: &mut OldSigner, lo: usize, hi: usize) -> (IdentityDoc, usize) {
    let entries = entries_near_the_cap(&old.signer, 2_000);
    let large = with_renewed(old, entries, Some(VECTOR_START_MS)).await;
    let padded = |pad: usize| {
        let mut body = large.body().clone();
        body.version = 5;
        body.inbox.url = format!("https://{}.switch.example", "a".repeat(pad));
        body
    };
    let pad = (1..3_000)
        .find(|pad| {
            let mut six = padded(*pad);
            six.version = 6;
            six.record_max_age = Some(60);
            let m = enrollment_measure(old, &six, [0; 32]);
            m.bytes + lo <= m.limit && m.bytes + hi >= m.limit
        })
        .expect("a padding at the edge");
    let five = IdentityDoc::sign(&old.key, padded(pad)).unwrap();
    old.switch.deliver_identity(&five).unwrap();
    old.signer
        .delivered(five.signed().clone(), Some(large.hash()), None)
        .await
        .unwrap();
    let six = old.signer.set_record_max_age(Some(60)).await.unwrap();
    (six, super::enrollment_limit().unwrap())
}

/// At the edge, the measure of a move's enrollment is never below the real move's body, and
/// above it by exactly the App IDs of the apps the version lists, counted as revoked already
/// (Switch wire 3.7, 7.1).
#[tokio::test]
async fn test_vectors_old_signer_measures_a_real_move_at_the_edge() {
    let mut old = old_signer().await;
    let (six, limit) = at_the_edge(&mut old, 16, 20).await;
    let prev = old.signer.state.newest.as_ref().unwrap().prev.unwrap();
    let measured = enrollment_measure(&old, six.body(), prev);
    let real = real_move_request(&old, &six);
    // Each listed App ID, in `revoked_apps`: a 26-character text, quoted, and its comma, 29
    // bytes of the enrollment's JSON, which travels base64url-encoded (wire 2.2).
    let listed = six
        .body()
        .apps
        .iter()
        .filter(|app| !old.signer.state.tombstones.contains(&app.app_id))
        .count();
    assert!(measured.bytes >= real);
    assert!((measured.bytes - real).abs_diff(listed * 29 * 4 / 3) <= 2);
    assert!(real + 16 <= limit);
}

/// At the edge, revoking an app with no `renewed` entries goes through: its App ID was in the
/// measure already, as a listed app's, so its removal shrinks every body (Switch wire 3.7,
/// 7.1, spec 12.2).
#[tokio::test]
async fn test_vectors_old_signer_revokes_an_app_without_renewals_at_the_edge() {
    let mut old = old_signer().await;
    let (six, _) = at_the_edge(&mut old, 16, 30).await;
    let keys = load("keys.json");
    let phone = app_keys(&keys, "phone").app_id_bytes();
    assert!(six.body().renewed.iter().all(|r| r.app_id != phone));
    let removed = old
        .signer
        .revoke(phone, None, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    assert!(removed.listed_cert(&phone).is_none());
    old.signer.set_record_max_age(Some(61)).await.unwrap();
}

/// A reduction signed at the edge closes, and both the renewing version and its closing still
/// fit a real move (Switch wire 3.7, 3.8, 7.1).
#[tokio::test]
async fn test_vectors_old_signer_closes_and_moves_a_reduction_at_the_edge() {
    let mut old = old_signer().await;
    let (wallet, change) = reduction_at_the_edge(&mut old).await;
    let six = old.signer.renew(wallet, change).await.unwrap();
    let limit = super::enrollment_limit().unwrap();
    assert!(real_move_request(&old, &six) <= limit);
    old.clock.set_ms(VECTOR_START_MS + 3 * 60_000);
    old.signer.resume().await.unwrap();
    old.signer.run_due().await.unwrap();
    assert!(old.signer.owed().unwrap().is_empty(), "nothing owed");
    let closed = old.signer.identity_doc().unwrap().unwrap();
    assert!(closed.body().renewed.iter().all(|r| r.until.is_some()));
    assert!(real_move_request(&old, &closed) <= limit);
}

/// A reduction signed at the edge whose renewing delivery failed, then a revocation of an app
/// without renewals while the closing is owed: the closing still fits, and the revocation
/// completes after it, nothing wedged (Switch wire 3.8, 7.1, spec 12.2).
#[tokio::test]
async fn test_vectors_old_signer_revokes_while_a_closing_is_owed_at_the_edge() {
    let mut old = old_signer().await;
    let (wallet, change) = reduction_at_the_edge(&mut old).await;
    let keys = load("keys.json");
    let phone = app_keys(&keys, "phone").app_id_bytes();
    old.switch.fail_next(Fault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    old.signer.renew(wallet, change).await.unwrap_err();
    old.signer
        .revoke(phone, None, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap_err();
    old.clock.set_ms(VECTOR_START_MS + 3 * 60_000);
    old.signer.resume().await.unwrap();
    old.signer.run_due().await.unwrap();
    assert!(
        old.signer.owed().unwrap().is_empty(),
        "the closing was delivered"
    );
    let newest = old.signer.identity_doc().unwrap().unwrap();
    assert!(
        newest.listed_cert(&phone).is_none(),
        "the revocation completed"
    );
    let limit = super::enrollment_limit().unwrap();
    assert!(real_move_request(&old, &newest) <= limit);
}

/// At the edge, a restore in place after the switch shows a listed app revoked: the restore
/// adds that App ID to the records, which the measure counted already, as a listed app's, so
/// its next version, measured against the cap itself, is signed (Switch wire 3.13, 7.1).
#[tokio::test]
async fn test_vectors_old_signer_restores_at_the_edge_after_a_revocation_at_the_switch() {
    let mut old = old_signer().await;
    at_the_edge(&mut old, 16, 20).await;
    let keys = load("keys.json");
    let wallet = app_keys(&keys, "wallet").app_id_bytes();
    old.switch.revoke(wallet).unwrap();
    let restored = old
        .signer
        .restore(UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    assert!(old.signer.state.tombstones.contains(&wallet));
    let limit = super::enrollment_limit().unwrap();
    assert!(real_move_request(&old, &restored) <= limit);
}

/// At the edge, a take-over after the switch shows a listed app revoked: the new signer's
/// records take that App ID, which the measure counted already, and its first version is
/// signed and delivered (Switch wire 3.12, 7.1).
#[tokio::test]
async fn test_vectors_new_signer_takes_over_at_the_edge_after_a_revocation_at_the_switch() {
    let mut old = old_signer().await;
    let (six, _) = at_the_edge(&mut old, 16, 20).await;
    let keys = load("keys.json");
    let wallet = app_keys(&keys, "wallet").app_id_bytes();
    old.switch.revoke(wallet).unwrap();
    old.signer
        .hand_over_to(old.phone, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    let alice = old.key.public();
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &alice).unwrap();
    let phone = super::ReceivingApp {
        keys: app_keys(&keys, "phone"),
        cert: AppCert::verify(&document("phone certificate"), &alice).unwrap(),
        origin: six.inbox().url.clone(),
        service_key: v3.inbox().service_key,
    };
    let env = SignerEnv {
        store: StoreHandle::inline(Arc::new(MemoryStore::new())),
        clock: old.clock.clone(),
        transport: old.transport.clone(),
        homeserver: old.homeserver.clone(),
        protocols: Protocols::new(vec![Arc::new(VectorScopes::new())]).unwrap(),
    };
    let new = Signer::receive_hand_over(env, &phone, Arc::new(Vault(Mutex::new(None))))
        .await
        .unwrap();
    assert!(new.state.tombstones.contains(&wallet));
    let taken = new.identity_doc().unwrap().unwrap();
    assert_eq!(old.switch.identity_doc().unwrap().hash(), taken.hash());
    for measure in super::measures(&new.state, taken.body(), None).unwrap() {
        assert!(measure.bytes <= measure.limit, "{measure:?}");
    }
}

/// App IDs no version of alice's ever listed, which a faulty or hostile switch shows revoked.
const NEVER_LISTED: [[u8; 16]; 3] = [[0x41; 16], [0x42; 16], [0x43; 16]];

/// At the edge, a restore in place while the switch shows revoked App IDs no version listed:
/// the signer takes a removal from the switch only for an app its version lists, so its
/// records don't grow and its next version is signed (Switch wire 3.13, 7.1, 7.4.12).
#[tokio::test]
async fn test_vectors_old_signer_restores_at_the_edge_ignoring_removals_of_apps_never_listed() {
    let mut old = old_signer().await;
    at_the_edge(&mut old, 16, 20).await;
    for app in NEVER_LISTED {
        old.switch.revoke(app).unwrap();
    }
    let restored = old
        .signer
        .restore(UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    assert!(
        NEVER_LISTED
            .iter()
            .all(|app| !old.signer.state.tombstones.contains(app))
    );
    let limit = super::enrollment_limit().unwrap();
    assert!(real_move_request(&old, &restored) <= limit);
    old.signer.set_record_max_age(Some(61)).await.unwrap();
}

/// At the edge, a take-over while the switch shows revoked App IDs no version listed: the new
/// signer's records don't take them, and its first version is delivered (Switch wire 3.12,
/// 7.1, 7.4.12).
#[tokio::test]
async fn test_vectors_new_signer_takes_over_at_the_edge_ignoring_removals_of_apps_never_listed() {
    let mut old = old_signer().await;
    let (six, _) = at_the_edge(&mut old, 16, 20).await;
    old.signer
        .hand_over_to(old.phone, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap();
    for app in NEVER_LISTED {
        old.switch.revoke(app).unwrap();
    }
    let keys = load("keys.json");
    let alice = old.key.public();
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &alice).unwrap();
    let phone = super::ReceivingApp {
        keys: app_keys(&keys, "phone"),
        cert: AppCert::verify(&document("phone certificate"), &alice).unwrap(),
        origin: six.inbox().url.clone(),
        service_key: v3.inbox().service_key,
    };
    let env = SignerEnv {
        store: StoreHandle::inline(Arc::new(MemoryStore::new())),
        clock: old.clock.clone(),
        transport: old.transport.clone(),
        homeserver: old.homeserver.clone(),
        protocols: Protocols::new(vec![Arc::new(VectorScopes::new())]).unwrap(),
    };
    let new = Signer::receive_hand_over(env, &phone, Arc::new(Vault(Mutex::new(None))))
        .await
        .unwrap();
    assert!(
        NEVER_LISTED
            .iter()
            .all(|app| !new.state.tombstones.contains(app))
    );
    let taken = new.identity_doc().unwrap().unwrap();
    assert_eq!(old.switch.identity_doc().unwrap().hash(), taken.hash());
}

/// alice padded so that a reduction of the wallet, as the signer measures its renewing
/// version (one more entry, closed, at the next epoch), lands 16 to 20 bytes under the
/// enrollment cap. Returns the wallet and the reduction to ask for.
async fn reduction_at_the_edge(old: &mut OldSigner) -> ([u8; 16], CertChange) {
    let alice = old.key.public();
    let renewed = AppCert::verify(&document("wallet certificate, renewed"), &alice).unwrap();
    let keys = load("keys.json");
    let wallet = app_keys(&keys, "wallet").app_id_bytes();
    let entries = entries_near_the_cap(&old.signer, 2_000);
    let large = with_renewed(old, entries, Some(VECTOR_START_MS)).await;
    let padded = |pad: usize| {
        let mut body = large.body().clone();
        body.version = 5;
        body.inbox.url = format!("https://{}.switch.example", "a".repeat(pad));
        body
    };
    let renewing = |pad: usize| {
        let mut body = padded(pad);
        body.version = 6;
        body.renewed.push(RenewedCert {
            app_id: wallet,
            cert: body.apps[0].cert,
            until: Some(0),
        });
        body.apps[0].cert = renewed.hash();
        body.data_epoch += 1;
        body
    };
    let pad = (1..3_000)
        .find(|pad| {
            let m = enrollment_measure(old, &renewing(*pad), [0; 32]);
            m.bytes + 16 <= m.limit && m.bytes + 20 >= m.limit
        })
        .expect("a padding at the edge");
    let five = IdentityDoc::sign(&old.key, padded(pad)).unwrap();
    old.switch.deliver_identity(&five).unwrap();
    old.signer
        .delivered(five.signed().clone(), Some(large.hash()), None)
        .await
        .unwrap();
    old.clock.set_ms(VECTOR_START_MS + 2 * 60_000);
    let change = CertChange {
        scopes: Some(renewed.scopes().to_vec()),
        expires_at: Some(renewed.expires_at()),
    };
    (wallet, change)
}

/// alice rotated her key in place before the loss: her version 4, at generation 2, names
/// generation 1's key in `service_keys`. Her service then loses everything, and she recovers
/// there: the version leaves out every generation at or below `recovery_from`, so nothing
/// resolves a lost generation's key (Switch wire 3.3, spec 12.6 step 1).
#[tokio::test]
async fn test_vectors_old_signer_recovers_without_the_lost_generations_service_keys() {
    let mut old = old_signer().await;
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &old.key.public()).unwrap();
    let mut body = v3.body().clone();
    body.version = 4;
    body.generation = 2;
    body.service_keys
        .push(pubky_switch_core::records::ServiceKeyEntry {
            generation: 1,
            key: [0x11; 32],
        });
    let rotated = IdentityDoc::sign(&old.key, body).unwrap();
    old.switch.deliver_identity(&rotated).unwrap();
    old.signer
        .delivered(rotated.signed().clone(), Some(v3.hash()), None)
        .await
        .unwrap();
    old.switch.lose_identity();
    // At the scripted switch's own origin, which its enrollment names.
    let recovered = old
        .signer
        .declare_provider_loss(
            pubky_switch_client::testing::SWITCH_ORIGIN,
            UserConfirmed::shown_and_confirmed(),
        )
        .await
        .unwrap();
    assert_eq!(recovered.generation(), 3);
    assert_eq!(recovered.body().recovery_from, Some(2));
    assert!(recovered.body().service_keys.is_empty());
    assert_eq!(old.switch.identity_doc().unwrap().hash(), recovered.hash());
}

/// A listed app whose certificate this install doesn't hold may hold `lists.manage`, so the
/// recovery leaves the staged admission for its upload, failing closed (Switch spec 12.6
/// step 2). The backup's seal refuses such a version before any delivery (Switch wire
/// 3.12), so the rule is held here on its own.
#[tokio::test]
async fn test_vectors_old_signer_counts_an_unknown_certificate_as_managing_lists() {
    let mut old = old_signer().await;
    let v3 = IdentityDoc::verify(&document("alice identity.json"), &old.key.public()).unwrap();
    let mut body = v3.body().clone();
    let held = old.signer.held_certs().unwrap();
    body.apps.retain(|listed| {
        held.iter()
            .find(|cert| cert.hash() == listed.cert)
            .is_some_and(|cert| !cert.has_permission(Permission::ListsManage))
    });
    assert!(!body.apps.is_empty(), "an app without lists.manage");
    let without = IdentityDoc::sign(&old.key, body).unwrap();
    assert!(!old.signer.listed_may_manage_lists(&without).unwrap());
    old.signer.state.certs.clear();
    assert!(old.signer.listed_may_manage_lists(&without).unwrap());
}

/// A recovery whose version, naming a longer origin, the cap can't take is refused before
/// its enrollment is sent: nothing at the service, and the user may declare it at another
/// origin (Switch spec 12.6 step 1, wire 7.1).
#[tokio::test]
async fn test_vectors_old_signer_refuses_a_recovery_over_the_cap_before_enrolling() {
    let mut old = old_signer().await;
    with_renewed(&mut old, 1_560, Some(VECTOR_START_MS)).await;
    old.switch.lose_identity();
    let sent = old.transport.requests().len();
    let long = format!("https://{}.example", "a".repeat(200));
    let refused = old
        .signer
        .declare_provider_loss(&long, UserConfirmed::shown_and_confirmed())
        .await
        .unwrap_err();
    assert!(
        matches!(
            refused,
            SignerError::Refused(Refusal::IdentityTooLarge { .. })
        ),
        "{refused:?}"
    );
    assert_eq!(old.transport.requests().len(), sent, "nothing sent");
    assert!(old.signer.flow.is_none());
    assert!(!old.signer.state.recovering);
}
