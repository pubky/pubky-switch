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

/// The vectors' protocol, read from the spec's files so the tests name none: the first
/// reserved protocol, with its roots; keyed are the scopes the vectors give keys for (scope
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
        let own = pubky_switch_core::scopes::reserved()
            .unwrap()
            .first()
            .unwrap()
            .clone();
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
            name: own.name,
            roots: own.roots,
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

/// `signer_handover`'s records with `doc` in place of version 3, and `prev`, as JSON bytes:
/// the records of a backup holding `doc` (Switch wire 3.13).
fn records_with(plaintext: &[u8], doc: &SignedDoc, prev: [u8; 32]) -> Vec<u8> {
    let v3 = document("alice identity.json");
    let mut records = std::str::from_utf8(plaintext)
        .unwrap()
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
        *backup.open(&old.key).unwrap().to_json().unwrap(),
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
/// signer renews the wallet without `manage_contacts`, a scope with keys, and expiring earlier,
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

/// `http.json`'s account erasure and its answer (Switch wire 7.4.16): at the vector's time,
/// the erasure alice's signer sends is the vector's request, its body naming her account's
/// service key, its headers and signature byte for byte; the vector's answer, signed with that
/// key and carrying no head, confirms it, and the signer then signs nothing more.
#[tokio::test]
async fn test_vectors_old_signer_erases_the_account_as_the_vectors_do() {
    let http = load("http.json");
    let request = http["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| text(r, "name").starts_with("signer: account erasure"))
        .unwrap();
    let answer = http["responses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| text(r, "name").starts_with("signer: account erasure answer"))
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
