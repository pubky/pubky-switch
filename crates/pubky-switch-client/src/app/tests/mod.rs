//! The app layer's flow tests, against a scripted switch ([`fake::FakeSwitch`]) answering
//! through the `MockTransport`, a fake Homeserver, and a neutral sample protocol. Keys come
//! from the vectors' fixed seeds, whose prefix is read from `spec/vectors/README.md`.

mod fake;
mod flows;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::message::Message;
use pubky_switch_core::ops::{AllowKind, OpKind};
use pubky_switch_core::records::{
    AppCert, AppCertBody, AppRequest, AppRequestBody, Approval, AuthRequest,
    DEFAULT_CERT_LIFETIME_MS, IDENTITY_PATH, IdentityBody, IdentityDoc, IdentityPolicy, Inbox,
    ListedApp, app_record_path,
};
use serde_json::{Value, json};

use self::fake::{FakeSwitch, ORIGIN};
use super::{
    App, AppConfig, AppEnv, Effect, HomeserverReader, JoinRequest, LocalWrite, MissedEntries,
    Outcome, Protocol, ReceivedMessage, ResendNeeded,
};
use crate::clock::{Clock, TestClock};
use crate::error::TransportError;
use crate::store::{MemoryStore, StateStore, StoreHandle};
use crate::transport::BoxFuture;

/// 2026-01-01T00:00:00Z.
pub(crate) const START: u64 = 1_767_225_600_000;

/// The seed prefix of the vectors' README ("Seeds"), read from the README, the
/// convention's one source.
fn seed_prefix() -> String {
    let path = format!(
        "{}/../../spec/vectors/README.md",
        env!("CARGO_MANIFEST_DIR")
    );
    let readme = std::fs::read_to_string(&path).unwrap();
    let start = readme.find("BLAKE3(\"").unwrap() + 8;
    let len = readme[start..].find('"').unwrap();
    readme[start..start + len].to_owned()
}

/// A fixed secret of the vectors: `BLAKE3(prefix + label)`.
pub(crate) fn seed(label: &str) -> [u8; 32] {
    *blake3::hash(format!("{}{label}", seed_prefix()).as_bytes()).as_bytes()
}

pub(crate) fn app_keys(name: &str) -> AppKeys {
    AppKeys::from_secrets(
        seed(&format!("alice/{name}/signing")),
        seed(&format!("alice/{name}/bundle")),
    )
}

/// A neutral protocol: scope `scope-a` has keys and sends and receives `sample.note`;
/// `sample.notice` goes between own apps. A note writes a conversation entry for its sender
/// with the cursor move, and keeps its text locally.
#[derive(Default)]
pub(crate) struct SampleProtocol {
    pub(crate) received: Mutex<Vec<(u64, String, bool)>>,
    pub(crate) resends: Mutex<Vec<ResendNeeded>>,
    pub(crate) missed: Mutex<Vec<MissedEntries>>,
}

impl Protocol for SampleProtocol {
    fn has_keys(&self, scope: &str) -> bool {
        scope == "scope-a" || scope.starts_with("scope-a:")
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        kind == "sample.notice"
    }

    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String> {
        match message.kind.as_str() {
            "sample.note" if sender.holds_scope("scope-a") && own.holds_scope("scope-a") => Ok(()),
            "sample.notice" => Ok(()),
            _ => Err("sample: a kind these scopes don't send or receive".into()),
        }
    }

    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        if cert.holds_scope("scope-a") {
            vec!["sample.note".into(), "sample.notice".into()]
        } else {
            Vec::new()
        }
    }

    fn receive(&self, message: &ReceivedMessage) -> Outcome {
        let Some(text) = message.message.body.get("text").and_then(Value::as_str) else {
            return Outcome::Drop {
                reason: "sample: body.text isn't text".into(),
            };
        };
        self.received.lock().unwrap().push((
            message.seq,
            message.message.msg_id.clone(),
            message.conflict.is_some(),
        ));
        let local = vec![LocalWrite::Put {
            key: format!("notes/{}", message.message.msg_id).into_bytes(),
            value: text.as_bytes().to_vec(),
        }];
        let ops = if message.message.kind == "sample.note" {
            vec![(
                Vec::new(),
                OpKind::AllowPut {
                    pubky: message.sender,
                    kind: AllowKind::Conversation,
                },
            )]
        } else {
            Vec::new()
        };
        Outcome::Apply(Effect { ops, local })
    }

    fn resend_needed(&self, needed: &ResendNeeded) -> Vec<LocalWrite> {
        self.resends.lock().unwrap().push(needed.clone());
        vec![LocalWrite::Put {
            key: format!("resend/{}", needed.accepted_from_ms).into_bytes(),
            value: b"1".to_vec(),
        }]
    }

    fn missed(&self, missed: &MissedEntries) -> Vec<LocalWrite> {
        self.missed.lock().unwrap().push(missed.clone());
        vec![LocalWrite::Put {
            key: format!("missed/{}", missed.seq).into_bytes(),
            value: b"1".to_vec(),
        }]
    }
}

/// Public files by identity and path.
type Files = HashMap<([u8; 32], String), Vec<u8>>;

/// A Homeserver of public files, failing on demand.
#[derive(Default)]
pub(crate) struct FakeHomeserver {
    pub(crate) files: Mutex<Files>,
    pub(crate) down: Mutex<bool>,
}

impl FakeHomeserver {
    pub(crate) fn publish(&self, doc: &IdentityDoc) {
        self.files.lock().unwrap().insert(
            (doc.identity(), IDENTITY_PATH.to_owned()),
            serde_json::to_vec(doc.signed()).unwrap(),
        );
    }
}

impl HomeserverReader for FakeHomeserver {
    fn get(
        &self,
        identity: [u8; 32],
        path: String,
    ) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        let answer = if *self.down.lock().unwrap() {
            Err(TransportError::Connect("down".into()))
        } else {
            Ok(self.files.lock().unwrap().get(&(identity, path)).cloned())
        };
        Box::pin(async move { answer })
    }
}

/// Alice's account, bob as her counterparty, and the signer's documents.
pub(crate) struct World {
    pub(crate) clock: Arc<TestClock>,
    pub(crate) alice: IdentityKey,
    pub(crate) bob: IdentityKey,
    pub(crate) bob_keys: AppKeys,
    pub(crate) bob_cert: AppCert,
    pub(crate) switch: Arc<FakeSwitch>,
    pub(crate) homeserver: Arc<FakeHomeserver>,
    pub(crate) store: Arc<MemoryStore>,
    pub(crate) protocol: Arc<SampleProtocol>,
    /// Alice's newest document body.
    pub(crate) body: Mutex<IdentityBody>,
}

pub(crate) fn cert_for(
    identity: &IdentityKey,
    keys: &AppKeys,
    issued: u64,
    scopes: &[&str],
) -> AppCert {
    AppCert::issue(
        identity,
        AppCertBody::new(
            identity.public(),
            keys.signing_public(),
            keys.bundle_public(),
            scopes.iter().map(|s| (*s).to_owned()).collect(),
            &[],
            issued,
            issued + DEFAULT_CERT_LIFETIME_MS,
        ),
    )
    .unwrap()
}

impl World {
    pub(crate) fn new() -> Self {
        let clock = Arc::new(TestClock::new(START));
        let alice = IdentityKey::from_secret(seed("alice/identity"));
        let bob = IdentityKey::from_secret(seed("bob/identity"));
        let bob_keys = AppKeys::from_secrets(seed("bob/shop/signing"), seed("bob/shop/bundle"));
        let bob_cert = cert_for(&bob, &bob_keys, START - 1000, &["scope-a"]);
        let service = SigningKey::from_bytes(&seed("service/alice"));
        let switch = FakeSwitch::new(
            IdentityKey::from_secret(seed("alice/identity")),
            service.clone(),
            Arc::clone(&clock),
        );
        let homeserver = Arc::new(FakeHomeserver::default());
        let mut bob_body = IdentityBody::first(
            bob.public(),
            [2; 16],
            Inbox::new("https://other.example", [3; 32]),
            IdentityPolicy::default(),
        );
        bob_body.apps.push(ListedApp {
            app_id: bob_cert.app_id(),
            cert: bob_cert.hash(),
        });
        homeserver.publish(&IdentityDoc::sign(&bob, bob_body).unwrap());
        let body = IdentityBody::first(
            alice.public(),
            [1; 16],
            Inbox::new(ORIGIN, service.verifying_key().to_bytes()),
            IdentityPolicy::default(),
        );
        Self {
            clock,
            alice,
            bob,
            bob_keys,
            bob_cert,
            switch,
            homeserver,
            store: Arc::new(MemoryStore::new()),
            protocol: Arc::new(SampleProtocol::default()),
            body: Mutex::new(body),
        }
    }

    pub(crate) fn env_on(&self, store: Arc<dyn StateStore>) -> AppEnv {
        AppEnv {
            store: StoreHandle::inline(store),
            transport: self.switch.transport(),
            clock: Arc::clone(&self.clock) as Arc<dyn Clock>,
            homeserver: Arc::clone(&self.homeserver) as Arc<dyn HomeserverReader>,
        }
    }

    pub(crate) fn env(&self) -> AppEnv {
        self.env_on(Arc::clone(&self.store) as Arc<dyn StateStore>)
    }

    pub(crate) fn config() -> AppConfig {
        AppConfig::default()
    }

    /// The next version of alice's document, changed by `change`, delivered to the switch
    /// and published.
    pub(crate) fn next_doc(&self, change: impl FnOnce(&mut IdentityBody)) -> IdentityDoc {
        let mut body = self.body.lock().unwrap();
        if self.switch.lock().doc.is_some() {
            body.version += 1;
        }
        change(&mut body);
        let doc = IdentityDoc::sign(&self.alice, body.clone()).unwrap();
        self.switch.deliver_identity(&doc);
        self.homeserver.publish(&doc);
        doc
    }

    /// The signer approves `keys` for `scopes`: a certificate, the document that lists it,
    /// and the approval.
    pub(crate) fn approve(&self, keys: &AppKeys, scopes: &[&str]) -> JoinRequest {
        let cert = cert_for(&self.alice, keys, self.clock.now_ms(), scopes);
        let auth = AuthRequest {
            client_id: "sample.example".into(),
            client_key: [7; 32],
            caps: format!("{}:rw", app_record_path(&keys.app_id_bytes())),
            secret: [8; 32],
        };
        let request = AppRequest::sign(
            keys,
            AppRequestBody::new(
                keys,
                scopes.iter().map(|s| (*s).to_owned()).collect(),
                &auth,
            ),
        )
        .unwrap();
        let doc = self.next_doc(|body| {
            body.apps.push(ListedApp {
                app_id: cert.app_id(),
                cert: cert.hash(),
            })
        });
        let protocol = SampleProtocol::default();
        let approval =
            Approval::issue(&self.alice, &request, cert, doc, &|s| protocol.has_keys(s)).unwrap();
        JoinRequest {
            identity: self.alice.public(),
            keys: keys.clone(),
            request,
            approval: approval.to_json().unwrap(),
        }
    }

    pub(crate) async fn join(&self, name: &str) -> App {
        let request = self.approve(&app_keys(name), &["scope-a"]);
        App::join(self.env(), self.protocol.clone(), Self::config(), request)
            .await
            .unwrap()
    }

    pub(crate) async fn load(&self, app: [u8; 16]) -> App {
        App::load(self.env(), self.protocol.clone(), Self::config(), app)
            .await
            .unwrap()
    }

    /// A note from bob's app to `to`.
    pub(crate) fn note(&self, to: [u8; 16], text: &str) -> (u64, Message) {
        self.switch.send(
            &self.bob,
            &self.bob_keys,
            &self.bob_cert,
            "sample.note",
            json!({ "text": text }),
            &[to],
        )
    }

    /// How many conversation entries the switch applied: effects done.
    pub(crate) fn effects(&self) -> usize {
        self.switch
            .applied()
            .iter()
            .filter(|op| matches!(op.body().kind, OpKind::AllowPut { .. }))
            .count()
    }
}
