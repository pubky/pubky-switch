//! The app layer's flow tests, against the scripted switch of [`crate::testing`], its
//! Homeserver, and a neutral sample protocol. Keys come from the test seeds.

mod flows;
mod forget;
mod kept_status;
mod moves;
mod not_registered;
mod own_record;
mod parked;
mod passed;
mod protocol_api;
mod protocol_reads;
mod push;
mod sender_document;
mod sender_key;
mod shared_flows;
mod store_failures;
mod unverified;
mod uploads;
mod writer_certs;

use std::sync::{Arc, Mutex};

use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::message::Message;
use pubky_switch_core::ops::{AllowKind, OpKind};
use pubky_switch_core::records::{
    AppCert, IdentityBody, IdentityDoc, IdentityPolicy, Inbox, ListedApp,
};
use pubky_switch_core::scopes::Permission;
use serde_json::{Value, json};

use super::{
    App, AppConfig, AppEnv, Effect, JoinRequest, LocalWrite, MissedEntries, Outcome, Protocol,
    ReceivedMessage, ResendNeeded,
};
use crate::clock::{Clock, TestClock};
use crate::store::{MemoryStore, StateStore};
use crate::testing::{
    AppSpec, PEER_ORIGIN, ProtocolSpec, ScriptedSwitch, Seeds, TestHomeserver, TestIdentity,
    TestSigner, issue_cert,
};

/// 2026-01-01T00:00:00Z.
pub(crate) const START: u64 = crate::testing::START_MS;

/// A fixed secret of the test seeds.
pub(crate) fn seed(label: &str) -> [u8; 32] {
    Seeds::default().seed(label)
}

/// A test identity of the default seeds.
pub(crate) fn identity(name: &str) -> TestIdentity {
    TestIdentity::new(&Seeds::default(), name)
}

/// The keys of alice's app `name`.
pub(crate) fn app_keys(name: &str) -> AppKeys {
    identity("alice").app_keys(name)
}

/// What the signer needs of the sample protocol: `scope-a` has keys.
pub(crate) fn sample_spec() -> ProtocolSpec {
    ProtocolSpec {
        keyed_scopes: vec!["scope-a".into()],
        ..ProtocolSpec::default()
    }
}

/// A neutral protocol: scope `scope-a` has keys and sends and receives `sample.note`;
/// `sample.notice` goes between own apps. A note writes a conversation entry for its sender
/// with the cursor move, and keeps its text locally.
#[derive(Default)]
pub(crate) struct SampleProtocol {
    pub(crate) received: Mutex<Vec<(u64, String, bool)>>,
    pub(crate) resends: Mutex<Vec<ResendNeeded>>,
    pub(crate) missed: Mutex<Vec<MissedEntries>>,
    /// How many of the next re-send and missed calls fail, as when the protocol can't read
    /// its own state.
    pub(crate) failing: Mutex<u32>,
    /// The `seq`s of missed items whose call always fails.
    pub(crate) failing_missed: Mutex<Vec<u64>>,
}

impl SampleProtocol {
    /// Whether this call fails, counting it down.
    fn fails(&self) -> bool {
        let mut failing = self.failing.lock().unwrap();
        let fails = *failing > 0;
        *failing = failing.saturating_sub(1);
        fails
    }
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

    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        match message.message.body.get("text") {
            Some(Value::String(_)) => Ok(()),
            _ => Err("sample: body.text isn't text".into()),
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

    fn resend_needed(
        &self,
        needed: &ResendNeeded,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        if self.fails() {
            return Err(crate::error::StoreError::Unavailable.into());
        }
        self.resends.lock().unwrap().push(needed.clone());
        Ok(vec![LocalWrite::Put {
            key: format!("resend/{}", needed.accepted_from_ms).into_bytes(),
            value: b"1".to_vec(),
        }])
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        if self.failing_missed.lock().unwrap().contains(&missed.seq) || self.fails() {
            return Err(crate::error::StoreError::Unavailable.into());
        }
        self.missed.lock().unwrap().push(missed.clone());
        Ok(vec![LocalWrite::Put {
            key: format!("missed/{}", missed.seq).into_bytes(),
            value: b"1".to_vec(),
        }])
    }
}

/// Alice's account, bob as her counterparty, and the signer's documents.
pub(crate) struct World {
    pub(crate) clock: Arc<TestClock>,
    pub(crate) alice: IdentityKey,
    pub(crate) bob: IdentityKey,
    pub(crate) bob_keys: AppKeys,
    pub(crate) bob_cert: AppCert,
    /// Alice's signer, with her account's switch.
    pub(crate) signer: TestSigner,
    pub(crate) switch: Arc<ScriptedSwitch>,
    pub(crate) homeserver: Arc<TestHomeserver>,
    pub(crate) store: Arc<MemoryStore>,
    pub(crate) protocol: Arc<SampleProtocol>,
}

/// A certificate for `keys` with `scopes` and `conversation.add`, as [`World::approve`]
/// grants.
pub(crate) fn cert_for(
    identity: &IdentityKey,
    keys: &AppKeys,
    issued: u64,
    scopes: &[&str],
) -> AppCert {
    issue_cert(identity, keys, &sample_app(scopes), issued).unwrap()
}

/// What the sample protocol's apps are approved for: `scopes`, and `conversation.add` for its
/// conversation entries.
pub(crate) fn sample_app(scopes: &[&str]) -> AppSpec {
    AppSpec::new(scopes).with_permissions(&[Permission::ConversationAdd])
}

impl World {
    pub(crate) fn new() -> Self {
        let clock = Arc::new(TestClock::new(START));
        let alice = identity("alice");
        let bob = identity("bob");
        let bob_keys = bob.app_keys("shop");
        let bob_cert = cert_for(bob.key(), &bob_keys, START - 1000, &["scope-a"]);
        let homeserver = Arc::new(TestHomeserver::new());
        let mut bob_body = IdentityBody::first(
            bob.public(),
            bob.signer_id(),
            Inbox::new(PEER_ORIGIN, [3; 32]),
            IdentityPolicy::default(),
        );
        bob_body.apps.push(ListedApp {
            app_id: bob_cert.app_id(),
            cert: bob_cert.hash(),
        });
        homeserver
            .publish(&IdentityDoc::sign(bob.key(), bob_body).unwrap())
            .unwrap();
        let signer = TestSigner::new(
            alice.clone(),
            Arc::clone(&clock),
            Arc::clone(&homeserver),
            sample_spec(),
        );
        Self {
            clock,
            alice: IdentityKey::from_secret(alice.key().secret_bytes()),
            bob: IdentityKey::from_secret(bob.key().secret_bytes()),
            bob_keys,
            bob_cert,
            switch: Arc::clone(signer.switch()),
            signer,
            homeserver,
            store: Arc::new(MemoryStore::new()),
            protocol: Arc::new(SampleProtocol::default()),
        }
    }

    pub(crate) fn env_on(&self, store: Arc<dyn StateStore>) -> AppEnv {
        self.signer.env(store)
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
        self.signer.next_doc(change).unwrap()
    }

    /// The signer approves `keys` for [`sample_app`] with `scopes`: a certificate, the
    /// document that lists it, and the approval.
    pub(crate) fn approve(&self, keys: &AppKeys, scopes: &[&str]) -> JoinRequest {
        self.signer.approve(keys, &sample_app(scopes)).unwrap()
    }

    /// Another own app, `name`, listed and registered at the switch with `permissions`, as
    /// another device of the account: for operations a test injects with
    /// [`ScriptedSwitch::app_op`].
    pub(crate) fn other_app(&self, name: &str, permissions: &[Permission]) -> AppKeys {
        let keys = app_keys(name);
        let spec = AppSpec::new(&["scope-a"]).with_permissions(permissions);
        self.signer.register_app(&keys, &spec).unwrap();
        keys
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
        self.switch
            .send(
                &self.bob,
                &self.bob_keys,
                &self.bob_cert,
                "sample.note",
                json!({ "text": text }),
                &[to],
            )
            .unwrap()
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

/// What the tests read of the entries stored locally, by the `seq` each was read at.
impl App {
    /// The entry stored locally that was read at `seq`.
    pub(crate) fn stored_at(&self, seq: u64) -> Option<&crate::app::state::ParkedEntry> {
        self.state.parked.values().find(|entry| entry.seq == seq)
    }

    /// The local ID of the entry stored locally that was read at `seq`.
    pub(crate) fn stored_id_at(&self, seq: u64) -> Option<u64> {
        self.state
            .parked
            .iter()
            .find(|(_, entry)| entry.seq == seq)
            .map(|(id, _)| *id)
    }

    /// The `seq`s the entries stored locally were read at, in local ID order.
    pub(crate) fn stored_seqs(&self) -> Vec<u64> {
        self.state.parked.values().map(|entry| entry.seq).collect()
    }

    /// The reads in a row the store kept the entry read at `seq` from finishing, whether it
    /// is on the feed or stored locally.
    pub(crate) fn retry_reads_at(&self, seq: u64) -> Option<u32> {
        let stored = self
            .stored_id_at(seq)
            .and_then(|id| self.state.stored_retries.get(&id));
        stored
            .or_else(|| self.state.retries.get(&seq))
            .map(|retry| retry.reads)
    }

    /// Whether no count of the store's retries is kept, for entries on the feed or stored.
    pub(crate) fn no_retries(&self) -> bool {
        self.state.retries.is_empty() && self.state.stored_retries.is_empty()
    }
}
