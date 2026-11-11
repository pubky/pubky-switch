//! Test support: a scripted Switch and the fixtures to drive the app layer against it, for
//! the tests of this crate, of the signer, and of a protocol built on the Switch.
//!
//! **For tests only.** This module exists only with the `test-support` feature, which is not
//! a default feature and which no production build enables. Its keys come from fixed
//! seeds, its randomness is not to be relied on, and it keeps everything in memory.
//!
//! The scripted switch models the switch's answers as the spec gives them (Switch wire 7.4):
//! every answer, head, transition proof and service transition is built from the core's
//! types and signed with a real service key, so the client checks them as it checks a
//! service's. Every batch, submitted or injected, goes through the core's rules (Switch wire
//! 6.4). It is no substitute for the service: `FAKES.md`, next to this module, lists what it
//! fakes or leaves out, such as quotas, rates, trusted time, retention and durability.
//!
//! - [`ScriptedSwitch`]: one account's switch, its chain, feed, directory and shared state,
//!   with [`Fault`]s to inject. Apps of other identities reach its inbox as senders do:
//!   admission by the lists and invite codes, the directory with `known_version`, peer copies
//!   of their `identity.json`, connect requests, `identity_needed` and `stale_key`. A claim
//!   read (`GET /claims/{claim_key}`) answers with the claim view and its entries, each with
//!   its step, `seq`, signed operation and transition proof, none for a tombstone (Switch
//!   wire 7.4.8).
//! - [`PeerSwitch`]: another identity's switch, as a sender sees it: its directory, inbox
//!   and peer copies of `identity.json`.
//! - [`Router`]: a [`crate::transport::Transport`] that sends each request to the switch of
//!   its origin.
//! - [`TestHomeserver`]: the public files an app reads, `identity.json` among them.
//! - [`Seeds`] and [`TestIdentity`]: deterministic keys from a seed prefix and labels.
//! - [`TestSigner`]: the signer side of an identity whose account is at a
//!   [`ScriptedSwitch`]: its `identity.json` versions, certificates and approvals, for an
//!   app to join with. Two signers at two origins ([`TestSigner::at`]), routed by a
//!   [`Router`], let their apps message each other.
//! - [`ProtocolSpec`], [`AppSpec`] and [`TestProtocol`]: what a protocol supplies, given by
//!   the caller, and a [`crate::app::Protocol`] built from it that records what it receives.
//!
//! Nothing here names a protocol: scopes, kinds and collections all come from the caller.
//!
//! ```
//! use std::sync::Arc;
//!
//! use pubky_switch_client::app::{App, AppConfig};
//! use pubky_switch_client::clock::TestClock;
//! use pubky_switch_client::store::{MemoryStore, StateStore};
//! use pubky_switch_client::testing::{
//!     AppSpec, ProtocolSpec, START_MS, Seeds, TestHomeserver, TestIdentity, TestProtocol,
//!     TestSigner,
//! };
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let seeds = Seeds::default();
//! let clock = Arc::new(TestClock::new(START_MS));
//! let homeserver = Arc::new(TestHomeserver::new());
//! let spec = ProtocolSpec {
//!     keyed_scopes: vec!["notes".into()],
//!     accepts: vec!["example.note".into()],
//!     ..ProtocolSpec::default()
//! };
//! let alice = TestSigner::new(
//!     TestIdentity::new(&seeds, "alice"),
//!     Arc::clone(&clock),
//!     Arc::clone(&homeserver),
//!     spec.clone(),
//! );
//! let keys = alice.identity().app_keys("wallet");
//! let request = alice.approve(&keys, &AppSpec::new(&["notes"]))?;
//! let store = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
//! let protocol = Arc::new(TestProtocol::new(spec));
//! let app = App::join(alice.env(store), protocol, AppConfig::default(), request).await?;
//! assert!(alice.switch().app(&app.app_id()).receive_key.is_some());
//! # Ok(())
//! # }
//! ```

mod fixture;
mod homeserver;
mod peer;
mod router;
mod switch;

pub use fixture::{AppSpec, ProtocolSpec, TestProtocol, TestSigner, issue_cert};
pub use homeserver::TestHomeserver;
pub use peer::{PEER_ORIGIN, PeerApp, PeerSwitch};
pub use router::Router;
pub use switch::{Fault, HeldRecord, MAX_PAGE_BYTES, SWITCH_ORIGIN, ScriptedSwitch, SwitchApp};

#[cfg(test)]
pub(crate) use switch::{Item, PushReg};

/// A [`RestoreContext`](crate::app::RestoreContext) for a protocol's own tests of its
/// [`Protocol::restore_layer`](crate::app::Protocol::restore_layer): the identity, App ID,
/// naming key and certificate of a backup the test builds, as [`crate::app::App::restore`]
/// passes them once it has checked the certificate ([`issue_cert`] builds one).
pub fn restore_context<'a>(
    identity: [u8; 32],
    app_id: [u8; 16],
    naming: &'a pubky_switch_core::ident::NamingKey,
    cert: &'a pubky_switch_core::records::AppCert,
) -> crate::app::RestoreContext<'a> {
    crate::app::RestoreContext::new(identity, app_id, naming, cert)
}

use pubky_switch_core::keys::{AppKeys, IdentityKey, ReceiveKey};

/// The time test clocks start at by default: 2026-01-01T00:00:00Z, in Unix milliseconds.
pub const START_MS: u64 = 1_767_225_600_000;

/// The default prefix of [`Seeds`]: a seed is `BLAKE3(prefix + label)`.
pub const TEST_SEED_PREFIX: &str = "pubky-switch/test/";

/// A failure of the test support itself: a document that doesn't sign, or scripted state
/// that lacks what a call needs.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScriptError {
    /// A core operation failed: a document that doesn't sign, seal or read.
    #[error("core: {0}")]
    Core(#[from] pubky_switch_core::Error),
    /// A document that doesn't serialize.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// The scripted state lacks what the call needs, such as an app without a receive key.
    #[error("missing: {0}")]
    Missing(String),
    /// The scripted switch refused an injected batch, as it would the same batch submitted:
    /// the answer's status and error body (Switch wire 7.6).
    #[error("refused with {status}")]
    Refused {
        /// The HTTP status.
        status: u16,
        /// The error body.
        body: serde_json::Value,
    },
}

/// Deterministic secrets: `BLAKE3(prefix + label)`, so a test's keys are the same on every
/// run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seeds {
    prefix: String,
}

impl Default for Seeds {
    /// Seeds under [`TEST_SEED_PREFIX`].
    fn default() -> Self {
        Self::new(TEST_SEED_PREFIX)
    }
}

impl Seeds {
    /// Seeds under `prefix`.
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_owned(),
        }
    }

    /// The prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The secret for `label`: `BLAKE3(prefix + label)`.
    pub fn seed(&self, label: &str) -> [u8; 32] {
        *blake3::hash(format!("{}{label}", self.prefix).as_bytes()).as_bytes()
    }
}

/// A named identity with deterministic keys: every secret is a seed labelled
/// `<name>/<what>`, and the service key of its account is `service/<name>`.
pub struct TestIdentity {
    name: String,
    seeds: Seeds,
    key: IdentityKey,
}

impl Clone for TestIdentity {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            seeds: self.seeds.clone(),
            key: IdentityKey::from_secret(self.key.secret_bytes()),
        }
    }
}

impl std::fmt::Debug for TestIdentity {
    // The name and public key only; never the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TestIdentity({}, {})", self.name, self.key.id())
    }
}

impl TestIdentity {
    /// The identity `name`, its key from the seed `<name>/identity`.
    pub fn new(seeds: &Seeds, name: &str) -> Self {
        Self {
            name: name.to_owned(),
            seeds: seeds.clone(),
            key: IdentityKey::from_secret(seeds.seed(&format!("{name}/identity"))),
        }
    }

    /// The name its seeds are labelled with.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The seeds it draws from.
    pub fn seeds(&self) -> &Seeds {
        &self.seeds
    }

    /// The identity key.
    pub fn key(&self) -> &IdentityKey {
        &self.key
    }

    /// The identity's public key.
    pub fn public(&self) -> [u8; 32] {
        self.key.public()
    }

    /// The seed labelled `<name>/<label>`.
    pub fn seed(&self, label: &str) -> [u8; 32] {
        self.seeds.seed(&format!("{}/{label}", self.name))
    }

    /// The keys of its app `app`: seeds `<name>/<app>/signing` and `<name>/<app>/bundle`.
    pub fn app_keys(&self, app: &str) -> AppKeys {
        AppKeys::from_secrets(
            self.seed(&format!("{app}/signing")),
            self.seed(&format!("{app}/bundle")),
        )
    }

    /// Receive key `n` of its app `app`: seed `<name>/<app>/receive/<n>`.
    pub fn receive_key(&self, app: &str, n: u64) -> ReceiveKey {
        ReceiveKey::from_secret(n, self.seed(&format!("{app}/receive/{n}")))
    }

    /// The secret of its account's service key: seed `service/<name>`.
    pub fn service_secret(&self) -> [u8; 32] {
        self.seeds.seed(&format!("service/{}", self.name))
    }

    /// The signer install ID its `identity.json` names: the first 16 bytes of the seed
    /// `<name>/signer`.
    pub fn signer_id(&self) -> [u8; 16] {
        let seed = self.seed("signer");
        let mut id = [0; 16];
        id.copy_from_slice(&seed[..16]);
        id
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pubky_switch_core::http::header;
    use serde_json::json;

    use super::*;
    use crate::clock::TestClock;
    use crate::error::TransportError;
    use crate::transport::{Request, Transport};

    #[test]
    fn test_scripted_error_body_omits_an_absent_current() {
        // Switch wire, Conventions, "Absent and null": a writer omits an absent member.
        let (_, body) = switch::bad(
            pubky_switch_core::http::ErrorCode::NotFound,
            "x",
            serde_json::Value::Null,
        );
        assert!(body.get("current").is_none(), "{body}");
        let (_, body) = switch::bad(
            pubky_switch_core::http::ErrorCode::Conflict,
            "x",
            json!({ "server_time": 1 }),
        );
        assert_eq!(body["current"], json!({ "server_time": 1 }));
    }

    #[test]
    fn test_scripted_versions_start_at_zero_as_the_services() {
        let identity = pubky_switch_core::keys::IdentityKey::from_secret([3; 32]);
        let switch = ScriptedSwitch::new(&identity, [4; 32], Arc::new(TestClock::new(0)));
        assert_eq!(switch.apps_version(), 0);
        assert_eq!(switch.lock().directory_version, 0);
    }

    #[test]
    fn test_scripted_peer_answers_as_the_service_without_current_or_versions() {
        // Switch wire 7.6: `not_admitted` carries no `current`, and an absent one is left
        // out; both versions start at 0 (Switch wire 7.4.10).
        let (_, body) = peer::bad(
            pubky_switch_core::http::ErrorCode::NotAdmitted,
            serde_json::Value::Null,
        );
        assert!(body.get("current").is_none(), "{body}");
        let seeds = Seeds::default();
        let peer = PeerSwitch::new(
            TestIdentity::new(&seeds, "bob"),
            PEER_ORIGIN,
            Arc::new(TestClock::new(START_MS)),
            Arc::new(TestHomeserver::new()),
        );
        let inner = peer.lock();
        assert_eq!((inner.apps_version, inner.directory_version), (0, 0));
    }

    #[test]
    fn test_scripted_switch_second_leave_is_not_current_without_current() {
        // Switch wire 7.6: `403 not_current` carries no `current`.
        let seeds = Seeds::default();
        let signer = TestSigner::new(
            TestIdentity::new(&seeds, "alice"),
            Arc::new(TestClock::new(START_MS)),
            Arc::new(TestHomeserver::new()),
            ProtocolSpec::default(),
        );
        let keys = signer.identity().app_keys("phone");
        signer
            .register_app(&keys, &AppSpec::new(&["notes"]))
            .unwrap();
        let app = pubky_switch_core::enc::zbase32_encode(&keys.app_id_bytes());
        let path = format!("/v1/{}/apps/{app}/leave", signer.identity().key().id());
        let mut leave = request(SWITCH_ORIGIN, &path);
        leave.method = "POST".into();
        leave
            .headers
            .push(crate::transport::Header::new(header::APP, &app));
        assert_eq!(signer.switch().handle(&leave).unwrap().status, 200);
        let again = signer.switch().handle(&leave).unwrap();
        assert_eq!(again.status, 403);
        let body: serde_json::Value = serde_json::from_slice(&again.body).unwrap();
        assert_eq!(body["code"], "not_current");
        assert!(body.get("current").is_none(), "{body}");
    }

    #[test]
    fn test_scripted_switch_key_change_in_place_serves_at_its_origin_only() {
        // Switch wire 3.7, 7.3 step 7: a staged account serves once the newest
        // `identity.json` names its origin and its service key; a key change in place keeps
        // the origin.
        use pubky_switch_core::records::{IdentityBody, IdentityDoc, IdentityPolicy, Inbox};
        let seeds = Seeds::default();
        let alice = TestIdentity::new(&seeds, "alice");
        let origin = "https://other-switch.example";
        let clock = Arc::new(TestClock::new(START_MS));
        let switch = ScriptedSwitch::unenrolled_at(alice.key(), [4; 32], clock, origin);
        let changed = switch.change_key_into([5; 32]);
        let doc = |url: &str, version: u64| {
            let mut body = IdentityBody::first(
                alice.public(),
                alice.signer_id(),
                Inbox::new(url, changed.service_key()),
                IdentityPolicy::default(),
            );
            body.version = version;
            IdentityDoc::sign(alice.key(), body).unwrap()
        };
        changed.deliver_identity(&doc(SWITCH_ORIGIN, 1)).unwrap();
        assert!(changed.lock().staged, "another origin");
        changed.deliver_identity(&doc(origin, 2)).unwrap();
        assert!(!changed.lock().staged);
    }

    #[test]
    fn test_scripted_switch_directory_lists_apps_in_the_documents_order() {
        // Switch wire 7.4.10: the current apps, in the order the newest identity.json lists
        // them, not by App ID.
        let seeds = Seeds::default();
        let signer = TestSigner::new(
            TestIdentity::new(&seeds, "alice"),
            Arc::new(TestClock::new(START_MS)),
            Arc::new(TestHomeserver::new()),
            ProtocolSpec::default(),
        );
        let mut keys: Vec<_> = ["one", "two", "three"]
            .iter()
            .map(|name| signer.identity().app_keys(name))
            .collect();
        // Registered, and so listed, in descending App ID order.
        keys.sort_by_key(|keys| std::cmp::Reverse(keys.app_id_bytes()));
        for app in &keys {
            signer.register_app(app, &AppSpec::new(&["notes"])).unwrap();
        }
        let path = format!("/v1/{}/directory", signer.identity().key().id());
        let answer = signer
            .switch()
            .handle(&request(SWITCH_ORIGIN, &path))
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&answer.body).unwrap();
        let shown: Vec<&str> = body["apps"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|app| app["app_id"].as_str())
            .collect();
        let listed: Vec<String> = keys
            .iter()
            .map(|keys| pubky_switch_core::enc::zbase32_encode(&keys.app_id_bytes()))
            .collect();
        assert_eq!(shown, listed);
    }

    fn request(origin: &str, path: &str) -> Request {
        Request {
            method: "GET".into(),
            origin: origin.into(),
            path_and_query: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[test]
    fn test_seeds_follow_the_prefix_and_label() {
        let seeds = Seeds::default();
        assert_eq!(seeds.prefix(), TEST_SEED_PREFIX);
        assert_eq!(
            seeds.seed("alice/identity"),
            *blake3::hash(b"pubky-switch/test/alice/identity").as_bytes()
        );
        assert_ne!(
            Seeds::new("other/").seed("alice/identity"),
            seeds.seed("alice/identity")
        );
        let alice = TestIdentity::new(&seeds, "alice");
        assert_eq!(
            alice.key().secret_bytes(),
            seeds.seed("alice/identity"),
            "the identity key is the seed alice/identity"
        );
        assert_eq!(alice.service_secret(), seeds.seed("service/alice"));
        assert_eq!(alice.clone().public(), alice.public());
    }

    #[test]
    fn test_protocol_spec_keys_listed_scopes_and_their_sub_scopes_only() {
        let spec = ProtocolSpec {
            keyed_scopes: vec!["notes".into()],
            ..ProtocolSpec::default()
        };
        assert!(spec.has_keys("notes"));
        assert!(spec.has_keys("notes:one"));
        assert!(!spec.has_keys("notes-other"));
        assert!(!spec.has_keys("other"));
    }

    #[test]
    fn test_scripted_switch_send_to_an_app_without_a_receive_key_fails() {
        let seeds = Seeds::default();
        let alice = TestIdentity::new(&seeds, "alice");
        let bob = TestIdentity::new(&seeds, "bob");
        let clock = Arc::new(TestClock::new(START_MS));
        let switch = ScriptedSwitch::new(alice.key(), alice.service_secret(), clock);
        let keys = bob.app_keys("shop");
        let cert = issue_cert(bob.key(), &keys, &AppSpec::new(&["notes"]), START_MS).unwrap();
        let sent = switch.send(
            bob.key(),
            &keys,
            &cert,
            "example.note",
            json!({}),
            &[[1; 16]],
        );
        assert!(matches!(sent, Err(ScriptError::Missing(_))), "{sent:?}");
        assert_eq!(switch.seq(), 0);
    }

    #[test]
    fn test_scripted_switch_signs_answers_and_applies_faults_once() {
        let seeds = Seeds::default();
        let alice = TestIdentity::new(&seeds, "alice");
        let clock = Arc::new(TestClock::new(START_MS));
        let switch = ScriptedSwitch::new(alice.key(), alice.service_secret(), clock);
        let path = format!("/v1/{}/directory", alice.key().id());
        switch.fail_next(Fault::Error {
            path: "directory".into(),
            code: pubky_switch_core::http::ErrorCode::Unavailable,
            current: json!(null),
        });
        let failed = switch.handle(&request(SWITCH_ORIGIN, &path)).unwrap();
        assert_eq!(failed.status, 503);
        let answered = switch.handle(&request(SWITCH_ORIGIN, &path)).unwrap();
        assert_eq!(answered.status, 200);
        assert!(answered.header(header::SERVICE_SIGNATURE).is_some());
    }

    #[test]
    fn test_scripted_switch_batch_retry_and_no_op_follow_the_core() {
        use pubky_switch_core::ops::{OpKind, OpsRequest, sign_batch};
        use pubky_switch_core::records::{AppRecord, AppRecordBody};
        use pubky_switch_core::scopes::Permission;

        use crate::clock::Clock;
        use crate::transport::Header;

        let seeds = Seeds::default();
        let clock = Arc::new(TestClock::new(START_MS));
        let signer = TestSigner::new(
            TestIdentity::new(&seeds, "alice"),
            Arc::clone(&clock),
            Arc::new(TestHomeserver::new()),
            ProtocolSpec::default(),
        );
        let switch = signer.switch();
        let alice = signer.identity().public();
        let keys = signer.identity().app_keys("phone");
        let spec = AppSpec::new(&["notes"]).with_permissions(&Permission::ALL);
        let cert = signer.register_app(&keys, &spec).unwrap();
        let post = |kinds: Vec<OpKind>, id: [u8; 16]| {
            let ops = sign_batch(&keys, &alice, Some(keys.app_id_bytes()), 1, id, {
                kinds.into_iter().map(|kind| (vec![], kind)).collect()
            })
            .unwrap();
            let mut request = request(
                SWITCH_ORIGIN,
                &format!("/v1/{}/ops", signer.identity().key().id()),
            );
            request.method = "POST".into();
            request.headers.push(Header::new(
                header::APP,
                &pubky_switch_core::enc::zbase32_encode(&keys.app_id_bytes()),
            ));
            request.body = OpsRequest::new(&ops, None).to_json();
            let answer = switch.handle(&request).unwrap();
            let body: serde_json::Value = serde_json::from_slice(&answer.body).unwrap();
            (answer.status, body)
        };
        let deny = |pubky| OpKind::DenyPut { pubky };
        let (status, first) = post(vec![deny([1; 32])], [1; 16]);
        assert_eq!(
            (status, first["proofs"].as_array().map(Vec::len)),
            (200, Some(1))
        );
        let seq = switch.seq();
        // A retry gets the original proofs; other operations under the same ID are refused.
        let (status, again) = post(vec![deny([1; 32])], [1; 16]);
        assert_eq!((status, &again["proofs"]), (200, &first["proofs"]));
        let (status, other) = post(vec![deny([2; 32])], [1; 16]);
        assert_eq!((status, other["code"].as_str()), (409, Some("conflict")));
        // The record the switch holds, again: a no-op, which chains nothing.
        let record = switch.app(&keys.app_id_bytes()).record.unwrap();
        let (status, noop) = post(vec![OpKind::AppPut { record }], [2; 16]);
        assert_eq!(
            (status, noop["proofs"].as_array().map(Vec::len)),
            (200, Some(0))
        );
        assert_eq!(switch.seq(), seq);
        // A later record is applied.
        clock.advance_ms(1000);
        let later =
            AppRecord::sign(&keys, AppRecordBody::new(&cert, vec![], clock.now_ms())).unwrap();
        let later = OpKind::AppPut {
            record: later.signed().clone(),
        };
        assert_eq!(post(vec![later], [3; 16]).0, 200);
        assert_eq!(switch.seq(), seq + 1);
    }

    #[tokio::test]
    async fn test_router_sends_by_origin_and_fails_to_connect_elsewhere() {
        let seeds = Seeds::default();
        let alice = TestIdentity::new(&seeds, "alice");
        let clock = Arc::new(TestClock::new(START_MS));
        let switch = ScriptedSwitch::new(alice.key(), alice.service_secret(), clock);
        let router = Router::new();
        router.add_switch(SWITCH_ORIGIN, &switch);
        let path = format!("/v1/{}/directory", alice.key().id());
        let answer = router.send(request(SWITCH_ORIGIN, &path)).await.unwrap();
        assert_eq!(answer.status, 200);
        let error = router.send(request(PEER_ORIGIN, &path)).await.unwrap_err();
        assert!(matches!(error, TransportError::Connect(_)), "{error:?}");
        router.remove(SWITCH_ORIGIN);
        assert!(router.send(request(SWITCH_ORIGIN, &path)).await.is_err());
        assert_eq!(router.log().len(), 3);
    }

    #[test]
    fn test_peer_switch_publishes_its_apps_and_refuses_an_unknown_rotation() {
        let seeds = Seeds::default();
        let clock = Arc::new(TestClock::new(START_MS));
        let homeserver = Arc::new(TestHomeserver::new());
        let bob = TestIdentity::new(&seeds, "bob");
        let peer = PeerSwitch::new(bob.clone(), PEER_ORIGIN, clock, Arc::clone(&homeserver));
        let shop = peer
            .add_app("shop", &AppSpec::new(&["notes"]), &["example.note"], false)
            .unwrap();
        let doc = homeserver.identity_doc(&bob.public()).unwrap();
        assert!(doc.listed_cert(&shop).is_some());
        assert!(peer.rotate(0).is_ok());
        assert_eq!(peer.apps()[0].receive_keys.len(), 2);
        assert!(matches!(peer.rotate(1), Err(ScriptError::Missing(_))));
    }
}
