//! The signer side of a test identity, and what a protocol supplies: the documents an app
//! needs to join (`identity.json`, its certificate and the approval), built from the core's
//! types, and a protocol built from the caller's details.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::message::Message;
use pubky_switch_core::records::{
    AppCert, AppCertBody, AppRequest, AppRequestBody, Approval, AuthRequest,
    DEFAULT_CERT_LIFETIME_MS, IdentityBody, IdentityDoc, IdentityPolicy, Inbox, ListedApp,
    app_record_path,
};
use pubky_switch_core::scopes::Permission;

use super::{SWITCH_ORIGIN, ScriptError, ScriptedSwitch, TestHomeserver, TestIdentity};
use crate::app::{
    AppEnv, Collection, Effect, HomeserverReader, JoinRequest, LocalWrite, MissedEntries, Outcome,
    Protocol, ReceivedMessage, ResendNeeded,
};
use crate::clock::{Clock, TestClock};
use crate::store::{StateStore, StoreHandle};
use crate::transport::Transport;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What an app's certificate grants: its scopes and its switch permissions (Switch spec
/// 3.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppSpec {
    /// The certificate's scopes, as the protocol names them.
    pub scopes: Vec<String>,
    /// The certificate's switch permissions.
    pub permissions: Vec<Permission>,
}

impl AppSpec {
    /// A certificate with `scopes` and no switch permissions.
    pub fn new(scopes: &[&str]) -> Self {
        Self {
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            permissions: Vec::new(),
        }
    }

    /// The same, with `permissions`.
    #[must_use]
    pub fn with_permissions(mut self, permissions: &[Permission]) -> Self {
        self.permissions = permissions.to_vec();
        self
    }
}

/// The details a protocol supplies, which the Switch treats as opaque strings (Switch spec
/// 1): the scopes that have keys, the collections and their policies, and the kinds an
/// app's record accepts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProtocolSpec {
    /// The scopes with Shared Data Keys (Switch spec 3.5). A sub-scope (`<scope>:<sub>`) of
    /// a listed scope has keys too.
    pub keyed_scopes: Vec<String>,
    /// The protocol's collections, each with its fixed policy (Switch spec 10.3).
    pub collections: Vec<Collection>,
    /// The kinds an app's record lists in `accepts` (Switch spec 3.4).
    pub accepts: Vec<String>,
}

impl ProtocolSpec {
    /// Whether `scope` has Shared Data Keys: it is listed, or is a sub-scope of one listed.
    pub fn has_keys(&self, scope: &str) -> bool {
        self.keyed_scopes.iter().any(|keyed| {
            scope == keyed
                || scope
                    .strip_prefix(keyed.as_str())
                    .is_some_and(|rest| rest.starts_with(':'))
        })
    }
}

/// A certificate for the app with `keys`, issued by `identity` at `issued_at` with the
/// default lifetime, granting what `app` names.
///
/// # Errors
///
/// When the certificate doesn't sign.
pub fn issue_cert(
    identity: &IdentityKey,
    keys: &AppKeys,
    app: &AppSpec,
    issued_at: u64,
) -> Result<AppCert, ScriptError> {
    Ok(AppCert::issue(
        identity,
        AppCertBody::new(
            identity.public(),
            keys.signing_public(),
            keys.bundle_public(),
            app.scopes.clone(),
            &app.permissions,
            issued_at,
            issued_at.saturating_add(DEFAULT_CERT_LIFETIME_MS),
        ),
    )?)
}

/// The signer side of an identity whose account is at a [`ScriptedSwitch`]: it keeps the
/// newest `identity.json` body, signs each next version, delivers it to the switch and
/// publishes it on the [`TestHomeserver`], and approves apps to join.
///
/// The account's switch is created with it, under the identity's service key, and its
/// first `identity.json` names it at [`SWITCH_ORIGIN`], or at the origin
/// [`TestSigner::at`] gives. The first document is delivered with the first approval or
/// [`TestSigner::next_doc`].
///
/// Two signers at two origins, their switches routed by a [`super::Router`], let their
/// apps message each other: each switch answers the other identity's apps as a sender sees
/// it, with admission, peer copies, `stale_key` and invite codes.
pub struct TestSigner {
    identity: TestIdentity,
    origin: String,
    clock: Arc<TestClock>,
    homeserver: Arc<TestHomeserver>,
    switch: Arc<ScriptedSwitch>,
    spec: ProtocolSpec,
    body: Mutex<IdentityBody>,
}

impl std::fmt::Debug for TestSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TestSigner({:?}, version {})",
            self.identity,
            lock(&self.body).version
        )
    }
}

impl TestSigner {
    /// The signer of `identity`, with its account's switch; `spec` says which scopes have
    /// keys for the approvals.
    pub fn new(
        identity: TestIdentity,
        clock: Arc<TestClock>,
        homeserver: Arc<TestHomeserver>,
        spec: ProtocolSpec,
    ) -> Self {
        Self::at(identity, SWITCH_ORIGIN, clock, homeserver, spec)
    }

    /// The signer of `identity`, its account's switch named at `origin`, where a
    /// [`super::Router`] routes it.
    pub fn at(
        identity: TestIdentity,
        origin: &str,
        clock: Arc<TestClock>,
        homeserver: Arc<TestHomeserver>,
        spec: ProtocolSpec,
    ) -> Self {
        let switch = ScriptedSwitch::new(
            identity.key(),
            identity.service_secret(),
            Arc::clone(&clock),
        );
        let body = IdentityBody::first(
            identity.public(),
            identity.signer_id(),
            Inbox::new(origin, switch.service_key()),
            IdentityPolicy::default(),
        );
        Self {
            identity,
            origin: origin.to_owned(),
            clock,
            homeserver,
            switch,
            spec,
            body: Mutex::new(body),
        }
    }

    /// The identity.
    pub fn identity(&self) -> &TestIdentity {
        &self.identity
    }

    /// The origin its `identity.json` names for the account's switch.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The account's switch.
    pub fn switch(&self) -> &Arc<ScriptedSwitch> {
        &self.switch
    }

    /// The Homeserver it publishes on.
    pub fn homeserver(&self) -> &Arc<TestHomeserver> {
        &self.homeserver
    }

    /// The test clock.
    pub fn clock(&self) -> &Arc<TestClock> {
        &self.clock
    }

    /// The protocol details it approves with.
    pub fn spec(&self) -> &ProtocolSpec {
        &self.spec
    }

    /// The newest `identity.json` body, as signed or about to be.
    pub fn body(&self) -> IdentityBody {
        lock(&self.body).clone()
    }

    /// The next version of the `identity.json`, changed by `change`, delivered to the
    /// account's switch and published. The first call signs version 1.
    ///
    /// # Errors
    ///
    /// When the document doesn't sign or isn't taken.
    pub fn next_doc(
        &self,
        change: impl FnOnce(&mut IdentityBody),
    ) -> Result<IdentityDoc, ScriptError> {
        let mut body = lock(&self.body);
        if self.switch.identity_doc().is_some() {
            body.version += 1;
        }
        change(&mut body);
        let doc = IdentityDoc::sign(self.identity.key(), body.clone())?;
        self.switch.deliver_identity(&doc)?;
        self.homeserver.publish(&doc)?;
        Ok(doc)
    }

    /// The next version of the `identity.json`, changed by `change` and published, without
    /// delivering it to any switch: for a caller that delivers it elsewhere, as in a move.
    ///
    /// # Errors
    ///
    /// When the document doesn't sign.
    pub fn sign_next(
        &self,
        change: impl FnOnce(&mut IdentityBody),
    ) -> Result<IdentityDoc, ScriptError> {
        let mut body = lock(&self.body);
        body.version += 1;
        change(&mut body);
        let doc = IdentityDoc::sign(self.identity.key(), body.clone())?;
        self.homeserver.publish(&doc)?;
        Ok(doc)
    }

    /// The signer approves the app with `keys` for what `app` names, now: its certificate,
    /// the next `identity.json` listing it (delivered and published), and the approval, as
    /// the join request the app joins with.
    ///
    /// # Errors
    ///
    /// When a document doesn't sign or the approval isn't issued.
    pub fn approve(&self, keys: &AppKeys, app: &AppSpec) -> Result<JoinRequest, ScriptError> {
        let cert = issue_cert(self.identity.key(), keys, app, self.clock.now_ms())?;
        let auth = AuthRequest {
            client_id: "app.example".into(),
            client_key: [7; 32],
            caps: format!("{}:rw", app_record_path(&keys.app_id_bytes())),
            secret: [8; 32],
        };
        let request = AppRequest::sign(keys, AppRequestBody::new(keys, app.scopes.clone(), &auth))?;
        let doc = self.next_doc(|body| {
            body.apps.push(ListedApp {
                app_id: cert.app_id(),
                cert: cert.hash(),
            })
        })?;
        let approval = Approval::issue(self.identity.key(), &request, cert, doc, &|s| {
            self.spec.has_keys(s)
        })?;
        Ok(JoinRequest {
            identity: self.identity.public(),
            keys: keys.clone(),
            request,
            approval: approval.to_json()?,
        })
    }

    /// An app's environment on `store`, talking to the account's switch only.
    pub fn env(&self, store: Arc<dyn StateStore>) -> AppEnv {
        self.env_with(store, self.switch.transport())
    }

    /// An app's environment on `store`, talking through `transport`, such as a
    /// [`super::Router`].
    pub fn env_with(&self, store: Arc<dyn StateStore>, transport: Arc<dyn Transport>) -> AppEnv {
        AppEnv {
            store: StoreHandle::inline(store),
            transport,
            clock: Arc::clone(&self.clock) as Arc<dyn Clock>,
            homeserver: Arc::clone(&self.homeserver) as Arc<dyn HomeserverReader>,
        }
    }
}

/// A [`Protocol`] built from a [`ProtocolSpec`], for tests that need one without a
/// protocol of their own. It accepts the spec's kinds from any app, sends none between own
/// apps, and records every message it receives; a received message has no lasting effect
/// beyond the cursor move.
#[derive(Debug, Default)]
pub struct TestProtocol {
    spec: ProtocolSpec,
    received: Mutex<Vec<ReceivedMessage>>,
    resends: Mutex<Vec<ResendNeeded>>,
    missed: Mutex<Vec<MissedEntries>>,
}

impl TestProtocol {
    /// The protocol `spec` describes.
    pub fn new(spec: ProtocolSpec) -> Self {
        Self {
            spec,
            ..Self::default()
        }
    }

    /// The details it was built from.
    pub fn spec(&self) -> &ProtocolSpec {
        &self.spec
    }

    /// Every message received, in order.
    pub fn received(&self) -> Vec<ReceivedMessage> {
        lock(&self.received).clone()
    }

    /// Every re-send the app asked for, in order.
    pub fn resends(&self) -> Vec<ResendNeeded> {
        lock(&self.resends).clone()
    }

    /// Every `missed` item handed over, in order.
    pub fn missed_entries(&self) -> Vec<MissedEntries> {
        lock(&self.missed).clone()
    }
}

impl Protocol for TestProtocol {
    fn has_keys(&self, scope: &str) -> bool {
        self.spec.has_keys(scope)
    }

    fn sent_between_own_apps(&self, _kind: &str) -> bool {
        false
    }

    fn check_scopes(
        &self,
        message: &Message,
        _sender: &AppCert,
        _own: &AppCert,
    ) -> Result<(), String> {
        if self.spec.accepts.contains(&message.kind) {
            Ok(())
        } else {
            Err("test protocol: a kind it doesn't accept".into())
        }
    }

    fn accepts(&self, _cert: &AppCert) -> Vec<String> {
        self.spec.accepts.clone()
    }

    fn receive(&self, message: &ReceivedMessage) -> Outcome {
        lock(&self.received).push(message.clone());
        Outcome::Apply(Effect::default())
    }

    fn resend_needed(&self, needed: &ResendNeeded) -> Vec<LocalWrite> {
        lock(&self.resends).push(needed.clone());
        Vec::new()
    }

    fn missed(&self, missed: &MissedEntries) -> Vec<LocalWrite> {
        lock(&self.missed).push(missed.clone());
        Vec::new()
    }

    fn collections(&self) -> Vec<Collection> {
        self.spec.collections.clone()
    }
}
