//! Another identity's switch, as a sender sees it: the account at another origin, with its
//! apps' records and receive keys, its inbox and the peer copies of other identities'
//! `identity.json` (Switch wire 7.4.3, 7.4.5, 7.4.7, 7.4.10). It checks what a sender relies
//! on: admission, the sender's listing in the copy it holds, the targets' current keys and
//! the `apps_version`, and retries by content.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use ed25519_dalek::SigningKey;
use pubky_switch_core::enc::{app_id_decode, b64, pubky_key, zbase32_encode};
use pubky_switch_core::envelope::parse_header;
use pubky_switch_core::http::{ErrorCode, header, request_signature_of, sign_response};
use pubky_switch_core::keys::{AppKeys, ReceiveKey};
use pubky_switch_core::message::{Message, MessagePlaintext};
use pubky_switch_core::records::{
    AppCert, AppRecord, AppRecordBody, IdentityBody, IdentityDoc, IdentityPolicy, Inbox, ListedApp,
    ReceiveKeyBody, ReceiveKeyRecord,
};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::rfc3339;
use serde_json::{Value, json};

use super::{AppSpec, ScriptError, ScriptedSwitch, TestHomeserver, TestIdentity, issue_cert};
use crate::clock::{Clock, TestClock};
use crate::error::TransportError;
use crate::transport::{BoxFuture, Header, Request, Response, Transport};

/// The origin a [`PeerSwitch`] is reached at, unless a test routes another one to it.
pub const PEER_ORIGIN: &str = "https://other.example";

/// One app of the peer identity.
#[derive(Clone, Debug)]
pub struct PeerApp {
    /// Its static keys.
    pub keys: AppKeys,
    /// Its certificate.
    pub cert: AppCert,
    /// Its app record (signed).
    pub record: SignedDoc,
    /// Every receive key with its signed record, the current one last.
    pub receive_keys: Vec<(ReceiveKey, SignedDoc)>,
    /// The `apps_version` at which it became reachable.
    pub since: u64,
}

/// One accepted entry.
#[derive(Clone)]
pub(crate) struct Appended {
    pub(crate) envelope: Vec<u8>,
}

pub(crate) struct PeerInner {
    pub(crate) identity: TestIdentity,
    pub(crate) service: SigningKey,
    pub(crate) clock: Arc<TestClock>,
    pub(crate) homeserver: Arc<TestHomeserver>,
    pub(crate) body: IdentityBody,
    pub(crate) apps: Vec<PeerApp>,
    pub(crate) apps_version: u64,
    pub(crate) directory_version: u64,
    pub(crate) inbox: Vec<Appended>,
    answered: HashMap<Vec<u8>, Value>,
    /// The peer copies of other identities' `identity.json`.
    pub(crate) peers: HashMap<[u8; 32], IdentityDoc>,
    /// Admitted senders; `None` admits every sender.
    pub(crate) admitted: Option<HashSet<[u8; 32]>>,
    /// Invite codes and their uses left.
    pub(crate) codes: HashMap<String, u64>,
    pub(crate) connects: Vec<[u8; 32]>,
    pub(crate) faults: VecDeque<(String, ErrorCode, Value)>,
    /// Every request, as (method, route).
    pub(crate) requests: Vec<(String, String)>,
    pub(crate) down: bool,
    /// Every answer is `503 staged`, as at an account recovering from a provider loss.
    pub(crate) staged: bool,
    /// Answers are signed with this key in place of the service key, as by a switch whose
    /// key no document names.
    pub(crate) foreign: Option<SigningKey>,
}

/// The switch of another identity, the counterparty a sending app writes to.
///
/// It publishes the identity's `identity.json` on the [`TestHomeserver`] each time an app
/// is added, and opens what its inbox accepts with the apps' receive keys.
pub struct PeerSwitch {
    inner: Mutex<PeerInner>,
}

impl std::fmt::Debug for PeerSwitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.lock();
        write!(
            f,
            "PeerSwitch({:?}, {} apps)",
            inner.identity,
            inner.apps.len()
        )
    }
}

/// An error answer (Switch wire 7.6): `current` only where there is one, `Value::Null`
/// standing for none, since a writer omits an absent member (Switch wire, Conventions,
/// "Absent and null").
pub(crate) fn bad(code: ErrorCode, current: Value) -> (u16, Value) {
    let mut body = json!({ "code": code.as_str(), "message": "scripted" });
    if !current.is_null() {
        body["current"] = current;
    }
    (code.status(), body)
}

/// `409 identity_needed`, with `known_version` as in `current` (Switch wire 7.1, 7.6).
fn identity_needed(version: Option<u64>) -> (u16, Value) {
    let (status, mut body) = bad(ErrorCode::IdentityNeeded, json!({ "version": version }));
    body["known_version"] = json!(version);
    (status, body)
}

impl PeerSwitch {
    /// The switch of `identity` at `origin`, with no apps yet; its service key is the
    /// identity's. Its `identity.json` goes on after any version the Homeserver holds.
    pub fn new(
        identity: TestIdentity,
        origin: &str,
        clock: Arc<TestClock>,
        homeserver: Arc<TestHomeserver>,
    ) -> Arc<Self> {
        let service = SigningKey::from_bytes(&identity.service_secret());
        let mut body = IdentityBody::first(
            identity.public(),
            identity.signer_id(),
            Inbox::new(origin, service.verifying_key().to_bytes()),
            IdentityPolicy::default(),
        );
        if let Some(held) = homeserver.identity_doc(&identity.public()) {
            body.version = held.version().saturating_add(1);
        }
        Arc::new(Self {
            inner: Mutex::new(PeerInner {
                identity,
                service,
                clock,
                homeserver,
                body,
                apps: Vec::new(),
                // Both start at 0, as at the service (Switch wire 7.4.10).
                apps_version: 0,
                directory_version: 0,
                inbox: Vec::new(),
                answered: HashMap::new(),
                peers: HashMap::new(),
                admitted: None,
                codes: HashMap::new(),
                connects: Vec::new(),
                faults: VecDeque::new(),
                requests: Vec::new(),
                down: false,
                staged: false,
                foreign: None,
            }),
        })
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, PeerInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The identity's public key.
    pub fn identity(&self) -> [u8; 32] {
        self.lock().identity.public()
    }

    /// Add the identity's app `name`, its keys from the identity's seeds, certified for
    /// what `app` names and accepting `accepts`, with receive key 0; the next
    /// `identity.json` lists it and is published. `bump` raises the `apps_version`. Returns
    /// its App ID.
    ///
    /// # Errors
    ///
    /// When a record or the document doesn't sign.
    pub fn add_app(
        &self,
        name: &str,
        app: &AppSpec,
        accepts: &[&str],
        bump: bool,
    ) -> Result<[u8; 16], ScriptError> {
        let mut inner = self.lock();
        let keys = inner.identity.app_keys(name);
        let now = inner.clock.now_ms();
        let cert = issue_cert(inner.identity.key(), &keys, app, now.saturating_sub(1000))?;
        let record = AppRecord::sign(
            &keys,
            AppRecordBody::new(
                &cert,
                accepts.iter().map(|k| (*k).to_owned()).collect(),
                now,
            ),
        )?;
        let key = inner.identity.receive_key(name, 0);
        let key_record = ReceiveKeyRecord::sign(&keys, &cert, ReceiveKeyBody::new(&cert, &key))?;
        if bump {
            inner.apps_version += 1;
        }
        inner.directory_version += 1;
        let since = inner.apps_version;
        inner.body.apps.push(ListedApp {
            app_id: cert.app_id(),
            cert: cert.hash(),
        });
        inner.body.version += 1;
        let app_id = cert.app_id();
        inner.apps.push(PeerApp {
            keys,
            cert,
            record: record.signed().clone(),
            receive_keys: vec![(key, key_record.signed().clone())],
            since,
        });
        inner.publish()?;
        Ok(app_id)
    }

    /// Rotate the receive key of the app at `index`, in the order added: a new current key,
    /// from the seed `<name>/<index>/receive/<n>`.
    ///
    /// # Errors
    ///
    /// When there is no such app, or the record doesn't sign.
    pub fn rotate(&self, index: usize) -> Result<(), ScriptError> {
        let mut inner = self.lock();
        let identity = inner.identity.clone();
        let app = inner
            .apps
            .get_mut(index)
            .ok_or_else(|| ScriptError::Missing(format!("no peer app at {index}")))?;
        let n = app.receive_keys.len() as u64;
        let key = ReceiveKey::from_secret(n, identity.seed(&format!("{index}/receive/{n}")));
        let record =
            ReceiveKeyRecord::sign(&app.keys, &app.cert, ReceiveKeyBody::new(&app.cert, &key))?;
        app.receive_keys.push((key, record.signed().clone()));
        inner.directory_version += 1;
        Ok(())
    }

    /// The identity's apps, in the order added.
    pub fn apps(&self) -> Vec<PeerApp> {
        self.lock().apps.clone()
    }

    /// Answer the next request to `route` (such as `inbox` or `directory`) with the error
    /// `code` and `current`, applying nothing.
    pub fn fail_next(&self, route: &str, code: ErrorCode, current: Value) {
        self.lock()
            .faults
            .push_back((route.to_owned(), code, current));
    }

    /// Admit only `senders`, and senders with an invite code; `None` admits every sender.
    pub fn admit_only(&self, senders: Option<&[[u8; 32]]>) {
        self.lock().admitted = senders.map(|s| s.iter().copied().collect());
    }

    /// An invite code that admits a sender `uses` times.
    pub fn add_invite_code(&self, code: &str, uses: u64) {
        self.lock().codes.insert(code.to_owned(), uses);
    }

    /// The senders with a connect request.
    pub fn connects(&self) -> Vec<[u8; 32]> {
        self.lock().connects.clone()
    }

    /// The peer copy of `identity`'s `identity.json` the switch holds.
    pub fn peer_copy(&self, identity: &[u8; 32]) -> Option<IdentityDoc> {
        self.lock().peers.get(identity).cloned()
    }

    /// A provider loss declared in place (Switch spec 12.6): the account signs with the key
    /// of `service_secret` from now on, at the next generation, holds no peer copy, and is
    /// staged until [`PeerSwitch::set_staged`] ends it; the identity's next `identity.json`,
    /// naming the new key and the lost generation, is published.
    ///
    /// # Errors
    ///
    /// When the document doesn't sign.
    pub fn recover_in_place(&self, service_secret: [u8; 32]) -> Result<(), ScriptError> {
        let mut inner = self.lock();
        inner.service = SigningKey::from_bytes(&service_secret);
        let lost = inner.body.generation;
        inner.body.generation = lost.saturating_add(1);
        inner.body.recovery_from = Some(lost);
        let url = inner.body.inbox.url.clone();
        inner.body.inbox = Inbox::new(&url, inner.service.verifying_key().to_bytes());
        inner.body.version = inner.body.version.saturating_add(1);
        inner.peers.clear();
        inner.answered.clear();
        inner.staged = true;
        inner.publish()
    }

    /// Answer `503 staged` to everything, or serve again.
    pub fn set_staged(&self, staged: bool) {
        self.lock().staged = staged;
    }

    /// Sign every answer with the key of `secret`, which no document names, or, with
    /// `None`, with the service key again.
    pub fn sign_with(&self, secret: Option<[u8; 32]>) {
        self.lock().foreign = secret.map(|s| SigningKey::from_bytes(&s));
    }

    /// Make the switch unreachable, or reachable again.
    pub fn set_down(&self, down: bool) {
        self.lock().down = down;
    }

    /// The `msg_id` of every accepted entry, opened with the apps' receive keys.
    pub fn received(&self) -> Vec<String> {
        let inner = self.lock();
        let identity = inner.identity.public();
        inner
            .inbox
            .iter()
            .filter_map(|entry| {
                inner.apps.iter().find_map(|app| {
                    app.receive_keys.iter().find_map(|(key, _)| {
                        let plaintext =
                            MessagePlaintext::open(&entry.envelope, &identity, &key.secret())
                                .ok()?;
                        Some(Message::parse(plaintext.json(), &[]).ok()?.msg_id)
                    })
                })
            })
            .collect()
    }

    /// The envelopes the inbox accepted, in order.
    pub fn envelopes(&self) -> Vec<Vec<u8>> {
        self.lock()
            .inbox
            .iter()
            .map(|entry| entry.envelope.clone())
            .collect()
    }

    /// The routes asked, in order, as `"METHOD route"`.
    pub fn routes(&self) -> Vec<String> {
        self.lock()
            .requests
            .iter()
            .map(|(m, r)| format!("{m} {r}"))
            .collect()
    }

    /// A message of `kind` with `body` from the app `from` of this identity, entered at
    /// `switch` for its apps `to`, as if its inbox had accepted it. Returns the entry's
    /// `seq` and the message.
    ///
    /// # Errors
    ///
    /// When this identity has no app `from`, or as [`ScriptedSwitch::send`].
    pub fn send_to(
        &self,
        switch: &ScriptedSwitch,
        from: [u8; 16],
        kind: &str,
        body: Value,
        to: &[[u8; 16]],
    ) -> Result<(u64, Message), ScriptError> {
        let (identity, app) = {
            let inner = self.lock();
            let app = inner
                .apps
                .iter()
                .find(|app| app.cert.app_id() == from)
                .cloned()
                .ok_or_else(|| ScriptError::Missing("no such peer app".into()))?;
            (inner.identity.clone(), app)
        };
        switch.send(identity.key(), &app.keys, &app.cert, kind, body, to)
    }

    /// A transport to this switch.
    pub fn transport(self: &Arc<Self>) -> Arc<dyn Transport> {
        Arc::clone(self) as Arc<dyn Transport>
    }

    fn handle(&self, request: &Request) -> Result<Response, TransportError> {
        let mut inner = self.lock();
        if inner.down {
            return Err(TransportError::Connect("down".into()));
        }
        let rest = request
            .path_and_query
            .splitn(4, '/')
            .nth(3)
            .unwrap_or_default()
            .to_owned();
        let route = rest.split('?').next().unwrap_or_default().to_owned();
        inner.requests.push((request.method.clone(), route.clone()));
        if let Some(index) = inner.faults.iter().position(|(r, _, _)| *r == route)
            && let Some((_, code, current)) = inner.faults.remove(index)
        {
            let (status, body) = bad(code, current);
            return Ok(inner.respond(request, status, &body));
        }
        if inner.staged {
            let (status, body) = bad(ErrorCode::Staged, json!(null));
            return Ok(inner.respond(request, status, &body));
        }
        let sender = request
            .header(header::IDENTITY)
            .and_then(|text| pubky_key(text).ok())
            .unwrap_or_default();
        let app = request
            .header(header::APP)
            .and_then(|text| app_id_decode(text).ok())
            .unwrap_or_default();
        let code = request.header(header::INVITE_CODE).map(str::to_owned);
        let answer = match (request.method.as_str(), route.as_str()) {
            ("GET", "directory") => inner.directory(sender, code.as_deref()),
            ("POST", "inbox") => Ok(inner.append(request, sender, app, code.as_deref())),
            ("PUT", "peers") => Ok(inner.peers(sender, &request.body)),
            ("POST", "connect") => Ok(inner.connect(sender, app)),
            _ => Ok(bad(ErrorCode::NotFound, json!(null))),
        };
        let (status, body) =
            answer.map_err(|error| TransportError::Other(format!("peer switch: {error}")))?;
        Ok(inner.respond(request, status, &body))
    }
}

impl Transport for PeerSwitch {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        let answer = self.handle(&request);
        Box::pin(async move { answer })
    }
}

impl PeerInner {
    fn doc(&self) -> Result<IdentityDoc, ScriptError> {
        Ok(IdentityDoc::sign(self.identity.key(), self.body.clone())?)
    }

    fn publish(&mut self) -> Result<(), ScriptError> {
        let doc = self.doc()?;
        self.homeserver.publish(&doc)
    }

    fn respond(&self, request: &Request, status: u16, body: &Value) -> Response {
        let bytes = body.to_string().into_bytes();
        let server_time = rfc3339(self.clock.now_ms());
        let request_signature = request_signature_of(request.header(header::SIGNATURE));
        let signature = sign_response(
            self.foreign.as_ref().unwrap_or(&self.service),
            status,
            request_signature.as_ref(),
            &server_time,
            &bytes,
        );
        Response {
            status,
            headers: vec![
                Header::new(header::SERVICE_SIGNATURE, &b64(&signature)),
                Header::new(header::SERVER_TIME, &server_time),
            ],
            body: bytes,
        }
    }

    fn known(&self, sender: &[u8; 32]) -> Value {
        self.peers
            .get(sender)
            .map_or(Value::Null, |d| json!(d.version()))
    }

    fn admits(&mut self, sender: &[u8; 32], code: Option<&str>, use_code: bool) -> bool {
        if self.admitted.as_ref().is_none_or(|a| a.contains(sender)) {
            return true;
        }
        let Some(code) = code else {
            return false;
        };
        match self.codes.get_mut(code) {
            Some(left) if *left > 0 => {
                if use_code {
                    *left -= 1;
                    if let Some(admitted) = self.admitted.as_mut() {
                        admitted.insert(*sender);
                    }
                }
                true
            }
            _ => false,
        }
    }

    fn listed(&self, sender: &[u8; 32], app: &[u8; 16]) -> bool {
        self.peers
            .get(sender)
            .is_some_and(|doc| doc.listed_cert(app).is_some())
    }

    fn directory(
        &mut self,
        sender: [u8; 32],
        code: Option<&str>,
    ) -> Result<(u16, Value), ScriptError> {
        if !self.admits(&sender, code, false) {
            return Ok(bad(ErrorCode::NotAdmitted, json!(null)));
        }
        let apps: Vec<Value> = self
            .apps
            .iter()
            .map(|app| {
                json!({ "app_id": zbase32_encode(&app.cert.app_id()), "record": app.record,
                        "receive_key": app.receive_keys.last().map(|(_, r)| r.clone()) })
            })
            .collect();
        Ok((
            200,
            json!({ "identity": self.doc()?.signed(), "apps": apps,
                    "directory_version": self.directory_version,
                    "apps_version": self.apps_version, "known_version": self.known(&sender) }),
        ))
    }

    fn append(
        &mut self,
        request: &Request,
        sender: [u8; 32],
        app: [u8; 16],
        code: Option<&str>,
    ) -> (u16, Value) {
        // The query is read first, as at the service: decoded, a parameter given twice
        // refused (Switch wire 7.1).
        let query = request
            .path_and_query
            .split_once('?')
            .map_or("", |(_, query)| query);
        let Some(params) = super::switch::parse_query(query) else {
            return bad(ErrorCode::BadRequest, json!(null));
        };
        if let Some(answer) = self.answered.get(&request.body) {
            return (200, answer.clone());
        }
        let Some(sealed_for) = params
            .get("apps_version")
            .and_then(|value| super::switch::decimal(value))
        else {
            return bad(ErrorCode::BadRequest, json!(null));
        };
        if !self.admits(&sender, code, false) {
            return bad(ErrorCode::NotAdmitted, json!(null));
        }
        if !self.listed(&sender, &app) {
            let version = self.peers.get(&sender).map(IdentityDoc::version);
            return identity_needed(version);
        }
        let Ok(parsed) = parse_header(&request.body) else {
            return bad(ErrorCode::BadRequest, json!(null));
        };
        let kids: Vec<[u8; 8]> = parsed.kids().collect();
        let mut stale = Vec::new();
        let mut unknown = Vec::new();
        for kid in &kids {
            let holder = self
                .apps
                .iter()
                .find(|a| a.receive_keys.iter().any(|(k, _)| k.kid == *kid));
            match holder.and_then(|app| Some((app, app.receive_keys.last()?))) {
                Some((app, (current, record))) if current.kid != *kid => {
                    stale.push(json!({ "app_id": zbase32_encode(&app.cert.app_id()),
                                       "record": record }));
                }
                Some(_) => {}
                None => unknown.push(b64(kid)),
            }
        }
        let added: Vec<Value> = self
            .apps
            .iter()
            .filter(|app| {
                app.since > sealed_for
                    && !app.receive_keys.iter().any(|(k, _)| kids.contains(&k.kid))
            })
            .filter_map(|app| {
                let (_, record) = app.receive_keys.last()?;
                Some(json!({ "app_id": zbase32_encode(&app.cert.app_id()),
                             "app_record": app.record, "record": record }))
            })
            .collect();
        if !stale.is_empty() || !unknown.is_empty() || !added.is_empty() {
            return bad(
                ErrorCode::StaleKey,
                json!({ "receive_keys": stale, "not_current": [], "unknown_kids": unknown,
                        "added_apps": added, "apps_version": self.apps_version }),
            );
        }
        self.admits(&sender, code, true);
        let accepted_at = self.clock.now_ms();
        self.inbox.push(Appended {
            envelope: request.body.clone(),
        });
        let entry_id = [self.inbox.len().to_le_bytes()[0]; 16];
        let answer = json!({ "entry_id": b64(&entry_id),
                             "accepted_at": rfc3339(accepted_at),
                             "directory_version": self.directory_version,
                             "known_version": self.known(&sender) });
        self.answered.insert(request.body.clone(), answer.clone());
        (200, answer)
    }

    fn peers(&mut self, sender: [u8; 32], body: &[u8]) -> (u16, Value) {
        let Ok(signed) = serde_json::from_slice::<SignedDoc>(body) else {
            return bad(ErrorCode::BadRequest, json!(null));
        };
        let Ok(doc) = IdentityDoc::verify(&signed, &sender) else {
            return bad(ErrorCode::BadRequest, json!(null));
        };
        if let Some(held) = self.peers.get(&sender) {
            if held.version() == doc.version() && held.body_hash() != doc.body_hash() {
                return bad(
                    ErrorCode::StaleIdentity,
                    json!({ "version": held.version(), "identity": held.signed() }),
                );
            }
            if held.version() > doc.version() {
                return bad(
                    ErrorCode::StaleIdentity,
                    json!({ "version": held.version() }),
                );
            }
        }
        let version = doc.version();
        self.peers.insert(sender, doc);
        (200, json!({ "version": version, "known_version": version }))
    }

    fn connect(&mut self, sender: [u8; 32], app: [u8; 16]) -> (u16, Value) {
        if !self.listed(&sender, &app) {
            return identity_needed(None);
        }
        if !self.connects.contains(&sender) {
            self.connects.push(sender);
        }
        (
            200,
            json!({ "pending": true, "known_version": self.known(&sender) }),
        )
    }
}
