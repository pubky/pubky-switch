//! A counterparty's switch for the sending flows: bob's account at another origin, with his
//! apps' records and receive keys, his inbox and the peer copies of other identities'
//! `identity.json` (Switch wire 7.4.3, 7.4.5, 7.4.7, 7.4.10). It checks what a sender relies
//! on: admission, the sender's listing in the copy it holds, the targets' current keys and
//! the `apps_version`, and retries by content.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use ed25519_dalek::SigningKey;
use pubky_switch_core::enc::{app_id_decode, b64, pubky_key, zbase32_encode};
use pubky_switch_core::envelope::parse_header;
use pubky_switch_core::http::{ErrorCode, header, request_signature_of, sign_response};
use pubky_switch_core::keys::{AppKeys, IdentityKey, ReceiveKey};
use pubky_switch_core::message::{Message, MessagePlaintext};
use pubky_switch_core::records::{
    AppCert, AppRecord, AppRecordBody, IdentityBody, IdentityDoc, IdentityPolicy, Inbox, ListedApp,
    ReceiveKeyBody, ReceiveKeyRecord,
};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::rfc3339;
use serde_json::{Value, json};

use super::{FakeHomeserver, cert_for, seed};
use crate::clock::{Clock, TestClock};
use crate::error::TransportError;
use crate::transport::{BoxFuture, Header, Request, Response, Transport};

pub(crate) const PEER_ORIGIN: &str = "https://other.example";

/// One of bob's apps.
pub(crate) struct PeerApp {
    pub(crate) keys: AppKeys,
    pub(crate) cert: AppCert,
    pub(crate) record: SignedDoc,
    /// Every receive key, the current one last.
    pub(crate) receive_keys: Vec<(ReceiveKey, SignedDoc)>,
    /// The `apps_version` at which it became reachable.
    pub(crate) since: u64,
}

/// One accepted entry.
#[derive(Clone)]
pub(crate) struct Appended {
    pub(crate) envelope: Vec<u8>,
}

pub(crate) struct PeerInner {
    pub(crate) identity: IdentityKey,
    pub(crate) service: SigningKey,
    pub(crate) clock: Arc<TestClock>,
    pub(crate) homeserver: Arc<FakeHomeserver>,
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
}

/// Bob's switch.
pub(crate) struct PeerSwitch {
    inner: Mutex<PeerInner>,
}

fn bad(code: ErrorCode, current: Value) -> (u16, Value) {
    (
        code.status(),
        json!({ "code": code.as_str(), "message": "scripted", "current": current }),
    )
}

impl PeerSwitch {
    /// Bob's switch with one app, `shop`, which accepts `kinds`; bob's `identity.json`
    /// naming it is published.
    pub(crate) fn new(
        bob: &IdentityKey,
        clock: Arc<TestClock>,
        homeserver: Arc<FakeHomeserver>,
        kinds: &[&str],
    ) -> Arc<Self> {
        let service = SigningKey::from_bytes(&seed("service/bob"));
        let mut body = IdentityBody::first(
            bob.public(),
            [2; 16],
            Inbox::new(PEER_ORIGIN, service.verifying_key().to_bytes()),
            IdentityPolicy::default(),
        );
        // The world published version 1 already.
        body.version = 2;
        let switch = Arc::new(Self {
            inner: Mutex::new(PeerInner {
                identity: IdentityKey::from_secret(bob.secret_bytes()),
                service,
                clock,
                homeserver,
                body,
                apps: Vec::new(),
                apps_version: 1,
                directory_version: 1,
                inbox: Vec::new(),
                answered: HashMap::new(),
                peers: HashMap::new(),
                admitted: None,
                codes: HashMap::new(),
                connects: Vec::new(),
                faults: VecDeque::new(),
                requests: Vec::new(),
                down: false,
            }),
        });
        switch.add_app("shop", kinds, false);
        switch
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, PeerInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Add one of bob's apps, listed in a new `identity.json`; `bump` raises the
    /// `apps_version`.
    pub(crate) fn add_app(&self, name: &str, kinds: &[&str], bump: bool) -> [u8; 16] {
        let mut inner = self.lock();
        let keys = AppKeys::from_secrets(
            seed(&format!("bob/{name}/signing")),
            seed(&format!("bob/{name}/bundle")),
        );
        let now = inner.clock.now_ms();
        let cert = cert_for(&inner.identity, &keys, now - 1000, &["scope-a"]);
        let record = AppRecord::sign(
            &keys,
            AppRecordBody::new(&cert, kinds.iter().map(|k| (*k).to_owned()).collect(), now),
        )
        .unwrap();
        let key = ReceiveKey::from_secret(0, seed(&format!("bob/{name}/receive/0")));
        let key_record =
            ReceiveKeyRecord::sign(&keys, &cert, ReceiveKeyBody::new(&cert, &key)).unwrap();
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
        inner.publish();
        app_id
    }

    /// Rotate the receive key of bob's app `index`.
    pub(crate) fn rotate(&self, index: usize) {
        let mut inner = self.lock();
        let app = &mut inner.apps[index];
        let n = app.receive_keys.len() as u64;
        let key = ReceiveKey::from_secret(n, seed(&format!("bob/{index}/receive/{n}")));
        let record =
            ReceiveKeyRecord::sign(&app.keys, &app.cert, ReceiveKeyBody::new(&app.cert, &key))
                .unwrap();
        app.receive_keys.push((key, record.signed().clone()));
        inner.directory_version += 1;
    }

    pub(crate) fn fail_next(&self, route: &str, code: ErrorCode, current: Value) {
        self.lock()
            .faults
            .push_back((route.to_owned(), code, current));
    }

    /// The `msg_id` of every accepted entry, opened with bob's keys.
    pub(crate) fn received(&self) -> Vec<String> {
        let inner = self.lock();
        let bob = inner.identity.public();
        inner
            .inbox
            .iter()
            .filter_map(|entry| {
                inner.apps.iter().find_map(|app| {
                    app.receive_keys.iter().find_map(|(key, _)| {
                        let plaintext =
                            MessagePlaintext::open(&entry.envelope, &bob, &key.secret()).ok()?;
                        Some(Message::parse(plaintext.json(), &[]).ok()?.msg_id)
                    })
                })
            })
            .collect()
    }

    /// The routes asked, in order.
    pub(crate) fn routes(&self) -> Vec<String> {
        self.lock()
            .requests
            .iter()
            .map(|(m, r)| format!("{m} {r}"))
            .collect()
    }

    pub(crate) fn transport(self: &Arc<Self>) -> Arc<dyn Transport> {
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
        if let Some(index) = inner.faults.iter().position(|(r, _, _)| *r == route) {
            let (_, code, current) = inner.faults.remove(index).unwrap();
            let (status, body) = bad(code, current);
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
        let (status, body) = match (request.method.as_str(), route.as_str()) {
            ("GET", "directory") => inner.directory(sender, code.as_deref()),
            ("POST", "inbox") => inner.append(request, sender, app, code.as_deref()),
            ("PUT", "peers") => inner.peers(sender, &request.body),
            ("POST", "connect") => inner.connect(sender, app),
            _ => bad(ErrorCode::NotFound, json!(null)),
        };
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
    fn publish(&mut self) {
        let doc = IdentityDoc::sign(&self.identity, self.body.clone()).unwrap();
        self.homeserver.publish(&doc);
    }

    fn doc(&self) -> IdentityDoc {
        IdentityDoc::sign(&self.identity, self.body.clone()).unwrap()
    }

    fn respond(&self, request: &Request, status: u16, body: &Value) -> Response {
        let bytes = body.to_string().into_bytes();
        let server_time = rfc3339(self.clock.now_ms());
        let request_signature = request_signature_of(request.header(header::SIGNATURE));
        let signature = sign_response(
            &self.service,
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

    fn directory(&mut self, sender: [u8; 32], code: Option<&str>) -> (u16, Value) {
        if !self.admits(&sender, code, false) {
            return bad(ErrorCode::NotAdmitted, json!({}));
        }
        let apps: Vec<Value> = self
            .apps
            .iter()
            .map(|app| {
                json!({ "app_id": zbase32_encode(&app.cert.app_id()), "record": app.record,
                        "receive_key": app.receive_keys.last().map(|(_, r)| r.clone()) })
            })
            .collect();
        (
            200,
            json!({ "identity": self.doc().signed(), "apps": apps,
                    "directory_version": self.directory_version,
                    "apps_version": self.apps_version, "known_version": self.known(&sender) }),
        )
    }

    fn append(
        &mut self,
        request: &Request,
        sender: [u8; 32],
        app: [u8; 16],
        code: Option<&str>,
    ) -> (u16, Value) {
        if let Some(answer) = self.answered.get(&request.body) {
            return (200, answer.clone());
        }
        if !self.admits(&sender, code, false) {
            return bad(ErrorCode::NotAdmitted, json!({}));
        }
        if !self.listed(&sender, &app) {
            let version = self.peers.get(&sender).map(IdentityDoc::version);
            return bad(ErrorCode::IdentityNeeded, json!({ "version": version }));
        }
        let sealed_for: u64 = request
            .path_and_query
            .split("apps_version=")
            .nth(1)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let Ok(parsed) = parse_header(&request.body) else {
            return bad(ErrorCode::BadRequest, json!(null));
        };
        let kids: Vec<[u8; 8]> = parsed.kids().collect();
        let mut stale = Vec::new();
        let mut unknown = Vec::new();
        for kid in &kids {
            match self
                .apps
                .iter()
                .find(|a| a.receive_keys.iter().any(|(k, _)| k.kid == *kid))
            {
                Some(app) if app.receive_keys.last().unwrap().0.kid != *kid => {
                    stale.push(json!({ "app_id": zbase32_encode(&app.cert.app_id()),
                                       "record": app.receive_keys.last().unwrap().1 }));
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
            .map(|app| {
                json!({ "app_id": zbase32_encode(&app.cert.app_id()), "app_record": app.record,
                        "record": app.receive_keys.last().unwrap().1 })
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
        let answer = json!({ "entry_id": b64(&[self.inbox.len() as u8; 16]),
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
            return bad(ErrorCode::IdentityNeeded, json!({ "version": null }));
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

/// A transport that sends each request to the switch of its origin.
pub(crate) struct Router {
    pub(crate) routes: Vec<(String, Arc<dyn Transport>)>,
    /// Every request, as "METHOD origin path", in order.
    pub(crate) log: Mutex<Vec<String>>,
}

impl Transport for Router {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        self.log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(format!(
                "{} {} {}",
                request.method, request.origin, request.path_and_query
            ));
        match self
            .routes
            .iter()
            .find(|(origin, _)| *origin == request.origin)
        {
            Some((_, transport)) => transport.send(request),
            None => Box::pin(async { Err(TransportError::Refused("no such origin".into())) }),
        }
    }
}
