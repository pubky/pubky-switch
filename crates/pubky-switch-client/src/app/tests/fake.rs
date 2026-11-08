//! A scripted switch for the app's flow tests: one account, its chain, feed and directory,
//! answering through the [`MockTransport`] with answers signed by the account's service
//! key, built from the core's types. It checks what the app layer relies on (receive key
//! numbers, record times, batch retries by ID) and nothing else.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use ed25519_dalek::SigningKey;
use pubky_switch_core::chain::{
    ChainTip, ItemType, ProofBody, ProofState, ServiceTransition, SignedHead, Stub,
    TransitionProof, ZERO_HASH, item_hash,
};
use pubky_switch_core::enc::{app_id_decode, b64, pubky_id, zbase32_encode};
use pubky_switch_core::envelope::Recipient;
use pubky_switch_core::http::{ErrorCode, header, request_signature_of, sign_response};
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::message::{Message, Sender};
use pubky_switch_core::ops::{OpKind, OpsRequest, Position, SignedOp, sign_batch};
use pubky_switch_core::records::{AppCert, BundlePart, IdentityDoc};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::rfc3339;
use serde_json::{Map, Value, json};

use crate::clock::{Clock, TestClock};
use crate::error::TransportError;
use crate::transport::{Header, MockTransport, Request, Response};

/// One item of the account's sequence.
#[derive(Clone, Debug)]
pub(crate) enum Item {
    Entry {
        seq: u64,
        sender: [u8; 32],
        cert: SignedDoc,
        accepted_at: u64,
        envelope: Vec<u8>,
        targets: Vec<[u8; 16]>,
    },
    Chain {
        seq: u64,
        stub: Stub,
        item_type: ItemType,
        item: SignedDoc,
        proof: Option<SignedDoc>,
        /// Shown in full only to this app (a key bundle part).
        only_for: Option<[u8; 16]>,
    },
    Unreadable {
        seq: u64,
        sender: [u8; 32],
        accepted_at: u64,
    },
    Missed {
        seq: u64,
        entries: u64,
        from: u64,
        until: u64,
    },
}

impl Item {
    fn seq(&self) -> u64 {
        match self {
            Item::Entry { seq, .. }
            | Item::Chain { seq, .. }
            | Item::Unreadable { seq, .. }
            | Item::Missed { seq, .. } => *seq,
        }
    }

    fn batch(&self) -> Option<[u8; 16]> {
        match self {
            Item::Chain { stub, .. } => stub.open().ok()?.batch.map(|b| b.id),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct AppAtSwitch {
    pub(crate) record: Option<SignedDoc>,
    pub(crate) cert: Option<AppCert>,
    pub(crate) receive_key: Option<SignedDoc>,
    pub(crate) receive_n: Option<u64>,
    pub(crate) cursor: u64,
    pub(crate) departed: bool,
    pub(crate) full_requested: Option<u64>,
}

/// A fault the switch applies to the next request whose path contains `path`.
#[derive(Clone, Debug)]
pub(crate) enum Fault {
    /// Answer this error without applying anything.
    Error {
        path: String,
        code: ErrorCode,
        current: Value,
    },
    /// Apply the request, then lose the answer.
    LoseAnswer { path: String },
}

pub(crate) struct Inner {
    pub(crate) identity: IdentityKey,
    pub(crate) service: SigningKey,
    pub(crate) clock: Arc<TestClock>,
    pub(crate) tip: ChainTip,
    pub(crate) seq: u64,
    pub(crate) items: Vec<Item>,
    pub(crate) tips: Vec<ChainTip>,
    pub(crate) doc: Option<IdentityDoc>,
    pub(crate) apps: BTreeMap<[u8; 16], AppAtSwitch>,
    pub(crate) bundles: BTreeMap<[u8; 16], Vec<(BundlePart, u64)>>,
    pub(crate) answered: HashMap<[u8; 16], Value>,
    pub(crate) checkpoint: Option<SignedHead>,
    /// Stubs at or below this `seq` are gone (dropped behind a checkpoint).
    pub(crate) dropped_through: u64,
    pub(crate) faults: VecDeque<Fault>,
    /// Every operation applied, in order, for counting effects.
    pub(crate) applied: Vec<SignedOp>,
}

/// The scripted switch.
pub(crate) struct FakeSwitch {
    inner: Mutex<Inner>,
}

pub(crate) const ORIGIN: &str = "https://switch.example";

fn bad(code: ErrorCode, message: &str, current: Value) -> (u16, Value) {
    (
        code.status(),
        json!({ "code": code.as_str(), "message": message, "current": current }),
    )
}

impl FakeSwitch {
    pub(crate) fn new(
        identity: IdentityKey,
        service: SigningKey,
        clock: Arc<TestClock>,
    ) -> Arc<Self> {
        let tip = ChainTip {
            generation: 1,
            seq: 0,
            chain_hash: ZERO_HASH,
        };
        Arc::new(Self {
            inner: Mutex::new(Inner {
                identity,
                service,
                clock,
                tip,
                seq: 0,
                items: Vec::new(),
                tips: vec![tip],
                doc: None,
                apps: BTreeMap::new(),
                bundles: BTreeMap::new(),
                answered: HashMap::new(),
                checkpoint: None,
                dropped_through: 0,
                faults: VecDeque::new(),
                applied: Vec::new(),
            }),
        })
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The transport the app talks to this switch through.
    pub(crate) fn transport(self: &Arc<Self>) -> Arc<MockTransport> {
        let switch = Arc::clone(self);
        Arc::new(MockTransport::with_handler(move |request| {
            switch.handle(request)
        }))
    }

    pub(crate) fn fail_next(&self, fault: Fault) {
        self.lock().faults.push_back(fault);
    }

    fn handle(&self, request: &Request) -> Result<Response, TransportError> {
        let mut inner = self.lock();
        let path = request.path_and_query.clone();
        let mut lose = false;
        if let Some(index) = inner.faults.iter().position(|fault| match fault {
            Fault::Error { path: p, .. } | Fault::LoseAnswer { path: p } => {
                path.contains(p.as_str())
            }
        }) {
            match inner.faults.remove(index) {
                Some(Fault::Error { code, current, .. }) => {
                    let (status, body) = bad(code, "scripted", current);
                    return Ok(inner.respond(request, status, &body));
                }
                Some(Fault::LoseAnswer { .. }) => lose = true,
                None => {}
            }
        }
        let caller = request
            .header(header::APP)
            .and_then(|text| app_id_decode(text).ok());
        let rest = path.splitn(4, '/').nth(3).unwrap_or_default().to_owned();
        let (status, body) = inner.route(request, caller, &rest);
        if lose {
            return Err(TransportError::Timeout);
        }
        Ok(inner.respond(request, status, &body))
    }

    /// Deliver an own `identity.json` (the signer's `PUT /identity`).
    pub(crate) fn deliver_identity(&self, doc: &IdentityDoc) {
        let mut inner = self.lock();
        let bytes = doc.signed().doc_bytes().unwrap();
        let hash = item_hash(ItemType::Identity, &bytes);
        let state = ProofState::Identity {
            version: doc.version(),
            generation: doc.generation(),
            data_epoch: doc.data_epoch(),
        };
        inner.chain_item(
            ItemType::Identity,
            doc.signed().clone(),
            hash,
            None,
            "identity",
            &state,
            None,
        );
        inner.doc = Some(doc.clone());
    }

    /// An entry from `from`'s app `keys` (certificate `cert`), sealed to `to` apps' current
    /// receive keys.
    pub(crate) fn send(
        &self,
        from: &IdentityKey,
        keys: &AppKeys,
        cert: &AppCert,
        kind: &str,
        body: Value,
        to: &[[u8; 16]],
    ) -> (u64, Message) {
        let account = self.lock().identity.public();
        let now = self.lock().clock.now_ms();
        let body: Map<String, Value> = body.as_object().cloned().unwrap_or_default();
        let message = Message::new(
            kind,
            Sender::of_app(from.public(), keys),
            account,
            now,
            vec![],
            body,
        )
        .unwrap();
        let plaintext = message.sign(keys).unwrap();
        let seq = self.send_plaintext(from.public(), cert, &plaintext, to);
        (seq, message)
    }

    /// An entry carrying a signed plaintext, sealed again to `to` apps' current keys (a
    /// re-send keeps the bytes).
    pub(crate) fn send_plaintext(
        &self,
        sender: [u8; 32],
        cert: &AppCert,
        plaintext: &pubky_switch_core::message::MessagePlaintext,
        to: &[[u8; 16]],
    ) -> u64 {
        let account = self.lock().identity.public();
        let recipients: Vec<Recipient> = to
            .iter()
            .map(|app| {
                let inner = self.lock();
                let record = inner.apps[app].receive_key.clone().unwrap();
                let value: Value = record.peek().unwrap();
                let public =
                    pubky_switch_core::enc::unb64_array::<32>(value["x25519"].as_str().unwrap())
                        .unwrap();
                Recipient::new(public)
            })
            .collect();
        let envelope = plaintext.seal(&account, &recipients, false).unwrap();
        self.send_envelope(sender, cert, envelope, to)
    }

    pub(crate) fn send_envelope(
        &self,
        sender: [u8; 32],
        cert: &AppCert,
        envelope: Vec<u8>,
        to: &[[u8; 16]],
    ) -> u64 {
        let mut inner = self.lock();
        let seq = inner.next_seq();
        let accepted_at = inner.clock.now_ms();
        inner.items.push(Item::Entry {
            seq,
            sender,
            cert: cert.signed().clone(),
            accepted_at,
            envelope,
            targets: to.to_vec(),
        });
        seq
    }

    pub(crate) fn push_unreadable(&self, sender: [u8; 32], accepted_at: u64) -> u64 {
        let mut inner = self.lock();
        let seq = inner.next_seq();
        inner.items.push(Item::Unreadable {
            seq,
            sender,
            accepted_at,
        });
        seq
    }

    pub(crate) fn push_missed(&self, entries: u64, from: u64, until: u64) -> u64 {
        let mut inner = self.lock();
        let seq = inner.next_seq();
        inner.items.push(Item::Missed {
            seq,
            entries,
            from,
            until,
        });
        seq
    }

    /// An operation of the signer (identity key, `app_id` null), in a batch of its own.
    pub(crate) fn signer_op(&self, kind: OpKind) -> u64 {
        let mut inner = self.lock();
        let key = inner.identity.clone_key();
        let account = key.public();
        let ops = sign_batch(
            &key,
            &account,
            None,
            inner.tip.generation,
            rand_id(),
            vec![(vec![], kind)],
        )
        .unwrap();
        inner.apply_ops(None, &ops);
        inner.seq
    }

    /// An operation an app signs, applied as the switch would: a thief's registration.
    pub(crate) fn app_op(&self, keys: &AppKeys, kind: OpKind) -> Result<u64, Value> {
        let mut inner = self.lock();
        let account = inner.identity.public();
        let ops = sign_batch(
            keys,
            &account,
            Some(keys.app_id_bytes()),
            inner.tip.generation,
            rand_id(),
            vec![(vec![], kind)],
        )
        .unwrap();
        match inner.check_ops(Some(keys.app_id_bytes()), &ops) {
            Some((_, body)) => Err(body),
            None => {
                inner.apply_ops(Some(keys.app_id_bytes()), &ops);
                Ok(inner.seq)
            }
        }
    }

    /// Roll the chain back to `seq`: everything after it is gone, and the tip is as it was.
    pub(crate) fn roll_back_to(&self, seq: u64) {
        let mut inner = self.lock();
        inner.items.retain(|item| item.seq() <= seq);
        let tip = inner
            .tips
            .iter()
            .rev()
            .find(|tip| tip.seq <= seq)
            .copied()
            .unwrap();
        inner.tips.retain(|t| t.seq <= seq);
        inner.tip = tip;
        inner.seq = seq;
    }

    pub(crate) fn applied(&self) -> Vec<SignedOp> {
        self.lock().applied.clone()
    }

    pub(crate) fn app(&self, app: &[u8; 16]) -> AppAtSwitch {
        self.lock().apps.get(app).cloned().unwrap_or_default()
    }

    pub(crate) fn tip_seq(&self) -> u64 {
        self.lock().tip.seq
    }
}

fn rand_id() -> [u8; 16] {
    pubky_switch_core::ops::random_batch_id().unwrap()
}

trait CloneKey {
    fn clone_key(&self) -> IdentityKey;
}

impl CloneKey for IdentityKey {
    fn clone_key(&self) -> IdentityKey {
        IdentityKey::from_secret(self.secret_bytes())
    }
}

impl Inner {
    fn now(&self) -> u64 {
        self.clock.now_ms()
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn head(&self) -> SignedHead {
        SignedHead::sign(&self.service, &self.identity.public(), &self.tip)
    }

    fn respond(&self, request: &Request, status: u16, body: &Value) -> Response {
        let bytes = body.to_string().into_bytes();
        let server_time = rfc3339(self.now());
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

    /// Append one chain item and its proof.
    #[allow(clippy::too_many_arguments)]
    fn chain_item(
        &mut self,
        item_type: ItemType,
        item: SignedDoc,
        hash: [u8; 32],
        batch: Option<pubky_switch_core::ops::BatchRef>,
        object: &str,
        state: &ProofState,
        only_for: Option<[u8; 16]>,
    ) -> SignedDoc {
        let seq = self.next_seq();
        let now = self.now();
        let (stub, tip) = self.tip.append(seq, now, item_type, hash, batch).unwrap();
        self.tip = tip;
        self.tips.push(tip);
        let proof = TransitionProof::sign(
            &self.service,
            &self.identity.public(),
            ProofBody::new(stub.clone(), object.to_owned(), state),
        )
        .unwrap();
        self.items.push(Item::Chain {
            seq,
            stub,
            item_type,
            item,
            proof: Some(proof.signed().clone()),
            only_for,
        });
        proof.signed().clone()
    }

    fn service_transition(&mut self, transition: ServiceTransition) -> SignedDoc {
        let signed = transition
            .sign(&self.service, &self.identity.public())
            .unwrap();
        let hash = item_hash(ItemType::Service, &signed.doc_bytes().unwrap());
        let object = transition.proof_object().unwrap_or_default();
        let state = ProofState::Service(transition.to_value());
        self.chain_item(ItemType::Service, signed, hash, None, &object, &state, None)
    }

    /// The refusal the switch gives a batch, if any.
    fn check_ops(&self, caller: Option<[u8; 16]>, ops: &[SignedOp]) -> Option<(u16, Value)> {
        if let Some(app) = caller
            && self.apps.get(&app).is_some_and(|a| a.departed)
        {
            return Some(bad(ErrorCode::NotCurrent, "departed", json!({})));
        }
        for op in ops {
            match &op.body().kind {
                OpKind::ReceiveKeyPut { record } => {
                    let app = caller?;
                    let value: Value = record.peek().ok()?;
                    let n = value["n"].as_u64()?;
                    let held = self.apps.get(&app).cloned().unwrap_or_default();
                    if held.receive_key.as_ref() == Some(record) {
                        continue;
                    }
                    let expected = held.receive_n.map_or(0, |c| c + 1);
                    if n != expected {
                        return Some(bad(
                            ErrorCode::Conflict,
                            "receive key number",
                            json!({ "receive_key": held.receive_key }),
                        ));
                    }
                }
                OpKind::AppPut { record } => {
                    let app = caller?;
                    let held = self.apps.get(&app).cloned().unwrap_or_default();
                    if let Some(old) = &held.record
                        && old != record
                    {
                        let time = |doc: &SignedDoc| {
                            let v: Value = doc.peek().unwrap();
                            pubky_switch_core::time::parse_rfc3339(
                                v["updated_at"].as_str().unwrap(),
                            )
                            .unwrap()
                        };
                        if time(record) <= time(old) {
                            return Some(bad(
                                ErrorCode::Conflict,
                                "updated_at",
                                json!({ "record": old }),
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn apply_ops(&mut self, caller: Option<[u8; 16]>, ops: &[SignedOp]) -> Vec<SignedDoc> {
        let mut proofs = Vec::new();
        for op in ops {
            let body = op.body();
            let hash = op.item_hash().unwrap();
            let object = body.kind.proof_object(body.app_id.as_ref()).unwrap();
            let mut only_for = None;
            let state = match &body.kind {
                OpKind::AppPut { record } => {
                    let app = caller.unwrap();
                    let entry = self.apps.entry(app).or_default();
                    entry.record = Some(record.clone());
                    let v: Value = record.peek().unwrap();
                    let cert = SignedDoc::from_strict_value(&v["cert"]).unwrap();
                    entry.cert = AppCert::verify(&cert, &self.identity.public()).ok();
                    ProofState::App { app_id: app }
                }
                OpKind::ReceiveKeyPut { record } => {
                    let app = caller.unwrap();
                    let v: Value = record.peek().unwrap();
                    let n = v["n"].as_u64().unwrap();
                    let kid = pubky_switch_core::enc::unb64_array::<8>(v["kid"].as_str().unwrap())
                        .unwrap();
                    let entry = self.apps.entry(app).or_default();
                    entry.receive_key = Some(record.clone());
                    entry.receive_n = Some(n);
                    ProofState::ReceiveKey { n, kid }
                }
                OpKind::KeyBundlePut(put) => {
                    only_for = Some(put.target_app_id);
                    let seq = self.seq + 1;
                    let part = BundlePart {
                        bundle: put.bundle.clone(),
                        first_epoch: put.first_epoch,
                        last_epoch: put.last_epoch,
                    };
                    let parts = self.bundles.entry(put.target_app_id).or_default();
                    parts.retain(|(p, _)| {
                        p.last_epoch < put.first_epoch || p.first_epoch > put.last_epoch
                    });
                    parts.push((part, seq));
                    parts.sort_by_key(|(p, _)| p.first_epoch);
                    if let Some(app) = self.apps.get_mut(&put.target_app_id) {
                        app.full_requested = None;
                    }
                    ProofState::KeyBundle { bundle_seq: seq }
                }
                OpKind::CertPut { cert, .. } => ProofState::Cert {
                    cert: cert.doc_hash().unwrap(),
                },
                OpKind::AllowPut { kind, .. } => ProofState::Allow {
                    kind: *kind,
                    present: true,
                },
                OpKind::DenyPut { .. } => ProofState::Deny { denied: true },
                _ => ProofState::Deny { denied: false },
            };
            proofs.push(self.chain_item(
                ItemType::Op,
                op.signed().clone(),
                hash,
                Some(body.batch),
                &object,
                &state,
                only_for,
            ));
            self.applied.push(op.clone());
        }
        proofs
    }

    fn route(&mut self, request: &Request, caller: Option<[u8; 16]>, rest: &str) -> (u16, Value) {
        let (route, query) = rest.split_once('?').unwrap_or((rest, ""));
        let me = caller.map(|app| zbase32_encode(&app)).unwrap_or_default();
        match (request.method.as_str(), route) {
            ("POST", "ops") => self.ops(caller, &request.body),
            ("GET", "feed") => self.feed(caller, query),
            ("GET", "directory") => self.directory(),
            ("GET", r) if r == format!("apps/{me}/keys") => {
                let parts = self
                    .bundles
                    .get(&caller.unwrap())
                    .cloned()
                    .unwrap_or_default();
                if parts.is_empty() {
                    return bad(ErrorCode::NotFound, "none", json!(null));
                }
                let bundles: Vec<Value> = parts
                    .iter()
                    .map(|(part, seq)| {
                        json!({ "bundle": part.bundle, "seq": seq,
                                "first_epoch": part.first_epoch, "last_epoch": part.last_epoch })
                    })
                    .collect();
                (200, json!({ "bundles": bundles }))
            }
            ("POST", r) if r == format!("apps/{me}/keys") => {
                let now = self.now();
                let app = self.apps.entry(caller.unwrap()).or_default();
                let at = *app.full_requested.get_or_insert(now);
                (200, json!({ "requested": rfc3339(at) }))
            }
            ("POST", r) if r == format!("apps/{me}/leave") => {
                let app = caller.unwrap();
                if self.apps.get(&app).is_some_and(|a| a.departed) {
                    return bad(ErrorCode::NotCurrent, "departed", json!({}));
                }
                self.apps.entry(app).or_default().departed = true;
                let at = self.now();
                let proof = self.service_transition(ServiceTransition::Leave { app_id: app, at });
                (
                    200,
                    json!({ "proofs": [proof], "head": self.head().to_value() }),
                )
            }
            _ => bad(ErrorCode::NotFound, "no route", json!(null)),
        }
    }

    fn ops(&mut self, caller: Option<[u8; 16]>, body: &[u8]) -> (u16, Value) {
        let Ok(request) = OpsRequest::parse(body) else {
            return bad(ErrorCode::BadRequest, "ops", json!(null));
        };
        let ops: Vec<SignedOp> = request
            .signed()
            .map(|signed| SignedOp::peek(signed).unwrap())
            .collect();
        if let Some(id) = ops.first().map(|op| op.body().batch.id)
            && let Some(answer) = self.answered.get(&id)
        {
            let mut answer = answer.clone();
            answer["head"] = self.head().to_value();
            return (200, answer);
        }
        if let Some(refusal) = self.check_ops(caller, &ops) {
            return refusal;
        }
        if let Some(app) = caller
            && self.apps.get(&app).is_some_and(|a| a.departed)
        {
            return bad(ErrorCode::NotCurrent, "departed", json!({}));
        }
        let proofs = self.apply_ops(caller, &ops);
        if let (Some(app), Some(position)) = (caller, request.cursor()) {
            self.apps.entry(app).or_default().cursor = position.seq;
        }
        let answer = json!({ "proofs": proofs, "head": self.head().to_value() });
        if let Some(op) = ops.first() {
            self.answered.insert(op.body().batch.id, answer.clone());
        }
        (200, answer)
    }

    fn feed(&mut self, caller: Option<[u8; 16]>, query: &str) -> (u16, Value) {
        let Some(app) = caller else {
            return bad(ErrorCode::PermissionMissing, "own apps only", json!(null));
        };
        if self.apps.get(&app).is_some_and(|a| a.departed) {
            return bad(ErrorCode::NotCurrent, "departed", json!({}));
        }
        let mut after = 0;
        let mut limit = 100usize;
        for pair in query.split('&') {
            match pair.split_once('=') {
                Some(("after", value)) => after = Position::parse(value).unwrap().seq,
                Some(("limit", value)) => limit = value.parse().unwrap(),
                _ => {}
            }
        }
        let mut items = Vec::new();
        let mut last = after;
        let mut truncated = false;
        let candidates: Vec<Item> = self
            .items
            .iter()
            .filter(|item| item.seq() > after)
            .cloned()
            .collect();
        let mut open_batch: Option<[u8; 16]> = None;
        for item in candidates {
            if items.len() >= limit && open_batch.is_none_or(|b| item.batch() != Some(b)) {
                truncated = true;
                break;
            }
            last = item.seq();
            open_batch = item.batch();
            if let Some(value) = self.show(&item, app) {
                items.push(value);
            }
        }
        if !truncated {
            last = last.max(self.seq);
        }
        let mut page = json!({
            "items": items,
            "next": format!("{}:{last}", self.tip.generation),
            "scanned_through": last,
            "more": truncated,
            "head": self.head().to_value(),
        });
        if let Some(checkpoint) = &self.checkpoint {
            page["checkpoint"] = checkpoint.to_value();
        }
        (200, page)
    }

    fn show(&self, item: &Item, app: [u8; 16]) -> Option<Value> {
        Some(match item {
            Item::Entry {
                seq,
                sender,
                cert,
                accepted_at,
                envelope,
                targets,
            } => {
                if !targets.contains(&app) {
                    return None;
                }
                json!({ "type": "entry", "seq": seq, "entry_id": b64(&[*seq as u8; 16]),
                        "sender": pubky_id(sender), "cert": cert,
                        "accepted_at": rfc3339(*accepted_at), "envelope": b64(envelope) })
            }
            Item::Chain {
                seq,
                stub,
                item_type,
                item,
                proof,
                only_for,
            } => {
                if *seq <= self.dropped_through {
                    return None;
                }
                if only_for.is_some_and(|target| target != app) {
                    return Some(json!({ "type": "stub", "seq": seq, "stub": stub.to_value() }));
                }
                let mut value = json!({ "type": "chain", "seq": seq, "stub": stub.to_value(),
                                        "item_type": item_type.as_str(), "item": item });
                if let Some(proof) = proof
                    && *item_type == ItemType::Op
                {
                    value["proof"] = json!(proof);
                }
                value
            }
            Item::Unreadable {
                seq,
                sender,
                accepted_at,
            } => json!({ "type": "unreadable", "seq": seq, "entry_id": b64(&[*seq as u8; 16]),
                         "sender": pubky_id(sender), "accepted_at": rfc3339(*accepted_at) }),
            Item::Missed {
                seq,
                entries,
                from,
                until,
            } => json!({ "type": "missed", "seq": seq, "entries": entries,
                         "accepted_from": rfc3339(*from), "accepted_until": rfc3339(*until) }),
        })
    }

    fn directory(&self) -> (u16, Value) {
        let apps: Vec<Value> = self
            .apps
            .iter()
            .filter(|(_, app)| !app.departed && app.record.is_some())
            .map(|(id, app)| {
                json!({ "app_id": zbase32_encode(id), "record": app.record,
                        "receive_key": app.receive_key })
            })
            .collect();
        (
            200,
            json!({ "identity": self.doc.as_ref().map(|d| d.signed().clone()),
                    "apps": apps, "directory_version": self.seq, "apps_version": 1 }),
        )
    }
}
