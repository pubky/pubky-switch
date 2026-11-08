//! The scripted switch's shared state: shared records, claims, the lists, invite codes and
//! connect requests, with their reads (Switch wire 6.2, 6.8, 7.4.6 to 7.4.9). The record and
//! claim rules are the core's.

use std::collections::BTreeMap;

use pubky_switch_core::chain::{ItemType, ProofState};
use pubky_switch_core::claims::{
    Claim, ClaimLimits, ClaimTally, EntryContext, MAX_CLAIM_AGE_MS, apply_entry,
};
use pubky_switch_core::enc::{b64, pubky_id, unb64_array, zbase32_encode};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ops::{
    AllowKind, ConditionState, OpKind, OpsRequest, RecordVersion, SignedOp, check_conditions,
};
use pubky_switch_core::shared::{RecordState, check_record_put};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::rfc3339;
use serde_json::{Value, json};

use super::{FakeSwitch, Inner, bad};
use crate::clock::Clock;
use crate::transport::Request;

/// A record as the switch holds it, with what its reads return.
#[derive(Clone, Debug)]
pub(crate) struct HeldWrite {
    pub(crate) state: RecordState,
    pub(crate) op: SignedDoc,
    pub(crate) proof: SignedDoc,
    pub(crate) writer: [u8; 16],
    pub(crate) seq: u64,
}

/// One claim entry as `GET /claims` returns it.
#[derive(Clone, Debug)]
pub(crate) struct HeldEntry {
    step: u64,
    seq: u64,
    op: SignedDoc,
    proof: SignedDoc,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Shared {
    pub(crate) records: BTreeMap<[u8; 32], HeldWrite>,
    pub(crate) claims: BTreeMap<[u8; 32], Claim>,
    entries: BTreeMap<[u8; 32], Vec<HeldEntry>>,
    pub(crate) connect: Vec<([u8; 32], u64)>,
    invites: BTreeMap<[u8; 32], (u64, u64, [u8; 16])>,
    /// Answer the next record read without its proof, as after a recovery upload.
    pub(crate) hide_proofs: bool,
}

impl Shared {
    /// Hold an invite code as if `writer` had registered it, for a faulty service's export.
    pub(crate) fn plant_invite(&mut self, code_hash: [u8; 32], max_uses: u64, writer: [u8; 16]) {
        self.invites.insert(code_hash, (max_uses, 0, writer));
    }
}

/// The state before a batch, for its conditions.
struct Before<'a> {
    shared: &'a Shared,
    now: u64,
}

impl ConditionState for Before<'_> {
    fn record_version(&self, key: &[u8; 32]) -> RecordVersion {
        self.shared
            .records
            .get(key)
            .map_or(RecordVersion::NONE, |held| held.state.version)
    }

    fn may_read_record(&self, _: &[u8; 32]) -> bool {
        true
    }

    fn claim_step(&self, claim_key: &[u8; 32]) -> u64 {
        self.shared
            .claims
            .get(claim_key)
            .map_or(0, |claim| claim.step)
    }

    fn claim_view(&self, _: &[u8; 32]) -> Option<Value> {
        None
    }

    fn may_read_claims(&self) -> bool {
        true
    }

    fn server_time(&self) -> u64 {
        self.now
    }
}

/// Whether a batch carries an operation of the shared state.
fn shared_batch(ops: &[SignedOp]) -> bool {
    ops.iter().any(|op| {
        matches!(
            op.body().kind,
            OpKind::RecordPut(_)
                | OpKind::Claim(_)
                | OpKind::InviteCodePut(_)
                | OpKind::InviteCodeDelete { .. }
                | OpKind::DenyPut { .. }
                | OpKind::DenyDelete { .. }
                | OpKind::AllowPut { .. }
                | OpKind::AllowDelete { .. }
        )
    })
}

impl FakeSwitch {
    /// A pending connect request from `pubky`.
    pub(crate) fn push_connect(&self, pubky: [u8; 32]) {
        let mut inner = self.lock();
        let now = inner.clock.now_ms();
        inner.shared.connect.push((pubky, now));
    }

    /// The pending connect requests.
    pub(crate) fn connects(&self) -> Vec<[u8; 32]> {
        self.lock().shared.connect.iter().map(|(p, _)| *p).collect()
    }

    /// A record write another own app makes, applied as the switch would.
    pub(crate) fn record_view(&self, key: &[u8; 32]) -> Option<HeldWrite> {
        self.lock().shared.records.get(key).cloned()
    }

    /// The claim the switch holds for `claim_key`.
    pub(crate) fn claim(&self, claim_key: &[u8; 32]) -> Option<Claim> {
        self.lock().shared.claims.get(claim_key).cloned()
    }
}

impl Inner {
    /// The routes of the shared state; `None` for any other.
    pub(super) fn route_shared(
        &mut self,
        request: &Request,
        caller: Option<[u8; 16]>,
        rest: &str,
    ) -> Option<(u16, Value)> {
        let (route, query) = rest.split_once('?').unwrap_or((rest, ""));
        match (request.method.as_str(), route) {
            ("POST", "ops") => {
                let parsed = OpsRequest::parse(&request.body).ok()?;
                let ops: Vec<SignedOp> = parsed
                    .signed()
                    .filter_map(|signed| SignedOp::peek(signed).ok())
                    .collect();
                if !shared_batch(&ops) {
                    return None;
                }
                Some(self.shared_ops(caller, &parsed, &ops))
            }
            // A scripted answer, for a faulty service, takes precedence.
            ("GET", "allow") if self.allow.is_none() => Some(self.allow_list()),
            ("GET", "connect") => {
                let requests: Vec<Value> = self
                    .shared
                    .connect
                    .iter()
                    .map(|(pubky, at)| json!({ "pubky": pubky_id(pubky), "at": rfc3339(*at) }))
                    .collect();
                Some((
                    200,
                    json!({ "requests": requests, "max_pending": 50, "full": false }),
                ))
            }
            ("DELETE", r) if r.starts_with("connect/") => {
                let id = r.trim_start_matches("connect/");
                let pubky = pubky_switch_core::enc::pubky_key(id).ok()?;
                let before = self.shared.connect.len();
                self.shared.connect.retain(|(p, _)| *p != pubky);
                if self.shared.connect.len() == before {
                    return Some(bad(ErrorCode::NotFound, "no request", json!(null)));
                }
                Some((200, json!({ "declined": id })))
            }
            ("GET", "records") => {
                let mut collection = None;
                for pair in query.split('&') {
                    if let Some(("collection", value)) = pair.split_once('=') {
                        collection = unb64_array::<32>(value).ok();
                    }
                }
                let collection = collection?;
                let views: Vec<Value> = self
                    .shared
                    .records
                    .values()
                    .filter(|held| held.state.collection == collection && !held.state.deleted)
                    .map(|held| self.view(held))
                    .collect();
                Some((
                    200,
                    json!({ "records": views, "seq": self.seq, "next": null }),
                ))
            }
            ("GET", r) if r.starts_with("records/") => {
                let key = unb64_array::<32>(r.trim_start_matches("records/")).ok()?;
                Some(match self.shared.records.get(&key) {
                    Some(held) => (200, self.view(held)),
                    None => bad(ErrorCode::NotFound, "no record", json!(null)),
                })
            }
            ("GET", r) if r.starts_with("claims/") => {
                let claim_key = unb64_array::<32>(r.trim_start_matches("claims/")).ok()?;
                Some(self.claim_answer(&claim_key))
            }
            _ => None,
        }
    }

    fn view(&self, held: &HeldWrite) -> Value {
        let cert = self
            .apps
            .get(&held.writer)
            .and_then(|app| app.cert.clone())
            .map(|cert| cert.signed().clone());
        let mut view = json!({
            "key": b64(&held.state.key),
            "collection": b64(&held.state.collection),
            "read_scope": held.state.policy.read_scope,
            "write_scopes": held.state.policy.write_scopes,
            "generation": held.state.version.generation,
            "version": held.state.version.version,
            "seq": held.seq,
            "deleted": held.state.deleted,
            "writer": zbase32_encode(&held.writer),
            "op": held.op,
            "divergent": false,
            "cert": cert,
        });
        if !self.shared.hide_proofs {
            view["proof"] = json!(held.proof);
        }
        view
    }

    fn claim_answer(&mut self, claim_key: &[u8; 32]) -> (u16, Value) {
        let now = self.now();
        if self
            .shared
            .claims
            .get(claim_key)
            .is_some_and(|claim| claim.deletable(Some(now), MAX_CLAIM_AGE_MS))
        {
            self.shared.claims.remove(claim_key);
            self.shared.entries.remove(claim_key);
        }
        let Some(claim) = self.shared.claims.get(claim_key) else {
            return bad(ErrorCode::NotFound, "no claim", json!(null));
        };
        let apps = self.apps.clone();
        let current = |app: &[u8; 16]| apps.get(app).is_some_and(|a| !a.departed);
        let view = claim.view(claim_key, now, &current).to_value();
        let entries: Vec<Value> = if claim.tombstone {
            Vec::new()
        } else {
            self.shared
                .entries
                .get(claim_key)
                .into_iter()
                .flatten()
                .map(|e| json!({ "step": e.step, "seq": e.seq, "op": e.op, "proof": e.proof }))
                .collect()
        };
        (200, json!({ "claim": view, "entries": entries }))
    }

    fn allow_list(&self) -> (u16, Value) {
        let mut contacts: BTreeMap<[u8; 32], ()> = BTreeMap::new();
        let mut conversations: BTreeMap<[u8; 32], [u8; 16]> = BTreeMap::new();
        let mut deny: BTreeMap<[u8; 32], ()> = BTreeMap::new();
        for op in &self.applied {
            let writer = op.body().app_id.unwrap_or_default();
            match &op.body().kind {
                OpKind::AllowPut { pubky, kind } => match kind {
                    AllowKind::Contact => {
                        contacts.insert(*pubky, ());
                    }
                    AllowKind::Conversation => {
                        conversations.entry(*pubky).or_insert(writer);
                    }
                },
                OpKind::AllowDelete { pubky, kind } => match kind {
                    AllowKind::Contact => {
                        contacts.remove(pubky);
                    }
                    AllowKind::Conversation => {
                        conversations.remove(pubky);
                    }
                },
                OpKind::DenyPut { pubky } => {
                    deny.insert(*pubky, ());
                }
                OpKind::DenyDelete { pubky } => {
                    deny.remove(pubky);
                }
                _ => {}
            }
        }
        let now = rfc3339(self.now());
        let codes: Vec<Value> = self
            .shared
            .invites
            .iter()
            .map(|(hash, (max, uses, by))| {
                json!({ "code_hash": b64(hash), "expires_at": now, "max_uses": max,
                        "uses": uses, "written_by": zbase32_encode(by) })
            })
            .collect();
        (
            200,
            json!({
                "contacts": contacts.keys().map(pubky_id).collect::<Vec<_>>(),
                "conversations": conversations.iter().map(|(p, by)| json!({
                    "pubky": pubky_id(p), "written_by": zbase32_encode(by), "at": now })).collect::<Vec<_>>(),
                "deny": deny.keys().map(pubky_id).collect::<Vec<_>>(),
                "flagged": [],
                "invite_codes": codes,
            }),
        )
    }

    /// A batch of the shared state: every rule checked on the state before the batch, the
    /// operations in order, then applied all or nothing.
    fn shared_ops(
        &mut self,
        caller: Option<[u8; 16]>,
        request: &OpsRequest,
        ops: &[SignedOp],
    ) -> (u16, Value) {
        if let Some(id) = ops.first().map(|op| op.body().batch.id)
            && let Some(answer) = self.answered.get(&id)
        {
            let mut answer = answer.clone();
            answer["head"] = self.head().to_value();
            return (200, answer);
        }
        // Switch wire 6.4 step 6: an operation naming another generation.
        let generation = self.tip.generation;
        if ops.iter().any(|op| op.body().generation != generation) {
            return bad(
                ErrorCode::StaleGeneration,
                "generation",
                json!({ "generation": generation }),
            );
        }
        let Some(writer) = caller else {
            return bad(ErrorCode::PermissionMissing, "apps only", json!({}));
        };
        if self.apps.get(&writer).is_some_and(|a| a.departed) {
            return bad(ErrorCode::NotCurrent, "departed", json!({}));
        }
        let epoch = self.doc.as_ref().map_or(1, |d| d.data_epoch());
        let now = self.now();
        let before = Before {
            shared: &self.shared,
            now,
        };
        for op in ops {
            if let Err(refusal) = check_conditions(&op.body().conditions, &before) {
                return bad(
                    refusal.code,
                    "condition",
                    refusal.current.unwrap_or(json!({})),
                );
            }
        }
        let mut claims = self.shared.claims.clone();
        let mut after: Vec<Option<Claim>> = Vec::new();
        for op in ops {
            match &op.body().kind {
                OpKind::RecordPut(put) => {
                    let held = self.shared.records.get(&put.key);
                    let view = held.map(|h| self.view(h));
                    if let Err(refusal) =
                        check_record_put(put, held.map(|h| &h.state), epoch, true, view.as_ref())
                    {
                        return bad(refusal.code, "record", refusal.current.unwrap_or(json!({})));
                    }
                    after.push(None);
                }
                OpKind::Claim(fields) => {
                    let Ok(entry) = fields.check() else {
                        return bad(ErrorCode::BadRequest, "claim", json!(null));
                    };
                    let apps = self.apps.clone();
                    let current = |app: &[u8; 16]| apps.get(app).is_some_and(|a| !a.departed);
                    let cx = EntryContext {
                        writer,
                        now,
                        can_read: true,
                        is_current: &current,
                        limits: ClaimLimits::default(),
                        tally: ClaimTally::count(claims.values(), &writer),
                    };
                    match apply_entry(claims.get(&entry.claim_key), &entry, &cx) {
                        Ok(claim) => {
                            claims.insert(entry.claim_key, claim.clone());
                            after.push(Some(claim));
                        }
                        Err(refusal) => {
                            return bad(
                                refusal.code,
                                "claim",
                                refusal.current.unwrap_or(json!({})),
                            );
                        }
                    }
                }
                OpKind::InviteCodePut(put) if self.shared.invites.contains_key(&put.code_hash) => {
                    return bad(ErrorCode::Conflict, "registered", json!({}));
                }
                OpKind::InviteCodeDelete { code_hash }
                    if !self.shared.invites.contains_key(code_hash) =>
                {
                    return bad(ErrorCode::NotFound, "no code", json!(null));
                }
                _ => after.push(None),
            }
        }
        let mut proofs = Vec::new();
        let generation = self.tip.generation;
        for (op, claim) in ops.iter().zip(after) {
            let body = op.body();
            let hash = op.item_hash().unwrap();
            let object = body.kind.proof_object(body.app_id.as_ref()).unwrap();
            let seq = self.seq + 1;
            let state = match (&body.kind, &claim) {
                (OpKind::RecordPut(put), _) => {
                    let state = RecordState::after(put, generation, seq);
                    ProofState::Record {
                        version: RecordVersion::new(generation, seq),
                        deleted: state.deleted,
                    }
                }
                (OpKind::Claim(fields), Some(claim)) => {
                    let key = <[u8; 32]>::try_from(fields.claim_key.as_slice()).unwrap();
                    let apps = self.apps.clone();
                    let current = |app: &[u8; 16]| apps.get(app).is_some_and(|a| !a.departed);
                    ProofState::Claim(claim.view(&key, now, &current).to_value())
                }
                (OpKind::InviteCodePut(put), _) => ProofState::InviteCodePut {
                    max_uses: put.max_uses,
                },
                (OpKind::InviteCodeDelete { .. }, _) => ProofState::InviteCodeDelete,
                (OpKind::AllowPut { kind, .. }, _) => ProofState::Allow {
                    kind: *kind,
                    present: true,
                },
                (OpKind::AllowDelete { kind, .. }, _) => ProofState::Allow {
                    kind: *kind,
                    present: false,
                },
                (OpKind::DenyPut { .. }, _) => ProofState::Deny { denied: true },
                _ => ProofState::Deny { denied: false },
            };
            let proof = self.chain_item(
                ItemType::Op,
                op.signed().clone(),
                hash,
                Some(body.batch),
                &object,
                &state,
                None,
            );
            match (&body.kind, claim) {
                (OpKind::RecordPut(put), _) => {
                    self.shared.records.insert(
                        put.key,
                        HeldWrite {
                            state: RecordState::after(put, generation, seq),
                            op: op.signed().clone(),
                            proof: proof.clone(),
                            writer,
                            seq,
                        },
                    );
                }
                (OpKind::Claim(fields), Some(claim)) => {
                    let key = <[u8; 32]>::try_from(fields.claim_key.as_slice()).unwrap();
                    self.shared.entries.entry(key).or_default().push(HeldEntry {
                        step: fields.expected_step,
                        seq,
                        op: op.signed().clone(),
                        proof: proof.clone(),
                    });
                    self.shared.claims.insert(key, claim);
                }
                (OpKind::InviteCodePut(put), _) => {
                    self.shared
                        .invites
                        .insert(put.code_hash, (put.max_uses, 0, writer));
                }
                (OpKind::InviteCodeDelete { code_hash }, _) => {
                    self.shared.invites.remove(code_hash);
                }
                (OpKind::AllowPut { pubky, kind }, _) => {
                    self.shared.connect.retain(|(p, _)| p != pubky);
                    // A scripted `GET /allow` shows the contacts added since.
                    let id = json!(pubky_id(pubky));
                    if *kind == AllowKind::Contact
                        && let Some(contacts) = self
                            .allow
                            .as_mut()
                            .and_then(|allow| allow["contacts"].as_array_mut())
                        && !contacts.contains(&id)
                    {
                        contacts.push(id);
                    }
                }
                (OpKind::DenyPut { pubky }, _) => {
                    self.shared.connect.retain(|(p, _)| p != pubky);
                }
                _ => {}
            }
            self.applied.push(op.clone());
            proofs.push(proof);
        }
        if let Some(position) = request.cursor() {
            self.apps.entry(writer).or_default().cursor = position.seq;
        }
        let answer = json!({ "proofs": proofs, "head": self.head().to_value() });
        if let Some(op) = ops.first() {
            self.answered.insert(op.body().batch.id, answer.clone());
        }
        (200, answer)
    }
}
