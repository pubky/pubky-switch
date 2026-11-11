//! The scripted switch's shared state: shared records, claims, the lists, invite codes and
//! connect requests, their reads (Switch wire 7.4.6 to 7.4.9), and the rules of their
//! operations (Switch wire 6.2, 6.8), which are the core's.

use std::collections::{BTreeMap, BTreeSet};

use pubky_switch_core::chain::{ProofState, TransitionProof};
use pubky_switch_core::claims::{
    Claim, ClaimFields, ClaimLimits, ClaimTally, EntryContext, MAX_CLAIM_AGE_MS, apply_entry,
};
use pubky_switch_core::enc::{b64, pubky_id, unb64_array, zbase32_encode};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ops::{
    AllowKind, ConditionState, InviteCodePut, MAX_INVITE_USES, RecordPut, RecordVersion, Refusal,
    SignedOp, check_invite_code_put,
};
use pubky_switch_core::records::AppCert;
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::shared::{RecordState, check_record_put};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::rfc3339;
use serde_json::{Value, json};

use super::{Answer, Inner, ScriptedSwitch, SwitchApp, bad};
use crate::clock::Clock;
use crate::transport::Request;

/// A shared record as the switch holds it, with what its reads return (Switch wire 7.4.9).
#[derive(Clone, Debug)]
pub struct HeldRecord {
    /// The record's state after its newest write.
    pub state: RecordState,
    /// The newest write's signed `record.put`.
    pub op: SignedDoc,
    /// The write's transition proof.
    pub proof: SignedDoc,
    /// The App ID that wrote it.
    pub writer: [u8; 16],
    /// The writer's certificate the switch checked the write against, kept with the record:
    /// a renewal or revocation later doesn't change it (Switch wire 7.4.9). `None` for a
    /// record held without it, whose view carries the certificate of the writer's record.
    pub cert: Option<SignedDoc>,
    /// The write's `seq`.
    pub seq: u64,
}

/// An invite code the switch holds (Switch spec 7).
#[derive(Clone, Debug)]
pub(crate) struct Invite {
    pub(crate) max_uses: u64,
    pub(crate) uses: u64,
    pub(crate) writer: [u8; 16],
    pub(crate) expires_at: u64,
    pub(crate) context: Value,
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
    pub(crate) records: BTreeMap<[u8; 32], HeldRecord>,
    pub(crate) claims: BTreeMap<[u8; 32], Claim>,
    entries: BTreeMap<[u8; 32], Vec<HeldEntry>>,
    pub(crate) connect: Vec<([u8; 32], u64)>,
    /// By code hash.
    pub(crate) invites: BTreeMap<[u8; 32], Invite>,
    contacts: BTreeSet<[u8; 32]>,
    /// By Pubky ID: the writer and the time of the entry.
    conversations: BTreeMap<[u8; 32], ([u8; 16], u64)>,
    /// Conversation entries the service wrote for senders an invite code admitted, by Pubky
    /// ID: the code's hash, the time of the entry and the code's context (Switch spec 7,
    /// Switch wire 6.5 `conversation.add`).
    pub(crate) service_conversations: BTreeMap<[u8; 32], ([u8; 32], u64, Value)>,
    /// The service time of the last append each conversation entry admitted, by Pubky ID
    /// (Switch wire 7.4.6 `last_used`): none until one.
    conversation_used: BTreeMap<[u8; 32], u64>,
    deny: BTreeSet<[u8; 32]>,
    /// The flagged senders `GET /allow` shows, with their hits (Switch wire 7.4.6).
    pub(crate) flagged: BTreeMap<[u8; 32], u64>,
    /// Answer the next record read without its proof, as after a recovery upload.
    pub(crate) hide_proofs: bool,
    /// A faulty listing: every page names these two keys as `next` in turn, for the first
    /// 50 pages.
    pub(crate) alternate_next: Option<([u8; 32], [u8; 32])>,
    /// Listing pages answered.
    pub(crate) listings: u64,
}

#[cfg(test)]
impl Shared {
    /// Hold an invite code as if `writer` had registered it, for a faulty service's export.
    pub(crate) fn plant_invite(&mut self, code_hash: [u8; 32], max_uses: u64, writer: [u8; 16]) {
        self.invites.insert(
            code_hash,
            Invite {
                max_uses,
                uses: 0,
                writer,
                expires_at: u64::MAX,
                context: Value::Null,
            },
        );
    }
}

/// What a shared operation is checked and applied with.
pub(super) struct OpContext<'a> {
    /// The writing app; `None` for the signer.
    pub(super) writer: Option<[u8; 16]>,
    /// The certificate the writer is checked against; `None` for the signer.
    pub(super) cert: Option<&'a AppCert>,
    /// The account's apps, for record views and claim views.
    pub(super) apps: &'a BTreeMap<[u8; 16], SwitchApp>,
    /// Whether an app is current (Switch spec 3.4).
    pub(super) is_current: &'a dyn Fn(&[u8; 16]) -> bool,
    /// The service time of the batch.
    pub(super) now: u64,
    /// The account's current data epoch.
    pub(super) data_epoch: u64,
}

impl OpContext<'_> {
    /// Whether the writer may read a record of `read_scope` (the signer reads everything).
    fn may_read(&self, read_scope: &str) -> bool {
        self.cert.is_none_or(|cert| cert.holds_scope(read_scope))
    }

    /// Whether the writer holds `claims.read`.
    fn may_read_claims(&self) -> bool {
        self.cert
            .is_none_or(|cert| cert.has_permission(Permission::ClaimsRead))
    }
}

/// The state before a batch, for its conditions (Switch wire 6.3).
pub(super) struct Before<'a> {
    pub(super) shared: &'a Shared,
    pub(super) cx: &'a OpContext<'a>,
}

impl ConditionState for Before<'_> {
    fn record_version(&self, key: &[u8; 32]) -> RecordVersion {
        self.shared
            .records
            .get(key)
            .map_or(RecordVersion::NONE, |held| held.state.version)
    }

    fn may_read_record(&self, key: &[u8; 32]) -> bool {
        self.shared
            .records
            .get(key)
            .is_none_or(|held| self.cx.may_read(&held.state.policy.read_scope))
    }

    fn claim_step(&self, claim_key: &[u8; 32]) -> u64 {
        self.shared
            .claims
            .get(claim_key)
            .map_or(0, |claim| claim.step)
    }

    fn claim_view(&self, claim_key: &[u8; 32]) -> Option<Value> {
        self.shared.claims.get(claim_key).map(|claim| {
            claim
                .view(claim_key, self.cx.now, self.cx.is_current)
                .to_value()
        })
    }

    fn may_read_claims(&self) -> bool {
        self.cx.may_read_claims()
    }

    fn server_time(&self) -> u64 {
        self.cx.now
    }
}

/// A record's view, as `GET /records` returns it (Switch wire 7.4.9): its `cert` is the one
/// the write was checked against, or for a record held without it, the one the writer's
/// record carries.
fn record_view(held: &HeldRecord, apps: &BTreeMap<[u8; 16], SwitchApp>, proof: bool) -> Value {
    let cert = held.cert.clone().or_else(|| {
        apps.get(&held.writer)
            .and_then(|app| app.cert.clone())
            .map(|cert| cert.signed().clone())
    });
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
    if proof {
        view["proof"] = json!(held.proof);
    }
    view
}

/// The rules of the shared operations, each against the state the earlier operations of its
/// batch left. Records and claim entries are kept once their proof is signed, by
/// [`Shared::record_written`] and [`Shared::claim_written`].
impl Shared {
    /// `record.put` (Switch wire 6.2, Switch spec 10.3), by [`check_record_put`].
    pub(super) fn record_put(
        &self,
        put: &RecordPut,
        cx: &OpContext<'_>,
        generation: u64,
        seq: u64,
    ) -> Result<ProofState, Refusal> {
        let held = self.records.get(&put.key);
        let view = held.map(|h| record_view(h, cx.apps, true));
        check_record_put(
            put,
            held.map(|h| &h.state),
            cx.data_epoch,
            cx.may_read(&put.policy.read_scope),
            view.as_ref(),
        )?;
        Ok(ProofState::Record {
            version: RecordVersion::new(generation, seq),
            deleted: put.value_sealed.looks_like_delete(),
        })
    }

    /// The generations the kept proofs name (Switch wire 3.3 "Service keys"): each held
    /// record's current write's proof, and each entry proof of a live claim, not a
    /// tombstone. A proof that doesn't read is left out.
    pub(crate) fn kept_proof_generations(&self) -> (Vec<u64>, Vec<u64>) {
        let generation = |proof: &SignedDoc| {
            TransitionProof::peek(proof)
                .ok()
                .map(|p| p.envelope().generation)
        };
        let records = self
            .records
            .values()
            .filter_map(|held| generation(&held.proof))
            .collect();
        let entries = self
            .entries
            .iter()
            .filter(|(key, _)| self.claims.get(*key).is_some_and(|c| !c.tombstone))
            .flat_map(|(_, entries)| entries.iter().filter_map(|e| generation(&e.proof)))
            .collect();
        (records, entries)
    }

    /// Whether the entry at `seq` belongs to the claim held at `claim_key`, and that claim
    /// isn't a tombstone: a compacted or deleted claim's entries are gone (Switch wire 6.8
    /// "Tombstones", 7.5).
    pub(super) fn claim_entry_current(&self, claim_key: &[u8; 32], seq: u64) -> bool {
        self.claims.get(claim_key).is_some_and(|c| !c.tombstone)
            && self
                .entries
                .get(claim_key)
                .is_some_and(|entries| entries.iter().any(|e| e.seq == seq))
    }

    /// Keep a written record with its proof.
    pub(super) fn record_written(&mut self, put: &RecordPut, written: Written<'_>) {
        self.records.insert(
            put.key,
            HeldRecord {
                state: RecordState::after(put, written.generation, written.seq),
                op: written.op.signed().clone(),
                proof: written.proof.clone(),
                writer: written.writer,
                cert: written.cert.map(|cert| cert.signed().clone()),
                seq: written.seq,
            },
        );
    }

    /// A claim entry (Switch wire 6.8), by [`apply_entry`] with the default limits.
    pub(super) fn claim(
        &mut self,
        fields: &ClaimFields,
        cx: &OpContext<'_>,
    ) -> Result<ProofState, Refusal> {
        let entry = fields.check()?;
        let writer = cx.writer.unwrap_or_default();
        let entry_cx = EntryContext {
            writer,
            now: cx.now,
            can_read: cx.may_read_claims(),
            is_current: cx.is_current,
            limits: ClaimLimits::default(),
            tally: ClaimTally::count(self.claims.values(), &writer),
        };
        let claim = apply_entry(self.claims.get(&entry.claim_key), &entry, &entry_cx)?;
        let view = claim
            .view(&entry.claim_key, cx.now, cx.is_current)
            .to_value();
        self.claims.insert(entry.claim_key, claim);
        Ok(ProofState::Claim(view))
    }

    /// Keep a claim entry with its proof, for `GET /claims`.
    pub(super) fn claim_written(&mut self, fields: &ClaimFields, written: Written<'_>) {
        let Ok(entry) = fields.check() else {
            return;
        };
        self.entries
            .entry(entry.claim_key)
            .or_default()
            .push(HeldEntry {
                step: fields.expected_step,
                seq: written.seq,
                op: written.op.signed().clone(),
                proof: written.proof.clone(),
            });
    }

    /// `invite_code.put` (Switch wire 6.2), by [`check_invite_code_put`].
    pub(super) fn invite_code_put(
        &mut self,
        put: &InviteCodePut,
        cx: &OpContext<'_>,
    ) -> Result<ProofState, Refusal> {
        check_invite_code_put(
            put,
            MAX_INVITE_USES,
            self.invites.contains_key(&put.code_hash),
        )?;
        self.invites.insert(
            put.code_hash,
            Invite {
                max_uses: put.max_uses,
                uses: 0,
                writer: cx.writer.unwrap_or_default(),
                expires_at: put.expires_at,
                context: put.context.value().clone(),
            },
        );
        Ok(ProofState::InviteCodePut {
            max_uses: put.max_uses,
        })
    }

    /// `invite_code.delete` (Switch wire 6.2): the core has no rule for it that needs state;
    /// a code that isn't registered is `404`.
    pub(super) fn invite_code_delete(
        &mut self,
        code_hash: &[u8; 32],
    ) -> Result<ProofState, Refusal> {
        if self.invites.remove(code_hash).is_none() {
            return Err(Refusal::new(
                ErrorCode::NotFound,
                "Switch wire 6.2: no such invite code",
            ));
        }
        Ok(ProofState::InviteCodeDelete)
    }

    /// `allow.put` (Switch wire 6.2): the entry, and the sender's connect request goes
    /// (Switch wire 7.4.7).
    pub(super) fn allow_put(
        &mut self,
        pubky: &[u8; 32],
        kind: AllowKind,
        cx: &OpContext<'_>,
    ) -> ProofState {
        match kind {
            AllowKind::Contact => {
                self.contacts.insert(*pubky);
            }
            AllowKind::Conversation => {
                self.conversations
                    .entry(*pubky)
                    .or_insert((cx.writer.unwrap_or_default(), cx.now));
            }
        }
        self.connect.retain(|(p, _)| p != pubky);
        ProofState::Allow {
            kind,
            present: true,
        }
    }

    /// A contact the account holds without an operation that wrote it, as an upload after a
    /// provider loss brings one back (Switch spec 12.6 step 2).
    #[cfg(test)]
    pub(crate) fn add_contact(&mut self, pubky: [u8; 32]) {
        self.contacts.insert(pubky);
    }

    /// Note an admitted append's time on `sender`'s conversation entry, an app's or the
    /// service's, if it has one (Switch spec 7 "Pruning", Switch wire 7.4.6 `last_used`).
    pub(super) fn note_conversation_used(&mut self, sender: &[u8; 32], at: u64) {
        if self.conversations.contains_key(sender)
            || self.service_conversations.contains_key(sender)
        {
            self.conversation_used.insert(*sender, at);
        }
    }

    /// `allow.delete` (Switch wire 6.2); a conversation entry goes whoever wrote it.
    pub(super) fn allow_delete(&mut self, pubky: &[u8; 32], kind: AllowKind) -> ProofState {
        match kind {
            AllowKind::Contact => self.contacts.remove(pubky),
            AllowKind::Conversation => {
                self.conversation_used.remove(pubky);
                let service = self.service_conversations.remove(pubky).is_some();
                self.conversations.remove(pubky).is_some() || service
            }
        };
        ProofState::Allow {
            kind,
            present: false,
        }
    }

    /// `deny.put` and `deny.delete` (Switch wire 6.2); a denial ends the connect request.
    pub(super) fn deny(&mut self, pubky: &[u8; 32], denied: bool) -> ProofState {
        if denied {
            self.deny.insert(*pubky);
            self.connect.retain(|(p, _)| p != pubky);
        } else {
            self.deny.remove(pubky);
        }
        ProofState::Deny { denied }
    }

    /// Whether a record's current write isn't a delete.
    pub(super) fn record_live(&self, key: &[u8; 32]) -> bool {
        self.records
            .get(key)
            .is_some_and(|held| !held.state.deleted)
    }

    /// Whether the allowlist holds the entry.
    pub(super) fn allowed(&self, pubky: &[u8; 32], kind: AllowKind) -> bool {
        match kind {
            AllowKind::Contact => self.contacts.contains(pubky),
            AllowKind::Conversation => {
                self.conversations.contains_key(pubky)
                    || self.service_conversations.contains_key(pubky)
            }
        }
    }

    /// Whether the deny list holds the Pubky ID.
    pub(super) fn denied(&self, pubky: &[u8; 32]) -> bool {
        self.deny.contains(pubky)
    }
}

/// `403 permission_missing`, for a read the caller may not make.
fn permission_missing(message: &str) -> Answer {
    bad(ErrorCode::PermissionMissing, message, json!(null))
}

/// A written operation, once its proof is signed.
pub(super) struct Written<'a> {
    pub(super) op: &'a SignedOp,
    pub(super) proof: &'a SignedDoc,
    pub(super) writer: [u8; 16],
    /// The certificate the writer was checked against; `None` for the signer.
    pub(super) cert: Option<&'a AppCert>,
    pub(super) generation: u64,
    pub(super) seq: u64,
}

impl ScriptedSwitch {
    /// A pending connect request from `pubky` (Switch wire 7.4.7).
    pub fn push_connect(&self, pubky: [u8; 32]) {
        let mut inner = self.lock();
        let now = inner.clock.now_ms();
        inner.shared.connect.push((pubky, now));
    }

    /// The identities with a pending connect request.
    pub fn connects(&self) -> Vec<[u8; 32]> {
        self.lock().shared.connect.iter().map(|(p, _)| *p).collect()
    }

    /// The shared record the switch holds at `key`, deleted or not.
    pub fn record(&self, key: &[u8; 32]) -> Option<HeldRecord> {
        self.lock().shared.records.get(key).cloned()
    }

    /// The claim the switch holds for `claim_key`.
    pub fn claim(&self, claim_key: &[u8; 32]) -> Option<Claim> {
        self.lock().shared.claims.get(claim_key).cloned()
    }
}

impl Inner {
    /// The reads of the shared state, for `caller` (`None` for the signer); `None` for any
    /// other route.
    pub(super) fn route_shared(
        &mut self,
        request: &Request,
        caller: Option<[u8; 16]>,
        rest: &str,
    ) -> Option<Answer> {
        let (route, query) = rest.split_once('?').unwrap_or((rest, ""));
        Some(match (request.method.as_str(), route) {
            // A scripted answer, for a faulty service, takes precedence.
            ("GET", "allow") if self.allow.is_none() => self.allow_list(),
            ("GET", "connect") => {
                let requests: Vec<Value> = self
                    .shared
                    .connect
                    .iter()
                    .map(|(pubky, at)| json!({ "pubky": pubky_id(pubky), "at": rfc3339(*at) }))
                    .collect();
                (
                    200,
                    json!({ "requests": requests, "max_pending": 50, "full": false }),
                )
            }
            ("DELETE", r) if r.starts_with("connect/") => {
                let id = r.trim_start_matches("connect/");
                let pubky = pubky_switch_core::enc::pubky_key(id).ok()?;
                let before = self.shared.connect.len();
                self.shared.connect.retain(|(p, _)| *p != pubky);
                if self.shared.connect.len() == before {
                    return Some(bad(ErrorCode::NotFound, "no request", json!(null)));
                }
                (200, json!({ "declined": id }))
            }
            ("GET", "records") => self.list_records(caller, query),
            ("GET", r) if r.starts_with("records/") => {
                self.record_answer(caller, r.trim_start_matches("records/"))
            }
            ("GET", r) if r.starts_with("claims/") => {
                // Only an own app holding `claims.read`, before the key is read
                // (`crates/pubky-switch/src/service/claims.rs`, `get_claim`).
                let reads = caller
                    .and_then(|app| self.checked_cert(&app))
                    .is_some_and(|cert| cert.has_permission(Permission::ClaimsRead));
                if !reads {
                    return Some(permission_missing(
                        "7.4.8: reading claims needs claims.read",
                    ));
                }
                match unb64_array::<32>(r.trim_start_matches("claims/")) {
                    Ok(claim_key) => self.claim_answer(&claim_key),
                    Err(_) => bad(ErrorCode::BadRequest, "a claim key is b64(32)", json!(null)),
                }
            }
            _ => return None,
        })
    }

    /// The certificate an own app's record reads are checked against (Switch wire 7.4.9),
    /// the one the switch checks the app against; the signer reads no records (`403
    /// permission_missing`, `crates/pubky-switch/src/service/records.rs`, `only_apps`).
    fn record_reader(&self, caller: Option<[u8; 16]>) -> Result<Option<AppCert>, Answer> {
        match caller {
            Some(app) => Ok(self.checked_cert(&app)),
            None => Err(permission_missing(
                "7.4.9: apps read records; the signer doesn't",
            )),
        }
    }

    /// `GET /records/{key}` (Switch wire 7.4.9), in the service's order
    /// (`crates/pubky-switch/src/service/records.rs`, `get_record`): the signer refused, the
    /// key read (`400`), the record found (`404`), then its `read_scope` held by the reader's
    /// certificate (`403 permission_missing`). An own app the switch holds no certificate
    /// for holds no scope.
    fn record_answer(&self, caller: Option<[u8; 16]>, key: &str) -> Answer {
        let cert = match self.record_reader(caller) {
            Ok(cert) => cert,
            Err(refused) => return refused,
        };
        let Ok(key) = unb64_array::<32>(key) else {
            return bad(
                ErrorCode::BadRequest,
                "a record key is b64(32)",
                json!(null),
            );
        };
        let Some(held) = self.shared.records.get(&key) else {
            return bad(ErrorCode::NotFound, "no record", json!(null));
        };
        if !cert.is_some_and(|cert| cert.holds_scope(&held.state.policy.read_scope)) {
            return permission_missing("7.4.9: reading the record needs its read_scope");
        }
        (200, record_view(held, &self.apps, !self.shared.hide_proofs))
    }

    /// `GET /records?collection=&after=&limit=` (Switch wire 7.4.9), its query read as the
    /// service reads it (`crates/pubky-switch/src/service/records.rs`,
    /// `RecordsQuery::parse`): `collection` required and `b64(32)`, `after` a record key,
    /// its text the one keys compare with, and `limit` digits only, 1 to 1000; other
    /// parameters ignored. The records shown are those whose `read_scope` the reader's
    /// certificate holds.
    fn list_records(&mut self, caller: Option<[u8; 16]>, query: &str) -> Answer {
        let cert = match self.record_reader(caller) {
            Ok(cert) => cert,
            Err(refused) => return refused,
        };
        let param = |name: &str| {
            query
                .split('&')
                .find_map(|pair| match pair.split_once('=') {
                    Some((key, value)) if key == name => Some(value),
                    _ => None,
                })
        };
        let Some(collection) = param("collection") else {
            return bad(ErrorCode::BadRequest, "collection is required", json!(null));
        };
        let Ok(collection) = unb64_array::<32>(collection) else {
            return bad(ErrorCode::BadRequest, "collection", json!(null));
        };
        // A key has one text (Switch wire 1.2): the one given, read, is what keys compare
        // with, as unpadded base64url text in ASCII order.
        let after = match param("after").map(unb64_array::<32>) {
            None => None,
            Some(Ok(key)) => Some(b64(&key)),
            Some(Err(_)) => return bad(ErrorCode::BadRequest, "after", json!(null)),
        };
        let limit = match param("limit") {
            None => 1000,
            Some(text) => match text.parse::<usize>() {
                Ok(value @ 1..=1000)
                    if text.len() <= 16 && text.bytes().all(|b| b.is_ascii_digit()) =>
                {
                    value
                }
                _ => return bad(ErrorCode::BadRequest, "limit", json!(null)),
            },
        };
        // Ordered by the base64url text of their keys, after `after` (Switch wire 7.4.9).
        let mut listed: Vec<(String, Value)> = self
            .shared
            .records
            .values()
            .filter(|held| held.state.collection == collection && !held.state.deleted)
            .filter(|held| {
                cert.as_ref()
                    .is_some_and(|cert| cert.holds_scope(&held.state.policy.read_scope))
            })
            .map(|held| {
                (
                    b64(&held.state.key),
                    record_view(held, &self.apps, !self.shared.hide_proofs),
                )
            })
            .filter(|(key, _)| after.as_ref().is_none_or(|after| key > after))
            .collect();
        listed.sort_by(|a, b| a.0.cmp(&b.0));
        let mut views = Vec::new();
        let mut bytes = 0usize;
        let mut last = None;
        let mut more = false;
        for (key, view) in listed {
            let size = view.to_string().len();
            // `limit`, or the byte budget, ends the page; its first view is shown whatever
            // its size.
            if views.len() >= limit
                || (!views.is_empty() && bytes.saturating_add(size) > self.max_page_bytes)
            {
                more = true;
                break;
            }
            bytes = bytes.saturating_add(size);
            views.push(view);
            last = Some(key);
        }
        self.shared.listings += 1;
        let next = match self.shared.alternate_next {
            Some((a, b)) if self.shared.listings <= 50 => {
                json!(b64(if self.shared.listings % 2 == 1 {
                    &a
                } else {
                    &b
                }))
            }
            _ if more => json!(last),
            _ => json!(null),
        };
        (
            200,
            json!({ "records": views, "seq": self.seq, "next": next }),
        )
    }

    fn claim_answer(&mut self, claim_key: &[u8; 32]) -> Answer {
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
        let current = |app: &[u8; 16]| self.app_current(&self.apps, app);
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

    fn allow_list(&self) -> Answer {
        let now = self.now();
        let codes: Vec<Value> = self
            .shared
            .invites
            .iter()
            .filter(|(_, invite)| invite.uses < invite.max_uses && now < invite.expires_at)
            .map(|(hash, invite)| {
                json!({ "code_hash": b64(hash), "expires_at": rfc3339(invite.expires_at),
                        "max_uses": invite.max_uses, "uses": invite.uses,
                        "written_by": zbase32_encode(&invite.writer) })
            })
            .collect();
        let conversations: Vec<Value> = self
            .shared
            .conversations
            .iter()
            .map(|(pubky, (by, at))| {
                (
                    pubky,
                    json!({ "pubky": pubky_id(pubky), "written_by": zbase32_encode(by),
                            "at": rfc3339(*at) }),
                )
            })
            // The entries the service wrote, each with its code's context (Switch wire
            // 7.4.6).
            .chain(
                self.shared
                    .service_conversations
                    .iter()
                    .filter(|(pubky, _)| !self.shared.conversations.contains_key(*pubky))
                    .map(|(pubky, (code, at, context))| {
                        (
                            pubky,
                            json!({ "pubky": pubky_id(pubky), "written_by": "service",
                                    "code_hash": b64(code), "context": context,
                                    "at": rfc3339(*at) }),
                        )
                    }),
            )
            // `last_used`, once an append the entry admitted.
            .map(|(pubky, mut entry)| {
                if let Some(used) = self.shared.conversation_used.get(pubky) {
                    entry["last_used"] = json!(rfc3339(*used));
                }
                entry
            })
            .collect();
        (
            200,
            json!({
                "contacts": self.shared.contacts.iter().map(pubky_id).collect::<Vec<_>>(),
                "conversations": conversations,
                "deny": self.shared.deny.iter().map(pubky_id).collect::<Vec<_>>(),
                "flagged": self
                    .shared
                    .flagged
                    .iter()
                    .map(|(pubky, hits)| json!({ "pubky": pubky_id(pubky), "hits": hits }))
                    .collect::<Vec<_>>(),
                "invite_codes": codes,
            }),
        )
    }
}
