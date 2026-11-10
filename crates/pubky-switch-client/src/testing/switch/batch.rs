//! The scripted switch's batch handler (Switch wire 6.4). Every batch goes through it,
//! whether an app submits it with `POST /ops` or a test injects it with
//! [`ScriptedSwitch::app_op`](super::ScriptedSwitch::app_op) or
//! [`ScriptedSwitch::signer_op`](super::ScriptedSwitch::signer_op): the same authentication of
//! the writer, the same checks, the same state changes, proofs and chain items. The rules are
//! the core's; `FAKES.md` lists what it leaves out.

use std::collections::BTreeMap;

use pubky_switch_core::chain::{ItemType, ProofState};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ops::{
    AllowKind, AppPutEffect, BATCH_PROOFS_MS, BatchEffect, BatchRecord, CertPutEffect, Held,
    KeyBundleEffect, KeyBundlePut, OpKind, Position, ReceiveKeyEffect, Refusal, RetryCheck,
    SignedOp, Writer, batch_effect, check_app_put, check_batch, check_cert_put, check_conditions,
    check_key_bundle_put, check_permission, check_receive_key_put, check_shape, ops_hash,
    retry_check,
};
use pubky_switch_core::records::{AppCert, AppRecord, ReceiveKeyRecord, Standing};
use pubky_switch_core::sig::SignedDoc;
use serde_json::{Value, json};

use super::shared::{Before, OpContext, Shared, Written};
use super::{Answer, Inner, SwitchApp, missing};
use crate::testing::ScriptError;

/// Why a batch ends: a refusal the switch answers, or a failure of the script itself.
enum Fail {
    Refused(Refusal),
    Script(ScriptError),
}

impl From<Refusal> for Fail {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

impl From<ScriptError> for Fail {
    fn from(error: ScriptError) -> Self {
        Self::Script(error)
    }
}

impl From<pubky_switch_core::Error> for Fail {
    fn from(error: pubky_switch_core::Error) -> Self {
        Self::Script(error.into())
    }
}

/// The error answer of a refusal (Switch wire 7.6): `current` only where the rule gives one.
pub(super) fn refused(refusal: &Refusal) -> Answer {
    let mut body = json!({ "code": refusal.code.as_str(), "message": refusal.reason });
    if let Some(current) = &refusal.current {
        body["current"] = current.clone();
    }
    (refusal.status(), body)
}

/// The state a batch changes, applied all or nothing (Switch wire 6.4 step 11).
struct Draft {
    apps: BTreeMap<[u8; 16], SwitchApp>,
    bundles: BTreeMap<[u8; 16], Vec<(KeyBundlePut, u64)>>,
    kids: BTreeMap<[u8; 8], [u8; 16]>,
    shared: Shared,
    /// The directory's versions (Switch wire 7.4.10).
    directory_version: u64,
    apps_version: u64,
    reachable_since: BTreeMap<[u8; 16], u64>,
}

/// What the no-op and rate rules compare a batch with, before it (Switch wire 6.4 step 7).
struct HeldState<'a>(&'a Inner);

impl Held for HeldState<'_> {
    fn app_record(&self, app_id: &[u8; 16]) -> Option<SignedDoc> {
        self.0.apps.get(app_id)?.record.clone()
    }

    fn receive_key(&self, app_id: &[u8; 16]) -> Option<SignedDoc> {
        self.0.apps.get(app_id)?.receive_key.clone()
    }

    fn renewed_cert(&self, app_id: &[u8; 16]) -> Option<SignedDoc> {
        Some(self.0.apps.get(app_id)?.renewed.as_ref()?.signed().clone())
    }

    fn record_cert(&self, app_id: &[u8; 16]) -> Option<SignedDoc> {
        Some(self.0.apps.get(app_id)?.cert.as_ref()?.signed().clone())
    }

    fn holds_bundle_part(&self, part: &KeyBundlePut) -> bool {
        self.0
            .bundles
            .get(&part.target_app_id)
            .is_some_and(|parts| parts.iter().any(|(held, _)| held == part))
    }

    fn record_live(&self, key: &[u8; 32]) -> bool {
        self.0.shared.record_live(key)
    }

    fn allowed(&self, pubky: &[u8; 32], kind: AllowKind) -> bool {
        self.0.shared.allowed(pubky, kind)
    }

    fn denied(&self, pubky: &[u8; 32]) -> bool {
        self.0.shared.denied(pubky)
    }
}

fn not_current(reason: &str) -> Refusal {
    Refusal::new(ErrorCode::NotCurrent, format!("Switch wire 7.2: {reason}"))
}

impl Inner {
    /// Apply a batch from `caller` (`None` for the signer), as the switch does (Switch wire
    /// 6.4 steps 3 to 11), and give its answer.
    ///
    /// # Errors
    ///
    /// Only when the script fails, such as a proof that doesn't sign; a refusal is an error
    /// answer.
    pub(super) fn submit(
        &mut self,
        caller: Option<[u8; 16]>,
        signed: &[SignedDoc],
        cursor: Option<Position>,
    ) -> Result<Answer, ScriptError> {
        match self.batch(caller, signed, cursor) {
            Ok(answer) => Ok(answer),
            Err(Fail::Refused(refusal)) => Ok(refused(&refusal)),
            Err(Fail::Script(error)) => Err(error),
        }
    }

    /// Whether `app` is current in `apps` (Switch spec 3.4): neither revoked nor departed,
    /// and its record's certificate, or a renewed one, listed or in an open renewal in the
    /// newest `identity.json` and unexpired.
    pub(super) fn app_current(&self, apps: &BTreeMap<[u8; 16], SwitchApp>, app: &[u8; 16]) -> bool {
        let (Some(held), Some(doc)) = (apps.get(app), &self.doc) else {
            return false;
        };
        let now = self.now();
        !held.departed
            && [held.renewed.as_ref(), held.cert.as_ref()]
                .into_iter()
                .flatten()
                .any(|cert| {
                    matches!(
                        doc.standing(app, &cert.hash()),
                        Standing::Listed | Standing::RenewedOpen
                    ) && !cert.expired_at(now)
                })
    }

    fn answer(&self, proofs: &[SignedDoc]) -> Answer {
        (
            200,
            json!({ "proofs": proofs, "head": self.head().to_value() }),
        )
    }

    fn batch(
        &mut self,
        caller: Option<[u8; 16]>,
        signed: &[SignedDoc],
        cursor: Option<Position>,
    ) -> Result<Answer, Fail> {
        let identity = self.identity.public();
        let now = self.now();
        let cert = caller
            .map(|app| self.authenticate(app, signed))
            .transpose()?;
        // Step 3: each operation's signature with the caller's key.
        let key = cert.as_ref().map_or(identity, AppCert::signing_key);
        let ops = signed
            .iter()
            .map(|doc| SignedOp::verify(doc, &key, &identity, caller.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        check_batch(&ops)?;
        // Step 5: a retry gets the original proofs while they are kept.
        let hash = match ops.first() {
            Some(first) => {
                let hash = ops_hash(&ops)?;
                let mut held = self.batches.get(&first.body().batch.id).cloned();
                if let Some(record) = held.as_mut()
                    && record.proofs_expired(now, BATCH_PROOFS_MS)
                {
                    record.proofs = None;
                }
                if let RetryCheck::Retry(proofs) = retry_check(held.as_ref(), &hash)? {
                    return Ok(self.answer(&proofs));
                }
                Some(hash)
            }
            None => None,
        };
        // Step 6.
        let generation = self.tip.generation;
        if ops.iter().any(|op| op.body().generation != generation) {
            return Err(Refusal::new(
                ErrorCode::StaleGeneration,
                "Switch wire 6.4: an operation naming another generation",
            )
            .with_current(json!({ "generation": generation }))
            .into());
        }
        // Step 7: no rates and no trusted time here (FAKES.md).
        let effect = batch_effect(&ops, &HeldState(self), cursor.is_some());
        if effect == BatchEffect::NoOp {
            return Ok(self.answer(&[]));
        }
        let (mut draft, states) = {
            let is_current = |app: &[u8; 16]| self.app_current(&self.apps, app);
            let cx = OpContext {
                writer: caller,
                cert: cert.as_ref(),
                apps: &self.apps,
                is_current: &is_current,
                now,
                data_epoch: self.doc.as_ref().map_or(1, |doc| doc.data_epoch()),
            };
            // Step 8: every condition, against the state before the batch.
            let before = Before {
                shared: &self.shared,
                cx: &cx,
            };
            for op in &ops {
                check_conditions(&op.body().conditions, &before)?;
            }
            // Step 9: each operation against the state the earlier ones left.
            let writer = cert.as_ref().map_or(Writer::Signer, Writer::App);
            let mut draft = self.draft();
            let mut states = Vec::with_capacity(ops.len());
            for (seq, op) in (self.seq + 1..).zip(&ops) {
                check_permission(&op.body().kind, writer)?;
                check_shape(op.body())?;
                states.push(self.apply_op(&mut draft, op, &cx, cert.as_ref(), seq)?);
            }
            (draft, states)
        };
        // Step 10.
        if let (Some(app), Some(position)) = (caller, cursor) {
            draft.apps.entry(app).or_default().cursor = position.seq;
        }
        if effect == BatchEffect::Unchanged {
            self.commit(draft);
            return Ok(self.answer(&[]));
        }
        // Step 11: the chain items and their proofs, then the state, all at once.
        let first_seq = self.seq + 1;
        let mut proofs = Vec::with_capacity(ops.len());
        for (op, (state, only_for)) in ops.iter().zip(states) {
            let body = op.body();
            let object = body
                .kind
                .proof_object(body.app_id.as_ref())
                .ok_or_else(|| missing("an operation without a proof object"))?;
            let proof = self.chain_item(
                ItemType::Op,
                op.signed().clone(),
                op.item_hash()?,
                Some(body.batch),
                &object,
                &state,
                only_for,
            )?;
            let written = Written {
                op,
                proof: &proof,
                writer: caller.unwrap_or_default(),
                generation,
                seq: self.seq,
            };
            match &body.kind {
                OpKind::RecordPut(put) => draft.shared.record_written(put, written),
                OpKind::Claim(fields) => draft.shared.claim_written(fields, written),
                OpKind::AllowPut {
                    pubky,
                    kind: AllowKind::Contact,
                } => self.show_scripted_contact(pubky),
                _ => {}
            }
            self.applied.push(op.clone());
            proofs.push(proof);
        }
        self.commit(draft);
        if let (Some(first), Some(ops_hash)) = (ops.first(), hash) {
            self.batches.insert(
                first.body().batch.id,
                BatchRecord {
                    ops_hash,
                    proofs: Some(proofs.clone()),
                    at: now,
                    first_seq,
                    last_seq: self.seq,
                },
            );
        }
        Ok(self.answer(&proofs))
    }

    /// The certificate an own app's batch is checked against (Switch wire 7.2): a stored
    /// renewed certificate once the newest `identity.json` lists it, else its record's; for
    /// an app without a record, the record of the batch's first `app.put` naming it. The app
    /// is current with it, and it hasn't expired.
    fn authenticate(&self, app: [u8; 16], signed: &[SignedDoc]) -> Result<AppCert, Fail> {
        let held = self.apps.get(&app);
        if held.is_some_and(|a| a.departed) {
            return Err(not_current("the app is revoked or departed").into());
        }
        let listed = |cert: &AppCert| {
            self.doc
                .as_ref()
                .map(|doc| doc.standing(&app, &cert.hash()))
        };
        let cert = match held.and_then(|a| a.cert.clone()) {
            Some(record_cert) => match held.and_then(|a| a.renewed.clone()) {
                Some(renewed) if listed(&renewed) == Some(Standing::Listed) => renewed,
                _ => record_cert,
            },
            None => self.first_call(app, signed)?,
        };
        if !matches!(
            listed(&cert),
            Some(Standing::Listed | Standing::RenewedOpen)
        ) {
            return Err(not_current("the app isn't listed with its certificate").into());
        }
        if cert.expired_at(self.now()) {
            return Err(Refusal::new(
                ErrorCode::CertExpired,
                "Switch wire 7.2: the certificate has expired",
            )
            .into());
        }
        Ok(cert)
    }

    /// An own app's first call (Switch wire 7.2): the batch's first `app.put` naming the
    /// caller, whose record verifies and whose signing key gives the caller's App ID.
    fn first_call(&self, app: [u8; 16], signed: &[SignedDoc]) -> Result<AppCert, Fail> {
        let record = signed
            .iter()
            .filter_map(|doc| SignedOp::peek(doc).ok())
            .find_map(|op| match (&op.body().kind, op.body().app_id) {
                (OpKind::AppPut { record }, Some(id)) if id == app => Some(record.clone()),
                _ => None,
            })
            .ok_or_else(|| not_current("an own app's first call carries its app.put"))?;
        let bad_signature = |why: &str| Refusal::new(ErrorCode::BadSignature, why);
        let record = AppRecord::verify(&record, &self.identity.public())
            .map_err(|_| bad_signature("Switch wire 7.2: the first call's app record"))?;
        if record.cert().app_id() != app {
            return Err(bad_signature("Switch wire 7.2: the record names another app").into());
        }
        Ok(record.cert().clone())
    }

    fn draft(&self) -> Draft {
        Draft {
            apps: self.apps.clone(),
            bundles: self.bundles.clone(),
            kids: self.kids.clone(),
            shared: self.shared.clone(),
            directory_version: self.directory_version,
            apps_version: self.apps_version,
            reachable_since: self.reachable_since.clone(),
        }
    }

    fn commit(&mut self, draft: Draft) {
        self.apps = draft.apps;
        self.bundles = draft.bundles;
        self.kids = draft.kids;
        self.shared = draft.shared;
        self.directory_version = draft.directory_version;
        self.apps_version = draft.apps_version;
        self.reachable_since = draft.reachable_since;
    }

    /// One operation's own rules (Switch wire 6.2, 6.8), against `draft`, which it changes:
    /// the proof's state, and the app a key bundle part is shown in full to.
    fn apply_op(
        &self,
        draft: &mut Draft,
        op: &SignedOp,
        cx: &OpContext<'_>,
        cert: Option<&AppCert>,
        seq: u64,
    ) -> Result<(ProofState, Option<[u8; 16]>), Fail> {
        let body = op.body();
        let generation = self.tip.generation;
        // `check_permission` let only an app write its own record and receive key.
        let own = || {
            body.app_id
                .zip(cert)
                .ok_or_else(|| Refusal::bad_request("Switch wire 6.2: for an app only"))
        };
        let state = match &body.kind {
            OpKind::RecordPut(put) => draft.shared.record_put(put, cx, generation, seq)?,
            OpKind::Claim(fields) => draft.shared.claim(fields, cx)?,
            OpKind::AllowPut { pubky, kind } => draft.shared.allow_put(pubky, *kind, cx),
            OpKind::AllowDelete { pubky, kind } => draft.shared.allow_delete(pubky, *kind),
            OpKind::DenyPut { pubky } => draft.shared.deny(pubky, true),
            OpKind::DenyDelete { pubky } => draft.shared.deny(pubky, false),
            OpKind::InviteCodePut(put) => draft.shared.invite_code_put(put, cx)?,
            OpKind::InviteCodeDelete { code_hash } => draft.shared.invite_code_delete(code_hash)?,
            OpKind::AppPut { record } => self.app_put(draft, own()?.0, record)?,
            OpKind::ReceiveKeyPut { record } => {
                let (app, cert) = own()?;
                self.receive_key_put(draft, app, cert, record)?
            }
            OpKind::KeyBundlePut(put) => {
                let state = self.key_bundle_put(draft, put, seq)?;
                return Ok((state, Some(put.target_app_id)));
            }
            OpKind::CertPut {
                target_app_id,
                cert,
            } => self.cert_put(draft, target_app_id, cert)?,
        };
        Ok((state, None))
    }

    /// `app.put`, by [`check_app_put`]; a stored record changes the directory (Switch wire
    /// 7.4.10).
    fn app_put(
        &self,
        draft: &mut Draft,
        app: [u8; 16],
        record: &SignedDoc,
    ) -> Result<ProofState, Fail> {
        let identity = self.identity.public();
        let new = AppRecord::verify(record, &identity).map_err(Refusal::from)?;
        let held = draft
            .apps
            .get(&app)
            .and_then(|a| a.record.as_ref())
            .map(|r| AppRecord::verify(r, &identity))
            .transpose()?;
        let listed = self.doc.as_ref().and_then(|doc| doc.listed_cert(&app));
        if check_app_put(&app, &new, listed, held.as_ref())? != AppPutEffect::Unchanged {
            let entry = draft.apps.entry(app).or_default();
            entry.record = Some(record.clone());
            entry.cert = Some(new.cert().clone());
            draft.directory_version += 1;
        }
        Ok(ProofState::App { app_id: app })
    }

    /// `receive_key.put`, by [`check_receive_key_put`]; an unchanged one's proof shows the
    /// current `n` and kid (Switch wire 6.4 "No-ops"). A stored key changes the directory,
    /// and an app's first makes it reachable, which moves `apps_version` (Switch wire
    /// 7.4.10).
    fn receive_key_put(
        &self,
        draft: &mut Draft,
        app: [u8; 16],
        cert: &AppCert,
        record: &SignedDoc,
    ) -> Result<ProofState, Fail> {
        let new = ReceiveKeyRecord::verify(record, cert).map_err(Refusal::from)?;
        let entry = draft.apps.entry(app).or_default();
        let current = entry
            .receive_key
            .as_ref()
            .map(|r| ReceiveKeyRecord::verify(r, cert))
            .transpose()?;
        let effect = check_receive_key_put(
            &new,
            current.as_ref(),
            entry.record.is_some(),
            self.any_first_n,
            draft.kids.contains_key(&new.kid()),
        )?;
        let shown = match (effect, current) {
            (ReceiveKeyEffect::Unchanged, Some(current)) => current,
            _ => {
                let first = entry.receive_key.is_none() && !entry.departed;
                entry.receive_key = Some(record.clone());
                entry.receive_n = Some(new.n());
                draft.kids.insert(new.kid(), app);
                draft.directory_version += 1;
                if first {
                    draft.apps_version += 1;
                    draft.reachable_since.insert(app, draft.apps_version);
                }
                new
            }
        };
        Ok(ProofState::ReceiveKey {
            n: shown.n(),
            kid: shown.kid(),
        })
    }

    /// `key_bundle.put`, by [`check_key_bundle_put`]. A pending full-bundle request ends once
    /// the stored parts cover every data epoch from 1 to the current one (Switch wire 6.2).
    fn key_bundle_put(
        &self,
        draft: &mut Draft,
        put: &KeyBundlePut,
        seq: u64,
    ) -> Result<ProofState, Fail> {
        let target = put.target_app_id;
        let current = self.app_current(&draft.apps, &target);
        let parts = draft.bundles.entry(target).or_default();
        let stored: Vec<KeyBundlePut> = parts.iter().map(|(part, _)| part.clone()).collect();
        let bundle_seq = match check_key_bundle_put(put, current, &stored)? {
            KeyBundleEffect::Unchanged => parts
                .iter()
                .find(|(part, _)| part == put)
                .map_or(seq, |(_, at)| *at),
            KeyBundleEffect::Stores { replaces } => {
                let mut index = 0;
                parts.retain(|_| {
                    let keep = !replaces.contains(&index);
                    index += 1;
                    keep
                });
                parts.push((put.clone(), seq));
                parts.sort_by_key(|(part, _)| part.first_epoch);
                let epoch = self.doc.as_ref().map_or(1, |doc| doc.data_epoch());
                if covers(parts, epoch)
                    && let Some(app) = draft.apps.get_mut(&target)
                {
                    app.full_requested = None;
                }
                seq
            }
        };
        Ok(ProofState::KeyBundle { bundle_seq })
    }

    /// `cert.put`, by [`check_cert_put`].
    fn cert_put(
        &self,
        draft: &mut Draft,
        target: &[u8; 16],
        cert: &SignedDoc,
    ) -> Result<ProofState, Fail> {
        let renewed = AppCert::verify(cert, &self.identity.public()).map_err(Refusal::from)?;
        let held = draft.apps.entry(*target).or_default();
        let active = !held.departed && held.record.is_some();
        if check_cert_put(&renewed, held.cert.as_ref(), active, held.renewed.as_ref())?
            == CertPutEffect::Stores
        {
            held.renewed = Some(renewed);
        }
        Ok(ProofState::Cert {
            cert: cert.doc_hash()?,
        })
    }

    /// A scripted `GET /allow`, for a faulty service, shows the contacts added since.
    fn show_scripted_contact(&mut self, pubky: &[u8; 32]) {
        let id = Value::from(pubky_switch_core::enc::pubky_id(pubky));
        if let Some(contacts) = self
            .allow
            .as_mut()
            .and_then(|allow| allow["contacts"].as_array_mut())
            && !contacts.contains(&id)
        {
            contacts.push(id);
        }
    }
}

/// Whether parts sorted by their first epoch cover every data epoch from 1 to `epoch`.
fn covers(parts: &[(KeyBundlePut, u64)], epoch: u64) -> bool {
    let mut next = 1u64;
    for (part, _) in parts {
        if part.first_epoch > next {
            break;
        }
        next = next.max(part.last_epoch.saturating_add(1));
    }
    next > epoch
}
