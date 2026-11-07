//! `claims.json`: the 69-step script through every row of the claim rules, deadline pinning,
//! the reconciliation window, unchanged batches with and without `cursor.set`, and `app.put`
//! of the held record and of a record at its `updated_at`; then the per-app claim limits on
//! a switch of their own (Switch wire 6.2, 6.4, 6.8, 9.3).
//!
//! The script runs through the core's pure functions: every write is built and signed as its
//! app's operation, verified, checked for its writer's permission and its shape, and applied
//! with [`apply_entry`] to the claim held for its key; reads give the claim view; requests of
//! the file are read, verified and written again byte for byte, then decided by the no-op,
//! condition and `app.put` rules.
//!
//! What a pure core can't have is modelled here as the service would do it, and only that:
//! authentication (a revoked app gets `403 not_current` before anything is read, Switch wire
//! 7.2), the service clock the script advances, the store of claims by key, and the sweep of
//! Switch wire 7.3 step 4, which deletes what [`Claim::deletable`] says, by the time base.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::SigningKey;
use pubky_switch_core::claims::{
    Claim, ClaimLimits, ClaimTally, EntryContext, MAX_CLAIM_AGE_MS, apply_entry,
};
use pubky_switch_core::enc::{app_id_decode, b64 as b64e, hash, pubky_id};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::labels;
use pubky_switch_core::ops::{
    AllowKind, BatchEffect, ConditionState, Held, KeyBundlePut, OpBody, OpKind, OpsRequest,
    RecordVersion, Refusal, SignedOp, Writer, batch_effect, check_app_put, check_batch,
    check_conditions, check_permission, check_shape,
};
use pubky_switch_core::records::{AppCert, AppRecord, ReceiveKeyRecord};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::parse_rfc3339;
use serde_json::{Value, json};

use crate::common::*;

/// A seed of the vectors: `BLAKE3(prefix + label)` (README "Seeds").
fn seed(label: &str) -> [u8; 32] {
    hash(format!("{}{label}", seed_prefix()).as_bytes())
}

fn signed_of(value: &Value) -> SignedDoc {
    serde_json::from_value(value.clone()).unwrap()
}

/// An app of the script, with its certificate and what it registered.
struct App {
    app_id: [u8; 16],
    key: SigningKey,
    cert: AppCert,
    record: AppRecord,
    receive_key: ReceiveKeyRecord,
}

/// What the switch answers: a body, or a refusal.
type Answer = Result<Value, Refusal>;

/// One switch of the script: the account's apps, the claims it holds by key, and its clock.
struct Switch {
    identity: [u8; 32],
    now: u64,
    apps: HashMap<String, App>,
    revoked: HashSet<[u8; 16]>,
    claims: HashMap<[u8; 32], Claim>,
    limits: ClaimLimits,
    cursors: HashMap<[u8; 16], String>,
    batches: u64,
}

impl Switch {
    fn new(v: &Value, limits: ClaimLimits) -> Self {
        let identity = pubky(st(v, "identity"));
        let id_key = SigningKey::from_bytes(&seed(st(v, "identity_seed_label")));
        assert_eq!(
            id_key.verifying_key().to_bytes(),
            identity,
            "the identity's seed"
        );
        let mut apps = HashMap::new();
        for (name, a) in v["apps"].as_object().unwrap() {
            let app_id = app_id_decode(st(a, "app_id")).unwrap();
            let key = SigningKey::from_bytes(&seed(st(a, "signing_seed_label")));
            assert_eq!(
                pubky_switch_core::enc::app_id_bytes(&key.verifying_key().to_bytes()),
                app_id,
                "{name}: the App ID derives from the signing key"
            );
            let cert = AppCert::verify(&signed_of(&a["cert"]), &identity).unwrap();
            assert_eq!(cert.app_id(), app_id);
            let permissions: Vec<&str> = cert.permissions().iter().map(|p| p.as_str()).collect();
            assert_eq!(permissions, strings(&a["inbox_permissions"]), "{name}");
            let record = AppRecord::verify(&signed_of(&a["registered_record"]), &identity).unwrap();
            assert_eq!(
                record.cert(),
                &cert,
                "{name}: the record carries the certificate"
            );
            let receive_key =
                ReceiveKeyRecord::verify(&signed_of(&a["registered_receive_key"]), &cert).unwrap();
            assert_eq!(receive_key.n(), 0, "{name}: the first receive key");
            apps.insert(
                name.clone(),
                App {
                    app_id,
                    key,
                    cert,
                    record,
                    receive_key,
                },
            );
        }
        Self {
            identity,
            now: parse_rfc3339(st(v, "start_time")).unwrap(),
            apps,
            revoked: HashSet::new(),
            claims: HashMap::new(),
            limits,
            cursors: HashMap::new(),
            batches: 0,
        }
    }

    /// Current: neither revoked nor departed, with a certificate that hasn't expired. The
    /// script's `identity.json` lists every app with its certificate.
    fn is_current(&self, app_id: &[u8; 16]) -> bool {
        !self.revoked.contains(app_id)
            && self
                .apps
                .values()
                .any(|a| &a.app_id == app_id && !a.cert.expired_at(self.now))
    }

    /// The sweep of Switch wire 7.3 step 4, with trusted time: the script's clock is the
    /// time base.
    fn sweep(&mut self) {
        let now = self.now;
        self.claims
            .retain(|_, claim| !claim.deletable(Some(now), MAX_CLAIM_AGE_MS));
    }

    /// Authentication (Switch wire 7.2): an own app that isn't current is `403 not_current`.
    fn authenticate(&self, name: &str) -> Result<&App, Refusal> {
        let app = &self.apps[name];
        if !self.is_current(&app.app_id) {
            return Err(Refusal::new(ErrorCode::NotCurrent, "not current"));
        }
        Ok(app)
    }

    fn view(&self, claim_key: &[u8; 32]) -> Option<Value> {
        let current = |a: &[u8; 16]| self.is_current(a);
        self.claims
            .get(claim_key)
            .map(|c| c.view(claim_key, self.now, &current).to_value())
    }

    /// `GET /claims/{claim_key}` (Switch wire 7.4.8).
    fn read(&mut self, name: &str, claim_key: &[u8; 32]) -> Answer {
        self.sweep();
        let app = self.authenticate(name)?;
        if !app.cert.has_permission(Permission::ClaimsRead) {
            return Err(Refusal::new(ErrorCode::PermissionMissing, "claims.read"));
        }
        self.view(claim_key)
            .map(|claim| json!({ "claim": claim }))
            .ok_or_else(|| Refusal::new(ErrorCode::NotFound, "no such claim"))
    }

    /// A batch of one claim operation, signed by its app, verified, checked for its writer's
    /// permission and shape, and applied (Switch wire 6.4 steps 3, 4 and 9).
    fn write(&mut self, name: &str, op: &Value) -> Answer {
        self.sweep();
        self.batches += 1;
        let app = self.authenticate(name)?;
        let mut body = json!({
            "identity": pubky_id(&self.identity),
            "app_id": pubky_switch_core::enc::zbase32_encode(&app.app_id),
            "generation": 1,
            "batch": { "id": b64e(&seed(&format!("claims/script/batch/{}", self.batches))[..16]), "count": 1 },
            "op": "claim",
        });
        for (k, v) in op.as_object().unwrap() {
            body[k] = v.clone();
        }
        let parsed = OpBody::parse(&serde_json::to_vec(&body).unwrap())?;
        let signed = SignedOp::sign(&app.key, parsed).unwrap();
        let op = SignedOp::verify(
            signed.signed(),
            &app.key.verifying_key().to_bytes(),
            &self.identity,
            Some(&app.app_id),
        )?;
        check_batch(std::slice::from_ref(&op))?;
        check_permission(&op.body().kind, Writer::App(&app.cert))?;
        check_shape(op.body())?;
        let OpKind::Claim(fields) = &op.body().kind else {
            panic!("a claim operation");
        };
        let entry = fields.check()?;
        let writer = app.app_id;
        let can_read = app.cert.has_permission(Permission::ClaimsRead);
        let tally = ClaimTally::count(self.claims.values(), &writer);
        let current = |a: &[u8; 16]| self.is_current(a);
        let cx = EntryContext {
            writer,
            now: self.now,
            can_read,
            is_current: &current,
            limits: self.limits,
            tally,
        };
        let next = apply_entry(self.claims.get(&entry.claim_key), &entry, &cx)?;
        self.claims.insert(entry.claim_key, next);
        Ok(json!({ "claim": self.view(&entry.claim_key) }))
    }

    /// A `POST /ops` body of the file (Switch wire 6.4): read, its operations verified and
    /// written again byte for byte, then decided by the no-op, condition and `app.put` rules.
    fn request(&mut self, name: &str, body: &str) -> Answer {
        self.sweep();
        let app = self.authenticate(name)?;
        let request = OpsRequest::parse(body.as_bytes())?;
        assert_eq!(
            request.to_json(),
            body.as_bytes(),
            "{name}: the request rebuilt"
        );
        let key = app.key.verifying_key().to_bytes();
        let ops: Vec<SignedOp> = request
            .signed()
            .map(|d| SignedOp::verify(d, &key, &self.identity, Some(&app.app_id)))
            .collect::<Result<_, _>>()?;
        for op in &ops {
            assert_eq!(&SignedOp::sign(&app.key, op.body().clone()).unwrap(), op);
            assert_eq!(
                op.body().to_json().unwrap(),
                op.signed().body_bytes().unwrap()
            );
        }
        assert_eq!(
            OpsRequest::new(&ops, request.cursor()).to_json(),
            body.as_bytes()
        );
        check_batch(&ops)?;
        let cursor = request.cursor();
        match batch_effect(&ops, self, cursor.is_some()) {
            BatchEffect::NoOp => return Ok(json!({ "proofs": [] })),
            BatchEffect::Unchanged => {
                let state = State {
                    switch: self,
                    reader: name,
                };
                check_conditions(ops.iter().flat_map(|o| &o.body().conditions), &state)?;
                if let Some(position) = cursor {
                    let id = self.apps[name].app_id;
                    self.cursors.insert(id, position.to_string());
                }
                return Ok(json!({ "proofs": [] }));
            }
            BatchEffect::Apply { .. } => {}
        }
        let mut proofs = Vec::new();
        for op in &ops {
            let OpKind::AppPut { record } = &op.body().kind else {
                panic!("{name}: only app.put batches change something here");
            };
            let record = AppRecord::verify(record, &self.identity)?;
            let app = &self.apps[name];
            check_app_put(
                &app.app_id,
                &record,
                Some(app.cert.hash()),
                Some(&app.record),
            )?;
            proofs.push(Value::Null);
        }
        Ok(json!({ "proofs": proofs }))
    }
}

impl Held for Switch {
    fn app_record(&self, app_id: &[u8; 16]) -> Option<SignedDoc> {
        let app = self.apps.values().find(|a| &a.app_id == app_id)?;
        Some(app.record.signed().clone())
    }
    fn receive_key(&self, app_id: &[u8; 16]) -> Option<SignedDoc> {
        let app = self.apps.values().find(|a| &a.app_id == app_id)?;
        Some(app.receive_key.signed().clone())
    }
    fn renewed_cert(&self, _: &[u8; 16]) -> Option<SignedDoc> {
        None
    }
    fn record_cert(&self, app_id: &[u8; 16]) -> Option<SignedDoc> {
        let app = self.apps.values().find(|a| &a.app_id == app_id)?;
        Some(app.cert.signed().clone())
    }
    fn holds_bundle_part(&self, _: &KeyBundlePut) -> bool {
        false
    }
    fn record_live(&self, _: &[u8; 32]) -> bool {
        false
    }
    fn allowed(&self, _: &[u8; 32], _: AllowKind) -> bool {
        false
    }
    fn denied(&self, _: &[u8; 32]) -> bool {
        false
    }
}

/// The state before a batch, as its caller may read it (Switch wire 6.3, 7.6). The script's
/// switch holds no shared records.
struct State<'a> {
    switch: &'a Switch,
    reader: &'a str,
}

impl ConditionState for State<'_> {
    fn record_version(&self, _: &[u8; 32]) -> RecordVersion {
        RecordVersion::NONE
    }
    fn may_read_record(&self, _: &[u8; 32]) -> bool {
        true
    }
    fn claim_step(&self, claim_key: &[u8; 32]) -> u64 {
        self.switch.claims.get(claim_key).map_or(0, |c| c.step)
    }
    fn claim_view(&self, claim_key: &[u8; 32]) -> Option<Value> {
        self.switch.view(claim_key)
    }
    fn may_read_claims(&self) -> bool {
        self.switch.apps[self.reader]
            .cert
            .has_permission(Permission::ClaimsRead)
    }
    fn server_time(&self) -> u64 {
        self.switch.now
    }
}

/// Compare an answer with a step's `expect`: the claim view or the number of proofs on
/// success; the status, code and `current` of a refusal.
fn expect(step: &Value, answer: &Answer, label: &str) {
    let e = &step["expect"];
    match answer {
        Ok(body) => {
            assert_eq!(int(e, "status"), 200, "{label}: {body}");
            if let Some(claim) = e.get("claim") {
                assert_eq!(&body["claim"], claim, "{label}: the claim view");
            }
            if let Some(proofs) = e.get("proofs") {
                assert_eq!(
                    body["proofs"].as_array().unwrap().len() as u64,
                    proofs.as_u64().unwrap(),
                    "{label}: proofs"
                );
            }
        }
        Err(refused) => {
            assert_eq!(
                u64::from(refused.status()),
                int(e, "status"),
                "{label}: {refused}"
            );
            assert_eq!(refused.code.as_str(), st(e, "code"), "{label}: {refused}");
            match e.get("current").filter(|c| !c.is_null()) {
                Some(current) => {
                    assert_eq!(refused.current.as_ref(), Some(current), "{label}: current")
                }
                None => assert_eq!(refused.current, None, "{label}: no current"),
            }
        }
    }
}

/// Check that a step's `entry` names what its `op` carries: the attempt by its name and a
/// deadline `deadline_after_s` after the start.
fn check_entry(v: &Value, step: &Value, attempts: &HashMap<String, String>, start: u64) {
    let entry = &step["entry"];
    let op = &step["op"];
    assert_eq!(st(op, "attempt_id"), attempts[st(entry, "attempt")]);
    assert_eq!(st(op, "type"), st(entry, "type"));
    assert_eq!(op["expected_step"], entry["expected_step"]);
    match entry.get("deadline_after_s") {
        Some(s) => assert_eq!(
            parse_rfc3339(st(op, "deadline")).unwrap(),
            start + s.as_u64().unwrap() * 1000
        ),
        None => assert!(op.get("deadline").is_none()),
    }
    if let Some(evidence) = entry.get("evidence") {
        assert_eq!(
            st(op, "evidence_ref"),
            st(&v["evidence_refs"], evidence.as_str().unwrap())
        );
    }
}

/// Run a script's steps on a switch.
fn run(
    v: &Value,
    switch: &mut Switch,
    steps: &[Value],
    claim_keys: &Value,
    attempts: &HashMap<String, String>,
) -> HashSet<String> {
    let start = switch.now;
    let mut actions = HashSet::new();
    for step in steps {
        let n = int(step, "n");
        let action = st(step, "action");
        actions.insert(action.to_owned());
        let label = format!("step {n} ({action})");
        let key = |s: &Value| b64n::<32>(st(claim_keys, st(s, "claim_key")));
        let answer = match action {
            "write" => {
                check_entry(v, step, attempts, start);
                assert_eq!(st(&step["op"], "claim_key"), b64e(&key(step)), "{label}");
                switch.write(st(step, "app"), &step["op"])
            }
            "read" => switch.read(st(step, "app"), &key(step)),
            "advance" => {
                switch.now += int(step, "seconds") * 1000;
                continue;
            }
            "revoke" => {
                let id = switch.apps[st(step, "app")].app_id;
                switch.revoked.insert(id);
                Ok(json!({}))
            }
            "noop_batch" => {
                check_noop_request(step, switch);
                switch.request(st(step, "app"), st(step, "request_body"))
            }
            "app_put" => {
                check_app_put_request(step, switch);
                switch.request(st(step, "app"), st(step, "request_body"))
            }
            other => panic!("{label}: action {other}"),
        };
        expect(step, &answer, &label);
    }
    actions
}

/// A `noop_batch` step's request: one unchanged `app.put` of the record the app registered,
/// conditioned on a claim's step when `condition_step` is set, with `cursor.set` when
/// `cursor` is true.
fn check_noop_request(step: &Value, switch: &Switch) {
    let request = OpsRequest::parse(st(step, "request_body").as_bytes()).unwrap();
    let ops: Vec<SignedOp> = request
        .signed()
        .map(|d| SignedOp::peek(d).unwrap())
        .collect();
    assert_eq!(ops.len(), 1);
    let body = ops[0].body();
    let app = &switch.apps[st(step, "app")];
    assert_eq!(
        body.kind,
        OpKind::AppPut {
            record: app.record.signed().clone()
        }
    );
    match step["condition_step"].as_u64() {
        Some(s) => assert!(matches!(
            body.conditions.as_slice(),
            [pubky_switch_core::ops::Condition::ClaimStep { step, .. }] if *step == s
        )),
        None => assert!(body.conditions.is_empty()),
    }
    assert_eq!(
        request.cursor().is_some(),
        step["cursor"] == Value::Bool(true)
    );
    if let Some(p) = step["cursor_position"].as_str() {
        assert_eq!(request.cursor().unwrap().to_string(), p);
    }
}

/// An `app_put` step's request: one `app.put` of `record`, the held record, or the held
/// record at its `updated_at` with another body, signed by the app.
fn check_app_put_request(step: &Value, switch: &Switch) {
    let request = OpsRequest::parse(st(step, "request_body").as_bytes()).unwrap();
    let op = SignedOp::peek(request.signed().next().unwrap()).unwrap();
    let record = signed_of(&step["record"]);
    assert_eq!(
        op.body().kind,
        OpKind::AppPut {
            record: record.clone()
        }
    );
    let held = &switch.apps[st(step, "app")].record;
    match st(step, "variant") {
        "held" => assert_eq!(&record, held.signed()),
        "equal_time" => {
            let other = AppRecord::verify(&record, &switch.identity).unwrap();
            assert_eq!(other.updated_at(), held.updated_at());
            assert_ne!(other.signed().body, held.signed().body);
            assert!(
                pubky_switch_core::sig::verify(
                    &other.cert().signing_key(),
                    labels::sig::APP_RECORD,
                    &[&other.signed().body_bytes().unwrap()],
                    &other.signed().sig_bytes().unwrap()
                )
                .is_ok()
            );
        }
        other => panic!("variant {other}"),
    }
}

fn names(map: &Value) -> HashMap<String, String> {
    map.as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
        .collect()
}

#[test]
fn test_vectors_claims() {
    let v = load("claims.json");
    let steps = arr(&v, "steps");
    assert_eq!(steps.len(), 69);
    let mut switch = Switch::new(&v, ClaimLimits::default());
    let actions = run(
        &v,
        &mut switch,
        steps,
        &v["claim_keys"],
        &names(&v["attempts"]),
    );
    for action in [
        "write",
        "read",
        "advance",
        "revoke",
        "noop_batch",
        "app_put",
    ] {
        assert!(actions.contains(action), "the script has {action} steps");
    }
    // Step 61 moved A's cursor; step 60, refused, didn't before it.
    assert_eq!(switch.cursors.len(), 1);
    // Every row of the claim rules was refused or applied along the way.
    let rows: HashSet<&str> = steps.iter().filter_map(|s| s["row"].as_str()).collect();
    for row in ["1", "2", "3", "4", "5", "6", "7"] {
        assert!(rows.contains(row), "row {row}");
    }

    // The per-app limits, on a switch of their own (Switch wire 6.8, 9.3).
    let q = &v["quota"];
    let limits = ClaimLimits {
        max_claims: int(&q["limits"], "max_claims"),
        open_attempts_per_app: int(&q["limits"], "open_attempts_per_app"),
        claim_share_percent: int(&q["limits"], "claim_share_percent"),
        ..ClaimLimits::default()
    };
    assert_eq!(limits.claim_share(), 3);
    let mut quota = Switch::new(&v, limits);
    let refused = run(
        &v,
        &mut quota,
        arr(q, "steps"),
        &q["claim_keys"],
        &names(&q["attempts"]),
    );
    assert_eq!(refused, HashSet::from(["write".to_owned()]));
    let limit_answers: Vec<&Value> = arr(q, "steps")
        .iter()
        .filter_map(|s| s["expect"]["current"].get("limit"))
        .collect();
    assert_eq!(
        limit_answers,
        [&json!("open_attempts"), &json!("claim_share")]
    );
}
