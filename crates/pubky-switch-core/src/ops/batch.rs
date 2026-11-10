//! Batches (Switch wire 6.4, Switch spec 13.5): the `POST /ops` body and its entry rules, the
//! batch rules, conditions against the state before the batch, no-ops and rate classes,
//! retries, and building a signed batch.

use serde_json::{Value, json};

use super::Refusal;
use super::body::{
    BatchRef, Condition, KeyBundlePut, MAX_OP_BYTES, OpBody, OpKind, RecordVersion, SignedOp,
    carrying, carrying_len,
};
use crate::enc::{b64, hash, lp, random_bytes};
use crate::error::{Result, invalid};
use crate::http::ErrorCode;
use crate::json::{MAX_INT, parse_json};
use crate::sig::SignedDoc;
use crate::signing::Signs;
use crate::time::rfc3339;

/// The most entries of a `POST /ops` body, `cursor.set` included (Switch wire 6.4).
pub const MAX_BATCH_ENTRIES: usize = 8;

/// `batch_proofs_ms`, 30 days: how long a batch's proofs, and at least its ID, are kept
/// (Switch wire 6.4 step 5, 9.2). An operator may raise it but not lower it, since apps
/// compare batch IDs over 30 days.
pub const BATCH_PROOFS_MS: u64 = 2_592_000_000;

/// A feed position or cursor, `<generation>:<seq>` (Switch wire 1.7).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Position {
    /// The generation.
    pub generation: u64,
    /// The `seq` in that generation.
    pub seq: u64,
}

impl Position {
    /// Read `<generation>:<seq>`: two decimal integers of the wire range (Switch wire 1.7).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for any other text.
    pub fn parse(text: &str) -> Result<Self> {
        let number = |part: &str| -> Result<u64> {
            if part.is_empty() || part.len() > 16 || !part.bytes().all(|b| b.is_ascii_digit()) {
                return invalid("Switch wire 1.7: a position isn't two decimal integers");
            }
            match part.parse::<u64>() {
                Ok(n) if n <= MAX_INT => Ok(n),
                _ => invalid("Switch wire 1.7: a position is out of range"),
            }
        };
        let Some((generation, seq)) = text.split_once(':') else {
            return invalid("Switch wire 1.7: a position has no ':'");
        };
        Ok(Self {
            generation: number(generation)?,
            seq: number(seq)?,
        })
    }
}

impl std::fmt::Display for Position {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.generation, self.seq)
    }
}

/// One entry of a `POST /ops` body (Switch wire 6.4).
#[derive(Clone, Debug, PartialEq)]
pub enum Entry {
    /// A signed operation, in its carrying form.
    Signed(SignedDoc),
    /// `cursor.set`: unsigned and outside the batch count; the request signature covers it.
    Cursor(Position),
}

/// A `POST /v1/{id}/ops` body: `{ "ops": [entry, ...] }` (Switch wire 6.4).
#[derive(Clone, Debug, PartialEq)]
pub struct OpsRequest {
    /// The entries, in order.
    pub entries: Vec<Entry>,
}

impl OpsRequest {
    /// A request of signed operations, then the cursor if any, as a writer sends its batch.
    pub fn new(ops: &[SignedOp], cursor: Option<Position>) -> Self {
        let mut entries: Vec<Entry> = ops
            .iter()
            .map(|o| Entry::Signed(o.signed().clone()))
            .collect();
        entries.extend(cursor.map(Entry::Cursor));
        Self { entries }
    }

    /// The body's exact JSON bytes: each signed operation as `{"body","sig"}` and the cursor
    /// as `{"op":"cursor.set","position"}`.
    pub fn to_json(&self) -> Vec<u8> {
        let entries: Vec<Vec<u8>> = self
            .entries
            .iter()
            .map(|e| match e {
                Entry::Signed(doc) => carrying(doc),
                Entry::Cursor(position) => {
                    let mut o = super::body::Obj::new();
                    o.str("op", "cursor.set")
                        .str("position", &position.to_string());
                    o.finish()
                }
            })
            .collect();
        let mut o = super::body::Obj::new();
        o.raw("ops", &super::body::array(&entries));
        o.finish()
    }

    /// Read a body, in the order of Switch wire 6.4 step 2, before any signature is checked:
    /// strict JSON; 1 to 8 entries; each entry with only its own members, `body` and `sig` or
    /// `cursor.set`'s `op` and `position`; at most one `cursor.set`; then any signed operation
    /// over 512 KiB in its compact carrying form. Members of the outer object other than
    /// `ops` are ignored.
    ///
    /// # Errors
    ///
    /// `400 bad_request`, then `413 too_large`.
    pub fn parse(body: &[u8]) -> std::result::Result<Self, Refusal> {
        let value: Value = parse_json(body)?;
        let Some(raw) = value.get("ops").and_then(Value::as_array) else {
            return Err(Refusal::bad_request(
                "Switch wire 6.4: the body has no ops array",
            ));
        };
        if !(1..=MAX_BATCH_ENTRIES).contains(&raw.len()) {
            return Err(Refusal::bad_request(
                "Switch wire 6.4: a batch has 1 to 8 entries",
            ));
        }
        let mut entries = Vec::with_capacity(raw.len());
        for entry in raw {
            if entry.get("op").is_some() {
                super::read::only(entry, &["op", "position"], "a cursor.set entry")?;
                if entry.get("op").and_then(Value::as_str) != Some("cursor.set") {
                    return Err(Refusal::bad_request(
                        "Switch wire 6.4: an unsigned entry is a cursor.set",
                    ));
                }
                let position = super::read::req_str(entry, "position", "cursor.set")?;
                entries.push(Entry::Cursor(Position::parse(position)?));
            } else {
                entries.push(Entry::Signed(SignedDoc::from_strict_value(entry)?));
            }
        }
        if entries
            .iter()
            .filter(|e| matches!(e, Entry::Cursor(_)))
            .count()
            > 1
        {
            return Err(Refusal::bad_request(
                "Switch wire 6.4: at most one cursor.set per batch",
            ));
        }
        for entry in &entries {
            if let Entry::Signed(doc) = entry
                && carrying_len(&doc.body, &doc.sig) > MAX_OP_BYTES
            {
                return Err(Refusal::new(
                    ErrorCode::TooLarge,
                    "Switch wire 6.1: a signed operation over 512 KiB",
                ));
            }
        }
        Ok(Self { entries })
    }

    /// The signed operations, in order.
    pub fn signed(&self) -> impl Iterator<Item = &SignedDoc> {
        self.entries.iter().filter_map(|e| match e {
            Entry::Signed(doc) => Some(doc),
            Entry::Cursor(_) => None,
        })
    }

    /// The cursor position, if the body carries `cursor.set`.
    pub fn cursor(&self) -> Option<Position> {
        self.entries.iter().find_map(|e| match e {
            Entry::Cursor(p) => Some(*p),
            Entry::Signed(_) => None,
        })
    }

    /// The batch rules that depend on the caller (Switch wire 6.2 "The signer's operations",
    /// 6.4 step 4): the signer has no cursor, so a `cursor.set` in its batch is refused.
    /// `signer` is whether the request verified with the identity key.
    ///
    /// # Errors
    ///
    /// `400 bad_request`.
    pub fn check_caller(&self, signer: bool) -> std::result::Result<(), Refusal> {
        if signer && self.cursor().is_some() {
            return Err(Refusal::bad_request(
                "Switch wire 6.2: the signer's batch carries no cursor.set",
            ));
        }
        Ok(())
    }
}

/// The batch rules (Switch wire 6.4 step 4) for a request's verified signed operations: every
/// operation has the same batch ID and count, the count is the number of signed operations,
/// and no record is written twice. A batch of only `cursor.set` has no operations and no
/// batch ID.
///
/// # Errors
///
/// `400 bad_request`.
pub fn check_batch(ops: &[SignedOp]) -> std::result::Result<(), Refusal> {
    let Some(first) = ops.first() else {
        return Ok(());
    };
    let batch = first.body().batch;
    if ops.iter().any(|o| o.body().batch != batch) {
        return Err(Refusal::bad_request(
            "Switch wire 6.4: every operation has the batch's ID and count",
        ));
    }
    if u64::try_from(ops.len()).ok() != Some(batch.count) {
        return Err(Refusal::bad_request(
            "Switch wire 6.4: count isn't the number of signed operations",
        ));
    }
    let mut keys: Vec<&[u8; 32]> = Vec::new();
    for op in ops {
        if let OpKind::RecordPut(put) = &op.body().kind {
            if keys.contains(&&put.key) {
                return Err(Refusal::bad_request(
                    "Switch wire 6.2: a batch writes one record twice",
                ));
            }
            keys.push(&put.key);
        }
    }
    Ok(())
}

/// The bounds of a `cursor.set` position (Switch wire 6.2): its generation is `current`, or
/// `continued_from`, the generation a cooperative move's sequence continues from, and its
/// `seq` is at most `newest`, the newest `seq` of the account's sequence.
///
/// # Errors
///
/// `400 bad_request`.
pub fn check_cursor(
    position: Position,
    current: u64,
    continued_from: Option<u64>,
    newest: u64,
) -> std::result::Result<(), Refusal> {
    if position.generation != current && Some(position.generation) != continued_from {
        return Err(Refusal::bad_request(
            "Switch wire 6.2: a cursor.set of another generation",
        ));
    }
    if position.seq > newest {
        return Err(Refusal::bad_request(
            "Switch wire 6.2: a cursor.set past the newest seq",
        ));
    }
    Ok(())
}

/// A batch ID: 16 bytes from the secure random generator (Switch wire 1.7).
///
/// # Errors
///
/// [`crate::Error::Crypto`] if the generator fails.
pub fn random_batch_id() -> Result<[u8; 16]> {
    random_bytes::<16>()
}

/// Sign a batch for its writer (Switch wire 6.1, 6.4): each operation, with its conditions,
/// names the batch ID and the number of operations. `app_id` is `None` for the signer.
///
/// # Errors
///
/// As [`SignedOp::sign`], and [`crate::Error::Invalid`] for an empty batch or one of more
/// than 8 operations.
pub fn sign_batch(
    writer: &impl Signs,
    identity: &[u8; 32],
    app_id: Option<[u8; 16]>,
    generation: u64,
    batch_id: [u8; 16],
    ops: Vec<(Vec<Condition>, OpKind)>,
) -> Result<Vec<SignedOp>> {
    if !(1..=MAX_BATCH_ENTRIES).contains(&ops.len()) {
        return invalid("Switch wire 6.4: a batch has 1 to 8 signed operations");
    }
    let count = u64::try_from(ops.len()).unwrap_or(u64::MAX);
    ops.into_iter()
        .map(|(conditions, kind)| {
            SignedOp::sign(
                writer,
                OpBody {
                    identity: *identity,
                    app_id,
                    generation,
                    batch: BatchRef {
                        id: batch_id,
                        count,
                    },
                    conditions,
                    kind,
                },
            )
        })
        .collect()
}

/// A batch's operation hash: `hash(lp(signed document bytes of each operation, in order))`
/// (Switch wire 10.3), by which the service recognizes a retry (Switch wire 6.4 step 5).
///
/// # Errors
///
/// As [`SignedOp::doc_bytes`].
pub fn ops_hash(ops: &[SignedOp]) -> Result<[u8; 32]> {
    let docs = ops
        .iter()
        .map(SignedOp::doc_bytes)
        .collect::<Result<Vec<_>>>()?;
    let parts: Vec<&[u8]> = docs.iter().map(Vec::as_slice).collect();
    Ok(hash(&lp(&parts)))
}

/// A batch record (Switch wire 6.4 step 5, 9.1): the batch's operation hash, its transition
/// proofs while kept, when it was applied and the `seq`s of its first and last chain items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchRecord {
    /// The operation hash.
    pub ops_hash: [u8; 32],
    /// The transition proofs, one per operation; `None` once dropped.
    pub proofs: Option<Vec<SignedDoc>>,
    /// The service time of the batch, in Unix milliseconds.
    pub at: u64,
    /// The `seq` of its first chain item.
    pub first_seq: u64,
    /// The `seq` of its last chain item.
    pub last_seq: u64,
}

impl BatchRecord {
    /// Whether its proofs are due to go at `now`: `proofs_ms` after the batch.
    pub fn proofs_expired(&self, now: u64, proofs_ms: u64) -> bool {
        now >= self.at.saturating_add(proofs_ms)
    }

    /// Whether the record is still held: while its proofs are, or any of the batch's chain
    /// stubs is kept (`stub_kept`, by `seq`).
    pub fn held(&self, stub_kept: impl Fn(u64) -> bool) -> bool {
        self.proofs.is_some() || (self.first_seq..=self.last_seq).any(stub_kept)
    }
}

/// What the retry rule does with a batch (Switch wire 6.4 step 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetryCheck {
    /// An ID the service doesn't hold: the batch goes on.
    New,
    /// The same signed operations while the proofs are kept: answer with the original
    /// proofs and the newest head.
    Retry(Vec<SignedDoc>),
}

/// The retry rule (Switch wire 6.4 step 5) for a batch with operation hash `ops_hash`
/// against the record the service holds for its ID, if any.
///
/// # Errors
///
/// `409 conflict` for other operations under a held ID, or a retry whose proofs are gone.
pub fn retry_check(
    held: Option<&BatchRecord>,
    ops_hash: &[u8; 32],
) -> std::result::Result<RetryCheck, Refusal> {
    match held {
        None => Ok(RetryCheck::New),
        Some(record) if &record.ops_hash != ops_hash => Err(Refusal::conflict(
            "Switch wire 6.4: a batch ID in the chain with other operations",
        )),
        Some(BatchRecord {
            proofs: Some(proofs),
            ..
        }) => Ok(RetryCheck::Retry(proofs.clone())),
        Some(_) => Err(Refusal::conflict(
            "Switch wire 6.4: a retry whose proofs were dropped",
        )),
    }
}

/// The state conditions are checked against, before the batch (Switch wire 6.3), and what the
/// caller may read of it (Switch wire 7.6).
pub trait ConditionState {
    /// A record's current version; [`RecordVersion::NONE`] for a record that doesn't exist or
    /// whose key the service forgot.
    fn record_version(&self, key: &[u8; 32]) -> RecordVersion;
    /// Whether the caller may see the record's version: it holds the record's read scope, or
    /// the record doesn't exist.
    fn may_read_record(&self, key: &[u8; 32]) -> bool;
    /// A claim's step, 0 when the service holds nothing for it.
    fn claim_step(&self, claim_key: &[u8; 32]) -> u64;
    /// The claim view, if the service holds the claim.
    fn claim_view(&self, claim_key: &[u8; 32]) -> Option<Value>;
    /// Whether the caller holds `claims.read`.
    fn may_read_claims(&self) -> bool;
    /// The service's time when it applies the batch, in Unix milliseconds.
    fn server_time(&self) -> u64;
}

/// Check conditions against the state before the batch (Switch wire 6.3, 6.4 step 8).
///
/// # Errors
///
/// `409 conflict` at the first that fails, with the current value the caller may read
/// (Switch wire 7.6): `{ "record_version": { "key", "generation", "version" } }`, `{
/// "claim_step": { "claim_key", "step" }, "claim": view | null }` or `{ "server_time" }`, and
/// `{}` for what it may not read.
pub fn check_conditions<'a>(
    conditions: impl IntoIterator<Item = &'a Condition>,
    state: &impl ConditionState,
) -> std::result::Result<(), Refusal> {
    for condition in conditions {
        let current = match condition {
            Condition::RecordVersion { key, version } => {
                let now = state.record_version(key);
                let holds = if version.version == 0 {
                    now.is_none()
                } else {
                    now == *version
                };
                (!holds).then(|| {
                    if state.may_read_record(key) {
                        json!({ "record_version": {
                            "key": b64(key),
                            "generation": now.generation,
                            "version": now.version,
                        } })
                    } else {
                        json!({})
                    }
                })
            }
            Condition::ClaimStep { claim_key, step } => {
                let now = state.claim_step(claim_key);
                (now != *step).then(|| {
                    if state.may_read_claims() {
                        json!({
                            "claim_step": { "claim_key": b64(claim_key), "step": now },
                            "claim": state.claim_view(claim_key).unwrap_or(Value::Null),
                        })
                    } else {
                        json!({})
                    }
                })
            }
            Condition::ServerTimeIn { start, end } => {
                let now = state.server_time();
                let inside = start.is_none_or(|s| now >= s) && end.is_none_or(|e| now < e);
                (!inside).then(|| json!({ "server_time": rfc3339(now) }))
            }
        };
        if let Some(current) = current {
            return Err(
                Refusal::conflict("Switch wire 6.3: a condition fails").with_current(current)
            );
        }
    }
    Ok(())
}

/// What the service holds that the no-op and rate rules compare a batch with, before the
/// batch (Switch wire 6.4 step 7).
pub trait Held {
    /// The app record the service holds for an app.
    fn app_record(&self, app_id: &[u8; 16]) -> Option<SignedDoc>;
    /// An app's current receive key record.
    fn receive_key(&self, app_id: &[u8; 16]) -> Option<SignedDoc>;
    /// The renewed certificate stored for an app, if any.
    fn renewed_cert(&self, app_id: &[u8; 16]) -> Option<SignedDoc>;
    /// The certificate the app's held record carries.
    fn record_cert(&self, app_id: &[u8; 16]) -> Option<SignedDoc>;
    /// Whether the target's stored key bundle parts hold this part, with the same epochs.
    fn holds_bundle_part(&self, part: &KeyBundlePut) -> bool;
    /// Whether a record's current write isn't a delete.
    fn record_live(&self, key: &[u8; 32]) -> bool;
    /// Whether the allowlist holds the entry.
    fn allowed(&self, pubky: &[u8; 32], kind: super::body::AllowKind) -> bool;
    /// Whether the deny list holds the Pubky ID.
    fn denied(&self, pubky: &[u8; 32]) -> bool;
}

/// Whether a signed operation is unchanged (Switch wire 6.4 "No-ops"): an `app.put` of the
/// record the service holds for the calling app, a `receive_key.put` of its current receive
/// key record, a signer's `cert.put` of the renewed certificate the service stores (or,
/// without one, of the certificate the app's record carries), and a signer's `key_bundle.put`
/// of a part it stores with the same epochs, each byte for byte. Nothing else is.
pub fn unchanged(body: &OpBody, held: &impl Held) -> bool {
    match (&body.kind, &body.app_id) {
        (OpKind::AppPut { record }, Some(app)) => held.app_record(app).as_ref() == Some(record),
        (OpKind::ReceiveKeyPut { record }, Some(app)) => {
            held.receive_key(app).as_ref() == Some(record)
        }
        (
            OpKind::CertPut {
                target_app_id,
                cert,
            },
            None,
        ) => {
            held.renewed_cert(target_app_id)
                .or_else(|| held.record_cert(target_app_id))
                .as_ref()
                == Some(cert)
        }
        (OpKind::KeyBundlePut(part), None) => held.holds_bundle_part(part),
        _ => false,
    }
}

/// What the service does with a batch at Switch wire 6.4 step 7.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchEffect {
    /// A batch without `cursor.set` whose every signed operation is unchanged: answered `{
    /// "proofs": [], "head" }` before the conditions and each operation's checks, with no
    /// chain item, no batch record and no rate.
    NoOp,
    /// A batch with `cursor.set` whose every signed operation is unchanged: never a no-op. Its
    /// conditions and operations are checked, the cursor moves only if all pass, and then
    /// there is no chain item, no batch record and no rate, and the answer is `{ "proofs":
    /// [], "head" }`.
    Unchanged,
    /// The batch goes on to the rates, then its conditions and operations.
    Apply {
        /// It counts against the app's operation rate, `ops_per_min`.
        operation_rate: bool,
        /// It counts against the app's control rate, `control_per_min`, too.
        control_rate: bool,
    },
}

/// The no-op decision and the rate classes of a batch (Switch wire 6.4 step 7, "Operation and
/// control rates"), against the state before it.
///
/// A batch from an own app counts against its operation rate when it carries an ordinary
/// operation or a repeatable control mutation, and against its control rate when it carries
/// a repeatable control mutation: an `app.put` or `receive_key.put` that changes what the
/// service holds, and a `record.put` that deletes, an `allow.delete` or a `deny.delete` of
/// something that isn't there. A claim entry other than `attempt`, a deletion or removal of
/// something present, `invite_code.delete` and every signer batch count against neither.
/// `cursor`: the batch carries `cursor.set`. A batch of only `cursor.set` has no operations,
/// and is applied like any other.
pub fn batch_effect(ops: &[SignedOp], held: &impl Held, cursor: bool) -> BatchEffect {
    let mut all_unchanged = !ops.is_empty();
    let (mut ordinary, mut control) = (false, false);
    for op in ops {
        let body = op.body();
        let same = unchanged(body, held);
        all_unchanged &= same;
        match &body.kind {
            OpKind::RecordPut(put) => {
                if !put.value_sealed.looks_like_delete() {
                    ordinary = true;
                } else if !held.record_live(&put.key) {
                    control = true;
                }
            }
            OpKind::Claim(fields) => {
                ordinary |= fields.kind == crate::claims::ClaimType::Attempt;
            }
            OpKind::AllowPut { .. } | OpKind::DenyPut { .. } | OpKind::InviteCodePut(_) => {
                ordinary = true;
            }
            OpKind::AllowDelete { pubky, kind } => control |= !held.allowed(pubky, *kind),
            OpKind::DenyDelete { pubky } => control |= !held.denied(pubky),
            OpKind::AppPut { .. } | OpKind::ReceiveKeyPut { .. } => control |= !same,
            OpKind::InviteCodeDelete { .. } | OpKind::KeyBundlePut(_) | OpKind::CertPut { .. } => {}
        }
    }
    if all_unchanged {
        return if cursor {
            BatchEffect::Unchanged
        } else {
            BatchEffect::NoOp
        };
    }
    let signer = ops.iter().all(|o| o.body().app_id.is_none());
    BatchEffect::Apply {
        operation_rate: !signer && (ordinary || control),
        control_rate: !signer && control,
    }
}

/// Whether a batch depends on the service's time, so that without trusted time it is `503
/// unavailable` (Switch wire 7.3): it carries an `attempt` or a `server_time_in` condition,
/// or an outcome that only an attempt's orphan age or its owner's certificate expiry allows,
/// which `outcome_depends` judges for each claim entry and its writer (see
/// [`crate::claims::entry_depends_on_time`]).
pub fn depends_on_time(
    ops: &[SignedOp],
    outcome_depends: &dyn Fn(&crate::claims::ClaimFields, Option<&[u8; 16]>) -> bool,
) -> bool {
    ops.iter().any(|op| {
        let body = op.body();
        body.conditions
            .iter()
            .any(|c| matches!(c, Condition::ServerTimeIn { .. }))
            || match &body.kind {
                OpKind::Claim(fields) => {
                    fields.kind == crate::claims::ClaimType::Attempt
                        || outcome_depends(fields, body.app_id.as_ref())
                }
                _ => false,
            }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::{ClaimFields, ClaimType};
    use crate::keys::{AppKeys, IdentityKey};
    use crate::ops::body::AllowKind;

    fn identity() -> IdentityKey {
        IdentityKey::from_secret([1; 32])
    }

    fn app() -> AppKeys {
        AppKeys::from_secrets([2; 32], [3; 32])
    }

    fn claim(kind: ClaimType) -> OpKind {
        OpKind::Claim(ClaimFields {
            claim_key: vec![1; 32],
            kind,
            expected_step: 0,
            attempt_id: vec![2; 16],
            orphan_after: (kind == ClaimType::Attempt).then_some(60),
            deadline: None,
            basis: None,
            evidence_ref: None,
        })
    }

    fn batch(kinds: Vec<OpKind>) -> Vec<SignedOp> {
        let a = app();
        sign_batch(
            &a,
            &identity().public(),
            Some(a.app_id_bytes()),
            1,
            [7; 16],
            kinds.into_iter().map(|k| (Vec::new(), k)).collect(),
        )
        .unwrap()
    }

    #[test]
    fn test_position_reads_two_decimal_integers() {
        assert_eq!(
            Position::parse("3:1042").unwrap(),
            Position {
                generation: 3,
                seq: 1042
            }
        );
        assert_eq!(Position::parse("1:0").unwrap().to_string(), "1:0");
        for bad in [
            "1",
            ":1",
            "1:",
            "1:-2",
            "1:+2",
            "a:1",
            "1:2:3",
            "1:99999999999999999",
        ] {
            assert!(Position::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_ops_request_round_trips_and_counts_entries() {
        let ops = batch(vec![claim(ClaimType::Attempt)]);
        let request = OpsRequest::new(
            &ops,
            Some(Position {
                generation: 1,
                seq: 0,
            }),
        );
        let bytes = request.to_json();
        let read = OpsRequest::parse(&bytes).unwrap();
        assert_eq!(read, request);
        assert_eq!(read.signed().count(), 1);
        assert_eq!(
            read.cursor(),
            Some(Position {
                generation: 1,
                seq: 0
            })
        );
        assert!(OpsRequest::parse(br#"{"ops":[]}"#).is_err());
        let nine = format!(
            "{{\"ops\":[{}]}}",
            [r#"{"op":"cursor.set","position":"1:0"}"#; 9].join(",")
        );
        assert!(OpsRequest::parse(nine.as_bytes()).is_err());
        let two = br#"{"ops":[{"op":"cursor.set","position":"1:0"},{"op":"cursor.set","position":"1:1"}]}"#;
        assert!(OpsRequest::parse(two).is_err());
    }

    #[test]
    fn test_ops_request_signer_carries_no_cursor() {
        let ops = batch(vec![claim(ClaimType::Attempt)]);
        let position = Position {
            generation: 1,
            seq: 0,
        };
        let with_cursor = OpsRequest::new(&ops, Some(position));
        with_cursor.check_caller(false).unwrap();
        assert_eq!(with_cursor.check_caller(true).unwrap_err().status(), 400);
        let cursor_only = OpsRequest::new(&[], Some(position));
        assert_eq!(cursor_only.check_caller(true).unwrap_err().status(), 400);
        OpsRequest::new(&ops, None).check_caller(true).unwrap();
    }

    #[test]
    fn test_ops_request_refuses_members_beside_an_entry_and_oversize_ops() {
        let extra = br#"{"ops":[{"op":"cursor.set","position":"1:0","x":1}]}"#;
        assert_eq!(OpsRequest::parse(extra).unwrap_err().status(), 400);
        let other_op = br#"{"ops":[{"op":"claim","position":"1:0"}]}"#;
        assert!(OpsRequest::parse(other_op).is_err());
        let signed = br#"{"ops":[{"body":"e30","sig":"AA","x":1}]}"#;
        assert_eq!(OpsRequest::parse(signed).unwrap_err().status(), 400);
        let big = format!(
            "{{\"ops\":[{{\"body\":\"{}\",\"sig\":\"AA\"}}]}}",
            "A".repeat(MAX_OP_BYTES)
        );
        assert_eq!(OpsRequest::parse(big.as_bytes()).unwrap_err().status(), 413);
        // A 400 among the entries answers before a 413.
        let both = format!(
            "{{\"ops\":[{{\"body\":\"{}\",\"sig\":\"AA\"}},{{\"x\":1}}]}}",
            "A".repeat(MAX_OP_BYTES)
        );
        assert_eq!(
            OpsRequest::parse(both.as_bytes()).unwrap_err().status(),
            400
        );
    }

    #[test]
    fn test_check_batch_rules() {
        let ops = batch(vec![claim(ClaimType::Attempt), claim(ClaimType::Failed)]);
        assert!(check_batch(&ops).is_ok());
        assert!(check_batch(&ops[..1]).is_err(), "count is 2");
        let other = batch(vec![claim(ClaimType::Attempt)]);
        assert!(check_batch(&[ops[0].clone(), other[0].clone()]).is_err());
        assert!(check_batch(&[]).is_ok());
        assert!(
            sign_batch(
                &app(),
                &identity().public(),
                Some(app().app_id_bytes()),
                1,
                [7; 16],
                Vec::new()
            )
            .is_err()
        );
    }

    #[test]
    fn test_ops_hash_and_retries() {
        let ops = batch(vec![claim(ClaimType::Attempt)]);
        let h = ops_hash(&ops).unwrap();
        let docs = [ops[0].doc_bytes().unwrap()];
        assert_eq!(h, hash(&lp(&[&docs[0]])));
        let proofs = vec![SignedDoc::from_parts(b"{}", &[0; 64])];
        let record = BatchRecord {
            ops_hash: h,
            proofs: Some(proofs.clone()),
            at: 0,
            first_seq: 3,
            last_seq: 4,
        };
        assert_eq!(retry_check(None, &h).unwrap(), RetryCheck::New);
        assert_eq!(
            retry_check(Some(&record), &h).unwrap(),
            RetryCheck::Retry(proofs)
        );
        assert_eq!(
            retry_check(Some(&record), &[0; 32]).unwrap_err().status(),
            409
        );
        let dropped = BatchRecord {
            proofs: None,
            ..record.clone()
        };
        assert_eq!(retry_check(Some(&dropped), &h).unwrap_err().status(), 409);
        assert!(!record.proofs_expired(BATCH_PROOFS_MS - 1, BATCH_PROOFS_MS));
        assert!(record.proofs_expired(BATCH_PROOFS_MS, BATCH_PROOFS_MS));
        assert!(dropped.held(|seq| seq == 4));
        assert!(!dropped.held(|seq| seq == 5));
    }

    struct State {
        version: RecordVersion,
        readable: bool,
        step: u64,
        claims_read: bool,
        now: u64,
    }

    impl ConditionState for State {
        fn record_version(&self, _: &[u8; 32]) -> RecordVersion {
            self.version
        }
        fn may_read_record(&self, _: &[u8; 32]) -> bool {
            self.readable
        }
        fn claim_step(&self, _: &[u8; 32]) -> u64 {
            self.step
        }
        fn claim_view(&self, _: &[u8; 32]) -> Option<Value> {
            None
        }
        fn may_read_claims(&self) -> bool {
            self.claims_read
        }
        fn server_time(&self) -> u64 {
            self.now
        }
    }

    #[test]
    fn test_conditions_hold_or_conflict_with_current() {
        let state = State {
            version: RecordVersion::new(1, 6),
            readable: true,
            step: 2,
            claims_read: true,
            now: 100,
        };
        let record = |g, v| Condition::RecordVersion {
            key: [1; 32],
            version: RecordVersion::new(g, v),
        };
        assert!(check_conditions(&[record(1, 6)], &state).is_ok());
        let refused = check_conditions(&[record(1, 5)], &state).unwrap_err();
        assert_eq!(refused.current.unwrap()["record_version"]["version"], 6);
        // Version 0 holds only for a record that doesn't exist, whatever the generation.
        assert!(check_conditions(&[record(9, 0)], &state).is_err());
        let absent = State {
            version: RecordVersion::NONE,
            ..state
        };
        assert!(check_conditions(&[record(9, 0)], &absent).is_ok());
        let step = |s| Condition::ClaimStep {
            claim_key: [2; 32],
            step: s,
        };
        assert!(check_conditions(&[step(2)], &state).is_ok());
        let refused = check_conditions(&[step(1)], &state).unwrap_err();
        assert_eq!(
            refused.current.unwrap(),
            json!({"claim_step": {"claim_key": b64(&[2; 32]), "step": 2}, "claim": null})
        );
        let blind = State {
            claims_read: false,
            readable: false,
            ..state
        };
        assert_eq!(
            check_conditions(&[step(1)], &blind).unwrap_err().current,
            Some(json!({}))
        );
        assert_eq!(
            check_conditions(&[record(1, 5)], &blind)
                .unwrap_err()
                .current,
            Some(json!({}))
        );
        let window = |s, e| Condition::ServerTimeIn { start: s, end: e };
        assert!(check_conditions(&[window(Some(100), Some(101))], &blind).is_ok());
        assert!(check_conditions(&[window(None, None)], &blind).is_ok());
        assert!(check_conditions(&[window(Some(101), None)], &blind).is_err());
        let refused = check_conditions(&[window(None, Some(100))], &blind).unwrap_err();
        assert_eq!(refused.current.unwrap()["server_time"], rfc3339(100));
    }

    #[derive(Default)]
    struct Holds {
        record: Option<SignedDoc>,
        live: bool,
        allowed: bool,
    }

    impl Held for Holds {
        fn app_record(&self, _: &[u8; 16]) -> Option<SignedDoc> {
            self.record.clone()
        }
        fn receive_key(&self, _: &[u8; 16]) -> Option<SignedDoc> {
            None
        }
        fn renewed_cert(&self, _: &[u8; 16]) -> Option<SignedDoc> {
            None
        }
        fn record_cert(&self, _: &[u8; 16]) -> Option<SignedDoc> {
            None
        }
        fn holds_bundle_part(&self, _: &KeyBundlePut) -> bool {
            false
        }
        fn record_live(&self, _: &[u8; 32]) -> bool {
            self.live
        }
        fn allowed(&self, _: &[u8; 32], _: AllowKind) -> bool {
            self.allowed
        }
        fn denied(&self, _: &[u8; 32]) -> bool {
            false
        }
    }

    #[test]
    fn test_batch_effect_no_ops_and_rates() {
        let record = SignedDoc::from_parts(b"{}", &[1; 64]);
        let put = OpKind::AppPut {
            record: record.clone(),
        };
        let holds = Holds {
            record: Some(record.clone()),
            ..Holds::default()
        };
        let ops = batch(vec![put.clone()]);
        assert_eq!(batch_effect(&ops, &holds, false), BatchEffect::NoOp);
        assert_eq!(batch_effect(&ops, &holds, true), BatchEffect::Unchanged);
        let fresh = Holds::default();
        assert_eq!(
            batch_effect(&ops, &fresh, false),
            BatchEffect::Apply {
                operation_rate: true,
                control_rate: true
            }
        );
        // An unchanged app.put beside an attempt counts against no rate itself.
        let mixed = batch(vec![put, claim(ClaimType::Attempt)]);
        assert_eq!(
            batch_effect(&mixed, &holds, false),
            BatchEffect::Apply {
                operation_rate: true,
                control_rate: false
            }
        );
        let outcome = batch(vec![claim(ClaimType::Failed)]);
        assert_eq!(
            batch_effect(&outcome, &holds, false),
            BatchEffect::Apply {
                operation_rate: false,
                control_rate: false
            }
        );
        let removal = batch(vec![OpKind::AllowDelete {
            pubky: [1; 32],
            kind: AllowKind::Contact,
        }]);
        assert_eq!(
            batch_effect(&removal, &fresh, false),
            BatchEffect::Apply {
                operation_rate: true,
                control_rate: true
            }
        );
        let present = Holds {
            allowed: true,
            ..Holds::default()
        };
        assert_eq!(
            batch_effect(&removal, &present, false),
            BatchEffect::Apply {
                operation_rate: false,
                control_rate: false
            }
        );
        assert_eq!(
            batch_effect(&[], &fresh, true),
            BatchEffect::Apply {
                operation_rate: false,
                control_rate: false
            }
        );
    }

    #[test]
    fn test_depends_on_time() {
        let never = |_: &ClaimFields, _: Option<&[u8; 16]>| false;
        assert!(depends_on_time(
            &batch(vec![claim(ClaimType::Attempt)]),
            &never
        ));
        assert!(!depends_on_time(
            &batch(vec![claim(ClaimType::Failed)]),
            &never
        ));
        let always = |_: &ClaimFields, _: Option<&[u8; 16]>| true;
        assert!(depends_on_time(
            &batch(vec![claim(ClaimType::Failed)]),
            &always
        ));
        let a = app();
        let windowed = sign_batch(
            &a,
            &identity().public(),
            Some(a.app_id_bytes()),
            1,
            [7; 16],
            vec![(
                vec![Condition::ServerTimeIn {
                    start: None,
                    end: None,
                }],
                OpKind::DenyPut { pubky: [1; 32] },
            )],
        )
        .unwrap();
        assert!(depends_on_time(&windowed, &never));
    }

    #[test]
    fn test_check_cursor_keeps_the_generation_and_head_bounds() {
        let at = |generation, seq| Position { generation, seq };
        assert!(check_cursor(at(1, 0), 1, None, 0).is_ok());
        assert!(check_cursor(at(1, 9), 1, None, 9).is_ok());
        // After a cooperative move, the generation the sequence continues from.
        assert!(check_cursor(at(1, 9), 2, Some(1), 12).is_ok());
        assert!(check_cursor(at(2, 12), 2, Some(1), 12).is_ok());
        let refused = |position| check_cursor(position, 1, None, 9).err().map(|r| r.code);
        assert_eq!(refused(at(1, 10)), Some(ErrorCode::BadRequest));
        assert_eq!(refused(at(77, 9)), Some(ErrorCode::BadRequest));
        assert_eq!(refused(at(0, 0)), Some(ErrorCode::BadRequest));
        assert!(check_cursor(at(3, 0), 2, Some(1), 12).is_err());
    }
}
