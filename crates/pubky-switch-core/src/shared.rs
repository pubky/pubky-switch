//! Shared records (Switch spec 10.3, Switch wire 6.2 `record.put`): the pure rules of a
//! record's version, the compare-and-swap of `expected_version`, a policy fixed at creation,
//! and the checks an app makes before it takes a write in place of the one it holds.
//!
//! The service keeps each record's current write; its version is the (generation, `seq`) of
//! that write, so versions only grow across the account, whoever writes. The value is sealed
//! under the read scope's key, which the switch never holds: it compares scope strings and
//! gives versions, and apps check every write they read.

use serde_json::{Value, json};

use crate::chain::{ItemType, TransitionProof, item_hash};
use crate::enc::{b64, unb64_array};
use crate::error::{Error, Result, invalid};
use crate::http::ErrorCode;
use crate::ident::Policy;
use crate::json::{MAX_INT, parse_json, reject_unknown_members};
use crate::ops::body::Obj;
use crate::ops::{Condition, RecordPut, RecordVersion, Refusal, SignedOp};
use crate::records::IdentityDoc;

/// One application of a record write at the service, ordered by generation, sequence, then
/// item hash (Switch wire 6.3). Its shape alone does not prove an application occurred.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApplicationRef {
    /// Positive application generation, at most the wire integer maximum.
    pub generation: u64,
    /// Positive sequence within that generation, at most the wire integer maximum.
    pub seq: u64,
    /// Hash of the full applied item.
    pub item_hash: [u8; 32],
}

impl ApplicationRef {
    /// Read an exact reference object under the strict JSON rules.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for malformed members or an invalid reference.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::read(&parse_json(bytes)?)
    }

    pub(crate) fn read(value: &Value) -> Result<Self> {
        const NAMES: [&str; 3] = ["generation", "seq", "item_hash"];
        reject_unknown_members(value, &NAMES, "reference")?;
        let member = |name: &str| {
            value
                .get(name)
                .ok_or_else(|| Error::Invalid(format!("Switch wire 6.3: missing member {name}")))
        };
        let integer = |name: &str| match member(name)?.as_u64() {
            Some(n) if n <= MAX_INT => Ok(n),
            _ => invalid("Switch wire 6.3: expected a wire integer"),
        };
        let hash = member("item_hash")?
            .as_str()
            .ok_or_else(|| Error::Invalid("Switch wire 6.3: expected a string".into()))?;
        let reference = Self {
            generation: integer("generation")?,
            seq: integer("seq")?,
            item_hash: unb64_array(hash)?,
        };
        reference.check()?;
        Ok(reference)
    }

    /// Check that both integers are positive wire integers (Switch wire 6.3).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for a zero or out-of-range integer.
    pub fn check(&self) -> Result<()> {
        for n in [self.generation, self.seq] {
            if n == 0 || n > MAX_INT {
                return invalid("Switch wire 6.3: expected a positive wire integer");
            }
        }
        Ok(())
    }

    /// Write the reference in member order (Switch wire 6.3).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for a zero or out-of-range integer.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.check()?;
        let mut out = Obj::new();
        out.int("generation", self.generation)
            .int("seq", self.seq)
            .str("item_hash", &b64(&self.item_hash));
        Ok(out.finish())
    }
}

/// Exact current facts for a `record_current` condition (Switch wire 6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentRecord {
    /// The application at the service, distinct from an uploaded source version.
    pub revision: ApplicationRef,
    /// Whether the current application deletes the record.
    pub deleted: bool,
}

/// A record as the service holds it (Switch spec 10.3): its key, collection and policy, fixed
/// at creation, and its current version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordState {
    /// The record key.
    pub key: [u8; 32],
    /// The collection ID.
    pub collection: [u8; 32],
    /// The policy.
    pub policy: Policy,
    /// The version of the current write.
    pub version: RecordVersion,
    /// The current write is a delete.
    pub deleted: bool,
}

impl RecordState {
    /// The record after a write the service applied at (`generation`, `seq`): the write's
    /// key, collection and policy, its version, and whether it deletes (its `ct` the tag
    /// alone, which the service can't open: a reader decides a delete by opening it).
    pub fn after(put: &RecordPut, generation: u64, seq: u64) -> Self {
        Self {
            key: put.key,
            collection: put.collection,
            policy: put.policy.clone(),
            version: RecordVersion::new(generation, seq),
            deleted: put.value_sealed.looks_like_delete(),
        }
    }
}

/// Whether a write or a `record_version` condition that names `named` builds on what the
/// service holds at `key` (Switch spec 10.3, Switch wire 6.2, 6.3), the one judge of a named
/// version, for the service and every switch that applies operations:
///
/// - `{0, 0}` holds only when the service holds nothing at the key: no live record and no
///   delete it keeps. A write over a kept delete names that delete;
/// - any other version holds when it is the held write's version (`held`, with that write's
///   application). When that write was taken from a recovery upload, its application isn't
///   at its version, and two uploads can share a version (Switch spec 12.6 step 3): the
///   version holds then only beside a `record_current` among the operation's `conditions`
///   that names that application.
pub fn version_holds<'a>(
    key: &[u8; 32],
    named: RecordVersion,
    held: Option<(RecordVersion, ApplicationRef)>,
    conditions: impl IntoIterator<Item = &'a Condition>,
) -> bool {
    let Some((version, revision)) = held else {
        return named.is_none();
    };
    if named != version {
        return false;
    }
    let from_upload = revision.generation != version.generation || revision.seq != version.version;
    !from_upload
        || conditions.into_iter().any(|condition| {
            matches!(condition, Condition::RecordCurrent { key: k, revision: r, .. }
                if k == key && *r == revision)
        })
}

/// The service's rules for a `record.put` against the record it holds, after the writer's
/// permission and the operation's shape (Switch wire 6.2, 6.4 step 9, Switch spec 10.3):
///
/// - the sealed value's data epoch is the current one (`data_epoch`), else `409 stale_epoch`
///   with `current.data_epoch`;
/// - a write over a record the service holds, live or deleted, a create included, repeats
///   the record's collection and policy, its `permanent` member included, else `400`, before
///   the versions are compared (Switch spec 10.3.1);
/// - `expected_version` holds by [`version_holds`] against the held write (`current`, with
///   its application) and the operation's `conditions`; else `409 conflict`, whose `current`
///   carries `record` and the current write's `record_view` to a writer with the read scope
///   (`may_read`), `{}` to one without, and `record` at `{0, 0}` with a null `record_view`
///   to every writer when the service holds nothing at the key.
///
/// # Errors
///
/// As above.
pub fn check_record_put<'a>(
    put: &RecordPut,
    conditions: impl IntoIterator<Item = &'a Condition>,
    current: Option<(&RecordState, ApplicationRef)>,
    data_epoch: u64,
    may_read: bool,
    record_view: Option<&Value>,
) -> std::result::Result<(), Refusal> {
    if put.value_sealed.data_epoch != data_epoch {
        return Err(Refusal::new(
            ErrorCode::StaleEpoch,
            "Switch wire 6.2: a sealed value at another data epoch",
        )
        .with_current(json!({ "data_epoch": data_epoch })));
    }
    if let Some((held, _)) = current
        && (held.collection != put.collection || held.policy != put.policy)
    {
        return Err(Refusal::bad_request(
            "Switch spec 10.3: a write repeats the record's collection and policy",
        ));
    }
    let held = current.map(|(held, revision)| (held.version, revision));
    if version_holds(&put.key, put.expected_version, held, conditions) {
        return Ok(());
    }
    let current = match (current, may_read) {
        (Some((held, _)), true) => json!({
            "record": {
                "key": b64(&held.key),
                "generation": held.version.generation,
                "version": held.version.version,
            },
            "record_view": record_view.cloned().unwrap_or(Value::Null),
        }),
        (Some(_), false) => json!({}),
        (None, _) => json!({
            "record": { "key": b64(&put.key), "generation": 0, "version": 0 },
            "record_view": null,
        }),
    };
    Err(
        Refusal::conflict("Switch wire 6.2: expected_version isn't the record's current version")
            .with_current(current),
    )
}

/// What a transition proof gives a shared record write (Switch wire 6.2 "Accepting a write"
/// step 2): the write's time, and its version when the proof verifies with the current
/// service key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dated {
    /// The write's service time, from the proof's stub.
    pub time: u64,
    /// The authenticated version; `None` for an earlier generation's proof.
    pub version: Option<RecordVersion>,
}

/// Date a `record.put` by the transition proof kept with the record (Switch wire 6.2
/// "Accepting a write" step 2), with the newest own `identity.json` the app holds.
///
/// A proof of the document's own generation that verifies with the current service key must
/// have a stub whose `item_hash` is the operation's, an `object` that is the record key, and
/// a `state` whose generation and version are the stub's; it dates the write and gives its
/// version. A proof is checked only with the key listed for the generation its stub names,
/// so a lost generation's proof dates nothing even when it verifies with the current key,
/// as after a provider loss at the same service (Switch wire 3.3). A proof of an earlier
/// generation dates the write, without a version, when it verifies with the key `identity`
/// lists for its stub's generation in `service_keys`, and its stub's `item_hash` is the
/// operation's. Whether the stub contradicts a chain hash the app verified is the caller's
/// check.
///
/// # Errors
///
/// [`Error::Invalid`] or [`Error::Signature`]: the proof dates nothing. A proof that
/// verifies with the current key and names another operation or object is signed
/// misbehaviour, a rollback.
pub fn date_write(
    proof: &crate::sig::SignedDoc,
    op: &SignedOp,
    identity: &IdentityDoc,
) -> Result<Dated> {
    let id = identity.identity();
    let item = item_hash(ItemType::Op, &op.doc_bytes()?);
    let crate::ops::OpKind::RecordPut(put) = &op.body().kind else {
        return crate::error::invalid("Switch wire 6.2: the operation isn't a record.put");
    };
    let bad = |why: &str| Err(Error::Invalid(format!("Switch wire 6.2 step 2: {why}")));
    // A service applies only operations of its own generation (Switch wire 6.4 step 6), so a
    // proof whose stub names another generation than the operation is no proof of it.
    let of_its_generation =
        |env: &crate::chain::ChainEnvelope| env.generation == op.body().generation;
    if let Ok(checked) = TransitionProof::verify(proof, &identity.inbox().service_key, &id)
        && checked.envelope().generation == identity.generation()
    {
        let env = checked.envelope();

        if env.item_type != ItemType::Op || env.item_hash != item {
            return bad("the proof's stub isn't the operation's");
        }
        if !of_its_generation(env) {
            return bad("the proof's stub isn't of the operation's generation");
        }
        checked
            .check_binds(op)
            .map_err(|e| Error::Invalid(e.to_string()))?;
        if checked.body().object != b64(&put.key) {
            return bad("the proof's object isn't the record key");
        }
        let state = &checked.body().state;
        let version = RecordVersion::new(
            state
                .get("generation")
                .and_then(Value::as_u64)
                .unwrap_or(u64::MAX),
            state
                .get("version")
                .and_then(Value::as_u64)
                .unwrap_or(u64::MAX),
        );
        if version != RecordVersion::new(env.generation, env.seq) {
            return bad("the proof's state isn't its stub's version");
        }
        return Ok(Dated {
            time: env.server_time,
            version: Some(version),
        });
    }
    let peeked = TransitionProof::peek(proof)?;
    let generation = peeked.envelope().generation;
    if generation >= identity.generation() {
        return bad("the proof doesn't verify with the current service key");
    }
    let Some(key) = identity.service_key_of(generation) else {
        return bad("service_keys doesn't name the proof's generation, which dates nothing");
    };
    let checked = TransitionProof::verify(proof, &key, &id)?;
    if checked.envelope().item_hash != item {
        return bad("the proof's stub isn't the operation's");
    }
    if !of_its_generation(checked.envelope()) {
        return bad("the proof's stub isn't of the operation's generation");
    }
    checked
        .check_binds(op)
        .map_err(|e| Error::Invalid(e.to_string()))?;
    Ok(Dated {
        time: checked.envelope().server_time,
        version: None,
    })
}

/// A write's version as an app holds it (Switch wire 6.2 "Accepting a write" step 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteVersion {
    /// The version: from a proof or a verified stub (authenticated), or the record view's.
    pub version: RecordVersion,
    /// Whether a proof or a verified stub gave it.
    pub authenticated: bool,
    /// The version the write signed as `expected_version`.
    pub expected_version: RecordVersion,
}

impl WriteVersion {
    /// Step 6's check: the version's generation is the operation's `generation`, and the
    /// version is after `expected_version`.
    pub fn plausible(&self, op_generation: u64) -> bool {
        self.version.generation == op_generation && self.version > self.expected_version
    }

    /// Whether an app takes this write in place of the one it holds (Switch wire 6.2,
    /// Switch spec 10.3): with both versions authenticated, the higher one; with this one
    /// unauthenticated, only if its `expected_version` is the held version or later; with the
    /// held one unauthenticated, the held write counts as just after its own
    /// `expected_version`. So a service can't pass an older genuine write off as newer. The
    /// same write again with an authenticated version makes the held one authenticated,
    /// which is the caller's to note.
    pub fn replaces(&self, held: &WriteVersion) -> bool {
        match (self.authenticated, held.authenticated) {
            (true, true) => self.version > held.version,
            (true, false) => self.version > held.expected_version,
            (false, true) => self.expected_version >= held.version,
            (false, false) => self.expected_version > held.expected_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ident::{NamingKey, collection_id, record_key_from_blinded};
    use crate::keys::IdentityKey;
    use crate::ops::IdInputs;
    use crate::sealed::SealedValue;

    fn reference(generation: u64, seq: u64, byte: u8) -> ApplicationRef {
        ApplicationRef {
            generation,
            seq,
            item_hash: [byte; 32],
        }
    }

    #[test]
    fn test_reference_exact_json_and_order() {
        let value = reference(1, 2, 3);
        assert_eq!(
            String::from_utf8(value.to_json().unwrap()).unwrap(),
            r#"{"generation":1,"seq":2,"item_hash":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"}"#
        );
        assert_eq!(
            ApplicationRef::parse(&value.to_json().unwrap()).unwrap(),
            value
        );
        assert!(reference(1, 2, 254) < reference(1, 2, 255));
        assert!(reference(1, 2, 255) < reference(1, 3, 0));
        assert!(reference(1, 3, 255) < reference(2, 1, 0));
        assert!(reference(MAX_INT, MAX_INT, 0).check().is_ok());
    }

    #[test]
    fn test_reference_strict_members_and_integer_bounds() {
        let good = reference(1, 2, 3);
        for field in ["generation", "seq", "item_hash"] {
            let mut value: Value = serde_json::from_slice(&good.to_json().unwrap()).unwrap();
            value.as_object_mut().unwrap().remove(field);
            assert!(ApplicationRef::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        for bad in [
            json!(0),
            json!(MAX_INT + 1),
            json!(-1),
            json!(1.5),
            json!("1"),
            Value::Null,
            json!(true),
        ] {
            for field in ["generation", "seq"] {
                let mut value: Value = serde_json::from_slice(&good.to_json().unwrap()).unwrap();
                value[field] = bad.clone();
                assert!(ApplicationRef::parse(&serde_json::to_vec(&value).unwrap()).is_err());
            }
        }
        for bad in [0, MAX_INT + 1] {
            assert!(reference(bad, 2, 3).to_json().is_err());
            assert!(reference(1, bad, 3).check().is_err());
        }
        let text = String::from_utf8(good.to_json().unwrap()).unwrap();
        for extra in [r#""generation":1,"#, r#""unknown":null,"#] {
            assert!(ApplicationRef::parse(format!("{{{extra}{}", &text[1..]).as_bytes()).is_err());
        }
        assert!(
            ApplicationRef::parse(
                text.replace("\"generation\":1", "\"generation\":1e0")
                    .as_bytes()
            )
            .is_err()
        );
        let mut value: Value = serde_json::from_str(&text).unwrap();
        for hash in [b64(&[0; 31]), b64(&[0; 33]), format!("{}=", b64(&[0; 32]))] {
            value["item_hash"] = json!(hash);
            assert!(ApplicationRef::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }

    fn put(expected: RecordVersion, epoch: u64, delete: bool) -> RecordPut {
        let id = IdentityKey::from_secret([1; 32]);
        let naming = NamingKey::from_root(&id.switch_root());
        let policy = Policy::new("scope-a", &["scope-a"]);
        let blinded = naming.blind(b"natural");
        let key = record_key_from_blinded("sample.collection", &blinded, &policy.hash().unwrap());
        let scope_key = id.scope_key(epoch, "scope-a");
        let json: &[u8] = if delete { b"" } else { b"{}" };
        RecordPut {
            key,
            collection: collection_id("sample.collection", &id.public()),
            policy,
            expected_version: expected,
            value_sealed: SealedValue::seal(&scope_key, &id.public(), epoch, "scope-a", &key, json)
                .unwrap(),
            id_inputs: IdInputs {
                collection: "sample.collection".into(),
                blinded_key: blinded,
            },
        }
    }

    /// The application of a write chained at (`generation`, `seq`).
    fn applied(generation: u64, seq: u64) -> ApplicationRef {
        ApplicationRef {
            generation,
            seq,
            item_hash: [7; 32],
        }
    }

    #[test]
    fn test_record_put_compare_and_swap() {
        let create = put(RecordVersion::NONE, 1, false);
        let none: [Condition; 0] = [];
        assert!(check_record_put(&create, &none, None, 1, true, None).is_ok());
        let held = RecordState::after(&create, 1, 6);
        assert_eq!(held.version, RecordVersion::new(1, 6));
        let current = Some((&held, applied(1, 6)));
        // A create at a live record conflicts; with the read scope, current shows it.
        let refused =
            check_record_put(&create, &none, current, 1, true, Some(&json!({"v": 1}))).unwrap_err();
        assert_eq!(refused.status(), 409);
        let shown = refused.current.unwrap();
        assert_eq!(shown["record"]["version"], 6);
        assert_eq!(shown["record_view"], json!({"v": 1}));
        let blind = check_record_put(&create, &none, current, 1, false, None).unwrap_err();
        assert_eq!(blind.current, Some(json!({})));
        let update = put(RecordVersion::new(1, 6), 1, false);
        assert!(check_record_put(&update, &none, current, 1, true, None).is_ok());
        let stale = put(RecordVersion::new(1, 5), 1, false);
        assert!(check_record_put(&stale, &none, current, 1, true, None).is_err());
        // A key the service holds nothing for, never written or forgotten, shows version 0
        // to every writer.
        for may_read in [true, false] {
            let forgotten = check_record_put(&update, &none, None, 1, may_read, None).unwrap_err();
            assert_eq!(
                forgotten.current,
                Some(json!({
                    "record": {"key": b64(&update.key), "generation": 0, "version": 0},
                    "record_view": null,
                }))
            );
        }
    }

    /// The service's state at one record key, for its conditions.
    struct AtKey {
        key: [u8; 32],
        held: Option<(RecordVersion, ApplicationRef, bool)>,
        readable: bool,
    }

    impl crate::ops::ConditionState for AtKey {
        fn record_current(&self, key: &[u8; 32]) -> Option<CurrentRecord> {
            self.held
                .filter(|_| *key == self.key)
                .map(|(_, revision, deleted)| CurrentRecord { revision, deleted })
        }
        fn record_view(&self, _: &[u8; 32]) -> Option<Value> {
            None
        }
        fn record_version(&self, key: &[u8; 32]) -> RecordVersion {
            self.held
                .filter(|_| *key == self.key)
                .map_or(RecordVersion::NONE, |(version, ..)| version)
        }
        fn may_read_record(&self, _: &[u8; 32]) -> bool {
            self.readable
        }
        fn claim_step(&self, _: &[u8; 32]) -> u64 {
            0
        }
        fn claim_view(&self, _: &[u8; 32]) -> Option<Value> {
            None
        }
        fn may_read_claims(&self) -> bool {
            false
        }
        fn server_time(&self) -> u64 {
            0
        }
    }

    /// One rule judges every named version, a write's `expected_version` and a
    /// `record_version` condition alike: `{0, 0}` only where the service holds nothing,
    /// another version only where it is the held write's, and a write taken from a recovery
    /// upload only beside a `record_current` naming it.
    #[test]
    fn test_version_holds_for_writes_and_conditions() {
        let v = RecordVersion::new;
        let from_upload = ApplicationRef {
            generation: 2,
            seq: 3,
            item_hash: [8; 32],
        };
        let other_upload = ApplicationRef {
            item_hash: [9; 32],
            ..from_upload
        };
        let nothing = None;
        let live = Some((v(1, 6), applied(1, 6), false));
        let kept_delete = Some((v(1, 9), applied(1, 9), true));
        let uploaded = Some((v(1, 6), from_upload, false));
        // (held, named, a `record_current` beside it, holds)
        let cases = [
            (nothing, RecordVersion::NONE, None, true),
            (nothing, v(1, 6), None, false),
            (live, RecordVersion::NONE, None, false),
            (live, v(1, 6), None, true),
            (live, v(1, 5), None, false),
            (kept_delete, RecordVersion::NONE, None, false),
            (kept_delete, v(1, 9), None, true),
            (kept_delete, v(1, 6), None, false),
            (uploaded, v(1, 6), None, false),
            (uploaded, v(1, 6), Some(from_upload), true),
            (uploaded, v(1, 6), Some(other_upload), false),
            (uploaded, RecordVersion::NONE, Some(from_upload), false),
        ];
        for (i, (held, named, current, holds)) in cases.into_iter().enumerate() {
            let write = put(named, 1, false);
            let conditions: Vec<Condition> = current
                .map(|revision| Condition::RecordCurrent {
                    key: write.key,
                    revision,
                    deleted: false,
                })
                .into_iter()
                .collect();
            let state = held.map(|(version, revision, deleted)| {
                let mut state = RecordState::after(&put(RecordVersion::NONE, 1, deleted), 1, 1);
                state.version = version;
                (state, revision)
            });
            let current = state.as_ref().map(|(state, revision)| (state, *revision));
            let written = check_record_put(&write, &conditions, current, 1, true, None);
            assert_eq!(written.is_ok(), holds, "record.put, case {i}: {written:?}");
            for readable in [true, false] {
                let at = AtKey {
                    key: write.key,
                    held,
                    readable,
                };
                let mut guarded = conditions.clone();
                guarded.push(Condition::RecordVersion {
                    key: write.key,
                    version: named,
                });
                let checked = crate::ops::check_conditions(&guarded, &at);
                assert_eq!(
                    checked.is_ok(),
                    holds,
                    "record_version, case {i}: {checked:?}"
                );
            }
        }
    }

    #[test]
    fn test_record_put_stale_epoch_and_fixed_policy() {
        let create = put(RecordVersion::NONE, 1, false);
        let refused = check_record_put(&create, &[], None, 2, true, None).unwrap_err();
        assert_eq!(refused.code, ErrorCode::StaleEpoch);
        assert_eq!(refused.current, Some(json!({"data_epoch": 2})));
        let held = RecordState::after(&create, 1, 6);
        let mut other = put(RecordVersion::new(1, 6), 1, false);
        other.policy = Policy::new("scope-a", &["scope-a", "scope-b"]);
        assert_eq!(
            check_record_put(&other, &[], Some((&held, applied(1, 6))), 1, true, None)
                .unwrap_err()
                .status(),
            400
        );
        let mut moved = put(RecordVersion::new(1, 6), 1, false);
        moved.collection = [0; 32];
        assert_eq!(
            check_record_put(&moved, &[], Some((&held, applied(1, 6))), 1, true, None)
                .unwrap_err()
                .status(),
            400
        );
    }

    /// `put` with its policy `policy`, its key derived again for it.
    fn put_at(policy: &Policy, expected: RecordVersion, epoch: u64, delete: bool) -> RecordPut {
        let mut put = put(expected, epoch, delete);
        let id = IdentityKey::from_secret([1; 32]);
        let blinded = NamingKey::from_root(&id.switch_root()).blind(b"natural");
        put.key = record_key_from_blinded("sample.collection", &blinded, &policy.hash().unwrap());
        put.policy = policy.clone();
        put
    }

    #[test]
    fn test_record_put_later_write_repeats_the_permanent_member() {
        // A permanent record: a later write repeats its policy whole, the member included
        // (Switch spec 10.3.1). One that drops it, or names another generation, could
        // then delete the record as an ordinary one.
        let ordinary = Policy::new("scope-a", &["scope-a"]);
        for named in [None, Some(2)] {
            let policy = ordinary.clone().permanent(named);
            let held = RecordState::after(&put_at(&policy, RecordVersion::NONE, 1, false), 1, 6);
            let at = RecordVersion::new(1, 6);
            let mut same = put_at(&policy, at, 1, false);
            assert!(
                check_record_put(&same, &[], Some((&held, applied(1, 6))), 1, true, None).is_ok()
            );
            for other in [
                ordinary.clone(),
                ordinary.clone().permanent(Some(3)),
                ordinary
                    .clone()
                    .permanent(if named.is_some() { None } else { Some(2) }),
            ] {
                same.policy = other.clone();
                let refused =
                    check_record_put(&same, &[], Some((&held, applied(1, 6))), 1, true, None)
                        .unwrap_err();
                assert_eq!(refused.status(), 400, "{policy:?} then {other:?}");
                assert_eq!(refused.code, ErrorCode::BadRequest);
            }
            // A delete without the member: refused here too, whatever its own shape allows.
            let mut dropped = put_at(&policy, at, 1, true);
            dropped.policy = ordinary.clone();
            assert_eq!(
                check_record_put(&dropped, &[], Some((&held, applied(1, 6))), 1, true, None)
                    .unwrap_err()
                    .status(),
                400
            );
        }
    }

    #[test]
    fn test_record_put_create_over_a_held_record_repeats_its_policy() {
        // After a provider loss, an upload that isn't a create fills a key the service
        // lacks with the policy it names: nothing ties that key to a policy. An ordinary
        // policy at a permanent key, deleted, isn't created again at `{0, 0}` with the
        // permanent policy: a create over a held record repeats its policy, as a later
        // write does, and so the key never reads as never written (Switch spec 10.3.1).
        let permanent = Policy::new("scope-a", &["scope-a"]).permanent(None);
        let create = put_at(&permanent, RecordVersion::NONE, 1, false);
        let mut uploaded = put_at(&permanent, RecordVersion::new(1, 3), 1, false);
        uploaded.policy = Policy::new("scope-a", &["scope-a"]);
        let filled = RecordState::after(&uploaded, 1, 4);
        assert_eq!(filled.key, create.key);
        let mut delete = put_at(&permanent, RecordVersion::new(1, 4), 1, true);
        delete.policy = filled.policy.clone();
        assert!(
            check_record_put(&delete, &[], Some((&filled, applied(1, 4))), 1, true, None).is_ok()
        );
        let deleted = RecordState::after(&delete, 2, 9);
        assert!(deleted.deleted);
        let refused =
            check_record_put(&create, &[], Some((&deleted, applied(2, 9))), 1, true, None)
                .unwrap_err();
        assert_eq!(refused.status(), 400);
        // Over the live record too, before the compare-and-swap.
        let refused = check_record_put(&create, &[], Some((&filled, applied(1, 4))), 1, true, None)
            .unwrap_err();
        assert_eq!(refused.status(), 400);
        // A create of the held policy passes the policy check and meets the compare-and-swap:
        // `{0, 0}` doesn't hold over a kept delete, only once the service forgets the key.
        let mut ordinary_create = create.clone();
        ordinary_create.policy = filled.policy.clone();
        let refused = check_record_put(
            &ordinary_create,
            &[],
            Some((&deleted, applied(2, 9))),
            1,
            true,
            None,
        )
        .unwrap_err();
        assert_eq!(refused.status(), 409);
        assert!(check_record_put(&ordinary_create, &[], None, 1, true, None).is_ok());
    }

    /// A record write, chained at (`generation`, `seq`), and the proof of it signed by
    /// `service`.
    fn written(
        generation: u64,
        seq: u64,
        service: &ed25519_dalek::SigningKey,
    ) -> (SignedOp, crate::sig::SignedDoc) {
        written_at(generation, generation, seq, service)
    }

    /// A record write of `op_generation`, chained at (`generation`, `seq`), and the proof of
    /// it signed by `service`.
    fn written_at(
        op_generation: u64,
        generation: u64,
        seq: u64,
        service: &ed25519_dalek::SigningKey,
    ) -> (SignedOp, crate::sig::SignedDoc) {
        use crate::chain::{ChainTip, ProofBody, ProofState, ZERO_HASH};
        use crate::keys::AppKeys;
        use crate::ops::{BatchRef, OpBody, OpKind};
        let id = IdentityKey::from_secret([1; 32]);
        let app = AppKeys::from_secrets([2; 32], [3; 32]);
        let body = OpBody {
            identity: id.public(),
            app_id: Some(app.app_id_bytes()),
            generation: op_generation,
            batch: BatchRef {
                id: [7; 16],
                count: 1,
            },
            conditions: Vec::new(),
            kind: OpKind::RecordPut(put(RecordVersion::NONE, 1, false)),
        };
        let op = SignedOp::sign(&app, body).unwrap();
        let tip = ChainTip {
            generation,
            seq: seq - 1,
            chain_hash: ZERO_HASH,
        };
        let (stub, _) = tip
            .append(
                seq,
                1_767_225_600_000,
                ItemType::Op,
                op.item_hash().unwrap(),
                Some(op.body().batch),
            )
            .unwrap();
        let OpKind::RecordPut(p) = &op.body().kind else {
            unreachable!()
        };
        let state = ProofState::Record {
            version: RecordVersion::new(generation, seq),
            deleted: false,
            revision: ApplicationRef {
                generation,
                seq,
                item_hash: op.item_hash().unwrap(),
            },
        };
        let proof = TransitionProof::sign(
            service,
            &id.public(),
            ProofBody::new(stub, b64(&p.key), &state),
        )
        .unwrap();
        (op, proof.signed().clone())
    }

    fn identity_doc(
        generation: u64,
        current: [u8; 32],
        earlier: &[(u64, [u8; 32])],
    ) -> IdentityDoc {
        use crate::records::{IdentityBody, IdentityPolicy, Inbox, ServiceKeyEntry};
        let id = IdentityKey::from_secret([1; 32]);
        let mut body = IdentityBody::first(
            id.public(),
            [4; 16],
            Inbox::new("https://inbox.example", current),
            IdentityPolicy::default(),
        );
        body.generation = generation;
        body.service_keys = earlier
            .iter()
            .map(|(generation, key)| ServiceKeyEntry {
                generation: *generation,
                key: *key,
            })
            .collect();
        IdentityDoc::sign(&id, body).unwrap()
    }

    #[test]
    fn test_date_write_by_the_current_and_an_earlier_service_key() {
        let old = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let new = ed25519_dalek::SigningKey::from_bytes(&[6; 32]);
        let (old_key, new_key) = (
            old.verifying_key().to_bytes(),
            new.verifying_key().to_bytes(),
        );
        // The current key's proof dates the write and gives its version.
        let (op, proof) = written(2, 6, &new);
        let doc = identity_doc(2, new_key, &[(1, old_key)]);
        let dated = date_write(&proof, &op, &doc).unwrap();
        assert_eq!(dated.version, Some(RecordVersion::new(2, 6)));
        assert_eq!(dated.time, 1_767_225_600_000);
        // An earlier generation's proof dates it without a version, with the key listed.
        let (op, proof) = written(1, 6, &old);
        let dated = date_write(&proof, &op, &doc).unwrap();
        assert_eq!(dated.version, None);
        // A generation service_keys doesn't name dates nothing.
        assert!(date_write(&proof, &op, &identity_doc(2, new_key, &[])).is_err());
        // Nor does a lost generation's proof that the current key signed, as after a provider
        // loss at the same service: it gives no version.
        let (op, proof) = written(1, 6, &new);
        assert!(date_write(&proof, &op, &identity_doc(2, new_key, &[])).is_err());
        // A proof of another operation dates nothing.
        let (other, _) = written(2, 7, &new);
        let (_, proof) = written(2, 6, &new);
        assert!(date_write(&proof, &other, &doc).is_err());
        // A proof of another generation than the operation's dates nothing, whichever key
        // signed it: the current one, or the one listed for the stub's generation.
        let (op, proof) = written_at(1, 2, 6, &new);
        let error = date_write(&proof, &op, &doc).unwrap_err();
        assert!(
            error.to_string().contains("operation's generation"),
            "{error}"
        );
        let (op, proof) = written_at(2, 1, 6, &old);
        let error = date_write(&proof, &op, &doc).unwrap_err();
        assert!(
            error.to_string().contains("operation's generation"),
            "{error}"
        );
    }

    fn changed_record_proofs(
        proof: &crate::sig::SignedDoc,
        service: &ed25519_dalek::SigningKey,
    ) -> Vec<crate::sig::SignedDoc> {
        let proof = TransitionProof::peek(proof).unwrap();
        (0..7)
            .map(|case| {
                let mut body = proof.body().clone();
                match case {
                    0 => {
                        body.state.as_object_mut().unwrap().remove("revision");
                    }
                    1 => body.state["revision"]["generation"] = serde_json::json!(9),
                    2 => body.state["revision"]["seq"] = serde_json::json!(9),
                    3 => body.state["revision"]["item_hash"] = serde_json::json!(b64(&[9; 32])),
                    4 => body.state["revision"]["extra"] = Value::Null,
                    5 => body.state["revision"]["seq"] = serde_json::json!(0),
                    _ => body.state["deleted"] = Value::Bool(true),
                }
                TransitionProof::sign(service, &IdentityKey::from_secret([1; 32]).public(), body)
                    .unwrap()
                    .signed()
                    .clone()
            })
            .collect()
    }

    #[test]
    fn test_record_current_binding_checks_the_applied_reference() {
        let service = ed25519_dalek::SigningKey::from_bytes(&[6; 32]);
        let (op, proof) = written(2, 6, &service);
        let key = service.verifying_key().to_bytes();
        let id = IdentityKey::from_secret([1; 32]).public();
        crate::chain::bind_answer(
            std::slice::from_ref(&op),
            std::slice::from_ref(&proof),
            &key,
            &id,
        )
        .unwrap();
        for changed in changed_record_proofs(&proof, &service) {
            // Each changed body has a genuine service signature; binding is the refusal.
            TransitionProof::verify(&changed, &key, &id).unwrap();
            assert!(matches!(
                crate::chain::bind_answer(std::slice::from_ref(&op), &[changed], &key, &id),
                Err(crate::chain::ChainError::Proof(_))
            ));
        }
    }

    #[test]
    fn test_record_current_dating_checks_the_applied_reference() {
        let service = ed25519_dalek::SigningKey::from_bytes(&[6; 32]);
        let key = service.verifying_key().to_bytes();
        let doc = identity_doc(2, key, &[]);
        let (op, proof) = written(2, 6, &service);
        assert_eq!(
            date_write(&proof, &op, &doc).unwrap().version,
            Some(RecordVersion::new(2, 6))
        );
        for changed in changed_record_proofs(&proof, &service) {
            assert!(date_write(&changed, &op, &doc).is_err());
        }
        let old_doc = identity_doc(3, [8; 32], &[(2, key)]);
        assert_eq!(date_write(&proof, &op, &old_doc).unwrap().version, None);
        for changed in changed_record_proofs(&proof, &service) {
            assert!(date_write(&changed, &op, &old_doc).is_err());
        }
    }

    #[test]
    fn test_record_current_proof_producer_checks_application_position() {
        use crate::ops::{StateAfter, proof_state};
        let service = ed25519_dalek::SigningKey::from_bytes(&[6; 32]);
        let (op, _) = written(2, 6, &service);
        for version in [
            RecordVersion::new(1, 6),
            RecordVersion::new(2, 0),
            RecordVersion::new(2, crate::json::MAX_INT + 1),
        ] {
            assert!(proof_state(&op, &StateAfter::Record(version)).is_err());
        }
        let state = proof_state(&op, &StateAfter::Record(RecordVersion::new(2, 6))).unwrap();
        assert_eq!(
            state.to_value()["revision"]["item_hash"],
            b64(&op.item_hash().unwrap())
        );
    }

    #[test]
    fn test_write_version_ordering() {
        let v = |g, s| RecordVersion::new(g, s);
        let auth = |version, expected| WriteVersion {
            version,
            authenticated: true,
            expected_version: expected,
        };
        let unauth = |version, expected| WriteVersion {
            version,
            authenticated: false,
            expected_version: expected,
        };
        assert!(auth(v(1, 8), v(1, 6)).replaces(&auth(v(1, 6), v(0, 0))));
        assert!(!auth(v(1, 6), v(0, 0)).replaces(&auth(v(1, 8), v(1, 6))));
        // An unauthenticated version must build on the held one or later.
        assert!(unauth(v(1, 99), v(1, 8)).replaces(&auth(v(1, 8), v(1, 6))));
        assert!(!unauth(v(1, 99), v(1, 6)).replaces(&auth(v(1, 8), v(1, 6))));
        // A held unauthenticated write is just after its own expected_version.
        assert!(auth(v(1, 7), v(1, 6)).replaces(&unauth(v(1, 99), v(1, 6))));
        assert!(!auth(v(1, 6), v(0, 0)).replaces(&unauth(v(1, 99), v(1, 6))));
        assert!(unauth(v(2, 1), v(1, 7)).replaces(&unauth(v(1, 99), v(1, 6))));
        assert!(!unauth(v(2, 1), v(1, 6)).replaces(&unauth(v(1, 99), v(1, 6))));
        assert!(auth(v(1, 8), v(1, 6)).plausible(1));
        assert!(!auth(v(1, 8), v(1, 6)).plausible(2));
        assert!(!auth(v(1, 6), v(1, 6)).plausible(1));
    }
}
