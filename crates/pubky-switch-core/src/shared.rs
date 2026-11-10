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
use crate::enc::b64;
use crate::error::{Error, Result};
use crate::http::ErrorCode;
use crate::ident::Policy;
use crate::ops::{RecordPut, RecordVersion, Refusal, SignedOp};
use crate::records::IdentityDoc;

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

/// The service's rules for a `record.put` against the record it holds, after the writer's
/// permission and the operation's shape (Switch wire 6.2, 6.4 step 9, Switch spec 10.3):
///
/// - the sealed value's data epoch is the current one (`data_epoch`), else `409 stale_epoch`
///   with `current.data_epoch`;
/// - a later write repeats the record's collection and policy, else `400`;
/// - `expected_version` is the record's current version, and `{0, 0}` matches a record that
///   is absent, forgotten (`current` `None`) or deleted; else `409 conflict`, whose `current`
///   carries `record` and the current write's `record_view` to a writer with the read scope
///   (`may_read`), and `{}` otherwise.
///
/// # Errors
///
/// As above.
pub fn check_record_put(
    put: &RecordPut,
    current: Option<&RecordState>,
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
    if let Some(held) = current
        && !put.expected_version.is_none()
        && (held.collection != put.collection || held.policy != put.policy)
    {
        return Err(Refusal::bad_request(
            "Switch spec 10.3: a later write repeats the record's collection and policy",
        ));
    }
    let matches = match current {
        None => put.expected_version.is_none(),
        Some(held) => {
            (put.expected_version.is_none() && held.deleted)
                || (!put.expected_version.is_none() && put.expected_version == held.version)
        }
    };
    if matches {
        return Ok(());
    }
    let current = match (current, may_read) {
        (Some(held), true) => json!({
            "record": {
                "key": b64(&held.key),
                "generation": held.version.generation,
                "version": held.version.version,
            },
            "record_view": record_view.cloned().unwrap_or(Value::Null),
        }),
        _ => json!({}),
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
/// A proof that verifies with the current service key must have a stub whose `item_hash` is
/// the operation's, an `object` that is the record key, and a `state` whose generation and
/// version are the stub's; it dates the write and gives its version. A proof of an earlier
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
    if let Ok(checked) = TransitionProof::verify(proof, &identity.inbox().service_key, &id) {
        let env = checked.envelope();
        if env.item_type != ItemType::Op || env.item_hash != item {
            return bad("the proof's stub isn't the operation's");
        }
        if !of_its_generation(env) {
            return bad("the proof's stub isn't of the operation's generation");
        }
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
            id_inputs: expected.is_none().then(|| IdInputs {
                collection: "sample.collection".into(),
                blinded_key: blinded,
            }),
        }
    }

    #[test]
    fn test_record_put_compare_and_swap() {
        let create = put(RecordVersion::NONE, 1, false);
        assert!(check_record_put(&create, None, 1, true, None).is_ok());
        let held = RecordState::after(&create, 1, 6);
        assert_eq!(held.version, RecordVersion::new(1, 6));
        // A create at a live record conflicts; with the read scope, current shows it.
        let refused =
            check_record_put(&create, Some(&held), 1, true, Some(&json!({"v": 1}))).unwrap_err();
        assert_eq!(refused.status(), 409);
        let current = refused.current.unwrap();
        assert_eq!(current["record"]["version"], 6);
        assert_eq!(current["record_view"], json!({"v": 1}));
        let blind = check_record_put(&create, Some(&held), 1, false, None).unwrap_err();
        assert_eq!(blind.current, Some(json!({})));
        let update = put(RecordVersion::new(1, 6), 1, false);
        assert!(check_record_put(&update, Some(&held), 1, true, None).is_ok());
        let stale = put(RecordVersion::new(1, 5), 1, false);
        assert!(check_record_put(&stale, Some(&held), 1, true, None).is_err());
        assert!(
            check_record_put(&update, None, 1, true, None).is_err(),
            "the key was forgotten"
        );
    }

    #[test]
    fn test_record_put_deleted_record_is_created_again_or_continued() {
        let delete = put(RecordVersion::new(1, 6), 1, true);
        let deleted = RecordState::after(&delete, 1, 9);
        assert!(deleted.deleted);
        assert!(
            check_record_put(
                &put(RecordVersion::NONE, 1, false),
                Some(&deleted),
                1,
                true,
                None
            )
            .is_ok()
        );
        assert!(
            check_record_put(
                &put(RecordVersion::new(1, 9), 1, false),
                Some(&deleted),
                1,
                true,
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn test_record_put_stale_epoch_and_fixed_policy() {
        let create = put(RecordVersion::NONE, 1, false);
        let refused = check_record_put(&create, None, 2, true, None).unwrap_err();
        assert_eq!(refused.code, ErrorCode::StaleEpoch);
        assert_eq!(refused.current, Some(json!({"data_epoch": 2})));
        let held = RecordState::after(&create, 1, 6);
        let mut other = put(RecordVersion::new(1, 6), 1, false);
        other.policy = Policy::new("scope-a", &["scope-a", "scope-b"]);
        assert_eq!(
            check_record_put(&other, Some(&held), 1, true, None)
                .unwrap_err()
                .status(),
            400
        );
        let mut moved = put(RecordVersion::new(1, 6), 1, false);
        moved.collection = [0; 32];
        assert_eq!(
            check_record_put(&moved, Some(&held), 1, true, None)
                .unwrap_err()
                .status(),
            400
        );
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
