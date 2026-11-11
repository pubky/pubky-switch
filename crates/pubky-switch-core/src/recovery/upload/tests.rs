//! The upload's body and item checks, on an identity whose generation 3 was lost: one app
//! writing a record built on (3, 10) and an attempt, the lost service's proofs of both.

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use super::*;
use crate::chain::{ChainTip, ProofBody, ProofState};
use crate::claims::{
    Basis, ClaimFields, ClaimLimits, ClaimTally, ClaimType, EntryContext, apply_entry,
};
use crate::enc::{b64, pubky_id};
use crate::ident::Policy;
use crate::keys::{AppKeys, IdentityKey};
use crate::ops::{BatchRef, OpBody};
use crate::records::{AppCertBody, IdentityBody, IdentityPolicy, Inbox};
use crate::recovery::merge_upload_claim;
use crate::sealed::SealedValue;

const NOW: u64 = 1_800_000_000_000;
const SCOPE: &str = "scope-a";
const LOST: u64 = 3;
const CLAIM_KEY: [u8; 32] = [20; 32];
const ATTEMPT: [u8; 16] = [21; 16];

fn identity() -> IdentityKey {
    IdentityKey::from_secret([1; 32])
}

fn app() -> AppKeys {
    AppKeys::from_secrets([2; 32], [3; 32])
}

fn lost_key() -> SigningKey {
    SigningKey::from_bytes(&[5; 32])
}

fn cert_with(scopes: &[&str], permissions: &[Permission]) -> AppCert {
    let keys = app();
    let body = AppCertBody::new(
        identity().public(),
        keys.signing_public(),
        keys.bundle_public(),
        scopes.iter().map(|s| (*s).to_owned()).collect(),
        permissions,
        NOW - 1_000,
        NOW + 1_000_000,
    );
    AppCert::issue(&identity(), body).unwrap()
}

fn cert() -> AppCert {
    cert_with(&[SCOPE], &[Permission::ClaimsWrite])
}

/// An `identity.json` of `generation` naming `key` as its service key.
fn doc(generation: u64, key: &SigningKey) -> SignedDoc {
    let mut body = IdentityBody::first(
        identity().public(),
        [9; 16],
        Inbox::new("https://lost.example", key.verifying_key().to_bytes()),
        IdentityPolicy::default(),
    );
    body.generation = generation;
    IdentityDoc::sign(&identity(), body)
        .unwrap()
        .signed()
        .clone()
}

fn op_at(generation: u64, kind: OpKind) -> SignedOp {
    SignedOp::sign(
        &app(),
        OpBody {
            identity: identity().public(),
            app_id: Some(app().app_id_bytes()),
            generation,
            batch: BatchRef {
                id: [4; 16],
                count: 1,
            },
            conditions: Vec::new(),
            kind,
        },
    )
    .unwrap()
}

fn put(built_on: RecordVersion) -> RecordPut {
    let id = identity();
    let key = [30; 32];
    RecordPut {
        key,
        collection: [31; 32],
        policy: Policy::new(SCOPE, &[SCOPE]),
        expected_version: built_on,
        value_sealed: SealedValue::seal(
            &id.scope_key(1, SCOPE),
            &id.public(),
            1,
            SCOPE,
            &key,
            b"{}",
        )
        .unwrap(),
        id_inputs: None,
    }
}

fn record_op(generation: u64) -> SignedOp {
    op_at(
        generation,
        OpKind::RecordPut(put(RecordVersion::new(3, 10))),
    )
}

fn attempt_fields() -> ClaimFields {
    ClaimFields {
        claim_key: CLAIM_KEY.to_vec(),
        kind: ClaimType::Attempt,
        expected_step: 0,
        attempt_id: ATTEMPT.to_vec(),
        orphan_after: Some(86_400),
        deadline: None,
        basis: None,
        evidence_ref: None,
    }
}

fn done_fields() -> ClaimFields {
    ClaimFields {
        kind: ClaimType::Done,
        expected_step: 1,
        orphan_after: None,
        basis: Some(Basis::Owner),
        ..attempt_fields()
    }
}

/// The lost service's proof of `op`, applied at `seq` and `time`, showing `state`.
fn proof_of(op: &SignedOp, seq: u64, time: u64, object: String, state: &ProofState) -> SignedDoc {
    let tip = ChainTip {
        generation: op.body().generation,
        seq: seq - 1,
        chain_hash: [8; 32],
    };
    let (stub, _) = tip
        .append(
            seq,
            time,
            ItemType::Op,
            op.item_hash().unwrap(),
            Some(op.body().batch),
        )
        .unwrap();
    TransitionProof::sign(
        &lost_key(),
        &identity().public(),
        ProofBody::new(stub, object, state),
    )
    .unwrap()
    .signed()
    .clone()
}

fn record_proof(op: &SignedOp, version: RecordVersion, time: u64) -> SignedDoc {
    let state = ProofState::Record {
        version,
        deleted: false,
    };
    proof_of(op, version.version, time, b64(&[30; 32]), &state)
}

/// The claim after `entries`, as the lost service would show it.
fn view_after(entries: &[ClaimFields]) -> ClaimView {
    let anyone = |_: &[u8; 16]| true;
    let cx = EntryContext {
        writer: app().app_id_bytes(),
        now: NOW,
        can_read: true,
        is_current: &anyone,
        limits: ClaimLimits::default(),
        tally: ClaimTally::default(),
    };
    let mut claim = None;
    for fields in entries {
        claim = Some(apply_entry(claim.as_ref(), &fields.check().unwrap(), &cx).unwrap());
    }
    claim.unwrap().view(&CLAIM_KEY, NOW, &anyone)
}

fn claim_proof(op: &SignedOp, view: &ClaimView, seq: u64) -> SignedDoc {
    proof_of(
        op,
        seq,
        NOW - 5_000,
        b64(&CLAIM_KEY),
        &ProofState::Claim(view.to_value()),
    )
}

fn uploaded(op: &SignedOp, proof: Option<SignedDoc>) -> UploadedOp {
    UploadedOp {
        op: op.signed().clone(),
        cert: cert().signed().clone(),
        proof,
    }
}

fn body_with(records: Vec<UploadedOp>, claims: Vec<UploadedOp>) -> UploadBody {
    UploadBody {
        lost_identity: Some(doc(LOST, &lost_key())),
        records,
        claims,
        ..UploadBody::default()
    }
}

fn check(body: &UploadBody, removed: &[RemovedApp]) -> CheckedUpload {
    let id = identity().public();
    check_upload(
        body,
        &UploadContext {
            identity: &id,
            recovery_from: LOST,
            removed,
        },
    )
}

fn version_of(checked: &CheckedUpload) -> UploadVersion {
    checked.records[0].uploaded.version
}

// The body

fn parse(value: Value) -> Result<UploadBody, Refusal> {
    UploadBody::parse(value.to_string().as_bytes())
}

#[test]
fn test_upload_body_reads_each_member_and_an_empty_one() {
    let op = record_op(LOST);
    let head = SignedHead::sign(
        &lost_key(),
        &identity().public(),
        &ChainTip {
            generation: LOST,
            seq: 9,
            chain_hash: [8; 32],
        },
    );
    let pubky = pubky_id(&[40; 32]);
    let body = parse(json!({
        "lost_identity": doc(LOST, &lost_key()),
        "records": [{ "op": op.signed(), "cert": cert().signed() }],
        "heads": [head.to_value()],
        "proofs": [record_proof(&op, RecordVersion::new(3, 50), NOW)],
        "lists": { "deny": [pubky] },
    }))
    .unwrap();
    assert_eq!(body.records.len(), 1);
    assert!(body.records[0].proof.is_none());
    assert!(body.claims.is_empty(), "a missing member is empty");
    assert_eq!(body.heads, vec![head]);
    let lists = body.lists.unwrap();
    assert_eq!(lists.contacts, None, "contacts left out");
    assert_eq!(lists.deny, Some(vec![[40; 32]]));
    assert_eq!(parse(json!({})).unwrap(), UploadBody::default());
}

#[test]
fn test_upload_body_that_doesnt_read_is_400() {
    for body in [
        json!([]),
        json!({ "records": {} }),
        json!({ "records": [{ "op": "x" }] }),
        json!({ "records": [{ "cert": { "body": "a", "sig": "b" } }] }),
        json!({ "heads": [{ "seq": 1 }] }),
        json!({ "lists": { "contacts": ["not a pubky"] } }),
        json!({ "lists": { "allow": [] } }),
        json!({ "checkpoint": 1 }),
    ] {
        let refusal = parse(body.clone()).unwrap_err();
        assert_eq!(refusal.status(), 400, "{body}");
    }
}

#[test]
fn test_upload_lists_need_the_callers_permission() {
    let lists = |contacts: Option<Vec<[u8; 32]>>, deny: Option<Vec<[u8; 32]>>| UploadBody {
        lists: Some(UploadLists { contacts, deny }),
        ..UploadBody::default()
    };
    let none = cert_with(&[SCOPE], &[]);
    let read = cert_with(&[SCOPE], &[Permission::ListsRead]);
    let manage = cert_with(&[SCOPE], &[Permission::ListsManage]);
    let missing = |body: &UploadBody, cert: &AppCert| {
        body.check_permissions(cert).unwrap_err().code == ErrorCode::PermissionMissing
    };
    // Contacts, an empty array included, need lists.manage.
    let contacts = lists(Some(Vec::new()), None);
    assert!(missing(&contacts, &read));
    assert!(contacts.check_permissions(&manage).is_ok());
    assert!(contacts.ends_staged_admission(&manage));
    // Deny entries need lists.read or lists.manage, and end nothing.
    let deny = lists(None, Some(vec![[40; 32]]));
    assert!(missing(&deny, &none));
    assert!(deny.check_permissions(&read).is_ok());
    assert!(deny.check_permissions(&manage).is_ok());
    assert!(!deny.ends_staged_admission(&manage));
    assert!(UploadBody::default().check_permissions(&none).is_ok());
}

// Records

#[test]
fn test_upload_record_proof_gives_its_version() {
    let op = record_op(LOST);
    let proof = record_proof(&op, RecordVersion::new(3, 50), NOW);
    let checked = check(
        &body_with(vec![uploaded(&op, Some(proof.clone()))], vec![]),
        &[],
    );
    assert_eq!(
        version_of(&checked),
        UploadVersion::proved(RecordVersion::new(3, 50))
    );
    assert_eq!(
        checked.records[0].uploaded.op_hash,
        op.signed().doc_hash().unwrap()
    );
    // A `proofs` entry whose stub is the operation's gives it as well.
    let mut body = body_with(vec![uploaded(&op, None)], vec![]);
    body.proofs = vec![proof];
    let checked = check(&body, &[]);
    assert_eq!(
        version_of(&checked),
        UploadVersion::proved(RecordVersion::new(3, 50))
    );
    assert_eq!(checked.proofs, 1);
}

#[test]
fn test_upload_record_without_proof_gets_its_bound() {
    let op = record_op(LOST);
    let checked = check(&body_with(vec![uploaded(&op, None)], vec![]), &[]);
    assert_eq!(
        version_of(&checked),
        UploadVersion::bound(LOST, RecordVersion::new(3, 10)).unwrap()
    );
    assert_eq!((checked.unverified, checked.distrusted), (0, 0));
}

#[test]
fn test_upload_out_of_range_proof_counts_as_none() {
    // A proof gives a version only in the operation's own generation and above the version
    // it built on (Switch wire 6.2 step 6); any other is as no proof, and the bound stands.
    let op = record_op(LOST);
    let bound = UploadVersion::bound(LOST, RecordVersion::new(3, 10)).unwrap();
    for version in [
        RecordVersion::new(3, 10),
        RecordVersion::new(3, 4),
        RecordVersion::new(2, 50),
    ] {
        let state = ProofState::Record {
            version,
            deleted: false,
        };
        let proof = proof_of(&op, 60, NOW, b64(&[30; 32]), &state);
        let checked = check(&body_with(vec![uploaded(&op, Some(proof))], vec![]), &[]);
        assert_eq!(version_of(&checked), bound, "{version:?}");
    }
}

#[test]
fn test_upload_proof_of_another_key_or_operation_is_none() {
    let op = record_op(LOST);
    let other = op_at(LOST, OpKind::RecordPut(put(RecordVersion::new(3, 11))));
    let bound = UploadVersion::bound(LOST, RecordVersion::new(3, 10)).unwrap();
    let foreign = {
        let mut doc = record_proof(&op, RecordVersion::new(3, 50), NOW);
        doc.sig = record_proof(&other, RecordVersion::new(3, 50), NOW).sig;
        doc
    };
    for proof in [
        record_proof(&other, RecordVersion::new(3, 50), NOW),
        foreign,
    ] {
        let checked = check(&body_with(vec![uploaded(&op, Some(proof))], vec![]), &[]);
        assert_eq!(version_of(&checked), bound);
    }
}

#[test]
fn test_upload_without_lost_identity_checks_no_proof() {
    let op = record_op(LOST);
    let proof = record_proof(&op, RecordVersion::new(3, 50), NOW);
    let head = SignedHead::sign(
        &lost_key(),
        &identity().public(),
        &ChainTip {
            generation: LOST,
            seq: 9,
            chain_hash: [8; 32],
        },
    );
    let bound = UploadVersion::bound(LOST, RecordVersion::new(3, 10)).unwrap();
    // Missing, of another generation, or signed by another identity.
    let stranger = {
        let mut doc = doc(LOST, &lost_key());
        doc.sig = b64(&[0; 64]);
        doc
    };
    for lost in [None, Some(doc(2, &lost_key())), Some(stranger)] {
        let body = UploadBody {
            lost_identity: lost,
            records: vec![uploaded(&op, Some(proof.clone()))],
            heads: vec![head],
            proofs: vec![proof.clone()],
            ..UploadBody::default()
        };
        let checked = check(&body, &[]);
        assert_eq!(version_of(&checked), bound);
        assert_eq!(
            (checked.heads, checked.proofs, checked.unverified),
            (0, 0, 2)
        );
    }
    let body = UploadBody {
        heads: vec![head],
        ..body_with(vec![], vec![])
    };
    assert_eq!(check(&body, &[]).heads, 1);
}

#[test]
fn test_upload_operation_that_doesnt_verify_is_unverified() {
    let op = record_op(LOST);
    let mut forged = uploaded(&op, None);
    forged.op.sig = b64(&[0; 64]);
    let mut no_scope = uploaded(&op, None);
    no_scope.cert = cert_with(&["scope-b"], &[]).signed().clone();
    let mut bad_cert = uploaded(&op, None);
    bad_cert.cert.sig = b64(&[0; 64]);
    let records = vec![
        forged,
        no_scope,
        bad_cert,
        // Of N's generation: it belongs in `POST /ops`.
        uploaded(&record_op(LOST + 1), None),
        // A claim entry among the records.
        uploaded(&op_at(LOST, OpKind::Claim(attempt_fields())), None),
        // Built on a later generation than its own.
        uploaded(
            &op_at(LOST, OpKind::RecordPut(put(RecordVersion::new(4, 1)))),
            None,
        ),
    ];
    let checked = check(&body_with(records, vec![uploaded(&op, None)]), &[]);
    assert!(checked.records.is_empty() && checked.claims.is_empty());
    assert_eq!(checked.unverified, 7);
    // An earlier generation's operation counts, with its bound.
    let earlier = op_at(2, OpKind::RecordPut(put(RecordVersion::new(2, 10))));
    let checked = check(&body_with(vec![uploaded(&earlier, None)], vec![]), &[]);
    assert_eq!(version_of(&checked).version, RecordVersion::new(2, 11));
}

#[test]
fn test_upload_removed_app_counts_only_dated_before_distrust() {
    let op = record_op(LOST);
    let removed = [RemovedApp {
        app_id: app().app_id_bytes(),
        distrust_from: NOW,
    }];
    let with_proof = |time| {
        let proof = record_proof(&op, RecordVersion::new(3, 50), time);
        check(
            &body_with(vec![uploaded(&op, Some(proof))], vec![]),
            &removed,
        )
    };
    assert_eq!(with_proof(NOW).records.len(), 1, "at distrust_from itself");
    assert_eq!(with_proof(NOW + 1).distrusted, 1);
    let checked = check(&body_with(vec![uploaded(&op, None)], vec![]), &removed);
    assert_eq!((checked.records.len(), checked.distrusted), (0, 1));
    // A claim entry, likewise.
    let attempt = op_at(LOST, OpKind::Claim(attempt_fields()));
    let checked = check(&body_with(vec![], vec![uploaded(&attempt, None)]), &removed);
    assert_eq!((checked.claims.len(), checked.distrusted), (0, 1));
}

// Claims

#[test]
fn test_upload_claim_entries_group_by_key_with_their_proofs() {
    let attempt = op_at(LOST, OpKind::Claim(attempt_fields()));
    let done = op_at(LOST, OpKind::Claim(done_fields()));
    let view = view_after(&[attempt_fields()]);
    let claims = vec![
        uploaded(&done, None),
        uploaded(&attempt, Some(claim_proof(&attempt, &view, 7))),
    ];
    let checked = check(&body_with(vec![], claims), &[]);
    let entries = &checked.claims[&CLAIM_KEY];
    assert_eq!(entries.len(), 2);
    assert!(entries[0].proof.is_none());
    let proof = entries[1].proof.as_ref().unwrap();
    assert_eq!((proof.at, &proof.view), (NOW - 5_000, &view));
    assert_eq!(entries[1].writer, app().app_id_bytes());
}

#[test]
fn test_upload_settled_proof_rebuilds_a_tombstone_only_for_nothing_held() {
    let done = op_at(LOST, OpKind::Claim(done_fields()));
    let view = view_after(&[attempt_fields(), done_fields()]);
    assert_eq!(view.status, ClaimStatus::Settled);
    let mut body = body_with(vec![], vec![]);
    body.proofs = vec![claim_proof(&done, &view, 8)];
    let checked = check(&body, &[]);
    let settled = checked.settled.get(&CLAIM_KEY).unwrap();
    assert_eq!(settled.1, NOW - 5_000);
    let merge = merge_upload_claim(None, Some(settled), &[], NOW, 64);
    let tombstone = merge.claim.unwrap();
    assert!(merge.changed && tombstone.tombstone && tombstone.settled);
    assert!(tombstone.attempts.iter().all(|a| a.from_upload));
    // A claim the service holds isn't rebuilt from the proof.
    let held = super::super::tombstone_from_proof(&view, NOW - 9_000).unwrap();
    let merge = merge_upload_claim(Some(&held), Some(settled), &[], NOW, 64);
    assert!(!merge.changed);
    // An open claim's proof rebuilds nothing.
    let attempt = op_at(LOST, OpKind::Claim(attempt_fields()));
    body.proofs = vec![claim_proof(&attempt, &view_after(&[attempt_fields()]), 7)];
    assert!(check(&body, &[]).settled.is_empty());
}
