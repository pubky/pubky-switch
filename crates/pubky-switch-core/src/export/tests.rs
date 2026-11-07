//! Unit tests of the export formats and checks, on a small account built here: an identity
//! with one app, its record and receive key, one shared record and one live claim, frozen
//! for a move to a next service.

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use super::*;
use crate::chain::{
    ChainTip, ItemType, ProofBody, ProofState, ServiceTransition, SignedHead, Stub,
    TransitionProof, item_hash,
};
use crate::claims::{
    Claim, ClaimFields, ClaimLimits, ClaimTally, ClaimType, EntryContext, Outcome, Pin, apply_entry,
};
use crate::enc::{b64, pubky_id, zbase32_encode};
use crate::http::ErrorCode;
use crate::ident::{NamingKey, Policy, collection_id, record_key_from_blinded};
use crate::keys::{AppKeys, IdentityKey, ReceiveKey};
use crate::ops::{BatchRef, OpBody, OpKind, RecordPut, RecordVersion, Refusal, SignedOp};
use crate::records::{
    AppCert, AppCertBody, AppRecord, AppRecordBody, ExportTransfer, ExportTransferBody, Freeze,
    FreezeBody, IdentityBody, IdentityDoc, IdentityPolicy, Inbox, KeyBundle, ListedApp,
    ReceiveKeyBody, ReceiveKeyRecord, Unfreeze,
};
use crate::scopes::Permission;
use crate::sealed::SealedValue;
use crate::sig::SignedDoc;

const START: u64 = 1_767_225_600_000;
const DAY: u64 = 86_400_000;
const OLD: &str = "https://old.example";
const NEXT: &str = "https://next.example";
const SCOPE: &str = "scope-a";
const CLAIM_KEY: [u8; 32] = [20; 32];
const ATTEMPT: [u8; 16] = [21; 16];

fn identity() -> IdentityKey {
    IdentityKey::from_secret([1; 32])
}

fn app() -> AppKeys {
    AppKeys::from_secrets([2; 32], [3; 32])
}

fn other_app() -> AppKeys {
    AppKeys::from_secrets([12; 32], [13; 32])
}

fn old_key() -> SigningKey {
    SigningKey::from_bytes(&[5; 32])
}

fn next_key() -> SigningKey {
    SigningKey::from_bytes(&[6; 32])
}

fn cert_of(keys: &AppKeys) -> AppCert {
    let body = AppCertBody::new(
        identity().public(),
        keys.signing_public(),
        keys.bundle_public(),
        vec![SCOPE.to_owned()],
        &[Permission::ClaimsWrite],
        START - DAY,
        START + 365 * DAY,
    );
    AppCert::issue(&identity(), body).unwrap()
}

fn batch(id: u8, count: u64) -> BatchRef {
    BatchRef {
        id: [id; 16],
        count,
    }
}

fn op(kind: OpKind, batch: BatchRef) -> SignedOp {
    SignedOp::sign(
        &app(),
        OpBody {
            identity: identity().public(),
            app_id: Some(app().app_id_bytes()),
            generation: 1,
            batch,
            conditions: Vec::new(),
            kind,
        },
    )
    .unwrap()
}

fn record_put() -> RecordPut {
    let id = identity();
    let naming = NamingKey::from_root(&id.switch_root());
    let policy = Policy::new(SCOPE, &[SCOPE]);
    let blinded = naming.blind(b"natural");
    let key = record_key_from_blinded("sample.collection", &blinded, &policy.hash().unwrap());
    let sealed =
        SealedValue::seal(&id.scope_key(1, SCOPE), &id.public(), 1, SCOPE, &key, b"{}").unwrap();
    RecordPut {
        key,
        collection: collection_id("sample.collection", &id.public()),
        policy,
        expected_version: RecordVersion::NONE,
        value_sealed: sealed,
        id_inputs: Some(crate::ops::IdInputs {
            collection: "sample.collection".into(),
            blinded_key: blinded,
        }),
    }
}

fn attempt_fields() -> ClaimFields {
    ClaimFields {
        claim_key: CLAIM_KEY.to_vec(),
        kind: ClaimType::Attempt,
        expected_step: 0,
        attempt_id: ATTEMPT.to_vec(),
        orphan_after: Some(86_400),
        deadline: Some(START + 2 * DAY),
        basis: None,
        evidence_ref: None,
    }
}

/// The account, its export and what the next service compares it with.
#[derive(Clone)]
struct Fixture {
    id: [u8; 32],
    cert: AppCert,
    doc: IdentityDoc,
    freeze: Freeze,
    parts: Vec<Part>,
    manifest: Manifest,
    chunks: Vec<(ChunkRef, Vec<u8>)>,
    stubs: Vec<Stub>,
    record_proof: SignedDoc,
    claim_proof: TransitionProof,
    uploads: Uploads,
    now: u64,
}

fn fixture() -> Fixture {
    let ik = identity();
    let id = ik.public();
    let keys = app();
    let app_id = keys.app_id_bytes();
    let cert = cert_of(&keys);
    let old_public = old_key().verifying_key().to_bytes();
    let mut body = IdentityBody::first(
        id,
        [9; 16],
        Inbox::new(OLD, old_public),
        IdentityPolicy::default(),
    );
    body.apps = vec![ListedApp {
        app_id,
        cert: cert.hash(),
    }];
    let doc = IdentityDoc::sign(&ik, body).unwrap();
    let record = AppRecord::sign(&keys, AppRecordBody::new(&cert, Vec::new(), START)).unwrap();
    let rk = ReceiveKey::from_secret(0, [8; 32]);
    let rk_record = ReceiveKeyRecord::sign(&keys, &cert, ReceiveKeyBody::new(&cert, &rk)).unwrap();
    let freeze = Freeze::sign(
        &ik,
        FreezeBody {
            identity: id,
            inbox: Inbox::new(NEXT, next_key().verifying_key().to_bytes()),
            next_generation: 2,
            issued_at: START + 3_500,
            nonce: [4; 16],
        },
    )
    .unwrap();
    let app_put = op(
        OpKind::AppPut {
            record: record.signed().clone(),
        },
        batch(10, 2),
    );
    let key_put = op(
        OpKind::ReceiveKeyPut {
            record: rk_record.signed().clone(),
        },
        batch(10, 2),
    );
    let put = record_put();
    let write = op(OpKind::RecordPut(put.clone()), batch(11, 1));
    let attempt = op(OpKind::Claim(attempt_fields()), batch(12, 1));
    let freeze_at = START + 4_000;
    let transition = ServiceTransition::Freeze {
        freeze_hash: freeze.hash(),
        next_generation: 2,
        inbox: freeze.next().clone(),
        at: freeze_at,
    }
    .sign(&old_key(), &id)
    .unwrap();
    // The chain: seq 1 the identity.json, 2 and 3 the app's batch, 4 the write, 6 the
    // attempt, 7 the freeze transition; seq 5 went to an inbox entry, read and deleted.
    let items: Vec<(ItemType, SignedDoc, Option<BatchRef>, u64)> = vec![
        (ItemType::Identity, doc.signed().clone(), None, START),
        (
            ItemType::Op,
            app_put.signed().clone(),
            Some(batch(10, 2)),
            START + 1_000,
        ),
        (
            ItemType::Op,
            key_put.signed().clone(),
            Some(batch(10, 2)),
            START + 1_000,
        ),
        (
            ItemType::Op,
            write.signed().clone(),
            Some(batch(11, 1)),
            START + 2_000,
        ),
        (
            ItemType::Op,
            attempt.signed().clone(),
            Some(batch(12, 1)),
            START + 3_000,
        ),
        (ItemType::Service, transition, None, freeze_at),
    ];
    let mut tip = ChainTip {
        generation: 1,
        seq: 0,
        chain_hash: [0; 32],
    };
    let mut stubs = Vec::new();
    let mut parts = Vec::new();
    for ((item_type, signed, batch, time), seq) in items.iter().zip([1, 2, 3, 4, 6, 7]) {
        let hash = item_hash(*item_type, &signed.doc_bytes().unwrap());
        let (stub, next) = tip.append(seq, *time, *item_type, hash, *batch).unwrap();
        tip = next;
        stubs.push(stub.clone());
        parts.push(Part::Chain(ChainPart {
            seq,
            stub,
            item_type: *item_type,
            doc: Some(signed.clone()),
            context: Value::Null,
        }));
    }
    let head = SignedHead::sign(&old_key(), &id, &tip);
    let record_proof = TransitionProof::sign(
        &old_key(),
        &id,
        ProofBody::new(
            stubs[3].clone(),
            b64(&put.key),
            &ProofState::Record {
                version: RecordVersion::new(1, 4),
                deleted: false,
            },
        ),
    )
    .unwrap();
    let nobody = |_: &[u8; 16]| true;
    let cx = EntryContext {
        writer: app_id,
        now: START + 3_000,
        can_read: true,
        is_current: &nobody,
        limits: ClaimLimits::default(),
        tally: ClaimTally::default(),
    };
    let entry = attempt_fields().check().unwrap();
    let claim = apply_entry(None, &entry, &cx).unwrap();
    let view = claim.view(&CLAIM_KEY, START + 3_000, &nobody);
    let claim_proof = TransitionProof::sign(
        &old_key(),
        &id,
        ProofBody::new(
            stubs[4].clone(),
            b64(&CLAIM_KEY),
            &ProofState::Claim(view.to_value()),
        ),
    )
    .unwrap();
    let mut all = vec![Part::Meta(MetaPart {
        identity: doc.signed().clone(),
        generation: 1,
        seq: 7,
        directory_version: 3,
        apps_version: 1,
        app_added_at: vec![(app_id, 1)],
    })];
    all.extend(parts);
    all.push(Part::App(AppPart {
        app_id,
        record: Some(record.signed().clone()),
        record_seq: Some(2),
        record_at_ms: Some(START + 1_000),
        receive_keys: vec![(rk_record.signed().clone(), 3)],
        cursor: 7,
        last_seen_ms: Some(START + 3_000),
        revoked_at_ms: None,
        departed_at_ms: None,
        departure_epoch: None,
        rotated: false,
        renewed_cert: None,
        lagging: false,
        keys_through: Some(1),
        full_bundle_requested_ms: None,
    }));
    all.push(Part::Claim(ClaimPart {
        claim_key: CLAIM_KEY,
        claim: ClaimState {
            step: 1,
            attempts: vec![AttemptState {
                attempt_id: ATTEMPT,
                owner: app_id,
                outcome: Outcome::Open,
                opened_at_ms: START + 3_000,
                orphan_after_s: 86_400,
                possibly_duplicate: false,
                duplicate: false,
                deadline_ms: Some(START + 2 * DAY),
                from_upload: false,
                resolved_by: None,
            }],
            current: Some(ATTEMPT),
            settled: false,
            divergent: false,
            pinned_deadline: Pin::At(START + 2 * DAY),
            rebuilt: false,
            creator: Some(app_id),
            last_entry_ms: Some(START + 3_000),
        },
    }));
    all.push(Part::ClaimEntry(ClaimEntryPart {
        claim_key: CLAIM_KEY,
        step: 0,
        seq: 6,
        op: attempt.signed().clone(),
        proof: claim_proof.signed().clone(),
    }));
    all.push(Part::Record(RecordEntry {
        key: put.key,
        collection: put.collection,
        read_scope: SCOPE.into(),
        write_scopes: vec![SCOPE.into()],
        generation: 1,
        version: 4,
        op: None,
        seq: 4,
        deleted: false,
        writer: app_id,
        from_upload: false,
        upload_base: None,
        size: put.value_sealed.ct.len() as u64,
        cert: None,
        proof: Some(record_proof.signed().clone()),
    }));
    let mut batches = vec![
        (10, START + 1_000, vec![app_put, key_put]),
        (11, START + 2_000, vec![write]),
        (12, START + 3_000, vec![attempt]),
    ];
    batches.sort_by_key(|(id, _, _)| b64(&[*id; 16]));
    for (bid, at, ops) in batches {
        all.push(Part::Batch(BatchPart {
            id: [bid; 16],
            ops_hash: crate::ops::ops_hash(&ops).unwrap(),
            at_ms: at,
        }));
    }
    let chunks = pack(&all, DEFAULT_CHUNK_TARGET).unwrap();
    let manifest = Manifest::sign(
        &old_key(),
        ManifestBody::new(
            id,
            freeze.hash(),
            1,
            freeze_at,
            head,
            None,
            chunks.iter().map(|(r, _)| r.clone()).collect(),
        )
        .unwrap(),
    )
    .unwrap();
    Fixture {
        id,
        cert,
        doc,
        freeze,
        parts: all,
        manifest,
        chunks,
        stubs,
        record_proof: record_proof.signed().clone(),
        claim_proof,
        uploads: Uploads::default(),
        now: freeze_at,
    }
}

impl Fixture {
    fn run(&self) -> Result<Import, Refusal> {
        self.run_with(&self.parts)
    }

    /// Activate `parts`, under the manifest signed again with their count.
    fn run_with(&self, parts: &[Part]) -> Result<Import, Refusal> {
        let manifest = self.resign(|b| b.parts = parts.len() as u64);
        self.run_manifest(&manifest, parts)
    }

    fn run_manifest(&self, manifest: &Manifest, parts: &[Part]) -> Result<Import, Refusal> {
        activate(
            &Activation {
                manifest,
                freeze: &self.freeze,
                enrolled: &self.doc,
                now: Some(self.now),
                uploads: &self.uploads,
                revoked_apps: &[],
            },
            parts,
        )
    }

    fn resign(&self, change: impl FnOnce(&mut ManifestBody)) -> Manifest {
        let mut body = self.manifest.body().clone();
        change(&mut body);
        Manifest::sign(&old_key(), body).unwrap()
    }

    fn index(&self, kind: &str) -> usize {
        self.parts.iter().position(|p| p.kind() == kind).unwrap()
    }

    fn with(&self, change: impl FnOnce(&mut Vec<Part>)) -> Vec<Part> {
        let mut parts = self.parts.clone();
        change(&mut parts);
        parts
    }
}

fn refused(result: Result<Import, Refusal>, code: ErrorCode, rule: &str) {
    let error = result.expect_err(rule);
    assert_eq!(error.code, code, "{rule}: {error}");
    assert!(error.reason.contains(rule), "{rule}: {error}");
}

fn chain_mut(parts: &mut [Part], seq: u64) -> &mut ChainPart {
    parts
        .iter_mut()
        .find_map(|p| match p {
            Part::Chain(c) if c.seq == seq => Some(c),
            _ => None,
        })
        .unwrap()
}

fn record_mut(parts: &mut [Part]) -> &mut RecordEntry {
    parts
        .iter_mut()
        .find_map(|p| match p {
            Part::Record(r) => Some(r),
            _ => None,
        })
        .unwrap()
}

fn app_mut(parts: &mut [Part]) -> &mut AppPart {
    parts
        .iter_mut()
        .find_map(|p| match p {
            Part::App(a) => Some(a),
            _ => None,
        })
        .unwrap()
}

fn claim_mut(parts: &mut [Part]) -> &mut ClaimState {
    parts
        .iter_mut()
        .find_map(|p| match p {
            Part::Claim(c) => Some(&mut c.claim),
            _ => None,
        })
        .unwrap()
}

/// Put parts in the order of Switch wire 10.3, for cases that add parts.
fn sorted(mut parts: Vec<Part>) -> Vec<Part> {
    let rank = |p: &Part| {
        [
            "meta",
            "chain",
            "entry",
            "app",
            "claim",
            "tombstone",
            "record",
            "batch",
            "contact",
            "conversation",
            "deny",
            "invite_code",
            "connect",
            "flag",
            "peer",
            "peer_floor",
            "divergent",
        ]
        .iter()
        .position(|k| {
            *k == match p.kind() {
                "key_bundle" => "app",
                "claim_entry" => "claim",
                other => other,
            }
        })
        .unwrap()
    };
    parts.sort_by_key(rank);
    parts
}

// ---- The manifest ----

#[test]
fn test_manifest_signs_reads_and_hashes() {
    let f = fixture();
    let read = Manifest::verify(
        f.manifest.signed(),
        &old_key().verifying_key().to_bytes(),
        &f.id,
    )
    .unwrap();
    assert_eq!(read, f.manifest);
    assert_eq!(read.hash(), f.manifest.signed().doc_hash().unwrap());
    let body = f.manifest.body().to_json();
    let text = String::from_utf8(body).unwrap();
    assert!(text.starts_with(r#"{"v":1,"kind":"pubky-switch.export_manifest","identity":""#));
    assert!(text.contains(r#""checkpoint":null,"parts":"#));
}

#[test]
fn test_manifest_refuses_another_key_identity_or_kind() {
    let f = fixture();
    let next = next_key().verifying_key().to_bytes();
    assert!(matches!(
        Manifest::verify(f.manifest.signed(), &next, &f.id),
        Err(crate::Error::Signature(_))
    ));
    let other = IdentityKey::from_secret([7; 32]).public();
    assert!(
        Manifest::verify(
            f.manifest.signed(),
            &old_key().verifying_key().to_bytes(),
            &other
        )
        .is_err()
    );
    let mut v: Value = serde_json::from_slice(&f.manifest.body().to_json()).unwrap();
    v["kind"] = json!("pubky-switch.export_chunk");
    let bytes = serde_json::to_vec(&v).unwrap();
    let signed = SignedDoc::sign_bytes(
        &old_key(),
        crate::labels::sig::EXPORT_MANIFEST,
        &[&f.id],
        bytes,
    );
    assert!(Manifest::verify(&signed, &old_key().verifying_key().to_bytes(), &f.id).is_err());
    v["kind"] = json!(MANIFEST_KIND);
    v.as_object_mut().unwrap().remove("checkpoint");
    let bytes = serde_json::to_vec(&v).unwrap();
    let signed = SignedDoc::sign_bytes(
        &old_key(),
        crate::labels::sig::EXPORT_MANIFEST,
        &[&f.id],
        bytes,
    );
    assert!(
        Manifest::verify(&signed, &old_key().verifying_key().to_bytes(), &f.id).is_err(),
        "checkpoint is always written"
    );
}

#[test]
fn test_manifest_binding() {
    let f = fixture();
    f.manifest.check_binding(&f.id, &f.freeze, &f.doc).unwrap();
    for (what, m) in [
        ("identity", f.resign(|b| b.identity = [3; 32])),
        ("freeze_hash", f.resign(|b| b.freeze_hash = [3; 32])),
        ("generation", f.resign(|b| b.generation = 2)),
        ("next_generation", f.resign(|b| b.next_generation = 3)),
    ] {
        let error = m.check_binding(&f.id, &f.freeze, &f.doc).unwrap_err();
        assert_eq!(error.status(), 400, "{what}");
        assert!(error.reason.contains(what), "{what}: {error}");
    }
}

#[test]
fn test_manifest_chunk_list() {
    let f = fixture();
    f.manifest.check_chunks(MAX_IMPORT_BYTES).unwrap();
    let chunk = f.manifest.body().chunks[0].clone();
    let two = |second: ChunkRef| {
        f.resign(|b| {
            b.chunks.push(second.clone());
            b.parts = second.last + 1;
            b.bytes += second.len;
        })
    };
    let next = ChunkRef {
        id: "00001".into(),
        len: 10,
        hash: [0; 32],
        first: chunk.last + 1,
        last: chunk.last + 1,
    };
    two(next.clone()).check_chunks(MAX_IMPORT_BYTES).unwrap();
    let cases = [
        (
            "the same ID twice",
            two(ChunkRef {
                id: chunk.id.clone(),
                ..next.clone()
            }),
            400,
        ),
        (
            "a gap",
            two(ChunkRef {
                first: chunk.last + 2,
                last: chunk.last + 2,
                ..next.clone()
            }),
            400,
        ),
        ("bytes", f.resign(|b| b.bytes += 1), 400),
        ("parts", f.resign(|b| b.parts += 1), 400),
        ("none", f.resign(|b| b.chunks.clear()), 400),
        (
            "over 1 MiB",
            two(ChunkRef {
                len: MAX_CHUNK_BYTES as u64 + 1,
                ..next.clone()
            }),
            413,
        ),
    ];
    for (what, m, status) in cases {
        assert_eq!(
            m.check_chunks(MAX_IMPORT_BYTES).unwrap_err().status(),
            status,
            "{what}"
        );
    }
    assert_eq!(
        f.manifest.check_chunks(10).unwrap_err().status(),
        413,
        "the import limit"
    );
}

#[test]
fn test_manifest_chunk_checks() {
    let f = fixture();
    let (r, bytes) = &f.chunks[0];
    f.manifest.check_chunk(&r.id, bytes).unwrap();
    assert_eq!(f.manifest.check_fetched(&r.id, bytes).unwrap(), 0);
    assert_eq!(
        f.manifest.check_chunk("other", bytes).unwrap_err().status(),
        404
    );
    let mut changed = bytes.clone();
    changed[30] ^= 1;
    let error = f.manifest.check_chunk(&r.id, &changed).unwrap_err();
    assert_eq!(error.status(), 409);
    assert_eq!(error.current.unwrap()["chunk"]["len"], r.len);
    let big = vec![b' '; MAX_CHUNK_BYTES + 1];
    assert_eq!(
        f.manifest.check_chunk(&r.id, &big).unwrap_err().status(),
        413
    );
    // A chunk of the right hash but out of place: index 1 where the manifest puts 0.
    let moved = Chunk {
        index: 1,
        first: 0,
        parts: f.parts.clone(),
    }
    .to_json()
    .unwrap();
    let m = f.resign(|b| {
        b.chunks[0].len = moved.len() as u64;
        b.chunks[0].hash = crate::enc::hash(&moved);
        b.bytes = moved.len() as u64;
    });
    assert_eq!(m.check_chunk(&r.id, &moved).unwrap_err().status(), 400);
    // Reading every part from the chunks.
    assert_eq!(f.manifest.read_parts(&[bytes]).unwrap(), f.parts);
    assert_eq!(f.manifest.read_parts(&[]).unwrap_err().status(), 400);
    let fewer = f.resign(|b| b.parts -= 1);
    assert_eq!(fewer.read_parts(&[bytes]).unwrap_err().status(), 400);
}

// ---- Chunks and packing ----

#[test]
fn test_chunk_round_trips_and_frames() {
    let f = fixture();
    let (r, bytes) = &f.chunks[0];
    let chunk = Chunk::parse(bytes).unwrap();
    assert_eq!(chunk.to_json().unwrap(), *bytes);
    assert_eq!(Chunk::read_frame(bytes).unwrap(), (0, 0, f.parts.len()));
    assert_eq!(r.id, chunk_id(0));
    assert_eq!(chunk_id(12), "00012");
    assert_eq!(
        chunk_overhead(0, 0),
        r#"{"v":1,"kind":"pubky-switch.export_chunk","index":0,"first":0,"parts":[]}"#.len()
    );
    assert_eq!(
        chunk_overhead(crate::json::MAX_INT, crate::json::MAX_INT),
        MAX_CHUNK_OVERHEAD
    );
}

#[test]
fn test_chunk_refuses_other_forms() {
    for bad in [
        &br#"{"v":2,"kind":"pubky-switch.export_chunk","index":0,"first":0,"parts":[]}"#[..],
        br#"{"v":1,"kind":"other","index":0,"first":0,"parts":[]}"#,
        br#"{"v":1,"kind":"pubky-switch.export_chunk","index":-1,"first":0,"parts":[]}"#,
        br#"{"v":1,"kind":"pubky-switch.export_chunk","index":0,"first":0,"parts":{}}"#,
        br#"{"v":1,"kind":"pubky-switch.export_chunk","index":0,"first":0,"parts":[{"part":"future"}]}"#,
        br#"{"v":1,"kind":"pubky-switch.export_chunk","index":0,"index":0,"first":0,"parts":[]}"#,
    ] {
        assert_eq!(Chunk::parse(bad).unwrap_err().status(), 400);
    }
    // A chain part's context is opaque; a number elsewhere isn't.
    let ok = br#"{"v":1,"kind":"pubky-switch.export_chunk","index":0,"first":0,"parts":[{"part":"contact","pubky":"PK"}]}"#;
    let text = String::from_utf8(ok.to_vec())
        .unwrap()
        .replace("PK", &pubky_id(&identity().public()));
    Chunk::parse(text.as_bytes()).unwrap();
    assert!(Chunk::parse(text.replace(r#""index":0"#, r#""index":0.5"#).as_bytes()).is_err());
}

#[test]
fn test_pack_splits_at_the_target_and_refuses_oversized_parts() {
    let f = fixture();
    let one = pack(&f.parts, DEFAULT_CHUNK_TARGET).unwrap();
    assert_eq!(one.len(), 1);
    let many = pack(&f.parts, 1).unwrap();
    assert_eq!(
        many.len(),
        f.parts.len(),
        "a part per chunk below the smallest part"
    );
    for (i, (r, bytes)) in many.iter().enumerate() {
        assert_eq!((r.first, r.last), (i as u64, i as u64));
        assert!(r.matches(bytes));
    }
    let huge = Part::Chain(ChainPart {
        context: json!("x".repeat(MAX_CHUNK_BYTES)),
        ..match &f.parts[1] {
            Part::Chain(c) => c.clone(),
            _ => unreachable!(),
        }
    });
    assert_eq!(
        pack(&[huge], DEFAULT_CHUNK_TARGET).unwrap_err().status(),
        413
    );
}

// ---- Parts ----

fn other_parts() -> Vec<Value> {
    let f = fixture();
    let pk = pubky_id(&f.id);
    let app = zbase32_encode(&app().app_id_bytes());
    let k = b64(&[1; 32]);
    let t = "2026-01-01T00:00:00.000Z";
    vec![
        json!({ "part": "entry", "seq": 9, "sender": pk, "cert": f.cert.signed(), "accepted_at_ms": 1,
            "context": null, "envelope": "", "targets": [app],
            "result": { "entry_id": b64(&[2; 16]), "accepted_at": t, "directory_version": 3 },
            "unreadable": true, "missed": { "entries": 2, "from_ms": 1, "until_ms": 2 } }),
        json!({ "part": "key_bundle", "app_id": app, "bundle": { "envelope": "AQID", "sig": b64(&[1; 64]) },
            "seq": 7, "first_epoch": 1, "last_epoch": 2 }),
        json!({ "part": "tombstone", "claim_key": k, "tombstone": { "step": 2, "attempts": [{
            "attempt_id": b64(&[3; 16]), "owner": app, "outcome": "done", "opened_at_ms": 1,
            "orphan_after_s": 60, "possibly_duplicate": false, "duplicate": false,
            "deadline_ms": null, "from_upload": false, "resolved_by": app }],
            "deadline_ms": null, "creator": app, "last_entry_ms": 5 } }),
        json!({ "part": "contact", "pubky": pk }),
        json!({ "part": "deny", "pubky": pk }),
        json!({ "part": "conversation", "pubky": pk, "written_by": "service", "code_hash": k,
            "context": { "ref": 1.5 }, "at": t, "last_used": t }),
        json!({ "part": "conversation", "pubky": pk, "written_by": app, "at": t }),
        json!({ "part": "invite_code", "code_hash": k, "expires_at": t, "expires_at_ms": 1767225600000u64,
            "max_uses": 1, "uses": 0, "context": null, "written_by": app }),
        json!({ "part": "connect", "pubky": pk, "at": t }),
        json!({ "part": "flag", "pubky": pk, "hits": 3 }),
        json!({ "part": "peer", "doc": f.doc.signed() }),
        json!({ "part": "peer_floor", "identity": pk, "version": 3, "generation": 1, "body_hash": k }),
        json!({ "part": "divergent", "key": k, "index": 0, "upload": f.record_proof }),
    ]
}

#[test]
fn test_part_every_kind_round_trips() {
    let f = fixture();
    for part in &f.parts {
        let bytes = part.to_json().unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(Part::read(&value).unwrap(), *part, "{}", part.kind());
    }
    for value in other_parts() {
        let part = Part::read(&value).unwrap_or_else(|e| panic!("{}: {e}", value["part"]));
        let again: Value = serde_json::from_slice(&part.to_json().unwrap()).unwrap();
        assert_eq!(again, value, "{}", part.kind());
    }
}

#[test]
fn test_part_reading_rules() {
    let f = fixture();
    let app = serde_json::from_slice::<Value>(&f.parts[f.index("app")].to_json().unwrap()).unwrap();
    // "Or null" members may be absent; unknown members are ignored.
    let mut absent = app.clone();
    for k in [
        "record",
        "record_seq",
        "last_seen_ms",
        "renewed_cert",
        "keys_through",
    ] {
        absent.as_object_mut().unwrap().remove(k);
    }
    absent["future"] = json!(1);
    Part::read(&absent).unwrap();
    // Listed members are present.
    for k in ["cursor", "rotated", "lagging", "receive_keys", "app_id"] {
        let mut v = app.clone();
        v.as_object_mut().unwrap().remove(k);
        assert_eq!(Part::read(&v).unwrap_err().status(), 400, "{k}");
    }
    // An earlier form's members are refused, whatever they hold.
    for old in [json!(null), json!([]), json!("x")] {
        let mut v = app.clone();
        v["key_bundles"] = old.clone();
        assert!(Part::read(&v).unwrap_err().reason.contains("key_bundles"));
        let mut c: Value =
            serde_json::from_slice(&f.parts[f.index("claim")].to_json().unwrap()).unwrap();
        c["claim"]["entries"] = old;
        assert!(Part::read(&c).unwrap_err().reason.contains("entries"));
    }
    let mut b: Value =
        serde_json::from_slice(&f.parts[f.index("batch")].to_json().unwrap()).unwrap();
    b["record"]["proofs"] = json!([f.record_proof]);
    assert_eq!(
        Part::read(&b).unwrap_err().status(),
        400,
        "a batch's proofs"
    );
    let others = other_parts();
    let find = |kind: &str| others.iter().find(|p| p["part"] == kind).unwrap().clone();
    for (what, v) in [
        ("unknown kind", json!({ "part": "future" })),
        ("no kind", json!({ "pubky": "x" })),
        ("connect.at a number", {
            let mut v = find("connect");
            v["at"] = json!(5);
            v
        }),
        ("invite_code by the service", {
            let mut v = find("invite_code");
            v["written_by"] = json!("service");
            v
        }),
        ("invite_code without context", {
            let mut v = find("invite_code");
            v.as_object_mut().unwrap().remove("context");
            v
        }),
        ("key_bundle from epoch 0", {
            let mut v = find("key_bundle");
            v["first_epoch"] = json!(0);
            v
        }),
        ("key_bundle first above last", {
            let mut v = find("key_bundle");
            v["first_epoch"] = json!(3);
            v
        }),
        ("key_bundle not an object", {
            let mut v = find("key_bundle");
            v["bundle"] = json!("x");
            v
        }),
        ("an attempt's outcome", {
            let mut v = find("tombstone");
            v["tombstone"]["attempts"][0]["outcome"] = json!("lost");
            v
        }),
        ("entry without envelope", {
            let mut v = find("entry");
            v.as_object_mut().unwrap().remove("envelope");
            v
        }),
        ("conversation code without context", {
            let mut v = find("conversation");
            v.as_object_mut().unwrap().remove("context");
            v
        }),
        ("peer_floor body hash", {
            let mut v = find("peer_floor");
            v["body_hash"] = json!("AA");
            v
        }),
        ("a signed document", {
            let mut v = find("peer");
            v["doc"]["sig"] = json!("AA");
            v
        }),
    ] {
        assert_eq!(Part::read(&v).unwrap_err().status(), 400, "{what}");
    }
    // The pin: absent before any attempt, null for "none".
    let mut c: Value =
        serde_json::from_slice(&f.parts[f.index("claim")].to_json().unwrap()).unwrap();
    let pin = |c: &Value| match Part::read(c).unwrap() {
        Part::Claim(p) => p.claim.pinned_deadline,
        _ => unreachable!(),
    };
    assert_eq!(pin(&c), Pin::At(START + 2 * DAY));
    c["claim"]["pinned_deadline"] = Value::Null;
    assert_eq!(pin(&c), Pin::NoDeadline);
    c["claim"]
        .as_object_mut()
        .unwrap()
        .remove("pinned_deadline");
    assert_eq!(pin(&c), Pin::Unpinned);
}

// ---- The part order ----

#[test]
fn test_part_order() {
    let f = fixture();
    check_part_order(&f.parts).unwrap();
    let mut all = f.parts.clone();
    // Each kind once: the second conversation part names the same counterparty.
    let mut seen = Vec::new();
    for part in other_parts().iter().map(|v| Part::read(v).unwrap()) {
        if !matches!(part.kind(), "key_bundle" | "entry") && !seen.contains(&part.kind()) {
            seen.push(part.kind());
            all.push(part);
        }
    }
    let all = sorted(all);
    check_part_order(&all).unwrap();
    let pk = |seed: u8| IdentityKey::from_secret([seed; 32]).public();
    let (low, high) = {
        let (a, b) = (pk(30), pk(31));
        if pubky_id(&a) < pubky_id(&b) {
            (a, b)
        } else {
            (b, a)
        }
    };
    let meta = f.parts[0].clone();
    let ok = |rest: Vec<Part>| check_part_order(&[vec![meta.clone()], rest].concat());
    ok(vec![
        Part::Contact(low),
        Part::Contact(high),
        Part::Deny(low),
    ])
    .unwrap();
    // Keys by their text: "-" sorts before "A" as text, after it as bytes.
    let dash = [0xfb; 32];
    let a = [0x00; 32];
    assert!(b64(&dash).starts_with('-') && b64(&a).starts_with('A'));
    let tomb = |key: [u8; 32]| {
        Part::Tombstone(TombstonePart {
            claim_key: key,
            tombstone: TombstoneState {
                step: 1,
                attempts: Vec::new(),
                deadline_ms: None,
                creator: None,
                last_entry_ms: None,
            },
        })
    };
    ok(vec![tomb(dash), tomb(a)]).unwrap();
    let connect = |at: u64| Part::Connect(ConnectPart { pubky: low, at });
    ok(vec![connect(5), connect(5), connect(6)]).unwrap();
    let div = |key: [u8; 32], index: u64| {
        Part::Divergent(DivergentPart {
            key,
            index,
            upload: f.record_proof.clone(),
        })
    };
    ok(vec![div(dash, 0), div(dash, 1), div(a, 0)]).unwrap();
    ok((0..8).map(|i| div(a, i)).collect()).unwrap();
    for (what, rest) in [
        ("keys by text", vec![tomb(a), tomb(dash)]),
        ("a key once", vec![Part::Contact(low), Part::Contact(low)]),
        (
            "groups in order",
            vec![Part::Deny(low), Part::Contact(high)],
        ),
        ("connect oldest first", vec![connect(6), connect(5)]),
        ("a second meta", vec![meta.clone()]),
        ("divergent from 1", vec![div(a, 1)]),
        ("divergent with a gap", vec![div(a, 0), div(a, 2)]),
        ("nine divergent", (0..9).map(|i| div(a, i)).collect()),
        (
            "another record's in between",
            vec![div(dash, 0), div(a, 0), div(dash, 1)],
        ),
    ] {
        assert_eq!(ok(rest).unwrap_err().status(), 400, "{what}");
    }
    // A chain part out of seq order; a claim_entry or key_bundle part away from its parent.
    let mut swapped = f.parts.clone();
    swapped.swap(2, 3);
    assert!(check_part_order(&swapped).is_err());
    let ci = f.index("claim");
    let mut moved = f.parts.clone();
    moved.swap(ci, ci + 1);
    assert!(
        check_part_order(&moved)
            .unwrap_err()
            .reason
            .contains("doesn't follow")
    );
    let mut twice = f.parts.clone();
    twice.insert(ci + 2, f.parts[ci + 1].clone());
    assert!(
        check_part_order(&twice)
            .unwrap_err()
            .reason
            .contains("ascend")
    );
    let bundle = |first: u64| {
        Part::KeyBundle(KeyBundlePart {
            app_id: app().app_id_bytes(),
            bundle: KeyBundle::from_parts(vec![1], [1; 64]),
            seq: 7,
            first_epoch: first,
            last_epoch: first,
        })
    };
    let ai = f.index("app");
    let mut bundles = f.parts.clone();
    bundles.insert(ai + 1, bundle(1));
    bundles.insert(ai + 2, bundle(2));
    check_part_order(&bundles).unwrap();
    bundles.swap(ai + 1, ai + 2);
    assert!(check_part_order(&bundles).is_err());
    let mut before = f.parts.clone();
    before.insert(ai, bundle(1));
    assert!(check_part_order(&before).is_err());
}

// ---- The calls ----

#[test]
fn test_export_read_checks() {
    let f = fixture();
    let old = old_key().verifying_key().to_bytes();
    let transfer = ExportTransfer::sign(
        &identity(),
        ExportTransferBody {
            identity: f.id,
            freeze_hash: f.freeze.hash(),
            manifest_hash: f.manifest.hash(),
            from: Inbox::new(OLD, old),
            to: f.freeze.next().clone(),
            issued_at: START + 4_500,
        },
    )
    .unwrap();
    let read = |caller, frozen: bool, has_identity: bool| ExportRead {
        caller,
        frozen_with: frozen.then_some(&f.freeze),
        has_identity,
        origin: OLD,
        service_key: &old,
    };
    read(ExportCaller::Signer, true, true)
        .check_manifest()
        .unwrap();
    let status = |r: Result<(), Refusal>| r.unwrap_err().status();
    assert_eq!(
        status(read(ExportCaller::Other, true, true).check_manifest()),
        403
    );
    assert_eq!(
        status(read(ExportCaller::NextService(&transfer), true, true).check_manifest()),
        403
    );
    assert_eq!(
        status(read(ExportCaller::Signer, false, true).check_manifest()),
        409
    );
    assert_eq!(
        status(read(ExportCaller::Signer, true, false).check_manifest()),
        404
    );
    let id = f.chunks[0].0.id.clone();
    read(ExportCaller::Signer, true, true)
        .check_chunk(&f.manifest, &id)
        .unwrap();
    read(ExportCaller::NextService(&transfer), true, true)
        .check_chunk(&f.manifest, &id)
        .unwrap();
    let chunk_status =
        |r: ExportRead<'_>, id: &str| r.check_chunk(&f.manifest, id).unwrap_err().status();
    assert_eq!(
        chunk_status(read(ExportCaller::Other, true, true), &id),
        403
    );
    assert_eq!(
        chunk_status(read(ExportCaller::Signer, true, true), "other"),
        404
    );
    let other_manifest = f.resign(|b| b.last_time += 1);
    let refused = read(ExportCaller::NextService(&transfer), true, true)
        .check_chunk(&other_manifest, &id)
        .unwrap_err();
    assert_eq!(
        (refused.status(), refused.code),
        (403, ErrorCode::NotAdmitted)
    );
}

#[test]
fn test_chunk_answer_and_bodies_round_trip() {
    let answer = ChunkAnswer {
        id: "00000".into(),
        data: b"{}".to_vec(),
    };
    assert_eq!(answer.to_json(), br#"{"id":"00000","data":"e30"}"#);
    assert_eq!(ChunkAnswer::parse(&answer.to_json()).unwrap(), answer);
    assert!(ChunkAnswer::parse(br#"{"id":"00000"}"#).is_err());
    let status = ImportStatus {
        manifest: [1; 32],
        chunks: 2,
        missing: vec!["00001".into()],
        activated: false,
        pulled: 1,
        pull_error: Some("chunk 00001: unreachable".into()),
    };
    assert_eq!(ImportStatus::parse(&status.to_json()).unwrap(), status);
    let quiet = ImportStatus {
        pull_error: None,
        ..status.clone()
    };
    assert!(
        !String::from_utf8(quiet.to_json())
            .unwrap()
            .contains("pull_error")
    );
    assert!(ImportStatus::parse(br#"{"manifest":"x"}"#).is_err());
    let activate_request = ActivateRequest { manifest: [2; 32] };
    assert_eq!(
        ActivateRequest::parse(&activate_request.to_json()).unwrap(),
        activate_request
    );
    activate_request.check(Some(&[2; 32])).unwrap();
    assert_eq!(
        activate_request.check(Some(&[3; 32])).unwrap_err().status(),
        409
    );
    assert_eq!(activate_request.check(None).unwrap_err().status(), 409);
    let f = fixture();
    let answer = ActivateAnswer {
        activated: f.manifest.hash(),
        imported: 7,
        head: f.manifest.body().head,
    };
    assert_eq!(ActivateAnswer::parse(&answer.to_json()).unwrap(), answer);
}

#[test]
fn test_import_start_checks_in_order() {
    let f = fixture();
    let n_key = next_key().verifying_key().to_bytes();
    let old = old_key().verifying_key().to_bytes();
    let transfer = ExportTransfer::sign(
        &identity(),
        ExportTransferBody {
            identity: f.id,
            freeze_hash: f.freeze.hash(),
            manifest_hash: f.manifest.hash(),
            from: Inbox::new(OLD, old),
            to: Inbox::new(NEXT, n_key),
            issued_at: START + 4_500,
        },
    )
    .unwrap();
    let start = ImportStart {
        manifest: f.manifest.signed().clone(),
        freeze: f.freeze.signed().clone(),
        transfer: Some(transfer.signed().clone()),
    };
    assert_eq!(ImportStart::parse(&start.to_json()).unwrap(), start);
    assert!(ImportStart::parse(br#"{"manifest":null}"#).is_err());
    let none = |_: &[u8; 32]| false;
    let cx = |current| StartChecks {
        identity: &f.id,
        held: Some(&f.doc),
        origin: NEXT,
        service_key: &n_key,
        cancelled: &none,
        max_import_bytes: MAX_IMPORT_BYTES,
        current,
    };
    match start.check(&cx(None)).unwrap() {
        StartDecision::Begin(started) => {
            assert_eq!(started.manifest, f.manifest);
            assert_eq!(started.transfer.as_ref(), Some(&transfer));
        }
        other => panic!("{other:?}"),
    }
    let same = CurrentImport {
        manifest_hash: f.manifest.hash(),
        activated: false,
        freeze_issued_at: 0,
    };
    assert!(matches!(
        start.check(&cx(Some(same))).unwrap(),
        StartDecision::Status(Some(_))
    ));
    let other = CurrentImport {
        manifest_hash: [9; 32],
        ..same
    };
    assert!(
        matches!(
            start.check(&cx(Some(other))).unwrap(),
            StartDecision::Begin(_)
        ),
        "a newer freeze replaces"
    );
    let newer = CurrentImport {
        freeze_issued_at: START + 3_500,
        ..other
    };
    assert_eq!(start.check(&cx(Some(newer))).unwrap_err().status(), 409);
    let activated = CurrentImport {
        activated: true,
        ..other
    };
    assert_eq!(start.check(&cx(Some(activated))).unwrap_err().status(), 409);
    // Step 2: the freeze verifies (401) and names this service (400); not cancelled (409).
    let mut forged = start.clone();
    forged.freeze.sig = b64(&[0; 64]);
    assert_eq!(forged.check(&cx(None)).unwrap_err().status(), 401);
    let elsewhere = StartChecks {
        origin: "https://else.example",
        ..cx(None)
    };
    assert_eq!(start.check(&elsewhere).unwrap_err().status(), 400);
    let all = |_: &[u8; 32]| true;
    let cancelled = StartChecks {
        cancelled: &all,
        ..cx(None)
    };
    assert_eq!(start.check(&cancelled).unwrap_err().status(), 409);
    // Step 3: the manifest verifies with the held identity.json's key (401), or 409 without one.
    let unheld = StartChecks {
        held: None,
        ..cx(None)
    };
    assert_eq!(start.check(&unheld).unwrap_err().status(), 409);
    let mut resigned = start.clone();
    resigned.manifest = Manifest::sign(&next_key(), f.manifest.body().clone())
        .unwrap()
        .signed()
        .clone();
    assert_eq!(resigned.check(&cx(None)).unwrap_err().status(), 401);
    // Steps 5 and 6.
    let mut unbound = start.clone();
    unbound.manifest = f.resign(|b| b.next_generation = 3).signed().clone();
    unbound.transfer = None;
    assert_eq!(unbound.check(&cx(None)).unwrap_err().status(), 400);
    let small = StartChecks {
        max_import_bytes: 1,
        ..cx(None)
    };
    assert_eq!(start.check(&small).unwrap_err().status(), 413);
    // Step 7: a transfer for another manifest.
    let mut stale = start.clone();
    stale.manifest = f.resign(|b| b.last_time += 1).signed().clone();
    assert_eq!(stale.check(&cx(None)).unwrap_err().status(), 400);
    let mut bad_transfer = start.clone();
    bad_transfer.transfer = Some(SignedDoc::from_parts(b"{}", &[0; 64]));
    assert_eq!(bad_transfer.check(&cx(None)).unwrap_err().status(), 401);
}

#[test]
fn test_decide_start() {
    let current = CurrentImport {
        manifest_hash: [1; 32],
        activated: false,
        freeze_issued_at: 10,
    };
    assert!(decide_start(None, &[1; 32], 10).unwrap());
    assert!(!decide_start(Some(current), &[1; 32], 0).unwrap());
    assert!(decide_start(Some(current), &[2; 32], 11).unwrap());
    assert!(decide_start(Some(current), &[2; 32], 10).is_err());
    let activated = CurrentImport {
        activated: true,
        ..current
    };
    assert!(decide_start(Some(activated), &[2; 32], 11).is_err());
}

#[test]
fn test_abort_at_next() {
    let f = fixture();
    let unfreeze = Unfreeze::sign(&identity(), &f.freeze.hash());
    assert_eq!(
        check_abort_at_next(&unfreeze, &f.id, false, None).unwrap(),
        f.freeze.hash()
    );
    assert_eq!(
        check_abort_at_next(&unfreeze, &f.id, false, Some(&f.freeze.hash())).unwrap(),
        f.freeze.hash()
    );
    let status = |r: Result<[u8; 32], Refusal>| r.unwrap_err().status();
    assert_eq!(
        status(check_abort_at_next(&unfreeze, &f.id, true, None)),
        409
    );
    assert_eq!(
        status(check_abort_at_next(&unfreeze, &f.id, false, Some(&[3; 32]))),
        409
    );
    let other = IdentityKey::from_secret([7; 32]).public();
    assert_eq!(
        status(check_abort_at_next(&unfreeze, &other, false, None)),
        401
    );
    let answer = crate::records::DiscardAnswer::sign(&next_key(), &f.id, &f.freeze.hash());
    let carrying = unfreeze.clone().with_discarded(answer);
    assert_eq!(
        status(check_abort_at_next(&carrying, &f.id, false, None)),
        400
    );
}

// ---- The activation ----

#[test]
fn test_activation_imports_the_account() {
    let f = fixture();
    let import = f.run().unwrap();
    let app_id = app().app_id_bytes();
    assert_eq!(
        (import.seq, import.generation, import.last_time),
        (7, 1, f.now)
    );
    assert_eq!(import.chain.len(), 6);
    assert_eq!(import.reachable, [app_id]);
    assert_eq!(import.app_added_at, [(app_id, 1)]);
    assert_eq!(import.records[0].state.version, RecordVersion::new(1, 4));
    let claim: &Claim = &import.claims[0].claim;
    assert_eq!(
        (claim.step, claim.creator, claim.last_entry),
        (1, Some(app_id), Some(START + 3_000))
    );
    assert_eq!(import.batches.len(), 3);
    // Without trusted time, it waits.
    let waits = activate(
        &Activation {
            manifest: &f.manifest,
            freeze: &f.freeze,
            enrolled: &f.doc,
            now: None,
            uploads: &f.uploads,
            revoked_apps: &[],
        },
        &f.parts,
    );
    refused(waits, ErrorCode::Unavailable, "trusted time");
    // The enrollment's revoked apps stay tombstones; one the export lacks is added.
    let revoked = [app_id, other_app().app_id_bytes()];
    let held = activate(
        &Activation {
            manifest: &f.manifest,
            freeze: &f.freeze,
            enrolled: &f.doc,
            now: Some(f.now),
            uploads: &f.uploads,
            revoked_apps: &revoked,
        },
        &f.parts,
    )
    .unwrap();
    assert_eq!(held.apps.len(), 2);
    assert!(held.apps.iter().all(|a| a.revoked && a.is_tombstone()));
    assert!(held.reachable.is_empty() && held.app_added_at.is_empty());
}

#[test]
fn test_activation_reads_and_orders_the_parts() {
    let f = fixture();
    let manifest = f.resign(|b| b.parts += 1);
    refused(
        f.run_manifest(&manifest, &f.parts),
        ErrorCode::BadRequest,
        "number of parts",
    );
    let swapped = f.with(|p| p.swap(2, 3));
    refused(f.run_with(&swapped), ErrorCode::BadRequest, "out of order");
    let overlapping = f.with(|p| {
        let ai = p.iter().position(|x| x.kind() == "app").unwrap();
        for (i, (first, last)) in [(1, 2), (2, 3)].into_iter().enumerate() {
            p.insert(
                ai + 1 + i,
                Part::KeyBundle(KeyBundlePart {
                    app_id: app().app_id_bytes(),
                    bundle: KeyBundle::from_parts(vec![1], [1; 64]),
                    seq: 2,
                    first_epoch: first,
                    last_epoch: last,
                }),
            );
        }
    });
    refused(
        f.run_with(&overlapping),
        ErrorCode::BadRequest,
        "key_bundle parts",
    );
}

#[test]
fn test_activation_identity_and_heads() {
    let f = fixture();
    let mut bad_sig = f.parts.clone();
    if let Part::Meta(m) = &mut bad_sig[0] {
        m.identity.sig = b64(&[0; 64]);
    }
    refused(f.run_with(&bad_sig), ErrorCode::BadSignature, "");
    // Enrolled with a later version, the export's is behind it.
    let mut later = f.doc.body().clone();
    later.version = 2;
    let enrolled = IdentityDoc::sign(&identity(), later.clone()).unwrap();
    let behind = activate(
        &Activation {
            manifest: &f.manifest,
            freeze: &f.freeze,
            enrolled: &enrolled,
            now: Some(f.now),
            uploads: &f.uploads,
            revoked_apps: &[],
        },
        &f.parts,
    );
    refused(behind, ErrorCode::Conflict, "goes back on the enrolled one");
    // The same version, other bytes.
    let mut same = f.doc.body().clone();
    same.data_epoch = 1;
    same.signer = [8; 16];
    let other = IdentityDoc::sign(&identity(), same).unwrap();
    let differs = activate(
        &Activation {
            manifest: &f.manifest,
            freeze: &f.freeze,
            enrolled: &other,
            now: Some(f.now),
            uploads: &f.uploads,
            revoked_apps: &[],
        },
        &f.parts,
    );
    assert!(differs.is_err());
    // The head and the checkpoint are the old service's, the checkpoint before the head.
    let mut head = f.manifest.body().head;
    head.sig = [0; 64];
    refused(
        f.run_manifest(&f.resign(|b| b.head = head), &f.parts),
        ErrorCode::BadSignature,
        "the head",
    );
    let tip = |index: usize, seq: u64, generation: u64| ChainTip {
        generation,
        seq,
        chain_hash: f.stubs[index].chain_hash,
    };
    let mut cp = SignedHead::sign(&old_key(), &f.id, &tip(1, 2, 1));
    cp.sig = [0; 64];
    refused(
        f.run_manifest(&f.resign(|b| b.checkpoint = Some(cp)), &f.parts),
        ErrorCode::BadSignature,
        "the checkpoint",
    );
    // At the head, or of a later generation.
    for c in [tip(5, 7, 1), tip(1, 2, 2)] {
        let cp = SignedHead::sign(&old_key(), &f.id, &c);
        let m = f.resign(|b| b.checkpoint = Some(cp));
        refused(
            f.run_manifest(&m, &f.parts),
            ErrorCode::Conflict,
            "the checkpoint isn't",
        );
    }
    // The meta part's generation and seq are the head's.
    let mut parts = f.parts.clone();
    if let Part::Meta(m) = &mut parts[0] {
        m.seq = 5;
    }
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "the meta part's generation or seq",
    );
}

#[test]
fn test_activation_chain_rules() {
    let f = fixture();
    // A document that isn't its stub's.
    let parts = f.with(|p| {
        let doc = chain_mut(p, 3).doc.clone();
        chain_mut(p, 2).doc = doc;
    });
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "the chain part at seq 2",
    );
    // A stub missing from the chain: the link breaks.
    let parts = f.with(|p| p.retain(|x| !matches!(x, Part::Chain(c) if c.seq == 4)));
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "the chain part at seq 6",
    );
    // A chain that doesn't end at the head.
    let tip = ChainTip {
        generation: 1,
        seq: 6,
        chain_hash: f.stubs[4].chain_hash,
    };
    let early = f.resign(|b| b.head = SignedHead::sign(&old_key(), &f.id, &tip));
    refused(
        f.run_manifest(&early, &f.parts),
        ErrorCode::Conflict,
        "the meta part's generation or seq",
    );
    let parts = f.with(|p| {
        if let Part::Meta(m) = &mut p[0] {
            m.seq = 6;
        }
    });
    refused(
        f.run_manifest(
            &f.resign(|b| {
                b.head = SignedHead::sign(&old_key(), &f.id, &tip);
                b.parts = parts.len() as u64
            }),
            &parts,
        ),
        ErrorCode::Conflict,
        "doesn't end at the manifest's head",
    );
    // The freeze transition's document dropped, or the manifest naming another freeze.
    let parts = f.with(|p| chain_mut(p, 7).doc = None);
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "its document was dropped",
    );
    let other = f.resign(|b| b.freeze_hash = [3; 32]);
    refused(
        f.run_manifest(&other, &f.parts),
        ErrorCode::Conflict,
        "names another freeze",
    );
    // `last_time` before the transition's `at`, or ahead of this service's time.
    let early = f.resign(|b| b.last_time -= 1);
    refused(
        f.run_manifest(&early, &f.parts),
        ErrorCode::Conflict,
        "last_time is before",
    );
    let mut late = f.clone();
    late.now = f.now - crate::records::CLOCK_TOLERANCE_MS;
    late.run().unwrap();
    late.now -= 1;
    refused(
        late.run(),
        ErrorCode::Conflict,
        "ahead of this service's time",
    );
}

#[test]
fn test_activation_newest_identity_item() {
    let f = fixture();
    let mut v2 = f.doc.body().clone();
    v2.version = 2;
    let newer = IdentityDoc::sign(&identity(), v2).unwrap();
    let parts = f.with(|p| {
        if let Part::Meta(m) = &mut p[0] {
            m.identity = newer.signed().clone();
        }
    });
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "newest identity item",
    );
}

#[test]
fn test_activation_uploaded_heads() {
    let mut f = fixture();
    let app_id = app().app_id_bytes();
    let head_at = |seq: u64, hash: [u8; 32]| UploadedHead {
        app_id,
        head: SignedHead::sign(
            &old_key(),
            &f.id,
            &ChainTip {
                generation: 1,
                seq,
                chain_hash: hash,
            },
        ),
    };
    f.uploads.heads = vec![
        head_at(3, f.stubs[2].chain_hash),
        head_at(7, f.stubs[5].chain_hash),
    ];
    f.run().unwrap();
    f.uploads.heads = vec![head_at(3, [7; 32])];
    refused(f.run(), ErrorCode::Conflict, "isn't on the imported chain");
    f.uploads.heads = vec![head_at(8, [7; 32])];
    refused(f.run(), ErrorCode::Conflict, "isn't on the imported chain");
    // With a checkpoint at 3, a head before it is ignored, one at it is checked.
    let checkpoint = SignedHead::sign(
        &old_key(),
        &f.id,
        &ChainTip {
            generation: 1,
            seq: 3,
            chain_hash: f.stubs[2].chain_hash,
        },
    );
    let mut after: Vec<Part> = f.parts.clone();
    after.retain(|p| !matches!(p, Part::Chain(c) if c.seq <= 3));
    let m = f.resign(|b| {
        b.checkpoint = Some(checkpoint);
        b.parts = after.len() as u64
    });
    f.uploads.heads = vec![head_at(1, [7; 32])];
    f.run_manifest(&m, &after).unwrap();
    f.uploads.heads = vec![head_at(3, [7; 32])];
    refused(
        f.run_manifest(&m, &after),
        ErrorCode::Conflict,
        "isn't on the imported chain",
    );
    f.uploads.heads = vec![head_at(3, f.stubs[2].chain_hash)];
    f.run_manifest(&m, &after).unwrap();
    // The chain parts must start right after the checkpoint.
    let mut gap = after.clone();
    gap.retain(|p| !matches!(p, Part::Chain(c) if c.seq == 4));
    let mg = f.resign(|b| {
        b.checkpoint = Some(checkpoint);
        b.parts = gap.len() as u64
    });
    f.uploads.heads.clear();
    refused(
        f.run_manifest(&mg, &gap),
        ErrorCode::Conflict,
        "the chain part at seq 6",
    );
}

#[test]
fn test_activation_apps() {
    let f = fixture();
    // Every listed app has a part.
    let parts = f.with(|p| p.retain(|x| x.kind() != "app"));
    refused(f.run_with(&parts), ErrorCode::Conflict, "no app part");
    // A record of another app.
    let other = other_app();
    let other_record = AppRecord::sign(
        &other,
        AppRecordBody::new(&cert_of(&other), Vec::new(), START),
    )
    .unwrap();
    let parts = f.with(|p| app_mut(p).record = Some(other_record.signed().clone()));
    refused(f.run_with(&parts), ErrorCode::BadRequest, "another app's");
    // Receive keys out of order, not the chain item, or not the chain's newest.
    let parts = f.with(|p| {
        let a = app_mut(p);
        let k = a.receive_keys[0].clone();
        a.receive_keys.push(k);
    });
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "increasing n and seq",
    );
    let parts = f.with(|p| app_mut(p).receive_keys[0].1 = 4);
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "isn't that chain item",
    );
    let parts = f.with(|p| app_mut(p).receive_keys.clear());
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "isn't the chain's newest",
    );
    let parts = f.with(|p| app_mut(p).record = None);
    refused(
        f.run_with(&parts),
        ErrorCode::BadRequest,
        "without a record",
    );
    // A key bundle part without the identity's signature.
    let parts = f.with(|p| {
        let ai = p.iter().position(|x| x.kind() == "app").unwrap();
        p.insert(
            ai + 1,
            Part::KeyBundle(KeyBundlePart {
                app_id: app().app_id_bytes(),
                bundle: KeyBundle::from_parts(vec![1], [1; 64]),
                seq: 2,
                first_epoch: 1,
                last_epoch: 1,
            }),
        );
    });
    refused(
        f.run_with(&parts),
        ErrorCode::BadSignature,
        "a key bundle part",
    );
    // A renewed certificate of another app.
    let parts = f.with(|p| app_mut(p).renewed_cert = Some((cert_of(&other).signed().clone(), 4)));
    refused(
        f.run_with(&parts),
        ErrorCode::BadRequest,
        "renewed certificate",
    );
}

#[test]
fn test_activation_revoke_in_chain_marks_the_app() {
    // A revoke transition before the freeze makes the app revoked, whatever its part says.
    let f = fixture();
    let import = f.run().unwrap();
    assert!(!import.apps[0].revoked);
    let mut part = f.parts[f.index("app")].clone();
    if let Part::App(a) = &mut part {
        a.revoked_at_ms = Some(START);
    }
    let parts = f.with(|p| {
        let ai = p.iter().position(|x| x.kind() == "app").unwrap();
        p[ai] = part;
    });
    let import = f.run_with(&parts).unwrap();
    assert!(import.apps[0].revoked);
    assert!(import.reachable.is_empty());
}

#[test]
fn test_activation_records() {
    let f = fixture();
    // The op carried as well, the same bytes, imports; other bytes don't.
    let op4 = match &f.parts[4] {
        Part::Chain(c) => c.doc.clone(),
        _ => unreachable!(),
    };
    let parts = f.with(|p| record_mut(p).op = op4.clone());
    f.run_with(&parts).unwrap();
    let op5 = match &f.parts[5] {
        Part::Chain(c) => c.doc.clone(),
        _ => unreachable!(),
    };
    let parts = f.with(|p| record_mut(p).op = op5);
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "its op isn't the chain item at its seq",
    );
    let parts = f.with(|p| chain_mut(p, 4).doc = None);
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "op is null and no chain part",
    );
    // The writer's certificate: named, or the app part's; another app's doesn't verify.
    let parts = f.with(|p| record_mut(p).cert = Some(f.cert.signed().clone()));
    f.run_with(&parts).unwrap();
    let parts = f.with(|p| record_mut(p).cert = Some(cert_of(&other_app()).signed().clone()));
    refused(f.run_with(&parts), ErrorCode::BadSignature, "");
    // Members that aren't the operation's.
    for change in [
        (|r: &mut RecordEntry| r.size += 1) as fn(&mut RecordEntry),
        |r| r.deleted = true,
        |r| r.read_scope = "scope-b".into(),
        |r| r.collection = [3; 32],
        |r| r.generation = 2,
    ] {
        let parts = f.with(|p| change(record_mut(p)));
        refused(
            f.run_with(&parts),
            ErrorCode::Conflict,
            "isn't its operation's",
        );
    }
    let parts = f.with(|p| record_mut(p).version = 5);
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "the full chain item at its seq",
    );
    // The proof: missing, another write's, or signed by another key.
    let parts = f.with(|p| record_mut(p).proof = None);
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "no proof of its current write",
    );
    let parts = f.with(|p| record_mut(p).proof = Some(f.claim_proof.signed().clone()));
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "isn't the proof of its current write",
    );
    let mut forged = f.record_proof.clone();
    forged.sig = f.claim_proof.signed().sig.clone();
    let parts = f.with(|p| record_mut(p).proof = Some(forged));
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "doesn't verify with generation 1's",
    );
    // From an upload, a record of this generation, or one carrying a proof.
    let parts = f.with(|p| record_mut(p).from_upload = true);
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "isn't of an earlier generation",
    );
    // A record.put the chain holds with its document that isn't current: the record part gone.
    let parts = f.with(|p| p.retain(|x| x.kind() != "record"));
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "isn't its key's current write",
    );
}

#[test]
fn test_activation_claims() {
    let f = fixture();
    let app_id = app().app_id_bytes();
    let other = other_app().app_id_bytes();
    for (rule, change) in [
        (
            "its creator",
            (|c: &mut ClaimState| c.creator = Some([9; 16])) as fn(&mut ClaimState),
        ),
        ("its creator", |c| c.creator = None),
        ("its last_entry_ms", |c| {
            c.last_entry_ms = Some(START + 2_999)
        }),
        ("its last_entry_ms", |c| c.last_entry_ms = None),
        ("its step", |c| c.step = 2),
        ("its state isn't the state its entries give", |c| {
            c.current = None
        }),
        ("its state isn't the state its entries give", |c| {
            c.attempts[0].outcome = Outcome::Failed
        }),
        ("its state isn't the state its entries give", |c| {
            c.settled = true
        }),
        ("its state isn't the state its entries give", |c| {
            c.attempts[0].deadline_ms = None
        }),
        ("its state isn't the state its entries give", |c| {
            c.pinned_deadline = Pin::NoDeadline
        }),
    ] {
        let parts = f.with(|p| change(claim_mut(p)));
        refused(f.run_with(&parts), ErrorCode::Conflict, rule);
    }
    // No entries, unless rebuilt; a rebuilt claim counts for its first attempt's owner.
    let ci = f.index("claim");
    let parts = f.with(|p| {
        p.remove(ci + 1);
    });
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "a live claim without entries",
    );
    let parts = f.with(|p| {
        p.remove(ci + 1);
        claim_mut(p).rebuilt = true;
    });
    f.run_with(&parts).unwrap();
    let parts = f.with(|p| {
        p.remove(ci + 1);
        let c = claim_mut(p);
        c.rebuilt = true;
        c.creator = Some(other);
    });
    refused(f.run_with(&parts), ErrorCode::Conflict, "its creator");
    // An entry's proof: forged, another entry's, or not the chain item.
    let parts = f.with(|p| {
        if let Part::ClaimEntry(e) = &mut p[ci + 1] {
            e.proof.sig = b64(&[0; 64]);
        }
    });
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "doesn't verify with the old service's key",
    );
    let parts = f.with(|p| {
        if let Part::ClaimEntry(e) = &mut p[ci + 1] {
            e.proof = f.record_proof.clone();
        }
    });
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "isn't that entry's",
    );
    let parts = f.with(|p| {
        if let Part::ClaimEntry(e) = &mut p[ci + 1] {
            e.step = 1;
        }
    });
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "isn't that entry's",
    );
    let _ = app_id;
}

#[test]
fn test_activation_tombstones_entries_and_batches() {
    let f = fixture();
    let app_id = app().app_id_bytes();
    let tomb = |creator| {
        Part::Tombstone(TombstonePart {
            claim_key: [30; 32],
            tombstone: TombstoneState {
                step: 2,
                attempts: vec![AttemptState {
                    attempt_id: [31; 16],
                    owner: app_id,
                    outcome: Outcome::Done,
                    opened_at_ms: START,
                    orphan_after_s: 60,
                    possibly_duplicate: false,
                    duplicate: false,
                    deadline_ms: None,
                    from_upload: false,
                    resolved_by: Some(app_id),
                }],
                deadline_ms: None,
                creator,
                last_entry_ms: Some(START + 1),
            },
        })
    };
    let mut parts = f.parts.clone();
    parts.push(tomb(Some(app_id)));
    let import = f.run_with(&sorted(parts)).unwrap();
    assert_eq!(import.tombstones.len(), 1);
    assert!(import.tombstones[0].claim.tombstone);
    let mut parts = f.parts.clone();
    parts.push(tomb(Some([9; 16])));
    refused(
        f.run_with(&sorted(parts)),
        ErrorCode::Conflict,
        "a tombstone's creator",
    );
    // Inbox entries: at a seq the old service gave an entry, not a chain item's or later.
    let entry = |seq| {
        Part::Entry(EntryPart {
            seq,
            sender: f.id,
            cert: f.cert.signed().clone(),
            accepted_at_ms: START,
            context: Value::Null,
            envelope: Vec::new(),
            targets: vec![app_id],
            result: EntryResult {
                entry_id: [2; 16],
                accepted_at: START,
                directory_version: 1,
            },
            unreadable: true,
            missed: None,
        })
    };
    let mut parts = f.parts.clone();
    parts.push(entry(5));
    let import = f.run_with(&sorted(parts)).unwrap();
    assert_eq!(import.entries.len(), 1);
    for seq in [6, 8] {
        let mut parts = f.parts.clone();
        parts.push(entry(seq));
        refused(
            f.run_with(&sorted(parts)),
            ErrorCode::Conflict,
            "isn't at a seq",
        );
    }
    // Every batch a kept stub names has its part.
    let parts = f.with(|p| p.retain(|x| x.kind() != "batch"));
    refused(
        f.run_with(&parts),
        ErrorCode::Conflict,
        "without its batch part",
    );
}

#[test]
fn test_activation_evidence() {
    let mut f = fixture();
    let app_id = app().app_id_bytes();
    let upload = |proof: TransitionProof| UploadedProof { app_id, proof };
    // The record's and the attempt's own proofs hold.
    let record_proof = TransitionProof::peek(&f.record_proof).unwrap();
    f.uploads.proofs = vec![upload(record_proof.clone()), upload(f.claim_proof.clone())];
    f.run().unwrap();
    // Without the claim, the attempt's evidence fails; without the record, so does its.
    let no_claim: Vec<Part> = f
        .parts
        .iter()
        .filter(|p| !matches!(p.kind(), "claim" | "claim_entry"))
        .cloned()
        .collect();
    f.uploads.proofs = vec![upload(f.claim_proof.clone())];
    refused(
        f.run_with(&no_claim),
        ErrorCode::Conflict,
        "a claim with an attempt",
    );
    // A SETTLED proof: the claim held settled, or as a tombstone, unless the old service
    // may have deleted it by `last_time`.
    let settled = |deadline: Option<u64>| {
        let claim = Claim {
            step: 2,
            settled: true,
            pin: deadline.map_or(Pin::NoDeadline, Pin::At),
            ..Claim::default()
        };
        let view = claim.view(&CLAIM_KEY, START, &|_| true);
        TransitionProof::sign(
            &old_key(),
            &f.id,
            ProofBody::new(
                f.stubs[4].clone(),
                b64(&CLAIM_KEY),
                &ProofState::Claim(view.to_value()),
            ),
        )
        .unwrap()
    };
    f.uploads.proofs = vec![upload(settled(Some(START + DAY)))];
    refused(f.run(), ErrorCode::Conflict, "SETTLED");
    let window = crate::claims::RECONCILIATION_MS;
    f.uploads.proofs = vec![upload(settled(Some(f.now - window)))];
    f.run().unwrap();
    f.uploads.proofs = vec![upload(settled(Some(f.now - window + 1)))];
    refused(f.run(), ErrorCode::Conflict, "SETTLED");
    f.uploads.proofs = vec![upload(settled(None))];
    refused(f.run(), ErrorCode::Conflict, "SETTLED");
    // A record proof of a delete holds with the record absent; of a write it doesn't.
    let deleted = TransitionProof::sign(
        &old_key(),
        &f.id,
        ProofBody::new(
            f.stubs[3].clone(),
            b64(&[3; 32]),
            &ProofState::Record {
                version: RecordVersion::new(1, 4),
                deleted: true,
            },
        ),
    )
    .unwrap();
    f.uploads.proofs = vec![upload(deleted)];
    f.run().unwrap();
    let absent = TransitionProof::sign(
        &old_key(),
        &f.id,
        ProofBody::new(
            f.stubs[3].clone(),
            b64(&[3; 32]),
            &ProofState::Record {
                version: RecordVersion::new(1, 4),
                deleted: false,
            },
        ),
    )
    .unwrap();
    f.uploads.proofs = vec![upload(absent)];
    refused(f.run(), ErrorCode::Conflict, "a record at a version");
}

#[test]
fn test_activation_peers_and_floors() {
    let f = fixture();
    let peer_key = IdentityKey::from_secret([40; 32]);
    let peer = IdentityDoc::sign(
        &peer_key,
        IdentityBody::first(
            peer_key.public(),
            [1; 16],
            Inbox::new(OLD, [2; 32]),
            IdentityPolicy::default(),
        ),
    )
    .unwrap();
    let floor = |identity| {
        Part::PeerFloor(PeerFloorPart {
            identity,
            version: 1,
            generation: 1,
            body_hash: [4; 32],
        })
    };
    let mut parts = f.parts.clone();
    parts.push(Part::Peer(PeerPart {
        doc: peer.signed().clone(),
    }));
    parts.push(floor(f.id));
    let import = f.run_with(&sorted(parts)).unwrap();
    assert_eq!(import.peers.len(), 1);
    let mut parts = f.parts.clone();
    parts.push(Part::Peer(PeerPart {
        doc: peer.signed().clone(),
    }));
    parts.push(floor(peer_key.public()));
    refused(
        f.run_with(&sorted(parts)),
        ErrorCode::BadRequest,
        "a peer_floor beside a peer part",
    );
    let mut forged = peer.signed().clone();
    forged.sig = b64(&[0; 64]);
    let mut parts = f.parts.clone();
    parts.push(Part::Peer(PeerPart { doc: forged }));
    refused(f.run_with(&sorted(parts)), ErrorCode::BadSignature, "");
}
