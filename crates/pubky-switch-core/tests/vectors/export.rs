//! `export.json`: a complete export of alice's account (Switch wire 10.2, 10.3), its
//! manifest signed with the fixed service key, which activates under Switch wire 10.5 at a
//! next service enrolled with her version 3 at the freeze's time, and the record and claim
//! parts a faulty old service could send instead, each refused at the activation.
//!
//! The chunk is read part by part and every part written again, byte for byte; the parts are
//! packed again into the chunk, the manifest rebuilt over it and signed again with the fixed
//! key. What the export shares with `chain.json`, `documents.json` and `http.json` is
//! compared with those files.

use ed25519_dalek::SigningKey;
use pubky_switch_core::chain::{SignedHead, Stub, TransitionProof};
use pubky_switch_core::enc::{app_id_decode, b64 as b64e, hash};
use pubky_switch_core::export::{
    Activation, Chunk, ChunkAnswer, DEFAULT_CHUNK_TARGET, ExportCaller, ExportRead, Import,
    MAX_IMPORT_BYTES, Manifest, ManifestBody, Part, UploadedHead, UploadedProof, Uploads, activate,
    pack,
};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::labels;
use pubky_switch_core::ops::Refusal;
use pubky_switch_core::records::{CLOCK_TOLERANCE_MS, ExportTransfer, Freeze, IdentityDoc};
use pubky_switch_core::sig::SignedDoc;
use serde_json::{Value, json};

use crate::common::*;

/// What the activation of the vector's export compares with.
struct Fixture {
    alice: [u8; 32],
    o_key: [u8; 32],
    o_secret: SigningKey,
    manifest: Manifest,
    chunk: Vec<u8>,
    parts: Vec<Part>,
    freeze: Freeze,
    enrolled: IdentityDoc,
}

impl Fixture {
    fn load() -> Self {
        let keys = keys();
        let v = load("export.json");
        let alice = keys.identity("alice");
        let o_key = b64n::<32>(st(&v, "service_key"));
        let signed: SignedDoc = serde_json::from_value(v["manifest"]["signed"].clone()).unwrap();
        let manifest = Manifest::verify(&signed, &o_key, &alice).unwrap();
        let chunk = st(&v["chunks"][0], "json").as_bytes().to_vec();
        let parts = manifest.read_parts(&[&chunk]).unwrap();
        Self {
            alice,
            o_key,
            o_secret: SigningKey::from_bytes(&keys.secret(&o_key).unwrap()),
            manifest,
            chunk,
            parts,
            freeze: Freeze::verify(&document("alice freeze"), &alice).unwrap(),
            enrolled: IdentityDoc::verify(&document("alice identity.json"), &alice).unwrap(),
        }
    }

    fn run(
        &self,
        manifest: &Manifest,
        parts: &[Part],
        uploads: &Uploads,
        now: u64,
    ) -> Result<Import, Refusal> {
        activate(
            &Activation {
                manifest,
                freeze: &self.freeze,
                enrolled: &self.enrolled,
                now: Some(now),
                uploads,
                revoked_apps: &[],
            },
            parts,
        )
    }

    /// The activation of `parts` under the vector's manifest, its part count changed to
    /// theirs and signed again with the fixed key.
    fn run_parts(&self, parts: &[Part]) -> Result<Import, Refusal> {
        let manifest = self.resign(|b| b.parts = parts.len() as u64);
        self.run(&manifest, parts, &Uploads::default(), self.now())
    }

    fn now(&self) -> u64 {
        self.manifest.body().last_time
    }

    /// The vector's manifest, changed and signed again with the fixed key.
    fn resign(&self, change: impl FnOnce(&mut ManifestBody)) -> Manifest {
        let mut body = self.manifest.body().clone();
        change(&mut body);
        Manifest::sign(&self.o_secret, body).unwrap()
    }

    fn index(&self, kind: &str) -> usize {
        self.parts.iter().position(|p| p.kind() == kind).unwrap()
    }
}

fn refused(result: Result<Import, Refusal>, code: ErrorCode, rule: &str) {
    let error = result.expect_err(rule);
    assert_eq!(error.code, code, "{rule}: {error}");
    assert!(error.reason.contains(rule), "{rule}: {error}");
}

#[test]
fn test_vectors_export() {
    let f = Fixture::load();
    check_manifest(&f);
    check_parts_byte_for_byte(&f);
    let import = check_activation(&f);
    check_record_rejections(&f);
    check_claim_rejections(&f);
    check_activation_rules(&f);
    check_uploads(&f);
    check_chain_cross(&f, &import);
    check_documents_cross(&f);
    check_http_cross(&f);
}

/// The manifest (Switch wire 10.2): a signed document under the fixed service key, its
/// signature reproduced, bound to documents.json's freeze, its chunk list well formed.
fn check_manifest(f: &Fixture) {
    let keys = keys();
    let m = &load("export.json")["manifest"];
    assert_eq!(st(m, "label"), labels::sig::EXPORT_MANIFEST);
    let signed = f.manifest.signed();
    assert_eq!(signed.body_bytes().unwrap(), st(m, "body").as_bytes());
    assert_eq!(signed.compact(), st(m, "compact"));
    assert_eq!(
        hex::encode(signed.doc_bytes().unwrap()),
        st(m, "doc_bytes_hex")
    );
    assert_eq!(
        b64e(&f.manifest.hash()),
        st(m, "doc_hash"),
        "the manifest hash"
    );
    assert!(reproduce(
        &keys,
        &f.o_key,
        labels::sig::EXPORT_MANIFEST,
        &[&f.alice, st(m, "body").as_bytes()],
        &signed.sig_bytes().unwrap(),
    ));
    assert_eq!(
        f.o_key,
        keys.service_key(&pubky_switch_core::enc::pubky_id(&f.alice))
    );
    // Only the old service's key verifies it, for alice only.
    let bob = keys.identity("bob");
    assert!(matches!(
        Manifest::verify(
            signed,
            &keys.service_key(&pubky_switch_core::enc::pubky_id(&bob)),
            &f.alice
        ),
        Err(pubky_switch_core::Error::Signature(_))
    ));
    assert!(Manifest::verify(signed, &f.o_key, &bob).is_err());
    // Bound to the move, its chunk list well formed (Switch wire 10.4 steps 5 and 6).
    f.manifest
        .check_binding(&f.alice, &f.freeze, &f.enrolled)
        .unwrap();
    f.manifest.check_chunks(MAX_IMPORT_BYTES).unwrap();
    let body = f.manifest.body();
    assert_eq!(body.chunks.len(), 1);
    assert_eq!(body.chunks[0].id, "00000");
    assert!(
        body.checkpoint.is_none(),
        "the chain parts start at 32 zero bytes"
    );
    let more = f.resign(|b| b.bytes += 1);
    assert_eq!(
        more.check_chunks(MAX_IMPORT_BYTES).unwrap_err().status(),
        400
    );
    assert_eq!(more.check_chunks(0).unwrap_err().status(), 400);
    assert_eq!(f.manifest.check_chunks(1000).unwrap_err().status(), 413);
    let skipped = f.resign(|b| b.next_generation = 3);
    assert_eq!(
        skipped
            .check_binding(&f.alice, &f.freeze, &f.enrolled)
            .unwrap_err()
            .status(),
        400
    );
    // The chunk: its length and hash are the manifest's (Switch wire 10.4).
    let c = &load("export.json")["chunks"][0];
    assert_eq!(f.chunk.len() as u64, int(c, "len"));
    assert_eq!(b64e(&hash(&f.chunk)), st(c, "hash"));
    f.manifest.check_chunk("00000", &f.chunk).unwrap();
    let mut tampered = f.chunk.clone();
    tampered[20] ^= 1;
    let error = f.manifest.check_chunk("00000", &tampered).unwrap_err();
    assert_eq!(error.status(), 409);
    assert_eq!(error.current.unwrap()["chunk"]["id"], "00000");
    assert_eq!(
        f.manifest.check_chunk("00001", b"{}").unwrap_err().status(),
        404
    );
    assert_eq!(f.manifest.missing(|id| id == "00000"), Vec::<String>::new());
    assert_eq!(f.manifest.missing(|_| false), ["00000"]);
}

/// Every part written again, byte for byte; the parts packed again into the chunk; and the
/// manifest rebuilt over it and signed again with the fixed key (Switch wire 10.2, 10.3).
fn check_parts_byte_for_byte(f: &Fixture) {
    let value: Value = serde_json::from_slice(&f.chunk).unwrap();
    let raw = arr(&value, "parts");
    assert_eq!(raw.len(), f.parts.len());
    assert_eq!(f.parts.len(), 19);
    let mut written = Vec::new();
    for (part, raw) in f.parts.iter().zip(raw) {
        assert_eq!(part.kind(), st(raw, "part"));
        let bytes = part.to_json().unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            *raw,
            "{}",
            part.kind()
        );
        assert_eq!(Part::read(raw).unwrap(), *part, "{}", part.kind());
        written.push(bytes);
    }
    let chunk = Chunk::parse(&f.chunk).unwrap();
    assert_eq!((chunk.index, chunk.first), (0, 0));
    assert_eq!(
        chunk.to_json().unwrap(),
        f.chunk,
        "the chunk, byte for byte"
    );
    let packed = pack(&f.parts, DEFAULT_CHUNK_TARGET).unwrap();
    assert_eq!(packed.len(), 1);
    assert_eq!(packed[0].1, f.chunk);
    assert_eq!(packed[0].0, f.manifest.body().chunks[0]);
    let m = f.manifest.body();
    let body = ManifestBody::new(
        m.identity,
        m.freeze_hash,
        m.generation,
        m.last_time,
        m.head,
        m.checkpoint,
        packed.into_iter().map(|(r, _)| r).collect(),
    )
    .unwrap();
    assert_eq!(&body, m);
    let signed = Manifest::sign(&f.o_secret, body).unwrap();
    assert_eq!(
        signed.signed(),
        f.manifest.signed(),
        "the manifest, signed again"
    );
    // Packed to a smaller chunk size, the same parts make more chunks, in order.
    let small = pack(&f.parts, 4096).unwrap();
    assert!(small.len() > 1);
    let mut next = 0;
    for (i, (r, bytes)) in small.iter().enumerate() {
        assert_eq!(r.id, format!("{i:05}"));
        assert_eq!(r.first, next);
        assert_eq!(r.len, bytes.len() as u64);
        next = r.last + 1;
        let c = Chunk::parse(bytes).unwrap();
        assert_eq!(c.index, i as u64);
    }
    assert_eq!(next, 19);
}

/// The full activation, at a next service enrolled with alice's version 3 whose trusted time
/// is the freeze's (vectors README, "Export").
fn check_activation(f: &Fixture) -> Import {
    let keys = keys();
    let import = f
        .run(&f.manifest, &f.parts, &Uploads::default(), f.now())
        .unwrap();
    let wallet = app_id_decode(&keys.app("wallet").app_id).unwrap();
    let phone = app_id_decode(&keys.app("phone").app_id).unwrap();
    assert_eq!((import.seq, import.chain.len()), (10, 9));
    assert_eq!(import.identity.version(), f.enrolled.version());
    assert_eq!(import.manifest_hash, f.manifest.hash());
    assert_eq!(import.reachable, [wallet], "the wallet alone is reachable");
    assert_eq!(import.app_added_at, [(wallet, 1)]);
    // Seq 9's revoke makes the phone revoked here, whatever its part says.
    let p = import.apps.iter().find(|a| a.part.app_id == phone).unwrap();
    assert!(p.revoked && p.is_tombstone());
    assert_eq!(import.records.len(), 1);
    assert_eq!(import.records[0].state.version.version, 8);
    assert_eq!(import.claims.len(), 1);
    let claim = &import.claims[0].claim;
    assert_eq!((claim.step, claim.creator), (1, Some(wallet)));
    assert_eq!(claim.last_entry, Some(1_767_225_603_000));
    assert_eq!(import.batches.len(), 3);
    assert_eq!(
        import.freeze_at,
        f.now(),
        "last_time is the freeze transition's time"
    );
    assert!(f.now() > f.freeze.body().issued_at);
    // The enrollment's revoked apps stay tombstones.
    let revoked = [wallet];
    let held = activate(
        &Activation {
            manifest: &f.manifest,
            freeze: &f.freeze,
            enrolled: &f.enrolled,
            now: Some(f.now()),
            uploads: &Uploads::default(),
            revoked_apps: &revoked,
        },
        &f.parts,
    )
    .unwrap();
    let w = held.apps.iter().find(|a| a.part.app_id == wallet).unwrap();
    assert!(w.revoked && w.is_tombstone());
    assert!(held.reachable.is_empty() && held.app_added_at.is_empty());
    // Without trusted time the activation waits.
    let waits = activate(
        &Activation {
            manifest: &f.manifest,
            freeze: &f.freeze,
            enrolled: &f.enrolled,
            now: None,
            uploads: &Uploads::default(),
            revoked_apps: &[],
        },
        &f.parts,
    );
    refused(waits, ErrorCode::Unavailable, "no trusted time");
    import
}

/// `record_rejections`: the record part as a faulty old service could send it, each refused
/// at the activation for its rule (Switch wire 10.5).
fn check_record_rejections(f: &Fixture) {
    let v = load("export.json");
    let ri = f.index("record");
    let cases = arr(&v, "record_rejections");
    assert_eq!(cases.len(), 3);
    for case in cases {
        let name = st(case, "name");
        let rule = match name {
            "no proof" => "no proof of its current write",
            "a proof whose signature doesn't verify with O's key" => {
                "doesn't verify with generation 1's service key"
            }
            "the proof of another write, the record's first (seq 6)" => {
                "isn't the proof of its current write"
            }
            other => panic!("unknown record rejection {other}"),
        };
        assert!(st(case, "rule").contains("wire 10.5"), "{name}");
        let mut parts = f.parts.clone();
        parts[ri] = Part::read(&json!({ "part": "record", "record": case["record"] })).unwrap();
        refused(
            f.run(&f.manifest, &parts, &Uploads::default(), f.now()),
            ErrorCode::Conflict,
            rule,
        );
    }
}

/// `claim_rejections`: the claim part as a faulty old service could send it, each refused at
/// the activation for its rule (Switch wire 6.8, 10.5).
fn check_claim_rejections(f: &Fixture) {
    let v = load("export.json");
    let ci = f.index("claim");
    let cases = arr(&v, "claim_rejections");
    assert_eq!(cases.len(), 2);
    for case in cases {
        let name = st(case, "name");
        let rule = match name {
            "a creator other than the owner of its first attempt" => "its creator",
            "a last_entry_ms before its last entry's time" => "its last_entry_ms",
            other => panic!("unknown claim rejection {other}"),
        };
        let mut parts = f.parts.clone();
        parts[ci] = Part::read(&json!({
            "part": "claim", "claim_key": case["claim_key"], "claim": case["claim"]
        }))
        .unwrap();
        refused(
            f.run(&f.manifest, &parts, &Uploads::default(), f.now()),
            ErrorCode::Conflict,
            rule,
        );
    }
}

/// More of the activation's checks on the vector's export, each refused for its rule.
fn check_activation_rules(f: &Fixture) {
    // The parts in order: two chain parts swapped are refused by the order (400), before
    // the link (409); meta not first is 400.
    let mut swapped = f.parts.clone();
    swapped.swap(2, 3);
    refused(f.run_parts(&swapped), ErrorCode::BadRequest, "out of order");
    let mut swapped = f.parts.clone();
    swapped.swap(0, 1);
    refused(
        f.run_parts(&swapped),
        ErrorCode::BadRequest,
        "only the first, is meta",
    );
    // A document that isn't its stub's.
    let mut parts = f.parts.clone();
    let doc3 = match &parts[3] {
        Part::Chain(c) => c.doc.clone(),
        _ => unreachable!(),
    };
    if let Part::Chain(c) = &mut parts[2] {
        c.doc = doc3;
    }
    refused(
        f.run_parts(&parts),
        ErrorCode::Conflict,
        "the chain part at seq",
    );
    // Every batch a kept stub names has its part.
    let without: Vec<Part> = f
        .parts
        .iter()
        .filter(|p| p.kind() != "batch")
        .cloned()
        .collect();
    refused(
        f.run_parts(&without),
        ErrorCode::Conflict,
        "without its batch part",
    );
    // The freeze transition's document dropped.
    let mut parts = f.parts.clone();
    if let Part::Chain(c) = &mut parts[9] {
        c.doc = None;
    }
    refused(
        f.run_parts(&parts),
        ErrorCode::Conflict,
        "isn't the freeze transition",
    );
    // A manifest naming another freeze.
    let other = f.resign(|b| b.freeze_hash = [7; 32]);
    refused(
        f.run(&other, &f.parts, &Uploads::default(), f.now()),
        ErrorCode::Conflict,
        "names another freeze",
    );
    // `last_time` 1 ms before the transition's `at`.
    let early = f.resign(|b| b.last_time -= 1);
    refused(
        f.run(&early, &f.parts, &Uploads::default(), f.now()),
        ErrorCode::Conflict,
        "last_time is before",
    );
    // Up to the clock tolerance ahead of this service's time imports; 1 ms more doesn't.
    f.run(
        &f.manifest,
        &f.parts,
        &Uploads::default(),
        f.now() - CLOCK_TOLERANCE_MS,
    )
    .unwrap();
    refused(
        f.run(
            &f.manifest,
            &f.parts,
            &Uploads::default(),
            f.now() - CLOCK_TOLERANCE_MS - 1,
        ),
        ErrorCode::Conflict,
        "ahead of this service's time",
    );
    // The meta part's identity.json: a version behind the enrolled one, or not the newest
    // identity item of the chain parts.
    let mut parts = f.parts.clone();
    if let Part::Meta(meta) = &mut parts[0] {
        meta.identity = document("alice identity.json, first delivery (version 1)");
    }
    refused(
        f.run_parts(&parts),
        ErrorCode::Conflict,
        "goes back on the enrolled one",
    );
    let alice = f.alice;
    let v6 = IdentityDoc::verify(
        &document("alice identity.json, record age limit (version 6)"),
        &alice,
    )
    .unwrap();
    let later = activate(
        &Activation {
            manifest: &f.manifest,
            freeze: &f.freeze,
            enrolled: &v6,
            now: Some(f.now()),
            uploads: &Uploads::default(),
            revoked_apps: &[],
        },
        &f.parts,
    );
    assert!(later.is_err(), "an export behind the enrolled version");
    // The meta part's seq and generation are the head's.
    for change in [|m: &mut u64| *m = 9, |m: &mut u64| *m = 11] {
        let mut parts = f.parts.clone();
        if let Part::Meta(meta) = &mut parts[0] {
            change(&mut meta.seq);
        }
        refused(
            f.run_parts(&parts),
            ErrorCode::Conflict,
            "generation or seq isn't the head's",
        );
    }
    // A broken head signature is 401.
    let mut head = f.manifest.body().head;
    head.sig = [0; 64];
    let forged = f.resign(|b| b.head = head);
    refused(
        f.run(&forged, &f.parts, &Uploads::default(), f.now()),
        ErrorCode::BadSignature,
        "the head",
    );
    // The wallet's receive key at another seq, or none while the chain holds one.
    let wi = f
        .parts
        .iter()
        .position(|p| matches!(p, Part::App(a) if a.record.is_some()))
        .unwrap();
    let mut parts = f.parts.clone();
    if let Part::App(a) = &mut parts[wi] {
        a.receive_keys[0].1 = 5;
    }
    refused(
        f.run_parts(&parts),
        ErrorCode::Conflict,
        "isn't that chain item",
    );
    let mut parts = f.parts.clone();
    if let Part::App(a) = &mut parts[wi] {
        a.receive_keys.clear();
    }
    refused(
        f.run_parts(&parts),
        ErrorCode::Conflict,
        "isn't the chain's newest",
    );
    // Without the wallet's part, a listed app has none.
    let mut parts = f.parts.clone();
    parts.remove(wi);
    refused(f.run_parts(&parts), ErrorCode::Conflict, "no app part");
    // A record member that isn't its operation's.
    let ri = f.index("record");
    let mut parts = f.parts.clone();
    if let Part::Record(r) = &mut parts[ri] {
        r.size += 1;
    }
    refused(
        f.run_parts(&parts),
        ErrorCode::Conflict,
        "a member isn't its operation's",
    );
    // The record's op carried as well: the same bytes import.
    let op8 = match &f.parts[7] {
        Part::Chain(c) => c.doc.clone(),
        _ => unreachable!(),
    };
    let mut parts = f.parts.clone();
    if let Part::Record(r) = &mut parts[ri] {
        r.op = op8;
    }
    f.run_parts(&parts).unwrap();
    // A live claim without its entry.
    let ci = f.index("claim");
    let mut parts = f.parts.clone();
    parts.remove(ci + 1);
    refused(
        f.run_parts(&parts),
        ErrorCode::Conflict,
        "a live claim without entries",
    );
}

/// The uploaded heads and evidence (Switch wire 7.4.14, 10.5).
fn check_uploads(f: &Fixture) {
    let keys = keys();
    let chain = load("chain.json");
    let wallet = app_id_decode(&keys.app("wallet").app_id).unwrap();
    let head = |h: &Value| SignedHead::from_value(h).unwrap();
    let mut heads: Vec<UploadedHead> = arr(&chain, "signed_heads")
        .iter()
        .map(|h| UploadedHead {
            app_id: wallet,
            head: head(&h["head"]),
        })
        .collect();
    heads.push(UploadedHead {
        app_id: wallet,
        head: f.manifest.body().head,
    });
    let uploads = Uploads {
        heads,
        proofs: Vec::new(),
    };
    f.run(&f.manifest, &f.parts, &uploads, f.now()).unwrap();
    let forked = arr(&chain, "rejections")
        .iter()
        .find(|r| st(r, "name") == "forked head")
        .unwrap();
    let uploads = Uploads {
        heads: vec![UploadedHead {
            app_id: wallet,
            head: head(&forked["head"]),
        }],
        proofs: Vec::new(),
    };
    refused(
        f.run(&f.manifest, &f.parts, &uploads, f.now()),
        ErrorCode::Conflict,
        "isn't on the imported chain",
    );
    // chain.json's record proofs, (1, 6) and (1, 8), and the claim attempt's hold.
    let proofs: Vec<UploadedProof> = arr(&chain, "transition_proofs")
        .iter()
        .filter(|p| {
            let name = st(p, "name");
            name.starts_with("record.put") || name.starts_with("claim attempt")
        })
        .map(|p| UploadedProof {
            app_id: wallet,
            proof: TransitionProof::verify(
                &serde_json::from_value(p["signed"].clone()).unwrap(),
                &f.o_key,
                &f.alice,
            )
            .unwrap(),
        })
        .collect();
    assert_eq!(proofs.len(), 3);
    let uploads = Uploads {
        heads: Vec::new(),
        proofs: proofs.clone(),
    };
    f.run(&f.manifest, &f.parts, &uploads, f.now()).unwrap();
    // Without the claim, the attempt's evidence fails; without the record, the record's.
    let no_claim: Vec<Part> = f
        .parts
        .iter()
        .filter(|p| !matches!(p.kind(), "claim" | "claim_entry"))
        .cloned()
        .collect();
    let manifest = f.resign(|b| b.parts = no_claim.len() as u64);
    refused(
        f.run(&manifest, &no_claim, &uploads, f.now()),
        ErrorCode::Conflict,
        "a claim with an attempt",
    );
}

/// What the export shares with `chain.json`: its chain parts are that chain's items, seq 6's
/// superseded `record.put` a stub only, then the freeze transition, which extends chain.json's
/// head at 9; the record's proof and the claim entry's are chain.json's.
fn check_chain_cross(f: &Fixture, import: &Import) {
    let chain = load("chain.json");
    let items = arr(&chain, "items");
    let parts: Vec<_> = import.chain.iter().collect();
    assert_eq!(parts.len(), items.len() + 1);
    for (part, item) in parts.iter().zip(items) {
        assert_eq!(part.seq, int(item, "seq"));
        assert_eq!(part.stub, Stub::from_value(&item["stub"]).unwrap());
        assert_eq!(part.item_type.as_str(), st(item, "item_type"));
        let doc: SignedDoc = serde_json::from_value(item["item"].clone()).unwrap();
        if part.seq == 6 {
            assert!(part.doc.is_none(), "superseded by seq 8");
        } else {
            assert_eq!(part.doc.as_ref(), Some(&doc));
        }
        assert!(part.context.is_null());
    }
    let head9 = arr(&chain, "signed_heads")
        .iter()
        .map(|h| SignedHead::from_value(&h["head"]).unwrap())
        .find(|h| h.seq == 9)
        .unwrap();
    let freeze = parts.last().unwrap();
    assert_eq!(freeze.seq, 10);
    // The freeze transition's signature, reproduced from the fixed service key.
    let doc = freeze.doc.as_ref().unwrap();
    assert!(reproduce(
        &keys(),
        &f.o_key,
        labels::sig::SERVICE_OP,
        &[&f.alice, &doc.body_bytes().unwrap()],
        &doc.sig_bytes().unwrap(),
    ));
    assert_eq!(
        freeze.stub.open().unwrap().prev_chain_hash,
        head9.chain_hash
    );
    let proof = |prefix: &str| -> SignedDoc {
        let p = arr(&chain, "transition_proofs")
            .iter()
            .find(|p| st(p, "name").starts_with(prefix))
            .unwrap();
        serde_json::from_value(p["signed"].clone()).unwrap()
    };
    assert_eq!(
        import.records[0].part.proof,
        Some(proof("record.put update"))
    );
    assert_eq!(import.claims[0].entries[0].proof, proof("claim attempt"));
    // The meta part holds the newest identity.json, chained at seq 2.
    assert_eq!(import.identity.signed(), parts[1].doc.as_ref().unwrap());
}

/// What the export shares with `documents.json`: the freeze it belongs to, and the export
/// transfer that names its manifest.
fn check_documents_cross(f: &Fixture) {
    let transfer = ExportTransfer::verify(
        &document("alice export transfer, for export.json's manifest"),
        &f.alice,
    )
    .unwrap();
    assert_eq!(transfer.body().manifest_hash, f.manifest.hash());
    assert_eq!(transfer.body().freeze_hash, f.freeze.hash());
    assert_eq!(f.manifest.body().freeze_hash, f.freeze.hash());
    assert_eq!(&transfer.body().to, f.freeze.next());
    assert_eq!(&transfer.body().from, f.enrolled.inbox());
}

/// What the export shares with `http.json`: the next service's chunk fetch under the export
/// transfer, which the old service's checks admit, and its answer, the chunk.
fn check_http_cross(f: &Fixture) {
    let http = load("http.json");
    let request = arr(&http, "requests")
        .iter()
        .find(|r| st(r, "name").contains("export chunk fetch"))
        .unwrap();
    let id = st(request, "path").rsplit('/').next().unwrap();
    assert_eq!(
        st(request, "path"),
        format!(
            "/v1/{}/export/chunks/{id}",
            pubky_switch_core::enc::pubky_id(&f.alice)
        )
    );
    let transfer = ExportTransfer::verify(
        &SignedDoc::from_compact(st(&request["headers"], "switch-transfer")).unwrap(),
        &f.alice,
    )
    .unwrap();
    let read = ExportRead {
        caller: ExportCaller::NextService(&transfer),
        frozen_with: Some(&f.freeze),
        has_identity: true,
        origin: st(request, "origin"),
        service_key: &f.o_key,
    };
    let chunk = read.check_chunk(&f.manifest, id).unwrap();
    assert_eq!(chunk.id, "00000");
    assert_eq!(
        read.check_manifest().unwrap_err().status(),
        403,
        "the manifest is the signer's"
    );
    let response = arr(&http, "responses")
        .iter()
        .find(|r| st(r, "name").contains("the export chunk"))
        .unwrap();
    assert_eq!(b64n::<32>(st(response, "public_key")), f.o_key);
    let answer = ChunkAnswer {
        id: id.to_owned(),
        data: f.chunk.clone(),
    };
    assert_eq!(answer.to_json(), st(response, "body").as_bytes());
    assert_eq!(
        ChunkAnswer::parse(st(response, "body").as_bytes()).unwrap(),
        answer
    );
    f.manifest.check_fetched(id, &answer.data).unwrap();
}
