//! `chain.json`: one generation's chain with its item bytes and hashes, envelopes, chain
//! hashes, stubs, transition proofs and signed heads, the chains a verifier refuses, and the
//! batch ID window (Switch wire 6.5 to 6.7).
//!
//! The chain is rebuilt item by item from the items and the service's times, every proof is
//! rebuilt from the state the core computes for its item (the claim view from the claim
//! rules, the record's version from its `seq`) and signed again with the fixed service key,
//! and every head is signed again, byte for byte. The record delete after the chain
//! (`record_delete`) is generated here (README "How the files were generated").

use std::collections::HashMap;

use pubky_switch_core::chain::{
    ChainEnvelope, ChainError, ChainTip, ItemType, ProofBody, ProofState, ServiceTransition,
    SignedHead, Stub, TransitionProof, Verifier, ZERO_HASH, bind_answer, chain_hash,
    check_attempt_proof, item_hash,
};
use pubky_switch_core::claims::{ClaimLimits, ClaimTally, EntryContext, apply_entry};
use pubky_switch_core::enc::{app_id_decode, b64 as b64e};
use pubky_switch_core::keys::{AppKeys as SwitchAppKeys, IdentityKey};
use pubky_switch_core::ops::{
    OpKind, RecordVersion, SignedOp, StateAfter, ops_hash, proof_state, sign_batch,
};
use pubky_switch_core::records::{AppRecord, IdentityDoc, ReceiveKeyRecord};
use pubky_switch_core::sealed::{RecordValue, SealedValue};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::rfc3339;
use serde_json::{Value, json};

use crate::common::*;

/// One chain item of the file, read and checked.
struct Item {
    seq: u64,
    item_type: ItemType,
    item: SignedDoc,
    envelope: ChainEnvelope,
    stub: Stub,
}

fn signed_of(value: &Value) -> SignedDoc {
    serde_json::from_value(value.clone()).unwrap()
}

fn stub_of(value: &Value) -> Stub {
    Stub::from_value(value).unwrap()
}

fn item_type(text: &str) -> ItemType {
    match text {
        "op" => ItemType::Op,
        "identity" => ItemType::Identity,
        "service" => ItemType::Service,
        other => panic!("item type {other}"),
    }
}

/// Read one item of `items` (or of a rejection's `items`): its bytes and hash, its envelope
/// written again, its chain hash and its stub.
fn read_item(it: &Value) -> Item {
    let seq = int(it, "seq");
    let item_type = item_type(st(it, "item_type"));
    let item = signed_of(&it["item"]);
    let bytes = item.doc_bytes().unwrap();
    if let Some(hex) = it["item_bytes_hex"].as_str() {
        assert_eq!(hex::encode(&bytes), hex, "seq {seq}: item bytes");
    }
    let hash = item_hash(item_type, &bytes);
    assert_eq!(b64e(&hash), st(it, "item_hash"), "seq {seq}: item hash");
    let envelope_json = st(it, "envelope_json");
    let envelope = ChainEnvelope::parse(envelope_json.as_bytes()).unwrap();
    assert_eq!(
        envelope.to_json(),
        envelope_json.as_bytes(),
        "seq {seq}: envelope"
    );
    assert_eq!(envelope.item_hash, hash);
    assert_eq!(b64e(&envelope.prev_chain_hash), st(it, "prev_chain_hash"));
    let ch = chain_hash(&envelope.prev_chain_hash, envelope_json.as_bytes());
    assert_eq!(b64e(&ch), st(it, "chain_hash"), "seq {seq}: chain hash");
    let stub = stub_of(&it["stub"]);
    assert_eq!(stub, Stub::of(&envelope), "seq {seq}: stub");
    assert_eq!(
        serde_json::from_slice::<Value>(&stub.to_json()).unwrap(),
        it["stub"]
    );
    Item {
        seq,
        item_type,
        item,
        envelope,
        stub,
    }
}

/// A service transition read from its signed document, whose key the caller checks.
fn transition_of(signed: &SignedDoc) -> ServiceTransition {
    ServiceTransition::from_value(&signed.peek::<Value>().unwrap()).unwrap()
}

#[test]
fn test_vectors_chain() {
    let keys = keys();
    let v = load("chain.json");
    let generation = int(&v, "generation");
    let items: Vec<Item> = arr(&v, "items").iter().map(read_item).collect();
    assert!(items.len() >= 8);
    let first_body: Value = items[0].item.peek().unwrap();
    let identity = pubky(st(&first_body, "identity"));
    let account = pubky_switch_core::enc::pubky_id(&identity);
    let service_key = keys.service_key(&account);
    let service_secret = keys.secret(&service_key).unwrap();
    let service = ed25519_dalek::SigningKey::from_bytes(&service_secret);

    // The chain, rebuilt item by item from 32 zero bytes, with a gap in seqs where the inbox
    // entry took one.
    let mut tip = ChainTip {
        generation,
        seq: 0,
        chain_hash: ZERO_HASH,
    };
    let mut verifier = Verifier::new(generation);
    let mut ops: HashMap<u64, SignedOp> = HashMap::new();
    let mut records: HashMap<[u8; 16], AppRecord> = HashMap::new();
    let mut gaps = 0;
    for it in &items {
        let env = &it.envelope;
        if it.seq != tip.seq + 1 {
            gaps += 1;
        }
        let (stub, next) = tip
            .append(
                it.seq,
                env.server_time,
                it.item_type,
                env.item_hash,
                env.batch,
            )
            .unwrap();
        assert_eq!(stub, it.stub, "seq {}: appended", it.seq);
        tip = next;
        let checked = verifier.push(&it.stub).unwrap();
        Verifier::check_item(&checked, it.item_type, &it.item.doc_bytes().unwrap()).unwrap();
        // Each item verifies as what it is.
        match it.item_type {
            ItemType::Identity => {
                IdentityDoc::verify(&it.item, &identity).unwrap();
            }
            ItemType::Op => {
                let body: Value = it.item.peek().unwrap();
                let app = app_id_decode(st(&body, "app_id")).unwrap();
                let writer = keys.app_by_id(st(&body, "app_id"));
                let op = SignedOp::verify(&it.item, &writer.signing_public, &identity, Some(&app))
                    .unwrap();
                assert_eq!(env.batch, Some(op.body().batch), "seq {}: batch", it.seq);
                if let OpKind::AppPut { record } = &op.body().kind {
                    records.insert(app, AppRecord::verify(record, &identity).unwrap());
                }
                ops.insert(it.seq, op);
            }
            ItemType::Service => {
                let t = ServiceTransition::verify(&it.item, &service_key, &identity).unwrap();
                assert_eq!(t.to_json().unwrap(), it.item.body_bytes().unwrap());
                assert_eq!(&t.sign(&service, &identity).unwrap(), &it.item);
            }
        }
    }
    assert_eq!(gaps, 1, "the inbox entry's seq is the one gap");
    verifier.end_of_feed().unwrap();

    check_proofs(&v, &items, &ops, &records, &identity, &service);
    check_heads(&v, &items, &mut verifier, &identity, &service);
    check_rejections(&v, &items, &identity, &service_key);
    check_batch_id_window(&v);
    check_export_batches(&ops);
    check_record_delete(&keys, &items, &ops, &identity, &service);
}

/// The state the core computes for an operation's item: the claim view after the claim's
/// first entry, the record's version from the stub, the App ID, the receive key's `n` and
/// kid.
fn state_of_op(
    op: &SignedOp,
    proof: &TransitionProof,
    records: &HashMap<[u8; 16], AppRecord>,
) -> ProofState {
    let env = proof.envelope();
    let body = op.body();
    match &body.kind {
        OpKind::Claim(fields) => {
            let entry = fields.check().unwrap();
            let writer = body.app_id.unwrap();
            let current = |_: &[u8; 16]| true;
            let cx = EntryContext {
                writer,
                now: env.server_time,
                can_read: true,
                is_current: &current,
                limits: ClaimLimits::default(),
                tally: ClaimTally::default(),
            };
            assert_eq!(entry.expected_step, 0, "the claim's first entry");
            let claim = apply_entry(None, &entry, &cx).unwrap();
            let view = claim.view(&entry.claim_key, env.server_time, &current);
            // The attempt's proof passes the checks before acting on it.
            let checked = check_attempt_proof(proof, &entry, &writer, env.generation).unwrap();
            assert_eq!(checked, view);
            ProofState::Claim(view.to_value())
        }
        OpKind::RecordPut(put) => ProofState::Record {
            version: RecordVersion::new(env.generation, env.seq),
            deleted: put.value_sealed.looks_like_delete(),
        },
        OpKind::AppPut { .. } => ProofState::App {
            app_id: body.app_id.unwrap(),
        },
        OpKind::ReceiveKeyPut { record } => {
            let app = body.app_id.unwrap();
            let r = ReceiveKeyRecord::verify(record, records[&app].cert()).unwrap();
            ProofState::ReceiveKey {
                n: r.n(),
                kid: r.kid(),
            }
        }
        other => panic!("no proof rebuilt for {}", other.name()),
    }
}

/// Every transition proof, verified, bound to its item, and rebuilt from the state the core
/// computes for that item, then signed again with the fixed service key (Switch wire 6.5).
fn check_proofs(
    v: &Value,
    items: &[Item],
    ops: &HashMap<u64, SignedOp>,
    records: &HashMap<[u8; 16], AppRecord>,
    identity: &[u8; 32],
    service: &ed25519_dalek::SigningKey,
) {
    let key = service.verifying_key().to_bytes();
    let by_seq: HashMap<u64, &Item> = items.iter().map(|i| (i.seq, i)).collect();
    let proofs = arr(v, "transition_proofs");
    assert!(proofs.len() >= 8);
    let mut by_proof_seq: HashMap<u64, SignedDoc> = HashMap::new();
    for p in proofs {
        let name = st(p, "name");
        let signed = signed_of(&p["signed"]);
        assert_eq!(signed.body, b64e(st(p, "body").as_bytes()), "{name}");
        let proof = TransitionProof::verify(&signed, &key, identity).unwrap();
        let seq = proof.envelope().seq;
        let item = by_seq[&seq];
        assert_eq!(proof.body().chain, item.stub, "{name}: the item's stub");
        let (object, state) = match item.item_type {
            ItemType::Identity => {
                let doc = IdentityDoc::verify(&item.item, identity).unwrap();
                (
                    "identity".to_owned(),
                    ProofState::Identity {
                        version: doc.version(),
                        generation: doc.generation(),
                        data_epoch: doc.data_epoch(),
                    },
                )
            }
            ItemType::Service => {
                let t = transition_of(&item.item);
                (t.proof_object().unwrap(), ProofState::Service(t.to_value()))
            }
            ItemType::Op => {
                let op = &ops[&seq];
                // A proof of an operation binds it, as an app checks a `POST /ops` answer.
                proof.check_binds(op).unwrap();
                let body = op.body();
                let object = body.kind.proof_object(body.app_id.as_ref()).unwrap();
                (object, state_of_op(op, &proof, records))
            }
        };
        assert_eq!(proof.body().object, object, "{name}: object");
        let rebuilt = ProofBody::new(item.stub.clone(), object, &state);
        assert_eq!(
            rebuilt.to_json().unwrap(),
            st(p, "body").as_bytes(),
            "{name}: proof body rebuilt"
        );
        let again = TransitionProof::sign(service, identity, rebuilt).unwrap();
        assert_eq!(again.signed(), &signed, "{name}: signed again");
        by_proof_seq.insert(seq, signed);
    }
    // The answer to the batch of seq 7 and 8 binds its two operations, in order.
    let batch = vec![ops[&7].clone(), ops[&8].clone()];
    let answer = vec![by_proof_seq[&7].clone(), by_proof_seq[&8].clone()];
    assert_eq!(
        bind_answer(&batch, &answer, &key, identity).unwrap().len(),
        2
    );
    let swapped = vec![answer[1].clone(), answer[0].clone()];
    assert!(bind_answer(&batch, &swapped, &key, identity).is_err());
    assert!(bind_answer(&batch, &answer[..1], &key, identity).is_err());
    assert!(
        bind_answer(&batch, &[], &key, identity).is_err(),
        "a claim is never unchanged"
    );
    // The registration batch may be answered without proofs, as an unchanged batch.
    let registration = vec![ops[&3].clone(), ops[&4].clone()];
    assert!(
        bind_answer(&registration, &[], &key, identity)
            .unwrap()
            .is_empty()
    );
}

/// The two heads (Switch wire 6.7): verified, signed again, carried as a header, and
/// matching the verified chain.
fn check_heads(
    v: &Value,
    items: &[Item],
    verifier: &mut Verifier,
    identity: &[u8; 32],
    service: &ed25519_dalek::SigningKey,
) {
    let key = service.verifying_key().to_bytes();
    for h in arr(v, "signed_heads") {
        let head = SignedHead::from_value(&h["head"]).unwrap();
        head.verify(&key, identity).unwrap();
        let at = items.iter().find(|i| i.seq == head.seq).unwrap();
        let tip = ChainTip {
            generation: head.generation,
            seq: head.seq,
            chain_hash: at.stub.chain_hash,
        };
        assert_eq!(SignedHead::sign(service, identity, &tip), head);
        assert_eq!(head.to_header(), st(h, "switch_head_header"));
        assert_eq!(
            SignedHead::from_header(st(h, "switch_head_header")).unwrap(),
            head
        );
        verifier.head(head).unwrap();
    }
}

/// Push stubs until one is refused, then check the end of the feed.
fn run(verifier: &mut Verifier, stubs: &[Stub]) -> Result<(), ChainError> {
    for stub in stubs {
        verifier.push(stub)?;
    }
    verifier.end_of_feed()
}

/// The chains a verifier refuses, each for its rule (Switch wire 6.6, 6.7).
fn check_rejections(v: &Value, items: &[Item], identity: &[u8; 32], service_key: &[u8; 32]) {
    let rejections = arr(v, "rejections");
    assert!(rejections.len() >= 5);
    for r in rejections {
        let name = st(r, "name");
        let mut verifier = Verifier::new(int(v, "generation"));
        let error = if let Some(head) = r.get("head") {
            // A forked head: after every stub, a verified head at seq 3 with another hash.
            assert_eq!(st(r, "after"), "every stub");
            for it in items {
                verifier.push(&it.stub).unwrap();
            }
            let head = SignedHead::from_value(head).unwrap();
            head.verify(service_key, identity).unwrap();
            verifier.head(head).unwrap_err()
        } else if r["stubs"].is_string() {
            // A gap: the items of seq 1, then seq 6.
            verifier.push(&items[0].stub).unwrap();
            let six = items.iter().find(|i| i.seq == 6).unwrap();
            verifier.push(&six.stub).unwrap_err()
        } else {
            let stubs: Vec<Stub> = arr(r, "stubs").iter().map(stub_of).collect();
            // The full items, when given, match their stubs, with their links intact, so only
            // the batch rules refuse them.
            if let Some(full) = r["items"].as_array() {
                let read: Vec<Item> = full.iter().map(read_item).collect();
                for (it, stub) in read.iter().zip(&stubs) {
                    assert_eq!(&it.stub, stub, "{name}");
                }
                for pair in read.windows(2) {
                    assert_eq!(pair[1].envelope.prev_chain_hash, pair[0].stub.chain_hash);
                }
            }
            run(&mut verifier, &stubs).unwrap_err()
        };
        let rule = st(r, "rule");
        let matched = match &error {
            ChainError::PartialBatch { batch_id, .. } => {
                rule.contains("consecutive seqs") && st(r, "error").ends_with(&b64e(batch_id))
            }
            ChainError::FeedEndsInBatch { batch_id } => {
                rule.contains("never ends inside a batch")
                    && st(r, "error").ends_with(&b64e(batch_id))
            }
            ChainError::RepeatedBatchId { batch_id, .. } => {
                rule.contains("repeat") && st(r, "error").ends_with(&b64e(batch_id))
            }
            ChainError::Link { seq } => {
                rule.contains("extends the previous chain hash") && *seq == 6
            }
            ChainError::Head { seq } => rule.contains("matches its chain hash") && *seq == 3,
            _ => false,
        };
        assert!(
            matched,
            "{name}: refused for its rule ({rule}), got {error}"
        );
    }
}

/// The same batch again, 1 ms before, at and 1 ms after 30 days (Switch wire 6.6).
fn check_batch_id_window(v: &Value) {
    let cases = arr(v, "batch_id_window");
    assert_eq!(cases.len(), 3);
    for c in cases {
        let name = st(c, "name");
        let stubs: Vec<Stub> = arr(c, "stubs").iter().map(stub_of).collect();
        let envelopes: Vec<ChainEnvelope> = stubs.iter().map(|s| s.open().unwrap()).collect();
        // The repeat is the last batch; its first stub is `gap_ms` after the earlier one's.
        let mut starts = Vec::new();
        let mut left = 0;
        for e in &envelopes {
            if let Some(batch) = e.batch {
                if left == 0 {
                    starts.push((batch.id, e.server_time));
                    left = batch.count;
                }
                left -= 1;
            }
        }
        let (id, repeat) = *starts.last().unwrap();
        let first = starts.iter().find(|(b, _)| *b == id).unwrap().1;
        assert_eq!(repeat - first, int(c, "gap_ms"), "{name}");
        let outcome = run(&mut Verifier::new(1), &stubs);
        match st(c, "outcome") {
            "refused" => assert!(
                matches!(outcome, Err(ChainError::RepeatedBatchId { batch_id, .. }) if batch_id == id),
                "{name}: {outcome:?}"
            ),
            "accepted" => outcome.unwrap(),
            other => panic!("{name}: outcome {other}"),
        }
    }
}

/// The operation hashes `export.json` carries for the chain's batches (Switch wire 10.3):
/// `hash(lp(signed document bytes of each operation, in order))`.
fn check_export_batches(ops: &HashMap<u64, SignedOp>) {
    let export = load("export.json");
    let mut parts = Vec::new();
    find_batch_parts(&export, &mut parts);
    assert!(!parts.is_empty(), "export.json has batch parts");
    for part in parts {
        let id = b64n::<16>(st(&part, "id"));
        let mut batch: Vec<(u64, SignedOp)> = ops
            .iter()
            .filter(|(_, o)| o.body().batch.id == id)
            .map(|(s, o)| (*s, o.clone()))
            .collect();
        batch.sort_by_key(|(s, _)| *s);
        let batch: Vec<SignedOp> = batch.into_iter().map(|(_, o)| o).collect();
        assert!(!batch.is_empty());
        assert_eq!(
            b64e(&ops_hash(&batch).unwrap()),
            st(&part["record"], "ops_hash"),
            "the operation hash of batch {}",
            st(&part, "id")
        );
    }
}

/// The `batch` parts of an export, wherever they are, inside JSON texts included.
fn find_batch_parts(value: &Value, out: &mut Vec<Value>) {
    match value {
        Value::Object(m) => {
            if m.get("part").and_then(Value::as_str) == Some("batch") {
                out.push(value.clone());
            }
            m.values().for_each(|x| find_batch_parts(x, out));
        }
        Value::Array(a) => a.iter().for_each(|x| find_batch_parts(x, out)),
        Value::String(s) if s.starts_with('{') => {
            if let Ok(inner) = serde_json::from_str::<Value>(s) {
                find_batch_parts(&inner, out);
            }
        }
        _ => {}
    }
}

/// `record_delete`, which `pubky-switch-core` generates (README "How the files were
/// generated"): the wallet deletes the record of seq 8, in a batch of its own chained after
/// seq 9. Its sealed value is the tag alone (wire 6.2), sealed with the seed
/// `chain/record_delete/nonce`, under the batch ID of the seed `chain/record_delete/batch`.
/// The proof's state shows `deleted: true`, as the record rule gives it (wire 6.5).
fn check_record_delete(
    keys: &Keys,
    items: &[Item],
    ops: &HashMap<u64, SignedOp>,
    identity: &[u8; 32],
    service: &ed25519_dalek::SigningKey,
) {
    let wallet = keys.app("wallet");
    let app_id = app_id_decode(&wallet.app_id).unwrap();
    let updated = &ops[&8];
    let OpKind::RecordPut(update) = &updated.body().kind else {
        panic!("seq 8 is the record's update");
    };
    let sealed = &update.value_sealed;
    let scope_key = IdentityKey::from_secret(keys.identity_secrets[identity])
        .scope_key(sealed.data_epoch, &sealed.scope);
    let nonce: [u8; 24] = seed("chain/record_delete/nonce")[..24].try_into().unwrap();
    let mut put = update.clone();
    put.expected_version = RecordVersion::new(1, 8);
    put.value_sealed = SealedValue::seal_with_nonce(
        &scope_key,
        identity,
        sealed.data_epoch,
        &sealed.scope,
        &put.key,
        b"",
        &nonce,
    )
    .unwrap();
    assert!(put.value_sealed.looks_like_delete());
    let batch_id: [u8; 16] = seed("chain/record_delete/batch")[..16].try_into().unwrap();
    let signer = SwitchAppKeys::from_secrets(wallet.signing_secret, wallet.bundle_secret);
    let op = sign_batch(
        &signer,
        identity,
        Some(app_id),
        updated.body().generation,
        batch_id,
        vec![(Vec::new(), OpKind::RecordPut(put.clone()))],
    )
    .unwrap()
    .remove(0);

    // Chained after the chain's last item, a second after it.
    let last = items.last().unwrap();
    let tip = ChainTip {
        generation: last.envelope.generation,
        seq: last.seq,
        chain_hash: last.stub.chain_hash,
    };
    let bytes = op.signed().doc_bytes().unwrap();
    let hash = item_hash(ItemType::Op, &bytes);
    let at = last.envelope.server_time + 1000;
    let seq = last.seq + 1;
    let (stub, _) = tip
        .append(seq, at, ItemType::Op, hash, Some(op.body().batch))
        .unwrap();
    let item = json!({
        "chain_hash": b64e(&stub.chain_hash),
        "envelope_json": String::from_utf8(stub.envelope.clone()).unwrap(),
        "item": op.signed(),
        "item_bytes_hex": hex::encode(&bytes),
        "item_hash": b64e(&hash),
        "item_type": "op",
        "prev_chain_hash": b64e(&tip.chain_hash),
        "seq": seq,
        "stub": stub.to_value(),
    });

    // The proof, with the state the record rule gives a delete.
    let state = proof_state(
        &OpKind::RecordPut(put.clone()),
        &StateAfter::Record(RecordVersion::new(tip.generation, seq)),
    )
    .unwrap();
    assert_eq!(
        state,
        ProofState::Record {
            version: RecordVersion::new(tip.generation, seq),
            deleted: true,
        }
    );
    let object = op.body().kind.proof_object(Some(&app_id)).unwrap();
    let body = ProofBody::new(stub.clone(), object, &state);
    let proof = TransitionProof::sign(service, identity, body).unwrap();
    let body_text = String::from_utf8(proof.signed().body_bytes().unwrap()).unwrap();
    let section = json!({
        "description": format!(
            "A record.put that deletes (wire 6.2): the wallet deletes the record of seq 8, \
             expected_version (1, 8), in a batch of one chained after seq 9 at {}. Its \
             value_sealed.ct is the tag alone, so the switch takes it as a delete without \
             opening it, and its transition proof's state shows deleted true (wire 6.5). No \
             other file continues the chain this way: export.json freezes the account after \
             seq 9, and operations.json pays at seqs 10 and 11.",
            rfc3339(at)
        ),
        "item": item,
        "transition_proof": {
            "body": body_text,
            "name": format!("record.put delete (seq {seq}): deleted at version (1, {seq})"),
            "signed": proof.signed(),
        },
    });
    generated("chain.json", &[(Place::Member("/record_delete"), section)]);

    // The case as the file holds it: the item reads and links to the chain, the delete opens
    // as one, and the proof verifies, binds the operation and shows the delete.
    let file = load("chain.json");
    let case = &file["record_delete"];
    let read = read_item(&case["item"]);
    assert_eq!(read.envelope.prev_chain_hash, last.stub.chain_hash);
    let op = SignedOp::verify(&read.item, &wallet.signing_public, identity, Some(&app_id)).unwrap();
    let OpKind::RecordPut(put) = &op.body().kind else {
        panic!("record_delete is a record.put");
    };
    assert_eq!(
        put.value_sealed
            .open(&scope_key, identity, &put.key)
            .unwrap(),
        RecordValue::Delete
    );
    let p = &case["transition_proof"];
    let signed = signed_of(&p["signed"]);
    assert_eq!(signed.body, b64e(st(p, "body").as_bytes()));
    let proof =
        TransitionProof::verify(&signed, &service.verifying_key().to_bytes(), identity).unwrap();
    proof.check_binds(&op).unwrap();
    assert_eq!(proof.body().chain, read.stub);
    assert_eq!(proof.body().state["deleted"], Value::Bool(true));
}
