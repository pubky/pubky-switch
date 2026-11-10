//! The rules the switch applies to its own state: proof states rebuilt byte for byte from
//! `chain.json`'s operations (Switch wire 6.5), the per-kind limits and quota (9.3), the
//! `invite_code.delete` rule (6.2), and the key bundle parts an app keeps (6.2, 7.4.12).

// The helpers outside `#[test]` functions read fixed vector files, where a failure is a test
// failure: the workspace's no-panic lints don't apply to them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ed25519_dalek::SigningKey;
use pubky_switch_core::{
    chain::{ProofBody, ProofState, Stub, TransitionProof},
    claims::ClaimView,
    enc::{pubky_key, unb64},
    http::ErrorCode,
    ops::{
        Limits, List, OpKind, Quota, Refusal, SignedOp, StateAfter, StoredPart, check_quota,
        covers, invite_code_delete, keys_through, parts_to_drop, proof_state,
    },
    sig::SignedDoc,
};
use serde_json::Value;

fn vectors(name: &str) -> Value {
    let path = pubky_switch_core::spec_vectors_dir().join(name);
    serde_json::from_slice(&std::fs::read(path).expect("vector file")).expect("json")
}

fn hex32(value: &Value) -> [u8; 32] {
    hex::decode(value.as_str().expect("hex"))
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

/// The state after an operation, read from the operation and its place in the chain; a
/// claim's view from `view`.
fn state_after(op: &SignedOp, seq: u64, generation: u64, view: &Value) -> StateAfter {
    let body = op.body();
    match &body.kind {
        OpKind::RecordPut(_) => StateAfter::Record { generation, seq },
        OpKind::Claim(_) => StateAfter::Claim(ClaimView::from_value(view).expect("claim view")),
        OpKind::AppPut { .. } => StateAfter::App {
            app_id: body.app_id.expect("app"),
        },
        OpKind::ReceiveKeyPut { record } => {
            let fields: Value =
                serde_json::from_slice(&record.body_bytes().expect("body")).expect("json");
            StateAfter::ReceiveKey {
                n: fields["n"].as_u64().expect("n"),
                kid: unb64(fields["kid"].as_str().expect("kid"))
                    .expect("b64")
                    .try_into()
                    .expect("8 bytes"),
            }
        }
        _ => StateAfter::Op,
    }
}

#[test]
fn test_switch_rules_rebuild_chain_proofs() {
    let chain = vectors("chain.json");
    let keys = vectors("keys.json");
    let service = keys["service_keys"]
        .as_array()
        .expect("service keys")
        .iter()
        .find(|key| key["seed_label"] == "service/alice")
        .expect("alice's service key");
    let service_key = SigningKey::from_bytes(&hex32(&service["secret_hex"]));
    let identity = pubky_key(service["account"].as_str().expect("account")).expect("identity");
    let items = chain["items"].as_array().expect("items");
    let mut rebuilt = 0;
    for expected in chain["transition_proofs"].as_array().expect("proofs") {
        let body: Value =
            serde_json::from_str(expected["body"].as_str().expect("body")).expect("json");
        let envelope: Value = serde_json::from_slice(
            &unb64(body["chain"]["envelope"].as_str().expect("envelope")).expect("b64"),
        )
        .expect("json");
        if envelope["item_type"] != "op" {
            continue;
        }
        let seq = envelope["seq"].as_u64().expect("seq");
        let item = items
            .iter()
            .find(|item| item["seq"].as_u64() == Some(seq))
            .expect("the proof's chain item");
        let signed: SignedDoc = serde_json::from_value(item["item"].clone()).expect("signed op");
        let op = SignedOp::peek(&signed).expect("op");
        let stub = Stub {
            envelope: item["envelope_json"]
                .as_str()
                .expect("envelope")
                .as_bytes()
                .to_vec(),
            chain_hash: unb64(item["chain_hash"].as_str().expect("hash"))
                .expect("b64")
                .try_into()
                .expect("32 bytes"),
        };
        let generation = envelope["generation"].as_u64().expect("generation");
        let after = state_after(&op, seq, generation, &body["state"]);
        let state = proof_state(&op.body().kind, &after).expect("state");
        let object = op
            .body()
            .kind
            .proof_object(op.body().app_id.as_ref())
            .expect("object");
        let proof_body = ProofBody::new(stub, object, &state);
        let name = expected["name"].as_str().expect("name");
        assert_eq!(
            String::from_utf8(proof_body.to_json().expect("json")).expect("utf-8"),
            expected["body"].as_str().expect("body"),
            "{name}: body"
        );
        let proof = TransitionProof::sign(&service_key, &identity, proof_body).expect("sign");
        let expected_signed: SignedDoc =
            serde_json::from_value(expected["signed"].clone()).expect("signed");
        assert_eq!(proof.signed(), &expected_signed, "{name}: signed proof");
        rebuilt += 1;
    }
    assert_eq!(
        rebuilt, 5,
        "app.put, receive_key.put, two record.puts and a claim"
    );
}

#[test]
fn test_switch_rules_state_after_must_fit_the_operation() {
    let chain = vectors("chain.json");
    let item = &chain["items"].as_array().expect("items")[2];
    let signed: SignedDoc = serde_json::from_value(item["item"].clone()).expect("signed op");
    let op = SignedOp::peek(&signed).expect("op");
    assert!(matches!(op.body().kind, OpKind::AppPut { .. }));
    // An app.put given a record's version is a mistake, not a state.
    let wrong = StateAfter::Record {
        generation: 1,
        seq: 3,
    };
    assert!(proof_state(&op.body().kind, &wrong).is_err());
}

#[test]
fn test_switch_rules_invite_code_delete() {
    assert_eq!(invite_code_delete(true), Ok(ProofState::InviteCodeDelete));
    assert_eq!(
        invite_code_delete(false).expect_err("unknown").code,
        ErrorCode::NotFound
    );
}

fn limit_of(result: Result<(), Refusal>) -> Value {
    let refusal = result.expect_err("refused");
    assert_eq!(refusal.code, ErrorCode::QuotaExceeded);
    refusal.current.expect("current")["limit"].clone()
}

#[test]
fn test_switch_rules_record_quota() {
    let limits = Limits {
        max_record_keys: 2,
        record_quota_bytes: 100,
        ..Limits::default()
    };
    let record = |live_keys, stored_bytes, key_live, current_bytes, new_bytes| Quota::Record {
        live_keys,
        stored_bytes,
        key_live,
        current_bytes,
        new_bytes,
    };
    // A new key when the keys are full: record_keys, before the storage quota.
    assert_eq!(
        limit_of(check_quota(&record(2, 100, false, 0, 50), &limits)),
        "record_keys"
    );
    // A write to a live key passes the key limit; one that grows past the quota doesn't.
    assert!(check_quota(&record(2, 90, true, 10, 20), &limits).is_ok());
    assert_eq!(
        limit_of(check_quota(&record(2, 90, true, 10, 21), &limits)),
        "storage"
    );
    // A rewrite that doesn't grow, and a delete, always pass.
    assert!(check_quota(&record(2, 200, true, 50, 50), &limits).is_ok());
    assert!(check_quota(&record(2, 200, true, 50, 0), &limits).is_ok());
    // A deleted key written again counts as a new key.
    assert_eq!(
        limit_of(check_quota(&record(2, 0, false, 0, 1), &limits)),
        "record_keys"
    );
}

#[test]
fn test_switch_rules_list_and_invite_quota() {
    let limits = Limits {
        max_contacts: 1,
        max_conversations: 1,
        max_deny: 1,
        max_invite_codes: 1,
        ..Limits::default()
    };
    for (list, name) in [
        (List::Contacts, "contacts"),
        (List::Conversations, "conversations"),
        (List::Deny, "deny"),
    ] {
        let quota = |entries, present| Quota::List {
            list,
            entries,
            present,
        };
        assert_eq!(limit_of(check_quota(&quota(1, false), &limits)), name);
        assert!(
            check_quota(&quota(1, true), &limits).is_ok(),
            "already there"
        );
        assert!(check_quota(&quota(0, false), &limits).is_ok());
    }
    assert_eq!(
        limit_of(check_quota(
            &Quota::InviteCode {
                live: 1,
                held: false
            },
            &limits
        )),
        "invite_codes"
    );
    assert!(
        check_quota(
            &Quota::InviteCode {
                live: 1,
                held: true
            },
            &limits
        )
        .is_ok()
    );
    // The defaults are the wire format's, the claim limits the core's own.
    assert_eq!(
        Limits::default().claims,
        pubky_switch_core::claims::ClaimLimits::default()
    );
    assert_eq!(Limits::default().max_invite_codes, 1_000);
}

fn part(first_epoch: u64, last_epoch: u64, seq: u64) -> StoredPart {
    StoredPart {
        first_epoch,
        last_epoch,
        seq,
    }
}

#[test]
fn test_switch_rules_keys_through() {
    // Listed at epoch 1, two parts passed, a gap-free run to 3.
    let parts = [part(2, 2, 10), part(3, 3, 11)];
    assert_eq!(keys_through(Some(1), &parts, 11), Some(3));
    // The second part not passed yet.
    assert_eq!(keys_through(Some(1), &parts, 10), Some(2));
    // A part after a gap doesn't raise it until the gap is filled.
    assert_eq!(keys_through(Some(1), &[part(3, 4, 10)], 10), Some(1));
    assert_eq!(
        keys_through(Some(1), &[part(3, 4, 10), part(2, 2, 12)], 12),
        Some(4),
        "the gap filled later raises it through the earlier part"
    );
    // Unknown: only a part from epoch 1 makes it known.
    assert_eq!(keys_through(None, &[part(2, 3, 10)], 10), None);
    assert_eq!(keys_through(None, &[part(1, 3, 10)], 10), Some(3));
}

#[test]
fn test_switch_rules_parts_to_drop_and_cover() {
    let parts = [part(1, 2, 10), part(3, 3, 11), part(4, 5, 20)];
    // Passed by the cursor and covered by keys_through: the first two go.
    assert_eq!(parts_to_drop(&parts, 15, Some(3), false), vec![0, 1]);
    // Not covered yet, or not passed: they stay.
    assert_eq!(parts_to_drop(&parts, 15, Some(2), false), vec![0]);
    assert_eq!(
        parts_to_drop(&parts, 9, Some(5), false),
        Vec::<usize>::new()
    );
    // A pending full-bundle request, or unknown keys_through, keeps every part.
    assert!(parts_to_drop(&parts, 30, Some(5), true).is_empty());
    assert!(parts_to_drop(&parts, 30, None, false).is_empty());
    assert!(covers(&parts, 5));
    assert!(!covers(&parts, 6));
    assert!(!covers(&[part(2, 5, 1)], 5), "epoch 1 missing");
}
