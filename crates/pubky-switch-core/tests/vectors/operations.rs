//! `operations.json`: every operation type signed by its writer, the `POST /ops` body, the
//! operations to refuse for an unknown member at any depth, the batch entries to refuse, the
//! integer bounds and the attempt deadlines (Switch wire 6.1 to 6.4).
//!
//! Every operation is verified for its writer, read, written again from what was read and
//! signed again from the fixed keys, byte for byte; its shape and its writer's permission
//! are checked, and every sealed value opens with the identity's scope key.

use std::collections::HashMap;

use pubky_switch_core::claims::{ClaimEntry, EntryKind, attempt_deadline};
use pubky_switch_core::enc::{app_id_decode, b64 as b64e};
use pubky_switch_core::keys::{AppKeys as SwitchAppKeys, IdentityKey};
use pubky_switch_core::labels;
use pubky_switch_core::ops::{
    self, Entry, OpKind, OpsRequest, Refusal, SignedOp, Writer, check_batch, check_permission,
    check_shape,
};
use pubky_switch_core::records::AppCert;
use pubky_switch_core::sealed::RecordValue;
use pubky_switch_core::sig::{self, SignedDoc};
use pubky_switch_core::time::{parse_rfc3339, rfc3339};
use serde_json::{Value, json};

use crate::common::*;

/// The writer's verifying key and App ID: an app's signing key, or the identity key for the
/// signer.
fn writer_of(keys: &Keys, writer: &str, identity: &[u8; 32]) -> ([u8; 32], Option<[u8; 16]>) {
    if writer == "signer" {
        return (*identity, None);
    }
    let app = keys.app(writer);
    (
        app.signing_public,
        Some(app_id_decode(&app.app_id).unwrap()),
    )
}

fn signed_of(value: &Value) -> SignedDoc {
    serde_json::from_value(value.clone()).unwrap()
}

/// The certificates of `documents.json`, by App ID: the first one of each app, which the
/// operations here are written under.
fn certificates(identity: &[u8; 32]) -> HashMap<[u8; 16], AppCert> {
    let docs = load("documents.json");
    let mut certs = HashMap::new();
    for d in arr(&docs, "documents") {
        if st(d, "label") != labels::sig::APP_CERT {
            continue;
        }
        if let Ok(cert) = AppCert::verify(&signed_of(&d["signed"]), identity) {
            certs.entry(cert.app_id()).or_insert(cert);
        }
    }
    certs
}

#[test]
fn test_vectors_operations() {
    let keys = keys();
    let v = load("operations.json");
    let operations = arr(&v, "operations");
    assert!(!operations.is_empty());
    let mut by_name: HashMap<String, SignedOp> = HashMap::new();
    let mut identity = None;
    for o in operations {
        let name = st(o, "name");
        let body_text = st(o, "body");
        let signed = signed_of(&o["signed"]);
        assert_eq!(
            signed.body,
            b64e(body_text.as_bytes()),
            "{name}: carrying body"
        );
        let raw: Value = serde_json::from_str(body_text).unwrap();
        let id = pubky(st(&raw, "identity"));
        identity = Some(id);
        let (writer_key, app_id) = writer_of(&keys, st(o, "writer"), &id);

        // Verified for its writer (Switch wire 6.4 step 3), read, and written again.
        let op = SignedOp::verify(&signed, &writer_key, &id, app_id.as_ref())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            op.body().to_json().unwrap(),
            body_text.as_bytes(),
            "{name}: body rebuilt"
        );
        assert_eq!(op.body().kind.name(), st(&raw, "op"), "{name}: type");
        // Signed again from the fixed key, byte for byte.
        assert!(reproduce(
            &keys,
            &writer_key,
            labels::sig::OP,
            &[&id, body_text.as_bytes()],
            &signed.sig_bytes().unwrap()
        ));
        let secret = keys.secret(&writer_key).unwrap();
        let again = if app_id.is_some() {
            let app = keys.app(st(o, "writer"));
            let switch_keys = SwitchAppKeys::from_secrets(app.signing_secret, app.bundle_secret);
            SignedOp::sign(&switch_keys, op.body().clone()).unwrap()
        } else {
            SignedOp::sign(&IdentityKey::from_secret(secret), op.body().clone()).unwrap()
        };
        assert_eq!(again.signed(), &signed, "{name}: signed again");
        assert!(op.carrying_len() <= ops::MAX_OP_BYTES);

        // Its shape (Switch wire 6.4 step 9) holds: keys derive, bundles and certificates
        // verify, claim entries are well formed.
        check_shape(op.body()).unwrap_or_else(|e| panic!("{name}: shape: {e}"));
        if let OpKind::Claim(fields) = &op.body().kind {
            fields.check().unwrap();
        }
        // A sealed value opens with the identity's scope key of its data epoch.
        if let OpKind::RecordPut(put) = &op.body().kind {
            let sealed = &put.value_sealed;
            let key = IdentityKey::from_secret(keys.identity_secrets[&id])
                .scope_key(sealed.data_epoch, &sealed.scope);
            let value = sealed.open(&key, &id, &put.key).unwrap();
            assert_eq!(
                matches!(value, RecordValue::Delete),
                name.contains("delete"),
                "{name}: delete"
            );
        }
        by_name.insert(name.to_owned(), op);
    }
    let identity = identity.unwrap();
    check_permissions(&by_name, &identity);
    check_batches(&by_name);
    check_ops_request(&keys, &v, &identity);
    check_unknown_members(&keys, &v, &identity);
    check_batch_entries(&keys, &v, &identity);
    check_integer_bounds(&keys, &v, &identity);
    check_attempt_deadlines(&v, &by_name);
    check_invite_context(&keys, &v, &identity);
    check_shape_rejections(&keys, &v, &identity);
}

/// One case of `shape_rejections`: the operation `based_on` with each `(from, to)` of
/// `changes` made in its signed body, signed again by its writer, so its signature verifies
/// and only the shape check (Switch wire 6.4 step 9) decides.
fn shape_case(
    keys: &Keys,
    v: &Value,
    identity: &[u8; 32],
    name: &str,
    based_on: &str,
    changes: &[(&str, &str)],
) -> Value {
    let base = arr(v, "operations")
        .iter()
        .find(|o| st(o, "name") == based_on)
        .unwrap();
    let mut body = st(base, "body").to_owned();
    for (from, to) in changes {
        assert_eq!(body.matches(from).count(), 1, "{name}: {from}");
        body = body.replace(from, to);
    }
    let (writer_key, _) = writer_of(keys, st(base, "writer"), identity);
    let secret = keys.secret(&writer_key).unwrap();
    let sig = sig::sign(
        &ed25519_dalek::SigningKey::from_bytes(&secret),
        labels::sig::OP,
        &[identity, body.as_bytes()],
    );
    let signed = SignedDoc::from_parts(body.as_bytes(), &sig);
    let (key, app_id) = writer_of(keys, st(base, "writer"), identity);
    let op = SignedOp::verify(&signed, &key, identity, app_id.as_ref())
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    let refused = check_shape(op.body()).expect_err(name);
    json!({
        "name": name,
        "based_on": based_on,
        "writer": st(base, "writer"),
        "body": body,
        "signed": signed,
        "expect": { "status": refused.status(), "code": refused.code.as_str() },
        "rule": quoted(&refused.reason),
    })
}

/// `shape_rejections`, which `pubky-switch-core` generates (README "How the files were
/// generated"): the `record.put create` of `operations` with its policy changed so that its
/// shape (Switch wire 6.2, 6.4 step 9) fails, its key derived again for that policy (wire
/// 1.5), so only the scope rule decides, and signed again by its writer: a `read_scope`,
/// with the sealed value's `scope`, or a `write_scopes` entry that isn't a scope (wire 3.1
/// "Scope names").
fn check_shape_rejections(keys: &Keys, v: &Value, identity: &[u8; 32]) {
    let based_on = "record.put create";
    let base = arr(v, "operations")
        .iter()
        .find(|o| st(o, "name") == based_on)
        .unwrap();
    let body: Value = serde_json::from_str(st(base, "body")).unwrap();
    let read = st(&body, "read_scope").to_owned();
    let writes = strings(&body["write_scopes"]);
    let key = st(&body, "key").to_owned();
    let collection = st(&body["id_inputs"], "collection").to_owned();
    let blinded: [u8; 32] = b64n(st(&body["id_inputs"], "blinded_key"));
    let text = |value: &Value| serde_json::to_string(value).unwrap();
    // The changes that give the operation `new_read` and `new_writes`, with the key they
    // derive.
    let changes = |new_read: &str, new_writes: &[String]| -> Vec<(String, String)> {
        let refs: Vec<&str> = new_writes.iter().map(String::as_str).collect();
        let policy = pubky_switch_core::ident::Policy::new(new_read, &refs);
        let new_key = pubky_switch_core::ident::record_key_from_blinded(
            &collection,
            &blinded,
            &policy.hash().unwrap(),
        );
        vec![
            (
                format!(r#""key":{}"#, text(&json!(key))),
                format!(r#""key":{}"#, text(&json!(b64e(&new_key)))),
            ),
            (
                format!(r#""read_scope":{}"#, text(&json!(read))),
                format!(r#""read_scope":{}"#, text(&json!(new_read))),
            ),
            (
                format!(r#""write_scopes":{}"#, text(&json!(writes))),
                format!(r#""write_scopes":{}"#, text(&json!(new_writes))),
            ),
            (
                format!(r#""scope":{},"nonce""#, text(&json!(read))),
                format!(r#""scope":{},"nonce""#, text(&json!(new_read))),
            ),
        ]
    };
    let case = |name: &str, new_read: &str, new_writes: &[String]| {
        let changes = changes(new_read, new_writes);
        let pairs: Vec<(&str, &str)> = changes
            .iter()
            .filter(|(from, to)| from != to)
            .map(|(from, to)| (from.as_str(), to.as_str()))
            .collect();
        shape_case(keys, v, identity, name, based_on, &pairs)
    };
    let mut more_writes = writes.clone();
    more_writes.push(format!("{}:", writes[0]));
    let cases = vec![
        case(
            "record.put: read_scope with a NUL character",
            &format!("{read}\u{0}"),
            &writes,
        ),
        case(
            "record.put: read_scope in upper case",
            &read.to_uppercase(),
            &writes,
        ),
        case(
            "record.put: a write_scopes entry that isn't a scope",
            &read,
            &more_writes,
        ),
    ];
    let section = json!({
        "description": "Wire 6.2, 6.4 step 9: operations whose shape the service refuses, 400 bad_request, before it compares them with what it holds. Each case is the operation of operations named in based_on with the change its name gives made in its signed body, its record key derived again for the policy it then has (wire 1.5), and signed again by its writer, so its signature verifies and only the shape decides. A record's read_scope, its value_sealed's scope with it, and each write_scopes entry follow the scope rule of wire 3.1 \"Scope names\".",
        "cases": cases,
    });
    generated(
        "operations.json",
        &[(Place::Member("/shape_rejections"), section)],
    );
    let file = load("operations.json");
    for c in arr(&file["shape_rejections"], "cases") {
        let name = st(c, "name");
        let signed = signed_of(&c["signed"]);
        assert_eq!(signed.body, b64e(st(c, "body").as_bytes()), "{name}");
        let (key, app_id) = writer_of(keys, st(c, "writer"), identity);
        let op = SignedOp::verify(&signed, &key, identity, app_id.as_ref())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        expect_refusal(c, &check_shape(op.body()).unwrap_err(), name);
    }
}

/// `invite_context`, which `pubky-switch-core` generates (README "How the files were
/// generated"): the wallet's `invite_code.put` with its context padded with spaces inside
/// its object, signed again by the wallet. The limit counts the context as written in the
/// signed body (wire 6.2): 1,024 bytes are taken, and 1,025 are `413 too_large`, though the
/// context compacted is 1,000 bytes. Each signature verifies; only the shape check decides.
fn check_invite_context(keys: &Keys, v: &Value, identity: &[u8; 32]) {
    let wallet = keys.app("wallet");
    let app_id = app_id_decode(&wallet.app_id).unwrap();
    let based_on = arr(v, "operations")
        .iter()
        .find(|o| st(o, "name") == "invite_code.put")
        .unwrap();
    let text = st(based_on, "body");
    let context = r#""context":{"order":"order-1042"}"#;
    assert!(text.contains(context));
    let compact = format!(r#"{{"order":"{}"}}"#, "x".repeat(988));
    assert_eq!(compact.len(), 1000);
    let case = |name: &str, written: usize, expect: Value| {
        let padded = format!(
            r#"{{{}"order":"{}"}}"#,
            " ".repeat(written - 1000),
            "x".repeat(988)
        );
        let body = text.replace(context, &format!(r#""context":{padded}"#));
        let sig = sig::sign(
            &ed25519_dalek::SigningKey::from_bytes(&wallet.signing_secret),
            labels::sig::OP,
            &[identity, body.as_bytes()],
        );
        json!({
            "name": name,
            "based_on": "invite_code.put",
            "writer": "wallet",
            "body": body,
            "signed": SignedDoc::from_parts(body.as_bytes(), &sig),
            "context_bytes": written,
            "compact_bytes": compact.len(),
            "expect": expect,
        })
    };
    let section = json!({
        "description": "Wire 6.2: an invite code's context is at most 1024 bytes as the writer serialized it, the bytes of its value within the signed body from its first byte to its last, whitespace included, never a re-serialization; else 413 too_large. Each case is the invite_code.put of operations with its context written with spaces inside its object, signed again by the wallet, so its signature verifies and only the length decides. context_bytes is the context as written, compact_bytes compacted.",
        "cases": [
            case("1024 bytes as written: taken", 1024, json!({"valid": true})),
            case(
                "1025 bytes as written, 1000 compacted: refused",
                1025,
                json!({"status": 413, "code": "too_large"}),
            ),
        ],
    });
    generated(
        "operations.json",
        &[(Place::Member("/invite_context"), section)],
    );
    let file = load("operations.json");
    let cases = arr(&file["invite_context"], "cases");
    assert_eq!(cases.len(), 2);
    for c in cases {
        let name = st(c, "name");
        let signed = signed_of(&c["signed"]);
        assert_eq!(signed.body, b64e(st(c, "body").as_bytes()), "{name}");
        let op = SignedOp::verify(&signed, &wallet.signing_public, identity, Some(&app_id))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let OpKind::InviteCodePut(put) = &op.body().kind else {
            panic!("{name}: an invite_code.put");
        };
        assert_eq!(
            put.context.written_len() as u64,
            int(c, "context_bytes"),
            "{name}"
        );
        assert_eq!(
            serde_json::to_vec(put.context.value()).unwrap().len() as u64,
            int(c, "compact_bytes"),
            "{name}"
        );
        let outcome = check_shape(op.body());
        if c["expect"]["valid"] == Value::Bool(true) {
            outcome.unwrap_or_else(|e| panic!("{name}: {e}"));
        } else {
            expect_refusal(c, &outcome.unwrap_err(), name);
        }
    }
}

/// Each app's operation is one its certificate allows; the signer's only the signer writes
/// (Switch wire 6.2, 6.4 step 9).
fn check_permissions(ops: &HashMap<String, SignedOp>, identity: &[u8; 32]) {
    let certs = certificates(identity);
    for (name, op) in ops {
        let body = op.body();
        match body.app_id {
            None => {
                check_permission(&body.kind, Writer::Signer).unwrap();
                let some_cert = certs.values().next().unwrap();
                let refused = check_permission(&body.kind, Writer::App(some_cert)).unwrap_err();
                assert_eq!(refused.status(), 403, "{name}");
            }
            Some(app) => {
                let cert = &certs[&app];
                check_permission(&body.kind, Writer::App(cert))
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                assert!(
                    check_permission(&body.kind, Writer::Signer).is_err(),
                    "{name}"
                );
            }
        }
    }
}

/// The operations of one batch share its ID and count, and pass the batch rules (Switch wire
/// 6.4 step 4); the record written twice is refused.
fn check_batches(ops: &HashMap<String, SignedOp>) {
    let mut batches: HashMap<[u8; 16], Vec<&SignedOp>> = HashMap::new();
    for op in ops.values() {
        batches.entry(op.body().batch.id).or_default().push(op);
    }
    for group in batches.values() {
        let mut group: Vec<SignedOp> = group.iter().map(|o| (*o).clone()).collect();
        // The order within a batch doesn't matter to these rules.
        group.sort_by_key(|o| o.signed().sig.clone());
        assert_eq!(group[0].body().batch.count as usize, group.len());
        check_batch(&group).unwrap();
        if group.len() == 1 {
            assert!(check_batch(&[group[0].clone(), group[0].clone()]).is_err());
        }
    }
    // Two writes of one record in one batch: the create and the update share a key.
    let create = ops["record.put create"].clone();
    let update = ops["record.put update"].clone();
    let mut body = update.body().clone();
    body.batch = ops::BatchRef {
        id: [9; 16],
        count: 2,
    };
    let mut first = create.body().clone();
    first.batch = body.batch;
    let resigned = |b: pubky_switch_core::ops::OpBody| {
        let bytes = b.to_json().unwrap();
        SignedOp::peek(&SignedDoc::from_parts(&bytes, &[0; 64])).unwrap()
    };
    let refused = check_batch(&[resigned(first), resigned(body)]).unwrap_err();
    assert_eq!(refused.status(), 400);
}

/// The registration batch's `POST /ops` body (Switch wire 6.4): read, its operations
/// verified, and written again byte for byte.
fn check_ops_request(keys: &Keys, v: &Value, identity: &[u8; 32]) {
    let body = st(&v["ops_request"], "body");
    let request = OpsRequest::parse(body.as_bytes()).unwrap();
    assert_eq!(request.to_json(), body.as_bytes(), "ops_request rebuilt");
    let wallet = keys.app("wallet");
    let app_id = app_id_decode(&wallet.app_id).unwrap();
    let signed: Vec<SignedOp> = request
        .signed()
        .map(|d| SignedOp::verify(d, &wallet.signing_public, identity, Some(&app_id)).unwrap())
        .collect();
    assert_eq!(signed.len(), 2);
    assert!(matches!(signed[0].body().kind, OpKind::AppPut { .. }));
    assert!(matches!(
        signed[1].body().kind,
        OpKind::ReceiveKeyPut { .. }
    ));
    check_batch(&signed).unwrap();
    let cursor = request.cursor().unwrap();
    assert_eq!(cursor.to_string(), "1:0");
    assert_eq!(
        OpsRequest::new(&signed, Some(cursor)).to_json(),
        body.as_bytes()
    );
    assert!(matches!(request.entries.last(), Some(Entry::Cursor(_))));
}

/// The cases refused for an unknown member at the top level or nested (Switch wire 1.1,
/// 6.1): each signature verifies, and only the member check refuses it, `400 bad_request`.
fn check_unknown_members(keys: &Keys, v: &Value, identity: &[u8; 32]) {
    let cases = arr(&v["unknown_members"], "cases");
    assert!(cases.len() >= 9);
    for c in cases {
        let name = st(c, "name");
        let signed = signed_of(&c["signed"]);
        assert_eq!(signed.body, b64e(st(c, "body").as_bytes()), "{name}");
        let (key, app_id) = writer_of(keys, st(c, "writer"), identity);
        sig::verify(
            &key,
            labels::sig::OP,
            &[identity, st(c, "body").as_bytes()],
            &signed.sig_bytes().unwrap(),
        )
        .unwrap_or_else(|e| panic!("{name}: the signature verifies: {e}"));
        let refused = SignedOp::verify(&signed, &key, identity, app_id.as_ref()).unwrap_err();
        expect_refusal(c, &refused, name);
        assert!(
            refused.reason.contains("unknown member"),
            "{name}: {refused}"
        );
        // The same body without the member reads.
        let mut value: Value = serde_json::from_str(st(c, "body")).unwrap();
        remove_at(&mut value, st(c, "member"));
        ops::OpBody::parse(&serde_json::to_vec(&value).unwrap())
            .unwrap_or_else(|e| panic!("{name}: without the member: {e}"));
    }
}

/// Remove the member at a dotted path, numbers indexing arrays.
fn remove_at(value: &mut Value, path: &str) {
    let mut parts: Vec<&str> = path.split('.').collect();
    let last = parts.pop().unwrap();
    let mut node = value;
    for p in parts {
        node = match p.parse::<usize>() {
            Ok(i) => &mut node[i],
            Err(_) => &mut node[p],
        };
    }
    node.as_object_mut().unwrap().remove(last).unwrap();
}

fn expect_refusal(case: &Value, refused: &Refusal, name: &str) {
    let expect = &case["expect"];
    assert_eq!(
        u64::from(refused.status()),
        int(expect, "status"),
        "{name}: {refused}"
    );
    assert_eq!(
        refused.code.as_str(),
        st(expect, "code"),
        "{name}: {refused}"
    );
}

/// `POST /ops` bodies with a member beside a batch entry's own (Switch wire 6.4 step 2):
/// every signature still verifies, and the body is refused `400 bad_request` before any
/// signature is checked.
fn check_batch_entries(keys: &Keys, v: &Value, identity: &[u8; 32]) {
    let wallet = keys.app("wallet");
    let cases = arr(&v["unknown_members"]["batch_entries"], "cases");
    assert!(cases.len() >= 2);
    for c in cases {
        let name = st(c, "name");
        let body = st(c, "body");
        let refused = OpsRequest::parse(body.as_bytes()).unwrap_err();
        expect_refusal(c, &refused, name);
        let raw: Value = serde_json::from_str(body).unwrap();
        for entry in raw["ops"].as_array().unwrap() {
            if let (Some(b), Some(s)) = (entry["body"].as_str(), entry["sig"].as_str()) {
                let doc = SignedDoc {
                    body: b.into(),
                    sig: s.into(),
                };
                let app_id = app_id_decode(&wallet.app_id).unwrap();
                SignedOp::verify(&doc, &wallet.signing_public, identity, Some(&app_id))
                    .unwrap_or_else(|e| panic!("{name}: an entry's operation verifies: {e}"));
            }
        }
        let mut cleaned = raw.clone();
        remove_at(&mut cleaned, st(c, "member"));
        OpsRequest::parse(&serde_json::to_vec(&cleaned).unwrap())
            .unwrap_or_else(|e| panic!("{name}: without the member: {e}"));
    }
}

/// Integers at and beyond the bounds of Switch wire 1.1: 2^53 - 1 is taken; 2^53, a fraction,
/// an exponent and a sign are refused `400 bad_request`, whose signatures verify.
fn check_integer_bounds(keys: &Keys, v: &Value, identity: &[u8; 32]) {
    let cases = arr(&v["integer_bounds"], "cases");
    assert!(cases.len() >= 6);
    for c in cases {
        let name = st(c, "name");
        let body = st(c, "body");
        assert!(
            body.contains(&format!("\"orphan_after\":{}", st(c, "number"))),
            "{name}"
        );
        let signed = signed_of(&c["signed"]);
        assert_eq!(signed.body, b64e(body.as_bytes()), "{name}");
        let (key, app_id) = writer_of(keys, st(c, "writer"), identity);
        let outcome = SignedOp::verify(&signed, &key, identity, app_id.as_ref());
        if c["expect"]["valid"] == Value::Bool(true) {
            let op = outcome.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(op.body().to_json().unwrap(), body.as_bytes(), "{name}");
        } else {
            sig::verify(
                &key,
                labels::sig::OP,
                &[identity, body.as_bytes()],
                &signed.sig_bytes().unwrap(),
            )
            .unwrap();
            expect_refusal(c, &outcome.unwrap_err(), name);
        }
    }
}

/// The attempt deadlines (Switch wire 6.2): which instant `d` a request names is the
/// protocol's, so here each deadline is checked as the Switch's part of the rule: `d + 1 ms`
/// for an instant the case names, read at millisecond precision with further digits
/// truncated, written with three fraction digits, and carried by an `attempt` as written; no
/// deadline is carried as no member. The claim attempt of the operations carries the first
/// case's deadline.
fn check_attempt_deadlines(v: &Value, ops: &HashMap<String, SignedOp>) {
    let cases = arr(&v["attempt_deadlines"], "cases");
    assert!(!cases.is_empty());
    for c in cases {
        let name = st(c, "name");
        let entry = |deadline: Option<u64>| ClaimEntry {
            claim_key: [1; 32],
            attempt_id: [2; 16],
            expected_step: 0,
            kind: EntryKind::Attempt {
                orphan_after: 60,
                deadline,
            },
        };
        let Some(text) = c["deadline"].as_str() else {
            assert!(c["deadline"].is_null(), "{name}");
            assert_eq!(entry(None).fields().deadline, None);
            continue;
        };
        let deadline = parse_rfc3339(text).unwrap();
        assert_eq!(rfc3339(deadline), text, "{name}: three fraction digits");
        assert_eq!(entry(Some(deadline)).fields().deadline, Some(deadline));
        // Every instant the case names, at millisecond precision.
        let mut instants = Vec::new();
        collect_times(&c["fields"], &mut instants);
        if let Some(start) = c["billing_period_start"].as_str() {
            assert!(parse_rfc3339(start).unwrap() < deadline, "{name}");
        }
        if !instants.is_empty() {
            assert!(
                instants.iter().any(|d| attempt_deadline(*d) == deadline),
                "{name}: d + 1 ms for an instant the case names"
            );
        }
    }
    let first = parse_rfc3339(st(&cases[0], "deadline")).unwrap();
    let OpKind::Claim(attempt) = &ops["claim attempt"].body().kind else {
        panic!("the claim attempt is a claim");
    };
    assert_eq!(attempt.deadline, Some(first));
}

fn collect_times(value: &Value, out: &mut Vec<u64>) {
    match value {
        Value::String(s) => {
            if let Ok(ms) = parse_rfc3339(s) {
                out.push(ms);
            }
        }
        Value::Object(m) => m.values().for_each(|x| collect_times(x, out)),
        Value::Array(a) => a.iter().for_each(|x| collect_times(x, out)),
        _ => {}
    }
}
