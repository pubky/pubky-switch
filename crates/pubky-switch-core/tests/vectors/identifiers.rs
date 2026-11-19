//! `identifiers.json`: kids, App IDs, blinded inputs, policy hashes, collection IDs, record
//! keys and the invite code (Switch wire 1.5, 1.7).

use pubky_switch_core::enc::{self, app_id, app_id_bytes, b64, hash, kid, lp, suite_kid};
use pubky_switch_core::ident::{self, Permanent, Policy};
use serde_json::{Value, json};

use crate::common::*;

#[test]
fn test_vectors_identifiers() {
    let keys = keys();
    generated("identifiers.json", &policy_cases(&keys));
    let v = load("identifiers.json");
    for c in arr(&v, "app_id") {
        let public = b64n::<32>(st(c, "signing_public"));
        assert_eq!(hex::encode(hash(&public)), st(c, "blake3_hex"));
        assert_eq!(
            hex::encode(app_id_bytes(&public)),
            st(c, "app_id_bytes_hex")
        );
        assert_eq!(app_id(&public), st(c, "app_id"));
        assert_eq!(keys.app(st(c, "name")).app_id, st(c, "app_id"));
    }
    for c in arr(&v, "kid") {
        let public = b64n::<32>(st(c, "x25519_public"));
        assert_eq!(
            hex::encode(enc::derive("pubky-switch/v1/kid", &[&public])),
            st(c, "derive_hex")
        );
        assert_eq!(b64(&kid(&public)), st(c, "kid"));
        // A later suite's kid covers the suite too, so the same key bytes give another kid.
        assert_eq!(
            suite_kid(2, &public).to_vec(),
            enc::derive("pubky-switch/v1/kid", &[&2u64.to_be_bytes(), &public])[..8].to_vec()
        );
        assert_ne!(suite_kid(2, &public), kid(&public));
        assert_ne!(suite_kid(2, &public), suite_kid(3, &public));
    }
    for c in arr(&v, "blinded_inputs") {
        let naming = keys.naming(&pubky(st(c, "identity")));
        assert_eq!(
            b64(&naming.to_bytes()),
            st(c, "naming_key"),
            "{}",
            st(c, "name")
        );
        let input = hx(st(c, "input_hex"));
        assert_eq!(
            hex::encode(lp(&[&naming.to_bytes(), &input])),
            st(c, "key_material_hex")
        );
        assert_eq!(b64(&naming.blind(&input)), st(c, "blinded"));
    }
    let mut policies = Vec::new();
    for c in arr(&v, "policies") {
        let write: Vec<String> = strings(&c["write_scopes"]);
        // A permanent policy's member, and the generation its hash ends with, 0 for none.
        let permanent = c.get("permanent").map(|p| Permanent {
            generation: p["generation"].as_u64(),
        });
        let policy = Policy {
            read_scope: st(c, "read_scope").to_owned(),
            write_scopes: write.clone(),
            create_scope: c
                .get("create_scope")
                .map(|v| v.as_str().unwrap().to_owned()),
            permanent,
        };
        assert_eq!(
            hex::encode(policy_bytes(&policy)),
            st(c, "hashed_bytes_hex")
        );
        let policy_hash = policy.hash().unwrap();
        assert_eq!(b64(&policy_hash), st(c, "policy_hash"));
        // Write scopes in another order, or twice, are refused rather than reordered.
        if write.len() > 1 {
            let mut reversed = policy.clone();
            reversed.write_scopes.reverse();
            assert!(reversed.hash().is_err());
        }
        let mut doubled = policy.clone();
        doubled.write_scopes.push(write[write.len() - 1].clone());
        assert!(doubled.hash().is_err());
        policies.push(policy_hash);
    }
    for c in arr(&v, "collections") {
        let identity = pubky(st(c, "identity"));
        assert_eq!(
            b64(&ident::collection_id(st(c, "name"), &identity)),
            st(c, "collection_id")
        );
    }
    for c in arr(&v, "record_keys") {
        let name = st(c, "name");
        let holder = pubky(st(c, "identity"));
        let natural = hx(st(c, "natural_key_hex"));
        assert_eq!(b64(&natural), st(c, "natural_key"));
        let naming = keys.naming(&holder);
        let blinded = naming.blind(&natural);
        assert_eq!(b64(&blinded), st(c, "blinded_natural_key"), "{name}");
        let policy_hash = b64n::<32>(st(c, "policy_hash"));
        assert!(
            policies.contains(&policy_hash),
            "{name}: a policy of the file"
        );
        let collection = st(c, "collection");
        assert_eq!(
            hex::encode(lp(&[collection.as_bytes(), &blinded, &policy_hash])),
            st(c, "key_material_hex"),
            "{name}"
        );
        let record_key = ident::record_key_from_blinded(collection, &blinded, &policy_hash);
        assert_eq!(b64(&record_key), st(c, "record_key"), "{name}");
        assert_eq!(
            naming.record_key(collection, &natural, &policy_hash),
            record_key
        );
        // Another identity's naming key names another record.
        for other in keys.identities.values().filter(|i| **i != holder) {
            assert_ne!(
                keys.naming(other)
                    .record_key(collection, &natural, &policy_hash),
                record_key
            );
        }
    }
    let ic = &v["invite_code"];
    assert_eq!(
        hex::encode(b64n::<16>(st(ic, "code"))),
        st(ic, "code_bytes_hex")
    );
    assert_eq!(
        b64(&ident::invite_code_hash(st(ic, "code")).unwrap()),
        st(ic, "code_hash")
    );
    let uri = st(ic, "uri");
    let identity = uri
        .strip_prefix("pubky://")
        .and_then(|rest| rest.split('?').next())
        .unwrap();
    assert_eq!(
        ident::invite_code_uri(&pubky(identity), st(ic, "code")),
        uri
    );
}

/// Independent encoding of the policy inputs in wire 1.5.
fn policy_bytes(policy: &Policy) -> Vec<u8> {
    let label: &[u8] = match (policy.permanent, policy.create_scope.is_some()) {
        (None, false) => b"pubky-switch/v1/policy",
        (Some(_), false) => b"pubky-switch/v1/permanent-policy",
        (None, true) => b"pubky-switch/v1/create-scope-policy",
        (Some(_), true) => b"pubky-switch/v1/permanent-create-scope-policy",
    };
    let count = (policy.write_scopes.len() as u64).to_be_bytes();
    let generation = policy
        .permanent
        .map(|p| p.generation.unwrap_or(0).to_be_bytes());
    let mut parts = vec![label, policy.read_scope.as_bytes()];
    parts.extend(policy.create_scope.as_ref().map(String::as_bytes));
    parts.push(&count);
    parts.extend(policy.write_scopes.iter().map(String::as_bytes));
    parts.extend(generation.as_ref().map(|g| &g[..]));
    lp(&parts)
}

/// The permanent policies and record keys `pubky-switch-core` generates (README "How the
/// files were generated", wire 1.5, spec 10.3.1): `tasks`'s `task_closures`, under a
/// permanent policy naming no generation, with the record of the task of `task_items record
/// of a task done without an assignment`; and its `share_counts`, under a permanent policy
/// naming generation 1, with the record whose natural key is that of `shares record`
/// followed by `lp(u64(1))`, the generation it counts.
fn policy_cases(keys: &Keys) -> Vec<(Place<'static>, Value)> {
    let v = load("identifiers.json");
    let record = |name: &str| -> Value {
        arr(&v, "record_keys")
            .iter()
            .find(|c| st(c, "name") == name)
            .unwrap_or_else(|| panic!("no record key {name}"))
            .clone()
    };
    let policy_case = |name: &str, policy: &Policy| {
        let policy_hash = policy.hash().unwrap();
        let mut case = json!({
            "name": name,
            "read_scope": policy.read_scope,
            "write_scopes": policy.write_scopes,
            "hashed_bytes_hex": hex::encode(policy_bytes(policy)),
            "policy_hash": b64(&policy_hash),
        });
        if let Some(scope) = &policy.create_scope {
            case["create_scope"] = json!(scope);
        }
        if let Some(permanent) = policy.permanent {
            case["permanent"] = json!({"generation": permanent.generation});
        }
        (case, policy_hash)
    };
    let key_case =
        |name: &str, base: &Value, collection: &str, natural: Vec<u8>, policy: [u8; 32]| {
            let holder = pubky(st(base, "identity"));
            let blinded = keys.naming(&holder).blind(&natural);
            json!({
                "name": name,
                "identity": st(base, "identity"),
                "collection": collection,
                "natural_key": b64(&natural),
                "natural_key_hex": hex::encode(&natural),
                "blinded_natural_key": b64(&blinded),
                "policy_hash": b64(&policy),
                "key_material_hex": hex::encode(lp(&[collection.as_bytes(), &blinded, &policy])),
                "record_key": b64(&ident::record_key_from_blinded(collection, &blinded, &policy)),
            })
        };
    let (closures, closures_hash) = policy_case(
        "task_closures, permanent",
        &Policy::new("tasks", &["tasks"]).permanent(None),
    );
    let (counts, counts_hash) = policy_case(
        "share_counts, permanent for generation 1",
        &Policy::new("tasks_share", &["tasks_share"]).permanent(Some(1)),
    );
    let roles = Policy::new("tasks", &["tasks_share_run"]).with_create_scope("tasks_people_admin");
    let (separate, _) = policy_case("share_counts, separate create scope", &roles);
    let (permanent_separate, separate_hash) = policy_case(
        "share_counts, separate create scope and permanent",
        &roles.permanent(None),
    );
    let task = record("task_items record of a task done without an assignment");
    let share = record("shares record");
    let mut counted = hx(st(&share, "natural_key_hex"));
    counted.extend(lp(&[&1u64.to_be_bytes()]));
    vec![
        (Place::Case("/policies"), closures),
        (Place::Case("/policies"), counts),
        (Place::Case("/policies"), separate),
        (Place::Case("/policies"), permanent_separate),
        (
            Place::Case("/record_keys"),
            key_case(
                "share_counts record with a separate create scope",
                &share,
                "share_counts",
                hx(st(&share, "natural_key_hex")),
                separate_hash,
            ),
        ),
        (
            Place::Case("/record_keys"),
            key_case(
                "task_closures record of a task done without an assignment",
                &task,
                "task_closures",
                hx(st(&task, "natural_key_hex")),
                closures_hash,
            ),
        ),
        (
            Place::Case("/record_keys"),
            key_case(
                "share_counts record of generation 1",
                &share,
                "share_counts",
                counted,
                counts_hash,
            ),
        ),
    ]
}
