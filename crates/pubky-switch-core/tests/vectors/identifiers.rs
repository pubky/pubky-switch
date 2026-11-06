//! `identifiers.json`: kids, App IDs, blinded inputs, policy hashes, collection IDs, record
//! keys and the invite code (Switch wire 1.5, 1.7).

use pubky_switch_core::enc::{self, app_id, app_id_bytes, b64, hash, kid, lp, suite_kid};
use pubky_switch_core::ident::{self, Policy};

use crate::common::*;

#[test]
fn test_vectors_identifiers() {
    let keys = keys();
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
        let policy = Policy {
            read_scope: st(c, "read_scope").to_owned(),
            write_scopes: write.clone(),
        };
        let mut hashed: Vec<&[u8]> = vec![b"pubky-switch/v1/policy", policy.read_scope.as_bytes()];
        let count = (write.len() as u64).to_be_bytes();
        hashed.push(&count);
        hashed.extend(write.iter().map(String::as_bytes));
        assert_eq!(hex::encode(lp(&hashed)), st(c, "hashed_bytes_hex"));
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
