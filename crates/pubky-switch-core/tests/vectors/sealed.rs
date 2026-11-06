//! `sealed.json`: sealed shared record values, with their key, AAD, nonce, padded length and
//! ciphertext (Switch wire 6.2, Switch spec 13.4).

use pubky_switch_core::keys::{IdentityKey, ScopeKeys};
use pubky_switch_core::sealed::{self, RecordValue, SealedValue, TAG_LEN};
use serde_json::Value;

use crate::common::*;

#[test]
fn test_vectors_sealed() {
    let keys = keys();
    let v = load("sealed.json");
    let cases = arr(&v, "cases");
    assert!(!cases.is_empty());
    let mut deletes = 0;
    for c in cases {
        let name = st(c, "name");
        let identity = hx32(st(c, "identity_hex"));
        let record_key = b64n::<32>(st(c, "record_key"));
        let scope = st(c, "scope");
        let data_epoch = int(c, "data_epoch");

        // The key: the identity's scope_key(data_epoch, scope) (Switch wire 1.5).
        let secret = keys.identity_secrets[&identity];
        let identity_key = IdentityKey::from_secret(secret);
        let scope_key = identity_key.scope_key(data_epoch, scope);
        assert_eq!(
            hex::encode(scope_key),
            st(c, "scope_key_hex"),
            "{name}: key"
        );

        // The AAD and the nonce.
        let aad = sealed::aad(&identity, scope, &record_key);
        assert_eq!(hex::encode(&aad), st(c, "aad_hex"), "{name}: AAD");
        let nonce: [u8; 24] = hx(st(c, "nonce_hex")).try_into().expect("24 bytes");

        // The padded length, and the value as the record carries it.
        let json = st(c, "plaintext").as_bytes();
        let padded = sealed::pad(json).unwrap();
        assert_eq!(
            padded.len() as u64,
            int(c, "padded_len"),
            "{name}: padded_len"
        );
        assert_eq!(
            sealed::padded_len(json.len()),
            Some(padded.len()),
            "{name}: padded_len"
        );
        let carried: SealedValue =
            serde_json::from_value(c["sealed"].clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(carried.nonce, nonce, "{name}: nonce");
        assert_eq!(carried.scope, scope, "{name}: scope");
        assert_eq!(carried.data_epoch, data_epoch, "{name}: data_epoch");
        assert_eq!(carried.ct.len() as u64, int(c, "ct_len"), "{name}: ct_len");
        assert_eq!(carried.ct.len(), padded.len() + TAG_LEN, "{name}: ct_len");
        assert_eq!(
            serde_json::to_value(&carried).unwrap(),
            c["sealed"],
            "{name}"
        );
        carried
            .check_shape(scope)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(carried.check_shape("another-scope").is_err());

        // Sealed again with the fixed nonce, byte for byte.
        let resealed = SealedValue::seal_with_nonce(
            &scope_key,
            &identity,
            data_epoch,
            scope,
            &record_key,
            json,
            &nonce,
        )
        .unwrap();
        assert_eq!(resealed, carried, "{name}: ciphertext");

        // It opens to the value, or to a delete, with the scope key the reader holds.
        let opened = carried.open(&scope_key, &identity, &record_key).unwrap();
        let is_delete = c["is_delete"].as_bool().expect("is_delete");
        assert_eq!(is_delete, json.is_empty(), "{name}");
        assert_eq!(carried.looks_like_delete(), is_delete, "{name}");
        if is_delete {
            deletes += 1;
            assert_eq!(opened, RecordValue::Delete, "{name}");
            assert_eq!(
                carried.ct.len(),
                TAG_LEN,
                "{name}: a delete is the tag alone"
            );
        } else {
            assert_eq!(opened, RecordValue::Json(json.to_vec()), "{name}");
            assert!(sealed::BUCKETS.contains(&padded.len()), "{name}");
        }
        let held = ScopeKeys::derive_range(&identity_key, &[scope.to_owned()], 1, data_epoch);
        assert_eq!(
            carried.open_with(&held, &identity, &record_key).unwrap(),
            opened,
            "{name}"
        );

        // The AAD binds the record key, the scope and the identity; another key fails.
        assert!(carried.open(&scope_key, &identity, &[0; 32]).is_err());
        assert!(carried.open(&scope_key, &[0; 32], &record_key).is_err());
        let mut moved = carried.clone();
        moved.scope = "another-scope".into();
        assert!(moved.open(&scope_key, &identity, &record_key).is_err());
        let other_epoch = identity_key.scope_key(data_epoch + 1, scope);
        assert!(carried.open(&other_epoch, &identity, &record_key).is_err());
        let earlier = ScopeKeys::derive_range(&identity_key, &[scope.to_owned()], 1, 1);
        if data_epoch > 1 {
            assert!(carried.open_with(&earlier, &identity, &record_key).is_err());
        }

        // A value with a member beside the four is refused.
        let mut extra = c["sealed"].clone();
        extra["deleted"] = Value::Bool(true);
        assert!(serde_json::from_value::<SealedValue>(extra).is_err());
    }
    assert!(deletes > 0, "a delete marker");
}
