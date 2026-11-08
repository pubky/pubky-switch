//! `keys.json`: the fixed identities, apps and service keys (Switch wire 1.3, 1.5, 3).

use pubky_switch_core::enc::{self, app_id, app_id_bytes, b64, kid, lp, pubky_id};
use pubky_switch_core::{ident, keys as k, sig};

use crate::common::*;

#[test]
fn test_vectors_keys() {
    let v = load("keys.json");
    let mut roots = std::collections::HashMap::new();
    for i in arr(&v, "identities") {
        let secret = seed(st(i, "seed_label"));
        assert_eq!(hex::encode(secret), st(i, "secret_hex"));
        let public = sig::public_of(&secret);
        assert_eq!(hex::encode(public), st(i, "public_hex"));
        assert_eq!(pubky_id(&public), st(i, "pubky_id"));
        let identity = k::IdentityKey::from_secret(secret);
        assert_eq!(identity.public(), public);
        // The Switch root from the identity secret, the naming key from the root.
        let root = ident::switch_root(&secret);
        assert_eq!(hex::encode(root), st(i, "switch_root_hex"));
        assert_eq!(identity.switch_root(), root);
        assert_eq!(
            b64(&identity.naming_key().to_bytes()),
            st(i, "naming_key"),
            "naming key"
        );
        // The backup key: `derive("pubky-switch/v1/backup-key", identity secret)`,
        // clamped, its public key and kid; not the Switch root.
        let backup = identity.backup_secret();
        assert_eq!(hex::encode(backup), st(i, "backup_secret_hex"));
        assert_eq!(
            backup,
            clamp(enc::derive("pubky-switch/v1/backup-key", &[&secret]))
        );
        assert_eq!(b64(&identity.backup_public()), st(i, "backup_public"));
        assert_eq!(b64(&kid(&identity.backup_public())), st(i, "backup_kid"));
        assert_ne!(backup, root);
        roots.insert(st(i, "name").to_owned(), (root, identity));
    }
    // Scope keys of several data epochs and scopes.
    for c in arr(&v, "scope_keys") {
        let (root, identity) = &roots[st(c, "identity")];
        let (epoch, scope) = (int(c, "data_epoch"), st(c, "scope"));
        assert_eq!(
            hex::encode(lp(&[root, &epoch.to_be_bytes(), scope.as_bytes()])),
            st(c, "key_material_hex")
        );
        assert_eq!(b64(&ident::scope_key(root, epoch, scope)), st(c, "key"));
        assert_eq!(b64(&identity.scope_key(epoch, scope)), st(c, "key"));
    }
    // Scope keys differ by epoch and by scope.
    let scoped: Vec<_> = arr(&v, "scope_keys")
        .iter()
        .map(|c| {
            (
                st(c, "identity"),
                int(c, "data_epoch"),
                st(c, "scope"),
                st(c, "key"),
            )
        })
        .collect();
    for (i, a) in scoped.iter().enumerate() {
        for b in &scoped[i + 1..] {
            if (a.0, a.1, a.2) != (b.0, b.1, b.2) {
                assert_ne!(a.3, b.3, "{a:?} and {b:?} share a key");
            }
        }
    }
    // Sub-scope keys: `derive("pubky-switch/v1/sub-scope-key", scope_key(e, name), sub)`.
    let subs = arr(&v["sub_scope_keys"], "keys");
    assert_eq!(subs.len(), 2);
    for c in subs {
        let (root, identity) = &roots[st(c, "identity")];
        let (epoch, parent, sub) = (int(c, "data_epoch"), st(c, "parent"), st(c, "sub"));
        assert_eq!(st(c, "scope"), format!("{parent}:{sub}"));
        let parent_key = ident::scope_key(root, epoch, parent);
        assert_eq!(b64(&parent_key), st(c, "parent_key"));
        assert_eq!(
            hex::encode(lp(&[&parent_key, sub.as_bytes()])),
            st(c, "key_material_hex")
        );
        let key = ident::sub_scope_key(&parent_key, sub);
        assert_eq!(b64(&key), st(c, "key"));
        assert_eq!(
            b64(&ident::key_of_scope(root, epoch, st(c, "scope"))),
            st(c, "key")
        );
        assert_eq!(
            b64(&identity.scope_key(epoch, st(c, "scope"))),
            st(c, "key")
        );
        // Held through the parent's key, not the other way round.
        let held = k::ScopeKeys::derive_range(identity, &[parent.to_owned()], epoch, epoch);
        assert_eq!(held.get(epoch, st(c, "scope")), Some(key));
        let only_sub =
            k::ScopeKeys::derive_range(identity, &[st(c, "scope").to_owned()], epoch, epoch);
        assert_eq!(only_sub.get(epoch, parent), None);
        assert_ne!(key, parent_key);
        assert_ne!(key, ident::sub_scope_key(&parent_key, "another-sub"));
    }
    for s in arr(&v, "service_keys") {
        let secret = seed(st(s, "seed_label"));
        assert_eq!(hex::encode(secret), st(s, "secret_hex"));
        assert_eq!(b64(&sig::public_of(&secret)), st(s, "public"));
    }
    let next = &v["next_service_key"];
    let next_secret = seed(st(next, "seed_label"));
    assert_eq!(hex::encode(next_secret), st(next, "secret_hex"));
    assert_eq!(b64(&sig::public_of(&next_secret)), st(next, "public"));
    let current: Vec<&str> = arr(&v, "service_keys")
        .iter()
        .map(|s| st(s, "public"))
        .collect();
    assert!(
        !current.contains(&st(next, "public")),
        "the next service's key is its own"
    );
    for a in arr(&v, "apps") {
        let signing = seed(st(a, "signing_seed_label"));
        assert_eq!(hex::encode(signing), st(a, "signing_secret_hex"));
        let bundle = clamp(seed(st(a, "bundle_seed_label")));
        assert_eq!(hex::encode(bundle), st(a, "bundle_secret_hex"));
        let app = k::AppKeys::from_secrets(signing, seed(st(a, "bundle_seed_label")));
        let public = sig::public_of(&signing);
        assert_eq!(b64(&public), st(a, "signing_public"));
        assert_eq!(app.signing_public(), public);
        assert_eq!(
            hex::encode(app_id_bytes(&public)),
            st(a, "app_id_bytes_hex")
        );
        assert_eq!(app_id(&public), st(a, "app_id"));
        assert_eq!(app.app_id(), st(a, "app_id"));
        assert_eq!(app.bundle_secret(), bundle);
        assert_eq!(b64(&app.bundle_public()), st(a, "bundle_public"));
        assert_eq!(b64(&kid(&app.bundle_public())), st(a, "bundle_kid"));
        let r = &a["receive_key"];
        let receive = k::ReceiveKey::from_secret(int(r, "n"), seed(st(r, "seed_label")));
        assert_eq!(hex::encode(receive.secret()), st(r, "secret_hex"));
        assert_eq!(b64(&receive.public), st(r, "public"));
        assert_eq!(b64(&receive.kid), st(r, "kid"));
        assert!(!enc::x25519_low_order(&receive.public));
    }
    // The removed app has an App ID but no seed: it can't be derived.
    assert!(enc::app_id_decode(st(&v["removed_app"], "app_id")).is_ok());
}
