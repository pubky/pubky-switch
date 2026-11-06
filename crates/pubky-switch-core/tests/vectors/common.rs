//! Helpers shared by the vector tests.

#![allow(dead_code)]

use std::collections::HashMap;

use pubky_switch_core::enc::{pubky_key, unb64, unb64_array};
use pubky_switch_core::{ident, sig};
use serde_json::Value;

/// A vector file of `spec/vectors/`, parsed.
pub fn load(name: &str) -> Value {
    let path = format!("{}/../../spec/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The seed prefix of the vectors' README ("Seeds"): every fixed secret and random value is
/// `BLAKE3(prefix + label)`. It is read from the README, the convention's one source.
pub fn seed_prefix() -> String {
    let path = format!(
        "{}/../../spec/vectors/README.md",
        env!("CARGO_MANIFEST_DIR")
    );
    let readme = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let start = readme
        .find("BLAKE3(\"")
        .expect("the README names the seed rule")
        + 8;
    let len = readme[start..].find('"').expect("a closing quote");
    readme[start..start + len].to_owned()
}

/// A vector seed: `BLAKE3(prefix + label)` (README "Seeds").
pub fn seed(label: &str) -> [u8; 32] {
    *blake3::hash(format!("{}{label}", seed_prefix()).as_bytes()).as_bytes()
}

/// RFC 7748 clamping, as the README applies to X25519 secrets.
pub fn clamp(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

pub fn hx(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap_or_else(|e| panic!("{text}: {e}"))
}

pub fn hx32(text: &str) -> [u8; 32] {
    hx(text).try_into().expect("32 bytes")
}

pub fn b64(text: &str) -> Vec<u8> {
    unb64(text).unwrap_or_else(|e| panic!("{text}: {e}"))
}

pub fn b64n<const N: usize>(text: &str) -> [u8; N] {
    unb64_array::<N>(text).unwrap_or_else(|e| panic!("{text}: {e}"))
}

pub fn pubky(id: &str) -> [u8; 32] {
    pubky_key(id).unwrap_or_else(|e| panic!("{id}: {e}"))
}

pub fn st<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("{k} isn't a string in {v}"))
}

pub fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array()
        .unwrap_or_else(|| panic!("{k} isn't an array in {v}"))
}

pub fn int(v: &Value, k: &str) -> u64 {
    v[k].as_u64()
        .unwrap_or_else(|| panic!("{k} isn't an integer in {v}"))
}

pub fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("an array")
        .iter()
        .map(|x| x.as_str().expect("a string").to_owned())
        .collect()
}

/// One app of `keys.json`.
#[derive(Clone, Debug)]
pub struct AppKeys {
    pub name: String,
    pub identity: [u8; 32],
    pub app_id: String,
    pub signing_public: [u8; 32],
    pub signing_secret: [u8; 32],
    pub bundle_public: [u8; 32],
    pub bundle_secret: [u8; 32],
    pub receive_public: [u8; 32],
    pub receive_secret: [u8; 32],
    pub receive_kid: [u8; 8],
    pub scopes: Vec<String>,
    pub permissions: Vec<String>,
}

/// The fixed keys of `keys.json`.
pub struct Keys {
    pub apps: Vec<AppKeys>,
    /// Ed25519 public key to its secret, for every identity, app and service key.
    pub secrets: HashMap<[u8; 32], [u8; 32]>,
    /// Account (Pubky ID) to its service key at the service its `identity.json` names.
    pub service: HashMap<String, [u8; 32]>,
    /// Identity name (`alice`, `bob`) to its public key.
    pub identities: HashMap<String, [u8; 32]>,
    /// Identity public key to its secret.
    pub identity_secrets: HashMap<[u8; 32], [u8; 32]>,
}

impl Keys {
    pub fn app(&self, name: &str) -> &AppKeys {
        self.apps
            .iter()
            .find(|a| a.name == name)
            .unwrap_or_else(|| panic!("no app {name}"))
    }

    pub fn app_by_id(&self, id: &str) -> &AppKeys {
        self.apps
            .iter()
            .find(|a| a.app_id == id)
            .unwrap_or_else(|| panic!("no app {id}"))
    }

    pub fn identity(&self, name: &str) -> [u8; 32] {
        self.identities[name]
    }

    pub fn secret(&self, public: &[u8; 32]) -> Option<[u8; 32]> {
        self.secrets.get(public).copied()
    }

    pub fn root(&self, identity: &[u8; 32]) -> [u8; 32] {
        ident::switch_root(&self.identity_secrets[identity])
    }

    pub fn naming(&self, identity: &[u8; 32]) -> ident::NamingKey {
        ident::NamingKey::from_root(&self.root(identity))
    }

    pub fn service_key(&self, account: &str) -> [u8; 32] {
        self.service[account]
    }
}

pub fn keys() -> Keys {
    let k = load("keys.json");
    let mut secrets = HashMap::new();
    let mut identities = HashMap::new();
    let mut identity_secrets = HashMap::new();
    for i in arr(&k, "identities") {
        let secret = hx32(st(i, "secret_hex"));
        let public = sig::public_of(&secret);
        secrets.insert(public, secret);
        identity_secrets.insert(public, secret);
        identities.insert(st(i, "name").to_owned(), public);
    }
    let next = &k["next_service_key"];
    secrets.insert(b64n::<32>(st(next, "public")), hx32(st(next, "secret_hex")));
    let mut service = HashMap::new();
    for s in arr(&k, "service_keys") {
        let public = b64n::<32>(st(s, "public"));
        secrets.insert(public, hx32(st(s, "secret_hex")));
        service.insert(st(s, "account").to_owned(), public);
    }
    let apps = arr(&k, "apps")
        .iter()
        .map(|a| {
            let r = &a["receive_key"];
            let app = AppKeys {
                name: st(a, "name").to_owned(),
                identity: pubky(st(a, "identity")),
                app_id: st(a, "app_id").to_owned(),
                signing_public: b64n(st(a, "signing_public")),
                signing_secret: hx32(st(a, "signing_secret_hex")),
                bundle_public: b64n(st(a, "bundle_public")),
                bundle_secret: hx32(st(a, "bundle_secret_hex")),
                receive_public: b64n(st(r, "public")),
                receive_secret: hx32(st(r, "secret_hex")),
                receive_kid: b64n(st(r, "kid")),
                scopes: strings(&a["scopes"]),
                permissions: strings(&a["permissions"]),
            };
            secrets.insert(app.signing_public, app.signing_secret);
            app
        })
        .collect();
    Keys {
        apps,
        secrets,
        service,
        identities,
        identity_secrets,
    }
}

/// Sign again from the seed and compare: Ed25519 signing is deterministic.
pub fn reproduce(
    keys: &Keys,
    public: &[u8; 32],
    label: &str,
    fields: &[&[u8]],
    signature: &[u8; 64],
) -> bool {
    match keys.secret(public) {
        Some(secret) => {
            let key = ed25519_dalek::SigningKey::from_bytes(&secret);
            assert_eq!(
                &sig::sign(&key, label, fields),
                signature,
                "{label}: signature not reproduced from the seed"
            );
            true
        }
        None => false,
    }
}
