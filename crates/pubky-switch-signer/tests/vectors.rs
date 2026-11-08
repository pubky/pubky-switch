//! The signer's cases of the Switch vector set (`spec/vectors/`), through its public API.

// The helpers outside `#[test]` functions read fixed vector files, where a failure is a test
// failure: the workspace's no-panic lints don't apply to them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use pubky_switch_core::enc::b64;
use pubky_switch_signer::{IdentityKeyring, IdentitySecret, SecretVault, VaultError};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!("{}/../../spec/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn text<'a>(value: &'a Value, member: &str) -> &'a str {
    value[member]
        .as_str()
        .unwrap_or_else(|| panic!("{member} isn't a string"))
}

/// A host vault in process memory.
struct Vault(Mutex<Option<[u8; 32]>>);

impl SecretVault for Vault {
    fn load(&self) -> Result<Option<IdentitySecret>, VaultError> {
        Ok(self.0.lock().unwrap().map(IdentitySecret::from_bytes))
    }
    fn store(&self, secret: &IdentitySecret) -> Result<(), VaultError> {
        *self.0.lock().unwrap() = Some(*secret.as_bytes());
        Ok(())
    }
    fn delete(&self) -> Result<(), VaultError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

/// `keys.json` identities (Switch wire 1.3, 1.5, 3.13): a vault holding the fixed secret gives
/// the identity's public key, its Pubky ID, and the backup key the signer's backup is sealed
/// to, with its kid.
#[test]
fn test_vectors_keys_identities_through_the_vault() {
    let v = load("keys.json");
    let identities = v["identities"].as_array().expect("identities");
    assert!(!identities.is_empty());
    for identity in identities {
        let secret =
            IdentitySecret::from_slice(&hex::decode(text(identity, "secret_hex")).unwrap())
                .unwrap();
        let vault = Arc::new(Vault(Mutex::new(Some(*secret.as_bytes()))));
        let keyring = IdentityKeyring::open(vault).unwrap();
        let name = text(identity, "name");
        assert_eq!(
            hex::encode(keyring.public_key()),
            text(identity, "public_hex"),
            "{name}"
        );
        assert_eq!(keyring.pubky_id(), text(identity, "pubky_id"), "{name}");
        let (backup_public, backup_kid) = keyring.backup_public().unwrap();
        assert_eq!(
            b64(&backup_public),
            text(identity, "backup_public"),
            "{name}"
        );
        assert_eq!(b64(&backup_kid), text(identity, "backup_kid"), "{name}");
    }
}
