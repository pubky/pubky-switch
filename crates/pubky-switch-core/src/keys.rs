//! Key types (Switch spec 3.1, 3.5, 3.6): the identity key, an app's signing and bundle
//! keys, receive keys, and scope keys per data epoch.
//!
//! Every secret is zeroized when its holder is dropped, and no `Debug` output shows one.
//! Where secrets are stored is the caller's choice; Switch spec 3.1 says where they belong.

use ed25519_dalek::SigningKey;
use hpke::{Deserializable as _, Kem as _, Serializable as _, kem::X25519HkdfSha256};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::enc::{self, app_id, app_id_bytes, b64, kid, pubky_id, serde_b64};
use crate::error::{Error, Result};
use crate::ident::{self, NamingKey};
use crate::sig::{self, SignedDoc};

/// Clamp 32 bytes as an X25519 secret (RFC 7748).
pub fn clamp(mut secret: [u8; 32]) -> [u8; 32] {
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    secret
}

/// The X25519 public key of a secret.
pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(*secret).to_bytes()
}

/// The HPKE private key of X25519 secret bytes.
///
/// # Errors
///
/// [`Error::Crypto`] if the bytes aren't an X25519 secret.
pub fn x25519_private(secret: &[u8; 32]) -> Result<<X25519HkdfSha256 as hpke::Kem>::PrivateKey> {
    <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(secret)
        .map_err(|_| Error::Crypto("not an X25519 secret".into()))
}

/// The HPKE public key of X25519 public key bytes.
///
/// # Errors
///
/// [`Error::Crypto`] if the bytes aren't an X25519 public key.
pub fn x25519_public_key(public: &[u8; 32]) -> Result<<X25519HkdfSha256 as hpke::Kem>::PublicKey> {
    <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(public)
        .map_err(|_| Error::Crypto("not an X25519 public key".into()))
}

/// The bytes of an HPKE X25519 public key.
// For the envelopes' sealing (Switch wire 4.3); outside this crate's tests nothing calls it yet.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn x25519_public_bytes(key: &<X25519HkdfSha256 as hpke::Kem>::PublicKey) -> [u8; 32] {
    key.to_bytes().into()
}

/// The X25519 public key of an HPKE private key.
// For the envelopes' sealing (Switch wire 4.3); outside this crate's tests nothing calls it yet.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn hpke_public_of(private: &<X25519HkdfSha256 as hpke::Kem>::PrivateKey) -> [u8; 32] {
    x25519_public_bytes(&X25519HkdfSha256::sk_to_pk(private))
}

/// The identity key (Switch spec 3.1): the identity's Ed25519 secret.
///
/// It exists only in the signer and the signer's backups. Its holder derives every scope
/// key and the naming key, so it reads all of the identity's sealed data.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IdentityKey {
    secret: [u8; 32],
}

impl std::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentityKey({})", self.id())
    }
}

impl IdentityKey {
    /// A fresh identity key from the secure random generator.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] if the generator fails.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            secret: enc::random_bytes()?,
        })
    }

    /// The identity key with this 32-byte Ed25519 secret (seed). Sensitive.
    pub fn from_secret(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    /// The secret bytes, for a hand-over or a backup only (Switch wire 3.12, 3.13).
    /// Sensitive.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.secret)
    }

    /// The Ed25519 public key.
    pub fn public(&self) -> [u8; 32] {
        self.signing_key().verifying_key().to_bytes()
    }

    /// The Pubky ID.
    pub fn id(&self) -> String {
        pubky_id(&self.public())
    }

    /// Sign `lp(label, fields...)` (Switch wire 2.1).
    pub fn sign(&self, label: &str, fields: &[&[u8]]) -> [u8; 64] {
        sig::sign(&self.signing_key(), label, fields)
    }

    /// Sign exact body bytes as a signed document over `lp(label, prefix..., body)`.
    pub fn sign_doc(&self, label: &str, prefix: &[&[u8]], body: Vec<u8>) -> SignedDoc {
        SignedDoc::sign_bytes(&self.signing_key(), label, prefix, body)
    }

    /// The Switch root (Switch wire 1.5). Sensitive: it yields every scope key and the
    /// naming key.
    pub fn switch_root(&self) -> [u8; 32] {
        ident::switch_root(&self.secret)
    }

    /// The key of `scope` at `data_epoch`, a sub-scope included (Switch wire 1.5).
    pub fn scope_key(&self, data_epoch: u64, scope: &str) -> [u8; 32] {
        ident::key_of_scope(&self.switch_root(), data_epoch, scope)
    }

    /// The identity's naming key (Switch wire 1.5).
    pub fn naming_key(&self) -> NamingKey {
        NamingKey::from_root(&self.switch_root())
    }

    /// The X25519 secret of the backup key (Switch wire 1.5, 3.13). Sensitive.
    pub fn backup_secret(&self) -> [u8; 32] {
        ident::backup_secret(&self.secret)
    }

    /// The backup key's public key, which the signer's backup is sealed to.
    pub fn backup_public(&self) -> [u8; 32] {
        x25519_public(&self.backup_secret())
    }
}

/// An app's static keys (Switch spec 3.1): its Ed25519 signing key and X25519 bundle key.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AppKeys {
    #[serde(with = "serde_b64")]
    signing: [u8; 32],
    #[serde(with = "serde_b64")]
    bundle: [u8; 32],
}

impl std::fmt::Debug for AppKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppKeys({})", self.app_id())
    }
}

impl AppKeys {
    /// Fresh keys from the secure random generator.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] if the generator fails.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            signing: enc::random_bytes()?,
            bundle: clamp(enc::random_bytes()?),
        })
    }

    /// Keys from their secrets: an Ed25519 seed and an X25519 secret, which is clamped.
    /// Sensitive.
    pub fn from_secrets(signing: [u8; 32], bundle: [u8; 32]) -> Self {
        Self {
            signing,
            bundle: clamp(bundle),
        }
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.signing)
    }

    /// The signing key's Ed25519 public key.
    pub fn signing_public(&self) -> [u8; 32] {
        self.signing_key().verifying_key().to_bytes()
    }

    /// The App ID (Switch wire 1.3).
    pub fn app_id(&self) -> String {
        app_id(&self.signing_public())
    }

    /// The App ID's 16 bytes.
    pub fn app_id_bytes(&self) -> [u8; 16] {
        app_id_bytes(&self.signing_public())
    }

    /// The bundle key's X25519 public key.
    pub fn bundle_public(&self) -> [u8; 32] {
        x25519_public(&self.bundle)
    }

    /// The bundle key's secret, to open key bundles. Sensitive.
    pub fn bundle_secret(&self) -> [u8; 32] {
        self.bundle
    }

    /// Sign `lp(label, fields...)` (Switch wire 2.1).
    pub fn sign(&self, label: &str, fields: &[&[u8]]) -> [u8; 64] {
        sig::sign(&self.signing_key(), label, fields)
    }

    /// Sign exact body bytes as a signed document over `lp(label, prefix..., body)`.
    pub fn sign_doc(&self, label: &str, prefix: &[&[u8]], body: Vec<u8>) -> SignedDoc {
        SignedDoc::sign_bytes(&self.signing_key(), label, prefix, body)
    }
}

/// One receive key (Switch spec 3.6): an X25519 key with its number `n` and its kid.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ReceiveKey {
    /// The registration number; each new key is one higher (Switch spec 3.6).
    pub n: u64,
    #[serde(with = "serde_b64")]
    secret: [u8; 32],
    /// The X25519 public key.
    #[serde(with = "serde_b64")]
    pub public: [u8; 32],
    /// The 8-byte kid (Switch wire 1.5).
    #[serde(with = "serde_b64")]
    pub kid: [u8; 8],
}

impl std::fmt::Debug for ReceiveKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReceiveKey(n={}, kid={})", self.n, b64(&self.kid))
    }
}

impl ReceiveKey {
    /// A fresh receive key: 32 random bytes, clamped (Switch spec 3.6 recommends it).
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] if the generator fails.
    pub fn generate(n: u64) -> Result<Self> {
        Ok(Self::from_secret(n, enc::random_bytes()?))
    }

    /// The receive key with these secret bytes, clamped.
    pub fn from_secret(n: u64, secret: [u8; 32]) -> Self {
        let secret = clamp(secret);
        let public = x25519_public(&secret);
        Self {
            n,
            secret,
            public,
            kid: kid(&public),
        }
    }

    /// The secret bytes, to open envelopes. Sensitive.
    pub fn secret(&self) -> [u8; 32] {
        self.secret
    }
}

/// One scope key an app holds, for one scope and data epoch (Switch spec 3.5). Its `Debug`
/// names the epoch and scope, never the key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ScopeKey {
    /// The data epoch.
    pub data_epoch: u64,
    /// The scope, a sub-scope included.
    pub scope: String,
    /// The key.
    #[serde(with = "serde_b64")]
    pub key: [u8; 32],
}

impl std::fmt::Debug for ScopeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ScopeKey({}, {}, ..)", self.data_epoch, self.scope)
    }
}

/// The scope keys an app holds (Switch spec 3.5).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeKeys {
    /// Every key held.
    pub keys: Vec<ScopeKey>,
}

impl ScopeKeys {
    /// The keys of `scopes` for the data epochs `from..=to`, as the signer derives them for
    /// a key bundle (Switch spec 3.5).
    pub fn derive_range(identity: &IdentityKey, scopes: &[String], from: u64, to: u64) -> Self {
        let root = identity.switch_root();
        let mut keys = Vec::new();
        for epoch in from.max(1)..=to {
            for scope in scopes {
                keys.push(ScopeKey {
                    data_epoch: epoch,
                    scope: scope.clone(),
                    key: ident::key_of_scope(&root, epoch, scope),
                });
            }
        }
        Self { keys }
    }

    /// The key of `scope` at `data_epoch`, if held. An app holding a scope's key derives
    /// every one of its sub-scopes' keys of that epoch from it (Switch spec 3.5).
    pub fn get(&self, data_epoch: u64, scope: &str) -> Option<[u8; 32]> {
        let held = |scope: &str| {
            self.keys
                .iter()
                .find(|k| k.data_epoch == data_epoch && k.scope == scope)
                .map(|k| k.key)
        };
        held(scope).or_else(|| {
            let (parent, sub) = scope.split_once(':')?;
            Some(ident::sub_scope_key(&held(parent)?, sub))
        })
    }

    /// Add the keys of `other` that aren't held yet.
    pub fn merge(&mut self, other: &ScopeKeys) {
        for key in &other.keys {
            if self.get(key.data_epoch, &key.scope).is_none() {
                self.keys.push(key.clone());
            }
        }
    }

    /// The highest data epoch held for `scope`.
    pub fn max_epoch(&self, scope: &str) -> Option<u64> {
        self.keys
            .iter()
            .filter(|k| k.scope == scope)
            .map(|k| k.data_epoch)
            .max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_output_hides_secrets() {
        let identity = IdentityKey::from_secret([1; 32]);
        assert!(format!("{identity:?}").starts_with("IdentityKey("));
        let receive = ReceiveKey::from_secret(0, [2; 32]);
        assert!(!format!("{receive:?}").contains(&b64(&receive.secret())));
        let scope = ScopeKey {
            data_epoch: 1,
            scope: "s".into(),
            key: [3; 32],
        };
        assert_eq!(format!("{scope:?}"), "ScopeKey(1, s, ..)");
    }

    #[test]
    fn test_scope_keys_derive_sub_scopes_but_not_parents() {
        let identity = IdentityKey::from_secret([4; 32]);
        let parent = ScopeKeys::derive_range(&identity, &["name".into()], 1, 2);
        assert_eq!(
            parent.get(2, "name:sub"),
            Some(identity.scope_key(2, "name:sub"))
        );
        let sub = ScopeKeys::derive_range(&identity, &["name:sub".into()], 1, 1);
        assert_eq!(sub.get(1, "name"), None);
        assert_eq!(sub.get(2, "name:sub"), None);
        assert_eq!(parent.max_epoch("name"), Some(2));
    }

    #[test]
    fn test_x25519_public_matches_hpke() {
        let secret = clamp([5; 32]);
        let private = x25519_private(&secret).unwrap();
        assert_eq!(hpke_public_of(&private), x25519_public(&secret));
    }
}
