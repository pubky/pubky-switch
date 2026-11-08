//! Derived keys and identifiers (Switch wire 1.5, 1.7): the Switch root, scope and sub-scope
//! keys, the backup key, the naming key and blinded inputs, policy hashes, collection IDs,
//! record keys and invite code hashes.
//!
//! The Switch root and everything derived from it are sensitive: whoever holds the root
//! reads all of the identity's sealed data, past and future (Switch spec 3.1, 3.5).

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::enc::{derive, hash, lp, serde_b64, u64be, unb64};
use crate::error::{Result, invalid};
use crate::labels;

/// `switch_root = derive("pubky-switch/v1/scope-root", identity secret)` (Switch wire 1.5).
///
/// Only the signer computes it; it is never granted or delivered. It yields every scope key
/// of every data epoch and the naming key.
pub fn switch_root(identity_secret: &[u8; 32]) -> [u8; 32] {
    derive(labels::derive::SCOPE_ROOT, &[identity_secret])
}

/// `scope_key(e, s) = derive("pubky-switch/v1/scope-key", switch_root, u64(e), s)`, for a
/// scope name `s` without a sub-scope (Switch wire 1.5).
///
/// It comes from the Switch's own derivation, so no Pubky grant on any path reveals it
/// (Switch spec 3.5).
pub fn scope_key(switch_root: &[u8; 32], data_epoch: u64, scope: &str) -> [u8; 32] {
    derive(
        labels::derive::SCOPE_KEY,
        &[switch_root, &u64be(data_epoch), scope.as_bytes()],
    )
}

/// `sub_scope_key(e, name:<sub>) = derive("pubky-switch/v1/sub-scope-key", scope_key(e,
/// name), sub)` (Switch wire 1.5).
///
/// An app holding `name` derives every sub-scope's key from its `name` key; an app holding
/// only the sub-scope gets the key in its key bundles and can't work back to the parent's.
pub fn sub_scope_key(parent_key: &[u8; 32], sub: &str) -> [u8; 32] {
    derive(labels::derive::SUB_SCOPE_KEY, &[parent_key, sub.as_bytes()])
}

/// The key of any scope at a data epoch, a sub-scope `name:<sub>` included, from the
/// Switch root (Switch wire 1.5).
pub fn key_of_scope(switch_root: &[u8; 32], data_epoch: u64, scope: &str) -> [u8; 32] {
    match scope.split_once(':') {
        Some((name, sub)) => sub_scope_key(&scope_key(switch_root, data_epoch, name), sub),
        None => scope_key(switch_root, data_epoch, scope),
    }
}

/// The backup key's X25519 secret: `derive("pubky-switch/v1/backup-key", identity secret)`,
/// clamped (Switch wire 1.5, 3.13).
///
/// Only a holder of the identity key derives it, and it opens every signer backup of the
/// identity.
pub fn backup_secret(identity_secret: &[u8; 32]) -> [u8; 32] {
    crate::keys::clamp(derive(labels::derive::BACKUP_KEY, &[identity_secret]))
}

/// An identity's naming key: `derive("pubky-switch/v1/naming", switch_root)` (Switch wire
/// 1.5).
///
/// It blinds natural keys and a protocol's claim inputs, so the keys of records and claims
/// don't name their counterparty. It hides inputs from the service, not data from apps, so
/// it never rotates. Its `Debug` output never shows the key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct NamingKey(#[serde(with = "serde_b64")] [u8; 32]);

impl std::fmt::Debug for NamingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NamingKey(..)")
    }
}

impl NamingKey {
    /// The naming key of the identity with this Switch root.
    pub fn from_root(switch_root: &[u8; 32]) -> Self {
        Self(derive(labels::derive::NAMING, &[switch_root]))
    }

    /// A naming key from its 32 bytes, as a key bundle delivers it.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The key's bytes. Sensitive.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// `blind(x) = derive("pubky-switch/v1/name", naming_key, x)` (Switch wire 1.5).
    pub fn blind(&self, input: &[u8]) -> [u8; 32] {
        derive(labels::derive::NAME, &[&self.0, input])
    }

    /// The record key of a natural key: `derive("pubky-switch/v1/record", collection name,
    /// blind(natural key), policy hash)` (Switch wire 1.5).
    pub fn record_key(
        &self,
        collection: &str,
        natural_key: &[u8],
        policy_hash: &[u8; 32],
    ) -> [u8; 32] {
        record_key_from_blinded(collection, &self.blind(natural_key), policy_hash)
    }
}

/// A shared record's policy: one read scope and the write scopes, any one of which allows
/// writing (Switch spec 10.3).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    /// The scope needed to read; values are sealed under its key.
    pub read_scope: String,
    /// The scopes that allow writing, sorted ascending by bytes, without duplicates.
    pub write_scopes: Vec<String>,
}

impl Policy {
    /// A policy, with its write scopes sorted and without duplicates.
    pub fn new(read_scope: &str, write_scopes: &[&str]) -> Self {
        let mut write_scopes: Vec<String> = write_scopes.iter().map(|s| (*s).to_owned()).collect();
        write_scopes.sort();
        write_scopes.dedup();
        Self {
            read_scope: read_scope.to_owned(),
            write_scopes,
        }
    }

    /// `hash(lp("pubky-switch/v1/policy", read_scope, u64(n), write_scope_1, ...,
    /// write_scope_n))` (Switch wire 1.5).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] unless there is at least one write scope and they are
    /// sorted ascending by bytes without duplicates.
    pub fn hash(&self) -> Result<[u8; 32]> {
        if self.write_scopes.is_empty() {
            return invalid("Switch wire 1.5: a policy needs at least one write scope");
        }
        if self.write_scopes.windows(2).any(|w| w[0] >= w[1]) {
            return invalid(
                "Switch wire 1.5: write scopes must be sorted ascending without duplicates",
            );
        }
        let count = u64be(self.write_scopes.len() as u64);
        let mut parts: Vec<&[u8]> = vec![
            labels::derive::POLICY.as_bytes(),
            self.read_scope.as_bytes(),
            &count,
        ];
        parts.extend(self.write_scopes.iter().map(String::as_bytes));
        Ok(hash(&lp(&parts)))
    }
}

/// `derive("pubky-switch/v1/collection", collection name, identity)` (Switch wire 1.5).
pub fn collection_id(collection: &str, identity: &[u8; 32]) -> [u8; 32] {
    derive(
        labels::derive::COLLECTION,
        &[collection.as_bytes(), identity],
    )
}

/// `derive("pubky-switch/v1/record", collection name, blinded natural key, policy hash)`
/// (Switch wire 1.5), from the blinded natural key, as the service recomputes it from a
/// creating `record.put`'s `id_inputs`.
pub fn record_key_from_blinded(
    collection: &str,
    blinded: &[u8; 32],
    policy_hash: &[u8; 32],
) -> [u8; 32] {
    derive(
        labels::derive::RECORD,
        &[collection.as_bytes(), blinded, policy_hash],
    )
}

/// The smallest number of random bytes in an invite code (Switch wire 1.7).
pub const INVITE_CODE_MIN_BYTES: usize = 16;

/// An invite code's hash: `hash(code bytes)`, the code decoded from base64url (Switch wire
/// 1.5, 1.7).
///
/// # Errors
///
/// [`crate::Error::Invalid`] if the code isn't base64url of at least 16 bytes.
pub fn invite_code_hash(code: &str) -> Result<[u8; 32]> {
    let bytes = unb64(code)?;
    if bytes.len() < INVITE_CODE_MIN_BYTES {
        return invalid("Switch wire 1.7: an invite code holds at least 16 random bytes");
    }
    Ok(hash(&bytes))
}

/// The link that shows an invite code: `pubky://<id>?switch=invite&code=<code>` (Switch wire
/// 1.7).
pub fn invite_code_uri(identity: &[u8; 32], code: &str) -> String {
    format!(
        "pubky://{}?switch=invite&code={code}",
        crate::enc::pubky_id(identity)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_hash_requires_sorted_unique_write_scopes() {
        let sorted = Policy {
            read_scope: "a".into(),
            write_scopes: vec!["a".into(), "b".into()],
        };
        assert!(sorted.hash().is_ok());
        let unsorted = Policy {
            read_scope: "a".into(),
            write_scopes: vec!["b".into(), "a".into()],
        };
        assert!(unsorted.hash().is_err());
        let empty = Policy {
            read_scope: "a".into(),
            write_scopes: Vec::new(),
        };
        assert!(empty.hash().is_err());
        assert_eq!(Policy::new("a", &["b", "a", "b"]).hash(), sorted.hash());
    }

    #[test]
    fn test_key_of_scope_derives_sub_scopes_from_their_parent() {
        let root = [3u8; 32];
        let parent = scope_key(&root, 2, "name");
        assert_eq!(key_of_scope(&root, 2, "name"), parent);
        assert_eq!(
            key_of_scope(&root, 2, "name:sub"),
            sub_scope_key(&parent, "sub")
        );
        assert_ne!(key_of_scope(&root, 1, "name"), parent);
    }

    #[test]
    fn test_invite_code_hash_requires_sixteen_bytes() {
        assert!(invite_code_hash("IRrC78oNIjZ4hcet2fYnJQ").is_ok());
        assert!(invite_code_hash("IRrC78oNIjZ4hcet2fYn").is_err());
        assert!(invite_code_hash("not base64url!").is_err());
    }

    #[test]
    fn test_naming_key_debug_hides_the_key() {
        let key = NamingKey::from_bytes([0xAB; 32]);
        assert_eq!(format!("{key:?}"), "NamingKey(..)");
    }
}
