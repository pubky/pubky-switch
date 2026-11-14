//! A signing key behind one interface, so that request, response and webhook signing take
//! any of the keys that sign them: the identity key, an app's signing key, a service key or
//! a push key.
//!
//! Every implementation signs only the label and fields it is given, under a Switch label,
//! never caller-supplied bytes on their own (Switch wire 2.1). Where a key lives, in memory,
//! a keystore or an HSM, is the implementer's choice.

use ed25519_dalek::SigningKey;

use crate::keys::{AppKeys, IdentityKey};

/// A key that signs `lp(label, fields...)` with Ed25519 (Switch wire 2.1).
pub trait Signs {
    /// The Ed25519 public key that verifies this key's signatures.
    fn public_key(&self) -> [u8; 32];

    /// Sign `lp(label, fields...)`.
    fn sign_fields(&self, label: &str, fields: &[&[u8]]) -> [u8; 64];
}

/// A key that signs requests only: `lp(label, fields...)` under the request label
/// ([`crate::labels::sig::HTTP`]), the `Switch-Signature` of a request (Switch wire 2.1,
/// 7.1), and nothing else, so whoever holds it signs no operation or document.
pub trait SignsRequests {
    /// The Ed25519 public key that verifies this key's signatures.
    fn public_key(&self) -> [u8; 32];

    /// Sign `lp(label, fields...)` under the request label ([`crate::labels::sig::HTTP`]):
    /// `fields` are a request's signed fields ([`crate::http::request_fields`]).
    fn sign_request_fields(&self, fields: &[&[u8]]) -> [u8; 64];
}

impl Signs for IdentityKey {
    fn public_key(&self) -> [u8; 32] {
        self.public()
    }

    fn sign_fields(&self, label: &str, fields: &[&[u8]]) -> [u8; 64] {
        self.sign(label, fields)
    }
}

impl Signs for AppKeys {
    fn public_key(&self) -> [u8; 32] {
        self.signing_public()
    }

    fn sign_fields(&self, label: &str, fields: &[&[u8]]) -> [u8; 64] {
        self.sign(label, fields)
    }
}

impl Signs for SigningKey {
    fn public_key(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }

    fn sign_fields(&self, label: &str, fields: &[&[u8]]) -> [u8; 64] {
        crate::sig::sign(self, label, fields)
    }
}
