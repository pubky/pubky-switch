//! Signatures and signed documents (Switch wire 2).

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::enc::{b64, hash, lp, unb64, unb64_array};
use crate::error::{Error, Result};
use crate::json::{Doc, parse_json_as};
use crate::labels;

/// The signature input: `lp(label, field1, ..., fieldn)` (Switch wire 2.1).
pub fn signed_bytes(label: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(fields.len() + 1);
    parts.push(label.as_bytes());
    parts.extend_from_slice(fields);
    lp(&parts)
}

/// Sign `lp(label, fields...)` with Ed25519, deterministically (RFC 8032; Switch wire 2.1).
///
/// A writer signs each document, operation and message once, keeps the signed bytes and
/// sends exactly those again (Switch wire 2.1); it never signs the same body twice.
pub fn sign(key: &SigningKey, label: &str, fields: &[&[u8]]) -> [u8; 64] {
    key.sign(&signed_bytes(label, fields)).to_bytes()
}

/// The Ed25519 public key of a 32-byte secret (seed).
pub fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(secret).verifying_key().to_bytes()
}

/// Verify an Ed25519 signature over `lp(label, fields...)` as Switch wire 2.1 spells it
/// out, step by step, so the result doesn't depend on what one library checks.
///
/// 1. S is below the group order L.
/// 2. A, the public key, and R decode to curve points that re-encode to the same 32 bytes.
/// 3. Neither A nor R is of small order.
/// 4. The cofactorless equation holds: the encoding of `[S]B - [k]A` equals R's bytes, with
///    `k = SHA-512(R || A || M)` reduced mod L.
///
/// A mixed-order public key passes, as RFC 8032 has it.
///
/// # Errors
///
/// [`Error::Signature`] naming the step that refused the signature.
pub fn verify(
    public: &[u8; 32],
    label: &str,
    fields: &[&[u8]],
    signature: &[u8; 64],
) -> Result<()> {
    use curve25519_dalek::{Scalar, edwards::CompressedEdwardsY};
    let fail = |why: &str| Err(Error::Signature(format!("Switch wire 2.1: {why}")));
    let (r, s) = signature.split_at(32);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(s);
    if Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)).is_none() {
        return fail("S isn't below the group order");
    }
    let canonical = |bytes: &[u8]| {
        let mut point = [0u8; 32];
        point.copy_from_slice(bytes);
        CompressedEdwardsY(point)
            .decompress()
            .filter(|decoded| decoded.compress().to_bytes() == point)
    };
    let Some(a) = canonical(public) else {
        return fail("the public key is invalid or not canonical");
    };
    let Some(r_point) = canonical(r) else {
        return fail("R is invalid or not canonical");
    };
    if a.is_small_order() {
        return fail("the public key is of small order");
    }
    if r_point.is_small_order() {
        return fail("R is of small order");
    }
    let key = VerifyingKey::from_bytes(public)
        .map_err(|_| Error::Signature("Switch wire 2.1: the public key is invalid".into()))?;
    // Step 4: `verify_strict` computes the cofactorless equation and compares R byte for
    // byte; it repeats checks 1 and 3.
    key.verify_strict(
        &signed_bytes(label, fields),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| {
        Error::Signature(format!(
            "Switch wire 2.1: the equation doesn't hold ({label})"
        ))
    })
}

/// A signed document in its carrying form: `{ "body": "<base64url of the exact JSON
/// bytes>", "sig": "<base64url of the signature>" }` (Switch wire 2.2).
///
/// The body bytes are never re-serialized: signatures and hashes cover the exact bytes the
/// writer produced.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignedDoc {
    /// The exact JSON bytes of the body, base64url.
    pub body: String,
    /// The signature, base64url.
    pub sig: String,
}

impl SignedDoc {
    /// Sign exact body bytes; the signature covers `lp(label, prefix..., body)`.
    pub fn sign_bytes(key: &SigningKey, label: &str, prefix: &[&[u8]], body: Vec<u8>) -> Self {
        let mut fields = prefix.to_vec();
        fields.push(&body);
        let sig = sign(key, label, &fields);
        Self {
            body: b64(&body),
            sig: b64(&sig),
        }
    }

    /// A signed document from its body bytes and signature.
    pub fn from_parts(body: &[u8], sig: &[u8; 64]) -> Self {
        Self {
            body: b64(body),
            sig: b64(sig),
        }
    }

    /// The exact body bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if `body` isn't base64url.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        unb64(&self.body)
    }

    /// The signature bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if `sig` isn't base64url of 64 bytes.
    pub fn sig_bytes(&self) -> Result<[u8; 64]> {
        unb64_array::<64>(&self.sig)
    }

    /// The signed document bytes: `lp(body bytes, signature bytes)` (Switch wire 2.2).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if either member doesn't decode.
    pub fn doc_bytes(&self) -> Result<Vec<u8>> {
        Ok(lp(&[&self.body_bytes()?, &self.sig_bytes()?]))
    }

    /// The document hash: `hash(signed document bytes)` (Switch wire 2.2), as certificate,
    /// freeze and enrollment hashes use it.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if either member doesn't decode.
    pub fn doc_hash(&self) -> Result<[u8; 32]> {
        Ok(hash(&self.doc_bytes()?))
    }

    /// Verify the signature over `lp(label, prefix..., body)` and return the body bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if a member doesn't decode, [`Error::Signature`] if the signature
    /// doesn't verify.
    pub fn verify(&self, public: &[u8; 32], label: &str, prefix: &[&[u8]]) -> Result<Vec<u8>> {
        let body = self.body_bytes()?;
        let mut fields = prefix.to_vec();
        fields.push(&body);
        verify(public, label, &fields, &self.sig_bytes()?)?;
        Ok(body)
    }

    /// Verify, then parse the body strictly (Switch wire 1.1, 2.2).
    ///
    /// The label names the document, and with it its opaque members: an operation's, a
    /// service transition's, or none.
    ///
    /// # Errors
    ///
    /// As [`SignedDoc::verify`], and [`Error::Invalid`] if the body isn't strict JSON of
    /// type `T`.
    pub fn open<T: DeserializeOwned>(
        &self,
        public: &[u8; 32],
        label: &str,
        prefix: &[&[u8]],
    ) -> Result<T> {
        let doc = match label {
            labels::sig::OP => Doc::Op,
            labels::sig::SERVICE_OP => Doc::ServiceOp,
            _ => Doc::Plain,
        };
        parse_json_as(&self.verify(public, label, prefix)?, doc)
    }

    /// Parse the body without verifying, to find the key that must verify it (an app
    /// record names its own key, Switch wire 2.2), or to read an operation or a transition
    /// the chain vouches for.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if the body doesn't decode or isn't strict JSON of type `T`.
    pub fn peek<T: DeserializeOwned>(&self) -> Result<T> {
        parse_json_as(&self.body_bytes()?, Doc::SignedBody)
    }

    /// The compact form `<body>.<sig>`, as headers carry it (Switch wire 2.2).
    pub fn compact(&self) -> String {
        format!("{}.{}", self.body, self.sig)
    }

    /// Read the compact form, split at the first `.` (Switch wire 2.2).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if the text has no `.`.
    pub fn from_compact(text: &str) -> Result<Self> {
        let (body, sig) = text.split_once('.').ok_or_else(|| {
            Error::Invalid("Switch wire 2.2: not a compact signed document".into())
        })?;
        Ok(Self {
            body: body.to_owned(),
            sig: sig.to_owned(),
        })
    }

    /// Read the carrying form from a JSON value, refusing members other than `body` and
    /// `sig`, as inside an operation body or a `POST /ops` entry (Switch wire 1.1, 2.2).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for another member, or a member that isn't a string.
    pub fn from_strict_value(value: &serde_json::Value) -> Result<Self> {
        crate::json::reject_unknown_members(value, &["body", "sig"], "a signed document")?;
        Ok(serde_json::from_value(value.clone())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[9; 32])
    }

    #[test]
    fn test_signed_doc_verifies_and_refuses_another_label() {
        let doc = SignedDoc::sign_bytes(&key(), labels::sig::APP_RECORD, &[], b"{}".to_vec());
        let public = public_of(&[9; 32]);
        assert_eq!(
            doc.verify(&public, labels::sig::APP_RECORD, &[]).unwrap(),
            b"{}"
        );
        assert!(matches!(
            doc.verify(&public, labels::sig::APP_CERT, &[]),
            Err(Error::Signature(_))
        ));
    }

    #[test]
    fn test_verify_refuses_unreduced_s() {
        let public = public_of(&[9; 32]);
        let mut signature = sign(&key(), "x", &[b"m"]);
        assert!(verify(&public, "x", &[b"m"], &signature).is_ok());
        signature[63] |= 0xF0;
        assert!(verify(&public, "x", &[b"m"], &signature).is_err());
    }

    #[test]
    fn test_compact_form_round_trips() {
        let doc = SignedDoc::sign_bytes(&key(), "x", &[], b"{}".to_vec());
        assert_eq!(SignedDoc::from_compact(&doc.compact()).unwrap(), doc);
        assert!(SignedDoc::from_compact("nodot").is_err());
    }

    #[test]
    fn test_strict_carrying_form_refuses_other_members() {
        let doc = SignedDoc::sign_bytes(&key(), "x", &[], b"{}".to_vec());
        let mut value = serde_json::to_value(&doc).unwrap();
        assert!(SignedDoc::from_strict_value(&value).is_ok());
        value["extra"] = serde_json::json!(1);
        assert!(SignedDoc::from_strict_value(&value).is_err());
    }
}
