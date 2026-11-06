//! The receive key record (Switch wire 3.4, Switch spec 3.6 and 4.4).

use serde::{Deserialize, Serialize};

use super::{
    AppCert, SuiteKey, check_suite_keys, check_tag, decode, encode, fmt, open_value,
    reject_unknown_suite_key_members,
};
use crate::enc::{kid, serde_b64, x25519_low_order};
use crate::error::{Result, invalid};
use crate::json::reject_unknown_members;
use crate::keys::{AppKeys, ReceiveKey};
use crate::labels;
use crate::sig::SignedDoc;

/// The receive key record's `kind`.
pub const RECEIVE_KEY_KIND: &str = "pubky-switch.receive_key";

/// The members of a receive key record, which refuses any other (Switch wire 1.1, 3.4).
const RECEIVE_KEY_MEMBERS: [&str; 8] = [
    "v",
    "kind",
    "identity",
    "app_id",
    "n",
    "kid",
    "x25519",
    "suite_keys",
];

/// The members of a receive key record (Switch wire 3.4), as its app writes them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiveKeyBody {
    /// The app's identity.
    #[serde(with = "fmt::pubky")]
    pub identity: [u8; 32],
    /// The signing app.
    #[serde(with = "fmt::app_id")]
    pub app_id: [u8; 16],
    /// The registration number: 0 for an app's first key at a service, then one more each
    /// time.
    pub n: u64,
    /// The kid of `x25519`.
    #[serde(with = "serde_b64")]
    pub kid: [u8; 8],
    /// The X25519 public key.
    #[serde(with = "serde_b64")]
    pub x25519: [u8; 32],
    /// Receive keys of later suites; writers of this version leave it out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suite_keys: Option<Vec<SuiteKey>>,
}

impl ReceiveKeyBody {
    /// The record of `key` for the app `cert` certifies.
    pub fn new(cert: &AppCert, key: &ReceiveKey) -> Self {
        Self {
            identity: cert.identity(),
            app_id: cert.app_id(),
            n: key.n,
            kid: key.kid,
            x25519: key.public,
            suite_keys: None,
        }
    }

    /// Check the record for the app `cert` certifies (Switch wire 3.4): its identity and App
    /// ID, `kid` derived from `x25519`, a key not of low order, and `suite_keys`, whose kids
    /// differ from `kid`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] naming the first rule that fails.
    pub fn check(&self, cert: &AppCert) -> Result<()> {
        if self.identity != cert.identity() || self.app_id != cert.app_id() {
            return invalid("Switch wire 3.4: identity and app_id aren't the certificate's");
        }
        if kid(&self.x25519) != self.kid {
            return invalid("Switch wire 3.4: kid isn't derived from x25519");
        }
        if x25519_low_order(&self.x25519) {
            return invalid("Switch wire 3.4: x25519 is a key of low order");
        }
        if let Some(keys) = &self.suite_keys {
            check_suite_keys(keys)?;
            if keys.iter().any(|k| k.kid() == self.kid) {
                return invalid("Switch wire 3.4: a suite key's kid equals kid");
            }
        }
        Ok(())
    }

    /// The body's exact JSON bytes, as its app writes them.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if it can't be written.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        encode(RECEIVE_KEY_KIND, self)
    }
}

/// A verified receive key record (Switch wire 3.4): signed by the app's signing key, for the
/// app its certificate names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveKeyRecord {
    body: ReceiveKeyBody,
    signed: SignedDoc,
}

impl ReceiveKeyRecord {
    /// Sign a record with the app's signing key, for the app `cert` certifies.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if `keys` aren't the certificate's or the body breaks a rule
    /// of Switch wire 3.4.
    pub fn sign(keys: &AppKeys, cert: &AppCert, body: ReceiveKeyBody) -> Result<Self> {
        if keys.signing_public() != cert.signing_key() {
            return invalid("Switch wire 3.4: the signing key isn't the certificate's");
        }
        body.check(cert)?;
        let signed = keys.sign_doc(labels::sig::RECEIVE_KEY, &[], body.to_json()?);
        Ok(Self { body, signed })
    }

    /// Verify a record against the certificate of the app it is for (Switch wire 3.4): the
    /// signature with its signing key, then the body strictly, its unknown members refused.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Signature`] if the app's key didn't sign it, and
    /// [`crate::Error::Invalid`] for any rule it breaks. A sender skips such a record.
    pub fn verify(signed: &SignedDoc, cert: &AppCert) -> Result<Self> {
        let value = open_value(signed, &cert.signing_key(), labels::sig::RECEIVE_KEY)?;
        reject_unknown_members(&value, &RECEIVE_KEY_MEMBERS, "a receive key record")?;
        reject_unknown_suite_key_members(&value)?;
        check_tag(&value, RECEIVE_KEY_KIND, "Switch wire 3.4")?;
        let body: ReceiveKeyBody = decode(value)?;
        body.check(cert)?;
        Ok(Self {
            body,
            signed: signed.clone(),
        })
    }

    /// The members as read.
    pub fn body(&self) -> &ReceiveKeyBody {
        &self.body
    }

    /// The signed document, in its exact bytes.
    pub fn signed(&self) -> &SignedDoc {
        &self.signed
    }

    /// The registration number.
    pub fn n(&self) -> u64 {
        self.body.n
    }

    /// The kid.
    pub fn kid(&self) -> [u8; 8] {
        self.body.kid
    }

    /// The X25519 public key.
    pub fn x25519(&self) -> [u8; 32] {
        self.body.x25519
    }

    /// Whether this record may follow `current`, the app's current record at the service
    /// (Switch spec 3.6): `n` 0 without one, else exactly one higher. After a provider loss
    /// the first record at the new service may carry any higher `n`, which the caller judges.
    pub fn follows(&self, current: Option<&ReceiveKeyRecord>) -> bool {
        match current {
            None => self.body.n == 0,
            Some(c) => c.body.n.checked_add(1) == Some(self.body.n),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::fixtures::{app, cert, other_app};

    fn record(n: u64) -> ReceiveKeyRecord {
        let c = cert(&["scope-a"]);
        let key = ReceiveKey::from_secret(n, [n as u8 + 10; 32]);
        ReceiveKeyRecord::sign(&app(), &c, ReceiveKeyBody::new(&c, &key)).unwrap()
    }

    fn resign(value: &serde_json::Value) -> SignedDoc {
        app().sign_doc(
            labels::sig::RECEIVE_KEY,
            &[],
            serde_json::to_vec(value).unwrap(),
        )
    }

    fn value() -> serde_json::Value {
        serde_json::from_slice(&record(0).signed().body_bytes().unwrap()).unwrap()
    }

    #[test]
    fn test_receive_key_round_trip() {
        let r = record(0);
        let read = ReceiveKeyRecord::verify(r.signed(), &cert(&["scope-a"])).unwrap();
        assert_eq!(read, r);
        let text = String::from_utf8(r.signed().body_bytes().unwrap()).unwrap();
        assert!(text.starts_with(r#"{"v":1,"kind":"pubky-switch.receive_key","identity":""#));
    }

    #[test]
    fn test_receive_key_refuses_unknown_members_and_bad_keys() {
        let c = cert(&["scope-a"]);
        let mut extra = value();
        extra["future"] = serde_json::json!(1);
        assert!(ReceiveKeyRecord::verify(&resign(&extra), &c).is_err());
        let mut wrong_kid = value();
        wrong_kid["kid"] = serde_json::json!(crate::enc::b64(&[0; 8]));
        let error = ReceiveKeyRecord::verify(&resign(&wrong_kid), &c).unwrap_err();
        assert!(error.to_string().contains("kid"), "{error}");
        let mut low = value();
        low["x25519"] = serde_json::json!(crate::enc::b64(&[0; 32]));
        low["kid"] = serde_json::json!(crate::enc::b64(&kid(&[0; 32])));
        let error = ReceiveKeyRecord::verify(&resign(&low), &c).unwrap_err();
        assert!(error.to_string().contains("low order"), "{error}");
        let foreign = other_app().sign_doc(
            labels::sig::RECEIVE_KEY,
            &[],
            serde_json::to_vec(&value()).unwrap(),
        );
        assert!(ReceiveKeyRecord::verify(&foreign, &c).is_err());
    }

    #[test]
    fn test_receive_key_suite_keys_kids_differ() {
        let c = cert(&["scope-a"]);
        let mut body = record(0).body().clone();
        body.suite_keys = Some(vec![SuiteKey {
            suite: 2,
            key: vec![1; 32],
        }]);
        body.check(&c).unwrap();
        body.suite_keys = Some(vec![]);
        assert!(body.check(&c).is_err());
    }

    #[test]
    fn test_receive_key_numbers_follow_one_by_one() {
        let (first, second, third) = (record(0), record(1), record(2));
        assert!(first.follows(None));
        assert!(!second.follows(None));
        assert!(second.follows(Some(&first)));
        assert!(!third.follows(Some(&first)));
    }
}
