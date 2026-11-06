//! The enrollment request and answer (Switch wire 3.7, Switch spec 4.3 and 6.2).

use serde::{Deserialize, Serialize};

use super::{IdentityDoc, IdentityPolicy, check_tag, decode, encode, fmt, is_origin, open_value};
use crate::enc::{serde_b64, zbase32_encode};
use crate::error::{Error, Result, invalid};
use crate::keys::IdentityKey;
use crate::labels;
use crate::sig::SignedDoc;

/// The enrollment's `kind`.
pub const ENROLL_KIND: &str = "pubky-switch.enroll";

/// The highest app limit a service may announce (Switch wire 3.7).
pub const MAX_APP_LIMIT: u64 = 255;

/// The members of an enrollment (Switch wire 3.7), as the signer writes them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentBody {
    /// The identity, which equals `Switch-Identity`.
    #[serde(with = "fmt::pubky")]
    pub identity: [u8; 32],
    /// The service's origin.
    pub origin: String,
    /// A random nonce, new for every enrollment.
    #[serde(with = "serde_b64")]
    pub nonce: [u8; 16],
    /// The policy; the delivered `identity.json`'s applies, this one is informational while
    /// the account is staged.
    pub policy: IdentityPolicy,
    /// The current `identity.json`, for a new provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_doc: Option<SignedDoc>,
    /// Every App ID the signer revoked or saw depart, ascending by their text; absent when
    /// empty.
    #[serde(
        default,
        with = "fmt::opt_app_ids",
        skip_serializing_if = "Option::is_none"
    )]
    pub revoked_apps: Option<Vec<[u8; 16]>>,
}

impl EnrollmentBody {
    /// Check the enrollment for the identity and the service origin the reader expects
    /// (Switch wire 3.7), and return the verified `identity_doc`, if any.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for another identity or origin, an `identity_doc` that
    /// doesn't verify for the identity, or `revoked_apps` present but empty or not unique and
    /// ascending by text (`400` at the service).
    pub fn check(&self, identity: &[u8; 32], origin: &str) -> Result<Option<IdentityDoc>> {
        if &self.identity != identity {
            return invalid("Switch wire 3.7: identity isn't the expected identity");
        }
        if self.origin != origin || !is_origin(&self.origin) {
            return invalid("Switch wire 3.7: the enrollment names another origin");
        }
        if let Some(revoked) = &self.revoked_apps {
            if revoked.is_empty() {
                return invalid("Switch wire 3.7: revoked_apps is absent when empty");
            }
            let texts: Vec<String> = revoked.iter().map(|id| zbase32_encode(id)).collect();
            if texts.windows(2).any(|w| matches!(w, [a, b] if a >= b)) {
                return invalid("Switch wire 3.7: revoked_apps isn't unique and ascending by text");
            }
        }
        self.identity_doc
            .as_ref()
            .map(|doc| IdentityDoc::verify(doc, identity))
            .transpose()
    }

    /// The body's exact JSON bytes, as the signer writes them.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if it can't be written.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        encode(ENROLL_KIND, self)
    }
}

/// A verified enrollment (Switch wire 3.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrollment {
    body: EnrollmentBody,
    identity_doc: Option<IdentityDoc>,
    signed: SignedDoc,
    hash: [u8; 32],
}

impl Enrollment {
    /// Sign an enrollment with the identity key. `revoked_apps` is sorted by text first, and
    /// left out when empty.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if the body breaks a rule of Switch wire 3.7.
    pub fn sign(key: &IdentityKey, mut body: EnrollmentBody) -> Result<Self> {
        if let Some(revoked) = &mut body.revoked_apps {
            revoked.sort_by_cached_key(|id| zbase32_encode(id));
            revoked.dedup();
            if revoked.is_empty() {
                body.revoked_apps = None;
            }
        }
        let identity_doc = body.check(&key.public(), &body.origin.clone())?;
        let signed = key.sign_doc(labels::sig::ENROLL, &[], body.to_json()?);
        let hash = signed.doc_hash()?;
        Ok(Self {
            body,
            identity_doc,
            signed,
            hash,
        })
    }

    /// Verify an enrollment for the identity and the service origin the reader expects.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Signature`] if the identity key didn't sign it, and
    /// [`crate::Error::Invalid`] for any rule it breaks.
    pub fn verify(signed: &SignedDoc, identity: &[u8; 32], origin: &str) -> Result<Self> {
        let value = open_value(signed, identity, labels::sig::ENROLL)?;
        check_tag(&value, ENROLL_KIND, "Switch wire 3.7")?;
        let body: EnrollmentBody = decode(value)?;
        let identity_doc = body.check(identity, origin)?;
        Ok(Self {
            body,
            identity_doc,
            signed: signed.clone(),
            hash: signed.doc_hash()?,
        })
    }

    /// The members as read.
    pub fn body(&self) -> &EnrollmentBody {
        &self.body
    }

    /// The enrollment's `identity_doc`, verified.
    pub fn identity_doc(&self) -> Option<&IdentityDoc> {
        self.identity_doc.as_ref()
    }

    /// The App IDs it names as revoked or departed, ascending by text.
    pub fn revoked_apps(&self) -> &[[u8; 16]] {
        self.body.revoked_apps.as_deref().unwrap_or_default()
    }

    /// The signed document, in its exact bytes.
    pub fn signed(&self) -> &SignedDoc {
        &self.signed
    }

    /// The enrollment hash: its document hash, which the answer names.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }
}

/// The limits an enrollment answer announces (Switch wire 3.7), with the defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Limits {
    /// The most apps in `identity.json`, never above 255.
    pub app_limit: u64,
    /// The envelope cap in bytes.
    pub max_envelope: u64,
    /// The cap on a sealed value's plaintext in bytes.
    pub max_sealed_value: u64,
    /// The inbox quota in bytes.
    pub quota_bytes: u64,
    /// The most entries in a batch.
    pub max_batch: u64,
    /// The shared record quota in bytes.
    pub record_quota_bytes: u64,
    /// The largest export the service imports; an answer without it stands for the default.
    #[serde(default = "default_max_import_bytes")]
    pub max_import_bytes: u64,
}

fn default_max_import_bytes() -> u64 {
    4_294_967_296
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            app_limit: 32,
            max_envelope: 65_536,
            max_sealed_value: 262_144,
            quota_bytes: 67_108_864,
            max_batch: 8,
            record_quota_bytes: 67_108_864,
            max_import_bytes: default_max_import_bytes(),
        }
    }
}

/// The body of the enrollment answer (Switch wire 3.7), which the response signature signs
/// with the account's service key. Unknown members are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnrollmentAnswer {
    /// The account's service key, or the pending key of the next generation.
    #[serde(with = "serde_b64")]
    pub service_key: [u8; 32],
    /// The account's limits.
    pub limits: Limits,
    /// The enrollment's identity.
    #[serde(with = "fmt::pubky")]
    pub identity: [u8; 32],
    /// The enrollment's origin.
    pub origin: String,
    /// The enrollment's nonce.
    #[serde(with = "serde_b64")]
    pub nonce: [u8; 16],
    /// The document hash of the enrollment it answers.
    #[serde(with = "serde_b64")]
    pub enrollment: [u8; 32],
}

impl EnrollmentAnswer {
    /// The answer to `enrollment` with this key and these limits.
    pub fn new(enrollment: &Enrollment, service_key: [u8; 32], limits: Limits) -> Self {
        Self {
            service_key,
            limits,
            identity: enrollment.body.identity,
            origin: enrollment.body.origin.clone(),
            nonce: enrollment.body.nonce,
            enrollment: enrollment.hash,
        }
    }

    /// Read an answer body; unknown members are ignored.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if it isn't strict JSON of this shape.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        crate::json::parse_json(bytes)
    }

    /// The answer's JSON bytes.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if it can't be written.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| Error::Invalid("Switch wire 3.7: unwritable".into()))
    }

    /// The signer's check that the answer answers `enrollment` (Switch wire 3.7): its
    /// identity, origin, nonce and enrollment hash, and an app limit of at most 255. The
    /// signer also verifies the response signature with `service_key`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] naming the member that doesn't match.
    pub fn check(&self, enrollment: &Enrollment) -> Result<()> {
        let body = &enrollment.body;
        if self.identity != body.identity || self.origin != body.origin || self.nonce != body.nonce
        {
            return invalid("Switch wire 3.7: the answer names another enrollment");
        }
        if self.enrollment != enrollment.hash {
            return invalid("Switch wire 3.7: enrollment isn't the enrollment's document hash");
        }
        if self.limits.app_limit > MAX_APP_LIMIT {
            return invalid("Switch wire 3.7: app_limit is above 255");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::fixtures::{app, identity, other_app};
    use crate::records::{IdentityBody, Inbox};

    const ORIGIN: &str = "https://inbox.example";

    fn body() -> EnrollmentBody {
        EnrollmentBody {
            identity: identity().public(),
            origin: ORIGIN.into(),
            nonce: [3; 16],
            policy: IdentityPolicy::default(),
            identity_doc: None,
            revoked_apps: None,
        }
    }

    #[test]
    fn test_enrollment_round_trip_and_origin() {
        let e = Enrollment::sign(&identity(), body()).unwrap();
        let read = Enrollment::verify(e.signed(), &identity().public(), ORIGIN).unwrap();
        assert_eq!(read, e);
        assert!(
            Enrollment::verify(e.signed(), &identity().public(), "https://other.example").is_err()
        );
        assert!(read.revoked_apps().is_empty());
    }

    #[test]
    fn test_enrollment_revoked_apps_rules() {
        let (a, b) = (app().app_id_bytes(), other_app().app_id_bytes());
        let mut both = body();
        both.revoked_apps = Some(vec![a, b, a]);
        let e = Enrollment::sign(&identity(), both).unwrap();
        let texts: Vec<String> = e.revoked_apps().iter().map(|i| zbase32_encode(i)).collect();
        assert_eq!(texts.len(), 2);
        assert!(texts[0] < texts[1], "sorted by text");
        let mut empty = body();
        empty.revoked_apps = Some(vec![]);
        assert!(empty.check(&identity().public(), ORIGIN).is_err());
        let mut unsorted = body();
        unsorted.revoked_apps = Some(e.revoked_apps().iter().rev().copied().collect());
        assert!(unsorted.check(&identity().public(), ORIGIN).is_err());
        let mut twice = body();
        twice.revoked_apps = Some(vec![a, a]);
        assert!(twice.check(&identity().public(), ORIGIN).is_err());
    }

    #[test]
    fn test_enrollment_carries_a_verified_identity_doc() {
        let doc = IdentityDoc::sign(
            &identity(),
            IdentityBody::first(
                identity().public(),
                [1; 16],
                Inbox::new(ORIGIN, [2; 32]),
                IdentityPolicy::default(),
            ),
        )
        .unwrap();
        let mut with_doc = body();
        with_doc.identity_doc = Some(doc.signed().clone());
        let e = Enrollment::sign(&identity(), with_doc.clone()).unwrap();
        assert_eq!(e.identity_doc(), Some(&doc));
        let mut forged = doc.signed().clone();
        forged.sig = crate::enc::b64(&[0; 64]);
        with_doc.identity_doc = Some(forged);
        assert!(with_doc.check(&identity().public(), ORIGIN).is_err());
    }

    #[test]
    fn test_enrollment_answer_checks() {
        let e = Enrollment::sign(&identity(), body()).unwrap();
        let answer = EnrollmentAnswer::new(&e, [5; 32], Limits::default());
        answer.check(&e).unwrap();
        let read = EnrollmentAnswer::from_json(&answer.to_json().unwrap()).unwrap();
        assert_eq!(read, answer);
        let mut other = answer.clone();
        other.nonce = [0; 16];
        assert!(other.check(&e).is_err());
        let mut wrong_hash = answer.clone();
        wrong_hash.enrollment = [0; 32];
        assert!(wrong_hash.check(&e).is_err());
        let mut big = answer;
        big.limits.app_limit = 256;
        assert!(big.check(&e).is_err());
        // An answer without max_import_bytes stands for the default.
        let text = r#"{"service_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","limits":{"app_limit":32,"max_envelope":1,"max_sealed_value":1,"quota_bytes":1,"max_batch":8,"record_quota_bytes":1},"identity":"IDENT","origin":"https://inbox.example","nonce":"AAAAAAAAAAAAAAAAAAAAAA","enrollment":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#
            .replace("IDENT", &identity().id());
        let read = EnrollmentAnswer::from_json(text.as_bytes()).unwrap();
        assert_eq!(read.limits.max_import_bytes, 4_294_967_296);
    }
}
