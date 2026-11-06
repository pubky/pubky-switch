//! The app certificate (Switch wire 3.1; Switch spec 3.2, 3.3).

use serde::{Deserialize, Serialize};

use super::{
    DAY_MS, SuiteKey, check_suite_keys, check_tag, decode, encode, fmt, open_value,
    reject_unknown_suite_key_members,
};
use crate::enc::{app_id_bytes, serde_b64, x25519_low_order};
use crate::error::{Result, invalid};
use crate::json::reject_unknown_members;
use crate::keys::IdentityKey;
use crate::labels;
use crate::scopes::{self, Permission};
use crate::sig::SignedDoc;

/// The certificate's `kind`.
pub const CERT_KIND: &str = "pubky-switch.app_cert";

/// The lifetime a signer gives a certificate by default, 365 days (Switch spec 3.2).
pub const DEFAULT_CERT_LIFETIME_MS: u64 = 365 * DAY_MS;

/// The longest lifetime any reader accepts, 730 days after `issued_at` (Switch wire 3.1).
pub const MAX_CERT_LIFETIME_MS: u64 = 730 * DAY_MS;

/// The members of a certificate, which refuses any other (Switch wire 1.1, 3.1).
const CERT_MEMBERS: [&str; 11] = [
    "v",
    "kind",
    "identity",
    "app_id",
    "signing_key",
    "bundle_key",
    "scopes",
    "permissions",
    "issued_at",
    "expires_at",
    "suite_keys",
];

/// The members of an app certificate (Switch wire 3.1), as its signer writes them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppCertBody {
    /// The identity that signs the certificate.
    #[serde(with = "fmt::pubky")]
    pub identity: [u8; 32],
    /// The App ID, derived from `signing_key`.
    #[serde(with = "fmt::app_id")]
    pub app_id: [u8; 16],
    /// The app's Ed25519 signing key.
    #[serde(with = "serde_b64")]
    pub signing_key: [u8; 32],
    /// The app's X25519 bundle key, which key bundles are sealed to.
    #[serde(with = "serde_b64")]
    pub bundle_key: [u8; 32],
    /// The protocol's scopes, opaque strings to the switch.
    pub scopes: Vec<String>,
    /// The switch permissions, by name, in the fixed order.
    pub permissions: Vec<String>,
    /// When the certificate was issued.
    #[serde(with = "fmt::time_ms")]
    pub issued_at: u64,
    /// When it expires: expired at or past this time.
    #[serde(with = "fmt::time_ms")]
    pub expires_at: u64,
    /// Bundle keys of later suites; writers of this version leave it out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suite_keys: Option<Vec<SuiteKey>>,
}

impl AppCertBody {
    /// A certificate body for the app with these keys, its App ID derived from the signing
    /// key, without `suite_keys`.
    pub fn new(
        identity: [u8; 32],
        signing_key: [u8; 32],
        bundle_key: [u8; 32],
        scopes: Vec<String>,
        permissions: &[Permission],
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            identity,
            app_id: app_id_bytes(&signing_key),
            signing_key,
            bundle_key,
            scopes,
            permissions: scopes::permission_names(permissions),
            issued_at,
            expires_at,
            suite_keys: None,
        }
    }

    /// Check the rules every reader applies (Switch wire 3.1), for the identity it expects,
    /// and return the permissions.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] naming the first rule that fails: the identity, the App ID's
    /// derivation, a bundle key of low order, the lifetime, `suite_keys`, the scope rule or
    /// the permissions.
    pub fn check(&self, identity: &[u8; 32]) -> Result<Vec<Permission>> {
        if &self.identity != identity {
            return invalid("Switch wire 3.1: identity isn't the expected identity");
        }
        if app_id_bytes(&self.signing_key) != self.app_id {
            return invalid("Switch wire 3.1: app_id isn't derived from signing_key");
        }
        if x25519_low_order(&self.bundle_key) {
            return invalid("Switch wire 3.1: bundle_key is an X25519 key of low order");
        }
        if self.expires_at <= self.issued_at {
            return invalid("Switch wire 3.1: expires_at isn't after issued_at");
        }
        if self.expires_at > self.issued_at.saturating_add(MAX_CERT_LIFETIME_MS) {
            return invalid("Switch wire 3.1: expires_at is more than 730 days after issued_at");
        }
        if let Some(keys) = &self.suite_keys {
            check_suite_keys(keys)?;
        }
        scopes::check_scopes(&self.scopes)?;
        scopes::check_permissions(&self.permissions)
    }

    /// The body's exact JSON bytes, as its signer writes them.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if it can't be written.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        encode(CERT_KIND, self)
    }
}

/// A verified app certificate (Switch wire 3.1): its signature verified with the identity
/// key, and every rule a reader checks held.
///
/// The switch enforces exactly its `permissions`; a protocol's verifiers also check their own
/// scope rules and that `permissions` is the list the scopes need, which this type doesn't.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppCert {
    body: AppCertBody,
    permissions: Vec<Permission>,
    signed: SignedDoc,
    hash: [u8; 32],
}

impl AppCert {
    /// Sign a certificate with the identity key, as the signer issues it (Switch spec 3.2).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if the body breaks a rule of Switch wire 3.1, for the
    /// identity of `key`.
    pub fn issue(key: &IdentityKey, body: AppCertBody) -> Result<Self> {
        let permissions = body.check(&key.public())?;
        let signed = key.sign_doc(labels::sig::APP_CERT, &[], body.to_json()?);
        let hash = signed.doc_hash()?;
        Ok(Self {
            body,
            permissions,
            signed,
            hash,
        })
    }

    /// Verify a certificate for the identity the reader expects (Switch wire 3.1; Switch wire
    /// 3.8 checks 1 and 2 for the identity): the signature first, then the body strictly,
    /// its unknown members refused.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Signature`] if the identity key didn't sign it, and
    /// [`crate::Error::Invalid`] for any rule of Switch wire 3.1 it breaks.
    pub fn verify(signed: &SignedDoc, identity: &[u8; 32]) -> Result<Self> {
        let value = open_value(signed, identity, labels::sig::APP_CERT)?;
        reject_unknown_members(&value, &CERT_MEMBERS, "an app certificate")?;
        reject_unknown_suite_key_members(&value)?;
        check_tag(&value, CERT_KIND, "Switch wire 3.1")?;
        let body: AppCertBody = decode(value)?;
        let permissions = body.check(identity)?;
        Ok(Self {
            body,
            permissions,
            signed: signed.clone(),
            hash: signed.doc_hash()?,
        })
    }

    /// The members as read.
    pub fn body(&self) -> &AppCertBody {
        &self.body
    }

    /// The signed document, in the exact bytes it was read or signed in.
    pub fn signed(&self) -> &SignedDoc {
        &self.signed
    }

    /// The certificate hash: the document hash, as `identity.json` lists it (Switch wire 2.2).
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The identity.
    pub fn identity(&self) -> [u8; 32] {
        self.body.identity
    }

    /// The App ID's 16 bytes.
    pub fn app_id(&self) -> [u8; 16] {
        self.body.app_id
    }

    /// The app's signing key.
    pub fn signing_key(&self) -> [u8; 32] {
        self.body.signing_key
    }

    /// The app's bundle key.
    pub fn bundle_key(&self) -> [u8; 32] {
        self.body.bundle_key
    }

    /// The scopes.
    pub fn scopes(&self) -> &[String] {
        &self.body.scopes
    }

    /// The switch permissions.
    pub fn permissions(&self) -> &[Permission] {
        &self.permissions
    }

    /// When it was issued.
    pub fn issued_at(&self) -> u64 {
        self.body.issued_at
    }

    /// When it expires.
    pub fn expires_at(&self) -> u64 {
        self.body.expires_at
    }

    /// Whether the certificate holds `scope`, holding `name` covering every `name:<sub>`
    /// (Switch wire 3.1, "Scope names").
    pub fn holds_scope(&self, scope: &str) -> bool {
        scopes::holds(&self.body.scopes, scope)
    }

    /// Whether the certificate grants the switch permission `permission`.
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    /// Whether the certificate has expired at `now`: at or past `expires_at` (Switch wire
    /// 3.1, 3.8 check 3).
    pub fn expired_at(&self, now: u64) -> bool {
        now >= self.body.expires_at
    }

    /// Whether this certificate is for the same app and keys as `other`: the same App ID,
    /// signing key and bundle key (Switch wire 3.8, "Renewal").
    pub fn same_app_and_keys(&self, other: &AppCert) -> bool {
        self.body.app_id == other.body.app_id
            && self.body.signing_key == other.body.signing_key
            && self.body.bundle_key == other.body.bundle_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::x25519_public;
    use crate::records::fixtures::{cert_body as body, identity};

    /// Sign a JSON value as a certificate, whatever it holds.
    fn sign_value(value: &serde_json::Value) -> SignedDoc {
        identity().sign_doc(
            labels::sig::APP_CERT,
            &[],
            serde_json::to_vec(value).unwrap(),
        )
    }

    fn value() -> serde_json::Value {
        serde_json::from_slice(&body(&["scope-a"]).to_json().unwrap()).unwrap()
    }

    #[test]
    fn test_cert_issue_and_verify_round_trip() {
        let cert = AppCert::issue(&identity(), body(&["scope-a", "name:sub"])).unwrap();
        let read = AppCert::verify(cert.signed(), &identity().public()).unwrap();
        assert_eq!(read, cert);
        assert_eq!(read.hash(), cert.signed().doc_hash().unwrap());
        assert!(read.holds_scope("name:sub") && !read.holds_scope("name"));
        assert!(read.has_permission(Permission::ConversationAdd));
        assert!(!read.has_permission(Permission::ClaimsWrite));
        let text = String::from_utf8(cert.signed().body_bytes().unwrap()).unwrap();
        assert!(text.starts_with(r#"{"v":1,"kind":"pubky-switch.app_cert","identity":""#));
        assert!(!text.contains("suite_keys"));
    }

    #[test]
    fn test_cert_verify_refuses_another_identity_or_signer() {
        let cert = AppCert::issue(&identity(), body(&["scope-a"])).unwrap();
        let other = IdentityKey::from_secret([9; 32]);
        assert!(matches!(
            AppCert::verify(cert.signed(), &other.public()),
            Err(crate::Error::Signature(_))
        ));
        let mut wrong = value();
        wrong["identity"] = serde_json::json!(other.id());
        let error = AppCert::verify(&sign_value(&wrong), &identity().public()).unwrap_err();
        assert!(error.to_string().contains("expected identity"), "{error}");
    }

    #[test]
    fn test_cert_refuses_unknown_members() {
        let mut extra = value();
        extra["future"] = serde_json::json!(1);
        let error = AppCert::verify(&sign_value(&extra), &identity().public()).unwrap_err();
        assert!(error.to_string().contains("unknown member"), "{error}");
        let mut nested = value();
        nested["suite_keys"] = serde_json::json!([{"suite": 2, "key": "AA", "future": 1}]);
        assert!(AppCert::verify(&sign_value(&nested), &identity().public()).is_err());
        let mut fine = value();
        fine["suite_keys"] = serde_json::json!([{"suite": 2, "key": "AA"}]);
        AppCert::verify(&sign_value(&fine), &identity().public()).unwrap();
    }

    #[test]
    fn test_cert_lifetime_rules() {
        let issued = crate::records::fixtures::ISSUED;
        let mut ok = body(&["scope-a"]);
        ok.expires_at = issued + MAX_CERT_LIFETIME_MS;
        ok.check(&identity().public()).unwrap();
        for expires in [issued, issued - 1, issued + MAX_CERT_LIFETIME_MS + 1] {
            let mut bad = body(&["scope-a"]);
            bad.expires_at = expires;
            assert!(bad.check(&identity().public()).is_err(), "{expires}");
        }
        for (what, expires) in [
            ("missing", None),
            ("null", Some(serde_json::Value::Null)),
            ("not a time", Some(serde_json::json!("never"))),
        ] {
            let mut v = value();
            match expires {
                None => {
                    v.as_object_mut().unwrap().remove("expires_at");
                }
                Some(e) => v["expires_at"] = e,
            }
            assert!(
                AppCert::verify(&sign_value(&v), &identity().public()).is_err(),
                "expires_at {what}"
            );
        }
    }

    #[test]
    fn test_cert_refuses_a_low_order_bundle_key() {
        let mut bad = body(&["scope-a"]);
        bad.bundle_key = [0; 32];
        let error = bad.check(&identity().public()).unwrap_err();
        assert!(error.to_string().contains("low order"), "{error}");
        bad.bundle_key = x25519_public(&[5; 32]);
        bad.check(&identity().public()).unwrap();
    }

    #[test]
    fn test_cert_refuses_a_foreign_app_id() {
        let mut bad = body(&["scope-a"]);
        bad.app_id = [7; 16];
        let error = bad.check(&identity().public()).unwrap_err();
        assert!(error.to_string().contains("derived"), "{error}");
    }

    #[test]
    fn test_cert_applies_the_scope_and_permission_rules() {
        let error = body(&["name", "name:sub"])
            .check(&identity().public())
            .unwrap_err();
        assert!(error.to_string().contains("sub-scopes"), "{error}");
        let mut unordered = body(&["scope-a"]);
        unordered.permissions = vec!["conversation.add".into(), "claims.read".into()];
        assert!(unordered.check(&identity().public()).is_err());
    }

    #[test]
    fn test_cert_expiry_is_at_or_past_expires_at() {
        let cert = AppCert::issue(&identity(), body(&["scope-a"])).unwrap();
        assert!(!cert.expired_at(cert.expires_at() - 1));
        assert!(cert.expired_at(cert.expires_at()));
    }
}
