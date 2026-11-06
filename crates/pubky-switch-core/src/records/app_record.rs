//! The app record (Switch wire 3.2, Switch spec 4.2).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{AppCert, CLOCK_TOLERANCE_MS, check_tag, decode, encode, fmt, open_value};
use crate::enc::{serde_b64, unb64_array};
use crate::error::{Result, invalid};
use crate::json::parse_json;
use crate::keys::AppKeys;
use crate::labels;
use crate::sig::SignedDoc;

/// The app record's `kind`.
pub const RECORD_KIND: &str = "pubky-switch.app";

/// The members of an app record (Switch wire 3.2), as its app writes them.
///
/// `capabilities` and `public_endpoints` are a protocol's members; the switch reads them only
/// to know whether the record has public endpoints, which then need an `expires_at`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRecordBody {
    /// The app's identity.
    #[serde(with = "fmt::pubky")]
    pub identity: [u8; 32],
    /// The App ID, the certificate's.
    #[serde(with = "fmt::app_id")]
    pub app_id: [u8; 16],
    /// The key that verifies this record, the certificate's.
    #[serde(with = "serde_b64")]
    pub signing_key: [u8; 32],
    /// The app's certificate, in its carrying form.
    pub cert: SignedDoc,
    /// The message kinds the app takes, in its protocol's names. It may narrow the
    /// certificate's scopes, never widen them (Switch spec 3.4).
    pub accepts: Vec<String>,
    /// The protocol's capabilities object, opaque to the switch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<serde_json::Map<String, Value>>,
    /// The public endpoints: an identifier to an opaque payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_endpoints: Option<BTreeMap<String, String>>,
    /// A display label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// When the record was made; the later `updated_at` wins between two records.
    #[serde(with = "fmt::time_ms")]
    pub updated_at: u64,
    /// When the record expires: required with public endpoints, `null` otherwise. Always
    /// written.
    #[serde(with = "fmt::opt_time_ms")]
    pub expires_at: Option<u64>,
}

impl AppRecordBody {
    /// A record for the app `cert` certifies, with no capabilities, no public endpoints and
    /// no label.
    pub fn new(cert: &AppCert, accepts: Vec<String>, updated_at: u64) -> Self {
        Self {
            identity: cert.identity(),
            app_id: cert.app_id(),
            signing_key: cert.signing_key(),
            cert: cert.signed().clone(),
            accepts,
            capabilities: None,
            public_endpoints: None,
            label: None,
            updated_at,
            expires_at: None,
        }
    }

    /// Whether the record has public endpoints.
    pub fn has_public_endpoints(&self) -> bool {
        self.public_endpoints
            .as_ref()
            .is_some_and(|e| !e.is_empty())
    }

    /// Check the record for the identity the reader expects (Switch wire 3.2): `identity`,
    /// the certificate for that identity, the same `app_id` and `signing_key` as the
    /// certificate, and an `expires_at` when it has public endpoints. Returns the certificate.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Signature`] if the certificate's signature fails, and
    /// [`crate::Error::Invalid`] for any other rule.
    pub fn check(&self, identity: &[u8; 32]) -> Result<AppCert> {
        if &self.identity != identity {
            return invalid("Switch wire 3.2: identity isn't the expected identity");
        }
        let cert = AppCert::verify(&self.cert, identity)?;
        if cert.app_id() != self.app_id {
            return invalid("Switch wire 3.2: app_id isn't the certificate's");
        }
        if cert.signing_key() != self.signing_key {
            return invalid("Switch wire 3.2: signing_key isn't the certificate's");
        }
        if self.has_public_endpoints() && self.expires_at.is_none() {
            return invalid("Switch wire 3.2: a record with public endpoints needs expires_at");
        }
        Ok(cert)
    }

    /// The body's exact JSON bytes, as its app writes them.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if it can't be written.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        encode(RECORD_KIND, self)
    }
}

/// A verified app record (Switch wire 3.2): signed with the signing key it names, which its
/// certificate, verified for the identity, certifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRecord {
    body: AppRecordBody,
    cert: AppCert,
    signed: SignedDoc,
}

impl AppRecord {
    /// Sign a record with the app's signing key.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if the body breaks a rule of Switch wire 3.2 or names
    /// another signing key than `keys`'.
    pub fn sign(keys: &AppKeys, body: AppRecordBody) -> Result<Self> {
        if body.signing_key != keys.signing_public() {
            return invalid("Switch wire 3.2: signing_key isn't the app's");
        }
        let cert = body.check(&body.identity)?;
        let signed = keys.sign_doc(labels::sig::APP_RECORD, &[], body.to_json()?);
        Ok(Self { body, cert, signed })
    }

    /// Verify a record for the identity the reader expects (Switch wire 3.2): read
    /// `signing_key` from the body, verify the signature with it, then check the members and
    /// the certificate. Unknown members are ignored (Switch wire 1.1).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Signature`] if a signature fails, [`crate::Error::Invalid`] for any
    /// other rule.
    pub fn verify(signed: &SignedDoc, identity: &[u8; 32]) -> Result<Self> {
        let peeked: Value = parse_json(&signed.body_bytes()?)?;
        let Some(key) = peeked.get("signing_key").and_then(Value::as_str) else {
            return invalid("Switch wire 3.2: the record names no signing_key");
        };
        let signing_key = unb64_array::<32>(key)?;
        let value = open_value(signed, &signing_key, labels::sig::APP_RECORD)?;
        check_tag(&value, RECORD_KIND, "Switch wire 3.2")?;
        let body: AppRecordBody = decode(value)?;
        let cert = body.check(identity)?;
        Ok(Self {
            body,
            cert,
            signed: signed.clone(),
        })
    }

    /// The members as read.
    pub fn body(&self) -> &AppRecordBody {
        &self.body
    }

    /// The certificate the record carries, verified.
    pub fn cert(&self) -> &AppCert {
        &self.cert
    }

    /// The signed document, in its exact bytes.
    pub fn signed(&self) -> &SignedDoc {
        &self.signed
    }

    /// When the record was made.
    pub fn updated_at(&self) -> u64 {
        self.body.updated_at
    }

    /// When the record expires, if it does.
    pub fn expires_at(&self) -> Option<u64> {
        self.body.expires_at
    }

    /// Whether `accepts` lists `kind`.
    pub fn accepts(&self, kind: &str) -> bool {
        self.body.accepts.iter().any(|k| k == kind)
    }

    /// Check 6 of Switch wire 3.8: whether the record carries `cert`, or an earlier
    /// certificate of the same app with the same signing and bundle keys.
    pub fn carries(&self, cert: &AppCert) -> bool {
        self.cert.hash() == cert.hash()
            || (self.cert.same_app_and_keys(cert) && self.cert.issued_at() < cert.issued_at())
    }

    /// Whether the record's `updated_at` is more than the clock tolerance ahead of the
    /// reader's clock `now`: such a record isn't used at all, and takes part in no
    /// comparison (Switch wire 3.2).
    pub fn is_ahead(&self, now: u64) -> bool {
        self.body.updated_at > now.saturating_add(CLOCK_TOLERANCE_MS)
    }

    /// The last instant a reader trusts the record, exclusive: the earlier of its
    /// `expires_at` and its `updated_at` plus the identity's record age limit, in seconds
    /// (Switch spec 4.3, `record_max_age`).
    pub fn trusted_until(&self, record_max_age_s: u64) -> u64 {
        let by_age = self
            .body
            .updated_at
            .saturating_add(record_max_age_s.saturating_mul(1000));
        self.body.expires_at.map_or(by_age, |e| e.min(by_age))
    }
}

/// How a reader orders two verified records of one app (Switch wire 3.2, "Equal times").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordOrder {
    /// The same body twice: one record.
    Same,
    /// The first has the later `updated_at`, and wins.
    Later,
    /// The second has the later `updated_at`, and wins.
    Earlier,
    /// The same `updated_at` and different body bytes: a conflict for every reader.
    Conflict,
}

impl AppRecord {
    /// Order this record against another of the same app (Switch wire 3.2, "Equal times"):
    /// the later `updated_at` wins, the same body twice is one record, and two bodies at one
    /// `updated_at` conflict. Bodies are compared as bytes, never re-serialized.
    pub fn order(&self, other: &AppRecord) -> RecordOrder {
        use std::cmp::Ordering;
        match self.body.updated_at.cmp(&other.body.updated_at) {
            Ordering::Greater => RecordOrder::Later,
            Ordering::Less => RecordOrder::Earlier,
            Ordering::Equal if self.signed.body == other.signed.body => RecordOrder::Same,
            Ordering::Equal => RecordOrder::Conflict,
        }
    }
}

/// A reader's view of one app's records (Switch spec 4.2, Switch wire 3.2): the newest record
/// it holds, the newest before it, and whether two records at the newest `updated_at`
/// conflict.
///
/// During a conflict the reader uses neither record and tells the user; it goes on with the
/// earlier record it holds, if any, and can still use the identity's other apps. A record
/// with a strictly later `updated_at` ends the conflict. A record more than the clock
/// tolerance ahead of the reader's clock takes part in nothing.
#[derive(Clone, Debug, Default)]
pub struct RecordView {
    newest: Option<AppRecord>,
    earlier: Option<AppRecord>,
    conflict: bool,
}

impl RecordView {
    /// An empty view.
    pub fn new() -> Self {
        Self::default()
    }

    /// See a verified record of the app at the reader's clock `now`. Returns whether the view
    /// is in conflict afterwards.
    pub fn see(&mut self, record: &AppRecord, now: u64) -> bool {
        if record.is_ahead(now) {
            return self.conflict;
        }
        match &self.newest {
            None => self.newest = Some(record.clone()),
            Some(newest) => match record.order(newest) {
                RecordOrder::Later => {
                    if !self.conflict {
                        self.earlier = self.newest.take();
                    }
                    self.newest = Some(record.clone());
                    self.conflict = false;
                }
                RecordOrder::Conflict => self.conflict = true,
                RecordOrder::Same | RecordOrder::Earlier => {}
            },
        }
        self.conflict
    }

    /// Whether two records at the newest `updated_at` conflict.
    pub fn in_conflict(&self) -> bool {
        self.conflict
    }

    /// The record the reader uses: the newest, or during a conflict the earlier one it holds.
    pub fn used(&self) -> Option<&AppRecord> {
        if self.conflict {
            self.earlier.as_ref()
        } else {
            self.newest.as_ref()
        }
    }
}

impl From<AppRecord> for SignedDoc {
    fn from(record: AppRecord) -> Self {
        record.signed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use crate::records::fixtures::{app, cert, identity, other_app};

    fn record(updated_at: u64, label: &str) -> AppRecord {
        let mut body =
            AppRecordBody::new(&cert(&["scope-a"]), vec!["sample.kind".into()], updated_at);
        body.label = Some(label.to_owned());
        AppRecord::sign(&app(), body).unwrap()
    }

    fn resign(value: &Value) -> SignedDoc {
        app().sign_doc(
            labels::sig::APP_RECORD,
            &[],
            serde_json::to_vec(value).unwrap(),
        )
    }

    fn value() -> Value {
        serde_json::from_slice(&record(10, "a").signed().body_bytes().unwrap()).unwrap()
    }

    #[test]
    fn test_app_record_sign_and_verify_round_trip() {
        let r = record(10, "a");
        let read = AppRecord::verify(r.signed(), &identity().public()).unwrap();
        assert_eq!(read, r);
        assert!(read.accepts("sample.kind") && !read.accepts("other.kind"));
        let text = String::from_utf8(r.signed().body_bytes().unwrap()).unwrap();
        assert!(text.ends_with(r#""updated_at":"1970-01-01T00:00:00.010Z","expires_at":null}"#));
    }

    #[test]
    fn test_app_record_ignores_unknown_members() {
        let mut v = value();
        v["future"] = serde_json::json!({"any": 1});
        AppRecord::verify(&resign(&v), &identity().public()).unwrap();
    }

    #[test]
    fn test_app_record_refuses_a_mismatch_with_its_certificate() {
        let mut v = value();
        v["app_id"] = serde_json::json!(other_app().app_id());
        let error = AppRecord::verify(&resign(&v), &identity().public()).unwrap_err();
        assert!(error.to_string().contains("app_id"), "{error}");
        let foreign = other_app().sign_doc(
            labels::sig::APP_RECORD,
            &[],
            serde_json::to_vec(&value()).unwrap(),
        );
        assert!(matches!(
            AppRecord::verify(&foreign, &identity().public()),
            Err(Error::Signature(_))
        ));
    }

    #[test]
    fn test_app_record_with_public_endpoints_needs_expires_at() {
        let mut v = value();
        v["public_endpoints"] = serde_json::json!({"id-1": "payload"});
        let error = AppRecord::verify(&resign(&v), &identity().public()).unwrap_err();
        assert!(error.to_string().contains("expires_at"), "{error}");
        v["expires_at"] = serde_json::json!("1970-01-31T00:00:00.000Z");
        AppRecord::verify(&resign(&v), &identity().public()).unwrap();
        // `expires_at` is always written: a record without it is refused.
        let mut missing = value();
        missing.as_object_mut().unwrap().remove("expires_at");
        assert!(AppRecord::verify(&resign(&missing), &identity().public()).is_err());
    }

    #[test]
    fn test_app_record_order_and_conflict() {
        let (a, b, later) = (record(10, "a"), record(10, "b"), record(11, "a"));
        assert_eq!(a.order(&b), RecordOrder::Conflict);
        assert_eq!(a.order(&a.clone()), RecordOrder::Same);
        assert_eq!(later.order(&a), RecordOrder::Later);
        assert_eq!(a.order(&later), RecordOrder::Earlier);
    }

    #[test]
    fn test_record_view_keeps_the_earlier_record_during_a_conflict() {
        let (old, a, b, later) = (
            record(5, "o"),
            record(10, "a"),
            record(10, "b"),
            record(11, "c"),
        );
        let now = 1_000;
        let mut view = RecordView::new();
        assert!(!view.see(&old, now));
        assert!(!view.see(&a, now));
        assert!(!view.see(&a, now), "the same body again is one record");
        assert!(view.see(&b, now));
        assert_eq!(view.used(), Some(&old));
        assert!(view.see(&old, now), "an older record changes nothing");
        let ahead = record(now + CLOCK_TOLERANCE_MS + 1, "f");
        assert!(
            view.see(&ahead, now),
            "a record too far ahead takes part in nothing"
        );
        assert!(!view.see(&later, now));
        assert_eq!(view.used(), Some(&later));
        let mut fresh = RecordView::new();
        fresh.see(&a, now);
        assert!(fresh.see(&b, now));
        assert_eq!(fresh.used(), None, "no earlier record to fall back on");
    }

    #[test]
    fn test_app_record_carries_its_certificate_or_an_earlier_one() {
        let r = record(10, "a");
        assert!(r.carries(r.cert()));
        let mut renewed_body = crate::records::fixtures::cert_body(&["scope-a"]);
        renewed_body.issued_at += 1;
        renewed_body.expires_at += 1;
        let renewed = AppCert::issue(&identity(), renewed_body).unwrap();
        assert!(
            r.carries(&renewed),
            "an earlier certificate of the same app and keys"
        );
        let other = AppCert::issue(
            &identity(),
            crate::records::fixtures::cert_body_for(&other_app(), &["scope-a"]),
        )
        .unwrap();
        assert!(!r.carries(&other));
    }

    #[test]
    fn test_app_record_age_and_ahead_rules() {
        let t = 1_000_000;
        let r = record(t, "a");
        assert_eq!(r.trusted_until(60), t + 60_000);
        assert!(!r.is_ahead(t - CLOCK_TOLERANCE_MS));
        assert!(r.is_ahead(t - CLOCK_TOLERANCE_MS - 1));
    }
}
