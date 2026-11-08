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
use crate::scopes::is_name;
use crate::sig::SignedDoc;

/// The app record's `kind`.
pub const RECORD_KIND: &str = "pubky-switch.app";

/// The members a protocol adds to an app record, by protocol name (Switch wire 3.2).
///
/// The switch checks only their form: each name has the syntax of a scope name and each
/// value is an object. It never reads inside a member.
pub type ProtocolMembers = BTreeMap<String, serde_json::Map<String, Value>>;

/// The members of an app record (Switch wire 3.2), as its app writes them.
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
    /// What the app's protocols add to its record, one member per protocol, each defined by
    /// its protocol. Written as `{}` when they add nothing; a missing or `null` member reads
    /// as empty, and a protocol's `null` value as no member.
    #[serde(default, deserialize_with = "protocols::deserialize")]
    pub protocols: ProtocolMembers,
    /// A display label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// When the record was made; the later `updated_at` wins between two records.
    #[serde(with = "fmt::time_ms")]
    pub updated_at: u64,
    /// When the record expires, chosen by the app; `None` means it doesn't. Always written.
    /// A protocol may require one, which its own readers check.
    #[serde(with = "fmt::opt_time_ms")]
    pub expires_at: Option<u64>,
}

impl AppRecordBody {
    /// A record for the app `cert` certifies, with no protocol members and no label.
    pub fn new(cert: &AppCert, accepts: Vec<String>, updated_at: u64) -> Self {
        Self {
            identity: cert.identity(),
            app_id: cert.app_id(),
            signing_key: cert.signing_key(),
            cert: cert.signed().clone(),
            accepts,
            protocols: ProtocolMembers::new(),
            label: None,
            updated_at,
            expires_at: None,
        }
    }

    /// The member a protocol added to the record, if any. The switch never reads inside it.
    pub fn protocol(&self, name: &str) -> Option<&serde_json::Map<String, Value>> {
        self.protocols.get(name)
    }

    /// Check the record for the identity the reader expects (Switch wire 3.2): `identity`,
    /// the certificate for that identity, the same `app_id` and `signing_key` as the
    /// certificate, and the form of `protocols`. Returns the certificate.
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
        if self.protocols.keys().any(|name| !is_name(name)) {
            return invalid("Switch wire 3.2: a protocol member's name isn't a scope name");
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

/// The form check of `protocols` as it is read (Switch wire 3.2 "Protocols' members").
mod protocols {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer};
    use serde_json::Value;

    use super::ProtocolMembers;

    /// Read `protocols`: an object, or `null` for none, whose values are objects, or `null`
    /// for no member. Names are checked with the rest of the record.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ProtocolMembers, D::Error> {
        let Some(members) = Option::<serde_json::Map<String, Value>>::deserialize(deserializer)?
        else {
            return Ok(ProtocolMembers::new());
        };
        let mut out = ProtocolMembers::new();
        for (name, value) in members {
            match value {
                Value::Null => {}
                Value::Object(member) => {
                    out.insert(name, member);
                }
                _ => {
                    return Err(D::Error::custom(
                        "Switch wire 3.2: a protocol member isn't an object",
                    ));
                }
            }
        }
        Ok(out)
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
    fn test_app_record_protocols_are_checked_for_form_only() {
        // Written as `{}` when the protocols add nothing.
        let text = String::from_utf8(record(10, "a").signed().body_bytes().unwrap()).unwrap();
        assert!(text.contains(r#""protocols":{}"#), "{text}");
        // A protocol's member is any object, read back as it was written.
        let mut v = value();
        v["protocols"] = serde_json::json!({"sample": {"any": [1, {"deep": "x"}]}, "other-1": {}});
        let read = AppRecord::verify(&resign(&v), &identity().public()).unwrap();
        assert_eq!(read.body().protocol("sample").unwrap()["any"][0], 1);
        assert!(read.body().protocol("other-1").is_some());
        // A missing or null `protocols`, and a null member, read as no member.
        let mut missing = value();
        missing.as_object_mut().unwrap().remove("protocols");
        assert!(
            AppRecord::verify(&resign(&missing), &identity().public())
                .unwrap()
                .body()
                .protocols
                .is_empty()
        );
        let mut nulls = value();
        nulls["protocols"] = serde_json::json!({"sample": null});
        assert!(
            AppRecord::verify(&resign(&nulls), &identity().public())
                .unwrap()
                .body()
                .protocol("sample")
                .is_none()
        );
        // The form check: an object of objects under scope-name syntax.
        for bad in [
            serde_json::json!([]),
            serde_json::json!("x"),
            serde_json::json!({"sample": []}),
            serde_json::json!({"sample": "x"}),
            serde_json::json!({"Sample": {}}),
            serde_json::json!({"": {}}),
            serde_json::json!({"a.b": {}}),
        ] {
            let mut v = value();
            v["protocols"] = bad.clone();
            assert!(
                AppRecord::verify(&resign(&v), &identity().public()).is_err(),
                "{bad}"
            );
        }
        // The switch requires no `expires_at`, but it is always written.
        let mut no_expiry = value();
        no_expiry.as_object_mut().unwrap().remove("expires_at");
        assert!(AppRecord::verify(&resign(&no_expiry), &identity().public()).is_err());
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
