//! The Switch's signed documents (Switch wire 3): app certificates and records,
//! `identity.json`, receive key records, key bundles, freezes and unfreezes, enrollments,
//! app requests, approvals, export transfers, and the signer's hand-over and backup, with the
//! pure rules the service, apps and the signer apply to them.
//!
//! Each document comes in two types:
//!
//! - a body (`AppCertBody`, `IdentityBody`, ...): plain data with public fields, the members
//!   a writer puts in the document, with keys as bytes and times as Unix milliseconds;
//! - the signed document (`AppCert`, `IdentityDoc`, ...), which only a check makes: `sign`
//!   for a writer, `verify` for a reader. Its fields are private, so holding one means the
//!   signature verified and every rule of its section held.
//!
//! Readers never re-serialize a document: a verified one keeps the exact bytes it was read
//! from (Switch wire 1.1, 2.2). Writers produce compact JSON with the members in the order
//! of the wire format's tables.

mod app_record;
mod app_request;
mod approval;
mod cert;
mod delivery;
mod enroll;
mod export_transfer;
#[cfg(test)]
mod fixtures;
mod freeze;
mod handover;
mod identity;
mod key_bundle;
mod receive_key;
mod renewal;

pub use app_record::{AppRecord, AppRecordBody, RECORD_KIND, RecordOrder, RecordView};
pub use app_request::{
    APP_REQUEST_KIND, AppRequest, AppRequestBody, Approve, AuthRequest, IDENTITY_PATH,
    SIGNER_BACKUP_PATH, SignerView, app_backup_path, app_record_path, check_app_request,
    check_caps,
};
pub use approval::{
    APPROVAL_CLAIM_TYPE, APPROVAL_KIND, Approval, ApprovalClaim, ApprovedApp, CLAIM_PARAMETER,
    claim_signed_bytes,
};
pub use cert::{AppCert, AppCertBody, CERT_KIND, DEFAULT_CERT_LIFETIME_MS, MAX_CERT_LIFETIME_MS};
pub use delivery::{
    AccountView, Delivery, DeliveryRefusal, GenerationChange, KeptProofs, check_delivery,
    check_kept_service_keys, needed_generations, signer_service_keys,
};
pub use enroll::{
    ENROLL_KIND, Enrollment, EnrollmentAnswer, EnrollmentBody, Limits, MAX_APP_LIMIT,
};
pub use export_transfer::{EXPORT_TRANSFER_KIND, ExportTransfer, ExportTransferBody};
pub use freeze::{DiscardAnswer, FREEZE_KIND, Freeze, FreezeBody, Unfreeze, UnfreezeAt};
pub use handover::{
    DeliveryKind, HANDOVER_KIND, MAX_BUNDLE_PARTS, MAX_HANDOVER_ENVELOPES, RestoreStart,
    SignerBackup, SignerHandover, SignerRecords, TakeOver, abort_body, backup_taken_over,
    check_handover_copies, check_restore_copies, revoked_after, succeeded, take_over_body,
    taken_over,
};
pub use identity::{
    Admission, ConnectRequests, DEFAULT_RECORD_MAX_AGE_S, IDENTITY_KIND, IdentityBody, IdentityDoc,
    IdentityPolicy, ListedApp, MAX_SERVICE_KEYS, RemovedApp, RenewedCert, SeenBodies,
    ServiceKeyEntry, Standing, VersionOrder,
};
pub use key_bundle::{
    BundlePart, BundleReading, KEY_BUNDLE_KIND, KeyBundle, KeyBundleContents, MissingKeys,
    PartReader, SkipReason, SkippedPart, StoredPart, check_bundle_keys, check_part_order,
    covers_from_one, full_bundle_ranges, incremental_first_epoch, keyed_scopes, missing_keys,
    missing_ranges, needs_cert_put, note_stored, ranges_for_cert, reader_certs, seal_bundle_parts,
};
pub use receive_key::{RECEIVE_KEY_KIND, ReceiveKeyBody, ReceiveKeyRecord};
pub use renewal::{
    CheckFailure, check_presented, closing_until, is_reduction, is_renewal, owed_closings,
    reduction_rotates, renewal_epochs,
};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::enc::{serde_b64, serde_b64_vec, suite_kid};
use crate::error::{Error, Result, invalid};
use crate::json::parse_json;
use crate::sig::SignedDoc;

/// A day in Unix milliseconds.
pub const DAY_MS: u64 = 86_400_000;

/// The clock tolerance between services and readers, 5 minutes (Switch spec 11, Switch wire
/// 3.8 and 5.1 check 7).
pub const CLOCK_TOLERANCE_MS: u64 = 5 * 60_000;

/// The service an `identity.json`, a freeze or an export transfer names: its origin and the
/// account's service key there (Switch wire 3.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Inbox {
    /// The switch origin exactly as requests sign it: `https://host[:port]`, no path, no
    /// trailing slash.
    pub url: String,
    /// The account's service key at that origin.
    #[serde(with = "serde_b64")]
    pub service_key: [u8; 32],
}

impl Inbox {
    /// The inbox at `url` with `service_key`.
    pub fn new(url: &str, service_key: [u8; 32]) -> Self {
        Self {
            url: url.to_owned(),
            service_key,
        }
    }

    /// Check that `url` is a switch origin (Switch wire 3.3).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if it isn't.
    pub fn check(&self) -> Result<()> {
        if is_origin(&self.url) {
            Ok(())
        } else {
            invalid("Switch wire 3.3: inbox.url isn't an https origin without a path")
        }
    }
}

/// Whether `url` is a switch origin: `https://host[:port]`, with no path, query, fragment,
/// user information or trailing slash (Switch wire 3.3).
pub fn is_origin(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    // Every label of the host is non-empty and neither starts nor ends with `-`.
    let host_ok = !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    // A port of 1 to 65535 written without leading zeros, as the connecting side reads it
    // (Switch wire 7.1).
    let port_ok = port.is_none_or(|p| {
        p.bytes().all(|b| b.is_ascii_digit())
            && !p.starts_with('0')
            && p.parse::<u16>().is_ok_and(|n| n != 0)
    });
    host_ok && port_ok
}

/// A key of a later suite, as a certificate's or a receive key record's `suite_keys` carries
/// it (Switch wire 3.1, 3.4). No suite but suite 1 exists in this version: writers write
/// none, and readers check the form and ignore the keys.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SuiteKey {
    /// The suite, the envelope's suite byte: 2 to 255.
    pub suite: u64,
    /// The key, 1 to 4096 bytes.
    #[serde(with = "serde_b64_vec")]
    pub key: Vec<u8>,
}

impl SuiteKey {
    /// The key's kid, derived over its suite and the key (Switch wire 1.5).
    pub fn kid(&self) -> [u8; 8] {
        suite_kid(self.suite, &self.key)
    }
}

/// The most entries of a `suite_keys` list (Switch wire 3.1).
pub const MAX_SUITE_KEYS: usize = 4;

/// The longest key in a `suite_keys` entry, in bytes (Switch wire 3.1).
pub const MAX_SUITE_KEY_BYTES: usize = 4096;

/// Check a present `suite_keys` list (Switch wire 3.1): 1 to 4 entries, suites from 2 to 255
/// strictly ascending, keys of 1 to 4096 bytes.
///
/// # Errors
///
/// [`Error::Invalid`] naming the rule that failed.
pub fn check_suite_keys(keys: &[SuiteKey]) -> Result<()> {
    if !(1..=MAX_SUITE_KEYS).contains(&keys.len()) {
        return invalid("Switch wire 3.1: suite_keys holds 1 to 4 entries");
    }
    let mut last = None;
    for key in keys {
        if !(2..=255).contains(&key.suite) {
            return invalid("Switch wire 3.1: suite_keys: a suite outside 2 to 255");
        }
        if last.is_some_and(|l| l >= key.suite) {
            return invalid("Switch wire 3.1: suite_keys: suites not strictly ascending");
        }
        if !(1..=MAX_SUITE_KEY_BYTES).contains(&key.key.len()) {
            return invalid("Switch wire 3.1: suite_keys: a key outside 1 to 4096 bytes");
        }
        last = Some(key.suite);
    }
    Ok(())
}

/// The members of a `suite_keys` entry, which refuses any other (Switch wire 1.1).
const SUITE_KEY_MEMBERS: [&str; 2] = ["suite", "key"];

/// Refuse unknown members in each entry of a `suite_keys` member, if present (Switch wire
/// 1.1).
fn reject_unknown_suite_key_members(body: &Value) -> Result<()> {
    if let Some(Value::Array(entries)) = body.get("suite_keys") {
        for entry in entries {
            crate::json::reject_unknown_members(entry, &SUITE_KEY_MEMBERS, "a suite key")?;
        }
    }
    Ok(())
}

/// Verify a signed document over `lp(label, body)` and parse its body strictly into a JSON
/// value (Switch wire 1.1, 2.2).
fn open_value(signed: &SignedDoc, public: &[u8; 32], label: &str) -> Result<Value> {
    parse_json(&signed.verify(public, label, &[])?)
}

/// Check a document's `v` and `kind` (Switch wire 1.1).
fn check_tag(body: &Value, kind: &str, section: &str) -> Result<()> {
    if body.get("v").and_then(Value::as_u64) != Some(1) {
        return invalid(format!("{section}: v isn't 1"));
    }
    if body.get("kind").and_then(Value::as_str) != Some(kind) {
        return invalid(format!("{section}: kind isn't {kind}"));
    }
    Ok(())
}

/// Decode a checked JSON value into a body type.
fn decode<T: DeserializeOwned>(body: Value) -> Result<T> {
    Ok(serde_json::from_value(body)?)
}

/// A body with its `v` and `kind`, as a writer puts them first.
#[derive(Serialize)]
struct Tagged<'a, T: Serialize> {
    v: u64,
    kind: &'a str,
    #[serde(flatten)]
    body: &'a T,
}

/// Write a body as compact JSON, `v` and `kind` first, then its members in their order.
fn encode<T: Serialize>(kind: &str, body: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(&Tagged { v: 1, kind, body })
        .map_err(|_| Error::Invalid("Switch wire 1.1: the body can't be written as JSON".into()))
}

/// The text of a core error, as a serde error message carries it, so that
/// [`crate::error::json_reason`] keeps the rule it names.
fn reason(error: Error) -> String {
    match error {
        Error::Invalid(why) | Error::Signature(why) | Error::Crypto(why) => why,
    }
}

/// Serde helpers for the members of Switch documents.
mod fmt {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::enc;
    use crate::time;

    /// A Pubky ID, as the 32 bytes of its key (Switch wire 1.3).
    pub mod pubky {
        use super::*;

        pub fn serialize<S: Serializer>(key: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&enc::pubky_id(key))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
            let text = String::deserialize(d)?;
            enc::pubky_key(&text).map_err(|e| D::Error::custom(super::super::reason(e)))
        }
    }

    /// An App ID, as its 16 bytes (Switch wire 1.3).
    pub mod app_id {
        use super::*;

        pub fn serialize<S: Serializer>(id: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&enc::zbase32_encode(id))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
            let text = String::deserialize(d)?;
            enc::app_id_decode(&text).map_err(|e| D::Error::custom(super::super::reason(e)))
        }
    }

    /// A present list of App IDs, `None` when absent or `null`.
    pub mod opt_app_ids {
        use super::*;

        pub fn serialize<S: Serializer>(
            ids: &Option<Vec<[u8; 16]>>,
            s: S,
        ) -> Result<S::Ok, S::Error> {
            let texts: Option<Vec<String>> = ids
                .as_ref()
                .map(|ids| ids.iter().map(|id| enc::zbase32_encode(id)).collect());
            texts.serialize(s)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> Result<Option<Vec<[u8; 16]>>, D::Error> {
            let Some(texts) = Option::<Vec<String>>::deserialize(d)? else {
                return Ok(None);
            };
            texts
                .iter()
                .map(|t| {
                    enc::app_id_decode(t).map_err(|e| D::Error::custom(super::super::reason(e)))
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Some)
        }
    }

    /// A time, as Unix milliseconds, written with three fraction digits (Switch wire 1.6).
    pub mod time_ms {
        use super::*;

        pub fn serialize<S: Serializer>(ms: &u64, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&time::rfc3339(*ms))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
            let text = String::deserialize(d)?;
            time::parse_rfc3339(&text).map_err(|e| D::Error::custom(super::super::reason(e)))
        }
    }

    /// A `time | null`, written as `null` when `None`. Used without `default`, it is a
    /// member that is required and always written (Switch wire, "Absent and null").
    pub mod opt_time_ms {
        use super::*;

        pub fn serialize<S: Serializer>(ms: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
            ms.map(time::rfc3339).serialize(s)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
            match Option::<String>::deserialize(d)? {
                None => Ok(None),
                Some(text) => time::parse_rfc3339(&text)
                    .map(Some)
                    .map_err(|e| D::Error::custom(super::super::reason(e))),
            }
        }
    }

    /// A required member that may be `null`: missing is refused, `null` is `None`.
    pub fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
        d: D,
    ) -> Result<Option<T>, D::Error> {
        Option::<T>::deserialize(d)
    }

    /// An optional member read as its default when `null`, as readers treat `null` like a
    /// missing member (Switch wire, "Absent and null").
    pub fn null_default<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(
        d: D,
    ) -> Result<T, D::Error> {
        Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_origin_takes_https_origins_only() {
        for ok in [
            "https://inbox.example",
            "https://inbox.example:8443",
            "https://127.0.0.1",
        ] {
            assert!(is_origin(ok), "{ok}");
        }
        for bad in [
            "http://inbox.example",
            "https://inbox.example/",
            "https://inbox.example/v1",
            "https://inbox.example?x",
            "https://user@inbox.example",
            "https://inbox.example:",
            "https://inbox.example:99999",
            "https://inbox.example:0",
            "https://inbox.example:00443",
            "https://-",
            "https://.",
            "https://inbox..example",
            "https://-inbox.example",
            "https://",
        ] {
            assert!(!is_origin(bad), "{bad}");
        }
    }

    #[test]
    fn test_suite_keys_form() {
        let key = |suite: u64, len: usize| SuiteKey {
            suite,
            key: vec![9; len],
        };
        check_suite_keys(&[key(2, 32), key(7, 4096)]).unwrap();
        for (bad, rule) in [
            (vec![], "1 to 4"),
            (
                vec![key(2, 1), key(3, 1), key(4, 1), key(5, 1), key(6, 1)],
                "1 to 4",
            ),
            (vec![key(1, 32)], "outside 2 to 255"),
            (vec![key(256, 32)], "outside 2 to 255"),
            (vec![key(3, 32), key(2, 32)], "ascending"),
            (vec![key(2, 32), key(2, 32)], "ascending"),
            (vec![key(2, 0)], "1 to 4096"),
            (vec![key(2, 4097)], "1 to 4096"),
        ] {
            let error = check_suite_keys(&bad).unwrap_err().to_string();
            assert!(error.contains(rule), "{error}");
        }
        assert_ne!(key(2, 32).kid(), key(3, 32).kid());
    }

    #[test]
    fn test_check_tag_refuses_another_version_or_kind() {
        let body = serde_json::json!({"v": 1, "kind": "k"});
        check_tag(&body, "k", "S").unwrap();
        assert!(check_tag(&serde_json::json!({"v": 2, "kind": "k"}), "k", "S").is_err());
        assert!(check_tag(&serde_json::json!({"kind": "k"}), "k", "S").is_err());
        assert!(check_tag(&body, "other", "S").is_err());
    }
}
