//! Reading the members of an operation body that strict JSON parsing has checked (Switch wire
//! 1.1), into typed values.
//!
//! Every reason names the member and the rule, never the member's value, which is the refused
//! document's text.

use serde_json::Value;

use crate::enc::{app_id_decode, pubky_key, unb64, unb64_array};
use crate::error::{Error, Result, invalid};
use crate::json::{MAX_INT, reject_unknown_members};
use crate::time::parse_rfc3339;

/// A refusal naming `member` of `what`.
fn refuse<T>(what: &str, member: &str, rule: &str) -> Result<T> {
    invalid(format!("Switch wire 6.2: {what}: {member} {rule}"))
}

/// The members of `value`, refusing any but `allowed` (Switch wire 1.1).
pub(crate) fn only(value: &Value, allowed: &[&str], what: &str) -> Result<()> {
    reject_unknown_members(value, allowed, what)
}

/// A member that is present and not `null`.
pub(crate) fn opt<'a>(value: &'a Value, member: &str) -> Option<&'a Value> {
    value.get(member).filter(|v| !v.is_null())
}

/// A required member, present and not `null`.
pub(crate) fn req<'a>(value: &'a Value, member: &str, what: &str) -> Result<&'a Value> {
    match opt(value, member) {
        Some(v) => Ok(v),
        None => refuse(what, member, "is missing"),
    }
}

/// A string.
pub(crate) fn text<'a>(value: &'a Value, member: &str, what: &str) -> Result<&'a str> {
    match value.as_str() {
        Some(s) => Ok(s),
        None => refuse(what, member, "isn't a string"),
    }
}

/// A required string member.
pub(crate) fn req_str<'a>(value: &'a Value, member: &str, what: &str) -> Result<&'a str> {
    text(req(value, member, what)?, member, what)
}

/// An integer of the wire range (Switch wire 1.1).
pub(crate) fn int(value: &Value, member: &str, what: &str) -> Result<u64> {
    match value.as_u64() {
        Some(n) if n <= MAX_INT => Ok(n),
        _ => refuse(what, member, "isn't an integer from 0 to 2^53 - 1"),
    }
}

/// A required integer member.
pub(crate) fn req_int(value: &Value, member: &str, what: &str) -> Result<u64> {
    int(req(value, member, what)?, member, what)
}

/// An optional integer member, `null` read as absent.
pub(crate) fn opt_int(value: &Value, member: &str, what: &str) -> Result<Option<u64>> {
    opt(value, member).map(|v| int(v, member, what)).transpose()
}

/// Base64url of exactly `N` bytes.
pub(crate) fn b64n<const N: usize>(value: &Value, member: &str, what: &str) -> Result<[u8; N]> {
    unb64_array::<N>(text(value, member, what)?)
        .map_err(|_| Error::Invalid(format!("Switch wire 6.2: {what}: {member} isn't b64({N})")))
}

/// A required member of base64url of exactly `N` bytes.
pub(crate) fn req_b64n<const N: usize>(value: &Value, member: &str, what: &str) -> Result<[u8; N]> {
    b64n::<N>(req(value, member, what)?, member, what)
}

/// A required member of base64url of any length.
pub(crate) fn req_b64(value: &Value, member: &str, what: &str) -> Result<Vec<u8>> {
    unb64(req_str(value, member, what)?)
        .map_err(|_| Error::Invalid(format!("Switch wire 6.2: {what}: {member} isn't base64url")))
}

/// A required time member, as Unix milliseconds (Switch wire 1.6).
pub(crate) fn req_time(value: &Value, member: &str, what: &str) -> Result<u64> {
    time(req(value, member, what)?, member, what)
}

/// A time, as Unix milliseconds (Switch wire 1.6).
pub(crate) fn time(value: &Value, member: &str, what: &str) -> Result<u64> {
    parse_rfc3339(text(value, member, what)?).map_err(|_| {
        Error::Invalid(format!(
            "Switch wire 6.2: {what}: {member} isn't a time (Switch wire 1.6)"
        ))
    })
}

/// A member that must be present and may be `null`: `time | null`.
pub(crate) fn nullable_time(value: &Value, member: &str, what: &str) -> Result<Option<u64>> {
    match value.get(member) {
        None => refuse(what, member, "is missing"),
        Some(Value::Null) => Ok(None),
        Some(v) => time(v, member, what).map(Some),
    }
}

/// A required Pubky ID member, as its 32 bytes (Switch wire 1.3).
pub(crate) fn req_pubky(value: &Value, member: &str, what: &str) -> Result<[u8; 32]> {
    pubky_key(req_str(value, member, what)?).map_err(|_| {
        Error::Invalid(format!(
            "Switch wire 6.2: {what}: {member} isn't a Pubky ID"
        ))
    })
}

/// An App ID, as its 16 bytes (Switch wire 1.3).
pub(crate) fn app_id(value: &Value, member: &str, what: &str) -> Result<[u8; 16]> {
    app_id_decode(text(value, member, what)?)
        .map_err(|_| Error::Invalid(format!("Switch wire 6.2: {what}: {member} isn't an App ID")))
}

/// A required App ID member.
pub(crate) fn req_app_id(value: &Value, member: &str, what: &str) -> Result<[u8; 16]> {
    app_id(req(value, member, what)?, member, what)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_read_members_by_type() {
        let v = json!({"n": 3, "s": "x", "z": null, "t": "2026-01-01T00:00:00.000Z"});
        assert_eq!(req_int(&v, "n", "doc").unwrap(), 3);
        assert_eq!(req_str(&v, "s", "doc").unwrap(), "x");
        assert!(opt(&v, "z").is_none());
        assert!(req(&v, "z", "doc").is_err());
        assert_eq!(opt_int(&v, "z", "doc").unwrap(), None);
        assert_eq!(req_time(&v, "t", "doc").unwrap(), 1_767_225_600_000);
        assert!(req_int(&v, "s", "doc").is_err());
        assert!(req_str(&v, "n", "doc").is_err());
        assert!(nullable_time(&v, "missing", "doc").is_err());
        assert_eq!(nullable_time(&v, "z", "doc").unwrap(), None);
    }

    #[test]
    fn test_read_refusals_never_quote_the_value() {
        let v = json!({"k": "secret-text"});
        let error = req_b64n::<32>(&v, "k", "doc").unwrap_err().to_string();
        assert!(!error.contains("secret-text"), "{error}");
        assert!(error.contains("b64(32)"), "{error}");
    }
}
