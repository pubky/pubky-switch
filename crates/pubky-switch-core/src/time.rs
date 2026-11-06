//! Times (Switch wire 1.6): RFC 3339 in UTC, as Unix milliseconds.
//!
//! The core reads no clock. Every function that depends on time takes it as an argument, in
//! Unix milliseconds.

use chrono::{DateTime, NaiveDate, SecondsFormat, Utc};

use crate::error::{Result, invalid};

/// The last time the grammar can write, `9999-12-31T23:59:59.999Z` (Switch wire 1.6).
pub const MAX_TIME_MS: u64 = 253_402_300_799_999;

/// Write a time with exactly three fraction digits, as documents, messages, records,
/// response bodies and `Switch-Server-Time` carry it (Switch wire 1.6).
///
/// A time past the last one the grammar can write, such as a long duration added to a
/// time, is written as that last time: it means "never".
pub fn rfc3339(ms: u64) -> String {
    format(ms, SecondsFormat::Millis)
}

/// Write a time without a fraction, as `Switch-Timestamp` carries it (Switch wire 1.6).
pub fn rfc3339_seconds(ms: u64) -> String {
    format(ms, SecondsFormat::Secs)
}

fn format(ms: u64, seconds: SecondsFormat) -> String {
    let ms = i64::try_from(ms.min(MAX_TIME_MS)).unwrap_or(0);
    DateTime::<Utc>::from_timestamp_millis(ms)
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
        .to_rfc3339_opts(seconds, true)
}

/// Read a time into Unix milliseconds (Switch wire 1.6).
///
/// The grammar is `YYYY-MM-DDTHH:MM:SS[.F]Z`, with a fraction of 1 to 9 digits. Further
/// digits than milliseconds are truncated, not rounded. This reader takes the grammar only:
/// a space for `T` and numeric offsets, which some readers allow, are refused, which the
/// wire format leaves to each reader.
///
/// # Errors
///
/// [`crate::Error::Invalid`] for anything outside the grammar, a date that doesn't exist, a
/// leap second, a fraction of 0 or more than 9 digits, and a time before 1970.
pub fn parse_rfc3339(text: &str) -> Result<u64> {
    let refuse = || invalid("Switch wire 1.6: not an RFC 3339 time of the grammar");
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes.last() != Some(&b'Z') {
        return refuse();
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = bytes.get(range)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(part).ok()?.parse().ok()
    };
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if separators.iter().any(|(i, c)| bytes.get(*i) != Some(c)) {
        return refuse();
    }
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        digits(0..4),
        digits(5..7),
        digits(8..10),
        digits(11..13),
        digits(14..16),
        digits(17..19),
    ) else {
        return refuse();
    };
    let fraction_ms = match &bytes[19..bytes.len() - 1] {
        [] => 0,
        [b'.', fraction @ ..] => {
            if fraction.is_empty() || fraction.len() > 9 || !fraction.iter().all(u8::is_ascii_digit)
            {
                return refuse();
            }
            fraction
                .iter()
                .chain(std::iter::repeat(&b'0'))
                .take(3)
                .fold(0u64, |ms, d| ms * 10 + u64::from(d - b'0'))
        }
        _ => return refuse(),
    };
    if hour > 23 || minute > 59 || second > 59 {
        return refuse();
    }
    let Some(date) = NaiveDate::from_ymd_opt(i32::try_from(year).unwrap_or(-1), month, day) else {
        return refuse();
    };
    let Some(time) = date.and_hms_opt(hour, minute, second) else {
        return refuse();
    };
    let Ok(seconds) = u64::try_from(time.and_utc().timestamp()) else {
        return invalid("Switch wire 1.6: a time before 1970");
    };
    seconds
        .checked_mul(1000)
        .and_then(|ms| ms.checked_add(fraction_ms))
        .map_or_else(refuse, Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc3339_writes_three_fraction_digits() {
        assert_eq!(rfc3339(1_767_225_630_123), "2026-01-01T00:00:30.123Z");
        assert_eq!(rfc3339_seconds(1_767_225_900_000), "2026-01-01T00:05:00Z");
        assert_eq!(rfc3339(u64::MAX), "9999-12-31T23:59:59.999Z");
    }

    #[test]
    fn test_parse_rfc3339_truncates_and_refuses_outside_the_grammar() {
        assert_eq!(
            parse_rfc3339("2026-01-01T00:00:00.9999Z").unwrap(),
            1_767_225_600_999
        );
        assert_eq!(
            parse_rfc3339("2026-01-01T00:00:00.5Z").unwrap(),
            1_767_225_600_500
        );
        for bad in [
            "2026-01-01T00:00:60Z",
            "2026-02-30T00:00:00Z",
            "2026-01-01T00:00:00.Z",
            "2026-01-01 00:00:00Z",
            "2026-01-01T01:00:00+01:00",
            "1969-12-31T23:59:59Z",
        ] {
            assert!(parse_rfc3339(bad).is_err(), "{bad}");
        }
    }
}
