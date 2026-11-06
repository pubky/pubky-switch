//! Byte encodings (Switch wire 1.2 to 1.5): `lp()`, integers, BLAKE3 and `derive()`,
//! base64url, z-base-32, Pubky IDs, App IDs and kids.

use base64::Engine as _;

use crate::error::{Error, Result, invalid};
use crate::labels;

/// `lp(x1, ..., xn) = u32_be(len(x1)) || x1 || ... || u32_be(len(xn)) || xn` (Switch wire 1.4).
///
/// `lp()` of no parts is empty. A part longer than `u32::MAX` bytes can't be encoded; no
/// Switch input comes near that (an envelope is at most 64 KiB), so such a part is cut to
/// its length prefix's range rather than silently wrapping.
pub fn lp(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len().saturating_add(4)).sum());
    for part in parts {
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(part.get(..len as usize).unwrap_or(part));
    }
    out
}

/// Split `lp()` bytes back into their parts; `None` if they aren't well formed.
pub fn split_lp(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut parts = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let (len, tail) = rest.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
        if tail.len() < len {
            return None;
        }
        let (part, tail) = tail.split_at(len);
        parts.push(part.to_vec());
        rest = tail;
    }
    Some(parts)
}

/// An integer inside `lp()`: 8 bytes, big-endian (Switch wire 1.4).
pub fn u64be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// `hash(x)`: BLAKE3 with a 32-byte output (Switch wire 1.5).
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// `derive(label, parts...) = BLAKE3-derive_key(context = label, key material =
/// lp(parts...))`, 32 bytes (Switch wire 1.5).
pub fn derive(label: &str, parts: &[&[u8]]) -> [u8; 32] {
    blake3::derive_key(label, &lp(parts))
}

/// `N` bytes from the operating system's secure random generator.
///
/// # Errors
///
/// [`Error::Crypto`] if the generator fails.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    use chacha20poly1305::aead::rand_core::{OsRng, RngCore as _};
    let mut out = [0u8; N];
    OsRng
        .try_fill_bytes(&mut out)
        .map_err(|_| Error::Crypto("the secure random generator failed".into()))?;
    Ok(out)
}

/// The first `N` bytes of a byte slice of at least `N` bytes.
pub(crate) fn prefix<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let len = N.min(bytes.len());
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

/// Base64url without padding (Switch wire 1.2).
pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url without padding (Switch wire 1.2).
///
/// Refuses `=` padding, `+` and `/`, whitespace, lengths of the form 4k + 1 and non-zero
/// trailing bits, so each byte string has exactly one text.
///
/// # Errors
///
/// [`Error::Invalid`] for any text that isn't the one encoding of some bytes.
pub fn unb64(text: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| Error::Invalid("Switch wire 1.2: not base64url without padding".into()))
}

/// Decode base64url of exactly `N` bytes (Switch wire 1.2).
///
/// # Errors
///
/// [`Error::Invalid`] if the text isn't base64url or doesn't decode to `N` bytes.
pub fn unb64_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    unb64(text)?.try_into().map_err(|_| {
        Error::Invalid(format!(
            "Switch wire 1.2: a base64url value of {N} bytes expected"
        ))
    })
}

const ZBASE32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// z-base-32, most significant bits first, the last group filled with zero bits, no
/// padding, lower case (Switch wire 1.3).
pub fn zbase32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ZBASE32[((buffer >> bits) & 31) as usize]));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ZBASE32[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Decode z-base-32 into exactly `N` bytes (Switch wire 1.3).
///
/// # Errors
///
/// [`Error::Invalid`] for a wrong length, a character outside the alphabet (upper case
/// included) or non-zero trailing bits, so each key has one ID.
pub fn zbase32_decode<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != (N * 8).div_ceil(5) {
        return invalid("Switch wire 1.3: z-base-32 length");
    }
    let mut out = Vec::with_capacity(N);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for ch in text.bytes() {
        let value = ZBASE32
            .iter()
            .position(|c| *c == ch)
            .ok_or_else(|| Error::Invalid("Switch wire 1.3: z-base-32 character".into()))?;
        buffer = (buffer << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    if buffer != 0 {
        return invalid("Switch wire 1.3: z-base-32 trailing bits");
    }
    out.try_into()
        .map_err(|_| Error::Invalid("Switch wire 1.3: z-base-32 length".into()))
}

/// The Pubky ID of an Ed25519 public key: 52 z-base-32 characters (Switch wire 1.3).
pub fn pubky_id(public: &[u8; 32]) -> String {
    zbase32_encode(public)
}

/// The Ed25519 public key a Pubky ID names (Switch wire 1.3).
///
/// # Errors
///
/// [`Error::Invalid`] if the text isn't the one z-base-32 encoding of 32 bytes.
pub fn pubky_key(id: &str) -> Result<[u8; 32]> {
    zbase32_decode::<32>(id)
}

/// The 16 bytes of an App ID: the first 16 bytes of `hash(signing public key)` (Switch
/// wire 1.3, 1.5).
pub fn app_id_bytes(signing_public: &[u8; 32]) -> [u8; 16] {
    prefix(&hash(signing_public))
}

/// The App ID of an app's signing key: 26 z-base-32 characters (Switch wire 1.3).
pub fn app_id(signing_public: &[u8; 32]) -> String {
    zbase32_encode(&app_id_bytes(signing_public))
}

/// Decode an App ID into its 16 bytes (Switch wire 1.3).
///
/// # Errors
///
/// [`Error::Invalid`] if the text isn't the one z-base-32 encoding of 16 bytes.
pub fn app_id_decode(id: &str) -> Result<[u8; 16]> {
    zbase32_decode::<16>(id)
}

/// The suite of this version's X25519 keys: the envelope's suite byte (Switch wire 4.2).
pub const SUITE_1: u64 = 1;

/// The kid of a suite 1 X25519 key: the first 8 bytes of `derive("pubky-switch/v1/kid",
/// key)` (Switch wire 1.5).
pub fn kid(x25519_public: &[u8; 32]) -> [u8; 8] {
    suite_kid(SUITE_1, x25519_public)
}

/// The kid of a key of `suite` (Switch wire 1.5): as [`kid`] for suite 1, and the first
/// 8 bytes of `derive("pubky-switch/v1/kid", u64(suite), key)` for a later suite, so keys
/// of two suites never share a kid.
pub fn suite_kid(suite: u64, key: &[u8]) -> [u8; 8] {
    let digest = if suite == SUITE_1 {
        derive(labels::derive::KID, &[key])
    } else {
        derive(labels::derive::KID, &[&u64be(suite), key])
    };
    prefix(&digest)
}

/// Whether an X25519 public key is of low order, on the curve or its twist (Switch spec
/// 3.6, Switch wire 4.2).
///
/// X25519 with such a key gives the all-zero shared value whatever the secret, which RFC
/// 9180 aborts on, so nothing can be sealed to it. Registrations, certificates and senders
/// refuse it.
pub fn x25519_low_order(public: &[u8; 32]) -> bool {
    // Every clamped secret is a multiple of the cofactor 8, so the product is all zeros
    // exactly for the points of order 1, 2, 4 or 8.
    curve25519_dalek::montgomery::MontgomeryPoint(*public)
        .mul_clamped([0x55; 32])
        .to_bytes()
        == [0u8; 32]
}

/// Serde helpers for fixed-size byte arrays written as base64url (Switch wire 1.2).
pub mod serde_b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize bytes as base64url without padding.
    pub fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::b64(bytes))
    }

    /// Deserialize base64url of exactly `N` bytes.
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        let text = String::deserialize(deserializer)?;
        super::unb64_array::<N>(&text).map_err(serde::de::Error::custom)
    }
}

/// Serde helpers for byte strings of any length written as base64url (Switch wire 1.2).
pub mod serde_b64_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize bytes as base64url without padding.
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::b64(bytes))
    }

    /// Deserialize base64url of any length.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        super::unb64(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lp_round_trips() {
        let bytes = lp(&[b"ab", b"", b"c"]);
        assert_eq!(
            bytes,
            [0, 0, 0, 2, b'a', b'b', 0, 0, 0, 0, 0, 0, 0, 1, b'c']
        );
        assert_eq!(
            split_lp(&bytes),
            Some(vec![b"ab".to_vec(), Vec::new(), b"c".to_vec()])
        );
        assert!(lp(&[]).is_empty());
    }

    #[test]
    fn test_split_lp_rejects_truncated_input() {
        assert_eq!(split_lp(&[0, 0, 0, 3, b'a']), None);
        assert_eq!(split_lp(&[0, 0]), None);
    }

    #[test]
    fn test_unb64_rejects_padding_and_other_alphabets() {
        assert_eq!(unb64("AQ").unwrap(), [1]);
        for bad in ["AQ==", "A+8", "A/8", "A Q", "A", "AR"] {
            assert!(unb64(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_zbase32_round_trips_and_rejects_noise() {
        let key = [7u8; 32];
        let id = pubky_id(&key);
        assert_eq!(id.len(), 52);
        assert_eq!(pubky_key(&id).unwrap(), key);
        assert!(pubky_key(&id.to_uppercase()).is_err());
        assert!(pubky_key(&id[..51]).is_err());
        // The last character carries one bit; any other filled bit is refused.
        let mut tampered = id.clone();
        tampered.pop();
        tampered.push('n');
        assert!(pubky_key(&tampered).is_err());
    }

    #[test]
    fn test_x25519_low_order_detects_the_zero_point() {
        assert!(x25519_low_order(&[0u8; 32]));
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(x25519_low_order(&one));
        assert!(!x25519_low_order(&[9u8; 32]));
    }
}
