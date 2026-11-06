//! Sealed shared record values (Switch wire 6.2, Switch spec 13.4): the `value_sealed` of a
//! `record.put`.
//!
//! ```json
//! { "data_epoch": 4, "scope": "<read scope>", "nonce": "<24 bytes>", "ct": "<ct and tag>" }
//! ```
//!
//! A value is sealed with XChaCha20-Poly1305 under the key of the record's read scope at the
//! data epoch, `scope_key(data_epoch, scope)` (Switch spec 3.5), with a random nonce and the
//! AAD `lp("pubky-switch/v1/sealed", identity, scope, record key)`, so a value can't be moved
//! to another record, scope or identity. The plaintext is `u32_be(len(JSON)) || JSON || zero
//! padding`, padded to the smallest of [`BUCKETS`] that holds it, so the stored length shows
//! only the bucket (Switch spec 15). A delete is the empty plaintext, unpadded, so its `ct` is
//! the 16-byte tag alone.
//!
//! The nonce comes from the operating system's secure random generator; only test builds can
//! fix it, to rebuild the shared vectors.

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use serde::{Deserialize, Serialize};

use crate::enc::{lp, random_bytes, serde_b64, serde_b64_vec};
use crate::envelope::check_padding;
use crate::error::{Error, Result, SizeRefusal, invalid};
use crate::ident::Policy;
use crate::json::check_json;
use crate::keys::ScopeKeys;
use crate::labels;

/// The lengths a padded value may have: 2^k bytes for k from 9 to 18 and 3 * 2^k for k from 8
/// to 16, ascending, each at most half again the one below (Switch wire 6.2).
pub const BUCKETS: [usize; 19] = [
    512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536,
    98304, 131072, 196608, 262144,
];
/// The XChaCha20-Poly1305 nonce (Switch wire 1.2, 6.2).
pub const NONCE_LEN: usize = 24;
/// The AEAD tag that ends every `ct` (Switch wire 6.2).
pub const TAG_LEN: usize = 16;
/// The longest value JSON: the largest bucket less the length prefix, 262,140 bytes (Switch
/// wire 6.2).
pub const MAX_JSON_LEN: usize = 262_140;
/// The longest `ct`: the largest bucket and the tag, 262,160 bytes; a longer one is answered
/// `413` (Switch wire 6.2).
pub const MAX_CT_LEN: usize = 262_160;

const LEN_PREFIX: usize = 4;

/// The length of the padded plaintext of a value of `json_len` bytes (Switch wire 6.2): the
/// smallest bucket that holds `4 + json_len`, or 0 for a delete, whose empty plaintext stays
/// unpadded.
///
/// `None` for a value no bucket holds, over 262,140 bytes.
pub fn padded_len(json_len: usize) -> Option<usize> {
    if json_len == 0 {
        return Some(0);
    }
    let needed = json_len.checked_add(LEN_PREFIX)?;
    BUCKETS.into_iter().find(|bucket| needed <= *bucket)
}

/// Pad a value's JSON: `u32_be(len(JSON)) || JSON || zero padding`, [`padded_len`] bytes long
/// (Switch wire 6.2, Switch spec 13.4). An empty `json`, a delete, stays empty.
///
/// # Errors
///
/// [`Error::Invalid`] for a value over 262,140 bytes, which fits no bucket; the service
/// answers such a write `413`.
pub fn pad(json: &[u8]) -> Result<Vec<u8>> {
    let Some(len) = padded_len(json.len()) else {
        return invalid("Switch wire 6.2: a value over 262140 bytes fits no bucket");
    };
    if len == 0 {
        return Ok(Vec::new());
    }
    let prefix = u32::try_from(json.len())
        .map_err(|_| Error::Invalid("Switch wire 6.2: a value over 262140 bytes".into()))?;
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&prefix.to_be_bytes());
    out.extend_from_slice(json);
    out.resize(len, 0);
    Ok(out)
}

/// What an opened value holds (Switch wire 6.2 "Accepting a write", step 7).
#[derive(Clone, PartialEq, Eq)]
pub enum RecordValue {
    /// The empty plaintext: a delete, and nothing else is one.
    Delete,
    /// The value's JSON bytes, strict JSON (Switch wire 1.1).
    Json(Vec<u8>),
}

impl std::fmt::Debug for RecordValue {
    // A value is record content, which stays out of logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Delete => f.write_str("Delete"),
            Self::Json(json) => write!(f, "Json({} bytes)", json.len()),
        }
    }
}

/// Remove a value's padding after opening (Switch wire 6.2): the empty plaintext is a delete;
/// otherwise the length must fit, the padding be all zeros and the JSON strict.
///
/// # Errors
///
/// [`Error::Invalid`] for a plaintext shorter than its prefix, a length that runs past it, an
/// empty JSON, a non-zero padding byte, or JSON that breaks Switch wire 1.1: a value that
/// "doesn't open".
pub fn unpad(plaintext: &[u8]) -> Result<RecordValue> {
    if plaintext.is_empty() {
        return Ok(RecordValue::Delete);
    }
    let (len, rest) = plaintext
        .split_first_chunk::<LEN_PREFIX>()
        .ok_or_else(|| Error::Invalid("Switch wire 6.2: a value shorter than its length".into()))?;
    let len = usize::try_from(u32::from_be_bytes(*len)).unwrap_or(usize::MAX);
    let (json, padding) = rest.split_at_checked(len).ok_or_else(|| {
        Error::Invalid("Switch wire 6.2: a value length that runs past its bucket".into())
    })?;
    if json.is_empty() {
        return invalid(
            "Switch wire 6.2: a padded value without JSON; only an empty plaintext is a delete",
        );
    }
    check_padding(padding)?;
    check_json(json)?;
    Ok(RecordValue::Json(json.to_vec()))
}

/// The AAD of a sealed value: `lp("pubky-switch/v1/sealed", identity, scope, record key)`
/// (Switch wire 6.2, Switch spec 13.4).
pub fn aad(identity: &[u8; 32], scope: &str, record_key: &[u8; 32]) -> Vec<u8> {
    lp(&[
        labels::derive::SEALED.as_bytes(),
        identity,
        scope.as_bytes(),
        record_key,
    ])
}

/// The service's check of a `ct` length (Switch wire 6.2): 16 bytes, a delete, or a bucket
/// plus the tag.
///
/// # Errors
///
/// [`SizeRefusal::TooLarge`] past 262,160 bytes, [`SizeRefusal::BadRequest`] for any other
/// length.
pub fn check_ct_len(len: usize) -> std::result::Result<(), SizeRefusal> {
    if len > MAX_CT_LEN {
        return Err(SizeRefusal::TooLarge(
            "Switch wire 6.2: a sealed value over 262160 bytes".into(),
        ));
    }
    let padded = len.checked_sub(TAG_LEN);
    if padded == Some(0) || padded.is_some_and(|padded| BUCKETS.contains(&padded)) {
        return Ok(());
    }
    Err(SizeRefusal::BadRequest(
        "Switch wire 6.2: a sealed value whose length is neither the tag nor a bucket and the tag"
            .into(),
    ))
}

/// A sealed value as a `record.put` carries it (Switch wire 6.2). Unknown members are
/// refused, at every depth of an operation body (Switch wire 1.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedValue {
    /// The data epoch of the key; the service requires the current one (Switch spec 13.4).
    pub data_epoch: u64,
    /// The scope of the key: the record's `read_scope`.
    pub scope: String,
    /// The XChaCha20-Poly1305 nonce, random.
    #[serde(with = "serde_b64")]
    pub nonce: [u8; NONCE_LEN],
    /// The ciphertext and its 16-byte tag.
    #[serde(with = "serde_b64_vec")]
    pub ct: Vec<u8>,
}

impl SealedValue {
    /// Seal a value's JSON for the record `record_key` of `identity`, padded to its bucket,
    /// under `scope_key`, the key of `scope` at `data_epoch` (Switch wire 6.2). An empty
    /// `json` seals a delete. The nonce comes from the secure random generator.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a value over 262,140 bytes; [`Error::Crypto`] if the random
    /// generator fails.
    pub fn seal(
        scope_key: &[u8; 32],
        identity: &[u8; 32],
        data_epoch: u64,
        scope: &str,
        record_key: &[u8; 32],
        json: &[u8],
    ) -> Result<Self> {
        let nonce = random_bytes::<NONCE_LEN>()?;
        Self::seal_nonce(
            scope_key, identity, data_epoch, scope, record_key, json, &nonce,
        )
    }

    /// Seal a value under the policy's read scope at `data_epoch`, with the key `keys` hold
    /// for it (Switch wire 6.2, Switch spec 3.5). An empty `json` seals a delete.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when `keys` hold no key of the read scope at that epoch, and as
    /// [`SealedValue::seal`].
    pub fn seal_for(
        keys: &ScopeKeys,
        policy: &Policy,
        data_epoch: u64,
        identity: &[u8; 32],
        record_key: &[u8; 32],
        json: &[u8],
    ) -> Result<Self> {
        let scope = policy.read_scope.as_str();
        let key = zeroize::Zeroizing::new(keys.get(data_epoch, scope).ok_or_else(|| {
            Error::Crypto("Switch spec 3.5: no key of the read scope at this data epoch".into())
        })?);
        Self::seal(&key, identity, data_epoch, scope, record_key, json)
    }

    /// A delete: the sealed empty plaintext, unpadded, so `ct` is the tag alone (Switch wire
    /// 6.2).
    ///
    /// # Errors
    ///
    /// As [`SealedValue::seal`].
    pub fn delete(
        scope_key: &[u8; 32],
        identity: &[u8; 32],
        data_epoch: u64,
        scope: &str,
        record_key: &[u8; 32],
    ) -> Result<Self> {
        Self::seal(scope_key, identity, data_epoch, scope, record_key, b"")
    }

    /// [`SealedValue::seal`] with a fixed nonce, to rebuild the shared vectors. Test builds
    /// only: never reuse a nonce under one key.
    ///
    /// # Errors
    ///
    /// As [`SealedValue::seal`].
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn seal_with_nonce(
        scope_key: &[u8; 32],
        identity: &[u8; 32],
        data_epoch: u64,
        scope: &str,
        record_key: &[u8; 32],
        json: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self> {
        Self::seal_nonce(
            scope_key, identity, data_epoch, scope, record_key, json, nonce,
        )
    }

    fn seal_nonce(
        scope_key: &[u8; 32],
        identity: &[u8; 32],
        data_epoch: u64,
        scope: &str,
        record_key: &[u8; 32],
        json: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self> {
        let padded = zeroize::Zeroizing::new(pad(json)?);
        let ct = XChaCha20Poly1305::new(scope_key.into())
            .encrypt(
                chacha20poly1305::XNonce::from_slice(nonce),
                Payload {
                    msg: &padded,
                    aad: &aad(identity, scope, record_key),
                },
            )
            .map_err(|_| Error::Crypto("Switch wire 6.2: the value doesn't seal".into()))?;
        Ok(Self {
            data_epoch,
            scope: scope.to_owned(),
            nonce: *nonce,
            ct,
        })
    }

    /// The service's checks of a sealed value that need no key (Switch wire 6.2, Switch spec
    /// 13.4): `scope` is the record's `read_scope`, and `ct` has a length the rule allows.
    /// The data epoch's check needs the account's state and is the service's.
    ///
    /// # Errors
    ///
    /// [`SizeRefusal::TooLarge`] for a `ct` past 262,160 bytes, and
    /// [`SizeRefusal::BadRequest`] for another scope or length.
    pub fn check_shape(&self, read_scope: &str) -> std::result::Result<(), SizeRefusal> {
        check_ct_len(self.ct.len())?;
        if self.scope != read_scope {
            return Err(SizeRefusal::BadRequest(
                "Switch spec 13.4: a sealed value's scope isn't the record's read scope".into(),
            ));
        }
        Ok(())
    }

    /// Whether `ct` is the tag alone, the shape of a delete. It proves nothing: only a value
    /// that opens to the empty plaintext is a delete (Switch wire 6.2 step 7).
    pub fn looks_like_delete(&self) -> bool {
        self.ct.len() == TAG_LEN
    }

    /// Open the value with `scope_key`, the key of its scope at its data epoch, for the
    /// record `record_key` of `identity`, and remove the padding (Switch wire 6.2 step 7).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a `ct` length the rule doesn't allow or a plaintext [`unpad`]
    /// refuses; [`Error::Crypto`] for a value that doesn't open with the key, for this
    /// record, scope and identity.
    pub fn open(
        &self,
        scope_key: &[u8; 32],
        identity: &[u8; 32],
        record_key: &[u8; 32],
    ) -> Result<RecordValue> {
        check_ct_len(self.ct.len())?;
        let plaintext = zeroize::Zeroizing::new(
            XChaCha20Poly1305::new(scope_key.into())
                .decrypt(
                    chacha20poly1305::XNonce::from_slice(&self.nonce),
                    Payload {
                        msg: &self.ct,
                        aad: &aad(identity, &self.scope, record_key),
                    },
                )
                .map_err(|_| Error::Crypto("Switch wire 6.2: the value doesn't open".into()))?,
        );
        unpad(&plaintext)
    }

    /// Open the value with the key `keys` hold for its scope and data epoch (Switch wire 6.2
    /// step 7, Switch spec 3.5).
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when `keys` hold no key of that scope and epoch: the value is
    /// unreadable; otherwise as [`SealedValue::open`].
    pub fn open_with(
        &self,
        keys: &ScopeKeys,
        identity: &[u8; 32],
        record_key: &[u8; 32],
    ) -> Result<RecordValue> {
        let key =
            zeroize::Zeroizing::new(keys.get(self.data_epoch, &self.scope).ok_or_else(|| {
                Error::Crypto("Switch wire 6.2: no key of the value's scope and data epoch".into())
            })?);
        self.open(&key, identity, record_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKey;

    const IDENTITY: [u8; 32] = [0x21; 32];
    const RECORD: [u8; 32] = [0x31; 32];
    const KEY: [u8; 32] = [0x41; 32];

    fn sealed(json: &[u8]) -> SealedValue {
        SealedValue::seal(&KEY, &IDENTITY, 1, "scope-a", &RECORD, json).unwrap()
    }

    /// Seal an arbitrary plaintext, as a faulty writer could.
    fn sealed_raw(plaintext: &[u8]) -> SealedValue {
        let ct = XChaCha20Poly1305::new((&KEY).into())
            .encrypt(
                chacha20poly1305::XNonce::from_slice(&[9; 24]),
                Payload {
                    msg: plaintext,
                    aad: &aad(&IDENTITY, "scope-a", &RECORD),
                },
            )
            .unwrap();
        SealedValue {
            data_epoch: 1,
            scope: "scope-a".into(),
            nonce: [9; 24],
            ct,
        }
    }

    #[test]
    fn test_sealed_buckets_follow_the_rule() {
        let mut want: Vec<usize> = (9..=18).map(|k| 1 << k).collect();
        want.extend((8..=16).map(|k| 3 << k));
        want.sort_unstable();
        assert_eq!(BUCKETS.to_vec(), want);
        for pair in BUCKETS.windows(2) {
            assert!(pair[1] * 2 <= pair[0] * 3, "{pair:?}");
        }
        assert_eq!(MAX_JSON_LEN, BUCKETS[18] - 4);
        assert_eq!(MAX_CT_LEN, BUCKETS[18] + TAG_LEN);
    }

    #[test]
    fn test_sealed_padded_len_edges() {
        assert_eq!(padded_len(0), Some(0));
        assert_eq!(padded_len(1), Some(512));
        assert_eq!(padded_len(508), Some(512));
        assert_eq!(padded_len(509), Some(768));
        assert_eq!(padded_len(MAX_JSON_LEN), Some(262_144));
        assert_eq!(padded_len(MAX_JSON_LEN + 1), None);
        assert!(pad(&vec![b' '; MAX_JSON_LEN + 1]).is_err());
        assert_eq!(pad(b"").unwrap(), Vec::<u8>::new());
        let padded = pad(b"{}").unwrap();
        assert_eq!(padded.len(), 512);
        assert_eq!(&padded[..6], &[0, 0, 0, 2, b'{', b'}']);
    }

    #[test]
    fn test_sealed_value_round_trips_in_every_size() {
        for json_len in [2, 508, 509, 1020, 1021, 100_000] {
            let mut json = vec![b' '; json_len];
            json[0] = b'1';
            let value = sealed(&json);
            assert_eq!(value.ct.len(), padded_len(json_len).unwrap() + TAG_LEN);
            value.check_shape("scope-a").unwrap();
            assert_eq!(
                value.open(&KEY, &IDENTITY, &RECORD).unwrap(),
                RecordValue::Json(json)
            );
        }
        assert!(SealedValue::seal(&KEY, &IDENTITY, 1, "s", &RECORD, &vec![b' '; 262_141]).is_err());
    }

    #[test]
    fn test_sealed_value_delete_stays_empty() {
        let delete = SealedValue::delete(&KEY, &IDENTITY, 1, "scope-a", &RECORD).unwrap();
        assert_eq!(delete.ct.len(), TAG_LEN);
        assert!(delete.looks_like_delete());
        delete.check_shape("scope-a").unwrap();
        assert_eq!(
            delete.open(&KEY, &IDENTITY, &RECORD).unwrap(),
            RecordValue::Delete
        );
        assert!(!sealed(b"{}").looks_like_delete());
    }

    #[test]
    fn test_sealed_value_is_bound_to_its_record_scope_identity_and_key() {
        let value = sealed(b"{}");
        assert!(value.open(&KEY, &IDENTITY, &[0; 32]).is_err());
        assert!(value.open(&KEY, &[0; 32], &RECORD).is_err());
        assert!(value.open(&[0; 32], &IDENTITY, &RECORD).is_err());
        let mut moved = value.clone();
        moved.scope = "scope-b".into();
        assert!(moved.open(&KEY, &IDENTITY, &RECORD).is_err());
    }

    #[test]
    fn test_sealed_value_refuses_bad_padding() {
        let mut dirty = pad(b"{}").unwrap();
        dirty[511] = 1;
        assert!(sealed_raw(&dirty).open(&KEY, &IDENTITY, &RECORD).is_err());
        let mut overrun = pad(b"{}").unwrap();
        overrun[..4].copy_from_slice(&512u32.to_be_bytes());
        assert!(sealed_raw(&overrun).open(&KEY, &IDENTITY, &RECORD).is_err());
        let mut empty_json = vec![0u8; 512];
        empty_json[..4].copy_from_slice(&0u32.to_be_bytes());
        assert!(
            sealed_raw(&empty_json)
                .open(&KEY, &IDENTITY, &RECORD)
                .is_err()
        );
        let mut not_json = pad(b"{}").unwrap();
        not_json[4] = b'x';
        assert!(
            sealed_raw(&not_json)
                .open(&KEY, &IDENTITY, &RECORD)
                .is_err()
        );
        // An unpadded value has a length no bucket allows.
        assert!(
            sealed_raw(b"\0\0\0\x02{}")
                .open(&KEY, &IDENTITY, &RECORD)
                .is_err()
        );
        // A writer that pads past the smallest bucket isn't refused by readers.
        let mut wide = pad(b"{}").unwrap();
        wide.resize(1024, 0);
        assert!(sealed_raw(&wide).open(&KEY, &IDENTITY, &RECORD).is_ok());
    }

    #[test]
    fn test_sealed_ct_len_rule() {
        for ok in [16, 528, 784, 262_160] {
            check_ct_len(ok).unwrap();
        }
        for (len, status) in [
            (0, 400),
            (15, 400),
            (17, 400),
            (527, 400),
            (1000, 400),
            (262_161, 413),
            (300_000, 413),
        ] {
            assert_eq!(check_ct_len(len).unwrap_err().status(), status, "{len}");
        }
        let value = sealed(b"{}");
        assert!(value.check_shape("scope-b").is_err());
    }

    #[test]
    fn test_sealed_value_json_form_is_strict() {
        let value = sealed(b"{}");
        let json = serde_json::to_value(&value).unwrap();
        assert_eq!(json["nonce"].as_str().unwrap().len(), 32);
        let back: SealedValue = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(back, value);
        let mut extra = json.clone();
        extra["deleted"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SealedValue>(extra).is_err());
        let mut short_nonce = json;
        short_nonce["nonce"] = serde_json::json!("AAAA");
        assert!(serde_json::from_value::<SealedValue>(short_nonce).is_err());
    }

    #[test]
    fn test_sealed_value_uses_the_read_scope_key_of_the_epoch() {
        let identity = IdentityKey::from_secret([5; 32]);
        let public = identity.public();
        let keys = ScopeKeys::derive_range(&identity, &["scope-a".into()], 1, 2);
        let policy = Policy::new("scope-a", &["scope-a"]);
        let value = SealedValue::seal_for(&keys, &policy, 2, &public, &RECORD, b"{}").unwrap();
        assert_eq!((value.data_epoch, value.scope.as_str()), (2, "scope-a"));
        assert_eq!(
            value
                .open(&identity.scope_key(2, "scope-a"), &public, &RECORD)
                .unwrap(),
            RecordValue::Json(b"{}".to_vec())
        );
        assert!(value.open_with(&keys, &public, &RECORD).is_ok());
        assert!(SealedValue::seal_for(&keys, &policy, 3, &public, &RECORD, b"{}").is_err());
        let other = Policy::new("scope-b", &["scope-a"]);
        assert!(SealedValue::seal_for(&keys, &other, 1, &public, &RECORD, b"{}").is_err());
        let mut later = value;
        later.data_epoch = 3;
        assert!(later.open_with(&keys, &public, &RECORD).is_err());
    }

    #[test]
    fn test_sealed_value_with_nonce_is_deterministic() {
        let one = SealedValue::seal_with_nonce(&KEY, &IDENTITY, 1, "s", &RECORD, b"{}", &[3; 24])
            .unwrap();
        let two = SealedValue::seal_with_nonce(&KEY, &IDENTITY, 1, "s", &RECORD, b"{}", &[3; 24])
            .unwrap();
        assert_eq!(one, two);
        assert_ne!(sealed(b"{}").nonce, sealed(b"{}").nonce);
    }

    #[test]
    fn test_record_value_debug_hides_content() {
        let value = RecordValue::Json(b"{\"secret\":1}".to_vec());
        assert_eq!(format!("{value:?}"), "Json(12 bytes)");
    }
}
