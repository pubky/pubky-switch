//! The binary envelope (Switch wire 4, Switch spec 5.1): one plaintext sealed to 1 to 255
//! recipient apps of one identity.
//!
//! ```text
//! header: "PSW1" | version 1 | suite 1 | flags (bit 0 = notify) | n | key commitment (32)
//!         n x { kid (8) | enc (32) | wrapped content key (48) }
//! body:   nonce (24) | ciphertext and tag
//! ```
//!
//! Suite 1 (Switch wire 4.2) seals the padded plaintext with XChaCha20-Poly1305 under a fresh
//! content key, with the whole header as AAD, and wraps the content key to each recipient
//! with HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305, with
//! the header's first 40 bytes as AAD. The key commitment makes every recipient open the same
//! plaintext or none. The total length is one of four buckets, 1, 4, 16 or 64 KiB.
//!
//! Every random input of a sealing (the content key, the nonce and each recipient's HPKE
//! ephemeral keying material) comes from the operating system's secure random generator; no
//! production function takes them from its caller (Switch spec 5.1). Only test builds can
//! fix them, to rebuild the shared vectors.

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable as _, OpModeR, OpModeS, Serializable as _};
use zeroize::{Zeroize as _, Zeroizing};

use crate::enc::{SUITE_1, derive, kid, lp, random_bytes, x25519_low_order};
use crate::error::{Error, Result, SizeRefusal, invalid};
use crate::keys::{hpke_public_of, x25519_private, x25519_public_key};
use crate::labels;

/// The magic that starts every envelope: `PSW1` (Switch wire 4.1).
pub const MAGIC: [u8; 4] = *b"PSW1";
/// The envelope version (Switch wire 4.1).
pub const VERSION: u8 = 1;
/// The suite byte of suite 1 (Switch wire 4.1, 4.2).
pub const SUITE: u8 = SUITE_1 as u8;
/// The `notify` flag, bit 0 of the flags byte; every other bit is 0 (Switch wire 4.1).
pub const FLAG_NOTIFY: u8 = 1;
/// The most recipients one envelope carries (Switch wire 4.1).
pub const MAX_RECIPIENTS: usize = 255;
/// The fixed part of the header, magic through key commitment, which is also the HPKE AAD
/// (Switch wire 4.1).
pub const FIXED_HEADER_LEN: usize = 40;
/// One recipient's wrap: `kid (8) || enc (32) || wrapped content key (48)` (Switch wire 4.1).
pub const WRAP_LEN: usize = KID_LEN + ENC_LEN + WRAPPED_KEY_LEN;
/// The XChaCha20-Poly1305 nonce of the body (Switch wire 4.1).
pub const NONCE_LEN: usize = 24;
/// The AEAD tag of the body (Switch wire 4.1).
pub const TAG_LEN: usize = 16;
/// The lengths an envelope may have (Switch wire 4.1).
pub const BUCKETS: [usize; 4] = [1024, 4096, 16384, 65536];
/// The largest envelope, 64 KiB (Switch wire 4.1, 4.4).
pub const MAX_ENVELOPE_LEN: usize = 65536;
/// The most bytes a framed plaintext (`u32_be(len) || JSON`) carries as JSON in a
/// one-recipient envelope: 65,368 less the length, 65,364 (Switch wire 3.12, 4.5).
pub const MAX_FRAMED_JSON_LEN: usize = 65_364;

const KID_LEN: usize = 8;
const ENC_LEN: usize = 32;
const WRAPPED_KEY_LEN: usize = 48;
const CONTENT_KEY_LEN: usize = 32;
const FRAME_PREFIX_LEN: usize = 4;

/// The header's length with `recipients` wraps: `40 + 88n` (Switch wire 4.1).
///
/// `None` for more than [`MAX_RECIPIENTS`].
pub const fn header_len(recipients: usize) -> Option<usize> {
    if recipients > MAX_RECIPIENTS {
        return None;
    }
    // At most 40 + 88 * 255 = 22,480: no overflow.
    Some(FIXED_HEADER_LEN + WRAP_LEN * recipients)
}

/// The smallest bucket that holds a plaintext of `plaintext_len` bytes for `recipients`
/// recipients: `40 + 88n + 24 + len + 16 <= bucket` (Switch wire 4.1).
///
/// `None` when no bucket holds it, or for a recipient count outside 1 to 255.
pub fn bucket_for(recipients: usize, plaintext_len: usize) -> Option<usize> {
    if recipients == 0 {
        return None;
    }
    let needed = header_len(recipients)?
        .checked_add(NONCE_LEN + TAG_LEN)?
        .checked_add(plaintext_len)?;
    BUCKETS.into_iter().find(|bucket| needed <= *bucket)
}

/// The most plaintext an envelope to `recipients` recipients holds: 65,536 less the header,
/// the nonce and the tag; 65,368 for one recipient (Switch wire 4.1).
///
/// `None` for a recipient count outside 1 to 255.
pub const fn max_plaintext_len(recipients: usize) -> Option<usize> {
    if recipients == 0 {
        return None;
    }
    match header_len(recipients) {
        // At most 22,480 + 40, below 65,536: no underflow.
        Some(header) => Some(MAX_ENVELOPE_LEN - header - NONCE_LEN - TAG_LEN),
        None => None,
    }
}

/// The key commitment: `derive("pubky-switch/v1/key-commit", content key)` (Switch wire 1.5,
/// 4.1).
pub fn key_commitment(content_key: &[u8; 32]) -> [u8; 32] {
    derive(labels::derive::KEY_COMMIT, &[content_key])
}

/// The HPKE `info` of a wrap: `lp("pubky-switch/v1/hpke", recipient identity, kid)`, 72 bytes
/// (Switch wire 1.5, 4.2).
///
/// The recipient identity is the message's `to`, or the identity itself for a key bundle, a
/// hand-over or a backup.
pub fn hpke_info(recipient_identity: &[u8; 32], kid: &[u8; 8]) -> Vec<u8> {
    lp(&[labels::derive::HPKE.as_bytes(), recipient_identity, kid])
}

/// One recipient key an envelope is wrapped to: an app's current receive key, or its bundle
/// key for a key bundle or a hand-over, or the identity's backup key (Switch wire 4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recipient {
    kid: [u8; 8],
    public: [u8; 32],
}

impl Recipient {
    /// The recipient with this suite 1 X25519 public key; its kid follows from the key
    /// (Switch wire 1.5).
    pub fn new(public: [u8; 32]) -> Self {
        Self {
            kid: kid(&public),
            public,
        }
    }

    /// The key's kid.
    pub fn kid(&self) -> [u8; 8] {
        self.kid
    }

    /// The X25519 public key.
    pub fn public(&self) -> [u8; 32] {
        self.public
    }
}

/// One recipient's wrap in a header (Switch wire 4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wrap {
    /// The kid of the recipient key.
    pub kid: [u8; 8],
    /// The HPKE `enc`: the 32-byte ephemeral public key.
    pub enc: [u8; 32],
    /// The content key wrapped by HPKE, with its tag.
    pub wrapped_key: [u8; 48],
}

/// An envelope's header, read without decrypting (Switch wire 4.1, 4.3 step 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// The `notify` flag.
    pub notify: bool,
    /// The key commitment.
    pub key_commitment: [u8; 32],
    /// The recipient wraps, in the sender's order; at least one.
    pub wraps: Vec<Wrap>,
    /// The body's nonce, which follows the header.
    pub nonce: [u8; 24],
}

impl Header {
    /// The header's length in bytes: `40 + 88n` (Switch wire 4.1).
    pub fn len(&self) -> usize {
        // A parsed header has 1 to 255 wraps.
        header_len(self.wraps.len()).unwrap_or(usize::MAX)
    }

    /// Whether the header has no wraps; a parsed header never is.
    pub fn is_empty(&self) -> bool {
        self.wraps.is_empty()
    }

    /// The kids of the recipient keys, in order.
    pub fn kids(&self) -> impl Iterator<Item = [u8; 8]> + '_ {
        self.wraps.iter().map(|wrap| wrap.kid)
    }
}

/// Take the next `N` bytes of `rest`.
fn take<const N: usize>(rest: &mut &[u8]) -> Option<[u8; N]> {
    let (head, tail) = rest.split_first_chunk::<N>()?;
    *rest = tail;
    Some(*head)
}

/// Read an envelope's header: opening step 1 (Switch wire 4.3).
///
/// Checks the magic, version 1, suite 1, no unknown flag bits, at least one recipient, and
/// that the length covers the header, the nonce and a tag. It doesn't check that the length
/// is a bucket, which the inbox does ([`check_at_inbox`]).
///
/// # Errors
///
/// [`Error::Invalid`] naming the check that failed.
pub fn parse_header(envelope: &[u8]) -> Result<Header> {
    let short = || invalid("Switch wire 4.3 step 1: shorter than its header, nonce and tag");
    let mut rest = envelope;
    let Some(magic) = take::<4>(&mut rest) else {
        return short();
    };
    let Some([version, suite, flags, count]) = take::<4>(&mut rest) else {
        return short();
    };
    if magic != MAGIC {
        return invalid("Switch wire 4.3 step 1: not a PSW1 envelope");
    }
    if version != VERSION {
        return invalid("Switch wire 4.3 step 1: an envelope version other than 1");
    }
    if suite != SUITE {
        return invalid("Switch wire 4.3 step 1: a suite other than 1");
    }
    if flags & !FLAG_NOTIFY != 0 {
        return invalid("Switch wire 4.3 step 1: unknown flag bits");
    }
    if count == 0 {
        return invalid("Switch wire 4.3 step 1: an envelope without recipients");
    }
    let Some(key_commitment) = take::<32>(&mut rest) else {
        return short();
    };
    let mut wraps = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let (Some(kid), Some(enc), Some(wrapped_key)) = (
            take::<KID_LEN>(&mut rest),
            take::<ENC_LEN>(&mut rest),
            take::<WRAPPED_KEY_LEN>(&mut rest),
        ) else {
            return short();
        };
        wraps.push(Wrap {
            kid,
            enc,
            wrapped_key,
        });
    }
    let Some(nonce) = take::<NONCE_LEN>(&mut rest) else {
        return short();
    };
    if rest.len() < TAG_LEN {
        return short();
    }
    Ok(Header {
        notify: flags & FLAG_NOTIFY != 0,
        key_commitment,
        wraps,
        nonce,
    })
}

/// The inbox's checks of an envelope (Switch wire 4.3, 4.4): its size, opening step 1, a
/// bucket length, and no key wrapped to twice.
///
/// The inbox reads only the header. That every kid is the current receive key of a current
/// app is the service's check (Switch wire 7.4.3), on the kids this returns; with one current
/// receive key per app, a kid twice is the one app wrapped to twice.
///
/// # Errors
///
/// [`SizeRefusal::TooLarge`] over 64 KiB, and [`SizeRefusal::BadRequest`] for a header that
/// doesn't parse, a length that isn't a bucket, or a kid twice.
pub fn check_at_inbox(envelope: &[u8]) -> std::result::Result<Header, SizeRefusal> {
    if envelope.len() > MAX_ENVELOPE_LEN {
        return Err(SizeRefusal::TooLarge(
            "Switch wire 4.4: an envelope over 64 KiB".into(),
        ));
    }
    let header = parse_header(envelope).map_err(|error| match error {
        Error::Invalid(why) | Error::Signature(why) | Error::Crypto(why) => {
            SizeRefusal::BadRequest(why)
        }
    })?;
    if !BUCKETS.contains(&envelope.len()) {
        return Err(SizeRefusal::BadRequest(
            "Switch wire 4.4: an envelope length that isn't a bucket".into(),
        ));
    }
    if has_duplicate_kid(header.kids()) {
        return Err(SizeRefusal::BadRequest(
            "Switch wire 4.4: one app wrapped to twice".into(),
        ));
    }
    Ok(header)
}

fn has_duplicate_kid(kids: impl Iterator<Item = [u8; 8]>) -> bool {
    let mut seen = std::collections::HashSet::new();
    kids.into_iter().any(|kid| !seen.insert(kid))
}

/// Seal `plaintext` to `recipients`, keys of apps of `recipient_identity` (Switch wire 4.3).
///
/// The plaintext is padded with zeros to the smallest bucket that holds it (Switch wire
/// 4.1). The content key, the nonce and each recipient's HPKE ephemeral keying material come
/// from the operating system's secure random generator.
///
/// # Errors
///
/// [`Error::Invalid`] for no recipient, more than 255, a key twice, or a plaintext no bucket
/// holds; [`Error::Crypto`] for a recipient key of low order, which a sender skips (Switch
/// wire 4.2), or a failing random generator.
pub fn seal(
    recipient_identity: &[u8; 32],
    recipients: &[Recipient],
    plaintext: &[u8],
    notify: bool,
) -> Result<Vec<u8>> {
    let content_key = Zeroizing::new(random_bytes::<CONTENT_KEY_LEN>()?);
    let nonce = random_bytes::<NONCE_LEN>()?;
    let ikm_e = Zeroizing::new(
        recipients
            .iter()
            .map(|_| random_bytes::<32>())
            .collect::<Result<Vec<_>>>()?,
    );
    seal_parts(
        recipient_identity,
        recipients,
        plaintext,
        notify,
        &content_key,
        &nonce,
        &ikm_e,
    )
}

/// [`seal`] with fixed randomness, to rebuild the shared vectors: the content key, the nonce,
/// and per recipient, in order, the 32 bytes of HPKE ephemeral keying material `ikmE` (RFC
/// 9180 `DeriveKeyPair`). Test builds only: production sealing takes no randomness from its
/// caller (Switch wire 4.2).
///
/// # Errors
///
/// As [`seal`], and [`Error::Invalid`] unless there is one `ikmE` per recipient.
#[cfg(any(test, feature = "test-vectors"))]
pub fn seal_with(
    recipient_identity: &[u8; 32],
    recipients: &[Recipient],
    plaintext: &[u8],
    notify: bool,
    content_key: &[u8; 32],
    nonce: &[u8; 24],
    ikm_e: &[[u8; 32]],
) -> Result<Vec<u8>> {
    seal_parts(
        recipient_identity,
        recipients,
        plaintext,
        notify,
        content_key,
        nonce,
        ikm_e,
    )
}

/// The HPKE ephemeral key pair `DeriveKeyPair(ikmE)` derives: the secret `skE` and the public
/// key, which is the wrap's `enc` (RFC 9180; Switch wire 4.2). Test builds only, to check the
/// vectors' intermediate values.
#[cfg(any(test, feature = "test-vectors"))]
pub fn ephemeral_key(ikm_e: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let (secret, _) = <X25519HkdfSha256 as hpke::Kem>::derive_keypair(ikm_e);
    (secret.to_bytes().into(), hpke_public_of(&secret))
}

/// The sealing steps of Switch wire 4.3 with the random inputs given.
fn seal_parts(
    recipient_identity: &[u8; 32],
    recipients: &[Recipient],
    plaintext: &[u8],
    notify: bool,
    content_key: &[u8; 32],
    nonce: &[u8; 24],
    ikm_e: &[[u8; 32]],
) -> Result<Vec<u8>> {
    let Some(count) = u8::try_from(recipients.len()).ok().filter(|n| *n > 0) else {
        return invalid("Switch wire 4.1: an envelope has 1 to 255 recipients");
    };
    if ikm_e.len() != recipients.len() {
        return invalid("Switch wire 4.2: one HPKE ephemeral keying material per recipient");
    }
    if has_duplicate_kid(recipients.iter().map(Recipient::kid)) {
        return invalid("Switch wire 4.4: one app wrapped to twice");
    }
    let Some(bucket) = bucket_for(recipients.len(), plaintext.len()) else {
        return invalid("Switch wire 4.1: a plaintext no envelope bucket holds");
    };
    // Step 1: the header's first 40 bytes, with the key commitment.
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&[VERSION, SUITE, if notify { FLAG_NOTIFY } else { 0 }, count]);
    out.extend_from_slice(&key_commitment(content_key));
    let hpke_aad = out.clone();
    // Step 2: one wrap per recipient, in order.
    for (recipient, ikm) in recipients.iter().zip(ikm_e) {
        let (enc, wrapped_key) =
            wrap_content_key(recipient_identity, recipient, content_key, &hpke_aad, ikm)?;
        out.extend_from_slice(&recipient.kid);
        out.extend_from_slice(&enc);
        out.extend_from_slice(&wrapped_key);
    }
    // Step 3: the plaintext padded with zeros to the bucket's plaintext length, sealed under
    // the content key with the whole header as AAD.
    let padded_len = bucket
        .checked_sub(out.len())
        .and_then(|rest| rest.checked_sub(NONCE_LEN + TAG_LEN))
        .ok_or_else(|| Error::Crypto("Switch wire 4.1: the bucket doesn't fit".into()))?;
    let mut padded = Zeroizing::new(plaintext.to_vec());
    padded.resize(padded_len, 0);
    let ciphertext = XChaCha20Poly1305::new(content_key.into())
        .encrypt(
            chacha20poly1305::XNonce::from_slice(nonce),
            Payload {
                msg: &padded,
                aad: &out,
            },
        )
        .map_err(|_| Error::Crypto("Switch wire 4.3: the body doesn't seal".into()))?;
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    if out.len() != bucket {
        return Err(Error::Crypto(
            "Switch wire 4.1: the envelope isn't its bucket's length".into(),
        ));
    }
    Ok(out)
}

/// One HPKE key wrap (Switch wire 4.2): the `enc` and the wrapped content key.
fn wrap_content_key(
    recipient_identity: &[u8; 32],
    recipient: &Recipient,
    content_key: &[u8; 32],
    hpke_aad: &[u8],
    ikm_e: &[u8; 32],
) -> Result<([u8; ENC_LEN], [u8; WRAPPED_KEY_LEN])> {
    // A low-order key gives the all-zero shared value, which RFC 9180 aborts on: a sender
    // skips such an app (Switch wire 3.4, 4.2).
    if x25519_low_order(&recipient.public) {
        return Err(Error::Crypto(
            "Switch wire 4.2: a recipient key of low order".into(),
        ));
    }
    let public = x25519_public_key(&recipient.public)?;
    let mut rng = IkmSource::new(ikm_e);
    let (enc, wrapped) =
        hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            &public,
            &hpke_info(recipient_identity, &recipient.kid),
            content_key,
            hpke_aad,
            &mut rng,
        )
        .map_err(|_| Error::Crypto("Switch wire 4.2: the key wrap doesn't seal".into()))?;
    if !rng.drawn_exactly_once() {
        return Err(Error::Crypto(
            "Switch wire 4.2: HPKE drew other than one ephemeral key".into(),
        ));
    }
    let wrapped_key: [u8; WRAPPED_KEY_LEN] = wrapped.as_slice().try_into().map_err(|_| {
        Error::Crypto("Switch wire 4.2: a wrapped content key of the wrong length".into())
    })?;
    Ok((enc.to_bytes().into(), wrapped_key))
}

/// Hands HPKE one ephemeral keying material `ikmE`: DHKEM(X25519) draws exactly 32 bytes per
/// encapsulation (RFC 9180 `GenerateKeyPair`). A further draw is never served from the same
/// bytes: it gets zeros and makes the wrap fail.
struct IkmSource {
    ikm: Zeroizing<[u8; 32]>,
    used: usize,
    overdrawn: bool,
}

impl IkmSource {
    fn new(ikm: &[u8; 32]) -> Self {
        Self {
            ikm: Zeroizing::new(*ikm),
            used: 0,
            overdrawn: false,
        }
    }

    fn drawn_exactly_once(&self) -> bool {
        !self.overdrawn && self.used == self.ikm.len()
    }
}

impl hpke::rand_core::TryRng for IkmSource {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
        let source = self
            .used
            .checked_add(dst.len())
            .and_then(|end| self.ikm.get(self.used..end));
        match source {
            Some(bytes) if !self.overdrawn => {
                dst.copy_from_slice(bytes);
                self.used = self.used.saturating_add(dst.len());
            }
            _ => {
                dst.zeroize();
                self.overdrawn = true;
            }
        }
        Ok(())
    }
}

impl hpke::rand_core::TryCryptoRng for IkmSource {}

/// Open an envelope with the recipient secret of one of its keys: opening steps 1 to 5
/// (Switch wire 4.3). Returns the padded plaintext, which [`unframe`] or the message
/// plaintext reader parse (step 6).
///
/// `recipient_identity` is the opener's own identity. The secret is a receive key's, a bundle
/// key's or the backup key's; its kid follows from its public key. A recipient doesn't check
/// that the length is a bucket: the inbox refused anything else, and the key commitment and
/// the tag bind every byte.
///
/// # Errors
///
/// [`Error::Invalid`] for a header that fails step 1; [`Error::Crypto`] naming the step for
/// an envelope not wrapped to this key (2), an `enc` of low order (Switch wire 4.2), a wrap
/// that doesn't open (3), a content key that doesn't match the key commitment (4), or a body
/// that doesn't decrypt (5).
pub fn open(
    envelope: &[u8],
    recipient_identity: &[u8; 32],
    secret: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>> {
    let header = parse_header(envelope)?;
    let content_key = unwrap_content_key(envelope, &header, recipient_identity, secret)?;
    // Step 5: the body, with the whole header as AAD.
    let (header_bytes, body) = envelope
        .split_at_checked(header.len())
        .ok_or_else(|| Error::Invalid("Switch wire 4.3 step 1: a short envelope".into()))?;
    let ciphertext = body
        .get(NONCE_LEN..)
        .ok_or_else(|| Error::Invalid("Switch wire 4.3 step 1: a short envelope".into()))?;
    XChaCha20Poly1305::new((&*content_key).into())
        .decrypt(
            chacha20poly1305::XNonce::from_slice(&header.nonce),
            Payload {
                msg: ciphertext,
                aad: header_bytes,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Crypto("Switch wire 4.3 step 5: the body doesn't decrypt".into()))
}

/// The content key of an envelope as the holder of `secret` unwraps it, checked against the
/// key commitment: opening steps 1 to 4 (Switch wire 4.3). Test builds only, to check the
/// vectors' content keys.
///
/// # Errors
///
/// As [`open`], steps 1 to 4.
#[cfg(any(test, feature = "test-vectors"))]
pub fn content_key_of(
    envelope: &[u8],
    recipient_identity: &[u8; 32],
    secret: &[u8; 32],
) -> Result<[u8; 32]> {
    let header = parse_header(envelope)?;
    Ok(*unwrap_content_key(
        envelope,
        &header,
        recipient_identity,
        secret,
    )?)
}

/// Opening steps 2 to 4 (Switch wire 4.3).
fn unwrap_content_key(
    envelope: &[u8],
    header: &Header,
    recipient_identity: &[u8; 32],
    secret: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let private = x25519_private(secret)?;
    let own_kid = kid(&hpke_public_of(&private));
    // Step 2: the wrap for this key.
    let wrap = header
        .wraps
        .iter()
        .find(|wrap| wrap.kid == own_kid)
        .ok_or_else(|| {
            Error::Crypto("Switch wire 4.3 step 2: the envelope isn't wrapped to this key".into())
        })?;
    // A recipient refuses an `enc` of low order (Switch wire 4.2).
    if x25519_low_order(&wrap.enc) {
        return Err(Error::Crypto(
            "Switch wire 4.2: the enc for this key is of low order".into(),
        ));
    }
    // Step 3: the HPKE wrap, with the info for the own identity and the kid, and the first
    // 40 header bytes as AAD.
    let enc = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&wrap.enc)
        .map_err(|_| Error::Crypto("Switch wire 4.3 step 3: the enc isn't a key".into()))?;
    let hpke_aad = envelope
        .get(..FIXED_HEADER_LEN)
        .ok_or_else(|| Error::Invalid("Switch wire 4.3 step 1: a short envelope".into()))?;
    let unwrapped = Zeroizing::new(
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &private,
            &enc,
            &hpke_info(recipient_identity, &own_kid),
            &wrap.wrapped_key,
            hpke_aad,
        )
        .map_err(|_| Error::Crypto("Switch wire 4.3 step 3: the key wrap doesn't open".into()))?,
    );
    let content_key = Zeroizing::new(
        <[u8; CONTENT_KEY_LEN]>::try_from(unwrapped.as_slice()).map_err(|_| {
            Error::Crypto("Switch wire 4.3 step 3: the content key isn't 32 bytes".into())
        })?,
    );
    // Step 4: the key commitment, so every recipient opens the same plaintext or none.
    if key_commitment(&content_key) != header.key_commitment {
        return Err(Error::Crypto(
            "Switch wire 4.3 step 4: the content key doesn't match the key commitment".into(),
        ));
    }
    Ok(content_key)
}

/// Frame a JSON document for an envelope: `u32_be(len(JSON)) || JSON`, which sealing pads with
/// zeros (Switch wire 4.5). Key bundles, hand-over parts and backups use it.
///
/// # Errors
///
/// [`Error::Invalid`] for a document whose length doesn't fit 32 bits.
pub fn frame(json: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(json.len())
        .map_err(|_| Error::Invalid("Switch wire 4.5: a document over 4 GiB".into()))?;
    let mut out = Vec::with_capacity(json.len().saturating_add(FRAME_PREFIX_LEN));
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(json);
    Ok(out)
}

/// Read a framed plaintext (Switch wire 4.5): the JSON bytes, after checking that the length
/// doesn't run past the plaintext and that every padding byte is zero.
///
/// # Errors
///
/// [`Error::Invalid`] for a plaintext shorter than its length prefix, a length that runs
/// past it, or a non-zero padding byte.
pub fn unframe(plaintext: &[u8]) -> Result<&[u8]> {
    let (len, rest) = plaintext
        .split_first_chunk::<FRAME_PREFIX_LEN>()
        .ok_or_else(|| {
            Error::Invalid("Switch wire 4.5: a plaintext shorter than its length".into())
        })?;
    let len = usize::try_from(u32::from_be_bytes(*len)).unwrap_or(usize::MAX);
    let (json, padding) = rest.split_at_checked(len).ok_or_else(|| {
        Error::Invalid("Switch wire 4.5: a length that runs past the plaintext".into())
    })?;
    check_padding(padding)?;
    Ok(json)
}

/// Check that padding is all zeros (Switch wire 4.3 step 6, 4.5).
pub(crate) fn check_padding(padding: &[u8]) -> Result<()> {
    if padding.iter().any(|byte| *byte != 0) {
        return invalid("Switch wire 4.5: a non-zero padding byte");
    }
    Ok(())
}

/// Seal a framed JSON document to one key, `notify` 0: a key bundle to an app's bundle key
/// (Switch wire 3.5), a hand-over part to the new signer's bundle key (3.12), a backup part
/// to the identity's backup key (3.13). The recipient identity is the identity itself.
///
/// # Errors
///
/// As [`seal`]; a document of more than [`MAX_FRAMED_JSON_LEN`] bytes fits no envelope.
pub fn seal_framed(identity: &[u8; 32], recipient: &Recipient, json: &[u8]) -> Result<Vec<u8>> {
    seal(
        identity,
        std::slice::from_ref(recipient),
        &frame(json)?,
        false,
    )
}

/// [`seal_framed`] with fixed randomness, as [`seal_with`]. Test builds only.
///
/// # Errors
///
/// As [`seal_framed`].
#[cfg(any(test, feature = "test-vectors"))]
pub fn seal_framed_with(
    identity: &[u8; 32],
    recipient: &Recipient,
    json: &[u8],
    content_key: &[u8; 32],
    nonce: &[u8; 24],
    ikm_e: &[u8; 32],
) -> Result<Vec<u8>> {
    seal_with(
        identity,
        std::slice::from_ref(recipient),
        &frame(json)?,
        false,
        content_key,
        nonce,
        std::slice::from_ref(ikm_e),
    )
}

/// The random inputs of one sealing to one key, fixed to rebuild the shared vectors: the
/// content key, the nonce and the recipient's HPKE ephemeral keying material `ikmE`. Test
/// builds only: production sealing takes no randomness from its caller (Switch wire 4.2).
#[cfg(any(test, feature = "test-vectors"))]
#[derive(Clone, Copy)]
pub struct FixedRandomness {
    /// The content key.
    pub content_key: [u8; 32],
    /// The body's nonce.
    pub nonce: [u8; 24],
    /// The recipient's `ikmE`.
    pub ikm_e: [u8; 32],
}

#[cfg(any(test, feature = "test-vectors"))]
impl std::fmt::Debug for FixedRandomness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FixedRandomness(..)")
    }
}

#[cfg(any(test, feature = "test-vectors"))]
impl FixedRandomness {
    /// [`seal_framed_with`] with these inputs. Test builds only.
    ///
    /// # Errors
    ///
    /// As [`seal_framed`].
    pub fn seal_framed(
        &self,
        identity: &[u8; 32],
        recipient: &Recipient,
        json: &[u8],
    ) -> Result<Vec<u8>> {
        seal_framed_with(
            identity,
            recipient,
            json,
            &self.content_key,
            &self.nonce,
            &self.ikm_e,
        )
    }
}

/// Open an envelope holding a framed JSON document (Switch wire 4.3, 4.5), as a key bundle,
/// a hand-over part or a backup part: the JSON bytes. They may hold keys, so they are
/// zeroized when dropped.
///
/// # Errors
///
/// As [`open`] and [`unframe`].
pub fn open_framed(
    envelope: &[u8],
    identity: &[u8; 32],
    secret: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>> {
    let plaintext = open(envelope, identity, secret)?;
    Ok(Zeroizing::new(unframe(&plaintext)?.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ReceiveKey;

    const IDENTITY: [u8; 32] = [0x11; 32];

    fn key(seed: u8) -> ReceiveKey {
        ReceiveKey::from_secret(0, [seed; 32])
    }

    fn fixed_seal(recipients: &[&ReceiveKey], plaintext: &[u8], notify: bool) -> Vec<u8> {
        let list: Vec<Recipient> = recipients
            .iter()
            .map(|k| Recipient::new(k.public))
            .collect();
        let ikm: Vec<[u8; 32]> = (0..list.len()).map(|i| [i as u8 + 1; 32]).collect();
        seal_with(
            &IDENTITY, &list, plaintext, notify, &[7; 32], &[8; 24], &ikm,
        )
        .unwrap()
    }

    #[test]
    fn test_envelope_seal_opens_for_every_recipient() {
        let (a, b) = (key(1), key(2));
        let envelope = seal(
            &IDENTITY,
            &[Recipient::new(a.public), Recipient::new(b.public)],
            b"hello",
            true,
        )
        .unwrap();
        assert_eq!(envelope.len(), 1024);
        let header = check_at_inbox(&envelope).unwrap();
        assert!(header.notify);
        assert_eq!(header.kids().collect::<Vec<_>>(), vec![a.kid, b.kid]);
        let opened_a = open(&envelope, &IDENTITY, &a.secret()).unwrap();
        let opened_b = open(&envelope, &IDENTITY, &b.secret()).unwrap();
        assert_eq!(opened_a, opened_b);
        assert_eq!(opened_a.len(), 1024 - 40 - 2 * 88 - 24 - 16);
        assert!(opened_a.starts_with(b"hello"));
        check_padding(&opened_a[5..]).unwrap();
    }

    #[test]
    fn test_envelope_seal_draws_fresh_randomness() {
        let a = key(1);
        let recipients = [Recipient::new(a.public)];
        let one = seal(&IDENTITY, &recipients, b"same", false).unwrap();
        let two = seal(&IDENTITY, &recipients, b"same", false).unwrap();
        assert_eq!(one[..8], two[..8]);
        assert_ne!(one[8..40], two[8..40], "a fresh content key");
        assert_ne!(one[48..80], two[48..80], "a fresh ephemeral key");
        assert_ne!(one[128..152], two[128..152], "a fresh nonce");
    }

    #[test]
    fn test_envelope_seal_with_is_deterministic() {
        let a = key(1);
        assert_eq!(
            fixed_seal(&[&a], b"x", false),
            fixed_seal(&[&a], b"x", false)
        );
        assert_ne!(
            fixed_seal(&[&a], b"x", false),
            fixed_seal(&[&a], b"x", true)
        );
    }

    #[test]
    fn test_envelope_seal_refuses_bad_recipient_lists() {
        let a = key(1);
        let one = [Recipient::new(a.public)];
        assert!(seal(&IDENTITY, &[], b"x", false).is_err());
        let twice = [one[0], one[0]];
        assert!(seal(&IDENTITY, &twice, b"x", false).is_err());
        let many: Vec<Recipient> = (0..256u16)
            .map(|i| Recipient::new(ReceiveKey::from_secret(0, [i as u8; 32]).public))
            .collect();
        assert!(seal(&IDENTITY, &many, b"x", false).is_err());
        assert!(seal_with(&IDENTITY, &one, b"x", false, &[1; 32], &[2; 24], &[]).is_err());
    }

    #[test]
    fn test_envelope_seal_refuses_low_order_keys() {
        let mut low = [0xff_u8; 32];
        low[0] = 0xec;
        low[31] = 0x7f;
        let refused = seal(&IDENTITY, &[Recipient::new(low)], b"x", false).unwrap_err();
        assert!(refused.to_string().contains("low order"), "{refused}");
        assert!(seal(&IDENTITY, &[Recipient::new([0; 32])], b"x", false).is_err());
    }

    #[test]
    fn test_envelope_buckets_and_the_largest_plaintext() {
        assert_eq!(bucket_for(1, 0), Some(1024));
        assert_eq!(bucket_for(1, 1024 - 40 - 88 - 40), Some(1024));
        assert_eq!(bucket_for(1, 1024 - 40 - 88 - 40 + 1), Some(4096));
        assert_eq!(max_plaintext_len(1), Some(65_368));
        assert_eq!(bucket_for(1, 65_368), Some(65_536));
        assert_eq!(bucket_for(1, 65_369), None);
        assert_eq!(bucket_for(0, 1), None);
        assert_eq!(bucket_for(256, 1), None);
        assert_eq!(max_plaintext_len(0), None);
        assert_eq!(header_len(255), Some(22_480));
        let a = key(1);
        let big = seal(&IDENTITY, &[Recipient::new(a.public)], &[7; 5000], false).unwrap();
        assert_eq!(big.len(), 16_384);
        assert!(seal(&IDENTITY, &[Recipient::new(a.public)], &[0; 65_369], false).is_err());
        assert_eq!(MAX_FRAMED_JSON_LEN, max_plaintext_len(1).unwrap() - 4);
    }

    #[test]
    fn test_envelope_header_refuses_each_malformation() {
        let a = key(1);
        let envelope = fixed_seal(&[&a], b"x", false);
        assert!(parse_header(&envelope).is_ok());
        let mutate = |index: usize, value: u8| {
            let mut bytes = envelope.clone();
            bytes[index] = value;
            parse_header(&bytes).unwrap_err().to_string()
        };
        assert!(mutate(0, b'X').contains("PSW1"));
        assert!(mutate(4, 2).contains("version"));
        assert!(mutate(5, 2).contains("suite"));
        assert!(mutate(6, 2).contains("flag"));
        assert!(mutate(7, 0).contains("without recipients"));
        // A count past the bytes, and lengths short of the nonce and a tag.
        assert!(mutate(7, 255).contains("shorter"));
        assert!(parse_header(&envelope[..40 + 88 + 24 + 15]).is_err());
        assert!(parse_header(&envelope[..40 + 88 + 24 + 16]).is_ok());
        assert!(parse_header(&envelope[..7]).is_err());
    }

    #[test]
    fn test_envelope_inbox_check_applies_the_size_rules() {
        let (a, b) = (key(1), key(2));
        let envelope = fixed_seal(&[&a, &b], b"x", false);
        assert!(check_at_inbox(&envelope).is_ok());
        let mut over = envelope.clone();
        over.resize(65_537, 0);
        let too_large = check_at_inbox(&over).unwrap_err();
        assert_eq!((too_large.status(), too_large.code()), (413, "too_large"));
        let not_bucket = check_at_inbox(&envelope[..1000]).unwrap_err();
        assert_eq!(
            (not_bucket.status(), not_bucket.code()),
            (400, "bad_request")
        );
        let mut bad_magic = envelope.clone();
        bad_magic[0] = 0;
        assert_eq!(check_at_inbox(&bad_magic).unwrap_err().status(), 400);
        // The second wrap names the first one's kid.
        let mut twice = envelope.clone();
        twice.copy_within(40..48, 128);
        assert!(
            check_at_inbox(&twice)
                .unwrap_err()
                .to_string()
                .contains("twice")
        );
    }

    #[test]
    fn test_envelope_open_refuses_tampering_at_its_step() {
        let (a, b, c) = (key(1), key(2), key(3));
        let envelope = fixed_seal(&[&a, &b], b"x", false);
        let step = |bytes: &[u8], identity: &[u8; 32], secret: &[u8; 32]| {
            open(bytes, identity, secret).unwrap_err().to_string()
        };
        assert!(step(&envelope, &IDENTITY, &c.secret()).contains("step 2"));
        assert!(step(&envelope, &[0x22; 32], &a.secret()).contains("step 3"));
        let mut flipped = envelope.clone();
        flipped[6] ^= FLAG_NOTIFY;
        assert!(step(&flipped, &IDENTITY, &a.secret()).contains("step 3"));
        // The second wrap is in the body's AAD only: the first recipient's wrap opens, and
        // the body doesn't.
        let mut second_wrap = envelope.clone();
        second_wrap[40 + 88 + 50] ^= 1;
        assert!(step(&second_wrap, &IDENTITY, &a.secret()).contains("step 5"));
        let mut body = envelope.clone();
        let last = body.len() - 1;
        body[last] ^= 1;
        assert!(step(&body, &IDENTITY, &a.secret()).contains("step 5"));
        // A low-order enc is refused before HPKE runs.
        let mut low_enc = envelope.clone();
        low_enc[48..80].copy_from_slice(&[0; 32]);
        assert!(step(&low_enc, &IDENTITY, &a.secret()).contains("low order"));
    }

    #[test]
    fn test_envelope_open_refuses_another_content_key() {
        let (a, b) = (key(1), key(2));
        let honest = fixed_seal(&[&a, &b], b"x", false);
        // The same header with the second wrap carrying another content key: its holder
        // unwraps a key that doesn't match the commitment.
        let other = Recipient::new(b.public);
        let (enc, wrapped) =
            wrap_content_key(&IDENTITY, &other, &[9; 32], &honest[..40], &[5; 32]).unwrap();
        let mut forged = honest.clone();
        forged[128 + 8..128 + 40].copy_from_slice(&enc);
        forged[128 + 40..128 + 88].copy_from_slice(&wrapped);
        let refused = content_key_of(&forged, &IDENTITY, &b.secret()).unwrap_err();
        assert!(refused.to_string().contains("step 4"), "{refused}");
        assert_eq!(
            content_key_of(&forged, &IDENTITY, &a.secret()).unwrap(),
            [7; 32]
        );
    }

    #[test]
    fn test_envelope_ikm_source_serves_one_draw() {
        use hpke::rand_core::TryRng as _;
        let mut source = IkmSource::new(&[3; 32]);
        let mut first = [0u8; 32];
        source.try_fill_bytes(&mut first).unwrap();
        assert_eq!(first, [3; 32]);
        assert!(source.drawn_exactly_once());
        let mut again = [1u8; 4];
        source.try_fill_bytes(&mut again).unwrap();
        assert_eq!(again, [0; 4]);
        assert!(!source.drawn_exactly_once());
        let mut short = IkmSource::new(&[3; 32]);
        short.try_fill_bytes(&mut [0u8; 16]).unwrap();
        assert!(!short.drawn_exactly_once());
    }

    #[test]
    fn test_envelope_ephemeral_key_is_the_enc() {
        let a = key(1);
        let envelope = fixed_seal(&[&a], b"x", false);
        let (_, enc) = ephemeral_key(&[1; 32]);
        assert_eq!(parse_header(&envelope).unwrap().wraps[0].enc, enc);
    }

    #[test]
    fn test_envelope_hpke_info_and_commitment() {
        let info = hpke_info(&IDENTITY, &[4; 8]);
        assert_eq!(info.len(), 72);
        assert!(info[4..].starts_with(b"pubky-switch/v1/hpke"));
        assert_ne!(key_commitment(&[1; 32]), key_commitment(&[2; 32]));
    }

    #[test]
    fn test_framed_round_trips_and_refuses_bad_padding() {
        let mut framed = frame(b"{}").unwrap();
        assert_eq!(framed, [0, 0, 0, 2, b'{', b'}']);
        framed.extend_from_slice(&[0, 0]);
        assert_eq!(unframe(&framed).unwrap(), b"{}");
        framed.push(1);
        assert!(unframe(&framed).is_err());
        assert!(unframe(&[0, 0, 0, 9, b'{']).is_err());
        assert!(unframe(&[0, 0]).is_err());
        assert_eq!(unframe(&[0, 0, 0, 0]).unwrap(), b"");
    }

    #[test]
    fn test_framed_seal_opens_to_its_document() {
        let bundle_key = key(4);
        let recipient = Recipient::new(bundle_key.public);
        let envelope = seal_framed(&IDENTITY, &recipient, br#"{"v":1}"#).unwrap();
        assert!(!parse_header(&envelope).unwrap().notify);
        let json = open_framed(&envelope, &IDENTITY, &bundle_key.secret()).unwrap();
        assert_eq!(json.as_slice(), br#"{"v":1}"#);
        let fixed =
            seal_framed_with(&IDENTITY, &recipient, b"{}", &[1; 32], &[2; 24], &[3; 32]).unwrap();
        assert_eq!(
            open_framed(&fixed, &IDENTITY, &bundle_key.secret())
                .unwrap()
                .as_slice(),
            b"{}"
        );
        let too_big = vec![b' '; MAX_FRAMED_JSON_LEN + 1];
        assert!(seal_framed(&IDENTITY, &recipient, &too_big).is_err());
        assert!(seal_framed(&IDENTITY, &recipient, &too_big[1..]).is_ok());
    }
}
