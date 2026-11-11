//! Key bundles (Switch wire 3.5, Switch spec 3.5): an app's scope keys and the identity's
//! naming key, sealed to the app's certified bundle key and signed by the identity key.
//!
//! A bundle covers a contiguous range of data epochs `[first_epoch, last_epoch]`. One whose
//! envelope wouldn't fit 64 KiB is stored as several parts, each signed and sealed on its
//! own, so an app opens each without the others. Every part names, in `cert`, the document
//! hash of the certificate it was made for, and holds exactly one key for each scope with
//! keys of that certificate and each data epoch of its range.
//!
//! Which scopes have keys is the protocol's choice (Switch spec 3.5): every function here
//! that needs it takes it as `has_keys`, a predicate on a scope name. The Switch gives no
//! scope a meaning of its own.
//!
//! The signer builds parts with [`seal_bundle_parts`]; an app reads them with
//! [`PartReader`], which applies every skip rule of Switch wire 3.5 "Reading". The pure rules
//! of incremental bundles and full bundles on request are [`incremental_first_epoch`],
//! [`missing_ranges`] and [`covers_from_one`]; a full bundle on request covers every epoch
//! from 1 to the current one (Switch wire 3.5 "Full bundles on request").

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

use super::{AppCert, IdentityDoc, fmt, is_renewal};
use crate::enc::{serde_b64, serde_b64_vec, unb64_array};
use crate::envelope::{self, MAX_FRAMED_JSON_LEN, Recipient};
use crate::error::{Error, Result, invalid};
use crate::ident::NamingKey;
use crate::json::parse_json;
use crate::keys::{IdentityKey, ScopeKey, ScopeKeys};
use crate::labels;
use crate::sig;

/// The `kind` of a key bundle plaintext (Switch wire 3.5).
pub const KEY_BUNDLE_KIND: &str = "pubky-switch.key_bundle";

/// A lower bound on the bytes one scope key takes in a bundle's JSON: the shortest entry,
/// `{"data_epoch":1,"scope":"x","key":"<43 characters>"}`, takes 81. A range with more keys
/// than the largest framed JSON holds at this size can't fit one envelope, so the signer
/// halves it without building it.
const MIN_KEY_JSON_LEN: usize = 64;

/// A key bundle as it travels: an envelope to the target app's bundle key and the identity
/// key's signature over `lp("pubky-switch/v1/key-bundle", identity, target App ID, envelope
/// bytes)` (Switch wire 3.5). Readers ignore unknown members (Switch wire 1.1).
///
/// Its `Debug` output names the envelope's length only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBundle {
    #[serde(with = "serde_b64_vec")]
    envelope: Vec<u8>,
    #[serde(with = "serde_b64")]
    sig: [u8; 64],
}

impl std::fmt::Debug for KeyBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyBundle({} bytes)", self.envelope.len())
    }
}

impl KeyBundle {
    /// A key bundle from its envelope and signature, as a reader receives them.
    pub fn from_parts(envelope: Vec<u8>, sig: [u8; 64]) -> Self {
        Self { envelope, sig }
    }

    /// The envelope bytes.
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// The identity key's signature.
    pub fn sig(&self) -> [u8; 64] {
        self.sig
    }

    /// Seal `contents` to the certified bundle key of `cert`'s app and sign it with the
    /// identity key, for that app (Switch wire 3.5). The envelope's recipient identity is the
    /// identity itself and `notify` is 0.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `cert` isn't a certificate of this identity, `contents` names
    /// another certificate, or its JSON fits no envelope; [`Error::Crypto`] as
    /// [`envelope::seal`].
    pub fn seal(key: &IdentityKey, cert: &AppCert, contents: &KeyBundleContents) -> Result<Self> {
        let identity = key.public();
        if cert.identity() != identity {
            return invalid("Switch wire 3.5: the certificate is of another identity");
        }
        if contents.cert != cert.hash() {
            return invalid("Switch wire 3.5: the bundle names another certificate");
        }
        let json = contents.to_json()?;
        let envelope = envelope::seal_framed(&identity, &Recipient::new(cert.bundle_key()), &json)?;
        Ok(Self::signed(key, &cert.app_id(), envelope))
    }

    /// Seal the exact plaintext JSON `json` to `bundle_key` for the app `target`, with fixed
    /// randomness, and sign it, to rebuild the shared vectors, the parts a reader must skip
    /// included. Test builds only.
    ///
    /// # Errors
    ///
    /// As [`envelope::seal_framed`].
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn seal_json_with(
        key: &IdentityKey,
        target: &[u8; 16],
        bundle_key: &[u8; 32],
        json: &[u8],
        randomness: &envelope::FixedRandomness,
    ) -> Result<Self> {
        let envelope = randomness.seal_framed(&key.public(), &Recipient::new(*bundle_key), json)?;
        Ok(Self::signed(key, target, envelope))
    }

    fn signed(key: &IdentityKey, target: &[u8; 16], envelope: Vec<u8>) -> Self {
        let sig = key.sign(labels::sig::KEY_BUNDLE, &[&key.public(), target, &envelope]);
        Self { envelope, sig }
    }

    /// Verify the identity key's signature over the identity, the target App ID and the
    /// envelope bytes (Switch wire 3.5).
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] if it doesn't verify.
    pub fn verify(&self, identity: &[u8; 32], target: &[u8; 16]) -> Result<()> {
        sig::verify(
            identity,
            labels::sig::KEY_BUNDLE,
            &[identity, target, &self.envelope],
            &self.sig,
        )
    }

    /// Verify the bundle for the app `target`, open it with that app's bundle secret and read
    /// its plaintext (Switch wire 3.5 "Reading").
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] if it doesn't verify, [`Error::Crypto`] or [`Error::Invalid`] if
    /// it doesn't open, and [`Error::Invalid`] for a plaintext
    /// [`KeyBundleContents::parse`] refuses.
    pub fn open(
        &self,
        identity: &[u8; 32],
        target: &[u8; 16],
        bundle_secret: &[u8; 32],
    ) -> Result<KeyBundleContents> {
        self.verify(identity, target)?;
        let json = envelope::open_framed(&self.envelope, identity, bundle_secret)?;
        KeyBundleContents::parse(&json)
    }
}

/// The plaintext of a key bundle or a part (Switch wire 3.5): the naming key, the
/// certificate it was made for, its range of data epochs and its scope keys. Its `Debug`
/// output shows no key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBundleContents {
    /// The identity's naming key.
    pub naming_key: NamingKey,
    /// The document hash of the certificate the bundle or part was made for.
    pub cert: [u8; 32],
    /// The first data epoch it holds keys for.
    pub first_epoch: u64,
    /// The last data epoch it holds keys for.
    pub last_epoch: u64,
    /// Its scope keys, each inside the range.
    pub keys: ScopeKeys,
}

/// The plaintext as it is read; unknown members are ignored (Switch wire 1.1).
#[derive(Deserialize)]
struct ContentsIn {
    v: u64,
    kind: String,
    naming_key: String,
    cert: String,
    first_epoch: u64,
    last_epoch: u64,
    keys: Vec<KeyIn>,
}

impl Drop for ContentsIn {
    fn drop(&mut self) {
        self.naming_key.zeroize();
    }
}

#[derive(Deserialize)]
struct KeyIn {
    data_epoch: u64,
    scope: String,
    key: String,
}

impl Drop for KeyIn {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// The plaintext as the signer writes it: the members in the order of Switch wire 3.5.
#[derive(Serialize)]
struct ContentsOut<'a> {
    v: u64,
    kind: &'a str,
    #[serde(with = "serde_b64")]
    naming_key: [u8; 32],
    #[serde(with = "serde_b64")]
    cert: [u8; 32],
    first_epoch: u64,
    last_epoch: u64,
    keys: &'a [ScopeKey],
}

impl Drop for ContentsOut<'_> {
    fn drop(&mut self) {
        self.naming_key.zeroize();
    }
}

impl KeyBundleContents {
    /// The plaintext of a part made for `cert` over `first_epoch..=last_epoch`: one key for
    /// each scope of `cert` that `has_keys` names and each epoch of the range, epochs
    /// ascending and scopes in the certificate's order, as the signer derives them (Switch
    /// wire 1.5, 3.5).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a range that doesn't start at 1 or later, or ends before it
    /// starts, or a certificate of another identity.
    pub fn derive(
        key: &IdentityKey,
        cert: &AppCert,
        first_epoch: u64,
        last_epoch: u64,
        has_keys: &dyn Fn(&str) -> bool,
    ) -> Result<Self> {
        check_range(first_epoch, last_epoch)?;
        if cert.identity() != key.public() {
            return invalid("Switch wire 3.5: the certificate is of another identity");
        }
        let scopes: Vec<String> = keyed_scopes(cert, has_keys)
            .into_iter()
            .map(str::to_owned)
            .collect();
        Ok(Self {
            naming_key: key.naming_key(),
            cert: cert.hash(),
            first_epoch,
            last_epoch,
            keys: ScopeKeys::derive_range(key, &scopes, first_epoch, last_epoch),
        })
    }

    /// Read a plaintext's JSON strictly (Switch wire 1.1, 3.5): `v` 1, its `kind`, a range
    /// starting at 1 or later and ending no earlier, and every key inside the range.
    ///
    /// Whether the keys are exactly those of the certificate `cert` names needs that
    /// certificate: [`check_bundle_keys`].
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] naming the rule that failed; the text never quotes a key.
    pub fn parse(json: &[u8]) -> Result<Self> {
        let wire: ContentsIn = parse_json(json)?;
        if wire.v != 1 {
            return invalid("Switch wire 3.5: v isn't 1");
        }
        if wire.kind != KEY_BUNDLE_KIND {
            return invalid("Switch wire 3.5: kind isn't pubky-switch.key_bundle");
        }
        check_range(wire.first_epoch, wire.last_epoch)?;
        let mut keys = Vec::with_capacity(wire.keys.len());
        for entry in &wire.keys {
            if !(wire.first_epoch..=wire.last_epoch).contains(&entry.data_epoch) {
                return invalid("Switch wire 3.5: a key outside first_epoch..last_epoch");
            }
            keys.push(ScopeKey {
                data_epoch: entry.data_epoch,
                scope: entry.scope.clone(),
                key: unb64_array::<32>(&entry.key)?,
            });
        }
        Ok(Self {
            naming_key: NamingKey::from_bytes(unb64_array::<32>(&wire.naming_key)?),
            cert: unb64_array::<32>(&wire.cert)?,
            first_epoch: wire.first_epoch,
            last_epoch: wire.last_epoch,
            keys: ScopeKeys { keys },
        })
    }

    /// The plaintext's JSON, compact, with the members in the order of Switch wire 3.5. It
    /// holds keys, so it is zeroized when dropped.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if it can't be written.
    pub fn to_json(&self) -> Result<Zeroizing<Vec<u8>>> {
        let out = ContentsOut {
            v: 1,
            kind: KEY_BUNDLE_KIND,
            naming_key: self.naming_key.to_bytes(),
            cert: self.cert,
            first_epoch: self.first_epoch,
            last_epoch: self.last_epoch,
            keys: &self.keys.keys,
        };
        serde_json::to_vec(&out).map(Zeroizing::new).map_err(|_| {
            Error::Invalid("Switch wire 3.5: the key bundle can't be written as JSON".into())
        })
    }
}

/// Check a range of data epochs: `1 <= first <= last` (Switch wire 3.5).
fn check_range(first_epoch: u64, last_epoch: u64) -> Result<()> {
    if first_epoch == 0 || first_epoch > last_epoch {
        return invalid("Switch wire 3.5: a range of data epochs from 1, first at most last");
    }
    Ok(())
}

/// The scopes of `cert` that have keys, by the protocol's choice `has_keys`, in the
/// certificate's order (Switch spec 3.5). A labelled sub-scope is one when the protocol says
/// so; its keys are then its own sub-scope keys (Switch wire 1.5).
pub fn keyed_scopes<'a>(cert: &'a AppCert, has_keys: &dyn Fn(&str) -> bool) -> Vec<&'a str> {
    cert.scopes()
        .iter()
        .map(String::as_str)
        .filter(|scope| has_keys(scope))
        .collect()
}

/// Check that a part's keys are exactly one for each scope with keys of `cert`, the
/// certificate it names, and each data epoch of its range, and no other (Switch wire 3.5):
/// a key of another scope, a `(scope, data_epoch)` pair twice, or a pair missing makes it
/// invalid, and the reader skips it.
///
/// # Errors
///
/// [`Error::Invalid`] naming the rule that failed.
pub fn check_bundle_keys(
    contents: &KeyBundleContents,
    cert: &AppCert,
    has_keys: &dyn Fn(&str) -> bool,
) -> Result<()> {
    if contents.cert != cert.hash() {
        return invalid("Switch wire 3.5: the part names another certificate");
    }
    let scopes = keyed_scopes(cert, has_keys);
    let mut seen = BTreeSet::new();
    for key in &contents.keys.keys {
        if !scopes.contains(&key.scope.as_str()) {
            return invalid(
                "Switch wire 3.5: a key for a scope the certificate doesn't hold as a scope with keys",
            );
        }
        if !(contents.first_epoch..=contents.last_epoch).contains(&key.data_epoch) {
            return invalid("Switch wire 3.5: a key outside first_epoch..last_epoch");
        }
        if !seen.insert((key.data_epoch, key.scope.as_str())) {
            return invalid("Switch wire 3.5: two keys for one scope and data epoch");
        }
    }
    // Every pair is in range, of a keyed scope, and once: the pairs are complete exactly
    // when there are as many as the range and the scopes make.
    let epochs = contents
        .last_epoch
        .checked_sub(contents.first_epoch)
        .and_then(|span| span.checked_add(1));
    let expected = epochs.and_then(|e| e.checked_mul(u64::try_from(scopes.len()).ok()?));
    if expected != u64::try_from(seen.len()).ok() {
        return invalid(
            "Switch wire 3.5: the part lacks a key of its certificate's scopes and range",
        );
    }
    Ok(())
}

/// One key bundle part with the range it names in the clear, as `key_bundle.put` stores it
/// (Switch wire 6.2), `GET /keys` answers it and an approval carries it (Switch wire 3.10):
/// `{ "bundle", "first_epoch", "last_epoch" }`. The signature doesn't cover the clear range,
/// so a reader compares it with the plaintext's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundlePart {
    /// The signed, sealed bundle.
    pub bundle: KeyBundle,
    /// The first data epoch it names.
    pub first_epoch: u64,
    /// The last data epoch it names.
    pub last_epoch: u64,
}

impl BundlePart {
    /// The range it names in the clear.
    pub fn range(&self) -> (u64, u64) {
        (self.first_epoch, self.last_epoch)
    }
}

/// The signer's parts for `cert`'s app over `first_epoch..=last_epoch` (Switch wire 3.5
/// "Parts"): the whole range when its envelope fits 64 KiB, otherwise its two halves, split
/// again until each fits. Each part holds the naming key and the keys of `cert`'s scopes
/// with keys (`has_keys`) for its own range only, names `cert`, and is signed and sealed on
/// its own. The parts are in epoch order.
///
/// `last_epoch` is the data epoch the bundle is made for: the current one, or during a
/// rotation the next one. No part holds the Switch root.
///
/// # Errors
///
/// [`Error::Invalid`] for a bad range, a certificate of another identity, or one data
/// epoch whose keys don't fit an envelope; [`Error::Crypto`] as [`envelope::seal`].
pub fn seal_bundle_parts(
    key: &IdentityKey,
    cert: &AppCert,
    first_epoch: u64,
    last_epoch: u64,
    has_keys: &dyn Fn(&str) -> bool,
) -> Result<Vec<BundlePart>> {
    check_range(first_epoch, last_epoch)?;
    if cert.identity() != key.public() {
        return invalid("Switch wire 3.5: the certificate is of another identity");
    }
    let scopes = u64::try_from(keyed_scopes(cert, has_keys).len()).unwrap_or(u64::MAX);
    let most_keys = u64::try_from(MAX_FRAMED_JSON_LEN / MIN_KEY_JSON_LEN).unwrap_or(u64::MAX);
    let mut parts = Vec::new();
    // Depth first, the earlier half on top, so the parts come out in epoch order.
    let mut ranges = vec![(first_epoch, last_epoch)];
    while let Some((first, last)) = ranges.pop() {
        let epochs = last.saturating_sub(first).saturating_add(1);
        let too_many = epochs.saturating_mul(scopes) > most_keys;
        if !too_many {
            let contents = KeyBundleContents::derive(key, cert, first, last, has_keys)?;
            if contents.to_json()?.len() <= MAX_FRAMED_JSON_LEN {
                parts.push(BundlePart {
                    bundle: KeyBundle::seal(key, cert, &contents)?,
                    first_epoch: first,
                    last_epoch: last,
                });
                continue;
            }
        }
        if first == last {
            return invalid("Switch wire 3.5: one data epoch's keys don't fit an envelope");
        }
        let mid = first.saturating_add(last.saturating_sub(first) / 2);
        ranges.push((mid.saturating_add(1), last));
        ranges.push((first, mid));
    }
    Ok(parts)
}

/// Check the ranges of a `GET /keys` answer's parts, or an approval's, as they name them in
/// the clear (Switch wire 3.5 "Reading"): each from 1, first at most last, in `first_epoch`
/// order and never overlapping. Parts out of order or overlapping refuse the whole answer,
/// since merging them would pick between two keys. An empty list is none.
///
/// # Errors
///
/// [`Error::Invalid`] naming the rule the ranges break.
pub fn check_part_order(ranges: impl IntoIterator<Item = (u64, u64)>) -> Result<()> {
    let mut previous_last: Option<u64> = None;
    for (first, last) in ranges {
        check_range(first, last)?;
        if previous_last.is_some_and(|previous| first <= previous) {
            return invalid("Switch wire 3.5: parts out of first_epoch order or overlapping");
        }
        previous_last = Some(last);
    }
    Ok(())
}

/// Why an app skips a key bundle part (Switch wire 3.5 "Reading"). The other parts still
/// count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// The identity key's signature over this app and the envelope doesn't verify.
    Unverified,
    /// The envelope doesn't open with the app's bundle secret, or its plaintext isn't a key
    /// bundle: the rule it breaks.
    Unopened(String),
    /// The plaintext's range isn't the range the part names in the clear, which the
    /// signature doesn't cover: a service could have relabelled it.
    Relabelled,
    /// A key for an epoch after the next one, the newest data epoch the app knows plus one.
    AfterNextEpoch,
    /// Another naming key than an earlier part's or the one the app holds. An identity has
    /// one naming key: the app alerts the user.
    OtherNamingKey,
    /// The part names a certificate the app doesn't take parts for: a stale part, one for a
    /// renewal its newest `identity.json` doesn't list yet, or one it can't check.
    UnknownCert,
    /// The keys aren't exactly one for each scope with keys of the certificate and each
    /// data epoch of the range: the rule they break.
    WrongKeys(String),
}

impl SkipReason {
    /// Whether the app alerts the user: a naming key other than the identity's one, which
    /// would split its blinded names from the other apps' (Switch wire 3.5).
    pub fn alerts(&self) -> bool {
        matches!(self, Self::OtherNamingKey)
    }
}

/// A part an app skipped, by its index in the list it read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedPart {
    /// Its index in the parts read.
    pub index: usize,
    /// The range it names in the clear.
    pub range: (u64, u64),
    /// Why it was skipped.
    pub reason: SkipReason,
}

/// What an app takes from a list of parts (Switch wire 3.5 "Reading").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BundleReading {
    /// The naming key: the one the app held, or the first part taken sets it.
    pub naming_key: Option<NamingKey>,
    /// The scope keys of every part taken, merged.
    pub keys: ScopeKeys,
    /// The ranges of the parts taken, in order.
    pub taken: Vec<(u64, u64)>,
    /// The parts skipped, in order.
    pub skipped: Vec<SkippedPart>,
}

impl BundleReading {
    /// Whether a skipped part calls for alerting the user.
    pub fn alerts(&self) -> bool {
        self.skipped.iter().any(|part| part.reason.alerts())
    }
}

/// An app's reader of its key bundle parts (Switch wire 3.5 "Reading"). It holds the app's
/// bundle secret, so it has no `Debug`.
pub struct PartReader<'a> {
    /// The app's identity.
    pub identity: [u8; 32],
    /// The app's own App ID, which every part's signature names.
    pub app_id: [u8; 16],
    /// The secret of the app's bundle key. Sensitive.
    pub bundle_secret: &'a [u8; 32],
    /// The newest data epoch the app knows, from its newest `identity.json`: a part with a
    /// key after `newest_epoch + 1` is skipped.
    pub newest_epoch: u64,
    /// The certificates the app takes parts for ([`reader_certs`]); at approval, the
    /// approval's certificate alone.
    pub certs: &'a [&'a AppCert],
    /// The protocol's choice of the scopes that have keys.
    pub has_keys: &'a dyn Fn(&str) -> bool,
}

impl PartReader<'_> {
    /// Verify, open and check one part, every skip rule but the naming key's: the
    /// signature, the envelope, the plaintext, the clear range, the next epoch, the
    /// certificate it names and its keys.
    ///
    /// # Errors
    ///
    /// The [`SkipReason`] of the first rule it breaks.
    pub fn open_part(
        &self,
        part: &BundlePart,
    ) -> std::result::Result<KeyBundleContents, SkipReason> {
        let contents = self.open_signed(part)?;
        self.check_contents(part, contents)
    }

    /// Verify a part's signature and open it.
    fn open_signed(&self, part: &BundlePart) -> std::result::Result<KeyBundleContents, SkipReason> {
        part.bundle
            .verify(&self.identity, &self.app_id)
            .map_err(|_| SkipReason::Unverified)?;
        let json = envelope::open_framed(&part.bundle.envelope, &self.identity, self.bundle_secret)
            .map_err(|error| SkipReason::Unopened(error.to_string()))?;
        KeyBundleContents::parse(&json).map_err(|error| SkipReason::Unopened(error.to_string()))
    }

    /// The skip rules after opening, but the naming key's: the clear range, the next
    /// epoch, the certificate the part names and its keys.
    fn check_contents(
        &self,
        part: &BundlePart,
        contents: KeyBundleContents,
    ) -> std::result::Result<KeyBundleContents, SkipReason> {
        if (contents.first_epoch, contents.last_epoch) != part.range() {
            return Err(SkipReason::Relabelled);
        }
        if contents.last_epoch > self.newest_epoch.saturating_add(1) {
            return Err(SkipReason::AfterNextEpoch);
        }
        let cert = self
            .certs
            .iter()
            .find(|cert| cert.hash() == contents.cert)
            .ok_or(SkipReason::UnknownCert)?;
        check_bundle_keys(&contents, cert, self.has_keys)
            .map_err(|error| SkipReason::WrongKeys(error.to_string()))?;
        Ok(contents)
    }

    /// Read a list of parts and merge their keys (Switch wire 3.5 "Reading"). `held` is the
    /// naming key the app holds, `None` at approval: then the first part taken sets it, and
    /// every later part must carry the same one.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the parts, by the ranges they name in the clear, are out of
    /// order or overlap: the app takes no part of the list. A part that breaks another rule
    /// is skipped instead ([`BundleReading::skipped`]).
    pub fn read(&self, parts: &[BundlePart], held: Option<&NamingKey>) -> Result<BundleReading> {
        check_part_order(parts.iter().map(BundlePart::range))?;
        let mut reading = BundleReading {
            naming_key: held.cloned(),
            ..BundleReading::default()
        };
        for (index, part) in parts.iter().enumerate() {
            let skip = |reason| SkippedPart {
                index,
                range: part.range(),
                reason,
            };
            let contents = match self.open_signed(part) {
                Ok(contents) => contents,
                Err(reason) => {
                    reading.skipped.push(skip(reason));
                    continue;
                }
            };
            // Another naming key in a part the identity key signed is an alert, whatever
            // else is wrong with the part, so it is judged first (Switch spec 3.5).
            if reading
                .naming_key
                .as_ref()
                .is_some_and(|naming| naming != &contents.naming_key)
            {
                reading.skipped.push(skip(SkipReason::OtherNamingKey));
                continue;
            }
            let contents = match self.check_contents(part, contents) {
                Ok(contents) => contents,
                Err(reason) => {
                    reading.skipped.push(skip(reason));
                    continue;
                }
            };
            reading.naming_key = Some(contents.naming_key.clone());
            reading.keys.merge(&contents.keys);
            reading.taken.push(part.range());
        }
        Ok(reading)
    }
}

/// The certificates an app takes key bundle parts for (Switch wire 3.5 "Reading"): the one
/// it presents, and each renewal of it among `held` (the same App ID, signing key and bundle
/// key, a later `issued_at`, Switch wire 3.8) that its newest `identity.json` lists for its
/// App ID. `held` are the certificate bodies the app has, from `cert.put` in its feed or
/// from its own record.
pub fn reader_certs<'a>(
    presented: &'a AppCert,
    held: &'a [AppCert],
    newest: &IdentityDoc,
) -> Vec<&'a AppCert> {
    let mut certs = vec![presented];
    for cert in held {
        if is_renewal(presented, cert)
            && newest.listed_cert(&cert.app_id()) == Some(cert.hash())
            && !certs.iter().any(|c| c.hash() == cert.hash())
        {
            certs.push(cert);
        }
    }
    certs
}

/// Scope keys an app lacks for one scope: the epochs `first_epoch..=last_epoch`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingKeys {
    /// The scope.
    pub scope: String,
    /// The first epoch lacking.
    pub first_epoch: u64,
    /// The last epoch lacking.
    pub last_epoch: u64,
}

/// The scope keys an app lacks for `cert`'s scopes with keys, over the data epochs from 1
/// to `through`, the current one (Switch wire 3.5 "Full bundles on request"). An app that
/// lacks any after fetching its parts asks once for a full bundle (`POST /keys`, Switch wire
/// 7.4.11). Each scope's gaps as ranges, scopes in the certificate's order.
pub fn missing_keys(
    held: &ScopeKeys,
    cert: &AppCert,
    has_keys: &dyn Fn(&str) -> bool,
    through: u64,
) -> Vec<MissingKeys> {
    let mut missing = Vec::new();
    for scope in keyed_scopes(cert, has_keys) {
        let covered: Vec<(u64, u64)> = held
            .keys
            .iter()
            .filter(|key| key.scope == scope)
            .map(|key| (key.data_epoch, key.data_epoch))
            .collect();
        for (first_epoch, last_epoch) in missing_ranges(&covered, 1, through) {
            missing.push(MissingKeys {
                scope: scope.to_owned(),
                first_epoch,
                last_epoch,
            });
        }
    }
    missing
}

/// The ranges of data epochs from `from` to `through` that no range of `covered` holds, in
/// order (Switch wire 3.5 "Full bundles on request", 7.4.12 `bundle_ranges`). `covered` may
/// be in any order and overlap.
pub fn missing_ranges(covered: &[(u64, u64)], from: u64, through: u64) -> Vec<(u64, u64)> {
    let mut sorted = covered.to_vec();
    sorted.sort_unstable();
    let mut missing = Vec::new();
    // `next` is the first epoch not yet known to be covered; `None` past the integer range.
    let mut next = Some(from);
    for (first, last) in sorted {
        let Some(at) = next.filter(|at| *at <= through) else {
            break;
        };
        if first > at {
            missing.push((at, first.saturating_sub(1).min(through)));
        }
        next = Some(at.max(first)).and_then(|start| {
            if last >= start {
                last.checked_add(1)
            } else {
                Some(start)
            }
        });
    }
    if let Some(at) = next.filter(|at| *at <= through) {
        missing.push((at, through));
    }
    missing
}

/// Whether `ranges` cover every data epoch from 1 to `current`: then a pending full-bundle
/// request clears (Switch wire 3.5 "Full bundles on request").
pub fn covers_from_one(ranges: &[(u64, u64)], current: u64) -> bool {
    missing_ranges(ranges, 1, current).is_empty()
}

/// The first data epoch of an app's next bundle (Switch wire 3.5 "Incremental bundles"):
/// the one after `keys_through`, the newest epoch through which the app holds every key, as
/// `GET /apps` shows it, carried on through `stored`, the ranges of the parts stored for the
/// app's listed certificate, which it may not have fetched yet. So the bundle never overlaps a
/// stored part, and never replaces one the app hasn't fetched (the parts stored for an app
/// never overlap): a renewal that adds a scope stores a full bundle with that scope's earlier
/// keys, which `keys_through` doesn't vouch for. Epoch 1, a full bundle, when the service
/// shows no `keys_through` or a full bundle is requested.
pub fn incremental_first_epoch(
    keys_through: Option<u64>,
    stored: &[(u64, u64)],
    full_requested: bool,
) -> u64 {
    let Some(mut held) = keys_through.filter(|_| !full_requested) else {
        return 1;
    };
    let mut sorted = stored.to_vec();
    sorted.sort_unstable();
    for (first, last) in sorted {
        if first <= held.saturating_add(1) {
            held = held.max(last);
        }
    }
    held.saturating_add(1)
}

/// A key bundle part the signer stored for an app, as the signer keeps it and a hand-over
/// or a backup lists it (`bundle_parts`, Switch wire 3.12): the app, the range and the
/// certificate the part was made for. The service shows only the ranges, so the signer
/// keeps which certificate each part names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StoredPart {
    /// The app the part was stored for.
    #[serde(with = "fmt::app_id")]
    pub app_id: [u8; 16],
    /// The first data epoch.
    pub first_epoch: u64,
    /// The last data epoch.
    pub last_epoch: u64,
    /// The document hash of the certificate the part was made for.
    #[serde(with = "serde_b64")]
    pub cert: [u8; 32],
}

/// Note a part the service took for its app: it replaces every part of that app whose range
/// it overlaps, as at the service (Switch wire 3.5 "Parts", 6.2).
pub fn note_stored(stored: &mut Vec<StoredPart>, part: StoredPart) {
    stored.retain(|held| {
        held.app_id != part.app_id
            || held.last_epoch < part.first_epoch
            || part.last_epoch < held.first_epoch
    });
    stored.push(part);
}

/// Whether the batch of a full bundle's first part also stores the current certificate
/// with `cert.put` (Switch wire 3.5 "Full bundles on request"): when the app's record at the
/// service carries another certificate (`record_cert`, Switch wire 7.4.12), as at a renewal.
pub fn needs_cert_put(record_cert: Option<&[u8; 32]>, current: &AppCert) -> bool {
    record_cert.is_some_and(|hash| hash != &current.hash())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enc::b64;
    use crate::ident;
    use crate::records::fixtures::{app, cert, cert_body, identity, other_app};
    use crate::records::{IdentityBody, IdentityPolicy, Inbox, ListedApp};
    use std::collections::BTreeMap;

    /// The key of every `(data_epoch, scope)` pair in `keys`.
    fn by_pair(keys: &ScopeKeys) -> BTreeMap<(u64, String), [u8; 32]> {
        keys.keys
            .iter()
            .map(|key| ((key.data_epoch, key.scope.clone()), key.key))
            .collect()
    }

    fn naming_text(naming: &NamingKey) -> String {
        b64(&naming.to_bytes())
    }

    /// The scope key a signer derives for `scope` at `data_epoch`.
    fn derived(key: &IdentityKey, data_epoch: u64, scope: &str) -> [u8; 32] {
        ident::key_of_scope(&key.switch_root(), data_epoch, scope)
    }

    /// The unit tests' protocol: `scope-a` and `scope-b` have keys, `plain` has none.
    fn has_keys(scope: &str) -> bool {
        scope.starts_with("scope-")
    }

    fn the_cert() -> AppCert {
        cert(&["scope-a", "plain", "scope-b"])
    }

    fn reader<'a>(certs: &'a [&'a AppCert], secret: &'a [u8; 32]) -> PartReader<'a> {
        PartReader {
            identity: identity().public(),
            app_id: app().app_id_bytes(),
            bundle_secret: secret,
            newest_epoch: 3,
            certs,
            has_keys: &has_keys,
        }
    }

    fn contents(first: u64, last: u64) -> KeyBundleContents {
        KeyBundleContents::derive(&identity(), &the_cert(), first, last, &has_keys).unwrap()
    }

    fn part_of(contents: &KeyBundleContents) -> BundlePart {
        BundlePart {
            bundle: KeyBundle::seal(&identity(), &the_cert(), contents).unwrap(),
            first_epoch: contents.first_epoch,
            last_epoch: contents.last_epoch,
        }
    }

    #[test]
    fn test_key_bundle_contents_round_trip_in_table_order() {
        let c = contents(1, 2);
        let json = c.to_json().unwrap();
        let text = std::str::from_utf8(&json).unwrap();
        assert!(text.starts_with(r#"{"v":1,"kind":"pubky-switch.key_bundle","naming_key":""#));
        assert!(text.contains(
            r#""first_epoch":1,"last_epoch":2,"keys":[{"data_epoch":1,"scope":"scope-a","key":""#
        ));
        assert_eq!(KeyBundleContents::parse(&json).unwrap(), c);
        // Epochs ascending, scopes in the certificate's order, keyed scopes only.
        let order: Vec<(u64, &str)> = c
            .keys
            .keys
            .iter()
            .map(|k| (k.data_epoch, k.scope.as_str()))
            .collect();
        assert_eq!(
            order,
            [
                (1, "scope-a"),
                (1, "scope-b"),
                (2, "scope-a"),
                (2, "scope-b")
            ]
        );
        assert_eq!(
            by_pair(&c.keys)[&(2, "scope-b".into())],
            derived(&identity(), 2, "scope-b")
        );
        assert_eq!(c.naming_key, identity().naming_key());
        assert!(!format!("{c:?}").contains(&naming_text(&c.naming_key)));
    }

    #[test]
    fn test_key_bundle_contents_parse_refuses_each_rule() {
        let good = String::from_utf8(contents(2, 2).to_json().unwrap().to_vec()).unwrap();
        KeyBundleContents::parse(good.as_bytes()).unwrap();
        for (bad, rule) in [
            (good.replacen(r#""v":1"#, r#""v":2"#, 1), "v isn't 1"),
            (good.replacen("key_bundle", "other", 1), "kind"),
            (
                good.replacen(r#""first_epoch":2"#, r#""first_epoch":0"#, 1),
                "from 1",
            ),
            (
                good.replacen(r#""first_epoch":2"#, r#""first_epoch":3"#, 1),
                "from 1",
            ),
            (
                good.replacen(r#""last_epoch":2"#, r#""last_epoch":3"#, 1)
                    .replacen(r#""data_epoch":2"#, r#""data_epoch":4"#, 1),
                "outside",
            ),
            (
                good.replacen(r#","cert":""#, r#","certx":""#, 1),
                "missing field `cert`",
            ),
        ] {
            let error = KeyBundleContents::parse(bad.as_bytes()).unwrap_err();
            assert!(error.to_string().contains(rule), "{rule}: {error}");
        }
        // Unknown members are ignored.
        let extra = good.replacen(r#"{"v":1"#, r#"{"future":true,"v":1"#, 1);
        KeyBundleContents::parse(extra.as_bytes()).unwrap();
    }

    #[test]
    fn test_key_bundle_seal_opens_for_its_app_only() {
        let c = contents(1, 1);
        let bundle = KeyBundle::seal(&identity(), &the_cert(), &c).unwrap();
        let (id, target) = (identity().public(), app().app_id_bytes());
        assert_eq!(
            bundle.open(&id, &target, &app().bundle_secret()).unwrap(),
            c
        );
        assert!(format!("{bundle:?}").starts_with("KeyBundle("));
        // Another app's signature fields, another bundle secret, another identity.
        let other = other_app();
        assert!(matches!(
            bundle.open(&id, &other.app_id_bytes(), &app().bundle_secret()),
            Err(Error::Signature(_))
        ));
        assert!(bundle.open(&id, &target, &other.bundle_secret()).is_err());
        let mut tampered = bundle.clone();
        tampered.envelope[100] ^= 1;
        assert!(tampered.verify(&id, &target).is_err());
        // The signer seals only for its own certificates, and the certificate the bundle names.
        let stranger = IdentityKey::from_secret([9; 32]);
        assert!(KeyBundle::seal(&stranger, &the_cert(), &c).is_err());
        let mut other_cert = c.clone();
        other_cert.cert = [7; 32];
        assert!(KeyBundle::seal(&identity(), &the_cert(), &other_cert).is_err());
    }

    #[test]
    fn test_key_bundle_check_keys_refuses_each_rule() {
        let cert = the_cert();
        let good = contents(1, 2);
        check_bundle_keys(&good, &cert, &has_keys).unwrap();
        let with = |change: &dyn Fn(&mut Vec<ScopeKey>)| {
            let mut c = good.clone();
            change(&mut c.keys.keys);
            check_bundle_keys(&c, &cert, &has_keys)
                .unwrap_err()
                .to_string()
        };
        let key = |epoch: u64, scope: &str| ScopeKey {
            data_epoch: epoch,
            scope: scope.into(),
            key: [1; 32],
        };
        assert!(with(&|k| k.push(key(1, "plain"))).contains("doesn't hold"));
        assert!(with(&|k| k.push(key(1, "unheld"))).contains("doesn't hold"));
        assert!(with(&|k| k.push(key(1, "scope-a"))).contains("two keys"));
        assert!(
            with(&|k| {
                k.pop();
            })
            .contains("lacks")
        );
        assert!(with(&|k| k.push(key(3, "scope-a"))).contains("outside"));
        let mut named = good.clone();
        named.cert = [2; 32];
        assert!(check_bundle_keys(&named, &cert, &has_keys).is_err());
        // A certificate without keyed scopes takes a part without keys.
        let plain = cert_for(&["plain"]);
        let empty = KeyBundleContents::derive(&identity(), &plain, 1, 4, &has_keys).unwrap();
        assert!(empty.keys.keys.is_empty());
        check_bundle_keys(&empty, &plain, &has_keys).unwrap();
    }

    fn cert_for(scopes: &[&str]) -> AppCert {
        AppCert::issue(&identity(), cert_body(scopes)).unwrap()
    }

    #[test]
    fn test_key_bundle_parts_split_by_halving() {
        let cert = the_cert();
        let one = seal_bundle_parts(&identity(), &cert, 1, 5, &has_keys).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].range(), (1, 5));
        // About 90 bytes a key: 400 epochs of two scopes need two envelopes.
        let many = seal_bundle_parts(&identity(), &cert, 1, 400, &has_keys).unwrap();
        let ranges: Vec<(u64, u64)> = many.iter().map(BundlePart::range).collect();
        assert_eq!(ranges, [(1, 200), (201, 400)]);
        for part in &many {
            assert!(part.bundle.envelope().len() <= envelope::MAX_ENVELOPE_LEN);
        }
        check_part_order(ranges.iter().copied()).unwrap();
        let secret = app().bundle_secret();
        let certs = [&cert];
        let mut r = reader(&certs, &secret);
        r.newest_epoch = 400;
        let reading = r.read(&many, None).unwrap();
        assert!(reading.skipped.is_empty(), "{:?}", reading.skipped);
        assert_eq!(reading.keys.keys.len(), 800);
        assert!(missing_keys(&reading.keys, &cert, &has_keys, 400).is_empty());
        // A bad range or another identity's certificate is refused.
        assert!(seal_bundle_parts(&identity(), &cert, 0, 1, &has_keys).is_err());
        assert!(seal_bundle_parts(&identity(), &cert, 3, 2, &has_keys).is_err());
        let stranger = IdentityKey::from_secret([9; 32]);
        assert!(seal_bundle_parts(&stranger, &cert, 1, 1, &has_keys).is_err());
    }

    #[test]
    fn test_key_bundle_parts_cover_a_large_range_in_order() {
        let cert = the_cert();
        let parts = seal_bundle_parts(&identity(), &cert, 1, 2000, &has_keys).unwrap();
        assert!(parts.len() > 4);
        let ranges: Vec<(u64, u64)> = parts.iter().map(BundlePart::range).collect();
        check_part_order(ranges.iter().copied()).unwrap();
        assert!(covers_from_one(&ranges, 2000));
        assert_eq!(ranges.last().map(|r| r.1), Some(2000));
    }

    #[test]
    fn test_key_bundle_part_order() {
        check_part_order([]).unwrap();
        check_part_order([(1, 2), (3, 3), (5, 9)]).unwrap();
        for bad in [
            vec![(2, 3), (1, 1)],
            vec![(1, 2), (2, 3)],
            vec![(1, 1), (1, 1)],
            vec![(0, 1)],
            vec![(3, 2)],
        ] {
            assert!(check_part_order(bad.clone()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn test_key_bundle_reader_skips_each_rule() {
        let cert = the_cert();
        let certs = [&cert];
        let secret = app().bundle_secret();
        let r = reader(&certs, &secret);
        let good = part_of(&contents(1, 2));
        assert!(r.open_part(&good).is_ok());

        let mut unverified = good.clone();
        unverified.bundle.sig = [0; 64];
        assert_eq!(r.open_part(&unverified), Err(SkipReason::Unverified));

        let wrong_secret = other_app().bundle_secret();
        let r2 = reader(&certs, &wrong_secret);
        assert!(matches!(r2.open_part(&good), Err(SkipReason::Unopened(_))));

        let mut relabelled = good.clone();
        relabelled.last_epoch = 3;
        assert_eq!(r.open_part(&relabelled), Err(SkipReason::Relabelled));

        let late = part_of(&contents(5, 5));
        assert_eq!(r.open_part(&late), Err(SkipReason::AfterNextEpoch));
        // The next epoch itself is taken, during a rotation.
        assert!(r.open_part(&part_of(&contents(4, 4))).is_ok());

        let stale = cert_for(&["scope-a"]);
        let stale_part = BundlePart {
            bundle: KeyBundle::seal(
                &identity(),
                &stale,
                &KeyBundleContents::derive(&identity(), &stale, 1, 1, &has_keys).unwrap(),
            )
            .unwrap(),
            first_epoch: 1,
            last_epoch: 1,
        };
        assert_eq!(r.open_part(&stale_part), Err(SkipReason::UnknownCert));

        let mut extra = contents(1, 1);
        extra.keys.keys.push(ScopeKey {
            data_epoch: 1,
            scope: "plain".into(),
            key: [3; 32],
        });
        assert!(matches!(
            r.open_part(&part_of(&extra)),
            Err(SkipReason::WrongKeys(_))
        ));
    }

    #[test]
    fn test_key_bundle_reader_merges_and_checks_the_naming_key() {
        let cert = the_cert();
        let certs = [&cert];
        let secret = app().bundle_secret();
        let r = reader(&certs, &secret);
        let first = part_of(&contents(1, 1));
        let second = part_of(&contents(2, 3));
        let reading = r.read(&[first.clone(), second.clone()], None).unwrap();
        assert_eq!(reading.taken, [(1, 1), (2, 3)]);
        assert_eq!(reading.naming_key, Some(identity().naming_key()));
        assert_eq!(reading.keys.keys.len(), 6);
        assert!(!reading.alerts());

        // A part with another naming key is skipped and alerts; the others still count.
        let mut forged = contents(2, 3);
        forged.naming_key = NamingKey::from_bytes([4; 32]);
        let forged = part_of(&forged);
        let reading = r.read(&[first.clone(), forged.clone()], None).unwrap();
        assert_eq!(reading.taken, [(1, 1)]);
        assert_eq!(reading.skipped[0].reason, SkipReason::OtherNamingKey);
        assert!(reading.alerts());
        // Against a held naming key too.
        let held = NamingKey::from_bytes([4; 32]);
        let reading = r.read(std::slice::from_ref(&first), Some(&held)).unwrap();
        assert!(reading.taken.is_empty() && reading.alerts());
        // Another naming key alerts even in a part that breaks a later rule as well, here
        // one that names a certificate the app doesn't hold.
        let stale = cert_for(&["scope-a"]);
        let mut stale_contents =
            KeyBundleContents::derive(&identity(), &stale, 2, 2, &has_keys).unwrap();
        stale_contents.naming_key = NamingKey::from_bytes([5; 32]);
        let both = BundlePart {
            bundle: KeyBundle::seal(&identity(), &stale, &stale_contents).unwrap(),
            first_epoch: 2,
            last_epoch: 2,
        };
        let reading = r.read(&[first.clone(), both], None).unwrap();
        assert_eq!(reading.skipped[0].reason, SkipReason::OtherNamingKey);
        assert!(reading.alerts());

        // Overlapping or out-of-order parts refuse the whole list.
        assert!(r.read(&[second.clone(), first.clone()], None).is_err());
        assert!(r.read(&[first.clone(), first], None).is_err());
        // An empty list is none.
        assert_eq!(r.read(&[], None).unwrap(), BundleReading::default());
    }

    #[test]
    fn test_key_bundle_reader_certs_take_listed_renewals_only() {
        let presented = the_cert();
        let mut body = cert_body(&["scope-a"]);
        body.issued_at += 1;
        let renewal = AppCert::issue(&identity(), body).unwrap();
        let mut older = cert_body(&["scope-a"]);
        older.issued_at -= 1;
        let older = AppCert::issue(&identity(), older).unwrap();
        let foreign = AppCert::issue(
            &identity(),
            crate::records::fixtures::cert_body_for(&other_app(), &["scope-a"]),
        )
        .unwrap();
        let held = [renewal.clone(), older, foreign];
        let doc = |listed: &AppCert| {
            let mut body = IdentityBody::first(
                identity().public(),
                [0; 16],
                Inbox::new("https://inbox.example", [5; 32]),
                IdentityPolicy::default(),
            );
            body.apps.push(ListedApp {
                app_id: listed.app_id(),
                cert: listed.hash(),
            });
            IdentityDoc::sign(&identity(), body).unwrap()
        };
        let listing_renewal = doc(&renewal);
        let certs = reader_certs(&presented, &held, &listing_renewal);
        let hashes: Vec<[u8; 32]> = certs.iter().map(|c| c.hash()).collect();
        assert_eq!(hashes, [presented.hash(), renewal.hash()]);
        // Not listed yet: only the presented one.
        let listing_presented = doc(&presented);
        assert_eq!(reader_certs(&presented, &held, &listing_presented).len(), 1);
    }

    #[test]
    fn test_key_bundle_missing_keys_and_ranges() {
        let cert = the_cert();
        let mut held = contents(1, 2).keys;
        held.merge(&contents(4, 4).keys);
        let missing = missing_keys(&held, &cert, &has_keys, 5);
        assert_eq!(
            missing,
            [
                MissingKeys {
                    scope: "scope-a".into(),
                    first_epoch: 3,
                    last_epoch: 3
                },
                MissingKeys {
                    scope: "scope-a".into(),
                    first_epoch: 5,
                    last_epoch: 5
                },
                MissingKeys {
                    scope: "scope-b".into(),
                    first_epoch: 3,
                    last_epoch: 3
                },
                MissingKeys {
                    scope: "scope-b".into(),
                    first_epoch: 5,
                    last_epoch: 5
                },
            ]
        );
        assert!(missing_keys(&held, &cert, &has_keys, 2).is_empty());

        assert_eq!(missing_ranges(&[], 1, 3), [(1, 3)]);
        assert_eq!(
            missing_ranges(&[(2, 3), (6, 6)], 1, 8),
            [(1, 1), (4, 5), (7, 8)]
        );
        assert_eq!(missing_ranges(&[(6, 6), (1, 4), (2, 3)], 1, 6), [(5, 5)]);
        assert_eq!(missing_ranges(&[(1, 9)], 1, 3), []);
        assert_eq!(missing_ranges(&[(1, u64::MAX)], 1, u64::MAX), []);
        assert_eq!(missing_ranges(&[], 4, 3), []);
        assert!(covers_from_one(&[(1, 2), (3, 5)], 5));
        assert!(!covers_from_one(&[(1, 2), (4, 5)], 5));
        assert!(!covers_from_one(&[(2, 5)], 5));
    }

    #[test]
    fn test_key_bundle_incremental_and_full_requests() {
        assert_eq!(incremental_first_epoch(Some(3), &[], false), 4);
        assert_eq!(incremental_first_epoch(Some(3), &[], true), 1);
        assert_eq!(incremental_first_epoch(None, &[], false), 1);
        // Carried on through the stored parts it continues, in any order, so it never
        // overlaps one; a part after a gap doesn't count.
        assert_eq!(incremental_first_epoch(Some(1), &[(1, 2)], false), 3);
        assert_eq!(
            incremental_first_epoch(Some(1), &[(4, 5), (2, 3)], false),
            6
        );
        assert_eq!(incremental_first_epoch(Some(1), &[(3, 4)], false), 2);
        assert_eq!(incremental_first_epoch(Some(5), &[(1, 2)], false), 6);
        // A full bundle all the same when none is shown or one is requested.
        assert_eq!(incremental_first_epoch(None, &[(1, 2)], false), 1);
        assert_eq!(incremental_first_epoch(Some(1), &[(1, 2)], true), 1);
        assert_eq!(
            incremental_first_epoch(Some(u64::MAX), &[], false),
            u64::MAX
        );

        let cert = the_cert();
        let app_id = cert.app_id();
        let other_id = other_app().app_id_bytes();
        let part = |app_id: [u8; 16], first, last, cert: [u8; 32]| StoredPart {
            app_id,
            first_epoch: first,
            last_epoch: last,
            cert,
        };
        let mut stored = vec![];
        note_stored(&mut stored, part(app_id, 1, 2, cert.hash()));
        note_stored(&mut stored, part(app_id, 3, 4, [8; 32]));
        note_stored(&mut stored, part(other_id, 1, 9, cert.hash()));
        // A part replaces the parts of its app it overlaps, no other app's.
        note_stored(&mut stored, part(app_id, 2, 3, cert.hash()));
        assert_eq!(stored.len(), 2);
        assert!(stored.contains(&part(other_id, 1, 9, cert.hash())));

        assert!(needs_cert_put(Some(&[1; 32]), &cert));
        assert!(!needs_cert_put(Some(&cert.hash()), &cert));
        assert!(!needs_cert_put(None, &cert));
    }

    #[test]
    fn test_key_bundle_stored_part_json() {
        let part = StoredPart {
            app_id: app().app_id_bytes(),
            first_epoch: 2,
            last_epoch: 3,
            cert: [6; 32],
        };
        let text = serde_json::to_string(&part).unwrap();
        assert!(text.starts_with(&format!(
            r#"{{"app_id":"{}","first_epoch":2,"last_epoch":3,"cert":""#,
            app().app_id()
        )));
        assert_eq!(serde_json::from_str::<StoredPart>(&text).unwrap(), part);
    }
}
