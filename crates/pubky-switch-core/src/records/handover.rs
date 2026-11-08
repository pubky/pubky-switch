//! The signer hand-over and the signer backup (Switch wire 3.12, 3.13; Switch spec 12.8).
//!
//! Both carry the signer's records, [`SignerRecords`]: the identity key, the newest
//! `identity.json` a service accepted, the App IDs revoked for good, the certificates that
//! document references, the switch's limits and the key bundle parts stored for its apps.
//! Their JSON is split into 1 to 128 parts, each sealed in its own envelope:
//!
//! - a hand-over to the new signer's certified bundle key, signed over `lp(label, identity,
//!   the new signer's App ID, u32_be(n), envelope_1, ..., envelope_n)`;
//! - a backup to the identity's backup key, which only a holder of the identity key derives,
//!   signed over `lp(label, identity, u32_be(n), envelope_1, ..., envelope_n)`.
//!
//! The signature binds the count and the order, so parts swapped, missing or added refuse
//! it. The hand-over's take-over and abort, and the backup's restore, are pure rules here;
//! the deliveries and the reads of the switch's and the Homeserver's copies are the
//! signer's.
//!
//! Security: the plaintext holds the identity secret. It is zeroized when dropped, never
//! shown by `Debug`, and opened only after the signature verifies.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize as _, Zeroizing};

use super::{AppCert, IdentityBody, IdentityDoc, Limits, StoredPart, fmt};
use crate::enc::{b64, kid, serde_b64, unb64, unb64_array, zbase32_encode};
use crate::envelope::{self, MAX_FRAMED_JSON_LEN, Recipient};
use crate::error::{Error, Result, invalid};
use crate::json::parse_json;
use crate::keys::IdentityKey;
use crate::labels;
use crate::sig::{self, SignedDoc};

/// The `kind` of a hand-over's and a backup's plaintext (Switch wire 3.12, 3.13).
pub const HANDOVER_KIND: &str = "pubky-switch.signer_handover";

/// The most envelopes a hand-over or a backup holds (Switch wire 3.12).
pub const MAX_HANDOVER_ENVELOPES: usize = 128;

/// The most `bundle_parts` entries (Switch wire 3.12).
pub const MAX_BUNDLE_PARTS: usize = 2048;

/// The signer's records (Switch wire 3.12, 3.13): the plaintext of a hand-over and of a
/// backup.
///
/// Holding one means its checks 1 and 2 held: the secret is the identity's, `identity_doc`
/// verifies for it, and every certificate it references is among `certs` and verifies.
/// It holds the identity key, so its `Debug` shows only the identity and the version.
#[derive(Clone)]
pub struct SignerRecords {
    key: IdentityKey,
    identity_doc: IdentityDoc,
    revoked_apps: Vec<[u8; 16]>,
    certs: Vec<AppCert>,
    limits: Limits,
    bundle_parts: Vec<StoredPart>,
    prev: Option<[u8; 32]>,
}

impl std::fmt::Debug for SignerRecords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SignerRecords({}, version {})",
            self.key.id(),
            self.identity_doc.version()
        )
    }
}

/// The plaintext as it is read; unknown members are ignored (Switch wire 1.1).
#[derive(Deserialize)]
struct RecordsIn {
    v: u64,
    kind: String,
    identity: String,
    identity_secret: String,
    identity_doc: SignedDoc,
    revoked_apps: Vec<String>,
    certs: Vec<SignedDoc>,
    limits: Limits,
    bundle_parts: Vec<StoredPart>,
    #[serde(default)]
    prev: Option<String>,
}

impl Drop for RecordsIn {
    fn drop(&mut self) {
        self.identity_secret.zeroize();
    }
}

/// The plaintext as the signer writes it: the members in the order of Switch wire 3.12.
#[derive(Serialize)]
struct RecordsOut<'a> {
    v: u64,
    kind: &'a str,
    #[serde(with = "fmt::pubky")]
    identity: [u8; 32],
    #[serde(with = "serde_b64")]
    identity_secret: [u8; 32],
    identity_doc: &'a SignedDoc,
    revoked_apps: Vec<String>,
    certs: Vec<&'a SignedDoc>,
    limits: &'a Limits,
    bundle_parts: &'a [StoredPart],
    #[serde(skip_serializing_if = "Option::is_none")]
    prev: Option<String>,
}

impl Drop for RecordsOut<'_> {
    fn drop(&mut self) {
        self.identity_secret.zeroize();
    }
}

impl SignerRecords {
    /// The records a signer hands over or backs up (Switch wire 3.12, 3.13).
    ///
    /// `identity_doc` is the newest `identity.json` a service accepted from the signer, or
    /// for a backup the newest it signed. `certs` keeps exactly the certificates it
    /// references, those of its `apps` and `renewed`, from `issued`. `revoked_apps` is kept
    /// unique and ascending by text. `bundle_parts` keeps the parts stored for each listed
    /// app made for its listed certificate, each once. `prev` is a backup's: the document
    /// hash of the version `identity_doc` builds on, `None` for a first version and in a
    /// hand-over.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `identity_doc` is of another identity, a certificate it
    /// references isn't among `issued`, or more than 2,048 parts remain.
    pub fn new(
        key: IdentityKey,
        identity_doc: IdentityDoc,
        revoked_apps: &[[u8; 16]],
        issued: &[AppCert],
        limits: Limits,
        bundle_parts: &[StoredPart],
        prev: Option<[u8; 32]>,
    ) -> Result<Self> {
        if identity_doc.identity() != key.public() {
            return invalid("Switch wire 3.12: identity_doc is of another identity");
        }
        let Some(certs) = referenced_certs(&identity_doc, issued) else {
            return invalid("Switch wire 3.12: a certificate identity_doc references isn't held");
        };
        let bundle_parts = listed_parts(&identity_doc, bundle_parts, true)?;
        Ok(Self {
            key,
            certs,
            revoked_apps: as_set(revoked_apps),
            limits,
            bundle_parts,
            prev,
            identity_doc,
        })
    }

    /// Read the records from their JSON, the parts concatenated: checks 1 and 2 of Switch
    /// wire 3.12 that need no envelope. `v`, `kind` and `identity` are right and
    /// `identity_secret` is the secret of the identity's key (1); `identity_doc` verifies
    /// for the identity, every certificate it lists in `apps` and `renewed` is among `certs`,
    /// and each of `certs` verifies for the identity (2). A certificate it doesn't reference
    /// is dropped; so are `bundle_parts` entries for an app or a certificate it doesn't
    /// list, and repeated ones. Unknown members are ignored.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] or [`Error::Signature`] naming the check that failed; the text
    /// never quotes the plaintext.
    pub fn parse(json: &[u8], identity: &[u8; 32]) -> Result<Self> {
        let wire: RecordsIn = parse_json(json).map_err(|e| at_check(1, e))?;
        if wire.v != 1 {
            return invalid("Switch wire 3.12 check 1: v isn't 1");
        }
        if wire.kind != HANDOVER_KIND {
            return invalid("Switch wire 3.12 check 1: kind isn't pubky-switch.signer_handover");
        }
        if crate::enc::pubky_key(&wire.identity).ok().as_ref() != Some(identity) {
            return invalid("Switch wire 3.12 check 1: another identity");
        }
        let secret = Zeroizing::new(
            unb64_array::<32>(&wire.identity_secret)
                .map_err(|_| Error::Invalid("Switch wire 3.12 check 1: identity_secret".into()))?,
        );
        let key = IdentityKey::from_secret(*secret);
        if &key.public() != identity {
            return invalid("Switch wire 3.12 check 1: identity_secret isn't the identity key's");
        }
        let identity_doc =
            IdentityDoc::verify(&wire.identity_doc, identity).map_err(|e| at_check(2, e))?;
        let all = wire
            .certs
            .iter()
            .map(|signed| AppCert::verify(signed, identity))
            .collect::<Result<Vec<_>>>()
            .map_err(|e| at_check(2, e))?;
        let Some(certs) = referenced_certs(&identity_doc, &all) else {
            return invalid(
                "Switch wire 3.12 check 2: a certificate identity_doc lists isn't among certs",
            );
        };
        let revoked_apps = wire
            .revoked_apps
            .iter()
            .map(|text| crate::enc::app_id_decode(text))
            .collect::<Result<Vec<_>>>()?;
        let bundle_parts = listed_parts(&identity_doc, &wire.bundle_parts, false)?;
        let prev = wire.prev.as_deref().map(unb64_array::<32>).transpose()?;
        Ok(Self {
            key,
            identity_doc,
            revoked_apps: as_set(&revoked_apps),
            certs,
            limits: wire.limits,
            bundle_parts,
            prev,
        })
    }

    /// The records' JSON, compact, with the members in the order of Switch wire 3.12, `prev`
    /// only when present. It holds the identity secret, so it is zeroized when dropped.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if it can't be written.
    pub fn to_json(&self) -> Result<Zeroizing<Vec<u8>>> {
        let out = RecordsOut {
            v: 1,
            kind: HANDOVER_KIND,
            identity: self.key.public(),
            identity_secret: self.key.secret_bytes(),
            identity_doc: self.identity_doc.signed(),
            revoked_apps: self
                .revoked_apps
                .iter()
                .map(|id| zbase32_encode(id))
                .collect(),
            certs: self.certs.iter().map(AppCert::signed).collect(),
            limits: &self.limits,
            bundle_parts: &self.bundle_parts,
            prev: self.prev.map(|hash| b64(&hash)),
        };
        serde_json::to_vec(&out).map(Zeroizing::new).map_err(|_| {
            Error::Invalid("Switch wire 3.12: the records can't be written as JSON".into())
        })
    }

    /// The identity key. Sensitive.
    pub fn key(&self) -> &IdentityKey {
        &self.key
    }

    /// The handed-over `identity.json`: its version, generation and document hash are the
    /// old signer's high-water mark.
    pub fn identity_doc(&self) -> &IdentityDoc {
        &self.identity_doc
    }

    /// The App IDs revoked or departed, kept for good, ascending by text.
    pub fn revoked_apps(&self) -> &[[u8; 16]] {
        &self.revoked_apps
    }

    /// The certificates `identity_doc` references, those of `apps` then `renewed`.
    pub fn certs(&self) -> &[AppCert] {
        &self.certs
    }

    /// The switch's limits, from its enrollment answer.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The key bundle parts stored for the listed apps, made for their listed certificates.
    /// The receiver counts these ranges as stored for that certificate (Switch wire 3.5).
    pub fn bundle_parts(&self) -> &[StoredPart] {
        &self.bundle_parts
    }

    /// A backup's `prev`: the document hash of the version `identity_doc` builds on.
    pub fn prev(&self) -> Option<[u8; 32]> {
        self.prev
    }
}

/// The certificates `doc` references, those of its `apps` then its `renewed`, each once,
/// from `held`; `None` when one isn't held.
fn referenced_certs(doc: &IdentityDoc, held: &[AppCert]) -> Option<Vec<AppCert>> {
    let body = doc.body();
    let mut certs: Vec<AppCert> = Vec::new();
    for hash in body
        .apps
        .iter()
        .map(|app| app.cert)
        .chain(body.renewed.iter().map(|renewed| renewed.cert))
    {
        let cert = held.iter().find(|cert| cert.hash() == hash)?;
        if !certs.iter().any(|kept| kept.hash() == hash) {
            certs.push(cert.clone());
        }
    }
    Some(certs)
}

/// The parts of `parts` stored for an app `doc` lists and made for its listed certificate,
/// each once, in order; refused for more than 2,048 entries.
///
/// A writer (`strict`) also refuses a range that isn't from 1, first at most last. A reader
/// drops such an entry instead, as it drops one for an app or a certificate `doc` doesn't
/// list: a part left out is one the receiver can't tell, so it only stores it again (Switch
/// wire 3.12 `bundle_parts`).
fn listed_parts(doc: &IdentityDoc, parts: &[StoredPart], strict: bool) -> Result<Vec<StoredPart>> {
    if parts.len() > MAX_BUNDLE_PARTS {
        return invalid("Switch wire 3.12: more than 2,048 bundle_parts");
    }
    let mut kept: Vec<StoredPart> = Vec::new();
    for part in parts {
        let well_formed = part.first_epoch != 0 && part.first_epoch <= part.last_epoch;
        if !well_formed {
            if strict {
                return invalid(
                    "Switch wire 3.12: a bundle part's range isn't from 1, first at most last",
                );
            }
            continue;
        }
        if doc.listed_cert(&part.app_id) == Some(part.cert) && !kept.contains(part) {
            kept.push(*part);
        }
    }
    Ok(kept)
}

/// App IDs as a set, ascending by their text (Switch wire 3.7, 3.12).
fn as_set(ids: &[[u8; 16]]) -> Vec<[u8; 16]> {
    let mut texts: Vec<(String, [u8; 16])> =
        ids.iter().map(|id| (zbase32_encode(id), *id)).collect();
    texts.sort();
    texts.dedup();
    texts.into_iter().map(|(_, id)| id).collect()
}

/// `error`, its text prefixed with the check of Switch wire 3.12 that refused it.
fn at_check(check: u8, error: Error) -> Error {
    let prefix = |why: String| format!("Switch wire 3.12 check {check}: {why}");
    match error {
        Error::Invalid(why) => Error::Invalid(prefix(why)),
        Error::Signature(why) => Error::Signature(prefix(why)),
        Error::Crypto(why) => Error::Crypto(prefix(why)),
    }
}

/// Envelopes and their signature, as a hand-over and a backup carry them: `{ "envelopes":
/// [b64], "sig": b64 }`. Readers ignore unknown members (Switch wire 1.1).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SealedParts {
    #[serde(serialize_with = "b64_list", deserialize_with = "unb64_list")]
    envelopes: Vec<Vec<u8>>,
    #[serde(with = "serde_b64")]
    sig: [u8; 64],
}

fn b64_list<S: Serializer>(list: &[Vec<u8>], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.collect_seq(list.iter().map(|bytes| b64(bytes)))
}

fn unb64_list<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<Vec<u8>>, D::Error> {
    use serde::de::Error as _;
    Vec::<String>::deserialize(d)?
        .iter()
        .map(|text| unb64(text).map_err(|_| D::Error::custom("an envelope isn't base64url")))
        .collect()
}

impl SealedParts {
    /// Split `json` into parts of at most the largest framed JSON, seal each to
    /// `recipient` and sign them (Switch wire 3.12 "Parts").
    fn seal(
        key: &IdentityKey,
        target: Option<&[u8; 16]>,
        recipient: &Recipient,
        json: &[u8],
    ) -> Result<Self> {
        let identity = key.public();
        let parts: Vec<&[u8]> = json.chunks(MAX_FRAMED_JSON_LEN).collect();
        check_count(parts.len())?;
        let envelopes = parts
            .iter()
            .map(|part| envelope::seal_framed(&identity, recipient, part))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self::signed(key, target, envelopes))
    }

    #[cfg(any(test, feature = "test-vectors"))]
    fn seal_with(
        key: &IdentityKey,
        target: Option<&[u8; 16]>,
        recipient: &Recipient,
        parts: &[&[u8]],
        randomness: &[envelope::FixedRandomness],
    ) -> Result<Self> {
        check_count(parts.len())?;
        if randomness.len() != parts.len() {
            return invalid("Switch wire 3.12: one fixed randomness per part");
        }
        let identity = key.public();
        let envelopes = parts
            .iter()
            .zip(randomness)
            .map(|(part, fixed)| fixed.seal_framed(&identity, recipient, part))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self::signed(key, target, envelopes))
    }

    fn signed(key: &IdentityKey, target: Option<&[u8; 16]>, envelopes: Vec<Vec<u8>>) -> Self {
        let identity = key.public();
        let count = count_bytes(envelopes.len());
        let sig = match target {
            Some(app_id) => key.sign(
                labels::sig::SIGNER_HANDOVER,
                &fields(&identity, Some(app_id), &count, &envelopes),
            ),
            None => key.sign(
                labels::sig::SIGNER_BACKUP,
                &fields(&identity, None, &count, &envelopes),
            ),
        };
        Self { envelopes, sig }
    }

    /// Check 1's count and signature.
    fn verify(&self, identity: &[u8; 32], target: Option<&[u8; 16]>) -> Result<()> {
        check_count(self.envelopes.len())?;
        let count = count_bytes(self.envelopes.len());
        let label = match target {
            Some(_) => labels::sig::SIGNER_HANDOVER,
            None => labels::sig::SIGNER_BACKUP,
        };
        sig::verify(
            identity,
            label,
            &fields(identity, target, &count, &self.envelopes),
            &self.sig,
        )
        .map_err(|e| at_check(1, e))
    }

    /// Open every envelope with `secret` and concatenate the parts, in order (check 1).
    fn open(&self, identity: &[u8; 32], secret: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        let mut json = Zeroizing::new(Vec::new());
        for envelope in &self.envelopes {
            let part =
                envelope::open_framed(envelope, identity, secret).map_err(|e| at_check(1, e))?;
            json.extend_from_slice(&part);
        }
        Ok(json)
    }
}

impl std::fmt::Debug for SealedParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} envelopes", self.envelopes.len())
    }
}

/// 1 to 128 envelopes (Switch wire 3.12 check 1).
fn check_count(count: usize) -> Result<()> {
    if !(1..=MAX_HANDOVER_ENVELOPES).contains(&count) {
        return invalid("Switch wire 3.12 check 1: 1 to 128 envelopes");
    }
    Ok(())
}

/// `u32_be(n)`; at most 128 after [`check_count`].
fn count_bytes(count: usize) -> [u8; 4] {
    u32::try_from(count).unwrap_or(u32::MAX).to_be_bytes()
}

/// The signed fields after the label: identity, the target App ID for a hand-over,
/// `u32_be(n)`, then each envelope's bytes (Switch wire 2.3).
fn fields<'a>(
    identity: &'a [u8; 32],
    target: Option<&'a [u8; 16]>,
    count: &'a [u8; 4],
    envelopes: &'a [Vec<u8>],
) -> Vec<&'a [u8]> {
    let mut out: Vec<&[u8]> = vec![identity];
    if let Some(app_id) = target {
        out.push(app_id);
    }
    out.push(count);
    out.extend(envelopes.iter().map(Vec::as_slice));
    out
}

/// A signer hand-over (Switch wire 3.12): the signer's records, sealed in parts to the new
/// signer's certified bundle key and signed for its App ID. It travels through the switch
/// (`PUT` and `GET /v1/{id}/handover`, Switch wire 7.4.17).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignerHandover(SealedParts);

impl SignerHandover {
    /// Seal `records` to `new_signer`, the certificate of the app taking over (Switch wire
    /// 3.12). The old signer seals only to an app its newest `identity.json` lists as current
    /// with that certificate; that the version is delivered, that no closing delivery is
    /// owed and that no move is under way are the caller's to check. From then on it is
    /// handing over: it signs nothing for the identity but an abort ([`abort_body`]).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `records` or `new_signer` are of another identity, the
    /// records' `identity_doc` doesn't list `new_signer`, or the JSON needs more than 64
    /// parts; [`Error::Crypto`] as [`envelope::seal`].
    pub fn seal(key: &IdentityKey, new_signer: &AppCert, records: &SignerRecords) -> Result<Self> {
        let identity = key.public();
        if records.key.public() != identity || new_signer.identity() != identity {
            return invalid(
                "Switch wire 3.12: the records or the new signer are of another identity",
            );
        }
        if records.identity_doc.listed_cert(&new_signer.app_id()) != Some(new_signer.hash()) {
            return invalid(
                "Switch wire 3.12: the new signer isn't a current app with this certificate",
            );
        }
        let json = records.to_json()?;
        SealedParts::seal(
            key,
            Some(&new_signer.app_id()),
            &Recipient::new(new_signer.bundle_key()),
            &json,
        )
        .map(Self)
    }

    /// Seal the given parts of a JSON, in order, to `bundle_key` for the app `target`, with
    /// fixed randomness per part, and sign them, to rebuild the shared vectors. Test builds
    /// only.
    ///
    /// # Errors
    ///
    /// As [`SignerHandover::seal`].
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn seal_parts_with(
        key: &IdentityKey,
        target: &[u8; 16],
        bundle_key: &[u8; 32],
        parts: &[&[u8]],
        randomness: &[envelope::FixedRandomness],
    ) -> Result<Self> {
        SealedParts::seal_with(
            key,
            Some(target),
            &Recipient::new(*bundle_key),
            parts,
            randomness,
        )
        .map(Self)
    }

    /// A hand-over from its envelopes and signature, as the new signer receives it.
    pub fn from_parts(envelopes: Vec<Vec<u8>>, sig: [u8; 64]) -> Self {
        Self(SealedParts { envelopes, sig })
    }

    /// The envelopes, in order.
    pub fn envelopes(&self) -> &[Vec<u8>] {
        &self.0.envelopes
    }

    /// The identity key's signature.
    pub fn sig(&self) -> [u8; 64] {
        self.0.sig
    }

    /// Check 1's count and signature: 1 to 128 envelopes, and `sig` verifies with the
    /// identity key over `target`, their number and their bytes, in order.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a count outside 1 to 128, [`Error::Signature`] for a signature
    /// that doesn't verify.
    pub fn verify(&self, identity: &[u8; 32], target: &[u8; 16]) -> Result<()> {
        self.0.verify(identity, Some(target))
    }

    /// The switch's checks when the signer stores the hand-over for `target`, a current app,
    /// without opening anything (Switch wire 7.4.17): 1 to 128 envelopes, each passing the
    /// inbox's checks (Switch wire 4.4) with one recipient, the kid of `target`'s certified
    /// bundle key, and the signature over `target`, the count and the bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] naming the rule that fails, [`Error::Signature`] for the signature.
    pub fn check_stored(
        &self,
        identity: &[u8; 32],
        target: &[u8; 16],
        target_bundle_key: &[u8; 32],
    ) -> Result<()> {
        check_count(self.0.envelopes.len())?;
        let bundle_kid = kid(target_bundle_key);
        for envelope in &self.0.envelopes {
            let header = envelope::check_at_inbox(envelope)?;
            if header.kids().ne([bundle_kid]) {
                return invalid(
                    "Switch wire 7.4.17: an envelope isn't for the target's certified bundle key alone",
                );
            }
        }
        self.verify(identity, target)
    }

    /// The new signer's checks 1 and 2 (Switch wire 3.12), refusing at the first failure:
    /// the count and the signature over its own App ID `app_id`; every envelope opens with
    /// its bundle secret and the parts, concatenated in order, parse as the records
    /// ([`SignerRecords::parse`]); and `identity_doc` lists the new signer's app. Check 3 is
    /// [`check_handover_copies`].
    ///
    /// A new signer that refuses a hand-over once an envelope has opened deletes what it
    /// received and tells the user; nothing here keeps a copy of the secret.
    ///
    /// # Errors
    ///
    /// The error of the first check that fails, its text naming the check.
    pub fn open(
        &self,
        identity: &[u8; 32],
        app_id: &[u8; 16],
        bundle_secret: &[u8; 32],
    ) -> Result<SignerRecords> {
        self.verify(identity, app_id)?;
        let json = self.0.open(identity, bundle_secret)?;
        let records = SignerRecords::parse(&json, identity)?;
        if records.identity_doc.listed_cert(app_id).is_none() {
            return invalid(
                "Switch wire 3.12 check 2: identity_doc doesn't list the new signer's app",
            );
        }
        Ok(records)
    }
}

/// The new signer's check 3 (Switch wire 3.12): neither the switch's copy of
/// `identity.json` (`GET /apps` `identity`, Switch wire 7.4.12) nor the Homeserver's is newer
/// than the handed-over one, by version or generation, or another document at its version.
/// An abort that won fails it.
///
/// # Errors
///
/// [`Error::Invalid`] naming the copy's fault.
pub fn check_handover_copies(records: &SignerRecords, copies: &[&IdentityDoc]) -> Result<()> {
    for copy in copies {
        check_not_ahead(&records.identity_doc, copy, "Switch wire 3.12 check 3")?;
    }
    Ok(())
}

/// A copy is neither newer than `held`, by version or generation, nor another document at
/// its version. Documents are compared whole (Switch wire 2.1, "Sign once").
fn check_not_ahead(held: &IdentityDoc, copy: &IdentityDoc, section: &str) -> Result<()> {
    if copy.version() > held.version() || copy.generation() > held.generation() {
        return invalid(format!("{section}: a copy of identity.json is newer"));
    }
    if copy.version() == held.version() && copy.signed() != held.signed() {
        return invalid(format!(
            "{section}: another identity.json at the same version"
        ));
    }
    Ok(())
}

/// The App IDs the new signer, or a restored install, takes as revoked (Switch wire 3.12,
/// 3.13): those of `revoked_apps`, of `identity_doc`'s `removed`, and those the switch's
/// `GET /apps` shows revoked or departed, each once, ascending by text.
pub fn revoked_after(records: &SignerRecords, switch_revoked: &[[u8; 16]]) -> Vec<[u8; 16]> {
    let all: Vec<[u8; 16]> = records
        .revoked_apps
        .iter()
        .copied()
        .chain(records.identity_doc.body().removed.iter().map(|r| r.app_id))
        .chain(switch_revoked.iter().copied())
        .collect();
    as_set(&all)
}

/// The new signer's first delivery (Switch wire 3.12), and a restore's next one (3.13):
/// `identity_doc`'s content at its version plus 1, naming `signer`, its own install's ID,
/// and the `prev` it delivers with, the document hash of `identity_doc` (Switch wire 7.4.2).
/// The hand-over takes effect when that delivery wins the compare-and-swap.
///
/// # Errors
///
/// [`Error::Invalid`] past the integer range.
pub fn take_over_body(
    records: &SignerRecords,
    signer: [u8; 16],
) -> Result<(IdentityBody, [u8; 32])> {
    let mut body = records.identity_doc.body().clone();
    body.version = body
        .version
        .checked_add(1)
        .ok_or_else(|| Error::Invalid("Switch wire 3.12: the version can't grow".into()))?;
    body.signer = signer;
    Ok((body, records.identity_doc.hash()))
}

/// The old signer's abort (Switch wire 3.12, Switch spec 12.8), until the hand-over takes
/// effect: `identity_doc`'s content again at its version plus 2, never plus 1, so it never
/// shares a version with the new signer's first one, and its `prev`, the document hash of
/// `identity_doc`. Both build on that hash, so exactly one wins the compare-and-swap. The
/// abort is signed once and sent again, the same bytes, after a lost answer.
///
/// # Errors
///
/// [`Error::Invalid`] past the integer range.
pub fn abort_body(identity_doc: &IdentityDoc) -> Result<(IdentityBody, [u8; 32])> {
    let mut body = identity_doc.body().clone();
    body.version = body
        .version
        .checked_add(2)
        .ok_or_else(|| Error::Invalid("Switch wire 3.12: the version can't grow".into()))?;
    Ok((body, identity_doc.hash()))
}

/// What the new signer's take-over delivery came to (Switch wire 3.12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TakeOver {
    /// It won the compare-and-swap, a retry of the same bytes included: the new signer is
    /// the signer. It writes its backup now (Switch wire 3.13).
    Effective,
    /// `409 stale_identity`: an abort, or another signer, got ahead. The new signer deletes
    /// `identity_secret` and the records it received, and tells the user.
    Cancelled,
}

impl TakeOver {
    /// Read the delivery's answer: a `2xx` makes it take effect, `409 stale_identity`
    /// cancels it, and any other answer decides nothing yet (`None`): the delivery is sent
    /// again, the same bytes.
    pub fn from_answer(status: u16, code: Option<&str>) -> Option<Self> {
        match (status, code) {
            (200..=299, _) => Some(Self::Effective),
            (409, Some("stale_identity")) => Some(Self::Cancelled),
            _ => None,
        }
    }
}

/// Whether the old signer has been succeeded (Switch wire 3.12, Switch spec 12.8): a copy of
/// `identity.json` at `version` with document hash `hash`, from the switch or the `current`
/// of a `409 stale_identity` that answers its abort, is newer than the handed-over version
/// and isn't one it delivered. Then it deletes the key and its records. It never takes its
/// own abort, held at the switch, for the new signer's version: `delivered` holds the
/// abort's hash too.
pub fn succeeded(
    handed_over: &IdentityDoc,
    delivered: &[[u8; 32]],
    version: u64,
    hash: &[u8; 32],
) -> bool {
    version > handed_over.version() && !delivered.contains(hash)
}

/// A signer backup (Switch wire 3.13): the signer's records sealed in parts to the identity's
/// backup key and signed, kept on the Homeserver at
/// [`super::SIGNER_BACKUP_PATH`]. It is public ciphertext: anyone sees its size and when it
/// changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignerBackup(SealedParts);

impl SignerBackup {
    /// Seal `records` to the backup key of `key`'s identity and sign them (Switch wire 3.13).
    /// `records` holds the newest version the signer signed, and its `prev`.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `records` are of another identity or need more than 64
    /// parts; [`Error::Crypto`] as [`envelope::seal`].
    pub fn seal(key: &IdentityKey, records: &SignerRecords) -> Result<Self> {
        if records.key.public() != key.public() {
            return invalid("Switch wire 3.13: the records are of another identity");
        }
        let json = records.to_json()?;
        SealedParts::seal(key, None, &Recipient::new(key.backup_public()), &json).map(Self)
    }

    /// Seal the given parts, in order, to the identity's backup key with fixed randomness per
    /// part, and sign them, to rebuild the shared vectors. Test builds only.
    ///
    /// # Errors
    ///
    /// As [`SignerBackup::seal`].
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn seal_parts_with(
        key: &IdentityKey,
        parts: &[&[u8]],
        randomness: &[envelope::FixedRandomness],
    ) -> Result<Self> {
        SealedParts::seal_with(
            key,
            None,
            &Recipient::new(key.backup_public()),
            parts,
            randomness,
        )
        .map(Self)
    }

    /// A backup from its envelopes and signature, as it is read from the Homeserver.
    pub fn from_parts(envelopes: Vec<Vec<u8>>, sig: [u8; 64]) -> Self {
        Self(SealedParts { envelopes, sig })
    }

    /// The envelopes, in order.
    pub fn envelopes(&self) -> &[Vec<u8>] {
        &self.0.envelopes
    }

    /// The identity key's signature.
    pub fn sig(&self) -> [u8; 64] {
        self.0.sig
    }

    /// The count and the signature: 1 to 128 envelopes, and `sig` verifies with the identity
    /// key over their number and their bytes, in order.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a count outside 1 to 128, [`Error::Signature`] for a signature
    /// that doesn't verify.
    pub fn verify(&self, identity: &[u8; 32]) -> Result<()> {
        self.0.verify(identity, None)
    }

    /// Open the backup with the identity key, as a restore checks it (Switch wire 3.13
    /// "Restoring"): a new signer's checks 1 and 2 with the backup's label and fields and the
    /// backup key derived from `key`, without asking that `identity_doc` list an app of the
    /// restoring install's own. Check 3 is [`check_restore_copies`].
    ///
    /// # Errors
    ///
    /// The error of the first check that fails.
    pub fn open(&self, key: &IdentityKey) -> Result<SignerRecords> {
        let identity = key.public();
        self.verify(&identity)?;
        let secret = Zeroizing::new(key.backup_secret());
        let json = self.0.open(&identity, &secret)?;
        SignerRecords::parse(&json, &identity)
    }
}

/// Where a restore starts (Switch wire 3.13, check 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreStart {
    /// The switch holds `identity_doc` itself: the install delivers the next version.
    AtBackup,
    /// The switch holds the version whose document hash is `prev`, or no copy under a backup
    /// of the account's first document: the signer stopped between writing the backup and
    /// delivering, so the restore delivers `identity_doc` first, then the next version.
    DeliverBackupFirst,
}

/// A restore's check 3 (Switch wire 3.13): the switch's copy (`GET /apps` `identity`) is
/// `identity_doc` itself, or the version whose document hash is `prev`; a switch with no
/// copy counts as at `prev` only when the backup has none; and the Homeserver's copy is
/// neither newer than `identity_doc` nor another one at its version. Any other copy makes
/// the backup stale.
///
/// # Errors
///
/// [`Error::Invalid`] naming why the restore is refused.
pub fn check_restore_copies(
    records: &SignerRecords,
    switch_copy: Option<&IdentityDoc>,
    homeserver_copy: Option<&IdentityDoc>,
) -> Result<RestoreStart> {
    let start = match switch_copy {
        Some(copy) if copy.signed() == records.identity_doc.signed() => RestoreStart::AtBackup,
        Some(copy) if records.prev == Some(copy.hash()) => RestoreStart::DeliverBackupFirst,
        Some(_) => {
            return invalid(
                "Switch wire 3.13 check 3: the switch holds neither the backup's version nor the one it builds on",
            );
        }
        None if records.prev.is_none() => RestoreStart::DeliverBackupFirst,
        None => {
            return invalid(
                "Switch wire 3.13 check 3: the switch holds no copy, and the backup builds on one",
            );
        }
    };
    if let Some(copy) = homeserver_copy {
        check_not_ahead(&records.identity_doc, copy, "Switch wire 3.13 check 3")?;
    }
    Ok(start)
}

/// Whether a backup found before writing shows that another install has taken over (Switch
/// wire 3.13 "Another install's backup"): it names another install than `own_signer` at or
/// past `own_newest`, the newest version a service accepted from this signer. Then the
/// signer writes nothing and refuses this and every later signing call.
pub fn taken_over(found: &SignerRecords, own_signer: &[u8; 16], own_newest: u64) -> bool {
    &found.identity_doc.body().signer != own_signer && found.identity_doc.version() >= own_newest
}

/// A delivery of a new `identity.json` version, by when it writes the backup (Switch wire
/// 3.13 "When it is written").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryKind {
    /// An ordinary new version.
    NewVersion,
    /// A new signer's first version after a hand-over.
    TakeOver,
    /// A restored install's deliveries.
    Restore,
    /// An old signer's abort.
    Abort,
}

impl DeliveryKind {
    /// Whether the backup is written before the delivery, holding its version, so it is
    /// never behind the switch's copy and a write that fails stops the delivery; otherwise,
    /// for the deliveries that race another signer, once the delivery has won, so one that
    /// loses never overwrites the winner's backup.
    pub fn backup_before(self) -> bool {
        matches!(self, Self::NewVersion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handover_count_takes_one_to_128_envelopes() {
        assert!(check_count(1).is_ok());
        assert!(check_count(MAX_HANDOVER_ENVELOPES).is_ok());
        assert_eq!(MAX_HANDOVER_ENVELOPES, 128);
        assert!(check_count(0).is_err());
        assert!(check_count(MAX_HANDOVER_ENVELOPES + 1).is_err());
    }
    use crate::records::fixtures::{app, cert, cert_body_for, identity, other_app};
    use crate::records::{IdentityPolicy, Inbox, ListedApp, RemovedApp, RenewedCert};

    fn certs() -> (AppCert, AppCert) {
        let mine = cert(&["scope-a"]);
        let other = AppCert::issue(&identity(), cert_body_for(&other_app(), &["scope-a"])).unwrap();
        (mine, other)
    }

    fn doc(version: u64, listed: &[&AppCert]) -> IdentityDoc {
        let mut body = IdentityBody::first(
            identity().public(),
            [1; 16],
            Inbox::new("https://inbox.example", [5; 32]),
            IdentityPolicy::default(),
        );
        body.version = version;
        for cert in listed {
            body.apps.push(ListedApp {
                app_id: cert.app_id(),
                cert: cert.hash(),
            });
        }
        body.removed.push(RemovedApp {
            app_id: [3; 16],
            distrust_from: 1,
        });
        IdentityDoc::sign(&identity(), body).unwrap()
    }

    fn records(prev: Option<[u8; 32]>) -> SignerRecords {
        let (mine, other) = certs();
        let d = doc(3, &[&mine, &other]);
        let part = StoredPart {
            app_id: other.app_id(),
            first_epoch: 1,
            last_epoch: 1,
            cert: other.hash(),
        };
        let stray = StoredPart {
            cert: [9; 32],
            ..part
        };
        SignerRecords::new(
            identity(),
            d,
            &[[2; 16], [1; 16], [2; 16]],
            &[other.clone(), mine.clone(), other],
            Limits::default(),
            &[part, stray, part],
            prev,
        )
        .unwrap()
    }

    #[test]
    fn test_handover_records_round_trip_in_table_order() {
        let r = records(None);
        assert_eq!(r.certs().len(), 2, "each referenced certificate once");
        assert_eq!(r.bundle_parts().len(), 1, "listed and once");
        assert_eq!(r.revoked_apps().len(), 2);
        let json = r.to_json().unwrap();
        let text = std::str::from_utf8(&json).unwrap();
        assert!(text.starts_with(r#"{"v":1,"kind":"pubky-switch.signer_handover","identity":""#));
        assert!(text.contains(r#","identity_secret":""#));
        assert!(text.contains(r#","limits":{"app_limit":32,"#));
        assert!(!text.contains("prev"));
        let back = SignerRecords::parse(&json, &identity().public()).unwrap();
        assert_eq!(*back.to_json().unwrap(), *json);
        assert!(!format!("{back:?}").contains(&b64(&identity().secret_bytes())));

        let with_prev = records(Some([4; 32]));
        let json = with_prev.to_json().unwrap();
        assert!(
            std::str::from_utf8(&json)
                .unwrap()
                .ends_with(&format!(r#","prev":"{}"}}"#, b64(&[4; 32])))
        );
        assert_eq!(
            SignerRecords::parse(&json, &identity().public())
                .unwrap()
                .prev(),
            Some([4; 32])
        );
    }

    #[test]
    fn test_handover_records_refuse_each_check() {
        let good: serde_json::Value =
            serde_json::from_slice(&records(None).to_json().unwrap()).unwrap();
        let refuse = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut v = good.clone();
            change(&mut v);
            SignerRecords::parse(&serde_json::to_vec(&v).unwrap(), &identity().public())
                .unwrap_err()
                .to_string()
        };
        assert!(refuse(&|v| v["v"] = 2.into()).contains("check 1"));
        assert!(refuse(&|v| v["kind"] = "other.kind".into()).contains("check 1"));
        let stranger = IdentityKey::from_secret([9; 32]);
        assert!(refuse(&|v| v["identity"] = stranger.id().into()).contains("check 1"));
        assert!(refuse(&|v| v["identity_secret"] = b64(&[9; 32]).into()).contains("check 1"));
        let other_doc = serde_json::to_value(doc(4, &[]).signed()).unwrap();
        // A document listing an app whose certificate isn't among certs.
        let (mine, _) = certs();
        let unknown = AppCert::issue(
            &identity(),
            crate::records::fixtures::cert_body(&["scope-b"]),
        )
        .unwrap();
        let listing_unknown = serde_json::to_value(doc(3, &[&unknown]).signed()).unwrap();
        assert!(refuse(&|v| v["identity_doc"] = listing_unknown.clone()).contains("check 2"));
        let mut forged = good["identity_doc"].clone();
        forged["sig"] = b64(&[0; 64]).into();
        assert!(refuse(&|v| v["identity_doc"] = forged.clone()).contains("check 2"));
        let mut bad_cert = good["certs"][0].clone();
        bad_cert["sig"] = b64(&[0; 64]).into();
        assert!(refuse(&|v| v["certs"][0] = bad_cert.clone()).contains("check 2"));
        // A malformed bundle part, an unreferenced certificate and a document without apps
        // are dropped, not refused.
        let mut v = good.clone();
        v["bundle_parts"][0]["first_epoch"] = 0.into();
        let r =
            SignerRecords::parse(&serde_json::to_vec(&v).unwrap(), &identity().public()).unwrap();
        assert!(r.bundle_parts().is_empty());
        let mut bad_range = r.bundle_parts().to_vec();
        bad_range.push(StoredPart {
            app_id: certs().0.app_id(),
            first_epoch: 2,
            last_epoch: 1,
            cert: certs().0.hash(),
        });
        let d = doc(3, &[&certs().0]);
        assert!(
            SignerRecords::new(
                identity(),
                d,
                &[],
                &[certs().0],
                Limits::default(),
                &bad_range,
                None
            )
            .is_err()
        );
        let mut v = good.clone();
        v["certs"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::to_value(unknown.signed()).unwrap());
        let r =
            SignerRecords::parse(&serde_json::to_vec(&v).unwrap(), &identity().public()).unwrap();
        assert_eq!(r.certs().len(), 2);
        let mut v = good.clone();
        v["identity_doc"] = other_doc;
        SignerRecords::parse(&serde_json::to_vec(&v).unwrap(), &identity().public()).unwrap();
        // The writer refuses certificates it doesn't hold.
        assert!(
            SignerRecords::new(
                identity(),
                doc(3, &[&mine]),
                &[],
                &[],
                Limits::default(),
                &[],
                None
            )
            .is_err()
        );
        let too_many = vec![
            StoredPart {
                app_id: mine.app_id(),
                first_epoch: 1,
                last_epoch: 1,
                cert: mine.hash()
            };
            MAX_BUNDLE_PARTS + 1
        ];
        assert!(
            SignerRecords::new(
                identity(),
                doc(3, &[&mine]),
                &[],
                std::slice::from_ref(&mine),
                Limits::default(),
                &too_many,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn test_handover_seal_opens_for_the_new_signer() {
        let (mine, other) = certs();
        let r = records(None);
        let handover = SignerHandover::seal(&identity(), &mine, &r).unwrap();
        assert_eq!(handover.envelopes().len(), 1);
        let id = identity().public();
        let opened = handover
            .open(&id, &mine.app_id(), &app().bundle_secret())
            .unwrap();
        assert_eq!(*opened.to_json().unwrap(), *r.to_json().unwrap());
        handover
            .check_stored(&id, &mine.app_id(), &mine.bundle_key())
            .unwrap();
        assert!(
            handover
                .check_stored(&id, &other.app_id(), &other.bundle_key())
                .is_err()
        );
        assert!(
            handover
                .check_stored(&id, &mine.app_id(), &other.bundle_key())
                .is_err()
        );
        // Another app's App ID or bundle secret opens nothing.
        assert!(matches!(
            handover.open(&id, &other.app_id(), &app().bundle_secret()),
            Err(Error::Signature(_))
        ));
        assert!(
            handover
                .open(&id, &mine.app_id(), &other_app().bundle_secret())
                .is_err()
        );
        // Only to a listed app with its listed certificate.
        let unlisted = AppCert::issue(
            &identity(),
            crate::records::fixtures::cert_body(&["scope-b"]),
        )
        .unwrap();
        assert!(SignerHandover::seal(&identity(), &unlisted, &r).is_err());
        // Its JSON round-trips.
        let text = serde_json::to_string(&handover).unwrap();
        assert!(text.starts_with(r#"{"envelopes":[""#));
        assert_eq!(
            serde_json::from_str::<SignerHandover>(&text).unwrap(),
            handover
        );
    }

    #[test]
    fn test_handover_signature_binds_count_and_order() {
        let (mine, _) = certs();
        let r = records(None);
        let json = r.to_json().unwrap();
        let (a, b) = json.split_at(json.len() / 2);
        let fixed = |n: u8| envelope::FixedRandomness {
            content_key: [n; 32],
            nonce: [n; 24],
            ikm_e: [n.wrapping_add(1); 32],
        };
        let key = mine.bundle_key();
        let target = mine.app_id();
        let h = SignerHandover::seal_parts_with(
            &identity(),
            &target,
            &key,
            &[a, b],
            &[fixed(1), fixed(2)],
        )
        .unwrap();
        let id = identity().public();
        let secret = app().bundle_secret();
        h.open(&id, &target, &secret).unwrap();
        let envs = h.envelopes().to_vec();
        let swapped = SignerHandover::from_parts(vec![envs[1].clone(), envs[0].clone()], h.sig());
        let missing = SignerHandover::from_parts(vec![envs[0].clone()], h.sig());
        for bad in [swapped, missing] {
            let error = bad.open(&id, &target, &secret).unwrap_err();
            assert!(matches!(error, Error::Signature(_)), "{error}");
            assert!(error.to_string().contains("check 1"));
        }
        assert!(
            SignerHandover::from_parts(vec![], h.sig())
                .open(&id, &target, &secret)
                .is_err()
        );
        assert!(
            SignerHandover::from_parts(vec![envs[0].clone(); 65], h.sig())
                .verify(&id, &target)
                .is_err()
        );
        // Parts that don't parse once joined, under a valid signature.
        let half =
            SignerHandover::seal_parts_with(&identity(), &target, &key, &[a], &[fixed(3)]).unwrap();
        assert!(
            half.open(&id, &target, &secret)
                .unwrap_err()
                .to_string()
                .contains("check 1")
        );
        assert!(
            SignerHandover::seal_parts_with(&identity(), &target, &key, &[a, b], &[fixed(1)])
                .is_err()
        );
    }

    #[test]
    fn test_handover_copies_and_revoked() {
        let r = records(None);
        let held = r.identity_doc().clone();
        check_handover_copies(&r, &[&held]).unwrap();
        let (mine, other) = certs();
        let older = doc(2, &[&mine]);
        check_handover_copies(&r, &[&older]).unwrap();
        let newer = doc(4, &[&mine, &other]);
        assert!(check_handover_copies(&r, &[&older, &newer]).is_err());
        let beside = doc(3, &[&mine]);
        assert!(check_handover_copies(&r, &[&beside]).is_err());
        let mut later_generation = held.body().clone();
        later_generation.version = 2;
        later_generation.generation = 2;
        let later_generation = IdentityDoc::sign(&identity(), later_generation).unwrap();
        assert!(check_handover_copies(&r, &[&later_generation]).is_err());

        let revoked = revoked_after(&r, &[[1; 16], [7; 16]]);
        let expected = as_set(&[[1; 16], [2; 16], [3; 16], [7; 16]]);
        assert_eq!(revoked, expected);
    }

    #[test]
    fn test_handover_take_over_and_abort_versions() {
        let r = records(None);
        let (body, prev) = take_over_body(&r, [8; 16]).unwrap();
        assert_eq!(body.version, 4);
        assert_eq!(body.signer, [8; 16]);
        assert_eq!(prev, r.identity_doc().hash());
        let (abort, prev) = abort_body(r.identity_doc()).unwrap();
        assert_eq!(abort.version, 5);
        assert_eq!(abort.signer, r.identity_doc().body().signer);
        assert_eq!(prev, r.identity_doc().hash());
        let mut end = r.identity_doc().body().clone();
        end.version = u64::MAX - 1;
        let end = IdentityDoc::sign(&identity(), end).unwrap();
        assert!(abort_body(&end).is_err());

        assert_eq!(TakeOver::from_answer(200, None), Some(TakeOver::Effective));
        assert_eq!(
            TakeOver::from_answer(409, Some("stale_identity")),
            Some(TakeOver::Cancelled)
        );
        assert_eq!(TakeOver::from_answer(409, Some("conflict")), None);
        assert_eq!(TakeOver::from_answer(503, None), None);

        let handed = r.identity_doc();
        let abort_doc = IdentityDoc::sign(&identity(), abort).unwrap();
        assert!(!succeeded(
            handed,
            &[abort_doc.hash()],
            5,
            &abort_doc.hash()
        ));
        assert!(succeeded(handed, &[abort_doc.hash()], 4, &[6; 32]));
        assert!(!succeeded(handed, &[], 3, &handed.hash()));
    }

    #[test]
    fn test_backup_round_trip_and_restore_checks() {
        let first_hash = doc(1, &[]).hash();
        let r = records(Some(first_hash));
        let backup = SignerBackup::seal(&identity(), &r).unwrap();
        let opened = backup.open(&identity()).unwrap();
        assert_eq!(*opened.to_json().unwrap(), *r.to_json().unwrap());
        assert!(backup.open(&IdentityKey::from_secret([9; 32])).is_err());
        // A hand-over's signature isn't a backup's.
        let (mine, _) = certs();
        let handover = SignerHandover::seal(&identity(), &mine, &r).unwrap();
        let as_backup = SignerBackup::from_parts(handover.envelopes().to_vec(), handover.sig());
        assert!(matches!(
            as_backup.verify(&identity().public()),
            Err(Error::Signature(_))
        ));

        let held = opened.identity_doc().clone();
        let at_prev = doc(1, &[]);
        assert_eq!(
            check_restore_copies(&opened, Some(&held), None).unwrap(),
            RestoreStart::AtBackup
        );
        assert_eq!(
            check_restore_copies(&opened, Some(&at_prev), Some(&held)).unwrap(),
            RestoreStart::DeliverBackupFirst
        );
        let stale = doc(2, &[]);
        assert!(check_restore_copies(&opened, Some(&stale), None).is_err());
        assert!(check_restore_copies(&opened, None, None).is_err());
        let newer = doc(4, &[]);
        assert!(check_restore_copies(&opened, Some(&held), Some(&newer)).is_err());
        let first = records(None);
        assert_eq!(
            check_restore_copies(&first, None, None).unwrap(),
            RestoreStart::DeliverBackupFirst
        );

        assert!(taken_over(&opened, &[8; 16], 3));
        assert!(!taken_over(&opened, &[8; 16], 4));
        assert!(!taken_over(&opened, &[1; 16], 3));
        assert!(DeliveryKind::NewVersion.backup_before());
        for kind in [
            DeliveryKind::TakeOver,
            DeliveryKind::Restore,
            DeliveryKind::Abort,
        ] {
            assert!(!kind.backup_before());
        }
    }

    #[test]
    fn test_handover_splits_large_records_into_parts() {
        let (mine, other) = certs();
        let mut body = doc(3, &[&mine, &other]).body().clone();
        let mut renewed = Vec::new();
        // Many renewed certificates make a JSON over one envelope.
        for i in 0..100u64 {
            let mut b = cert_body_for(&other_app(), &["scope-a"]);
            b.issued_at -= i + 1;
            let c = AppCert::issue(&identity(), b).unwrap();
            body.renewed.push(RenewedCert {
                app_id: c.app_id(),
                cert: c.hash(),
                until: None,
            });
            renewed.push(c);
        }
        let d = IdentityDoc::sign(&identity(), body).unwrap();
        let mut issued = vec![mine.clone(), other];
        issued.extend(renewed);
        let r =
            SignerRecords::new(identity(), d, &[], &issued, Limits::default(), &[], None).unwrap();
        assert!(r.to_json().unwrap().len() > MAX_FRAMED_JSON_LEN);
        let handover = SignerHandover::seal(&identity(), &mine, &r).unwrap();
        assert_eq!(handover.envelopes().len(), 2);
        let opened = handover
            .open(&identity().public(), &mine.app_id(), &app().bundle_secret())
            .unwrap();
        assert_eq!(opened.certs().len(), 102);
    }
}
