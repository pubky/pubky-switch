//! The approval (Switch wire 3.10, Switch spec 3.2 and 3.5): what the signer returns to an
//! approved app, as the companion claim of its Pubky grant approval.
//!
//! It carries only public material and one sealed key bundle: the hash of the app request
//! it answers, the app's certificate, the `identity.json` that lists it, and the app's full
//! key bundle, in parts, sealed to its certified bundle key. Whoever holds the auth
//! request's secret, and so can read the claim from the relay, learns no key.
//!
//! The companion claim's signed bytes are not an `lp()` input: the identity key signs
//! `UTF8("x-pubky-switch-claim|pubky-switch.v1.approval|") || SHA-256(auth secret) ||
//! approval JSON bytes`, and the claim's plaintext is the JSON bytes followed by the 64-byte
//! signature. The input starts with `x`, so it is no input of any other format the identity
//! key signs (Switch wire 2.1).

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::key_bundle::{BundlePart, PartReader, covers_from_one, seal_bundle_parts};
use super::{AppCert, AppRequest, AuthRequest, IdentityDoc, check_tag};
use crate::enc::{serde_b64, unb64_array};
use crate::error::{Error, Result, invalid};
use crate::ident::NamingKey;
use crate::json::parse_json;
use crate::keys::{IdentityKey, ScopeKeys};
use crate::sig::{self, SignedDoc};

/// The approval's `kind` (Switch wire 3.10).
pub const APPROVAL_KIND: &str = "pubky-switch.approval";

/// The query parameter an auth request announces the companion claim with (Switch wire
/// 3.10).
pub const CLAIM_PARAMETER: &str = "x-pubky-switch-claim";

/// The approval's claim type, written with dots since claim identifiers allow only letters,
/// digits, `-`, `_` and `.` (Switch wire 3.10).
pub const APPROVAL_CLAIM_TYPE: &str = "pubky-switch.v1.approval";

/// The length of the claim's signature, after the approval's JSON bytes.
const CLAIM_SIG_LEN: usize = 64;

/// The bytes the identity key signs for the companion claim (Switch wire 2.3, 3.10):
/// `UTF8("x-pubky-switch-claim|pubky-switch.v1.approval|")`, then the SHA-256 of the auth
/// request's decoded 32-byte secret, then the approval's JSON bytes.
pub fn claim_signed_bytes(auth_secret: &[u8; 32], approval_json: &[u8]) -> Vec<u8> {
    let prefix = format!("{CLAIM_PARAMETER}|{APPROVAL_CLAIM_TYPE}|");
    let digest: [u8; 32] = Sha256::digest(auth_secret).into();
    let mut out = Vec::with_capacity(
        prefix
            .len()
            .saturating_add(digest.len())
            .saturating_add(approval_json.len()),
    );
    out.extend_from_slice(prefix.as_bytes());
    out.extend_from_slice(&digest);
    out.extend_from_slice(approval_json);
    out
}

/// An approval, as the signer builds it (Switch wire 3.10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    request: [u8; 32],
    cert: AppCert,
    identity: IdentityDoc,
    bundles: Vec<BundlePart>,
}

/// The approval as it is written: the members in the order of Switch wire 3.10.
#[derive(Serialize)]
struct ApprovalOut<'a> {
    v: u64,
    kind: &'a str,
    #[serde(with = "serde_b64")]
    request: [u8; 32],
    cert: &'a SignedDoc,
    identity: &'a SignedDoc,
    bundles: &'a [BundlePart],
}

impl Approval {
    /// The approval of `request`: its certificate `cert`, the `identity.json` version that
    /// lists it as delivered to the service, and the app's full key bundle from epoch 1 to
    /// that document's `data_epoch`, sealed to the certified bundle key in parts (Switch wire
    /// 3.5, 3.10). The scope keys are those of `cert`'s scopes with keys, the protocol's
    /// choice `has_keys`.
    ///
    /// # Errors
    ///
    /// As [`Approval::new`] and [`seal_bundle_parts`].
    pub fn issue(
        key: &IdentityKey,
        request: &AppRequest,
        cert: AppCert,
        identity: IdentityDoc,
        has_keys: &dyn Fn(&str) -> bool,
    ) -> Result<Self> {
        let bundles = seal_bundle_parts(key, &cert, 1, identity.data_epoch(), has_keys)?;
        Self::new(request, cert, identity, bundles)
    }

    /// An approval from its parts, checked as the signer sends it: `cert` names the
    /// request's App ID and keys, `identity` lists it for the app, and the parts, in
    /// `first_epoch` order without overlap, cover every data epoch from 1 to the document's
    /// `data_epoch`.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] naming the rule that fails.
    pub fn new(
        request: &AppRequest,
        cert: AppCert,
        identity: IdentityDoc,
        bundles: Vec<BundlePart>,
    ) -> Result<Self> {
        if !names_requested_app(&cert, request) {
            return invalid("Switch wire 3.10: the certificate names another app or other keys");
        }
        if cert.identity() != identity.identity()
            || identity.listed_cert(&cert.app_id()) != Some(cert.hash())
        {
            return invalid("Switch wire 3.10: identity.json doesn't list the certificate");
        }
        super::check_part_order(bundles.iter().map(BundlePart::range))?;
        let ranges: Vec<(u64, u64)> = bundles.iter().map(BundlePart::range).collect();
        if !covers_from_one(&ranges, identity.data_epoch()) {
            return invalid("Switch wire 3.10: the parts don't cover epochs 1 to data_epoch");
        }
        Ok(Self {
            request: request.hash(),
            cert,
            identity,
            bundles,
        })
    }

    /// The document hash of the app request it answers.
    pub fn request(&self) -> [u8; 32] {
        self.request
    }

    /// The app's certificate.
    pub fn cert(&self) -> &AppCert {
        &self.cert
    }

    /// The `identity.json` version that lists the certificate.
    pub fn identity(&self) -> &IdentityDoc {
        &self.identity
    }

    /// The key bundle parts.
    pub fn bundles(&self) -> &[BundlePart] {
        &self.bundles
    }

    /// The approval's JSON, compact, with the members in the order of Switch wire 3.10: the
    /// claim's unsigned payload.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if it can't be written.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&ApprovalOut {
            v: 1,
            kind: APPROVAL_KIND,
            request: self.request,
            cert: self.cert.signed(),
            identity: self.identity.signed(),
            bundles: &self.bundles,
        })
        .map_err(|_| Error::Invalid("Switch wire 3.10: the approval can't be written".into()))
    }

    /// The app's checks of an approval's JSON (Switch wire 3.10), refusing at the first
    /// failure:
    ///
    /// 1. `v` and `kind` are right, and `request` is the hash of the request it sent;
    /// 2. `cert` verifies for `identity` and names the app's own App ID, signing key and
    ///    bundle key, those of `request`;
    /// 3. `identity` verifies for the identity and lists the certificate's hash for the app;
    /// 4. it reads `bundles` by the rules of Switch wire 3.5 "Reading", holding no naming key
    ///    yet: every part names the approval's certificate and is taken, so each holds
    ///    exactly one key for each scope with keys (`has_keys`) of the certificate and each
    ///    data epoch of its range, and together they cover every epoch from 1 to the
    ///    document's `data_epoch`.
    ///
    /// Unknown members are ignored (Switch wire 1.1). The caller verifies the companion
    /// claim's signature first ([`ApprovalClaim::verify`]).
    ///
    /// # Errors
    ///
    /// The error of the first check that fails, its text naming the step.
    pub fn read(
        json: &[u8],
        request: &AppRequest,
        identity: &[u8; 32],
        bundle_secret: &[u8; 32],
        has_keys: &dyn Fn(&str) -> bool,
    ) -> Result<ApprovedApp> {
        // Step 1.
        let value: Value = parse_json(json).map_err(|e| at_step(1, e))?;
        check_tag(&value, APPROVAL_KIND, "Switch wire 3.10 step 1")?;
        let named = value
            .get("request")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Invalid("Switch wire 3.10 step 1: no request".into()))
            .and_then(|text| unb64_array::<32>(text).map_err(|e| at_step(1, e)))?;
        if named != request.hash() {
            return invalid("Switch wire 3.10 step 1: request isn't the hash of the app request");
        }
        // Step 2.
        let cert = member::<SignedDoc>(&value, "cert", 2)
            .and_then(|signed| AppCert::verify(&signed, identity).map_err(|e| at_step(2, e)))?;
        if !names_requested_app(&cert, request) {
            return invalid(
                "Switch wire 3.10 step 2: the certificate names another App ID or other keys",
            );
        }
        // Step 3.
        let doc = member::<SignedDoc>(&value, "identity", 3)
            .and_then(|signed| IdentityDoc::verify(&signed, identity).map_err(|e| at_step(3, e)))?;
        if doc.listed_cert(&cert.app_id()) != Some(cert.hash()) {
            return invalid(
                "Switch wire 3.10 step 3: identity.json doesn't list the certificate for the app",
            );
        }
        // Step 4.
        let parts = member::<Vec<BundlePart>>(&value, "bundles", 4)?;
        let certs = [&cert];
        let reader = PartReader {
            identity: *identity,
            app_id: cert.app_id(),
            bundle_secret,
            newest_epoch: doc.data_epoch(),
            certs: &certs,
            has_keys,
        };
        let reading = reader.read(&parts, None).map_err(|e| at_step(4, e))?;
        if let Some(skipped) = reading.skipped.first() {
            return invalid(format!(
                "Switch wire 3.10 step 4: part {} isn't taken: {:?}",
                skipped.index, skipped.reason
            ));
        }
        if !covers_from_one(&reading.taken, doc.data_epoch()) {
            return invalid(
                "Switch wire 3.10 step 4: the parts don't cover epochs 1 to data_epoch",
            );
        }
        let Some(naming_key) = reading.naming_key else {
            return invalid("Switch wire 3.10 step 4: no part");
        };
        Ok(ApprovedApp {
            cert,
            identity: doc,
            naming_key,
            keys: reading.keys,
        })
    }
}

/// Whether `cert` names the App ID, signing key and bundle key `request` asked for.
fn names_requested_app(cert: &AppCert, request: &AppRequest) -> bool {
    let asked = request.body();
    cert.app_id() == asked.app_id
        && cert.signing_key() == asked.signing_key
        && cert.bundle_key() == asked.bundle_key
}

/// A member of the approval, decoded, its failure at `step`.
fn member<T: serde::de::DeserializeOwned>(value: &Value, name: &str, step: u8) -> Result<T> {
    let found = value
        .get(name)
        .ok_or_else(|| Error::Invalid(format!("Switch wire 3.10 step {step}: no {name}")))?;
    serde_json::from_value(found.clone()).map_err(|e| at_step(step, e.into()))
}

/// `error`, its text prefixed with the step of Switch wire 3.10 that refused it.
fn at_step(step: u8, error: Error) -> Error {
    let prefix = |why: String| format!("Switch wire 3.10 step {step}: {why}");
    match error {
        Error::Invalid(why) => Error::Invalid(prefix(why)),
        Error::Signature(why) => Error::Signature(prefix(why)),
        Error::Crypto(why) => Error::Crypto(prefix(why)),
    }
}

/// What an app keeps from a valid approval (Switch wire 3.10): its certificate, the
/// `identity.json` that lists it, the naming key and its scope keys. It then follows Switch
/// spec 12.1 step 2. Its `Debug` output shows no key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedApp {
    /// The app's certificate.
    pub cert: AppCert,
    /// The `identity.json` that lists it.
    pub identity: IdentityDoc,
    /// The identity's naming key.
    pub naming_key: NamingKey,
    /// The app's scope keys, every epoch from 1 to the document's `data_epoch`.
    pub keys: ScopeKeys,
}

/// The companion claim's plaintext (Switch wire 3.10): the approval's JSON bytes followed by
/// the identity key's 64-byte signature over [`claim_signed_bytes`].
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalClaim {
    json: Vec<u8>,
    sig: [u8; 64],
}

impl std::fmt::Debug for ApprovalClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ApprovalClaim({} bytes)", self.json.len())
    }
}

impl ApprovalClaim {
    /// Sign `approval` as the companion claim of the grant approval of `auth`, with the
    /// identity key (Switch wire 3.10). The signer signs each claim once.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `approval` is of another identity, or can't be written.
    pub fn sign(key: &IdentityKey, auth: &AuthRequest, approval: &Approval) -> Result<Self> {
        if approval.cert.identity() != key.public() {
            return invalid("Switch wire 3.10: the approval is of another identity");
        }
        let json = approval.to_json()?;
        let sig = key.sign_message(&claim_signed_bytes(&auth.secret, &json));
        Ok(Self { json, sig })
    }

    /// Read a claim's plaintext: the approval's JSON bytes, then 64 bytes of signature.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a plaintext shorter than a signature.
    pub fn from_plaintext(plaintext: &[u8]) -> Result<Self> {
        let at = plaintext.len().checked_sub(CLAIM_SIG_LEN).ok_or_else(|| {
            Error::Invalid("Switch wire 3.10: a claim shorter than its signature".into())
        })?;
        let (json, sig) = plaintext.split_at_checked(at).ok_or_else(|| {
            Error::Invalid("Switch wire 3.10: a claim shorter than its signature".into())
        })?;
        let sig: [u8; 64] = sig.try_into().map_err(|_| {
            Error::Invalid("Switch wire 3.10: a claim shorter than its signature".into())
        })?;
        Ok(Self {
            json: json.to_vec(),
            sig,
        })
    }

    /// The claim's plaintext: the approval's JSON bytes followed by the signature.
    pub fn plaintext(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.json.len().saturating_add(CLAIM_SIG_LEN));
        out.extend_from_slice(&self.json);
        out.extend_from_slice(&self.sig);
        out
    }

    /// The approval's JSON bytes.
    pub fn json(&self) -> &[u8] {
        &self.json
    }

    /// The signature.
    pub fn sig(&self) -> [u8; 64] {
        self.sig
    }

    /// Check the signature with the identity key over the claim's signed bytes for the auth
    /// request `auth`, before the app reads the approval (Switch wire 3.10); then the
    /// approval's JSON bytes, for [`Approval::read`].
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] if it doesn't verify.
    pub fn verify(&self, identity: &[u8; 32], auth: &AuthRequest) -> Result<&[u8]> {
        sig::verify_message(
            identity,
            &claim_signed_bytes(&auth.secret, &self.json),
            &self.sig,
            "the approval's companion claim",
        )?;
        Ok(&self.json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::fixtures::{app, cert, identity, other_app};
    use crate::records::{
        AppRequestBody, IdentityBody, IdentityPolicy, Inbox, KeyBundle, KeyBundleContents,
        ListedApp, app_record_path,
    };

    fn has_keys(scope: &str) -> bool {
        scope.starts_with("scope-")
    }

    fn scopes() -> [&'static str; 3] {
        ["scope-a", "plain", "scope-b"]
    }

    fn auth() -> AuthRequest {
        AuthRequest {
            client_id: "app.example".into(),
            client_key: [7; 32],
            caps: format!("{}:rw", app_record_path(&app().app_id_bytes())),
            secret: [8; 32],
        }
    }

    fn request() -> AppRequest {
        let body = AppRequestBody::new(&app(), scopes().map(String::from).to_vec(), &auth());
        AppRequest::sign(&app(), body).unwrap()
    }

    fn doc_listing(listed: &AppCert, data_epoch: u64) -> IdentityDoc {
        let mut body = IdentityBody::first(
            identity().public(),
            [0; 16],
            Inbox::new("https://inbox.example", [5; 32]),
            IdentityPolicy::default(),
        );
        body.version = 3;
        body.data_epoch = data_epoch;
        body.apps.push(ListedApp {
            app_id: listed.app_id(),
            cert: listed.hash(),
        });
        IdentityDoc::sign(&identity(), body).unwrap()
    }

    fn approval() -> Approval {
        let c = cert(&scopes());
        Approval::issue(
            &identity(),
            &request(),
            c.clone(),
            doc_listing(&c, 2),
            &has_keys,
        )
        .unwrap()
    }

    fn read(json: &[u8]) -> Result<ApprovedApp> {
        Approval::read(
            json,
            &request(),
            &identity().public(),
            &app().bundle_secret(),
            &has_keys,
        )
    }

    fn step_of(error: Error) -> u8 {
        let text = error.to_string();
        (1..=4)
            .find(|step| text.contains(&format!("Switch wire 3.10 step {step}")))
            .unwrap_or_else(|| panic!("no step in {text}"))
    }

    #[test]
    fn test_approval_reads_back_with_every_key() {
        let a = approval();
        let json = a.to_json().unwrap();
        let text = std::str::from_utf8(&json).unwrap();
        assert!(text.starts_with(r#"{"v":1,"kind":"pubky-switch.approval","request":""#));
        let got = read(&json).unwrap();
        assert_eq!(got.cert, *a.cert());
        assert_eq!(got.identity, *a.identity());
        assert_eq!(got.naming_key, identity().naming_key());
        assert_eq!(got.keys.keys.len(), 4, "two keyed scopes, epochs 1 and 2");
        for key in &got.keys.keys {
            assert_eq!(key.key, identity().scope_key(key.data_epoch, &key.scope));
        }
        // No key appears in the clear.
        for key in &got.keys.keys {
            assert!(!text.contains(&crate::enc::b64(&key.key)));
        }
        assert!(!text.contains(&crate::enc::b64(&got.naming_key.to_bytes())));
    }

    #[test]
    fn test_approval_read_refuses_at_each_step() {
        let a = approval();
        let good: Value = serde_json::from_slice(&a.to_json().unwrap()).unwrap();
        let refuse = |change: &dyn Fn(&mut Value)| {
            let mut v = good.clone();
            change(&mut v);
            step_of(read(&serde_json::to_vec(&v).unwrap()).unwrap_err())
        };
        assert_eq!(refuse(&|v| v["v"] = 2.into()), 1);
        assert_eq!(refuse(&|v| v["kind"] = "other.kind".into()), 1);
        assert_eq!(
            refuse(&|v| v["request"] = crate::enc::b64(&[1; 32]).into()),
            1
        );
        let other = AppCert::issue(
            &identity(),
            crate::records::fixtures::cert_body_for(&other_app(), &scopes()),
        )
        .unwrap();
        let other_cert = serde_json::to_value(other.signed()).unwrap();
        assert_eq!(refuse(&|v| v["cert"] = other_cert.clone()), 2);
        let foreign = IdentityKey::from_secret([9; 32]);
        let mut body = cert(&scopes()).body().clone();
        body.identity = foreign.public();
        let foreign_cert = AppCert::issue(&foreign, body).unwrap();
        let foreign_cert = serde_json::to_value(foreign_cert.signed()).unwrap();
        assert_eq!(refuse(&|v| v["cert"] = foreign_cert.clone()), 2);
        let unlisting = doc_listing(&other, 2);
        let unlisting = serde_json::to_value(unlisting.signed()).unwrap();
        assert_eq!(refuse(&|v| v["identity"] = unlisting.clone()), 3);
        assert_eq!(refuse(&|v| v["bundles"] = serde_json::json!([])), 4);
        assert_eq!(refuse(&|v| v["bundles"][0]["first_epoch"] = 2.into()), 4);
        // A part that isn't taken refuses the approval, although the others cover every
        // epoch: here a second part whose signature doesn't verify.
        let mut extra = good["bundles"][0].clone();
        extra["first_epoch"] = 3.into();
        extra["last_epoch"] = 3.into();
        extra["bundle"]["sig"] = crate::enc::b64(&[0; 64]).into();
        assert_eq!(
            refuse(&|v| v["bundles"].as_array_mut().unwrap().push(extra.clone())),
            4
        );
        // Another bundle secret opens nothing.
        let error = Approval::read(
            &a.to_json().unwrap(),
            &request(),
            &identity().public(),
            &other_app().bundle_secret(),
            &has_keys,
        )
        .unwrap_err();
        assert_eq!(step_of(error), 4);
        // Parts that leave an epoch out.
        let c = a.cert().clone();
        let only_two = KeyBundleContents::derive(&identity(), &c, 2, 2, &has_keys).unwrap();
        let part = BundlePart {
            bundle: KeyBundle::seal(&identity(), &c, &only_two).unwrap(),
            first_epoch: 2,
            last_epoch: 2,
        };
        let gap = serde_json::to_value(vec![part]).unwrap();
        assert_eq!(refuse(&|v| v["bundles"] = gap.clone()), 4);
    }

    #[test]
    fn test_approval_new_checks_what_the_signer_sends() {
        let c = cert(&scopes());
        let doc = doc_listing(&c, 2);
        let bundles = seal_bundle_parts(&identity(), &c, 1, 2, &has_keys).unwrap();
        Approval::new(&request(), c.clone(), doc.clone(), bundles.clone()).unwrap();
        let short = seal_bundle_parts(&identity(), &c, 1, 1, &has_keys).unwrap();
        assert!(Approval::new(&request(), c.clone(), doc.clone(), short).is_err());
        let other = AppCert::issue(
            &identity(),
            crate::records::fixtures::cert_body_for(&other_app(), &scopes()),
        )
        .unwrap();
        assert!(Approval::new(&request(), other.clone(), doc, bundles.clone()).is_err());
        assert!(Approval::new(&request(), c, doc_listing(&other, 2), bundles).is_err());
    }

    #[test]
    fn test_approval_claim_signs_the_prefixed_bytes() {
        let a = approval();
        let claim = ApprovalClaim::sign(&identity(), &auth(), &a).unwrap();
        let signed = claim_signed_bytes(&auth().secret, claim.json());
        let prefix = b"x-pubky-switch-claim|pubky-switch.v1.approval|";
        assert!(signed.starts_with(prefix));
        assert_eq!(signed[0], 0x78);
        let digest: [u8; 32] = Sha256::digest(auth().secret).into();
        assert_eq!(&signed[prefix.len()..prefix.len() + 32], &digest);
        assert_eq!(&signed[prefix.len() + 32..], claim.json());

        let plaintext = claim.plaintext();
        assert_eq!(plaintext.len(), claim.json().len() + 64);
        let again = ApprovalClaim::from_plaintext(&plaintext).unwrap();
        assert_eq!(again, claim);
        let json = again.verify(&identity().public(), &auth()).unwrap();
        read(json).unwrap();
        assert!(format!("{claim:?}").starts_with("ApprovalClaim("));

        // Another auth secret, a changed byte, another identity: refused.
        let mut other_auth = auth();
        other_auth.secret[0] ^= 1;
        assert!(matches!(
            again.verify(&identity().public(), &other_auth),
            Err(Error::Signature(_))
        ));
        let mut tampered = plaintext.clone();
        tampered[5] ^= 1;
        let tampered = ApprovalClaim::from_plaintext(&tampered).unwrap();
        assert!(tampered.verify(&identity().public(), &auth()).is_err());
        assert!(
            again
                .verify(&other_app().signing_public(), &auth())
                .is_err()
        );
        assert!(ApprovalClaim::from_plaintext(&[0; 63]).is_err());
        // The signer signs only its own identity's approvals.
        assert!(ApprovalClaim::sign(&IdentityKey::from_secret([9; 32]), &auth(), &a).is_err());
    }
}
