//! The app request and the signer's checks of it (Switch wire 3.9, Switch spec 3.2 and 3.4).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{AppCert, IdentityDoc, check_tag, decode, encode, fmt};
use crate::enc::{app_id_bytes, hash, serde_b64, unb64_array, x25519_low_order, zbase32_encode};
use crate::error::{Error, Result, invalid};
use crate::json::{parse_json, reject_unknown_members};
use crate::keys::AppKeys;
use crate::labels;
use crate::scopes;
use crate::sig::SignedDoc;

/// The app request's `kind`.
pub const APP_REQUEST_KIND: &str = "pubky-switch.app_request";

/// The path of `identity.json` on the Homeserver, which no app's grant may cover (Switch
/// spec 3.4).
pub const IDENTITY_PATH: &str = "/pub/pubky-switch/v1/identity.json";

/// The path of the signer's backup on the Homeserver, which no app's grant may cover (Switch
/// wire 3.13).
pub const SIGNER_BACKUP_PATH: &str = "/pub/pubky-switch/v1/signer-backup.json";

/// The members of an app request, which refuses any other (Switch wire 1.1, 3.9).
const APP_REQUEST_MEMBERS: [&str; 10] = [
    "v",
    "kind",
    "app_id",
    "signing_key",
    "bundle_key",
    "scopes",
    "client_id",
    "client_key",
    "caps",
    "secret_hash",
];

/// The path of an app's record on the Homeserver: `/pub/pubky-switch/v1/apps/<app_id>.json`
/// (Switch spec 3.4).
pub fn app_record_path(app_id: &[u8; 16]) -> String {
    format!("/pub/pubky-switch/v1/apps/{}.json", zbase32_encode(app_id))
}

/// The folder of an app's backups on the Homeserver:
/// `/priv/pubky-switch/v1/apps/<app_id>/` (Switch spec 3.4).
pub fn app_backup_path(app_id: &[u8; 16]) -> String {
    format!("/priv/pubky-switch/v1/apps/{}/", zbase32_encode(app_id))
}

/// The Pubky auth request an app request travels with (Switch wire 3.9). Its `Debug` output
/// never shows the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthRequest {
    /// The client ID (`cid`).
    pub client_id: String,
    /// The client key (`cpk`), which the Pubky grant is bound to.
    pub client_key: [u8; 32],
    /// The capabilities, exactly as the auth request carries them.
    pub caps: String,
    /// The auth request's 32-byte secret.
    pub secret: [u8; 32],
}

impl std::fmt::Debug for AuthRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthRequest")
            .field("client_id", &self.client_id)
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

impl AuthRequest {
    /// `hash(secret)`, which the app request names (Switch wire 3.9).
    pub fn secret_hash(&self) -> [u8; 32] {
        hash(&self.secret)
    }
}

/// The members of an app request (Switch wire 3.9), as the app writes them. It names no
/// identity: the user picks it in the signer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRequestBody {
    /// The App ID, derived from `signing_key`.
    #[serde(with = "fmt::app_id")]
    pub app_id: [u8; 16],
    /// The app's signing key, which signs the request.
    #[serde(with = "serde_b64")]
    pub signing_key: [u8; 32],
    /// The app's bundle key.
    #[serde(with = "serde_b64")]
    pub bundle_key: [u8; 32],
    /// The scopes the app asks for.
    pub scopes: Vec<String>,
    /// The auth request's client ID.
    pub client_id: String,
    /// The auth request's client key.
    #[serde(with = "serde_b64")]
    pub client_key: [u8; 32],
    /// The auth request's capabilities.
    pub caps: String,
    /// `hash(secret)` of the auth request's secret.
    #[serde(with = "serde_b64")]
    pub secret_hash: [u8; 32],
}

impl AppRequestBody {
    /// The request of the app with `keys` for `scopes`, bound to `auth`.
    pub fn new(keys: &AppKeys, scopes: Vec<String>, auth: &AuthRequest) -> Self {
        Self {
            app_id: keys.app_id_bytes(),
            signing_key: keys.signing_public(),
            bundle_key: keys.bundle_public(),
            scopes,
            client_id: auth.client_id.clone(),
            client_key: auth.client_key,
            caps: auth.caps.clone(),
            secret_hash: auth.secret_hash(),
        }
    }

    /// Check what step 1 of Switch wire 3.9 checks of the members: `app_id` derived from
    /// `signing_key`, a bundle key not of low order, and the scope rule.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] naming the first rule that fails.
    pub fn check(&self) -> Result<()> {
        if app_id_bytes(&self.signing_key) != self.app_id {
            return invalid("Switch wire 3.9: app_id isn't derived from signing_key");
        }
        if x25519_low_order(&self.bundle_key) {
            return invalid("Switch wire 3.9: bundle_key is an X25519 key of low order");
        }
        scopes::check_scopes(&self.scopes)
    }

    /// The body's exact JSON bytes, as the app writes them.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if it can't be written.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        encode(APP_REQUEST_KIND, self)
    }
}

/// A verified app request (Switch wire 3.9, step 1 but the protocol's known scopes): signed
/// with the signing key it names, so the app holds that key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRequest {
    body: AppRequestBody,
    signed: SignedDoc,
    hash: [u8; 32],
}

impl AppRequest {
    /// Sign a request with the app's signing key.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if the body names other keys than `keys` or breaks a rule of
    /// Switch wire 3.9.
    pub fn sign(keys: &AppKeys, body: AppRequestBody) -> Result<Self> {
        if body.signing_key != keys.signing_public() {
            return invalid("Switch wire 3.9: signing_key isn't the app's");
        }
        body.check()?;
        let signed = keys.sign_doc(labels::sig::APP_REQUEST, &[], body.to_json()?);
        let hash = signed.doc_hash()?;
        Ok(Self { body, signed, hash })
    }

    /// Verify a request with the signing key it names, then the body strictly, its unknown
    /// members refused (Switch wire 3.9 step 1). Whether its scopes are ones the signer knows
    /// is [`check_app_request`]'s.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Signature`] if the named key didn't sign it, and
    /// [`crate::Error::Invalid`] for any other rule of step 1.
    pub fn verify(signed: &SignedDoc) -> Result<Self> {
        let peeked: Value = parse_json(&signed.body_bytes()?)?;
        let Some(key) = peeked.get("signing_key").and_then(Value::as_str) else {
            return invalid("Switch wire 3.9: the request names no signing_key");
        };
        let signing_key = unb64_array::<32>(key)?;
        let value: Value =
            parse_json(&signed.verify(&signing_key, labels::sig::APP_REQUEST, &[])?)?;
        reject_unknown_members(&value, &APP_REQUEST_MEMBERS, "an app request")?;
        check_tag(&value, APP_REQUEST_KIND, "Switch wire 3.9")?;
        let body: AppRequestBody = decode(value)?;
        body.check()?;
        Ok(Self {
            body,
            signed: signed.clone(),
            hash: signed.doc_hash()?,
        })
    }

    /// The members as read.
    pub fn body(&self) -> &AppRequestBody {
        &self.body
    }

    /// The signed document, in its exact bytes.
    pub fn signed(&self) -> &SignedDoc {
        &self.signed
    }

    /// The request's document hash, which the approval names (Switch wire 3.10).
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Whether the request binds `auth` (Switch wire 3.9 step 2): its client ID, client key
    /// and capabilities, and the hash of its secret.
    pub fn binds(&self, auth: &AuthRequest) -> bool {
        self.body.client_id == auth.client_id
            && self.body.client_key == auth.client_key
            && self.body.caps == auth.caps
            && self.body.secret_hash == auth.secret_hash()
    }
}

/// Whether `path`, a capability's path, covers `target`: it is that path, or a folder it lies
/// in.
fn covers(path: &str, target: &str) -> bool {
    path == target || (path.ends_with('/') && target.starts_with(path))
}

/// Step 3 of Switch wire 3.9: `caps` names exactly the app's own paths, each `path:rw`,
/// joined by `,`, each once. Its record always; its backup folder optionally; and the paths
/// `extra_paths` its protocol adds for it. No path may cover `identity.json` or the signer's
/// backup.
///
/// # Errors
///
/// [`crate::Error::Invalid`] naming the rule that fails. The message never repeats a path.
pub fn check_caps(caps: &str, app_id: &[u8; 16], extra_paths: &[&str]) -> Result<()> {
    let (record, backup) = (app_record_path(app_id), app_backup_path(app_id));
    let mut seen: Vec<&str> = Vec::new();
    for cap in caps.split(',') {
        let Some(path) = cap.strip_suffix(":rw") else {
            return invalid("Switch wire 3.9 step 3: a capability that isn't path:rw");
        };
        if seen.contains(&path) {
            return invalid("Switch wire 3.9 step 3: a path named twice");
        }
        if covers(path, IDENTITY_PATH) || covers(path, SIGNER_BACKUP_PATH) {
            return invalid(
                "Switch wire 3.9 step 3: a path that covers identity.json or the signer's backup",
            );
        }
        if path != record && path != backup && !extra_paths.contains(&path) {
            return invalid("Switch wire 3.9 step 3: a path that isn't one of the app's own");
        }
        seen.push(path);
    }
    if !seen.contains(&record.as_str()) {
        return invalid("Switch wire 3.9 step 3: caps doesn't name the app's record");
    }
    Ok(())
}

/// What the signer holds to check an app request, for steps 1 and 3 to 6 of Switch wire 3.9.
pub struct SignerView<'a> {
    /// The App IDs it revoked or saw depart, kept for good.
    pub revoked: &'a [[u8; 16]],
    /// The newest `identity.json`.
    pub identity: &'a IdentityDoc,
    /// The certificates of the apps it lists.
    pub listed: &'a [AppCert],
    /// The app limit the switch announced.
    pub app_limit: u64,
    /// The paths the app's protocol adds to its own, which the user allows for it.
    pub extra_paths: &'a [&'a str],
    /// Whether the signer knows a scope, by its protocol's names.
    pub knows_scope: &'a dyn Fn(&str) -> bool,
}

/// What approving a request does (Switch wire 3.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Approve {
    /// A new App ID: a new certificate.
    New,
    /// The listed App ID with its listed keys: approving renews its certificate (Switch wire
    /// 3.8).
    Renew,
}

/// The signer's checks of an app request, in order, refusing at the first failure (Switch
/// wire 3.9 steps 1 to 6).
///
/// # Errors
///
/// [`crate::Error::Signature`] or [`crate::Error::Invalid`]; an invalid one names its step
/// as `Switch wire 3.9 step N`.
pub fn check_app_request(
    signed: &SignedDoc,
    auth: &AuthRequest,
    view: &SignerView<'_>,
) -> Result<(AppRequest, Approve)> {
    let request = AppRequest::verify(signed).map_err(|error| match error {
        Error::Invalid(why) => Error::Invalid(format!("Switch wire 3.9 step 1: {why}")),
        Error::Signature(why) => Error::Signature(format!("Switch wire 3.9 step 1: {why}")),
        other => other,
    })?;
    let body = request.body();
    if body.scopes.iter().any(|s| !(view.knows_scope)(s)) {
        return invalid("Switch wire 3.9 step 1: a scope the signer doesn't know");
    }
    if !request.binds(auth) {
        return invalid("Switch wire 3.9 step 2: the request doesn't bind the auth request");
    }
    check_caps(&body.caps, &body.app_id, view.extra_paths)?;
    if view.revoked.contains(&body.app_id) || view.identity.lists_removed(&body.app_id) {
        return invalid("Switch wire 3.9 step 4: an App ID revoked, departed or removed");
    }
    let approve = match view.identity.listed_cert(&body.app_id) {
        Some(listed) => {
            let Some(cert) = view.listed.iter().find(|c| c.hash() == listed) else {
                return invalid("Switch wire 3.9 step 5: no certificate for the listed App ID");
            };
            if cert.signing_key() != body.signing_key || cert.bundle_key() != body.bundle_key {
                return invalid(
                    "Switch wire 3.9 step 5: a listed App ID is never given other keys",
                );
            }
            Approve::Renew
        }
        None => {
            let apps = u64::try_from(view.identity.body().apps.len()).unwrap_or(u64::MAX);
            if apps >= view.app_limit {
                return invalid("Switch wire 3.9 step 6: the app limit is reached");
            }
            Approve::New
        }
    };
    Ok((request, approve))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::fixtures::{app, cert, identity, other_app};
    use crate::records::{IdentityBody, IdentityPolicy, Inbox, ListedApp, RemovedApp};

    fn auth() -> AuthRequest {
        AuthRequest {
            client_id: "app.example".into(),
            client_key: [5; 32],
            caps: format!("{}:rw", app_record_path(&app().app_id_bytes())),
            secret: [6; 32],
        }
    }

    fn request() -> AppRequest {
        AppRequest::sign(
            &app(),
            AppRequestBody::new(&app(), vec!["scope-a".into()], &auth()),
        )
        .unwrap()
    }

    fn doc(listed: bool) -> IdentityDoc {
        let mut b = IdentityBody::first(
            identity().public(),
            [1; 16],
            Inbox::new("https://inbox.example", [2; 32]),
            IdentityPolicy::default(),
        );
        if listed {
            b.apps.push(ListedApp {
                app_id: app().app_id_bytes(),
                cert: cert(&["scope-a"]).hash(),
            });
        }
        IdentityDoc::sign(&identity(), b).unwrap()
    }

    fn knows(scope: &str) -> bool {
        scope.starts_with("scope-")
    }

    fn check(
        signed: &SignedDoc,
        auth: &AuthRequest,
        identity: &IdentityDoc,
        revoked: &[[u8; 16]],
        limit: u64,
    ) -> Result<Approve> {
        let listed = [cert(&["scope-a"])];
        let view = SignerView {
            revoked,
            identity,
            listed: &listed,
            app_limit: limit,
            extra_paths: &[],
            knows_scope: &knows,
        };
        check_app_request(signed, auth, &view).map(|(_, a)| a)
    }

    fn step(result: Result<Approve>) -> String {
        let error = result.unwrap_err().to_string();
        error
            .split("step ")
            .nth(1)
            .and_then(|s| s.get(..1))
            .unwrap_or("signature")
            .to_owned()
    }

    fn resign(f: impl Fn(&mut Value), keys: &AppKeys) -> SignedDoc {
        let mut v: Value =
            serde_json::from_slice(&request().signed().body_bytes().unwrap()).unwrap();
        f(&mut v);
        keys.sign_doc(
            labels::sig::APP_REQUEST,
            &[],
            serde_json::to_vec(&v).unwrap(),
        )
    }

    #[test]
    fn test_app_request_round_trip_and_approvals() {
        let r = request();
        assert_eq!(AppRequest::verify(r.signed()).unwrap(), r);
        assert!(r.binds(&auth()));
        assert_eq!(
            check(r.signed(), &auth(), &doc(false), &[], 32).unwrap(),
            Approve::New
        );
        assert_eq!(
            check(r.signed(), &auth(), &doc(true), &[], 32).unwrap(),
            Approve::Renew
        );
    }

    #[test]
    fn test_app_request_step_one_refusals() {
        let unknown = resign(|v| v["future"] = serde_json::json!(1), &app());
        assert_eq!(step(check(&unknown, &auth(), &doc(false), &[], 32)), "1");
        let other_id = resign(
            |v| v["app_id"] = serde_json::json!(other_app().app_id()),
            &app(),
        );
        assert_eq!(step(check(&other_id, &auth(), &doc(false), &[], 32)), "1");
        let unknown_scope = resign(|v| v["scopes"] = serde_json::json!(["other"]), &app());
        assert_eq!(
            step(check(&unknown_scope, &auth(), &doc(false), &[], 32)),
            "1"
        );
        let beside = resign(
            |v| v["scopes"] = serde_json::json!(["scope-a", "scope-a:x"]),
            &app(),
        );
        assert!(check(&beside, &auth(), &doc(false), &[], 32).is_err());
        let low = resign(
            |v| v["bundle_key"] = serde_json::json!(crate::enc::b64(&[0; 32])),
            &app(),
        );
        assert_eq!(step(check(&low, &auth(), &doc(false), &[], 32)), "1");
        let by_other = resign(|_| {}, &other_app());
        assert!(matches!(
            AppRequest::verify(&by_other),
            Err(crate::Error::Signature(_))
        ));
    }

    #[test]
    fn test_app_request_steps_two_to_six() {
        let r = request();
        let mut other_secret = auth();
        other_secret.secret[0] ^= 1;
        assert_eq!(
            step(check(r.signed(), &other_secret, &doc(false), &[], 32)),
            "2"
        );
        let id = app().app_id_bytes();
        assert_eq!(
            step(check(r.signed(), &auth(), &doc(false), &[id], 32)),
            "4"
        );
        let mut removed = IdentityBody::first(
            identity().public(),
            [1; 16],
            Inbox::new("https://inbox.example", [2; 32]),
            IdentityPolicy::default(),
        );
        removed.removed.push(RemovedApp {
            app_id: id,
            distrust_from: 0,
        });
        let removed = IdentityDoc::sign(&identity(), removed).unwrap();
        assert_eq!(step(check(r.signed(), &auth(), &removed, &[], 32)), "4");
        let other_bundle = resign(
            |v| v["bundle_key"] = serde_json::json!(crate::enc::b64(&other_app().bundle_public())),
            &app(),
        );
        assert_eq!(
            step(check(&other_bundle, &auth(), &doc(true), &[], 32)),
            "5"
        );
        assert_eq!(step(check(r.signed(), &auth(), &doc(false), &[], 0)), "6");
    }

    #[test]
    fn test_app_request_caps_rule() {
        let id = app().app_id_bytes();
        let (record, backup) = (app_record_path(&id), app_backup_path(&id));
        let extra = "/pub/sample/profile.json";
        check_caps(&format!("{record}:rw"), &id, &[]).unwrap();
        check_caps(&format!("{backup}:rw,{record}:rw"), &id, &[]).unwrap();
        check_caps(&format!("{record}:rw,{extra}:rw"), &id, &[extra]).unwrap();
        for caps in [
            format!("{record}:rw,{extra}:rw"),
            format!("{record}:rw,/pub/pubky-switch/:rw"),
            format!("{record}:rw,/:rw"),
            format!("{record}:rw,{IDENTITY_PATH}:rw"),
            format!("{record}:rw,{record}:rw"),
            format!("{record}:r"),
            format!("{backup}:rw"),
            format!("{}:rw", app_record_path(&other_app().app_id_bytes())),
        ] {
            let error = check_caps(&caps, &id, &[]).unwrap_err().to_string();
            assert!(error.contains("step 3"), "{caps}: {error}");
        }
        // A protocol path that covers identity.json is refused all the same.
        assert!(check_caps(&format!("{record}:rw,/pub/:rw"), &id, &["/pub/"]).is_err());
    }

    #[test]
    fn test_auth_request_debug_hides_the_secret() {
        assert!(!format!("{:?}", auth()).contains("secret"));
    }
}
