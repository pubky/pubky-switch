//! `identity.json` (Switch wire 3.3, Switch spec 4.3): the switch pointer and service keys,
//! the current, removed and renewed apps, the data epoch, the admission policy, the record
//! age limit and the signing install, with the version and generation rules, the standing of
//! a certificate and equivocation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{CLOCK_TOLERANCE_MS, Inbox, check_tag, decode, encode, fmt, open_value};
use crate::enc::{hash, serde_b64};
use crate::error::{Result, invalid};
use crate::keys::IdentityKey;
use crate::labels;
use crate::sig::SignedDoc;

/// The `kind` of `identity.json`.
pub const IDENTITY_KIND: &str = "pubky-switch.identity";

/// The most entries of `service_keys` (Switch wire 3.3).
pub const MAX_SERVICE_KEYS: usize = 256;

/// The record age limit when `identity.json` sets none: 90 days, in seconds (Switch wire 3.3).
pub const DEFAULT_RECORD_MAX_AGE_S: u64 = 90 * 86_400;

/// The admission mode (Switch wire 3.3): `contacts_and_conversations` is the only one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Admission {
    /// Contacts and conversation entries are admitted (Switch spec 7).
    #[default]
    #[serde(rename = "contacts_and_conversations")]
    ContactsAndConversations,
}

/// The connect request settings of the policy (Switch wire 3.3): every member required and
/// none `null`, so a reader refuses an object without one. A signer writes the defaults when
/// the user sets none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectRequests {
    /// Whether strangers may ask to be invited; `false` by default.
    pub enabled: bool,
    /// The most pending connect requests; 50 by default. Any `int`: the service caps it at
    /// its `max_connect_pending` (Switch wire 9.2).
    pub max_pending: u64,
    /// Whether a connect request pushes; `false` by default.
    pub push: bool,
}

fn default_max_pending() -> u64 {
    50
}

impl Default for ConnectRequests {
    fn default() -> Self {
        Self {
            enabled: false,
            max_pending: default_max_pending(),
            push: false,
        }
    }
}

/// The admission settings of `identity.json` and an enrollment (Switch wire 3.3, 3.7).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityPolicy {
    /// The admission mode.
    pub admission: Admission,
    /// The connect request settings.
    pub connect_requests: ConnectRequests,
}

/// A current app: its App ID and the hash of its certificate (Switch wire 3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ListedApp {
    /// The App ID.
    #[serde(with = "fmt::app_id")]
    pub app_id: [u8; 16],
    /// The document hash of its certificate.
    #[serde(with = "serde_b64")]
    pub cert: [u8; 32],
}

/// A removed app (Switch wire 3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RemovedApp {
    /// The App ID.
    #[serde(with = "fmt::app_id")]
    pub app_id: [u8; 16],
    /// From when its messages are distrusted, a time on its service.
    #[serde(with = "fmt::time_ms")]
    pub distrust_from: u64,
}

/// An earlier certificate of a current app, during and after a renewal (Switch wire 3.3,
/// 3.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RenewedCert {
    /// The App ID.
    #[serde(with = "fmt::app_id")]
    pub app_id: [u8; 16],
    /// The document hash of the earlier certificate.
    #[serde(with = "serde_b64")]
    pub cert: [u8; 32],
    /// `None` while the renewal is open; once set, the earlier certificate counts only for
    /// messages accepted more than the clock tolerance before it. Always written.
    #[serde(with = "fmt::opt_time_ms")]
    pub until: Option<u64>,
}

/// The service key of an earlier generation (Switch wire 3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceKeyEntry {
    /// The generation.
    pub generation: u64,
    /// Its service key.
    #[serde(with = "serde_b64")]
    pub key: [u8; 32],
}

/// The members of `identity.json` (Switch wire 3.3), as the signer writes them: `renewed`
/// last, after `recovery_from` and `record_max_age`, and the optional lists left out when
/// empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityBody {
    /// The identity, which signs the document.
    #[serde(with = "fmt::pubky")]
    pub identity: [u8; 32],
    /// The version: at least 1, higher on every update.
    pub version: u64,
    /// The generation: at least 1, higher on each provider change.
    pub generation: u64,
    /// The signer ID of the install that signs for the identity.
    #[serde(with = "serde_b64")]
    pub signer: [u8; 16],
    /// The switch and the account's service key there.
    pub inbox: Inbox,
    /// The admission settings.
    pub policy: IdentityPolicy,
    /// The current apps.
    pub apps: Vec<ListedApp>,
    /// The removed apps.
    pub removed: Vec<RemovedApp>,
    /// The current data epoch: at least 1, only increasing.
    pub data_epoch: u64,
    /// The generation lost in the most recent provider loss, if any. Always written.
    #[serde(deserialize_with = "fmt::nullable")]
    pub recovery_from: Option<u64>,
    /// The record age limit in seconds; `None` stands for 90 days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_max_age: Option<u64>,
    /// The service keys of earlier generations, ascending; a present `[]` is none.
    #[serde(
        default,
        deserialize_with = "fmt::null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub service_keys: Vec<ServiceKeyEntry>,
    /// The earlier certificates of current apps.
    #[serde(
        default,
        deserialize_with = "fmt::null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub renewed: Vec<RenewedCert>,
}

impl IdentityBody {
    /// A new identity's first document: version, generation and data epoch 1, no apps.
    pub fn first(
        identity: [u8; 32],
        signer: [u8; 16],
        inbox: Inbox,
        policy: IdentityPolicy,
    ) -> Self {
        Self {
            identity,
            version: 1,
            generation: 1,
            signer,
            inbox,
            policy,
            apps: Vec::new(),
            removed: Vec::new(),
            data_epoch: 1,
            recovery_from: None,
            record_max_age: None,
            service_keys: Vec::new(),
            renewed: Vec::new(),
        }
    }

    /// Check the rules every reader applies (Switch wire 3.3), for the identity it expects.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] naming the first rule that fails: the identity, a counter
    /// below 1, the inbox origin, the "Lists" rule, `record_max_age` or `service_keys`.
    pub fn check(&self, identity: &[u8; 32]) -> Result<()> {
        if &self.identity != identity {
            return invalid("Switch wire 3.3: identity isn't the expected identity");
        }
        if self.version == 0 || self.generation == 0 || self.data_epoch == 0 {
            return invalid("Switch wire 3.3: version, generation and data_epoch start at 1");
        }
        self.inbox.check()?;
        for (i, app) in self.apps.iter().enumerate() {
            if self.apps.iter().take(i).any(|a| a.app_id == app.app_id) {
                return invalid("Switch wire 3.3: an App ID twice in apps");
            }
            if self.removed.iter().any(|r| r.app_id == app.app_id) {
                return invalid("Switch wire 3.3: an App ID in both apps and removed");
            }
        }
        for (i, removed) in self.removed.iter().enumerate() {
            if self
                .removed
                .iter()
                .take(i)
                .any(|r| r.app_id == removed.app_id)
            {
                return invalid("Switch wire 3.3: an App ID twice in removed");
            }
        }
        if self.record_max_age == Some(0) {
            return invalid("Switch wire 3.3: record_max_age is at least 1");
        }
        if self.service_keys.len() > MAX_SERVICE_KEYS {
            return invalid("Switch wire 3.3: service_keys holds at most 256 entries");
        }
        if self
            .service_keys
            .windows(2)
            .any(|w| matches!(w, [a, b] if a.generation >= b.generation))
        {
            return invalid(
                "Switch wire 3.3: service_keys isn't ascending by generation, each once",
            );
        }
        if self
            .service_keys
            .iter()
            .any(|k| k.generation == 0 || k.generation >= self.generation)
        {
            return invalid(
                "Switch wire 3.3: a service_keys generation isn't before the document's",
            );
        }
        Ok(())
    }

    /// Set `until` of every open renewal of `app_id` to `until`, as a closing delivery does
    /// (Switch wire 3.8). Returns how many entries it closed.
    pub fn close_renewals(&mut self, app_id: &[u8; 16], until: u64) -> usize {
        let open = self
            .renewed
            .iter_mut()
            .filter(|r| &r.app_id == app_id && r.until.is_none());
        open.map(|entry| entry.until = Some(until)).count()
    }

    /// The body's exact JSON bytes, as the signer writes them.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if it can't be written.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        encode(IDENTITY_KIND, self)
    }
}

/// The standing of a certificate in an `identity.json` (Switch wire 3.8, check 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// `apps` lists the app with this certificate.
    Listed,
    /// `apps` lists the app with another certificate, and `renewed` this one, open.
    RenewedOpen,
    /// As above, with `until` set.
    RenewedClosed {
        /// The renewal's `until`.
        until: u64,
    },
    /// `removed` lists the app.
    Removed {
        /// Its `distrust_from`.
        distrust_from: u64,
    },
    /// Anything else: the certificate counts for nothing.
    None,
}

impl Standing {
    /// Whether the certificate counts for a message accepted at `accepted_at`, with the clock
    /// tolerance (Switch wire 3.8 check 5, 5.1 check 7): listed and open renewals count; a
    /// closed renewal if `accepted_at + 5 min < until`; a removed app if `accepted_at + 5 min
    /// <= distrust_from`.
    pub fn counts_at(self, accepted_at: u64) -> bool {
        let t = accepted_at.saturating_add(CLOCK_TOLERANCE_MS);
        match self {
            Standing::Listed | Standing::RenewedOpen => true,
            Standing::RenewedClosed { until } => t < until,
            Standing::Removed { distrust_from } => t <= distrust_from,
            Standing::None => false,
        }
    }

    /// Whether the certificate makes its app current now (Switch wire 3.8): listed, or an
    /// open renewal.
    pub fn current_now(self) -> bool {
        matches!(self, Standing::Listed | Standing::RenewedOpen)
    }
}

/// How one `identity.json` stands to another of the same identity (Switch wire 3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionOrder {
    /// The same signed document.
    Same,
    /// The same body under another signature: not equivocation, but another document wherever
    /// documents are compared whole.
    SameBody,
    /// A higher version at no lower generation.
    Newer,
    /// A lower version or a lower generation: a rollback.
    Older,
    /// Another body at the same version: equivocation.
    Equivocation,
}

/// A verified `identity.json` (Switch wire 3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityDoc {
    body: IdentityBody,
    signed: SignedDoc,
    hash: [u8; 32],
    body_hash: [u8; 32],
}

impl IdentityDoc {
    /// Sign a document with the identity key.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if the body breaks a rule of Switch wire 3.3 for the
    /// identity of `key`.
    pub fn sign(key: &IdentityKey, body: IdentityBody) -> Result<Self> {
        body.check(&key.public())?;
        let bytes = body.to_json()?;
        let body_hash = hash(&bytes);
        let signed = key.sign_doc(labels::sig::IDENTITY, &[], bytes);
        let hash = signed.doc_hash()?;
        Ok(Self {
            body,
            signed,
            hash,
            body_hash,
        })
    }

    /// Verify a document for the identity the reader expects. Unknown members are ignored
    /// (Switch wire 1.1).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Signature`] if the identity key didn't sign it, and
    /// [`crate::Error::Invalid`] for any rule of Switch wire 3.3 it breaks.
    pub fn verify(signed: &SignedDoc, identity: &[u8; 32]) -> Result<Self> {
        let value = open_value(signed, identity, labels::sig::IDENTITY)?;
        check_tag(&value, IDENTITY_KIND, "Switch wire 3.3")?;
        let body: IdentityBody = decode(value)?;
        body.check(identity)?;
        Ok(Self {
            body,
            signed: signed.clone(),
            hash: signed.doc_hash()?,
            body_hash: hash(&signed.body_bytes()?),
        })
    }

    /// Verify a document of the identity it names, as a switch reads another identity's copy
    /// at `PUT /peers`, where the body gives the key (Switch wire 7.4.5).
    ///
    /// # Errors
    ///
    /// As [`IdentityDoc::verify`].
    pub fn verify_named(signed: &SignedDoc) -> Result<Self> {
        let peeked: serde_json::Value = crate::json::parse_json(&signed.body_bytes()?)?;
        let Some(id) = peeked.get("identity").and_then(serde_json::Value::as_str) else {
            return invalid("Switch wire 3.3: the document names no identity");
        };
        Self::verify(signed, &crate::enc::pubky_key(id)?)
    }

    /// The members as read.
    pub fn body(&self) -> &IdentityBody {
        &self.body
    }

    /// The signed document, in its exact bytes.
    pub fn signed(&self) -> &SignedDoc {
        &self.signed
    }

    /// The document hash, as `prev` names it (Switch wire 2.2, 3.3).
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// `hash(body bytes)`, which apps keep per version to see equivocation (Switch wire 3.3).
    pub fn body_hash(&self) -> [u8; 32] {
        self.body_hash
    }

    /// The identity.
    pub fn identity(&self) -> [u8; 32] {
        self.body.identity
    }

    /// The version.
    pub fn version(&self) -> u64 {
        self.body.version
    }

    /// The generation.
    pub fn generation(&self) -> u64 {
        self.body.generation
    }

    /// The data epoch.
    pub fn data_epoch(&self) -> u64 {
        self.body.data_epoch
    }

    /// The switch and the account's current service key.
    pub fn inbox(&self) -> &Inbox {
        &self.body.inbox
    }

    /// The record age limit in milliseconds: the document's, or 90 days.
    pub fn record_max_age_ms(&self) -> u64 {
        self.body
            .record_max_age
            .unwrap_or(DEFAULT_RECORD_MAX_AGE_S)
            .saturating_mul(1000)
    }

    /// The service key of generation `generation`: `inbox.service_key` for the document's own
    /// generation, otherwise the one `service_keys` lists. `None` for a generation the
    /// document doesn't name, whose proofs date nothing (Switch wire 3.3).
    pub fn service_key_of(&self, generation: u64) -> Option<[u8; 32]> {
        if generation == self.body.generation {
            return Some(self.body.inbox.service_key);
        }
        self.body
            .service_keys
            .iter()
            .find(|k| k.generation == generation)
            .map(|k| k.key)
    }

    /// The certificate hash `apps` lists for `app_id`.
    pub fn listed_cert(&self, app_id: &[u8; 16]) -> Option<[u8; 32]> {
        self.body
            .apps
            .iter()
            .find(|a| &a.app_id == app_id)
            .map(|a| a.cert)
    }

    /// Whether `removed` lists `app_id`.
    pub fn lists_removed(&self, app_id: &[u8; 16]) -> bool {
        self.body.removed.iter().any(|r| &r.app_id == app_id)
    }

    /// The standing of the certificate with hash `cert` for `app_id` (Switch wire 3.8). A
    /// `renewed` entry counts only while `apps` lists its app.
    pub fn standing(&self, app_id: &[u8; 16], cert: &[u8; 32]) -> Standing {
        if let Some(removed) = self.body.removed.iter().find(|r| &r.app_id == app_id) {
            return Standing::Removed {
                distrust_from: removed.distrust_from,
            };
        }
        let Some(listed) = self.listed_cert(app_id) else {
            return Standing::None;
        };
        if &listed == cert {
            return Standing::Listed;
        }
        match self
            .body
            .renewed
            .iter()
            .find(|r| &r.app_id == app_id && &r.cert == cert)
        {
            Some(RenewedCert { until: None, .. }) => Standing::RenewedOpen,
            Some(RenewedCert {
                until: Some(until), ..
            }) => Standing::RenewedClosed { until: *until },
            None => Standing::None,
        }
    }

    /// Whether the certificate counts for a message accepted at `accepted_at` (Switch wire
    /// 3.8 check 5).
    pub fn counts_at(&self, app_id: &[u8; 16], cert: &[u8; 32], accepted_at: u64) -> bool {
        self.standing(app_id, cert).counts_at(accepted_at)
    }

    /// Whether the certificate makes its app current now (Switch wire 3.8).
    pub fn current_now(&self, app_id: &[u8; 16], cert: &[u8; 32]) -> bool {
        self.standing(app_id, cert).current_now()
    }

    /// The first-document rule (Switch wire 3.3): the first document of an account enrolled
    /// without one has version, generation and data epoch 1, or carries `recovery_from`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] otherwise (`400 bad_request` at the service).
    pub fn check_first(&self) -> Result<()> {
        let b = &self.body;
        if b.recovery_from.is_some() || (b.version, b.generation, b.data_epoch) == (1, 1, 1) {
            Ok(())
        } else {
            invalid(
                "Switch wire 3.3: a first document has version, generation and data_epoch 1, \
                 or recovery_from",
            )
        }
    }

    /// How `other`, a document of the same identity, stands to this one (Switch wire 3.3).
    /// Bodies are compared as bytes.
    pub fn compare(&self, other: &IdentityDoc) -> VersionOrder {
        let (mine, theirs) = (&self.body, &other.body);
        if theirs.version == mine.version {
            return if other.signed == self.signed {
                VersionOrder::Same
            } else if other.body_hash == self.body_hash {
                VersionOrder::SameBody
            } else {
                VersionOrder::Equivocation
            };
        }
        if theirs.version > mine.version && theirs.generation >= mine.generation {
            VersionOrder::Newer
        } else {
            VersionOrder::Older
        }
    }

    /// Check that `later` may follow this document at an app (Switch wire 3.3): a higher
    /// version at no lower generation, the same data epoch or a higher one, and no App ID in
    /// `apps` that this one lists in `removed`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] naming the rule `later` breaks: a rollback, equivocation, or
    /// a removed app listed again, which the app shows the user.
    pub fn check_successor(&self, later: &IdentityDoc) -> Result<()> {
        match self.compare(later) {
            VersionOrder::Newer => {}
            VersionOrder::Same | VersionOrder::SameBody => {
                return invalid("Switch wire 3.3: not a later version");
            }
            VersionOrder::Older => {
                return invalid("Switch wire 3.3: a lower version or generation");
            }
            VersionOrder::Equivocation => {
                return invalid("Switch wire 3.3: equivocation: another body at one version");
            }
        }
        if later.body.data_epoch < self.body.data_epoch {
            return invalid("Switch wire 3.3: data_epoch only increases");
        }
        if later
            .body
            .apps
            .iter()
            .any(|a| self.lists_removed(&a.app_id))
        {
            return invalid("Switch wire 3.3: a later version lists a removed App ID in apps");
        }
        Ok(())
    }
}

/// The `identity.json` bodies an app has seen, one hash per identity and version, from any
/// source (Switch wire 3.3, "Equivocation"). A second body at one version shows equivocation:
/// the app stops paying that identity, or anyone when it is its own, and alerts the user.
#[derive(Clone, Debug, Default)]
pub struct SeenBodies {
    seen: BTreeMap<([u8; 32], u64), [u8; 32]>,
    equivocating: Vec<[u8; 32]>,
}

impl SeenBodies {
    /// Nothing seen yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// See a verified document.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] when another body was seen at its version: the alert.
    pub fn see(&mut self, doc: &IdentityDoc) -> Result<()> {
        let key = (doc.identity(), doc.version());
        match self.seen.get(&key) {
            None => {
                self.seen.insert(key, doc.body_hash());
                Ok(())
            }
            Some(seen) if *seen == doc.body_hash() => Ok(()),
            Some(_) => {
                if !self.equivocating.contains(&key.0) {
                    self.equivocating.push(key.0);
                }
                invalid("Switch wire 3.3: equivocation: two bodies at one version")
            }
        }
    }

    /// Whether `identity` was shown to equivocate.
    pub fn equivocates(&self, identity: &[u8; 32]) -> bool {
        self.equivocating.contains(identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::fixtures::{app, identity, other_app};

    pub(crate) fn body() -> IdentityBody {
        let mut b = IdentityBody::first(
            identity().public(),
            [7; 16],
            Inbox::new("https://inbox.example", [8; 32]),
            IdentityPolicy::default(),
        );
        b.apps.push(ListedApp {
            app_id: app().app_id_bytes(),
            cert: [1; 32],
        });
        b
    }

    fn sign(b: IdentityBody) -> IdentityDoc {
        IdentityDoc::sign(&identity(), b).unwrap()
    }

    fn resign(value: &serde_json::Value) -> SignedDoc {
        identity().sign_doc(
            labels::sig::IDENTITY,
            &[],
            serde_json::to_vec(value).unwrap(),
        )
    }

    #[test]
    fn test_identity_doc_round_trip_and_member_order() {
        let doc = sign(body());
        let read = IdentityDoc::verify(doc.signed(), &identity().public()).unwrap();
        assert_eq!(read, doc);
        let text = String::from_utf8(doc.signed().body_bytes().unwrap()).unwrap();
        assert!(text.starts_with(r#"{"v":1,"kind":"pubky-switch.identity","identity":""#));
        assert!(text.ends_with(r#""removed":[],"data_epoch":1,"recovery_from":null}"#));
        let mut renewed = body();
        renewed.record_max_age = Some(60);
        renewed.renewed.push(RenewedCert {
            app_id: app().app_id_bytes(),
            cert: [2; 32],
            until: None,
        });
        let text = String::from_utf8(sign(renewed).signed().body_bytes().unwrap()).unwrap();
        let (rma, ren) = (
            text.find("record_max_age").unwrap(),
            text.find("renewed").unwrap(),
        );
        assert!(
            text.find("recovery_from").unwrap() < rma && rma < ren,
            "renewed is last"
        );
    }

    #[test]
    fn test_identity_doc_requires_always_written_members() {
        let mut v: serde_json::Value = serde_json::from_slice(&body().to_json().unwrap()).unwrap();
        IdentityDoc::verify(&resign(&v), &identity().public()).unwrap();
        v.as_object_mut().unwrap().remove("recovery_from");
        assert!(IdentityDoc::verify(&resign(&v), &identity().public()).is_err());
        let mut no_signer: serde_json::Value =
            serde_json::from_slice(&body().to_json().unwrap()).unwrap();
        no_signer["signer"] = serde_json::json!(crate::enc::b64(&[1; 15]));
        assert!(IdentityDoc::verify(&resign(&no_signer), &identity().public()).is_err());
        let mut extra: serde_json::Value =
            serde_json::from_slice(&body().to_json().unwrap()).unwrap();
        extra["future"] = serde_json::json!({"n": 1});
        IdentityDoc::verify(&resign(&extra), &identity().public())
            .expect("unknown members are ignored");
    }

    #[test]
    fn test_identity_lists_rule() {
        let mut twice = body();
        twice.apps.push(twice.apps[0]);
        assert!(twice.check(&identity().public()).is_err());
        let mut both = body();
        both.removed.push(RemovedApp {
            app_id: app().app_id_bytes(),
            distrust_from: 0,
        });
        let error = both.check(&identity().public()).unwrap_err();
        assert!(error.to_string().contains("both"), "{error}");
        let mut removed_twice = body();
        let r = RemovedApp {
            app_id: other_app().app_id_bytes(),
            distrust_from: 0,
        };
        removed_twice.removed.extend([r, r]);
        assert!(removed_twice.check(&identity().public()).is_err());
    }

    #[test]
    fn test_identity_counters_policy_and_age_limit() {
        for f in [
            (|b: &mut IdentityBody| b.version = 0) as fn(&mut IdentityBody),
            |b| b.generation = 0,
            |b| b.data_epoch = 0,
            |b| b.record_max_age = Some(0),
            |b| b.inbox.url = "https://inbox.example/".into(),
        ] {
            let mut b = body();
            f(&mut b);
            assert!(b.check(&identity().public()).is_err());
        }
        let mut v: serde_json::Value = serde_json::from_slice(&body().to_json().unwrap()).unwrap();
        v["policy"]["admission"] = serde_json::json!("everyone");
        assert!(IdentityDoc::verify(&resign(&v), &identity().public()).is_err());
        // Every connect_requests member is required, and none is null.
        let mut v: serde_json::Value = serde_json::from_slice(&body().to_json().unwrap()).unwrap();
        IdentityDoc::verify(&resign(&v), &identity().public()).unwrap();
        v["policy"]["connect_requests"] = serde_json::json!({});
        assert!(IdentityDoc::verify(&resign(&v), &identity().public()).is_err());
        for member in ["enabled", "max_pending", "push"] {
            let mut v: serde_json::Value =
                serde_json::from_slice(&body().to_json().unwrap()).unwrap();
            let connect = v["policy"]["connect_requests"].as_object_mut().unwrap();
            connect.remove(member);
            assert!(
                IdentityDoc::verify(&resign(&v), &identity().public()).is_err(),
                "{member} missing"
            );
            v["policy"]["connect_requests"][member] = serde_json::Value::Null;
            assert!(
                IdentityDoc::verify(&resign(&v), &identity().public()).is_err(),
                "{member} null"
            );
        }
        let mut b = body();
        b.record_max_age = Some(30);
        assert_eq!(sign(b).record_max_age_ms(), 30_000);
        assert_eq!(
            sign(body()).record_max_age_ms(),
            DEFAULT_RECORD_MAX_AGE_S * 1000
        );
    }

    #[test]
    fn test_identity_service_keys_rules() {
        let key = |generation| ServiceKeyEntry {
            generation,
            key: [generation as u8; 32],
        };
        let at = |generation: u64, keys: Vec<ServiceKeyEntry>| {
            let mut b = body();
            b.generation = generation;
            b.service_keys = keys;
            b
        };
        at(2, vec![key(1)]).check(&identity().public()).unwrap();
        at(300, (1..=256).map(key).collect())
            .check(&identity().public())
            .unwrap();
        for (what, b) in [
            ("257 entries", at(300, (1..=257).map(key).collect())),
            ("descending", at(5, vec![key(2), key(1)])),
            ("twice", at(5, vec![key(1), key(1)])),
            ("its own generation", at(2, vec![key(1), key(2)])),
            ("a later generation", at(2, vec![key(3)])),
            ("generation 0", at(2, vec![key(0)])),
        ] {
            assert!(b.check(&identity().public()).is_err(), "{what}");
        }
        let doc = sign(at(2, vec![key(1)]));
        assert_eq!(doc.service_key_of(1), Some([1; 32]));
        assert_eq!(doc.service_key_of(2), Some([8; 32]));
        assert_eq!(doc.service_key_of(3), None);
        // A present `[]` is none.
        let mut v: serde_json::Value = serde_json::from_slice(&body().to_json().unwrap()).unwrap();
        v["service_keys"] = serde_json::json!([]);
        let read = IdentityDoc::verify(&resign(&v), &identity().public()).unwrap();
        assert!(read.body().service_keys.is_empty());
    }

    #[test]
    fn test_identity_standing_and_counting() {
        let (wallet, gone) = (app().app_id_bytes(), other_app().app_id_bytes());
        let mut b = body();
        b.apps[0].cert = [2; 32];
        b.renewed.push(RenewedCert {
            app_id: wallet,
            cert: [1; 32],
            until: None,
        });
        b.removed.push(RemovedApp {
            app_id: gone,
            distrust_from: 1_000_000,
        });
        let open = sign(b.clone());
        assert_eq!(open.standing(&wallet, &[2; 32]), Standing::Listed);
        assert_eq!(open.standing(&wallet, &[1; 32]), Standing::RenewedOpen);
        assert_eq!(open.standing(&wallet, &[3; 32]), Standing::None);
        assert!(open.current_now(&wallet, &[1; 32]));
        assert_eq!(b.close_renewals(&wallet, 600_000), 1);
        assert_eq!(b.close_renewals(&wallet, 700_000), 0, "only open entries");
        let closed = sign(b);
        assert!(!closed.current_now(&wallet, &[1; 32]));
        let until = 600_000;
        assert!(closed.counts_at(&wallet, &[1; 32], until - CLOCK_TOLERANCE_MS - 1));
        assert!(!closed.counts_at(&wallet, &[1; 32], until - CLOCK_TOLERANCE_MS));
        let distrust = 1_000_000;
        assert!(closed.counts_at(&gone, &[9; 32], distrust - CLOCK_TOLERANCE_MS));
        assert!(!closed.counts_at(&gone, &[9; 32], distrust - CLOCK_TOLERANCE_MS + 1));
        assert!(!closed.current_now(&gone, &[9; 32]));
    }

    #[test]
    fn test_identity_first_document_rule() {
        sign(body()).check_first().unwrap();
        let mut later = body();
        later.version = 3;
        assert!(sign(later.clone()).check_first().is_err());
        later.recovery_from = Some(1);
        sign(later).check_first().unwrap();
    }

    #[test]
    fn test_identity_compare_and_successor() {
        let v1 = sign(body());
        let mut b2 = body();
        b2.version = 2;
        let v2 = sign(b2.clone());
        assert_eq!(v1.compare(&v2), VersionOrder::Newer);
        assert_eq!(v2.compare(&v1), VersionOrder::Older);
        assert_eq!(v1.compare(&v1.clone()), VersionOrder::Same);
        let mut other = body();
        other.data_epoch = 2;
        assert_eq!(v1.compare(&sign(other)), VersionOrder::Equivocation);
        let mut resigned = v1.clone();
        resigned.signed.sig = crate::enc::b64(&[3; 64]);
        assert_eq!(v1.compare(&resigned), VersionOrder::SameBody);
        let mut lower_generation = b2.clone();
        lower_generation.generation = 2;
        let at_generation_2 = sign(lower_generation);
        let mut b3 = body();
        b3.version = 3;
        assert_eq!(
            at_generation_2.compare(&sign(b3)),
            VersionOrder::Older,
            "a lower generation"
        );
        v1.check_successor(&v2).unwrap();
        assert!(v2.check_successor(&v1).is_err());
        assert!(v1.check_successor(&v1).is_err());
        // An App ID once removed is never listed again.
        let mut removed = body();
        removed.version = 4;
        removed.apps.clear();
        removed.removed.push(RemovedApp {
            app_id: app().app_id_bytes(),
            distrust_from: 0,
        });
        let removed_doc = sign(removed);
        let mut back = body();
        back.version = 5;
        let error = removed_doc.check_successor(&sign(back)).unwrap_err();
        assert!(error.to_string().contains("removed"), "{error}");
    }

    #[test]
    fn test_seen_bodies_flags_equivocation_only() {
        let v1 = sign(body());
        let mut seen = SeenBodies::new();
        seen.see(&v1).unwrap();
        seen.see(&v1).unwrap();
        let mut other = body();
        other.data_epoch = 2;
        assert!(seen.see(&sign(other)).is_err());
        assert!(seen.equivocates(&identity().public()));
    }

    #[test]
    fn test_identity_verify_named_reads_the_key_from_the_body() {
        let doc = sign(body());
        assert_eq!(IdentityDoc::verify_named(doc.signed()).unwrap(), doc);
    }
}
