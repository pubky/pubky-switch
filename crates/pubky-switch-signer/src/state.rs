//! The signer's records in the host's store, and the flow in progress.
//!
//! Everything lives in one namespace, `signer/<identity>`, under two keys: the records
//! (`SignerState`) and the flow in progress (`Flow`), always committed together. A flow
//! holds every artifact it signed before sending it, so a crash resends the same bytes and
//! nothing is signed twice (Switch wire 2.1). Nothing in the Switch spec fixes this layout;
//! it is the crate's own, versioned by [`SCHEMA_VERSION`].
//!
//! The records hold no secret: the identity key stays in the host's vault. A take-over's flow
//! holds the hand-over as the switch served it, sealed to the new signer's bundle key, until
//! the secret it carries is in the vault (Switch wire 3.12).

use pubky_switch_client::store::{StoreHandle, WriteBatch};
use pubky_switch_core::enc::zbase32_encode;
use pubky_switch_core::records::{
    DEFAULT_CERT_LIFETIME_MS, IdentityDoc, IdentityPolicy, Limits, SignerBackup, SignerHandover,
    StoredPart,
};
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};

use crate::alert::Alert;
use crate::error::{Result, SignerError};

/// The version of the records' layout.
pub const SCHEMA_VERSION: u32 = 1;

/// The prefix of the signer's namespace, which the identity's Pubky ID in z-base-32 follows.
pub const SIGNER_NAMESPACE_PREFIX: &str = "signer/";

const STATE_KEY: &[u8] = b"state";
const FLOW_KEY: &[u8] = b"flow";

/// The signer's namespace for an identity: `signer/<identity>`.
pub fn signer_namespace(identity: &[u8; 32]) -> String {
    format!("{SIGNER_NAMESPACE_PREFIX}{}", zbase32_encode(identity))
}

/// The switch the identity is enrolled at (Switch wire 3.7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Service {
    /// The switch origin, exactly as `identity.json` names it.
    pub(crate) origin: String,
    /// The account's service key, from the enrollment answer.
    pub(crate) service_key: [u8; 32],
    /// The limits the enrollment answer announced, which the switch gives only then.
    pub(crate) limits: Limits,
}

/// The newest `identity.json` a service accepted from this signer, or that it adopted: its
/// high-water mark (Switch spec 4.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Newest {
    /// The document, as signed.
    pub(crate) doc: SignedDoc,
    /// The document hash of the version it builds on; `None` for a first version and an
    /// adopted copy.
    pub(crate) prev: Option<[u8; 32]>,
    /// Whether it is published on the Homeserver.
    pub(crate) published: bool,
    /// The service time at which the switch took it, from its delivery's transition proof;
    /// `None` for an adopted copy. A reduction's cutoff is this time plus the clock tolerance
    /// (Switch wire 3.8).
    #[serde(default)]
    pub(crate) delivered_at: Option<u64>,
}

/// The signer's records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SignerState {
    /// The layout version.
    pub(crate) v: u32,
    /// The identity.
    pub(crate) identity: [u8; 32],
    /// This install's signer ID, picked at random when it first signs (Switch spec 4.3).
    pub(crate) install: [u8; 16],
    /// The switch, once the enrollment is answered.
    pub(crate) service: Option<Service>,
    /// The newest version accepted or adopted.
    pub(crate) newest: Option<Newest>,
    /// The highest version this install committed a signed `identity.json` at, sent or not.
    /// Every new version is signed above it, so no version is signed twice with two bodies
    /// (Switch spec 4.3, 13.2).
    pub(crate) signed_through: u64,
    /// Every App ID revoked or seen departing, kept for good (Switch spec 12.2).
    pub(crate) tombstones: Vec<[u8; 16]>,
    /// The certificates the newest document references, as signed.
    pub(crate) certs: Vec<SignedDoc>,
    /// The key bundle parts stored for each listed app (Switch wire 3.5).
    pub(crate) bundle_parts: Vec<StoredPart>,
    /// Another install that the newest document or the backup names as the signer.
    pub(crate) managed_by: Option<[u8; 16]>,
    /// The version of a newer `identity.json` this install signed itself that the switch or
    /// the Homeserver holds: the records are behind, and nothing is signed until a restore
    /// from the signer backup replaces them ([`crate::Signer::restore`]).
    #[serde(default)]
    pub(crate) records_behind: Option<u64>,
    /// The document hash of another body at the mark's version that the Homeserver
    /// published, which raised [`Alert::Equivocation`].
    #[serde(default)]
    pub(crate) homeserver_other: Option<[u8; 32]>,
    /// That copy, once the user has seen its alert: publication writes the switch's copy over
    /// it (Switch wire 3.3 "Deliver, then publish").
    #[serde(default)]
    pub(crate) republish_over: Option<[u8; 32]>,
    /// The revocations asked for whose removal isn't delivered yet, with the earlier
    /// `distrust_from` the user picked, if any (Switch spec 12.2).
    #[serde(default)]
    pub(crate) revoking: Vec<Revoking>,
    /// The removed apps whose Homeserver record is still to be deleted (Switch spec 12.2
    /// step 4).
    #[serde(default)]
    pub(crate) cleanup: Vec<[u8; 16]>,
    /// The apps of `cleanup` whose [`Alert::GrantRevocationOwed`] was raised: once for each
    /// owed deletion, so the user can clear it while a deletion keeps failing.
    #[serde(default)]
    pub(crate) grant_reminded: Vec<[u8; 16]>,
    /// The removed apps a restore found whose record may still be on the Homeserver: the
    /// routine run checks them, a few at a time, and owes the deletion of those it finds.
    #[serde(default)]
    pub(crate) deletion_checks: Vec<[u8; 16]>,
    /// A restore's backup write is owed: it raced another signer, so it is written once its
    /// delivery has won (Switch wire 3.13).
    #[serde(default)]
    pub(crate) backup_owed: bool,
    /// The hand-over this install is making, until it takes effect or is aborted (Switch wire
    /// 3.12): it signs nothing for the identity but the abort meanwhile.
    #[serde(default)]
    pub(crate) handing_over: Option<HandingOver>,
    /// This install is taking the identity over from a hand-over, until its first delivery
    /// has won and the received secret is in the vault (Switch wire 3.12).
    #[serde(default)]
    pub(crate) taking_over: bool,
    /// A take-over's first version won, and its publication waits for its backup (Switch wire
    /// 3.12): the old signer's deletion relies on that order.
    #[serde(default)]
    pub(crate) publish_after_backup: bool,
    /// The hand-over took effect, naming this install as the signer: committed before the key
    /// is deleted, so records a crash leaves behind are deleted on the next open and count as
    /// none for a new set-up (Switch spec 12.8).
    #[serde(default)]
    pub(crate) handed_over_to: Option<[u8; 16]>,
    /// The full-bundle requests whose answer the switch refused, not tried again until the
    /// app asks anew.
    #[serde(default)]
    pub(crate) refused_requests: Vec<RefusedRequest>,
    /// The service time at which the switch took the first version this signer delivered
    /// that lists each app: no app left or was revoked before it (Switch spec 12.3).
    #[serde(default)]
    pub(crate) listed_at: Vec<([u8; 16], u64)>,
    /// The alerts the user hasn't cleared.
    pub(crate) alerts: Vec<Alert>,
    /// The certificate lifetime new certificates get, in milliseconds (Switch spec 3.2).
    #[serde(default = "default_cert_lifetime")]
    pub(crate) cert_lifetime_ms: u64,
    /// For each app, how many automatic renewals in a row no record of it has taken up: at
    /// two, the signer stops renewing it by itself (Switch spec 3.1). A renewal the user asks
    /// for, or a record carrying the newest certificate, takes the app out.
    #[serde(default)]
    pub(crate) untaken_renewals: Vec<([u8; 16], u32)>,
    /// The companion claims of approvals, signed once, until the host has delivered them
    /// (Switch wire 3.10).
    #[serde(default)]
    pub(crate) claims: Vec<PendingClaim>,
    /// The switch showed a rollback or an equivocation, and no delivery has succeeded since:
    /// the signer doesn't know that the switch holds its high-water version, so it releases
    /// no claim.
    #[serde(default)]
    pub(crate) switch_unconfirmed: bool,
    /// The highest data epoch whose keys this signer ever sent in a bundle, by a rotation it
    /// gave up too. While it is above the newest version's `data_epoch`, some apps may hold
    /// keys of an epoch no version raised: before its next rotation the signer completes that
    /// epoch, giving every current app holding each keyed scope its keys through it and
    /// delivering a version that raises `data_epoch` to it, then rotates by one (Switch spec
    /// 3.2, 3.5). A restore or a hand-over takes it as the highest `last_epoch` of the parts
    /// it receives and of `keys_through` and `bundle_ranges` in `GET /apps` (Switch wire 3.5,
    /// 3.12, 7.4.12), never below the newest `data_epoch`.
    #[serde(default)]
    pub(crate) epoch_through: u64,
    /// The version that was delivered again for its service time, because a closing delivery
    /// is owed and the delivery's answer was lost: its retry's answer must carry that time
    /// (Switch wire 7.4.2). It concerns only that version.
    #[serde(default)]
    pub(crate) time_asked: Option<u64>,
    /// The version whose retry gave no service time either: the closing stays owed, with
    /// [`Alert::ReductionNotClosed`] shown, until a later version's delivery carries a service
    /// time to close at.
    #[serde(default)]
    pub(crate) closing_unavailable: Option<u64>,
    /// The identity's account at its switch is erased (Switch spec 12.7): the records stay,
    /// and nothing more is signed for that account.
    #[serde(default)]
    pub(crate) erased: bool,
}

/// A hand-over this install is making (Switch wire 3.12).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HandingOver {
    /// The new signer's App ID.
    pub(crate) to_app: [u8; 16],
    /// The version handed over, as signed: the newest the switch accepted from this install.
    pub(crate) doc: SignedDoc,
    /// The hand-over, sealed to the new signer's bundle key and signed once, and sent again
    /// with the same bytes. It is ciphertext only that app opens.
    pub(crate) handover: SignerHandover,
    /// Where its `PUT /handover` is.
    pub(crate) sent: HandOverSent,
    /// The document hash of the abort, once it is signed: never taken for the new signer's
    /// version.
    pub(crate) abort: Option<[u8; 32]>,
    /// The take-back, once it is signed: kept to be sent again, the same bytes.
    #[serde(default)]
    pub(crate) take_back: Option<TakeBack>,
}

/// A take-back of the identity from a new signer that is lost (Switch wire 3.12).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TakeBack {
    /// The version, as signed: the switch's copy's content, naming this install.
    pub(crate) doc: SignedDoc,
    /// The document hash of the switch's copy it builds on.
    pub(crate) prev: [u8; 32],
    /// The install the switch's copy named.
    pub(crate) from: [u8; 16],
}

/// Where a hand-over's `PUT /handover` is (Switch wire 7.4.17).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum HandOverSent {
    /// Not answered yet: it is sent again, the same bytes.
    Pending,
    /// The switch stores it for the new signer.
    Stored,
    /// The switch refused it for good. An earlier send may still be stored, so the hand-over
    /// stays in progress until it takes effect or the user aborts it.
    Refused,
}

/// A take-over's first delivery (Switch wire 3.12), signed once with the received key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TakeOverDelivery {
    /// The version, as signed: the handed-over one plus 1, naming this install.
    pub(crate) doc: SignedDoc,
    /// The document hash of the handed-over version it builds on.
    pub(crate) prev: [u8; 32],
    /// Whether it won: the secret is put in the vault next, and nothing is sent again.
    pub(crate) won: bool,
}

/// A revocation asked for, until the version that removes the app is delivered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Revoking {
    /// The App ID.
    pub(crate) app_id: [u8; 16],
    /// An earlier `distrust_from` than the revocation time, which the user picked after a
    /// compromise.
    pub(crate) distrust_from: Option<u64>,
    /// The revocation's time, from the proof of the switch's answer (Switch wire 7.4.12).
    #[serde(default)]
    pub(crate) revoked_at: Option<u64>,
    /// Whether the switch answered the revocation, so it serves the app no more.
    #[serde(default)]
    pub(crate) taken: bool,
}

/// A full-bundle request the switch refused an answer to, by the time the app asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RefusedRequest {
    /// The app.
    pub(crate) app_id: [u8; 16],
    /// When it asked (`full_bundle_requested`, Switch wire 7.4.12).
    pub(crate) requested: u64,
}

/// An approval's companion claim, signed with the version that lists its certificate and
/// released to the host once the switch took that version (Switch wire 3.10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingClaim {
    /// The document hash of the app request it answers.
    pub(crate) request: [u8; 32],
    /// The approved app.
    pub(crate) app_id: [u8; 16],
    /// The document hash of its certificate.
    pub(crate) cert: [u8; 32],
    /// The capabilities of the Pubky grant, as the auth request carries them.
    pub(crate) caps: String,
    /// The claim's plaintext: the approval's JSON bytes, then the identity key's signature.
    #[serde(with = "pubky_switch_core::enc::serde_b64_vec")]
    pub(crate) plaintext: Vec<u8>,
}

/// The certificate lifetime of records written before it was kept: the default.
fn default_cert_lifetime() -> u64 {
    DEFAULT_CERT_LIFETIME_MS
}

impl SignerState {
    /// Keep only the certificates the newest version references, of its apps and its
    /// `renewed` entries, and the claims of certificates it lists: a version that wasn't
    /// delivered leaves none of its own behind.
    pub(crate) fn prune_unreferenced(&mut self) {
        let doc = self.newest_doc().ok().flatten();
        let referenced = |hash: &[u8; 32]| {
            doc.as_ref().is_some_and(|doc| {
                doc.body().apps.iter().any(|a| &a.cert == hash)
                    || doc.body().renewed.iter().any(|r| &r.cert == hash)
            })
        };
        self.certs
            .retain(|cert| cert.doc_hash().is_ok_and(|hash| referenced(&hash)));
        self.claims.retain(|claim| {
            doc.as_ref()
                .is_some_and(|doc| doc.listed_cert(&claim.app_id) == Some(claim.cert))
        });
    }

    /// The records of a new identity, for this install.
    pub(crate) fn new(identity: [u8; 32], install: [u8; 16]) -> Self {
        Self {
            v: SCHEMA_VERSION,
            identity,
            install,
            service: None,
            newest: None,
            signed_through: 0,
            tombstones: Vec::new(),
            certs: Vec::new(),
            bundle_parts: Vec::new(),
            managed_by: None,
            records_behind: None,
            homeserver_other: None,
            republish_over: None,
            revoking: Vec::new(),
            cleanup: Vec::new(),
            grant_reminded: Vec::new(),
            deletion_checks: Vec::new(),
            backup_owed: false,
            handing_over: None,
            taking_over: false,
            handed_over_to: None,
            publish_after_backup: false,
            refused_requests: Vec::new(),
            listed_at: Vec::new(),
            alerts: Vec::new(),
            cert_lifetime_ms: DEFAULT_CERT_LIFETIME_MS,
            untaken_renewals: Vec::new(),
            claims: Vec::new(),
            switch_unconfirmed: false,
            epoch_through: 0,
            time_asked: None,
            closing_unavailable: None,
            erased: false,
        }
    }

    /// The newest document, verified.
    pub(crate) fn newest_doc(&self) -> Result<Option<IdentityDoc>> {
        self.newest
            .as_ref()
            .map(|n| IdentityDoc::verify(&n.doc, &self.identity))
            .transpose()
            .map_err(SignerError::from)
    }

    /// Add `alert` unless it is held already.
    pub(crate) fn alert(&mut self, alert: Alert) {
        if !self.alerts.contains(&alert) {
            self.alerts.push(alert);
        }
    }

    /// Note the size of the newest version, `bytes`, the larger of its delivery and a move's
    /// enrollment carrying it (Switch wire 3.7, 7.1): [`Alert::IdentityNearLimit`] past three
    /// quarters of the body cap they share, replacing an earlier one, or none.
    pub(crate) fn note_size(&mut self, bytes: usize) {
        self.alerts
            .retain(|alert| !matches!(alert, Alert::IdentityNearLimit { .. }));
        let Some(limit) = pubky_switch_core::http::body_cap("PUT", "/v1/id/identity") else {
            return;
        };
        if bytes.saturating_mul(4) > limit.saturating_mul(3) {
            self.alerts.push(Alert::IdentityNearLimit {
                bytes: u64::try_from(bytes).unwrap_or(u64::MAX),
                limit: u64::try_from(limit).unwrap_or(u64::MAX),
            });
        }
    }
}

/// Where a delivery of a new version is (Switch spec 4.3, 12.8; Switch wire 3.13).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum DeliverStep {
    /// Signed and committed; the backup holding it is next.
    Signed,
    /// The backup holding it is on the Homeserver; the delivery is next.
    BackupWritten,
}

/// The flow in progress, with every artifact it signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Flow {
    /// Enrolling a new identity at a switch (Switch spec 4.3, Switch wire 3.7).
    Enroll {
        /// The switch origin.
        origin: String,
        /// The signed enrollment, sent again until it is answered.
        enrollment: SignedDoc,
        /// The policy the first `identity.json` carries.
        policy: IdentityPolicy,
    },
    /// Renewing an app's certificate (Switch spec 3.2, Switch wire 3.8), or completing a data
    /// epoch before a rotation: storing the new certificate and the key bundles at the switch,
    /// batch by batch, then delivering the version.
    Renew {
        /// The signed batches, each sent again with the same bytes until it is answered.
        batches: Vec<RenewBatch>,
        /// How many batches the switch took.
        sent: usize,
        /// The renewing version, as signed.
        doc: SignedDoc,
        /// The document hash of the version it builds on.
        prev: Option<[u8; 32]>,
    },
    /// Taking the identity over from a hand-over (Switch wire 3.12), until the first
    /// delivery has won and the secret is in the vault.
    TakingOver {
        /// The hand-over as the switch served it, sealed to this app's bundle key: the secret
        /// is opened from it in memory, to sign and to send, and goes to the vault only once
        /// the delivery has won.
        handover: SignerHandover,
        /// This app's App ID, the hand-over's target.
        app_id: [u8; 16],
        /// The first delivery, once check 3 has passed and it is signed.
        delivery: Option<TakeOverDelivery>,
    },
    /// Erasing the identity's account at its switch (Switch spec 12.7, Switch wire 7.4.16):
    /// first `identity.json` and the app records leave the Homeserver, then the erasure is
    /// sent until it is answered.
    Erase {
        /// The Homeserver's files are deleted.
        unpublished: bool,
        /// The App IDs whose grant reminder this erasure raised: withdrawn if it ends without
        /// erasing the account.
        #[serde(default)]
        reminded: Vec<[u8; 16]>,
        /// An erasure request went out and no answer came back: it may have landed, so the
        /// operator's `404` now means it did (Switch wire 7.4.16).
        #[serde(default)]
        unanswered: bool,
    },
    /// Delivering a new `identity.json` version, then publishing it.
    Deliver {
        /// The new version, as signed.
        doc: SignedDoc,
        /// The document hash of the version it builds on.
        prev: Option<[u8; 32]>,
        /// The backup holding it, sealed and signed once.
        backup: Option<SignerBackup>,
        /// Where it is.
        step: DeliverStep,
    },
}

/// One signed batch of a renewal or an epoch's completion, and the key bundle parts it stores.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RenewBatch {
    /// The batch, as signed.
    pub(crate) bytes: Bytes,
    /// The key bundle parts it stores (Switch wire 3.5).
    pub(crate) parts: Vec<StoredPart>,
}

/// Bytes kept as they were signed, stored in base64url.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct Bytes(
    #[serde(with = "pubky_switch_core::enc::serde_b64_vec")] pub(crate) Vec<u8>,
);

/// Delete the records and the flow of `identity`, in one atomic write: once the identity was
/// handed over, or a take-over was cancelled (Switch spec 12.8).
pub(crate) async fn delete(store: &StoreHandle, identity: &[u8; 32]) -> Result<()> {
    let ns = signer_namespace(identity);
    let mut batch = WriteBatch::new();
    for key in [STATE_KEY, FLOW_KEY] {
        batch
            .delete(&ns, key)
            .map_err(|e| SignerError::Records(e.to_string()))?;
    }
    store.commit(batch).await?;
    Ok(())
}

/// Whether the store holds records for `identity` that a new set-up would replace: any but
/// those of a hand-over that took effect, which are only waiting to be deleted.
pub(crate) async fn set_up(store: &StoreHandle, identity: &[u8; 32]) -> Result<bool> {
    Ok(load(store, identity)
        .await?
        .is_some_and(|(state, _)| state.handed_over_to.is_none()))
}

/// Read the records and the flow of `identity`; `None` when the store holds none.
pub(crate) async fn load(
    store: &StoreHandle,
    identity: &[u8; 32],
) -> Result<Option<(SignerState, Option<Flow>)>> {
    let ns = signer_namespace(identity);
    let Some(bytes) = store.get(&ns, STATE_KEY).await? else {
        return Ok(None);
    };
    let state: SignerState = decode(&bytes)?;
    if state.v != SCHEMA_VERSION || &state.identity != identity {
        return Err(SignerError::Records(
            "another layout version or identity".into(),
        ));
    }
    let flow = match store.get(&ns, FLOW_KEY).await? {
        Some(bytes) => Some(decode(&bytes)?),
        None => None,
    };
    Ok(Some((state, flow)))
}

/// Commit the records and the flow together, in one atomic write.
pub(crate) async fn save(
    store: &StoreHandle,
    state: &SignerState,
    flow: Option<&Flow>,
) -> Result<()> {
    let ns = signer_namespace(&state.identity);
    let mut batch = WriteBatch::new();
    batch
        .put(&ns, STATE_KEY, encode(state)?)
        .map_err(|e| SignerError::Records(e.to_string()))?;
    match flow {
        Some(flow) => batch
            .put(&ns, FLOW_KEY, encode(flow)?)
            .map_err(|e| SignerError::Records(e.to_string()))?,
        None => batch
            .delete(&ns, FLOW_KEY)
            .map_err(|e| SignerError::Records(e.to_string()))?,
    };
    store.commit(batch).await?;
    Ok(())
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| SignerError::Records(e.to_string()))
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    // The decoder's message can quote the stored value, which may hold signed records:
    // only the position is kept.
    serde_json::from_slice(bytes)
        .map_err(|e| SignerError::Records(format!("at line {} column {}", e.line(), e.column())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_near_limit_raised_replaced_and_cleared() {
        // The cap a delivery and a move's enrollment share is 256 KiB (Switch wire 3.7, 7.1):
        // past three quarters of it the user is told, one alert at a time, with the newest
        // size, and none once the version is smaller again.
        let limit = 256 << 10;
        let near = |bytes: usize| Alert::IdentityNearLimit {
            bytes: bytes as u64,
            limit: limit as u64,
        };
        let mut state = SignerState::new([1; 32], [2; 16]);
        state.note_size(limit * 3 / 4);
        assert!(state.alerts.is_empty());
        state.note_size(limit * 3 / 4 + 1);
        assert_eq!(state.alerts, [near(limit * 3 / 4 + 1)]);
        state.note_size(limit + 10);
        assert_eq!(state.alerts, [near(limit + 10)]);
        state.note_size(1_000);
        assert!(state.alerts.is_empty());
    }

    #[test]
    fn test_state_written_before_the_approval_fields_still_reads() {
        // The records as they were written before the certificate lifetime and the claims
        // were kept: both take their defaults.
        let state = SignerState::new([1; 32], [2; 16]);
        let mut value = serde_json::to_value(&state).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("cert_lifetime_ms");
        object.remove("claims");
        let read: SignerState = decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(read.cert_lifetime_ms, DEFAULT_CERT_LIFETIME_MS);
        assert!(read.claims.is_empty());
        assert_eq!(read, state);
    }
}
