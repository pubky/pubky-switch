//! The signer's records in the host's store, and the flow in progress.
//!
//! Everything lives in one namespace, `signer/<identity>`, under two keys: the records
//! (`SignerState`) and the flow in progress (`Flow`), always committed together. A flow
//! holds every artifact it signed before sending it, so a crash resends the same bytes and
//! nothing is signed twice (Switch wire 2.1). Nothing in the Switch spec fixes this layout;
//! it is the crate's own, versioned by [`SCHEMA_VERSION`].
//!
//! The records hold no secret: the identity key stays in the host's vault.

use pubky_switch_client::store::{StoreHandle, WriteBatch};
use pubky_switch_core::enc::zbase32_encode;
use pubky_switch_core::records::{
    DEFAULT_CERT_LIFETIME_MS, IdentityDoc, IdentityPolicy, Limits, SignerBackup, StoredPart,
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
    /// The alerts the user hasn't cleared.
    pub(crate) alerts: Vec<Alert>,
    /// The certificate lifetime new certificates get, in milliseconds (Switch spec 3.2).
    pub(crate) cert_lifetime_ms: u64,
    /// The companion claims of approvals, signed once, until the host has delivered them
    /// (Switch wire 3.10).
    pub(crate) claims: Vec<PendingClaim>,
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

impl SignerState {
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
            alerts: Vec::new(),
            cert_lifetime_ms: DEFAULT_CERT_LIFETIME_MS,
            claims: Vec::new(),
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
    /// Renewing an app's certificate (Switch spec 3.2, Switch wire 3.8): storing the new
    /// certificate and the key bundles at the switch, batch by batch, then delivering the
    /// renewing version.
    Renew {
        /// The renewed app.
        app_id: [u8; 16],
        /// The signed batches, each sent again with the same bytes until it is answered.
        batches: Vec<Bytes>,
        /// How many batches the switch took.
        sent: usize,
        /// The key bundle parts the batches store.
        parts: Vec<StoredPart>,
        /// The renewing version, as signed.
        doc: SignedDoc,
        /// The document hash of the version it builds on.
        prev: Option<[u8; 32]>,
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

/// Bytes kept as they were signed, stored in base64url.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct Bytes(
    #[serde(with = "pubky_switch_core::enc::serde_b64_vec")] pub(crate) Vec<u8>,
);

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
