//! Shared records (Switch spec 8.2, 8.3, 10.3; Switch wire 6.2 `record.put`, 7.4.9).
//!
//! A shared record is a protocol's: its collections and their fixed policies come from
//! [`super::Protocol::collections`], or from the caller as a [`Collection`]. The app keeps,
//! per record key, the write it took (`rec/<key>`), the protocol's mark of what it has seen
//! there (`hw/<key>`), and the writes it refused (`flag/<key>/<version>`).
//!
//! - **Keys** come from the naming key: `derive("pubky-switch/v1/record", collection,
//!   blind(natural key), policy hash)` (Switch spec 13.3).
//! - **Writes** are compare-and-swap on the version the app holds, `{0, 0}` with `id_inputs`
//!   to create a record or create a deleted one again; the value is sealed under the read
//!   scope's key at the current data epoch, a sub-scope's key derived from its parent's
//!   (Switch spec 3.5, 13.4). A delete is the sealed empty plaintext.
//! - **Every write the app reads** (from the feed, a read, a list page or after its own
//!   write) passes the checks of Switch wire 6.2 "Accepting a write" before it is taken: the
//!   writer's certificate and signature, the proof or stub that dates it and gives its
//!   version, the collection's fixed policy and the key's derivation, the writer's standing
//!   at the write's time, its write scope, and the sealed value opening. Signed evidence of
//!   misbehaviour is a rollback (Switch spec 10.1); any other failure leaves the write
//!   ignored and shown with the app it names (Switch spec 8.2).
//! - **A write replaces the one held** only if it is newer by the core's rule
//!   ([`WriteVersion::replaces`]), and only if the protocol finds it doesn't go back on what
//!   the app has seen there ([`super::Protocol::record_regression`]). A write refused that
//!   way is flagged, its content not acted on, but its version followed, so the app's next
//!   write builds on it and puts back the content it trusts (Switch spec 8.2).
//! - **Listing** runs at join and after a `missed` item (Switch spec 8.2, 8.3).

use pubky_switch_core::chain::{ChainEnvelope, TransitionProof};
use pubky_switch_core::enc::{b64, serde_b64, serde_b64_vec, unb64_array};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ident::{Policy, collection_id, record_key_from_blinded};
use pubky_switch_core::ops::{Condition, IdInputs, OpKind, RecordPut, RecordVersion, SignedOp};
use pubky_switch_core::records::{AppCert, AppRecord, Standing};
use pubky_switch_core::sealed::{RecordValue, SealedValue};
use pubky_switch_core::shared::{WriteVersion, date_write};
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};

use super::batch::OpBatch;
use super::error::{Alarm, Refusal};
use super::events::AppEvent;
use super::state::{Tx, key};
use super::{App, AppError};
use crate::client::answers::{ChainItem, SharedRecordView};
use crate::error::ClientError;

const RECORD_PREFIX: &str = "rec/";
const SEEN_PREFIX: &str = "hw/";
const FLAG_PREFIX: &str = "flag/";
const CERT_PREFIX: &str = "ocert/";
/// Set while the app owes a listing of its collections: at join, after a `missed` item.
pub(crate) const LIST_DUE: &str = "list_due";

/// The most records one listing page asks for (Switch wire 7.4.9).
const LIST_PAGE: u32 = 1000;

/// How many times a write is built again after a conflict before the call gives up.
const UPDATE_TRIES: usize = 4;

pub(crate) fn record_key_of(key: &[u8; 32]) -> String {
    format!("{RECORD_PREFIX}{}", b64(key))
}

pub(crate) fn seen_key(key: &[u8; 32]) -> String {
    format!("{SEEN_PREFIX}{}", b64(key))
}

fn flag_key(key: &[u8; 32], version: RecordVersion) -> String {
    format!(
        "{FLAG_PREFIX}{}/{}/{}",
        b64(key),
        key::num(version.generation),
        key::num(version.version)
    )
}

fn cert_key(app_id: &[u8; 16], cert_hash: &[u8; 32]) -> String {
    format!(
        "{CERT_PREFIX}{}/{}",
        pubky_switch_core::enc::zbase32_encode(app_id),
        b64(cert_hash)
    )
}

/// Which policies a collection's records may have (Switch spec 3.3, 10.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PolicyFamily {
    /// The fixed policy alone.
    #[default]
    Fixed,
    /// The fixed policy, whose read scope is a name, and one policy per sub-scope of that
    /// name: for `<sub>`, the read scope `<name>:<sub>`, and the write scopes with `<name>`
    /// narrowed to `<name>:<sub>` and the others kept. An app holding `<name>` reads every
    /// member, one holding only `<name>:<sub>` its own (Switch spec 3.3, 8.2).
    SubScopes,
}

/// A collection of a protocol and its fixed policy (Switch spec 10.3). The collection name
/// is the protocol's opaque string. One name may come with several policies, such as one per
/// sub-scope: either each as a collection of its own here, or as one collection with the
/// family [`PolicyFamily::SubScopes`], which lists and reads every member the app holds
/// the read scope of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    /// The collection name.
    pub name: String,
    /// The fixed policy; with [`PolicyFamily::SubScopes`], the name scope's.
    pub policy: Policy,
    /// The policies besides the fixed one.
    pub family: PolicyFamily,
}

impl Collection {
    /// A collection with its fixed policy alone.
    pub fn new(name: &str, policy: Policy) -> Self {
        Self {
            name: name.to_owned(),
            policy,
            family: PolicyFamily::Fixed,
        }
    }

    /// A collection with the name scope's `policy` and one policy per sub-scope
    /// ([`PolicyFamily::SubScopes`]).
    pub fn with_sub_scopes(name: &str, policy: Policy) -> Self {
        Self {
            name: name.to_owned(),
            policy,
            family: PolicyFamily::SubScopes,
        }
    }

    /// The collection ID of `identity` (Switch spec 13.3).
    pub fn id(&self, identity: &[u8; 32]) -> [u8; 32] {
        collection_id(&self.name, identity)
    }

    /// The policy of sub-scope `sub` ([`PolicyFamily::SubScopes`]).
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a collection without sub-scope policies, a fixed read scope
    /// that isn't a name, or a `sub` that isn't a sub-scope (Switch spec 3.3).
    pub fn sub_scope_policy(&self, sub: &str) -> Result<Policy, AppError> {
        let name = self.policy.read_scope.as_str();
        if self.family != PolicyFamily::SubScopes
            || !pubky_switch_core::scopes::is_name(name)
            || !pubky_switch_core::scopes::is_sub(sub)
        {
            return Err(Refusal::Usage(
                "Switch spec 3.3: no sub-scope policy of this collection for that sub-scope".into(),
            )
            .into());
        }
        let narrowed = format!("{name}:{sub}");
        let writes: Vec<&str> = self
            .policy
            .write_scopes
            .iter()
            .map(|scope| {
                if scope == name {
                    narrowed.as_str()
                } else {
                    scope.as_str()
                }
            })
            .collect();
        Ok(Policy::new(&narrowed, &writes))
    }

    /// The collection of sub-scope `sub` alone: its records, read and written under that
    /// sub-scope's policy, for a [`RecordTarget`].
    ///
    /// # Errors
    ///
    /// As [`Collection::sub_scope_policy`].
    pub fn sub_scope(&self, sub: &str) -> Result<Collection, AppError> {
        Ok(Collection::new(&self.name, self.sub_scope_policy(sub)?))
    }

    /// Which member of the family `policy` is: `Some(None)` for the fixed policy,
    /// `Some(Some(sub))` for the policy of sub-scope `sub`, `None` for a policy the
    /// collection doesn't have.
    pub fn member(&self, policy: &Policy) -> Option<Option<String>> {
        if *policy == self.policy {
            return Some(None);
        }
        if self.family != PolicyFamily::SubScopes {
            return None;
        }
        let (name, sub) = pubky_switch_core::scopes::split(&policy.read_scope)?;
        let sub = sub?;
        if name != self.policy.read_scope {
            return None;
        }
        let expected = self.sub_scope_policy(sub).ok()?;
        (expected == *policy).then(|| Some(sub.to_owned()))
    }

    /// Whether a record may have `policy` in this collection.
    pub fn admits(&self, policy: &Policy) -> bool {
        self.member(policy).is_some()
    }

    /// Whether a certificate holds the read scope of any member, so its app lists the
    /// collection (Switch spec 8.3).
    pub fn readable_by(&self, cert: &AppCert) -> bool {
        if cert.holds_scope(&self.policy.read_scope) {
            return true;
        }
        self.family == PolicyFamily::SubScopes
            && cert.scopes().iter().any(|scope| {
                pubky_switch_core::scopes::split(scope)
                    .is_some_and(|(name, sub)| sub.is_some() && name == self.policy.read_scope)
            })
    }
}

/// A record by its collection and natural key, which the naming key blinds (Switch spec
/// 13.3). Its `Debug` shows no natural key.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordTarget {
    /// The collection and its fixed policy.
    pub collection: Collection,
    /// The natural key, the protocol's bytes.
    pub natural_key: Vec<u8>,
}

impl std::fmt::Debug for RecordTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecordTarget({}, ..)", self.collection.name)
    }
}

impl RecordTarget {
    /// The record of `natural_key` in `collection`.
    pub fn new(collection: Collection, natural_key: &[u8]) -> Self {
        Self {
            collection,
            natural_key: natural_key.to_vec(),
        }
    }
}

/// What a record holds, as the app reads it. Its `Debug` shows only the size.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordContent {
    /// The value's JSON bytes.
    Value(#[serde(with = "serde_b64_vec")] Vec<u8>),
    /// A delete: the sealed empty plaintext (Switch wire 6.2).
    Deleted,
    /// Sealed at a data epoch whose key the app doesn't hold (Switch spec 3.5).
    Unreadable,
}

impl std::fmt::Debug for RecordContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value(bytes) => write!(f, "Value({} bytes)", bytes.len()),
            Self::Deleted => f.write_str("Deleted"),
            Self::Unreadable => f.write_str("Unreadable"),
        }
    }
}

impl RecordContent {
    /// The value's JSON bytes, if the record holds a readable value.
    pub fn value(&self) -> Option<&[u8]> {
        match self {
            Self::Value(bytes) => Some(bytes),
            _ => None,
        }
    }
}

/// A shared record as the app holds it: the newest write it accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedRecord {
    /// The record key.
    pub key: [u8; 32],
    /// The collection name.
    pub collection: String,
    /// The policy.
    pub policy: Policy,
    /// The version of the write held.
    pub version: RecordVersion,
    /// Whether a proof or a verified stub gave the version; otherwise it is the service's
    /// word, known only to be after the version the write was built on (Switch spec 10.3).
    pub authenticated: bool,
    /// The writer.
    pub writer: [u8; 16],
    /// The write's service time, when a proof or a verified stub dates it.
    pub written_at_ms: Option<u64>,
    /// The content.
    pub content: RecordContent,
    /// A write by a removed app that nothing dates: no automatic attempt relies on it
    /// (Switch spec 12.2 step 3).
    pub doubtful: bool,
    /// The switch's current write is one the app refused: the content is what the app
    /// trusts, and its next write builds on the refused write's version (Switch spec 8.2).
    pub flagged: bool,
}

/// A signed operation the app keeps as evidence: a `record.put` or a claim entry, its
/// writer's certificate, and its transition proof when held. Its `Debug` shows no content.
#[derive(Clone, PartialEq, Eq)]
pub struct KeptOp {
    /// The signed operation, with its sealed value.
    pub op: SignedDoc,
    /// The writer's certificate.
    pub cert: SignedDoc,
    /// The transition proof of its write, if held.
    pub proof: Option<SignedDoc>,
}

impl std::fmt::Debug for KeptOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeptOp(proof: {})", self.proof.is_some())
    }
}

/// What the app keeps of the shared state, as evidence for the uploads of a move or a
/// recovery (Switch spec 12.5 step 3, 12.6 step 3): each operation goes as one kept
/// operation, each proof as one kept proof. Its `Debug` shows only counts.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SharedEvidence {
    /// The record writes held and the claim entries kept.
    pub ops: Vec<KeptOp>,
    /// The SETTLED and tombstone proofs kept.
    pub proofs: Vec<SignedDoc>,
}

impl std::fmt::Debug for SharedEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SharedEvidence({} ops, {} proofs)",
            self.ops.len(),
            self.proofs.len()
        )
    }
}

/// A write the app refused (Switch spec 8.2): shown with the app it names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlaggedWrite {
    /// The record key.
    #[serde(with = "serde_b64")]
    pub key: [u8; 32],
    /// The write's version as shown.
    #[serde(with = "version_serde")]
    pub version: RecordVersion,
    /// The app that signed it.
    #[serde(with = "serde_b64")]
    pub writer: [u8; 16],
    /// The rule it broke, without content.
    pub reason: String,
}

mod version_serde {
    use pubky_switch_core::ops::RecordVersion;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<S: Serializer>(v: &RecordVersion, s: S) -> Result<S::Ok, S::Error> {
        (v.generation, v.version).serialize(s)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<RecordVersion, D::Error> {
        let (generation, version) = <(u64, u64)>::deserialize(d)?;
        Ok(RecordVersion::new(generation, version))
    }
}

mod opt_version_serde {
    use pubky_switch_core::ops::RecordVersion;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        v: &Option<RecordVersion>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        v.map(|v| (v.generation, v.version)).serialize(s)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<RecordVersion>, D::Error> {
        Ok(Option::<(u64, u64)>::deserialize(d)?.map(|(g, v)| RecordVersion::new(g, v)))
    }
}

/// `rec/<key>`: the write the app took for a record. Sensitive: it holds the opened value.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HeldRecord {
    collection: String,
    policy: Policy,
    op: SignedDoc,
    cert: Option<SignedDoc>,
    proof: Option<SignedDoc>,
    #[serde(with = "version_serde")]
    version: RecordVersion,
    authenticated: bool,
    #[serde(with = "version_serde")]
    expected: RecordVersion,
    written_at_ms: Option<u64>,
    #[serde(with = "serde_b64")]
    writer: [u8; 16],
    #[serde(with = "serde_b64")]
    item_hash: [u8; 32],
    content: RecordContent,
    doubtful: bool,
    /// The switch's current write, which the app refused: its version.
    #[serde(with = "opt_version_serde")]
    follow: Option<RecordVersion>,
}

impl std::fmt::Debug for HeldRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HeldRecord({}, {:?})", self.collection, self.content)
    }
}

impl HeldRecord {
    /// The version the next write builds on: the switch's current write's, also when the
    /// app refused it.
    pub(crate) fn base_version(&self) -> RecordVersion {
        self.follow.unwrap_or(self.version)
    }

    fn write_version(&self) -> WriteVersion {
        WriteVersion {
            version: self.version,
            authenticated: self.authenticated,
            expected_version: self.expected,
        }
    }

    pub(crate) fn shared(&self, key: &[u8; 32]) -> SharedRecord {
        SharedRecord {
            key: *key,
            collection: self.collection.clone(),
            policy: self.policy.clone(),
            version: self.version,
            authenticated: self.authenticated,
            writer: self.writer,
            written_at_ms: self.written_at_ms,
            content: self.content.clone(),
            doubtful: self.doubtful,
            flagged: self.follow.is_some(),
        }
    }
}

/// What the app reads a write from (Switch wire 6.2 "Accepting a write" step 1).
#[derive(Clone, Copy)]
pub(crate) struct Evidence<'a> {
    pub(crate) op: &'a SignedDoc,
    pub(crate) cert: Option<&'a SignedDoc>,
    pub(crate) proof: Option<&'a SignedDoc>,
    /// The write's verified chain stub, from the feed.
    pub(crate) stub: Option<&'a ChainEnvelope>,
    /// The record view's version: the service's word.
    pub(crate) view_version: Option<RecordVersion>,
}

/// A write that passed the checks.
struct Accepted {
    key: [u8; 32],
    collection: Collection,
    op: SignedDoc,
    cert: AppCert,
    proof: Option<SignedDoc>,
    version: WriteVersion,
    time: Option<u64>,
    writer: [u8; 16],
    item_hash: [u8; 32],
    content: RecordContent,
    doubtful: bool,
}

/// Why a write wasn't taken.
enum Refused {
    /// Signed evidence of misbehaviour: a rollback.
    Misbehaviour(String),
    /// A failed check: ignored and shown with the app it names.
    Invalid { writer: [u8; 16], reason: String },
    /// Not a write the app takes: another collection, or a writer it can't find.
    Ignored,
}

/// What [`App::take_write`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Taken {
    New,
    Same,
    NotNewer,
    Flagged,
}

impl App {
    // ---------------------------------------------------------------------------------
    // Keys and local reads

    /// The record key of `target`, from the naming key and the collection's policy (Switch
    /// spec 13.3).
    ///
    /// # Errors
    ///
    /// [`AppError::InvalidData`] for a policy whose write scopes aren't sorted and unique.
    pub fn record_key(&self, target: &RecordTarget) -> Result<[u8; 32], AppError> {
        Ok(self.state.naming.record_key(
            &target.collection.name,
            &target.natural_key,
            &target.collection.policy.hash()?,
        ))
    }

    pub(crate) async fn held_record(&self, key: &[u8; 32]) -> Result<Option<HeldRecord>, AppError> {
        self.reader().get(&record_key_of(key)).await
    }

    /// The record the app holds at `key`, without reading the switch.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn shared_record(&self, key: &[u8; 32]) -> Result<Option<SharedRecord>, AppError> {
        Ok(self.held_record(key).await?.map(|held| held.shared(key)))
    }

    /// Every record the app holds of `collection`, without reading the switch.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn records_of(&self, collection: &str) -> Result<Vec<SharedRecord>, AppError> {
        let mut out = Vec::new();
        for (rest, held) in self.reader().scan::<HeldRecord>(RECORD_PREFIX).await? {
            if held.collection != collection {
                continue;
            }
            let key = unb64_array::<32>(&rest).map_err(|_| store_corrupt())?;
            out.push(held.shared(&key));
        }
        Ok(out)
    }

    /// The writes the app refused (Switch spec 8.2), oldest key first.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn flagged_writes(&self) -> Result<Vec<FlaggedWrite>, AppError> {
        Ok(self
            .reader()
            .scan::<FlaggedWrite>(FLAG_PREFIX)
            .await?
            .into_iter()
            .map(|(_, flagged)| flagged)
            .collect())
    }

    /// The evidence the app keeps of the shared state: the record write it holds for each
    /// record, with the certificate and proof it was checked with, the claim entries it
    /// keeps, and the SETTLED and tombstone proofs, for the uploads of a move or a recovery
    /// (Switch spec 6.3, 12.5 step 3, 12.6 step 3).
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn shared_evidence(&self) -> Result<SharedEvidence, AppError> {
        let mut ops: Vec<KeptOp> = self
            .reader()
            .scan::<HeldRecord>(RECORD_PREFIX)
            .await?
            .into_iter()
            .filter_map(|(_, held)| {
                Some(KeptOp {
                    op: held.op,
                    cert: held.cert?,
                    proof: held.proof,
                })
            })
            .collect();
        let (claim_ops, proofs) = self.claim_evidence_items().await?;
        ops.extend(claim_ops);
        Ok(SharedEvidence { ops, proofs })
    }

    /// The protocol's mark of what the app has seen in record `key`, its high water.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn record_seen(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>, AppError> {
        Ok(self
            .reader()
            .get::<SeenMark>(&seen_key(key))
            .await?
            .map(|mark| mark.mark))
    }

    // ---------------------------------------------------------------------------------
    // Reads from the switch

    /// Read `target` from the switch (`GET /records/{key}`, Switch wire 7.4.9), take the
    /// write if it passes the checks and is newer, and return what the app holds then. A key
    /// the switch doesn't know, or forgot, leaves what the app holds.
    ///
    /// # Errors
    ///
    /// A rollback for signed evidence of misbehaviour; a failed call or commit.
    pub async fn read_record(
        &mut self,
        target: &RecordTarget,
    ) -> Result<Option<SharedRecord>, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let key = self.record_key(target)?;
            self.fetch_record(&key, &target.collection).await?;
            self.shared_record(&key).await
        })
        .await
    }

    pub(crate) async fn fetch_record(
        &mut self,
        key: &[u8; 32],
        collection: &Collection,
    ) -> Result<(), AppError> {
        let result = self.client.record(key).await;
        let view = match self.take(result).await {
            Ok(view) => view,
            Err(error) if error.code() == Some(ErrorCode::NotFound) => return Ok(()),
            Err(error) => return Err(error),
        };
        let mut tx = self.tx()?;
        self.take_view(&view, Some((key, collection)), &mut tx)
            .await?;
        self.commit(tx).await
    }

    /// List `collection`'s current records at the switch, page by page (Switch wire
    /// 7.4.9), and take each write that passes the checks and is newer. Returns how many
    /// records the switch listed.
    ///
    /// # Errors
    ///
    /// A rollback for signed evidence of misbehaviour; a failed call or commit.
    pub async fn list_collection(&mut self, collection: &Collection) -> Result<u64, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let id = collection.id(&self.state.meta.identity);
            let mut after: Option<[u8; 32]> = None;
            let mut listed = 0u64;
            loop {
                let result = self
                    .client
                    .records(&id, after.as_ref(), Some(LIST_PAGE))
                    .await;
                let page = self.take(result).await?;
                let mut tx = self.tx()?;
                for view in &page.records {
                    self.take_view(view, Some((&view.key, collection)), &mut tx)
                        .await?;
                    listed = listed.saturating_add(1);
                }
                self.commit(tx).await?;
                // Records are listed by the base64url text of their keys, compared as ASCII
                // (Switch wire 7.4.9): a `next` that doesn't move past the key asked after ends
                // the listing, so a service that names keys back and forth can't keep the app
                // reading.
                match page.next {
                    Some(next) if after.is_none_or(|after| b64(&next) > b64(&after)) => {
                        after = Some(next);
                    }
                    _ => return Ok(listed),
                }
            }
        })
        .await
    }

    /// List every collection of the protocol whose read scope the app's certificate holds
    /// (Switch spec 8.3, 12.1 step 3).
    ///
    /// # Errors
    ///
    /// As [`App::list_collection`].
    pub async fn list_collections(&mut self) -> Result<(), AppError> {
        Box::pin(async move {
            let collections: Vec<Collection> = self
                .protocol
                .collections()
                .into_iter()
                .filter(|c| c.readable_by(&self.state.cert))
                .collect();
            for collection in &collections {
                self.list_collection(collection).await?;
            }
            let mut tx = self.tx()?;
            tx.delete(LIST_DUE)?;
            self.commit(tx).await
        })
        .await
    }

    /// List the collections when a listing is owed: after joining, and after a `missed` item
    /// (Switch spec 8.2, 8.3).
    pub(crate) async fn list_collections_if_due(&mut self) -> Result<(), AppError> {
        if self.reader().exists(LIST_DUE).await? {
            self.list_collections().await?;
        }
        Ok(())
    }

    /// Take a record view, from a read, a list page or after a conflict.
    async fn take_view(
        &mut self,
        view: &SharedRecordView,
        expect: Option<(&[u8; 32], &Collection)>,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let evidence = Evidence {
            op: &view.op,
            cert: Some(&view.cert),
            proof: view.proof.as_ref(),
            stub: None,
            view_version: Some(RecordVersion::new(view.generation, view.version)),
        };
        if view.divergent {
            self.events
                .push(AppEvent::RecordDivergent { key: view.key });
        }
        self.read_write(&evidence, expect, view.key, tx).await
    }

    /// A `record.put` chain item from the feed, its stub verified (Switch spec 8.3): taken
    /// if newer than what the app holds.
    pub(crate) async fn feed_record_write(
        &mut self,
        item: &ChainItem,
        envelope: &ChainEnvelope,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let Ok(op) = SignedOp::peek(&item.item) else {
            return Ok(());
        };
        let OpKind::RecordPut(put) = &op.body().kind else {
            return Ok(());
        };
        let evidence = Evidence {
            op: &item.item,
            cert: None,
            proof: item.proof.as_ref(),
            stub: Some(envelope),
            view_version: None,
        };
        let key = put.key;
        self.read_write(&evidence, None, key, tx).await
    }

    /// Check a write and take it, or flag it, or raise the rollback it proves.
    async fn read_write(
        &mut self,
        evidence: &Evidence<'_>,
        expect: Option<(&[u8; 32], &Collection)>,
        shown_key: [u8; 32],
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        match self.accept_write(evidence, expect).await? {
            Ok(accepted) => {
                self.take_write(accepted, false, tx).await?;
            }
            Err(Refused::Misbehaviour(reason)) => {
                return Err(self.raise(Alarm::Rollback { reason }).await);
            }
            Err(Refused::Invalid { writer, reason }) => {
                let version = evidence
                    .stub
                    .map(|env| RecordVersion::new(env.generation, env.seq))
                    .or(evidence.view_version)
                    .unwrap_or(RecordVersion::NONE);
                self.flag_write(&shown_key, version, writer, reason, tx)
                    .await?;
            }
            Err(Refused::Ignored) => {}
        }
        Ok(())
    }

    /// Record a refused write, and follow its version when it is the switch's current one
    /// for a record the app holds.
    async fn flag_write(
        &mut self,
        key: &[u8; 32],
        version: RecordVersion,
        writer: [u8; 16],
        reason: String,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let flagged = FlaggedWrite {
            key: *key,
            version,
            writer,
            reason: reason.clone(),
        };
        tx.put(&flag_key(key, version), &flagged)?;
        if let Some(mut held) = self.held_record(key).await?
            && version > held.base_version()
        {
            held.follow = Some(version);
            tx.put(&record_key_of(key), &held)?;
        }
        self.events.push(AppEvent::WriteFlagged {
            key: *key,
            writer,
            reason,
        });
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // The checks of Switch wire 6.2 "Accepting a write"

    async fn accept_write(
        &mut self,
        evidence: &Evidence<'_>,
        expect: Option<(&[u8; 32], &Collection)>,
    ) -> Result<Result<Accepted, Refused>, AppError> {
        let identity = self.state.meta.identity;
        let Ok(peeked) = SignedOp::peek(evidence.op) else {
            return Ok(Err(Refused::Ignored));
        };
        let body = peeked.body().clone();
        let OpKind::RecordPut(put) = &body.kind else {
            return Ok(Err(Refused::Ignored));
        };
        let Some(writer) = body.app_id else {
            return Ok(Err(Refused::Ignored));
        };
        let invalid = |reason: &str| -> Result<Result<Accepted, Refused>, AppError> {
            Ok(Err(Refused::Invalid {
                writer,
                reason: reason.to_owned(),
            }))
        };
        if body.identity != identity {
            return invalid("Switch wire 6.2 step 1: the operation names another identity");
        }
        // Step 3: the collection of the protocol, with its fixed policy.
        let collection = match expect {
            Some((key, collection)) => {
                if put.key != *key {
                    return invalid("Switch wire 6.2 step 3: another record key than the one read");
                }
                collection.clone()
            }
            None => match self.collection_of(put) {
                Some(collection) => collection,
                None => return Ok(Err(Refused::Ignored)),
            },
        };
        if let Some(reason) = check_shape(put, &collection, &identity) {
            return invalid(reason);
        }
        // The member of the collection's policy family the write names.
        let collection = Collection::new(&collection.name, put.policy.clone());
        // Step 1: the writer's certificate and the signature.
        let Some((cert, op)) = self.writer_cert(evidence, &writer).await? else {
            return Ok(Err(Refused::Ignored));
        };
        // Step 2: what dates the write and gives its version.
        let item_hash = op.item_hash()?;
        let (time, proven) = match self.date(evidence, &op, item_hash) {
            Ok(dated) => dated,
            Err(reason) => return Ok(Err(Refused::Misbehaviour(reason))),
        };
        // Step 4: standing at the write's time.
        let mut doubtful = false;
        let mut standing = self.state.own_doc.standing(&writer, &cert.hash());
        if standing == Standing::None && self.refresh_identity().await.unwrap_or(false) {
            standing = self.state.own_doc.standing(&writer, &cert.hash());
        }
        match standing {
            Standing::Listed | Standing::RenewedOpen => {}
            Standing::RenewedClosed { until } => {
                if !time.is_some_and(|t| t < until) {
                    return invalid(
                        "Switch wire 6.2 step 4: an earlier certificate's write not dated before \
                         its renewal closed",
                    );
                }
            }
            Standing::Removed { distrust_from } => match time {
                Some(t) if t > distrust_from => {
                    return invalid(
                        "Switch wire 6.2 step 4: a removed app's write after distrust_from",
                    );
                }
                Some(_) => {}
                None => doubtful = true,
            },
            Standing::None => {
                return invalid("Switch wire 6.2 step 4: the writer has no standing");
            }
        }
        if time.is_some_and(|t| cert.expired_at(t)) {
            return invalid("Switch wire 6.2 step 4: the certificate had expired at the write");
        }
        // Step 5: a write scope.
        if !put
            .policy
            .write_scopes
            .iter()
            .any(|scope| cert.holds_scope(scope))
        {
            return invalid("Switch wire 6.2 step 5: the writer holds none of the write scopes");
        }
        // Step 6: the version.
        let version = match (proven, evidence.view_version) {
            (Some(version), _) => WriteVersion {
                version,
                authenticated: true,
                expected_version: put.expected_version,
            },
            (None, Some(version)) => WriteVersion {
                version,
                authenticated: false,
                expected_version: put.expected_version,
            },
            (None, None) => return invalid("Switch wire 6.2 step 6: nothing gives the version"),
        };
        if !version.plausible(body.generation) {
            return invalid(
                "Switch wire 6.2 step 6: the version isn't of the operation's generation, after \
                 its expected_version",
            );
        }
        // Step 7: the content.
        let content = match put
            .value_sealed
            .open_with(&self.state.scope_keys, &identity, &put.key)
        {
            Ok(RecordValue::Delete) => RecordContent::Deleted,
            Ok(RecordValue::Json(json)) => RecordContent::Value(json),
            Err(_)
                if self
                    .state
                    .scope_keys
                    .get(put.value_sealed.data_epoch, &put.value_sealed.scope)
                    .is_none() =>
            {
                RecordContent::Unreadable
            }
            Err(_) => return invalid("Switch wire 6.2 step 7: the value doesn't open"),
        };
        Ok(Ok(Accepted {
            key: put.key,
            collection,
            op: evidence.op.clone(),
            cert,
            proof: evidence.proof.cloned(),
            version,
            time,
            writer,
            item_hash,
            content,
            doubtful,
        }))
    }

    /// The protocol's collection a write names, by its collection ID and a policy of the
    /// collection's family: the member it names.
    fn collection_of(&self, put: &RecordPut) -> Option<Collection> {
        let identity = self.state.meta.identity;
        self.protocol
            .collections()
            .into_iter()
            .find(|c| c.id(&identity) == put.collection && c.admits(&put.policy))
            .map(|c| Collection::new(&c.name, put.policy.clone()))
    }

    /// The writer's certificate whose key verifies the operation: the record view's, the
    /// app's own, or one kept from the directory and the feed; the own directory is read
    /// again once for a writer the app doesn't know.
    async fn writer_cert(
        &mut self,
        evidence: &Evidence<'_>,
        writer: &[u8; 16],
    ) -> Result<Option<(AppCert, SignedOp)>, AppError> {
        let identity = self.state.meta.identity;
        let verify = |cert: &AppCert| -> Option<SignedOp> {
            if cert.app_id() != *writer {
                return None;
            }
            SignedOp::verify(evidence.op, &cert.signing_key(), &identity, Some(writer)).ok()
        };
        let mut candidates: Vec<AppCert> = Vec::new();
        if let Some(signed) = evidence.cert
            && let Ok(cert) = AppCert::verify(signed, &identity)
        {
            candidates.push(cert);
        }
        candidates.push(self.state.cert.clone());
        candidates.extend(self.state.renewal.iter().cloned());
        candidates.extend(self.kept_certs(writer).await?);
        if let Some(found) = self.best_cert(&candidates, &verify) {
            return Ok(Some(found));
        }
        if self.refresh_own_apps().await.is_ok() {
            let kept = self.kept_certs(writer).await?;
            return Ok(self.best_cert(&kept, &verify));
        }
        Ok(None)
    }

    /// Of the certificates whose key verifies the operation, the one with the best standing.
    fn best_cert(
        &self,
        candidates: &[AppCert],
        verify: &dyn Fn(&AppCert) -> Option<SignedOp>,
    ) -> Option<(AppCert, SignedOp)> {
        let rank = |cert: &AppCert| match self.state.own_doc.standing(&cert.app_id(), &cert.hash())
        {
            Standing::Listed => 0,
            Standing::RenewedOpen => 1,
            Standing::RenewedClosed { .. } => 2,
            Standing::Removed { .. } => 3,
            Standing::None => 4,
        };
        let mut best: Option<(AppCert, SignedOp)> = None;
        for cert in candidates {
            if let Some(op) = verify(cert)
                && best.as_ref().is_none_or(|(b, _)| rank(cert) < rank(b))
            {
                best = Some((cert.clone(), op));
            }
        }
        best
    }

    async fn kept_certs(&self, app_id: &[u8; 16]) -> Result<Vec<AppCert>, AppError> {
        let prefix = format!(
            "{CERT_PREFIX}{}/",
            pubky_switch_core::enc::zbase32_encode(app_id)
        );
        let identity = self.state.meta.identity;
        Ok(self
            .reader()
            .scan::<SignedDoc>(&prefix)
            .await?
            .into_iter()
            .filter_map(|(_, signed)| AppCert::verify(&signed, &identity).ok())
            .collect())
    }

    /// Keep an own app's certificate, from its record in the feed or the directory, for
    /// checking its writes.
    pub(crate) fn keep_cert(&self, cert: &AppCert, tx: &mut Tx) -> Result<(), AppError> {
        tx.put(&cert_key(&cert.app_id(), &cert.hash()), cert.signed())
    }

    /// An `app.put` of another own app in the feed: its certificate is kept.
    pub(crate) fn feed_app_record(&self, record: &SignedDoc, tx: &mut Tx) -> Result<(), AppError> {
        if let Ok(record) = AppRecord::verify(record, &self.state.meta.identity) {
            self.keep_cert(record.cert(), tx)?;
        }
        Ok(())
    }

    /// Read the own directory and keep the certificates of the identity's apps.
    pub(crate) async fn refresh_own_apps(&mut self) -> Result<(), AppError> {
        let result = self.client.directory(None).await;
        let directory = self.take(result).await?;
        let mut tx = self.tx()?;
        for app in &directory.apps {
            self.keep_cert(app.record.cert(), &mut tx)?;
        }
        self.commit(tx).await?;
        if directory.identity.version() > self.state.own_doc.version() {
            self.take_own_copy(directory.identity).await?;
        }
        Ok(())
    }

    /// Step 2: the write's time, and its version when a verified stub or a proof of the
    /// current key gives it. `Err` is signed evidence of misbehaviour.
    fn date(
        &self,
        evidence: &Evidence<'_>,
        op: &SignedOp,
        item_hash: [u8; 32],
    ) -> Result<(Option<u64>, Option<RecordVersion>), String> {
        if let Some(env) = evidence.stub {
            if env.item_hash != item_hash {
                return Err("Switch wire 6.6: a feed item doesn't match its stub".into());
            }
            return Ok((
                Some(env.server_time),
                Some(RecordVersion::new(env.generation, env.seq)),
            ));
        }
        let Some(proof) = evidence.proof else {
            return Ok((None, None));
        };
        let identity = self.state.meta.identity;
        let current_key = self.state.own_doc.inbox().service_key;
        if let Ok(checked) = TransitionProof::verify(proof, &current_key, &identity) {
            let env = checked.envelope();
            if let Some(chain) = self.state.chain.as_ref()
                && env.generation == self.state.meta.generation
                && let Some(hash) = chain.hash_at(env.seq)
                && hash != checked.body().chain.chain_hash
            {
                return Err(
                    "Switch wire 6.2 step 2: a proof contradicts the verified chain".into(),
                );
            }
            return match date_write(proof, op, &self.state.own_doc) {
                Ok(dated) => Ok((Some(dated.time), dated.version)),
                Err(error) => Err(error.to_string()),
            };
        }
        // An earlier generation's proof dates the write without a version; one that verifies
        // with no listed key dates nothing.
        Ok(match date_write(proof, op, &self.state.own_doc) {
            Ok(dated) => (Some(dated.time), None),
            Err(_) => (None, None),
        })
    }

    // ---------------------------------------------------------------------------------
    // Taking a write

    /// Take an accepted write if it is newer than the one held and the protocol finds it
    /// goes back on nothing the app has seen.
    async fn take_write(
        &mut self,
        accepted: Accepted,
        own: bool,
        tx: &mut Tx,
    ) -> Result<Taken, AppError> {
        let key = accepted.key;
        self.keep_cert(&accepted.cert, tx)?;
        let held = self.held_record(&key).await?;
        if let Some(held) = &held {
            if held.item_hash == accepted.item_hash {
                if accepted.version.authenticated && !held.authenticated {
                    let mut upgraded = held.clone();
                    upgraded.version = accepted.version.version;
                    upgraded.authenticated = true;
                    upgraded.written_at_ms = accepted.time.or(held.written_at_ms);
                    upgraded.proof = accepted.proof.clone().or(held.proof.clone());
                    tx.put(&record_key_of(&key), &upgraded)?;
                }
                return Ok(Taken::Same);
            }
            if !accepted.version.replaces(&held.write_version()) {
                return Ok(Taken::NotNewer);
            }
        }
        let seen: Option<SeenMark> = self.reader().get(&seen_key(&key)).await?;
        let new_value = accepted.content.value();
        if !own
            && let Some(mark) = &seen
            && let Some(reason) =
                self.protocol
                    .record_regression(&accepted.collection.name, &mark.mark, new_value)
        {
            let version = accepted.version.version;
            self.flag_write(&key, version, accepted.writer, reason, tx)
                .await?;
            return Ok(Taken::Flagged);
        }
        let marked = self.protocol.record_seen(
            &accepted.collection.name,
            if own {
                None
            } else {
                seen.as_ref().map(|m| m.mark.as_slice())
            },
            new_value,
        );
        match marked {
            Some(mark) => tx.put(&seen_key(&key), &SeenMark { mark })?,
            None if own => tx.delete(&seen_key(&key))?,
            None => {}
        }
        let record = HeldRecord {
            collection: accepted.collection.name.clone(),
            policy: accepted.collection.policy.clone(),
            op: accepted.op,
            cert: Some(accepted.cert.signed().clone()),
            proof: accepted.proof,
            version: accepted.version.version,
            authenticated: accepted.version.authenticated,
            expected: accepted.version.expected_version,
            written_at_ms: accepted.time,
            writer: accepted.writer,
            item_hash: accepted.item_hash,
            content: accepted.content,
            doubtful: accepted.doubtful,
            follow: None,
        };
        tx.put(&record_key_of(&key), &record)?;
        self.events.push(AppEvent::RecordChanged { key });
        Ok(Taken::New)
    }

    /// An own `record.put` the switch answered: taken at the version its proof gives.
    pub(crate) async fn cache_own_write(
        &mut self,
        op: &SignedOp,
        proof: &TransitionProof,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let OpKind::RecordPut(put) = &op.body().kind else {
            return Ok(());
        };
        let held = self.held_record(&put.key).await?;
        let collection = match held.as_ref() {
            Some(held) => Collection::new(&held.collection, held.policy.clone()),
            None => match self.collection_of(put) {
                Some(collection) => collection,
                None => match self
                    .reader()
                    .get::<String>(&pending_name_key(&put.key))
                    .await?
                {
                    Some(name) => Collection::new(&name, put.policy.clone()),
                    None => return Ok(()),
                },
            },
        };
        tx.delete(&pending_name_key(&put.key))?;
        let signed = proof.signed().clone();
        let own_cert = self.state.cert.signed().clone();
        let evidence = Evidence {
            op: op.signed(),
            cert: Some(&own_cert),
            proof: Some(&signed),
            stub: None,
            view_version: None,
        };
        let key = put.key;
        match self
            .accept_write(&evidence, Some((&key, &collection)))
            .await?
        {
            Ok(accepted) => {
                self.take_write(accepted, true, tx).await?;
            }
            Err(Refused::Misbehaviour(reason)) => {
                return Err(self.raise(Alarm::Rollback { reason }).await);
            }
            Err(_) => {}
        }
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // Writes

    /// The `record.put` of `value` at `target`, with `conditions`: built on the version the
    /// app holds, or a create (`{0, 0}` with `id_inputs`) for a record it holds nothing of or
    /// holds deleted, sealed under the read scope's key at the current data epoch (Switch
    /// spec 3.5, 10.3, 13.4). `None` writes a delete. To go in a batch ([`OpBatch::entry`]).
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] when the certificate holds none of the write scopes;
    /// [`Refusal::NotNow`] while the app lacks the read scope's key at the current data
    /// epoch (it fetches its key bundle first); a store failure.
    pub async fn record_op(
        &mut self,
        target: &RecordTarget,
        value: Option<&[u8]>,
        conditions: Vec<Condition>,
    ) -> Result<(Vec<Condition>, OpKind), AppError> {
        Box::pin(async move {
            let epoch = self.state.own_doc.data_epoch();
            let read_scope = &target.collection.policy.read_scope;
            if self.state.scope_keys.get(epoch, read_scope).is_none() {
                self.ensure_scope_keys().await?;
            }
            let key = self.record_key(target)?;
            let held = self.held_record(&key).await?;
            let put = record_put(&self.state, target, value, held.as_ref())?;
            Ok((conditions, OpKind::RecordPut(put)))
        })
        .await
    }

    /// Write `value` at `target` with `conditions`, compare-and-swap on the version the app
    /// holds (Switch spec 10.3). On `409 conflict` the app reads the record again before it
    /// returns the error, so the caller builds its write again on what the switch holds; on
    /// `409 stale_epoch` it takes the newer `identity.json` and its key bundle and writes
    /// once more.
    ///
    /// # Errors
    ///
    /// As [`App::record_op`] and [`App::submit_batch`].
    pub async fn put_record(
        &mut self,
        target: &RecordTarget,
        value: &[u8],
        conditions: Vec<Condition>,
    ) -> Result<SharedRecord, AppError> {
        Box::pin(async move { self.write_record(target, Some(value), conditions).await }).await
    }

    /// Delete the record at `target`: a write whose sealed value is empty (Switch spec
    /// 10.3).
    ///
    /// # Errors
    ///
    /// As [`App::put_record`].
    pub async fn delete_record(
        &mut self,
        target: &RecordTarget,
        conditions: Vec<Condition>,
    ) -> Result<SharedRecord, AppError> {
        Box::pin(async move { self.write_record(target, None, conditions).await }).await
    }

    async fn write_record(
        &mut self,
        target: &RecordTarget,
        value: Option<&[u8]>,
        conditions: Vec<Condition>,
    ) -> Result<SharedRecord, AppError> {
        self.ready_local().await?;
        let key = self.record_key(target)?;
        let mut epoch_retried = false;
        loop {
            let entry = self.record_op(target, value, conditions.clone()).await?;
            self.note_pending_name(&key, &target.collection).await?;
            match self.submit_batch(OpBatch::new().entry(entry)).await {
                Ok(_) => {
                    return self.shared_record(&key).await?.ok_or_else(|| {
                        AppError::InvalidData("the record written isn't held".into())
                    });
                }
                Err(error) if error.code() == Some(ErrorCode::StaleEpoch) && !epoch_retried => {
                    epoch_retried = true;
                    self.refresh_identity().await?;
                    self.fetch_key_bundle().await?;
                }
                Err(error) if error.code() == Some(ErrorCode::Conflict) => {
                    self.fetch_record(&key, &target.collection).await?;
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Build a record's next value from what the app holds and write it, building it again
    /// on what the switch holds after each `409 conflict` (Switch spec 10.3): `change` gets
    /// the current value (`None` for none, deleted or unreadable) and returns the new one,
    /// or `None` when nothing changes. Returns the record written, or `None` when `change`
    /// changed nothing.
    ///
    /// # Errors
    ///
    /// As [`App::put_record`]; `409 conflict` when the record kept changing.
    pub async fn update_record(
        &mut self,
        target: &RecordTarget,
        conditions: Vec<Condition>,
        mut change: impl FnMut(Option<&[u8]>) -> Option<Vec<u8>> + Send,
    ) -> Result<Option<SharedRecord>, AppError> {
        Box::pin(async move {
            let key = self.record_key(target)?;
            let mut last = None;
            for _ in 0..UPDATE_TRIES {
                let current = self.shared_record(&key).await?;
                let value = current.as_ref().and_then(|r| r.content.value());
                let Some(next) = change(value) else {
                    return Ok(None);
                };
                match self.put_record(target, &next, conditions.clone()).await {
                    Ok(record) => return Ok(Some(record)),
                    Err(error) if error.code() == Some(ErrorCode::Conflict) => last = Some(error),
                    Err(error) => return Err(error),
                }
            }
            Err(last.unwrap_or_else(|| {
                AppError::Switch(ClientError::Usage("the record kept changing".into()))
            }))
        })
        .await
    }

    /// A chain item of the shared state in the feed: a record write, a claim entry, a list
    /// change, or another own app's record, whose certificate is kept for its writes.
    pub(crate) async fn feed_shared_item(
        &mut self,
        item: &ChainItem,
        envelope: &ChainEnvelope,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let Ok(op) = SignedOp::peek(&item.item) else {
            return Ok(());
        };
        match &op.body().kind {
            OpKind::RecordPut(_) => self.feed_record_write(item, envelope, tx).await,
            OpKind::Claim(_) => self.feed_claim_entry(item, envelope, tx).await,
            OpKind::AppPut { record } => self.feed_app_record(record, tx),
            _ => self.feed_list_change(item, tx),
        }
    }

    /// Remember the collection name of a record the app creates, until its write is
    /// answered: the switch knows only the collection ID.
    async fn note_pending_name(
        &mut self,
        key: &[u8; 32],
        collection: &Collection,
    ) -> Result<(), AppError> {
        if self.held_record(key).await?.is_some() || self.collection_of_name(collection) {
            return Ok(());
        }
        let mut tx = self.tx()?;
        tx.put(&pending_name_key(key), &collection.name)?;
        self.commit(tx).await
    }

    pub(crate) fn collection_of_name(&self, collection: &Collection) -> bool {
        self.protocol
            .collections()
            .iter()
            .any(|c| c.name == collection.name && c.admits(&collection.policy))
    }
}

/// The `record.put` of `value` at `target` (`None` a delete), built on `held`, the write the
/// app holds there: on its version, or a create (`{0, 0}` with `id_inputs`) for a record it
/// holds nothing of or holds deleted, sealed under the read scope's key at the current data
/// epoch (Switch spec 3.5, 10.3, 13.4).
///
/// # Errors
///
/// [`Refusal::Usage`] when the certificate holds none of the write scopes;
/// [`Refusal::NotNow`] while the app lacks the read scope's key at the current data epoch.
pub(crate) fn record_put(
    state: &super::AppState,
    target: &RecordTarget,
    value: Option<&[u8]>,
    held: Option<&HeldRecord>,
) -> Result<RecordPut, AppError> {
    let policy = &target.collection.policy;
    if !policy
        .write_scopes
        .iter()
        .any(|scope| state.cert.holds_scope(scope))
    {
        return Err(Refusal::Usage(
            "Switch spec 10.3: the certificate holds none of the record's write scopes".into(),
        )
        .into());
    }
    let identity = state.meta.identity;
    let epoch = state.own_doc.data_epoch();
    let scope_key = state
        .scope_keys
        .get(epoch, &policy.read_scope)
        .ok_or_else(|| {
            AppError::Refused(Refusal::NotNow(
                "Switch spec 3.5: no key of the read scope at the current data epoch yet".into(),
            ))
        })?;
    let key = state.naming.record_key(
        &target.collection.name,
        &target.natural_key,
        &policy.hash()?,
    );
    let sealed = SealedValue::seal(
        &scope_key,
        &identity,
        epoch,
        &policy.read_scope,
        &key,
        value.unwrap_or_default(),
    )?;
    let base = match held {
        Some(held) if held.follow.is_some() || held.content != RecordContent::Deleted => {
            held.base_version()
        }
        _ => RecordVersion::NONE,
    };
    let id_inputs = base.is_none().then(|| IdInputs {
        collection: target.collection.name.clone(),
        blinded_key: state.naming.blind(&target.natural_key),
    });
    Ok(RecordPut {
        key,
        collection: target.collection.id(&identity),
        policy: policy.clone(),
        expected_version: base,
        value_sealed: sealed,
        id_inputs,
    })
}

/// Delete, with the keys on a leave, every record of the shared state, the outbox and the
/// sent messages that holds content or a bearer secret (Switch spec 3.1, 12.3).
pub(crate) fn destroy_shared(tx: &mut Tx) -> Result<(), AppError> {
    for prefix in [
        RECORD_PREFIX,
        SEEN_PREFIX,
        "recname/",
        "out/",
        "sent/",
        "sentt/",
        "invite/",
        "opq/",
    ] {
        tx.delete_prefix(prefix)?;
    }
    Ok(())
}

pub(crate) fn pending_name_key(key: &[u8; 32]) -> String {
    format!("recname/{}", b64(key))
}

/// `hw/<key>`: the protocol's mark of what the app has seen in a record.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SeenMark {
    #[serde(with = "serde_b64_vec")]
    pub(crate) mark: Vec<u8>,
}

/// Step 3's checks that need no state: the policy is one the collection fixes (its fixed
/// policy, or a member of its family), the collection ID is the name's, the sealed value's
/// scope is the read scope, and a create's key derives from its `id_inputs`.
fn check_shape(
    put: &RecordPut,
    collection: &Collection,
    identity: &[u8; 32],
) -> Option<&'static str> {
    if !collection.admits(&put.policy) || put.collection != collection.id(identity) {
        return Some("Switch wire 6.2 step 3: not the collection's fixed policy");
    }
    if put.value_sealed.scope != put.policy.read_scope {
        return Some("Switch wire 6.2 step 3: the sealed value's scope isn't the read scope");
    }
    if put.expected_version.is_none() {
        let Some(inputs) = &put.id_inputs else {
            return Some("Switch wire 6.2 step 3: a create without id_inputs");
        };
        let Ok(policy_hash) = put.policy.hash() else {
            return Some("Switch wire 6.2 step 3: a policy that doesn't hash");
        };
        if inputs.collection != collection.name
            || record_key_from_blinded(&inputs.collection, &inputs.blinded_key, &policy_hash)
                != put.key
        {
            return Some("Switch wire 6.2 step 3: the key doesn't derive from its id_inputs");
        }
    }
    None
}

fn store_corrupt() -> AppError {
    AppError::Store(crate::error::StoreError::Corrupt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collection() -> Collection {
        Collection::new("sample.items", Policy::new("scope-a", &["scope-a"]))
    }

    #[test]
    fn test_records_shape_refuses_another_policy() {
        let identity = [1; 32];
        let other = Collection::new("sample.items", Policy::new("scope-b", &["scope-b"]));
        let key = [2; 32];
        let put = RecordPut {
            key,
            collection: other.id(&identity),
            policy: other.policy.clone(),
            expected_version: RecordVersion::new(1, 4),
            value_sealed: SealedValue::seal(&[3; 32], &identity, 1, "scope-b", &key, b"{}")
                .unwrap(),
            id_inputs: None,
        };
        assert!(check_shape(&put, &collection(), &identity).is_some());
        assert!(check_shape(&put, &other, &identity).is_none());
    }

    #[test]
    fn test_records_shape_checks_a_creates_key_derivation() {
        let identity = [1; 32];
        let c = collection();
        let hash = c.policy.hash().unwrap();
        let blinded = [7; 32];
        let key = record_key_from_blinded(&c.name, &blinded, &hash);
        let mut put = RecordPut {
            key,
            collection: c.id(&identity),
            policy: c.policy.clone(),
            expected_version: RecordVersion::NONE,
            value_sealed: SealedValue::seal(&[3; 32], &identity, 1, "scope-a", &key, b"{}")
                .unwrap(),
            id_inputs: Some(IdInputs {
                collection: c.name.clone(),
                blinded_key: blinded,
            }),
        };
        assert!(check_shape(&put, &c, &identity).is_none());
        put.id_inputs = Some(IdInputs {
            collection: c.name.clone(),
            blinded_key: [8; 32],
        });
        assert!(check_shape(&put, &c, &identity).is_some());
        put.id_inputs = None;
        assert!(check_shape(&put, &c, &identity).is_some());
    }

    #[test]
    fn test_records_content_debug_shows_no_value() {
        let content = RecordContent::Value(b"secret".to_vec());
        assert_eq!(format!("{content:?}"), "Value(6 bytes)");
        let target = RecordTarget::new(collection(), b"secret-natural");
        assert!(!format!("{target:?}").contains("secret"));
    }
}
