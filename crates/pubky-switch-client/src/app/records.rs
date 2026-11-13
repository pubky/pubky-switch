//! Shared records (Switch spec 8.2, 8.3, 10.3; Switch wire 6.2 `record.put`, 7.4.9).
//!
//! A shared record is a protocol's: its collections and their fixed policies come from
//! [`super::Protocol::collections`], or from the caller as a [`Collection`]. The app keeps,
//! per record key, the write it took (`rec/<key>`), the protocol's mark of what it has seen
//! there (`hw/<key>`), and the writes it refused (`flag/<key>/<write>`).
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
//!   misbehaviour is a rollback (Switch spec 10.1). A failure that is only the service's
//!   word, and any failure of the app's own write but a value that doesn't open, leaves the
//!   write ignored, naming no app. Of those, a write refused for the certificate the service
//!   shows or a missing date, at a plausible version, is followed, so the next write builds
//!   on it; the others (a write served for another record, a signature that doesn't verify,
//!   a version missing or not plausible, an own write) aren't. Any other failure leaves the
//!   write ignored and shown with the app it names (Switch spec 8.2), once for each write,
//!   at most eight for a record, and followed.
//! - **A write replaces the one held** only if it is newer by the core's rule
//!   ([`WriteVersion::replaces`]), and only if the protocol finds it doesn't go back on what
//!   the app has seen there ([`super::Protocol::record_regression_on`]). A write refused that
//!   way is flagged, its content not acted on, but its version followed, so the app's next
//!   write builds on it and puts back the content it trusts (Switch spec 8.2).
//! - **Listing** runs at join, after a restore, after a `missed` item, and after a certificate
//!   taken that reads a collection the one before didn't (Switch spec 8.2, 8.3).

use pubky_switch_core::chain::{ChainEnvelope, TransitionProof};
use pubky_switch_core::enc::{b64, serde_b64, serde_b64_vec, unb64_array};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ident::{Policy, collection_id, record_key_from_blinded};
use pubky_switch_core::ops::{Condition, IdInputs, OpKind, RecordPut, RecordVersion, SignedOp};
use pubky_switch_core::records::{AppCert, AppRecord, IdentityDoc, Standing};
use pubky_switch_core::sealed::{RecordValue, SealedValue};
use pubky_switch_core::shared::{WriteVersion, date_write};
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};

use super::batch::OpBatch;
use super::error::{Alarm, Refusal};
use super::events::{AppEvent, Duty};
use super::protocol::{MAX_REGRESSION_REASON_BYTES, MAX_SEEN_MARK_BYTES, WriteBase};
use super::state::Tx;
use super::{App, AppError, IdentityRefresh};
use crate::client::answers::{ChainItem, SharedRecordView};
use crate::error::ClientError;

const RECORD_PREFIX: &str = "rec/";
const SEEN_PREFIX: &str = "hw/";
const FLAG_PREFIX: &str = "flag/";
/// The most flagged writes kept for one record ([`App::flagged_writes`]).
const FLAGGED_WRITES_PER_RECORD: usize = 8;
const CERT_PREFIX: &str = "ocert/";
/// Set while the app owes a listing of its collections: at join, after a `missed` item.
pub(crate) const LIST_DUE: &str = "list_due";
/// Set in the commit that takes a scope key, while the records held `Unreadable` are owed
/// a reopening ([`App::reopen_unreadable`]): cleared in the commit of a reopening that
/// finished, so a store that fails between the two loses nothing.
pub(crate) const REOPEN_DUE: &str = "reopen";
/// The most times one read makes an owed reopening that fails ([`App::reopen_if_due`]):
/// the first failure and one more try, such as after the page whose commit failed. The
/// next read tries again.
pub(crate) const REOPEN_TRIES_PER_READ: u32 = 2;

/// How far an owed listing got ([`ListProgress`]), while it is owed.
const LIST_AT: &str = "list_at";

/// `listc/<collection id>`: how far a call of [`App::list_collection`] that its budget
/// stopped got in that collection ([`CollectionListed::more`]).
const LISTC_PREFIX: &str = "listc/";

fn listc_key(id: &[u8; 32]) -> String {
    format!("{LISTC_PREFIX}{}", b64(id))
}

/// Owe a listing of the collections from their beginning, in `tx`: `list_due` set and
/// `list_at` deleted. Every new obligation starts the listing over, so a collection a
/// listing under way already listed to its end is listed again: it may read members it
/// didn't, such as after a renewal that widens the certificate (Switch spec 8.2, 8.3).
pub(crate) fn owe_listing(tx: &mut Tx) -> Result<(), AppError> {
    tx.put(LIST_DUE, &true)?;
    tx.delete(LIST_AT)?;
    Ok(())
}

/// The most listing pages one read of the feed asks for while it makes an owed listing
/// ([`App::receive`]): a listing that needs more goes on at the next read from the page
/// it reached, and the read stops before any entry meanwhile (Switch spec 8.2, wire
/// 7.4.4).
pub const LISTING_PAGES_PER_READ: u32 = 4;

/// What one call of [`App::list_collection`] took.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CollectionListed {
    /// How many records the switch listed in this call.
    pub records: u64,
    /// The call stopped on its budget, [`LISTING_PAGES_PER_READ`] pages or the call's time
    /// ([`super::AppConfig::call_budget_ms`]), before the collection's end: the host calls
    /// again at once, and the next call goes on from where this one got.
    pub more: bool,
}

/// The most records one listing page asks for (Switch wire 7.4.9).
const LIST_PAGE: u32 = 1000;

/// What taking one listed record writes, at most: its cached write (its operation, 512 KiB,
/// and opened value, 256 KiB, in base64, with its proof: 1.2 MiB), its mark as stored
/// ([`MAX_SEEN_MARK_BYTES`] in base64), a flagged write's rule, and its duty events.
const LISTED_RECORD_ROOM_BYTES: u64 =
    super::feed::CACHED_RECORD_BYTES + super::feed::KEPT_MARK_BYTES + (64 << 10);

// One listed record always fits a commit of its own.
const _: () = assert!(LISTED_RECORD_ROOM_BYTES < crate::store::MAX_BATCH_BYTES);

/// How many times a write is built again after a conflict before the call gives up.
const UPDATE_TRIES: usize = 4;

/// Whether the signed operation `op` is a `record.put` that deletes its record.
fn writes_a_delete(op: &SignedDoc) -> bool {
    SignedOp::peek(op).is_ok_and(|op| {
        matches!(&op.body().kind, OpKind::RecordPut(put) if put.value_sealed.looks_like_delete())
    })
}

/// What became of an owed listing of the collections at a read
/// ([`App::list_collections_if_due`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Listing {
    /// None is owed.
    NotDue,
    /// Made to its end.
    Listed,
    /// Owed, and waiting for a scope key the certificate lacks.
    WaitsForKey,
    /// Begun or carried on, and stopped on the read's page budget: the next read goes on.
    Unfinished,
}

/// How one collection's listing ended: listed to its end, or stopped on the page budget,
/// with the records listed either way.
enum Listed {
    Done(u64),
    Paused(u64),
}

/// `list_at`: how far an owed listing got, kept with each page it takes.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct ListProgress {
    /// The collections listed to their end, by collection ID in base64url.
    done: Vec<String>,
    /// The collection being listed, and the last key of its last page taken.
    at: Option<(String, String)>,
}

impl ListProgress {
    /// Where the listing of the collection `id` goes on: after the last key of its last
    /// page taken, or from its beginning.
    fn after(&self, id: &[u8; 32]) -> Result<Option<[u8; 32]>, AppError> {
        match &self.at {
            Some((at, key)) if *at == b64(id) => unb64_array::<32>(key)
                .map(Some)
                .map_err(|_| AppError::Store(crate::error::StoreError::Corrupt)),
            _ => Ok(None),
        }
    }

    /// A page of the collection `id` was taken; `next` is where the listing goes on, `None`
    /// at the collection's end.
    fn reached(&mut self, id: &[u8; 32], next: Option<&[u8; 32]>) {
        let id = b64(id);
        match next {
            Some(next) => self.at = Some((id, b64(next))),
            None => {
                self.at = None;
                if !self.done.contains(&id) {
                    self.done.push(id);
                }
            }
        }
    }
}

pub(crate) fn record_key_of(key: &[u8; 32]) -> String {
    format!("{RECORD_PREFIX}{}", b64(key))
}

pub(crate) fn seen_key(key: &[u8; 32]) -> String {
    format!("{SEEN_PREFIX}{}", b64(key))
}

/// Where a record's flagged writes are kept.
fn flag_prefix(key: &[u8; 32]) -> String {
    format!("{FLAG_PREFIX}{}/", b64(key))
}

/// A flagged write, by its item hash.
fn flag_key(key: &[u8; 32], write: &[u8; 32]) -> String {
    format!("{}{}", flag_prefix(key), b64(write))
}

/// A refused write as shown: its record key, the version shown, and its item hash.
struct Shown {
    key: [u8; 32],
    version: RecordVersion,
    write: [u8; 32],
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

    /// Whether a certificate scope `scope` reads a member of the collection: its read
    /// scope, or, in a sub-scope family, one of its sub-scopes (Switch spec 3.3, 10.3).
    pub(crate) fn read_by_scope(&self, scope: &str) -> bool {
        scope == self.policy.read_scope
            || (self.family == PolicyFamily::SubScopes
                && pubky_switch_core::scopes::split(scope)
                    .is_some_and(|(name, sub)| sub.is_some() && name == self.policy.read_scope))
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
#[serde(from = "StoredContent", into = "StoredContent")]
pub enum RecordContent {
    /// The value's JSON bytes.
    Value(Vec<u8>),
    /// A delete: the sealed empty plaintext (Switch wire 6.2).
    Deleted,
    /// The value isn't open, for now or for good ([`Unopened`]).
    Unreadable(Unopened),
}

/// Why a record's value isn't open (Switch spec 3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unopened {
    /// Not open for now: sealed at a data epoch whose key for its scope the app doesn't
    /// hold. The value opens once that key is fetched. An app is given the keys of every
    /// data epoch from 1 to the current one for each scope it holds, its approval's bundle
    /// and later parts included, but the key may still never come: a value sealed at an
    /// epoch the app gets no key for, such as one past the current epoch or under a scope
    /// its certificate no longer holds, or under a sub-scope it can't derive the key of,
    /// stays so. The app can't tell those apart from a key on its way.
    KeyNotHeld {
        /// The data epoch the value is sealed at.
        data_epoch: u64,
    },
    /// For good: the key is held and the value doesn't open with it. The write was
    /// flagged ([`super::AppEvent::WriteFlagged`]) and isn't tried again.
    DoesNotOpen,
}

/// [`RecordContent`] as the store holds it: a value not open for now is kept as before,
/// its data epoch read from the kept operation.
#[derive(Serialize, Deserialize)]
enum StoredContent {
    Value(#[serde(with = "serde_b64_vec")] Vec<u8>),
    Deleted,
    Unreadable,
    DoesNotOpen,
}

impl From<StoredContent> for RecordContent {
    fn from(stored: StoredContent) -> Self {
        match stored {
            StoredContent::Value(bytes) => Self::Value(bytes),
            StoredContent::Deleted => Self::Deleted,
            StoredContent::Unreadable => Self::Unreadable(Unopened::KeyNotHeld { data_epoch: 0 }),
            StoredContent::DoesNotOpen => Self::Unreadable(Unopened::DoesNotOpen),
        }
    }
}

impl From<RecordContent> for StoredContent {
    fn from(content: RecordContent) -> Self {
        match content {
            RecordContent::Value(bytes) => Self::Value(bytes),
            RecordContent::Deleted => Self::Deleted,
            RecordContent::Unreadable(Unopened::KeyNotHeld { .. }) => Self::Unreadable,
            RecordContent::Unreadable(Unopened::DoesNotOpen) => Self::DoesNotOpen,
        }
    }
}

impl std::fmt::Debug for RecordContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value(bytes) => write!(f, "Value({} bytes)", bytes.len()),
            Self::Deleted => f.write_str("Deleted"),
            Self::Unreadable(why) => write!(f, "Unreadable({why:?})"),
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

    /// Whether the value isn't open for now only: its key isn't held yet.
    fn waits_for_key(&self) -> bool {
        matches!(self, Self::Unreadable(Unopened::KeyNotHeld { .. }))
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
    /// The latest view the app read shows uploads after a provider loss that conflict with
    /// the current write, kept at the switch until a writer writes a newer version there
    /// (Switch spec 12.6 step 3). The content is still the current write's, taken by the
    /// usual checks; what to do about the conflict is the protocol's.
    pub divergent: bool,
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
    /// The claim entries kept without a certificate of their writer that verifies them, so
    /// left out of `ops`: an upload carries each entry with its writer's certificate
    /// (Switch wire 7.4.14).
    pub claim_entries_left_out: u64,
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
    cert: SignedDoc,
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
    /// Whether that refused write is a delete: the next write then builds on `{0, 0}`, as
    /// on a delete the app holds (Switch wire 6.2), since the service may forget the key.
    follow_deleted: bool,
    /// Whether the refused write followed names the app that signed it (Switch spec 8.2):
    /// `false` for one refused only on the service's word, which names nobody and reads as
    /// not flagged.
    follow_named: bool,
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

    /// The version the next write names, and a condition on the record: the base
    /// ([`HeldRecord::base_version`]), or `{0, 0}` when that base is a delete, held or
    /// followed. `{0, 0}` matches a record that is absent, forgotten or deleted (Switch wire
    /// 6.2, 6.3), so it stays right once the service forgets the key (Switch spec 10.3); the
    /// delete's own version would be `409 conflict` for good then.
    pub(crate) fn write_base(&self) -> RecordVersion {
        match self.follow {
            Some(_) if self.follow_deleted => RecordVersion::NONE,
            Some(version) => version,
            None if self.content == RecordContent::Deleted => RecordVersion::NONE,
            None => self.version,
        }
    }

    fn write_version(&self) -> WriteVersion {
        WriteVersion {
            version: self.version,
            authenticated: self.authenticated,
            expected_version: self.expected,
        }
    }

    pub(crate) fn shared(&self, key: &[u8; 32], divergent: bool) -> SharedRecord {
        SharedRecord {
            key: *key,
            collection: self.collection.clone(),
            policy: self.policy.clone(),
            version: self.version,
            authenticated: self.authenticated,
            writer: self.writer,
            written_at_ms: self.written_at_ms,
            content: match self.content {
                // The data epoch from the kept operation, which a value stored before it was
                // kept doesn't carry.
                RecordContent::Unreadable(Unopened::KeyNotHeld { .. }) => {
                    RecordContent::Unreadable(Unopened::KeyNotHeld {
                        data_epoch: sealed_epoch(&self.op).unwrap_or(0),
                    })
                }
                ref content => content.clone(),
            },
            doubtful: self.doubtful,
            flagged: self.follow.is_some() && self.follow_named,
            divergent,
        }
    }
}

/// The data epoch a kept `record.put` seals its value at.
fn sealed_epoch(op: &SignedDoc) -> Option<u64> {
    match &SignedOp::peek(op).ok()?.body().kind {
        OpKind::RecordPut(put) => Some(put.value_sealed.data_epoch),
        _ => None,
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

/// Whether a certificate of `standing` counts for a write at `time` (Switch wire 6.2
/// "Accepting a write" step 4): listed, or renewed with `until` `null`, at any time;
/// renewed and closed, for a write dated before `until`; of a removed app, for a write
/// dated at or before `distrust_from`, or one nothing dates, as doubtful.
fn counts_at(standing: Standing, time: Option<u64>) -> bool {
    match standing {
        Standing::Listed | Standing::RenewedOpen => true,
        Standing::RenewedClosed { until } => time.is_some_and(|t| t < until),
        Standing::Removed { distrust_from } => time.is_none_or(|t| t <= distrust_from),
        Standing::None => false,
    }
}

/// Whether `cert` was in force at a write at `time`, by the newest own `identity.json`:
/// its standing counts then, and it hadn't expired (Switch wire 6.2 "Accepting a write"
/// step 4).
fn in_force(doc: &IdentityDoc, cert: &AppCert, time: Option<u64>) -> bool {
    counts_at(doc.standing(&cert.app_id(), &cert.hash()), time)
        && time.is_none_or(|t| !cert.expired_at(t))
}

/// The writer's certificates whose key verifies a write's operation (Switch wire 6.2
/// "Accepting a write" step 1), with the operation they verify.
struct WriterCerts {
    /// The record view's `cert`: the certificate the service checked the write against
    /// (Switch wire 7.4.9).
    view: Option<AppCert>,
    /// The ones the app knows: its own, its pending renewal, and those kept from the
    /// directory and the feed.
    known: Vec<AppCert>,
    /// The operation, verified.
    op: SignedOp,
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
    /// A failed check: ignored and shown with the app it names. Made only once the writer's
    /// signature verified, never for a write the app's own key signed, and never for a
    /// failure that is only the service's word. `write` is the write's item hash.
    Invalid {
        writer: [u8; 16],
        write: [u8; 32],
        reason: String,
    },
    /// A value that doesn't open with its key held: shown with the app it names, as
    /// [`Refused::Invalid`], and a record held with this very write not open for now is held
    /// as not opening for good. The signature covers the sealed value, so only a device of
    /// the writer sealed it: this holds for a write the app's own key signed too.
    DoesNotOpen {
        writer: [u8; 16],
        write: [u8; 32],
        reason: String,
    },
    /// Not a write the app takes: another collection, or a writer it can't find.
    Ignored,
    /// A write at the key read, its version plausible, that the app doesn't take on the
    /// service's word only: a missing date, or the certificate the service chose. It names
    /// nobody, but its version is followed, so the app's next write builds on it and puts
    /// back what it trusts, as over a flagged write (Switch spec 8.2). `version` is the one
    /// step 6 checked: a proof's when one gives it, else the view's.
    Unnamed { version: RecordVersion },
    /// A write without a record view, that no certificate the app holds authorizes, while
    /// the newest own `identity.json` names a certificate of the writer in force at its
    /// time that the app doesn't hold: the record's view decides (Switch wire 6.2
    /// "Accepting a write" step 1). It names the member of the collection.
    Unheld(Collection),
}

/// What reading a write came to ([`App::read_write`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteRead {
    /// Taken: newer than the write held.
    Taken,
    /// The very write the app held.
    Held,
    /// No newer than the write held.
    NotNewer,
    /// Refused: a failed check, a regression the protocol found, or a write the app doesn't
    /// take.
    Refused,
}

/// What a read of one record came to ([`App::read_record_fresh`], Switch wire 7.4.9).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordRead {
    /// Read now: the switch's current write is the one the app holds.
    Fresh(SharedRecord),
    /// Nothing read now replaced what the app holds: the earlier copy it keeps, if any.
    Kept {
        /// The copy the app keeps.
        record: Option<SharedRecord>,
        /// Why nothing read now replaced it.
        reason: KeptReason,
    },
}

/// Why a read of a record kept the earlier copy ([`RecordRead::Kept`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeptReason {
    /// The switch holds no record at the key, or forgot it (`404`).
    NotFound,
    /// The switch's write was refused: a failed check, or one that goes back on what the
    /// app has seen ([`super::AppEvent::WriteFlagged`]).
    Refused,
    /// The switch's write is no newer than the one the app holds.
    NotNewer,
    /// The switch refused the read with an answer the same request won't change, such as
    /// `403 permission_missing` or `400` (the Retry column of Switch spec 6.4 saying "No"):
    /// reading again won't help as things stand.
    SwitchRefused {
        /// The error code.
        code: ErrorCode,
    },
    /// The switch couldn't be read for now: the network, a `5xx` or a `429`, or an answer
    /// that didn't verify; the error, without content.
    Unreachable(String),
}

/// What [`App::take_write`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Taken {
    /// A newer write, now held.
    New,
    /// The write held.
    Same,
    /// The write held, unopened before, now opened: no newer write. No path from the feed
    /// reaches it today: a key that arrives reopens the record through `reopen_unreadable`
    /// before the feed meets the write again. It stays so that `New` keeps meaning newer.
    Reopened,
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

    /// The collection of the record the app holds at `key`, as its write named it.
    pub(crate) async fn held_collection(
        &self,
        key: &[u8; 32],
    ) -> Result<Option<Collection>, AppError> {
        Ok(self
            .held_record(key)
            .await?
            .map(|held| Collection::new(&held.collection, held.policy)))
    }

    /// The record the app holds at `key`, without reading the switch.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn shared_record(&self, key: &[u8; 32]) -> Result<Option<SharedRecord>, AppError> {
        let Some(held) = self.held_record(key).await? else {
            return Ok(None);
        };
        Ok(Some(held.shared(key, self.is_divergent(key).await?)))
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
            out.push(held.shared(&key, self.is_divergent(&key).await?));
        }
        Ok(out)
    }

    /// The writes the app refused (Switch spec 8.2), by record key. Each write is kept once,
    /// at the version it was last shown at, and at most eight for each record, the one shown
    /// at the lowest version going first.
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
            .map(|(_, held)| KeptOp {
                op: held.op,
                cert: held.cert,
                proof: held.proof,
            })
            .collect();
        let (claim_ops, proofs, claim_entries_left_out) = self.claim_evidence_items().await?;
        ops.extend(claim_ops);
        Ok(SharedEvidence {
            ops,
            proofs,
            claim_entries_left_out,
        })
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

    /// Read the record at `key` from the switch and take its write; what came of it, `None`
    /// for a key the switch doesn't know.
    pub(crate) async fn fetch_record(
        &mut self,
        key: &[u8; 32],
        collection: &Collection,
    ) -> Result<Option<WriteRead>, AppError> {
        let Some(view) = self.record_view(key).await? else {
            return Ok(None);
        };
        let mut tx = self.tx()?;
        let read = self
            .take_view(&view, Some((key, collection)), &mut tx)
            .await?;
        self.commit(tx).await?;
        Ok(Some(read))
    }

    /// [`App::read_record`], telling a copy read now from an earlier one the app keeps
    /// (Switch wire 7.4.9): [`RecordRead::Fresh`] when the switch's current write is what the
    /// app holds after the read, taken now or the very write it held; otherwise
    /// [`RecordRead::Kept`], with the copy the app keeps, if any, and why nothing read now
    /// replaced it: a `404`, a write refused or no newer than the one held, a read the
    /// switch refused for good, or a switch it couldn't read for now. A kept copy isn't evidence of the switch's state now.
    ///
    /// # Errors
    ///
    /// A rollback for signed evidence of misbehaviour, an alarm, a refusal of the app's
    /// rules, or a failed commit. A failed call isn't one: it reads as
    /// [`KeptReason::SwitchRefused`] or [`KeptReason::Unreachable`].
    pub async fn read_record_fresh(
        &mut self,
        target: &RecordTarget,
    ) -> Result<RecordRead, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let key = self.record_key(target)?;
            let reason = match self.fetch_record(&key, &target.collection).await {
                Ok(Some(WriteRead::Taken | WriteRead::Held)) => {
                    if let Some(record) = self.shared_record(&key).await? {
                        return Ok(RecordRead::Fresh(record));
                    }
                    KeptReason::Refused
                }
                Ok(Some(WriteRead::NotNewer)) => KeptReason::NotNewer,
                Ok(Some(WriteRead::Refused)) => KeptReason::Refused,
                Ok(None) => KeptReason::NotFound,
                Err(AppError::Switch(ClientError::Switch { code, .. }))
                    if code.retry() == pubky_switch_core::http::Retry::No =>
                {
                    KeptReason::SwitchRefused { code }
                }
                Err(error @ (AppError::Switch(_) | AppError::Transport(_))) => {
                    KeptReason::Unreachable(error.to_string())
                }
                Err(error) => return Err(error),
            };
            Ok(RecordRead::Kept {
                record: self.shared_record(&key).await?,
                reason,
            })
        })
        .await
    }

    /// The switch's view of record `key` (`GET /records/{key}`, Switch wire 7.4.9); `None`
    /// for a key it doesn't know, or forgot.
    pub(crate) async fn record_view(
        &mut self,
        key: &[u8; 32],
    ) -> Result<Option<SharedRecordView>, AppError> {
        let result = self.client.record(key).await;
        match self.take(result).await {
            Ok(view) => Ok(Some(view)),
            Err(error) if error.code() == Some(ErrorCode::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// List `collection`'s current records at the switch, page by page (Switch wire
    /// 7.4.9), and take each write that passes the checks and is newer.
    ///
    /// The call is bounded: it asks for at most [`LISTING_PAGES_PER_READ`] pages and, once
    /// it asked for one, none past the call's time budget
    /// ([`super::AppConfig::call_budget_ms`]). One that stops before the collection's end
    /// says [`CollectionListed::more`], and each page's commit records how far it got
    /// (`listc/`), so the next call goes on from there, after a restart too. The call that
    /// reaches the end forgets that, and the next one starts at the beginning. Records
    /// written between two calls come on the feed. Its worst case at the defaults is four
    /// page requests, each under the request timeout.
    ///
    /// # Errors
    ///
    /// A rollback for signed evidence of misbehaviour; a failed call or commit.
    pub async fn list_collection(
        &mut self,
        collection: &Collection,
    ) -> Result<CollectionListed, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let budget = self.begin_budget();
            let id = collection.id(&self.state.meta.identity);
            let key = listc_key(&id);
            let mut progress: ListProgress = self.reader().get(&key).await?.unwrap_or_default();
            let after = progress.after(&id)?;
            let mut pages = LISTING_PAGES_PER_READ;
            let listed = self
                .list_from(
                    collection,
                    after,
                    &mut pages,
                    Some((&mut progress, &key)),
                    Some(&budget),
                )
                .await?;
            Ok(match listed {
                Listed::Paused(records) => CollectionListed {
                    records,
                    more: true,
                },
                Listed::Done(records) => {
                    let mut tx = self.tx()?;
                    tx.delete(&key)?;
                    self.commit(tx).await?;
                    CollectionListed {
                        records,
                        more: false,
                    }
                }
            })
        })
        .await
    }

    /// List `collection` from after the key `after`, at most `pages` pages, each counted
    /// off as it is asked for. With `progress`, each page's commit records how far the
    /// listing got under its store key, so the listing goes on from there at the next call.
    async fn list_from(
        &mut self,
        collection: &Collection,
        mut after: Option<[u8; 32]>,
        pages: &mut u32,
        mut progress: Option<(&mut ListProgress, &str)>,
        budget: Option<&super::CallBudget>,
    ) -> Result<Listed, AppError> {
        let id = collection.id(&self.state.meta.identity);
        let mut listed = 0u64;
        loop {
            // Past a read's time budget, once it asked for one page, it pauses as on its
            // page budget.
            let spent =
                budget.is_some_and(|budget| *pages < LISTING_PAGES_PER_READ && self.spent(budget));
            if *pages == 0 || spent {
                return Ok(Listed::Paused(listed));
            }
            *pages -= 1;
            let result = self
                .client
                .records(&id, after.as_ref(), Some(LIST_PAGE))
                .await;
            let page = self.take(result).await?;
            let mut tx = self.tx()?;
            for view in &page.records {
                // A page holds up to 1,000 views, each cached with its mark: the views taken
                // so far are committed first once one more might not fit.
                if tx.size().saturating_add(LISTED_RECORD_ROOM_BYTES)
                    > crate::store::MAX_BATCH_BYTES
                {
                    let full = std::mem::replace(&mut tx, self.tx()?);
                    self.commit(full).await?;
                }
                self.take_view(view, Some((&view.key, collection)), &mut tx)
                    .await?;
                listed = listed.saturating_add(1);
            }
            // Records are listed by the base64url text of their keys, compared as ASCII
            // (Switch wire 7.4.9): a `next` that doesn't move past the key asked after ends
            // the listing, so a service that names keys back and forth can't keep the app
            // reading.
            let next = page
                .next
                .filter(|next| after.is_none_or(|after| b64(next) > b64(&after)));
            if let Some((progress, key)) = progress.as_mut() {
                progress.reached(&id, next.as_ref());
                tx.put(key, &**progress)?;
            }
            self.commit(tx).await?;
            match next {
                Some(next) => after = Some(next),
                None => return Ok(Listed::Done(listed)),
            }
        }
    }

    /// Whether a listing of the collections is owed (`list_due`): from joining or a restore,
    /// a certificate taken that reads a collection the one before didn't, a `missed` item, or
    /// an `upload` transition past [`super::MAX_RECORD_MARKS`], until a listing has run
    /// (Switch spec 8.2, 8.3, 12.1 step 3). While it is true, the app's copy of the shared
    /// records may lack records the switch holds: a record's absence from the copy decides
    /// nothing. Read-only; the app makes the listing itself, at its next read.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn listing_owed(&self) -> Result<bool, AppError> {
        self.reader().exists(LIST_DUE).await
    }

    /// List every collection of the protocol whose read scope the app's certificate holds
    /// (Switch spec 8.3, 12.1 step 3). Returns whether more is left: `true` when the call
    /// stopped on its budget, [`LISTING_PAGES_PER_READ`] pages for all the collections or
    /// the call's time ([`super::AppConfig::call_budget_ms`]), and the host calls again at
    /// once.
    ///
    /// The listing goes on from where the last one that stopped got, as an owed listing
    /// does (`list_at`), skipping the collections it listed to their end. The call that
    /// lists the last one to its end settles an owed listing ([`App::listing_owed`]), and
    /// the next call starts at the beginning. Records written between two calls come on the
    /// feed. Its worst case at the defaults is four page requests.
    ///
    /// # Errors
    ///
    /// As [`App::list_collection`].
    pub async fn list_collections(&mut self) -> Result<bool, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let budget = self.begin_budget();
            let mut pages = LISTING_PAGES_PER_READ;
            Ok(!self.list_from_list_at(&mut pages, Some(&budget)).await?)
        })
        .await
    }

    /// List the collections when a listing is owed: after joining, a restore, a `missed`
    /// item, and a certificate taken that reads a collection the one before didn't (Switch
    /// spec 8.2, 8.3).
    ///
    /// A listing waits while the certificate lacks the key, at the current data epoch, of
    /// a read scope of a collection it lists, such as after a renewal that adds one: listed
    /// before its key arrives, a record would be held `Unreadable` until the key opened it
    /// ([`App::reopen_unreadable`]). `list_due` stays, so the read after the key arrives
    /// lists.
    ///
    /// The listing asks for at most `pages` pages, counted off as they go. One that needs
    /// more is [`Listing::Unfinished`]: each page's commit records how far it got, and the
    /// next call goes on from there, the collections listed to their end skipped. Records
    /// written meanwhile come on the feed past the item that owed the listing, which no
    /// read processes before the listing ends (Switch spec 8.2).
    pub(crate) fn list_collections_if_due<'a>(
        &'a mut self,
        pages: &'a mut u32,
        budget: Option<&'a super::CallBudget>,
    ) -> crate::transport::BoxFuture<'a, Result<Listing, AppError>> {
        // Boxed, as `App::receive_inner` says.
        Box::pin(self.list_collections_if_due_body(pages, budget))
    }

    async fn list_collections_if_due_body(
        &mut self,
        pages: &mut u32,
        budget: Option<&super::CallBudget>,
    ) -> Result<Listing, AppError> {
        if !self.reader().exists(LIST_DUE).await? {
            return Ok(Listing::NotDue);
        }
        if self.listing_lacks_keys() {
            return Ok(Listing::WaitsForKey);
        }
        Ok(if self.list_from_list_at(pages, budget).await? {
            Listing::Listed
        } else {
            Listing::Unfinished
        })
    }

    /// List the readable collections from where `list_at` got, at most `pages` pages,
    /// recording how far each page got. Returns whether the listing reached its end, and
    /// then deletes `list_due` and `list_at` in one commit.
    async fn list_from_list_at(
        &mut self,
        pages: &mut u32,
        budget: Option<&super::CallBudget>,
    ) -> Result<bool, AppError> {
        let mut progress: ListProgress = self.reader().get(LIST_AT).await?.unwrap_or_default();
        let collections: Vec<Collection> = self
            .protocol
            .collections()
            .into_iter()
            .filter(|c| c.readable_by(&self.state.cert))
            .collect();
        for collection in &collections {
            let id = collection.id(&self.state.meta.identity);
            if progress.done.contains(&b64(&id)) {
                continue;
            }
            let after = progress.after(&id)?;
            if let Listed::Paused(_) = self
                .list_from(
                    collection,
                    after,
                    pages,
                    Some((&mut progress, LIST_AT)),
                    budget,
                )
                .await?
            {
                return Ok(false);
            }
        }
        let mut tx = self.tx()?;
        tx.delete(LIST_DUE)?;
        tx.delete(LIST_AT)?;
        self.commit(tx).await?;
        Ok(true)
    }

    /// Whether the certificate lacks, at the current data epoch, the key of a scope it
    /// holds that reads a collection of the protocol (Switch spec 3.5).
    fn listing_lacks_keys(&self) -> bool {
        let epoch = self.state.own_doc.data_epoch();
        let collections = self.protocol.collections();
        self.state.cert.scopes().iter().any(|scope| {
            self.protocol.has_keys(scope)
                && self.state.scope_keys.get(epoch, scope).is_none()
                && collections.iter().any(|c| c.read_by_scope(scope))
        })
    }

    /// Open again, once a fetch took a scope key, the records held `Unreadable` whose value
    /// is sealed under a key the app now holds (Switch spec 3.5): their kept write goes
    /// through the checks again and is taken as opened ([`App::take_write`]). A data-epoch
    /// rotation and a listing before the keys came both leave such records. A value that
    /// still doesn't open with its key held is flagged and stays `Unreadable`; it is tried
    /// only at a fetch that takes a key, and when the write is read again, never at every
    /// read.
    ///
    /// The commit that takes the key keeps the reopening owed ([`REOPEN_DUE`]). The
    /// reopened records are committed as `list_collection` commits a listing, a commit
    /// whenever one more record might not fit, and only the last clears the mark: a failure
    /// at any of them leaves it owed, the records committed before it opened, and the next
    /// reading of the store goes on from there ([`App::reopen_if_due`]).
    pub(crate) async fn reopen_unreadable(&mut self) -> Result<(), AppError> {
        let held = self.reader().scan::<HeldRecord>(RECORD_PREFIX).await?;
        let mut tx = self.tx()?;
        for (_, record) in held {
            if !record.content.waits_for_key() {
                continue;
            }
            let Ok(op) = SignedOp::peek(&record.op) else {
                continue;
            };
            let OpKind::RecordPut(put) = &op.body().kind else {
                continue;
            };
            let sealed = &put.value_sealed;
            if self
                .state
                .scope_keys
                .get(sealed.data_epoch, &sealed.scope)
                .is_none()
            {
                continue;
            }
            if tx.size().saturating_add(LISTED_RECORD_ROOM_BYTES) > crate::store::MAX_BATCH_BYTES {
                let full = std::mem::replace(&mut tx, self.tx()?);
                self.commit(full).await?;
            }
            let collection = Collection::new(&record.collection, record.policy.clone());
            let evidence = Evidence {
                op: &record.op,
                cert: Some(&record.cert),
                proof: record.proof.as_ref(),
                stub: None,
                view_version: Some(record.version),
            };
            self.read_write(&evidence, Some((&put.key, &collection)), put.key, &mut tx)
                .await?;
        }
        if self.reader().exists(REOPEN_DUE).await? {
            tx.delete(REOPEN_DUE)?;
        }
        if !tx.is_empty() {
            self.commit(tx).await?;
        }
        Ok(())
    }

    /// The reopening a commit that took a scope key left owed, made now
    /// ([`App::reopen_unreadable`]), never while a page's writes are open. It owes nothing
    /// to the read: a reopening that fails keeps the mark, is reported
    /// ([`AppEvent::ReopeningOwed`]) and is made again at the next read, and the read goes
    /// on, from the store as committed when a commit failed. One read tries it at most
    /// [`REOPEN_TRIES_PER_READ`] times once it fails.
    ///
    /// # Errors
    ///
    /// A store that can't be read, and an alarm the reopening raised, or any failure once
    /// one is raised: the app is stopped, and the read ends there, so nothing is handed
    /// over or sent after the alarm.
    pub(crate) fn reopen_if_due(
        &mut self,
    ) -> crate::transport::BoxFuture<'_, Result<(), AppError>> {
        // Boxed, as `App::receive_inner` says.
        Box::pin(self.reopen_if_due_body())
    }

    async fn reopen_if_due_body(&mut self) -> Result<(), AppError> {
        if self.reopen_failures >= REOPEN_TRIES_PER_READ
            || !self.reader().exists(REOPEN_DUE).await?
        {
            return Ok(());
        }
        if let Err(error) = self.reopen_unreadable().await {
            if matches!(error, AppError::Alarm(_)) || self.state.alarm.is_some() {
                return Err(error);
            }
            self.reopen_failures = self.reopen_failures.saturating_add(1);
            self.events.push(AppEvent::ReopeningOwed {
                error: error.to_string(),
            });
            self.ready_local().await?;
        }
        Ok(())
    }

    /// Take a record view, from a read, a list page, after a conflict or after an upload;
    /// then hold what it says of divergent uploads, once the write is judged.
    pub(crate) async fn take_view(
        &mut self,
        view: &SharedRecordView,
        expect: Option<(&[u8; 32], &Collection)>,
        tx: &mut Tx,
    ) -> Result<WriteRead, AppError> {
        let evidence = Evidence {
            op: &view.op,
            cert: Some(&view.cert),
            proof: view.proof.as_ref(),
            stub: None,
            view_version: Some(RecordVersion::new(view.generation, view.version)),
        };
        let read = self.read_write(&evidence, expect, view.key, tx).await?;
        // Only a view of the key asked for says anything of that record's uploads.
        if expect.is_none_or(|(asked, _)| *asked == view.key) {
            self.note_view_divergence(&view.key, view.divergent, tx)
                .await?;
        }
        Ok(read)
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
        let mut viewed = None;
        let read = self
            .judge_write(&evidence, None, key, tx, &mut viewed)
            .await?;
        match viewed {
            // The record's view, read to judge the write, is the switch's latest word.
            Some(divergent) => self.note_view_divergence(&key, divergent, tx).await?,
            // A newer write clears the record's divergent uploads before it (Switch wire
            // 7.4.14); the write held doesn't: uploads after it may conflict with it.
            None if read == WriteRead::Taken => self.note_divergent(&key, false, tx).await?,
            None => {}
        }
        Ok(())
    }

    /// Check a write and take it, or flag it, or raise the rollback it proves; a view
    /// read to judge it says what the app holds of divergent uploads.
    async fn read_write(
        &mut self,
        evidence: &Evidence<'_>,
        expect: Option<(&[u8; 32], &Collection)>,
        shown_key: [u8; 32],
        tx: &mut Tx,
    ) -> Result<WriteRead, AppError> {
        let mut viewed = None;
        let read = self
            .judge_write(evidence, expect, shown_key, tx, &mut viewed)
            .await?;
        if let Some(divergent) = viewed {
            self.note_view_divergence(&shown_key, divergent, tx).await?;
        }
        Ok(read)
    }

    /// [`App::read_write`], with `viewed` set to the `divergent` of a view of `shown_key`
    /// read to judge the write, if one was.
    async fn judge_write(
        &mut self,
        evidence: &Evidence<'_>,
        expect: Option<(&[u8; 32], &Collection)>,
        shown_key: [u8; 32],
        tx: &mut Tx,
        viewed: &mut Option<bool>,
    ) -> Result<WriteRead, AppError> {
        let mut outcome = self.accept_write(evidence, expect, tx).await?;
        let mut version = evidence
            .stub
            .map(|env| RecordVersion::new(env.generation, env.seq))
            .or(evidence.view_version)
            .unwrap_or(RecordVersion::NONE);
        // A write the app holds no certificate in force at its time for: the record's view,
        // whose `cert` is the one the service checked the write against, decides (Switch
        // wire 6.2 "Accepting a write" step 1, 7.4.9).
        if let Err(Refused::Unheld(collection)) = &outcome {
            let collection = collection.clone();
            outcome = match self.record_view(&shown_key).await? {
                Some(view) => {
                    if view.key == shown_key {
                        *viewed = Some(view.divergent);
                    }
                    // A view of the feed's own write keeps what the feed gave it: the
                    // verified stub, which dates the write and gives its version whatever
                    // proof the view shows, and the item's proof. A view of another write
                    // is judged on its own evidence, and the feed write not at all.
                    let same = view.op == *evidence.op;
                    let stub = evidence.stub.filter(|_| same);
                    let view_version = RecordVersion::new(view.generation, view.version);
                    version = stub.map_or(view_version, |env| {
                        RecordVersion::new(env.generation, env.seq)
                    });
                    let evidence = Evidence {
                        op: &view.op,
                        cert: Some(&view.cert),
                        proof: view.proof.as_ref().or(evidence.proof.filter(|_| same)),
                        stub,
                        view_version: Some(view_version),
                    };
                    self.accept_write(&evidence, Some((&shown_key, &collection)), tx)
                        .await?
                }
                None => Err(Refused::Ignored),
            };
        }
        match outcome {
            Ok(accepted) => {
                return Ok(match self.take_write(accepted, false, tx).await? {
                    Taken::New => WriteRead::Taken,
                    Taken::Same | Taken::Reopened => WriteRead::Held,
                    Taken::NotNewer => WriteRead::NotNewer,
                    Taken::Flagged => WriteRead::Refused,
                });
            }
            Err(Refused::Misbehaviour(reason)) => {
                return Err(self.raise(Alarm::Rollback { reason }).await);
            }
            Err(Refused::Invalid {
                writer,
                write,
                reason,
            }) => {
                let deleted = writes_a_delete(evidence.op);
                let shown = Shown {
                    key: shown_key,
                    version,
                    write,
                };
                self.flag_write(shown, writer, reason, deleted, tx).await?;
            }
            Err(Refused::DoesNotOpen {
                writer,
                write,
                reason,
            }) => {
                // The record held with this very write, not open for now, won't open: its
                // version is the write's, so the flag below doesn't write it again.
                if let Some(mut held) = self.held_record(&shown_key).await?
                    && held.op == *evidence.op
                    && held.content.waits_for_key()
                {
                    held.content = RecordContent::Unreadable(Unopened::DoesNotOpen);
                    tx.put(&record_key_of(&shown_key), &held)?;
                }
                let deleted = writes_a_delete(evidence.op);
                let shown = Shown {
                    key: shown_key,
                    version,
                    write,
                };
                self.flag_write(shown, writer, reason, deleted, tx).await?;
            }
            Err(Refused::Unnamed { version: checked }) => {
                let deleted = writes_a_delete(evidence.op);
                self.follow_write(&shown_key, checked, deleted, false, tx)
                    .await?;
            }
            Err(Refused::Ignored | Refused::Unheld(_)) => {}
        }
        Ok(WriteRead::Refused)
    }

    /// Record a refused write, and follow its version when it is the switch's current one
    /// for a record the app holds.
    ///
    /// A write is kept once, by its item hash, which its writer signed, at the version it was
    /// last shown at: the same write shown again, at any version, replaces its entry. A
    /// record keeps at most [`FLAGGED_WRITES_PER_RECORD`], the one shown at the lowest
    /// version going first, so a service showing writes never grows them without bound.
    async fn flag_write(
        &mut self,
        shown: Shown,
        writer: [u8; 16],
        reason: String,
        deleted: bool,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let Shown {
            key,
            version,
            write,
        } = shown;
        let key = &key;
        let reason = cut_reason(reason);
        let flagged = FlaggedWrite {
            key: *key,
            version,
            writer,
            reason: reason.clone(),
        };
        let entry = flag_key(key, &write);
        let prefix = flag_prefix(key);
        let mut present: Vec<(String, Option<RecordVersion>)> = self
            .reader()
            .scan::<FlaggedWrite>(&prefix)
            .await?
            .into_iter()
            .map(|(rest, kept)| (format!("{prefix}{rest}"), Some(kept.version)))
            .filter(|(at, _)| tx.pending_state(at) != Some(false))
            .collect();
        for rest in tx.pending_put_keys(&prefix) {
            let at = format!("{prefix}{rest}");
            match present.iter_mut().find(|(held, _)| *held == at) {
                // Put again in this transaction: not dropped below.
                Some(held) => held.1 = None,
                None => present.push((at, None)),
            }
        }
        if !present.iter().any(|(at, _)| *at == entry) {
            let over = (present.len() + 1).saturating_sub(FLAGGED_WRITES_PER_RECORD);
            let mut stored: Vec<(String, RecordVersion)> = present
                .into_iter()
                .filter_map(|(at, version)| Some((at, version?)))
                .collect();
            stored.sort_by_key(|(_, version)| *version);
            for (at, _) in stored.iter().take(over) {
                tx.delete(at)?;
            }
        }
        tx.put(&entry, &flagged)?;
        self.follow_write(key, version, deleted, true, tx).await?;
        self.events.push(AppEvent::WriteFlagged {
            key: *key,
            writer,
            reason,
        });
        Ok(())
    }

    /// Follow a refused write's version when it is the switch's current one for a record the
    /// app holds, so the next write builds on it (Switch spec 8.2); `named` when the refusal
    /// names the app that signed it.
    async fn follow_write(
        &mut self,
        key: &[u8; 32],
        version: RecordVersion,
        deleted: bool,
        named: bool,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        if let Some(mut held) = self.held_record(key).await?
            && version > held.base_version()
        {
            held.follow = Some(version);
            held.follow_deleted = deleted;
            held.follow_named = named;
            tx.put(&record_key_of(key), &held)?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // The checks of Switch wire 6.2 "Accepting a write"

    /// `tx` is the transaction at hand, whose certificates kept but not committed yet
    /// count as known.
    async fn accept_write(
        &mut self,
        evidence: &Evidence<'_>,
        expect: Option<(&[u8; 32], &Collection)>,
        tx: &Tx,
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
        // Nothing before the signature check below names the writer: the body isn't verified
        // yet, so a faulty or hostile service could name any app in it. What fails before
        // it is ignored, as a write the app doesn't take.
        //
        // Step 3: the collection of the protocol. A write for another record key than the
        // one read is one the service served in its place: its writer wrote it for its own
        // key, so it isn't the writer's failure.
        let collection = match expect {
            Some((key, collection)) => {
                if put.key != *key {
                    return Ok(Err(Refused::Ignored));
                }
                collection.clone()
            }
            None => match self.collection_of(put) {
                Some(collection) => collection,
                None => return Ok(Err(Refused::Ignored)),
            },
        };
        // Step 1: the writer's certificates and the signature, which binds the identity and
        // the writer's App ID too.
        let Some(mut certs) = self.writer_certs(evidence, &writer, tx).await? else {
            // A feed write by a writer the newest own `identity.json` names, a removed one
            // included, whose certificate neither the app nor its directory holds: the
            // directory lists only current apps, and its read may fail. The record's view
            // decides (Switch wire 6.2 "Accepting a write" step 1).
            let doc = &self.state.own_doc;
            if evidence.cert.is_none()
                && (doc.listed_cert(&writer).is_some() || doc.lists_removed(&writer))
            {
                return Ok(Err(Refused::Unheld(Collection::new(
                    &collection.name,
                    put.policy.clone(),
                ))));
            }
            return Ok(Err(Refused::Ignored));
        };
        // The writer signed it, and the signature binds the identity (`SignedOp::verify`
        // refuses a body naming another): a failed check from here on names an app that made
        // the write, by the write's item hash, which its writer signed.
        //
        // One signed with this app's own key is the app's own write, under whichever of its
        // certificates it was made: the app checked its scopes when it made it, so the checks
        // of what it may write don't run again, but for the cutoff of its own removal (below).
        // A check it fails otherwise leaves it ignored, naming no app: a flag would name the
        // app itself.
        let own = writer == self.state.meta.app_id
            && SignedOp::verify(
                evidence.op,
                &self.state.keys.signing_public(),
                &identity,
                Some(&writer),
            )
            .is_ok();
        let item_hash = certs.op.item_hash()?;
        let invalid = |reason: &str| -> Result<Result<Accepted, Refused>, AppError> {
            if own {
                return Ok(Err(Refused::Ignored));
            }
            Ok(Err(Refused::Invalid {
                writer,
                write: item_hash,
                reason: reason.to_owned(),
            }))
        };
        if let Some(reason) = check_shape(put, &collection, &identity) {
            return invalid(reason);
        }
        // The member of the collection's policy family the write names.
        let collection = Collection::new(&collection.name, put.policy.clone());
        // Step 2: what dates the write and gives its version.
        let (time, proven) = match self.date(evidence, &certs.op, item_hash) {
            Ok(dated) => dated,
            Err(reason) => return Ok(Err(Refused::Misbehaviour(reason))),
        };
        // The version step 6 checks, `None` when nothing gives one.
        let shown = match (proven, evidence.view_version) {
            (Some(version), _) => Some(WriteVersion {
                version,
                authenticated: true,
                expected_version: put.expected_version,
            }),
            (None, Some(version)) => Some(WriteVersion {
                version,
                authenticated: false,
                expected_version: put.expected_version,
            }),
            (None, None) => None,
        };
        let plausible = shown.is_some_and(|version| version.plausible(body.generation));
        // A write refused on the service's word only, at the key read: followed, naming
        // nobody, when its version is plausible, so an honest service's record stays
        // writable, as one taken from a recovery upload under a renewal closed since; else
        // ignored.
        let unnamed = || -> Result<Result<Accepted, Refused>, AppError> {
            Ok(Err(match shown.filter(|_| plausible) {
                Some(checked) => Refused::Unnamed {
                    version: checked.version,
                },
                None => Refused::Ignored,
            }))
        };
        // Step 4: standing at the write's time, of a certificate of the writer that counts
        // for it (`write_cert`).
        let mut doubtful = false;
        let write_scopes = &put.policy.write_scopes;
        let Some(mut cert) = self.write_cert(&certs, time, write_scopes) else {
            return Ok(Err(Refused::Ignored));
        };
        let mut standing = self.state.own_doc.standing(&writer, &cert.hash());
        if !own
            && standing == Standing::None
            && matches!(
                self.refresh_identity().await,
                Ok(IdentityRefresh::Newer { .. })
            )
            && let Some(again) = self.write_cert(&certs, time, write_scopes)
        {
            cert = again;
            standing = self.state.own_doc.standing(&writer, &cert.hash());
        }
        let holds_write_scope =
            |cert: &AppCert| write_scopes.iter().any(|scope| cert.holds_scope(scope));
        let mut counts = in_force(&self.state.own_doc, &cert, time) && holds_write_scope(&cert);
        // No certificate of the writer the app holds counts for the write, while the newest
        // own `identity.json` names one in force at its time that the app doesn't hold: the
        // write may be the writer's under that one. Without a record view, the view decides
        // (step 1). With one, its `cert` is only the service's pick, as the write names no
        // certificate: the app reads its directory for the writer's listed certificate, once
        // for each the directory answers for while it runs. If that doesn't settle it, a
        // failure of steps 4 and 5 is the service's word, and the write is ignored, naming no
        // app. A read that fails marks nothing: a later write's judging reads again, once
        // `SENDER_REREAD_MS` has passed, so a failing directory costs at most one request a
        // minute.
        let mut unheld = !own && !counts && self.unheld_in_force(&writer, &certs, time);
        let now = self.now();
        let paced = self
            .directory_failed_ms
            .is_some_and(|at| at <= now && now - at < super::SENDER_REREAD_MS);
        if unheld
            && evidence.cert.is_some()
            && !paced
            && let Some(listed) = self.state.own_doc.listed_cert(&writer)
            && !certs.known.iter().any(|cert| cert.hash() == listed)
            && !self.directory_asked.contains(&listed)
        {
            let answered = self.refresh_own_apps().await.is_ok();
            if answered {
                self.directory_failed_ms = None;
                self.directory_asked.push(listed);
            } else {
                self.directory_failed_ms = Some(now);
            }
            if answered
                && let Some(again) = self.writer_certs(evidence, &writer, tx).await?
                && let Some(found) = self.write_cert(&again, time, write_scopes)
            {
                certs = again;
                cert = found;
                standing = self.state.own_doc.standing(&writer, &cert.hash());
                counts = in_force(&self.state.own_doc, &cert, time) && holds_write_scope(&cert);
                unheld = !counts && self.unheld_in_force(&writer, &certs, time);
            }
        }
        if unheld && evidence.cert.is_none() && time.is_some() {
            return Ok(Err(Refused::Unheld(collection)));
        }
        let invalid = |reason: &str| -> Result<Result<Accepted, Refused>, AppError> {
            if unheld {
                return unnamed();
            }
            invalid(reason)
        };
        match standing {
            // A removed app's key may be a lost device's (Switch spec 3.1, 12.2 step 3): its
            // own writes keep the `distrust_from` cutoff, ignored after it (`invalid` names
            // no app for an own write) and doubtful when nothing dates them.
            _ if own && !matches!(standing, Standing::Removed { .. }) => {}
            Standing::Listed | Standing::RenewedOpen => {}
            Standing::RenewedClosed { until } => match time {
                Some(t) if t >= until => {
                    return invalid(
                        "Switch wire 6.2 step 4: an earlier certificate's write dated after its \
                         renewal closed",
                    );
                }
                Some(_) => {}
                // Nothing dates it: the service keeps the proof of every current write (Switch
                // wire 7.4.9), so a missing one is the service's word. The write isn't taken
                // and names no app; its version is followed.
                None => return unnamed(),
            },
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
        if !own && time.is_some_and(|t| cert.expired_at(t)) {
            return invalid("Switch wire 6.2 step 4: the certificate had expired at the write");
        }
        // Step 5: a write scope.
        if !own && !holds_write_scope(&cert) {
            return invalid("Switch wire 6.2 step 5: the writer holds none of the write scopes");
        }
        // Step 6: the version. It is the service's word, not the writer's: a write whose
        // version is missing or not plausible is ignored, naming no app and followed by
        // nothing. A client loses nothing by it that a service withholding the write couldn't
        // take.
        let Some(version) = shown.filter(|_| plausible) else {
            return Ok(Err(Refused::Ignored));
        };
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
                RecordContent::Unreadable(Unopened::KeyNotHeld {
                    data_epoch: put.value_sealed.data_epoch,
                })
            }
            Err(_) => {
                return Ok(Err(Refused::DoesNotOpen {
                    writer,
                    write: item_hash,
                    reason: "Switch wire 6.2 step 7: the value doesn't open".into(),
                }));
            }
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

    /// The writer's certificates whose key verifies the operation: the record view's, and
    /// those the app knows, its own and the ones kept from the directory and the feed,
    /// those `tx` keeps included; the own directory is read again once for a writer the app
    /// doesn't know.
    async fn writer_certs(
        &mut self,
        evidence: &Evidence<'_>,
        writer: &[u8; 16],
        tx: &Tx,
    ) -> Result<Option<WriterCerts>, AppError> {
        let identity = self.state.meta.identity;
        let verify = |cert: AppCert| -> Option<(AppCert, SignedOp)> {
            if cert.app_id() != *writer {
                return None;
            }
            SignedOp::verify(evidence.op, &cert.signing_key(), &identity, Some(writer))
                .ok()
                .map(|op| (cert, op))
        };
        let view = evidence
            .cert
            .and_then(|signed| AppCert::verify(signed, &identity).ok())
            .and_then(verify);
        let mut candidates: Vec<AppCert> = vec![self.state.cert.clone()];
        candidates.extend(self.state.renewal.iter().cloned());
        candidates.extend(self.kept_certs(writer).await?);
        candidates.extend(self.pending_certs(tx, writer));
        let mut known: Vec<(AppCert, SignedOp)> =
            candidates.into_iter().filter_map(verify).collect();
        if view.is_none() && known.is_empty() {
            if self.refresh_own_apps().await.is_err() {
                return Ok(None);
            }
            known = self
                .kept_certs(writer)
                .await?
                .into_iter()
                .filter_map(verify)
                .collect();
        }
        let Some(op) = view.as_ref().or(known.first()).map(|(_, op)| op.clone()) else {
            return Ok(None);
        };
        Ok(Some(WriterCerts {
            view: view.map(|(cert, _)| cert),
            known: known.into_iter().map(|(cert, _)| cert).collect(),
            op,
        }))
    }

    /// The certificate a write is judged with (Switch wire 6.2 "Accepting a write" steps 1,
    /// 4 and 5, 7.4.9). A write names no certificate: every certificate of its writer has
    /// the signing key that verifies it. So it is judged with one of the writer's
    /// certificates that counts for it, in force at its time and holding a write scope:
    /// the record view's `cert`, the one the service checked the write against, when it
    /// counts, so a renewal later doesn't change what an earlier write is judged with;
    /// else a known certificate, of those the one in the best standing now, which still
    /// authorizes the write when nothing dates it, as after an upload. When none counts,
    /// the view's `cert`, or a known certificate in force, or the one in the best standing
    /// now, whose failure the checks give.
    fn write_cert(
        &self,
        certs: &WriterCerts,
        time: Option<u64>,
        write_scopes: &[String],
    ) -> Option<AppCert> {
        let doc = &self.state.own_doc;
        let holds_write_scope =
            |cert: &AppCert| write_scopes.iter().any(|scope| cert.holds_scope(scope));
        if let Some(cert) = certs
            .view
            .as_ref()
            .filter(|cert| in_force(doc, cert, time) && holds_write_scope(cert))
        {
            return Some(cert.clone());
        }
        let rank = |cert: &&AppCert| match doc.standing(&cert.app_id(), &cert.hash()) {
            Standing::Listed => 0,
            Standing::RenewedOpen => 1,
            Standing::RenewedClosed { .. } => 2,
            Standing::Removed { .. } => 3,
            Standing::None => 4,
        };
        let mut counting: Vec<&AppCert> = certs
            .known
            .iter()
            .filter(|cert| in_force(doc, cert, time))
            .collect();
        counting.sort_by_key(|cert| (rank(cert), cert.issued_at()));
        if let Some(cert) = counting.iter().find(|cert| holds_write_scope(cert)) {
            return Some((*cert).clone());
        }
        if let Some(cert) = &certs.view {
            return Some(cert.clone());
        }
        counting
            .first()
            .map(|cert| (*cert).clone())
            .or_else(|| certs.known.iter().min_by_key(rank).cloned())
    }

    /// Whether the newest own `identity.json` names a certificate of `writer` in force at
    /// `time` that the app doesn't hold (Switch wire 6.2 "Accepting a write" step 1); when
    /// nothing dates the write, one that counts without a date.
    fn unheld_in_force(&self, writer: &[u8; 16], certs: &WriterCerts, time: Option<u64>) -> bool {
        let doc = &self.state.own_doc;
        let held: Vec<[u8; 32]> = certs
            .known
            .iter()
            .chain(certs.view.as_ref())
            .map(AppCert::hash)
            .collect();
        doc.listed_cert(writer)
            .into_iter()
            .chain(
                doc.body()
                    .renewed
                    .iter()
                    .filter(|entry| &entry.app_id == writer)
                    .map(|entry| entry.cert),
            )
            .any(|hash| counts_at(doc.standing(writer, &hash), time) && !held.contains(&hash))
    }

    /// The certificates of `app_id` that `tx` keeps, not committed yet: those of the writes
    /// taken earlier in the same read, so one view read serves a page's writes under one
    /// certificate. Each is read once, however often `tx` keeps it.
    fn pending_certs(&self, tx: &Tx, app_id: &[u8; 16]) -> Vec<AppCert> {
        let prefix = format!(
            "{CERT_PREFIX}{}/",
            pubky_switch_core::enc::zbase32_encode(app_id)
        );
        let identity = self.state.meta.identity;
        let mut seen: Vec<&[u8]> = Vec::new();
        let mut certs = Vec::new();
        for write in tx.pending_writes() {
            if let crate::store::Write::Put { key, value, .. } = write
                && key.starts_with(prefix.as_bytes())
                && !seen.contains(&key.as_slice())
            {
                seen.push(key);
                if let Ok(signed) = super::state::decode::<SignedDoc>(value)
                    && let Ok(cert) = AppCert::verify(&signed, &identity)
                {
                    certs.push(cert);
                }
            }
        }
        certs
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
    ///
    /// The same write again, by its item hash, changes nothing but a version a proof now
    /// authenticates, unless the app holds it `Unreadable` and now opens it: a value never
    /// opened was never seen, so it is taken as a write is, its version evidence the better
    /// of the two, and the protocol checks and marks it (Switch spec 3.5, 8.2).
    async fn take_write(
        &mut self,
        mut accepted: Accepted,
        own: bool,
        tx: &mut Tx,
    ) -> Result<Taken, AppError> {
        let key = accepted.key;
        self.keep_cert(&accepted.cert, tx)?;
        let held = self.held_record(&key).await?;
        let reopened = held.as_ref().is_some_and(|held| {
            held.item_hash == accepted.item_hash
                && held.content.waits_for_key()
                && !matches!(accepted.content, RecordContent::Unreadable(_))
        });
        if let Some(held) = held.as_ref().filter(|_| reopened)
            && held.authenticated
            && !accepted.version.authenticated
        {
            accepted.version = held.write_version();
            accepted.proof = accepted.proof.take().or(held.proof.clone());
            accepted.time = held.written_at_ms.or(accepted.time);
        }
        if let Some(held) = held.as_ref().filter(|_| !reopened) {
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
        // What the write builds on, and whether the app holds it (Switch spec 8.2, 10.3).
        let expected_version = accepted.version.expected_version;
        // The write was verified before it got here, so its operation reads; its conditions
        // are the ones it signed (Switch wire 6.3).
        let conditions = SignedOp::peek(&accepted.op)
            .map(|op| op.body().conditions.clone())
            .unwrap_or_default();
        let base = WriteBase {
            expected_version,
            held: match &held {
                // A writer that holds a deleted record creates it again on `{0, 0}`
                // (Switch wire 6.2).
                Some(held) if expected_version.is_none() => held.content == RecordContent::Deleted,
                Some(held) => held.version == expected_version,
                None => expected_version.is_none(),
            },
            conditions,
        };
        // A write by this app is its own, also when the feed or a view shows it before its
        // answer, or another device of the app made it: one app is one principal (Switch
        // spec 3.1), so it is never checked against what this device saw, and it is marked
        // from the value written, as at its answer, once this device can read that value. A
        // flag would name the app itself.
        let own = own || accepted.writer == self.state.meta.app_id;
        if !own
            && let Some(mark) = &seen
            && let Some(reason) = self.protocol.record_regression_on(
                &accepted.collection.name,
                &mark.mark,
                new_value,
                base,
            )
        {
            let shown = Shown {
                key,
                version: accepted.version.version,
                write: accepted.item_hash,
            };
            let deleted = accepted.content == RecordContent::Deleted;
            self.flag_write(shown, accepted.writer, reason, deleted, tx)
                .await?;
            return Ok(Taken::Flagged);
        }
        // What the app saw of a record stays seen after its own delete (Switch spec 8.2):
        // the mark it holds stays, so a write that brings the record back without it is
        // checked against it. So does an own write this device can't read yet, such as
        // another device's at a data epoch whose key it hasn't fetched: the mark is set from
        // its value when the key comes and the record reopens (`reopen_unreadable`), which
        // takes it here again. Any other own write marks from the value it wrote.
        let keeps_mark =
            own && (accepted.content == RecordContent::Deleted || accepted.content.waits_for_key());
        let marked = if keeps_mark {
            None
        } else {
            self.protocol.record_seen(
                &accepted.collection.name,
                if own {
                    None
                } else {
                    seen.as_ref().map(|m| m.mark.as_slice())
                },
                new_value,
            )
        };
        match marked {
            // A mark over its bound isn't kept, and nothing of it is silent: another app's
            // write leaves the mark held, so what was seen before is still checked; an own
            // write's never leaves a mark that doesn't describe it. Either way the protocol
            // is told, in this change's commit, that the record can't be checked from here.
            Some(mark) if mark.len() > MAX_SEEN_MARK_BYTES => {
                if own {
                    tx.delete(&seen_key(&key))?;
                }
                self.keep_duty(
                    tx,
                    Duty::RecordUncheckable {
                        key,
                        writer: accepted.writer,
                        generation: accepted.version.version.generation,
                        version: accepted.version.version.version,
                        mark_bytes: u64::try_from(mark.len()).unwrap_or(u64::MAX),
                    },
                )?;
            }
            Some(mark) => tx.put(&seen_key(&key), &SeenMark { mark })?,
            None if own && !keeps_mark => tx.delete(&seen_key(&key))?,
            None => {}
        }
        let record = HeldRecord {
            collection: accepted.collection.name.clone(),
            policy: accepted.collection.policy.clone(),
            op: accepted.op,
            cert: accepted.cert.signed().clone(),
            proof: accepted.proof,
            version: accepted.version.version,
            authenticated: accepted.version.authenticated,
            expected: accepted.version.expected_version,
            written_at_ms: accepted.time,
            writer: accepted.writer,
            item_hash: accepted.item_hash,
            content: accepted.content,
            doubtful: accepted.doubtful,
            follow: held
                .as_ref()
                .and_then(|held| held.follow)
                .filter(|_| reopened),
            follow_deleted: held.as_ref().is_some_and(|held| held.follow_deleted) && reopened,
            follow_named: held.as_ref().is_none_or(|held| held.follow_named) || !reopened,
        };
        tx.put(&record_key_of(&key), &record)?;
        self.events.push(AppEvent::RecordChanged { key });
        Ok(if reopened {
            Taken::Reopened
        } else {
            Taken::New
        })
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
            .accept_write(&evidence, Some((&key, &collection)), tx)
            .await?
        {
            Ok(accepted) => {
                // The app's own write at this service clears the record's divergent
                // uploads there (Switch wire 7.4.14).
                if self.take_write(accepted, true, tx).await? == Taken::New {
                    self.note_divergent(&key, false, tx).await?;
                }
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
    /// An explicit write builds on the version held whatever its value: it overwrites a
    /// value held unopened only for now, its key not held yet
    /// (`RecordContent::Unreadable(Unopened::KeyNotHeld)`), without reading it. The caller
    /// sees that in the held record's `content` ([`App::shared_record`]) and decides;
    /// [`App::update_record`], which builds on the value, refuses it instead.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`] for a stopped or departed app;
    /// [`Refusal::Usage`] when the certificate holds none of the write scopes, for a value
    /// that isn't strict JSON (Switch wire 6.2), before anything is fetched, marked, signed
    /// or sent, or, for a write that isn't a delete, when the protocol's mark of the value
    /// ([`super::Protocol::record_seen`]) is over [`super::MAX_SEEN_MARK_BYTES`]: a delete
    /// makes no mark, and is never refused for one; [`Refusal::NotNow`] while the app lacks
    /// the read scope's key at the current data epoch (it fetches its key bundle first); a
    /// store failure.
    pub async fn record_op(
        &mut self,
        target: &RecordTarget,
        value: Option<&[u8]>,
        conditions: Vec<Condition>,
    ) -> Result<(Vec<Condition>, OpKind), AppError> {
        Box::pin(async move {
            self.refuse_when_stopped()?;
            // Before the key bundle is fetched and the protocol marks the value.
            refuse_non_json(value)?;
            let epoch = self.state.own_doc.data_epoch();
            let read_scope = &target.collection.policy.read_scope;
            if self.state.scope_keys.get(epoch, read_scope).is_none() {
                self.ensure_scope_keys().await?;
            }
            refuse_unmarkable(self.protocol.as_ref(), target, value)?;
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
    /// once more. Like [`App::record_op`], it overwrites a value held unopened only for now
    /// (`Unopened::KeyNotHeld`): the caller reads the held record's `content` first and
    /// decides.
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
        Box::pin(async move {
            self.write_record(target, Some(value), conditions, false)
                .await
        })
        .await
    }

    /// Delete the record at `target`: a write whose sealed value is empty (Switch spec
    /// 10.3). Like [`App::put_record`], it deletes a value held unopened only for now
    /// (`Unopened::KeyNotHeld`): the caller reads the held record's `content` first and
    /// decides.
    ///
    /// # Errors
    ///
    /// As [`App::put_record`].
    pub async fn delete_record(
        &mut self,
        target: &RecordTarget,
        conditions: Vec<Condition>,
    ) -> Result<SharedRecord, AppError> {
        Box::pin(async move { self.write_record(target, None, conditions, false).await }).await
    }

    /// `again` for a further try within one [`App::update_record`] ([`App::submit_checked`]).
    async fn write_record(
        &mut self,
        target: &RecordTarget,
        value: Option<&[u8]>,
        conditions: Vec<Condition>,
        again: bool,
    ) -> Result<SharedRecord, AppError> {
        let fresh = self.time_fresh_at;
        self.ready_local().await?;
        if again {
            self.time_fresh_at = fresh;
        }
        let key = self.record_key(target)?;
        let entry = self.record_op(target, value, conditions).await?;
        self.note_pending_name(&key, &target.collection).await?;
        // `409 stale_epoch` is followed inside `submit_batch`: the write is sealed again at
        // the new data epoch and sent once more.
        match self
            .submit_checked(OpBatch::new().entry(entry), again)
            .await
        {
            Ok(_) => self
                .shared_record(&key)
                .await?
                .ok_or_else(|| AppError::InvalidData("the record written isn't held".into())),
            Err(error) if error.code() == Some(ErrorCode::Conflict) => {
                self.fetch_record(&key, &target.collection).await?;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    /// Build a record's next value from what the app holds and write it, building it again
    /// on what the switch holds after each `409 conflict` (Switch spec 10.3): `change` gets
    /// the current value (`None` for none, deleted, or one that won't open) and returns the
    /// new one, or `None` when nothing changes. Returns the record written, or `None` when
    /// `change` changed nothing.
    ///
    /// A value the app holds unopened for want of its key (`KeyNotHeld`) isn't handed over
    /// as `None`, which would have `change` overwrite what it can't see: the write waits
    /// for the key (Switch spec 3.5, 8.2). The outbox's record jobs go through here, so a
    /// message's record job waits the same way.
    ///
    /// **Worst case.** At most four tries, a further one only while the call's time budget
    /// isn't spent ([`super::AppConfig::call_budget_ms`], 20 s by default). The call takes
    /// one time sample and sends at most one kept batch again in all
    /// ([`App::submit_batch`]): the first try sends at most four requests, those two, its
    /// own batch and, after a conflict, a read of the record; a further try two, its batch
    /// and that read. So with batches of a few KiB it ends within about 40 s at the default
    /// timeouts, whether the first try took them or a further one began just inside the
    /// budget; a larger batch's send has a longer timeout
    /// ([`crate::transport::HttpConfig`]), and the cases [`App::submit_batch`] names add
    /// their requests.
    ///
    /// # Errors
    ///
    /// As [`App::put_record`]; [`Refusal::NotNow`] while the held value waits for its key;
    /// `409 conflict` when the record kept changing, or when the budget ran out first.
    pub async fn update_record(
        &mut self,
        target: &RecordTarget,
        conditions: Vec<Condition>,
        mut change: impl FnMut(Option<&[u8]>) -> Option<Vec<u8>> + Send,
    ) -> Result<Option<SharedRecord>, AppError> {
        Box::pin(async move {
            let key = self.record_key(target)?;
            let budget = self.begin_budget();
            let mut last = None;
            for attempt in 0..UPDATE_TRIES {
                // A further try only within the call's time budget: past it the call
                // returns the conflict it last met.
                if attempt > 0 && self.spent(&budget) {
                    break;
                }
                let current = self.shared_record(&key).await?;
                if current.as_ref().is_some_and(|r| r.content.waits_for_key()) {
                    return Err(Refusal::NotNow(
                        "Switch spec 3.5: the record's value is sealed under a key the app \
                         doesn't hold yet"
                            .into(),
                    )
                    .into());
                }
                let value = current.as_ref().and_then(|r| r.content.value());
                let Some(next) = change(value) else {
                    return Ok(None);
                };
                match self
                    .write_record(target, Some(&next), conditions.clone(), attempt > 0)
                    .await
                {
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

/// Refuse a record value that isn't strict JSON, an empty one included; `None`, a delete,
/// passes. A record's value is strict JSON, and only the empty plaintext, a delete, isn't
/// (Switch wire 6.2 "Accepting a write", 1.1). The switch can't tell: the value is sealed
/// to the read scope's key, so it takes and chains any value, and a reader, the writer
/// included, finds one that isn't JSON doesn't open. So it is refused before it is signed
/// or sent.
pub(crate) fn refuse_non_json(value: Option<&[u8]>) -> Result<(), AppError> {
    if let Some(json) = value
        && pubky_switch_core::json::check_json(json).is_err()
    {
        return Err(Refusal::Usage(
            "Switch wire 6.2: a record's value is strict JSON (an empty one is a delete)".into(),
        )
        .into());
    }
    Ok(())
}

/// Refuse an own write whose mark ([`super::Protocol::record_seen`] after `value`, from
/// nothing, as for every own write) would be over [`MAX_SEEN_MARK_BYTES`]: the app couldn't
/// keep it, and the record couldn't be checked from that write on. An own delete keeps the
/// mark held and makes none, so it is never refused here.
pub(crate) fn refuse_unmarkable(
    protocol: &dyn super::Protocol,
    target: &RecordTarget,
    value: Option<&[u8]>,
) -> Result<(), AppError> {
    let Some(value) = value else {
        return Ok(());
    };
    match protocol.record_seen(&target.collection.name, None, Some(value)) {
        Some(mark) if mark.len() > MAX_SEEN_MARK_BYTES => Err(Refusal::Usage(format!(
            "the protocol's mark of this write takes {} bytes, over {MAX_SEEN_MARK_BYTES}",
            mark.len()
        ))
        .into()),
        _ => Ok(()),
    }
}

/// The `record.put` of `value` at `target` (`None` a delete), built on `held`, the write the
/// app holds there: on its version, or a create (`{0, 0}` with `id_inputs`) for a record it
/// holds nothing of or holds deleted, sealed under the read scope's key at the current data
/// epoch (Switch spec 3.5, 10.3, 13.4).
///
/// # Errors
///
/// [`Refusal::Usage`] when the certificate holds none of the write scopes, or for a value
/// that isn't strict JSON, an empty one included, before anything is sealed;
/// [`Refusal::NotNow`] while the app lacks the read scope's key at the current data epoch.
pub(crate) fn record_put(
    state: &super::AppState,
    target: &RecordTarget,
    value: Option<&[u8]>,
    held: Option<&HeldRecord>,
) -> Result<RecordPut, AppError> {
    refuse_non_json(value)?;
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
    let base = held.map_or(RecordVersion::NONE, HeldRecord::write_base);
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
/// sent messages that holds content or a bearer secret (Switch spec 3.1, 12.3), and the
/// kept batches with their ends and indexes, which no flush of a left app would prune.
pub(crate) fn destroy_shared(tx: &mut Tx) -> Result<(), AppError> {
    for prefix in [
        RECORD_PREFIX,
        SEEN_PREFIX,
        "recname/",
        "out/",
        "sent/",
        "sentt/",
        "outgone/",
        "outhold/",
        "invite/",
        "opq/",
        "kb/",
        "kbt/",
        "kbm/",
        "kba/",
        LISTC_PREFIX,
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

/// A protocol's rule, cut to [`MAX_REGRESSION_REASON_BYTES`] at a character boundary.
fn cut_reason(mut reason: String) -> String {
    if reason.len() > MAX_REGRESSION_REASON_BYTES {
        let mut end = MAX_REGRESSION_REASON_BYTES;
        while !reason.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        reason.truncate(end);
    }
    reason
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
