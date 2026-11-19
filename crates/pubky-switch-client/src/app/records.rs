//! Shared records (Switch spec 8.2, 8.3, 10.3; Switch wire 6.2 `record.put`, 7.4.9).
//!
//! A shared record is a protocol's: its collections and their fixed policies come from
//! [`super::Protocol::collections`], or from the caller as a [`Collection`]. The app keeps,
//! per record key, the write it took (`rec/<key>`), the protocol's mark of what it has seen
//! there (`hw/<key>`), and the writes it refused (`flag/<key>/<write>`).
//!
//! - **Keys** come from the naming key: `derive("pubky-switch/v1/record", collection,
//!   blind(natural key), policy hash)` (Switch spec 13.3).
//! - **Writes** are compare-and-swap on the version the app holds, a delete's included, and
//!   `{0, 0}` only to create a record the switch holds nothing of. Every write carries its
//!   collection name and blinded natural key; over a
//!   write taken from a recovery upload they name it exactly; the value is sealed under the read
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
//!   the app has seen there ([`super::Protocol::record_regression`]). A write refused that
//!   way is flagged, its content not acted on, but its version followed, so the app's next
//!   write builds on it and puts back the content it trusts (Switch spec 8.2).
//! - **Listing** runs at join, after a restore, after a `missed` item, and after a certificate
//!   taken that reads a collection the one before didn't (Switch spec 8.2, 8.3).

mod collection;
mod evidence;
mod inventory;
mod page_reader;
use evidence::{FollowedWrite, Historical, Placement, position};
pub(super) use page_reader::PageReader;
pub(super) mod previous;

pub use collection::{Collection, PolicyFamily, RecordTarget};
pub use inventory::CurrentCollection;

use pubky_switch_core::chain::{ChainEnvelope, SignedHead, TransitionProof};
use pubky_switch_core::enc::{b64, serde_b64, serde_b64_vec, unb64_array};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ident::Policy;
use pubky_switch_core::ops::{
    Condition, IdInputs, OpKind, RecordPut, RecordVersion, SignedOp, check_permanent,
};
use pubky_switch_core::records::{AppCert, AppRecord, IdentityDoc, Standing};
use pubky_switch_core::sealed::{RecordValue, SealedValue};
use pubky_switch_core::shared::{ApplicationRef, WriteVersion, date_write};
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};

use super::batch::OpBatch;
use super::error::{Alarm, Refusal};
use super::events::{AppEvent, Duty};
use super::order::{Handover, Kept};
use super::protocol::{MAX_REGRESSION_REASON_BYTES, MAX_SEEN_MARK_BYTES, WriteBase};
use super::state::{ChainRecord, Tx, key};
use super::{App, AppError, FeedPosition, IdentityRefresh};
use crate::client::Batch;
use crate::client::answers::{ChainItem, SharedRecordView};
use crate::client::read::Obj;
use crate::error::ClientError;

const RECORD_PREFIX: &str = "rec/";
/// The index of the records at a permanent policy the app holds live, by key, each with
/// its collection's name (Switch spec 10.3.1 "Absence"): kept with `rec/` by
/// [`put_held`], so a listing page judges absence without reading every held record.
const PERMANENT_PREFIX: &str = "recp/";
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

/// `list_due`: the listings of collections the app owes, one per protocol named: of that
/// protocol's readable collections, owed by the feed item at (generation, `seq`), or, for
/// `None`, outside the feed (a join, a restore, a certificate taken). One owed outside the
/// feed is made before a read hands anything; one a feed item owes is made once its
/// protocol is told through everything before that item, and that protocol is told
/// nothing after the item meanwhile (`order` module). Each protocol once: the earliest
/// position stands, and outside the feed comes before any.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ListDue {
    pub(crate) to: Vec<(String, Option<(u64, u64)>)>,
    /// A page settling an upload must cover this transition, even when a protocol's
    /// earlier handover remains outstanding.
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) upload: Option<FeedPosition>,
}

impl ListDue {
    /// The listings at feed positions, before calls at the same position.
    pub(crate) fn kept(&self) -> Vec<Kept> {
        self.to
            .iter()
            .filter_map(|(name, at)| {
                at.map(|(generation, seq)| Kept {
                    generation,
                    seq,
                    names: vec![name.clone()],
                    call: false,
                    held_gap: None,
                    deny: false,
                })
            })
            .collect()
    }

    /// Where the listing owed to protocol `name` is owed, if one is: `Some(None)` outside
    /// the feed.
    pub(crate) fn at(&self, name: &str) -> Option<Option<(u64, u64)>> {
        self.to
            .iter()
            .find(|(owed, _)| owed == name)
            .map(|(_, at)| *at)
    }
}

/// The listings owed as `tx` leaves them, or as the store holds them.
pub(crate) async fn list_due_in(
    reader: &super::state::Reader,
    tx: &Tx,
) -> Result<ListDue, AppError> {
    Ok(match tx.pending_get::<ListDue>(LIST_DUE)? {
        Some(due) => due.unwrap_or_default(),
        None => reader.get::<ListDue>(LIST_DUE).await?.unwrap_or_default(),
    })
}

/// Owe each protocol of `names` a listing of its collections from their beginning, in
/// `tx`, outside the feed: `list_due` names them and `list_at` is deleted. Every new
/// obligation starts the listing over, so a collection a listing under way already listed
/// to its end is listed again: it may read members it didn't, such as after a renewal that
/// widens the certificate (Switch spec 8.2, 8.3).
pub(crate) fn owe_listing(tx: &mut Tx, names: &[String]) -> Result<(), AppError> {
    let due = ListDue {
        to: names.iter().map(|name| (name.clone(), None)).collect(),
        upload: None,
    };
    put_list_due(tx, &due)
}

/// Keep the listings owed as `due` names them, in `tx`, each from its beginning
/// ([`owe_listing`]).
pub(crate) fn put_list_due(tx: &mut Tx, due: &ListDue) -> Result<(), AppError> {
    tx.put(LIST_DUE, due)?;
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
    /// The listing has more work. A page or time limit resumes from the last key.
    /// A change in the certificate that can read the collection requires a fresh
    /// range under the new grant. Keep the listing pending until it finishes.
    pub more: bool,
}

/// The most records one listing page asks for (Switch wire 7.4.9).
const LIST_PAGE: u32 = 1000;

/// What taking one listed record writes, at most: its cached write (its operation, 512 KiB,
/// and opened value, 256 KiB, in base64, with its proof: 1.2 MiB), its mark as stored
/// ([`MAX_SEEN_MARK_BYTES`] in base64), a flagged write's rule, and its duty events.
/// The reserved room covers either a deletion or the readable value's local observation.
const LISTED_RECORD_ROOM_BYTES: u64 = super::feed::CACHED_RECORD_BYTES
    + super::feed::KEPT_MARK_BYTES
    + super::deletion::ROOM
    + (64 << 10);

// One listed record always fits a commit of its own.
const _: () = assert!(LISTED_RECORD_ROOM_BYTES < crate::store::MAX_BATCH_BYTES);

/// How many times a write is built again after a conflict before the call gives up.
const UPDATE_TRIES: usize = 4;

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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ListProgress {
    /// The authority under which the preceding ranges were visible.
    #[serde(with = "serde_b64")]
    cert: [u8; 32],
    generation: u64,
    /// The collections listed to their end, by collection ID in base64url.
    done: Vec<String>,
    /// The collection being listed, and the last key of its last page taken.
    at: Option<(String, String)>,
}

impl ListProgress {
    fn for_reader(saved: Option<Self>, cert: [u8; 32], generation: u64) -> Self {
        saved
            .filter(|progress| progress.cert == cert && progress.generation == generation)
            .unwrap_or(Self {
                cert,
                generation,
                done: Vec::new(),
                at: None,
            })
    }

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

/// A record view, its checked observation, and whether it covers the pending uploads.
pub(super) struct ObservedView {
    pub(super) view: SharedRecordView,
    pub(super) at: CurrentAt,
    pub(super) covers_uploads: bool,
    /// This GET repeated the active service's already observed signed chain tip.
    at_known_tip: bool,
}

/// A key read or conflict can establish that even a tombstone is absent.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum MissingFrom {
    Key,
    LiveListing,
}

/// Local cursor identity for the set of policies this pass can admit. An older
/// cursor for the collection ID alone cannot establish coverage of additional generations.
fn listing_scope(
    id: &[u8; 32],
    collection: &Collection,
    members: Option<&[Collection]>,
) -> Result<[u8; 32], AppError> {
    let members = members.unwrap_or_else(|| std::slice::from_ref(collection));
    if !members.iter().any(|member| {
        member.name == collection.name && member.family == PolicyFamily::PermanentGenerations
    }) {
        return Ok(*id);
    }
    let mut policies = Vec::new();
    for member in members
        .iter()
        .filter(|member| member.name == collection.name)
    {
        let kind = match member.family {
            PolicyFamily::Fixed => 0,
            PolicyFamily::SubScopes => 1,
            PolicyFamily::PermanentGenerations => 2,
        };
        policies.push((kind, member.policy.hash()?));
    }
    policies.sort_unstable();
    policies.dedup();
    let mut bytes = id.to_vec();
    for (kind, policy) in policies {
        bytes.push(kind);
        bytes.extend_from_slice(&policy);
    }
    Ok(pubky_switch_core::enc::hash(&bytes))
}

/// The switch's answer to a read of one record key ([`App::record_answer`]).
pub(super) enum RecordAnswer {
    /// The record's view, with what it is current at.
    View(Box<ObservedView>),
    /// A hosted `404` covering the observations at this key.
    Absent,
    /// The answer does not cover the applicable record or upload observation.
    Inconclusive,
    /// `404` with `current: { "hosted": false }`: the switch doesn't host the identity
    /// (Switch wire 7.3 step 2). That says nothing of the record: the service reads as
    /// unreachable (Switch spec 10.3.1 "Absence", 12.7 step 5).
    NotHosted(Box<ClientError>),
}

/// What a read of one record key came to ([`App::fetch_record`]).
#[derive(Debug)]
pub(crate) enum Fetched {
    /// The switch's view, and what reading its write came to.
    Read(WriteRead),
    /// `404` at an account the switch hosts: it holds no record at the key.
    Absent,
    /// The signed `404` saying the switch doesn't host the identity: the service reads as
    /// unreachable, and the record isn't absent (Switch spec 10.3.1 "Absence", 12.7 step 5).
    NotHosted(Box<ClientError>),
}

pub(crate) fn record_key_of(key: &[u8; 32]) -> String {
    format!("{RECORD_PREFIX}{}", b64(key))
}

/// Write `held` as the record the app holds at `key`, and keep its entry in the index of
/// permanent records held live (`recp/`) in step: there while it is live and was seen live
/// at a permanent policy, else gone.
pub(crate) fn put_held(tx: &mut Tx, key: &[u8; 32], held: &HeldRecord) -> Result<(), AppError> {
    tx.put(&record_key_of(key), held)?;
    let index = format!("{PERMANENT_PREFIX}{}", b64(key));
    if held.live_in.is_some() && held.content != RecordContent::Deleted {
        tx.put(&index, &held.collection)
    } else {
        tx.delete(&index)
    }
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

/// The application of the write `item_hash` applied at `version` by a batch (Switch wire
/// 6.3): its chain position is its version. A view gives the application of a write taken
/// from a recovery upload instead.
fn applied_at(version: RecordVersion, item_hash: [u8; 32]) -> ApplicationRef {
    ApplicationRef {
        generation: version.generation,
        seq: version.version,
        item_hash,
    }
}

fn cert_key(app_id: &[u8; 16], cert_hash: &[u8; 32]) -> String {
    format!(
        "{CERT_PREFIX}{}/{}",
        pubky_switch_core::enc::zbase32_encode(app_id),
        b64(cert_hash)
    )
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
    /// Not trusted: the protocol's check refused the first write the app read of the
    /// record, so it holds that write for its version only, flagged
    /// ([`super::AppEvent::WriteFlagged`]): its next write builds on it (Switch spec 8.2).
    Refused,
}

/// [`RecordContent`] as the store holds it: a value not open for now is kept as
/// `Unreadable`, its data epoch read from the kept operation.
#[derive(Serialize, Deserialize)]
enum StoredContent {
    Value(#[serde(with = "serde_b64_vec")] Vec<u8>),
    Deleted,
    Unreadable,
    DoesNotOpen,
    Refused,
}

impl From<StoredContent> for RecordContent {
    fn from(stored: StoredContent) -> Self {
        match stored {
            StoredContent::Value(bytes) => Self::Value(bytes),
            StoredContent::Deleted => Self::Deleted,
            StoredContent::Unreadable => Self::Unreadable(Unopened::KeyNotHeld { data_epoch: 0 }),
            StoredContent::DoesNotOpen => Self::Unreadable(Unopened::DoesNotOpen),
            StoredContent::Refused => Self::Unreadable(Unopened::Refused),
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
            RecordContent::Unreadable(Unopened::Refused) => Self::Refused,
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

/// The retained write and the service application the app builds on for a record in a
/// recovery inventory (Switch wire 6.3, 7.4.14). They can differ after a refused write.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossRecordApplication {
    /// The opaque record key.
    #[serde(with = "serde_b64")]
    pub key: [u8; 32],
    /// The signed operation the app holds and its application.
    #[serde(with = "revision_serde")]
    pub held: ApplicationRef,
    /// The application the app last followed at this key.
    #[serde(with = "revision_serde")]
    pub followed: ApplicationRef,
    /// The version the app last followed.
    #[serde(with = "version_serde")]
    pub version: RecordVersion,
    /// Whether that write was a delete.
    pub deleted: bool,
    /// Whether a later read found that delete forgotten.
    pub gone: bool,
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
    /// The switch's current write is one the app didn't take on the service's word only, a
    /// missing date or the certificate the service chose: it names nobody and isn't
    /// flagged, the content is what the app trusts, and its next write builds on that
    /// write's version (Switch spec 8.2). A protocol that pauses a record over a write it
    /// can't trust sees the pause here; it lasts until a write the app takes replaces it.
    pub not_taken: bool,
    /// The next write builds on a different signed operation at [`Self::version`] than the
    /// one that supplied [`Self::content`]. Two uploads after a provider loss can share a
    /// record version (Switch spec 8.2, 12.6).
    pub different_write_at_held_version: bool,
    /// The latest view the app read shows uploads after a provider loss that conflict with
    /// the current write, kept at the switch until a writer writes a newer version there
    /// (Switch spec 12.6 step 3). The content is still the current write's, taken by the
    /// usual checks; what to do about the conflict is the protocol's.
    pub divergent: bool,
}

/// A signed operation the app keeps as evidence: a `record.put` or a claim entry, its
/// writer's certificate, and its transition proof when held. Its `Debug` shows no content.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// An application kept as (generation, `seq`, item hash).
mod revision_serde {
    use pubky_switch_core::enc::{b64, unb64_array};
    use pubky_switch_core::shared::ApplicationRef;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

    pub(crate) fn serialize<S: Serializer>(r: &ApplicationRef, s: S) -> Result<S::Ok, S::Error> {
        (r.generation, r.seq, b64(&r.item_hash)).serialize(s)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<ApplicationRef, D::Error> {
        let (generation, seq, hash) = <(u64, u64, String)>::deserialize(d)?;
        Ok(ApplicationRef {
            generation,
            seq,
            item_hash: unb64_array(&hash).map_err(D::Error::custom)?,
        })
    }
}

/// `rec/<key>`: the write the app took for a record. Sensitive: it holds the opened value.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(remote = "Self")]
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
    /// The held write's application at the service (Switch wire 6.3): at its version for a
    /// write a batch applied, the upload's position for one taken from a recovery upload.
    #[serde(with = "revision_serde")]
    applied: ApplicationRef,
    /// The current write the app builds on alongside the content it trusts.
    follow: Option<FollowedWrite>,
    /// The feed or answer position that selected this key's current application.
    observed: FeedPosition,
    /// A read found the switch holding nothing at the key while the write the next one
    /// builds on, held or followed, is a delete: the service forgot it (Switch spec 10.3),
    /// so the next write creates the record. A newer write taken or followed clears it.
    gone: bool,
    /// At a permanent policy, the newest generation the app saw the record live in (Switch
    /// spec 10.3.1 "Absence"); `None` for an ordinary policy, or one never seen live.
    live_in: Option<u64>,
}

impl std::fmt::Debug for HeldRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HeldRecord({}, {:?})", self.collection, self.content)
    }
}

/// A delete a record's next write builds on ([`HeldRecord::delete_base`]): its version, and
/// the item hash of its operation, which tells apart two deletes at one version after a
/// provider loss, as two uploads can share a version (Switch spec 12.6 step 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DeleteBase {
    #[serde(with = "version_serde")]
    pub(crate) version: RecordVersion,
    #[serde(with = "serde_b64")]
    pub(crate) item_hash: [u8; 32],
}

impl HeldRecord {
    /// The accepted view still selects the exact content and application the app
    /// trusts. A refused, followed or forgotten write retains its own disposition.
    fn matches_accepted_view(&self, accepted: &Accepted) -> bool {
        !self.gone
            && self.follow.is_none()
            && self.op == accepted.op
            && self.applied == accepted.write.applied
            && self.content == accepted.content
            && self.content != RecordContent::Unreadable(Unopened::Refused)
            && self.doubtful == accepted.doubtful
    }

    /// The write the next one builds on: the switch's current write, also when the app
    /// refused it or held an older one at its version: its version, its application and
    /// whether it is a delete.
    fn base_write(&self) -> (RecordVersion, ApplicationRef, bool) {
        match &self.follow {
            Some(f) => (f.version.version, f.applied, f.deleted),
            _ => (
                self.version,
                self.applied,
                self.content == RecordContent::Deleted,
            ),
        }
    }

    /// The delete the next write builds on, held or followed, also once the service forgot
    /// it; `None` when that write isn't a delete.
    pub(crate) fn delete_base(&self) -> Option<DeleteBase> {
        let (version, applied, deleted) = self.base_write();
        deleted.then_some(DeleteBase {
            version,
            item_hash: applied.item_hash,
        })
    }

    /// What the next write at `key` names (Switch spec 10.3, Switch wire 6.2, 6.3): the
    /// version of the write it builds on ([`HeldRecord::base_write`]), a delete included, or
    /// `{0, 0}` once a read found that delete forgotten (`gone`); and a `record_current`
    /// naming that write when it was taken from a recovery upload (its application isn't at
    /// its version), or applied in a generation a provider loss lost (`lost`, the own
    /// `identity.json`'s `recovery_from`) and not read at the new service since, as two
    /// uploads can share a version there (Switch spec 12.6 step 3).
    pub(crate) fn base(
        &self,
        key: &[u8; 32],
        lost: Option<u64>,
    ) -> (RecordVersion, Option<Condition>) {
        if self.gone {
            return (RecordVersion::NONE, None);
        }
        let (version, applied, deleted) = self.base_write();
        let uploaded = applied != applied_at(version, applied.item_hash);
        let named = (uploaded || lost.is_some_and(|lost| applied.generation <= lost)).then_some(
            Condition::RecordCurrent {
                key: *key,
                revision: applied,
                deleted,
            },
        );
        (version, named)
    }

    /// The condition a write depending on record `key` carries (Switch wire 6.3): the
    /// `record_current` of [`HeldRecord::base`] when it names one, else a `record_version`
    /// on its version.
    pub(crate) fn condition(&self, key: &[u8; 32], lost: Option<u64>) -> Condition {
        let (version, named) = self.base(key, lost);
        named.unwrap_or(Condition::RecordVersion { key: *key, version })
    }

    fn write_version(&self) -> WriteVersion {
        WriteVersion {
            version: self.version,
            authenticated: self.authenticated,
            expected_version: self.expected,
        }
    }

    pub(crate) fn shared(&self, key: &[u8; 32], divergent: bool) -> SharedRecord {
        let (base_version, base_application, _) = self.base_write();
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
            flagged: self.follow.as_ref().is_some_and(|f| f.named)
                || self.content == RecordContent::Unreadable(Unopened::Refused),
            not_taken: self.follow.as_ref().is_some_and(|f| !f.named),
            different_write_at_held_version: !self.gone
                && base_version == self.version
                && base_application.item_hash != self.item_hash,
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
    /// The write's application, from a record view's `revision` or the record held: the
    /// service's word.
    pub(crate) view_revision: Option<ApplicationRef>,
    /// What the answer showing the write is current at.
    pub(crate) current_at: CurrentAt,
    observation: ObservationSource,
}

/// What an answer showing a write is current at (Switch spec 10.3): what an older write
/// than the one held means comes from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CurrentAt {
    /// A feed item or an own application proof, as of the write's version.
    Itself,
    /// Previously held content reopened with a newly available key.
    Local,
    /// A record view of an answer current at this version: a read's head, a list page's
    /// `seq` in its head's generation (Switch wire 7.4.9).
    Answer(RecordVersion),
    /// The view predates a known recovery upload for the key or its collection.
    BeforeUpload(RecordVersion),
    /// A direct GET at the already known signed tip, with its checked view's divergence.
    KeyAtKnownTip(RecordVersion, bool),
}

impl CurrentAt {
    fn observation(self, divergent: bool) -> ObservationSource {
        let at = match self {
            Self::Answer(v) | Self::KeyAtKnownTip(v, _) => Some(position(v.generation, v.version)),
            _ => None,
        };
        ObservationSource::View { at, divergent }
    }

    /// What a record view read now with `head` is current at: `seq` in the head's
    /// generation, the head's own `seq` when `seq` is `None`; never another generation's.
    fn of(head: &SignedHead, seq: Option<u64>) -> Self {
        Self::Answer(RecordVersion::new(head.generation, seq.unwrap_or(head.seq)))
    }

    fn with_upload_coverage(self, covers_uploads: bool) -> Self {
        match self {
            Self::Answer(at) | Self::KeyAtKnownTip(at, _) if !covers_uploads => {
                Self::BeforeUpload(at)
            }
            at => at,
        }
    }

    /// Whether a record view read now shows the write: the switch's current write.
    fn viewed(self) -> bool {
        matches!(
            self,
            Self::Answer(_) | Self::BeforeUpload(_) | Self::KeyAtKnownTip(..)
        )
    }
}

/// How a write shown compares with the write held ([`compare_with_held`], Switch spec 10.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Order {
    /// Newer: it replaces the write held ([`WriteVersion::replaces`]), or nothing is held.
    Newer,
    /// The same write, by its item hash.
    Equal,
    /// Older, or not shown newer, by an answer current past the write held.
    Older(ShownWrite),
    /// Older, by an answer current at the version given, before the write held: overtaken.
    Overtaken(ShownWrite, RecordVersion),
}

/// The one comparison of a write shown with the write held, for every path that reads one
/// (Switch spec 10.1, 10.3): the same write by its item hash; newer by
/// [`WriteVersion::replaces`]; otherwise older. An older write is a rollback, `Err` with the
/// rule, when both versions are authenticated and the answer is current at or past the
/// held version, which also makes another write at the held version one. It was
/// overtaken when the answer is current before the held write: before its version, or,
/// for one held with the service's word only, at or before the version it was built on.
fn compare_with_held(
    shown: &WriteVersion,
    (item_hash, writer): ([u8; 32], [u8; 16]),
    held: &WriteVersion,
    held_hash: [u8; 32],
    at: CurrentAt,
) -> Result<Order, String> {
    if held_hash == item_hash {
        return Ok(Order::Equal);
    }
    if shown.replaces(held) {
        return Ok(Order::Newer);
    }
    let write = ShownWrite {
        version: shown.version,
        authenticated: shown.authenticated,
        item_hash,
        writer,
    };
    let current_at = match at {
        CurrentAt::Local => return Ok(Order::Overtaken(write, shown.version)),
        CurrentAt::Itself => shown.version,
        CurrentAt::Answer(version)
        | CurrentAt::BeforeUpload(version)
        | CurrentAt::KeyAtKnownTip(version, _) => version,
    };
    let before_held = if held.authenticated {
        current_at < held.version
    } else {
        current_at <= held.expected_version
    };
    if before_held {
        return Ok(Order::Overtaken(write, current_at));
    }
    if shown.authenticated && held.authenticated {
        return Err(
            "Switch spec 10.1, 10.3: an answer current at or past the record write held \
             shows an older one, or another at its version, both versions authenticated"
                .into(),
        );
    }
    Ok(Order::Older(write))
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

/// For a policy with separate roles the selected scope must already have been granted
/// at the authenticated time of the signed operation (Switch wire 6.2, step 5).
fn holds_write_role(cert: &AppCert, put: &RecordPut, time: Option<u64>) -> bool {
    (put.policy.create_scope.is_none() || time.is_some_and(|t| cert.issued_at() <= t))
        && put
            .policy
            .write_scopes_for(put.expected_version)
            .iter()
            .any(|scope| cert.holds_scope(scope))
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

struct WriteDate<'a> {
    time: Option<u64>,
    proven: Option<RecordVersion>,
    proof: Option<&'a SignedDoc>,
}

/// A write that passed the checks.
pub(super) struct Accepted {
    key: [u8; 32],
    collection: Collection,
    op: SignedDoc,
    cert: AppCert,
    write: FollowedWrite,
    placement: Placement,
    time: Option<u64>,
    writer: [u8; 16],
    /// The verified head or listing position at which a view showed this write.
    current_at: CurrentAt,
    observation: ObservationSource,
    /// The observation reaches every upload due for this key and collection.
    covers_uploads: bool,
    content: RecordContent,
    doubtful: bool,
}

impl Accepted {
    pub(super) fn revision(&self) -> ApplicationRef {
        self.write.applied
    }

    fn current_for_publication(&self) -> bool {
        self.write.version.authenticated
            && self.placement.at.is_some()
            && self.placement.historical.is_none()
            && matches!(self.placement.base, Order::Newer | Order::Equal)
            && matches!(self.placement.content, Order::Newer | Order::Equal)
    }

    pub(super) fn confirm_deletion(&self, observed: &mut super::deletion::Observation) -> bool {
        if !self.write.version.authenticated || self.doubtful {
            return false;
        }
        let changed =
            !observed.authenticated || (observed.proof.is_none() && self.write.proof.is_some());
        observed.authenticated = true;
        if observed.proof.is_none() {
            observed.proof.clone_from(&self.write.proof);
        }
        changed
    }

    pub(super) fn value(&self) -> Option<&[u8]> {
        self.content.value()
    }

    pub(super) fn check_publication(
        &self,
        app: &App,
        deletion: &super::deletion::Observation,
        repair: Option<&super::RecordRepair>,
        tx: &Tx,
    ) -> Result<Option<super::PutBackSuccessor>, AppError> {
        let Some(value) = self.content.value() else {
            return Ok(None);
        };
        let version = self.write.version.version;
        if !self.covers_uploads
            || self.doubtful
            || !self.write.version.authenticated
            || self.write.applied.generation != deletion.generation
            || version != RecordVersion::new(self.write.applied.generation, self.write.applied.seq)
        {
            return Ok(None);
        }
        let op = SignedOp::peek(&self.op).map_err(|_| super::corrupt())?;
        let OpKind::RecordPut(put) = &op.body().kind else {
            return Err(super::corrupt());
        };
        if put.policy != deletion.put()?.policy || op.body().generation != deletion.generation {
            return Ok(None);
        }
        let successor = super::RecordSuccessor {
            repair: repair.filter(|r| r.deletion == deletion.revision()),
            value,
            version,
            revision: self.write.applied,
            writer: self.writer,
            expected_version: put.expected_version,
            conditions: &op.body().conditions,
            policy: &put.policy,
        };
        let signed = SignedOp::peek(&deletion.operation).map_err(|_| super::corrupt())?;
        app.with_deletion(deletion, &signed, tx, |owner, original, cx| {
            owner
                .record_put_back_successor(original, &successor, cx)
                .map(Some)
        })
    }
}

/// Why a write wasn't taken.
enum Refused {
    /// Signed evidence of misbehaviour: a rollback.
    Misbehaviour(String),
    /// The signed item identifies the writer responsible for this failed check. A value
    /// that fails to open with its key held also identifies an own writer.
    Named {
        writer: [u8; 16],
        item: [u8; 32],
        reason: String,
        does_not_open: bool,
        checked: Option<Box<(FollowedWrite, Placement)>>,
    },
    /// Not a write the app takes: another collection, or a writer it can't find.
    Ignored,
    /// A write at the key read, its version plausible, that the app doesn't take on the
    /// service's word only: a missing date, or the certificate the service chose. It names
    /// nobody, but its version is followed, so the app's next write builds on it and puts
    /// back what it trusts, as over a flagged write (Switch spec 8.2). `version` is the one
    /// step 6 checked: a proof's when one gives it, else the view's.
    Unnamed(Box<(FollowedWrite, Placement)>),
    /// A write without a record view, that no certificate the app holds authorizes, while
    /// the newest own `identity.json` names a certificate of the writer in force at its
    /// time that the app doesn't hold: the record's view decides (Switch wire 6.2
    /// "Accepting a write" step 1). It names the member of the collection.
    Unheld(Collection),
}

impl Refused {
    fn named(
        writer: [u8; 16],
        item: [u8; 32],
        reason: &str,
        does_not_open: bool,
        checked: Option<(FollowedWrite, Placement)>,
    ) -> Self {
        Self::Named {
            writer,
            item,
            reason: reason.to_owned(),
            does_not_open,
            checked: checked.map(|(mut write, placement)| {
                write.named = true;
                Box::new((write, placement))
            }),
        }
    }
}

/// What [`App::update_record_on`] came to.
pub(crate) enum Updated {
    /// The record written, or `None` when `change` changed nothing.
    Written(Option<SharedRecord>),
    /// Stopped at `deleted`, a delete other than the call's base, before anything was
    /// written over it; `last` is the conflict a try met before, if one did.
    Stopped {
        deleted: DeleteBase,
        last: Option<AppError>,
    },
}

/// What reading a write came to ([`App::read_write`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteRead {
    /// Taken: newer than the write held.
    Taken,
    /// The very write the app held.
    Equal,
    /// Older than the write held, or not shown newer ([`KeptReason::Older`]).
    Older(ShownWrite),
    /// Older than the write held, by an answer current before it: overtaken
    /// ([`KeptReason::Overtaken`]).
    Overtaken(ShownWrite, RecordVersion),
    /// The observation cannot be placed in this key's history.
    Unordered,
    /// Refused: a failed check, a regression the protocol found, or a write the app doesn't
    /// take.
    Refused,
    /// Not judged: the protocol of its collection isn't told through everything before
    /// the write yet ([`App::may_tell`]); nothing was written for it.
    Waits,
}

impl WriteRead {
    /// Whether the answer that showed the write says anything of the record now: one
    /// overtaken by the write held or waiting for its owner cannot establish the current
    /// view (Switch spec 10.3).
    fn says_of_now(self) -> bool {
        !matches!(self, Self::Overtaken(..) | Self::Unordered | Self::Waits)
    }
}

/// What the source of a readable write establishes at this application.
#[derive(Clone, Copy)]
enum ObservationSource {
    View {
        at: Option<FeedPosition>,
        divergent: bool,
    },
    Applied,
    Reopened,
}

impl ObservationSource {
    fn divergent(self, current: bool, previous: bool, newer: bool) -> bool {
        match self {
            Self::View { divergent, .. } if current => divergent,
            Self::Applied if newer && current => false,
            _ => previous,
        }
    }
}

/// The view read to obtain a missing writer certificate (Switch wire 6.2).
enum WriterView {
    NotRead,
    Historical,
    Current { divergent: bool },
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
    /// The current service holds no record at the key, or forgot it. Its signed hosted
    /// `404` covers the app's observations at the key, within its current read scope.
    NotFound,
    /// The switch's write was refused: a failed check, or one that goes back on what the
    /// app has seen ([`super::AppEvent::WriteFlagged`]).
    Refused,
    /// The switch shows another write than the one the app holds that isn't newer by the
    /// rule of Switch spec 10.3, by an answer current past the write held: older, or built
    /// on an earlier version than the one held. Both versions authenticated would be a
    /// rollback instead (an alarm, Switch spec 10.1), so `write.authenticated` `false`, or a
    /// held version that is the service's word only ([`SharedRecord::authenticated`]), says
    /// this is the service's claim of the record now, as for a record taken from a recovery
    /// upload. The event [`super::AppEvent::RecordShownOlder`] tells it too.
    Older(ShownWrite),
    /// The switch shows an older write than the one the app holds, by an answer current at
    /// `current_at`, before the write held: overtaken by it, it says nothing of the record
    /// now (Switch spec 10.3).
    #[non_exhaustive]
    Overtaken {
        /// The write shown.
        write: ShownWrite,
        /// What the answer is current at: a read's head, a list page's `seq`.
        current_at: RecordVersion,
    },
    /// The switch refused the read with an answer the same request won't change, such as
    /// `403 permission_missing` or `400` (the Retry column of Switch spec 6.4 saying "No"):
    /// reading again won't help as things stand.
    SwitchRefused {
        /// The error code.
        code: ErrorCode,
    },
    /// The switch couldn't be read for now: the network, a `5xx` or a `429`, an answer
    /// that didn't verify, or the signed `404` saying it doesn't host the identity, which
    /// says nothing of the record (Switch spec 10.3.1 "Absence", 12.7 step 5); the error,
    /// without content.
    Unreachable(String),
}

/// A write the switch showed that the app didn't take for being older than the one it
/// holds ([`KeptReason::Older`], [`KeptReason::Overtaken`]). It passed the checks of Switch
/// spec 10.3, so its writer signed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ShownWrite {
    /// Its version: from a transition proof or a verified stub when `authenticated`, else the
    /// record view's.
    pub version: RecordVersion,
    /// Whether a transition proof naming the write, or its verified chain stub, gives
    /// `version` (Switch spec 10.3).
    pub authenticated: bool,
    /// Its item hash, which its writer signed.
    pub item_hash: [u8; 32],
    /// The app that signed it.
    pub writer: [u8; 16],
}

/// What [`App::take_write`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Taken {
    /// The collection owner still has to take an earlier deletion.
    Waits,
    /// A newer write, now held.
    New,
    /// The write held.
    Equal,
    /// The write held, unopened before, now opened: no newer write. No path from the feed
    /// reaches it today: a key that arrives reopens the record through `reopen_unreadable`
    /// before the feed meets the write again. It stays so that `New` keeps meaning newer.
    Reopened,
    /// Older than the write held ([`Order::Older`]).
    Older(ShownWrite),
    /// Older, by an answer current before the write held ([`Order::Overtaken`]).
    Historical(Historical),
    /// Newer, and refused by the protocol's regression check.
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
        target.key_with(&self.state.naming)
    }

    pub(crate) async fn held_record(&self, key: &[u8; 32]) -> Result<Option<HeldRecord>, AppError> {
        self.reader().get(&record_key_of(key)).await
    }

    /// What `tx` leaves at `key` once it commits: its own write there, else the store's
    /// value. Every judging of a write reads through the transaction it writes in, so two
    /// writes of one record in one commit, such as two views of one key on a list page, are
    /// each judged against what the other left.
    pub(super) async fn read_in<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
        tx: &Tx,
    ) -> Result<Option<T>, AppError> {
        match tx.pending_get::<T>(key)? {
            Some(pending) => Ok(pending),
            None => self.reader().get(key).await,
        }
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
        self.shared_evidence_with_details(None).await
    }

    pub(super) async fn shared_evidence_with_details(
        &self,
        mut details: Option<&mut super::LossInventoryDetails>,
    ) -> Result<SharedEvidence, AppError> {
        let mut ops = Vec::new();
        for (key, held) in self.reader().scan::<HeldRecord>(RECORD_PREFIX).await? {
            if let Some(details) = details.as_deref_mut() {
                let (version, followed, deleted) = held.base_write();
                details.records.push(LossRecordApplication {
                    key: unb64_array(&key)
                        .map_err(|_| AppError::Store(crate::error::StoreError::Corrupt))?,
                    held: held.applied,
                    followed,
                    version,
                    deleted,
                    gone: held.gone,
                });
            }
            ops.push(KeptOp {
                op: held.op,
                cert: held.cert,
                proof: held.proof,
            });
        }
        let (claim_ops, proofs, claim_entries_left_out) =
            self.claim_evidence_items(details).await?;
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

    /// Apply the collection owner's changes at the same verified boundary as its
    /// native mark, including a later covering view of the delete (Switch spec 8.2).
    fn end_record_lifetime(
        &self,
        key: [u8; 32],
        collection: &Collection,
        version: RecordVersion,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let owner = self
            .protocols
            .of_collection(&collection.name)
            .ok_or_else(store_corrupt)?;
        let record = super::RecordMarkContext {
            key,
            collection,
            naming: &self.state.naming,
        };
        let context = super::ReceiveContext::new(
            &self.state,
            &self.protocols,
            &owner.name,
            self.env.store.store().as_ref(),
            &self.ns,
            false,
            &[],
            tx.pending_local(),
            tx.pending_writes(),
        );
        let local = owner
            .protocol
            .record_lifetime_ended(&record, version, &context)
            .map_err(AppError::Protocol)?;
        let bytes = super::local_writes_bytes(&local);
        if bytes > super::MAX_STEP_LOCAL_BYTES {
            return Err(crate::error::StoreError::TooLarge {
                size: u64::try_from(bytes).unwrap_or(u64::MAX),
                cap: super::MAX_STEP_LOCAL_BYTES as u64,
            }
            .into());
        }
        tx.local(&super::protocols::qualify(&owner.name, local))?;
        tx.delete(&seen_key(&key))
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

    /// Read the record at `key` from the switch and take its write; what came of it.
    pub(crate) async fn fetch_record(
        &mut self,
        key: &[u8; 32],
        collection: &Collection,
    ) -> Result<Fetched, AppError> {
        Ok(Box::pin(self.fetch_record_application(key, collection))
            .await?
            .0)
    }

    async fn fetch_record_application(
        &mut self,
        key: &[u8; 32],
        collection: &Collection,
    ) -> Result<(Fetched, Option<ApplicationRef>), AppError> {
        let uploads = self.record_uploads(key, collection).await?;
        let record = match Box::pin(self.record_answer(key, uploads)).await? {
            RecordAnswer::View(record) => record,
            RecordAnswer::Absent if self.state.cert.holds_scope(&collection.policy.read_scope) => {
                return Ok((Fetched::Absent, None));
            }
            RecordAnswer::Absent | RecordAnswer::Inconclusive => {
                return Ok((Fetched::Read(WriteRead::Unordered), None));
            }
            // It doesn't host the identity: that says nothing of the record, and the
            // service reads as unreachable (Switch spec 10.3.1 "Absence", 12.7 step 5).
            RecordAnswer::NotHosted(error) => return Ok((Fetched::NotHosted(error), None)),
        };
        let mut tx = self.tx()?;
        let expect = Some((key, collection));
        let at = match record.at {
            CurrentAt::Answer(v)
                if record.at_known_tip && record.covers_uploads && record.view.key == *key =>
            {
                CurrentAt::KeyAtKnownTip(v, record.view.divergent)
            }
            at => at,
        };
        let read = self
            .take_view(&record.view, at, expect, record.covers_uploads, &mut tx)
            .await?;
        self.commit(tx).await?;
        // A view can still supply historical write evidence after a provider change.
        // Only the service generation the app follows can report this key as fresh now.
        let current =
            matches!(record.at, CurrentAt::Answer(v) if v.generation == self.state.meta.generation);
        Ok(if current && record.covers_uploads {
            (Fetched::Read(read), Some(record.view.revision))
        } else {
            (Fetched::Read(WriteRead::Unordered), None)
        })
    }

    /// [`App::read_record`], telling a copy read now from an earlier one the app keeps
    /// (Switch wire 7.4.9): [`RecordRead::Fresh`] when the switch's current write is what the
    /// app holds after the read, taken now or the very write it held; otherwise
    /// [`RecordRead::Kept`], with the copy the app keeps, if any, and why nothing read now
    /// replaced it: a `404`, a write refused, an older write than the one held, shown by an
    /// answer current past it or overtaken by it, a read the switch refused for good, or a
    /// switch it couldn't read for now. A kept copy isn't evidence of the switch's state now.
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
                Ok(Fetched::Read(WriteRead::Taken | WriteRead::Equal)) => {
                    if let Some(record) = self.shared_record(&key).await? {
                        return Ok(RecordRead::Fresh(record));
                    }
                    KeptReason::Refused
                }
                Ok(Fetched::Read(WriteRead::Older(write))) => KeptReason::Older(write),
                Ok(Fetched::Read(WriteRead::Overtaken(write, current_at))) => {
                    KeptReason::Overtaken { write, current_at }
                }
                Ok(Fetched::Read(WriteRead::Refused | WriteRead::Waits | WriteRead::Unordered)) => {
                    KeptReason::Refused
                }
                Ok(Fetched::Absent) => KeptReason::NotFound,
                // A switch that doesn't host the identity says nothing of the record: it
                // reads as unreachable (Switch spec 10.3.1 "Absence", 12.7 step 5).
                Ok(Fetched::NotHosted(error)) => {
                    KeptReason::Unreachable(AppError::Switch(*error).to_string())
                }
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

    /// Read the service's current record and return its accepted contents, exact application
    /// and signed input together (Switch wire 6.2, 6.3, 7.4.9). A missing or noncurrent
    /// read returns no evidence. A divergent or doubtful record keeps its ordinary flags.
    ///
    /// # Errors
    ///
    /// As [`Self::read_record_fresh`].
    pub async fn read_record_application(
        &mut self,
        target: &RecordTarget,
    ) -> Result<Option<(SharedRecord, ApplicationRef, KeptOp)>, AppError> {
        self.ready_local().await?;
        self.refuse_when_stopped()?;
        let key = self.record_key(target)?;
        let (Fetched::Read(WriteRead::Taken | WriteRead::Equal), Some(application)) =
            Box::pin(self.fetch_record_application(&key, &target.collection)).await?
        else {
            return Ok(None);
        };
        let Some(held) = self.held_record(&key).await? else {
            return Ok(None);
        };
        if held.gone || held.follow.is_some() || held.applied != application {
            return Ok(None);
        }
        let record = held.shared(&key, self.is_divergent(&key).await?);
        Ok(Some((
            record,
            application,
            KeptOp {
                op: held.op,
                cert: held.cert,
                proof: held.proof,
            },
        )))
    }

    /// The switch's view of record `key` (`GET /records/{key}`, Switch wire 7.4.9), with what
    /// it is current at: the answer's head, of the generation it names; `None`
    /// for a key it doesn't know, or forgot, at an account it hosts, which is absence
    /// (Switch spec 10.3.1 "Absence", [`App::note_absent`]).
    ///
    /// # Errors
    ///
    /// The signed `404` saying the switch doesn't host the identity, as the failed call it
    /// is: the service reads as unreachable, and the record isn't absent (Switch spec
    /// 10.3.1 "Absence", 12.7 step 5). The rollback alarm for a permanent record the app
    /// holds live that reads absent; a failed call.
    pub(super) async fn record_view(
        &mut self,
        key: &[u8; 32],
        collection: &Collection,
    ) -> Result<Option<Box<ObservedView>>, AppError> {
        let uploads = self.record_uploads(key, collection).await?;
        match Box::pin(self.record_answer(key, uploads)).await? {
            RecordAnswer::View(record) => Ok(Some(record)),
            RecordAnswer::Absent | RecordAnswer::Inconclusive => Ok(None),
            RecordAnswer::NotHosted(error) => Err(AppError::Switch(*error)),
        }
    }

    fn upload_for_collection(
        &self,
        collection: &str,
        due: Option<ListDue>,
    ) -> Option<FeedPosition> {
        let due = due?;
        let owner = self.protocols.of_collection(collection)?;
        due.upload.filter(|_| due.at(&owner.name).is_some())
    }

    async fn listing_upload(&self, collection: &str) -> Result<Option<FeedPosition>, AppError> {
        Ok(self.upload_for_collection(collection, self.reader().get::<ListDue>(LIST_DUE).await?))
    }

    async fn record_uploads(
        &self,
        key: &[u8; 32],
        collection: &Collection,
    ) -> Result<[Option<FeedPosition>; 2], AppError> {
        Ok([
            self.record_upload(key).await?,
            self.listing_upload(&collection.name).await?,
        ])
    }

    fn covers_upload(&self, at: FeedPosition, upload: FeedPosition) -> bool {
        at.generation == self.state.meta.generation && self.covers(at, upload)
    }

    fn covers_uploads(&self, at: FeedPosition, uploads: [Option<FeedPosition>; 2]) -> bool {
        uploads
            .into_iter()
            .flatten()
            .all(|upload| self.covers_upload(at, upload))
    }

    /// A covering key GET can have an earlier chain head than a collection snapshot
    /// that already showed the same application and divergence (Switch wire 7.4.9).
    pub(super) async fn upload_view_already_held(
        &self,
        view: &SharedRecordView,
        upload: FeedPosition,
        tx: &Tx,
    ) -> Result<bool, AppError> {
        let Some(held) = self
            .read_in::<HeldRecord>(&record_key_of(&view.key), tx)
            .await?
        else {
            return Ok(false);
        };
        Ok(self.covers_upload(held.observed, upload)
            && held.op == view.op
            && held.applied == view.revision
            && held.base_write().1 == view.revision
            && self.is_divergent(&view.key).await? == view.divergent)
    }

    /// Read a held delete's current signed operation without delivering it ahead of the
    /// feed. Only a verified later application can overtake the held replacement.
    pub(super) async fn current_put_back_write(
        &mut self,
        deletion: &super::deletion::Observation,
    ) -> Result<Option<Accepted>, AppError> {
        let collection = Collection::new(&deletion.collection, deletion.put()?.policy);
        let Some(observed) = self.record_view(&deletion.key, &collection).await? else {
            return Ok(None);
        };
        if !observed.covers_uploads {
            return Ok(None);
        }
        let ObservedView { view, at, .. } = *observed;
        let evidence = Evidence {
            op: &view.op,
            cert: Some(&view.cert),
            proof: view.proof.as_ref(),
            stub: None,
            view_version: Some(RecordVersion::new(view.generation, view.version)),
            view_revision: Some(view.revision),
            current_at: at,
            observation: at.observation(view.divergent),
        };
        let tx = self.tx()?;
        match self
            .accept_write(&evidence, Some((&deletion.key, &collection)), &tx)
            .await?
        {
            Ok(accepted) if accepted.current_for_publication() => {
                let at = self.feed_order(
                    accepted.write.applied.generation,
                    accepted.write.applied.seq,
                );
                let original = self.feed_order(deletion.generation, deletion.seq);
                if at > original && accepted.write.applied.item_hash != deletion.delete.item_hash
                    || at == original
                        && accepted.write.applied.item_hash == deletion.delete.item_hash
                        && accepted.write.version.version == deletion.delete.version
                {
                    return Ok(Some(accepted));
                }
            }
            Err(Refused::Misbehaviour(reason)) => {
                return Err(self.raise(Alarm::Rollback { reason }).await);
            }
            _ => {}
        }
        Err(Refusal::NotNow(
            "the current record does not establish this delete or its successor".into(),
        )
        .into())
    }

    /// The switch's answer to `GET /records/{key}` (Switch wire 7.4.9), telling a key it
    /// doesn't hold from an identity it doesn't host.
    pub(super) async fn record_answer(
        &mut self,
        key: &[u8; 32],
        uploads: [Option<FeedPosition>; 2],
    ) -> Result<RecordAnswer, AppError> {
        let (result, head) = match self.client.record_with_head(key).await {
            Ok(answer) => (Ok(answer), None),
            Err(failure) => (Err(failure.error), failure.head),
        };
        let (view, head) = match self.take(result).await {
            Ok(answer) => (Some(answer.view), answer.head),
            Err(AppError::Switch(error)) if error.is_not_hosted() => {
                return Ok(RecordAnswer::NotHosted(Box::new(error)));
            }
            Err(error) if error.code() == Some(ErrorCode::NotFound) => {
                let head = head.ok_or_else(|| {
                    ClientError::InvalidResponse(
                        "Switch wire 7.1: a hosted record absence carries a head".into(),
                    )
                })?;
                (None, *head)
            }
            Err(error) => return Err(error),
        };
        let at = self.current_at(head, None).await?;
        let at_known_tip = self.keep_record_tip(head).await?;
        // An upload has no record.put of its own. Only an observation covering that
        // transition can judge what the upload changed, even at a previously unknown key.
        let covers_uploads = self.covers_uploads(position(head.generation, head.seq), uploads);
        if let Some(view) = view {
            return Ok(RecordAnswer::View(Box::new(ObservedView {
                view,
                at,
                covers_uploads,
                at_known_tip,
            })));
        }
        if !covers_uploads {
            return Ok(RecordAnswer::Inconclusive);
        }
        let mut tx = self.tx()?;
        let current = self.note_absent(key, at, MissingFrom::Key, &mut tx).await?;
        if current
            && at_known_tip
            && let Some(collection) = self.held_collection(key).await?
        {
            self.observe_member(
                &collection.id(&self.identity()),
                key,
                position(head.generation, head.seq),
                inventory::Member::Absent,
                &mut tx,
            )
            .await?;
        }
        if !tx.is_empty() {
            self.commit(tx).await?;
        }
        Ok(if current {
            RecordAnswer::Absent
        } else {
            RecordAnswer::Inconclusive
        })
    }

    /// Keep the newest observed head before a key read takes effect. A listing can
    /// learn it in memory before a local read interrupts its first commit. Only a tip
    /// already saved by an earlier observation can confirm an inbox-only advance.
    async fn keep_record_tip(&mut self, head: SignedHead) -> Result<bool, AppError> {
        let Some(chain) = &self.state.chain else {
            return Ok(false);
        };
        let Some(tip) = chain.newest else {
            return Ok(false);
        };
        if head.generation != self.state.meta.generation || tip.generation != head.generation {
            return Ok(false);
        }
        let saved = self.reader().get::<ChainRecord>(key::CHAIN).await?;
        if let Some(saved) = saved {
            if saved.last_seq > tip.seq {
                return Ok(false);
            }
            if let Some(value) = saved.newest {
                let prior = SignedHead::from_value(&value)
                    .map_err(|_| AppError::Store(crate::error::StoreError::Corrupt))?;
                if prior == tip {
                    return Ok(head == tip && chain.verified_seq() <= head.seq);
                }
                if prior.generation > tip.generation
                    || (prior.generation == tip.generation && prior.seq >= tip.seq)
                {
                    return Ok(false);
                }
            }
        }
        let mut tx = self.tx()?;
        if let Some(chain) = self.state.chain.as_mut() {
            chain.write(&mut tx)?;
            self.commit(tx).await?;
        }
        Ok(false)
    }

    /// Compare a refused batch's record evidence at the head of that reply (Switch wire
    /// 6.3, 7.6). A later read has its own head, even if it returns the same write.
    pub(super) async fn note_record_conflict(
        &mut self,
        batch: &Batch,
        current: &serde_json::Value,
        head: Option<&SignedHead>,
    ) -> Result<(), AppError> {
        let Some(head) = head else {
            if RecordConflict::read(current, batch)?.is_some() {
                return Err(ClientError::InvalidResponse(
                    "Switch wire 7.1: a record conflict for an own app carries no Switch-Head"
                        .into(),
                )
                .into());
            }
            return Ok(());
        };
        let at = self.current_at(*head, None).await?;
        let mut tx = self.tx()?;
        match RecordConflict::read(current, batch)? {
            Some(RecordConflict::View(view)) => {
                if let Ok(op) = SignedOp::peek(&view.op)
                    && let OpKind::RecordPut(put) = &op.body().kind
                    && put.key == view.key
                    && let Some(collection) = self.collection_for_write(put, &tx).await?
                {
                    let uploads = self.record_uploads(&view.key, &collection).await?;
                    let covers = self.covers_uploads(position(head.generation, head.seq), uploads);
                    self.take_view(&view, at, Some((&view.key, &collection)), covers, &mut tx)
                        .await?;
                }
            }
            Some(RecordConflict::Absent(key)) => {
                self.note_absent(&key, at, MissingFrom::Key, &mut tx)
                    .await?;
            }
            // The service's position identifies neither the operation nor its writer. A
            // caller that needs the value reads it through the ordinary record endpoint.
            Some(RecordConflict::Position) | None => {}
        }
        if let Some(chain) = self.state.chain.as_mut() {
            chain.write(&mut tx)?;
        }
        if !tx.is_empty() {
            self.commit(tx).await?;
        }
        Ok(())
    }

    /// What a record view read now with `head` is current at ([`CurrentAt::of`]), the head
    /// first checked against the verified chain, as every head of an own answer is (Switch
    /// spec 10.1): one that contradicts it is the switch's rollback, raised here. A head of
    /// another generation than the one the app follows isn't compared with its chain.
    async fn current_at(
        &mut self,
        head: SignedHead,
        seq: Option<u64>,
    ) -> Result<CurrentAt, AppError> {
        if head.generation == self.state.meta.generation
            && let Err(alarm) = self.note_answer_head(head, &[])
        {
            return Err(self.raise(alarm).await);
        }
        Ok(CurrentAt::of(&head, seq))
    }

    /// List `collection`'s current records at the switch, page by page (Switch wire
    /// 7.4.9), and take each write that passes the checks and is newer. Only policies
    /// admitted by this supplied collection are taken; [`App::list_collections`] lists
    /// the union of all registered readable policy members of each collection.
    ///
    /// The call is bounded: it asks for at most [`LISTING_PAGES_PER_READ`] pages and, once
    /// it asked for one, none past the call's time budget
    /// ([`super::AppConfig::call_budget_ms`]). One that stops before the collection's end
    /// says [`CollectionListed::more`], and each page's commit records how far it got
    /// (`listc/`), so the next call goes on from there, after a restart too. The call that
    /// reaches the end forgets that, and the next one starts at the beginning. Records
    /// written between two calls come on the feed. Each distinct account head can require
    /// an own-directory read to establish the reader's scope. When its certificate
    /// changes, a bounded feed read can obtain the renewal before the listing resumes.
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
            let mut progress: ListProgress = ListProgress::for_reader(
                self.reader().get(&key).await?,
                self.state.cert.hash(),
                self.state.meta.generation,
            );
            let after = progress.after(&listing_scope(&id, collection, None)?)?;
            let mut pages = LISTING_PAGES_PER_READ;
            let listed = self
                .list_from(
                    collection,
                    None,
                    after,
                    &mut pages,
                    (&mut progress, &key),
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
        members: Option<&[Collection]>,
        mut after: Option<[u8; 32]>,
        pages: &mut u32,
        (progress, progress_key): (&mut ListProgress, &str),
        budget: Option<&super::CallBudget>,
    ) -> Result<Listed, AppError> {
        let id = collection.id(&self.state.meta.identity);
        let upload = self.listing_upload(&collection.name).await?;
        let scope = listing_scope(&id, collection, members)?;
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
            // A page is current at its `seq`, in the generation of the head it came with,
            // never another's (Switch spec 10.3).
            let at = self.current_at(page.head, Some(page.seq)).await?;
            // Inbox entries can advance the snapshot past the last chain item. Both
            // positions in this generation must have reached the applicable upload.
            let upload_at = position(page.head.generation, page.seq.min(page.head.seq));
            if upload.is_some_and(|upload| !self.covers_upload(upload_at, upload)) {
                return Ok(Listed::Paused(listed));
            }
            let mut tx = self.tx()?;
            // A page's last inbox position can exceed its signed chain tip. Keep
            // that tip before any selected record can survive a split page or reload.
            if page.head.generation == self.state.meta.generation
                && let Some(chain) = self.state.chain.as_mut()
            {
                chain.write(&mut tx)?;
            }
            let mut listed_members = Vec::new();
            for view in &page.records {
                // A page holds up to 1,000 views, each cached with its mark: the views taken
                // so far are committed first once one more might not fit.
                if tx.size().saturating_add(LISTED_RECORD_ROOM_BYTES)
                    > crate::store::MAX_BATCH_BYTES
                {
                    let full = std::mem::replace(&mut tx, self.tx()?);
                    self.commit(full).await?;
                }
                // An automatic listing has one cursor per collection ID, and judges
                // each record against any registered readable member of that collection.
                // An explicit listing keeps the caller's supplied policy (Switch spec 3.3).
                let member = members
                    .and_then(|members| {
                        let op = SignedOp::peek(&view.op).ok()?;
                        let OpKind::RecordPut(put) = &op.body().kind else {
                            return None;
                        };
                        members.iter().find(|member| {
                            member.name == collection.name && member.admits(&put.policy)
                        })
                    })
                    .unwrap_or(collection);
                let mark = self.record_upload(&view.key).await?;
                let covers = mark.is_none_or(|upload| self.covers_upload(upload_at, upload));
                if members.is_some() {
                    let read = self
                        .judge_view(view, at, Some((&view.key, member)), covers, &mut tx)
                        .await?;
                    listed_members.push(inventory::ListedMember::new(view, &id, read, covers));
                } else {
                    self.take_view(view, at, Some((&view.key, member)), covers, &mut tx)
                        .await?;
                }
                listed = listed.saturating_add(1);
            }
            // Records are listed by the base64url text of their keys, compared as ASCII
            // (Switch wire 7.4.9): a `next` that doesn't move past the key asked after ends
            // the listing, so a service that names keys back and forth can't keep the app
            // reading.
            let next = page
                .next
                .filter(|next| after.is_none_or(|after| b64(next) > b64(&after)));
            // A page contains only the keys the service's current reader may see.
            // The app can still hold a wider certificate while the renewal is in its feed.
            if let Some(directory) = self
                .unconfirmed_page_reader(Some(page.head), progress, None)
                .await?
            {
                if !tx.is_empty() {
                    self.commit(tx).await?;
                }
                Box::pin(self.follow_page_reader(directory)).await?;
                return Ok(Listed::Paused(listed));
            }
            let shown: Vec<[u8; 32]> = page.records.iter().map(|view| view.key).collect();
            Box::pin(self.note_unlisted(
                &collection.name,
                (after.as_ref(), next.as_ref()),
                &shown,
                at,
                upload_at,
                &mut tx,
            ))
            .await?;
            // Keep the continuation and the covered inventory with the page's records.
            // Only a page too large for one batch leaves earlier records to be read again.
            let mut checkpoint = Tx::new(&self.ns);
            if members.is_some() {
                self.keep_inventory_page(
                    collection,
                    after,
                    &page,
                    listed_members,
                    &mut checkpoint,
                )?;
            }
            progress.reached(&scope, next.as_ref());
            checkpoint.put(progress_key, progress)?;
            self.append_listing_writes(&mut tx, checkpoint).await?;
            if !tx.is_empty() {
                self.commit(tx).await?;
            }
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
    /// (Switch spec 8.3, 12.1 step 3). Returns whether more is left. Call again when
    /// the time budget or [`LISTING_PAGES_PER_READ`] was reached, or the service's reader
    /// certificate still needs to be established. When the local certificate reads
    /// none of the registered collections, the own directory checks that grant before
    /// the listing can finish.
    ///
    /// The listing goes on from where the last one that stopped got, as an owed listing
    /// does (`list_at`), skipping the collections it listed to their end. The call that
    /// lists the last one to its end settles an owed listing ([`App::listing_owed`]), and
    /// the next call starts at the beginning. Records written between two calls come on the
    /// feed. The same directory and renewal checks apply as for [`App::list_collection`].
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
        let Some(due) = self.reader().get::<ListDue>(LIST_DUE).await? else {
            return Ok(Listing::NotDue);
        };
        // Every writer names registered protocols: a listing owed to another could never
        // be made, and would stay owed for ever.
        if due
            .to
            .iter()
            .any(|(name, _)| !self.protocols.contains(name))
        {
            return Err(AppError::Store(crate::error::StoreError::Corrupt));
        }
        self.listing_waits = false;
        self.listed_every = false;
        // The protocols whose listing is made now, in registration order: one owed outside
        // the feed, or one told through everything before the item that owes it.
        let ready: Vec<(String, Option<(u64, u64)>)> = self
            .protocols
            .names()
            .into_iter()
            .filter_map(|name| due.at(&name).map(|at| (name, at)))
            .filter(|(name, at)| match at {
                None => true,
                Some((generation, seq)) => {
                    self.ready_at(name, self.feed_order(*generation, *seq), Handover::Listing)
                }
            })
            .collect();
        if ready.is_empty() {
            return Ok(Listing::NotDue);
        }
        // A listing waits for a scope key, protocol by protocol.
        let mut waiting: Vec<(String, Option<(u64, u64)>)> = Vec::new();
        let mut listing: Vec<String> = Vec::new();
        for (name, at) in ready {
            if self.listing_lacks_keys(&self.readable_collections(&name)) {
                waiting.push((name, at));
            } else {
                listing.push(name);
            }
        }
        // Nothing can be listed, and no protocol goes on meanwhile: the read waits for the
        // key, as with one protocol.
        let all_wait = self
            .protocols
            .iter()
            .all(|registered| waiting.iter().any(|(name, _)| *name == registered.name));
        if all_wait {
            return Ok(Listing::WaitsForKey);
        }
        let mut progress: ListProgress = ListProgress::for_reader(
            self.reader().get(LIST_AT).await?,
            self.state.cert.hash(),
            self.state.meta.generation,
        );
        let before = *pages;
        for name in &listing {
            let collections = self.readable_collections(name);
            for collection in &collections {
                let id = collection.id(&self.state.meta.identity);
                let scope = listing_scope(&id, collection, Some(&collections))?;
                if progress.done.contains(&b64(&scope)) {
                    continue;
                }
                let after = progress.after(&scope)?;
                if let Listed::Paused(_) = self
                    .list_from(
                        collection,
                        Some(&collections),
                        after,
                        pages,
                        (&mut progress, LIST_AT),
                        budget,
                    )
                    .await?
                {
                    return Ok(Listing::Unfinished);
                }
            }
        }
        // A grant can acquire its first readable collection while the app is
        // offline. Settling that owner still requires the service's current reader.
        if *pages == before
            && listing.iter().any(|name| {
                self.protocols
                    .get(name)
                    .is_some_and(|p| !p.collections().is_empty())
            })
            && !self
                .reader_ready_without_a_page(&progress, due.upload)
                .await?
        {
            return Ok(Listing::Unfinished);
        }
        // Settled for those listed, in one commit with their positions: each is told
        // through the item that owed its listing, unless a call about that item is still
        // kept for it, and may be told what comes after.
        let calls = self.kept_calls().await?;
        let mut tx = self.tx()?;
        let mut left = ListDue {
            upload: due.upload,
            ..ListDue::default()
        };
        for (name, at) in &due.to {
            if !listing.contains(name) {
                left.to.push((name.clone(), *at));
            }
        }
        // One owed outside the feed that waits for a key while the read goes on for the
        // others takes its protocol's own position as its place: that protocol stays there,
        // told nothing further, until the listing is made.
        for (name, at) in &waiting {
            if at.is_none() {
                let place = self.told(name);
                for owed in &mut left.to {
                    if owed.0 == *name {
                        owed.1 = Some(place);
                    }
                }
            }
        }
        self.listing_waits = !waiting.is_empty();
        if left == due {
            return Ok(Listing::NotDue);
        }
        if left.to.is_empty() {
            tx.delete(LIST_DUE)?;
        } else {
            tx.put(LIST_DUE, &left)?;
        }
        tx.delete(LIST_AT)?;
        for name in &listing {
            if let Some(Some((generation, seq))) = due.at(name) {
                let called = calls.iter().any(|kept| {
                    kept.names.contains(name)
                        && self.feed_order(kept.generation, kept.seq)
                            == self.feed_order(generation, seq)
                });
                if !called {
                    self.told_through(name, generation, seq);
                }
            }
        }
        self.put_told(&mut tx)?;
        self.commit(tx).await?;
        self.listed_every = listing.len() == self.protocols.names().len();
        Ok(if listing.is_empty() {
            Listing::NotDue
        } else {
            Listing::Listed
        })
    }

    /// Keep each outstanding listing and its position after a read's listing step:
    /// it is a prerequisite even at sequence zero ([`App::may_tell`]).
    pub(crate) async fn note_listing_due(&mut self) -> Result<(), AppError> {
        let due: ListDue = self.reader().get(LIST_DUE).await?.unwrap_or_default();
        self.listing_due = due;
        Ok(())
    }

    /// The collections of protocol `name` the app's certificate reads.
    fn readable_collections(&self, name: &str) -> Vec<Collection> {
        self.protocols
            .get(name)
            .map(|protocol| protocol.collections())
            .unwrap_or_default()
            .into_iter()
            .filter(|c| c.readable_by(&self.state.cert))
            .collect()
    }

    /// The calls kept for protocols (`owed/`), in feed order, each with the protocols it
    /// names ([`Kept`]).
    pub(crate) async fn kept_calls(&self) -> Result<Vec<Kept>, AppError> {
        let owed = self.owed_calls().await?;
        let mut kept = owed
            .into_iter()
            .map(|(rest, owed)| {
                let (generation, seq) = super::feed::owed_place(&rest)?;
                Ok(Kept {
                    generation,
                    seq,
                    deny: owed.call.is_deny(),
                    held_gap: owed.call.held_gap(seq),
                    names: owed.to,
                    call: true,
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        kept.sort_by_key(|kept| self.feed_order(kept.generation, kept.seq));
        Ok(kept)
    }

    /// Everything kept for protocols at a feed position, in feed order: the calls
    /// (`owed/`) and the listings feed items owe (`list_due`), a listing before a call at
    /// the same item ([`Kept`]).
    pub(crate) async fn kept_things(&self) -> Result<Vec<Kept>, AppError> {
        let mut kept = self
            .reader()
            .get::<ListDue>(LIST_DUE)
            .await?
            .unwrap_or_default()
            .kept();
        kept.extend(self.kept_calls().await?);
        kept.extend(self.deletion_positions());
        kept.sort_by_key(|kept| self.feed_order(kept.generation, kept.seq));
        Ok(kept)
    }

    /// List every readable collection from where `list_at` got, at most `pages` pages,
    /// recording how far each page got, as the host asks ([`App::list_collections`]).
    /// Returns whether the listing reached its end, which settles every listing owed.
    async fn list_from_list_at(
        &mut self,
        pages: &mut u32,
        budget: Option<&super::CallBudget>,
    ) -> Result<bool, AppError> {
        let mut progress: ListProgress = ListProgress::for_reader(
            self.reader().get(LIST_AT).await?,
            self.state.cert.hash(),
            self.state.meta.generation,
        );
        let registered = self.protocols.collections();
        let has_collections = !registered.is_empty();
        let collections: Vec<Collection> = registered
            .into_iter()
            .filter(|c| c.readable_by(&self.state.cert))
            .collect();
        let before = *pages;
        for collection in &collections {
            let id = collection.id(&self.state.meta.identity);
            let scope = listing_scope(&id, collection, Some(&collections))?;
            if progress.done.contains(&b64(&scope)) {
                continue;
            }
            let after = progress.after(&scope)?;
            if let Listed::Paused(_) = self
                .list_from(
                    collection,
                    Some(&collections),
                    after,
                    pages,
                    (&mut progress, LIST_AT),
                    budget,
                )
                .await?
            {
                return Ok(false);
            }
        }
        if has_collections && *pages == before {
            let due = self.reader().get::<ListDue>(LIST_DUE).await?;
            if !self
                .reader_ready_without_a_page(&progress, due.and_then(|due| due.upload))
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

    /// Whether a readable collection member lacks its current scope key (Switch spec 3.5).
    fn listing_lacks_keys(&self, collections: &[Collection]) -> bool {
        let epoch = self.state.own_doc.data_epoch();
        collections.iter().any(|collection| {
            collection.any_read_scope(&self.state.cert, |scope| {
                self.protocols.has_keys(scope) && self.state.scope_keys.get(epoch, scope).is_none()
            })
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
        // A record of a protocol that is behind the read stays as it is, and the reopening
        // stays owed: it is opened once that protocol is with the read (`order` module).
        let mut left = false;
        for (_, record) in held {
            if !record.content.waits_for_key() {
                continue;
            }
            let protocol = self
                .protocols
                .of_collection(&record.collection)
                .map(|registered| registered.name.clone());
            if !self.may_tell_of(protocol.as_deref()) {
                left = true;
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
                view_revision: Some(record.applied),
                current_at: CurrentAt::Local,
                observation: ObservationSource::Reopened,
            };
            self.read_write(&evidence, Some((&put.key, &collection)), put.key, &mut tx)
                .await?;
        }
        if !left && self.reader().exists(REOPEN_DUE).await? {
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

    /// Take a record view, from a read, a list page, after a conflict or after an upload,
    /// current at `at`; then hold what it says of divergent uploads, once the write is
    /// judged.
    pub(crate) async fn take_view(
        &mut self,
        view: &SharedRecordView,
        at: CurrentAt,
        expect: Option<(&[u8; 32], &Collection)>,
        covers_uploads: bool,
        tx: &mut Tx,
    ) -> Result<WriteRead, AppError> {
        let read = self
            .judge_view(view, at, expect, covers_uploads, tx)
            .await?;
        if let CurrentAt::Answer(version) | CurrentAt::KeyAtKnownTip(version, _) = at {
            let (key, id) = expect.map_or((view.key, view.collection), |(key, collection)| {
                (*key, collection.id(&self.identity()))
            });
            if self
                .protocols
                .collections()
                .iter()
                .any(|c| c.id(&self.identity()) == id)
            {
                let member = inventory::ListedMember::new(
                    view,
                    &id,
                    read,
                    covers_uploads && key == view.key,
                );
                self.observe_member(
                    &id,
                    &key,
                    position(version.generation, version.version),
                    member.member,
                    tx,
                )
                .await?;
            }
        }
        Ok(read)
    }

    async fn judge_view(
        &mut self,
        view: &SharedRecordView,
        at: CurrentAt,
        expect: Option<(&[u8; 32], &Collection)>,
        covers_uploads: bool,
        tx: &mut Tx,
    ) -> Result<WriteRead, AppError> {
        let key = expect.map_or(view.key, |(key, _)| *key);
        if !SignedOp::peek(&view.op)
            .is_ok_and(|op| matches!(&op.body().kind, OpKind::RecordPut(put) if put.key == key))
        {
            return Ok(WriteRead::Unordered);
        }
        let at = at.with_upload_coverage(covers_uploads);
        let evidence = Evidence {
            op: &view.op,
            cert: Some(&view.cert),
            proof: view.proof.as_ref(),
            stub: None,
            view_version: Some(RecordVersion::new(view.generation, view.version)),
            view_revision: Some(view.revision),
            current_at: at,
            observation: at.observation(view.divergent),
        };
        let read = self.read_write(&evidence, expect, key, tx).await?;
        // An earlier view can supply the signed write, while the latest upload's
        // divergence remains unknown (Switch wire 7.4.14).
        if covers_uploads && key == view.key && read.says_of_now() {
            self.note_view_divergence(&key, view.divergent, tx).await?;
        }
        Ok(read)
    }

    /// A `record.put` chain item from the feed, its stub verified (Switch spec 8.3): taken
    /// if newer than what the app holds, at its place in feed order: one the protocol of
    /// its collection isn't told through everything before is [`WriteRead::Waits`], and the
    /// read holds it.
    pub(crate) async fn feed_record_write(
        &mut self,
        item: &ChainItem,
        envelope: &ChainEnvelope,
        page_time_ms: u64,
        tx: &mut Tx,
    ) -> Result<WriteRead, AppError> {
        let Ok(op) = SignedOp::peek(&item.item) else {
            return Ok(WriteRead::Refused);
        };
        let OpKind::RecordPut(put) = &op.body().kind else {
            return Ok(WriteRead::Refused);
        };
        let evidence = Evidence {
            op: &item.item,
            cert: None,
            proof: item.proof.as_ref(),
            stub: Some(envelope),
            view_version: None,
            view_revision: None,
            current_at: CurrentAt::Itself,
            observation: ObservationSource::Applied,
        };
        let key = put.key;
        let mut viewed = WriterView::NotRead;
        let read = self
            .judge_write(&evidence, None, key, Some(page_time_ms), tx, &mut viewed)
            .await?;
        if read == WriteRead::Waits {
            return Ok(read);
        }
        self.observe_collection_write(put, envelope, read, tx)
            .await?;
        match viewed {
            // The record's view, read to judge the write, is the switch's latest word.
            WriterView::Current { divergent } if read.says_of_now() => {
                self.note_view_divergence(&key, divergent, tx).await?;
            }
            // A newer write clears the record's divergent uploads before it (Switch wire
            // 7.4.14); the write held doesn't: uploads after it may conflict with it.
            WriterView::NotRead if read == WriteRead::Taken => {
                if let Some(collection) = self.collection_for_write(put, tx).await? {
                    let uploads = self.record_uploads(&key, &collection).await?;
                    if self.covers_uploads(position(envelope.generation, item.seq), uploads) {
                        self.note_divergent(&key, false, tx).await?;
                    }
                }
            }
            _ => {}
        }
        Ok(read)
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
        let mut viewed = WriterView::NotRead;
        let read = self
            .judge_write(evidence, expect, shown_key, None, tx, &mut viewed)
            .await?;
        if let WriterView::Current { divergent } = viewed
            && read.says_of_now()
        {
            self.note_view_divergence(&shown_key, divergent, tx).await?;
        }
        Ok(read)
    }

    /// [`App::read_write`], with `viewed` recording whether a view of `shown_key`
    /// supplied its writer certificate and covered its pending uploads.
    ///
    /// A write the feed shows (`feed`) is judged at its item, for the protocol of its
    /// collection: one that protocol isn't told through everything before
    /// ([`App::may_tell`]) is [`WriteRead::Waits`], before anything is read or written for
    /// it, so no check, mark, flag, divergence or event reaches a protocol past an item it
    /// hasn't taken (Switch spec 8.3). The record's protocol is the record's as the app
    /// holds or names it, else that of the collection the write names; one of neither
    /// can't be placed, and waits until every protocol may be told. A view from a listing,
    /// a read again or a reopening is judged for a protocol its caller found may be told.
    async fn judge_write(
        &mut self,
        evidence: &Evidence<'_>,
        expect: Option<(&[u8; 32], &Collection)>,
        shown_key: [u8; 32],
        page_time_ms: Option<u64>,
        tx: &mut Tx,
        viewed: &mut WriterView,
    ) -> Result<WriteRead, AppError> {
        if page_time_ms.is_some() {
            let protocol = self
                .write_protocol(evidence, expect, &shown_key, tx)
                .await?;
            if !self.may_tell_of(protocol.as_deref()) {
                return Ok(WriteRead::Waits);
            }
        }
        // Boxed: the checks hold a deep future, which a receive on a small stack can't.
        let mut evidence = *evidence;
        let mut outcome = Box::pin(self.accept_write(&evidence, expect, tx)).await?;
        // A write the app holds no certificate in force at its time for: the record's view,
        // whose cert is the one the service checked the write against, decides (Switch
        // wire 6.2 "Accepting a write" step 1, 7.4.9).
        let current_view;
        if let Err(Refused::Unheld(collection)) = outcome {
            let Some(observed) = self.record_view(&shown_key, &collection).await? else {
                return Ok(WriteRead::Refused);
            };
            let at = observed.at.with_upload_coverage(observed.covers_uploads);
            current_view = observed.view;
            if current_view.key != shown_key
                || !SignedOp::peek(&current_view.op).is_ok_and(
                    |op| matches!(&op.body().kind, OpKind::RecordPut(put) if put.key == shown_key),
                )
            {
                return Ok(WriteRead::Refused);
            }
            *viewed = if observed.covers_uploads {
                WriterView::Current {
                    divergent: current_view.divergent,
                }
            } else {
                WriterView::Historical
            };
            // A re-read of the feed operation keeps its stub and proof. When the view
            // shows another operation, both acceptance and refusal judge only that one.
            let same = current_view.op == *evidence.op;
            evidence = Evidence {
                op: &current_view.op,
                cert: Some(&current_view.cert),
                proof: current_view
                    .proof
                    .as_ref()
                    .or(evidence.proof.filter(|_| same)),
                stub: evidence.stub.filter(|_| same),
                view_version: Some(RecordVersion::new(
                    current_view.generation,
                    current_view.version,
                )),
                view_revision: Some(current_view.revision),
                current_at: at,
                observation: at.observation(current_view.divergent),
            };
            outcome =
                Box::pin(self.accept_write(&evidence, Some((&shown_key, &collection)), tx)).await?;
        }
        match outcome {
            Ok(accepted) => {
                let key = accepted.key;
                return Ok(
                    match self
                        .take_write(
                            accepted,
                            false,
                            page_time_ms.filter(|_| evidence.stub.is_some()),
                            None,
                            tx,
                        )
                        .await?
                    {
                        Taken::Waits => WriteRead::Waits,
                        Taken::New => WriteRead::Taken,
                        Taken::Equal | Taken::Reopened => WriteRead::Equal,
                        Taken::Older(write) => {
                            self.events.push(AppEvent::RecordShownOlder { key, write });
                            WriteRead::Older(write)
                        }
                        Taken::Historical(h) => h.read(),
                        Taken::Flagged => WriteRead::Refused,
                    },
                );
            }
            Err(Refused::Misbehaviour(reason)) => {
                return Err(self.raise(Alarm::Rollback { reason }).await);
            }
            Err(Refused::Named {
                writer,
                item,
                reason,
                does_not_open,
                checked,
            }) => {
                if does_not_open
                    && let Some(mut held) = self
                        .read_in::<HeldRecord>(&record_key_of(&shown_key), tx)
                        .await?
                    && held.op == *evidence.op
                    && held.content.waits_for_key()
                {
                    held.content = RecordContent::Unreadable(Unopened::DoesNotOpen);
                    put_held(tx, &shown_key, &held)?;
                }
                let version = checked
                    .as_ref()
                    .map(|c| c.0.version.version)
                    .or(evidence.view_version)
                    .unwrap_or(RecordVersion::NONE);
                self.flag_write(
                    Shown {
                        key: shown_key,
                        version,
                        write: item,
                    },
                    writer,
                    reason,
                    tx,
                )
                .await?;
                if let Some(checked) = checked {
                    let (write, placement) = *checked;
                    self.follow_write(&shown_key, write, placement, tx).await?;
                    if let Some(h) = placement.historical {
                        return Ok(h.read());
                    }
                }
            }
            Err(Refused::Unnamed(checked)) => {
                let (write, placement) = *checked;
                self.follow_write(&shown_key, write, placement, tx).await?;
                if let Some(h) = placement.historical {
                    return Ok(h.read());
                }
            }
            Err(Refused::Ignored | Refused::Unheld(_)) => {}
        }
        Ok(WriteRead::Refused)
    }

    /// Record the reason for refusing a write whose signature identifies its writer.
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
        mut write: FollowedWrite,
        placement: Placement,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let Some(mut held) = self.read_in::<HeldRecord>(&record_key_of(key), tx).await? else {
            return Ok(());
        };
        let current = placement.at.filter(|_| placement.historical.is_none());
        if let Some(f) = held
            .follow
            .as_mut()
            .filter(|f| f.applied.item_hash == write.applied.item_hash)
        {
            f.retain(write.version, write.proof.as_ref());
            f.named |= write.named;
            if let Some(at) = current {
                f.applied = write.applied;
                held.observed = at;
                held.gone = false;
            }
        } else if let Some(at) = current
            && (placement.base == Order::Newer
                || (matches!(placement.base, Order::Older(_))
                    && write.version.version == held.base_write().0))
        {
            if write.applied.item_hash == held.item_hash {
                write.retain(held.write_version(), held.proof.as_ref());
            }
            if !write.named {
                self.events.push(AppEvent::WriteNotTaken { key: *key });
            }
            held.follow = Some(write);
            held.observed = at;
            held.gone = false;
        } else {
            return Ok(());
        }
        put_held(tx, key, &held)?;
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
        // certificates it was made. A uniform policy can use its original local scope check;
        // a distinct creation scope requires evidence of the role for this operation.
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
        let uniform_own = own && put.policy.create_scope.is_none();
        let item_hash = certs.op.item_hash()?;
        // A view's revision names this signed operation, even when a recovery upload
        // changed its position (Switch wire 6.3). A mismatch invalidates the response,
        // including the divergence state it reports. It says nothing about the writer.
        if evidence
            .view_revision
            .is_some_and(|revision| revision.item_hash != item_hash)
        {
            return Err(ClientError::InvalidResponse(
                "Switch wire 6.3: the record revision names a different operation".into(),
            )
            .into());
        }
        // Date this operation independently of the reason for refusing its content. Only a
        // plausible write version can change what a later conditional write builds on.
        let WriteDate {
            mut time,
            proven,
            proof,
        } = match self.date(evidence, &certs.op, item_hash) {
            Ok(dated) => dated,
            Err(reason) => return Ok(Err(Refused::Misbehaviour(reason))),
        };
        let held = self
            .read_in::<HeldRecord>(&record_key_of(&put.key), tx)
            .await?;
        let version = proven
            .or(evidence.view_version)
            .map(|version| WriteVersion {
                version,
                authenticated: proven.is_some(),
                expected_version: put.expected_version,
            });
        let mut checked = None;
        if let Some(version) = version.filter(|v| v.plausible(body.generation)) {
            let mut write = FollowedWrite {
                version,
                applied: evidence
                    .view_revision
                    .unwrap_or(applied_at(version.version, item_hash)),
                proof: proof.cloned(),
                deleted: put.value_sealed.looks_like_delete(),
                named: false,
            };
            // A new view of the same item can change its application. It cannot take away
            // evidence already verified for that operation, including a feed stub.
            if let Some(h) = &held {
                if h.item_hash == item_hash {
                    if !write.version.authenticated && !h.authenticated {
                        write.version = h.write_version();
                    }
                    write.retain(h.write_version(), h.proof.as_ref());
                    time = time.or(h.written_at_ms);
                }
                if let Some(f) = h
                    .follow
                    .as_ref()
                    .filter(|f| f.applied.item_hash == item_hash)
                {
                    if !write.version.authenticated && !f.version.authenticated {
                        write.version = f.version;
                    }
                    write.retain(f.version, f.proof.as_ref());
                    time = time.or_else(|| {
                        f.proof
                            .as_ref()
                            .and_then(|p| date_write(p, &certs.op, &self.state.own_doc).ok())
                            .map(|d| d.time)
                    });
                }
            }
            let placement =
                match self.place_write(&write, writer, evidence.current_at, held.as_ref()) {
                    Ok(placement) => placement,
                    Err(reason) => return Ok(Err(Refused::Misbehaviour(reason))),
                };
            checked = Some((write, placement));
        }
        let invalid = |reason: &str| -> Result<Result<Accepted, Refused>, AppError> {
            Ok(Err(if own {
                Refused::Ignored
            } else {
                Refused::named(writer, item_hash, reason, false, checked.clone())
            }))
        };
        if let Some(reason) = check_shape(put, &collection, &identity) {
            return invalid(reason);
        }
        let collection = Collection::new(&collection.name, put.policy.clone());
        if let Err(refused) = check_permanent(put, body.generation) {
            return Ok(Err(match proven {
                Some(_) => Refused::Misbehaviour(refused.reason),
                None => Refused::Ignored,
            }));
        }
        let unnamed = || -> Result<Result<Accepted, Refused>, AppError> {
            Ok(Err(checked.clone().map_or(Refused::Ignored, |w| {
                Refused::Unnamed(Box::new(w))
            })))
        };
        // Step 4: standing at the write's time, of a certificate of the writer that counts
        // for it (`write_cert`).
        let mut doubtful = false;
        let Some(mut cert) = self.write_cert(&certs, time, put) else {
            return Ok(Err(Refused::Ignored));
        };
        let mut standing = self.state.own_doc.standing(&writer, &cert.hash());
        if !uniform_own
            && standing == Standing::None
            && matches!(
                self.refresh_identity().await,
                Ok(IdentityRefresh::Newer { .. } | IdentityRefresh::ClockMovedBack { newer: true })
            )
            && let Some(again) = self.write_cert(&certs, time, put)
        {
            cert = again;
            standing = self.state.own_doc.standing(&writer, &cert.hash());
        }
        let mut counts =
            in_force(&self.state.own_doc, &cert, time) && holds_write_role(&cert, put, time);
        // No certificate of the writer the app holds counts for the write, while the newest
        // own `identity.json` names one in force at its time that the app doesn't hold: the
        // write may be the writer's under that one. Without a record view, the view decides
        // (step 1). With one, its `cert` is only the service's pick, as the write names no
        // certificate: the app reads its directory for the writer's listed certificate, once
        // for each the directory answers for while it runs. If that doesn't settle it, a
        // failure of steps 4 and 5 is the service's word, and the write is ignored, naming no
        // app. A failed directory read marks nothing. A later write can trigger another
        // lookup once `SENDER_REREAD_MS` has passed.
        let mut unheld = !uniform_own && !counts && self.unheld_in_force(&writer, &certs, time);
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
                && let Some(found) = self.write_cert(&again, time, put)
            {
                certs = again;
                cert = found;
                standing = self.state.own_doc.standing(&writer, &cert.hash());
                counts = in_force(&self.state.own_doc, &cert, time)
                    && holds_write_role(&cert, put, time);
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
            _ if uniform_own && !matches!(standing, Standing::Removed { .. }) => {}
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
        if !uniform_own && time.is_some_and(|t| cert.expired_at(t)) {
            return invalid("Switch wire 6.2 step 4: the certificate had expired at the write");
        }
        // A later certificate cannot establish which role this writer had at the
        // original operation. Keep its revision until a dated, qualifying write arrives.
        if put.policy.create_scope.is_some() && !counts {
            return unnamed();
        }
        // Step 5: a write scope.
        if !uniform_own && !holds_write_role(&cert, put, time) {
            return invalid("Switch wire 6.2 step 5: the writer holds none of the write scopes");
        }
        // Step 6: the version. It is the service's word, not the writer's: a write whose
        // version is missing or not plausible is ignored, naming no app and followed by
        // nothing. A client loses nothing by it that a service withholding the write couldn't
        // take.
        let Some((write, placement)) = checked else {
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
                return Ok(Err(Refused::named(
                    writer,
                    item_hash,
                    "Switch wire 6.2 step 7: the value doesn't open",
                    true,
                    Some((write, placement)),
                )));
            }
        };
        // A signed successor can be learned at an earlier position, but only an
        // observation covering the upload can release its deletion's service cursor
        // (Switch spec 10.3, Switch wire 7.4.14).
        let covers_uploads = match evidence.observation {
            ObservationSource::View { at, .. } => at.is_some(),
            ObservationSource::Applied
                if super::put_back::at_key(&self.state.put_backs, &put.key)
                    .next()
                    .is_some() =>
            {
                self.record_source_current(
                    &put.key,
                    &collection.name,
                    evidence.observation,
                    write.applied,
                    position(write.applied.generation, write.applied.seq),
                    tx,
                )
                .await?
            }
            _ => false,
        };
        Ok(Ok(Accepted {
            key: put.key,
            collection,
            op: evidence.op.clone(),
            cert,
            write,
            placement,
            time,
            writer,
            current_at: evidence.current_at,
            observation: evidence.observation,
            covers_uploads,
            content,
            doubtful,
        }))
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
        candidates.extend(self.kept_renewal().cloned());
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
        put: &RecordPut,
    ) -> Option<AppCert> {
        let doc = &self.state.own_doc;
        if let Some(cert) = certs
            .view
            .as_ref()
            .filter(|cert| in_force(doc, cert, time) && holds_write_role(cert, put, time))
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
        if let Some(cert) = counting
            .iter()
            .find(|cert| holds_write_role(cert, put, time))
        {
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
    pub(crate) fn pending_certs(&self, tx: &Tx, app_id: &[u8; 16]) -> Vec<AppCert> {
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
    /// current key gives it. Only an independently checked transition proof is portable.
    fn date<'a>(
        &self,
        evidence: &Evidence<'a>,
        op: &SignedOp,
        item_hash: [u8; 32],
    ) -> Result<WriteDate<'a>, String> {
        let dated = evidence
            .proof
            .map(|proof| self.date_proof(proof, op))
            .transpose()?
            .flatten();
        let mut date = WriteDate {
            time: dated.map(|d| d.time),
            proven: dated.and_then(|d| d.version),
            proof: evidence.proof.filter(|_| dated.is_some()),
        };
        if let Some(env) = evidence.stub {
            if env.item_hash != item_hash {
                return Err("Switch wire 6.6: a feed item doesn't match its stub".into());
            }
            let version = RecordVersion::new(env.generation, env.seq);
            date.proof = date.proof.filter(|p| evidence::proof_at(p, version));
            date.proven = Some(version);
            date.time = Some(env.server_time);
        }
        Ok(date)
    }

    fn date_proof(
        &self,
        proof: &SignedDoc,
        op: &SignedOp,
    ) -> Result<Option<pubky_switch_core::shared::Dated>, String> {
        let identity = self.state.meta.identity;
        let current_key = self.state.own_doc.inbox().service_key;
        // Checked with the current key only for a proof of the newest own `identity.json`'s
        // generation: after a provider loss at the same service a lost generation's proofs
        // verify with that key too, and date nothing (Switch wire 3.3, 6.2 step 2).
        if let Ok(checked) = TransitionProof::verify(proof, &current_key, &identity)
            && checked.envelope().generation == self.state.own_doc.generation()
        {
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
            return date_write(proof, op, &self.state.own_doc)
                .map(Some)
                .map_err(|e| e.to_string());
        }
        // A listed earlier key can date this operation without authenticating its position.
        Ok(date_write(proof, op, &self.state.own_doc).ok())
    }

    // ---------------------------------------------------------------------------------
    // Taking a write

    /// A repair may refer to an earlier complete value only when this reader can verify
    /// the two exact record applications in its own collection (Switch spec 8.2).
    fn record_repair(
        &self,
        candidate: &Accepted,
        held: Option<&HeldRecord>,
        tx: &Tx,
    ) -> Result<Option<super::RecordRepair>, AppError> {
        let key = candidate.key;
        let generation = self.state.meta.generation;
        let Some(held) = held.filter(|h| {
            h.authenticated
                && !h.doubtful
                && !h.gone
                && h.follow
                    .as_ref()
                    .is_none_or(|followed| followed.applied == candidate.write.applied)
                && h.content.value().is_some()
                && h.applied == applied_at(h.version, h.item_hash)
                && h.version.generation == generation
                && h.policy == candidate.collection.policy
        }) else {
            return Ok(None);
        };
        if super::put_back::at_key(&self.state.put_backs, &key)
            .next()
            .is_none()
            || !candidate.write.version.authenticated
            || candidate.doubtful
            || candidate.content.value().is_none()
            || candidate.write.version.expected_version != held.version
            || candidate.write.applied
                != applied_at(
                    candidate.write.version.version,
                    candidate.write.applied.item_hash,
                )
            || candidate.write.applied.generation != generation
            || candidate.write.applied.seq <= held.applied.seq
            || !self.state.cert.holds_scope(&held.policy.read_scope)
        {
            return Ok(None);
        }
        let proposed = SignedOp::peek(&candidate.op).map_err(|_| store_corrupt())?;
        if proposed.body().generation != generation
            || !proposed
                .body()
                .conditions
                .contains(&Condition::RecordCurrent {
                    key,
                    revision: held.applied,
                    deleted: false,
                })
        {
            return Ok(None);
        }
        let identity = &self.state.meta.identity;
        let cert = AppCert::verify(&held.cert, identity).map_err(|_| store_corrupt())?;
        let previous = SignedOp::verify(
            &held.op,
            &cert.signing_key(),
            identity,
            Some(&cert.app_id()),
        )
        .map_err(|_| store_corrupt())?;
        let OpKind::RecordPut(put) = &previous.body().kind else {
            return Err(store_corrupt());
        };
        if previous.item_hash()? != held.item_hash
            || put.key != key
            || put.collection != candidate.collection.id(identity)
            || put.policy != held.policy
            || previous.body().generation != generation
        {
            return Ok(None);
        }
        let Some(deletion) = previous.body().conditions.iter().find_map(|c| match c {
            Condition::RecordCurrent {
                key: k,
                revision,
                deleted: true,
            } if *k == key
                && revision.generation == generation
                && put.expected_version == RecordVersion::new(generation, revision.seq) =>
            {
                Some(*revision)
            }
            _ => None,
        }) else {
            return Ok(None);
        };
        let id = (key, put.expected_version, deletion.item_hash);
        let Some(hold) = self
            .state
            .put_backs
            .get(&id)
            .filter(|h| !h.observing && h.observation.revision() == deletion)
        else {
            return Ok(None);
        };
        let original = SignedOp::peek(&hold.observation.operation).map_err(|_| store_corrupt())?;
        self.with_deletion(&hold.observation, &original, tx, |_, d, _| {
            let Some(prior) = d.exact_value.filter(|_| {
                d.original_in_current_generation
                    && d.exact_version_authenticated
                    && d.base.expected_version.generation == generation
                    && d.policy == Some(&held.policy)
            }) else {
                return Ok(None);
            };
            let Ok(RecordValue::Json(value)) =
                put.value_sealed
                    .open_with(&self.state.scope_keys, identity, &key)
            else {
                return Ok(None);
            };
            Ok(
                (held.content.value() == Some(&value)).then(|| super::RecordRepair {
                    key,
                    deletion,
                    policy: held.policy.clone(),
                    prior_value: prior.to_vec(),
                    held_value: value,
                }),
            )
        })
    }

    pub(super) async fn take_publication_candidate(
        &mut self,
        write: Accepted,
        due: &super::deletion::Id,
        tx: &mut Tx,
    ) -> Result<bool, AppError> {
        let mut selected = false;
        if let Some(owner) = self.protocols.of_collection(&write.collection.name)
            && self.may_tell(&owner.name)
        {
            self.take_write(write, false, None, Some((due, &mut selected)), tx)
                .await?;
        }
        Ok(selected)
    }

    /// Take an accepted write if it is newer than the one held and the protocol finds it
    /// goes back on nothing the app has seen.
    ///
    /// The same write again, by its item hash, changes nothing but a version a proof now
    /// authenticates and, shown by a record view as the current write, the application the
    /// next write names, unless the app holds it `Unreadable` and now opens it: a value never
    /// opened was never seen, so it is taken as a write is, its version evidence the better
    /// of the two, and the protocol checks and marks it (Switch spec 3.5, 8.2).
    async fn take_write(
        &mut self,
        mut accepted: Accepted,
        settling_own: bool,
        page_time_ms: Option<u64>,
        due: Option<(&super::deletion::Id, &mut bool)>,
        tx: &mut Tx,
    ) -> Result<Taken, AppError> {
        let result = Box::pin(async {
            let key = accepted.key;
            // The application proof settles an own submission even while a foreign
            // observation is owed. Foreign handovers still follow the owner's feed order.
            let owner = self.protocols.of_collection(&accepted.collection.name);
            let at = self.feed_order(accepted.write.applied.generation, accepted.write.applied.seq);
            if !settling_own && self.owed_deletions().any(|d| {
                (d.key == key || owner.is_some_and(|owner| owner.name == d.owner))
                    && self.feed_order(d.generation, d.seq) < at
            }) {
                return Ok(Taken::Waits);
            }
            self.keep_cert(&accepted.cert, tx)?;
            let held = self.read_in::<HeldRecord>(&record_key_of(&key), tx).await?;
            let seen: Option<SeenMark> = self.read_in(&seen_key(&key), tx).await?;
            let prior_mark = seen.as_ref().map(|mark| mark.mark.as_slice());
            let qualified = accepted.content.value().and_then(|value| {
                let input = super::RecordMarkContext { key, collection: &accepted.collection, naming: &self.state.naming };
                owner?.protocol.qualify_record_mark(&input, prior_mark, value)
            });
            let reopened = held.as_ref().is_some_and(|held| {
                held.item_hash == accepted.write.applied.item_hash
                    && (held.content.waits_for_key() || (qualified.is_some() && held.content == RecordContent::Unreadable(Unopened::Refused)))
                    && !matches!(accepted.content, RecordContent::Unreadable(_))
            });
            let placement = accepted.placement;
            let current = placement.at.filter(|_| placement.historical.is_none());
            let observed = current.or_else(|| held.as_ref().map(|h| h.observed))
                .ok_or_else(store_corrupt)?;
            let selects_base = current.is_some() && (matches!(placement.base, Order::Newer | Order::Equal)
                || (accepted.current_at.viewed() && held.as_ref().is_some_and(|h|
                    accepted.write.version.version == h.base_write().0)));
            let lifetime_mark = accepted.collection.policy.permanent.is_none() && owner.is_some_and(|owner|
                owner.protocol.mark_ends_at_delete(&accepted.collection.name));
            let needs_current = qualified.is_some() || (lifetime_mark && accepted.content == RecordContent::Deleted);
            let qualifiable = if needs_current && placement.historical.is_none() && accepted.write.version.authenticated && !accepted.doubtful {
                let source = accepted.observation;
                let covers = self.record_source_current(&key, &accepted.collection.name, source, accepted.write.applied, observed, tx).await?;
                let previous = match tx.pending_state(&super::uploaded::divergent_key(&key)) {
                    Some(held) => held,
                    None => self.is_divergent(&key).await?,
                };
                covers && !source.divergent(covers, previous, placement.content == Order::Newer && !reopened)
            } else {
                false
            };
            let (due, selected) = due.unzip();
            let mut repair = None;
            if accepted.current_for_publication()
                && qualified.as_ref().is_none_or(|result| qualifiable
                    && result.as_ref().is_ok_and(|mark| mark.len() <= MAX_SEEN_MARK_BYTES))
            {
                use super::put_back::Publication;
                let evidence = self.record_repair(&accepted, held.as_ref(), tx)?;
                let original = evidence.as_ref().map(|r| {
                    let version = RecordVersion::new(r.deletion.generation, r.deletion.seq);
                    (key, version, r.deletion.item_hash)
                });
                let decision = self.saw_put_back_write(
                    &key,
                    due.or(original.as_ref()),
                    accepted.write.applied,
                    Some((&accepted, evidence.as_ref())),
                    page_time_ms,
                    tx,
                ).await?;
                // A retry for a different deletion checks only that duty. The feed or
                // the matching duty takes the repair with its own owner's decision.
                let other_delete = due.zip(original.as_ref()).is_some_and(|(due, original)| due != original);
                if !settling_own && (matches!(decision, Publication::PendingObservation) || other_delete) {
                    return Ok(Taken::Waits);
                }
                if matches!(decision, Publication::Selected) && let Some(selected) = selected { *selected = true; }
                if let Publication::Covered(deletion) = decision {
                    repair = evidence.filter(|r| r.deletion == deletion);
                }
            }
            let ends_mark = lifetime_mark && selects_base && qualifiable && accepted.content == RecordContent::Deleted;
            if selects_base && let Some(at) = current {
                self.retire_deletion_receipts(key, Some((accepted.write.applied.item_hash, RecordVersion::new(at.generation, at.seq))), tx)?;
            }
            // A historical read may supply the operation for a held record. A
            // collection that qualifies its mark still needs a covering read.
            if reopened && qualified.is_some() && let Some(h) = placement.historical {
                self.follow_write(&key, accepted.write, placement, tx).await?;
                return Ok(Taken::Historical(h));
            }
            if let Some(held) = held.as_ref().filter(|_| !reopened) {
                if placement.content == Order::Equal {
                    // A page may have ended at an inbox entry after its latest
                    // chain operation (Switch wire 7.4.9). A matching key GET at
                    // that exact signed tip confirms the content without moving
                    // the stronger feed observation back.
                    let confirms = if let CurrentAt::KeyAtKnownTip(tip, divergent) = accepted.current_at
                        && matches!(placement.historical, Some(Historical::Overtaken(..)))
                        && held.observed.generation == tip.generation
                        && held.observed.seq > tip.version
                        && self.state.cert.holds_scope(&held.policy.read_scope)
                        && held.matches_accepted_view(&accepted)
                    {
                        self.is_divergent(&key).await? == divergent
                    } else {
                        false
                    };
                    let mut upgraded = held.clone();
                    upgraded.version = accepted.write.version.version;
                    upgraded.authenticated = accepted.write.version.authenticated;
                    upgraded.proof = accepted.write.proof.clone();
                    upgraded.written_at_ms = accepted.time.or(held.written_at_ms);
                    if let Some(f) = upgraded.follow.as_mut().filter(|f| f.applied.item_hash == accepted.write.applied.item_hash) {
                        f.retain(accepted.write.version, accepted.write.proof.as_ref());
                    }
                    if selects_base {
                        upgraded.live_in = self.live_in(&held.policy, &held.content, held.live_in);
                        upgraded.observed = observed;
                        upgraded.gone = false;
                        upgraded.applied = accepted.write.applied;
                        if upgraded.content == RecordContent::Unreadable(Unopened::Refused) {
                            accepted.write.named = true;
                            upgraded.follow = Some(accepted.write);
                        } else {
                            upgraded.follow = None;
                        }
                    }
                    // A fresh proof may be the first evidence that a held delete was current.
                    if ends_mark && upgraded.content == RecordContent::Deleted && upgraded.follow.is_none() {
                        self.end_record_lifetime(key, &accepted.collection, upgraded.version, tx)?;
                    }
                    if upgraded != *held {
                        put_held(tx, &key, &upgraded)?;
                    }
                    if let Some(h) = placement.historical && !confirms {
                        return Ok(Taken::Historical(h));
                    }
                    self.observe_readable_record(&key, &upgraded, Some(held), accepted.observation, false, tx).await?;
                    return Ok(Taken::Equal);
                }
                if let Some(h) = placement.historical {
                    // Even an overtaken view can carry a matching proof for a followed item.
                    self.follow_write(&key, accepted.write, placement, tx).await?;
                    return Ok(Taken::Historical(h));
                }
                if let Order::Older(write) = placement.content {
                    if accepted.current_at.viewed() && accepted.write.version.version == held.version {
                        self.follow_write(&key, accepted.write, placement, tx).await?;
                    }
                    return Ok(Taken::Older(write));
                }
                // A proven create over a permanent record the app holds live: the switch let
                // the record go and took a create at `{0, 0}` in its place, which absence
                // would show had the app read it in between (Switch spec 10.3.1 "Absence").
                if accepted.write.version.authenticated
                    && accepted.write.version.expected_version.is_none()
                    && held.content != RecordContent::Deleted
                    && absence_is_rollback(
                        &held.policy,
                        held.live_in,
                        self.state.meta.generation,
                        self.state.own_doc.body().recovery_from,
                    )
                {
                    let reason =
                        "Switch spec 10.3.1: a create over a permanent record seen live".into();
                    return Err(Box::pin(self.raise(Alarm::Rollback { reason })).await);
                }
            }
            let new_value = accepted.content.value();
            // What the write builds on, and whether the app holds it (Switch spec 8.2, 10.3).
            let expected_version = accepted.write.version.expected_version;
            // The write was verified before it got here, so its operation reads; its conditions
            // are the ones it signed (Switch wire 6.3).
            let conditions = SignedOp::peek(&accepted.op)
                .map(|op| op.body().conditions.clone())
                .unwrap_or_default();
            let base = WriteBase {
                repair: None,
                expected_version,
                held: match &held {
                    // A create applies only where the service holds nothing: over a delete
                    // this app holds, it follows the service forgetting that delete (Switch wire
                    // 6.2), so it builds on the absence the delete left.
                    Some(held) if expected_version.is_none() => {
                        held.content == RecordContent::Deleted
                    }
                    Some(held) => held.version == expected_version,
                    None => expected_version.is_none(),
                },
                conditions,
                written_at_ms: accepted.time,
            };
            // A write by this app is its own, also when the feed or a view shows it before its
            // answer, or another device of the app made it: one app is one principal (Switch
            // spec 3.1). An owner can qualify its mark against this key on either
            // device. The ordinary regression report names only another app.
            let own = settling_own || accepted.writer == self.state.meta.app_id;
            // Every write of another app the app would take is checked, the first of a
            // record included, against nothing seen yet (Switch spec 8.2).
            let (marked_value, regression, name_writer) = match qualified {
                Some(_) if !qualifiable => (None, Some("record evidence is not current and qualified".to_owned()), false),
                Some(Ok(mark)) if mark.len() > MAX_SEEN_MARK_BYTES => (None, Some("the qualified record mark exceeds the client limit".to_owned()), false),
                Some(Ok(mark)) => (Some(mark), None, false),
                Some(Err(reason)) => (None, Some(reason), !own),
                None => (None, (!own).then(|| self.protocols.record_regression(
                    &accepted.collection.name, prior_mark, new_value, WriteBase { repair, ..base.clone() },
                )).flatten(), true),
            };
            if !own && accepted.content == RecordContent::Deleted
                && let Some(owner) = self.protocols.of_collection(&accepted.collection.name) {
                let needed = held.as_ref().and_then(|h| h.base(&key, self.state.own_doc.body().recovery_from).1);
                let predecessor = held.as_ref().filter(|h| h.authenticated
                    && h.policy == accepted.collection.policy && h.content.value().is_some())
                    .map(|h| super::deletion::Predecessor {
                        source: KeptOp { op: h.op.clone(), cert: h.cert.clone(), proof: h.proof.clone() },
                        dated_at_expected: !h.doubtful && h.version == expected_version,
                        exact: h.version == expected_version && h.follow.is_none() && !h.gone
                            && needed.as_ref().is_none_or(|c| base.conditions.contains(c))
                            && base.conditions.iter().all(|c| !matches!(c, Condition::RecordCurrent {
                                key: k, revision, deleted, .. } if *k == key && (*revision != h.applied || *deleted))),
                    });
                let hold = super::deletion::Observation {
                    key, owner: owner.name.clone(), collection: accepted.collection.name.clone(),
                    delete: DeleteBase { version: accepted.write.version.version, item_hash: accepted.write.applied.item_hash },
                    operation: accepted.op.clone(), cert: accepted.cert.signed().clone(),
                    authenticated: accepted.write.version.authenticated && !accepted.doubtful, proof: accepted.write.proof.clone(),
                    generation: accepted.write.applied.generation, seq: accepted.write.applied.seq,
                    page_time_ms,
                    seen: seen.clone(), held: base.held, written_at_ms: base.written_at_ms, predecessor,
                };
                if held.as_ref().and_then(HeldRecord::delete_base) != Some(hold.delete) && !self.state.deletions.contains_key(&hold.id())
                    && !self.state.deletion_receipts.contains_key(&hold.id()) && !self.state.put_backs.contains_key(&hold.id()) {
                    self.take_put_back_observation(self.deletion_hold(hold), tx)?;
                }
            }
            if let Some(reason) = regression {
                let shown = Shown {
                    key,
                    version: accepted.write.version.version,
                    write: accepted.write.applied.item_hash,
                };
                accepted.write.named = name_writer;
                // With nothing held, there is no version to follow the refused write from:
                // it is held for its version only, its value not trusted
                // ([`Unopened::Refused`]), and followed as itself, a delete included, so the
                // record reads as flagged and the next write builds on it, or creates the
                // record once the service forgot that delete (Switch spec 8.2, 10.3).
                if held.is_none() {
                    let refused = HeldRecord {
                        collection: accepted.collection.name.clone(),
                        policy: accepted.collection.policy.clone(),
                        op: accepted.op.clone(),
                        cert: accepted.cert.signed().clone(),
                        proof: accepted.write.proof.clone(),
                        version: accepted.write.version.version,
                        authenticated: accepted.write.version.authenticated,
                        expected: accepted.write.version.expected_version,
                        written_at_ms: accepted.time,
                        writer: accepted.writer,
                        item_hash: accepted.write.applied.item_hash,
                        content: RecordContent::Unreadable(Unopened::Refused),
                        doubtful: accepted.doubtful,
                        applied: accepted.write.applied,
                        follow: Some(accepted.write.clone()),
                        observed,
                        gone: false,
                        live_in: None,
                    };
                    put_held(tx, &key, &refused)?;
                } else {
                    self.follow_write(&key, accepted.write, placement, tx).await?;
                }
                if name_writer {
                    self.flag_write(shown, accepted.writer, reason, tx).await?;
                } else {
                    self.events.push(AppEvent::RecordChanged { key });
                }
                return Ok(Taken::Flagged);
            }
            // What the app saw of a record stays seen after its own delete (Switch spec 8.2):
            // the mark it holds stays, so a write that brings the record back without it is
            // checked against it. So does an own write this device can't read yet, such as
            // another device's at a data epoch whose key it hasn't fetched: the mark is set from
            // its value when the key comes and the record reopens (`reopen_unreadable`), which
            // takes it here again. Any other own write marks from the value it wrote.
            let keeps_mark = (own && (accepted.content == RecordContent::Deleted || accepted.content.waits_for_key()))
                || (lifetime_mark && new_value.is_none());
            let marked = if marked_value.is_some() {
                marked_value
            } else if keeps_mark {
                None
            } else {
                self.protocols.record_seen(
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
                    let to = self.owners_of_collection(&accepted.collection.name);
                    self.keep_duty_for(
                        tx,
                        to,
                        Duty::RecordUncheckable {
                            key,
                            writer: accepted.writer,
                            generation: accepted.write.version.version.generation,
                            version: accepted.write.version.version.version,
                            mark_bytes: u64::try_from(mark.len()).unwrap_or(u64::MAX),
                        },
                    )?;
                }
                Some(mark) => tx.put(&seen_key(&key), &SeenMark { mark })?,
                None if ends_mark => self.end_record_lifetime(key, &accepted.collection, accepted.write.version.version, tx)?,
                None if own && !keeps_mark => tx.delete(&seen_key(&key))?,
                None => {}
            }
            let live_in = self.live_in(
                &accepted.collection.policy,
                &accepted.content,
                held.as_ref().and_then(|held| held.live_in),
            );
            let record = HeldRecord {
                live_in,
                collection: accepted.collection.name.clone(),
                policy: accepted.collection.policy.clone(),
                op: accepted.op,
                cert: accepted.cert.signed().clone(),
                proof: accepted.write.proof,
                version: accepted.write.version.version,
                authenticated: accepted.write.version.authenticated,
                expected: accepted.write.version.expected_version,
                written_at_ms: accepted.time,
                writer: accepted.writer,
                item_hash: accepted.write.applied.item_hash,
                content: accepted.content,
                doubtful: accepted.doubtful,
                applied: held.as_ref().filter(|_| reopened && !selects_base).map_or(accepted.write.applied, |h| h.applied),
                follow: held.as_ref().and_then(|h| h.follow.clone()).filter(|_| !selects_base),
                observed: held.as_ref().filter(|_| !selects_base).map_or(observed, |h| h.observed),
                gone: !selects_base && held.as_ref().is_some_and(|h| h.gone),
            };
            if placement.historical.is_none() {
                self.observe_readable_record(&key, &record, held.as_ref(), accepted.observation, !reopened, tx).await?;
            }
            put_held(tx, &key, &record)?;
            self.events.push(AppEvent::RecordChanged { key });
            Ok(if let Some(h) = placement.historical {
                Taken::Historical(h)
            } else if reopened {
                Taken::Reopened
            } else {
                Taken::New
            })
        })
        .await;
        if result.is_err() {
            self.reload = true;
        }
        result
    }

    async fn record_source_current(
        &self,
        key: &[u8; 32],
        collection: &str,
        source: ObservationSource,
        applied: ApplicationRef,
        observed: FeedPosition,
        tx: &Tx,
    ) -> Result<bool, AppError> {
        let at = match source {
            ObservationSource::View { at, .. } => at,
            ObservationSource::Applied => Some(position(applied.generation, applied.seq)),
            ObservationSource::Reopened => Some(observed),
        };
        let current = if let Some(at) = at.filter(|at| at.generation == self.state.meta.generation)
        {
            // A prior item in this transaction may have raised the minimum for this
            // collection or key since the service read began.
            let listing = self.read_in::<ListDue>(LIST_DUE, tx).await?;
            self.covers_uploads(
                at,
                [
                    self.record_upload_in(key, tx).await?,
                    self.upload_for_collection(collection, listing),
                ],
            )
        } else {
            false
        };
        Ok(current)
    }

    /// Commit what the collection owner learned with the accepted record. A protocol
    /// can derive its physical target through the context and carry its own qualified
    /// observations across a selected backup (Switch spec 8.2, 12.4).
    async fn observe_readable_record(
        &self,
        key: &[u8; 32],
        record: &HeldRecord,
        previous: Option<&HeldRecord>,
        source: ObservationSource,
        newer: bool,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        if !record.authenticated || record.content.value().is_none() {
            return Ok(());
        }
        let Some(owner) = self.protocols.of_collection(&record.collection) else {
            return Ok(());
        };
        let prior_divergence = match tx.pending_state(&super::uploaded::divergent_key(key)) {
            Some(held) => held,
            None => self.is_divergent(key).await?,
        };
        let current = self
            .record_source_current(
                key,
                &record.collection,
                source,
                record.applied,
                record.observed,
                tx,
            )
            .await?;
        let divergent = source.divergent(current, prior_divergence, newer);
        let accepted = record.shared(key, divergent);
        let before = previous.map(|held| held.shared(key, prior_divergence));
        let input = super::RecordObservation {
            record: &accepted,
            previous: before.as_ref(),
            operation: &record.op,
            application: record.applied,
            current,
        };
        let context = super::ReceiveContext::new(
            &self.state,
            &self.protocols,
            &owner.name,
            self.env.store.store().as_ref(),
            &self.ns,
            false,
            &[],
            tx.pending_local(),
            tx.pending_writes(),
        );
        let local = owner
            .protocol
            .observe_record(&input, &context)
            .map_err(AppError::Protocol)?;
        let bytes = super::local_writes_bytes(&local);
        if bytes > super::MAX_STEP_LOCAL_BYTES {
            return Err(crate::error::StoreError::TooLarge {
                size: u64::try_from(bytes).unwrap_or(u64::MAX),
                cap: super::MAX_STEP_LOCAL_BYTES as u64,
            }
            .into());
        }
        tx.local(&super::protocols::qualify(&owner.name, local))
    }

    /// The collection as held, registered, or named when building an own write.
    async fn collection_for_write(
        &self,
        put: &RecordPut,
        tx: &Tx,
    ) -> Result<Option<Collection>, AppError> {
        if let Some(held) = self
            .read_in::<HeldRecord>(&record_key_of(&put.key), tx)
            .await?
        {
            return Ok(Some(Collection::new(&held.collection, held.policy)));
        }
        if let Some(collection) = self.collection_of(put) {
            return Ok(Some(collection));
        }
        Ok(self
            .reader()
            .get::<String>(&pending_name_key(&put.key))
            .await?
            .map(|name| Collection::new(&name, put.policy.clone())))
    }

    /// The newest generation a record at `policy` was seen live in, once it is seen with
    /// `content` in the generation the app follows: that one for a live record at a
    /// permanent policy, else `held` (Switch spec 10.3.1 "Absence").
    fn live_in(&self, policy: &Policy, content: &RecordContent, held: Option<u64>) -> Option<u64> {
        if policy.permanent.is_none() || *content == RecordContent::Deleted {
            return held;
        }
        let now = self.state.meta.generation;
        Some(held.map_or(now, |held| held.max(now)))
    }

    /// Apply a signed absence according to what the request could return. A listing
    /// covers live records. Only a key answer also covers a retained deletion
    /// (Switch spec 10.3.1 "Absence", Switch wire 7.4.9).
    ///
    /// # Errors
    ///
    /// The alarm; a store failure.
    pub(super) async fn note_absent(
        &mut self,
        key: &[u8; 32],
        current: CurrentAt,
        from: MissingFrom,
        tx: &mut Tx,
    ) -> Result<bool, AppError> {
        let CurrentAt::Answer(v) = current else {
            return Ok(false);
        };
        let at = position(v.generation, v.version);
        if self
            .record_upload(key)
            .await?
            .is_some_and(|upload| !self.covers_upload(at, upload))
        {
            return Ok(false);
        }
        let held = self.read_in::<HeldRecord>(&record_key_of(key), tx).await?;
        if let Some(held) = &held
            && self
                .listing_upload(&held.collection)
                .await?
                .is_some_and(|upload| !self.covers_upload(at, upload))
        {
            return Ok(false);
        }
        // A protected delete must still exist throughout its protected interval,
        // including before a later observation of the same key (Switch spec 10.3).
        let can_report_absence = v.generation == self.state.meta.generation
            && (from == MissingFrom::LiveListing
                || self.put_back_absence_is_current(key, at).await?);
        let current = can_report_absence
            && held.as_ref().is_none_or(|held| {
                let (_, applied, _) = held.base_write();
                self.state.cert.holds_scope(&held.policy.read_scope)
                    && self.covers(at, held.observed)
                    && self.covers(at, position(held.applied.generation, held.applied.seq))
                    && self.covers(at, position(applied.generation, applied.seq))
            });
        if let Some(mut held) = held.filter(|_| current) {
            self.check_absent(&held, at.generation).await?;
            if from == MissingFrom::Key
                && held.delete_base().is_some()
                && (!held.gone || held.observed != at)
            {
                held.gone = true;
                held.observed = at;
                put_held(tx, key, &held)?;
            }
        }
        if from == MissingFrom::Key {
            self.retire_absent_receipts(*key, at, tx)?;
        }
        Ok(current)
    }

    async fn check_absent(&mut self, held: &HeldRecord, generation: u64) -> Result<(), AppError> {
        // The switch shows only records whose read scope the caller's certificate covers:
        // one the app no longer reads, after a renewal that dropped its scope, is left out
        // of a listing as any record it can't read is (Switch wire 7.4.9).
        if held.content != RecordContent::Deleted
            && self.state.cert.holds_scope(&held.policy.read_scope)
            && absence_is_rollback(
                &held.policy,
                held.live_in.filter(|seen| *seen <= generation),
                generation,
                self.state
                    .own_doc
                    .body()
                    .recovery_from
                    .filter(|lost| *lost < generation),
            )
        {
            let reason = "Switch spec 10.3.1: a permanent record seen live reads absent".into();
            return Err(Box::pin(self.raise(Alarm::Rollback { reason })).await);
        }
        Ok(())
    }

    /// [`App::note_absent`] for each record of `collection` the app holds whose key a
    /// listing page covered, after `after` and through `last` (to the end for `None`), and
    /// that the page didn't list.
    ///
    /// Check the index of permanent records held live (`recp/`). Deleted keys are
    /// normally absent from these pages (Switch wire 7.4.9).
    async fn note_unlisted(
        &mut self,
        collection: &str,
        (after, last): (Option<&[u8; 32]>, Option<&[u8; 32]>),
        listed: &[[u8; 32]],
        at: CurrentAt,
        upload_at: FeedPosition,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let (after, last) = (after.map(|k| b64(k)), last.map(|k| b64(k)));
        for (rest, of) in self.reader().scan::<String>(PERMANENT_PREFIX).await? {
            if of != collection
                || after.as_ref().is_some_and(|after| rest <= *after)
                || last.as_ref().is_some_and(|last| rest > *last)
            {
                continue;
            }
            let key = unb64_array::<32>(&rest).map_err(|_| store_corrupt())?;
            if !listed.contains(&key)
                && self
                    .record_upload(&key)
                    .await?
                    .is_none_or(|upload| self.covers_upload(upload_at, upload))
            {
                let mut omitted = Tx::new(&self.ns);
                Box::pin(self.note_absent(&key, at, MissingFrom::LiveListing, &mut omitted))
                    .await?;
                self.append_listing_writes(tx, omitted).await?;
            }
        }
        Ok(())
    }

    /// Flush earlier records only when adding the next listing writes would exceed a batch.
    async fn append_listing_writes(&mut self, tx: &mut Tx, writes: Tx) -> Result<(), AppError> {
        if tx.size().saturating_add(writes.size()) > crate::store::MAX_BATCH_BYTES {
            let full = std::mem::replace(tx, self.tx()?);
            self.commit(full).await?;
        }
        tx.append(writes)
    }

    /// A pending observation may finish after the app settled an own write or read
    /// the deletion as gone. Keep the owner's evidence while retiring the acknowledgement.
    pub(super) async fn retire_completed_deletion(
        &mut self,
        key: [u8; 32],
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        if let Some(held) = self.held_record(&key).await? {
            if held.gone {
                self.retire_deletion_receipts(key, None, tx)?;
            } else if held.authenticated {
                self.retire_deletion_receipts(key, Some((held.item_hash, held.version)), tx)?;
            }
        }
        Ok(())
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
        let Some(collection) = self.collection_for_write(put, tx).await? else {
            return Ok(());
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
            view_revision: None,
            current_at: CurrentAt::Itself,
            observation: ObservationSource::Applied,
        };
        let key = put.key;
        let observed = match self
            .accept_write(&evidence, Some((&key, &collection)), tx)
            .await?
        {
            Ok(accepted) => {
                // The app's own write at this service clears the record's divergent
                // uploads there (Switch wire 7.4.14).
                if self.take_write(accepted, true, None, None, tx).await? == Taken::New {
                    self.note_divergent(&key, false, tx).await?;
                }
                WriteRead::Taken
            }
            Err(Refused::Misbehaviour(reason)) => {
                return Err(self.raise(Alarm::Rollback { reason }).await);
            }
            Err(_) => WriteRead::Refused,
        };
        self.observe_collection_write(put, proof.envelope(), observed, tx)
            .await?;
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // Writes

    /// The `record.put` of `value` at `target`, with `conditions`: built on the version the
    /// app holds, a delete's included, with the `record_current` that names it when it was
    /// taken from a recovery upload, or a create (`{0, 0}`) for a record it
    /// holds nothing of or whose delete a read found forgotten, sealed under the read scope's
    /// key at the current data epoch (Switch spec 3.5, 10.3, 13.4). `None` writes a delete.
    /// To go in a batch ([`OpBatch::entry`]).
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
            let key = self.record_key(target)?;
            if let Some(value) = value {
                let seen = self.record_seen(&key).await?;
                refuse_unmarkable(
                    &self.protocols,
                    &self.state.naming,
                    key,
                    &target.collection,
                    value,
                    seen.as_deref(),
                )?;
            }
            let held = self.held_record(&key).await?;
            let (put, named) = record_put(&self.state, target, value, held.as_ref())?;
            Ok((with_named(conditions, named), OpKind::RecordPut(put)))
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
    /// The call never writes over a delete `change` wasn't asked on: when a try finds the
    /// record built on another delete than the one the call started from, or a delete where
    /// it started from a value or from nothing, it returns the `409 conflict` it last met
    /// instead of calling `change` with `None`, and the caller decides again from what the
    /// app now holds (Switch spec 10.3).
    ///
    /// The app makes at most four update tries. Each further try must begin within
    /// [`super::AppConfig::call_budget_ms`] (20 s by default). Across these tries the
    /// app can read the service time once and resubmit one kept batch. Each try can
    /// submit its own batch and read the held record after a conflict. Record writes
    /// and reads use the bulk timeout because they can return a full record view.
    /// Each HTTP send has its own deadline. A timestamp correction or the recovery
    /// cases described by [`App::submit_batch`] can add sends.
    ///
    /// # Errors
    ///
    /// As [`App::put_record`]; [`Refusal::NotNow`] while the held value waits for its key;
    /// `409 conflict` when the record kept changing, or when the budget ran out first.
    pub async fn update_record(
        &mut self,
        target: &RecordTarget,
        conditions: Vec<Condition>,
        change: impl FnMut(Option<&[u8]>) -> Option<Vec<u8>> + Send,
    ) -> Result<Option<SharedRecord>, AppError> {
        Box::pin(async move {
            match self
                .update_record_on(target, conditions, None, change)
                .await?
            {
                Updated::Written(record) => Ok(record),
                Updated::Stopped { last, .. } => Err(last.unwrap_or_else(|| {
                    AppError::Switch(ClientError::Usage(
                        "the record was deleted since the call began".into(),
                    ))
                })),
            }
        })
        .await
    }

    /// [`App::update_record`] from `base`, the delete the record's next write built on when
    /// its caller decided to write (`Some(None)` for none), or, for `None`, the one it
    /// builds on when the call begins. Each try first compares the delete the next write
    /// would build on with that base ([`HeldRecord::delete_base`]), by its version and its
    /// operation: another one, also one at the base's version, or a delete where the base
    /// was none, stops the call before anything is written over it (Switch spec 10.3, 12.6
    /// step 3). A delete the service forgot since still counts as that delete.
    pub(crate) async fn update_record_on(
        &mut self,
        target: &RecordTarget,
        conditions: Vec<Condition>,
        base: Option<Option<DeleteBase>>,
        mut change: impl FnMut(Option<&[u8]>) -> Option<Vec<u8>> + Send,
    ) -> Result<Updated, AppError> {
        Box::pin(async move {
            let key = self.record_key(target)?;
            let budget = self.begin_budget();
            let mut last = None;
            let mut base = base;
            for attempt in 0..UPDATE_TRIES {
                // A further try only within the call's time budget: past it the call returns
                // the conflict it last met.
                if attempt > 0 && self.spent(&budget) {
                    break;
                }
                let now = self
                    .held_record(&key)
                    .await?
                    .and_then(|held| held.delete_base());
                let from = *base.get_or_insert(now);
                if let Some(deleted) = now
                    && from != now
                {
                    return Ok(Updated::Stopped { deleted, last });
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
                    return Ok(Updated::Written(None));
                };
                match self
                    .write_record(target, Some(&next), conditions.clone(), attempt > 0)
                    .await
                {
                    Ok(record) => return Ok(Updated::Written(Some(record))),
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
    /// Returns whether the item waits: a record write whose protocol isn't told through
    /// everything before it ([`WriteRead::Waits`]), which the read holds.
    pub(crate) async fn feed_shared_item(
        &mut self,
        item: &ChainItem,
        envelope: &ChainEnvelope,
        page_time_ms: u64,
        tx: &mut Tx,
    ) -> Result<bool, AppError> {
        let Ok(op) = SignedOp::peek(&item.item) else {
            return Ok(false);
        };
        match &op.body().kind {
            OpKind::RecordPut(_) => Ok(self
                .feed_record_write(item, envelope, page_time_ms, tx)
                .await?
                == WriteRead::Waits),
            OpKind::Claim(_) => self
                .feed_claim_entry(item, envelope, tx)
                .await
                .map(|()| false),
            OpKind::AppPut { record } => {
                self.feed_app_record(record, tx)?;
                Box::pin(self.take_own_later(record, tx)).await
            }
            _ => self.feed_list_change(item, tx).map(|()| false),
        }
    }

    /// The protocol a write is judged for ([`App::judge_write`]): the collection's asked
    /// for, else the record's as the app holds it or names it pending, else that of the
    /// protocol's collection the write names; `None` when none of them is a registered
    /// protocol's.
    async fn write_protocol(
        &self,
        evidence: &Evidence<'_>,
        expect: Option<(&[u8; 32], &Collection)>,
        shown_key: &[u8; 32],
        tx: &Tx,
    ) -> Result<Option<String>, AppError> {
        if let Some((_, collection)) = expect {
            return Ok(self
                .protocols
                .of_collection(&collection.name)
                .map(|registered| registered.name.clone()));
        }
        if let Some(name) = self.record_protocol_in(shown_key, tx).await? {
            return Ok(Some(name));
        }
        let named = SignedOp::peek(evidence.op)
            .ok()
            .and_then(|op| match &op.body().kind {
                OpKind::RecordPut(put) => self.collection_of(put),
                _ => None,
            });
        Ok(named.and_then(|collection| {
            self.protocols
                .of_collection(&collection.name)
                .map(|registered| registered.name.clone())
        }))
    }

    /// [`App::record_protocol`], `tx`'s writes included: a record taken in `tx` is placed by
    /// the collection it is taken in.
    pub(crate) async fn record_protocol_in(
        &self,
        key: &[u8; 32],
        tx: &Tx,
    ) -> Result<Option<String>, AppError> {
        let collection = match tx.pending_get::<HeldRecord>(&record_key_of(key))? {
            Some(Some(held)) => Some(held.collection),
            Some(None) => None,
            None => self.held_record(key).await?.map(|held| held.collection),
        };
        let collection = match collection {
            Some(name) => Some(name),
            None => match tx.pending_get::<String>(&pending_name_key(key))? {
                Some(name) => name,
                None => self.reader().get::<String>(&pending_name_key(key)).await?,
            },
        };
        Ok(collection.and_then(|name| {
            self.protocols
                .of_collection(&name)
                .map(|registered| registered.name.clone())
        }))
    }

    /// The protocol whose collection holds the record at `key`, as far as the app knows: the
    /// collection of the record it holds, or the one it noted for a record it creates;
    /// `None` when it knows neither, or no registered protocol owns the collection.
    pub(crate) async fn record_protocol(&self, key: &[u8; 32]) -> Result<Option<String>, AppError> {
        let collection = match self.held_record(key).await? {
            Some(held) => Some(held.collection),
            None => self.reader().get::<String>(&pending_name_key(key)).await?,
        };
        Ok(collection.and_then(|name| {
            self.protocols
                .of_collection(&name)
                .map(|registered| registered.name.clone())
        }))
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
}

/// Refuse a write by protocol `name` at a target that is another registered protocol's:
/// in a collection that protocol gives, or sealed under a scope whose root it owns. A
/// receive step and a protocol's batch write only that protocol's own records, so no step
/// of one protocol changes what another is told (Switch spec 3.3, 8.3).
pub(crate) fn refuse_foreign_target(
    protocols: &super::ProtocolSet,
    name: &str,
    target: &RecordTarget,
) -> Result<(), AppError> {
    let collection = &target.collection;
    match protocols.foreign_owner(name, Some(&collection.name), &collection.policy.read_scope) {
        Some(owner) => Err(Refusal::Usage(format!(
            "Switch spec 3.3: `{}` is a record of protocol `{owner}`, not of `{name}`",
            collection.name
        ))
        .into()),
        None => Ok(()),
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

/// Check a local value against its collection's target and mark before signing it.
/// The protocol must be able to retain the resulting mark within the client limit.
pub(crate) fn refuse_unmarkable(
    protocol: &super::ProtocolSet,
    naming: &pubky_switch_core::ident::NamingKey,
    key: [u8; 32],
    collection: &Collection,
    value: &[u8],
    seen: Option<&[u8]>,
) -> Result<(), AppError> {
    let input = super::RecordMarkContext {
        key,
        collection,
        naming,
    };
    let qualified = protocol
        .of_collection(&collection.name)
        .and_then(|owner| owner.protocol.qualify_record_mark(&input, seen, value));
    let mark = match qualified {
        Some(result) => Some(result.map_err(Refusal::Usage)?),
        None => protocol.record_seen(&collection.name, None, Some(value)),
    };
    match mark {
        Some(mark) if mark.len() > MAX_SEEN_MARK_BYTES => Err(Refusal::Usage(format!(
            "the protocol's mark of this write takes {} bytes, over {MAX_SEEN_MARK_BYTES}",
            mark.len()
        ))
        .into()),
        _ => Ok(()),
    }
}

/// The `record.put` of `value` at `target` (`None` a delete), built on `held`, the write the
/// app holds there ([`HeldRecord::base`]): on its version, a delete's included, or a create
/// (`{0, 0}`) for a record it holds nothing of or whose delete the service
/// forgot, sealed under the read scope's key at the current data epoch (Switch spec 3.5,
/// 10.3, 13.4). With it, the `record_current` the write must carry when its base names one.
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
) -> Result<(RecordPut, Option<Condition>), AppError> {
    let policy = target.concrete_policy()?;
    let identity = state.meta.identity;
    let key = state.naming.record_key(
        &target.collection.name,
        &target.natural_key,
        &policy.hash()?,
    );
    let lost = state.own_doc.body().recovery_from;
    let (base, named) = held.map_or((RecordVersion::NONE, None), |held| held.base(&key, lost));
    let sealed = seal_record(state, policy, base, &key, value)?;
    let id_inputs = IdInputs {
        collection: target.collection.name.clone(),
        blinded_key: state.naming.blind(&target.natural_key),
    };
    let put = RecordPut {
        key,
        collection: target.collection.id(&identity),
        policy: policy.clone(),
        expected_version: base,
        value_sealed: sealed,
        id_inputs,
    };
    Ok((put, named))
}

/// Seal a write to an existing key, whose natural key need not be known to the reader.
pub(super) fn seal_record(
    state: &super::AppState,
    policy: &Policy,
    base: RecordVersion,
    key: &[u8; 32],
    value: Option<&[u8]>,
) -> Result<SealedValue, AppError> {
    refuse_non_json(value)?;
    if !policy
        .write_scopes_for(base)
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
    Ok(SealedValue::seal(
        &scope_key,
        &identity,
        epoch,
        &policy.read_scope,
        key,
        value.unwrap_or_default(),
    )?)
}

/// The record material a failed write or condition may return (Switch wire 6.3, 7.6).
enum RecordConflict {
    View(Box<SharedRecordView>),
    Position,
    Absent([u8; 32]),
}

impl RecordConflict {
    fn read(current: &serde_json::Value, batch: &Batch) -> Result<Option<Self>, ClientError> {
        let what = "Switch wire 6.3: the current record of a write conflict";
        let unbound = || {
            ClientError::InvalidResponse(
                "Switch wire 6.3: the conflict does not match a submitted write or condition"
                    .into(),
            )
        };
        let conditions = || batch.ops().iter().flat_map(|op| &op.body().conditions);
        let record = current.get("record");
        let position = current.get("record_version");
        let view = current.get("record_view");
        let read_position = |shown| -> Result<_, ClientError> {
            let o = Obj::of(shown, what)?;
            Ok((
                o.b64n::<32>("key")?,
                RecordVersion::new(o.u64("generation")?, o.u64("version")?),
            ))
        };
        let read_view = |value| SharedRecordView::read(Obj::of(value, what)?);
        let record =
            match (record, position, view) {
                (None, None, None) => return Ok(None),
                // An app.put refusal also names "record": the signed app registration.
                (Some(_), None, None)
                    if batch
                        .ops()
                        .iter()
                        .any(|op| matches!(op.body().kind, OpKind::AppPut { .. })) =>
                {
                    return Ok(None);
                }
                (Some(shown), None, Some(view)) => {
                    let (key, version) = read_position(shown)?;
                    if !batch.ops().iter().any(
                        |op| matches!(&op.body().kind, OpKind::RecordPut(put) if put.key == key),
                    ) {
                        return Err(unbound());
                    }
                    if version.is_none() && view.is_null() {
                        Self::Absent(key)
                    } else {
                        let view = read_view(view)?;
                        if version.version == 0
                            || view.key != key
                            || version != RecordVersion::new(view.generation, view.version)
                        {
                            return Err(unbound());
                        }
                        Self::View(Box::new(view))
                    }
                }
                (None, None, Some(view)) => {
                    let view = read_view(view)?;
                    if !conditions().any(
                        |c| matches!(c, Condition::RecordCurrent { key, .. } if *key == view.key),
                    ) {
                        return Err(unbound());
                    }
                    Self::View(Box::new(view))
                }
                (None, Some(shown), None) => {
                    let (key, version) = read_position(shown)?;
                    if !conditions().any(|c| match c {
                        Condition::RecordVersion { key: asked, .. } => *asked == key,
                        Condition::RecordCurrent { key: asked, .. } => {
                            version.is_none() && *asked == key
                        }
                        _ => false,
                    }) || (version.version == 0 && !version.is_none())
                    {
                        return Err(unbound());
                    }
                    if version.is_none() {
                        Self::Absent(key)
                    } else {
                        Self::Position
                    }
                }
                _ => return Err(unbound()),
            };
        Ok(Some(record))
    }
}

/// The condition on record `key` a write depending on it carries
/// ([`super::App::record_condition`]), from `held`, the write the app holds there, and
/// `lost`, the own `identity.json`'s `recovery_from`.
pub(crate) fn record_condition(
    key: &[u8; 32],
    held: Option<&HeldRecord>,
    lost: Option<u64>,
) -> Condition {
    held.map_or(
        Condition::RecordVersion {
            key: *key,
            version: RecordVersion::NONE,
        },
        |held| held.condition(key, lost),
    )
}

/// `conditions` with `named`, the `record_current` a write's base names
/// ([`HeldRecord::base`]), unless the caller gave that very condition.
pub(crate) fn with_named(
    mut conditions: Vec<Condition>,
    named: Option<Condition>,
) -> Vec<Condition> {
    if let Some(named) = named
        && !conditions.contains(&named)
    {
        conditions.push(named);
    }
    conditions
}

/// Delete, with the keys on a leave, every record of the shared state, the outbox and the
/// sent messages that holds content or a bearer secret (Switch spec 3.1, 12.3), and the
/// kept batches with their ends and indexes, which no flush of a left app would prune.
pub(crate) fn destroy_shared(tx: &mut Tx) -> Result<(), AppError> {
    tx.delete(page_reader::READER_RENEWAL)?;
    for prefix in [
        RECORD_PREFIX,
        PERMANENT_PREFIX,
        SEEN_PREFIX,
        "recname/",
        "loss-data/",
        "loss-upload/",
        "out/",
        "sent/",
        "sentt/",
        "outgone/",
        "outhold/",
        "outheld/",
        "invite/",
        "opq/",
        "kb/",
        "kbt/",
        "kbm/",
        "kba/",
        "clpage/",
        "clwrite/",
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

/// Whether a signed answer that shows a permanent record's key absent is a rollback (Switch
/// spec 10.3.1 "Absence"), for a record the app holds live at `policy`, last seen live in
/// generation `live_in`, while the app follows `generation` and its newest own
/// `identity.json` names `recovery_from`: not for an ordinary policy or one never seen live,
/// nor when the provider lost the record since (`recovery_from` at or past `live_in`), nor
/// once the account is past the generation the policy names.
pub(crate) fn absence_is_rollback(
    policy: &Policy,
    live_in: Option<u64>,
    generation: u64,
    recovery_from: Option<u64>,
) -> bool {
    let (Some(permanent), Some(seen)) = (policy.permanent, live_in) else {
        return false;
    };
    let lost_since = recovery_from.is_some_and(|lost| lost >= seen);
    let passed = permanent.generation.is_some_and(|named| generation > named);
    !lost_since && !passed
}

/// Step 3's checks that need no state: the policy is one the collection fixes (its fixed
/// policy, or a member of its family), the collection ID is the name's, the sealed value's
/// scope is the read scope, and both addresses derive from the signed inputs.
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
    if put.id_inputs.collection != collection.name || put.check_address(identity).is_err() {
        return Some("Switch wire 6.2 step 3: the key doesn't derive from its id_inputs");
    }
    None
}

fn store_corrupt() -> AppError {
    AppError::Store(crate::error::StoreError::Corrupt)
}

/// A protocol's rule, cut to [`MAX_REGRESSION_REASON_BYTES`] at a character boundary.
pub(crate) fn cut_reason(mut reason: String) -> String {
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
    use pubky_switch_core::ident::record_key_from_blinded;

    /// A record view is current in the generation of the head its answer carries, at the
    /// page's `seq` for a list page (Switch spec 10.3).
    #[test]
    fn test_records_current_at_is_the_heads_generation() {
        let head = SignedHead {
            chain_version: 1,
            generation: 2,
            seq: 40,
            chain_hash: [0; 32],
            sig: [0; 64],
        };
        assert_eq!(
            CurrentAt::of(&head, Some(3)),
            CurrentAt::Answer(RecordVersion::new(2, 3))
        );
        assert_eq!(
            CurrentAt::of(&head, None),
            CurrentAt::Answer(RecordVersion::new(2, 40))
        );
    }

    /// One comparison for every path that shows a write (Switch spec 10.1, 10.3): the same
    /// write by its item hash, a newer one, an older one by an answer current past the held
    /// write, an overtaken one, and the rollback, two authenticated
    /// versions by an answer current at or past the held one.
    #[test]
    fn test_records_compare_with_held_by_what_the_answer_is_current_at() {
        let v = RecordVersion::new;
        let write = |version, authenticated, expected| WriteVersion {
            version,
            authenticated,
            expected_version: expected,
        };
        let held = write(v(1, 10), true, v(1, 5));
        let held_unproven = write(v(1, 10), false, v(1, 9));
        let older = write(v(1, 8), true, v(1, 3));
        let older_unproven = write(v(1, 8), false, v(1, 3));
        let at_held = write(v(1, 10), true, v(1, 5));
        let shown = |w: WriteVersion| ShownWrite {
            version: w.version,
            authenticated: w.authenticated,
            item_hash: [2; 32],
            writer: [3; 16],
        };
        let rollback = Err(String::new());
        let cases = [
            (older, held, [1; 32], CurrentAt::Itself, Ok(Order::Equal)),
            (
                write(v(1, 12), true, v(1, 10)),
                held,
                [2; 32],
                CurrentAt::Answer(v(1, 12)),
                Ok(Order::Newer),
            ),
            (
                older,
                held,
                [2; 32],
                CurrentAt::Answer(v(1, 20)),
                rollback.clone(),
            ),
            (
                older,
                held,
                [2; 32],
                CurrentAt::Answer(v(1, 10)),
                rollback.clone(),
            ),
            (at_held, held, [2; 32], CurrentAt::Itself, rollback.clone()),
            (
                older,
                held,
                [2; 32],
                CurrentAt::Answer(v(1, 9)),
                Ok(Order::Overtaken(shown(older), v(1, 9))),
            ),
            (
                older,
                held,
                [2; 32],
                CurrentAt::Itself,
                Ok(Order::Overtaken(shown(older), v(1, 8))),
            ),
            (
                older_unproven,
                held,
                [2; 32],
                CurrentAt::Answer(v(1, 20)),
                Ok(Order::Older(shown(older_unproven))),
            ),
            (
                older,
                held_unproven,
                [2; 32],
                CurrentAt::Answer(v(1, 10)),
                Ok(Order::Older(shown(older))),
            ),
            (
                older,
                held_unproven,
                [2; 32],
                CurrentAt::Answer(v(1, 9)),
                Ok(Order::Overtaken(shown(older), v(1, 9))),
            ),
        ];
        for (i, (shown_write, held, hash, at, wanted)) in cases.into_iter().enumerate() {
            let got = compare_with_held(&shown_write, (hash, [3; 16]), &held, [1; 32], at)
                .map_err(|_| String::new());
            assert_eq!(got, wanted, "case {i}");
        }
    }

    #[test]
    fn test_permanent_sub_scope_policy_keeps_the_member() {
        let base = Policy::new("scope-a", &["scope-a"]);
        let kept = Collection::with_sub_scopes("sample.kept", base.clone().permanent(Some(3)));
        let policy = kept.sub_scope_policy("s1").unwrap();
        assert_eq!(policy.read_scope, "scope-a:s1");
        assert_eq!(policy.permanent, base.clone().permanent(Some(3)).permanent);
        assert!(kept.admits(&policy));
        let ordinary = Collection::with_sub_scopes("sample.items", base);
        assert_eq!(ordinary.sub_scope_policy("s1").unwrap().permanent, None);
    }

    #[test]
    fn test_permanent_absence_by_generation() {
        let ordinary = Policy::new("scope-a", &["scope-a"]);
        let none = ordinary.clone().permanent(None);
        let named = ordinary.clone().permanent(Some(2));
        // (policy, live in, generation followed, recovery_from, rollback)
        let cases = [
            (&ordinary, Some(1), 1, None, false),
            (&none, None, 1, None, false),
            (&none, Some(1), 1, None, true),
            // A move carries every record: absent after it is a rollback too.
            (&none, Some(1), 2, None, true),
            // Lost with the provider, and an upload may bring it back.
            (&none, Some(1), 2, Some(1), false),
            (&none, Some(2), 3, Some(2), false),
            // Seen live after the loss: the new switch lost it.
            (&none, Some(2), 2, Some(1), true),
            (&named, Some(2), 2, None, true),
            (&named, Some(2), 3, None, false),
        ];
        for (policy, live_in, generation, recovery_from, rollback) in cases {
            assert_eq!(
                absence_is_rollback(policy, live_in, generation, recovery_from),
                rollback,
                "{policy:?} {live_in:?} {generation} {recovery_from:?}"
            );
        }
    }

    fn collection() -> Collection {
        Collection::new("sample.items", Policy::new("scope-a", &["scope-a"]))
    }

    #[test]
    fn test_records_shape_refuses_another_policy() {
        let identity = [1; 32];
        let other = Collection::new("sample.items", Policy::new("scope-b", &["scope-b"]));
        let blinded_key = [2; 32];
        let key = record_key_from_blinded(&other.name, &blinded_key, &other.policy.hash().unwrap());
        let put = RecordPut {
            key,
            collection: other.id(&identity),
            policy: other.policy.clone(),
            expected_version: RecordVersion::new(1, 4),
            value_sealed: SealedValue::seal(&[3; 32], &identity, 1, "scope-b", &key, b"{}")
                .unwrap(),
            id_inputs: IdInputs {
                collection: other.name.clone(),
                blinded_key,
            },
        };
        assert!(check_shape(&put, &collection(), &identity).is_some());
        assert!(check_shape(&put, &other, &identity).is_none());
    }

    #[test]
    fn test_records_shape_checks_key_derivation_on_create_and_update() {
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
            id_inputs: IdInputs {
                collection: c.name.clone(),
                blinded_key: blinded,
            },
        };
        for base in [RecordVersion::NONE, RecordVersion::new(1, 4)] {
            put.expected_version = base;
            put.id_inputs.blinded_key = blinded;
            assert!(check_shape(&put, &c, &identity).is_none());
            put.id_inputs.blinded_key = [8; 32];
            assert!(check_shape(&put, &c, &identity).is_some());
        }
    }

    #[test]
    fn test_records_content_debug_shows_no_value() {
        let content = RecordContent::Value(b"secret".to_vec());
        assert_eq!(format!("{content:?}"), "Value(6 bytes)");
        let target = RecordTarget::new(collection(), b"secret-natural");
        assert!(!format!("{target:?}").contains("secret"));
    }
}
