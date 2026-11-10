//! The parts of an export chunk (Switch wire 10.3): every kind, read as the table gives its
//! members and written in the order the old service writes them.
//!
//! Reading follows Switch wire 10.3: every listed member is present, except that one marked
//! "or `null`" may also be absent, which reads as `null`, and one marked "absent otherwise"
//! is present only in the case named. Unknown members are ignored, as in every export part
//! (Switch wire 1.1), with two exceptions that keep an earlier exporter's state from
//! vanishing unseen: an `app` part with `key_bundles` and a `claim` part whose claim has
//! `entries` are refused, whatever the member holds. Times without a `_ms` or `_s` suffix are
//! times of Switch wire 1.6. A part that doesn't read is `400 bad_request`; signatures are
//! checked later, in the order of Switch wire 10.5.
//!
//! Writing puts each part's members in the order of its row of the table, and the members of
//! the service's own state objects (`claim`, `tombstone`, `record`, a batch's `record`, an
//! entry's `result` and each attempt) sorted by name.

use serde_json::Value;

use super::bad;
use crate::chain::{ItemType, Stub};
use crate::claims::{Outcome, Pin};
use crate::enc::{app_id_decode, b64, pubky_id, pubky_key, unb64, unb64_array, zbase32_encode};
use crate::error::{Error, Result};
use crate::json::MAX_INT;
use crate::ops::body::{Obj, array, carrying, string_array};
use crate::ops::{RecordVersion, Refusal};
use crate::records::KeyBundle;
use crate::sig::SignedDoc;
use crate::time::{parse_rfc3339, rfc3339};

/// Who wrote a conversation entry: an app, or the service itself for an entry an invite code
/// created (Switch wire 10.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Writer {
    /// The App ID of the writing app.
    App([u8; 16]),
    /// `service`.
    Service,
}

/// The `meta` part: the account-wide values, always the first part (Switch wire 10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaPart {
    /// The newest signed `identity.json`.
    pub identity: SignedDoc,
    /// The generation g.
    pub generation: u64,
    /// The last `seq` given out, entries and chain items.
    pub seq: u64,
    /// The directory version (Switch wire 7.4.10).
    pub directory_version: u64,
    /// The apps version (Switch wire 7.4.10).
    pub apps_version: u64,
    /// Each app reachable now, with the `apps_version` at which it became reachable.
    pub app_added_at: Vec<([u8; 16], u64)>,
}

/// A `chain` part: one stub the old service keeps, with its document while it keeps that
/// (Switch wire 10.3).
#[derive(Clone, Debug, PartialEq)]
pub struct ChainPart {
    /// The item's `seq`.
    pub seq: u64,
    /// The stub (Switch wire 6.6).
    pub stub: Stub,
    /// The item's type.
    pub item_type: ItemType,
    /// The signed document, `None` once the old service dropped it (Switch wire 7.5).
    pub doc: Option<SignedDoc>,
    /// The invite code context of a service-written conversation entry, else `null`.
    pub context: Value,
}

/// A `missed` item's counts (Switch wire 7.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Missed {
    /// The entries deleted before their target read them.
    pub entries: u64,
    /// The first acceptance time among them, in Unix milliseconds.
    pub from_ms: u64,
    /// The last acceptance time among them, in Unix milliseconds.
    pub until_ms: u64,
}

/// An inbox entry's original append answer, which a retry by content gets (Switch wire
/// 7.4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryResult {
    /// The entry ID.
    pub entry_id: [u8; 16],
    /// When the entry was accepted, in Unix milliseconds.
    pub accepted_at: u64,
    /// The directory version the answer named.
    pub directory_version: u64,
}

/// An `entry` part: one pending inbox entry (Switch wire 10.3).
#[derive(Clone, Debug, PartialEq)]
pub struct EntryPart {
    /// The entry's `seq`.
    pub seq: u64,
    /// The sender's Pubky ID.
    pub sender: [u8; 32],
    /// The sender app's certificate.
    pub cert: SignedDoc,
    /// When the entry was accepted, in Unix milliseconds.
    pub accepted_at_ms: u64,
    /// The invite code context, or `null`.
    pub context: Value,
    /// The envelope; empty for an unreadable entry.
    pub envelope: Vec<u8>,
    /// The target apps.
    pub targets: Vec<[u8; 16]>,
    /// The original append answer.
    pub result: EntryResult,
    /// Whether the entry is unreadable.
    pub unreadable: bool,
    /// The counts of a `missed` item, for one only.
    pub missed: Option<Missed>,
}

/// An `app` part: one app the service holds, or a purged app's tombstone (Switch wire 10.3,
/// 9.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppPart {
    /// The App ID.
    pub app_id: [u8; 16],
    /// The signed app record.
    pub record: Option<SignedDoc>,
    /// The `seq` of its `app.put`.
    pub record_seq: Option<u64>,
    /// The time of its `app.put`, in Unix milliseconds.
    pub record_at_ms: Option<u64>,
    /// The receive key records with their `seq`s, oldest first, the last current.
    pub receive_keys: Vec<(SignedDoc, u64)>,
    /// The cursor, 0 before the app's first cursor move.
    pub cursor: u64,
    /// When the app was last seen, in Unix milliseconds.
    pub last_seen_ms: Option<u64>,
    /// When it was revoked.
    pub revoked_at_ms: Option<u64>,
    /// When it departed.
    pub departed_at_ms: Option<u64>,
    /// The data epoch at its departure.
    pub departure_epoch: Option<u64>,
    /// Whether the rotation after its departure is done.
    pub rotated: bool,
    /// A renewed certificate the record doesn't carry yet, with the `seq` of its `cert.put`.
    pub renewed_cert: Option<(SignedDoc, u64)>,
    /// Whether the app is marked lagging.
    pub lagging: bool,
    /// The data epoch the app holds every key through.
    pub keys_through: Option<u64>,
    /// When the app asked for a full bundle, in Unix milliseconds.
    pub full_bundle_requested_ms: Option<u64>,
}

/// A `key_bundle` part: one key bundle part the service stores for an app, right after the
/// app's part (Switch wire 10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBundlePart {
    /// The app it is stored for.
    pub app_id: [u8; 16],
    /// The signed, sealed part.
    pub bundle: KeyBundle,
    /// The `seq` of its `key_bundle.put`.
    pub seq: u64,
    /// Its first data epoch.
    pub first_epoch: u64,
    /// Its last data epoch.
    pub last_epoch: u64,
}

/// An attempt in a `claim` or `tombstone` part (Switch wire 10.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptState {
    /// The attempt ID.
    pub attempt_id: [u8; 16],
    /// The App ID of its owner.
    pub owner: [u8; 16],
    /// Its outcome.
    pub outcome: Outcome,
    /// The service time of its `attempt`, in Unix milliseconds.
    pub opened_at_ms: u64,
    /// Seconds after which it is orphaned while open.
    pub orphan_after_s: u64,
    /// Row 1's flag (Switch wire 6.8).
    pub possibly_duplicate: bool,
    /// Row 2's flag (Switch wire 6.8).
    pub duplicate: bool,
    /// The deadline it named, in Unix milliseconds.
    pub deadline_ms: Option<u64>,
    /// Rebuilt from a recovery upload, so always orphaned.
    pub from_upload: bool,
    /// The App ID that wrote its outcome; absent while open.
    pub resolved_by: Option<[u8; 16]>,
}

/// A live claim's state in a `claim` part (Switch wire 10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimState {
    /// The number of entries.
    pub step: u64,
    /// Every attempt, oldest first.
    pub attempts: Vec<AttemptState>,
    /// The current attempt.
    pub current: Option<[u8; 16]>,
    /// Whether an attempt is done.
    pub settled: bool,
    /// Whether uploads after a provider loss conflict.
    pub divergent: bool,
    /// The deadline the first attempt pinned: absent before any attempt, `null` for a pin to
    /// "none".
    pub pinned_deadline: Pin,
    /// Rebuilt from uploads after a provider loss.
    pub rebuilt: bool,
    /// The App ID whose `attempt` created the claim.
    pub creator: Option<[u8; 16]>,
    /// The service time at which its last entry was applied.
    pub last_entry_ms: Option<u64>,
}

/// A `claim` part: one live claim, followed by its `claim_entry` parts (Switch wire 10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimPart {
    /// The claim key.
    pub claim_key: [u8; 32],
    /// The claim.
    pub claim: ClaimState,
}

/// A `claim_entry` part: one entry of a live claim with its transition proof, right after
/// the claim's part (Switch wire 10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimEntryPart {
    /// The claim key.
    pub claim_key: [u8; 32],
    /// The claim's step before the entry.
    pub step: u64,
    /// The entry's chain item.
    pub seq: u64,
    /// The signed claim entry.
    pub op: SignedDoc,
    /// Its transition proof.
    pub proof: SignedDoc,
    /// The writer's certificate the entry was checked against, or `None` for the one the
    /// record in the writer's `app` part carries, as in a `record` part. Always written
    /// (Switch wire 10.3).
    pub cert: Option<SignedDoc>,
}

/// A tombstone's state in a `tombstone` part (Switch wire 10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TombstoneState {
    /// The number of entries.
    pub step: u64,
    /// Every attempt, oldest first.
    pub attempts: Vec<AttemptState>,
    /// The pinned deadline, in Unix milliseconds.
    pub deadline_ms: Option<u64>,
    /// The App ID whose `attempt` created the claim.
    pub creator: Option<[u8; 16]>,
    /// The service time of its last entry.
    pub last_entry_ms: Option<u64>,
}

/// A `tombstone` part (Switch wire 10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TombstonePart {
    /// The claim key.
    pub claim_key: [u8; 32],
    /// The tombstone.
    pub tombstone: TombstoneState,
}

/// A shared record in a `record` part: its current write (Switch wire 10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordEntry {
    /// The record key.
    pub key: [u8; 32],
    /// The collection ID.
    pub collection: [u8; 32],
    /// The read scope.
    pub read_scope: String,
    /// The write scopes.
    pub write_scopes: Vec<String>,
    /// The generation of the current write.
    pub generation: u64,
    /// The `seq` of the current write in `generation`.
    pub version: u64,
    /// The signed `record.put` of the current version, or `None` when the `chain` part at
    /// `seq` carries it.
    pub op: Option<SignedDoc>,
    /// The chain item at this service that holds `op`.
    pub seq: u64,
    /// Whether the current write deletes.
    pub deleted: bool,
    /// The writer's App ID.
    pub writer: [u8; 16],
    /// Set by a recovery upload.
    pub from_upload: bool,
    /// The uploaded version that writes at the next service built on.
    pub upload_base: Option<RecordVersion>,
    /// Its bytes for the storage quota: its `ct` decoded, 0 for a delete.
    pub size: u64,
    /// The writer's certificate the write was checked against, or `None` for the one the
    /// writer's `app` part carries.
    pub cert: Option<SignedDoc>,
    /// The transition proof of the current write; absent for a record from a recovery
    /// upload.
    pub proof: Option<SignedDoc>,
}

/// A `batch` part: a batch record without its proofs (Switch wire 10.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchPart {
    /// The batch ID.
    pub id: [u8; 16],
    /// The operation hash (Switch wire 6.4).
    pub ops_hash: [u8; 32],
    /// The service time of the batch, in Unix milliseconds.
    pub at_ms: u64,
}

/// A `conversation` part (Switch wire 10.3).
#[derive(Clone, Debug, PartialEq)]
pub struct ConversationPart {
    /// The counterparty's Pubky ID.
    pub pubky: [u8; 32],
    /// Who wrote it.
    pub written_by: Writer,
    /// When an invite code created it: the code's hash and context.
    pub invite: Option<([u8; 32], Value)>,
    /// When it was written, in Unix milliseconds.
    pub at: u64,
    /// When the last append it admitted came; absent until one.
    pub last_used: Option<u64>,
}

/// An `invite_code` part (Switch wire 10.3).
#[derive(Clone, Debug, PartialEq)]
pub struct InviteCodePart {
    /// The code's hash.
    pub code_hash: [u8; 32],
    /// When it expires, in Unix milliseconds. `expires_at_ms` is written from it and never
    /// read.
    pub expires_at: u64,
    /// The appends it admits.
    pub max_uses: u64,
    /// The appends it admitted.
    pub uses: u64,
    /// Any JSON value, `null` included.
    pub context: Value,
    /// The App ID that registered it.
    pub written_by: [u8; 16],
}

/// A `connect` part: a pending connect request (Switch wire 10.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectPart {
    /// The sender's Pubky ID.
    pub pubky: [u8; 32],
    /// When the request arrived, in Unix milliseconds.
    pub at: u64,
}

/// A `flag` part: a sender that keeps hitting the limits (Switch wire 10.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlagPart {
    /// The sender's Pubky ID.
    pub pubky: [u8; 32],
    /// Its limit hits.
    pub hits: u64,
}

/// A `peer` part: the signed `identity.json` of another identity (Switch wire 10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerPart {
    /// The signed document.
    pub doc: SignedDoc,
}

impl PeerPart {
    /// The identity the document names, read without verifying it.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if the body doesn't read or names no Pubky ID.
    pub fn identity(&self) -> Result<[u8; 32]> {
        let body: Value = self.doc.peek()?;
        let id = body
            .get("identity")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Invalid("Switch wire 10.3: a peer names no identity".into()))?;
        pubky_key(id).map_err(|_| {
            Error::Invalid("Switch wire 10.3: a peer's identity isn't a Pubky ID".into())
        })
    }
}

/// A `peer_floor` part: the floor a dropped peer copy left (Switch wire 10.3, 7.4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerFloorPart {
    /// The identity whose copy was dropped.
    pub identity: [u8; 32],
    /// The dropped copy's version.
    pub version: u64,
    /// Its generation.
    pub generation: u64,
    /// Its body hash.
    pub body_hash: [u8; 32],
}

/// A `divergent` part: one uploaded `record.put` that conflicts with the record (Switch wire
/// 10.3, Switch spec 12.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DivergentPart {
    /// The record key.
    pub key: [u8; 32],
    /// Its place among the record's divergent uploads, from 0.
    pub index: u64,
    /// The uploaded signed `record.put`.
    pub upload: SignedDoc,
}

/// One part of an export (Switch wire 10.3), its `part` member naming its kind.
#[derive(Clone, Debug, PartialEq)]
pub enum Part {
    /// `meta`.
    Meta(MetaPart),
    /// `chain`.
    Chain(ChainPart),
    /// `entry`.
    Entry(EntryPart),
    /// `app`.
    App(AppPart),
    /// `key_bundle`.
    KeyBundle(KeyBundlePart),
    /// `claim`.
    Claim(ClaimPart),
    /// `claim_entry`.
    ClaimEntry(ClaimEntryPart),
    /// `tombstone`.
    Tombstone(TombstonePart),
    /// `record`.
    Record(RecordEntry),
    /// `batch`.
    Batch(BatchPart),
    /// `contact`: a contact's Pubky ID.
    Contact([u8; 32]),
    /// `conversation`.
    Conversation(ConversationPart),
    /// `deny`: a denied Pubky ID.
    Deny([u8; 32]),
    /// `invite_code`.
    InviteCode(InviteCodePart),
    /// `connect`.
    Connect(ConnectPart),
    /// `flag`.
    Flag(FlagPart),
    /// `peer`.
    Peer(PeerPart),
    /// `peer_floor`.
    PeerFloor(PeerFloorPart),
    /// `divergent`.
    Divergent(DivergentPart),
}

/// Reads the members of one object of a part, naming the part's kind in every refusal and
/// never the member's value.
#[derive(Clone, Copy)]
struct Members<'a> {
    value: &'a Value,
    what: &'a str,
}

impl<'a> Members<'a> {
    fn of(value: &'a Value, what: &'a str) -> Result<Self> {
        if !value.is_object() {
            return Err(refuse(what, "", "isn't an object"));
        }
        Ok(Self { value, what })
    }

    fn fail(&self, member: &str, rule: &str) -> Error {
        refuse(self.what, member, rule)
    }

    /// A listed member: present, `null` included.
    fn present(&self, member: &str) -> Result<&'a Value> {
        self.value
            .get(member)
            .ok_or_else(|| self.fail(member, "is missing"))
    }

    /// A member that must be present and not `null`.
    fn req(&self, member: &str) -> Result<&'a Value> {
        match self.present(member)? {
            Value::Null => Err(self.fail(member, "is null")),
            v => Ok(v),
        }
    }

    /// A member marked "or `null`": absent reads as `null`.
    fn nullable(&self, member: &str) -> Option<&'a Value> {
        self.value.get(member).filter(|v| !v.is_null())
    }

    fn object(&self, member: &str) -> Result<Members<'a>> {
        let v = self.req(member)?;
        if !v.is_object() {
            return Err(self.fail(member, "isn't an object"));
        }
        Ok(Members {
            value: v,
            what: self.what,
        })
    }

    fn str(&self, member: &str) -> Result<&'a str> {
        self.req(member)?
            .as_str()
            .ok_or_else(|| self.fail(member, "isn't a string"))
    }

    fn int_of(&self, member: &str, v: &Value) -> Result<u64> {
        match v.as_u64() {
            Some(n) if n <= MAX_INT => Ok(n),
            _ => Err(self.fail(member, "isn't an integer from 0 to 2^53 - 1")),
        }
    }

    fn int(&self, member: &str) -> Result<u64> {
        self.int_of(member, self.req(member)?)
    }

    fn opt_int(&self, member: &str) -> Result<Option<u64>> {
        self.nullable(member)
            .map(|v| self.int_of(member, v))
            .transpose()
    }

    fn bool(&self, member: &str) -> Result<bool> {
        self.req(member)?
            .as_bool()
            .ok_or_else(|| self.fail(member, "isn't a bool"))
    }

    fn b64n<const N: usize>(&self, member: &str) -> Result<[u8; N]> {
        unb64_array::<N>(self.str(member)?).map_err(|_| self.fail(member, "isn't b64 of its size"))
    }

    fn time(&self, member: &str) -> Result<u64> {
        parse_rfc3339(self.str(member)?)
            .map_err(|_| self.fail(member, "isn't a time (Switch wire 1.6)"))
    }

    fn opt_time(&self, member: &str) -> Result<Option<u64>> {
        self.nullable(member).map(|_| self.time(member)).transpose()
    }

    fn pubky(&self, member: &str) -> Result<[u8; 32]> {
        pubky_key(self.str(member)?).map_err(|_| self.fail(member, "isn't a Pubky ID"))
    }

    fn app_id_of(&self, member: &str, v: &Value) -> Result<[u8; 16]> {
        v.as_str()
            .and_then(|s| app_id_decode(s).ok())
            .ok_or_else(|| self.fail(member, "isn't an App ID"))
    }

    fn app_id(&self, member: &str) -> Result<[u8; 16]> {
        self.app_id_of(member, self.req(member)?)
    }

    fn opt_app_id(&self, member: &str) -> Result<Option<[u8; 16]>> {
        self.nullable(member)
            .map(|v| self.app_id_of(member, v))
            .transpose()
    }

    fn doc_of(&self, member: &str, v: &Value) -> Result<SignedDoc> {
        let doc: SignedDoc = serde_json::from_value(v.clone())
            .map_err(|_| self.fail(member, "isn't a signed document"))?;
        // Both members decode, so every later check reads exact bytes.
        doc.body_bytes()
            .and_then(|_| doc.sig_bytes())
            .map_err(|_| self.fail(member, "isn't a signed document"))?;
        Ok(doc)
    }

    fn doc(&self, member: &str) -> Result<SignedDoc> {
        self.doc_of(member, self.req(member)?)
    }

    /// A signed document marked "always written": present, and `null` or a document.
    fn written_doc(&self, member: &str) -> Result<Option<SignedDoc>> {
        match self.present(member)? {
            Value::Null => Ok(None),
            v => self.doc_of(member, v).map(Some),
        }
    }

    fn opt_doc(&self, member: &str) -> Result<Option<SignedDoc>> {
        self.nullable(member)
            .map(|v| self.doc_of(member, v))
            .transpose()
    }

    fn array(&self, member: &str) -> Result<&'a Vec<Value>> {
        self.req(member)?
            .as_array()
            .ok_or_else(|| self.fail(member, "isn't an array"))
    }

    /// `[signed document, seq]`.
    fn doc_seq_of(&self, member: &str, v: &Value) -> Result<(SignedDoc, u64)> {
        match v.as_array().map(Vec::as_slice) {
            Some([doc, seq]) => Ok((self.doc_of(member, doc)?, self.int_of(member, seq)?)),
            _ => Err(self.fail(member, "isn't a [document, seq] pair")),
        }
    }

    /// An opaque member marked "or `null`".
    fn opaque(&self, member: &str) -> Value {
        self.value.get(member).cloned().unwrap_or(Value::Null)
    }

    /// A member that must be present and may hold any JSON value.
    fn any(&self, member: &str) -> Result<Value> {
        self.present(member).cloned()
    }

    /// A member that must be absent, an earlier form's.
    fn absent(&self, member: &str, rule: &str) -> Result<()> {
        if self.value.get(member).is_some() {
            return Err(self.fail(member, rule));
        }
        Ok(())
    }
}

fn refuse(what: &str, member: &str, rule: &str) -> Error {
    if member.is_empty() {
        Error::Invalid(format!("Switch wire 10.3: a {what} part {rule}"))
    } else {
        Error::Invalid(format!("Switch wire 10.3: a {what} part: {member} {rule}"))
    }
}

fn item_type(m: &Members<'_>) -> Result<ItemType> {
    ItemType::parse(m.str("item_type")?).map_err(|_| m.fail("item_type", "isn't known"))
}

fn read_attempt(m: &Members<'_>, v: &Value) -> Result<AttemptState> {
    let a = Members::of(v, m.what)?;
    Ok(AttemptState {
        attempt_id: a.b64n::<16>("attempt_id")?,
        owner: a.app_id("owner")?,
        outcome: Outcome::parse(a.str("outcome")?).map_err(|_| a.fail("outcome", "isn't known"))?,
        opened_at_ms: a.int("opened_at_ms")?,
        orphan_after_s: a.int("orphan_after_s")?,
        possibly_duplicate: a.bool("possibly_duplicate")?,
        duplicate: a.bool("duplicate")?,
        deadline_ms: a.opt_int("deadline_ms")?,
        from_upload: a.bool("from_upload")?,
        resolved_by: a.opt_app_id("resolved_by")?,
    })
}

fn read_attempts(m: &Members<'_>) -> Result<Vec<AttemptState>> {
    m.array("attempts")?
        .iter()
        .map(|v| read_attempt(m, v))
        .collect()
}

impl Part {
    /// The part's kind, as its `part` member names it.
    pub fn kind(&self) -> &'static str {
        match self {
            Part::Meta(_) => "meta",
            Part::Chain(_) => "chain",
            Part::Entry(_) => "entry",
            Part::App(_) => "app",
            Part::KeyBundle(_) => "key_bundle",
            Part::Claim(_) => "claim",
            Part::ClaimEntry(_) => "claim_entry",
            Part::Tombstone(_) => "tombstone",
            Part::Record(_) => "record",
            Part::Batch(_) => "batch",
            Part::Contact(_) => "contact",
            Part::Conversation(_) => "conversation",
            Part::Deny(_) => "deny",
            Part::InviteCode(_) => "invite_code",
            Part::Connect(_) => "connect",
            Part::Flag(_) => "flag",
            Part::Peer(_) => "peer",
            Part::PeerFloor(_) => "peer_floor",
            Part::Divergent(_) => "divergent",
        }
    }

    /// Read one part as Switch wire 10.3 gives its members.
    ///
    /// # Errors
    ///
    /// `400 bad_request` for an unknown kind, a listed member left out, a member that
    /// doesn't read, or an earlier form's member (`key_bundles`, `entries`, a batch's
    /// proofs).
    pub fn read(value: &Value) -> std::result::Result<Self, Refusal> {
        Self::read_value(value).map_err(|e| bad(super::reason(e)))
    }

    fn read_value(value: &Value) -> Result<Self> {
        let kind = Members::of(value, "chunk's")?.str("part")?;
        let m = Members::of(value, kind)?;
        Ok(match kind {
            "meta" => {
                let added = m.object("app_added_at")?;
                let mut app_added_at = Vec::new();
                if let Some(map) = added.value.as_object() {
                    for (app, version) in map {
                        let id = app_id_decode(app).map_err(|_| {
                            m.fail("app_added_at", "holds a key that isn't an App ID")
                        })?;
                        app_added_at.push((id, m.int_of("app_added_at", version)?));
                    }
                }
                Part::Meta(MetaPart {
                    identity: m.doc("identity")?,
                    generation: m.int("generation")?,
                    seq: m.int("seq")?,
                    directory_version: m.int("directory_version")?,
                    apps_version: m.int("apps_version")?,
                    app_added_at,
                })
            }
            "chain" => Part::Chain(ChainPart {
                seq: m.int("seq")?,
                stub: Stub::from_value(m.req("stub")?)
                    .map_err(|_| m.fail("stub", "doesn't read"))?,
                item_type: item_type(&m)?,
                doc: m.opt_doc("doc")?,
                context: m.opaque("context"),
            }),
            "entry" => {
                let r = m.object("result")?;
                let missed = match m.nullable("missed") {
                    None => None,
                    Some(_) => {
                        let x = m.object("missed")?;
                        Some(Missed {
                            entries: x.int("entries")?,
                            from_ms: x.int("from_ms")?,
                            until_ms: x.int("until_ms")?,
                        })
                    }
                };
                let targets = m
                    .array("targets")?
                    .iter()
                    .map(|t| m.app_id_of("targets", t))
                    .collect::<Result<Vec<_>>>()?;
                // Present, and empty for an unreadable entry.
                let envelope = match m.present("envelope")?.as_str() {
                    Some(text) => unb64(text).map_err(|_| m.fail("envelope", "isn't base64url"))?,
                    None => return Err(m.fail("envelope", "isn't a string")),
                };
                Part::Entry(EntryPart {
                    seq: m.int("seq")?,
                    sender: m.pubky("sender")?,
                    cert: m.doc("cert")?,
                    accepted_at_ms: m.int("accepted_at_ms")?,
                    context: m.opaque("context"),
                    envelope,
                    targets,
                    result: EntryResult {
                        entry_id: r.b64n::<16>("entry_id")?,
                        accepted_at: r.time("accepted_at")?,
                        directory_version: r.int("directory_version")?,
                    },
                    unreadable: m.bool("unreadable")?,
                    missed,
                })
            }
            "app" => {
                m.absent(
                    "key_bundles",
                    "is an earlier form: the stored parts are key_bundle parts",
                )?;
                let receive_keys = m
                    .array("receive_keys")?
                    .iter()
                    .map(|v| m.doc_seq_of("receive_keys", v))
                    .collect::<Result<Vec<_>>>()?;
                Part::App(AppPart {
                    app_id: m.app_id("app_id")?,
                    record: m.opt_doc("record")?,
                    record_seq: m.opt_int("record_seq")?,
                    record_at_ms: m.opt_int("record_at_ms")?,
                    receive_keys,
                    cursor: m.int("cursor")?,
                    last_seen_ms: m.opt_int("last_seen_ms")?,
                    revoked_at_ms: m.opt_int("revoked_at_ms")?,
                    departed_at_ms: m.opt_int("departed_at_ms")?,
                    departure_epoch: m.opt_int("departure_epoch")?,
                    rotated: m.bool("rotated")?,
                    renewed_cert: m
                        .nullable("renewed_cert")
                        .map(|v| m.doc_seq_of("renewed_cert", v))
                        .transpose()?,
                    lagging: m.bool("lagging")?,
                    keys_through: m.opt_int("keys_through")?,
                    full_bundle_requested_ms: m.opt_int("full_bundle_requested_ms")?,
                })
            }
            "key_bundle" => {
                let bundle: KeyBundle = serde_json::from_value(m.req("bundle")?.clone())
                    .map_err(|_| m.fail("bundle", "isn't a key bundle (Switch wire 3.5)"))?;
                let (first_epoch, last_epoch) = (m.int("first_epoch")?, m.int("last_epoch")?);
                if first_epoch == 0 || first_epoch > last_epoch {
                    return Err(m.fail("first_epoch", "isn't from 1 and at most last_epoch"));
                }
                Part::KeyBundle(KeyBundlePart {
                    app_id: m.app_id("app_id")?,
                    bundle,
                    seq: m.int("seq")?,
                    first_epoch,
                    last_epoch,
                })
            }
            "claim" => {
                let c = m.object("claim")?;
                c.absent(
                    "entries",
                    "is an earlier form: the entries are claim_entry parts",
                )?;
                let pinned_deadline = match c.value.get("pinned_deadline") {
                    None => Pin::Unpinned,
                    Some(Value::Null) => Pin::NoDeadline,
                    Some(v) => Pin::At(c.int_of("pinned_deadline", v)?),
                };
                Part::Claim(ClaimPart {
                    claim_key: m.b64n::<32>("claim_key")?,
                    claim: ClaimState {
                        step: c.int("step")?,
                        attempts: read_attempts(&c)?,
                        current: c
                            .nullable("current")
                            .map(|_| c.b64n::<16>("current"))
                            .transpose()?,
                        settled: c.bool("settled")?,
                        divergent: c.bool("divergent")?,
                        pinned_deadline,
                        rebuilt: c.bool("rebuilt")?,
                        creator: c.opt_app_id("creator")?,
                        last_entry_ms: c.opt_int("last_entry_ms")?,
                    },
                })
            }
            "claim_entry" => Part::ClaimEntry(ClaimEntryPart {
                claim_key: m.b64n::<32>("claim_key")?,
                step: m.int("step")?,
                seq: m.int("seq")?,
                op: m.doc("op")?,
                proof: m.doc("proof")?,
                cert: m.written_doc("cert")?,
            }),
            "tombstone" => {
                let t = m.object("tombstone")?;
                Part::Tombstone(TombstonePart {
                    claim_key: m.b64n::<32>("claim_key")?,
                    tombstone: TombstoneState {
                        step: t.int("step")?,
                        attempts: read_attempts(&t)?,
                        deadline_ms: t.opt_int("deadline_ms")?,
                        creator: t.opt_app_id("creator")?,
                        last_entry_ms: t.opt_int("last_entry_ms")?,
                    },
                })
            }
            "record" => {
                let r = m.object("record")?;
                let write_scopes = r
                    .array("write_scopes")?
                    .iter()
                    .map(|s| {
                        s.as_str().map(str::to_owned).ok_or_else(|| {
                            r.fail("write_scopes", "holds a member that isn't a string")
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let upload_base = match r.nullable("upload_base") {
                    None => None,
                    Some(v) => match v.as_array().map(Vec::as_slice) {
                        Some([g, n]) => Some(RecordVersion::new(
                            r.int_of("upload_base", g)?,
                            r.int_of("upload_base", n)?,
                        )),
                        _ => return Err(r.fail("upload_base", "isn't an [int, int] pair")),
                    },
                };
                Part::Record(RecordEntry {
                    key: r.b64n::<32>("key")?,
                    collection: r.b64n::<32>("collection")?,
                    read_scope: r.str("read_scope")?.to_owned(),
                    write_scopes,
                    generation: r.int("generation")?,
                    version: r.int("version")?,
                    op: r.opt_doc("op")?,
                    seq: r.int("seq")?,
                    deleted: r.bool("deleted")?,
                    writer: r.app_id("writer")?,
                    from_upload: r.bool("from_upload")?,
                    upload_base,
                    size: r.int("size")?,
                    cert: r.opt_doc("cert")?,
                    proof: r.opt_doc("proof")?,
                })
            }
            "batch" => {
                let r = m.object("record")?;
                if !r.array("proofs")?.is_empty() {
                    return Err(r.fail("proofs", "aren't empty: no batch proofs travel"));
                }
                Part::Batch(BatchPart {
                    id: m.b64n::<16>("id")?,
                    ops_hash: r.b64n::<32>("ops_hash")?,
                    at_ms: r.int("at_ms")?,
                })
            }
            "contact" => Part::Contact(m.pubky("pubky")?),
            "deny" => Part::Deny(m.pubky("pubky")?),
            "conversation" => {
                let written_by = match m.str("written_by")? {
                    "service" => Writer::Service,
                    _ => Writer::App(m.app_id("written_by")?),
                };
                let invite = match m.nullable("code_hash") {
                    None => None,
                    Some(_) => Some((m.b64n::<32>("code_hash")?, m.any("context")?)),
                };
                Part::Conversation(ConversationPart {
                    pubky: m.pubky("pubky")?,
                    written_by,
                    invite,
                    at: m.time("at")?,
                    last_used: m.opt_time("last_used")?,
                })
            }
            "invite_code" => Part::InviteCode(InviteCodePart {
                code_hash: m.b64n::<32>("code_hash")?,
                expires_at: m.time("expires_at")?,
                max_uses: m.int("max_uses")?,
                uses: m.int("uses")?,
                context: m.any("context")?,
                written_by: m.app_id("written_by")?,
            }),
            "connect" => Part::Connect(ConnectPart {
                pubky: m.pubky("pubky")?,
                at: m.time("at")?,
            }),
            "flag" => Part::Flag(FlagPart {
                pubky: m.pubky("pubky")?,
                hits: m.int("hits")?,
            }),
            "peer" => {
                let peer = PeerPart { doc: m.doc("doc")? };
                peer.identity()?;
                Part::Peer(peer)
            }
            "peer_floor" => Part::PeerFloor(PeerFloorPart {
                identity: m.pubky("identity")?,
                version: m.int("version")?,
                generation: m.int("generation")?,
                body_hash: m.b64n::<32>("body_hash")?,
            }),
            "divergent" => Part::Divergent(DivergentPart {
                key: m.b64n::<32>("key")?,
                index: m.int("index")?,
                upload: m.doc("upload")?,
            }),
            _ => {
                return Err(Error::Invalid(
                    "Switch wire 10.3: a part of an unknown kind".into(),
                ));
            }
        })
    }

    /// The part's exact JSON bytes, as the old service writes them.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if an opaque context can't be written.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut o = Obj::new();
        o.str("part", self.kind());
        match self {
            Part::Meta(p) => {
                let mut added: Vec<(String, u64)> = p
                    .app_added_at
                    .iter()
                    .map(|(id, n)| (zbase32_encode(id), *n))
                    .collect();
                added.sort();
                let mut a = Obj::new();
                for (id, n) in &added {
                    a.int(id, *n);
                }
                o.raw("identity", &carrying(&p.identity))
                    .int("generation", p.generation)
                    .int("seq", p.seq)
                    .int("directory_version", p.directory_version)
                    .int("apps_version", p.apps_version)
                    .raw("app_added_at", &a.finish());
            }
            Part::Chain(p) => {
                o.int("seq", p.seq)
                    .raw("stub", &p.stub.to_json())
                    .str("item_type", p.item_type.as_str());
                opt_raw(&mut o, "doc", p.doc.as_ref().map(carrying));
                o.raw("context", &json(&p.context)?);
            }
            Part::Entry(p) => {
                let mut r = Obj::new();
                r.str("accepted_at", &rfc3339(p.result.accepted_at))
                    .int("directory_version", p.result.directory_version)
                    .str("entry_id", &b64(&p.result.entry_id));
                let targets: Vec<String> = p.targets.iter().map(|t| zbase32_encode(t)).collect();
                o.int("seq", p.seq)
                    .str("sender", &pubky_id(&p.sender))
                    .raw("cert", &carrying(&p.cert))
                    .int("accepted_at_ms", p.accepted_at_ms)
                    .raw("context", &json(&p.context)?)
                    .str("envelope", &b64(&p.envelope))
                    .raw("targets", &string_array(&targets))
                    .raw("result", &r.finish())
                    .raw("unreadable", bool_json(p.unreadable));
                if let Some(missed) = p.missed {
                    let mut x = Obj::new();
                    x.int("entries", missed.entries)
                        .int("from_ms", missed.from_ms)
                        .int("until_ms", missed.until_ms);
                    o.raw("missed", &x.finish());
                }
            }
            Part::App(p) => {
                let keys: Vec<Vec<u8>> = p
                    .receive_keys
                    .iter()
                    .map(|(doc, seq)| doc_seq(doc, *seq))
                    .collect();
                o.str("app_id", &zbase32_encode(&p.app_id));
                opt_raw(&mut o, "record", p.record.as_ref().map(carrying));
                opt_int(&mut o, "record_seq", p.record_seq);
                opt_int(&mut o, "record_at_ms", p.record_at_ms);
                o.raw("receive_keys", &array(&keys)).int("cursor", p.cursor);
                opt_int(&mut o, "last_seen_ms", p.last_seen_ms);
                opt_int(&mut o, "revoked_at_ms", p.revoked_at_ms);
                opt_int(&mut o, "departed_at_ms", p.departed_at_ms);
                opt_int(&mut o, "departure_epoch", p.departure_epoch);
                o.raw("rotated", bool_json(p.rotated));
                opt_raw(
                    &mut o,
                    "renewed_cert",
                    p.renewed_cert.as_ref().map(|(doc, seq)| doc_seq(doc, *seq)),
                );
                o.raw("lagging", bool_json(p.lagging));
                opt_int(&mut o, "keys_through", p.keys_through);
                opt_int(
                    &mut o,
                    "full_bundle_requested_ms",
                    p.full_bundle_requested_ms,
                );
            }
            Part::KeyBundle(p) => {
                let mut b = Obj::new();
                b.str("envelope", &b64(p.bundle.envelope()))
                    .str("sig", &b64(&p.bundle.sig()));
                o.str("app_id", &zbase32_encode(&p.app_id))
                    .raw("bundle", &b.finish())
                    .int("seq", p.seq)
                    .int("first_epoch", p.first_epoch)
                    .int("last_epoch", p.last_epoch);
            }
            Part::Claim(p) => {
                let c = &p.claim;
                let mut s = Obj::new();
                s.raw("attempts", &attempts_json(&c.attempts));
                opt_str(&mut s, "creator", c.creator.map(|a| zbase32_encode(&a)));
                opt_str(&mut s, "current", c.current.map(|a| b64(&a)));
                s.raw("divergent", bool_json(c.divergent));
                opt_int(&mut s, "last_entry_ms", c.last_entry_ms);
                match c.pinned_deadline {
                    Pin::Unpinned => {}
                    Pin::NoDeadline => {
                        s.null("pinned_deadline");
                    }
                    Pin::At(deadline) => {
                        s.int("pinned_deadline", deadline);
                    }
                }
                s.raw("rebuilt", bool_json(c.rebuilt))
                    .raw("settled", bool_json(c.settled))
                    .int("step", c.step);
                o.str("claim_key", &b64(&p.claim_key))
                    .raw("claim", &s.finish());
            }
            Part::ClaimEntry(p) => {
                o.str("claim_key", &b64(&p.claim_key))
                    .int("step", p.step)
                    .int("seq", p.seq)
                    .raw("op", &carrying(&p.op))
                    .raw("proof", &carrying(&p.proof));
                opt_raw(&mut o, "cert", p.cert.as_ref().map(carrying));
            }
            Part::Tombstone(p) => {
                let t = &p.tombstone;
                let mut s = Obj::new();
                s.raw("attempts", &attempts_json(&t.attempts));
                opt_str(&mut s, "creator", t.creator.map(|a| zbase32_encode(&a)));
                opt_int(&mut s, "deadline_ms", t.deadline_ms);
                opt_int(&mut s, "last_entry_ms", t.last_entry_ms);
                s.int("step", t.step);
                o.str("claim_key", &b64(&p.claim_key))
                    .raw("tombstone", &s.finish());
            }
            Part::Record(r) => {
                let mut s = Obj::new();
                opt_raw(&mut s, "cert", r.cert.as_ref().map(carrying));
                s.str("collection", &b64(&r.collection))
                    .raw("deleted", bool_json(r.deleted))
                    .raw("from_upload", bool_json(r.from_upload))
                    .int("generation", r.generation)
                    .str("key", &b64(&r.key));
                opt_raw(&mut s, "op", r.op.as_ref().map(carrying));
                if let Some(proof) = &r.proof {
                    s.raw("proof", &carrying(proof));
                }
                s.str("read_scope", &r.read_scope)
                    .int("seq", r.seq)
                    .int("size", r.size);
                opt_raw(
                    &mut s,
                    "upload_base",
                    r.upload_base.map(|v| {
                        array(&[
                            v.generation.to_string().into_bytes(),
                            v.version.to_string().into_bytes(),
                        ])
                    }),
                );
                s.int("version", r.version)
                    .raw("write_scopes", &string_array(&r.write_scopes))
                    .str("writer", &zbase32_encode(&r.writer));
                o.raw("record", &s.finish());
            }
            Part::Batch(p) => {
                let mut r = Obj::new();
                r.int("at_ms", p.at_ms)
                    .str("ops_hash", &b64(&p.ops_hash))
                    .raw("proofs", b"[]");
                o.str("id", &b64(&p.id)).raw("record", &r.finish());
            }
            Part::Contact(pubky) | Part::Deny(pubky) => {
                o.str("pubky", &pubky_id(pubky));
            }
            Part::Conversation(p) => {
                o.str("pubky", &pubky_id(&p.pubky)).str(
                    "written_by",
                    &match p.written_by {
                        Writer::App(id) => zbase32_encode(&id),
                        Writer::Service => "service".to_owned(),
                    },
                );
                if let Some((code_hash, context)) = &p.invite {
                    o.str("code_hash", &b64(code_hash))
                        .raw("context", &json(context)?);
                }
                o.str("at", &rfc3339(p.at));
                if let Some(last_used) = p.last_used {
                    o.str("last_used", &rfc3339(last_used));
                }
            }
            Part::InviteCode(p) => {
                o.str("code_hash", &b64(&p.code_hash))
                    .str("expires_at", &rfc3339(p.expires_at))
                    .int("expires_at_ms", p.expires_at)
                    .int("max_uses", p.max_uses)
                    .int("uses", p.uses)
                    .raw("context", &json(&p.context)?)
                    .str("written_by", &zbase32_encode(&p.written_by));
            }
            Part::Connect(p) => {
                o.str("pubky", &pubky_id(&p.pubky))
                    .str("at", &rfc3339(p.at));
            }
            Part::Flag(p) => {
                o.str("pubky", &pubky_id(&p.pubky)).int("hits", p.hits);
            }
            Part::Peer(p) => {
                o.raw("doc", &carrying(&p.doc));
            }
            Part::PeerFloor(p) => {
                o.str("identity", &pubky_id(&p.identity))
                    .int("version", p.version)
                    .int("generation", p.generation)
                    .str("body_hash", &b64(&p.body_hash));
            }
            Part::Divergent(p) => {
                o.str("key", &b64(&p.key))
                    .int("index", p.index)
                    .raw("upload", &carrying(&p.upload));
            }
        }
        Ok(o.finish())
    }
}

fn json(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value)
        .map_err(|_| Error::Invalid("Switch wire 10.3: a context can't be written".into()))
}

fn bool_json(value: bool) -> &'static [u8] {
    if value { b"true" } else { b"false" }
}

fn opt_raw(o: &mut Obj, name: &str, value: Option<Vec<u8>>) {
    match value {
        Some(bytes) => o.raw(name, &bytes),
        None => o.null(name),
    };
}

fn opt_int(o: &mut Obj, name: &str, value: Option<u64>) {
    match value {
        Some(n) => o.int(name, n),
        None => o.null(name),
    };
}

fn opt_str(o: &mut Obj, name: &str, value: Option<String>) {
    match value {
        Some(text) => o.str(name, &text),
        None => o.null(name),
    };
}

fn doc_seq(doc: &SignedDoc, seq: u64) -> Vec<u8> {
    array(&[carrying(doc), seq.to_string().into_bytes()])
}

fn attempts_json(attempts: &[AttemptState]) -> Vec<u8> {
    let items: Vec<Vec<u8>> = attempts
        .iter()
        .map(|a| {
            let mut o = Obj::new();
            o.str("attempt_id", &b64(&a.attempt_id));
            opt_int(&mut o, "deadline_ms", a.deadline_ms);
            o.raw("duplicate", bool_json(a.duplicate))
                .raw("from_upload", bool_json(a.from_upload))
                .int("opened_at_ms", a.opened_at_ms)
                .int("orphan_after_s", a.orphan_after_s)
                .str("outcome", a.outcome.as_str())
                .str("owner", &zbase32_encode(&a.owner))
                .raw("possibly_duplicate", bool_json(a.possibly_duplicate));
            if let Some(by) = a.resolved_by {
                o.str("resolved_by", &zbase32_encode(&by));
            }
            o.finish()
        })
        .collect();
    array(&items)
}
