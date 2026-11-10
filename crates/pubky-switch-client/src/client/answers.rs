//! The answers of the switch's calls and the bodies the client writes (Switch wire 7.4, 8.1),
//! as plain owned types.
//!
//! Every answer is read only after its response signature verified with the pinned key.
//! Documents a reader checks by its own rules, such as a record view's operation or a feed
//! item's proof, stay signed documents here; documents of the account's own identity that
//! the client can check alone are verified into the core's types.

use pubky_switch_core::chain::{ItemType, SignedHead, Stub, TransitionProof};
use pubky_switch_core::claims::ClaimView;
use pubky_switch_core::enc::{app_id_decode, b64, pubky_id};
use pubky_switch_core::ops::Position;
use pubky_switch_core::records::{
    AppRecord, Freeze, IdentityDoc, KeyBundle, ReceiveKeyRecord, SignerHandover,
};
use pubky_switch_core::sig::SignedDoc;
use serde_json::{Map, Value, json};

use super::read::{self, Obj};
use crate::error::ClientError;

fn bad(what: &str) -> ClientError {
    ClientError::InvalidResponse(what.to_owned())
}

/// The answer of a write by an own app or the signer: the transition proofs of the chain
/// items it wrote, in order, and the newest head, each verified with the pinned key (Switch
/// wire 7.1).
#[derive(Clone, Debug, PartialEq)]
pub struct WriteAnswer {
    /// The transition proofs, verified.
    pub proofs: Vec<TransitionProof>,
    /// The newest head, verified.
    pub head: SignedHead,
}

/// The answer of `POST /v1/{id}/inbox` (Switch wire 7.4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendAnswer {
    /// The entry's ID.
    pub entry_id: [u8; 16],
    /// When the switch accepted it, in Unix milliseconds.
    pub accepted_at: u64,
    /// The recipient's directory version.
    pub directory_version: u64,
    /// For an app of another identity: the version of its identity's `identity.json` the
    /// service holds; `None` when it holds none, or for an own app.
    pub known_version: Option<u64>,
}

impl AppendAnswer {
    pub(crate) fn read(o: Obj<'_>) -> Result<Self, ClientError> {
        Ok(Self {
            entry_id: o.b64n("entry_id")?,
            accepted_at: o.time("accepted_at")?,
            directory_version: o.u64("directory_version")?,
            known_version: o.opt_u64("known_version")?,
        })
    }
}

/// The query of `GET /v1/{id}/feed` (Switch wire 7.4.4); `None` takes the service's default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeedQuery {
    /// The position the page starts after.
    pub after: Option<Position>,
    /// Items per page, 1 to 500.
    pub limit: Option<u32>,
    /// Long-poll seconds, at most 25.
    pub wait: Option<u32>,
}

impl FeedQuery {
    /// The path and query after `/v1/{id}/`: `feed`, then `after`, `limit` and `wait`, in
    /// that order.
    pub(crate) fn path(&self) -> String {
        let mut query = Vec::new();
        if let Some(after) = self.after {
            query.push(format!("after={after}"));
        }
        if let Some(limit) = self.limit {
            query.push(format!("limit={limit}"));
        }
        if let Some(wait) = self.wait {
            query.push(format!("wait={wait}"));
        }
        if query.is_empty() {
            "feed".to_owned()
        } else {
            format!("feed?{}", query.join("&"))
        }
    }
}

/// An `entry` feed item: an inbox entry for one of the app's targets (Switch wire 7.5).
#[derive(Clone, Debug, PartialEq)]
pub struct EntryItem {
    /// Its `seq`.
    pub seq: u64,
    /// The entry's ID.
    pub entry_id: [u8; 16],
    /// The sender's identity.
    pub sender: [u8; 32],
    /// The sender app's certificate.
    pub cert: SignedDoc,
    /// When the switch accepted it, in Unix milliseconds.
    pub accepted_at: u64,
    /// The invite code's context, if one admitted it; opaque.
    pub context: Option<Value>,
    /// The envelope bytes.
    pub envelope: Vec<u8>,
}

/// A `chain` feed item: a chain item the app may read in full (Switch wire 7.5).
#[derive(Clone, Debug, PartialEq)]
pub struct ChainItem {
    /// Its `seq`.
    pub seq: u64,
    /// The chain stub.
    pub stub: Stub,
    /// The item's type.
    pub item_type: ItemType,
    /// The signed document.
    pub item: SignedDoc,
    /// The context of a service-written conversation entry; opaque.
    pub context: Option<Value>,
    /// A signed operation's transition proof, unverified: the reader checks it with the
    /// service key of its generation (Switch wire 6.5).
    pub proof: Option<SignedDoc>,
}

/// One item of a feed page (Switch wire 7.5).
#[derive(Clone, Debug, PartialEq)]
pub enum FeedItem {
    /// An inbox entry.
    Entry(EntryItem),
    /// An entry no current app can open after its targets departed.
    Unreadable {
        /// Its `seq`.
        seq: u64,
        /// The entry's ID.
        entry_id: [u8; 16],
        /// The sender's identity.
        sender: [u8; 32],
        /// When the switch accepted it, in Unix milliseconds.
        accepted_at: u64,
    },
    /// Entries the service deleted before the lagging app read them (Switch wire 7.4.4).
    Missed {
        /// Its `seq`.
        seq: u64,
        /// How many entries.
        entries: u64,
        /// The first acceptance time, in Unix milliseconds; `None` when it doesn't parse,
        /// and the app then ignores the item.
        accepted_from: Option<u64>,
        /// The last acceptance time, as `accepted_from`.
        accepted_until: Option<u64>,
    },
    /// A chain item in full.
    Chain(ChainItem),
    /// A chain item's stub only.
    Stub {
        /// Its `seq`.
        seq: u64,
        /// The chain stub.
        stub: Stub,
    },
}

impl FeedItem {
    /// The item's `seq`.
    pub fn seq(&self) -> u64 {
        match self {
            FeedItem::Entry(EntryItem { seq, .. })
            | FeedItem::Unreadable { seq, .. }
            | FeedItem::Missed { seq, .. }
            | FeedItem::Chain(ChainItem { seq, .. })
            | FeedItem::Stub { seq, .. } => *seq,
        }
    }

    fn read(o: Obj<'_>) -> Result<Self, ClientError> {
        let seq = o.u64("seq")?;
        let stub = |o: &Obj<'_>| {
            o.get("stub")
                .and_then(|value| Stub::from_value(value).ok())
                .ok_or_else(|| bad("Switch wire 7.5: a feed item's stub doesn't read"))
        };
        Ok(match o.str("type")? {
            "entry" => FeedItem::Entry(EntryItem {
                seq,
                entry_id: o.b64n("entry_id")?,
                sender: o.pubky("sender")?,
                cert: o.doc("cert")?,
                accepted_at: o.time("accepted_at")?,
                context: o.value("context"),
                envelope: o.bytes("envelope")?,
            }),
            "unreadable" => FeedItem::Unreadable {
                seq,
                entry_id: o.b64n("entry_id")?,
                sender: o.pubky("sender")?,
                accepted_at: o.time("accepted_at")?,
            },
            "missed" => FeedItem::Missed {
                seq,
                entries: o.u64("entries")?,
                accepted_from: o.time("accepted_from").ok(),
                accepted_until: o.time("accepted_until").ok(),
            },
            "chain" => {
                let item_type = o.str("item_type")?;
                let item_type = [ItemType::Op, ItemType::Identity, ItemType::Service]
                    .into_iter()
                    .find(|known| known.as_str() == item_type)
                    .ok_or_else(|| bad("Switch wire 7.5: a chain item's item_type is unknown"))?;
                FeedItem::Chain(ChainItem {
                    seq,
                    stub: stub(&o)?,
                    item_type,
                    item: o.doc("item")?,
                    context: o.value("context"),
                    proof: o.opt_doc("proof")?,
                })
            }
            "stub" => FeedItem::Stub {
                seq,
                stub: stub(&o)?,
            },
            _ => return Err(bad("Switch wire 7.5: a feed item of an unknown type")),
        })
    }
}

/// A page of `GET /v1/{id}/feed` (Switch wire 7.4.4), read as a feed page so its opaque
/// contexts read (Switch wire 1.1).
#[derive(Clone, Debug, PartialEq)]
pub struct FeedPage {
    /// The items, in `seq` order.
    pub items: Vec<FeedItem>,
    /// The position to pass as the next `after`.
    pub next: Position,
    /// The last `seq` this page examined.
    pub scanned_through: u64,
    /// Whether items follow `scanned_through`.
    pub more: bool,
    /// The newest head, verified with the pinned key.
    pub head: SignedHead,
    /// The service's latest checkpoint, verified with the pinned key.
    pub checkpoint: Option<SignedHead>,
    /// The freeze of a frozen account, verified with the identity key; the app treats its
    /// writes as `410 moved` would.
    pub freeze: Option<Freeze>,
}

impl FeedPage {
    pub(crate) fn read(o: Obj<'_>, account: &[u8; 32]) -> Result<Self, ClientError> {
        let next = Position::parse(o.str("next")?)
            .map_err(|_| bad("Switch wire 7.4.4: a feed page's next isn't a position"))?;
        let freeze = match o.opt_doc("freeze")? {
            None => None,
            Some(signed) => Some(Freeze::verify(&signed, account)?),
        };
        Ok(Self {
            items: o
                .objects("items")?
                .into_iter()
                .map(FeedItem::read)
                .collect::<Result<_, _>>()?,
            next,
            scanned_through: o.u64("scanned_through")?,
            more: o.bool("more")?,
            head: o.head("head")?,
            checkpoint: o.opt_head("checkpoint")?,
            freeze,
        })
    }
}

/// The answer of `PUT /v1/{id}/peers` (Switch wire 7.4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeersAnswer {
    /// The version the service now holds.
    pub version: u64,
    /// For an app of another identity, the version of its identity's `identity.json` the
    /// service holds.
    pub known_version: Option<u64>,
}

impl PeersAnswer {
    pub(crate) fn read(o: Obj<'_>) -> Result<Self, ClientError> {
        Ok(Self {
            version: o.u64("version")?,
            known_version: o.opt_u64("known_version")?,
        })
    }
}

/// Who wrote a conversation entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrittenBy {
    /// The service, on the first append an invite code admitted.
    Service,
    /// An app.
    App([u8; 16]),
}

/// A conversation entry of `GET /v1/{id}/allow` (Switch wire 7.4.6).
#[derive(Clone, Debug, PartialEq)]
pub struct Conversation {
    /// The counterparty.
    pub pubky: [u8; 32],
    /// Who wrote it.
    pub written_by: WrittenBy,
    /// The hash of the invite code that created it.
    pub code_hash: Option<[u8; 32]>,
    /// The invite code's context; opaque.
    pub context: Option<Value>,
    /// When it was written, in Unix milliseconds.
    pub at: u64,
    /// The service time of the last append it admitted.
    pub last_used: Option<u64>,
}

/// A flagged sender of `GET /v1/{id}/allow` (Switch wire 7.4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flagged {
    /// The sender.
    pub pubky: [u8; 32],
    /// How many times it hit a rate limit.
    pub hits: u64,
}

/// A live invite code of `GET /v1/{id}/allow`, without its context (Switch wire 7.4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InviteCodeStatus {
    /// The code's hash.
    pub code_hash: [u8; 32],
    /// When it expires, in Unix milliseconds.
    pub expires_at: u64,
    /// The most uses.
    pub max_uses: u64,
    /// The uses so far.
    pub uses: u64,
    /// The app that registered it.
    pub written_by: [u8; 16],
}

/// The answer of `GET /v1/{id}/allow` (Switch wire 7.4.6), read as an allow list so the
/// conversations' opaque contexts read (Switch wire 1.1).
#[derive(Clone, Debug, PartialEq)]
pub struct AllowList {
    /// The contacts.
    pub contacts: Vec<[u8; 32]>,
    /// The conversation entries.
    pub conversations: Vec<Conversation>,
    /// The deny list.
    pub deny: Vec<[u8; 32]>,
    /// The senders that hit rate limits at least 3 times.
    pub flagged: Vec<Flagged>,
    /// The live invite codes.
    pub invite_codes: Vec<InviteCodeStatus>,
}

impl AllowList {
    pub(crate) fn read(o: Obj<'_>) -> Result<Self, ClientError> {
        let conversations = o
            .objects("conversations")?
            .into_iter()
            .map(|c| {
                let written_by = match c.str("written_by")? {
                    "service" => WrittenBy::Service,
                    app => WrittenBy::App(app_id_decode(app).map_err(|_| {
                        bad("Switch wire 7.4.6: a conversation's written_by doesn't read")
                    })?),
                };
                Ok(Conversation {
                    pubky: c.pubky("pubky")?,
                    written_by,
                    code_hash: c.opt_b64n("code_hash")?,
                    context: c.value("context"),
                    at: c.time("at")?,
                    last_used: c.opt_time("last_used")?,
                })
            })
            .collect::<Result<_, ClientError>>()?;
        let flagged = o
            .objects("flagged")?
            .into_iter()
            .map(|f| {
                Ok(Flagged {
                    pubky: f.pubky("pubky")?,
                    hits: f.u64("hits")?,
                })
            })
            .collect::<Result<_, ClientError>>()?;
        let invite_codes = o
            .objects("invite_codes")?
            .into_iter()
            .map(|i| {
                Ok(InviteCodeStatus {
                    code_hash: i.b64n("code_hash")?,
                    expires_at: i.time("expires_at")?,
                    max_uses: i.u64("max_uses")?,
                    uses: i.u64("uses")?,
                    written_by: i.app_id("written_by")?,
                })
            })
            .collect::<Result<_, ClientError>>()?;
        Ok(Self {
            contacts: o.each("contacts", read::pubky)?,
            conversations,
            deny: o.each("deny", read::pubky)?,
            flagged,
            invite_codes,
        })
    }
}

/// The answer of `POST /v1/{id}/connect` (Switch wire 7.4.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectAnswer {
    /// Always `true`: the request is pending, or was answered as if it were.
    pub pending: bool,
    /// The version of the caller's identity's `identity.json` the service holds.
    pub known_version: Option<u64>,
}

impl ConnectAnswer {
    pub(crate) fn read(o: Obj<'_>) -> Result<Self, ClientError> {
        Ok(Self {
            pending: o.bool("pending")?,
            known_version: o.opt_u64("known_version")?,
        })
    }
}

/// A pending connect request (Switch wire 7.4.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectRequest {
    /// The sender.
    pub pubky: [u8; 32],
    /// When it asked, in Unix milliseconds.
    pub at: u64,
}

/// The answer of `GET /v1/{id}/connect` (Switch wire 7.4.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectList {
    /// The requests, oldest first.
    pub requests: Vec<ConnectRequest>,
    /// The cap that applies.
    pub max_pending: u64,
    /// Whether the list is full.
    pub full: bool,
}

impl ConnectList {
    pub(crate) fn read(o: Obj<'_>) -> Result<Self, ClientError> {
        Ok(Self {
            requests: o
                .objects("requests")?
                .into_iter()
                .map(|r| {
                    Ok(ConnectRequest {
                        pubky: r.pubky("pubky")?,
                        at: r.time("at")?,
                    })
                })
                .collect::<Result<_, ClientError>>()?,
            max_pending: o.u64("max_pending")?,
            full: o.bool("full")?,
        })
    }
}

/// One entry of a claim (Switch wire 7.4.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimEntryItem {
    /// The claim's step before it, the operation's `expected_step`.
    pub step: u64,
    /// The operation's `seq`.
    pub seq: u64,
    /// The signed operation; the reader checks it (Switch wire 6.2).
    pub op: SignedDoc,
    /// Its transition proof; the reader checks it (Switch wire 6.5).
    pub proof: SignedDoc,
}

/// The answer of `GET /v1/{id}/claims/{claim_key}` (Switch wire 7.4.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimAnswer {
    /// The claim view.
    pub claim: ClaimView,
    /// The entries; none for a tombstone.
    pub entries: Vec<ClaimEntryItem>,
}

impl ClaimAnswer {
    pub(crate) fn read(o: Obj<'_>) -> Result<Self, ClientError> {
        let claim = o
            .get("claim")
            .ok_or_else(|| bad("Switch wire 7.4.8: the answer has no claim"))?;
        Ok(Self {
            claim: ClaimView::from_value(claim)?,
            entries: o
                .objects("entries")?
                .into_iter()
                .map(|e| {
                    Ok(ClaimEntryItem {
                        step: e.u64("step")?,
                        seq: e.u64("seq")?,
                        op: e.doc("op")?,
                        proof: e.doc("proof")?,
                    })
                })
                .collect::<Result<_, ClientError>>()?,
        })
    }
}

/// A record view of `GET /v1/{id}/records` (Switch wire 7.4.9). Readers take nothing from
/// it on trust: the writer, the version, `deleted` and the content come from the checks of
/// Switch wire 6.2 on `op`, `proof` and `cert`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedRecordView {
    /// The record key.
    pub key: [u8; 32],
    /// The collection ID.
    pub collection: [u8; 32],
    /// The policy's read scope.
    pub read_scope: String,
    /// The policy's write scopes.
    pub write_scopes: Vec<String>,
    /// The current version's generation.
    pub generation: u64,
    /// The current version.
    pub version: u64,
    /// The write's `seq`.
    pub seq: u64,
    /// Whether the current write is a delete.
    pub deleted: bool,
    /// The writer.
    pub writer: [u8; 16],
    /// The `record.put` that wrote the current version, with its sealed value.
    pub op: SignedDoc,
    /// Whether uploads after a provider loss conflict with it.
    pub divergent: bool,
    /// The transition proof that gives this version; absent for a record taken from a
    /// recovery upload.
    pub proof: Option<SignedDoc>,
    /// The writer's certificate the service checked the write against.
    pub cert: SignedDoc,
}

impl SharedRecordView {
    pub(crate) fn read(o: Obj<'_>) -> Result<Self, ClientError> {
        Ok(Self {
            key: o.b64n("key")?,
            collection: o.b64n("collection")?,
            read_scope: o.string("read_scope")?,
            write_scopes: o.each("write_scopes", read::string)?,
            generation: o.u64("generation")?,
            version: o.u64("version")?,
            seq: o.u64("seq")?,
            deleted: o.bool("deleted")?,
            writer: o.app_id("writer")?,
            op: o.doc("op")?,
            divergent: o.opt_bool("divergent")?.unwrap_or(false),
            proof: o.opt_doc("proof")?,
            cert: o.doc("cert")?,
        })
    }
}

/// A page of `GET /v1/{id}/records?collection=` (Switch wire 7.4.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordPage {
    /// The current records the caller may read, deleted ones left out.
    pub records: Vec<SharedRecordView>,
    /// The newest `seq` when the page was read.
    pub seq: u64,
    /// The key to pass as `after` for the next page; `None` on the last page.
    pub next: Option<[u8; 32]>,
}

impl RecordPage {
    pub(crate) fn read(o: Obj<'_>) -> Result<Self, ClientError> {
        Ok(Self {
            records: o
                .objects("records")?
                .into_iter()
                .map(SharedRecordView::read)
                .collect::<Result<_, _>>()?,
            seq: o.u64("seq")?,
            next: o.opt_b64n("next")?,
        })
    }
}

/// A current app of a directory (Switch wire 7.4.10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryApp {
    /// The App ID.
    pub app_id: [u8; 16],
    /// Its app record, verified for the account's identity.
    pub record: AppRecord,
    /// Its current receive key record, verified with the record's certificate.
    pub receive_key: Option<ReceiveKeyRecord>,
}

/// The answer of `GET /v1/{id}/directory` (Switch wire 7.4.10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directory {
    /// The newest `identity.json` the service holds, verified with the account's identity.
    pub identity: IdentityDoc,
    /// The current apps.
    pub apps: Vec<DirectoryApp>,
    /// Changes whenever the directory changes.
    pub directory_version: u64,
    /// Changes when an app becomes reachable or stops being reachable.
    pub apps_version: u64,
    /// For an app of another identity, the version of its identity's `identity.json` the
    /// service holds.
    pub known_version: Option<u64>,
    /// The App IDs of the entries left out of `apps`: a record or receive key record that
    /// doesn't verify, or an App ID listed more than once. A sender skips those apps and
    /// uses the others (Switch spec 8.1).
    pub skipped: Vec<[u8; 16]>,
}

impl Directory {
    pub(crate) fn read(o: Obj<'_>, account: &[u8; 32]) -> Result<Self, ClientError> {
        let identity = IdentityDoc::verify(&o.doc("identity")?, account)?;
        let mut apps: Vec<DirectoryApp> = Vec::new();
        let mut skipped: Vec<[u8; 16]> = Vec::new();
        for a in o.objects("apps")? {
            // An entry without an App ID that reads can't be named; it is left out.
            let Ok(app_id) = a.app_id("app_id") else {
                continue;
            };
            match Self::read_app(&a, app_id, account) {
                Ok(app) if !skipped.contains(&app_id) => {
                    if apps.iter().any(|held| held.app_id == app_id) {
                        // Listed twice: neither copy is used.
                        apps.retain(|held| held.app_id != app_id);
                        skipped.push(app_id);
                    } else {
                        apps.push(app);
                    }
                }
                Ok(_) => {}
                Err(_) => {
                    apps.retain(|held| held.app_id != app_id);
                    if !skipped.contains(&app_id) {
                        skipped.push(app_id);
                    }
                }
            }
        }
        Ok(Self {
            identity,
            apps,
            skipped,
            directory_version: o.u64("directory_version")?,
            apps_version: o.u64("apps_version")?,
            known_version: o.opt_u64("known_version")?,
        })
    }

    /// One app of the directory, its record verified for `account` and its receive key
    /// record with the record's certificate (Switch spec 8.1).
    fn read_app(
        a: &Obj<'_>,
        app_id: [u8; 16],
        account: &[u8; 32],
    ) -> Result<DirectoryApp, ClientError> {
        let record = AppRecord::verify(&a.doc("record")?, account)?;
        if record.cert().app_id() != app_id {
            return Err(bad(
                "Switch wire 7.4.10: an app record of another App ID than it is listed under",
            ));
        }
        let receive_key = match a.opt_doc("receive_key")? {
            None => None,
            Some(signed) => Some(ReceiveKeyRecord::verify(&signed, record.cert())?),
        };
        Ok(DirectoryApp {
            app_id,
            record,
            receive_key,
        })
    }
}

/// A key bundle part the service stores for the app (Switch wire 7.4.11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBundle {
    /// The key bundle; the app reads it by the rules of Switch wire 3.5 "Reading".
    pub bundle: KeyBundle,
    /// The `seq` of its `key_bundle.put`.
    pub seq: u64,
    /// Its first data epoch.
    pub first_epoch: u64,
    /// Its last data epoch.
    pub last_epoch: u64,
}

/// The answer of `GET /v1/{id}/apps/{app_id}/keys` (Switch wire 7.4.11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeysAnswer {
    /// The parts, ordered by `first_epoch`.
    pub bundles: Vec<StoredBundle>,
}

impl KeysAnswer {
    pub(crate) fn read(o: Obj<'_>) -> Result<Self, ClientError> {
        Ok(Self {
            bundles: o
                .objects("bundles")?
                .into_iter()
                .map(|b| {
                    let bundle = b
                        .get("bundle")
                        .and_then(|value| serde_json::from_value(value.clone()).ok())
                        .ok_or_else(|| bad("Switch wire 7.4.11: a key bundle doesn't read"))?;
                    Ok(StoredBundle {
                        bundle,
                        seq: b.u64("seq")?,
                        first_epoch: b.u64("first_epoch")?,
                        last_epoch: b.u64("last_epoch")?,
                    })
                })
                .collect::<Result<_, ClientError>>()?,
        })
    }
}

/// The body of `PUT /v1/{id}/push` (Switch wire 8.1). Its `Debug` shows the relay and how
/// many handles, never the handles.
#[derive(Clone, PartialEq, Eq)]
pub struct PushSetting {
    /// The relay URL: `https://` on port 443, with no user info.
    pub relay_url: String,
    /// The handles, at most 8, one per device; empty when starting a registration.
    pub handles: Vec<String>,
    /// The push key of the registration whose handles this sets; `None` to start one.
    pub push_key: Option<[u8; 32]>,
    /// On a start only: the push key of the registration it replaces.
    pub replaces: Option<[u8; 32]>,
}

impl std::fmt::Debug for PushSetting {
    // The handles reach the device through the relay: they stay out of logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushSetting")
            .field("relay_url", &self.relay_url)
            .field("handles", &self.handles.len())
            .field("push_key", &self.push_key.is_some())
            .field("replaces", &self.replaces.is_some())
            .finish()
    }
}

impl PushSetting {
    pub(crate) fn to_json(&self) -> Vec<u8> {
        let mut body = Map::new();
        body.insert("relay_url".into(), json!(self.relay_url));
        body.insert("handles".into(), json!(self.handles));
        if let Some(key) = &self.push_key {
            body.insert("push_key".into(), json!(b64(key)));
        }
        if let Some(key) = &self.replaces {
            body.insert("replaces".into(), json!(b64(key)));
        }
        Value::Object(body).to_string().into_bytes()
    }
}

/// The answer of `PUT /v1/{id}/push` (Switch wire 8.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushAnswer {
    /// The relay URL.
    pub relay_url: String,
    /// The number of handles kept.
    pub handles: u64,
    /// The registration's push key.
    pub push_key: [u8; 32],
}

impl PushAnswer {
    pub(crate) fn read(o: Obj<'_>) -> Result<Self, ClientError> {
        Ok(Self {
            relay_url: o.string("relay_url")?,
            handles: o.u64("handles")?,
            push_key: o.b64n("push_key")?,
        })
    }
}

/// An open attempt of an app (Switch wire 7.4.12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenAttempt {
    /// The claim key.
    pub claim_key: [u8; 32],
    /// The attempt ID.
    pub attempt_id: [u8; 16],
    /// `open` or `unknown`.
    pub outcome: String,
}

/// A key bundle part's epoch range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochRange {
    /// The first data epoch.
    pub first: u64,
    /// The last data epoch.
    pub last: u64,
}

/// An app's status in `GET /v1/{id}/apps` (Switch wire 7.4.12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppStatus {
    /// The App ID.
    pub app_id: [u8; 16],
    /// Whether it is current.
    pub current: bool,
    /// When the service last saw it.
    pub last_seen: Option<u64>,
    /// When it was revoked.
    pub revoked_at: Option<u64>,
    /// When it departed.
    pub departed_at: Option<u64>,
    /// A departure whose rotation isn't done.
    pub awaiting_rotation: bool,
    /// Its open attempts.
    pub open_attempts: Vec<OpenAttempt>,
    /// Inbox entries targeting it that it hasn't read.
    pub unread_entries: u64,
    /// Of those, the ones it is the only current target of.
    pub sole_target_unread: u64,
    /// The document hash of the certificate the app record the service holds carries.
    pub record_cert: Option<[u8; 32]>,
    /// When the service took that record.
    pub record_at: Option<u64>,
    /// Marked lagging.
    pub lagging: bool,
    /// The newest data epoch through which the app holds every scope key.
    pub keys_through: Option<u64>,
    /// A pending full-bundle request.
    pub full_bundle_requested: Option<u64>,
    /// The epoch range of each key bundle part the service stores for it, in order.
    pub bundle_ranges: Vec<EpochRange>,
    /// The expiry of the certificate the service checks the app against.
    pub cert_expires_at: Option<u64>,
}

impl AppStatus {
    fn read(o: Obj<'_>) -> Result<Self, ClientError> {
        let bundle_ranges = o
            .list("bundle_ranges")?
            .iter()
            .map(|range| match range.as_array().map(Vec::as_slice) {
                Some([first, last]) => Some(EpochRange {
                    first: first.as_u64()?,
                    last: last.as_u64()?,
                }),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| bad("Switch wire 7.4.12: a bundle range isn't two integers"))?;
        Ok(Self {
            app_id: o.app_id("app_id")?,
            current: o.bool("current")?,
            last_seen: o.opt_time("last_seen")?,
            revoked_at: o.opt_time("revoked_at")?,
            departed_at: o.opt_time("departed_at")?,
            awaiting_rotation: o.opt_bool("awaiting_rotation")?.unwrap_or(false),
            open_attempts: o
                .objects("open_attempts")?
                .into_iter()
                .map(|a| {
                    Ok(OpenAttempt {
                        claim_key: a.b64n("claim_key")?,
                        attempt_id: a.b64n("attempt_id")?,
                        outcome: a.string("outcome")?,
                    })
                })
                .collect::<Result<_, ClientError>>()?,
            unread_entries: o.opt_u64("unread_entries")?.unwrap_or(0),
            sole_target_unread: o.opt_u64("sole_target_unread")?.unwrap_or(0),
            record_cert: o.opt_b64n("record_cert")?,
            record_at: o.opt_time("record_at")?,
            lagging: o.opt_bool("lagging")?.unwrap_or(false),
            keys_through: o.opt_u64("keys_through")?,
            full_bundle_requested: o.opt_time("full_bundle_requested")?,
            bundle_ranges,
            cert_expires_at: o.opt_time("cert_expires_at")?,
        })
    }
}

/// A recovery in progress, in `GET /v1/{id}/apps` (Switch wire 7.4.12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryState {
    /// The lost generation.
    pub recovery_from: u64,
    /// When the recovery was declared.
    pub declared_at: u64,
    /// Whether admission is still staged.
    pub admission_staged: bool,
}

/// The answer of `GET /v1/{id}/apps` (Switch wire 7.4.12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppsAnswer {
    /// Every app the service knows or `identity.json` lists.
    pub apps: Vec<AppStatus>,
    /// The recovery in progress, if any.
    pub recovery: Option<RecoveryState>,
    /// The generations whose service keys `identity.json` keeps, ascending.
    pub proof_generations: Vec<u64>,
    /// The newest `identity.json` the service holds, as signed.
    pub identity: Option<SignedDoc>,
}

impl AppsAnswer {
    pub(crate) fn read(o: Obj<'_>) -> Result<Self, ClientError> {
        let recovery = match o.get("recovery") {
            None => None,
            Some(value) => {
                let r = Obj::of(value, "Switch wire 7.4.12: the recovery")?;
                Some(RecoveryState {
                    recovery_from: r.u64("recovery_from")?,
                    declared_at: r.time("declared_at")?,
                    admission_staged: r.bool("admission_staged")?,
                })
            }
        };
        Ok(Self {
            apps: o
                .objects("apps")?
                .into_iter()
                .map(AppStatus::read)
                .collect::<Result<_, _>>()?,
            recovery,
            proof_generations: o.each("proof_generations", read::int)?,
            identity: o.opt_doc("identity")?,
        })
    }
}

/// The answer of the public read `GET /v1/{id}/identity` (Switch wire 7.4.15).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    /// The newest `identity.json` the service holds, verified with the account's identity.
    pub identity: IdentityDoc,
    /// The freeze while the account is frozen, verified with the account's identity.
    pub freeze: Option<Freeze>,
}

impl PublicIdentity {
    pub(crate) fn read(o: Obj<'_>, account: &[u8; 32]) -> Result<Self, ClientError> {
        let freeze = match o.opt_doc("freeze")? {
            None => None,
            Some(signed) => Some(Freeze::verify(&signed, account)?),
        };
        Ok(Self {
            identity: IdentityDoc::verify(&o.doc("identity")?, account)?,
            freeze,
        })
    }
}

/// The answer of `PUT /v1/{id}/handover` (Switch wire 7.4.17).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandoverStored {
    /// The target app.
    pub app_id: [u8; 16],
    /// The number of parts stored.
    pub parts: u64,
}

impl HandoverStored {
    pub(crate) fn read(o: Obj<'_>) -> Result<Self, ClientError> {
        Ok(Self {
            app_id: o.app_id("app_id")?,
            parts: o.u64("parts")?,
        })
    }
}

/// The answer of `GET /v1/{id}/handover`: the body of the `PUT` the switch holds (Switch wire
/// 7.4.17). The target checks it as Switch wire 3.12 says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredHandover {
    /// The target app.
    pub app_id: [u8; 16],
    /// The hand-over.
    pub handover: SignerHandover,
}

impl StoredHandover {
    pub(crate) fn read(o: Obj<'_>) -> Result<Self, ClientError> {
        let handover = o
            .get("handover")
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .ok_or_else(|| bad("Switch wire 7.4.17: the hand-over doesn't read"))?;
        Ok(Self {
            app_id: o.app_id("app_id")?,
            handover,
        })
    }

    /// The `PUT` body: `{ "app_id", "handover": { "envelopes", "sig" } }`.
    pub(crate) fn to_json(&self) -> Result<Vec<u8>, ClientError> {
        let handover = serde_json::to_value(&self.handover)
            .map_err(|_| ClientError::Usage("the hand-over can't be written".into()))?;
        Ok(json!({
            "app_id": pubky_switch_core::enc::zbase32_encode(&self.app_id),
            "handover": handover,
        })
        .to_string()
        .into_bytes())
    }
}

/// An uploaded operation of `POST /v1/{id}/recovery/upload` (Switch wire 7.4.14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadedOp {
    /// The signed operation, with its sealed value.
    pub op: SignedDoc,
    /// Its writer's certificate.
    pub cert: SignedDoc,
    /// The old service's transition proof, if the app holds it.
    pub proof: Option<SignedDoc>,
}

/// The lists of a recovery upload (Switch wire 7.4.14).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UploadLists {
    /// Contacts, from an app with `lists.manage`.
    pub contacts: Vec<[u8; 32]>,
    /// Deny entries, from an app with `lists.read` or `lists.manage`.
    pub deny: Vec<[u8; 32]>,
}

/// The body of `POST /v1/{id}/recovery/upload` (Switch wire 7.4.14).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryUpload {
    /// An `identity.json` of the lost generation, after a provider loss.
    pub lost_identity: Option<SignedDoc>,
    /// `record.put` operations with their sealed values.
    pub records: Vec<UploadedOp>,
    /// Claim entries.
    pub claims: Vec<UploadedOp>,
    /// The old service's heads.
    pub heads: Vec<SignedHead>,
    /// The old service's transition proofs.
    pub proofs: Vec<SignedDoc>,
    /// The admission lists, if the app uploads them.
    pub lists: Option<UploadLists>,
}

impl RecoveryUpload {
    pub(crate) fn to_json(&self) -> Vec<u8> {
        let op = |u: &UploadedOp| {
            let mut m = Map::new();
            m.insert("op".into(), json!(u.op));
            m.insert("cert".into(), json!(u.cert));
            if let Some(proof) = &u.proof {
                m.insert("proof".into(), json!(proof));
            }
            Value::Object(m)
        };
        let mut body = Map::new();
        if let Some(doc) = &self.lost_identity {
            body.insert("lost_identity".into(), json!(doc));
        }
        body.insert(
            "records".into(),
            Value::Array(self.records.iter().map(op).collect()),
        );
        body.insert(
            "claims".into(),
            Value::Array(self.claims.iter().map(op).collect()),
        );
        body.insert(
            "heads".into(),
            Value::Array(self.heads.iter().map(SignedHead::to_value).collect()),
        );
        body.insert("proofs".into(), json!(self.proofs));
        if let Some(lists) = &self.lists {
            let ids = |keys: &[[u8; 32]]| keys.iter().map(pubky_id).collect::<Vec<_>>();
            body.insert(
                "lists".into(),
                json!({ "contacts": ids(&lists.contacts), "deny": ids(&lists.deny) }),
            );
        }
        Value::Object(body).to_string().into_bytes()
    }
}

/// What a recovery upload changed (Switch wire 7.4.14).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UploadChanges {
    /// Records filled in.
    pub records: Vec<[u8; 32]>,
    /// Records made divergent.
    pub divergent: Vec<[u8; 32]>,
    /// Claims filled in.
    pub claims: Vec<[u8; 32]>,
    /// Claims made divergent.
    pub divergent_claims: Vec<[u8; 32]>,
    /// Uploads without a verifiable proof.
    pub unverified: u64,
    /// Operations of removed apps not dated before their `distrust_from`.
    pub distrusted: u64,
    /// Claim entries the writer rules refused.
    pub refused: u64,
    /// Heads taken.
    pub heads: u64,
    /// Whether the lists changed.
    pub lists: bool,
}

impl UploadChanges {
    fn read(o: Obj<'_>) -> Result<Self, ClientError> {
        Ok(Self {
            records: o.each("records", read::b64_32)?,
            divergent: o.each("divergent", read::b64_32)?,
            claims: o.each("claims", read::b64_32)?,
            divergent_claims: o.each("divergent_claims", read::b64_32)?,
            unverified: o.opt_u64("unverified")?.unwrap_or(0),
            distrusted: o.opt_u64("distrusted")?.unwrap_or(0),
            refused: o.opt_u64("refused")?.unwrap_or(0),
            heads: o.opt_u64("heads")?.unwrap_or(0),
            lists: o.opt_bool("lists")?.unwrap_or(false),
        })
    }
}

/// The answer of `POST /v1/{id}/recovery/upload` (Switch wire 7.4.14), whose members depend
/// on where the account stands: after a provider loss `result`, `proof` and `head`; at a
/// staged service `heads` and `proofs`; after a published move also `merged` and `head`.
#[derive(Clone, Debug, PartialEq)]
pub struct UploadAnswer {
    /// What the upload changed, after a provider loss.
    pub result: Option<UploadChanges>,
    /// The `upload` transition's proof, verified with the pinned key.
    pub proof: Option<TransitionProof>,
    /// The newest head, verified with the pinned key.
    pub head: Option<SignedHead>,
    /// The heads counted.
    pub heads: Option<u64>,
    /// The proofs kept or checked.
    pub proofs: Option<u64>,
    /// What merged, after a published move.
    pub merged: Option<UploadChanges>,
}

impl UploadAnswer {
    /// The counts and changes; the proof and the head are the caller's to verify.
    pub(crate) fn read_counts(o: Obj<'_>) -> Result<Self, ClientError> {
        let changes = |name: &str| match o.get(name) {
            None => Ok(None),
            Some(_) => UploadChanges::read(o.object(name)?).map(Some),
        };
        Ok(Self {
            result: changes("result")?,
            proof: None,
            head: None,
            heads: o.opt_u64("heads")?,
            proofs: o.opt_u64("proofs")?,
            merged: changes("merged")?,
        })
    }
}
