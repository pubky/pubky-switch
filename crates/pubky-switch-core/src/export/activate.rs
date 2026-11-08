//! The activation (Switch wire 10.5): every check the next service makes on an export before
//! it makes it live, in the order the wire format lists them, and the state it then imports.
//!
//! The old service may be faulty or hostile, so the activation takes nothing on its word that
//! the chain or a signature can vouch for: the chain verifies under the old service's key up
//! to the freeze transition; apps' records and receive keys are those the chain holds; every
//! shared record is derived from its signed operation and carries the transition proof of
//! that write; every live claim is replayed from its entries ([`apply_entry`]); and the
//! heads and evidence apps uploaded must hold on the import.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::Value;

use super::manifest::Manifest;
use super::order::check_part_order;
use super::part::{
    AppPart, AttemptState, BatchPart, ChainPart, ClaimEntryPart, ClaimPart, ClaimState,
    ConnectPart, ConversationPart, EntryPart, FlagPart, InviteCodePart, KeyBundlePart, Part,
    PeerFloorPart, RecordEntry, TombstoneState,
};
use super::{bad, bad_signature, conflict, conflict_of, doc_refusal, reason};
use crate::chain::{
    ChainEnvelope, ItemType, ServiceTransition, SignedHead, TransitionProof, Verifier, item_hash,
};
use crate::claims::{
    Attempt, Claim, ClaimLimits, ClaimStatus, ClaimTally, ClaimView, EntryContext,
    MAX_CLAIM_AGE_MS, Pin, RECONCILIATION_MS, apply_entry,
};
use crate::enc::{b64, unb64_array, zbase32_encode};
use crate::http::ErrorCode;
use crate::ops::{OpKind, RecordVersion, Refusal, SignedOp};
use crate::records::{
    AppCert, AppRecord, CLOCK_TOLERANCE_MS, Freeze, IdentityDoc, ReceiveKeyRecord,
    check_part_order as check_bundle_ranges,
};
use crate::shared::RecordState;
use crate::sig::SignedDoc;

/// A head an app uploaded to the next service before the activation, checked with the old
/// service's key at the upload (Switch wire 7.4.14).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadedHead {
    /// The uploading app.
    pub app_id: [u8; 16],
    /// Its newest signed head.
    pub head: SignedHead,
}

/// A transition proof an app uploaded to the next service as evidence before the activation,
/// checked with the old service's key at the upload (Switch wire 7.4.14).
#[derive(Clone, Debug, PartialEq)]
pub struct UploadedProof {
    /// The uploading app.
    pub app_id: [u8; 16],
    /// The proof.
    pub proof: TransitionProof,
}

/// What apps uploaded to the next service before the activation (Switch wire 7.4.14, 10.5).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Uploads {
    /// The newest heads apps hold.
    pub heads: Vec<UploadedHead>,
    /// The evidence apps hold.
    pub proofs: Vec<UploadedProof>,
}

/// What the activation compares an export with (Switch wire 10.5).
#[derive(Clone, Copy, Debug)]
pub struct Activation<'a> {
    /// The manifest of the import, verified at its start (Switch wire 10.4).
    pub manifest: &'a Manifest,
    /// The freeze the import is bound to.
    pub freeze: &'a Freeze,
    /// The `identity.json` the next service was enrolled with; its service key is the old
    /// service's.
    pub enrolled: &'a IdentityDoc,
    /// The next service's trusted time, `None` without it (Switch spec 10.1).
    pub now: Option<u64>,
    /// What apps uploaded.
    pub uploads: &'a Uploads,
    /// The App IDs the enrollment named in `revoked_apps` (Switch wire 3.7), which stay
    /// tombstones whatever the export carries for them.
    pub revoked_apps: &'a [[u8; 16]],
}

/// An imported app (Switch wire 10.3, 10.5): its part, what it carries verified, its stored
/// key bundle parts, and the flags the chain adds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedApp {
    /// The part as read.
    pub part: AppPart,
    /// The verified app record.
    pub record: Option<AppRecord>,
    /// The verified receive key records with their `seq`s, oldest first.
    pub receive_keys: Vec<(ReceiveKeyRecord, u64)>,
    /// The verified renewed certificate and its `seq`.
    pub renewed_cert: Option<(AppCert, u64)>,
    /// The stored key bundle parts, in `first_epoch` order.
    pub key_bundles: Vec<KeyBundlePart>,
    /// Revoked: by its part, a `revoke` transition in the chain, or the enrollment.
    pub revoked: bool,
    /// Departed: by its part or a `leave` transition in the chain.
    pub departed: bool,
}

impl ImportedApp {
    /// Whether the app is a tombstone: a purged app's, or one the enrollment named revoked.
    pub fn is_tombstone(&self) -> bool {
        self.record.is_none() && self.receive_keys.is_empty()
    }
}

/// An imported claim, live or a tombstone (Switch wire 10.3, 10.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedClaim {
    /// The claim key.
    pub claim_key: [u8; 32],
    /// The claim: replayed from its entries for a live claim not rebuilt from uploads, else
    /// as its part gives it.
    pub claim: Claim,
    /// A live claim's entries with their proofs; none for a tombstone.
    pub entries: Vec<ClaimEntryPart>,
}

/// An imported shared record (Switch wire 10.3, 10.5): derived from its signed operation.
#[derive(Clone, Debug, PartialEq)]
pub struct ImportedRecord {
    /// The part as read.
    pub part: RecordEntry,
    /// The record's state, from the operation.
    pub state: RecordState,
    /// The verified `record.put` of the current write.
    pub op: SignedOp,
}

/// The state the next service swaps in at the activation (Switch wire 10.5 step 4).
#[derive(Clone, Debug, PartialEq)]
pub struct Import {
    /// The manifest hash.
    pub manifest_hash: [u8; 32],
    /// The imported `identity.json`.
    pub identity: IdentityDoc,
    /// The generation g.
    pub generation: u64,
    /// The last `seq` given out, the head's.
    pub seq: u64,
    /// The directory version.
    pub directory_version: u64,
    /// The apps version.
    pub apps_version: u64,
    /// The apps reachable at the import, current with a receive key (Switch wire 7.4.10).
    pub reachable: Vec<[u8; 16]>,
    /// `app_added_at` for the reachable apps only, as the meta part gives it: the service
    /// keeps no entry for an app that isn't reachable (Switch wire 10.3).
    pub app_added_at: Vec<([u8; 16], u64)>,
    /// The old service's head the import ends at.
    pub head: SignedHead,
    /// The checkpoint the chain parts start after, which the next service signs again with
    /// its own key.
    pub checkpoint: Option<SignedHead>,
    /// The manifest's `last_time`, which the next service's time continues from.
    pub last_time: u64,
    /// The freeze transition's `at`.
    pub freeze_at: u64,
    /// The chain parts, in `seq` order.
    pub chain: Vec<ChainPart>,
    /// The pending inbox entries.
    pub entries: Vec<EntryPart>,
    /// The apps, by App ID.
    pub apps: Vec<ImportedApp>,
    /// The live claims.
    pub claims: Vec<ImportedClaim>,
    /// The tombstones.
    pub tombstones: Vec<ImportedClaim>,
    /// The shared records.
    pub records: Vec<ImportedRecord>,
    /// The batch records, without proofs.
    pub batches: Vec<BatchPart>,
    /// The contacts.
    pub contacts: Vec<[u8; 32]>,
    /// The conversation entries.
    pub conversations: Vec<ConversationPart>,
    /// The deny list.
    pub deny: Vec<[u8; 32]>,
    /// The invite codes.
    pub invite_codes: Vec<InviteCodePart>,
    /// The connect requests, oldest first.
    pub connect: Vec<ConnectPart>,
    /// The flagged senders.
    pub flags: Vec<FlagPart>,
    /// The peers' verified `identity.json` copies.
    pub peers: Vec<IdentityDoc>,
    /// The floors dropped peer copies left.
    pub peer_floors: Vec<PeerFloorPart>,
    /// Each record's divergent uploads, in `index` order.
    pub divergent: Vec<([u8; 32], Vec<SignedDoc>)>,
}

/// One `chain` part, as the checks keep it.
struct Chained<'a> {
    part: &'a ChainPart,
    envelope: ChainEnvelope,
}

impl Chained<'_> {
    /// The operation the item carries, while its document is kept.
    fn op(&self) -> std::result::Result<Option<SignedOp>, Refusal> {
        match (&self.part.doc, self.part.item_type) {
            (Some(doc), ItemType::Op) => SignedOp::peek(doc).map(Some).map_err(|e| {
                conflict(format!(
                    "Switch wire 10.5: the operation at seq {} doesn't read: {}",
                    self.part.seq, e.reason
                ))
            }),
            _ => Ok(None),
        }
    }

    /// The service transition the item carries, while its document is kept.
    fn transition(&self) -> std::result::Result<Option<ServiceTransition>, Refusal> {
        match (&self.part.doc, self.part.item_type) {
            (Some(doc), ItemType::Service) => doc
                .peek::<Value>()
                .and_then(|v| ServiceTransition::from_value(&v))
                .map(Some)
                .map_err(|e| {
                    conflict_of(
                        &format!(
                            "Switch wire 10.5: the transition at seq {} doesn't read",
                            self.part.seq
                        ),
                        e,
                    )
                }),
            _ => Ok(None),
        }
    }
}

/// The parts, gathered as the parts of Switch wire 10.3 hold them (Switch wire 10.5 step 3).
#[derive(Default)]
struct Gathered<'a> {
    chain: Vec<&'a ChainPart>,
    entries: Vec<&'a EntryPart>,
    apps: Vec<(&'a AppPart, Vec<KeyBundlePart>)>,
    claims: Vec<(&'a ClaimPart, Vec<ClaimEntryPart>)>,
    tombstones: Vec<(&'a [u8; 32], &'a TombstoneState)>,
    records: Vec<&'a RecordEntry>,
    batches: Vec<BatchPart>,
    contacts: Vec<[u8; 32]>,
    conversations: Vec<ConversationPart>,
    deny: Vec<[u8; 32]>,
    invite_codes: Vec<InviteCodePart>,
    connect: Vec<ConnectPart>,
    flags: Vec<FlagPart>,
    peers: Vec<&'a SignedDoc>,
    peer_floors: Vec<PeerFloorPart>,
    divergent: Vec<([u8; 32], Vec<SignedDoc>)>,
}

fn gather(parts: &[Part]) -> std::result::Result<Gathered<'_>, Refusal> {
    let mut g = Gathered::default();
    for part in parts.iter().skip(1) {
        match part {
            Part::Meta(_) => return Err(bad("Switch wire 10.5: a second meta part")),
            Part::Chain(p) => g.chain.push(p),
            Part::Entry(p) => g.entries.push(p),
            Part::App(p) => g.apps.push((p, Vec::new())),
            Part::KeyBundle(p) => match g.apps.last_mut() {
                Some((app, bundles)) if app.app_id == p.app_id => bundles.push(p.clone()),
                _ => {
                    return Err(bad(
                        "Switch wire 10.3: a key_bundle part doesn't follow its app's part",
                    ));
                }
            },
            Part::Claim(p) => g.claims.push((p, Vec::new())),
            Part::ClaimEntry(p) => match g.claims.last_mut() {
                Some((claim, entries)) if claim.claim_key == p.claim_key => entries.push(p.clone()),
                _ => {
                    return Err(bad(
                        "Switch wire 10.3: a claim_entry part doesn't follow its claim's part",
                    ));
                }
            },
            Part::Tombstone(p) => g.tombstones.push((&p.claim_key, &p.tombstone)),
            Part::Record(p) => g.records.push(p),
            Part::Batch(p) => g.batches.push(*p),
            Part::Contact(p) => g.contacts.push(*p),
            Part::Conversation(p) => g.conversations.push(p.clone()),
            Part::Deny(p) => g.deny.push(*p),
            Part::InviteCode(p) => g.invite_codes.push(p.clone()),
            Part::Connect(p) => g.connect.push(*p),
            Part::Flag(p) => g.flags.push(*p),
            Part::Peer(p) => g.peers.push(&p.doc),
            Part::PeerFloor(p) => g.peer_floors.push(*p),
            Part::Divergent(p) => match g.divergent.last_mut() {
                Some((key, uploads)) if *key == p.key => uploads.push(p.upload.clone()),
                _ => g.divergent.push((p.key, vec![p.upload.clone()])),
            },
        }
    }
    for (_, bundles) in &g.apps {
        check_bundle_ranges(bundles.iter().map(|b| (b.first_epoch, b.last_epoch))).map_err(
            |e| {
                bad(format!(
                    "Switch wire 10.5: an app's key_bundle parts: {}",
                    reason(e)
                ))
            },
        )?;
    }
    Ok(g)
}

/// The facts of the chain parts the later checks read.
struct ChainFacts<'a> {
    /// The chain parts by `seq`.
    at: BTreeMap<u64, Chained<'a>>,
    /// The verifier after the last part.
    verifier: Verifier,
}

/// Run the activation's checks on an export (Switch wire 10.5 steps 2 and 3), in the order the
/// wire format lists them, answering with the first that fails. `parts` are every part of the
/// export, in manifest order ([`Manifest::read_parts`]). Returns the state to swap in.
///
/// # Errors
///
/// `503 unavailable` without trusted time; `400 bad_request`, `401 bad_signature` or `409
/// conflict` by the check that fails, its reason naming the rule.
pub fn activate(cx: &Activation<'_>, parts: &[Part]) -> std::result::Result<Import, Refusal> {
    let Some(now) = cx.now else {
        return Err(Refusal::new(
            ErrorCode::Unavailable,
            "Switch wire 10.5 step 2: no trusted time",
        ));
    };
    let m = cx.manifest.body();
    let identity = m.identity;
    let g = m.generation;
    let o_key = cx.enrolled.inbox().service_key;
    if u64::try_from(parts.len()).ok() != Some(m.parts) {
        return Err(bad(
            "Switch wire 10.5: the number of parts isn't the manifest's",
        ));
    }
    // The order of Switch wire 10.3, meta first and only first.
    check_part_order(parts)?;
    let Some(Part::Meta(meta)) = parts.first() else {
        return Err(bad("Switch wire 10.5: the first part isn't meta"));
    };
    let gathered = gather(parts)?;
    // The meta part's identity.json verifies for the identity.
    let doc = IdentityDoc::verify(&meta.identity, &identity).map_err(doc_refusal)?;
    // It has generation g and at least the enrolled version, and is that very document at
    // that version.
    let enrolled = cx.enrolled;
    if doc.generation() != g
        || doc.version() < enrolled.version()
        || (doc.version() == enrolled.version() && doc.hash() != enrolled.hash())
    {
        return Err(conflict(
            "Switch wire 10.5: the imported identity.json goes back on the enrolled one",
        ));
    }
    // The head and the checkpoint are the old service's.
    m.head
        .verify(&o_key, &identity)
        .map_err(|e| bad_signature(format!("Switch wire 10.5: the head: {}", reason(e))))?;
    if let Some(checkpoint) = &m.checkpoint {
        checkpoint.verify(&o_key, &identity).map_err(|e| {
            bad_signature(format!("Switch wire 10.5: the checkpoint: {}", reason(e)))
        })?;
        if checkpoint.generation > g || checkpoint.seq >= m.head.seq {
            return Err(conflict(
                "Switch wire 10.5: the checkpoint isn't in generation g or earlier, before the head",
            ));
        }
    }
    if meta.generation != g || meta.seq != m.head.seq {
        return Err(conflict(
            "Switch wire 10.5: the meta part's generation or seq isn't the head's",
        ));
    }
    let floor = m.checkpoint.map_or(0, |c| c.seq);
    let facts = check_chain(cx.manifest, &gathered.chain)?;
    let freeze_at = check_freeze_head(cx, &facts, &identity, &o_key)?;
    // The meta part's identity.json is the newest identity item of the chain parts.
    if let Some(newest) = facts
        .at
        .values()
        .rev()
        .find(|c| c.envelope.item_type == ItemType::Identity)
    {
        let bytes = meta.identity.doc_bytes().map_err(doc_refusal)?;
        if newest.envelope.item_hash != item_hash(ItemType::Identity, &bytes) {
            return Err(conflict(
                "Switch wire 10.5: the meta part's identity.json isn't the newest identity item",
            ));
        }
    }
    if m.last_time < freeze_at {
        return Err(conflict(
            "Switch wire 10.5: last_time is before the freeze transition's at",
        ));
    }
    let ahead = now.saturating_add(CLOCK_TOLERANCE_MS);
    if m.last_time > ahead || freeze_at > ahead {
        return Err(conflict(
            "Switch wire 10.5: last_time or the freeze's at is ahead of this service's time",
        ));
    }
    for uploaded in &cx.uploads.heads {
        let h = uploaded.head;
        if h.seq < floor {
            continue;
        }
        if h.seq > m.head.seq || facts.verifier.chain_hash_at(h.seq) != Some(h.chain_hash) {
            return Err(conflict(format!(
                "Switch wire 10.5: the head app {} uploaded at seq {} isn't on the imported chain",
                zbase32_encode(&uploaded.app_id),
                h.seq
            )));
        }
    }
    let mut apps = check_apps(&gathered, &facts, &doc, &identity, floor)?;
    let records = check_records(&gathered, &facts, &doc, &apps, cx, floor)?;
    let (claims, tombstones) = check_claims(&gathered, &facts, &identity, &o_key, g, floor)?;
    for entry in &gathered.entries {
        if entry.seq > meta.seq || facts.at.contains_key(&entry.seq) {
            return Err(conflict(format!(
                "Switch wire 10.5: the inbox entry at seq {} isn't at a seq the old service gave an entry",
                entry.seq
            )));
        }
    }
    let batch_ids: HashSet<[u8; 16]> = gathered.batches.iter().map(|b| b.id).collect();
    for chained in facts.at.values() {
        if let Some(batch) = chained.envelope.batch
            && !batch_ids.contains(&batch.id)
        {
            return Err(conflict(format!(
                "Switch wire 10.5: the stub at seq {} names a batch without its batch part",
                chained.part.seq
            )));
        }
    }
    check_evidence(cx, &claims, &tombstones, &records)?;
    let peers = gathered
        .peers
        .iter()
        .map(|d| IdentityDoc::verify_named(d).map_err(doc_refusal))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let peer_ids: HashSet<[u8; 32]> = peers.iter().map(IdentityDoc::identity).collect();
    if gathered
        .peer_floors
        .iter()
        .any(|f| peer_ids.contains(&f.identity))
    {
        return Err(bad(
            "Switch wire 10.3: a peer_floor beside a peer part of the same identity",
        ));
    }
    // The enrollment's revoked apps stay tombstones (Switch wire 10.5 step 4).
    for revoked in cx.revoked_apps {
        match apps.iter_mut().find(|a| &a.part.app_id == revoked) {
            Some(app) => {
                app.record = None;
                app.receive_keys.clear();
                app.renewed_cert = None;
                app.key_bundles.clear();
                app.revoked = true;
            }
            None => apps.push(tombstone_app(*revoked)),
        }
    }
    apps.sort_by_key(|a| zbase32_encode(&a.part.app_id));
    let reachable: Vec<[u8; 16]> = apps
        .iter()
        .filter(|a| is_reachable(a, &doc, now))
        .map(|a| a.part.app_id)
        .collect();
    let app_added_at = meta
        .app_added_at
        .iter()
        .filter(|(id, _)| reachable.contains(id))
        .copied()
        .collect();
    Ok(Import {
        manifest_hash: cx.manifest.hash(),
        identity: doc,
        generation: g,
        seq: meta.seq,
        directory_version: meta.directory_version,
        apps_version: meta.apps_version,
        reachable,
        app_added_at,
        head: m.head,
        checkpoint: m.checkpoint,
        last_time: m.last_time,
        freeze_at,
        chain: gathered.chain.iter().map(|c| (*c).clone()).collect(),
        entries: gathered.entries.iter().map(|e| (*e).clone()).collect(),
        apps,
        claims,
        tombstones,
        records,
        batches: gathered.batches,
        contacts: gathered.contacts,
        conversations: gathered.conversations,
        deny: gathered.deny,
        invite_codes: gathered.invite_codes,
        connect: gathered.connect,
        flags: gathered.flags,
        peers,
        peer_floors: gathered.peer_floors,
        divergent: gathered.divergent,
    })
}

/// The chain parts (Switch wire 10.5): each passes every check an app makes on a stub, from
/// the checkpoint's chain hash or 32 zero bytes, with no previous time right after the
/// checkpoint; its `seq` and item type are its stub's; a part with its document matches its
/// stub; and the chain ends at the head, of generation g.
fn check_chain<'a>(
    manifest: &Manifest,
    chain: &[&'a ChainPart],
) -> std::result::Result<ChainFacts<'a>, Refusal> {
    let m = manifest.body();
    let mut verifier = match &m.checkpoint {
        Some(checkpoint) => Verifier::from_checkpoint(checkpoint),
        None => Verifier::new(1),
    };
    let mut at = BTreeMap::new();
    for part in chain {
        let fail = |why: String| {
            conflict(format!(
                "Switch wire 10.5: the chain part at seq {}: {why}",
                part.seq
            ))
        };
        let envelope = verifier.push(&part.stub).map_err(|e| fail(e.to_string()))?;
        if envelope.seq != part.seq || envelope.item_type != part.item_type {
            return Err(fail("its seq or item type isn't its stub's".into()));
        }
        if let Some(doc) = &part.doc {
            let bytes = doc.doc_bytes().map_err(doc_refusal)?;
            Verifier::check_item(&envelope, part.item_type, &bytes)
                .map_err(|e| fail(e.to_string()))?;
        }
        at.insert(part.seq, Chained { part, envelope });
    }
    verifier
        .end_of_feed()
        .map_err(|e| conflict(format!("Switch wire 10.5: {e}")))?;
    let (last_seq, last_hash) = verifier.last();
    let ends_in_g = at
        .values()
        .next_back()
        .is_some_and(|c| c.envelope.generation == m.generation);
    if last_seq != m.head.seq
        || last_hash != m.head.chain_hash
        || m.head.generation != m.generation
        || !ends_in_g
    {
        return Err(conflict(
            "Switch wire 10.5: the chain doesn't end at the manifest's head, in generation g",
        ));
    }
    Ok(ChainFacts { at, verifier })
}

/// The head is the freeze transition (Switch wire 10.5): the last chain part, at the head's
/// `seq`, is a `service` item with its document, a `freeze` transition that verifies with the
/// old service's key and names the manifest's freeze. Returns its `at`.
fn check_freeze_head(
    cx: &Activation<'_>,
    facts: &ChainFacts<'_>,
    identity: &[u8; 32],
    o_key: &[u8; 32],
) -> std::result::Result<u64, Refusal> {
    let fail = |why: &str| {
        Err(conflict(format!(
            "Switch wire 10.5: the head isn't the freeze transition: {why}"
        )))
    };
    let m = cx.manifest.body();
    let Some(last) = facts.at.values().next_back() else {
        return fail("no chain part");
    };
    if last.part.seq != m.head.seq || last.part.item_type != ItemType::Service {
        return fail("the last chain part isn't a service item at the head");
    }
    let Some(doc) = &last.part.doc else {
        return fail("its document was dropped");
    };
    let Ok(transition) = ServiceTransition::verify(doc, o_key, identity) else {
        return fail("it doesn't verify with the old service's key");
    };
    match transition {
        ServiceTransition::Freeze {
            freeze_hash, at, ..
        } if freeze_hash == m.freeze_hash && freeze_hash == cx.freeze.hash() => Ok(at),
        ServiceTransition::Freeze { .. } => fail("it names another freeze"),
        _ => fail("it isn't a freeze transition"),
    }
}

/// The apps (Switch wire 10.5).
fn check_apps(
    g: &Gathered<'_>,
    facts: &ChainFacts<'_>,
    doc: &IdentityDoc,
    identity: &[u8; 32],
    floor: u64,
) -> std::result::Result<Vec<ImportedApp>, Refusal> {
    let missing = |app: &[u8; 16]| {
        conflict(format!(
            "Switch wire 10.5: no app part for app {}",
            zbase32_encode(app)
        ))
    };
    // Indexed once: the parts come from the old service, so lookups stay linear in them.
    let app_parts: HashSet<[u8; 16]> = g.apps.iter().map(|(p, _)| p.app_id).collect();
    let has_part = |app: &[u8; 16]| app_parts.contains(app);
    for listed in &doc.body().apps {
        if !has_part(&listed.app_id) {
            return Err(missing(&listed.app_id));
        }
    }
    // The newest `receive_key.put` the chain parts hold for each app, and the apps whose
    // `leave` or `revoke` the chain holds.
    let mut newest_key: HashMap<[u8; 16], u64> = HashMap::new();
    let mut revoked: HashSet<[u8; 16]> = HashSet::new();
    let mut departed: HashSet<[u8; 16]> = HashSet::new();
    for chained in facts.at.values() {
        if let Some(op) = chained.op()? {
            let body = op.body();
            if let (OpKind::AppPut { .. } | OpKind::ReceiveKeyPut { .. }, Some(app)) =
                (&body.kind, body.app_id)
            {
                if !has_part(&app) {
                    return Err(missing(&app));
                }
                if matches!(body.kind, OpKind::ReceiveKeyPut { .. }) {
                    newest_key.insert(app, chained.part.seq);
                }
            }
        }
        match chained.transition()? {
            Some(ServiceTransition::Revoke { app_id, .. }) => {
                revoked.insert(app_id);
            }
            Some(ServiceTransition::Leave { app_id, .. }) => {
                departed.insert(app_id);
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for (part, bundles) in &g.apps {
        let app = part.app_id;
        let record = part
            .record
            .as_ref()
            .map(|d| AppRecord::verify(d, identity).map_err(doc_refusal))
            .transpose()?;
        if record.as_ref().is_some_and(|r| r.cert().app_id() != app) {
            return Err(bad(
                "Switch wire 10.5: an app part's record is another app's",
            ));
        }
        let mut keys = Vec::new();
        let mut previous: Option<(u64, u64)> = None;
        for (signed, seq) in &part.receive_keys {
            let Some(record) = &record else {
                return Err(bad(
                    "Switch wire 10.5: an app part holds receive keys without a record",
                ));
            };
            let key = ReceiveKeyRecord::verify(signed, record.cert()).map_err(doc_refusal)?;
            if previous.is_some_and(|(n, s)| key.n() <= n || *seq <= s) {
                return Err(conflict(
                    "Switch wire 10.5: an app's receive keys aren't in increasing n and seq",
                ));
            }
            previous = Some((key.n(), *seq));
            if *seq > floor {
                let chained = facts.at.get(seq).map(Chained::op).transpose()?.flatten();
                let is_item = chained.is_some_and(|op| {
                    op.body().app_id == Some(app)
                        && matches!(&op.body().kind, OpKind::ReceiveKeyPut { record } if record == signed)
                });
                if !is_item {
                    return Err(conflict(format!(
                        "Switch wire 10.5: the receive key at seq {seq} isn't that chain item"
                    )));
                }
            }
            keys.push((key, *seq));
        }
        let purged = record.is_none() && doc.listed_cert(&app).is_none();
        if let Some(newest) = newest_key.get(&app)
            && !purged
            && keys.last().map(|(_, seq)| seq) != Some(newest)
        {
            return Err(conflict(
                "Switch wire 10.5: an app's last receive key isn't the chain's newest",
            ));
        }
        let renewed_cert = part
            .renewed_cert
            .as_ref()
            .map(|(signed, seq)| {
                let cert = AppCert::verify(signed, identity).map_err(doc_refusal)?;
                if cert.app_id() != app {
                    return Err(bad(
                        "Switch wire 10.5: an app part's renewed certificate is another app's",
                    ));
                }
                Ok((cert, *seq))
            })
            .transpose()?;
        for bundle in bundles {
            bundle.bundle.verify(identity, &app).map_err(|e| {
                bad_signature(format!(
                    "Switch wire 10.5: a key bundle part: {}",
                    reason(e)
                ))
            })?;
        }
        out.push(ImportedApp {
            part: (*part).clone(),
            record,
            receive_keys: keys,
            renewed_cert,
            key_bundles: bundles.clone(),
            revoked: part.revoked_at_ms.is_some() || revoked.contains(&app),
            departed: part.departed_at_ms.is_some() || departed.contains(&app),
        });
    }
    Ok(out)
}

/// The shared records (Switch wire 10.5): each derived from its signed operation, with the
/// proof of its current write.
fn check_records(
    g: &Gathered<'_>,
    facts: &ChainFacts<'_>,
    doc: &IdentityDoc,
    apps: &[ImportedApp],
    cx: &Activation<'_>,
    floor: u64,
) -> std::result::Result<Vec<ImportedRecord>, Refusal> {
    let m = cx.manifest.body();
    let identity = m.identity;
    // Every `record.put` the chain parts hold with its document, by key: its `seq`s.
    let mut puts: HashMap<[u8; 32], Vec<u64>> = HashMap::new();
    for chained in facts.at.values() {
        if let Some(op) = chained.op()?
            && let OpKind::RecordPut(put) = &op.body().kind
        {
            puts.entry(put.key).or_default().push(chained.part.seq);
        }
    }
    let lost = |generation: u64| {
        doc.body()
            .recovery_from
            .is_some_and(|lost| generation <= lost)
    };
    let mut out = Vec::new();
    for r in &g.records {
        let fail = |why: &str| conflict(format!("Switch wire 10.5: a shared record: {why}"));
        let chained = facts.at.get(&r.seq);
        let in_chain = match chained {
            Some(c) if c.part.item_type == ItemType::Op => c.part.doc.as_ref(),
            _ => None,
        };
        let op_doc = match (&r.op, in_chain) {
            (Some(carried), Some(chain)) if carried != chain => {
                return Err(fail("its op isn't the chain item at its seq"));
            }
            (Some(carried), _) => carried,
            (None, Some(chain)) => chain,
            (None, None) => {
                return Err(fail("op is null and no chain part at its seq carries it"));
            }
        };
        let cert = match &r.cert {
            Some(signed) => AppCert::verify(signed, &identity).map_err(doc_refusal)?,
            None => apps
                .iter()
                .find(|a| a.part.app_id == r.writer)
                .and_then(|a| a.record.as_ref())
                .map(|rec| rec.cert().clone())
                .ok_or_else(|| fail("no certificate: cert is null and the writer has no record"))?,
        };
        let op = SignedOp::verify(op_doc, &cert.signing_key(), &identity, Some(&r.writer))
            .map_err(|e| match e.code {
                ErrorCode::BadSignature => e,
                _ => fail(&format!("its operation doesn't verify: {}", e.reason)),
            })?;
        let OpKind::RecordPut(put) = &op.body().kind else {
            return Err(fail("its op isn't a record.put"));
        };
        if !put.policy.write_scopes.iter().any(|s| cert.holds_scope(s)) {
            return Err(fail(
                "the writer's certificate holds none of its write scopes",
            ));
        }
        let deleted = put.value_sealed.looks_like_delete();
        let size = if deleted {
            0
        } else {
            u64::try_from(put.value_sealed.ct.len()).unwrap_or(u64::MAX)
        };
        let generation = op.body().generation;
        if r.key != put.key
            || r.collection != put.collection
            || r.read_scope != put.policy.read_scope
            || r.write_scopes != put.policy.write_scopes
            || r.deleted != deleted
            || r.size != size
            || r.generation != generation
            || generation > m.generation
        {
            return Err(fail("a member isn't its operation's"));
        }
        let key_puts = puts.get(&r.key).map(Vec::as_slice).unwrap_or_default();
        if r.from_upload {
            if generation >= m.generation {
                return Err(fail(
                    "a record from an upload isn't of an earlier generation",
                ));
            }
            match chained {
                Some(c) => {
                    let listed = match c.transition()? {
                        Some(ServiceTransition::Upload { changes, .. }) => changes
                            .get("records")
                            .and_then(Value::as_array)
                            .is_some_and(|keys| {
                                keys.iter().any(|k| k.as_str() == Some(&b64(&r.key)))
                            }),
                        // The transition's document was dropped: the stub alone vouches.
                        None => c.part.doc.is_none() && c.part.item_type == ItemType::Service,
                        Some(_) => false,
                    };
                    if !listed {
                        return Err(fail("the upload transition at its seq doesn't list it"));
                    }
                }
                None if r.seq > floor => {
                    return Err(fail("no upload transition at its seq"));
                }
                None => {}
            }
        } else if m.checkpoint.is_some() && r.seq <= floor {
            if r.version > floor || !key_puts.is_empty() {
                return Err(fail(
                    "a write at or behind the checkpoint isn't one no chain part covers",
                ));
            }
        } else {
            let in_g = chained.is_some_and(|c| c.envelope.generation == generation);
            if in_chain != Some(op_doc)
                || !in_g
                || r.version != r.seq
                || key_puts.iter().any(|s| *s > r.seq)
            {
                return Err(fail(
                    "a write after the checkpoint isn't the full chain item at its seq, the newest",
                ));
            }
        }
        check_record_proof(r, &op, cx, doc, lost(generation))?;
        out.push(ImportedRecord {
            part: (*r).clone(),
            state: RecordState::after(put, r.generation, r.version),
            op,
        });
    }
    // Every `record.put` the chain parts hold with its document is its key's current write.
    let current_writes: HashMap<[u8; 32], u64> = g.records.iter().map(|r| (r.key, r.seq)).collect();
    for (key, seqs) in &puts {
        let current = current_writes.get(key).copied();
        if seqs.iter().any(|s| Some(*s) != current) {
            return Err(conflict(
                "Switch wire 10.5: a record.put the chain parts hold isn't its key's current write",
            ));
        }
    }
    Ok(out)
}

/// A record's proof (Switch wire 10.5): every part but one from a recovery upload carries the
/// proof of its current write, and an upload's carries none; the proof names that write and
/// verifies with that generation's service key, the old service's for g, else the one the
/// imported `identity.json` lists. A generation that document declares lost dates nothing,
/// so the record is kept without a proof.
fn check_record_proof(
    r: &RecordEntry,
    op: &SignedOp,
    cx: &Activation<'_>,
    doc: &IdentityDoc,
    lost: bool,
) -> std::result::Result<(), Refusal> {
    let m = cx.manifest.body();
    let fail = |why: &str| conflict(format!("Switch wire 10.5: a shared record: {why}"));
    let signed = match (r.from_upload, &r.proof) {
        (true, Some(_)) => {
            return Err(fail(
                "a record taken from a recovery upload carries a proof",
            ));
        }
        (true, None) => return Ok(()),
        (false, None) if lost => return Ok(()),
        (false, None) => return Err(fail("no proof of its current write")),
        (false, Some(signed)) => signed,
    };
    let proof = TransitionProof::peek(signed)
        .map_err(|e| fail(&format!("its proof doesn't read: {}", reason(e))))?;
    let env = proof.envelope();
    let state = &proof.body().state;
    let shows = |member: &str| state.get(member).and_then(Value::as_u64);
    let item = op.item_hash().map_err(doc_refusal)?;
    if env.item_type != ItemType::Op
        || env.item_hash != item
        || env.seq != r.seq
        || env.generation != op.body().generation
        || proof.body().object != b64(&r.key)
        || shows("generation") != Some(r.generation)
        || shows("version") != Some(r.version)
    {
        return Err(fail("its proof isn't the proof of its current write"));
    }
    let key = if env.generation == m.generation {
        Some(cx.enrolled.inbox().service_key)
    } else {
        doc.service_key_of(env.generation)
    };
    match key {
        Some(key) => TransitionProof::verify(signed, &key, &m.identity)
            .map(drop)
            .map_err(|_| {
                fail(&format!(
                    "its proof doesn't verify with generation {}'s service key",
                    env.generation
                ))
            }),
        None if lost => Ok(()),
        None => Err(fail(&format!(
            "its proof names generation {}, which the identity.json doesn't list",
            env.generation
        ))),
    }
}

/// The replay context: what an entry was applied against isn't known at the import, so no
/// limit refuses and no owner counts as current. The proofs the old service signed show the
/// state each entry gave, which the replay is compared with.
fn replay_context<'a>(
    writer: [u8; 16],
    now: u64,
    nobody: &'a dyn Fn(&[u8; 16]) -> bool,
) -> EntryContext<'a> {
    EntryContext {
        writer,
        now,
        can_read: false,
        is_current: nobody,
        limits: ClaimLimits {
            max_claims: u64::MAX,
            max_attempts_per_claim: u64::MAX,
            open_attempts_per_app: u64::MAX,
            claim_share_percent: 100,
        },
        tally: ClaimTally::default(),
    }
}

fn to_attempt(a: &AttemptState) -> Attempt {
    Attempt {
        attempt_id: a.attempt_id,
        owner: a.owner,
        outcome: a.outcome,
        opened_at: a.opened_at_ms,
        orphan_after: a.orphan_after_s,
        possibly_duplicate: a.possibly_duplicate,
        duplicate: a.duplicate,
        resolved_by: a.resolved_by,
        from_upload: a.from_upload,
    }
}

/// A live claim's part as a [`Claim`].
fn claim_of(c: &ClaimState) -> std::result::Result<Claim, Refusal> {
    let attempts: Vec<Attempt> = c.attempts.iter().map(to_attempt).collect();
    let current = match c.current {
        None => None,
        Some(id) => Some(
            attempts
                .iter()
                .position(|a| a.attempt_id == id)
                .ok_or_else(|| {
                    conflict(
                        "Switch wire 10.5: a claim's current attempt isn't one of its attempts",
                    )
                })?,
        ),
    };
    Ok(Claim {
        step: c.step,
        attempts,
        current,
        settled: c.settled,
        tombstone: false,
        pin: c.pinned_deadline,
        divergent: c.divergent,
        rebuilt: c.rebuilt,
        creator: c.creator,
        last_entry: c.last_entry_ms,
    })
}

/// A view without what depends on when it is read (Switch wire 10.5).
fn timeless(mut view: ClaimView) -> ClaimView {
    view.next_possibly_duplicate = false;
    for attempt in &mut view.attempts {
        attempt.orphaned = false;
    }
    view
}

/// The live claims and tombstones (Switch wire 10.5).
fn check_claims(
    g: &Gathered<'_>,
    facts: &ChainFacts<'_>,
    identity: &[u8; 32],
    o_key: &[u8; 32],
    generation: u64,
    floor: u64,
) -> std::result::Result<(Vec<ImportedClaim>, Vec<ImportedClaim>), Refusal> {
    let nobody = |_: &[u8; 16]| false;
    let mut claims = Vec::new();
    for (part, entries) in &g.claims {
        let fail = |why: &str| conflict(format!("Switch wire 10.5: a live claim: {why}"));
        let key = part.claim_key;
        let state = &part.claim;
        let mut replayed: Option<Claim> = None;
        let mut last: Option<(u64, TransitionProof)> = None;
        for entry in entries {
            if last.as_ref().is_some_and(|(step, _)| entry.step <= *step) {
                return Err(fail("its entries' steps don't increase"));
            }
            let op = SignedOp::peek(&entry.op)
                .map_err(|e| fail(&format!("an entry doesn't read: {}", e.reason)))?;
            let OpKind::Claim(fields) = &op.body().kind else {
                return Err(fail("an entry isn't a claim entry"));
            };
            let op_generation = op.body().generation;
            let proof = if op_generation == generation {
                TransitionProof::verify(&entry.proof, o_key, identity).map_err(|_| {
                    fail("an entry's proof doesn't verify with the old service's key")
                })?
            } else if op_generation < generation {
                // An entry of an earlier generation carries the proof of the service that
                // applied it, and is bound by its chain item instead.
                TransitionProof::peek(&entry.proof)
                    .map_err(|_| fail("an entry's proof doesn't read"))?
            } else {
                return Err(fail("an entry of a later generation"));
            };
            let env = proof.envelope();
            let item = op.item_hash().map_err(doc_refusal)?;
            if fields.claim_key.as_slice() != key.as_slice()
                || fields.expected_step != entry.step
                || proof.body().object != b64(&key)
                || env.item_type != ItemType::Op
                || env.item_hash != item
                || env.seq != entry.seq
                || proof.body().step != entry.step.checked_add(1)
            {
                return Err(fail("an entry's proof isn't that entry's"));
            }
            if entry.seq > floor {
                let on_chain = facts.at.get(&entry.seq).is_some_and(|c| {
                    c.part.stub.chain_hash == proof.body().chain.chain_hash
                        && c.part.doc.as_ref().is_none_or(|d| d == &entry.op)
                });
                if !on_chain {
                    return Err(fail("an entry isn't the chain item at its seq"));
                }
            }
            if !state.rebuilt {
                let writer = op
                    .body()
                    .app_id
                    .ok_or_else(|| fail("an entry without an app"))?;
                let checked = fields
                    .check()
                    .map_err(|e| fail(&format!("an entry doesn't read: {}", e.reason)))?;
                let cx = replay_context(writer, env.server_time, &nobody);
                let next = apply_entry(replayed.as_ref(), &checked, &cx)
                    .map_err(|e| fail(&format!("an entry doesn't apply: {}", e.reason)))?;
                replayed = Some(next);
            }
            last = Some((entry.step, proof));
        }
        let first_owner = state.attempts.first().map(|a| a.owner);
        let claim = match (&last, state.rebuilt) {
            (None, false) => return Err(fail("a live claim without entries")),
            (Some((step, _)), _)
                if state.step <= *step
                    || (!state.rebuilt && Some(state.step) != step.checked_add(1)) =>
            {
                return Err(fail("its step isn't one after its last entry"));
            }
            (_, true) => {
                if state.creator != first_owner {
                    return Err(fail("its creator isn't the owner of its first attempt"));
                }
                claim_of(state)?
            }
            (Some((_, proof)), false) => {
                let Some(claim) = replayed else {
                    return Err(fail("a live claim without entries"));
                };
                if state.creator != claim.creator || state.creator != first_owner {
                    return Err(fail("its creator isn't the owner of its first attempt"));
                }
                if state.last_entry_ms != Some(proof.envelope().server_time) {
                    return Err(fail("its last_entry_ms isn't its last entry's time"));
                }
                let shown = ClaimView::from_value(&proof.body().state)
                    .map_err(|_| fail("its last entry's proof shows no claim view"))?;
                let view = claim.view(&key, proof.envelope().server_time, &nobody);
                if timeless(view) != timeless(shown) {
                    return Err(fail(
                        "its state isn't the state its last entry's proof shows",
                    ));
                }
                let pinned = claim.pin.deadline();
                if claim.tombstone
                    || claim_of(state)? != claim
                    || state.attempts.iter().any(|a| a.deadline_ms != pinned)
                {
                    return Err(fail("its state isn't the state its entries give"));
                }
                claim
            }
        };
        claims.push(ImportedClaim {
            claim_key: key,
            claim,
            entries: entries.clone(),
        });
    }
    let mut tombstones = Vec::new();
    for (key, t) in &g.tombstones {
        if t.creator != t.attempts.first().map(|a| a.owner) {
            return Err(conflict(
                "Switch wire 10.5: a tombstone's creator isn't the owner of its first attempt",
            ));
        }
        tombstones.push(ImportedClaim {
            claim_key: **key,
            claim: Claim {
                step: t.step,
                attempts: t.attempts.iter().map(to_attempt).collect(),
                current: None,
                settled: true,
                tombstone: true,
                pin: t.deadline_ms.map_or(Pin::NoDeadline, Pin::At),
                divergent: false,
                rebuilt: false,
                creator: t.creator,
                last_entry: t.last_entry_ms,
            },
            entries: Vec::new(),
        });
    }
    Ok((claims, tombstones))
}

/// The uploaded evidence (Switch wire 10.5, Switch spec 12.5 step 3), compared by what the
/// operations signed: a claim a proof shows SETTLED is SETTLED here, live or as a tombstone,
/// unless the old service may have deleted it by `last_time`; a claim a proof shows with an
/// attempt is held with that attempt, at that step or later; a record a proof shows at a
/// version is that very write, or one whose signed `expected_version` is that version or
/// later, or absent when that version deletes.
fn check_evidence(
    cx: &Activation<'_>,
    claims: &[ImportedClaim],
    tombstones: &[ImportedClaim],
    records: &[ImportedRecord],
) -> std::result::Result<(), Refusal> {
    let last_time = cx.manifest.body().last_time;
    // Indexed once, so the work stays linear in the uploads and the import.
    let live_claims: HashMap<[u8; 32], &ImportedClaim> =
        claims.iter().map(|c| (c.claim_key, c)).collect();
    let tombstone_claims: HashMap<[u8; 32], &ImportedClaim> =
        tombstones.iter().map(|c| (c.claim_key, c)).collect();
    let held_records: HashMap<[u8; 32], &ImportedRecord> =
        records.iter().map(|r| (r.part.key, r)).collect();
    for uploaded in &cx.uploads.proofs {
        let fail = |what: &str| {
            Err(conflict(format!(
                "Switch wire 10.5: the evidence app {} uploaded shows {what}",
                zbase32_encode(&uploaded.app_id)
            )))
        };
        let body = uploaded.proof.body();
        let state = &body.state;
        if let Ok(view) = ClaimView::from_value(state) {
            let live = live_claims.get(&view.claim_key).copied();
            let tomb = tombstone_claims.get(&view.claim_key).copied();
            match (view.status, view.attempt_id) {
                (ClaimStatus::Settled, _) => {
                    let gone = match view.deadline {
                        Some(deadline) => deadline.saturating_add(RECONCILIATION_MS) <= last_time,
                        None => {
                            uploaded
                                .proof
                                .envelope()
                                .server_time
                                .saturating_add(MAX_CLAIM_AGE_MS)
                                <= last_time
                        }
                    };
                    if !gone && !live.is_some_and(|c| c.claim.settled) && tomb.is_none() {
                        return fail("a claim SETTLED that the import doesn't hold settled");
                    }
                }
                (ClaimStatus::Attempting, Some(attempt)) => {
                    let holds = |c: &ImportedClaim| {
                        c.claim.step >= view.step
                            && c.claim.attempts.iter().any(|a| a.attempt_id == attempt)
                    };
                    if !live.is_some_and(holds) && !tomb.is_some_and(holds) {
                        return fail("a claim with an attempt the import doesn't hold");
                    }
                }
                _ => {}
            }
        } else if let (Some(deleted), Some(generation), Some(version)) = (
            state.get("deleted").and_then(Value::as_bool),
            state.get("generation").and_then(Value::as_u64),
            state.get("version").and_then(Value::as_u64),
        ) {
            let shown = RecordVersion::new(generation, version);
            let held = unb64_array::<32>(&body.object)
                .ok()
                .and_then(|key| held_records.get(&key).copied());
            let holds = match held {
                None => deleted,
                Some(r) => {
                    let by_item =
                        r.op.item_hash()
                            .is_ok_and(|h| h == uploaded.proof.envelope().item_hash);
                    let by_expected = matches!(
                        &r.op.body().kind,
                        OpKind::RecordPut(put) if put.expected_version >= shown
                    );
                    by_item || by_expected
                }
            };
            if !holds {
                return fail("a record at a version the import doesn't hold");
            }
        }
    }
    Ok(())
}

/// The tombstone of an app the enrollment named revoked, which the export doesn't carry.
fn tombstone_app(app_id: [u8; 16]) -> ImportedApp {
    ImportedApp {
        part: AppPart {
            app_id,
            record: None,
            record_seq: None,
            record_at_ms: None,
            receive_keys: Vec::new(),
            cursor: 0,
            last_seen_ms: None,
            revoked_at_ms: None,
            departed_at_ms: None,
            departure_epoch: None,
            rotated: false,
            renewed_cert: None,
            lagging: false,
            keys_through: None,
            full_bundle_requested_ms: None,
        },
        record: None,
        receive_keys: Vec::new(),
        renewed_cert: None,
        key_bundles: Vec::new(),
        revoked: true,
        departed: false,
    }
}

/// Whether an app is reachable (Switch wire 7.4.10): current, that is listed with the
/// certificate its record carries, unexpired, neither revoked nor departed, and with a
/// receive key.
fn is_reachable(app: &ImportedApp, doc: &IdentityDoc, now: u64) -> bool {
    let Some(record) = &app.record else {
        return false;
    };
    let cert = record.cert();
    !app.revoked
        && !app.departed
        && !app.receive_keys.is_empty()
        && !cert.expired_at(now)
        && doc.current_now(&app.part.app_id, &cert.hash())
}
