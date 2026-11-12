//! The app's durable state: one record per key in the app's namespace `client/<app_id>`,
//! each value schema-versioned, and the transactions that change it.
//!
//! `STATE.md`, next to this file, lists every key and what it holds. Nothing in the Switch
//! spec fixes how an app persists its state; these are the crate's own rules, made so that
//! every network effect follows one pattern (`store` module): sign an artifact and commit it
//! with the next step, send those bytes until there is an answer, then commit the outcome.
//!
//! Every value is `{"v":<SCHEMA_VERSION>,"d":<record>}`. A reader refuses an earlier `v` as
//! an old schema and a later or unreadable one as corrupt, so a later schema adds a
//! migration instead of reading old bytes wrongly.
//!
//! Sensitive records (the app's keys, receive keys, scope keys, the naming key and parked
//! plaintexts) rely on the store's guarantees: device-bound and encrypted at rest (Switch
//! spec 3.1). Deleting a receive key removes its record in the same commit that makes the
//! deletion due, and the store deletes it for real.

use std::collections::{BTreeMap, BTreeSet};

use pubky_switch_core::enc::{b64, pubky_id, serde_b64, serde_b64_vec, zbase32_encode};
use pubky_switch_core::keys::ReceiveKey;
use pubky_switch_core::sig::SignedDoc;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::error::AppError;
use super::events::{AppEvent, ParkReason};
use super::protocol::LocalWrite;
use crate::error::StoreError;
use crate::store::{StoreHandle, Write, WriteBatch};

/// The schema version of every value the app layer writes. 2: a kept effect keeps the
/// entry it is for (`pending/effect`).
pub const SCHEMA_VERSION: u32 = 3;

/// The prefix of the protocol's own keys in the app's namespace.
pub const PROTOCOL_PREFIX: &[u8] = b"p/";

#[derive(Serialize)]
struct Out<'a, T> {
    v: u32,
    d: &'a T,
}

/// A record's bytes as read, once their version is checked ([`Version`]).
#[derive(Deserialize)]
struct In<T> {
    d: T,
}

/// A record's bytes: `{"v":<SCHEMA_VERSION>,"d":<record>}`.
pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(&Out {
        v: SCHEMA_VERSION,
        d: value,
    })
    .map_err(|_| AppError::Store(StoreError::Other("a record can't be written".into())))
}

/// The version of a record's bytes, read before its record, whose shape it decides.
#[derive(Deserialize)]
struct Version {
    v: u32,
}

/// Read a record's bytes. An earlier schema version is an old schema, read from the version
/// alone, before the record, whose shape that schema may not have; a later one, or bytes
/// that don't read, are corrupt.
pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, AppError> {
    let version: Version =
        serde_json::from_slice(bytes).map_err(|_| AppError::Store(StoreError::Corrupt))?;
    if version.v < SCHEMA_VERSION {
        return Err(AppError::Store(StoreError::OldSchema { found: version.v }));
    }
    if version.v != SCHEMA_VERSION {
        return Err(AppError::Store(StoreError::Corrupt));
    }
    let read: In<T> =
        serde_json::from_slice(bytes).map_err(|_| AppError::Store(StoreError::Corrupt))?;
    Ok(read.d)
}

/// The keys of the app's records (`STATE.md`). Numbers are zero-padded to 20 digits so
/// keys sort in numeric order.
pub(crate) mod key {
    use super::{b64, pubky_id, zbase32_encode};

    pub(crate) const META: &str = "meta";
    pub(crate) const KEYS: &str = "keys";
    pub(crate) const CERT: &str = "cert";
    pub(crate) const CERT_RENEWAL: &str = "cert/renewal";
    pub(crate) const RECORD: &str = "record";
    pub(crate) const NAMING: &str = "naming";
    pub(crate) const BUNDLE: &str = "bundle";
    pub(crate) const ROTATION: &str = "rotation";
    pub(crate) const DEVICE: &str = "device";
    pub(crate) const CURSOR: &str = "cursor";
    pub(crate) const CHAIN: &str = "chain";
    pub(crate) const JOIN: &str = "join";
    pub(crate) const ALARM: &str = "alarm";
    pub(crate) const RESTORE: &str = "restore";
    pub(crate) const LEAVE: &str = "leave";
    pub(crate) const SERVICE_TIME: &str = "service_time";
    pub(crate) const PENDING_EFFECT: &str = "pending/effect";
    pub(crate) const PENDING_RECORD: &str = "pending/record";
    /// The record the switch accepted last, owed to the Homeserver.
    pub(crate) const PENDING_PUBLISH: &str = "pending/publish";
    /// The newest record the switch accepted from the app.
    pub(crate) const ACCEPTED_RECORD: &str = "record/accepted";
    /// The ID the next duty event takes.
    pub(crate) const DUTY_NEXT: &str = "dutyn";
    /// The store's event epoch.
    pub(crate) const DUTY_EPOCH: &str = "dutye";
    /// The prefix of the kept duty events.
    pub(crate) const DUTY_PREFIX: &str = "duty/";

    /// Where the next read's retries of stored entries start from.
    pub(crate) const PARKED_NEXT: &str = "parkn";
    /// The local ID the next entry stored locally takes.
    pub(crate) const STORED_NEXT: &str = "parkid";
    /// Where telling the protocol again of the entries a restore brought back stands.
    pub(crate) const RETELL: &str = "retell";
    /// The prefix of the protocol calls owed.
    pub(crate) const OWED_PREFIX: &str = "owed/";

    /// A protocol call about the feed item at (`generation`, `seq`) the protocol couldn't
    /// answer yet.
    pub(crate) fn owed(generation: u64, seq: u64) -> String {
        format!("owed/{}/{}", num(generation), num(seq))
    }

    /// A duty event kept until acknowledged.
    pub(crate) fn duty(id: u64) -> String {
        format!("duty/{}", num(id))
    }

    pub(crate) fn num(n: u64) -> String {
        format!("{n:020}")
    }

    pub(crate) fn scope(epoch: u64, scope: &str) -> String {
        format!("scope/{}/{scope}", num(epoch))
    }

    pub(crate) fn receive_key(n: u64) -> String {
        format!("rk/{}", num(n))
    }

    pub(crate) fn kid(kid: &[u8; 8]) -> String {
        format!("kid/{}", b64(kid))
    }

    pub(crate) fn registration(n: u64) -> String {
        format!("reg/{}", num(n))
    }

    pub(crate) fn chain_at(seq: u64) -> String {
        format!("chain/at/{}", num(seq))
    }

    pub(crate) fn chain_batch(id: &[u8; 16]) -> String {
        format!("chain/batch/{}", b64(id))
    }

    pub(crate) fn processed(sender: &[u8; 32], msg_id: &str) -> String {
        format!("proc/{}/{msg_id}", pubky_id(sender))
    }

    pub(crate) fn processed_at(at: u64, sender: &[u8; 32], msg_id: &str) -> String {
        format!("proct/{}/{}/{msg_id}", num(at), pubky_id(sender))
    }

    pub(crate) fn seen(seq: u64) -> String {
        format!("seen/{}", num(seq))
    }

    pub(crate) fn held(seq: u64) -> String {
        format!("held/{}", num(seq))
    }

    pub(crate) fn retry(seq: u64) -> String {
        format!("retry/{}", num(seq))
    }

    /// An entry stored locally, by its local ID, which never changes.
    pub(crate) fn parked(id: u64) -> String {
        format!("parked/{}", num(id))
    }

    /// The count of the store's retries at an entry stored locally, by its local ID.
    pub(crate) fn stored_retry(id: u64) -> String {
        format!("sretry/{}", num(id))
    }

    pub(crate) fn asked(seq: u64) -> String {
        format!("asked/{}", num(seq))
    }

    pub(crate) fn departed(app_id: &[u8; 16]) -> String {
        format!("departed/{}", zbase32_encode(app_id))
    }

    pub(crate) fn ident_doc(identity: &[u8; 32]) -> String {
        format!("ident/{}/doc", pubky_id(identity))
    }

    pub(crate) fn ident_floor(identity: &[u8; 32]) -> String {
        format!("ident/{}/floor", pubky_id(identity))
    }

    pub(crate) fn ident_body(identity: &[u8; 32], version: u64) -> String {
        format!("ident/{}/body/{}", pubky_id(identity), num(version))
    }

    pub(crate) fn ident_equivocated(identity: &[u8; 32]) -> String {
        format!("ident/{}/equivocated", pubky_id(identity))
    }
}

/// `meta`: who the app is and where its account is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Meta {
    #[serde(with = "serde_b64")]
    pub(crate) identity: [u8; 32],
    #[serde(with = "serde_b64")]
    pub(crate) app_id: [u8; 16],
    /// The switch origin, as `identity.json` names it.
    pub(crate) origin: String,
    /// The account's service key, pinned.
    #[serde(with = "serde_b64")]
    pub(crate) service_key: [u8; 32],
    /// The generation the app follows.
    pub(crate) generation: u64,
}

/// `bundle`: what the app holds of its scope keys (Switch spec 3.5).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BundleState {
    /// The newest data epoch through which the app holds every scope key.
    pub(crate) keys_through: u64,
    /// When the app asked for a full bundle, until one covers every epoch.
    pub(crate) full_requested_ms: Option<u64>,
}

/// `rk/<n>`: a receive key the app holds (Switch spec 3.6). Sensitive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HeldKey {
    pub(crate) key: ReceiveKey,
    /// Its signed record, signed once (Switch wire 2.1 "Sign once").
    pub(crate) record: SignedDoc,
    /// The `seq` of its registration, once known.
    pub(crate) reg_seq: Option<u64>,
    /// The service time of its registration's chain item, once known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reg_time_ms: Option<u64>,
    /// The registration batch sent and not yet answered, its exact body.
    #[serde(with = "serde_b64_vec", default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) pending: Vec<u8>,
}

/// `kid/<kid>`: a kid this app or one of its devices made, kept after the key is deleted,
/// so a registration with any other kid is someone else's (Switch spec 3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct KnownKid {
    pub(crate) n: u64,
}

/// What a registration of the own app is, whose key this device doesn't hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RegStatus {
    /// The app's own key, lost to a restore or deleted on another device: older keys can be
    /// deleted after it.
    Own,
    /// A key another device of the app registered; this device waits for device sync.
    AwaitingSync,
    /// After a restore: a registration the app can't account for (Switch spec 12.4).
    Unaccounted,
}

/// `reg/<n>`: a registration of the own app whose key this device doesn't hold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Registration {
    #[serde(with = "serde_b64")]
    pub(crate) kid: [u8; 8],
    /// Its `seq`, when its chain item was seen.
    pub(crate) seq: Option<u64>,
    /// The service time it was accepted at, from its chain item.
    pub(crate) at_ms: Option<u64>,
    pub(crate) status: RegStatus,
}

/// `rotation`: the receive key rotation's bookkeeping (Switch spec 3.6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Rotation {
    /// The app-clock time of the last rotation, or the first registration.
    pub(crate) last_ms: u64,
    /// Whether an envelope wrapped to the current key was opened since.
    pub(crate) opened_since: bool,
}

/// `device`: whether the app runs on several devices sharing its keys (Switch spec 3.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Device {
    pub(crate) multi_device: bool,
}

/// `cursor`: the app's position in the feed (Switch spec 8.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Cursor {
    /// The generation of the positions.
    pub(crate) generation: u64,
    /// How far the app has processed: the `seq` the next read starts after. Never past an
    /// entry it holds.
    pub(crate) seq: u64,
    /// The cursor the service holds, confirmed by a batch; at most `seq`.
    pub(crate) at_service: u64,
    /// When the oldest deferred cursor-only move was deferred (app clock).
    pub(crate) deferred_since_ms: Option<u64>,
    /// The acceptance time of the last entry the cursor passed (service time).
    pub(crate) time_ms: u64,
}

/// `chain`: the chain view's small fields (`chain` module). The chain hashes and batch IDs
/// are records of their own.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ChainRecord {
    pub(crate) generation: u64,
    pub(crate) last_seq: u64,
    #[serde(with = "serde_b64")]
    pub(crate) last_hash: [u8; 32],
    pub(crate) last_time: Option<u64>,
    /// The open batch: its ID, count and items seen.
    pub(crate) open_batch: Option<(String, u64, u64)>,
    pub(crate) pending_heads: Vec<Value>,
    pub(crate) checkpoint_seq: u64,
    pub(crate) pruned_seq: u64,
    pub(crate) pending_checkpoint: Option<Value>,
    pub(crate) highest_time: Option<u64>,
    /// The newest head seen.
    pub(crate) newest: Option<Value>,
    /// Continuity since `verified_seq` is unverified: the app continued from the
    /// checkpoint at `checkpoint_seq` (Switch spec 8.3).
    pub(crate) gap: Option<(u64, u64)>,
    /// Heads and own-write stubs held beyond the verified position, with the service time
    /// of the answer that carried them.
    pub(crate) held: BTreeMap<u64, u64>,
    /// After a restore: where the app stands before missing stubs count as a rollback.
    pub(crate) restore: Option<RestorePending>,
}

/// After a restore, where the app stands before missing chain stubs count as a rollback
/// again (Switch wire 7.4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RestorePending {
    /// No cursor move since the restore was confirmed yet.
    Cursor,
    /// A cursor move was confirmed; the next page read starts after it.
    Read,
}

/// `proc/<sender>/<msg_id>`: a processed message (Switch spec 11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Processed {
    #[serde(with = "serde_b64")]
    pub(crate) hash: [u8; 32],
    /// When it was processed, app clock, for the retention.
    pub(crate) at_ms: u64,
}

/// `dutye`: the store's event epoch, chosen at random once the store starts empty
/// ([`super::EventId`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DutyEpoch {
    #[serde(with = "serde_b64")]
    pub(crate) epoch: [u8; super::events::EPOCH_LEN],
}

impl DutyEpoch {
    /// A new epoch, from the system's randomness.
    pub(crate) fn random() -> Result<Self, AppError> {
        let mut epoch = [0u8; super::events::EPOCH_LEN];
        getrandom::fill(&mut epoch).map_err(|_| {
            AppError::Store(StoreError::Other(
                "no randomness for the event epoch".into(),
            ))
        })?;
        Ok(Self { epoch })
    }
}

/// `parkn`: where the retries of entries stored locally stand. A round covers the entries
/// stored before it began, by the round each was stored in; it tries them in local ID order
/// from `next` on. One stored later waits for
/// the next round, so every entry is tried within two rounds, each of at most as many reads
/// as it covers entries over the per-read bound.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ParkedRound {
    /// The lowest local ID the round has yet to try.
    pub(crate) next: u64,
    /// The round's number: it covers the entries stored in an earlier one.
    pub(crate) number: u64,
}

impl ParkedRound {
    /// The entries of `due`, `(seq, round stored in)` in ascending `seq` order, one read
    /// tries, at most `cap`, and where the round stands after them. A round that runs out
    /// begins the next one, over every entry of `due`, which fills the rest of the read.
    pub(crate) fn turn(self, due: &[(u64, u64)], cap: usize) -> (Vec<u64>, ParkedRound) {
        let covers = |round: &ParkedRound, (seq, stored): (u64, u64)| {
            stored < round.number && seq >= round.next
        };
        let mut round = self;
        let mut seqs: Vec<u64> = due
            .iter()
            .copied()
            .filter(|entry| covers(&round, *entry))
            .take(cap)
            .map(|(seq, _)| seq)
            .collect();
        if let Some(last) = seqs.last() {
            round.next = last.saturating_add(1);
        }
        if seqs.len() < cap {
            let newest = due.iter().map(|(_, stored)| *stored).max().unwrap_or(0);
            round = ParkedRound {
                next: 0,
                number: round.number.max(newest).saturating_add(1),
            };
            let more: Vec<u64> = due
                .iter()
                .copied()
                .filter(|entry| covers(&round, *entry) && !seqs.contains(&entry.0))
                .take(cap.saturating_sub(seqs.len()))
                .map(|(seq, _)| seq)
                .collect();
            if let Some(last) = more.last() {
                round.next = last.saturating_add(1);
            }
            seqs.extend(more);
        }
        (seqs, round)
    }
}

/// `held/<seq>`: an entry held because its sender can't be checked yet (Switch spec 8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HeldEntry {
    pub(crate) since_ms: u64,
}

/// `retry/<seq>` for an entry on the feed, `sretry/<id>` for one stored locally: an entry
/// whose receive step couldn't finish because the protocol's store or the host failed
/// (`Outcome::Retry`): the reads in a row that ended so, and when the first was. Kept until
/// the entry is processed; it moves from the one key to the other when the entry is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RetryEntry {
    pub(crate) reads: u32,
    pub(crate) since_ms: u64,
}

/// `parked/<id>`: an entry stored locally and passed with the cursor (Switch spec 8.2),
/// keyed by a local ID that never changes, whatever provider change follows. Sensitive: it
/// holds the opened message, so its `Debug` shows only its size.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ParkedEntry {
    /// The `seq` the entry was read at, in [`ParkedEntry::generation`].
    pub(crate) seq: u64,
    /// The generation it was read at.
    pub(crate) generation: u64,
    #[serde(with = "serde_b64")]
    pub(crate) sender: [u8; 32],
    pub(crate) cert: SignedDoc,
    pub(crate) accepted_at_ms: u64,
    /// The signed plaintext's bytes (Switch wire 4.5).
    #[serde(with = "serde_b64_vec")]
    pub(crate) plaintext: Vec<u8>,
    pub(crate) context: Option<Value>,
    pub(crate) reason: ParkReason,
    /// The round of retries in which it was stored ([`ParkedRound`]): only a later round
    /// tries it, whatever its `seq`.
    #[serde(default)]
    pub(crate) round: u64,
    /// The host released it ([`super::App::release_parked`]): kept whatever reason it is
    /// stored for again, through a backup and a restore, so each later run is handed over
    /// as released ([`super::ReceivedMessage::released`]). An entry an earlier build stored
    /// has none; its reason [`ParkReason::Released`] says so ([`ParkedEntry::was_released`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) released: bool,
}

impl ParkedEntry {
    /// Whether the host released it, whatever it is stored for now.
    pub(crate) fn was_released(&self) -> bool {
        self.released || self.reason == ParkReason::Released
    }
}

/// `ident/<identity>/doc`: the newest `identity.json` held for an identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CachedDoc {
    pub(crate) doc: SignedDoc,
    /// When it was read from its source (app clock).
    pub(crate) fetched_ms: u64,
}

/// `ident/<identity>/floor`: the highest version and generation seen (Switch spec 4.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Floor {
    pub(crate) version: u64,
    pub(crate) generation: u64,
}

/// `join`: where the app is in joining (Switch spec 12.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum JoinStep {
    /// The registration batch is signed and kept; it is sent until answered.
    Registering {
        #[serde(with = "serde_b64_vec")]
        body: Vec<u8>,
    },
    /// Registered: the app follows its feed.
    Done,
}

/// `pending/effect`: a received message's effect, signed and kept before it is sent
/// (Switch spec 8.2). Its `Debug` names the entry only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingEffect {
    /// The batch's exact body.
    #[serde(with = "serde_b64_vec")]
    pub(crate) body: Vec<u8>,
    pub(crate) seq: u64,
    #[serde(with = "serde_b64")]
    pub(crate) sender: [u8; 32],
    pub(crate) msg_id: String,
    #[serde(with = "serde_b64")]
    pub(crate) hash: [u8; 32],
    pub(crate) accepted_at_ms: u64,
    pub(crate) kind: String,
    /// The protocol's local writes, committed with the outcome, kept in base64
    /// ([`kept_local`]).
    #[serde(with = "kept_local")]
    pub(crate) local: Vec<LocalWrite>,
    /// The cursor the batch moves to, if it moves it.
    pub(crate) cursor_to: Option<u64>,
    /// The entry lies past a held one: it is kept in `seen` until the cursor passes it.
    pub(crate) past_held: bool,
    /// The generation the entry was read at.
    pub(crate) generation: u64,
    /// The local ID of the entry when it was stored locally before: removing it from
    /// `parked` is part of the outcome.
    pub(crate) stored: Option<u64>,
    /// The deadlines the app computes itself for the claims the batch writes, kept with
    /// their evidence once it is applied (Switch wire 6.8), by claim key (base64url).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) deadlines: Vec<(String, super::claims::ObligationDeadline)>,
    /// When it was kept, before its first send, app clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) kept_ms: Option<u64>,
    /// The keys of the processed pairs the step forgets, deleted with the outcome, as its
    /// local writes are ([`super::ReceiveContext::forget_processed`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) forget: Vec<String>,
    /// What storing the entry locally takes, beside the fields above: the entry is stored
    /// when the effect is kept so long that its fate can't be known (Switch spec 12.5
    /// "Kept batches"). Required: a kept effect without it doesn't read.
    pub(crate) entry: KeptEntry,
}

/// The part of an entry a kept effect keeps so the entry can be stored locally
/// ([`PendingEffect::entry`]). Sensitive: it holds the opened message.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct KeptEntry {
    pub(crate) cert: SignedDoc,
    /// The signed plaintext's bytes (Switch wire 4.5).
    #[serde(with = "serde_b64_vec")]
    pub(crate) plaintext: Vec<u8>,
    pub(crate) context: Option<Value>,
}

impl std::fmt::Debug for ParkedEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ParkedEntry({:?}, {} plaintext bytes)",
            self.reason,
            self.plaintext.len()
        )
    }
}

impl std::fmt::Debug for PendingEffect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PendingEffect(seq {}, {} body bytes)",
            self.seq,
            self.body.len()
        )
    }
}

/// `pending/record`: the app's record, signed and kept before `app.put` is sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingRecord {
    #[serde(with = "serde_b64_vec")]
    pub(crate) body: Vec<u8>,
}

/// `restore`: an app restored from a backup (Switch spec 12.4).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RestoreState {
    /// The highest `n` the backup knew.
    pub(crate) n_floor: u64,
    /// Whether the app checked its current receive key record since the restore.
    pub(crate) key_checked: bool,
    /// The end of the registrations the restore asks about, set by its key check: the `n`
    /// of the key the restored app registered itself, or one above `n_floor` when its key
    /// was current; `None` until the check.
    pub(crate) own_key_n: Option<u64>,
    /// Reconcile mode: no new attempts until the protocol's reconciliation ends it.
    pub(crate) reconcile: bool,
}

/// `leave`: a leave in progress or done (Switch spec 12.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LeaveState {
    /// When `leave` succeeded, app clock; `None` while it is owed.
    pub(crate) left_at_ms: Option<u64>,
    /// The app deletes its keys only once its removal is published.
    pub(crate) two_step: bool,
    /// When the app first saw its `identity.json` list it in `removed`.
    pub(crate) removed_seen_ms: Option<u64>,
    /// When it deleted its keys.
    pub(crate) keys_deleted_ms: Option<u64>,
    /// The leave follows a compromise: the keys stay for the user.
    pub(crate) compromise: bool,
}

/// `service_time`: the highest service time verified, with the key that signed it, and
/// the offset from the device clock at the latest answer (Switch spec 10.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ServiceTime {
    #[serde(with = "serde_b64")]
    pub(crate) key: [u8; 32],
    pub(crate) highest_ms: u64,
    /// Service time less device time at the latest verified answer.
    pub(crate) offset_ms: i64,
}

/// A transaction: the writes of one commit, in the app's namespace, and the duty events
/// it keeps, reported once it commits.
#[derive(Debug)]
pub(crate) struct Tx {
    ns: String,
    batch: WriteBatch,
    duties: Vec<AppEvent>,
    /// The protocol's local writes in the batch, in order, which a receive step later in
    /// the same read sees before they are committed.
    local: Vec<LocalWrite>,
}

impl Tx {
    pub(crate) fn new(ns: &str) -> Self {
        Self {
            ns: ns.to_owned(),
            batch: WriteBatch::new(),
            duties: Vec::new(),
            local: Vec::new(),
        }
    }

    /// A duty event whose record this transaction writes: reported once it commits, and
    /// never if it doesn't.
    pub(crate) fn report(&mut self, event: AppEvent) {
        self.duties.push(event);
    }

    /// The duty events to report once this transaction commits.
    pub(crate) fn take_reports(&mut self) -> Vec<AppEvent> {
        std::mem::take(&mut self.duties)
    }

    pub(crate) fn put<T: Serialize>(&mut self, key: &str, value: &T) -> Result<(), AppError> {
        let bytes = encode(value)?;
        self.batch.put(&self.ns, key.as_bytes().to_vec(), bytes)?;
        Ok(())
    }

    pub(crate) fn delete(&mut self, key: &str) -> Result<(), AppError> {
        self.batch.delete(&self.ns, key.as_bytes().to_vec())?;
        Ok(())
    }

    pub(crate) fn delete_prefix(&mut self, prefix: &str) -> Result<(), AppError> {
        self.batch
            .delete_prefix(&self.ns, prefix.as_bytes().to_vec())?;
        Ok(())
    }

    /// The protocol's local writes, under its prefix.
    pub(crate) fn local(&mut self, writes: &[LocalWrite]) -> Result<(), AppError> {
        for write in writes {
            let prefixed = |k: &[u8]| [PROTOCOL_PREFIX, k].concat();
            match write {
                LocalWrite::Put { key, value } => {
                    self.batch.put(&self.ns, prefixed(key), value.clone())?;
                }
                LocalWrite::Delete { key } => {
                    self.batch.delete(&self.ns, prefixed(key))?;
                }
                LocalWrite::DeletePrefix { prefix } => {
                    self.batch.delete_prefix(&self.ns, prefixed(prefix))?;
                }
            }
            self.local.push(write.clone());
        }
        Ok(())
    }

    /// The protocol's local writes in the batch, not yet committed, in order.
    pub(crate) fn pending_local(&self) -> &[LocalWrite] {
        &self.local
    }

    /// Every write in the batch, not yet committed, in order.
    pub(crate) fn pending_writes(&self) -> &[Write] {
        &self.batch.writes
    }

    /// The bytes the batch counts against the store's batch size so far.
    pub(crate) fn size(&self) -> u64 {
        self.batch.size()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.batch.is_empty()
    }

    /// Commit, checked against the namespace first.
    pub(crate) async fn commit(self, store: &StoreHandle) -> Result<(), AppError> {
        self.batch.check_namespace(&self.ns)?;
        if self.batch.is_empty() {
            return Ok(());
        }
        store.commit(self.batch).await?;
        Ok(())
    }
}

/// Reads of the app's namespace.
#[derive(Clone, Debug)]
pub(crate) struct Reader {
    pub(crate) ns: String,
    pub(crate) store: StoreHandle,
}

/// The most entries one scan returns; scans page through larger sets.
const SCAN_PAGE: u32 = 512;

impl Reader {
    pub(crate) async fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, AppError> {
        match self.store.get(&self.ns, key.as_bytes()).await? {
            None => Ok(None),
            Some(bytes) => decode(&bytes).map(Some),
        }
    }

    pub(crate) async fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, AppError> {
        Ok(self.store.get(&self.ns, key).await?)
    }

    pub(crate) async fn exists(&self, key: &str) -> Result<bool, AppError> {
        Ok(self.store.get(&self.ns, key.as_bytes()).await?.is_some())
    }

    /// Every entry under `prefix`, the key's rest after the prefix, as text.
    pub(crate) async fn scan_raw(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, AppError> {
        let mut out = Vec::new();
        let mut after: Option<Vec<u8>> = None;
        loop {
            let page = self
                .store
                .scan(&self.ns, prefix.as_bytes(), after.as_deref(), SCAN_PAGE)
                .await?;
            let full = page.len() >= usize::try_from(SCAN_PAGE).unwrap_or(usize::MAX);
            for (key, value) in page {
                let rest = key
                    .get(prefix.len()..)
                    .and_then(|rest| std::str::from_utf8(rest).ok())
                    .ok_or(AppError::Store(StoreError::Corrupt))?
                    .to_owned();
                after = Some(key);
                out.push((rest, value));
            }
            if !full {
                return Ok(out);
            }
        }
    }

    /// Every record under `prefix`, decoded, by the key's rest.
    pub(crate) async fn scan<T: DeserializeOwned>(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, T)>, AppError> {
        self.scan_raw(prefix)
            .await?
            .into_iter()
            .map(|(rest, bytes)| Ok((rest, decode(&bytes)?)))
            .collect()
    }

    /// Every record under `prefix` keyed by a zero-padded number.
    pub(crate) async fn scan_numbered<T: DeserializeOwned>(
        &self,
        prefix: &str,
    ) -> Result<BTreeMap<u64, T>, AppError> {
        self.scan::<T>(prefix)
            .await?
            .into_iter()
            .map(|(rest, value)| Ok((parse_num(&rest)?, value)))
            .collect()
    }

    /// The numbers of the keys under `prefix`.
    pub(crate) async fn scan_numbers(&self, prefix: &str) -> Result<BTreeSet<u64>, AppError> {
        self.scan_raw(prefix)
            .await?
            .into_iter()
            .map(|(rest, _)| parse_num(&rest))
            .collect()
    }
}

pub(crate) fn parse_num(text: &str) -> Result<u64, AppError> {
    if text.len() != 20 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AppError::Store(StoreError::Corrupt));
    }
    text.parse::<u64>()
        .map_err(|_| AppError::Store(StoreError::Corrupt))
}

/// The kept form of local writes in a kept effect or batch: each key and value in
/// base64url (`{"Put":{"key":"…","value":"…"}}`), so a write keeps in at most 4/3 of its
/// bytes whatever they are (`MAX_STEP_LOCAL_BYTES`). It reads the form written before,
/// `LocalWrite`'s own, with its bytes as arrays of numbers, too, so no stored value needs a
/// migration.
pub(crate) mod kept_local {
    use pubky_switch_core::enc::{b64, serde_b64_vec};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::LocalWrite;

    fn bytes<S: Serializer>(bytes: &&[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64(bytes))
    }

    #[derive(Serialize)]
    enum Out<'a> {
        Put {
            #[serde(serialize_with = "bytes")]
            key: &'a [u8],
            #[serde(serialize_with = "bytes")]
            value: &'a [u8],
        },
        Delete {
            #[serde(serialize_with = "bytes")]
            key: &'a [u8],
        },
        DeletePrefix {
            #[serde(serialize_with = "bytes")]
            prefix: &'a [u8],
        },
    }

    #[derive(Deserialize)]
    enum Kept {
        Put {
            #[serde(with = "serde_b64_vec")]
            key: Vec<u8>,
            #[serde(with = "serde_b64_vec")]
            value: Vec<u8>,
        },
        Delete {
            #[serde(with = "serde_b64_vec")]
            key: Vec<u8>,
        },
        DeletePrefix {
            #[serde(with = "serde_b64_vec")]
            prefix: Vec<u8>,
        },
    }

    /// The base64 form, or the earlier one with arrays of numbers.
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        Kept(Kept),
        Earlier(LocalWrite),
    }

    pub(crate) fn serialize<S: Serializer>(writes: &[LocalWrite], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(writes.iter().map(|write| match write {
            LocalWrite::Put { key, value } => Out::Put { key, value },
            LocalWrite::Delete { key } => Out::Delete { key },
            LocalWrite::DeletePrefix { prefix } => Out::DeletePrefix { prefix },
        }))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<LocalWrite>, D::Error> {
        Ok(Vec::<Either>::deserialize(d)?
            .into_iter()
            .map(|write| match write {
                Either::Kept(Kept::Put { key, value }) => LocalWrite::Put { key, value },
                Either::Kept(Kept::Delete { key }) => LocalWrite::Delete { key },
                Either::Kept(Kept::DeletePrefix { prefix }) => LocalWrite::DeletePrefix { prefix },
                Either::Earlier(write) => write,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{MemoryStore, StateStore};
    use std::sync::Arc;

    use crate::app::{LOCAL_WRITE_OVERHEAD_BYTES, MAX_STEP_LOCAL_BYTES};
    use crate::store::MAX_VALUE_BYTES;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Kept {
        #[serde(with = "kept_local")]
        local: Vec<LocalWrite>,
    }

    fn writes() -> Vec<LocalWrite> {
        vec![
            LocalWrite::Put {
                key: b"k".to_vec(),
                value: vec![0, 255, 7],
            },
            LocalWrite::Delete { key: b"d".to_vec() },
            LocalWrite::DeletePrefix {
                prefix: b"p/".to_vec(),
            },
        ]
    }

    #[test]
    fn test_kept_local_writes_are_base64_and_read_back() {
        let kept = Kept { local: writes() };
        let json = serde_json::to_value(&kept).unwrap();
        assert_eq!(json["local"][0]["Put"]["value"], b64(&[0, 255, 7]));
        assert_eq!(serde_json::from_value::<Kept>(json).unwrap(), kept);
    }

    #[test]
    fn test_kept_local_writes_of_the_earlier_form_still_read() {
        // As `LocalWrite`'s own derive wrote them: bytes as arrays of numbers.
        let earlier = serde_json::json!({
            "local": writes()
                .iter()
                .map(|write| serde_json::to_value(write).unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            earlier["local"][0]["Put"]["value"],
            serde_json::json!([0, 255, 7])
        );
        assert_eq!(
            serde_json::from_value::<Kept>(earlier).unwrap(),
            Kept { local: writes() }
        );
    }

    /// A kept effect at the largest it can be: a `POST /ops` body at its 4 MiB cap, the
    /// largest plaintext and certificate, and `local` writes at the bound.
    fn largest_effect(local: Vec<LocalWrite>) -> PendingEffect {
        PendingEffect {
            body: vec![0xff; 4 << 20],
            seq: u64::MAX,
            sender: [0xff; 32],
            msg_id: "f".repeat(36),
            hash: [0xff; 32],
            accepted_at_ms: u64::MAX,
            kind: "k".repeat(65),
            local,
            cursor_to: Some(u64::MAX),
            past_held: true,
            generation: u64::MAX,
            stored: Some(u64::MAX),
            deadlines: (0..7)
                .map(|n| {
                    (
                        b64(&[n; 32]),
                        super::super::claims::ObligationDeadline::At(u64::MAX),
                    )
                })
                .collect(),
            kept_ms: Some(u64::MAX),
            forget: Vec::new(),
            entry: KeptEntry {
                cert: SignedDoc {
                    body: "A".repeat(33 * 1024),
                    sig: "A".repeat(86),
                },
                plaintext: vec![0xff; 64 * 1024],
                context: Some(Value::String("c".repeat(1024))),
            },
        }
    }

    #[test]
    fn test_kept_effect_at_the_bound_fits_one_value() {
        // One write at the bound, and the most writes the bound lets through.
        let one = vec![LocalWrite::Put {
            key: vec![0xff],
            value: vec![0xff; MAX_STEP_LOCAL_BYTES - 1 - LOCAL_WRITE_OVERHEAD_BYTES],
        }];
        let many: Vec<LocalWrite> = (0..MAX_STEP_LOCAL_BYTES / (1 + LOCAL_WRITE_OVERHEAD_BYTES))
            .map(|n| LocalWrite::Put {
                key: vec![u8::try_from(n % 256).unwrap()],
                value: Vec::new(),
            })
            .collect();
        for local in [one, many] {
            assert!(crate::app::local_writes_bytes(&local) <= MAX_STEP_LOCAL_BYTES);
            let size = encode(&largest_effect(local)).unwrap().len();
            assert!(
                u64::try_from(size).unwrap() < MAX_VALUE_BYTES,
                "{size} bytes kept"
            );
            // The arithmetic of `MAX_STEP_LOCAL_BYTES`: under 10.9 MiB.
            assert!(size < 109 * 1024 * 1024 / 10, "{size}");
        }
    }

    /// Reads of retries over `due` while each read stores more entries than the bound,
    /// at `seq`s `stored_at` gives; returns how many times each of the first was tried.
    fn rounds_over(first: &[u64], stored_at: impl Fn(u64) -> u64) -> BTreeMap<u64, usize> {
        let cap = 4;
        let mut due: Vec<(u64, u64)> = first.iter().map(|seq| (*seq, 0)).collect();
        let mut round = ParkedRound::default();
        let mut tries: BTreeMap<u64, usize> = BTreeMap::new();
        let mut last_try: BTreeMap<u64, usize> = BTreeMap::new();
        let mut stored = 0u64;
        for read in 1..=60usize {
            due.sort_unstable();
            let (seqs, after) = round.turn(&due, cap);
            assert!(seqs.len() <= cap);
            let mut unique = seqs.clone();
            unique.dedup();
            assert_eq!(unique.len(), seqs.len(), "no entry twice in a read");
            round = after;
            for seq in seqs {
                last_try.insert(seq, read);
                *tries.entry(seq).or_insert(0) += 1;
            }
            // None of the first waits longer than two rounds of the entries there are.
            let rounds = 2 * due.len().div_ceil(cap) + 1;
            for seq in first {
                let at = last_try.get(seq).copied().unwrap_or(0);
                assert!(read - at <= rounds, "{seq}: last tried {at}, now {read}");
            }
            // Each read stores more entries than the bound, in the round now under way.
            for _ in 0..cap + 2 {
                due.push((stored_at(stored), round.number));
                stored += 1;
            }
        }
        tries
    }

    #[test]
    fn test_parked_round_reaches_every_entry_however_many_come_later() {
        // Later entries above every earlier one.
        let tries = rounds_over(&[1, 2, 3, 4, 5, 6], |n| 100 + n);
        for seq in 1..=6u64 {
            assert!(
                tries.get(&seq).copied().unwrap_or(0) >= 3,
                "{seq}: {tries:?}"
            );
        }
    }

    #[test]
    fn test_parked_round_reaches_every_entry_whatever_their_ids() {
        // Entries stored before others whose IDs sort before them, as IDs of any order may.
        let first: Vec<u64> = (0..6).map(|i| u64::MAX - i).collect();
        let tries = rounds_over(&first, |n| 10 + n);
        for seq in &first {
            assert!(
                tries.get(seq).copied().unwrap_or(0) >= 3,
                "{seq}: {tries:?}"
            );
        }
    }

    #[test]
    fn test_record_round_trips_with_its_schema_version() {
        let cursor = Cursor {
            generation: 1,
            seq: 7,
            at_service: 5,
            deferred_since_ms: Some(9),
            time_ms: 11,
        };
        let bytes = encode(&cursor).unwrap();
        assert!(bytes.starts_with(b"{\"v\":3,\"d\":"));
        assert_eq!(decode::<Cursor>(&bytes).unwrap(), cursor);
    }

    #[test]
    fn test_record_of_an_earlier_schema_is_an_old_schema() {
        let bytes = br#"{"v":1,"d":{"generation":1}}"#;
        assert_eq!(
            decode::<Floor>(bytes).unwrap_err(),
            AppError::Store(StoreError::OldSchema { found: 1 })
        );
    }

    #[test]
    fn test_record_of_another_schema_is_corrupt() {
        let bytes = br#"{"v":4,"d":{"generation":1}}"#;
        assert_eq!(
            decode::<Floor>(bytes).unwrap_err(),
            AppError::Store(StoreError::Corrupt)
        );
        assert_eq!(
            decode::<Floor>(b"not json").unwrap_err(),
            AppError::Store(StoreError::Corrupt)
        );
    }

    #[test]
    fn test_parked_entry_debug_hides_the_message() {
        let parked = ParkedEntry {
            seq: 1,
            generation: 1,
            sender: [1; 32],
            cert: SignedDoc::from_parts(b"{}", &[0; 64]),
            accepted_at_ms: 1,
            plaintext: b"secret message".to_vec(),
            context: None,
            reason: ParkReason::Quota,
            round: 0,
            released: false,
        };
        let text = format!("{parked:?}");
        assert!(!text.contains("secret"), "{text}");
        assert!(text.contains("14 plaintext bytes"));
    }

    #[test]
    fn test_numbered_keys_sort_numerically() {
        assert!(key::receive_key(9) < key::receive_key(10));
        assert_eq!(parse_num(&key::num(42)).unwrap(), 42);
        assert!(parse_num("42").is_err());
        assert!(parse_num("0000000000000000004x").is_err());
    }

    #[tokio::test]
    async fn test_tx_writes_only_its_namespace_and_scans_page() {
        let store: Arc<dyn StateStore> = Arc::new(MemoryStore::new());
        let handle = StoreHandle::inline(Arc::clone(&store));
        let mut tx = Tx::new("client/a");
        for seq in 0..600u64 {
            tx.put(&key::held(seq), &HeldEntry { since_ms: seq })
                .unwrap();
        }
        tx.local(&[LocalWrite::Put {
            key: b"x".to_vec(),
            value: b"1".to_vec(),
        }])
        .unwrap();
        tx.commit(&handle).await.unwrap();
        let reader = Reader {
            ns: "client/a".into(),
            store: handle.clone(),
        };
        let held: BTreeMap<u64, HeldEntry> = reader.scan_numbered("held/").await.unwrap();
        assert_eq!(held.len(), 600);
        assert_eq!(held.get(&599), Some(&HeldEntry { since_ms: 599 }));
        assert_eq!(reader.get_raw(b"p/x").await.unwrap(), Some(b"1".to_vec()));
        // Another namespace never reads the app's records.
        assert!(store.scan("client/b", b"", None, 10).unwrap().is_empty());
    }
}
