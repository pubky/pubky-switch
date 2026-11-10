//! The app's durable state: one record per key in the app's namespace `client/<app_id>`,
//! each value schema-versioned, and the transactions that change it.
//!
//! `STATE.md`, next to this file, lists every key and what it holds. Nothing in the Switch
//! spec fixes how an app persists its state; these are the crate's own rules, made so that
//! every network effect follows one pattern (`store` module): sign an artifact and commit it
//! with the next step, send those bytes until there is an answer, then commit the outcome.
//!
//! Every value is `{"v":1,"d":<record>}`. A reader refuses another `v` as corrupt, so a later
//! schema adds a migration instead of reading old bytes wrongly.
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
use super::events::ParkReason;
use super::protocol::LocalWrite;
use crate::error::StoreError;
use crate::store::{StoreHandle, WriteBatch};

/// The schema version of every value the app layer writes.
pub const SCHEMA_VERSION: u32 = 1;

/// The prefix of the protocol's own keys in the app's namespace.
pub const PROTOCOL_PREFIX: &[u8] = b"p/";

#[derive(Serialize)]
struct Out<'a, T> {
    v: u32,
    d: &'a T,
}

#[derive(Deserialize)]
struct In<T> {
    v: u32,
    d: T,
}

/// A record's bytes: `{"v":1,"d":<record>}`.
pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(&Out {
        v: SCHEMA_VERSION,
        d: value,
    })
    .map_err(|_| AppError::Store(StoreError::Other("a record can't be written".into())))
}

/// Read a record's bytes; another schema version or bytes that don't read are corrupt.
pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, AppError> {
    let read: In<T> =
        serde_json::from_slice(bytes).map_err(|_| AppError::Store(StoreError::Corrupt))?;
    if read.v != SCHEMA_VERSION {
        return Err(AppError::Store(StoreError::Corrupt));
    }
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

    pub(crate) fn parked(seq: u64) -> String {
        format!("parked/{}", num(seq))
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

/// `held/<seq>`: an entry held because its sender can't be checked yet (Switch spec 8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HeldEntry {
    pub(crate) since_ms: u64,
}

/// `parked/<seq>`: an entry stored locally and passed with the cursor (Switch spec 8.2).
/// Sensitive: it holds the opened message, so its `Debug` shows only its size.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ParkedEntry {
    #[serde(with = "serde_b64")]
    pub(crate) sender: [u8; 32],
    pub(crate) cert: SignedDoc,
    pub(crate) accepted_at_ms: u64,
    /// The signed plaintext's bytes (Switch wire 4.5).
    #[serde(with = "serde_b64_vec")]
    pub(crate) plaintext: Vec<u8>,
    pub(crate) context: Option<Value>,
    pub(crate) reason: ParkReason,
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
    /// The protocol's local writes, committed with the outcome.
    pub(crate) local: Vec<LocalWrite>,
    /// The cursor the batch moves to, if it moves it.
    pub(crate) cursor_to: Option<u64>,
    /// The entry lies past a held one: it is kept in `seen` until the cursor passes it.
    pub(crate) past_held: bool,
    /// The entry was stored locally before: removing it from `parked` is part of the
    /// outcome.
    pub(crate) parked: bool,
    /// The deadlines the app computes itself for the claims the batch writes, kept with
    /// their evidence once it is applied (Switch wire 6.8), by claim key (base64url).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) deadlines: Vec<(String, super::claims::ObligationDeadline)>,
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
    /// The `n` of the key the restored app registered itself, if it did.
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

/// A transaction: the writes of one commit, in the app's namespace.
#[derive(Debug)]
pub(crate) struct Tx {
    ns: String,
    batch: WriteBatch,
}

impl Tx {
    pub(crate) fn new(ns: &str) -> Self {
        Self {
            ns: ns.to_owned(),
            batch: WriteBatch::new(),
        }
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
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{MemoryStore, StateStore};
    use std::sync::Arc;

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
        assert!(bytes.starts_with(b"{\"v\":1,\"d\":"));
        assert_eq!(decode::<Cursor>(&bytes).unwrap(), cursor);
    }

    #[test]
    fn test_record_of_another_schema_is_corrupt() {
        let bytes = br#"{"v":2,"d":{"generation":1}}"#;
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
            sender: [1; 32],
            cert: SignedDoc::from_parts(b"{}", &[0; 64]),
            accepted_at_ms: 1,
            plaintext: b"secret message".to_vec(),
            context: None,
            reason: ParkReason::Quota,
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
