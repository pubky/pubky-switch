//! The app layer: one app of an identity, run on top of the Switch.
//!
//! An [`App`] holds the app's keys, certificate and record, its own `identity.json`, its
//! receive keys, its scope keys and naming key, its view of the chain and its cursor, and
//! follows its feed. Every durable change lives in the host's [`crate::store::StateStore`]
//! under the namespace `client/<app_id>`, one record per key (`STATE.md` lists them), and
//! every change that goes with a network effect is committed in one write batch at the
//! moment the spec's crash rules give it:
//!
//! - a signed artifact (a registration, a record, an effect's batch) is committed before it
//!   is first sent, and resent byte for byte until answered (Switch wire 2.1 "Sign once");
//! - the cursor moves only with, or after, the effects it covers (Switch spec 8.2, 11);
//! - a retired receive key is deleted only once the cursor has passed the next key's
//!   registration (Switch spec 3.6).
//!
//! The protocol the app is built with ([`Protocol`]) gives the kind rules and the effects of
//! received messages; the Switch gives them no meaning (Switch spec 1). Its receive step
//! builds a message's record writes and claim entries through a [`ReceiveContext`], into the
//! batch that moves the cursor (Switch spec 8.2); its other writes go in batches of its own
//! ([`OpBatch`]), with its local writes and the messages it signed before queueing them
//! ([`App::sign_message`]), or alone ([`App::protocol_commit`]).
//!
//! Async is used only at the network edge: the switch, through the base client, the store,
//! through [`StoreHandle`], and the Homeserver, through [`HomeserverReader`] and, for an
//! app that publishes its record, [`HomeserverWriter`].
//!
//! Moves, provider loss and recovery, revocation and erasure as an app sees them, and push
//! with its peek, are in `provider.rs`, `recovery.rs`, `push.rs` and `peek.rs`.
//!
//! Sending with the outbox and directories, admission, shared records and claims, batches
//! with conditions, and the receive context are in `send.rs`, `directory.rs`,
//! `admission.rs`, `records.rs`, `claims.rs`, `batch.rs` and `context.rs`. `STATE.md` lists
//! the store keys each part keeps.
//!
//! Every call that reaches the network returns a boxed future at its boundary, so a caller's
//! stack holds only a pointer to the call's state, debug builds included.

mod chain;
mod error;
mod events;
mod feed;
mod forget;
mod identity;
mod kept;
mod keys;
mod own_record;
mod parked;
mod peek;
mod protocol;
mod provider;
mod push;
mod recovery;
mod renewal;
mod rotation;
mod state;
mod unverified;
mod uploaded;
mod wait;
mod writer_certs;

mod admission;
mod batch;
mod claims;
mod context;
mod directory;
mod records;
mod send;

#[cfg(test)]
mod tests;

pub use chain::{HELD_MARKS, STUBS_KEPT_FOR_MS};
pub use error::{Alarm, AppError, KeptAhead, Refusal, WontDeliver};
pub use events::{
    AppEvent, BackupRefusal, ClaimAttempt, DropReason, EVENT_ID_LEN, EventId, EventIdError,
    ParkReason, RefusedCall,
};
pub use feed::{FEED_PAGES_PER_READ, ReceiveReport, SENDER_REREAD_MS};
pub use identity::{DOC_CACHE_MS, HomeserverReader, IdentityRefresh, REVALIDATION_MS};
pub use kept::{KeptBatch, KeptBatchDrop, KeptBatchStatus};
pub use own_record::{HomeserverWriter, PUBLISHED_CHECK_MS, Publication};
pub use parked::{ParkedMessage, ParkedSummary};
pub use peek::{PEEK_PAGES, PeekReport, Peeked};
pub use protocol::{
    Effect, LOCAL_WRITE_OVERHEAD_BYTES, LocalWrite, MAX_CLAIM_READS, MAX_LOSS_CONVERSATIONS,
    MAX_REGRESSION_REASON_BYTES, MAX_SEEN_MARK_BYTES, MAX_STEP_LOCAL_BYTES, MissedEntries, Need,
    OpaqueRule, Outcome, PARKED_RETRIES_PER_READ, Protocol, ProtocolLayer, RETRY_EVENT_READS,
    ReceivedMessage, ResendNeeded, ResendReason, StoreFailure, WriteBase, decode_local_state,
    encode_local_state, local_writes_bytes,
};
pub use provider::{KEPT_BATCH_ANSWER_MS, KEPT_BATCH_MARGIN_MS, ProviderStatus};
pub use push::{MAX_HANDLE_BYTES, MAX_HANDLES, PushHandles, PushRegistration, PushRelay};
pub use recovery::{Evidence, LossActions, ProviderLoss, RESIDUAL_WINDOW_MS, RecoveryInfo};
pub use state::{PROTOCOL_PREFIX, SCHEMA_VERSION};
pub use unverified::{
    MAX_UNVERIFIED_AGE_MS, MAX_UNVERIFIED_PER_SENDER, MAX_UNVERIFIED_TOTAL,
    UNVERIFIED_DROPS_PER_COMMIT,
};
pub use uploaded::{MAX_RECORD_MARKS, RECORD_REREADS_PER_READ};
pub use wait::{
    FeedWait, MAX_PAUSE_MS, MAX_WAIT_SECONDS, MIN_PAUSE_MS, UPKEEP_READ_MS, WaitPace, Woken,
};

pub use admission::{INVITE_CODE_BYTES, InviteCode, LISTS_TOO_LARGE_RETRY_MS, SenderDisposition};
pub use batch::{
    KEPT_RESENDS_PER_READ, KEPT_RESENDS_PER_WRITE, MAX_KEPT_BATCHES_BYTES, OpBatch, server_time_in,
};
pub use claims::{
    CLAIM_REREADS_PER_READ, ClaimDoubt, ClaimEntryRead, ClaimEvidence, ClaimOp, ClaimRead,
    ClaimWritten, ObligationDeadline, claim_conflict,
};
pub use context::{ClaimFetch, LocalView, ReceiveContext, RestoreContext};
pub use directory::{
    HomeserverCopy, IdentityLookup, Initiator, MayAct, PEER_DELIVERY_MS, PeerIdentity,
    SwitchAnswer, SwitchCopy, SwitchLookup,
};
pub use records::{
    Collection, CollectionListed, FlaggedWrite, KeptOp, KeptReason, LISTING_PAGES_PER_READ,
    PolicyFamily, RecordContent, RecordRead, RecordTarget, SharedEvidence, SharedRecord, Unopened,
};
pub use send::{
    Delivery, MAX_CARRIED_OUTBOX_BYTES, OUTBOX_TRIES_PER_FLUSH, OutboxReport, OutgoingMessage,
    RecordJob, SENT_RETENTION_MS, SentMessage, SignedMessage, UNDELIVERABLE_MAX_MS,
    UNDELIVERABLE_MS, UNDELIVERABLE_TRIES, UNDELIVERABLE_TRY_SPACING_MS, UndeliverableReason,
};

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use pubky_switch_core::chain::TransitionProof;
use pubky_switch_core::enc::zbase32_encode;
use pubky_switch_core::ident::NamingKey;
use pubky_switch_core::keys::{AppKeys, ReceiveKey, ScopeKey, ScopeKeys};
use pubky_switch_core::ops::{Condition, OpKind, Position};
use pubky_switch_core::records::{
    AppCert, AppRecord, AppRecordBody, AppRequest, Approval, CLOCK_TOLERANCE_MS, DAY_MS,
    IdentityDoc, ReceiveKeyBody, ReceiveKeyRecord,
};
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};

use self::chain::ChainView;
use self::state::{
    BundleState, CachedDoc, Cursor, Device, HeldEntry, HeldKey, JoinStep, KnownKid, LeaveState,
    Meta, ParkedEntry, PendingEffect, PendingRecord, Processed, Reader, Registration,
    RestorePending, RestoreState, RetryEntry, Rotation, ServiceTime, Tx, key,
};
use crate::client::{Batch, Credentials, Submitted, SwitchClient};
use crate::clock::Clock;
use crate::error::{ClientError, StoreError};
use crate::store::{StoreHandle, client_namespace};
use crate::transport::Transport;

/// How many entries of the protocol's local state one store scan reads.
const PROTOCOL_SCAN_PAGE: u32 = 256;

/// The default receive key rotation interval: a day (Switch spec 3.6).
pub const DEFAULT_ROTATION_MS: u64 = DAY_MS;

/// The shortest rotation interval: an hour (Switch spec 3.6).
pub const MIN_ROTATION_MS: u64 = 3_600_000;

/// The default bounded wait for a sender that can't be checked, after which the entry is
/// stored locally and the cursor moves past it: 24 hours (Switch spec 8.2, the app's
/// choice).
pub const DEFAULT_PARK_AFTER_MS: u64 = DAY_MS;

/// The default time a cursor-only move waits for the app's next batch (Switch spec 8.2).
pub const DEFAULT_CURSOR_DEFER_MS: u64 = 2_000;

/// The longest a cursor-only move may be deferred while the app runs (Switch spec 8.2).
pub const MAX_CURSOR_DEFER_MS: u64 = 10_000;

/// How long processed (sender, `msg_id`) pairs are kept: 30 days plus the clock tolerance
/// (Switch spec 11).
pub const PROCESSED_RETENTION_MS: u64 = 30 * DAY_MS + CLOCK_TOLERANCE_MS;

/// How long a two-step leave waits after the app's removal is published before it deletes
/// its keys: the readers' 10-minute cache (Switch spec 12.3).
pub const LEAVE_CACHE_MS: u64 = 10 * 60_000;

/// A service time this far ahead of the device clock is shown to the user (Switch spec
/// 10.1).
pub const SERVICE_TIME_AHEAD_MS: u64 = DAY_MS;

/// The integrator's choices for one app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppConfig {
    /// The display label in the app record.
    pub label: Option<String>,
    /// The receive key rotation interval, at least [`MIN_ROTATION_MS`].
    pub rotation_interval_ms: u64,
    /// The bounded wait before an entry whose sender can't be checked is stored locally.
    pub park_after_ms: u64,
    /// How long a cursor-only move waits for the next batch, at most
    /// [`MAX_CURSOR_DEFER_MS`].
    pub cursor_defer_ms: u64,
    /// Items per feed page, 1 to 500.
    pub page_size: u32,
    /// Whether the app publishes its record on the Homeserver, as an app whose protocol
    /// needs public data does (Switch spec 4.2); such an app leaves in two steps (Switch spec
    /// 12.3). It needs [`AppEnv::homeserver_writer`].
    pub publishes_record: bool,
    /// The time budget of each bounded call, in milliseconds by the app's clock: 20 s by
    /// default. Once it has passed since the call began:
    /// - [`App::receive`]'s looping steps start no further request, each after its first,
    ///   and the read says [`ReceiveReport::more`], what is left kept for the next read;
    /// - [`App::update_record`] tries no further write;
    /// - [`App::flush_outbox`] starts no further unit after its first, and says
    ///   [`OutboxReport::more`];
    /// - [`App::list_collection`] and [`App::list_collections`] ask for no further page
    ///   after their first, and [`App::peek`] reads no further page.
    ///
    /// It bounds when those steps stop, not the call's whole time: each call's docs state
    /// what it may still send after the budget ran out. A write ([`App::submit_batch`]) and
    /// one message's try ([`App::send`], [`App::resend`], [`App::flush_message`]) don't take
    /// it: their bound is the requests they send.
    pub call_budget_ms: u64,
}

/// [`AppConfig::call_budget_ms`] by default.
pub const DEFAULT_CALL_BUDGET_MS: u64 = 20_000;

/// The time budget of one bounded call ([`AppConfig::call_budget_ms`]): when it began, by
/// the app's clock. Passed down to the loops of the call, so a call made inside another
/// keeps its own and a dropped call leaves nothing behind.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CallBudget {
    began_ms: u64,
    budget_ms: u64,
}

impl CallBudget {
    /// Whether the call has spent its budget at `now_ms`: it starts no further request.
    pub(crate) fn spent(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.began_ms) >= self.budget_ms
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            label: None,
            rotation_interval_ms: DEFAULT_ROTATION_MS,
            park_after_ms: DEFAULT_PARK_AFTER_MS,
            cursor_defer_ms: DEFAULT_CURSOR_DEFER_MS,
            page_size: 100,
            publishes_record: false,
            call_budget_ms: DEFAULT_CALL_BUDGET_MS,
        }
    }
}

impl AppConfig {
    fn rotation_ms(&self) -> u64 {
        self.rotation_interval_ms.max(MIN_ROTATION_MS)
    }

    fn defer_ms(&self) -> u64 {
        self.cursor_defer_ms.min(MAX_CURSOR_DEFER_MS)
    }

    fn page(&self) -> u32 {
        self.page_size.clamp(1, 500)
    }
}

/// What an app runs on: the host's store, the transport to its switch, the clock, the
/// Homeserver reader and, for an app that publishes its record, the Homeserver writer.
#[derive(Clone)]
pub struct AppEnv {
    /// The host's store.
    pub store: StoreHandle,
    /// The transport to the switch.
    pub transport: Arc<dyn Transport>,
    /// The app's clock.
    pub clock: Arc<dyn Clock>,
    /// Reads of Homeservers.
    pub homeserver: Arc<dyn HomeserverReader>,
    /// Writes to the own identity's Homeserver, for an app that publishes its record
    /// ([`AppConfig::publishes_record`]); `None` for one that doesn't.
    pub homeserver_writer: Option<Arc<dyn HomeserverWriter>>,
}

impl std::fmt::Debug for AppEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppEnv({:?})", self.store)
    }
}

/// A new app's approval, as it joins (Switch spec 12.1).
#[derive(Clone)]
pub struct JoinRequest {
    /// The identity that approved the app.
    pub identity: [u8; 32],
    /// The app's keys, the ones its request named.
    pub keys: AppKeys,
    /// The app request it sent.
    pub request: AppRequest,
    /// The approval's JSON bytes, from the companion claim whose signature the caller
    /// verified (Switch wire 3.10).
    pub approval: Vec<u8>,
}

impl std::fmt::Debug for JoinRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JoinRequest({:?})", self.keys)
    }
}

/// A token the host makes only after it showed the user what the call does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserConfirmed(());

impl UserConfirmed {
    /// The user confirmed.
    pub fn new() -> Self {
        Self(())
    }
}

impl Default for UserConfirmed {
    fn default() -> Self {
        Self::new()
    }
}

/// How the app leaves (Switch spec 12.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaveMode {
    /// Call `leave`, and delete the keys only once the signer published the app as
    /// removed and readers' caches passed: for an app whose record readers act on.
    TwoStep,
    /// Call `leave` and delete the keys at once, for example on uninstall. The user was
    /// warned that what readers do with the app's record may still reach it.
    Immediate(UserConfirmed),
}

/// Where a leave stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaveReport {
    /// The app left; the signer hasn't published it as removed yet.
    AwaitingRemoval,
    /// Published as removed; the keys go at this app-clock time.
    Removed {
        /// When.
        delete_keys_at_ms: u64,
    },
    /// The keys are deleted.
    Done,
}

/// The keys a device of the app shares with the app's other devices through the app's own
/// device sync (Switch spec 3.1, 3.6). Sensitive: its `Debug` shows no key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKeys {
    receive_keys: Vec<HeldKeyOut>,
    known: Vec<(String, u64)>,
    rotation_ms: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HeldKeyOut {
    key: ReceiveKey,
    record: SignedDoc,
}

impl std::fmt::Debug for DeviceKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeviceKeys({} keys)", self.receive_keys.len())
    }
}

/// An app's backup (Switch spec 12.4), as the app's own backup scheme stores it, encrypted
/// under a key the app or its user holds. It holds the signing key: apps should keep it out
/// of routine backups or encrypt it apart (Switch spec 12.4). Its `Debug` shows no key.
#[derive(Clone, Serialize, Deserialize)]
pub struct AppBackup {
    v: u32,
    meta: Meta,
    keys: AppKeys,
    cert: SignedDoc,
    /// The record the app presents, which may be one the switch hasn't accepted yet.
    record: SignedDoc,
    /// The newest record the switch accepted from the app (`record/accepted`), apart from
    /// `record`: a restore publishes this one, never `record` (Switch spec 4.2). Absent from
    /// a backup of an app the switch accepted no record from that it knows of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted: Option<SignedDoc>,
    naming: NamingKey,
    scope_keys: Vec<ScopeKey>,
    own_doc: SignedDoc,
    receive_keys: Vec<HeldKey>,
    known: Vec<(String, u64)>,
    rotation: Rotation,
    device: Device,
    cursor: Cursor,
    chain: state::ChainRecord,
    chain_at: Vec<(u64, String)>,
    chain_batches: Vec<(String, u64)>,
    departed: Vec<(String, u64)>,
    bundle: BundleState,
    /// The local ID the next entry stored locally takes (`parkid`), so a restore gives out
    /// none the app gave out before the backup, whether or not the backup carries its entry.
    stored_next: u64,
    /// When the backup was taken, the app's clock: a restore reinstalls the messages whose
    /// delivery is owed only within [`SENT_RETENTION_MS`] of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    taken_ms: Option<u64>,
    /// The highest service time the app had verified when the backup was taken, the base of
    /// the outbox's replay deadline in place of `taken_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    taken_service_ms: Option<u64>,
    /// The outbox (`out/`), oldest first, within its byte budget (`send::carried_outbox`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    outbox: Vec<send::OutboxItem>,
    /// The messages of the outbox left out past the budget, and whether each is a re-send.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    outbox_left_out: Vec<(String, bool)>,
    /// The counterparties whose messages the app holds ([`App::hold_queued`]), in base64:
    /// a restore holds them too, so it delivers none of their messages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    held_counterparties: Vec<String>,
    /// The protocol's layer, if it added one; absent from the bytes otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    protocol: Option<LayerOut>,
}

/// The version a backup with a protocol layer carries, in place of [`SCHEMA_VERSION`]: a
/// reader that knows no layers, which takes only that version, refuses such a backup
/// rather than restore it without the layer. A schema change gives both kinds of backup
/// new versions.
const LAYERED_BACKUP_VERSION: u32 = 4;
const _: () = assert!(LAYERED_BACKUP_VERSION != SCHEMA_VERSION);

/// A [`ProtocolLayer`] as a backup's bytes carry it, with what the app's feed holds beyond
/// its cursor at the same moment: the entries processed past a held one, the entries
/// stored locally, and the processed pairs (Switch spec 11). The layer reflects those
/// entries, so a restore that brought it back without them would hand them to the protocol
/// again.
#[derive(Clone, Serialize, Deserialize)]
struct LayerOut {
    name: String,
    data: String,
    #[serde(default)]
    seen: Vec<u64>,
    #[serde(default)]
    parked: Vec<(u64, ParkedEntry)>,
    /// Each pair's key after `proc/`, and its record.
    #[serde(default)]
    processed: Vec<(String, Processed)>,
}

impl std::fmt::Debug for AppBackup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppBackup({})", zbase32_encode(&self.meta.app_id))
    }
}

impl AppBackup {
    /// The backup's bytes.
    ///
    /// # Errors
    ///
    /// [`AppError::Store`] if it can't be written.
    pub fn to_bytes(&self) -> Result<Vec<u8>, AppError> {
        serde_json::to_vec(self)
            .map_err(|_| AppError::Store(StoreError::Other("the backup can't be written".into())))
    }

    /// Read a backup's bytes. A backup with a protocol layer carries a version of its own,
    /// which a reader from before layers refuses, so none restores it without the layer.
    ///
    /// # Errors
    ///
    /// [`StoreError::OldSchema`] for a backup an earlier schema wrote, as for a store of
    /// one; [`AppError::InvalidData`] if they don't read as a backup, or their version isn't
    /// the one of a backup with, or without, a layer.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AppError> {
        #[derive(Deserialize)]
        struct Version {
            v: u32,
            #[serde(default)]
            protocol: Option<serde_json::Value>,
        }
        let version: Version = serde_json::from_slice(bytes)
            .map_err(|_| AppError::InvalidData("the backup doesn't read".into()))?;
        let expected = if version.protocol.is_some() {
            LAYERED_BACKUP_VERSION
        } else {
            SCHEMA_VERSION
        };
        if version.v < expected {
            return Err(AppError::Store(StoreError::OldSchema { found: version.v }));
        }
        let backup: Self = serde_json::from_slice(bytes)
            .map_err(|_| AppError::InvalidData("the backup doesn't read".into()))?;
        if backup.v != expected {
            return Err(AppError::InvalidData(
                "the backup is of another schema version".into(),
            ));
        }
        Ok(backup)
    }

    /// The protocol's layer, if the backup holds one.
    ///
    /// # Errors
    ///
    /// [`AppError::InvalidData`] if its data doesn't read.
    pub fn protocol_layer(&self) -> Result<Option<ProtocolLayer>, AppError> {
        self.protocol
            .as_ref()
            .map(|layer| {
                Ok(ProtocolLayer {
                    protocol: layer.name.clone(),
                    data: pubky_switch_core::enc::unb64(&layer.data).map_err(|_| {
                        AppError::InvalidData("the backup: its protocol layer doesn't read".into())
                    })?,
                })
            })
            .transpose()
    }
}

/// A restore, built: the app and its one commit, or the error of a write the store can't
/// take in one batch: of the backup's own state, or of what a restore in place carries
/// beside it ([`Refusal::CarriedTooLarge`]).
enum Restorable {
    Ready(Box<App>, Tx),
    TooLarge(AppError),
    CarriedTooLarge { duty_events: u64, owed_calls: u64 },
}

/// How a restore's build treats the protocol's check of its layer: in full, for a restore
/// and a layered backup, or, for a plain backup's own check, only for the sizes, a refusal
/// counting as no layer writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LayerCheck {
    Full,
    SizesOnly,
}

/// The error of building a restore's commit: [`Restorable::TooLarge`] for writes over the
/// store's sizes ([`StoreError::TooLarge`]), which [`App::backup_layered`] reports as
/// [`BackupRefusal::TooLarge`]; any other error is returned as it is, unlabelled.
fn restore_build_error(error: AppError) -> Result<Restorable, AppError> {
    match error {
        AppError::Store(StoreError::TooLarge { .. }) => Ok(Restorable::TooLarge(error)),
        error => Err(error),
    }
}

/// The app's state in memory, as the store holds it.
#[derive(Clone, Debug)]
pub(crate) struct AppState {
    pub(crate) meta: Meta,
    pub(crate) keys: AppKeys,
    pub(crate) cert: AppCert,
    pub(crate) renewal: Option<AppCert>,
    pub(crate) record: SignedDoc,
    pub(crate) naming: NamingKey,
    pub(crate) scope_keys: ScopeKeys,
    pub(crate) bundle: BundleState,
    pub(crate) own_doc: IdentityDoc,
    pub(crate) receive_keys: BTreeMap<u64, HeldKey>,
    pub(crate) known_kids: BTreeMap<[u8; 8], u64>,
    pub(crate) registrations: BTreeMap<u64, Registration>,
    pub(crate) rotation: Rotation,
    pub(crate) device: Device,
    pub(crate) cursor: Cursor,
    pub(crate) chain: Option<ChainView>,
    pub(crate) held: BTreeMap<u64, HeldEntry>,
    pub(crate) retries: BTreeMap<u64, RetryEntry>,
    /// The counts of the store's retries at entries stored locally, by local ID.
    pub(crate) stored_retries: BTreeMap<u64, RetryEntry>,
    /// The local ID the next entry stored locally takes (`parkid`): it only goes up.
    pub(crate) next_stored_id: u64,
    /// Where the retries of stored entries stand in their round (`parkn`), so a bounded
    /// number each read reaches every one in turn.
    pub(crate) parked_round: state::ParkedRound,
    pub(crate) seen: BTreeSet<u64>,
    pub(crate) asked: BTreeSet<u64>,
    pub(crate) parked: BTreeMap<u64, ParkedEntry>,
    pub(crate) departed: BTreeMap<[u8; 16], u64>,
    pub(crate) join: JoinStep,
    pub(crate) pending_effect: Option<PendingEffect>,
    pub(crate) pending_record: Option<PendingRecord>,
    /// The record the switch holds and the Homeserver is still owed (`pending/publish`).
    pub(crate) pending_publish: Option<SignedDoc>,
    /// The newest record the switch accepted from the app (`record/accepted`), the one a
    /// publication writes.
    pub(crate) accepted: Option<SignedDoc>,
    pub(crate) alarm: Option<Alarm>,
    pub(crate) restore: Option<RestoreState>,
    pub(crate) leave: Option<LeaveState>,
    pub(crate) service_time: Option<ServiceTime>,
    /// The app isn't current any more, or its account is gone: every read stops.
    pub(crate) gone: Option<provider::GoneRecord>,
    /// The ID the next duty event takes (`dutyn`).
    pub(crate) next_duty: u64,
    /// The store's event epoch (`dutye`).
    pub(crate) duty_epoch: state::DutyEpoch,
    /// The wait before the account counts as erased, while it runs.
    pub(crate) erasing: Option<provider::ErasingRecord>,
}

/// One app of an identity, on top of the Switch.
pub struct App {
    env: AppEnv,
    protocol: Arc<dyn Protocol>,
    config: AppConfig,
    ns: String,
    state: AppState,
    client: SwitchClient,
    /// The store may hold other state than memory: reload before going on.
    reload: bool,
    /// The service time record changed and goes with the next commit.
    service_time_dirty: bool,
    /// The last Homeserver read that confirmed the own `identity.json`; kept in memory only.
    identity_confirmed: Option<identity::Confirmed>,
    events: Vec<AppEvent>,
    /// The highest duty event counter queued in `events` since the app was made: a kept one
    /// above it is queued after a reload (`events` module, "Duty events").
    duty_queued: u64,
    /// The highest duty event counter handed to the host since the app was made: no
    /// acknowledgement removes one above it.
    duty_handed: u64,
    /// When, by the device clock, an answer in this call last brought a verified service
    /// time ([`App::fresh_service_time`]).
    time_fresh_at: Option<u64>,
    /// When a kept batch was last answered `429 rate_limited`, and the end of the wait its
    /// `retry_after` asked, both device clock: no read sends the kept batches again in
    /// between (`App::resume_batches_before_feed`). Kept in memory only: a restart sends
    /// them at its first read.
    kept_rate_limited: Option<(u64, u64)>,
    /// The end of the wait a recovery upload's `429 rate_limited` asked, device clock: no
    /// upload of a provider loss's steps goes before it. In memory only.
    loss_upload_wait: Option<u64>,
    /// When a failed check 7 last had each sender's `identity.json` read again
    /// (`feed.rs`, [`SENDER_REREAD_MS`]). Kept in memory only: it bounds the reads, and a
    /// restart may read once more.
    sender_rereads: HashMap<[u8; 32], feed::SenderReread>,
    /// When an answer of each recipient's switch that didn't verify last had its
    /// `identity.json` read again (`send.rs`, [`SENDER_REREAD_MS`]), device clock. Kept in
    /// memory only: it bounds the reads, and a restart may read once more.
    peer_rereads: HashMap<[u8; 32], u64>,
    /// How many reads ([`App::receive`]) this app began since it was loaded.
    reads_begun: u64,
    /// How many times an owed reopening failed in the read under way ([`App::receive`]):
    /// after [`records::REOPEN_TRIES_PER_READ`], it is left for the next read. In memory
    /// only.
    reopen_failures: u32,
    /// When the Homeserver copy of the app's record was last read to compare it with the
    /// newest record the switch accepted, device clock (`own_record.rs`). In memory only.
    published_checked_ms: Option<u64>,
    /// When this app last asked for its full key bundle, device clock (`keys.rs`,
    /// [`keys::KEY_REQUEST_RETRY_MS`]). In memory only.
    bundle_asked_ms: Option<u64>,
    /// When a read last looked in the directory for a renewal the own `identity.json` lists
    /// and the app holds no `cert.put` for, without finding it, device clock
    /// ([`App::take_renewal_listed_elsewhere`]). In memory only.
    renewal_looked_ms: Option<u64>,
    /// Where a wait for the feed starts, as the last read left it ([`App::feed_wait`]). In
    /// memory only: a restart waits from the cursor.
    next_wait: wait::NextWait,
    /// The device time the last read that succeeded ended, in memory only: a quiet wait
    /// past [`UPKEEP_READ_MS`] after it is a read ([`App::feed_wait`]).
    read_done_ms: Option<u64>,
}

impl std::fmt::Debug for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "App({})", zbase32_encode(&self.state.meta.app_id))
    }
}

fn corrupt() -> AppError {
    AppError::Store(StoreError::Corrupt)
}

/// The ID of a store's first duty event.
const FIRST_DUTY: u64 = 1;

/// What a restore in place carries of what the app owes its protocol
/// ([`App::kept_for_protocol`]).
#[derive(Default)]
struct Carried {
    /// The store's epoch; `None` for one that didn't read, which a new epoch replaces.
    epoch: Option<state::DutyEpoch>,
    /// The counter the next duty event takes.
    next_duty: u64,
    /// The kept duty events and owed calls that read, by key, as stored.
    values: Vec<(String, serde_json::Value)>,
    /// The kept duty events left behind, their values unreadable.
    lost_duties: u64,
    /// The owed calls left behind, their values unreadable.
    lost_owed: u64,
    /// One past every local ID of an entry stored locally that a carried duty event names.
    stored_past: u64,
}

/// The entry a kept effect belongs to, as a backup holds it: stored as
/// [`ParkReason::Uncertain`], under its local ID if it was stored before (its flags kept),
/// else under `reserved`, the ID the live store reserved for it, built from what the kept
/// effect keeps of it.
fn uncertain_copy(
    state: &AppState,
    pending: &PendingEffect,
    reserved: Option<u64>,
) -> Result<(u64, ParkedEntry), AppError> {
    // An entry stored locally under a kept effect is kept until the effect settles
    // (`STATE.md`, `parked/`), and an entry read from the feed has its ID reserved: either
    // missing is a corrupt store.
    if let Some(id) = pending.stored {
        let stored = state.parked.get(&id).ok_or_else(missing)?;
        return Ok((
            id,
            ParkedEntry {
                reason: ParkReason::Uncertain,
                released: stored.was_released(),
                ..stored.clone()
            },
        ));
    }
    Ok((
        reserved.ok_or_else(missing)?,
        ParkedEntry {
            seq: pending.seq,
            generation: pending.generation,
            sender: pending.sender,
            cert: pending.entry.cert.clone(),
            accepted_at_ms: pending.accepted_at_ms,
            plaintext: pending.entry.plaintext.clone(),
            context: pending.entry.context.clone(),
            reason: ParkReason::Uncertain,
            round: state.parked_round.number,
            released: false,
            keys_at: None,
        },
    ))
}

fn missing() -> AppError {
    AppError::Store(StoreError::Corrupt)
}

impl App {
    // ---------------------------------------------------------------------------------
    // Joining, loading and restoring (Switch spec 12.1, 12.4)

    /// Join from an approval (Switch spec 12.1): read the approval by the app's checks
    /// (Switch wire 3.10), keep the keys, scope keys, naming key and certificate, then
    /// deliver the app record and register the first receive key in one batch. The batch
    /// is committed before it is first sent, so a crash resends the same bytes ([`App::load`]
    /// then [`App::receive`] finish it).
    ///
    /// Reading the current shared records before following the feed (Switch spec 12.1 step
    /// 3) is the records layer's; this follows the feed from the registration.
    ///
    /// # Errors
    ///
    /// [`Refusal::Approval`] for an approval that fails a check; otherwise the error of the
    /// store or the registration. After a store error nothing was kept; after a network
    /// error the registration is kept and resent on the next call.
    pub async fn join(
        env: AppEnv,
        protocol: Arc<dyn Protocol>,
        config: AppConfig,
        request: JoinRequest,
    ) -> Result<App, AppError> {
        Box::pin(async move {
            own_record::check_publisher(&env, &config)?;
            let approved = Approval::read(
                &request.approval,
                &request.request,
                &request.identity,
                &request.keys.bundle_secret(),
                &|scope| protocol.has_keys(scope),
            )
            .map_err(|error| Refusal::Approval(error.to_string()))?;
            let keys = request.keys;
            let cert = approved.cert;
            let doc = approved.identity;
            let now = env.clock.now_ms();
            let inbox = doc.inbox().clone();
            let meta = Meta {
                identity: request.identity,
                app_id: cert.app_id(),
                origin: inbox.url.clone(),
                service_key: inbox.service_key,
                generation: doc.generation(),
            };
            let ns = client_namespace(&meta.app_id);
            let reader = Reader {
                ns: ns.clone(),
                store: env.store.clone(),
            };
            if reader.exists(key::META).await? {
                return Err(Refusal::Usage("the app joined already; load it".into()).into());
            }
            let first = ReceiveKey::generate(0)?;
            let key_record =
                ReceiveKeyRecord::sign(&keys, &cert, ReceiveKeyBody::new(&cert, &first))?;
            let mut body = AppRecordBody::new(&cert, protocol.accepts(&cert), now);
            body.label = config.label.clone();
            let record = AppRecord::sign(&keys, body)?;
            let client = Self::client_for(&env, &meta, &keys, &cert)?;
            let batch = client.sign_batch(
                meta.generation,
                vec![
                    (
                        Vec::<Condition>::new(),
                        OpKind::AppPut {
                            record: record.signed().clone(),
                        },
                    ),
                    (
                        Vec::new(),
                        OpKind::ReceiveKeyPut {
                            record: key_record.signed().clone(),
                        },
                    ),
                ],
                None,
            )?;
            let held = HeldKey {
                key: first.clone(),
                record: key_record.signed().clone(),
                reg_seq: None,
                reg_time_ms: None,
                pending: Vec::new(),
            };
            let state = AppState {
                meta: meta.clone(),
                keys: keys.clone(),
                cert: cert.clone(),
                renewal: None,
                record: record.signed().clone(),
                naming: approved.naming_key.clone(),
                scope_keys: approved.keys.clone(),
                bundle: BundleState::default(),
                own_doc: doc.clone(),
                receive_keys: BTreeMap::from([(0, held.clone())]),
                known_kids: BTreeMap::from([(first.kid, 0)]),
                registrations: BTreeMap::new(),
                rotation: Rotation {
                    last_ms: now,
                    opened_since: false,
                },
                device: Device::default(),
                cursor: Cursor {
                    generation: meta.generation,
                    ..Cursor::default()
                },
                chain: None,
                held: BTreeMap::new(),
                retries: BTreeMap::new(),
                stored_retries: BTreeMap::new(),
                next_stored_id: FIRST_STORED_ID,
                parked_round: state::ParkedRound::default(),
                seen: BTreeSet::new(),
                asked: BTreeSet::new(),
                parked: BTreeMap::new(),
                departed: BTreeMap::new(),
                join: JoinStep::Registering {
                    body: batch.body().to_vec(),
                },
                pending_effect: None,
                pending_record: None,
                pending_publish: None,
                accepted: None,
                alarm: None,
                restore: None,
                leave: None,
                service_time: None,
                gone: None,
                next_duty: FIRST_DUTY,
                duty_epoch: state::DutyEpoch::random()?,
                erasing: None,
            };
            let mut app = App {
                env,
                protocol,
                config,
                ns,
                state,
                client,
                reload: false,
                service_time_dirty: false,
                identity_confirmed: None,
                events: Vec::new(),
                duty_queued: 0,
                duty_handed: 0,
                time_fresh_at: None,
                kept_rate_limited: None,
                loss_upload_wait: None,
                sender_rereads: HashMap::new(),
                published_checked_ms: None,
                bundle_asked_ms: None,
                renewal_looked_ms: None,
                next_wait: wait::NextWait::Cursor,
                read_done_ms: None,
                peer_rereads: HashMap::new(),
                reads_begun: 0,
                reopen_failures: 0,
            };
            app.update_keys_through();
            app.events.clear();
            let mut tx = Tx::new(&app.ns);
            tx.put(key::META, &meta)?;
            tx.put(key::KEYS, &keys)?;
            tx.put(key::CERT, cert.signed())?;
            tx.put(key::RECORD, record.signed())?;
            tx.put(key::NAMING, &approved.naming_key)?;
            for scope_key in &approved.keys.keys {
                tx.put(
                    &key::scope(scope_key.data_epoch, &scope_key.scope),
                    scope_key,
                )?;
            }
            tx.put(key::BUNDLE, &app.state.bundle)?;
            let taken = identity::take_copy(&app.reader(), &mut tx, &doc, None, now).await?;
            if taken.is_err() {
                return Err(AppError::InvalidData(
                    "Switch spec 4.3: the approval's identity.json equivocates".into(),
                ));
            }
            tx.put(&key::receive_key(0), &held)?;
            tx.put(&key::kid(&first.kid), &KnownKid { n: 0 })?;
            tx.put(key::ROTATION, &app.state.rotation)?;
            tx.put(key::DEVICE, &app.state.device)?;
            tx.put(key::CURSOR, &app.state.cursor)?;
            tx.put(key::JOIN, &app.state.join)?;
            records::owe_listing(&mut tx)?;
            tx.put(key::DUTY_EPOCH, &app.state.duty_epoch)?;
            tx.commit(&app.env.store).await?;
            app.finish_join().await?;
            Ok(app)
        })
        .await
    }

    /// Send the registration batch kept at join until it is answered, then follow the feed
    /// from the registration (Switch spec 8.3, 12.1 step 2).
    async fn finish_join(&mut self) -> Result<(), AppError> {
        let JoinStep::Registering { body } = &self.state.join else {
            return Ok(());
        };
        let batch = Batch::from_body(body.clone())?;
        let submitted = self.submit(&batch).await?;
        let [app_proof, key_proof] = submitted.proofs.as_slice() else {
            return Err(AppError::InvalidData(
                "Switch wire 6.5: the registration's answer carries no proof per operation".into(),
            ));
        };
        let app_env = app_proof.envelope();
        let anchor = app_env.seq.checked_sub(1).ok_or_else(|| {
            AppError::InvalidData("Switch wire 6.6: a registration at seq 0".into())
        })?;
        let mut view = ChainView::anchored(app_env.generation, anchor, app_env.prev_chain_hash);
        let head = submitted.head;
        view.observe_head(head)?;
        if let Some(time) = self.client.last_server_time() {
            view.note_held(head.seq, time);
        }
        let key_seq = key_proof.envelope().seq;
        if let Some(held) = self.state.receive_keys.get_mut(&0) {
            held.reg_seq = Some(key_seq);
            held.reg_time_ms = Some(key_proof.envelope().server_time);
            held.pending.clear();
        }
        self.state.cursor = Cursor {
            generation: app_env.generation,
            seq: anchor,
            at_service: anchor,
            deferred_since_ms: None,
            time_ms: 0,
        };
        self.state.join = JoinStep::Done;
        let mut tx = self.tx()?;
        view.write_all(&mut tx)?;
        if let Some(held) = self.state.receive_keys.get(&0) {
            tx.put(&key::receive_key(0), held)?;
        }
        tx.put(key::CURSOR, &self.state.cursor)?;
        tx.put(key::JOIN, &self.state.join)?;
        // The switch holds the record now: an app that publishes owes it to the Homeserver
        // (Switch spec 12.1 step 2).
        let record = renewal::delivered_record(&batch)?;
        self.note_accepted(&record, &mut tx)?;
        self.state.chain = Some(view);
        self.commit(tx).await?;
        self.took_accepted(record);
        self.publish_owed(false, true).await?;
        Ok(())
    }

    /// Load an app from the store alone: nothing is sent. Work left by a crash (a
    /// registration, an effect, a record delivery) resumes at the next network call.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotJoined`] when the store holds no such app, [`Refusal::Left`] once it
    /// deleted its keys, and [`AppError::Store`] for a store failure or a corrupt record.
    pub async fn load(
        env: AppEnv,
        protocol: Arc<dyn Protocol>,
        config: AppConfig,
        app_id: [u8; 16],
    ) -> Result<App, AppError> {
        Box::pin(async move {
            own_record::check_publisher(&env, &config)?;
            let ns = client_namespace(&app_id);
            let reader = Reader {
                ns: ns.clone(),
                store: env.store.clone(),
            };
            let state = Self::read_state(&reader).await?;
            let client = Self::client_for(&env, &state.meta, &state.keys, &state.cert)?;
            let mut app = App {
                env,
                protocol,
                config,
                ns,
                state,
                client,
                reload: false,
                service_time_dirty: false,
                identity_confirmed: None,
                events: Vec::new(),
                duty_queued: 0,
                duty_handed: 0,
                time_fresh_at: None,
                kept_rate_limited: None,
                loss_upload_wait: None,
                sender_rereads: HashMap::new(),
                published_checked_ms: None,
                bundle_asked_ms: None,
                renewal_looked_ms: None,
                next_wait: wait::NextWait::Cursor,
                read_done_ms: None,
                peer_rereads: HashMap::new(),
                reads_begun: 0,
                reopen_failures: 0,
            };
            // A store an earlier build wrote keeps the epoch read now.
            if !app.reader().exists(key::DUTY_EPOCH).await? {
                let mut tx = Tx::new(&app.ns);
                tx.put(key::DUTY_EPOCH, &app.state.duty_epoch)?;
                tx.commit(&app.env.store).await?;
            }
            // Batches an earlier build kept carry no index of their messages and attempts.
            app.index_kept_batches().await?;
            // Duty events not acknowledged before are delivered again (`events` module).
            let kept = app.kept_duties().await?;
            app.queue_duties(kept);
            Ok(app)
        })
        .await
    }

    async fn read_state(reader: &Reader) -> Result<AppState, AppError> {
        let meta: Meta = reader
            .get(key::META)
            .await?
            .ok_or(AppError::Refused(Refusal::NotJoined))?;
        let leave: Option<LeaveState> = reader.get(key::LEAVE).await?;
        if leave.is_some_and(|l| l.keys_deleted_ms.is_some()) {
            return Err(Refusal::Left.into());
        }
        let keys: AppKeys = reader.get(key::KEYS).await?.ok_or_else(missing)?;
        let cert_doc: SignedDoc = reader.get(key::CERT).await?.ok_or_else(missing)?;
        let cert = AppCert::verify(&cert_doc, &meta.identity).map_err(|_| corrupt())?;
        let renewal = match reader.get::<SignedDoc>(key::CERT_RENEWAL).await? {
            None => None,
            Some(doc) => Some(AppCert::verify(&doc, &meta.identity).map_err(|_| corrupt())?),
        };
        let mut scope_keys = ScopeKeys::default();
        for (_, scope_key) in reader.scan::<ScopeKey>("scope/").await? {
            scope_keys.keys.push(scope_key);
        }
        let (own_doc, _) = identity::held_copy(reader, &meta.identity)
            .await?
            .ok_or_else(missing)?;
        let mut known_kids = BTreeMap::new();
        for (rest, known) in reader.scan::<KnownKid>("kid/").await? {
            let kid = pubky_switch_core::enc::unb64_array::<8>(&rest).map_err(|_| corrupt())?;
            known_kids.insert(kid, known.n);
        }
        let mut departed = BTreeMap::new();
        for (rest, at) in reader.scan::<u64>("departed/").await? {
            let app = pubky_switch_core::enc::app_id_decode(&rest).map_err(|_| corrupt())?;
            departed.insert(app, at);
        }
        let parked: BTreeMap<u64, ParkedEntry> = reader.scan_numbered("parked/").await?;
        let next_stored_id = next_stored_id(reader.get::<u64>(key::STORED_NEXT).await?, &parked);
        Ok(AppState {
            keys,
            cert,
            renewal,
            record: reader.get(key::RECORD).await?.ok_or_else(missing)?,
            naming: reader.get(key::NAMING).await?.ok_or_else(missing)?,
            scope_keys,
            bundle: reader.get(key::BUNDLE).await?.unwrap_or_default(),
            own_doc,
            receive_keys: reader.scan_numbered("rk/").await?,
            known_kids,
            registrations: reader.scan_numbered("reg/").await?,
            rotation: reader.get(key::ROTATION).await?.unwrap_or_default(),
            device: reader.get(key::DEVICE).await?.unwrap_or_default(),
            cursor: reader.get(key::CURSOR).await?.ok_or_else(missing)?,
            chain: ChainView::load(reader).await?,
            held: reader.scan_numbered("held/").await?,
            retries: reader.scan_numbered("retry/").await?,
            stored_retries: reader.scan_numbered("sretry/").await?,
            next_stored_id,
            parked_round: reader.get(key::PARKED_NEXT).await?.unwrap_or_default(),
            seen: reader.scan_numbers("seen/").await?,
            asked: reader.scan_numbers("asked/").await?,
            parked,
            departed,
            join: reader.get(key::JOIN).await?.ok_or_else(missing)?,
            pending_effect: reader.get(key::PENDING_EFFECT).await?,
            pending_record: reader.get(key::PENDING_RECORD).await?,
            pending_publish: reader.get(key::PENDING_PUBLISH).await?,
            accepted: reader.get(key::ACCEPTED_RECORD).await?,
            alarm: reader.get(key::ALARM).await?,
            restore: reader.get(key::RESTORE).await?,
            leave,
            service_time: reader.get(key::SERVICE_TIME).await?,
            gone: reader.get(provider::keys::GONE).await?,
            next_duty: Self::next_duty(reader).await?,
            duty_epoch: match reader.get(key::DUTY_EPOCH).await? {
                Some(epoch) => epoch,
                // A store an earlier build wrote: `App::load` keeps this one.
                None => state::DutyEpoch::random()?,
            },
            erasing: reader.get(provider::keys::ERASING).await?,
            meta,
        })
    }

    /// The app's backup (Switch spec 12.4): its keys, certificate and record, scope keys
    /// and naming key, its receive keys and the kids it knows, its cursor and chain view,
    /// and its outbox. The app should take one at every rotation, replacing the previous one
    /// (Switch spec 3.6).
    ///
    /// The outbox goes in whole, but for the messages refused for good: each message with
    /// its signed plaintext and the envelope sealed for its last try, so a restore delivers
    /// what was queued before the backup with the same `msg_id` and bytes. A message the
    /// device the backup came from delivered after it is then sent again: the recipient's
    /// switch answers a retry of the same envelope with its first answer while it holds the
    /// entry (Switch wire 7.4.3 step 1), and the recipient's apps drop a second copy by its
    /// processed pair, kept at least 30 days from the first acceptance plus the clock
    /// tolerance (Switch spec 11). So a restore reinstalls a message whose delivery is owed
    /// only within [`SENT_RETENTION_MS`] of the backup, by the restoring device's clock;
    /// later it gives that delivery up, as for an undeliverable message
    /// ([`AppEvent::MessageUndelivered`]).
    ///
    /// A backup is only ever of committed state. After a failed commit the app's memory may
    /// be ahead of its store, such as a cursor past an entry whose processed pair and local
    /// writes weren't written, until its next call reads the store again: until then this
    /// refuses, since a backup of that memory would restore past an entry never processed.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`] when there is nothing to back up;
    /// [`Refusal::NotNow`] after a failed commit, until the app's next call reads its store
    /// again; a store failure reading the outbox.
    pub async fn backup(&self) -> Result<AppBackup, AppError> {
        if self.state.leave.is_some() {
            return Err(Refusal::Left.into());
        }
        if self.reload {
            return Err(Refusal::NotNow(
                "a commit failed: the app reads its store again at its next call".into(),
            )
            .into());
        }
        let mut backup = Self::backup_of(&self.state)?;
        self.carry_outbox(&self.reader(), &mut backup).await?;
        // The restore is built, not committed, as for a layered backup: one that can never
        // be installed is refused now.
        // A protocol may refuse to restore without its layer, its host restoring from a
        // layered backup: the sizes are checked with no layer writes then.
        let restorable = Self::restore_commit(
            self.env.clone(),
            Arc::clone(&self.protocol),
            self.config.clone(),
            &backup,
            LayerCheck::SizesOnly,
        )
        .await?;
        if let Restorable::TooLarge(error) = restorable {
            return Err(error);
        }
        Ok(backup)
    }

    /// The backup of `state`.
    fn backup_of(state: &AppState) -> Result<AppBackup, AppError> {
        if state.leave.is_some() {
            return Err(Refusal::Left.into());
        }
        let chain = state
            .chain
            .as_ref()
            .ok_or_else(|| AppError::Refused(Refusal::NotNow("the app isn't registered".into())))?;
        let (record, at, batches) = chain.export();
        Ok(AppBackup {
            v: SCHEMA_VERSION,
            meta: state.meta.clone(),
            keys: state.keys.clone(),
            cert: state.cert.signed().clone(),
            record: state.record.clone(),
            accepted: state.accepted.clone(),
            naming: state.naming.clone(),
            scope_keys: state.scope_keys.keys.clone(),
            own_doc: state.own_doc.signed().clone(),
            receive_keys: state.receive_keys.values().cloned().collect(),
            known: state
                .known_kids
                .iter()
                .map(|(kid, n)| (pubky_switch_core::enc::b64(kid), *n))
                .collect(),
            rotation: state.rotation,
            device: state.device,
            cursor: state.cursor,
            chain: record,
            chain_at: at
                .into_iter()
                .map(|(seq, hash)| (seq, pubky_switch_core::enc::b64(&hash)))
                .collect(),
            chain_batches: batches
                .into_iter()
                .map(|(id, t)| (pubky_switch_core::enc::b64(&id), t))
                .collect(),
            departed: state
                .departed
                .iter()
                .map(|(app, at)| (zbase32_encode(app), *at))
                .collect(),
            bundle: state.bundle.clone(),
            stored_next: state.next_stored_id,
            taken_ms: None,
            taken_service_ms: None,
            outbox: Vec::new(),
            outbox_left_out: Vec::new(),
            held_counterparties: Vec::new(),
            protocol: None,
        })
    }

    /// Put a backup's outbox back, in the restore's commit `tx` (Switch spec 11, 12.4): every
    /// message as the backup holds it, each owed delivery with its replay deadline
    /// ([`send::OutboxItem::replay_until`]), from the backup's verified service time, or its
    /// device time without one, less the clock tolerance. The deadline is checked at every
    /// try, not here. The messages the backup left out past its budget are told to the
    /// protocol as undelivered, in the same commit.
    fn reinstall_outbox(&mut self, backup: &AppBackup, tx: &mut Tx) -> Result<(), AppError> {
        let baseline = backup
            .taken_service_ms
            .or(backup.taken_ms)
            .unwrap_or(0)
            .saturating_sub(CLOCK_TOLERANCE_MS);
        for item in &backup.outbox {
            let mut item = item.clone();
            if item.delivery_owed() {
                item.replay_until(baseline);
            }
            send::put_outbox_item(tx, &item)?;
        }
        for rest in &backup.held_counterparties {
            let pubky = pubky_switch_core::enc::unb64_array::<32>(rest)
                .map_err(|_| AppError::InvalidData("a backup's held counterparty".into()))?;
            send::put_hold(tx, &pubky)?;
        }
        let now = self.now();
        for (msg_id, resend) in &backup.outbox_left_out {
            send::note_given_up(tx, msg_id, now)?;
            self.keep_duty(
                tx,
                events::Duty::MessageUndelivered {
                    msg_id: msg_id.clone(),
                    resend: *resend,
                },
            )?;
        }
        Ok(())
    }

    /// Put the outbox in `backup`, as `reader` holds it, with the backup's times (Switch
    /// spec 11): every message the app still owes a job, so a restore delivers what was
    /// queued before the backup with the same `msg_id` and bytes.
    async fn carry_outbox(&self, reader: &Reader, backup: &mut AppBackup) -> Result<(), AppError> {
        backup.taken_ms = Some(self.now());
        backup.taken_service_ms = self.state.service_time.map(|time| time.highest_ms);
        let carried = send::carried_outbox(reader).await?;
        backup.outbox = carried.items;
        backup.outbox_left_out = carried.left_out;
        backup.held_counterparties = reader
            .scan_raw(send::HOLD_PREFIX)
            .await?
            .into_iter()
            .map(|(rest, _)| rest)
            .collect();
        Ok(())
    }

    /// The app's backup with the protocol's layer (Switch spec 12.4), the layer taken by
    /// the app itself, so it is always of the same moment as the rest. In this one call,
    /// which holds the app exclusively so no other call writes its store meanwhile, the app
    /// reads from its store: its committed state (never memory that a failed commit left
    /// ahead of the store), the protocol's whole local state, which
    /// [`Protocol::backup_layer`] turns into the layer's bytes under
    /// [`Protocol::backup_name`], and what the feed holds beyond the cursor that the layer
    /// may reflect: the entries processed past a held one, the entries stored locally, and
    /// the processed pairs, so a restore hands none of those messages to the protocol
    /// again. It carries the outbox of the same moment, as [`App::backup`] does.
    /// [`App::restore`] installs it all in one commit.
    ///
    /// The restore of the backup is built, without writing anything, before it is
    /// returned: [`Protocol::restore_layer`] checks the layer, and the one commit that would
    /// install it must fit the store's sizes ([`crate::store::MAX_VALUE_BYTES`] for each
    /// value, [`crate::store::MAX_BATCH_BYTES`], 32 MiB, for the whole).
    ///
    /// That commit holds, beside the app's own state and the layer, every entry stored
    /// locally and every processed pair the app keeps (for 30 days plus the clock
    /// tolerance). While they add up to more than the batch size, every layered backup is
    /// refused, with [`AppEvent::BackupRefused`] for the host, until they drain: entries
    /// stored locally as they are processed, processed pairs as they age out. It applies the
    /// bounds on entries stored unverified first, as a read does (Switch spec 8.2), so the
    /// backup holds at most [`MAX_UNVERIFIED_TOTAL`] of them, and keeps the duty events of
    /// what they drop. So it needs a writable store, and the drops stay committed even if
    /// the backup is then refused. An app a read wouldn't run on (stopped by an alarm, left,
    /// or no longer current here) skips the bounds, and its backup only reads the store but
    /// for the one counter write below.
    ///
    /// It makes no network call. A kept effect isn't settled first, and a restore never
    /// carries one: the backup holds the effect's entry as what it is once the effect is
    /// gone, one whose effect's fate is unknown, stored as [`ParkReason::Uncertain`] (its
    /// flags, such as a release, kept) with the processed pair of its message, an entry read
    /// from the feed included. The restored app's bounds never drop it and its host may
    /// release it. Its read passes the feed entry, whose `seq` the backup's `seen` holds,
    /// with no event and no second application; the processed pair still catches a re-send
    /// of the message at a new `seq` within 30 days.
    /// The live store keeps the kept effect, which the app's next read settles. An entry
    /// read from the feed takes a local ID the live store reserves for it first, by moving
    /// its stored-entry counter on (`parkid`), on a halted app too: the backup's counter is
    /// one past it, and the live store never gives that ID to another entry, which a restore
    /// in place would install the copy over. The counter is the one write of its own; its
    /// commit also keeps a service time verified earlier and not yet committed, as every
    /// commit does. Neither changes anything a read or the protocol sees.
    ///
    /// The restored app tells its protocol of the copy as stored `Uncertain`
    /// ([`AppEvent::Parked`]), but not which of the kept batch's attempts are uncertain, as
    /// [`AppEvent::EffectUncertain`] would: the restore's reconcile mode covers that, since
    /// the protocol makes no new attempt until it has reconciled from the claims.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotNow`] for a protocol with no backup name; [`Refusal::Left`] or
    /// [`Refusal::NotNow`] when there is nothing to back up; a store failure; as
    /// [`App::restore`] for a backup it would refuse, such as a layer the protocol refuses
    /// ([`AppError::InvalidData`]) or one over the store's sizes ([`AppError::Store`], with
    /// [`AppEvent::BackupRefused`]).
    pub async fn backup_layered(&mut self) -> Result<AppBackup, AppError> {
        Box::pin(async move {
            let Some(name) = self.protocol.backup_name() else {
                return Err(Refusal::NotNow("the protocol names no backup layer".into()).into());
            };
            // The bounds on entries stored unverified first, as at a read, so a pile stored
            // during the last read doesn't go into the backup (Switch spec 8.2). An app a read
            // wouldn't run on, halted by an alarm, left, or no longer current here, commits
            // nothing: its backup is taken read-only, the entries as they are.
            self.ready_local().await?;
            let halted = self.refuse_when_halted().is_err() || self.not_current_here().is_some();
            if !halted {
                self.bound_unverified().await?;
            }
            // The local ID the copy of a kept effect's feed entry takes is reserved in the
            // live store first, for a halted app too: the backup's only write of its own
            // there (its commit also keeps a service time not yet committed), which changes
            // nothing a read or the protocol sees. Without it, the next entry the
            // live store stored would take the same ID, and a restore in place would install
            // the copy under an ID its carried duty events give another message.
            let reserved = if self
                .state
                .pending_effect
                .as_ref()
                .is_some_and(|pending| pending.stored.is_none())
            {
                let mut tx = self.tx()?;
                let id = self.new_stored_id(&mut tx)?;
                self.commit(tx).await?;
                Some(id)
            } else {
                None
            };
            let reader = self.reader();
            let state = Self::read_state(&reader).await?;
            let mut backup = Self::backup_of(&state)?;
            self.carry_outbox(&reader, &mut backup).await?;
            let local = self.protocol_scan(b"").await?;
            let mut processed = reader.scan::<Processed>("proc/").await?;
            let mut parked = state.parked.clone();
            let mut seen = state.seen.clone();
            if let Some(pending) = &state.pending_effect {
                // A restore never carries a kept effect, so the backup holds its entry as
                // what it is once the effect is gone: one whose effect's fate is unknown,
                // stored as `Uncertain` with the processed pair of its message, as the app
                // itself stores it when it can't tell (`feed.rs`, `park_uncertain`). The
                // bounds never drop it and the host may release it. A read passes its feed
                // entry (its `seq` is put in `seen` below), with no event and no second
                // application; the processed pair still catches a re-send at a new `seq`
                // within 30 days. The live store isn't touched.
                let (id, entry) = uncertain_copy(&state, pending, reserved)?;
                parked.insert(id, entry);
                // Its feed `seq` is passed, as the app passes it when it stores an entry: the
                // processed pair ages out after 30 days, and a restore from an older backup
                // must still never hand the entry over again unless the host releases the
                // stored copy. An entry stored before was passed when it was stored.
                if pending.stored.is_none() {
                    seen.insert(pending.seq);
                }
                let pair = key::processed(&pending.sender, &pending.msg_id);
                let rest = pair.strip_prefix("proc/").unwrap_or(&pair).to_owned();
                processed.retain(|(held, _)| *held != rest);
                processed.push((
                    rest,
                    Processed {
                        hash: pending.hash,
                        at_ms: self.now(),
                    },
                ));
            }
            let data = self.protocol.backup_layer(local).map_err(|why| {
                AppError::InvalidData(format!("the protocol's backup layer: {why}"))
            })?;
            backup.v = LAYERED_BACKUP_VERSION;
            backup.protocol = Some(LayerOut {
                name,
                data: pubky_switch_core::enc::b64(&data),
                seen: seen.into_iter().collect(),
                parked: parked.into_iter().collect(),
                processed,
            });
            // The restore is built, not committed, so a layer the protocol refuses, or one
            // over the store's sizes, is refused now rather than at a restore that can
            // never succeed. What this store would carry beside it at a restore in place
            // doesn't refuse the backup, which fits on its own: that restore is refused
            // until the host acknowledges, or restores onto an empty store.
            let restorable = Self::restore_commit(
                self.env.clone(),
                Arc::clone(&self.protocol),
                self.config.clone(),
                &backup,
                LayerCheck::Full,
            )
            .await?;
            if let Restorable::TooLarge(error) = restorable {
                self.events.push(AppEvent::BackupRefused {
                    reason: BackupRefusal::TooLarge,
                });
                return Err(error);
            }
            Ok(backup)
        })
        .await
    }

    /// Restore from a backup (Switch spec 12.4) into the store, replacing whatever the store
    /// holds for the app. The host asked the user first whether the device the backup came
    /// from is still in the user's hands; for a lost or stolen one it revokes the app and
    /// joins a new one instead.
    ///
    /// The app enters reconcile mode. At its next call it takes the certificate its current
    /// `identity.json` lists, read with its own record from the directory, if the backup
    /// predates a renewal, another device's included, checks its receive key
    /// record, registers a fresh key if it rotated after the backup, and asks the user
    /// about registrations it can't account for ([`App::restore_question`]).
    ///
    /// The backup's outbox goes back in, to be delivered by the next flush with the same
    /// `msg_id` and bytes; past [`SENT_RETENTION_MS`] from the backup, a delivery still
    /// owed is given up instead, with [`AppEvent::MessageUndelivered`] ([`App::backup`]).
    ///
    /// The protocol's layer ([`App::backup_layered`]) is installed with the
    /// app's own state, and with the entries and processed pairs of the same moment that
    /// the backup carries beside it, in one commit: the app checks its own state, then the
    /// layer's name
    /// against [`Protocol::backup_name`], then has [`Protocol::restore_layer`] check the
    /// layer, with the backup's identity and `blind` under its naming key ([`RestoreContext`]), and give its
    /// writes, all before it writes anything. When this returns `Ok`,
    /// both layers are in the store; on `Err`, neither is, and the store holds what it held
    /// before. The one exception is a commit whose outcome the store can't tell
    /// ([`StoreError::Unknown`]): it landed whole or not at all, and the host loads the app
    /// ([`App::load`]) to learn which.
    ///
    /// What the store holds that the app still owes its protocol stays, a layered restore's
    /// included: the duty events
    /// not acknowledged, with their IDs, delivered again as after [`App::load`], and the
    /// protocol calls it couldn't answer, made again by the next read. A backup carries
    /// neither, so a restore on another device starts without them, under a new event epoch
    /// ([`EventId`]).
    ///
    /// # Errors
    ///
    /// [`AppError::InvalidData`] for a backup that doesn't verify, for a protocol layer that
    /// another protocol, or a protocol without a backup name, made, or for one the protocol
    /// refuses; [`Refusal::CarriedTooLarge`] for a restore in place whose backup fits one
    /// commit but not with the duty events and owed calls the store would carry beside it;
    /// [`Refusal::Usage`] for an app that publishes its record without a Homeserver writer
    /// ([`AppEnv::homeserver_writer`]); a store failure, writes over the store's sizes
    /// included. Nothing is written on any of them.
    pub async fn restore(
        env: AppEnv,
        protocol: Arc<dyn Protocol>,
        config: AppConfig,
        backup: &AppBackup,
    ) -> Result<App, AppError> {
        Box::pin(async move {
            match Self::restore_commit(env, protocol, config, backup, LayerCheck::Full).await? {
                Restorable::Ready(app, tx) => {
                    tx.commit(&app.env.store).await?;
                    let mut app = *app;
                    // Committed: a failure here leaves the rest to the next read.
                    let _ = app.retell_restored().await;
                    let kept = app.kept_duties().await?;
                    app.queue_duties(kept);
                    Ok(app)
                }
                Restorable::TooLarge(error) => Err(error),
                Restorable::CarriedTooLarge {
                    duty_events,
                    owed_calls,
                } => Err(Refusal::CarriedTooLarge {
                    duty_events,
                    owed_calls,
                }
                .into()),
            }
        })
        .await
    }

    /// The app a backup restores and the one commit that installs it, checked and built
    /// within the store's sizes; nothing is written.
    async fn restore_commit(
        env: AppEnv,
        protocol: Arc<dyn Protocol>,
        config: AppConfig,
        backup: &AppBackup,
        layer_check: LayerCheck,
    ) -> Result<Restorable, AppError> {
        Box::pin(async move {
            // As at a join and a load: an app that publishes needs its writer.
            own_record::check_publisher(&env, &config)?;
            let meta = backup.meta.clone();
            let invalid = |why: &str| AppError::InvalidData(format!("the backup: {why}"));
            let cert = AppCert::verify(&backup.cert, &meta.identity)
                .map_err(|_| invalid("its certificate doesn't verify"))?;
            if cert.app_id() != meta.app_id || cert.signing_key() != backup.keys.signing_public() {
                return Err(invalid("its certificate isn't its keys'"));
            }
            // The app record the restore installs carries that very certificate, so what the
            // protocol checks below is all that is installed: the app writes the two
            // together, at a join and when it takes a certificate, so they never differ in a
            // backup it took.
            let record = AppRecord::verify(&backup.record, &meta.identity)
                .map_err(|_| invalid("its app record doesn't verify"))?;
            if record.cert().hash() != cert.hash() {
                return Err(invalid("its app record carries another certificate"));
            }
            // The newest record the switch accepted is the app's own, signed with its key.
            if let Some(accepted) = &backup.accepted {
                let accepted = AppRecord::verify(accepted, &meta.identity)
                    .map_err(|_| invalid("its accepted app record doesn't verify"))?;
                if accepted.cert().app_id() != meta.app_id
                    || accepted.cert().signing_key() != backup.keys.signing_public()
                {
                    return Err(invalid("its accepted app record isn't its keys'"));
                }
            }
            let own_doc = IdentityDoc::verify(&backup.own_doc, &meta.identity)
                .map_err(|_| invalid("its identity.json doesn't verify"))?;
            let mut at = BTreeMap::new();
            for (seq, hash) in &backup.chain_at {
                at.insert(
                    *seq,
                    pubky_switch_core::enc::unb64_array::<32>(hash)
                        .map_err(|_| invalid("chain"))?,
                );
            }
            let mut batches = BTreeMap::new();
            for (id, time) in &backup.chain_batches {
                batches.insert(
                    pubky_switch_core::enc::unb64_array::<16>(id).map_err(|_| invalid("chain"))?,
                    *time,
                );
            }
            let mut chain = ChainView::import(backup.chain.clone(), at, batches)?;
            // The cursor moves made after the backup are lost with it: missing stubs aren't a
            // rollback until the service holds a cursor this app moved and it read after that.
            chain.restore = Some(RestorePending::Cursor);
            let mut known_kids = BTreeMap::new();
            for (kid, n) in &backup.known {
                known_kids.insert(
                    pubky_switch_core::enc::unb64_array::<8>(kid).map_err(|_| invalid("kids"))?,
                    *n,
                );
            }
            let mut departed = BTreeMap::new();
            for (app, time) in &backup.departed {
                departed.insert(
                    pubky_switch_core::enc::app_id_decode(app)
                        .map_err(|_| invalid("departures"))?,
                    *time,
                );
            }
            let receive_keys: BTreeMap<u64, HeldKey> = backup
                .receive_keys
                .iter()
                .map(|held| (held.key.n, held.clone()))
                .collect();
            let n_floor = receive_keys.keys().next_back().copied().unwrap_or(0);
            let mut cursor = backup.cursor;
            // The service may hold a later cursor: the first move after the restore is sent.
            cursor.at_service = 0;
            cursor.deferred_since_ms = Some(env.clock.now_ms());
            // The protocol's layer, checked before anything is written: a layer that another
            // protocol made, or that this one refuses, refuses the restore.
            let layer = backup.protocol_layer()?;
            if let Some(layer) = &layer
                && protocol.backup_name().as_deref() != Some(layer.protocol.as_str())
            {
                return Err(invalid("its protocol layer is another protocol's"));
            }
            // The protocol checks its layer against the identity's naming key, the one the
            // restored app goes on with, before anything is written.
            let restoring = RestoreContext::new(meta.identity, meta.app_id, &backup.naming, &cert);
            let layer_writes = match protocol.restore_layer(layer.as_ref(), &restoring) {
                Ok(writes) => writes,
                Err(_) if layer_check == LayerCheck::SizesOnly => Vec::new(),
                Err(why) => {
                    return Err(AppError::InvalidData(format!(
                        "the backup's protocol layer: {why}"
                    )));
                }
            };
            let (seen, parked, processed) = match &backup.protocol {
                Some(layer) => (
                    layer.seen.iter().copied().collect::<BTreeSet<u64>>(),
                    layer.parked.iter().cloned().collect::<BTreeMap<_, _>>(),
                    layer
                        .processed
                        .iter()
                        .map(|(rest, record)| {
                            let (sender, msg_id) = rest
                                .split_once('/')
                                .filter(|(_, msg_id)| !msg_id.is_empty())
                                .ok_or_else(|| invalid("processed pairs"))?;
                            let sender = pubky_switch_core::enc::pubky_key(sender)
                                .map_err(|_| invalid("processed pairs"))?;
                            Ok((sender, msg_id.to_owned(), *record))
                        })
                        .collect::<Result<Vec<_>, AppError>>()?,
                ),
                None => (BTreeSet::new(), BTreeMap::new(), Vec::new()),
            };
            // An entry the cursor passed needs no mark.
            let seen: BTreeSet<u64> = seen
                .into_iter()
                .filter(|seq| *seq > backup.cursor.seq)
                .collect();
            let state = AppState {
                meta: meta.clone(),
                keys: backup.keys.clone(),
                cert: cert.clone(),
                renewal: None,
                record: backup.record.clone(),
                naming: backup.naming.clone(),
                scope_keys: ScopeKeys {
                    keys: backup.scope_keys.clone(),
                },
                // A full-bundle request the backup holds may have been answered and its
                // parts read and dropped since, by the device it came from, leaving the
                // feed only stubs: the restore drops it, so the first read fetches and asks
                // once if a key is still missing. A repeated request keeps the service's
                // first time while it is pending, so a restore adds one request at most
                // (Switch wire 7.4.11).
                bundle: BundleState {
                    full_requested_ms: None,
                    ..backup.bundle.clone()
                },
                own_doc: own_doc.clone(),
                receive_keys,
                known_kids,
                registrations: BTreeMap::new(),
                rotation: backup.rotation,
                device: backup.device,
                cursor,
                chain: Some(chain),
                held: BTreeMap::new(),
                retries: BTreeMap::new(),
                stored_retries: BTreeMap::new(),
                next_stored_id: next_stored_id(None, &parked),
                parked_round: state::ParkedRound::default(),
                seen,
                asked: BTreeSet::new(),
                parked,
                departed,
                join: JoinStep::Done,
                pending_effect: None,
                pending_record: None,
                pending_publish: None,
                // The newest record the switch accepted, as the backup carries it apart from
                // the record held, which may be one whose `app.put` was refused or never
                // answered: only the accepted one is published, and never over a later
                // Homeserver copy (Switch spec 4.2). The record held goes to the switch again
                // only with the next change the protocol makes (`own_record.rs`).
                accepted: backup.accepted.clone(),
                alarm: None,
                restore: Some(RestoreState {
                    n_floor,
                    key_checked: false,
                    own_key_n: None,
                    reconcile: true,
                }),
                leave: None,
                service_time: None,
                gone: None,
                next_duty: FIRST_DUTY,
                duty_epoch: state::DutyEpoch::random()?,
                erasing: None,
            };
            let ns = client_namespace(&meta.app_id);
            // A restore in place keeps the store's event epoch and counter, and what the store
            // holds of what the app still owes its protocol: the duty events not
            // acknowledged and the calls the protocol couldn't answer. A store with no epoch,
            // on another device or wiped, starts a new epoch at the first counter. A store
            // that can't be read fails the restore (`STATE.md`, "What the app owes its
            // protocol").
            let old = Reader {
                ns: ns.clone(),
                store: env.store.clone(),
            };
            let carried = Self::kept_for_protocol(&old).await?.unwrap_or_default();
            // A restore in place keeps the store's holds beside the backup's: a hold the host
            // set after the backup still holds (`App::hold_queued`).
            let old_holds: Vec<String> = old
                .scan_raw(send::HOLD_PREFIX)
                .await?
                .into_iter()
                .map(|(rest, _)| rest)
                .collect();
            // No local ID is given out twice: past the backup's counter, the counter of the
            // store restored in place, every ID a carried duty event names, and every entry
            // the backup brings back.
            let old_next = Self::stored_next_of(&old).await?;
            let next_stored_id = state
                .next_stored_id
                .max(backup.stored_next)
                .max(old_next)
                .max(carried.stored_past);
            let state = AppState {
                duty_epoch: carried.epoch.unwrap_or(state.duty_epoch),
                next_duty: carried.next_duty.max(FIRST_DUTY),
                next_stored_id,
                ..state
            };
            let client = Self::client_for(&env, &meta, &backup.keys, &cert)?;
            let mut app = App {
                env,
                protocol,
                config,
                ns,
                state,
                client,
                reload: false,
                service_time_dirty: false,
                identity_confirmed: None,
                events: Vec::new(),
                duty_queued: 0,
                duty_handed: 0,
                time_fresh_at: None,
                kept_rate_limited: None,
                loss_upload_wait: None,
                sender_rereads: HashMap::new(),
                published_checked_ms: None,
                bundle_asked_ms: None,
                renewal_looked_ms: None,
                next_wait: wait::NextWait::Cursor,
                read_done_ms: None,
                peer_rereads: HashMap::new(),
                reads_begun: 0,
                reopen_failures: 0,
            };
            // Every write of the one commit; what fails here is mostly a write the store
            // can't take in one batch, over its sizes.
            let mut tx = Tx::new(&app.ns);
            // Set once the backup's own writes are in: a size refusal after it is the
            // carried part's.
            let mut carrying = false;
            let built: Result<(), AppError> = async {
                tx.delete_prefix("")?;
                app.write_all(&mut tx).await?;
                for (sender, msg_id, record) in &processed {
                    feed::processed_writes(&mut tx, sender, msg_id, record.hash, record.at_ms)?;
                }
                records::owe_listing(&mut tx)?;
                // The entries it brings back are told to the protocol again, in steps after
                // the restore commits (Switch spec 12.4).
                parked::Retell::start(&app.state, &mut tx)?;
                app.reinstall_outbox(backup, &mut tx)?;
                for rest in &old_holds {
                    if let Ok(pubky) = pubky_switch_core::enc::unb64_array::<32>(rest) {
                        send::put_hold(&mut tx, &pubky)?;
                    }
                }
                tx.local(&layer_writes)?;
                tx.put(key::DUTY_NEXT, &app.state.next_duty)?;
                tx.put(key::DUTY_EPOCH, &app.state.duty_epoch)?;
                carrying = true;
                for (stored, value) in &carried.values {
                    tx.put(stored, value)?;
                }
                // What didn't read is left behind, and the protocol told how much.
                if carried.lost_duties > 0 || carried.lost_owed > 0 {
                    app.keep_duty(
                        &mut tx,
                        events::Duty::RestoreLeftBehind {
                            duty_events: carried.lost_duties,
                            owed_calls: carried.lost_owed,
                        },
                    )?;
                }
                Ok(())
            }
            .await;
            match built {
                Ok(()) => Ok(Restorable::Ready(Box::new(app), tx)),
                Err(AppError::Store(StoreError::TooLarge { .. })) if carrying => {
                    let count = |prefix: &str| {
                        let n = carried
                            .values
                            .iter()
                            .filter(|(stored, _)| stored.starts_with(prefix))
                            .count();
                        u64::try_from(n).unwrap_or(u64::MAX)
                    };
                    Ok(Restorable::CarriedTooLarge {
                        duty_events: count(key::DUTY_PREFIX),
                        owed_calls: count(key::OWED_PREFIX),
                    })
                }
                Err(error) => restore_build_error(error),
            }
        })
        .await
    }

    /// Every record of the state, after a full delete of the namespace in the same commit.
    async fn write_all(&mut self, tx: &mut Tx) -> Result<(), AppError> {
        let s = &mut self.state;
        tx.put(key::META, &s.meta)?;
        tx.put(key::KEYS, &s.keys)?;
        tx.put(key::CERT, s.cert.signed())?;
        tx.put(key::RECORD, &s.record)?;
        if let Some(accepted) = &s.accepted {
            tx.put(key::ACCEPTED_RECORD, accepted)?;
        }
        tx.put(key::NAMING, &s.naming)?;
        for scope_key in &s.scope_keys.keys {
            tx.put(
                &key::scope(scope_key.data_epoch, &scope_key.scope),
                scope_key,
            )?;
        }
        tx.put(key::BUNDLE, &s.bundle)?;
        let doc = s.own_doc.clone();
        tx.put(
            &key::ident_doc(&s.meta.identity),
            &CachedDoc {
                doc: doc.signed().clone(),
                fetched_ms: 0,
            },
        )?;
        tx.put(
            &key::ident_floor(&s.meta.identity),
            &state::Floor {
                version: doc.version(),
                generation: doc.generation(),
            },
        )?;
        tx.put(
            &key::ident_body(&s.meta.identity, doc.version()),
            &pubky_switch_core::enc::b64(&doc.body_hash()),
        )?;
        for (n, held) in &s.receive_keys {
            tx.put(&key::receive_key(*n), held)?;
        }
        for (kid, n) in &s.known_kids {
            tx.put(&key::kid(kid), &KnownKid { n: *n })?;
        }
        tx.put(key::ROTATION, &s.rotation)?;
        tx.put(key::DEVICE, &s.device)?;
        tx.put(key::CURSOR, &s.cursor)?;
        for (app, at) in &s.departed {
            tx.put(&key::departed(app), at)?;
        }
        for seq in &s.seen {
            tx.put(&key::seen(*seq), &())?;
        }
        for (id, parked) in &s.parked {
            tx.put(&key::parked(*id), parked)?;
        }
        tx.put(key::STORED_NEXT, &s.next_stored_id)?;
        tx.put(key::JOIN, &s.join)?;
        if let Some(restore) = &s.restore {
            tx.put(key::RESTORE, restore)?;
        }
        if let Some(chain) = s.chain.as_mut() {
            chain.write_all(tx)?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // Accessors

    /// The App ID.
    pub fn app_id(&self) -> [u8; 16] {
        self.state.meta.app_id
    }

    /// The identity.
    pub fn identity(&self) -> [u8; 32] {
        self.state.meta.identity
    }

    /// The certificate the app presents.
    pub fn cert(&self) -> &AppCert {
        &self.state.cert
    }

    /// The app's signed record, as the service holds it or is being delivered.
    pub fn record(&self) -> &SignedDoc {
        &self.state.record
    }

    /// The newest own `identity.json` held.
    pub fn own_identity(&self) -> &IdentityDoc {
        &self.state.own_doc
    }

    /// The data epoch of the newest own `identity.json`.
    pub fn data_epoch(&self) -> u64 {
        self.state.own_doc.data_epoch()
    }

    /// The scope key of `scope` at `data_epoch`, a sub-scope's derived from its parent's
    /// (Switch spec 3.5). Sensitive.
    pub fn scope_key(&self, data_epoch: u64, scope: &str) -> Option<[u8; 32]> {
        self.state.scope_keys.get(data_epoch, scope)
    }

    /// The naming key (Switch spec 3.5). Sensitive.
    pub fn naming_key(&self) -> &NamingKey {
        &self.state.naming
    }

    /// `blind(input)` under the identity's naming key: `derive("pubky-switch/v1/name",
    /// naming_key, input)` (Switch wire 1.5). Every app of the identity gets the same output
    /// for the same input, so a protocol derives from it the keys its apps share, such as
    /// its claim keys (Switch spec 10.2, 13.3), without holding the naming key itself.
    pub fn blind(&self, input: &[u8]) -> [u8; 32] {
        self.state.naming.blind(input)
    }

    /// The newest data epoch through which the app holds every scope key.
    pub fn keys_through(&self) -> u64 {
        self.state.bundle.keys_through
    }

    /// The position the app has processed to.
    pub fn cursor(&self) -> Position {
        Position {
            generation: self.state.cursor.generation,
            seq: self.state.cursor.seq,
        }
    }

    /// The cursor the service holds, as the app last confirmed it.
    pub fn service_cursor(&self) -> Position {
        Position {
            generation: self.state.cursor.generation,
            seq: self.state.cursor.at_service,
        }
    }

    /// The `n` of each receive key the app holds.
    pub fn receive_key_numbers(&self) -> Vec<u64> {
        self.state.receive_keys.keys().copied().collect()
    }

    /// The alarm that stopped the app, if any.
    pub fn alarm(&self) -> Option<&Alarm> {
        self.state.alarm.as_ref()
    }

    /// After an unexpected registration: the `distrust_from` the app asks the signer to
    /// revoke it from, the service time at which that registration was accepted (Switch
    /// spec 3.6).
    pub fn compromise_distrust_from(&self) -> Option<u64> {
        match &self.state.alarm {
            Some(Alarm::Compromise { distrust_from, .. }) => *distrust_from,
            _ => None,
        }
    }

    /// Whether the app is in reconcile mode: after a restore, or with continuity unverified
    /// (Switch spec 8.3, 12.4). The protocol makes no new attempts until its reconciliation
    /// ends it ([`App::end_reconcile`]).
    pub fn reconcile_mode(&self) -> bool {
        self.state.restore.as_ref().is_some_and(|r| r.reconcile)
            || self.state.chain.as_ref().is_some_and(|c| c.gap.is_some())
    }

    /// Whether the app may make an attempt now (Switch spec 3.6, 10.1, 12.4): no alarm, not
    /// left, no restore question open, not in reconcile mode, and, for an automatic attempt,
    /// the device clock within the clock tolerance of the service's.
    ///
    /// # Errors
    ///
    /// The [`Refusal`] that holds the attempt back.
    pub fn may_attempt(&self, automatic: bool) -> Result<(), Refusal> {
        if self.state.alarm.is_some() {
            return Err(Refusal::Stopped);
        }
        if self.state.leave.is_some() {
            return Err(Refusal::Left);
        }
        if !self.restore_question().is_empty() {
            return Err(Refusal::RestoreQuestionOpen);
        }
        if self.reconcile_mode() {
            return Err(Refusal::NotNow("reconcile mode".into()));
        }
        if automatic
            && self
                .clock_skew_ms()
                .is_some_and(|skew| skew > CLOCK_TOLERANCE_MS)
        {
            return Err(Refusal::NotNow(
                "the device clock and the service's differ by more than the tolerance".into(),
            ));
        }
        Ok(())
    }

    /// How far apart the device clock and the service's are (Switch spec 10.1), `None`
    /// before any verified answer.
    pub fn clock_skew_ms(&self) -> Option<u64> {
        let time = self.state.service_time?;
        let ahead = time.highest_ms.saturating_sub(self.now());
        Some(time.offset_ms.unsigned_abs().max(ahead))
    }

    /// Reconciliation finished (Switch spec 12.4 step 2.4): reconcile mode ends, and with it
    /// the unverified continuity, if any.
    ///
    /// # Errors
    ///
    /// [`Refusal::RestoreQuestionOpen`] while the restore question is open;
    /// [`Refusal::NotNow`] while a provider loss is followed and the app's evidence isn't
    /// uploaded yet (Switch spec 12.6 step 3); a store failure.
    pub async fn end_reconcile(&mut self, _confirmed: UserConfirmed) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            if !self.restore_question().is_empty() {
                return Err(Refusal::RestoreQuestionOpen.into());
            }
            self.refuse_before_upload().await?;
            let mut tx = self.tx()?;
            // With its key check done and nothing left to ask, the restore is over: its
            // record goes, and no registration is judged by the restore rule again.
            let over = self.state.restore.as_ref().is_some_and(|r| r.key_checked);
            if over {
                tx.delete(key::RESTORE)?;
            } else if let Some(restore) = self.state.restore.as_mut() {
                restore.reconcile = false;
                tx.put(key::RESTORE, restore)?;
            }
            if let Some(chain) = self.state.chain.as_mut() {
                chain.gap = None;
                chain.write(&mut tx)?;
            }
            self.commit(tx).await?;
            if over {
                self.state.restore = None;
            }
            Ok(())
        })
        .await
    }

    /// Take the events collected since the last call. Duty events among them stay kept
    /// until [`App::ack_events`] acknowledges them (`events` module, "Duty events").
    pub fn take_events(&mut self) -> Vec<AppEvent> {
        let events = std::mem::take(&mut self.events);
        for id in events.iter().filter_map(AppEvent::id) {
            self.duty_handed = self.duty_handed.max(id.counter());
        }
        events
    }

    /// Queue `event`, a stop the host acts on (`Removed`, `ProviderChanged`), unless it is
    /// already queued and not yet taken: several steps of one call may find the same stop,
    /// and the host is told once.
    pub(crate) fn push_once(&mut self, event: AppEvent) {
        if !self.events.contains(&event) {
            self.events.push(event);
        }
    }

    /// Queue duty events for the host, in order, and keep how far they go.
    fn queue_duties(&mut self, duties: Vec<AppEvent>) {
        for id in duties.iter().filter_map(AppEvent::id) {
            self.duty_queued = self.duty_queued.max(id.counter());
        }
        self.events.extend(duties);
    }

    /// After a reload: the kept duty events no call queued, such as those of a commit that
    /// answered [`StoreError::Unknown`] and was applied, queued now.
    async fn queue_unreported_duties(&mut self) -> Result<(), AppError> {
        let queued = self.duty_queued;
        let kept: Vec<AppEvent> = self
            .kept_duties()
            .await?
            .into_iter()
            .filter(|event| event.id().is_some_and(|id| id.counter() > queued))
            .collect();
        self.queue_duties(kept);
        Ok(())
    }

    /// How many protocol calls the protocol answered with an error and the app still owes
    /// it ([`Protocol::resend_needed`], [`Protocol::missed`]): each read makes them again,
    /// so a count that stays up shows a protocol that keeps failing.
    ///
    /// # Errors
    ///
    /// A failed store read.
    pub async fn owed_protocol_calls(&self) -> Result<u64, AppError> {
        let owed = self.reader().scan_raw(key::OWED_PREFIX).await?;
        Ok(u64::try_from(owed.len()).unwrap_or(u64::MAX))
    }

    /// The duty events kept and not acknowledged yet, by ascending ID: what a host that
    /// lost its copy of the reports still has to act on. Nothing but [`App::ack_events`]
    /// shortens this list (`events` module, "Duty events"). Listing them hands them to the
    /// host, as [`App::take_events`] does, so an acknowledgement up to the last of them
    /// removes them all.
    ///
    /// # Errors
    ///
    /// A failed store read.
    pub async fn unacknowledged_events(&mut self) -> Result<Vec<AppEvent>, AppError> {
        // A reload owed first, so what it queues is listed here, once.
        self.ready_local().await?;
        let kept = self.kept_duties().await?;
        for id in kept.iter().filter_map(AppEvent::id) {
            self.duty_handed = self.duty_handed.max(id.counter());
        }
        // Handed over here, so not again by the next report.
        let handed = self.duty_handed;
        self.events
            .retain(|event| event.id().is_none_or(|id| id.counter() > handed));
        Ok(kept)
    }

    /// The duty events kept, by ascending ID, without handing them to the host.
    pub(crate) async fn kept_duties(&self) -> Result<Vec<AppEvent>, AppError> {
        Ok(self
            .reader()
            .scan_numbered::<events::Duty>(key::DUTY_PREFIX)
            .await?
            .into_iter()
            .map(|(n, duty)| duty.event(EventId::new(self.state.duty_epoch.epoch, n)))
            .collect())
    }

    /// Acknowledge every duty event up to and including `up_to`: the host and its protocol
    /// kept what they say, and the store no longer keeps them, so no later
    /// [`App::load`] delivers them again. IDs rise in the order the events are reported,
    /// so a host acknowledges after acting on every duty event it took up to that ID. An
    /// ID no event has yet acknowledges only those before it. IDs compare only within one
    /// store ([`EventId::cmp_same_store`]). Only events this app value handed to the host,
    /// by [`App::take_events`] or a call's report, are removed: one kept but not yet taken,
    /// such as one queued after a reload, stays until it is taken and acknowledged.
    ///
    /// The host must call this once it has handed the events to its protocol and the
    /// protocol has kept what they say: nothing else removes a kept duty event, so a host
    /// that never acknowledges keeps them all, without limit (`events` module, "Duty
    /// events").
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for an ID of another store, such as one from before a restore on
    /// another device: nothing is acknowledged. A failed store read or commit; nothing is
    /// acknowledged then either.
    pub async fn ack_events(&mut self, up_to: EventId) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            if up_to.epoch() != self.state.duty_epoch.epoch {
                return Err(Refusal::Usage(
                    "an event ID of another store: nothing acknowledged".into(),
                )
                .into());
            }
            // Only what the host was handed: a kept event it never took stays.
            let through = up_to.counter().min(self.duty_handed);
            let kept = self.reader().scan_numbers(key::DUTY_PREFIX).await?;
            let mut tx = self.tx()?;
            for n in kept.range(..=through) {
                tx.delete(&key::duty(*n))?;
            }
            self.commit(tx).await
        })
        .await
    }

    /// Keep a duty event in `tx`, under the next ID: written in the commit of the change it
    /// reports, and reported once that commit is done (`events` module, "Duty events").
    pub(crate) fn keep_duty(&mut self, tx: &mut Tx, duty: events::Duty) -> Result<(), AppError> {
        let n = self.state.next_duty;
        let next = n.checked_add(1).ok_or_else(corrupt)?;
        tx.put(&key::duty(n), &duty)?;
        tx.put(key::DUTY_NEXT, &next)?;
        self.state.next_duty = next;
        tx.report(duty.event(EventId::new(self.state.duty_epoch.epoch, n)));
        Ok(())
    }

    /// What a restore in place carries across. `None` for a store that holds no epoch. A
    /// failed store read is the error: the restore can be tried again. A value that reads
    /// but doesn't decode is left behind and counted; a damaged epoch or counter starts a
    /// new epoch, since the kept counters may then be below IDs the host acknowledged.
    async fn kept_for_protocol(reader: &Reader) -> Result<Option<Carried>, AppError> {
        let Some(epoch) = reader.get_raw(key::DUTY_EPOCH.as_bytes()).await? else {
            return Ok(None);
        };
        let epoch = state::decode::<state::DutyEpoch>(&epoch).ok();
        let counter = match reader.get_raw(key::DUTY_NEXT.as_bytes()).await? {
            None => Some(FIRST_DUTY),
            Some(bytes) => state::decode::<u64>(&bytes).ok(),
        };
        let mut carried = Carried::default();
        let mut past_kept = FIRST_DUTY;
        for (rest, bytes) in reader.scan_raw(key::DUTY_PREFIX).await? {
            let read = state::parse_num(&rest).and_then(|n| {
                let duty = state::decode::<events::Duty>(&bytes)?;
                Ok((n, duty, state::decode::<serde_json::Value>(&bytes)?))
            });
            match read {
                Ok((n, duty, value)) => {
                    past_kept = past_kept.max(n.checked_add(1).ok_or_else(corrupt)?);
                    if let Some(id) = duty.stored_id() {
                        carried.stored_past = carried.stored_past.max(id.saturating_add(1));
                    }
                    carried
                        .values
                        .push((format!("{}{rest}", key::DUTY_PREFIX), value));
                }
                Err(_) => carried.lost_duties = carried.lost_duties.saturating_add(1),
            }
        }
        for (rest, bytes) in reader.scan_raw(key::OWED_PREFIX).await? {
            let read = state::decode::<feed::OwedCall>(&bytes)
                .and_then(|_| state::decode::<serde_json::Value>(&bytes));
            match read {
                Ok(value) => carried
                    .values
                    .push((format!("{}{rest}", key::OWED_PREFIX), value)),
                Err(_) => carried.lost_owed = carried.lost_owed.saturating_add(1),
            }
        }
        match (epoch, counter) {
            (Some(epoch), Some(counter)) => {
                carried.epoch = Some(epoch);
                carried.next_duty = counter.max(past_kept);
            }
            _ => carried.next_duty = past_kept,
        }
        Ok(Some(carried))
    }

    /// The local ID the store's next entry stored locally would take, for a restore in
    /// place: its counter (`parkid`) and, past it, every `parked/` and `sretry/` key it
    /// holds. A counter that doesn't read, from a store that was damaged or of another
    /// schema, gives way to those keys rather than to the first ID.
    async fn stored_next_of(reader: &Reader) -> Result<u64, AppError> {
        let counter = match reader.get_raw(key::STORED_NEXT.as_bytes()).await? {
            Some(bytes) => state::decode::<u64>(&bytes).ok(),
            None => None,
        };
        let mut next = counter.unwrap_or(FIRST_STORED_ID);
        for prefix in ["parked/", "sretry/"] {
            for (rest, _) in reader.scan_raw(prefix).await? {
                if let Ok(id) = state::parse_num(&rest) {
                    next = next.max(id.saturating_add(1));
                }
            }
        }
        Ok(next)
    }

    /// The ID the next duty event takes: past the counter and every kept event.
    async fn next_duty(reader: &Reader) -> Result<u64, AppError> {
        let counter: u64 = reader.get(key::DUTY_NEXT).await?.unwrap_or(FIRST_DUTY);
        let kept = reader.scan_numbers(key::DUTY_PREFIX).await?;
        let past_kept = match kept.last() {
            Some(last) => last.checked_add(1).ok_or_else(corrupt)?,
            None => FIRST_DUTY,
        };
        Ok(counter.max(past_kept))
    }

    /// The highest service time the app verified, Unix milliseconds (Switch spec 10.1): a
    /// protocol checks its deadlines against it rather than the device clock. `None` before
    /// any verified answer.
    pub fn highest_service_time(&self) -> Option<u64> {
        self.state.service_time.map(|time| time.highest_ms)
    }

    /// A value of the protocol's own local state, under its key space.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn protocol_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, AppError> {
        self.reader()
            .get_raw(&[PROTOCOL_PREFIX, key].concat())
            .await
    }

    /// Every value of the protocol's own local state whose key starts with `prefix`, with
    /// its key in the protocol's key space, in key order.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn protocol_scan(
        &self,
        prefix: &[u8],
    ) -> Result<Vec<crate::store::KeyValue>, AppError> {
        let full = [PROTOCOL_PREFIX, prefix].concat();
        let mut out = Vec::new();
        let mut after: Option<Vec<u8>> = None;
        loop {
            let page = self
                .env
                .store
                .scan(&self.ns, &full, after.as_deref(), PROTOCOL_SCAN_PAGE)
                .await?;
            let more = page.len() >= usize::try_from(PROTOCOL_SCAN_PAGE).unwrap_or(usize::MAX);
            for (key, value) in page {
                if let Some(rest) = key.get(PROTOCOL_PREFIX.len()..) {
                    out.push((rest.to_vec(), value.clone()));
                }
                after = Some(key);
            }
            if !more {
                return Ok(out);
            }
        }
    }

    /// Commit writes of the protocol's own local state on their own, in one store commit.
    /// Writes that go with a batch's outcome go in the batch instead
    /// ([`OpBatch::local`]), and those of a received message's effect with it
    /// ([`Effect::local`], [`ReceiveContext::local`]).
    ///
    /// # Errors
    ///
    /// [`Refusal::Left`] once the app deleted its keys; a store failure, after which nothing
    /// was written.
    pub async fn protocol_commit(&mut self, writes: &[LocalWrite]) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            if self
                .state
                .leave
                .is_some_and(|l| l.keys_deleted_ms.is_some())
            {
                return Err(Refusal::Left.into());
            }
            let mut tx = self.tx()?;
            tx.local(writes)?;
            self.commit(tx).await
        })
        .await
    }

    // ---------------------------------------------------------------------------------
    // Leaving (Switch spec 12.3)

    /// Leave the identity (Switch spec 12.3): `leave` at the service, then the keys go: at
    /// once for [`LeaveMode::Immediate`], or once the signer published the app as removed
    /// and readers' caches passed for [`LeaveMode::TwoStep`] ([`App::finish_leave`]).
    /// An app that publishes its record deletes it from the Homeserver first, and publishes
    /// nothing from the commit that starts the leave on, across a restart too (Switch spec
    /// 12.3).
    ///
    /// # Errors
    ///
    /// A failed call; the leave is tried again by the next call to `leave`.
    pub async fn leave(&mut self, mode: LeaveMode) -> Result<LeaveReport, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let two_step = matches!(mode, LeaveMode::TwoStep);
            self.leave_at_service(two_step, false).await?;
            match mode {
                LeaveMode::Immediate(_) => {
                    self.destroy_keys().await?;
                    Ok(LeaveReport::Done)
                }
                LeaveMode::TwoStep => self.finish_leave().await,
            }
        })
        .await
    }

    /// The second step of a two-step leave: once the own `identity.json` on the Homeserver
    /// lists the app in `removed`, wait [`LEAVE_CACHE_MS`] from when it was first seen, then
    /// delete the keys.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotNow`] if the app hasn't left; a failed read.
    pub async fn finish_leave(&mut self) -> Result<LeaveReport, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let Some(leave) = self.state.leave else {
                return Err(Refusal::NotNow("the app hasn't left".into()).into());
            };
            if leave.left_at_ms.is_none() {
                return Err(Refusal::NotNow("the leave hasn't reached the service".into()).into());
            }
            if leave.keys_deleted_ms.is_some() {
                return Ok(LeaveReport::Done);
            }
            let now = self.now();
            let seen = match leave.removed_seen_ms {
                Some(seen) => seen,
                None => {
                    let identity = self.state.meta.identity;
                    let doc =
                        identity::read_homeserver(self.env.homeserver.as_ref(), &identity).await?;
                    let removed = doc
                        .as_ref()
                        .is_some_and(|d| d.lists_removed(&self.state.meta.app_id));
                    if !removed {
                        return Ok(LeaveReport::AwaitingRemoval);
                    }
                    let mut tx = self.tx()?;
                    let leave = self.state.leave.get_or_insert_with(LeaveState::default);
                    leave.removed_seen_ms = Some(now);
                    tx.put(key::LEAVE, leave)?;
                    self.commit(tx).await?;
                    now
                }
            };
            let at = seen.saturating_add(LEAVE_CACHE_MS);
            if now < at {
                return Ok(LeaveReport::Removed {
                    delete_keys_at_ms: at,
                });
            }
            self.destroy_keys().await?;
            Ok(LeaveReport::Done)
        })
        .await
    }

    /// `leave` at the service, once: the intent is committed first, so a crash calls it
    /// again; an app the service already counts as departed is answered `403 not_current`,
    /// which is the leave done.
    async fn leave_at_service(&mut self, two_step: bool, compromise: bool) -> Result<(), AppError> {
        if self.state.leave.is_some_and(|l| l.left_at_ms.is_some()) {
            return Ok(());
        }
        if self.state.leave.is_none() {
            let mut tx = self.tx()?;
            let leave = LeaveState {
                compromise,
                ..LeaveState::default()
            };
            tx.put(key::LEAVE, &leave)?;
            self.state.leave = Some(leave);
            self.commit(tx).await?;
        }
        // A publishing app deletes its Homeserver record first (Switch spec 12.3); the leave
        // committed above stops every publication from here on. Only a two-step leave waits
        // for the delete: an immediate leave, and a compromise's, which leaves at once
        // (Switch spec 3.6), go on without it, the failure reported, and the signer's
        // clean-up deletes the record (Switch spec 12.2 step 4). This call's mode decides,
        // so an immediate leave asked for after a two-step one whose delete failed goes on
        // too; and once a compromise started the leave, every later call is a leave after
        // a compromise.
        let waits = two_step && !self.state.leave.is_some_and(|leave| leave.compromise);
        match self.unpublish_to_leave().await {
            Ok(()) => {}
            Err(AppError::Transport(error)) if !waits => {
                self.events.push(AppEvent::RecordPublishFailed {
                    error: error.to_string(),
                });
            }
            Err(error) => return Err(error),
        }
        let result = self.client.leave().await;
        let answered = match self.take(result).await {
            Ok(answer) => {
                if let Err(alarm) = self.note_answer_head(answer.head, &answer.proofs) {
                    return Err(self.raise(alarm).await);
                }
                true
            }
            Err(error) if error.code() == Some(pubky_switch_core::http::ErrorCode::NotCurrent) => {
                true
            }
            Err(error) => return Err(error),
        };
        if answered {
            let now = self.now();
            let mut tx = self.tx()?;
            let leave = self.state.leave.get_or_insert_with(LeaveState::default);
            leave.left_at_ms = Some(now);
            tx.put(key::LEAVE, leave)?;
            self.commit(tx).await?;
            self.events.push(AppEvent::Left);
        }
        Ok(())
    }

    /// Delete the keys, in the sense of Switch spec 3.1: every record that holds one, and
    /// the parked plaintexts. The store deletes them for real.
    async fn destroy_keys(&mut self) -> Result<(), AppError> {
        let now = self.now();
        let mut tx = Tx::new(&self.ns);
        for prefix in [
            "rk/",
            "scope/",
            "parked/",
            "pending/",
            "p/",
            key::DUTY_PREFIX,
            key::OWED_PREFIX,
        ] {
            tx.delete_prefix(prefix)?;
        }
        records::destroy_shared(&mut tx)?;
        tx.delete(key::KEYS)?;
        tx.delete(key::NAMING)?;
        let leave = self.state.leave.get_or_insert_with(LeaveState::default);
        leave.keys_deleted_ms = Some(now);
        tx.put(key::LEAVE, leave)?;
        self.commit(tx).await?;
        self.state.receive_keys.clear();
        self.state.scope_keys = ScopeKeys::default();
        self.state.parked.clear();
        self.events.push(AppEvent::KeysDestroyed);
        Ok(())
    }

    /// After a compromise: stop, and leave at once (Switch spec 3.6). The keys stay for the
    /// user; the leave is irreversible, so the copy holding the same signing key is refused
    /// from now on. A failed call is tried again at the next call.
    async fn leave_on_compromise(&mut self) {
        if self.state.leave.is_some_and(|l| l.left_at_ms.is_some()) {
            return;
        }
        // A failure leaves the leave owed: the next call reads the store again and tries it
        // again.
        if self.leave_at_service(false, true).await.is_err() {
            self.reload = true;
        }
    }

    // ---------------------------------------------------------------------------------
    // Internals

    fn client_for(
        env: &AppEnv,
        meta: &Meta,
        keys: &AppKeys,
        cert: &AppCert,
    ) -> Result<SwitchClient, AppError> {
        Ok(SwitchClient::new(
            &meta.origin,
            meta.identity,
            Credentials::App {
                identity: meta.identity,
                keys: keys.clone(),
                cert: cert.clone(),
            },
            Some(meta.service_key),
            Arc::clone(&env.transport),
            Arc::clone(&env.clock),
        )?)
    }

    pub(crate) fn now(&self) -> u64 {
        self.env.clock.now_ms()
    }

    pub(crate) fn reader(&self) -> Reader {
        Reader {
            ns: self.ns.clone(),
            store: self.env.store.clone(),
        }
    }

    /// A transaction, carrying the service time record when it changed.
    pub(crate) fn tx(&mut self) -> Result<Tx, AppError> {
        let mut tx = Tx::new(&self.ns);
        if self.service_time_dirty
            && let Some(time) = &self.state.service_time
        {
            tx.put(key::SERVICE_TIME, time)?;
        }
        Ok(tx)
    }

    /// Commit; after a failure the app reads its state again before going on.
    pub(crate) async fn commit(&mut self, mut tx: Tx) -> Result<(), AppError> {
        let duties = tx.take_reports();
        match tx.commit(&self.env.store).await {
            Ok(()) => {
                self.service_time_dirty = false;
                self.queue_duties(duties);
                Ok(())
            }
            Err(error) => {
                self.reload = true;
                Err(error)
            }
        }
    }

    /// The time budget of a call that begins now ([`AppConfig::call_budget_ms`]).
    pub(crate) fn begin_budget(&self) -> CallBudget {
        CallBudget {
            began_ms: self.now(),
            budget_ms: self.config.call_budget_ms,
        }
    }

    /// Whether `budget` is spent now.
    pub(crate) fn spent(&self, budget: &CallBudget) -> bool {
        budget.spent(self.now())
    }

    /// Reload after a failed commit, and refuse calls the app's state forbids.
    async fn ready_local(&mut self) -> Result<(), AppError> {
        // Each call takes a service time of its own before it judges a kept batch's age.
        self.time_fresh_at = None;
        if self.reload {
            self.state = Self::read_state(&self.reader()).await?;
            self.client = Self::client_for(
                &self.env,
                &self.state.meta,
                &self.state.keys,
                &self.state.cert,
            )?;
            self.service_time_dirty = false;
            // The reload is done only once the kept duty events it may owe the host are
            // queued: a replay that fails is made again by the next call.
            self.queue_unreported_duties().await?;
            self.reload = false;
        }
        Ok(())
    }

    /// Raise an alarm: keep it, stop, and return it as the error.
    pub(crate) async fn raise(&mut self, alarm: Alarm) -> AppError {
        if self.state.alarm.is_none() {
            self.state.alarm = Some(alarm.clone());
            self.events.push(AppEvent::Alarm(alarm.clone()));
            let tx = self.tx().and_then(|mut tx| {
                tx.put(key::ALARM, &alarm)?;
                Ok(tx)
            });
            if let Ok(tx) = tx {
                // A failed commit leaves the alarm in memory; the app is stopped either way
                // and raises it again on reload from the same evidence.
                let _ = self.commit(tx).await;
            }
        }
        AppError::Alarm(alarm)
    }

    /// Take a call's result: note the service time of a checked answer, raise an alarm for
    /// a time that went back, and a rollback for an answer that contradicts itself (Switch
    /// spec 10.1).
    pub(crate) async fn take<T>(&mut self, result: Result<T, ClientError>) -> Result<T, AppError> {
        if let Some(alarm) = self.note_service_time() {
            return Err(self.raise(alarm).await);
        }
        // An answer verified with the pinned key, an error answer included: the account is
        // there, and the erasure wait starts over (Switch spec 12.7).
        if matches!(result, Ok(_) | Err(ClientError::Switch { .. })) {
            self.clear_erasing().await?;
        }
        match result {
            Ok(value) => Ok(value),
            Err(ClientError::Chain(error)) => Err(self
                .raise(Alarm::Rollback {
                    reason: error.to_string(),
                })
                .await),
            Err(error) => Err(error.into()),
        }
    }

    /// The service time of the latest checked answer (Switch spec 10.1): the highest is
    /// kept with its key, and its offset from the device clock; an earlier one from the
    /// same key is misbehaviour, returned as the alarm.
    fn note_service_time(&mut self) -> Option<Alarm> {
        // Only the latest call's own stamped time: a refusal answered before the request
        // verified carries the last committed time, and measures nothing (Switch wire 7.1).
        let time = self.client.latest_server_time()?;
        let now = self.now();
        self.time_fresh_at = Some(now);
        let key = self.state.meta.service_key;
        let offset = i64::try_from(time)
            .unwrap_or(i64::MAX)
            .saturating_sub(i64::try_from(now).unwrap_or(i64::MAX));
        let mut alarm = None;
        let record = match self.state.service_time {
            Some(held) if held.key == key => {
                if time < held.highest_ms {
                    alarm = Some(Alarm::ServiceTimeBackwards {
                        highest: held.highest_ms,
                        signed: time,
                    });
                }
                ServiceTime {
                    key,
                    highest_ms: held.highest_ms.max(time),
                    offset_ms: offset,
                }
            }
            _ => ServiceTime {
                key,
                highest_ms: time,
                offset_ms: offset,
            },
        };
        if time > now.saturating_add(SERVICE_TIME_AHEAD_MS)
            || offset.unsigned_abs() > CLOCK_TOLERANCE_MS
        {
            let event = AppEvent::ClockSkew {
                skew_ms: offset.unsigned_abs(),
            };
            if !self.events.contains(&event) {
                self.events.push(event);
            }
        }
        if self.state.service_time != Some(record) {
            self.state.service_time = Some(record);
            self.service_time_dirty = true;
        }
        alarm
    }

    /// `POST /ops` with a batch whose body the caller committed: the answer's head goes to
    /// the chain view, and a signed answer that contradicts itself is a rollback. Nothing
    /// but a provider loss's registration goes before the loss's upload (Switch spec 12.6
    /// step 3). A kept batch signed for an earlier generation has its proofs checked with
    /// that generation's key (Switch wire 6.4 step 6).
    pub(crate) async fn submit(&mut self, batch: &Batch) -> Result<Submitted, AppError> {
        self.refuse_before_upload_of(Some(batch)).await?;
        let generation = batch_generation(batch);
        let result = match generation.filter(|g| *g < self.state.meta.generation) {
            Some(earlier) => match self.service_key_of(earlier).await? {
                Some(key) => self.client.submit_proved_by(batch, &key).await,
                None => self.client.submit(batch).await,
            },
            None => self.client.submit(batch).await,
        };
        let submitted = self.take(result).await?;
        if let Err(alarm) = self.note_answer_head(submitted.head, &submitted.proofs) {
            return Err(self.raise(alarm).await);
        }
        if let Some(position) = batch.cursor()
            && position.generation == self.state.cursor.generation
        {
            self.state.cursor.at_service = self.state.cursor.at_service.max(position.seq);
            if self.state.cursor.at_service >= self.state.cursor.seq {
                self.state.cursor.deferred_since_ms = None;
            }
            if let Some(chain) = self.state.chain.as_mut()
                && chain.restore == Some(RestorePending::Cursor)
            {
                chain.restore = Some(RestorePending::Read);
            }
        }
        Ok(submitted)
    }

    /// The head and proof stubs of a write answer: checked against the chain, and held as
    /// evidence until the feed reaches them (Switch wire 7.4.4).
    fn note_answer_head(
        &mut self,
        head: pubky_switch_core::chain::SignedHead,
        proofs: &[TransitionProof],
    ) -> Result<(), Alarm> {
        let time = self.client.last_server_time();
        let Some(chain) = self.state.chain.as_mut() else {
            return Ok(());
        };
        chain.observe_head(head).map_err(|error| match error {
            AppError::Alarm(alarm) => alarm,
            other => Alarm::Rollback {
                reason: other.to_string(),
            },
        })?;
        if let Some(time) = time {
            chain.note_held(head.seq, time);
            for proof in proofs {
                chain.note_held(proof.envelope().seq, time);
            }
        }
        Ok(())
    }

    /// The batch's operations, signed for the generation the app follows, with the
    /// deferred cursor move when there is room for it (Switch spec 8.2).
    pub(crate) fn sign_ops(
        &self,
        ops: Vec<(Vec<Condition>, OpKind)>,
        cursor_to: Option<u64>,
    ) -> Result<Batch, AppError> {
        let cursor = cursor_to
            .filter(|seq| *seq > self.state.cursor.at_service)
            .map(|seq| Position {
                generation: self.state.cursor.generation,
                seq,
            });
        Ok(self
            .client
            .sign_batch(self.state.meta.generation, ops, cursor)?)
    }

    /// The certificate changed: requests present the new one from now on.
    pub(crate) fn rebuild_client(&mut self) -> Result<(), AppError> {
        self.client = Self::client_for(
            &self.env,
            &self.state.meta,
            &self.state.keys,
            &self.state.cert,
        )?;
        Ok(())
    }
}

/// The generation a batch's signed operations name; `None` for a cursor-only batch.
pub(crate) fn batch_generation(batch: &Batch) -> Option<u64> {
    batch.ops().first().map(|op| op.body().generation)
}

/// The local ID the first entry stored locally takes.
const FIRST_STORED_ID: u64 = 1;

/// The local ID the next entry stored locally takes: the one kept, and in any case past
/// every one taken, so none is used twice.
fn next_stored_id(kept: Option<u64>, parked: &BTreeMap<u64, ParkedEntry>) -> u64 {
    let past = parked
        .keys()
        .next_back()
        .map_or(FIRST_STORED_ID, |id| id.saturating_add(1));
    kept.unwrap_or(FIRST_STORED_ID).max(past)
}
