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
//! through [`StoreHandle`], and the Homeserver, through [`HomeserverReader`].
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
mod identity;
mod keys;
mod peek;
mod protocol;
mod provider;
mod push;
mod recovery;
mod renewal;
mod rotation;
mod state;

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
pub use error::{Alarm, AppError, Refusal};
pub use events::{AppEvent, EventId, ParkReason};
pub use feed::ReceiveReport;
pub use identity::{DOC_CACHE_MS, HomeserverReader, IdentityRefresh, REVALIDATION_MS};
pub use peek::{PeekReport, Peeked};
pub use protocol::{
    Effect, LocalWrite, MAX_CLAIM_READS, MissedEntries, Need, OpaqueRule, Outcome, Protocol,
    ReceivedMessage, ResendNeeded, ResendReason,
};
pub use provider::ProviderStatus;
pub use push::{MAX_HANDLE_BYTES, MAX_HANDLES, PushHandles, PushRegistration, PushRelay};
pub use recovery::{Evidence, LossActions, ProviderLoss, RESIDUAL_WINDOW_MS, RecoveryInfo};
pub use state::{PROTOCOL_PREFIX, SCHEMA_VERSION};

pub use admission::{INVITE_CODE_BYTES, InviteCode};
pub use batch::{OpBatch, server_time_in};
pub use claims::{
    ClaimDoubt, ClaimEntryRead, ClaimEvidence, ClaimOp, ClaimRead, ClaimWritten,
    ObligationDeadline, claim_conflict,
};
pub use context::{ClaimFetch, LocalView, ReceiveContext};
pub use directory::{
    HomeserverCopy, IdentityLookup, Initiator, MayAct, PEER_DELIVERY_MS, PeerIdentity,
    SwitchAnswer, SwitchCopy, SwitchLookup,
};
pub use records::{
    Collection, FlaggedWrite, KeptOp, PolicyFamily, RecordContent, RecordTarget, SharedEvidence,
    SharedRecord,
};
pub use send::{
    Delivery, OutboxReport, OutgoingMessage, RecordJob, SENT_RETENTION_MS, SentMessage,
    SignedMessage, UNDELIVERABLE_MAX_MS, UNDELIVERABLE_MS, UNDELIVERABLE_TRIES,
    UNDELIVERABLE_TRY_SPACING_MS,
};

use std::collections::{BTreeMap, BTreeSet};
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
    Meta, ParkedEntry, PendingEffect, PendingRecord, Reader, Registration, RestorePending,
    RestoreState, Rotation, ServiceTime, Tx, key,
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
    /// Whether the app publishes its record on the Homeserver; such an app leaves in two
    /// steps (Switch spec 12.3).
    pub publishes_record: bool,
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

/// What an app runs on: the host's store, the transport to its switch, the clock and the
/// Homeserver reader.
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
    record: SignedDoc,
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

    /// Read a backup's bytes.
    ///
    /// # Errors
    ///
    /// [`AppError::InvalidData`] if they don't read as a backup of this schema.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AppError> {
        let backup: Self = serde_json::from_slice(bytes)
            .map_err(|_| AppError::InvalidData("the backup doesn't read".into()))?;
        if backup.v != SCHEMA_VERSION {
            return Err(AppError::InvalidData(
                "the backup is of another schema version".into(),
            ));
        }
        Ok(backup)
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
    pub(crate) seen: BTreeSet<u64>,
    pub(crate) asked: BTreeSet<u64>,
    pub(crate) parked: BTreeMap<u64, ParkedEntry>,
    pub(crate) departed: BTreeMap<[u8; 16], u64>,
    pub(crate) join: JoinStep,
    pub(crate) pending_effect: Option<PendingEffect>,
    pub(crate) pending_record: Option<PendingRecord>,
    pub(crate) alarm: Option<Alarm>,
    pub(crate) restore: Option<RestoreState>,
    pub(crate) leave: Option<LeaveState>,
    pub(crate) service_time: Option<ServiceTime>,
    /// The app isn't current any more, or its account is gone: every read stops.
    pub(crate) gone: Option<provider::GoneRecord>,
    /// The ID the next duty event takes (`dutyn`).
    pub(crate) next_duty: u64,
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
                seen: BTreeSet::new(),
                asked: BTreeSet::new(),
                parked: BTreeMap::new(),
                departed: BTreeMap::new(),
                join: JoinStep::Registering {
                    body: batch.body().to_vec(),
                },
                pending_effect: None,
                pending_record: None,
                alarm: None,
                restore: None,
                leave: None,
                service_time: None,
                gone: None,
                next_duty: FIRST_DUTY,
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
            tx.put(records::LIST_DUE, &true)?;
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
        self.state.chain = Some(view);
        self.commit(tx).await
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
            };
            // Duty events not acknowledged before are delivered again (`events` module).
            app.events = app.unacknowledged_events().await?;
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
            seen: reader.scan_numbers("seen/").await?,
            asked: reader.scan_numbers("asked/").await?,
            parked: reader.scan_numbered("parked/").await?,
            departed,
            join: reader.get(key::JOIN).await?.ok_or_else(missing)?,
            pending_effect: reader.get(key::PENDING_EFFECT).await?,
            pending_record: reader.get(key::PENDING_RECORD).await?,
            alarm: reader.get(key::ALARM).await?,
            restore: reader.get(key::RESTORE).await?,
            leave,
            service_time: reader.get(key::SERVICE_TIME).await?,
            gone: reader.get(provider::keys::GONE).await?,
            next_duty: Self::next_duty(reader).await?,
            erasing: reader.get(provider::keys::ERASING).await?,
            meta,
        })
    }

    /// The app's backup (Switch spec 12.4): its keys, certificate and record, scope keys
    /// and naming key, its receive keys and the kids it knows, its cursor and chain view.
    /// The app should take one at every rotation, replacing the previous one (Switch spec
    /// 3.6).
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`] when there is nothing to back up.
    pub fn backup(&self) -> Result<AppBackup, AppError> {
        if self.state.leave.is_some() {
            return Err(Refusal::Left.into());
        }
        let chain =
            self.state.chain.as_ref().ok_or_else(|| {
                AppError::Refused(Refusal::NotNow("the app isn't registered".into()))
            })?;
        let (record, at, batches) = chain.export();
        Ok(AppBackup {
            v: SCHEMA_VERSION,
            meta: self.state.meta.clone(),
            keys: self.state.keys.clone(),
            cert: self.state.cert.signed().clone(),
            record: self.state.record.clone(),
            naming: self.state.naming.clone(),
            scope_keys: self.state.scope_keys.keys.clone(),
            own_doc: self.state.own_doc.signed().clone(),
            receive_keys: self.state.receive_keys.values().cloned().collect(),
            known: self
                .state
                .known_kids
                .iter()
                .map(|(kid, n)| (pubky_switch_core::enc::b64(kid), *n))
                .collect(),
            rotation: self.state.rotation,
            device: self.state.device,
            cursor: self.state.cursor,
            chain: record,
            chain_at: at
                .into_iter()
                .map(|(seq, hash)| (seq, pubky_switch_core::enc::b64(&hash)))
                .collect(),
            chain_batches: batches
                .into_iter()
                .map(|(id, t)| (pubky_switch_core::enc::b64(&id), t))
                .collect(),
            departed: self
                .state
                .departed
                .iter()
                .map(|(app, at)| (zbase32_encode(app), *at))
                .collect(),
            bundle: self.state.bundle.clone(),
        })
    }

    /// Restore from a backup (Switch spec 12.4) into the store, replacing whatever the store
    /// holds for the app. The host asked the user first whether the device the backup came
    /// from is still in the user's hands; for a lost or stolen one it revokes the app and
    /// joins a new one instead.
    ///
    /// The app enters reconcile mode. At its next call it takes the certificate its
    /// `identity.json` lists if the backup predates a renewal, checks its receive key
    /// record, registers a fresh key if it rotated after the backup, and asks the user
    /// about registrations it can't account for ([`App::restore_question`]).
    ///
    /// # Errors
    ///
    /// [`AppError::InvalidData`] for a backup that doesn't verify; a store failure.
    pub async fn restore(
        env: AppEnv,
        protocol: Arc<dyn Protocol>,
        config: AppConfig,
        backup: &AppBackup,
    ) -> Result<App, AppError> {
        Box::pin(async move {
            let meta = backup.meta.clone();
            let invalid = |why: &str| AppError::InvalidData(format!("the backup: {why}"));
            let cert = AppCert::verify(&backup.cert, &meta.identity)
                .map_err(|_| invalid("its certificate doesn't verify"))?;
            if cert.app_id() != meta.app_id || cert.signing_key() != backup.keys.signing_public() {
                return Err(invalid("its certificate isn't its keys'"));
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
                bundle: backup.bundle.clone(),
                own_doc: own_doc.clone(),
                receive_keys,
                known_kids,
                registrations: BTreeMap::new(),
                rotation: backup.rotation,
                device: backup.device,
                cursor,
                chain: Some(chain),
                held: BTreeMap::new(),
                seen: BTreeSet::new(),
                asked: BTreeSet::new(),
                parked: BTreeMap::new(),
                departed,
                join: JoinStep::Done,
                pending_effect: None,
                pending_record: None,
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
                erasing: None,
            };
            let ns = client_namespace(&meta.app_id);
            // The store's duty event IDs go on rising, so an ID the host acknowledged before
            // is never given to another event; a counter that can't be read starts over.
            let old = Reader {
                ns: ns.clone(),
                store: env.store.clone(),
            };
            let next_duty = Self::next_duty(&old).await.unwrap_or(FIRST_DUTY);
            let state = AppState { next_duty, ..state };
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
            };
            let mut tx = Tx::new(&app.ns);
            tx.delete_prefix("")?;
            app.write_all(&mut tx).await?;
            tx.put(records::LIST_DUE, &true)?;
            tx.put(key::DUTY_NEXT, &app.state.next_duty)?;
            tx.commit(&app.env.store).await?;
            Ok(app)
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
            if let Some(restore) = self.state.restore.as_mut() {
                restore.reconcile = false;
                tx.put(key::RESTORE, restore)?;
            }
            if let Some(chain) = self.state.chain.as_mut() {
                chain.gap = None;
                chain.write(&mut tx)?;
            }
            self.commit(tx).await
        })
        .await
    }

    /// Take the events collected since the last call. Duty events among them stay kept
    /// until [`App::ack_events`] acknowledges them (`events` module, "Duty events").
    pub fn take_events(&mut self) -> Vec<AppEvent> {
        std::mem::take(&mut self.events)
    }

    /// The duty events kept and not acknowledged yet, by ascending ID: what a host that
    /// lost its copy of the reports still has to act on.
    ///
    /// # Errors
    ///
    /// A failed store read.
    pub async fn unacknowledged_events(&self) -> Result<Vec<AppEvent>, AppError> {
        Ok(self
            .reader()
            .scan_numbered::<events::Duty>(key::DUTY_PREFIX)
            .await?
            .into_iter()
            .map(|(n, duty)| duty.event(EventId::new(n)))
            .collect())
    }

    /// Acknowledge every duty event up to and including `up_to`: the host and its protocol
    /// kept what they say, and the store no longer keeps them, so no later
    /// [`App::load`] delivers them again. IDs rise in the order the events are reported,
    /// so a host acknowledges after acting on every duty event it took up to that ID. An
    /// ID no event has yet acknowledges only those before it.
    ///
    /// # Errors
    ///
    /// A failed store read or commit; nothing is acknowledged then.
    pub async fn ack_events(&mut self, up_to: EventId) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let kept = self.reader().scan_numbers(key::DUTY_PREFIX).await?;
            let mut tx = self.tx()?;
            for n in kept.range(..=up_to.get()) {
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
        tx.report(duty.event(EventId::new(n)));
        Ok(())
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
    /// Deleting the app's Homeserver record, where it publishes one, is the host's, before
    /// this call.
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
                two_step,
                compromise,
                ..LeaveState::default()
            };
            tx.put(key::LEAVE, &leave)?;
            self.state.leave = Some(leave);
            self.commit(tx).await?;
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
                self.events.extend(duties);
                Ok(())
            }
            Err(error) => {
                self.reload = true;
                Err(error)
            }
        }
    }

    /// Reload after a failed commit, and refuse calls the app's state forbids.
    async fn ready_local(&mut self) -> Result<(), AppError> {
        if self.reload {
            self.state = Self::read_state(&self.reader()).await?;
            self.client = Self::client_for(
                &self.env,
                &self.state.meta,
                &self.state.keys,
                &self.state.cert,
            )?;
            self.reload = false;
            self.service_time_dirty = false;
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
