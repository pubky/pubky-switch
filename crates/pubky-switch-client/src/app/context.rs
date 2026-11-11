//! What a protocol's receive step can do: [`ReceiveContext`] (Switch spec 8.2, 10.2, 10.3);
//! and what its other callbacks can read: [`LocalView`].
//!
//! An app that processes a message with a lasting effect writes the effect to its shared
//! record and advances its cursor in one batch (Switch spec 8.2). The context gives the
//! protocol, while it handles one message, what it needs to build that batch: the record
//! keys from the naming key, the writes the app holds and their versions, the claim views it
//! keeps, and the protocol's own local state. The writes the protocol adds go into the
//! effect's batch with the cursor move:
//!
//! - a `record.put` is sealed by the app under the policy's read scope at the current data
//!   epoch, with `expected_version` the version the app holds (Switch spec 10.3, 13.4);
//! - a claim entry goes as the protocol built it, with the deadline the app keeps for it
//!   (Switch wire 6.8);
//! - local writes commit with the outcome, as [`super::Effect::local`] does.
//!
//! The batch is signed and kept before it is sent, and its outcome committed with the
//! processed pair and the cursor, as every effect is (`STATE.md`). On `409 conflict` the
//! app reads the records and claims the context wrote again before it hands the message
//! over once more, so the next effect builds on what the switch holds.
//!
//! The protocol's callbacks are synchronous, so the context reads the host's store
//! synchronously, on the calling thread. What only the switch holds, such as a claim the app
//! keeps no view of, the step asks for with [`super::Outcome::Need`]: the app reads it,
//! keeps what it checked, and calls the step again with the answer in the context
//! ([`ReceiveContext::switch_claim`]), at most [`super::MAX_CLAIM_READS`] claims per entry.
//!
//! The step can also ask what the app knows of a sender's standing in the own identity's
//! lists ([`ReceiveContext::sender_disposition`]): whether the user blocked it or the
//! service flagged it, and how fresh that is.
//!
//! The protocol's other callbacks get a [`LocalView`]: the identity, the App ID and the
//! protocol's local state, read-only. Its restore step gets a [`RestoreContext`]: the
//! identity, the App ID and `blind` under the naming key of the backup being restored,
//! before anything is written.

use pubky_switch_core::claims::{ClaimView, EntryKind};
use pubky_switch_core::ident::NamingKey;
use pubky_switch_core::ops::{Condition, MAX_BATCH_ENTRIES, OpKind, RecordVersion};
use pubky_switch_core::records::AppCert;

use super::admission::{LISTS_AT, SenderDisposition, deny_key, flag_key};
use super::claims::{ClaimOp, ClaimRead, KeptClaim, ObligationDeadline, claim_key_of};
use super::error::Refusal;
use super::protocol::{LocalWrite, MAX_STEP_LOCAL_BYTES, local_writes_bytes};
use super::records::{
    Collection, HeldRecord, RecordTarget, SeenMark, SharedRecord, record_key_of, record_put,
    seen_key,
};
use super::state::{PROTOCOL_PREFIX, decode};
use super::{AppError, AppState};
use crate::store::{KeyValue, StateStore, Write};

/// The most entries one store scan returns; scans page through larger sets.
const SCAN_PAGE: u32 = 256;

/// The writes a receive step adds, taken by the app once the protocol returns.
#[derive(Debug, Default)]
pub(crate) struct ContextWrites {
    /// The operations, in the order added.
    pub(crate) ops: Vec<(Vec<Condition>, OpKind)>,
    /// The protocol's local writes.
    pub(crate) local: Vec<LocalWrite>,
    /// The records written, with their collections, to read again after a conflict.
    pub(crate) records: Vec<([u8; 32], Collection)>,
    /// The claims written, to read again after a conflict.
    pub(crate) claims: Vec<[u8; 32]>,
    /// The deadlines the app computes itself for the claims written (Switch wire 6.8).
    pub(crate) deadlines: Vec<([u8; 32], ObligationDeadline)>,
    /// A write couldn't be built now, such as for want of a scope key: the entry waits.
    pub(crate) not_now: Option<String>,
    /// A local write was refused for taking the step past [`MAX_STEP_LOCAL_BYTES`]: the
    /// effect is too large, whatever the step returns with it.
    pub(crate) over_local_bound: bool,
}

/// A claim the app read from the switch for a receive step ([`super::Need::Claim`]).
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum ClaimFetch {
    /// The switch's answer, checked as [`super::App::read_claim`] checks it (Switch wire
    /// 7.4.8); the app keeps its view.
    Read(ClaimRead),
    /// The switch holds nothing for the key (`404`).
    Absent,
    /// The switch refused the read for good, such as `403 permission_missing` for an app
    /// without `claims.read` (Switch spec 10.2): the error code.
    Refused(String),
}

/// What a protocol's receive step can read and add to the effect's batch
/// ([`super::Protocol::receive_with`]). Reads come from the app's store, and from the
/// switch through [`super::Outcome::Need`]; writes go into the batch that carries the cursor
/// move, at most 7 operations beside it (Switch wire 6.4).
pub struct ReceiveContext<'a> {
    state: &'a AppState,
    protocol: &'a dyn super::Protocol,
    store: &'a dyn StateStore,
    ns: &'a str,
    may_attempt: bool,
    fetched: &'a [([u8; 32], ClaimFetch)],
    /// The local writes of the entries processed before this one in the same read, not yet
    /// committed.
    pending: &'a [LocalWrite],
    /// Every write of the same read not yet committed, such as a deny list change the feed
    /// showed before this entry.
    pending_app: &'a [Write],
    writes: ContextWrites,
}

impl std::fmt::Debug for ReceiveContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReceiveContext({} operations)", self.writes.ops.len())
    }
}

fn store_error(error: crate::error::StoreError) -> AppError {
    AppError::Store(error)
}

fn local_get(store: &dyn StateStore, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, AppError> {
    store
        .get(ns, &[PROTOCOL_PREFIX, key].concat())
        .map_err(store_error)
}

/// A key's value after `pending`, local writes not yet committed: `Some(value)` when one of
/// them sets or removes it, `None` when none touches it.
fn pending_get(pending: &[LocalWrite], key: &[u8]) -> Option<Option<Vec<u8>>> {
    pending.iter().rev().find_map(|write| match write {
        LocalWrite::Put { key: k, value } if k.as_slice() == key => Some(Some(value.clone())),
        LocalWrite::Delete { key: k } if k.as_slice() == key => Some(None),
        LocalWrite::DeletePrefix { prefix } if key.starts_with(prefix) => Some(None),
        _ => None,
    })
}

/// An app key's value after `pending`, the read's writes not yet committed: as
/// [`pending_get`], for the app's own keys in `ns`.
fn pending_app_get(pending: &[Write], ns: &str, key: &[u8]) -> Option<Option<Vec<u8>>> {
    pending.iter().rev().find_map(|write| match write {
        Write::Put {
            ns: n,
            key: k,
            value,
        } if n == ns && k.as_slice() == key => Some(Some(value.clone())),
        Write::Delete { ns: n, key: k } if n == ns && k.as_slice() == key => Some(None),
        Write::DeletePrefix { ns: n, prefix } if n == ns && key.starts_with(prefix) => Some(None),
        _ => None,
    })
}

/// The values under `prefix` that `committed` holds, with `pending` applied in order.
fn pending_scan(committed: Vec<KeyValue>, pending: &[LocalWrite], prefix: &[u8]) -> Vec<KeyValue> {
    if pending.is_empty() {
        return committed;
    }
    let mut values: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = committed.into_iter().collect();
    for write in pending {
        match write {
            LocalWrite::Put { key, value } if key.starts_with(prefix) => {
                values.insert(key.clone(), value.clone());
            }
            LocalWrite::Put { .. } => {}
            LocalWrite::Delete { key } => {
                values.remove(key);
            }
            LocalWrite::DeletePrefix { prefix } => values.retain(|k, _| !k.starts_with(prefix)),
        }
    }
    values.into_iter().collect()
}

fn local_scan(store: &dyn StateStore, ns: &str, prefix: &[u8]) -> Result<Vec<KeyValue>, AppError> {
    let full = [PROTOCOL_PREFIX, prefix].concat();
    let mut out = Vec::new();
    let mut after: Option<Vec<u8>> = None;
    loop {
        let page = store
            .scan(ns, &full, after.as_deref(), SCAN_PAGE)
            .map_err(store_error)?;
        let more = page.len() >= usize::try_from(SCAN_PAGE).unwrap_or(usize::MAX);
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

/// What the protocol's callbacks other than the receive step can read: the app's identity
/// and App ID, and the protocol's own local state as committed ([`super::Protocol`],
/// "Callbacks and the store"). It reads the host's store synchronously, on the calling
/// thread, and writes nothing.
pub struct LocalView<'a> {
    identity: [u8; 32],
    app_id: [u8; 16],
    store: &'a dyn StateStore,
    ns: &'a str,
}

impl std::fmt::Debug for LocalView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalView")
    }
}

impl<'a> LocalView<'a> {
    pub(crate) fn new(
        identity: [u8; 32],
        app_id: [u8; 16],
        store: &'a dyn StateStore,
        ns: &'a str,
    ) -> Self {
        Self {
            identity,
            app_id,
            store,
            ns,
        }
    }

    /// The identity.
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }

    /// The App ID.
    pub fn app_id(&self) -> [u8; 16] {
        self.app_id
    }

    /// A value of the protocol's own local state, as committed.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn local_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, AppError> {
        local_get(self.store, self.ns, key)
    }

    /// Every value of the protocol's local state whose key starts with `prefix`, with its
    /// key in the protocol's key space, in key order, as committed.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn local_scan(&self, prefix: &[u8]) -> Result<Vec<KeyValue>, AppError> {
        local_scan(self.store, self.ns, prefix)
    }
}

/// What a protocol's restore step can read ([`super::Protocol::restore_layer`]): the
/// identity, the App ID, the certificate and the naming key of the backup being restored,
/// which the restored app goes on with, before anything is written.
///
/// With the certificate the protocol checks what the restored app may do by its own rules,
/// such as scopes or permissions it requires beyond the switch's, and refuses a backup it
/// wouldn't run with, before the restore commits ([`RestoreContext::cert`]).
///
/// With the naming key the protocol checks its layer against the identity before the
/// restore commits, such as that each claim key or record key it keeps is the one its
/// inputs derive to under the naming key (Switch wire 1.5, Switch spec 13.3). A layer it
/// refuses refuses the restore, and nothing of either layer is written. The naming key
/// itself stays with the app: the protocol derives through [`RestoreContext::blind`].
///
/// The naming key is the one the backup carries. The app can't verify it before the
/// restore, since it derives from the identity's Switch root, which the app doesn't hold;
/// it is the key the restored app goes on with, so a check here gives what a check after
/// the restore would. It doesn't protect against a forged backup that carries a consistent
/// wrong key.
#[derive(Debug)]
#[non_exhaustive]
pub struct RestoreContext<'a> {
    identity: [u8; 32],
    app_id: [u8; 16],
    naming: &'a NamingKey,
    cert: &'a AppCert,
}

impl<'a> RestoreContext<'a> {
    pub(crate) fn new(
        identity: [u8; 32],
        app_id: [u8; 16],
        naming: &'a NamingKey,
        cert: &'a AppCert,
    ) -> Self {
        Self {
            identity,
            app_id,
            naming,
            cert,
        }
    }

    /// The certificate the restore installs: the backup's own, which the app has checked
    /// is signed by the identity and names this App ID and the backup's signing key. It
    /// isn't checked against the identity's current `identity.json` here, nor for expiry:
    /// after the restore, before it sends anything, the app takes the certificate its
    /// `identity.json` lists if the backup's was renewed since (Switch spec 12.4).
    pub fn cert(&self) -> &'a AppCert {
        self.cert
    }

    /// The identity.
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }

    /// The App ID.
    pub fn app_id(&self) -> [u8; 16] {
        self.app_id
    }

    /// `blind(input)` under the backup's naming key (Switch wire 1.5), as
    /// [`super::App::blind`] and [`ReceiveContext::blind`] give it once restored: what a
    /// protocol derives its shared keys from, such as its claim keys (Switch spec 10.2,
    /// 13.3).
    pub fn blind(&self, input: &[u8]) -> [u8; 32] {
        self.naming.blind(input)
    }
}

impl<'a> ReceiveContext<'a> {
    // Each argument is a borrow or a flag the context reads on its own; a struct of them
    // would only be built here.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        state: &'a AppState,
        protocol: &'a dyn super::Protocol,
        store: &'a dyn StateStore,
        ns: &'a str,
        may_attempt: bool,
        fetched: &'a [([u8; 32], ClaimFetch)],
        pending: &'a [LocalWrite],
        pending_app: &'a [Write],
    ) -> Self {
        Self {
            state,
            protocol,
            store,
            ns,
            may_attempt,
            fetched,
            pending,
            pending_app,
            writes: ContextWrites::default(),
        }
    }

    pub(crate) fn into_writes(self) -> ContextWrites {
        self.writes
    }

    // ---------------------------------------------------------------------------------
    // The app

    /// The identity.
    pub fn identity(&self) -> [u8; 32] {
        self.state.meta.identity
    }

    /// The App ID.
    pub fn app_id(&self) -> [u8; 16] {
        self.state.meta.app_id
    }

    /// The certificate the app presents.
    pub fn cert(&self) -> &AppCert {
        &self.state.cert
    }

    /// The data epoch of the newest own `identity.json`, the one writes are sealed at.
    pub fn data_epoch(&self) -> u64 {
        self.state.own_doc.data_epoch()
    }

    /// The highest service time the app verified, Unix milliseconds (Switch spec 10.1);
    /// `None` before any verified answer.
    pub fn highest_service_time(&self) -> Option<u64> {
        self.state.service_time.map(|time| time.highest_ms)
    }

    /// `blind(input)` under the identity's naming key (Switch wire 1.5), as
    /// [`super::App::blind`]: what a protocol derives its shared keys from, such as the claim
    /// key of an obligation a message names (Switch spec 10.2, 13.3). The naming key itself
    /// stays with the app.
    pub fn blind(&self, input: &[u8]) -> [u8; 32] {
        self.state.naming.blind(input)
    }

    // ---------------------------------------------------------------------------------
    // Reads

    fn get<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>, AppError> {
        match self
            .store
            .get(self.ns, key.as_bytes())
            .map_err(store_error)?
        {
            None => Ok(None),
            Some(bytes) => decode(&bytes).map(Some),
        }
    }

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

    fn held(&self, key: &[u8; 32]) -> Result<Option<HeldRecord>, AppError> {
        self.get(&record_key_of(key))
    }

    /// The record the app holds at `target`: the newest write it accepted, its version and
    /// content.
    ///
    /// # Errors
    ///
    /// A store failure, or a policy that doesn't hash.
    pub fn record(&self, target: &RecordTarget) -> Result<Option<SharedRecord>, AppError> {
        let key = self.record_key(target)?;
        self.record_at(&key)
    }

    /// The record the app holds at `key`.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn record_at(&self, key: &[u8; 32]) -> Result<Option<SharedRecord>, AppError> {
        Ok(self.held(key)?.map(|held| held.shared(key)))
    }

    /// The protocol's mark of what the app has seen in record `key`, its high water.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn record_seen(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>, AppError> {
        Ok(self.get::<SeenMark>(&seen_key(key))?.map(|mark| mark.mark))
    }

    /// A `record_version` condition on the version of record `key` the app holds, or the
    /// version the switch showed for a write the app refused (Switch wire 6.3); `{0, 0}` for
    /// a record it holds nothing of.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn record_condition(&self, key: &[u8; 32]) -> Result<Condition, AppError> {
        let version = self
            .held(key)?
            .map_or(RecordVersion::NONE, |held| held.base_version());
        Ok(Condition::RecordVersion { key: *key, version })
    }

    /// The newest view the app keeps of the claim `claim_key` (Switch wire 6.8).
    ///
    /// # Errors
    ///
    /// A store failure, or a kept view that doesn't read.
    pub fn claim_view(&self, claim_key: &[u8; 32]) -> Result<Option<ClaimView>, AppError> {
        self.get::<KeptClaim>(&claim_key_of(claim_key))?
            .map(|kept| kept.view())
            .transpose()
    }

    /// A `claim_step` condition on the step of the claim view the app keeps, 0 when it keeps
    /// none (Switch wire 6.3).
    ///
    /// # Errors
    ///
    /// As [`ReceiveContext::claim_view`].
    pub fn claim_condition(&self, claim_key: &[u8; 32]) -> Result<Condition, AppError> {
        let step = self.claim_view(claim_key)?.map_or(0, |view| view.step);
        Ok(Condition::ClaimStep {
            claim_key: *claim_key,
            step,
        })
    }

    /// What the app read from the switch for this step at its request
    /// ([`super::Need::Claim`]): `None` for a claim the step hasn't asked for (Switch wire
    /// 7.4.8).
    pub fn switch_claim(&self, claim_key: &[u8; 32]) -> Option<&ClaimFetch> {
        self.fetched
            .iter()
            .find(|(key, _)| key == claim_key)
            .map(|(_, fetch)| fetch)
    }

    /// What the app knows of `pubky`'s standing in the own identity's lists before this
    /// message: on the app's copy of the deny list, among the flagged senders of its last
    /// [`super::App::allow_list`], and when that was ([`SenderDisposition`]). It reads the
    /// copy as committed, with the changes the feed showed earlier in the same read, which
    /// aren't committed yet.
    ///
    /// A protocol that keeps only a count of messages from a blocked or flagged sender
    /// (Switch spec 7 "Spam") asks for the message's sender. Both values are only as fresh
    /// as the app's copy of the lists: an app with `lists.read` refreshes it with
    /// [`super::App::allow_list`] when [`SenderDisposition::lists_as_of_ms`] is `None` or
    /// older than it accepts.
    ///
    /// # Errors
    ///
    /// A store failure, or a kept time that doesn't read.
    pub fn sender_disposition(&self, pubky: &[u8; 32]) -> Result<SenderDisposition, AppError> {
        let lists_as_of_ms = match self.app_get(LISTS_AT)? {
            None => None,
            Some(bytes) => Some(decode::<u64>(&bytes)?),
        };
        Ok(SenderDisposition {
            blocked: self.app_get(&deny_key(pubky))?.is_some(),
            flagged: self.app_get(&flag_key(pubky))?.is_some(),
            lists_as_of_ms,
        })
    }

    /// An app key's stored value, with the read's writes not yet committed.
    fn app_get(&self, key: &str) -> Result<Option<Vec<u8>>, AppError> {
        match pending_app_get(self.pending_app, self.ns, key.as_bytes()) {
            Some(value) => Ok(value),
            None => self.store.get(self.ns, key.as_bytes()).map_err(store_error),
        }
    }

    /// A value of the protocol's own local state before this message: as committed, with
    /// the local writes of the messages processed before it in the same read of the feed,
    /// which aren't committed yet. A step that ended in [`super::Outcome::Drop`],
    /// [`super::Outcome::Need`] or [`super::Outcome::Retry`] wrote nothing, so this shows
    /// none of its writes, nor of this step's own [`ReceiveContext::local`].
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn local_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, AppError> {
        match pending_get(self.pending, key) {
            Some(value) => Ok(value),
            None => local_get(self.store, self.ns, key),
        }
    }

    /// Every value of the protocol's local state whose key starts with `prefix`, with its
    /// key in the protocol's key space, in key order, before this message, as
    /// [`ReceiveContext::local_get`] reads it.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn local_scan(&self, prefix: &[u8]) -> Result<Vec<KeyValue>, AppError> {
        let committed = local_scan(self.store, self.ns, prefix)?;
        Ok(pending_scan(committed, self.pending, prefix))
    }

    // ---------------------------------------------------------------------------------
    // Writes

    /// How many operations the effect's batch holds so far.
    pub fn len(&self) -> usize {
        self.writes.ops.len()
    }

    /// Whether the effect's batch holds no operation yet.
    pub fn is_empty(&self) -> bool {
        self.writes.ops.is_empty()
    }

    fn room(&self) -> Result<(), AppError> {
        if self.writes.ops.len() >= MAX_BATCH_ENTRIES.saturating_sub(1) {
            return Err(Refusal::Usage(
                "Switch wire 6.4: an effect holds at most 7 operations beside the cursor".into(),
            )
            .into());
        }
        Ok(())
    }

    /// Write `value` at `target` in the effect's batch, with `conditions`: compare-and-swap
    /// on the version the app holds, or a create, sealed under the read scope's key at the
    /// current data epoch (Switch spec 10.3). Returns the record key.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] when the certificate holds none of the write scopes, the record is
    /// written already in this batch (Switch wire 6.2), the batch is full, or the
    /// protocol's mark of the value is over [`super::MAX_SEEN_MARK_BYTES`];
    /// [`Refusal::NotNow`] while the app lacks the read scope's key at the current data
    /// epoch: the message then waits, whatever the protocol returns, and is handed over
    /// again at a later read; a store failure.
    ///
    /// A write refused with [`Refusal::Usage`], its mark over the bound included, isn't
    /// added: a protocol that carries on returns an effect that applies without it. That is
    /// unlike [`ReceiveContext::local`] past [`MAX_STEP_LOCAL_BYTES`], whose effect is
    /// stored locally instead of applied.
    pub fn put_record(
        &mut self,
        target: &RecordTarget,
        value: &[u8],
        conditions: Vec<Condition>,
    ) -> Result<[u8; 32], AppError> {
        self.write_record(target, Some(value), conditions)
    }

    /// Delete the record at `target` in the effect's batch: a write whose sealed value is
    /// empty (Switch spec 10.3). Returns the record key.
    ///
    /// # Errors
    ///
    /// As [`ReceiveContext::put_record`].
    pub fn delete_record(
        &mut self,
        target: &RecordTarget,
        conditions: Vec<Condition>,
    ) -> Result<[u8; 32], AppError> {
        self.write_record(target, None, conditions)
    }

    /// A refused write adds nothing, and the effect goes on without it
    /// ([`ReceiveContext::put_record`]).
    fn write_record(
        &mut self,
        target: &RecordTarget,
        value: Option<&[u8]>,
        conditions: Vec<Condition>,
    ) -> Result<[u8; 32], AppError> {
        self.room()?;
        // A value that isn't JSON is refused before the protocol marks it, as `record_op`
        // does: nothing is handed on first.
        super::records::refuse_non_json(value)?;
        super::records::refuse_unmarkable(self.protocol, target, value)?;
        let key = self.record_key(target)?;
        if self.writes.records.iter().any(|(k, _)| *k == key) {
            return Err(
                Refusal::Usage("Switch wire 6.2: one write per record per batch".into()).into(),
            );
        }
        let held = self.held(&key)?;
        let put = match record_put(self.state, target, value, held.as_ref()) {
            Ok(put) => put,
            Err(AppError::Refused(Refusal::NotNow(why))) => {
                self.writes.not_now = Some(why.clone());
                return Err(Refusal::NotNow(why).into());
            }
            Err(error) => return Err(error),
        };
        self.writes.ops.push((conditions, OpKind::RecordPut(put)));
        self.writes.records.push((key, target.collection.clone()));
        Ok(key)
    }

    /// Add a claim entry to the effect's batch, with `conditions`, and the deadline the app
    /// computes itself for the obligation (Switch wire 6.8). An `attempt` passes the checks
    /// of [`super::App::may_attempt`] first, and its proof is checked once the batch is
    /// applied (Switch wire 6.5 "Binding").
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] when the batch is full; [`Refusal::NotNow`] for an `attempt`
    /// while the app may not attempt.
    pub fn claim(
        &mut self,
        op: ClaimOp,
        conditions: Vec<Condition>,
        deadline: ObligationDeadline,
    ) -> Result<(), AppError> {
        self.room()?;
        if matches!(op.entry().kind, EntryKind::Attempt { .. }) && !self.may_attempt {
            return Err(
                Refusal::NotNow("Switch spec 12.4: the app makes no attempt now".into()).into(),
            );
        }
        let claim_key = op.entry().claim_key;
        self.writes.ops.push((conditions, op.kind()));
        if !self.writes.claims.contains(&claim_key) {
            self.writes.claims.push(claim_key);
        }
        self.writes.deadlines.retain(|(k, _)| *k != claim_key);
        self.writes.deadlines.push((claim_key, deadline));
        Ok(())
    }

    /// Add another operation to the effect's batch, as the protocol built it.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] when the batch is full, for a `record.put` or a claim entry,
    /// which go through [`ReceiveContext::put_record`] and [`ReceiveContext::claim`], or for
    /// `app.put`, `receive_key.put`, `key_bundle.put` or `cert.put`, which the app layer
    /// builds itself.
    pub fn op(&mut self, conditions: Vec<Condition>, kind: OpKind) -> Result<(), AppError> {
        self.room()?;
        super::batch::refuse_lifecycle_ops(std::iter::once(&kind))?;
        if matches!(kind, OpKind::RecordPut(_) | OpKind::Claim(_)) {
            return Err(Refusal::Usage(
                "a record write or claim entry goes through put_record or claim".into(),
            )
            .into());
        }
        self.writes.ops.push((conditions, kind));
        Ok(())
    }

    /// A write of the protocol's own local state, committed with the outcome.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] when the write would take this step's local writes past
    /// [`MAX_STEP_LOCAL_BYTES`] ([`local_writes_bytes`]): the write isn't added, and an
    /// effect the step then applies is stored and passed as too large
    /// ([`super::ParkReason::EffectTooLarge`]), never applied without it.
    pub fn local(&mut self, write: LocalWrite) -> Result<(), AppError> {
        let after = local_writes_bytes(&self.writes.local)
            .saturating_add(local_writes_bytes(std::slice::from_ref(&write)));
        if after > MAX_STEP_LOCAL_BYTES {
            self.writes.over_local_bound = true;
            return Err(Refusal::Usage(format!(
                "a receive step writes at most {MAX_STEP_LOCAL_BYTES} bytes of local state"
            ))
            .into());
        }
        self.writes.local.push(write);
        Ok(())
    }
}
