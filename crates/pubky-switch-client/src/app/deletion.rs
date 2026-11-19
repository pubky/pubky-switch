//! A collection owner's observation of a signed record deletion (Switch spec 8.2).

use std::collections::{BTreeMap, btree_map::Entry};

use pubky_switch_core::enc::{b64, serde_b64};
use pubky_switch_core::ops::{Condition, OpKind, RecordVersion, SignedOp};
use pubky_switch_core::records::{AppCert, IdentityDoc};
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};

use super::order::{Handover, Kept};
use super::put_back::RecordHold;
use super::records::{self, DeleteBase};
use super::state::{Reader, Tx};
use super::{App, AppError, FeedPosition, ProtocolSet, PutBack};

pub(super) const PREFIX: &str = "delobs/";
pub(super) const RECEIPTS: &str = "delack/";
/// Space for the signed delete, sealed predecessor, their certificates and proof,
/// the outstanding signed batch, its successor merge, the owner's local writes and mark.
pub(super) const ROOM: u64 = 8 << 20;
const _: () = assert!(
    2 * pubky_switch_core::ops::MAX_OP_BYTES as u64
        + (128 << 10)
        + ((2 * pubky_switch_core::ops::MAX_OP_BYTES
            + super::MAX_STEP_LOCAL_BYTES
            + super::MAX_SEEN_MARK_BYTES) as u64
            * 4
            / 3)
        < ROOM
        && ROOM < crate::store::MAX_VALUE_BYTES
);

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Predecessor {
    pub(super) source: records::KeptOp,
    pub(super) exact: bool,
    pub(super) dated_at_expected: bool,
}

/// The immutable evidence still owed to the collection's owner.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Observation {
    #[serde(with = "serde_b64")]
    pub(super) key: [u8; 32],
    pub(super) owner: String,
    pub(super) collection: String,
    pub(super) delete: DeleteBase,
    pub(super) operation: SignedDoc,
    pub(super) proof: Option<SignedDoc>,
    pub(super) authenticated: bool,
    pub(super) cert: SignedDoc,
    pub(super) generation: u64,
    pub(super) seq: u64,
    pub(super) page_time_ms: Option<u64>,
    pub(super) held: bool,
    pub(super) seen: Option<records::SeenMark>,
    pub(super) predecessor: Option<Predecessor>,
    pub(super) written_at_ms: Option<u64>,
}

impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Observation")
            .field("owner", &self.owner)
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

impl Observation {
    pub(super) fn revision(&self) -> pubky_switch_core::shared::ApplicationRef {
        pubky_switch_core::shared::ApplicationRef {
            generation: self.generation,
            seq: self.seq,
            item_hash: self.delete.item_hash,
        }
    }

    pub(super) fn put(&self) -> Result<pubky_switch_core::ops::RecordPut, AppError> {
        let op = SignedOp::peek(&self.operation).map_err(|_| super::corrupt())?;
        match &op.body().kind {
            OpKind::RecordPut(put) => Ok(put.clone()),
            _ => Err(super::corrupt()),
        }
    }

    pub(super) fn id(&self) -> ([u8; 32], RecordVersion, [u8; 32]) {
        (self.key, self.delete.version, self.delete.item_hash)
    }

    pub(super) fn store_key(&self) -> String {
        self.key_in(PREFIX)
    }

    pub(super) fn key_in(&self, prefix: &str) -> String {
        format!(
            "{prefix}{}/{}/{}/{}",
            b64(&self.key),
            self.delete.version.generation,
            self.delete.version.version,
            b64(&self.delete.item_hash)
        )
    }

    fn prior_write(
        &self,
        identity: &[u8; 32],
        deletion: &SignedOp,
    ) -> Result<Option<SignedOp>, AppError> {
        let Some(prior) = &self.predecessor else {
            return Ok(None);
        };
        let cert = AppCert::verify(&prior.source.cert, identity).map_err(|_| super::corrupt())?;
        let op = SignedOp::verify(
            &prior.source.op,
            &cert.signing_key(),
            identity,
            Some(&cert.app_id()),
        )
        .map_err(|_| super::corrupt())?;
        if !matches!((&op.body().kind, &deletion.body().kind), (OpKind::RecordPut(put), OpKind::RecordPut(d))
            if put.key == self.key && put.collection == d.collection && put.policy == d.policy
            && put.check_address(identity).is_ok() && put.policy.read_scope == put.value_sealed.scope
            && !put.value_sealed.looks_like_delete()
            && put.policy.write_scopes_for(put.expected_version).iter().any(|scope| cert.holds_scope(scope)))
        {
            return Err(super::corrupt());
        }
        Ok(Some(op))
    }

    /// An imported mark or a claimed version cannot authenticate the predecessor. A
    /// delete can name its application directly. Otherwise its service proof must
    /// establish the signed predecessor at the delete's expected version.
    pub(super) fn restore_predecessor(&mut self, doc: &IdentityDoc) -> Result<(), AppError> {
        let deletion = SignedOp::peek(&self.operation).map_err(|_| super::corrupt())?;
        self.authenticated &= self
            .proof
            .as_ref()
            .and_then(|proof| pubky_switch_core::shared::date_write(proof, &deletion, doc).ok())
            .and_then(|dated| dated.version)
            == Some(self.delete.version);
        let Some(op) = self.prior_write(&doc.identity(), &deletion)? else {
            return Ok(());
        };
        let OpKind::RecordPut(d) = &deletion.body().kind else {
            return Err(super::corrupt());
        };
        let hash = op.item_hash()?;
        let named: Vec<_> = deletion
            .body()
            .conditions
            .iter()
            .filter_map(|c| match c {
                Condition::RecordCurrent {
                    key,
                    revision,
                    deleted,
                } if *key == self.key => Some((revision, deleted)),
                _ => None,
            })
            .collect();
        let prior = self.predecessor.as_mut().ok_or_else(super::corrupt)?;
        let version = prior
            .source
            .proof
            .as_ref()
            .and_then(|proof| pubky_switch_core::shared::date_write(proof, &op, doc).ok())
            .and_then(|d| d.version);
        prior.dated_at_expected = version == Some(d.expected_version);
        let named_match = !named.is_empty()
            && named
                .iter()
                .all(|(revision, deleted)| !**deleted && revision.item_hash == hash);
        if !named_match && version.is_none_or(|v| v > d.expected_version) {
            self.predecessor = None;
        } else {
            prior.exact &= named_match
                || (named.is_empty()
                    && version == Some(d.expected_version)
                    && doc
                        .body()
                        .recovery_from
                        .is_none_or(|lost| d.expected_version.generation > lost));
        }
        Ok(())
    }

    pub(super) fn check(
        &self,
        protocols: &ProtocolSet,
        identity: &[u8; 32],
    ) -> Result<(), AppError> {
        let owner = protocols
            .of_collection(&self.collection)
            .ok_or_else(super::corrupt)?;
        if owner.name != self.owner
            || self.delete.version.is_none()
            || self.seq == 0
            || self
                .seen
                .as_ref()
                .is_some_and(|m| m.mark.len() > super::MAX_SEEN_MARK_BYTES)
        {
            return Err(super::corrupt());
        }
        let cert = AppCert::verify(&self.cert, identity).map_err(|_| super::corrupt())?;
        let signed = SignedOp::verify(
            &self.operation,
            &cert.signing_key(),
            identity,
            Some(&cert.app_id()),
        )
        .map_err(|_| super::corrupt())?;
        let OpKind::RecordPut(deletion) = &signed.body().kind else {
            return Err(super::corrupt());
        };
        if signed.item_hash()? != self.delete.item_hash
            || deletion.key != self.key
            || deletion.check_address(identity).is_err()
            || !deletion.value_sealed.looks_like_delete()
            || !owner.protocol.collections().iter().any(|c| {
                c.name == self.collection
                    && c.id(identity) == deletion.collection
                    && c.admits(&deletion.policy)
            })
            || !deletion
                .policy
                .write_scopes_for(deletion.expected_version)
                .iter()
                .any(|scope| cert.holds_scope(scope))
        {
            return Err(super::corrupt());
        }
        Ok(())
    }
}

pub(super) type Id = ([u8; 32], RecordVersion, [u8; 32]);
pub(super) type Observations = BTreeMap<Id, Observation>;
pub(super) type Receipts = BTreeMap<Id, Receipt>;

/// Identifies the owner's already committed writes while the delete can be read again.
/// The owner keeps the contents in its own state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Receipt {
    #[serde(with = "serde_b64")]
    key: [u8; 32],
    delete: DeleteBase,
    pub(super) owner: String,
    read_scope: String,
    generation: u64,
    seq: u64,
}

impl Receipt {
    fn id(&self) -> Id {
        (self.key, self.delete.version, self.delete.item_hash)
    }

    pub(super) fn store_key(&self) -> String {
        format!(
            "{RECEIPTS}{}/{}/{}/{}",
            b64(&self.key),
            self.delete.version.generation,
            self.delete.version.version,
            b64(&self.delete.item_hash)
        )
    }

    fn valid(&self) -> bool {
        self.seq != 0
            && !self.delete.version.is_none()
            && pubky_switch_core::scopes::is_scope(&self.read_scope)
    }
}

pub(super) async fn load_receipts(reader: &Reader) -> Result<Receipts, AppError> {
    let mut receipts = Receipts::new();
    for (suffix, receipt) in reader.scan::<Receipt>(RECEIPTS).await? {
        if !receipt.valid() || receipt.store_key().strip_prefix(RECEIPTS) != Some(&suffix) {
            return Err(super::corrupt());
        }
        receipts.insert(receipt.id(), receipt);
    }
    Ok(receipts)
}

pub(super) fn layer_receipts(
    layers: &[super::LayerOut],
    pending: &mut Observations,
) -> Result<Receipts, AppError> {
    let mut receipts = Receipts::new();
    for layer in layers {
        for receipt in &layer.deletions {
            if receipt.owner != layer.name
                || !receipt.valid()
                || receipts.insert(receipt.id(), receipt.clone()).is_some()
            {
                return Err(super::corrupt());
            }
            pending.remove(&receipt.id());
        }
    }
    Ok(receipts)
}

pub(super) async fn load(reader: &Reader) -> Result<Observations, AppError> {
    let mut retained = Observations::new();
    for (suffix, observation) in reader.scan::<Observation>(PREFIX).await? {
        if observation.store_key().strip_prefix(PREFIX) != Some(&suffix) {
            return Err(super::corrupt());
        }
        retained.insert(observation.id(), observation);
    }
    Ok(retained)
}

pub(super) async fn restore(
    reader: &Reader,
    backup: &[Observation],
    protocols: &ProtocolSet,
    same_installation: bool,
    doc: &IdentityDoc,
) -> Result<Observations, AppError> {
    let mut retained = Observations::new();
    for observed in backup {
        let mut observed = observed.clone();
        observed.check(protocols, &doc.identity())?;
        observed.restore_predecessor(doc)?;
        if retained.insert(observed.id(), observed).is_some() {
            return Err(super::corrupt());
        }
    }
    if same_installation {
        for (id, mut local) in load(reader).await? {
            local.check(protocols, &doc.identity())?;
            local.page_time_ms = local
                .page_time_ms
                .or_else(|| retained.get(&id).and_then(|b| b.page_time_ms));
            retained.insert(id, local);
        }
    }
    Ok(retained)
}

impl App {
    pub(super) fn consult_deletion(
        &self,
        hold: &Observation,
        deletion: &SignedOp,
        tx: &Tx,
    ) -> Result<Option<PutBack>, AppError> {
        self.with_deletion(hold, deletion, tx, |owner, input, cx| {
            owner.record_put_back(input, cx)
        })
    }

    pub(super) fn with_deletion<T>(
        &self,
        hold: &Observation,
        deletion: &SignedOp,
        tx: &Tx,
        consult: impl FnOnce(
            &dyn super::Protocol,
            &super::RecordDeletion<'_>,
            &super::ReceiveContext<'_>,
        ) -> Result<T, super::StoreFailure>,
    ) -> Result<T, AppError> {
        let owner = self
            .protocols
            .of_collection(&hold.collection)
            .ok_or_else(super::corrupt)?;
        let OpKind::RecordPut(put) = &deletion.body().kind else {
            return Err(super::corrupt());
        };
        let prior = hold.prior_write(&self.state.meta.identity, deletion)?;
        let opened = prior.as_ref().and_then(|op| {
            let OpKind::RecordPut(put) = &op.body().kind else {
                return None;
            };
            match put
                .value_sealed
                .open_with(&self.state.scope_keys, &self.state.meta.identity, &hold.key)
                .ok()?
            {
                pubky_switch_core::sealed::RecordValue::Json(value) => Some(value),
                _ => None,
            }
        });
        let input = super::RecordDeletion {
            collection: &hold.collection,
            key: &hold.key,
            version: hold.delete.version,
            original_in_current_generation: hold.authenticated
                && hold.generation == self.state.meta.generation
                && deletion.body().generation == hold.generation
                && hold.delete.version == RecordVersion::new(hold.generation, hold.seq),
            writer: deletion.body().app_id.ok_or_else(super::corrupt)?,
            item_hash: hold.delete.item_hash,
            seen: hold.seen.as_ref().map(|m| m.mark.as_slice()),
            page_time_ms: hold.page_time_ms,
            policy: opened.as_ref().map(|_| &put.policy),
            exact_version_authenticated: opened.is_some()
                && hold
                    .predecessor
                    .as_ref()
                    .is_some_and(|prior| prior.exact && prior.dated_at_expected),
            exact_value: opened
                .as_deref()
                .filter(|_| hold.predecessor.as_ref().is_some_and(|prior| prior.exact)),
            base: super::WriteBase {
                repair: None,
                expected_version: put.expected_version,
                held: hold.held,
                conditions: deletion.body().conditions.clone(),
                written_at_ms: hold.written_at_ms,
            },
        };
        let cx = super::ReceiveContext::new(
            &self.state,
            &self.protocols,
            &hold.owner,
            self.env.store.store().as_ref(),
            &self.ns,
            false,
            &[],
            tx.pending_local(),
            tx.pending_writes(),
        );
        consult(owner.protocol.as_ref(), &input, &cx).map_err(AppError::Protocol)
    }

    pub(super) fn owed_deletions(&self) -> impl Iterator<Item = &Observation> {
        let restored = self
            .state
            .put_backs
            .values()
            .filter(|h| h.observing)
            .map(|h| &h.observation);
        self.state.deletions.values().chain(restored)
    }

    pub(super) fn deletion_positions(&self) -> impl Iterator<Item = Kept> + '_ {
        self.owed_deletions().map(|d| Kept {
            generation: d.generation,
            seq: d.seq,
            names: vec![d.owner.clone()],
            call: false,
            held_gap: None,
            deny: false,
        })
    }

    /// Only a later authenticated write, a current view, or a hosted absence in our
    /// read scope settles that this delete is no longer current. A listing may omit it.
    pub(super) fn retire_deletion_receipts(
        &mut self,
        key: [u8; 32],
        successor: Option<([u8; 32], RecordVersion)>,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        self.retire_receipts_where(key, tx, |app, r| match successor {
            Some((hash, at)) => {
                hash != r.delete.item_hash
                    && app.feed_order(at.generation, at.version)
                        >= app.feed_order(r.generation, r.seq)
            }
            None => app.state.cert.holds_scope(&r.read_scope),
        })
    }

    /// Absence at a verified head covers only deletes already applied by that position.
    pub(super) fn retire_absent_receipts(
        &mut self,
        key: [u8; 32],
        at: FeedPosition,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        self.retire_receipts_where(key, tx, |app, r| {
            app.state.cert.holds_scope(&r.read_scope)
                && app
                    .received_order(
                        at,
                        FeedPosition {
                            generation: r.generation,
                            seq: r.seq,
                        },
                    )
                    .is_some_and(std::cmp::Ordering::is_ge)
        })
    }

    fn retire_receipts_where(
        &mut self,
        key: [u8; 32],
        tx: &mut Tx,
        obsolete: impl Fn(&Self, &Receipt) -> bool,
    ) -> Result<(), AppError> {
        let first = (key, RecordVersion::NONE, [0; 32]);
        let obsolete: Vec<_> = self
            .state
            .deletion_receipts
            .range(first..)
            .take_while(|(id, _)| id.0 == key)
            .filter(|(_, r)| obsolete(self, r))
            .map(|(id, _)| *id)
            .collect();
        for id in obsolete {
            if let Some(receipt) = self.state.deletion_receipts.remove(&id) {
                tx.delete(&receipt.store_key())?;
            }
        }
        Ok(())
    }

    pub(super) fn deletion_hold(&self, observed: Observation) -> RecordHold {
        let protects =
            observed.page_time_ms.is_some() && observed.seq > self.state.cursor.at_service;
        RecordHold {
            observation: observed,
            protects,
            needs_cursor: false,
            pending: None,
            cursor_generation: None,
            waited: false,
            observing: false,
        }
    }

    /// First observation of the delete, or the first feed page for a retained record
    /// view. A retry of either sees its observation already committed.
    pub(super) fn take_put_back_observation(
        &mut self,
        mut hold: RecordHold,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        use PutBack::{Observe, Prepare, Write};
        let observed = &hold.observation;
        let deletion = SignedOp::peek(&observed.operation).map_err(|_| super::corrupt())?;
        let answer = match self.consult_deletion(observed, &deletion, tx) {
            Ok(mut answer) => {
                let writes = match &mut answer {
                    Some(Observe { observed } | Prepare { observed } | Write { observed, .. }) => {
                        std::mem::take(observed)
                    }
                    None => vec![],
                };
                let bytes = super::local_writes_bytes(&writes);
                if bytes > super::MAX_STEP_LOCAL_BYTES {
                    return self.await_put_back_observation(hold, tx);
                }
                if !writes.is_empty() {
                    let OpKind::RecordPut(put) = &deletion.body().kind else {
                        return Err(super::corrupt());
                    };
                    let receipt = Receipt {
                        owner: observed.owner.clone(),
                        key: observed.key,
                        delete: observed.delete,
                        generation: observed.generation,
                        seq: observed.seq,
                        read_scope: put.policy.read_scope.clone(),
                    };
                    tx.local(&super::protocols::qualify(&observed.owner, writes))?;
                    tx.put(&receipt.store_key(), &receipt)?;
                    self.state.deletion_receipts.insert(receipt.id(), receipt);
                }
                answer
            }
            Err(AppError::Protocol(_)) => return self.await_put_back_observation(hold, tx),
            Err(error) => return Err(error),
        };
        if self.state.deletions.remove(&observed.id()).is_some() {
            tx.delete(&observed.store_key())?;
        }
        hold.observing = false;
        // A later view or the first feed page can enrich an existing observation.
        // Settle an already-sent operation against the current record on retry.
        if hold
            .pending
            .as_ref()
            .is_some_and(|pending| pending.kept_ms.is_some())
        {
            return self.keep_put_back(hold, tx);
        }
        match answer {
            Some(Prepare { .. }) => self.keep_waiting(hold, tx),
            Some(Write { .. }) => self.keep_put_back(hold, tx),
            None if self.state.put_backs.contains_key(&observed.id()) => {
                self.keep_waiting(hold, tx)
            }
            _ => self.forget_put_back(&observed.id(), tx),
        }
    }

    fn await_put_back_observation(
        &mut self,
        mut hold: RecordHold,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        if self.state.put_backs.contains_key(&hold.observation.id()) {
            hold.observing = true;
            return self.keep_waiting(hold, tx);
        }
        let observed = hold.observation;
        if let Entry::Vacant(entry) = self.state.deletions.entry(observed.id()) {
            tx.put(&observed.store_key(), &observed)?;
            entry.insert(observed);
        }
        Ok(())
    }

    pub(super) async fn retry_deletions(
        &mut self,
        budget: &super::CallBudget,
    ) -> Result<(), AppError> {
        let mut due: Vec<_> = self
            .owed_deletions()
            .map(|d| (self.feed_order(d.generation, d.seq), d.id()))
            .collect();
        due.sort_unstable();
        for (index, (order, id)) in due.into_iter().enumerate() {
            if index > 0 && self.spent(budget) {
                break;
            }
            let hold = self.state.put_backs.get(&id).filter(|h| h.observing);
            let Some(observed) = hold
                .map(|h| &h.observation)
                .or_else(|| self.state.deletions.get(&id))
            else {
                continue;
            };
            if self.ready_at(&observed.owner, order, Handover::Call) {
                let hold = hold
                    .cloned()
                    .unwrap_or_else(|| self.deletion_hold(observed.clone()));
                let mut tx = self.tx()?;
                self.take_put_back_observation(hold, &mut tx)?;
                if self.state.deletion_receipts.contains_key(&id) {
                    self.retire_completed_deletion(id.0, &mut tx).await?;
                }
                if !tx.is_empty() {
                    self.commit(tx).await?;
                }
            }
        }
        Ok(())
    }
}
