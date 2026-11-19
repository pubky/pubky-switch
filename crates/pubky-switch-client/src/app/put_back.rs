//! Holding the service cursor until the collection owner verifies publication (Switch spec 8.2, 10.3).

use std::collections::BTreeMap;

use super::deletion::{Id, Observation};

use pubky_switch_core::http::{ErrorCode, Retry};
use pubky_switch_core::ops::{Condition, OpKind, RecordVersion, SignedOp};
use pubky_switch_core::records::{AppCert, IdentityDoc};
use pubky_switch_core::shared::ApplicationRef;
use serde::{Deserialize, Serialize};

use super::batch::PendingBatch;
use super::events::Duty;
use super::order::Handover;
use super::records::{self, DeleteBase};
use super::state::{Reader, Tx};
use super::{Alarm, App, AppError, Batch, Position, ProtocolSet, PutBack, Refusal};

pub(super) const PREFIX: &str = "hold/";

/// A collection waiting for publication at an exact signed deletion.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct RecordHold {
    pub(super) observation: Observation,
    pub(super) protects: bool,
    pub(super) needs_cursor: bool,
    pub(super) waited: bool,
    /// The owner has yet to save its first observation.
    pub(super) observing: bool,
    pub(super) pending: Option<PendingBatch>,
    /// Generation of the cursor included with the first conditional send.
    pub(super) cursor_generation: Option<u64>,
}

impl RecordHold {
    pub(super) fn store_key(&self) -> String {
        self.observation.key_in(PREFIX)
    }

    fn writable(&self, cert: &AppCert) -> Result<bool, AppError> {
        let policy = self.observation.put()?.policy;
        Ok(policy
            .write_scopes_for(self.observation.delete.version)
            .iter()
            .any(|scope| cert.holds_scope(scope)))
    }
    pub(super) fn condition(&self) -> Condition {
        Condition::RecordCurrent {
            key: self.observation.key,
            revision: ApplicationRef {
                generation: self.observation.generation,
                seq: self.observation.seq,
                item_hash: self.observation.delete.item_hash,
            },
            deleted: true,
        }
    }

    fn target(op: &SignedOp) -> Result<(DeleteBase, ApplicationRef, bool), AppError> {
        let OpKind::RecordPut(put) = &op.body().kind else {
            return Err(super::corrupt());
        };
        let [
            Condition::RecordCurrent {
                key,
                revision,
                deleted,
            },
        ] = op.body().conditions.as_slice()
        else {
            return Err(super::corrupt());
        };
        if *key != put.key {
            return Err(super::corrupt());
        }
        let (revision, deleted) = (*revision, *deleted);
        Ok((
            DeleteBase {
                version: put.expected_version,
                item_hash: revision.item_hash,
            },
            revision,
            deleted,
        ))
    }

    /// A confirmed application of this owner's original direct replacement.
    fn directly_replaced_by(&self, revision: ApplicationRef) -> Result<bool, AppError> {
        let Some(pending) = self.pending.as_ref().filter(|p| p.kept_ms.is_some()) else {
            return Ok(false);
        };
        let batch = Batch::from_body(pending.body.clone())?;
        let [op] = batch.ops() else {
            return Err(super::corrupt());
        };
        Ok(op.body().generation == revision.generation
            && op.item_hash()? == revision.item_hash
            && op.body().conditions.as_slice() == std::slice::from_ref(&self.condition()))
    }

    pub(super) fn check(
        &self,
        protocols: &ProtocolSet,
        identity: &[u8; 32],
        own: &AppCert,
    ) -> Result<(), AppError> {
        self.observation.check(protocols, identity)?;
        if self.cursor_generation.is_some()
            && self.pending.as_ref().is_none_or(|p| p.kept_ms.is_none())
        {
            return Err(super::corrupt());
        }
        if let Some(pending) = &self.pending {
            let deletion = self.observation.put()?;
            let batch = checked_replacement(pending, identity, own)?;
            let op = &batch.ops()[0];
            let (target, at, deleted) = Self::target(op)?;
            let authorized = if deleted {
                op.body().conditions.contains(&self.condition())
                    && target == self.observation.delete
            } else {
                at.generation == self.observation.generation
                    && at.seq > self.observation.seq
                    && target.version == RecordVersion::new(at.generation, at.seq)
            };
            if pending.protocol.is_some()
                || pending.record_deletion.is_some()
                || op.body().generation != at.generation
                || self
                    .cursor_generation
                    .is_some_and(|g| !deleted || g != op.body().generation)
                || !authorized
                || !matches!(&op.body().kind, OpKind::RecordPut(put) if put.key == self.observation.key
                && put.collection == deletion.collection && put.policy == deletion.policy)
            {
                return Err(super::corrupt());
            }
        }
        Ok(())
    }
}

/// A replacement is one existing-record write signed by this installation.
fn checked_replacement(
    pending: &PendingBatch,
    identity: &[u8; 32],
    own: &AppCert,
) -> Result<Batch, AppError> {
    let batch = Batch::from_body(pending.body.clone()).map_err(|_| super::corrupt())?;
    let [op] = batch.ops() else {
        return Err(super::corrupt());
    };
    SignedOp::verify(
        op.signed(),
        &own.signing_key(),
        identity,
        Some(&own.app_id()),
    )
    .map_err(|_| super::corrupt())?;
    if batch.cursor().is_some()
        || pending.first_send.is_some()
        || !pending.local.is_empty()
        || !pending.queued.is_empty()
        || !pending.invites.is_empty()
        || !pending.deadlines.is_empty()
        || !matches!(&op.body().kind, OpKind::RecordPut(put) if !put.expected_version.is_none() && put.check_address(identity).is_ok() && !put.value_sealed.looks_like_delete())
    {
        return Err(super::corrupt());
    }
    Ok(batch)
}

/// A sent publication whose original application is still unknown travels with a backup.
pub(super) async fn settlements(reader: &Reader) -> Result<Vec<PendingBatch>, AppError> {
    Ok(reader
        .scan::<PendingBatch>(super::batch::PENDING_PREFIX)
        .await?
        .into_iter()
        .map(|(_, p)| p)
        .filter(|p| p.record_deletion.is_some())
        .collect())
}

/// Whether this observation may proceed to the ordinary record check.
pub(super) enum Publication {
    PendingObservation,
    Observed,
    Selected,
    Covered(ApplicationRef),
}

pub(super) type Holds = BTreeMap<Id, RecordHold>;

pub(super) fn at_key<'a>(
    holds: &'a Holds,
    key: &'a [u8; 32],
) -> impl Iterator<Item = &'a RecordHold> {
    holds
        .range((*key, RecordVersion::NONE, [0; 32])..)
        .take_while(move |(id, _)| &id.0 == key)
        .map(|(_, hold)| hold)
}

pub(super) async fn load(reader: &Reader) -> Result<Holds, AppError> {
    let mut holds = Holds::new();
    for (suffix, hold) in reader.scan::<RecordHold>(PREFIX).await? {
        if hold.store_key().strip_prefix(PREFIX) != Some(&suffix)
            || holds.insert(hold.observation.id(), hold).is_some()
        {
            return Err(super::corrupt());
        }
    }
    Ok(holds)
}

/// An in-place restore keeps the work the installation accepted after the backup as
/// well as the backup's. The next verified page reconciles its service cursor.
pub(super) async fn restore(
    previous: Option<&Reader>,
    backed_up: &[RecordHold],
    protocols: &ProtocolSet,
    meta: &super::state::Meta,
    cert: &AppCert,
    doc: &IdentityDoc,
    layers: &[super::ProtocolLayer],
) -> Result<Holds, AppError> {
    let mut holds = Holds::new();
    for hold in backed_up {
        hold.check(protocols, &meta.identity, cert)?;
        let mut hold = hold.clone();
        hold.observation.restore_predecessor(doc)?;
        hold.observing |= !layers
            .iter()
            .any(|layer| layer.protocol == hold.observation.owner);
        if holds.insert(hold.observation.id(), hold).is_some() {
            return Err(super::corrupt());
        }
    }
    if let Some(reader) = previous {
        let local_holds = load(reader).await?;
        let lost = super::identity::held_copy(reader, &meta.identity)
            .await?
            .and_then(|(doc, _)| doc.body().recovery_from);
        let cursor: Option<super::state::Cursor> = reader.get(super::key::CURSOR).await?;
        for deletion in backed_up.iter().map(|h| &h.observation) {
            // A local unanswered observation precedes a prepared replacement in the backup.
            // A completed release or a provider loss, by contrast, ends the old hold.
            let passed = cursor
                .is_some_and(|c| c.generation >= deletion.generation && c.seq >= deletion.seq);
            if lost.is_some_and(|g| deletion.generation <= g)
                || (!local_holds.contains_key(&deletion.id())
                    && !reader.exists(&deletion.store_key()).await?
                    && (passed
                        || reader
                            .get::<records::HeldRecord>(&records::record_key_of(&deletion.key))
                            .await?
                            .and_then(|r| r.delete_base())
                            == Some(deletion.delete)))
            {
                holds.remove(&deletion.id());
            }
        }
        for (key, mut hold) in local_holds {
            hold.check(protocols, &meta.identity, cert)?;
            let same = holds.get(&key);
            if let Some(backup) = same {
                if hold.observation.page_time_ms.is_none()
                    && backup.observation.page_time_ms.is_some()
                {
                    hold.observation.page_time_ms = backup.observation.page_time_ms;
                    hold.protects = backup.protects;
                }
                if hold.pending.as_ref().is_none_or(|p| p.kept_ms.is_none())
                    && backup.pending.as_ref().is_some_and(|p| p.kept_ms.is_some())
                {
                    hold.pending = backup.pending.clone();
                    hold.cursor_generation = backup.cursor_generation;
                }
            }
            hold.observing = same.is_none_or(|backup| {
                backup.observing || backup.observation.page_time_ms != hold.observation.page_time_ms
            });
            holds.insert(key, hold);
        }
    }
    let mut positions = std::collections::BTreeSet::new();
    for hold in holds.values_mut() {
        if hold.protects && !positions.insert(hold.observation.seq) {
            return Err(super::corrupt());
        }
        hold.needs_cursor = hold.protects;
    }
    Ok(holds)
}

fn waits(error: &AppError) -> bool {
    matches!(
        error,
        AppError::Transport(_) | AppError::Refused(Refusal::NotNow(_))
    ) || error
        .code()
        .is_some_and(|code| code == ErrorCode::TooLarge || code.retry() != Retry::No)
}

impl App {
    pub(super) async fn restore_record_settlements(
        &mut self,
        backed_up: &[PendingBatch],
        previous: Option<&Reader>,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let mut candidates = backed_up.to_vec();
        if let Some(reader) = previous {
            candidates.extend(settlements(reader).await?);
        }
        candidates.sort_by_key(|pending| pending.queued_n);
        let mut kept_bytes = 0;
        for pending in candidates {
            let delete = pending.record_deletion.ok_or_else(super::corrupt)?;
            let owner = pending.protocol.as_deref().ok_or_else(super::corrupt)?;
            let protocol = self.protocols.get(owner).ok_or_else(super::corrupt)?;
            let identity = &self.state.meta.identity;
            let batch = checked_replacement(&pending, identity, &self.state.cert)?;
            let op = &batch.ops()[0];
            let OpKind::RecordPut(put) = &op.body().kind else {
                return Err(super::corrupt());
            };
            let (target, at, deleted) = RecordHold::target(op)?;
            let target_matches = op.body().generation == at.generation
                && target.version == RecordVersion::new(at.generation, at.seq)
                && if deleted {
                    target == delete
                } else {
                    at.generation == delete.version.generation && at.seq > delete.version.version
                };

            let owns_record = protocol.collections().iter().any(|collection| {
                collection.id(identity) == put.collection && collection.admits(&put.policy)
            });
            if pending.kept_ms.is_none()
                || delete.version.is_none()
                || !target_matches
                || !owns_record
            {
                return Err(super::corrupt());
            }
            let id = batch.id().ok_or_else(super::corrupt)?;
            if let Some(Some(other)) =
                tx.pending_get::<PendingBatch>(&super::batch::pending_key(&id))?
            {
                if other.body != pending.body
                    || other.local != pending.local
                    || other.protocol != pending.protocol
                    || other.record_deletion != Some(delete)
                    || other.kept_ms != pending.kept_ms
                {
                    return Err(super::corrupt());
                }
                continue;
            }
            let duty = (put.key, delete.version, delete.item_hash);
            if let Some(hold) = self.state.put_backs.get_mut(&duty)
                && hold
                    .pending
                    .as_ref()
                    .is_some_and(|p| p.body == pending.body)
            {
                hold.pending = None;
                hold.cursor_generation = None;
                if let Some(reader) = previous
                    && reader
                        .get::<PendingBatch>(&super::batch::pending_key(&id))
                        .await?
                        .is_some_and(|p| {
                            p.body == pending.body && p.record_deletion == Some(delete)
                        })
                    && !reader.exists(&hold.store_key()).await?
                    && !reader.exists(&hold.observation.store_key()).await?
                {
                    self.state.put_backs.remove(&duty);
                }
            }
            Self::stage_signed_batch(&id, &pending, &batch, &mut kept_bytes, tx)?;
        }
        Ok(())
    }

    pub(super) async fn retry_put_backs(
        &mut self,
        attempted: &mut std::collections::BTreeSet<Id>,
        budget: &super::CallBudget,
    ) -> Result<(), AppError> {
        let mut due: Vec<_> = self
            .state
            .put_backs
            .values()
            .map(|hold| (hold.observation.seq, hold.observation.id()))
            .collect();
        due.sort_unstable();
        for (_, key) in due {
            let Some(hold) = self.state.put_backs.get(&key).cloned() else {
                continue;
            };
            if hold.needs_cursor || hold.observing || attempted.contains(&key) {
                continue;
            }
            if self.spent(budget) {
                break;
            }
            attempted.insert(key);
            Box::pin(self.try_put_back(hold)).await?;
        }
        Ok(())
    }

    pub(super) async fn saw_put_back_write(
        &mut self,
        key: &[u8; 32],
        due: Option<&Id>,
        revision: ApplicationRef,
        write: Option<(&records::Accepted, Option<&super::RecordRepair>)>,
        feed_time: Option<u64>,
        tx: &mut Tx,
    ) -> Result<Publication, AppError> {
        let id = due.copied().or_else(|| {
            at_key(&self.state.put_backs, key)
                .find(|h| {
                    h.observation.generation == revision.generation
                        && h.observation.seq == revision.seq
                })
                .or_else(|| at_key(&self.state.put_backs, key).next())
                .map(|h| h.observation.id())
        });
        let Some(mut hold) = id.and_then(|id| self.state.put_backs.get(&id)).cloned() else {
            return Ok(Publication::Observed);
        };
        let original = &hold.observation;
        if revision.generation == original.generation
            && revision.seq == original.seq
            && revision.item_hash == original.delete.item_hash
        {
            if !hold.protects
                && let Some(time) = feed_time
                && revision.seq > self.state.cursor.seq
            {
                hold.protects = true;
                if let Some((write, _)) = write {
                    write.confirm_deletion(&mut hold.observation);
                } else {
                    // The feed has verified the chain stub at this hash and position.
                    hold.observation.authenticated = true;
                }
                hold.observation.page_time_ms = Some(time);
                self.take_put_back_observation(hold, tx)?;
            }
        } else if let Some((write, repair)) = write
            && write.value().is_some()
            && self.feed_order(revision.generation, revision.seq)
                > self.feed_order(original.generation, original.seq)
        {
            if hold.observing {
                return Ok(Publication::PendingObservation);
            }
            if hold.protects
                || hold.observation.page_time_ms.is_some()
                || hold.observation.seq <= self.state.cursor.seq
            {
                let decision = match write.check_publication(self, &hold.observation, repair, tx) {
                    Ok(Some(decision)) => decision,
                    Ok(None) | Err(AppError::Protocol(_)) => return Ok(Publication::Observed),
                    Err(error) => return Err(error),
                };
                let deletion = original.revision();
                let id = original.id();
                let current = write.revision();
                let decision = if hold.directly_replaced_by(current)? {
                    super::PutBackSuccessor::Covered
                } else {
                    decision
                };
                match decision {
                    super::PutBackSuccessor::Covered => {
                        self.displace_publication(&mut hold, Some(current), tx)
                            .await?;
                        self.forget_put_back(&id, tx)?;
                        if hold.protects
                            && !hold.needs_cursor
                            && self.state.cursor.seq >= hold.observation.seq.saturating_sub(1)
                        {
                            self.advance_feed_cursor(hold.observation.seq, None, tx)?;
                            tx.put(super::key::CURSOR, &self.state.cursor)?;
                        }
                        return Ok(Publication::Covered(deletion));
                    }
                    super::PutBackSuccessor::Merge { value } if write.value() != Some(&value) => {
                        let selected = self
                            .select_publication(&mut hold, current, false, &value, tx)
                            .await?;
                        self.keep_put_back(hold, tx)?;
                        if selected {
                            return Ok(Publication::Selected);
                        }
                    }
                    _ if hold.pending.is_some() => {
                        self.keep_unselected(&mut hold, current, tx).await?;
                        self.keep_waiting(hold, tx)?;
                    }
                    _ => (),
                }
            }
        }
        Ok(Publication::Observed)
    }

    /// Preserve the exact first submission when a different publication may satisfy the
    /// duty. Only its own result or its authenticated application settles that operation.
    async fn displace_publication(
        &mut self,
        hold: &mut RecordHold,
        current: Option<ApplicationRef>,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        hold.cursor_generation = None;
        let Some(mut pending) = hold.pending.take().filter(|p| p.kept_ms.is_some()) else {
            return Ok(());
        };
        let batch = Batch::from_body(pending.body.clone())?;
        let [op] = batch.ops() else {
            return Err(super::corrupt());
        };
        let hash = op.item_hash()?;
        let id = batch.id().ok_or_else(super::corrupt)?;
        pending.protocol = Some(hold.observation.owner.clone());
        if current.is_some_and(|at| at.generation == op.body().generation && at.item_hash == hash) {
            return self.end_kept_batch(&id, &pending, super::kept::Ended::Applied, tx);
        }
        let (_, base, _) = RecordHold::target(op)?;
        if current.is_none_or(|at| at == base) || !self.answer_decides(pending.kept_ms) {
            // An original-result retry is safe only if its old comparison cannot still
            // apply. A released or expired submission with no proof remains uncertain.
            return self.kept_batch_dropped(&id, &pending, &batch, tx).await;
        }
        pending.record_deletion = Some(hold.observation.delete);
        self.stage_kept_batch(&id, &mut pending, &batch, tx).await
    }

    /// A repeat of an unanswered operation can still take effect while its exact
    /// target remains current. Leave it under the owner's hold until authorized.
    async fn keep_unselected(
        &mut self,
        hold: &mut RecordHold,
        current: ApplicationRef,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        if let Some(pending) = &hold.pending
            && pending.kept_ms.is_some()
            && self.answer_decides(pending.kept_ms)
        {
            let batch = Batch::from_body(pending.body.clone())?;
            let [op] = batch.ops() else {
                return Err(super::corrupt());
            };
            if RecordHold::target(op)?.1 == current {
                return Ok(());
            }
        }
        self.displace_publication(hold, Some(current), tx).await
    }

    /// Sign only against the authenticated application the protocol just inspected. A
    /// repeated decision for the same value keeps the exact original operation and ID.
    async fn select_publication(
        &mut self,
        hold: &mut RecordHold,
        at: ApplicationRef,
        deleted: bool,
        value: &[u8],
        tx: &mut Tx,
    ) -> Result<bool, AppError> {
        let mut put = hold.observation.put()?;
        let collection = super::Collection::new(&hold.observation.collection, put.policy.clone());
        let seen: Option<records::SeenMark> =
            self.read_in(&records::seen_key(&put.key), tx).await?;
        if value.len() > pubky_switch_core::sealed::MAX_JSON_LEN
            || records::refuse_unmarkable(
                &self.protocols,
                &self.state.naming,
                put.key,
                &collection,
                value,
                seen.as_ref().map(|mark| mark.mark.as_slice()),
            )
            .is_err()
        {
            self.keep_unselected(hold, at, tx).await?;
            return Ok(false);
        }
        let when = Condition::RecordCurrent {
            key: hold.observation.key,
            revision: at,
            deleted,
        };
        if let Some(pending) = &hold.pending {
            let batch = Batch::from_body(pending.body.clone())?;
            let [op] = batch.ops() else {
                return Err(super::corrupt());
            };
            let OpKind::RecordPut(put) = &op.body().kind else {
                return Err(super::corrupt());
            };
            let sealed = &put.value_sealed;
            if op.body().conditions.as_slice() == std::slice::from_ref(&when)
                && op.body().generation == self.state.meta.generation
                && sealed.data_epoch == self.state.own_doc.data_epoch()
                && (pending.kept_ms.is_none() || self.answer_decides(pending.kept_ms))
                && let Some(key) = self.state.scope_keys.get(sealed.data_epoch, &sealed.scope)
                && matches!(sealed.open(&key, &self.state.meta.identity, &put.key)?,
                    pubky_switch_core::sealed::RecordValue::Json(bytes) if bytes.as_slice() == value)
            {
                return Ok(true);
            }
        }
        self.keep_unselected(hold, at, tx).await?;
        if hold.pending.is_some() {
            return Ok(false);
        }
        put.expected_version = if deleted {
            hold.observation.delete.version
        } else {
            RecordVersion::new(at.generation, at.seq)
        };
        put.value_sealed = match records::seal_record(
            &self.state,
            &put.policy,
            put.expected_version,
            &put.key,
            Some(value),
        ) {
            Ok(sealed) => sealed,
            Err(
                AppError::InvalidData(_)
                | AppError::Refused(Refusal::Usage(_) | Refusal::NotNow(_)),
            ) => return Ok(false),
            Err(error) => return Err(error),
        };
        let batch = self.sign_ops(vec![(vec![when], OpKind::RecordPut(put))], None)?;
        hold.pending = Some(PendingBatch {
            body: batch.body().to_vec(),
            ..PendingBatch::default()
        });
        Ok(true)
    }

    pub(super) async fn try_put_back(&mut self, mut hold: RecordHold) -> Result<(), AppError> {
        if hold.observation.generation > self.state.meta.generation {
            return Ok(());
        }
        if !hold.writable(&self.state.cert)? {
            return self
                .refuse_put_back(hold.observation.id(), "permission_missing")
                .await;
        }
        if hold.protects
            && !self.ready_at(
                &hold.observation.owner,
                self.feed_order(hold.observation.generation, hold.observation.seq),
                Handover::Through,
            )
        {
            return Ok(());
        }
        if !hold.protects
            && hold.observation.page_time_ms.is_none()
            && hold.observation.seq > self.state.cursor.seq
        {
            return Ok(());
        }
        let write = match self.current_put_back_write(&hold.observation).await {
            Ok(Some(write)) => write,
            Ok(None) => return Ok(()),
            Err(error) if waits(&error) || error.code() == Some(ErrorCode::PermissionMissing) => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let id = hold.observation.id();
        let current = write.revision();
        let deleted = current == hold.observation.revision();
        let mut tx = self.tx()?;
        let mut selected = false;
        if deleted {
            let changed = write.confirm_deletion(&mut hold.observation);
            let signed =
                SignedOp::peek(&hold.observation.operation).map_err(|_| super::corrupt())?;
            match self.consult_deletion(&hold.observation, &signed, &tx) {
                Ok(Some(PutBack::Observe { .. })) => {
                    self.displace_publication(&mut hold, Some(current), &mut tx)
                        .await?;
                    self.forget_put_back(&id, &mut tx)?;
                }
                Ok(Some(PutBack::Write { value, .. }))
                    if hold.observation.authenticated
                        && hold.observation.generation == self.state.meta.generation
                        && signed.body().generation == current.generation
                        && hold.observation.delete.version
                            == RecordVersion::new(current.generation, current.seq) =>
                {
                    selected = self
                        .select_publication(&mut hold, current, true, &value, &mut tx)
                        .await?;
                    self.keep_put_back(hold, &mut tx)?;
                }
                Ok(_) | Err(AppError::Protocol(_)) if hold.pending.is_some() => {
                    self.keep_unselected(&mut hold, current, &mut tx).await?;
                    self.keep_waiting(hold, &mut tx)?;
                }
                Ok(_) | Err(AppError::Protocol(_)) if changed => {
                    self.keep_put_back(hold, &mut tx)?
                }
                Ok(_) | Err(AppError::Protocol(_)) => (),
                Err(error) => return Err(error),
            }
        } else {
            selected = self.take_publication_candidate(write, &id, &mut tx).await?;
        }
        // Only a decision staged by this covering read may send. Another owner can
        // still have an earlier ordered handover, even with a previously signed batch.
        if !tx.is_empty() {
            self.commit(tx).await?;
        }
        if !selected {
            return Ok(());
        }
        let mut hold = self
            .state
            .put_backs
            .get(&id)
            .cloned()
            .ok_or_else(super::corrupt)?;
        let Some(pending) = hold.pending.as_ref() else {
            return Ok(());
        };
        let body = Batch::from_body(pending.body.clone())?;
        let [op] = body.ops() else {
            return Err(super::corrupt());
        };
        let (_, at, target_deleted) = RecordHold::target(op)?;
        if at != current
            || deleted != target_deleted
            || op.body().generation != self.state.meta.generation
        {
            return Ok(());
        }
        let first = pending.kept_ms.is_none();
        // Only the original conditional application may move the cursor through its own
        // deletion. A duplicate returns the original proofs before interpreting a cursor.
        let cursor = if first {
            let seq = hold.observation.seq;
            hold.cursor_generation = (deleted
                && hold.protects
                && self.state.cursor.seq >= seq.saturating_sub(1)
                && self.state.cursor.at_service < seq
                && self.put_back_limit(Some(&id)) >= seq)
                .then_some(self.state.cursor.generation);
            hold.pending.as_mut().ok_or_else(super::corrupt)?.kept_ms = Some(self.kept_stamp());
            let mut tx = self.tx()?;
            self.keep_put_back(hold.clone(), &mut tx)?;
            self.commit(tx).await?;
            hold.cursor_generation
                .map(|generation| Position { generation, seq })
        } else {
            None
        };
        let batch = Batch::new(body.ops().to_vec(), cursor)?;
        let bounded = self.bound_service_cursor(&batch, Some(&id))?;
        match self
            .submit_body(bounded.as_ref().unwrap_or(&batch), None)
            .await
        {
            Ok(answer) => {
                let proof = answer.proofs.first().ok_or_else(super::corrupt)?;
                let mut tx = self.tx()?;
                self.cache_own_write(op, proof, &mut tx).await?;
                // The successful reply can confirm the first-send cursor. Its position
                // and chain proof survive the very commit that retires the signed hold.
                tx.put(super::key::CURSOR, &self.state.cursor)?;
                if let Some(chain) = self.state.chain.as_mut() {
                    chain.write(&mut tx)?;
                }
                self.commit(tx).await
            }
            Err(error)
                if matches!(
                    error.code(),
                    Some(
                        ErrorCode::Conflict
                            | ErrorCode::StaleKey
                            | ErrorCode::StaleEpoch
                            | ErrorCode::StaleGeneration
                    )
                ) && self.answer_decides(hold.pending.as_ref().and_then(|p| p.kept_ms)) =>
            {
                // The signed refusal decides this exact submission. The next attempt
                // must consult the current application and its owner afresh.
                let Some(mut hold) = self.state.put_backs.get(&id).cloned() else {
                    return Ok(());
                };
                if hold.pending.as_ref().is_some_and(|p| p.body == body.body()) {
                    hold.pending = None;
                    hold.cursor_generation = None;
                    let mut tx = self.tx()?;
                    self.keep_waiting(hold, &mut tx)?;
                    self.commit(tx).await?;
                }
                Ok(())
            }
            Err(error) if waits(&error) => {
                if !hold.waited {
                    let mut tx = self.tx()?;
                    self.keep_waiting(hold, &mut tx)?;
                    self.commit(tx).await?;
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    pub(super) async fn release_put_backs_on_leave(&mut self) -> Result<(), AppError> {
        while let Some(&key) = self.state.put_backs.keys().next() {
            self.refuse_put_back(key, "left").await?;
        }
        Ok(())
    }

    /// Release a record replacement after its protocol was told that the write waits
    /// and the owner agrees it may pass that deletion (Switch spec 10.3).
    ///
    /// # Errors
    ///
    /// A usage refusal if this signed deletion has no waiting replacement, or a store failure.
    pub async fn release_put_back(
        &mut self,
        key: &[u8; 32],
        version: RecordVersion,
        item_hash: &[u8; 32],
    ) -> Result<(), AppError> {
        self.ready_local().await?;
        let delete = DeleteBase {
            version,
            item_hash: *item_hash,
        };
        let id = (*key, delete.version, delete.item_hash);
        let Some(hold) = self
            .state
            .put_backs
            .get(&id)
            .filter(|hold| hold.waited && !hold.observing)
            .cloned()
        else {
            return Err(Refusal::Usage("no waiting replacement at this record".into()).into());
        };
        let mut tx = self.tx()?;
        let op = SignedOp::peek(&hold.observation.operation).map_err(|_| super::corrupt())?;
        if !matches!(
            self.consult_deletion(&hold.observation, &op, &tx)?,
            Some(PutBack::Observe { .. })
        ) {
            return Err(Refusal::NotNow("the collection still requires publication".into()).into());
        }
        let mut hold = hold;
        self.displace_publication(&mut hold, None, &mut tx).await?;
        self.forget_put_back(&id, &mut tx)?;
        self.commit(tx).await
    }

    /// A protected deletion sets the earliest position that can speak for this key.
    /// At or beyond that point the service still owes the record (Switch spec 10.3).
    pub(super) async fn put_back_absence_is_current(
        &mut self,
        key: &[u8; 32],
        through: super::FeedPosition,
    ) -> Result<bool, AppError> {
        let mut current = true;
        let mut protected = false;
        for hold in at_key(&self.state.put_backs, key).filter(|h| h.protects) {
            if !self
                .state
                .cert
                .holds_scope(&hold.observation.put()?.policy.read_scope)
            {
                return Ok(false);
            }
            let at = super::FeedPosition {
                generation: hold.observation.generation,
                seq: hold.observation.seq,
            };
            if hold.needs_cursor || !self.covers(through, at) {
                current = false;
                continue;
            }
            protected = true;
            break;
        }
        if protected {
            let reason = "Switch spec 10.3: a record held for replacement is absent".into();
            return Err(self.raise(Alarm::Rollback { reason }).await);
        }
        Ok(current)
    }

    pub(super) fn keep_waiting(
        &mut self,
        mut hold: RecordHold,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        if !hold.waited {
            let duty = Duty::PutBackWaits {
                key: hold.observation.key,
                delete: hold.observation.delete,
            };
            self.keep_duty_for(tx, vec![hold.observation.owner.clone()], duty)?;
            hold.waited = true;
        }
        self.keep_put_back(hold, tx)
    }

    async fn refuse_put_back(&mut self, key: Id, reason: &str) -> Result<(), AppError> {
        let mut tx = self.tx()?;
        self.discard_put_back(key, reason, &mut tx).await?;
        self.commit(tx).await
    }

    pub(super) async fn discard_put_back(
        &mut self,
        key: Id,
        reason: &str,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let mut hold = self
            .state
            .put_backs
            .get(&key)
            .cloned()
            .ok_or_else(super::corrupt)?;
        self.displace_publication(&mut hold, None, tx).await?;
        let deletion = &hold.observation;
        let duty = Duty::PutBackRefused {
            key: key.0,
            delete: deletion.delete,
            reason: reason.to_owned(),
        };
        self.keep_duty_for(tx, vec![deletion.owner.clone()], duty)?;
        self.forget_put_back(&key, tx)
    }

    pub(super) async fn put_backs_after_renewal(&mut self, tx: &mut Tx) -> Result<(), AppError> {
        let keys: Vec<_> = self.state.put_backs.keys().copied().collect();
        for key in keys {
            if !self.state.put_backs[&key].writable(&self.state.cert)? {
                self.discard_put_back(key, "permission_missing", tx).await?;
            }
        }
        Ok(())
    }

    /// A delete passed by another copy of this app can only be replaced best effort.
    pub(super) async fn note_put_backs_passed(&mut self, cursor: u64) -> Result<(), AppError> {
        let passed: Vec<_> = self
            .state
            .put_backs
            .values()
            .filter(|h| {
                h.observation.generation <= self.state.meta.generation
                    && (h.needs_cursor || (h.protects && h.observation.seq <= cursor))
            })
            .map(|h| h.observation.id())
            .collect();
        for key in passed {
            let mut hold = self.state.put_backs[&key].clone();
            let mut tx = self.tx()?;
            hold.needs_cursor = false;
            hold.protects &= hold.observation.seq > cursor;
            self.keep_put_back(hold, &mut tx)?;
            self.commit(tx).await?;
        }
        Ok(())
    }

    /// A batch may pass its own delete while every earlier hold still bounds it.
    pub(super) fn put_back_limit(&self, applying: Option<&Id>) -> u64 {
        let authorized = self
            .state
            .put_backs
            .values()
            .filter(|h| {
                h.protects
                    && h.observation.generation <= self.state.meta.generation
                    && Some(&h.observation.id()) != applying
            })
            .map(|h| &h.observation);
        let cursor = self.state.cursor;
        let undecided = self.state.deletions.values().filter(|d| {
            d.page_time_ms.is_some()
                && d.generation == cursor.generation
                && d.seq > cursor.at_service
        });
        authorized
            .chain(undecided)
            .map(|d| d.seq.saturating_sub(1))
            .min()
            .unwrap_or(u64::MAX)
    }

    pub(super) fn bound_service_cursor(
        &self,
        batch: &Batch,
        applying: Option<&Id>,
    ) -> Result<Option<Batch>, AppError> {
        let Some(position) = batch.cursor() else {
            return Ok(None);
        };
        let limit = self.put_back_limit(applying);
        if position.seq <= limit || position.generation != self.state.cursor.generation {
            return Ok(None);
        }
        let cursor =
            (batch.ops().is_empty() || limit > self.state.cursor.at_service).then_some(Position {
                generation: position.generation,
                seq: limit,
            });
        Ok(Some(Batch::new(batch.ops().to_vec(), cursor)?))
    }

    pub(super) fn keep_put_back(&mut self, hold: RecordHold, tx: &mut Tx) -> Result<(), AppError> {
        hold.check(&self.protocols, &self.state.meta.identity, &self.state.cert)?;
        let at = hold.store_key();
        tx.put(&at, &hold)?;
        self.state.put_backs.insert(hold.observation.id(), hold);
        Ok(())
    }

    pub(super) fn forget_put_back(&mut self, key: &Id, tx: &mut Tx) -> Result<(), AppError> {
        if let Some(hold) = self.state.put_backs.remove(key) {
            tx.delete(&hold.store_key())?;
        }
        Ok(())
    }
}
