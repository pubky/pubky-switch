//! Provider loss and recovery, the app's side (Switch spec 12.6; Switch wire 7.4.14), and
//! the evidence an app keeps for the uploads of a move or a recovery.
//!
//! When the newest own `identity.json` names a new generation with `recovery_from` at least
//! the generation followed, the identity declared that generation lost. The app starts the
//! recovery in one commit, before any call: it follows the new service, starts a new cursor
//! and chain view from the start of the new sequence, keeps the old service's newest head,
//! and makes a fresh receive key, `n` higher than every `n` it registered, with the batch
//! that delivers its record and registers that key, signed once. Then, each step committed
//! as done before the next:
//!
//! 1. **Register** (step 1): the kept batch, until answered; the recovery record's time is
//!    the declaration's.
//! 2. **Upload** (step 3): the lost generation's `identity.json`, the record and claim
//!    operations it keeps with their writers' certificates and the old service's proofs,
//!    the old newest head (only while its continuity is verified) and the proofs it keeps,
//!    before its first record write.
//! 3. **Lists** (step 2): with `lists.manage`, the contacts and deny list from its copy of
//!    the lists; with `lists.read`, the deny list.
//! 4. **Re-sends** (step 4): the protocol queues its re-send requests for what the
//!    counterparties' inboxes accepted after the cursor's time at the old service, and names
//!    the counterparties whose conversation entries the app adds back; its local writes
//!    commit with the step, once.
//! 5. **Conversations** (step 2): the entries added back, never for a denied identity.
//!
//! The app stays in reconcile mode until the protocol's reconciliation ends it (Switch spec
//! 12.6 steps 5 and 6, 12.4): the obligations from before the loss are uncertain, which is
//! the protocol's to judge with the declaration time and the residual window.

use pubky_switch_core::chain::{
    ItemType, ServiceTransition, SignedHead, TransitionProof, Verifier, ZERO_HASH,
};
use pubky_switch_core::enc::{b64, pubky_id, pubky_key, serde_b64_vec};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::keys::ReceiveKey;
use pubky_switch_core::ops::{AllowKind, Condition, MAX_BATCH_ENTRIES, OpKind, Position, SignedOp};
use pubky_switch_core::records::{
    AppCert, CLOCK_TOLERANCE_MS, IdentityDoc, ReceiveKeyBody, ReceiveKeyRecord,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::App;
use super::chain::ChainView;
use super::context::LocalView;
use super::error::{AppError, Refusal};
use super::events::{AppEvent, Duty, KeptRefusal};
use super::identity::REVALIDATION_MS;
use super::protocol::{
    LocalWrite, MAX_LOSS_CONVERSATIONS, MAX_STEP_LOCAL_BYTES, local_writes_bytes,
};
use super::state::{Cursor, HeldKey, KnownKid, RestoreState, key};
use crate::client::Batch;
use crate::client::answers::{FeedItem, FeedQuery, RecoveryUpload, UploadLists, UploadedOp};
use crate::error::{ClientError, StoreError};

/// How long after a declared loss an attempt could still have been authorized at the old
/// service, before the offset between the two services' clocks: the 60 seconds an app trusts
/// its own `identity.json` before an attempt, plus the clock tolerance (Switch spec 12.6,
/// "Residual risk").
pub const RESIDUAL_WINDOW_MS: u64 = REVALIDATION_MS + CLOCK_TOLERANCE_MS;

/// The keys of this file's records (`STATE.md`, "Moves, recovery and push").
pub(crate) mod keys {
    use super::b64;

    /// A provider loss being followed, or followed.
    pub(crate) const LOSS: &str = "loss";

    /// A kept operation, by its document hash.
    pub(crate) fn op(hash: &[u8; 32]) -> String {
        format!("ev/op/{}", b64(hash))
    }

    /// A kept transition proof, by its document hash.
    pub(crate) fn proof(hash: &[u8; 32]) -> String {
        format!("ev/proof/{}", b64(hash))
    }
}

/// Evidence an app keeps for the uploads of a move or a recovery (Switch spec 12.5 step 3,
/// 12.6 step 3): the records layer, or the protocol, hands it over as it takes it. Its
/// `Debug` shows no content.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Evidence {
    /// A signed `record.put` or claim entry, with its writer's certificate and, when held,
    /// the transition proof of its write.
    Op {
        /// The signed operation, with its sealed value.
        op: SignedDoc,
        /// Its writer's certificate.
        cert: SignedDoc,
        /// The service's transition proof, if held.
        proof: Option<SignedDoc>,
    },
    /// A transition proof kept on its own: a SETTLED or tombstone proof, the proof of a
    /// record version, or of one of the app's own attempts still open.
    Proof(SignedDoc),
}

impl std::fmt::Debug for Evidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Evidence::Op { proof, .. } => {
                write!(f, "Evidence::Op(proof: {})", proof.is_some())
            }
            Evidence::Proof(_) => f.write_str("Evidence::Proof"),
        }
    }
}

/// `ev/op/<hash>`: a kept operation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KeptOp {
    op: SignedDoc,
    cert: SignedDoc,
    proof: Option<SignedDoc>,
}

/// A provider loss as the protocol sees it (Switch spec 12.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderLoss {
    /// The generation lost.
    pub lost_generation: u64,
    /// The generation recovered at.
    pub generation: u64,
    /// When the loss was declared: the recovery record's service time, in Unix
    /// milliseconds.
    pub declared_at_ms: u64,
    /// The acceptance time to ask re-sends from: the time of the cursor at the old service
    /// (Switch spec 12.6 step 4).
    pub accepted_from_ms: u64,
    /// Until when an attempt could have been authorized at the old service: the declaration
    /// plus the residual window and the offset between the services' clocks. Which
    /// obligations that makes uncertain is the protocol's (Switch spec 12.6 step 5).
    pub uncertain_until_ms: u64,
}

/// What the protocol does about a provider loss (Switch spec 12.6 steps 2 and 4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LossActions {
    /// The counterparties in its records, whose conversation entries the app adds back,
    /// except identities on its copy of the deny list. At most
    /// [`super::MAX_LOSS_CONVERSATIONS`] are added back, the first in key order; how many
    /// more there were is kept with the loss ([`RecoveryInfo::conversations_left_out`]).
    pub conversations: Vec<[u8; 32]>,
    /// The protocol's local writes that queue its re-send requests, committed once.
    pub local: Vec<LocalWrite>,
}

/// A provider loss the app follows or followed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryInfo {
    /// The protocol's view of the loss.
    pub loss: ProviderLoss,
    /// Whether the app's steps of the recovery have all run.
    pub steps_done: bool,
    /// How many counterparties of [`LossActions::conversations`] past
    /// [`super::MAX_LOSS_CONVERSATIONS`] the app didn't add back: their writes are refused
    /// `403 not_admitted` until a write of the app's admits them again (Switch spec 7).
    pub conversations_left_out: u64,
}

/// The steps of following a loss, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum LossStep {
    Register,
    Upload,
    Lists,
    Resend,
    Conversations,
    Done,
}

/// `loss`: a provider loss being followed (Switch spec 12.6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LossRecord {
    pub(crate) lost_generation: u64,
    pub(crate) generation: u64,
    pub(crate) step: LossStep,
    /// The old service's newest head, while the app had verified the chain it vouches for.
    pub(crate) newest_head: Option<Value>,
    /// The acceptance time of the last entry the cursor passed at the old service.
    pub(crate) cursor_time_ms: u64,
    pub(crate) declared_at_ms: Option<u64>,
    /// The old service's clock against the device's, at its last verified answer.
    pub(crate) old_offset_ms: Option<i64>,
    pub(crate) clock_offset_ms: u64,
    /// The new receive key's `n`.
    pub(crate) key_n: u64,
    /// The batch of the current step, signed once and kept until answered.
    #[serde(with = "serde_b64_vec", default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) batch: Vec<u8>,
    /// The counterparties whose conversation entries are still to be added back.
    pub(crate) conversations: Vec<String>,
    /// How many counterparties the protocol named past [`MAX_LOSS_CONVERSATIONS`], not
    /// added back.
    #[serde(default)]
    pub(crate) conversations_left_out: u64,
}

impl LossRecord {
    pub(crate) fn done(&self) -> bool {
        self.step == LossStep::Done
    }

    /// Keep the counterparties the loss adds back, sorted and once each, at most
    /// [`MAX_LOSS_CONVERSATIONS`] of them, so the record and its batches stay within the
    /// store's sizes; and how many it leaves out, with them, in the same commit.
    fn keep_conversations(&mut self, mut conversations: Vec<String>) {
        conversations.sort();
        conversations.dedup();
        let left_out = conversations.len().saturating_sub(MAX_LOSS_CONVERSATIONS);
        conversations.truncate(MAX_LOSS_CONVERSATIONS);
        self.conversations = conversations;
        self.conversations_left_out = u64::try_from(left_out).unwrap_or(u64::MAX);
    }

    fn view(&self) -> ProviderLoss {
        let declared = self.declared_at_ms.unwrap_or(0);
        ProviderLoss {
            lost_generation: self.lost_generation,
            generation: self.generation,
            declared_at_ms: declared,
            accepted_from_ms: self.cursor_time_ms,
            uncertain_until_ms: declared
                .saturating_add(RESIDUAL_WINDOW_MS)
                .saturating_add(self.clock_offset_ms),
        }
    }
}

fn corrupt() -> AppError {
    AppError::Store(StoreError::Corrupt)
}

impl App {
    // ---------------------------------------------------------------------------------
    // Evidence

    /// Keep evidence for the uploads of a move or a recovery (Switch spec 12.5 step 3, 12.6
    /// step 3). Each item is kept once, by its document hash. An operation must be a
    /// `record.put` or a claim entry of this identity, with its writer's certificate.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for an item that doesn't read as such; a store failure.
    pub async fn keep_evidence(&mut self, items: Vec<Evidence>) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let identity = self.state.meta.identity;
            let mut tx = self.tx()?;
            for item in items {
                match item {
                    Evidence::Op { op, cert, proof } => {
                        let usage = |why: &str| AppError::Refused(Refusal::Usage(why.into()));
                        let signed = SignedOp::peek(&op)
                            .map_err(|_| usage("evidence: the operation doesn't read"))?;
                        let body = signed.body();
                        if !matches!(body.kind, OpKind::RecordPut(_) | OpKind::Claim(_))
                            || body.identity != identity
                        {
                            return Err(usage(
                                "evidence: only this identity's record.put and claim entries",
                            ));
                        }
                        let writer = AppCert::verify(&cert, &identity)
                            .map_err(|_| usage("evidence: the certificate doesn't verify"))?;
                        if body.app_id != Some(writer.app_id()) {
                            return Err(usage("evidence: the certificate isn't the writer's"));
                        }
                        if let Some(proof) = &proof {
                            TransitionProof::peek(proof)
                                .map_err(|_| usage("evidence: the proof doesn't read"))?;
                        }
                        let hash = op.doc_hash()?;
                        tx.put(&keys::op(&hash), &KeptOp { op, cert, proof })?;
                    }
                    Evidence::Proof(proof) => {
                        TransitionProof::peek(&proof).map_err(|_| {
                            AppError::Refused(Refusal::Usage(
                                "evidence: the proof doesn't read".into(),
                            ))
                        })?;
                        tx.put(&keys::proof(&proof.doc_hash()?), &proof)?;
                    }
                }
            }
            self.commit(tx).await
        })
        .await
    }

    /// Forget evidence the app no longer keeps, such as proofs past their window.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn forget_evidence(&mut self, items: &[Evidence]) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let mut tx = self.tx()?;
            for item in items {
                match item {
                    Evidence::Op { op, .. } => tx.delete(&keys::op(&op.doc_hash()?))?,
                    Evidence::Proof(proof) => tx.delete(&keys::proof(&proof.doc_hash()?))?,
                }
            }
            self.commit(tx).await
        })
        .await
    }

    /// The kept operations, as uploads: the `record.put`s and the claim entries, those kept
    /// here and those the shared state holds (Switch spec 12.5 step 3, 12.6 step 3), each
    /// once.
    async fn kept_ops(&self) -> Result<(Vec<UploadedOp>, Vec<UploadedOp>), AppError> {
        let mut records = Vec::new();
        let mut claims = Vec::new();
        let mut kept: Vec<KeptOp> = self
            .reader()
            .scan::<KeptOp>("ev/op/")
            .await?
            .into_iter()
            .map(|(_, kept)| kept)
            .collect();
        for shared in self.shared_evidence().await?.ops {
            if !kept.iter().any(|k| k.op == shared.op) {
                kept.push(KeptOp {
                    op: shared.op,
                    cert: shared.cert,
                    proof: shared.proof,
                });
            }
        }
        for kept in kept {
            let claim = SignedOp::peek(&kept.op)
                .map(|op| matches!(op.body().kind, OpKind::Claim(_)))
                .map_err(|_| corrupt())?;
            let upload = UploadedOp {
                op: kept.op,
                cert: kept.cert,
                proof: kept.proof,
            };
            if claim {
                claims.push(upload);
            } else {
                records.push(upload);
            }
        }
        Ok((records, claims))
    }

    /// The kept proofs, those kept on their own and those of kept operations; with
    /// `service_key`, only those that verify with it.
    pub(crate) async fn kept_proofs(
        &self,
        service_key: Option<&[u8; 32]>,
    ) -> Result<Vec<SignedDoc>, AppError> {
        let reader = self.reader();
        let mut proofs: Vec<SignedDoc> = reader
            .scan::<SignedDoc>("ev/proof/")
            .await?
            .into_iter()
            .map(|(_, proof)| proof)
            .collect();
        for (_, kept) in reader.scan::<KeptOp>("ev/op/").await? {
            if let Some(proof) = kept.proof
                && !proofs.contains(&proof)
            {
                proofs.push(proof);
            }
        }
        // The shared state's evidence: its SETTLED and tombstone proofs, and the proofs of
        // the record writes and claim entries it holds.
        let shared = self.shared_evidence().await?;
        let shared_proofs = shared
            .proofs
            .into_iter()
            .chain(shared.ops.into_iter().filter_map(|kept| kept.proof));
        for proof in shared_proofs {
            if !proofs.contains(&proof) {
                proofs.push(proof);
            }
        }
        let identity = self.state.meta.identity;
        if let Some(key) = service_key {
            proofs.retain(|proof| TransitionProof::verify(proof, key, &identity).is_ok());
        }
        Ok(proofs)
    }

    // ---------------------------------------------------------------------------------
    // Following a loss

    pub(crate) async fn loss_record(&self) -> Result<Option<LossRecord>, AppError> {
        self.reader().get(keys::LOSS).await
    }

    /// The provider loss the app follows or followed last, if any.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn recovery_info(&self) -> Result<Option<RecoveryInfo>, AppError> {
        Ok(self.loss_record().await?.map(|loss| RecoveryInfo {
            loss: loss.view(),
            steps_done: loss.done(),
            conversations_left_out: loss.conversations_left_out,
        }))
    }

    /// Start following the loss `doc` declares, in one commit before any call.
    pub(crate) async fn start_loss(&mut self, doc: &IdentityDoc) -> Result<(), AppError> {
        let lost = self.state.meta.generation;
        let generation = doc.generation();
        let old_key = self.state.meta.service_key;
        let newest_head = self
            .state
            .chain
            .as_ref()
            .filter(|chain| chain.gap.is_none())
            .and_then(|chain| chain.newest)
            .map(|head| head.to_value());
        let old_offset_ms = self
            .state
            .service_time
            .filter(|time| time.key == old_key)
            .map(|time| time.offset_ms);
        // Switch spec 3.6, 12.6 step 1: `n` higher than every `n` the app registered.
        let highest = self
            .state
            .receive_keys
            .keys()
            .chain(self.state.registrations.keys())
            .chain(self.state.known_kids.values())
            .copied()
            .max()
            .unwrap_or(0);
        let n = highest
            .checked_add(1)
            .ok_or_else(|| AppError::InvalidData("receive key numbers ran out".into()))?;
        let fresh = ReceiveKey::generate(n)?;
        let record = ReceiveKeyRecord::sign(
            &self.state.keys,
            &self.state.cert,
            ReceiveKeyBody::new(&self.state.cert, &fresh),
        )?;
        let mut tx = self.tx()?;
        // The last copy of the lost generation, for the upload, if the feed didn't keep it.
        let held_doc = self.generation_doc(lost).await?;
        if held_doc.is_none() {
            tx.put(
                &super::provider::keys::generation(lost),
                &super::provider::GenerationRecord {
                    origin: self.state.meta.origin.clone(),
                    service_key: old_key,
                    doc: None,
                },
            )?;
        }
        // Follow the new service: a new sequence and chain, read from their start.
        self.state.meta.origin = doc.inbox().url.clone();
        self.state.meta.service_key = doc.inbox().service_key;
        self.state.meta.generation = generation;
        self.rebuild_client()?;
        // The kept writes, judged against the old chain view before it goes (Switch spec
        // 12.6 step 1, 13.5).
        let events = self
            .carry_kept_writes(&mut tx, super::provider::Carry::AfterLoss)
            .await?;
        let batch = self.sign_ops(
            vec![
                (
                    Vec::<Condition>::new(),
                    OpKind::AppPut {
                        record: self.state.record.clone(),
                    },
                ),
                (
                    Vec::new(),
                    OpKind::ReceiveKeyPut {
                        record: record.signed().clone(),
                    },
                ),
            ],
            None,
        )?;
        let time_ms = self.state.cursor.time_ms;
        self.state.cursor = Cursor {
            generation,
            seq: 0,
            at_service: 0,
            deferred_since_ms: None,
            time_ms,
        };
        let mut view = ChainView::anchored(generation, 0, ZERO_HASH);
        view.write_all(&mut tx)?;
        self.state.chain = Some(view);
        // Registrations at the old service mean nothing at the new one; the retired keys go
        // once the cursor passes the new key's registration there.
        for (old_n, held) in self.state.receive_keys.iter_mut() {
            held.reg_seq = None;
            held.reg_time_ms = None;
            held.pending.clear();
            tx.put(&key::receive_key(*old_n), held)?;
        }
        let held = HeldKey {
            key: fresh.clone(),
            record: record.signed().clone(),
            reg_seq: None,
            reg_time_ms: None,
            pending: Vec::new(),
        };
        tx.put(&key::receive_key(n), &held)?;
        tx.put(&key::kid(&fresh.kid), &KnownKid { n })?;
        self.state.receive_keys.insert(n, held);
        self.state.known_kids.insert(fresh.kid, n);
        self.state.registrations.clear();
        self.state.held.clear();
        self.state.seen.clear();
        self.state.asked.clear();
        self.state.retries.clear();
        for prefix in ["reg/", "held/", "seen/", "asked/", "retry/"] {
            tx.delete_prefix(prefix)?;
        }
        // The copy of the lists wasn't read from the new service: it reads as not refreshed,
        // and the first read after the loss refreshes it. The flagged senders stay until
        // then, the old service's being all the app knows.
        tx.delete(super::admission::LISTS_AT)?;
        tx.delete(super::admission::LISTS_TOO_LARGE)?;
        // Entries stored locally stay as they are: their local IDs, not the `seq`s they
        // were read at, key them, so nothing of them is written again here.
        if self.state.pending_record.take().is_some() {
            tx.delete(key::PENDING_RECORD)?;
        }
        // Reconcile mode until the protocol's reconciliation ends it (Switch spec 12.6 step 5).
        let restore = self.state.restore.get_or_insert(RestoreState {
            n_floor: n,
            key_checked: true,
            own_key_n: Some(n),
            reconcile: true,
        });
        restore.reconcile = true;
        tx.put(key::RESTORE, restore)?;
        let loss = LossRecord {
            lost_generation: lost,
            generation,
            step: LossStep::Register,
            newest_head,
            cursor_time_ms: time_ms,
            declared_at_ms: None,
            old_offset_ms,
            clock_offset_ms: 2 * CLOCK_TOLERANCE_MS,
            key_n: n,
            batch: batch.body().to_vec(),
            conversations: Vec::new(),
            conversations_left_out: 0,
        };
        tx.put(keys::LOSS, &loss)?;
        tx.put(key::META, &self.state.meta)?;
        tx.put(key::CURSOR, &self.state.cursor)?;
        self.commit(tx).await?;
        self.events.extend(events);
        self.events.push(AppEvent::ProviderLost {
            lost_generation: lost,
            generation,
        });
        Ok(())
    }

    /// Run the steps of a loss from where they stand, each committed as done. Returns
    /// `false` when a newer own `identity.json` names a later generation than the app
    /// follows: the loss is left where it stands, a stuck step included, and the newer
    /// document is followed instead (Switch spec 12.5 "Abort", 12.6). A loss superseded by
    /// another loss is replaced by it; one superseded by a move or a key change goes on at
    /// the generation followed once the app switched there.
    pub(crate) async fn run_loss(&mut self, mut loss: LossRecord) -> Result<bool, AppError> {
        while !loss.done() {
            if self.provider_superseded() {
                self.events.push(AppEvent::ProviderChangeSuperseded {
                    generation: self.state.meta.generation,
                    newer: self.state.own_doc.generation(),
                });
                return Ok(false);
            }
            if let Err(error) = self.loss_step(&mut loss).await {
                self.look_for_newer_doc(&error).await;
                if !self.provider_superseded() {
                    return Err(error);
                }
            }
        }
        self.push_after_provider_change().await?;
        Ok(true)
    }

    /// One step of a loss, committed as done.
    async fn loss_step(&mut self, loss: &mut LossRecord) -> Result<(), AppError> {
        match loss.step {
            LossStep::Register => {
                self.loss_register(loss).await?;
                loss.step = LossStep::Upload;
            }
            LossStep::Upload => {
                self.loss_upload(loss).await?;
                loss.step = LossStep::Lists;
            }
            LossStep::Lists => {
                self.loss_lists().await?;
                loss.step = LossStep::Resend;
            }
            LossStep::Resend => {
                // The protocol's local writes commit with the step: asked once.
                let actions = {
                    let store = std::sync::Arc::clone(self.env.store.store());
                    let view = LocalView::new(
                        self.state.meta.identity,
                        self.state.meta.app_id,
                        store.as_ref(),
                        &self.ns,
                    );
                    self.protocol.provider_lost_with(&loss.view(), &view)
                }
                // The step stays `Resend` in the record: the next call asks again.
                .map_err(AppError::Protocol)?;
                let copy = self.lists_copy().await?;
                let me = self.state.meta.identity;
                let may_add = self.state.cert.has_permission(Permission::ConversationAdd);
                loss.keep_conversations(
                    actions
                        .conversations
                        .iter()
                        .filter(|who| may_add && **who != me && !copy.deny.contains(who))
                        .map(pubky_id)
                        .collect(),
                );
                loss.step = LossStep::Conversations;
                let mut tx = self.tx()?;
                if local_writes_bytes(&actions.local) > MAX_STEP_LOCAL_BYTES {
                    // Over the bound: not committed, and not asked again, since the same
                    // answer would come and the recovery would never go on; the protocol is
                    // told, and the loss goes on.
                    self.keep_duty(
                        &mut tx,
                        Duty::LocalWritesRefused {
                            call: {
                                let view = loss.view();
                                KeptRefusal::Loss {
                                    lost_generation: view.lost_generation,
                                    generation: view.generation,
                                    declared_at_ms: view.declared_at_ms,
                                    accepted_from_ms: view.accepted_from_ms,
                                    uncertain_until_ms: view.uncertain_until_ms,
                                }
                            },
                        },
                    )?;
                } else {
                    tx.local(&actions.local)?;
                }
                tx.put(keys::LOSS, &*loss)?;
                return self.commit(tx).await;
            }
            LossStep::Conversations => {
                self.loss_conversations(loss).await?;
                loss.step = LossStep::Done;
                self.events.push(AppEvent::ProviderRecovered {
                    generation: loss.generation,
                });
            }
            LossStep::Done => {}
        }
        let mut tx = self.tx()?;
        tx.put(keys::LOSS, &*loss)?;
        if let Some(chain) = self.state.chain.as_mut() {
            chain.write(&mut tx)?;
        }
        self.commit(tx).await
    }

    /// Step 1: the kept batch delivers the record and registers the new key; then the
    /// recovery record, the new sequence's first item, gives the declaration's time.
    ///
    /// A `409 conflict` names the key registered there (Switch spec 3.6): this very key is
    /// a registration answered before. Another device's key is adopted: this device drops
    /// its own, and its record goes alone, signed once and kept, since the conflict applied
    /// nothing. A key no device of the app made is a compromise: the app stops and leaves.
    async fn loss_register(&mut self, loss: &mut LossRecord) -> Result<(), AppError> {
        let proofs = loop {
            let batch = Batch::from_body(loss.batch.clone())?;
            let registers = batch
                .ops()
                .iter()
                .any(|op| matches!(op.body().kind, OpKind::ReceiveKeyPut { .. }));
            let current = match self.submit(&batch).await {
                Ok(submitted) => break submitted.proofs,
                // The record alone: the service holds it, or a later one of the app's
                // (Switch spec 4.2).
                Err(AppError::Switch(ClientError::Switch {
                    code: ErrorCode::Conflict,
                    ..
                })) if !registers => break Vec::new(),
                Err(AppError::Switch(ClientError::Switch {
                    code: ErrorCode::Conflict,
                    current,
                    ..
                })) => current,
                Err(error) => return Err(error),
            };
            let named = self.conflict_receive_key(&current).await?;
            let ours = self.state.receive_keys.get(&loss.key_n).map(|h| h.key.kid);
            if Some(named.kid()) == ours {
                break Vec::new();
            }
            self.registered_elsewhere(loss.key_n, &named).await?;
            loss.key_n = named.n();
            let record = self.sign_ops(
                vec![(
                    Vec::<Condition>::new(),
                    OpKind::AppPut {
                        record: self.state.record.clone(),
                    },
                )],
                None,
            )?;
            loss.batch = record.body().to_vec();
            let mut tx = self.tx()?;
            tx.put(keys::LOSS, &*loss)?;
            self.commit(tx).await?;
        };
        let mut tx = self.tx()?;
        if let Some(proof) = proofs.get(1)
            && let Some(held) = self.state.receive_keys.get_mut(&loss.key_n)
        {
            held.reg_seq = Some(proof.envelope().seq);
            held.reg_time_ms = Some(proof.envelope().server_time);
            tx.put(&key::receive_key(loss.key_n), held)?;
        }
        // Switch spec 12.6 "Residual risk": the offset between the two services' clocks,
        // from the last time each signed; twice the clock tolerance without one from the old.
        let new_key = self.state.meta.service_key;
        if let (Some(old), Some(new)) = (
            loss.old_offset_ms,
            self.state
                .service_time
                .filter(|time| time.key == new_key)
                .map(|time| time.offset_ms),
        ) {
            loss.clock_offset_ms = old.abs_diff(new);
        }
        loss.declared_at_ms = Some(self.recovery_time().await?);
        loss.batch.clear();
        self.commit(tx).await
    }

    /// The recovery record's time: the first item of the new sequence, checked against the
    /// chain view (Switch spec 12.6 step 1). Without one, the time of the latest answer.
    async fn recovery_time(&mut self) -> Result<u64, AppError> {
        let fallback = self.client.last_server_time().unwrap_or(0);
        let generation = self.state.meta.generation;
        let query = FeedQuery {
            after: Some(Position { generation, seq: 0 }),
            limit: Some(1),
            wait: None,
        };
        let result = self.client.feed(query).await;
        let page = self.take(result).await?;
        let now = self.now();
        let multi = self.state.device.multi_device;
        let Some(chain) = self.state.chain.as_mut() else {
            return Ok(fallback);
        };
        let checked = match chain.feed_page(&page, now, multi) {
            Ok(checked) => checked,
            Err(AppError::Alarm(alarm)) => return Err(self.raise(alarm).await),
            Err(error) => return Err(error),
        };
        let Some(FeedItem::Chain(item)) = page.items.first() else {
            return Ok(fallback);
        };
        let Some(envelope) = checked.envelopes.get(&item.seq) else {
            return Ok(fallback);
        };
        let bytes = item.item.doc_bytes()?;
        if item.item_type != ItemType::Service
            || Verifier::check_item(envelope, item.item_type, &bytes).is_err()
        {
            return Ok(fallback);
        }
        let identity = self.state.meta.identity;
        match ServiceTransition::verify(&item.item, &self.state.meta.service_key, &identity) {
            Ok(ServiceTransition::Recovery { at, .. }) => Ok(at),
            _ => Ok(fallback),
        }
    }

    /// Step 3: upload what the app holds, before its first record write at the new service
    /// (Switch wire 7.4.14). A refusal is reported and the recovery goes on.
    async fn loss_upload(&mut self, loss: &LossRecord) -> Result<(), AppError> {
        let (records, claims) = self.kept_ops().await?;
        let proofs = self.kept_proofs(None).await?;
        let heads: Vec<SignedHead> = match &loss.newest_head {
            Some(value) => vec![SignedHead::from_value(value).map_err(|_| corrupt())?],
            None => Vec::new(),
        };
        if records.is_empty() && claims.is_empty() && proofs.is_empty() && heads.is_empty() {
            return Ok(());
        }
        let upload = RecoveryUpload {
            lost_identity: self.generation_doc(loss.lost_generation).await?,
            records,
            claims,
            heads,
            proofs,
            lists: None,
        };
        self.upload_here(&upload).await
    }

    /// Step 2: the app's copy of the lists, as its permissions allow (Switch spec 12.6
    /// step 2).
    async fn loss_lists(&mut self) -> Result<(), AppError> {
        let manage = self.state.cert.has_permission(Permission::ListsManage);
        let read = self.state.cert.has_permission(Permission::ListsRead);
        if !manage && !read {
            return Ok(());
        }
        let copy = self.lists_copy().await?;
        // An app with `lists.manage` uploads its contacts even when it holds none: the
        // upload ends staged admission (Switch spec 12.6 step 2).
        let lists = UploadLists {
            contacts: manage.then_some(copy.contacts),
            deny: copy.deny,
        };
        if lists.contacts.is_none() && lists.deny.is_empty() {
            return Ok(());
        }
        let upload = RecoveryUpload {
            lists: Some(lists),
            ..RecoveryUpload::default()
        };
        self.upload_here(&upload).await
    }

    /// `POST /recovery/upload` at the service followed; its head goes to the chain view.
    async fn upload_here(&mut self, upload: &RecoveryUpload) -> Result<(), AppError> {
        let result = self.client.recovery_upload(upload, false).await;
        match self.take(result).await {
            Ok(answer) => {
                if let Some(head) = answer.head {
                    let proofs: Vec<TransitionProof> = answer.proof.iter().cloned().collect();
                    if let Err(alarm) = self.note_answer_head(head, &proofs) {
                        return Err(self.raise(alarm).await);
                    }
                }
                let heads = answer
                    .heads
                    .or_else(|| answer.result.as_ref().map(|changes| changes.heads));
                let proofs = answer.proofs.or(Some(u64::from(answer.proof.is_some())));
                self.uploaded(Ok((heads, proofs)))
            }
            Err(AppError::Switch(error)) => self.uploaded(Err(error)),
            Err(error) => Err(error),
        }
    }

    /// Step 2: the conversation entries added back, in batches signed once and kept until
    /// answered.
    async fn loss_conversations(&mut self, loss: &mut LossRecord) -> Result<(), AppError> {
        loop {
            if loss.batch.is_empty() {
                if loss.conversations.is_empty() {
                    return Ok(());
                }
                let take = loss.conversations.len().min(MAX_BATCH_ENTRIES);
                let ops = loss
                    .conversations
                    .iter()
                    .take(take)
                    .map(|who| {
                        pubky_key(who).map(|pubky| {
                            (
                                Vec::<Condition>::new(),
                                OpKind::AllowPut {
                                    pubky,
                                    kind: AllowKind::Conversation,
                                },
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| corrupt())?;
                let batch = self.sign_ops(ops, None)?;
                loss.batch = batch.body().to_vec();
                let mut tx = self.tx()?;
                tx.put(keys::LOSS, &*loss)?;
                self.commit(tx).await?;
            }
            let batch = Batch::from_body(loss.batch.clone())?;
            let sent = batch.ops().len();
            self.submit(&batch).await?;
            loss.conversations
                .drain(..sent.min(loss.conversations.len()));
            loss.batch.clear();
            let mut tx = self.tx()?;
            tx.put(keys::LOSS, &*loss)?;
            self.commit(tx).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loss() -> LossRecord {
        LossRecord {
            lost_generation: 1,
            generation: 2,
            step: LossStep::Resend,
            newest_head: None,
            cursor_time_ms: 5,
            declared_at_ms: Some(6),
            old_offset_ms: None,
            clock_offset_ms: 0,
            key_n: 1,
            batch: Vec::new(),
            conversations: Vec::new(),
            conversations_left_out: 0,
        }
    }

    #[test]
    fn test_loss_conversations_past_the_cap_are_counted_left_out() {
        let named: Vec<String> = (0..MAX_LOSS_CONVERSATIONS + 3)
            .rev()
            .map(|n| format!("{n:08}"))
            .chain(std::iter::once(format!("{:08}", 0)))
            .collect();
        let mut record = loss();
        record.keep_conversations(named);
        assert_eq!(record.conversations.len(), MAX_LOSS_CONVERSATIONS);
        assert_eq!(record.conversations_left_out, 3);
        // The first in key order, once each.
        assert_eq!(
            record.conversations.first().map(String::as_str),
            Some("00000000")
        );
        assert!(record.conversations.windows(2).all(|w| w[0] < w[1]));
        // Kept with the loss: the count reads back, and a record without it reads as none.
        let bytes = serde_json::to_vec(&record).unwrap();
        let read: LossRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(read.conversations_left_out, 3);
        let mut old: Value = serde_json::from_slice(&bytes).unwrap();
        old.as_object_mut()
            .unwrap()
            .remove("conversations_left_out");
        let old: LossRecord = serde_json::from_value(old).unwrap();
        assert_eq!(old.conversations_left_out, 0);
        // Within the cap, none is left out.
        record.keep_conversations(vec!["b".into(), "a".into(), "a".into()]);
        assert_eq!(record.conversations, ["a", "b"]);
        assert_eq!(record.conversations_left_out, 0);
    }
}
