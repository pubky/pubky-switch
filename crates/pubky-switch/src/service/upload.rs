//! `POST /v1/{id}/recovery/upload` after a provider loss (Switch wire 7.4.14, Switch spec
//! 12.6 steps 2 and 3): an own app's evidence merged into what the account holds, and the
//! `upload` transition that lists what it changed.
//!
//! The body and every item are judged by the core ([`check_upload`]), the scripted switch
//! sharing the same checks; here the merge is applied to the stored state, in the account's
//! transaction: records, then claims, then lists, then staged admission, then the
//! transition. Uploads in a cooperative move aren't served yet.

use std::collections::{BTreeSet, HashMap, HashSet};

use pubky_switch_core::chain::ServiceTransition;
use pubky_switch_core::ops::{OpKind, SignedOp};
use pubky_switch_core::records::{AppCert, IdentityDoc, RemovedApp};
use pubky_switch_core::recovery::{
    CheckedRecord, CheckedUpload, HeldRecord, RecordMerge, UploadBody, UploadChanges,
    UploadContext, UploadLists, UploadVersion, check_upload, merge_checked_record,
    merge_upload_claim,
};
use pubky_switch_core::shared::RecordState;
use serde_json::json;

use super::batch::{VerifiedApp, check_own_app};
use super::recovery::{AdmissionEnd, chain_transition};
use super::{Answer, Service, batch::refused, store_error};
use crate::{
    http::error::ApiError,
    keys::ServiceSigner,
    store::{AccountTxn, ListName, RecordOrigin, StoreError, StoredListEntry, StoredRecord},
};

fn temporary() -> ApiError {
    ApiError::unavailable("7.6: a temporary failure")
}

/// The record at a key as the merge compares it: the hashes of its kept divergent uploads,
/// and, for one taken from an upload, its operation's hash and what it built on.
struct Held {
    record: Option<StoredRecord>,
    divergent: Vec<[u8; 32]>,
    /// For a record taken from an upload: its operation's `doc_hash` and `expected_version`.
    uploaded: Option<([u8; 32], pubky_switch_core::ops::RecordVersion)>,
}

impl Held {
    fn of(record: Option<StoredRecord>, divergent: Vec<[u8; 32]>) -> Result<Self, ApiError> {
        let uploaded = match &record {
            Some(
                stored @ StoredRecord {
                    origin: RecordOrigin::Uploaded { .. },
                    ..
                },
            ) => {
                // A record the account stored from an upload reads back; one that doesn't is
                // corrupt storage, a temporary failure.
                let op = SignedOp::peek(&stored.op).map_err(|_| temporary())?;
                let OpKind::RecordPut(put) = &op.body().kind else {
                    return Err(temporary());
                };
                let hash = stored.op.doc_hash().map_err(|_| temporary())?;
                Some((hash, put.expected_version))
            }
            _ => None,
        };
        Ok(Self {
            record,
            divergent,
            uploaded,
        })
    }

    fn view(&self) -> HeldRecord<'_> {
        match (&self.record, self.uploaded) {
            (None, _) => HeldRecord::Lacking,
            (Some(stored), Some((op_hash, built_on))) => HeldRecord::FromUpload {
                op_hash,
                built_on,
                version: UploadVersion {
                    version: stored.state.version,
                    exact: matches!(stored.origin, RecordOrigin::Uploaded { exact: true, .. }),
                },
                divergent: &self.divergent,
            },
            (Some(stored), None) => HeldRecord::WrittenHere {
                upload_base: match &stored.origin {
                    RecordOrigin::Written { upload_base, .. } => *upload_base,
                    RecordOrigin::Uploaded { .. } => None,
                },
                divergent: &self.divergent,
            },
        }
    }
}

/// The record an upload fills in or replaces, taken at the `upload` transition's `seq`.
fn taken(record: &CheckedRecord, seq: u64) -> StoredRecord {
    let put = &record.put;
    let deleted = put.value_sealed.looks_like_delete();
    StoredRecord {
        state: RecordState {
            key: put.key,
            collection: put.collection,
            policy: put.policy.clone(),
            version: record.uploaded.version.version,
            deleted,
        },
        value_bytes: if deleted {
            0
        } else {
            u64::try_from(put.value_sealed.ct.len()).unwrap_or(u64::MAX)
        },
        writer: record.writer,
        cert: record.cert.clone(),
        op: record.op.clone(),
        origin: RecordOrigin::Uploaded {
            seq,
            exact: record.uploaded.version.exact,
        },
        divergent: false,
    }
}

/// A recovery upload's items judged before the account's lock, and what they were judged
/// against: the endpoint takes the judgment only if both are unchanged under the lock.
pub(super) struct Prechecked {
    recovery_from: u64,
    removed: Vec<RemovedApp>,
    checked: CheckedUpload,
}

/// What a recovery upload settled before the account's lock: its slot of
/// `uploads_per_app_per_hour` (the seconds to wait when it got none), and its items judged,
/// when they could be.
pub(super) struct PreparedUpload {
    rate: Result<(), u64>,
    prechecked: Option<Prechecked>,
}

/// The `(account, app)` whose upload's items are being judged before the lock: one at a time
/// for each, removed when the judgment ends.
struct Judging<'a> {
    set: &'a parking_lot::Mutex<std::collections::HashSet<(String, [u8; 16])>>,
    key: (String, [u8; 16]),
}

impl<'a> Judging<'a> {
    /// Enter the judgment of `key`; `None` while another of its uploads is judged.
    fn enter(
        set: &'a parking_lot::Mutex<std::collections::HashSet<(String, [u8; 16])>>,
        key: (String, [u8; 16]),
    ) -> Option<Self> {
        // The set's lock ends with this statement, before a guard is made: dropping one
        // takes it again.
        let entered = set.lock().insert(key.clone());
        entered.then(|| Self { set, key })
    }
}

impl Drop for Judging<'_> {
    fn drop(&mut self) {
        self.set.lock().remove(&self.key);
    }
}

impl Service {
    /// What a recovery upload from the own app `verified` settles before the account's lock,
    /// at `time_ms` (Switch wire 7.4.14, 9.4). First its slot of `uploads_per_app_per_hour`,
    /// taken by every upload that verifies, a refused one included, so the hourly limit
    /// bounds the judgments too; then, with a slot, its items judged, at most one upload of
    /// each app of each account at a time: one sent while another is judged gets no slot
    /// (`429`, a second to wait). Every refusal is answered under the lock, in the wire's
    /// order.
    pub(super) async fn prepare_upload(
        &self,
        account: &str,
        verified: &VerifiedApp,
        body: &[u8],
        time_ms: u64,
    ) -> PreparedUpload {
        let key = (account.to_owned(), verified.app_id());
        let rate =
            self.upload_rate
                .take(key.clone(), self.limits.uploads_per_app_per_hour, time_ms);
        if rate.is_err() {
            return PreparedUpload {
                rate,
                prechecked: None,
            };
        }
        let Some(_judging) = Judging::enter(&self.upload_judging, key) else {
            return PreparedUpload {
                rate: Err(1),
                prechecked: None,
            };
        };
        PreparedUpload {
            rate,
            prechecked: self.precheck_upload(account, verified, body, time_ms).await,
        }
    }

    /// Judge a recovery upload's items before the account's lock, off the async threads:
    /// their signature work needs only the lost generation and the apps the held
    /// `identity.json` lists as removed, which are read without the lock. Only for an upload
    /// the endpoint would take: its app current with an unexpired certificate, its body read
    /// and its lists ones it may send, all checked here again as under the lock. `None`
    /// otherwise, or when the account is in no loss's generation: the endpoint answers it.
    async fn precheck_upload(
        &self,
        account: &str,
        verified: &VerifiedApp,
        body: &[u8],
        time_ms: u64,
    ) -> Option<Prechecked> {
        let identity = pubky_switch_core::enc::pubky_key(account).ok()?;
        let (doc, row, kept) = self
            .store
            .own_app_view(account, &verified.app_id())
            .await
            .ok()??;
        let held = match doc {
            Some(doc) => Some(IdentityDoc::verify(&doc, &identity).ok()?),
            None => None,
        };
        let cert = check_own_app(
            &identity,
            held.as_ref(),
            row.as_ref(),
            kept,
            verified,
            time_ms,
        )
        .ok()?;
        let upload = UploadBody::parse(body).ok()?;
        upload.check_permissions(&cert).ok()?;
        let recovery_from = self.store.recovery_from_of(account).await.ok()??;
        let removed = held
            .map(|doc| doc.body().removed.clone())
            .unwrap_or_default();
        let judged = removed.clone();
        let checked = tokio::task::spawn_blocking(move || {
            let cx = UploadContext {
                identity: &identity,
                recovery_from,
                removed: &judged,
            };
            check_upload(&upload, &cx)
        })
        .await
        .ok()?;
        Some(Prechecked {
            recovery_from,
            removed,
            checked,
        })
    }

    /// `POST /v1/{id}/recovery/upload` from the own app `caller` (Switch wire 7.4.14), at a
    /// serving account: `404` at one in neither stage; after a provider loss, `400` for a
    /// body that doesn't read, `403 permission_missing` for lists the caller may not send,
    /// `429 rate_limited` past `uploads_per_app_per_hour`, else the merge, one `upload`
    /// transition, and `{ result, proof, head }`. `held` is the account's newest
    /// `identity.json`, whose `removed` judges removed apps' operations. `prepared` is what
    /// the upload settled before the lock: its rate slot, answered `429` here in the wire's
    /// order, and its items judged, taken when their `recovery_from` and `removed` are the
    /// ones read here; otherwise the items are judged here.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn recovery_upload(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        held: Option<&IdentityDoc>,
        caller: &AppCert,
        body: &[u8],
        prepared: Option<&PreparedUpload>,
        time_ms: u64,
    ) -> Result<Answer, ApiError> {
        let Some(recovery) = txn.recovery().await.map_err(|e| store_error(&e))? else {
            return Err(ApiError::not_found(
                "7.4.14: neither after a provider loss nor in a move",
            ));
        };
        let upload = UploadBody::parse(body).map_err(refused)?;
        upload.check_permissions(caller).map_err(refused)?;
        let by = caller.app_id();
        // The slot was taken before the lock; an upload that settled nothing there takes it
        // here.
        let rate = match prepared {
            Some(prepared) => prepared.rate,
            None => self.upload_rate.take(
                (txn.head().id.clone(), by),
                self.limits.uploads_per_app_per_hour,
                time_ms,
            ),
        };
        rate.map_err(|retry| ApiError::rate_limited("9.4: recovery uploads from this app", retry))?;
        let prechecked = prepared.and_then(|prepared| prepared.prechecked.as_ref());
        let identity = txn.head().identity_key;
        let removed = held.map_or(&[][..], |doc| doc.body().removed.as_slice());
        let judged_here;
        let checked = match prechecked.filter(|pre| {
            pre.recovery_from == recovery.recovery_from && pre.removed.as_slice() == removed
        }) {
            Some(pre) => &pre.checked,
            None => {
                let cx = UploadContext {
                    identity: &identity,
                    recovery_from: recovery.recovery_from,
                    removed,
                };
                judged_here = check_upload(&upload, &cx);
                &judged_here
            }
        };
        // The transition's `seq`, given out first: a record taken from the upload is at it.
        let seq = txn.next_seq().map_err(|e| store_error(&e))?;
        let mut changes = UploadChanges {
            unverified: checked.unverified,
            distrusted: checked.distrusted,
            heads: checked.heads,
            ..UploadChanges::default()
        };
        let stored = |e: StoreError| store_error(&e);
        self.merge_records(txn, &checked.records, seq, &mut changes)
            .await?;
        self.merge_claims(txn, checked, time_ms, &mut changes)
            .await
            .map_err(stored)?;
        if let Some(lists) = &upload.lists {
            changes.lists = self
                .merge_lists(txn, lists, by, time_ms)
                .await
                .map_err(stored)?;
        }
        // Checked here, as `end_staged_admission` takes it: contacts, from an app holding
        // `lists.manage` (Switch spec 12.6 step 2).
        if upload.ends_staged_admission(caller) {
            self.end_staged_admission(txn, signer, AdmissionEnd::Upload { by }, time_ms)
                .await?;
        }
        let transition = ServiceTransition::Upload {
            by,
            changes: changes.to_value(),
            proofs: checked.proofs,
            at: time_ms,
        };
        let proof = chain_transition(txn, signer, &transition, seq, time_ms).await?;
        let head = self.head(txn, signer).await.ok_or_else(temporary)?;
        let body = json!({
            "result": changes.to_value(),
            "proof": proof,
            "head": head.to_value(),
        });
        let body = serde_json::to_vec(&body).map_err(|_| temporary())?;
        Ok(Answer::ok(body).with_head(Some(head)))
    }

    /// The upload's records, in upload order, against what the account holds (Switch wire
    /// 7.4.14 "Records"): filled in, replaced or made exact at `seq`, or kept as divergent.
    async fn merge_records(
        &self,
        txn: &mut AccountTxn,
        records: &[CheckedRecord],
        seq: u64,
        changes: &mut UploadChanges,
    ) -> Result<(), ApiError> {
        let stored = |e: StoreError| store_error(&e);
        let keys: Vec<[u8; 32]> = records
            .iter()
            .map(|r| r.put.key)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut held: HashMap<[u8; 32], Held> = HashMap::new();
        for record in txn.records(&keys).await.map_err(stored)? {
            let key = record.state.key;
            let divergent = txn.divergent_uploads(&key).await.map_err(stored)?;
            let hashes = divergent.into_iter().map(|d| d.op_hash).collect();
            held.insert(key, Held::of(Some(record), hashes)?);
        }
        let max = usize::try_from(self.limits.max_divergent_uploads).unwrap_or(usize::MAX);
        for record in records {
            let key = record.put.key;
            let at = held.entry(key).or_insert(Held {
                record: None,
                divergent: Vec::new(),
                uploaded: None,
            });
            let state = at.record.as_ref().map(|r| &r.state);
            match merge_checked_record(&at.view(), state, record, max) {
                RecordMerge::Fill | RecordMerge::Replace | RecordMerge::MakeExact => {
                    let new = taken(record, seq);
                    txn.put_record(&new).await.map_err(stored)?;
                    *at = Held::of(Some(new), std::mem::take(&mut at.divergent))?;
                    changes.record(key);
                }
                RecordMerge::Divergent { kept } => {
                    if kept {
                        let hash = record.uploaded.op_hash;
                        txn.add_divergent_upload(&key, &record.op, &hash)
                            .await
                            .map_err(stored)?;
                        at.divergent.push(hash);
                    }
                    changes.divergent_record(key);
                }
                RecordMerge::Unchanged => {}
            }
        }
        Ok(())
    }

    /// The upload's claim entries and SETTLED proofs, by claim key (Switch wire 7.4.14 "How a
    /// claim merges").
    async fn merge_claims(
        &self,
        txn: &mut AccountTxn,
        checked: &CheckedUpload,
        time_ms: u64,
        changes: &mut UploadChanges,
    ) -> Result<(), StoreError> {
        let keys: Vec<[u8; 32]> = checked
            .claims
            .keys()
            .chain(checked.settled.keys())
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let held: HashMap<_, _> = txn.claims(&keys).await?.into_iter().collect();
        for key in keys {
            let entries = checked.claims.get(&key).map_or(&[][..], Vec::as_slice);
            let merge = merge_upload_claim(
                held.get(&key),
                checked.settled.get(&key),
                entries,
                time_ms,
                self.limits.max_attempts_per_claim,
            );
            if merge.changed
                && let Some(claim) = &merge.claim
            {
                txn.put_claim(&key, claim).await?;
            }
            changes.claim(key, &merge);
        }
        Ok(())
    }

    /// The upload's lists added to what the account holds, never removed from it, each up to
    /// its limit (Switch wire 7.4.14 "Lists"): whether an entry was added.
    async fn merge_lists(
        &self,
        txn: &mut AccountTxn,
        lists: &UploadLists,
        by: [u8; 16],
        time_ms: u64,
    ) -> Result<bool, StoreError> {
        let mut added = false;
        for (list, entries, max) in [
            (ListName::Contact, &lists.contacts, self.limits.max_contacts),
            (ListName::Deny, &lists.deny, self.limits.max_deny),
        ] {
            let Some(entries) = entries else { continue };
            let unique: Vec<[u8; 32]> = entries
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let present: HashSet<[u8; 32]> = txn
                .list_entries(list, &unique)
                .await?
                .into_iter()
                .map(|entry| entry.pubky)
                .collect();
            let mut count = txn.list_count(list, &[]).await?;
            for pubky in unique.iter().filter(|p| !present.contains(*p)) {
                if count >= max {
                    break;
                }
                let entry = StoredListEntry {
                    pubky: *pubky,
                    written_by: Some(by),
                    at_ms: time_ms,
                };
                txn.put_list_entry(list, &entry).await?;
                count += 1;
                added = true;
            }
        }
        Ok(added)
    }
}
