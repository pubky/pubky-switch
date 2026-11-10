//! Steps 8 to 10 of a batch (Switch wire 6.4) over an [`OpsState`]: the conditions against the
//! state before the batch, then each operation's permission, shape, per-kind limits and own
//! rules against the state the earlier ones left, then the cursor. Pure: it changes the state
//! it is given, and the endpoint applies it to a copy it drops on a refusal.
//!
//! Every rule is the core's (`pubky_switch_core::ops`, `claims`, `shared`); this module
//! decides only what each rule is called with.

use pubky_switch_core::{
    chain::ProofState,
    claims::{EntryContext, apply_entry},
    ops::{
        AppPutEffect, CertPutEffect, KeyBundleEffect, Limits, List, OpKind, Position, Quota,
        ReceiveKeyEffect, Refusal, SignedOp, StateAfter, StoredPart, Writer, check_app_put,
        check_cert_put, check_conditions, check_cursor, check_invite_code_put,
        check_key_bundle_put, check_permission, check_quota, check_receive_key_put, check_shape,
        covers, invite_code_delete, proof_state,
    },
    records::{AppCert, AppRecord, ReceiveKeyRecord},
    scopes::Permission,
    shared::{RecordState, check_record_put},
    sig::SignedDoc,
};

use super::state::{Before, HeldInvite, HeldPart, HeldRecord, ListEntry, NewClaimEntry, OpsState};

/// A batch, as authenticated, to apply.
#[derive(Clone, Copy, Debug)]
pub struct Batch<'a> {
    /// Its signed operations, verified.
    pub ops: &'a [SignedOp],
    /// The certificate the writing app is checked against; `None` for the signer.
    pub writer: Option<&'a AppCert>,
    /// Its `cursor.set`, if any.
    pub cursor: Option<Position>,
    /// The `seq` its first operation takes.
    pub first_seq: u64,
    /// The per-kind limits.
    pub limits: &'a Limits,
}

/// What one operation left: the state its proof shows, and the app its chain item is shown
/// in full to, for a key bundle part (Switch wire 7.5).
#[derive(Clone, Debug, PartialEq)]
pub struct Applied {
    /// The proof's state.
    pub state: ProofState,
    /// The target app of a `key_bundle.put`.
    pub only_for: Option<[u8; 16]>,
}

/// Apply `batch` to `state` (Switch wire 6.4 steps 8 to 10). On a refusal `state` may be
/// partly changed: the caller drops it.
///
/// # Errors
///
/// The first refusal, by the order of steps 8 and 9, then a cursor that isn't one of the
/// account's positions (`400`).
pub fn apply(state: &mut OpsState, batch: &Batch<'_>) -> Result<Vec<Applied>, Refusal> {
    // Step 8: every condition, against the state before the batch.
    {
        let before = Before {
            state,
            writer: batch.writer,
        };
        for op in batch.ops {
            check_conditions(&op.body().conditions, &before)?;
        }
    }
    // Step 9: each operation against the state the earlier ones left.
    let writer = batch.writer.map_or(Writer::Signer, Writer::App);
    let mut applied = Vec::with_capacity(batch.ops.len());
    for (seq, op) in (batch.first_seq..).zip(batch.ops) {
        check_permission(&op.body().kind, writer)?;
        check_shape(op.body())?;
        let (after, only_for) = apply_op(state, batch, op, seq)?;
        let proof = proof_state(&op.body().kind, &after).map_err(Refusal::from)?;
        applied.push(Applied {
            state: proof,
            only_for,
        });
    }
    // Step 10: the cursor.
    if let Some(position) = batch.cursor {
        set_cursor(state, batch.writer, position)?;
    }
    Ok(applied)
}

/// `cursor.set` (Switch wire 6.2): the current generation, and a `seq` given out already.
fn set_cursor(
    state: &mut OpsState,
    writer: Option<&AppCert>,
    position: Position,
) -> Result<(), Refusal> {
    // `OpsRequest::check_caller` refuses a signer's cursor at step 4; a batch built
    // otherwise has no app whose cursor would move.
    let Some(cert) = writer else {
        return Err(Refusal::bad_request(
            "Switch wire 6.2: the signer's batch carries no cursor.set",
        ));
    };
    // No account continues another's sequence before cooperative moves are served.
    check_cursor(position, state.generation, None, state.newest_seq)?;
    // The cursor only moves forward: a position at or behind it leaves it where it is, and
    // isn't an error (Switch spec 8.3, Switch wire 6.2).
    let cursor = &mut state.apps.entry(cert.app_id()).or_default().cursor;
    if cursor.is_none_or(|current| position > current) {
        *cursor = Some(position);
    }
    Ok(())
}

fn writer_app<'a>(batch: &Batch<'a>) -> Result<&'a AppCert, Refusal> {
    // `check_permission` lets only apps write these.
    batch
        .writer
        .ok_or_else(|| Refusal::bad_request("Switch wire 6.2: for an app only"))
}

/// One operation's per-kind limits and own rules (Switch wire 6.2, 6.8, 9.3), against the
/// state the earlier operations left, which it changes.
fn apply_op(
    state: &mut OpsState,
    batch: &Batch<'_>,
    op: &SignedOp,
    seq: u64,
) -> Result<(StateAfter, Option<[u8; 16]>), Refusal> {
    let body = op.body();
    let now = state.now;
    let after = match &body.kind {
        OpKind::RecordPut(put) => {
            let cert = writer_app(batch)?;
            let held = state.records.get(&put.key);
            let key_live = held.is_some_and(|h| !h.state.deleted);
            let current_bytes = held.filter(|_| key_live).map_or(0, |h| h.value_bytes);
            let new_bytes = if put.value_sealed.looks_like_delete() {
                0
            } else {
                u64::try_from(put.value_sealed.ct.len()).unwrap_or(u64::MAX)
            };
            let (live_keys, stored_bytes) = state.record_usage();
            check_quota(
                &Quota::Record {
                    live_keys,
                    stored_bytes,
                    key_live,
                    current_bytes,
                    new_bytes,
                },
                batch.limits,
            )?;
            let view = state.record_view(&put.key);
            check_record_put(
                put,
                held.map(|h| &h.state),
                state.data_epoch(),
                cert.holds_scope(&put.policy.read_scope),
                view.as_ref(),
            )?;
            let record = RecordState::after(put, state.generation, seq);
            let version = record.version;
            state.records.insert(
                put.key,
                HeldRecord {
                    state: record,
                    value_bytes: new_bytes,
                    writer: cert.app_id(),
                    cert: cert.signed().clone(),
                    op: op.signed().clone(),
                    proof: None,
                },
            );
            StateAfter::Record(version)
        }
        OpKind::Claim(fields) => {
            let cert = writer_app(batch)?;
            let entry = fields.check()?;
            let writer = cert.app_id();
            let claim = {
                let current = |app: &[u8; 16]| state.is_current(app);
                let cx = EntryContext {
                    writer,
                    now,
                    can_read: cert.has_permission(Permission::ClaimsRead),
                    is_current: &current,
                    limits: batch.limits.claims,
                    tally: state.claim_tally(&writer),
                };
                let claim = apply_entry(state.claims.get(&entry.claim_key), &entry, &cx)?;
                let view = claim.view(&entry.claim_key, now, &current);
                (claim, view)
            };
            let (claim, view) = claim;
            state.claims.insert(entry.claim_key, claim);
            state.new_entries.push(NewClaimEntry {
                claim_key: entry.claim_key,
                step: fields.expected_step,
                seq,
                op: op.signed().clone(),
            });
            StateAfter::Claim(view)
        }
        OpKind::AllowPut { pubky, kind } => {
            let cert = writer_app(batch)?;
            let list = match kind {
                pubky_switch_core::ops::AllowKind::Contact => List::Contacts,
                pubky_switch_core::ops::AllowKind::Conversation => List::Conversations,
            };
            let entries = state.allow_list(*kind);
            let present = entries.contains_key(pubky);
            let total = match kind {
                pubky_switch_core::ops::AllowKind::Contact => state.totals.contacts,
                pubky_switch_core::ops::AllowKind::Conversation => state.totals.conversations,
            };
            check_quota(
                &Quota::List {
                    list,
                    entries: total.saturating_add(len(entries.len())),
                    present,
                },
                batch.limits,
            )?;
            state
                .allow_list_mut(*kind)
                .entry(*pubky)
                .or_insert(ListEntry {
                    written_by: cert.app_id(),
                    at: now,
                });
            StateAfter::Op
        }
        OpKind::AllowDelete { pubky, kind } => {
            state.allow_list_mut(*kind).remove(pubky);
            StateAfter::Op
        }
        OpKind::DenyPut { pubky } => {
            let cert = writer_app(batch)?;
            check_quota(
                &Quota::List {
                    list: List::Deny,
                    entries: state.totals.deny.saturating_add(len(state.deny.len())),
                    present: state.deny.contains_key(pubky),
                },
                batch.limits,
            )?;
            state.deny.entry(*pubky).or_insert(ListEntry {
                written_by: cert.app_id(),
                at: now,
            });
            StateAfter::Op
        }
        OpKind::DenyDelete { pubky } => {
            state.deny.remove(pubky);
            StateAfter::Op
        }
        OpKind::InviteCodePut(put) => {
            let cert = writer_app(batch)?;
            let held = state.invites.contains_key(&put.code_hash);
            check_quota(
                &Quota::InviteCode {
                    live: state.live_invites(),
                    held,
                },
                batch.limits,
            )?;
            check_invite_code_put(put, batch.limits.max_invite_uses, held)?;
            state.invites.insert(
                put.code_hash,
                HeldInvite {
                    max_uses: put.max_uses,
                    uses: 0,
                    writer: cert.app_id(),
                    expires_at: put.expires_at,
                    context: put.context.value().clone(),
                },
            );
            StateAfter::Op
        }
        OpKind::InviteCodeDelete { code_hash } => {
            invite_code_delete(state.invites.remove(code_hash).is_some())?;
            StateAfter::Op
        }
        OpKind::AppPut { record } => {
            let cert = writer_app(batch)?;
            app_put(state, cert.app_id(), record)?
        }
        OpKind::ReceiveKeyPut { record } => {
            let cert = writer_app(batch)?;
            receive_key_put(state, cert, record)?
        }
        OpKind::KeyBundlePut(put) => {
            let after = key_bundle_put(state, op, put, seq)?;
            return Ok((after, Some(put.target_app_id)));
        }
        OpKind::CertPut {
            target_app_id,
            cert,
        } => {
            cert_put(state, target_app_id, cert)?;
            StateAfter::Op
        }
    };
    Ok((after, None))
}

fn len(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// `app.put`, by [`check_app_put`]: a stored record moves the directory (Switch wire 7.4.10),
/// and drops a renewed certificate it now carries (Switch wire 3.8).
fn app_put(state: &mut OpsState, app: [u8; 16], record: &SignedDoc) -> Result<StateAfter, Refusal> {
    let new = AppRecord::verify(record, &state.identity).map_err(Refusal::from)?;
    let listed = state.doc.as_ref().and_then(|doc| doc.listed_cert(&app));
    let held = state.apps.get(&app).and_then(|a| a.record.as_ref());
    if check_app_put(&app, &new, listed, held)? != AppPutEffect::Unchanged {
        let now = state.now;
        let entry = state.apps.entry(app).or_default();
        if entry
            .renewed
            .as_ref()
            .is_some_and(|renewed| renewed.signed() == new.cert().signed())
        {
            entry.renewed = None;
        }
        entry.record = Some(new);
        entry.record_at = Some(now);
        state.directory_version = state.directory_version.saturating_add(1);
    }
    Ok(StateAfter::App { app_id: app })
}

/// `receive_key.put`, by [`check_receive_key_put`]. An unchanged one's proof shows the
/// current `n` and kid (Switch wire 6.4 "No-ops"). A stored key moves the directory, and an
/// app's first makes it reachable, which moves `apps_version` (Switch wire 7.4.10).
fn receive_key_put(
    state: &mut OpsState,
    cert: &AppCert,
    record: &SignedDoc,
) -> Result<StateAfter, Refusal> {
    let app = cert.app_id();
    let new = ReceiveKeyRecord::verify(record, cert).map_err(Refusal::from)?;
    let held = state.apps.get(&app);
    let current = held.and_then(|a| a.receive_key.as_ref());
    let effect = check_receive_key_put(
        &new,
        current,
        held.is_some_and(|a| a.record.is_some()),
        state.recovering,
        state.kids.contains(&new.kid()),
    )?;
    let shown = match (effect, current) {
        (ReceiveKeyEffect::Unchanged, Some(current)) => current.clone(),
        _ => {
            let first = current.is_none();
            state.kids.insert(new.kid());
            state.directory_version = state.directory_version.saturating_add(1);
            if first {
                state.apps_version = state.apps_version.saturating_add(1);
            }
            let apps_version = state.apps_version;
            let entry = state.apps.entry(app).or_default();
            if first {
                entry.reachable_since = Some(apps_version);
            }
            entry.receive_key = Some(new.clone());
            state.new_receive_keys.push((app, new.clone()));
            new
        }
    };
    Ok(StateAfter::ReceiveKey {
        n: shown.n(),
        kid: shown.kid(),
    })
}

/// `key_bundle.put`, by [`check_key_bundle_put`]. A pending full-bundle request ends once the
/// stored parts cover every data epoch from 1 to the current one (Switch wire 6.2).
fn key_bundle_put(
    state: &mut OpsState,
    op: &SignedOp,
    put: &pubky_switch_core::ops::KeyBundlePut,
    seq: u64,
) -> Result<StateAfter, Refusal> {
    let target = put.target_app_id;
    let current = state.is_current(&target);
    let epoch = state.data_epoch();
    let parts = state.parts.entry(target).or_default();
    let stored: Vec<_> = parts.iter().map(|part| part.put.clone()).collect();
    let bundle_seq = match check_key_bundle_put(put, current, &stored)? {
        KeyBundleEffect::Unchanged => parts
            .iter()
            .find(|part| &part.put == put)
            .map_or(seq, |part| part.seq),
        KeyBundleEffect::Stores { replaces } => {
            let mut index = 0;
            parts.retain(|_| {
                let keep = !replaces.contains(&index);
                index += 1;
                keep
            });
            parts.push(HeldPart {
                put: put.clone(),
                seq,
                op: op.signed().clone(),
            });
            parts.sort_by_key(|part| part.put.first_epoch);
            let spans: Vec<StoredPart> = parts
                .iter()
                .map(|part| StoredPart {
                    first_epoch: part.put.first_epoch,
                    last_epoch: part.put.last_epoch,
                    seq: part.seq,
                })
                .collect();
            if covers(&spans, epoch)
                && let Some(app) = state.apps.get_mut(&target)
            {
                app.full_requested = None;
            }
            seq
        }
    };
    Ok(StateAfter::KeyBundle { bundle_seq })
}

/// `cert.put`, by [`check_cert_put`].
fn cert_put(state: &mut OpsState, target: &[u8; 16], cert: &SignedDoc) -> Result<(), Refusal> {
    let renewed = AppCert::verify(cert, &state.identity).map_err(Refusal::from)?;
    let active = !state.kept.contains(target);
    let held = state.apps.entry(*target).or_default();
    let record_cert = held.record.as_ref().map(AppRecord::cert);
    if check_cert_put(&renewed, record_cert, active, held.renewed.as_ref())?
        == CertPutEffect::Stores
    {
        held.renewed = Some(renewed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::batch::state::{HeldApp, Needs};
    use pubky_switch_core::{
        claims::{Claim, ClaimTally},
        ops::{Condition, OpKind},
    };
    use serde_json::Value;

    fn chain() -> Value {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/vectors/chain.json");
        serde_json::from_slice(&std::fs::read(path).expect("chain.json")).expect("json")
    }

    fn op(chain: &Value, index: usize) -> SignedOp {
        let signed: SignedDoc =
            serde_json::from_value(chain["items"][index]["item"].clone()).expect("op");
        SignedOp::peek(&signed).expect("op")
    }

    /// The wallet's record, from `chain.json`'s `app.put`.
    fn wallet(chain: &Value) -> AppRecord {
        let app_put = op(chain, 2);
        let OpKind::AppPut { record } = &app_put.body().kind else {
            panic!("not an app.put");
        };
        AppRecord::verify(record, &app_put.body().identity).expect("record")
    }

    #[test]
    fn test_batch_needs_names_what_the_batch_touches() {
        let chain = chain();
        // Seq 7's claim, conditioned on the record seq 8 updates.
        let ops = [op(&chain, 5), op(&chain, 6)];
        let needs = Needs::of(&ops);
        assert_eq!(needs.records.len(), 1);
        assert_eq!(needs.claims.len(), 1);
        assert!(needs.pubkys.is_empty() && needs.invites.is_empty() && needs.targets.is_empty());
        let OpKind::RecordPut(put) = &ops[1].body().kind else {
            panic!("not a record.put");
        };
        assert!(needs.records.contains(&put.key));
        assert!(matches!(
            ops[0].body().conditions.first(),
            Some(Condition::RecordVersion { key, .. }) if key == &put.key
        ));
    }

    #[test]
    fn test_batch_totals_count_the_rest_of_the_account() {
        let mut state = OpsState::new([1; 32], 1, 4, 1_000);
        state.totals.claims = ClaimTally {
            claims: 10,
            created_by_writer: 2,
            open_attempts_of_writer: 1,
        };
        let writer = [5; 16];
        state.claims.insert(
            [9; 32],
            Claim {
                creator: Some(writer),
                ..Claim::default()
            },
        );
        assert_eq!(
            state.claim_tally(&writer),
            ClaimTally {
                claims: 11,
                created_by_writer: 3,
                open_attempts_of_writer: 1,
            }
        );
        state.totals.live_invites = 3;
        state.invites.insert(
            [1; 32],
            HeldInvite {
                max_uses: 1,
                uses: 0,
                writer,
                expires_at: 2_000,
                context: Value::Null,
            },
        );
        state.invites.insert(
            [2; 32],
            HeldInvite {
                max_uses: 1,
                uses: 0,
                writer,
                expires_at: 1_000,
                context: Value::Null,
            },
        );
        assert_eq!(state.live_invites(), 4, "the expired code doesn't count");
        assert_eq!(state.record_usage(), (0, 0));
    }

    #[test]
    fn test_batch_cursor_is_for_apps_and_reached_positions() {
        let chain = chain();
        let record = wallet(&chain);
        let cert = record.cert().clone();
        let limits = Limits::default();
        let mut state = OpsState::new(cert.identity(), 1, 4, 1_000);
        state.apps.insert(
            cert.app_id(),
            HeldApp {
                record: Some(record),
                ..HeldApp::default()
            },
        );
        let batch = |writer, seq| Batch {
            ops: &[],
            writer,
            cursor: Some(Position { generation: 1, seq }),
            first_seq: 5,
            limits: &limits,
        };
        assert_eq!(
            apply(&mut state.clone(), &batch(None, 1))
                .expect_err("signer")
                .status(),
            400
        );
        assert_eq!(
            apply(&mut state.clone(), &batch(Some(&cert), 5))
                .expect_err("unreached")
                .status(),
            400
        );
        apply(&mut state, &batch(Some(&cert), 4)).expect("cursor");
        assert_eq!(
            state.apps[&cert.app_id()].cursor,
            Some(Position {
                generation: 1,
                seq: 4
            })
        );
        // Nothing else moved.
        assert_eq!(state.directory_version, 0);
    }
}
