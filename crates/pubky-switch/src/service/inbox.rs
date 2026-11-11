//! `POST /v1/{id}/inbox` (Switch wire 7.4.3): an envelope kept for its target apps, which
//! read it in their feed. The service reads only the envelope's header: the receive keys it
//! is wrapped to. It never holds the keys that open it.
//!
//! The checks run in 7.4.3's order: a retry by content, admission and the sender's listing,
//! size and header, the rates, the targets, the quota, then the invite code's use.

use std::collections::{BTreeMap, BTreeSet};

use pubky_switch_core::{
    chain::{ItemType, ServiceTransition, item_hash},
    enc::{b64, hash, zbase32_encode},
    envelope::check_at_inbox,
    error::SizeRefusal,
    records::{AppCert, IdentityDoc, Standing},
    time::rfc3339,
};
use serde_json::{Value, json};

use super::{
    Answer, Service,
    admission::{Admitted, NOT_ADMITTED, admit},
    store_error,
};
use crate::{
    http::error::{ApiError, ErrorCode},
    keys::ServiceSigner,
    store::{AccountTxn, ListName, NewChainItem, NewEntry},
};

/// Who appends.
#[derive(Clone, Copy, Debug)]
pub(super) enum Appender<'a> {
    /// An own app, by the certificate it is checked against.
    OwnApp(&'a AppCert),
    /// An app of another identity, verified with the certificate it sent.
    OtherApp(&'a AppCert),
}

fn temporary() -> ApiError {
    ApiError::unavailable("7.6: a temporary failure")
}

fn not_admitted() -> ApiError {
    ApiError::new(ErrorCode::NotAdmitted, NOT_ADMITTED)
}

/// `409 identity_needed`, with the version of the sender's `identity.json` the service
/// holds, `null` for none or as to a stranger (Switch wire 7.6).
fn identity_needed(version: Option<u64>) -> ApiError {
    let mut error = ApiError::new(
        ErrorCode::IdentityNeeded,
        "7.4.3: the service's copy of the sender's identity.json doesn't list the app",
    )
    .with_current(json!({ "version": version }));
    error.known_version = Some(version);
    error
}

/// The append's answer, `{ entry_id, accepted_at, directory_version }`, in the order of
/// 7.4.3's table; `known_version` is added for an app of another identity.
fn stored_answer(entry_id: &[u8; 16], accepted_at: u64, directory_version: u64) -> Vec<u8> {
    format!(
        "{{\"entry_id\":\"{}\",\"accepted_at\":\"{}\",\"directory_version\":{}}}",
        b64(entry_id),
        rfc3339(accepted_at),
        directory_version
    )
    .into_bytes()
}

/// An answer with `known_version` added at its end, for an app of another identity.
fn with_known_version(stored: &[u8], known: Option<u64>) -> Vec<u8> {
    let mut body = stored.to_vec();
    if body.last() == Some(&b'}') {
        body.pop();
        body.extend_from_slice(b",\"known_version\":");
        body.extend_from_slice(
            match known {
                Some(version) => version.to_string().into_bytes(),
                None => b"null".to_vec(),
            }
            .as_slice(),
        );
        body.push(b'}');
    }
    body
}

impl Service {
    /// `POST /v1/{id}/inbox` (Switch wire 7.4.3) under the lock, from `appender`, with the
    /// account's newest `identity.json` `held`; `trusted` says whether the service has trusted
    /// time, which an invite code's expiry needs (7.3).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn append(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        held: Option<&IdentityDoc>,
        appender: Appender<'_>,
        envelope: &[u8],
        query: &BTreeMap<String, String>,
        invite_code: Option<&str>,
        trusted: bool,
        time_ms: u64,
    ) -> Result<Answer, ApiError> {
        let account = txn.head().clone();
        let (sender, cert, other) = match appender {
            Appender::OwnApp(cert) => (account.identity_key, cert, false),
            Appender::OtherApp(cert) => (cert.identity(), cert, true),
        };
        let sender_app = cert.app_id();

        // Check 1: a retry by content gets the stored answer, before any other check, the
        // query's included.
        let envelope_hash = hash(envelope);
        if let Some(stored) = txn
            .appended_answer(&sender, &envelope_hash)
            .await
            .map_err(|e| store_error(&e))?
        {
            return self.answer(txn, signer, stored, other).await;
        }
        let sealed_for = query
            .get("apps_version")
            .and_then(|text| {
                (!text.is_empty() && text.len() <= 16 && text.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| text.parse::<u64>().ok())
                    .flatten()
            })
            .ok_or_else(|| ApiError::bad_request("7.4.3: apps_version is required"))?;

        // Check 2: admission and the listing, for an app of another identity.
        let mut by_code = None;
        let mut known = None;
        if other {
            // Read from its own column, not the document: a refusal costs the same whether
            // or not a copy is held.
            let removed = txn
                .peer_lists_removed(&sender, &sender_app)
                .await
                .map_err(|e| store_error(&e))?;
            let standing = self.standing(txn, &sender).await?;
            let listed =
                !standing.denied && !removed && (standing.contact || standing.conversation);
            let invite = if listed {
                None
            } else {
                self.live_invite(txn, invite_code, time_ms).await?
            };
            // A stranger can't write at all: connect requests admit nobody to the inbox.
            match admit(standing, removed, invite, false).ok_or_else(not_admitted)? {
                Admitted::Listed => {}
                Admitted::InviteCode(code) => {
                    if !trusted {
                        return Err(ApiError::unavailable(
                            "7.3: an invite code's expiry needs trusted time",
                        ));
                    }
                    by_code = Some(code);
                }
                Admitted::ConnectRequests => return Err(not_admitted()),
            }
            // A removed app is answered like a stranger with no copy held (Switch wire 7.2).
            if removed {
                return Err(identity_needed(None));
            }
            // The held copy is read and verified only once the sender is admitted.
            let copy = txn.peer_copy(&sender).await.map_err(|e| store_error(&e))?;
            let copy = copy
                .as_ref()
                .map(|held| IdentityDoc::verify_named(&held.doc))
                .transpose()
                .map_err(|_| temporary())?;
            match copy
                .as_ref()
                .map(|doc| doc.standing(&sender_app, &cert.hash()))
            {
                Some(Standing::Listed | Standing::RenewedOpen) => {}
                Some(Standing::RenewedClosed { .. }) => {
                    return Err(ApiError::new(
                        ErrorCode::NotCurrent,
                        "3.8: the certificate's renewal has closed",
                    ));
                }
                _ => return Err(identity_needed(copy.as_ref().map(IdentityDoc::version))),
            }
            known = copy.as_ref().map(IdentityDoc::version);
        }

        // Check 3: size and header (Switch wire 4.4).
        let header = check_at_inbox(envelope).map_err(|refusal| match refusal {
            SizeRefusal::TooLarge(_) => {
                ApiError::new(ErrorCode::TooLarge, "4.4: the envelope is over 64 KiB")
            }
            SizeRefusal::BadRequest(_) => {
                ApiError::bad_request("4.4: the envelope's size or header isn't valid")
            }
        })?;

        // Check 4: the rates, each refusal a hit against a sender of another identity
        // (Switch wire 9.4): flags let apps offer to block a sender, and the account's own
        // identity is none.
        let limited = |txn: &mut AccountTxn, result: Result<(), u64>, what: &str| {
            result.map_err(|retry_after| {
                if other {
                    txn.note_flag_hit(sender, self.limits.max_flags);
                }
                ApiError::rate_limited(format!("9.4: {what}"), retry_after)
            })
        };
        let taken = self.sender_rate.take(
            (account.id.clone(), sender),
            self.limits.sender_per_min,
            time_ms,
        );
        limited(txn, taken, "appends from this sender identity")?;
        if other {
            let taken = self.sender_app_rate.take(
                (account.id.clone(), sender_app),
                self.limits.sender_app_per_min,
                time_ms,
            );
            limited(txn, taken, "appends from this sender app")?;
        }
        if header.notify {
            let taken = self.notify_rate.take(
                (account.id.clone(), sender),
                self.limits.notify_per_min,
                time_ms,
            );
            limited(txn, taken, "notifying appends from this sender identity")?;
        }

        // Check 5: every kid the current receive key of a current app, and every app added
        // since `apps_version` among the targets.
        let targets = self
            .targets(
                txn,
                held,
                &header,
                sealed_for,
                (!other).then_some(sender_app),
                time_ms,
            )
            .await?;

        // Check 6: the inbox quota, then the sender's share of it (Switch wire 9.3).
        let quota_bytes = u64::try_from(envelope.len())
            .unwrap_or(u64::MAX)
            .saturating_add(self.limits.entry_overhead_bytes);
        let usage = txn
            .inbox_usage(&sender)
            .await
            .map_err(|e| store_error(&e))?;
        if usage.total.saturating_add(quota_bytes) > self.limits.quota_bytes {
            return Err(ApiError::quota_exceeded("inbox", "6.3: the inbox is full"));
        }
        let share = self
            .limits
            .quota_bytes
            .saturating_mul(u64::from(self.limits.sender_share_percent))
            / 100;
        if usage.sender.saturating_add(quota_bytes) > share {
            return Err(ApiError::quota_exceeded(
                "sender_share",
                "6.3: the sender holds its share of the inbox",
            ));
        }

        // Check 7: an invite code that admitted the sender is used, atomically with the
        // append, and the service writes the sender's conversation entry and chains it.
        let mut context = None;
        if let Some(code) = by_code {
            context = Some(
                self.use_invite(txn, signer, &code, &sender, time_ms)
                    .await?,
            );
        } else if other {
            txn.note_conversation_used(&sender, time_ms)
                .await
                .map_err(|e| store_error(&e))?;
        }

        let seq = txn.next_seq().map_err(|e| store_error(&e))?;
        let entry_id = (self.entry_ids)();
        let (directory_version, _) = txn
            .directory_versions()
            .await
            .map_err(|e| store_error(&e))?;
        // The whole answer is stored, `known_version` as it is now: a retry gets this
        // original answer (check 1), so an app that is removed later learns nothing new.
        let mut stored = stored_answer(&entry_id, time_ms, directory_version);
        if other {
            stored = with_known_version(&stored, known);
        }
        txn.add_entry(&NewEntry {
            seq,
            entry_id,
            sender,
            sender_app,
            cert: cert.signed(),
            accepted_at_ms: time_ms,
            envelope,
            envelope_hash,
            targets: &targets,
            context: context.as_deref(),
            answer: &stored,
            quota_bytes,
        })
        .await
        .map_err(|e| store_error(&e))?;
        // An append brings the pressure lagging marks answer, with trusted time (Switch wire
        // 7.4.4).
        if trusted {
            let current = super::batch::load_apps(txn, held, time_ms)
                .await
                .map_err(|e| store_error(&e))?
                .current_app_ids();
            self.release(true)
                .mark(txn, &current)
                .await
                .map_err(|e| store_error(&e))?;
        }
        self.answer(txn, signer, stored, other).await
    }

    /// An append's stored answer: to an own app with the head; to an app of another
    /// identity (`other`) as stored, with its `known_version` and no head (Switch wire 7.1).
    async fn answer(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        stored: Vec<u8>,
        other: bool,
    ) -> Result<Answer, ApiError> {
        if other {
            return Ok(Answer::ok(stored));
        }
        let head = self.head(txn, signer).await.ok_or_else(temporary)?;
        Ok(Answer::ok(stored).with_head(Some(head)))
    }

    /// The target apps of an envelope whose header wraps to `header`'s kids, or `409
    /// stale_key` (Switch wire 7.4.3 check 5, 7.6): each kid the current receive key of a
    /// current app, and every app reachable since `sealed_for` among them (an own app
    /// appending, `own`, needn't wrap to itself).
    async fn targets(
        &self,
        txn: &mut AccountTxn,
        held: Option<&IdentityDoc>,
        header: &pubky_switch_core::envelope::Header,
        sealed_for: u64,
        own: Option<[u8; 16]>,
        time_ms: u64,
    ) -> Result<Vec<[u8; 16]>, ApiError> {
        // Current by the service's one rule, as the entries' release and the directory judge
        // it (Switch spec 3.4).
        let (state, apps) = super::batch::load_apps_and_rows(txn, held, time_ms)
            .await
            .map_err(|e| store_error(&e))?;
        let kids: Vec<[u8; 8]> = header.kids().collect();
        let holders: BTreeMap<[u8; 8], [u8; 16]> = txn
            .kid_holders(&kids)
            .await
            .map_err(|e| store_error(&e))?
            .into_iter()
            .collect();
        let mut targets = Vec::new();
        let mut stale = Vec::new();
        let mut not_current = Vec::new();
        let mut unknown = Vec::new();
        // One app wrapped to twice is `400` (Switch wire 4.4). The header check sees a kid
        // twice; two kids of one app show only here, as their holders resolve.
        let mut wrapped = BTreeSet::new();
        if holders.values().any(|holder| !wrapped.insert(*holder)) {
            return Err(ApiError::bad_request("4.4: one app wrapped to twice"));
        }
        // `receive_keys`, `not_current` and `added_apps` together name each app at most once
        // (Switch wire 7.6): an app stale or no longer current isn't among `added_apps` too.
        let mut named = BTreeSet::new();
        for kid in &kids {
            let Some(holder) = holders.get(kid) else {
                unknown.push(json!(b64(kid)));
                continue;
            };
            // Current (Switch wire 7.4.3 check 5 "the current receive key of a current app",
            // 7.6 `not_current`, spec 3.4), its certificate's expiry apart: that is the
            // sender's own check on the record the directory gave it (wire 3.8 check 3, spec
            // 8.1), and an entry wrapped to a lapsed app is held for it as its others are.
            if !state.is_current(holder) {
                named.insert(*holder);
                not_current.push(json!(zbase32_encode(holder)));
                continue;
            }
            let current_key = state
                .apps
                .get(holder)
                .and_then(|app| app.receive_key.as_ref());
            if current_key.map(|key| key.kid()) == Some(*kid) {
                targets.push(*holder);
            } else {
                named.insert(*holder);
                stale.push(json!({
                    "app_id": zbase32_encode(holder),
                    "record": current_key.map(|key| key.signed().clone()),
                }));
            }
        }
        let (_, apps_version) = txn
            .directory_versions()
            .await
            .map_err(|e| store_error(&e))?;
        let mut added = Vec::new();
        for app in &apps {
            let since = app.reachable_since.unwrap_or(0);
            if app.reachable_since.is_none()
                || since <= sealed_for
                || targets.contains(&app.app_id)
                || named.contains(&app.app_id)
                || own == Some(app.app_id)
                || !state.is_current(&app.app_id)
            {
                continue;
            }
            if let (Some(record), Some(key)) = (&app.record, &app.receive_key) {
                added.push(json!({
                    "app_id": zbase32_encode(&app.app_id),
                    "app_record": record,
                    "record": key,
                }));
            }
        }
        if !stale.is_empty() || !not_current.is_empty() || !unknown.is_empty() || !added.is_empty()
        {
            return Err(ApiError::new(
                ErrorCode::StaleKey,
                "3.7: envelope wrapped to a receive key that isn't current",
            )
            .with_current(json!({
                "receive_keys": stale,
                "not_current": not_current,
                "unknown_kids": unknown,
                "added_apps": added,
                "apps_version": apps_version,
            })));
        }
        Ok(targets)
    }

    /// Use the invite code `code`, write the service's conversation entry for `sender` and
    /// chain its `conversation.add` transition (Switch wire 7.4.3 check 7, 6.5): the code's
    /// context, as stored. `429 quota_exceeded` (`conversations`) while the list is full.
    async fn use_invite(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        code: &[u8; 32],
        sender: &[u8; 32],
        time_ms: u64,
    ) -> Result<Vec<u8>, ApiError> {
        let invite = txn
            .invites(&[*code])
            .await
            .map_err(|e| store_error(&e))?
            .into_iter()
            .next()
            .ok_or_else(not_admitted)?;
        let present = !txn
            .list_entries(ListName::Conversation, &[*sender])
            .await
            .map_err(|e| store_error(&e))?
            .is_empty();
        if !present {
            let entries = txn
                .list_count(ListName::Conversation, &[])
                .await
                .map_err(|e| store_error(&e))?;
            if entries >= self.limits.max_conversations {
                return Err(ApiError::quota_exceeded(
                    "conversations",
                    "6.3: the identity holds its limit of conversation entries",
                ));
            }
        }
        // The context as its writer wrote it, which the feed shows with the entry.
        let context = invite.context_written.clone();
        txn.use_invite(code, sender, &context, time_ms)
            .await
            .map_err(|e| store_error(&e))?;
        let identity = txn.head().identity_key;
        let transition = ServiceTransition::ConversationAdd {
            pubky: *sender,
            code_hash: *code,
            context: invite.context.clone(),
            at: time_ms,
        };
        let signed = transition
            .sign(signer, &identity)
            .map_err(|_| temporary())?;
        let item_bytes = signed.doc_bytes().map_err(|_| temporary())?;
        let item = item_hash(ItemType::Service, &item_bytes);
        let seq = txn.next_seq().map_err(|e| store_error(&e))?;
        let (stub, _tip) = txn
            .head()
            .chain_tip()
            .append(seq, time_ms, ItemType::Service, item, None)
            .map_err(|_| temporary())?;
        txn.append_chain_item(&NewChainItem {
            seq,
            item_type: ItemType::Service,
            item_bytes: &item_bytes,
            stub: &stub,
            server_time_ms: time_ms,
            only_for: None,
            proof: None,
        })
        .await
        .map_err(|e| store_error(&e))?;
        let _: &Value = &invite.context;
        Ok(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inbox_answer_in_table_order_with_known_version() {
        let stored = stored_answer(&[1; 16], 0, 4);
        assert_eq!(
            String::from_utf8(stored.clone()).expect("utf-8"),
            "{\"entry_id\":\"AQEBAQEBAQEBAQEBAQEBAQ\",\"accepted_at\":\"1970-01-01T00:00:00.000Z\",\"directory_version\":4}"
        );
        let with = String::from_utf8(with_known_version(&stored, Some(3))).expect("utf-8");
        assert!(with.ends_with(",\"directory_version\":4,\"known_version\":3}"));
        let none = String::from_utf8(with_known_version(&stored, None)).expect("utf-8");
        assert!(none.ends_with(",\"known_version\":null}"));
    }
}
