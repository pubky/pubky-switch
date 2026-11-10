//! `PUT /v1/{id}/peers` (Switch wire 7.4.5): another identity's `identity.json`, delivered
//! by that identity's app or by an own app, kept as the account's copy of it, the highest
//! version, one per identity. Admission and the listing checks of other identities' apps
//! read these copies.

use pubky_switch_core::{
    ident::invite_code_hash,
    records::{AppCert, IdentityDoc},
    sig::SignedDoc,
};
use serde_json::{Value, json};

use super::{
    Answer, Service,
    admission::{Admitted, Judgment, NOT_ADMITTED, Standing, admit, judge},
    store_error,
};
use crate::{
    http::error::{ApiError, ErrorCode},
    keys::ServiceSigner,
    store::{AccountTxn, HeldPeer, ListName, PeerFloor},
};

fn not_admitted() -> ApiError {
    ApiError::new(ErrorCode::NotAdmitted, NOT_ADMITTED)
}

fn storage(error: &crate::store::StoreError) -> ApiError {
    store_error(error)
}

/// Who delivers a copy.
#[derive(Clone, Copy, Debug)]
pub(super) enum Deliverer<'a> {
    /// An own app, delivering a counterparty's document.
    OwnApp,
    /// An app of another identity, verified with this certificate, delivering its own
    /// identity's document.
    OtherApp(&'a AppCert),
}

impl Service {
    /// Where the account's lists put `identity`.
    async fn standing(
        &self,
        txn: &mut AccountTxn,
        identity: &[u8; 32],
    ) -> Result<Standing, ApiError> {
        let mut standing = Standing::default();
        for (list, flag) in [
            (ListName::Contact, &mut standing.contact),
            (ListName::Conversation, &mut standing.conversation),
            (ListName::Deny, &mut standing.denied),
        ] {
            *flag = !txn
                .list_entries(list, &[*identity])
                .await
                .map_err(|e| storage(&e))?
                .is_empty();
        }
        Ok(standing)
    }

    /// The hash of the invite code `header` presents, if it names a code live at `now`.
    async fn live_invite(
        &self,
        txn: &mut AccountTxn,
        header: Option<&str>,
        now: u64,
    ) -> Result<Option<[u8; 32]>, ApiError> {
        let Some(hash) = header.and_then(|code| invite_code_hash(code).ok()) else {
            return Ok(None);
        };
        let invites = txn.invites(&[hash]).await.map_err(|e| storage(&e))?;
        Ok(invites
            .iter()
            .any(|invite| invite.uses < invite.max_uses && now < invite.expires_at_ms)
            .then_some(hash))
    }

    /// `PUT /v1/{id}/peers` (Switch wire 7.4.5), from an own app or an app of another
    /// identity; `trusted` says whether the service has trusted time, which an invite code's
    /// expiry needs (7.3).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn put_peers(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        held: Option<&IdentityDoc>,
        deliverer: Deliverer<'_>,
        body: &[u8],
        invite_code: Option<&str>,
        trusted: bool,
        time_ms: u64,
    ) -> Result<Answer, ApiError> {
        let value: Value = serde_json::from_slice(body)
            .map_err(|_| ApiError::bad_request("7.4.5: the body is a signed identity.json"))?;
        let signed = SignedDoc::from_strict_value(&value)
            .map_err(|_| ApiError::bad_request("7.4.5: the body is a signed identity.json"))?;
        let doc = IdentityDoc::verify_named(&signed)
            .map_err(|_| ApiError::bad_request("3.3: the identity.json doesn't verify"))?;
        let identity = doc.identity();
        let account = txn.head().clone();
        let copy = HeldPeer {
            doc: signed,
            version: doc.version(),
            generation: doc.generation(),
            body_hash: doc.body_hash(),
        };
        let cert = match deliverer {
            Deliverer::OwnApp => {
                if identity == account.identity_key {
                    return Err(ApiError::bad_request(
                        "7.4.5: an own app delivers counterparties' documents, not its own \
                         identity's",
                    ));
                }
                None
            }
            Deliverer::OtherApp(cert) => {
                if identity != cert.identity() {
                    return Err(not_admitted());
                }
                Some(cert)
            }
        };
        let held_copy = txn.peer_copy(&identity).await.map_err(|e| storage(&e))?;
        let standing = self.standing(txn, &identity).await?;
        let Some(cert) = cert else {
            // An own app's delivery needs no admission and counts against no rate.
            let answer = self
                .keep_copy(txn, &identity, held_copy.as_ref(), &copy, standing)
                .await?;
            let head = self
                .head(txn, signer)
                .await
                .ok_or_else(|| ApiError::unavailable("7.6: a temporary failure"))?;
            return Ok(answer_of(&answer, None)?.with_head(Some(head)));
        };

        // An app of another identity: admitted, or asking to connect where the policy
        // allows it. One the held copy or the delivered document lists in removed is
        // answered like a stranger (Switch wire 7.2).
        let app = cert.app_id();
        let removed = doc.lists_removed(&app)
            || held_copy
                .as_ref()
                .map(|held| IdentityDoc::verify_named(&held.doc))
                .transpose()
                .map_err(|_| ApiError::unavailable("7.6: a temporary failure"))?
                .is_some_and(|held| held.lists_removed(&app));
        let connect_requests = held.is_some_and(|doc| doc.body().policy.connect_requests.enabled);
        let listed = !standing.denied && !removed && (standing.contact || standing.conversation);
        let invite = if listed {
            None
        } else {
            self.live_invite(txn, invite_code, time_ms).await?
        };
        let admitted =
            admit(standing, removed, invite, connect_requests).ok_or_else(not_admitted)?;
        match admitted {
            Admitted::Listed => {}
            Admitted::InviteCode(hash) => {
                // Admitted only by a code, whose expiry is a time (Switch wire 7.3).
                if !trusted {
                    return Err(ApiError::unavailable(
                        "7.3: an invite code's expiry needs trusted time",
                    ));
                }
                self.invite_rate
                    .take(
                        (account.id.clone(), hash),
                        self.limits.invite_reads_per_min,
                        time_ms,
                    )
                    .map_err(|retry_after| {
                        ApiError::rate_limited("9.4: reads with this invite code", retry_after)
                    })?;
            }
            Admitted::ConnectRequests => {
                self.stranger_rate
                    .take(account.id.clone(), self.limits.stranger_per_min, time_ms)
                    .map_err(|retry_after| {
                        ApiError::rate_limited("9.4: strangers at this account", retry_after)
                    })?;
            }
        }
        if removed {
            // The delivered version, whatever the service holds, and no body compared. A
            // newer document is still kept, never going back (Switch wire 7.4.5).
            let floor = txn.peer_floor(&identity).await.map_err(|e| storage(&e))?;
            if judge(
                held_copy.as_ref(),
                floor.as_ref(),
                copy.version,
                copy.generation,
                &copy.body_hash,
            ) == Judgment::Keep
            {
                self.keep_copy(txn, &identity, held_copy.as_ref(), &copy, standing)
                    .await?;
            }
            return answer_of(&Kept::Version(copy.version), Some(copy.version));
        }
        let answer = self
            .keep_copy(txn, &identity, held_copy.as_ref(), &copy, standing)
            .await?;
        let known = match answer {
            Kept::Version(version) => Some(version),
            _ => None,
        };
        answer_of(&answer, known)
    }

    /// Judge `copy` against what the account holds of `identity`, and keep it if it is
    /// newer: within `max_peers`, the least recently delivered copy drops, strangers' first;
    /// a stranger's new copy never pushes out an admitted identity's, it drops itself
    /// instead; a dropped admitted copy leaves a floor (Switch wire 9.1).
    async fn keep_copy(
        &self,
        txn: &mut AccountTxn,
        identity: &[u8; 32],
        held: Option<&HeldPeer>,
        copy: &HeldPeer,
        standing: Standing,
    ) -> Result<Kept, ApiError> {
        let floor = match held {
            Some(_) => None,
            None => txn.peer_floor(identity).await.map_err(|e| storage(&e))?,
        };
        match judge(
            held,
            floor.as_ref(),
            copy.version,
            copy.generation,
            &copy.body_hash,
        ) {
            Judgment::Same => {
                txn.touch_peer(identity).await.map_err(|e| storage(&e))?;
                return Ok(Kept::Version(copy.version));
            }
            Judgment::Stale { version } => return Ok(Kept::Stale { version }),
            Judgment::Equivocation => {
                return Ok(Kept::Equivocation(held.cloned().ok_or_else(|| {
                    ApiError::unavailable("7.6: a temporary failure")
                })?));
            }
            Judgment::Keep => {}
        }
        txn.put_peer(identity, copy)
            .await
            .map_err(|e| storage(&e))?;
        let count = txn.peer_count().await.map_err(|e| storage(&e))?;
        if count > self.limits.max_peers {
            let admitted = !standing.denied && (standing.contact || standing.conversation);
            match txn
                .oldest_peer(identity, true)
                .await
                .map_err(|e| storage(&e))?
            {
                Some((stranger, _)) => {
                    txn.drop_peer(&stranger, None)
                        .await
                        .map_err(|e| storage(&e))?;
                }
                None if !admitted => {
                    txn.drop_peer(identity, None)
                        .await
                        .map_err(|e| storage(&e))?;
                }
                None => {
                    if let Some((oldest, dropped)) = txn
                        .oldest_peer(identity, false)
                        .await
                        .map_err(|e| storage(&e))?
                    {
                        let floor = PeerFloor {
                            version: dropped.version,
                            generation: dropped.generation,
                            body_hash: dropped.body_hash,
                        };
                        txn.drop_peer(&oldest, Some(floor))
                            .await
                            .map_err(|e| storage(&e))?;
                    }
                }
            }
        }
        Ok(Kept::Version(copy.version))
    }
}

/// What a delivery came to.
#[derive(Clone, Debug)]
enum Kept {
    /// The version the service now holds, or the version a removed app delivered.
    Version(u64),
    /// Below the held copy or a floor.
    Stale { version: u64 },
    /// Another body at the held version: the held copy.
    Equivocation(HeldPeer),
}

/// The answer to a delivery: `{ "version" }`, with `known_version` for an app of another
/// identity, or the `409 stale_identity` (Switch wire 7.4.5).
fn answer_of(kept: &Kept, known_version: Option<u64>) -> Result<Answer, ApiError> {
    match kept {
        Kept::Version(version) => {
            let mut body = json!({ "version": version });
            if let Some(known) = known_version {
                body["known_version"] = json!(known);
            }
            let body = serde_json::to_vec(&body)
                .map_err(|_| ApiError::unavailable("7.6: a temporary failure"))?;
            Ok(Answer::ok(body))
        }
        Kept::Stale { version } => Err(ApiError::new(
            ErrorCode::StaleIdentity,
            "7.4.5: a lower version or generation than the copy held",
        )
        .with_current(json!({ "version": version }))),
        Kept::Equivocation(held) => Err(ApiError::new(
            ErrorCode::StaleIdentity,
            "3.3: another identity.json at the version the service holds",
        )
        .with_current(json!({ "version": held.version, "identity": held.doc }))),
    }
}
