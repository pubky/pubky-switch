//! `GET /v1/{id}/directory` (Switch wire 7.4.10): the account's newest `identity.json` and
//! its current apps, each with its app record and receive key record, for own apps and for
//! apps of other identities that admission lets in (Switch spec 7).

use pubky_switch_core::records::{AppCert, IdentityDoc};
use serde_json::{Value, json};

use super::{
    Answer, Deferred, Service,
    admission::{Admitted, NOT_ADMITTED, admit},
    store_error,
};
use crate::{
    http::error::{ApiError, ErrorCode},
    keys::ServiceSigner,
    store::{AccountTxn, SnapshotRead},
};

/// Who reads the directory.
pub(super) enum Reader<'a> {
    /// An own app that verified.
    OwnApp,
    /// An app of another identity, verified with the certificate it sent.
    OtherApp(&'a AppCert),
}

/// A directory's apps and versions, read once the lock is gone from the snapshot of the
/// state under it.
#[derive(Debug)]
pub(super) struct DirectoryRead {
    snapshot: SnapshotRead,
    /// The identity, generation and last `seq` the locked transaction saw.
    account: ([u8; 32], u64, u64),
    /// The newest `identity.json`, as read under the lock.
    doc: IdentityDoc,
    /// For an app of another identity, its `known_version`.
    known: Option<Option<u64>>,
    time_ms: u64,
}

fn temporary() -> ApiError {
    ApiError::unavailable("7.6: a temporary failure")
}

impl Service {
    /// `GET /v1/{id}/directory` (Switch wire 7.4.10) under the lock, for `reader`, with the
    /// account's newest `identity.json` `held`; `trusted` says whether the service has
    /// trusted time, which an invite code's expiry needs (7.3).
    ///
    /// An app of another identity is admitted as at the inbox: a contact or conversation
    /// entry that isn't denied, or a live invite code, which isn't used. A code-admitted
    /// read counts against the code's rate, shared with `PUT /peers`. No stranger reads
    /// the directory, connect requests or not. An app that the held copy of its identity
    /// lists in `removed` counts only a code (7.2); that is read from its own column, so a
    /// refusal costs the same whether a copy is held or not.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn directory(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        held: Option<&IdentityDoc>,
        reader: Reader<'_>,
        invite_code: Option<&str>,
        trusted: bool,
        time_ms: u64,
    ) -> Result<Answer, ApiError> {
        let account = txn.head().clone();
        let mut known = None;
        if let Reader::OtherApp(cert) = reader {
            let sender = cert.identity();
            let removed = txn
                .peer_lists_removed(&sender, &cert.app_id())
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
            match admit(standing, removed, invite, false)
                .ok_or_else(|| ApiError::new(ErrorCode::NotAdmitted, NOT_ADMITTED))?
            {
                Admitted::Listed => {}
                Admitted::InviteCode(hash) => {
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
                    return Err(ApiError::new(ErrorCode::NotAdmitted, NOT_ADMITTED));
                }
            }
            // A removed app gets `null`, as a stranger would (Switch wire 7.1).
            if !removed {
                known = Some(
                    txn.peer_copy(&sender)
                        .await
                        .map_err(|e| store_error(&e))?
                        .map(|copy| copy.version),
                );
            } else {
                known = Some(None);
            }
        }
        let Some(doc) = held else {
            return Err(ApiError::not_found(
                "7.4.10: the account holds no identity.json yet",
            ));
        };

        // The apps are read after the lock, from the snapshot of the state under it
        // ([`Service::directory_body`]), so a long read holds no lock other requests wait
        // for.
        let head = match known {
            Some(_) => None,
            None => Some(self.head(txn, signer).await.ok_or_else(temporary)?),
        };
        let account = txn.head().clone();
        let snapshot = txn.snapshot_read().map_err(|e| store_error(&e))?;
        let mut answer = Answer::ok(Vec::new()).with_head(head);
        answer.deferred = Some(Deferred::Directory(Box::new(DirectoryRead {
            snapshot,
            account: (account.identity_key, account.generation, account.last_seq),
            doc: doc.clone(),
            known,
            time_ms,
        })));
        Ok(answer)
    }

    /// The directory of `read` (Switch wire 7.4.10): the current apps in the order the newest
    /// `identity.json` lists them, with the versions, and `known_version` for an app of
    /// another identity.
    pub(super) async fn directory_body(read: DirectoryRead) -> Result<Vec<u8>, ApiError> {
        let DirectoryRead {
            mut snapshot,
            account,
            doc,
            known,
            time_ms,
        } = read;
        // The account's apps, from the loader every judgment of currency uses.
        let (state, apps) =
            super::batch::load_apps_from_snapshot(&mut snapshot, account, Some(&doc), time_ms)
                .await
                .map_err(|e| store_error(&e))?;
        // The current apps, in the order the newest identity.json lists them: each once,
        // since a document naming an App ID twice doesn't verify (Switch wire 3.3).
        let mut listed: Vec<Value> = Vec::new();
        for entry in &doc.body().apps {
            let Some(app) = apps.iter().find(|app| app.app_id == entry.app_id) else {
                continue;
            };
            let Some(record) = &app.record else {
                continue;
            };
            // Current, not served (Switch wire 7.4.10 "the current apps", spec 3.4): an app
            // whose certificate has lapsed stays listed. A sender checks the certificate's
            // expiry itself (wire 3.8 check 3 at its clock), and the inbox takes an envelope
            // wrapped to it and holds the entry for it (7.4.3 check 5 takes current apps
            // too). So the directory changes only with its versions, never as a clock passes
            // an expiry.
            if !state.is_current(&app.app_id) {
                continue;
            }
            listed.push(json!({
                "app_id": pubky_switch_core::enc::zbase32_encode(&app.app_id),
                "record": record,
                "receive_key": app.receive_key,
            }));
        }
        let (directory_version, apps_version) = snapshot
            .directory_versions()
            .await
            .map_err(|e| store_error(&e))?;
        snapshot.finish().await.map_err(|e| store_error(&e))?;
        // Members sorted, the order of `http.json`'s directory, which serde_json's map keeps.
        let mut body = json!({
            "identity": doc.signed(),
            "apps": listed,
            "directory_version": directory_version,
            "apps_version": apps_version,
        });
        if let Some(known) = known {
            body["known_version"] = json!(known);
        }
        serde_json::to_vec(&body).map_err(|_| temporary())
    }
}
