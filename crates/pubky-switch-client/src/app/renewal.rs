//! Certificate renewal, the app's side (Switch spec 3.2 steps 3 and 4; Switch wire 3.8).
//!
//! The signer stores the app's renewed certificate at the service (`cert.put`, in the
//! feed), then delivers an `identity.json` listing its hash. The app keeps the certificate
//! from `cert.put` and takes it once its own `identity.json` lists it: it presents it from
//! then on, and delivers its record carrying it (`app.put`), signed once and kept before it
//! is sent. An app without the `cert.put`, such as one restored from a backup older than
//! the renewal, or one that was offline while another device of the app took the renewal
//! and put its record (the feed then shows the `cert.put` only as a stub), takes the
//! listed certificate from its own record in its directory, under the checks of Switch
//! spec 3.2 step 3: after a restore, and at a read's start while its own `identity.json`
//! lists another certificate (Switch wire 7.2 "How an own app reads it").

use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ops::{Condition, OpKind};
use pubky_switch_core::records::{AppCert, AppRecord, IdentityDoc, is_renewal};
use pubky_switch_core::sig::SignedDoc;

use super::events::AppEvent;
use super::state::{PendingRecord, Tx, key};
use super::{App, AppError, Publication};
use crate::client::Batch;
use crate::error::ClientError;

impl App {
    /// A `cert.put` for this app seen in the feed: kept if it renews the certificate the
    /// app presents (the same App ID, signing key and bundle key, a later `issued_at`).
    pub(crate) fn note_renewal(&mut self, signed: &SignedDoc, tx: &mut Tx) -> Result<(), AppError> {
        let Ok(cert) = AppCert::verify(signed, &self.state.meta.identity) else {
            return Ok(());
        };
        let newer_than_kept = self
            .state
            .renewal
            .as_ref()
            .is_none_or(|kept| cert.issued_at() > kept.issued_at());
        if is_renewal(&self.state.cert, &cert) && newer_than_kept {
            tx.put(key::CERT_RENEWAL, cert.signed())?;
            self.state.renewal = Some(cert);
            self.events.push(AppEvent::RenewalSeen);
        }
        Ok(())
    }

    /// Take the kept renewal once the own `identity.json` lists it, and deliver the record
    /// carrying it. Returns whether the certificate changed.
    pub(crate) async fn adopt_renewal(&mut self) -> Result<bool, AppError> {
        let Some(renewal) = self.state.renewal.clone() else {
            return Ok(false);
        };
        let me = self.state.meta.app_id;
        if self.state.own_doc.listed_cert(&me) != Some(renewal.hash()) {
            return Ok(false);
        }
        let old = AppRecord::verify(&self.state.record, &self.state.meta.identity)?;
        let mut body = old.body().clone();
        body.cert = renewal.signed().clone();
        body.accepts = self.protocols.accepts(&renewal);
        body.updated_at = self.now().max(old.updated_at().saturating_add(1));
        let record = AppRecord::sign(&self.state.keys, body)?;
        self.take_cert(renewal, record.signed().clone(), true, None)
            .await?;
        self.deliver_record().await?;
        Ok(true)
    }

    /// Present `cert` from now on, with `record`; `deliver` signs its `app.put` and keeps it
    /// before it is sent. A certificate that reads a member of a collection of the protocol
    /// the one before didn't owes a listing, in the same commit, so the next read lists it (Switch
    /// spec 8.3, Switch wire 7.4.9): the writes made there before it were stubs in the feed.
    ///
    /// With `accepted`, a record the switch holds that carries `cert`, that record is noted
    /// as the newest the switch accepted, in the same commit, and the published copy is
    /// checked against it at the next publication check.
    async fn take_cert(
        &mut self,
        cert: AppCert,
        record: SignedDoc,
        deliver: bool,
        accepted: Option<SignedDoc>,
    ) -> Result<(), AppError> {
        let issued_at = cert.issued_at();
        // A later renewal the app holds, of the certificate taken, stays held: it is taken
        // in turn once its listing comes (`adopt_renewal`).
        let keep_renewal = self
            .state
            .renewal
            .as_ref()
            .is_some_and(|held| is_renewal(&cert, held));
        // Member by member: a scope of the new certificate that reads a collection's member,
        // its fixed read scope or a sub-scope of its family, and that the one before doesn't
        // hold (Switch spec 3.3).
        let collections = self.protocols.collections();
        let widened = cert.scopes().iter().any(|scope| {
            !self.state.cert.holds_scope(scope)
                && collections.iter().any(|c| c.read_by_scope(scope))
        });
        self.state.cert = cert;
        self.rebuild_client()?;
        let mut tx = self.tx()?;
        if widened {
            super::records::owe_listing(&mut tx)?;
        }
        tx.put(key::CERT, self.state.cert.signed())?;
        tx.put(key::RECORD, &record)?;
        if !keep_renewal {
            tx.delete(key::CERT_RENEWAL)?;
        }
        if let Some(accepted) = &accepted {
            tx.put(key::ACCEPTED_RECORD, accepted)?;
        }
        if deliver {
            let pending = PendingRecord {
                body: self.record_batch(&record)?.body().to_vec(),
            };
            tx.put(key::PENDING_RECORD, &pending)?;
            self.state.pending_record = Some(pending);
        }
        self.state.record = record;
        if !keep_renewal {
            self.state.renewal = None;
        }
        self.commit(tx).await?;
        if let Some(accepted) = accepted {
            self.state.accepted = Some(accepted);
            self.published_checked_ms = None;
        }
        self.events.push(AppEvent::CertificateTaken { issued_at });
        Ok(())
    }

    /// The `app.put` batch. It is kept and may be sent again after the cursor moved on: a
    /// cursor move in it could take the service's cursor back, so it carries none (Switch
    /// spec 8.2).
    pub(crate) fn record_batch(&self, record: &SignedDoc) -> Result<Batch, AppError> {
        self.sign_ops(
            vec![(
                Vec::<Condition>::new(),
                OpKind::AppPut {
                    record: record.clone(),
                },
            )],
            None,
        )
    }

    /// Deliver what is owed of the record, then publish it (`own_record.rs`).
    pub(crate) async fn deliver_record(&mut self) -> Result<Publication, AppError> {
        let accepted = self.deliver_pending_record().await?;
        self.publish_owed(false, accepted).await
    }

    /// Send the kept `app.put` until answered; returns whether the switch accepted a record
    /// in this call. A `409 conflict` naming a record of this app with an `updated_at` at or
    /// after this one's (another device's) is written again once, later than the held one
    /// (Switch spec 4.2). One naming no record that verifies answers a re-send of a batch
    /// the switch applied and holds without its proofs (Switch wire 6.4 step 5), so the
    /// switch's directory decides it: a directory that shows this very record makes it
    /// delivered; one that shows a later record of the app, which another device put after
    /// it, makes it superseded (Switch spec 4.2 "The later `updated_at` wins"). The kept
    /// record is then dropped, and the later record taken in the same commit as the newest
    /// the switch accepted, and as the record the app presents when it carries the
    /// certificate the app presents: the app's next record builds on it, so this older body
    /// is never signed again over it. A later record carrying a renewal another device
    /// took is presented with that renewal when the newest `identity.json` lists it, and
    /// one under any other certificate is never taken ([`App::take_superseding`]).
    /// Otherwise it is refused, and nothing is noted or published. Once the switch holds the record, an app that publishes owes it to the
    /// Homeserver, in the commit that records the answer.
    pub(crate) async fn deliver_pending_record(&mut self) -> Result<bool, AppError> {
        let Some(pending) = self.state.pending_record.clone() else {
            return Ok(false);
        };
        let mut batch = Batch::from_body(pending.body)?;
        let result = self.submit(&batch).await;
        let held = match result {
            Ok(_) => None,
            Err(error) if error.code() == Some(ErrorCode::Conflict) => {
                let named = match &error {
                    AppError::Switch(ClientError::Switch { current, .. }) => current
                        .get("record")
                        .and_then(|value| SignedDoc::from_strict_value(value).ok())
                        .and_then(|doc| AppRecord::verify(&doc, &self.state.meta.identity).ok()),
                    _ => None,
                };
                // Boxed: the directory read is rare, and would otherwise widen every future
                // that delivers a record.
                if named.is_none() {
                    match Box::pin(self.switch_holds(&batch)).await? {
                        Held::This => {}
                        Held::Later(later) => {
                            let (later, identity) = *later;
                            Box::pin(self.take_superseding(later, identity)).await?;
                            return Ok(false);
                        }
                        Held::Other => return Err(error),
                    }
                }
                named
            }
            Err(error) => return Err(error),
        };
        if let Some(held) = held {
            let mine = AppRecord::verify(&self.state.record, &self.state.meta.identity)?;
            if held.cert().app_id() != self.state.meta.app_id {
                return Err(AppError::InvalidData(
                    "Switch wire 6.2: an app.put conflict naming another app's record".into(),
                ));
            }
            let mut body = mine.body().clone();
            body.updated_at = self
                .now()
                .max(held.updated_at().saturating_add(1))
                .max(mine.updated_at().saturating_add(1));
            let record = AppRecord::sign(&self.state.keys, body)?;
            batch = self.record_batch(record.signed())?;
            let mut tx = self.tx()?;
            tx.put(key::RECORD, record.signed())?;
            let pending = PendingRecord {
                body: batch.body().to_vec(),
            };
            tx.put(key::PENDING_RECORD, &pending)?;
            self.state.record = record.signed().clone();
            self.state.pending_record = Some(pending);
            self.commit(tx).await?;
            self.submit(&batch).await?;
        }
        let delivered = delivered_record(&batch)?;
        let mut tx = self.tx()?;
        tx.delete(key::PENDING_RECORD)?;
        tx.put(key::CURSOR, &self.state.cursor)?;
        self.note_accepted(&delivered, &mut tx)?;
        self.state.pending_record = None;
        self.commit(tx).await?;
        self.took_accepted(delivered);
        Ok(true)
    }

    /// Drop the kept record that `later`, a record of the app the switch holds, superseded,
    /// and take `later` in the same commit, as the newest record the switch accepted and
    /// as the record the app presents, when it carries the certificate the app presents.
    /// Nothing is owed to the Homeserver for it: the device that put it publishes it, and
    /// the next check compares the copy with it.
    ///
    /// A `later` carrying a renewal another device took, whose `cert.put` the feed shows
    /// only as a stub once the record carries it, is taken with that certificate first, as
    /// after a restore (Switch spec 3.2 step 3): when `identity`, the own `identity.json`
    /// the same directory answer carried, or the newer one held, lists it, and it renews
    /// the certificate held under the app's own keys. It is presented as it is, so nothing
    /// is signed over it, also when the app already holds that renewal's `cert.put`.
    ///
    /// A `later` under any other certificate, which only a faulty switch shows, is never
    /// taken: the kept record is dropped alone, nothing is noted as accepted, and nothing
    /// of it is published.
    async fn take_superseding(
        &mut self,
        later: AppRecord,
        identity: IdentityDoc,
    ) -> Result<(), AppError> {
        let me = self.state.meta.app_id;
        let newer = identity.version() > self.state.own_doc.version();
        let listed = if newer {
            identity.listed_cert(&me)
        } else {
            self.state.own_doc.listed_cert(&me)
        };
        let cert = later.cert();
        if cert.hash() != self.state.cert.hash()
            && listed == Some(cert.hash())
            && cert.signing_key() == self.state.keys.signing_public()
            && cert.bundle_key() == self.state.keys.bundle_public()
            && is_renewal(&self.state.cert, cert)
        {
            // Before the newer document is taken, which would sign a renewal the app holds
            // into the dropped body; and before the drop, so a crash between the two leaves
            // the kept record, whose re-send then finds the later record under the
            // certificate presented.
            self.take_cert(cert.clone(), later.signed().clone(), false, None)
                .await?;
        }
        if newer {
            self.take_own_copy(identity).await?;
        }
        let taken = later.cert().hash() == self.state.cert.hash();
        let signed = later.signed().clone();
        let mut tx = self.tx()?;
        tx.delete(key::PENDING_RECORD)?;
        if taken {
            tx.put(key::ACCEPTED_RECORD, &signed)?;
            tx.put(key::RECORD, &signed)?;
        }
        self.commit(tx).await?;
        self.state.pending_record = None;
        if taken {
            self.state.record = signed.clone();
            self.state.accepted = Some(signed);
            self.published_checked_ms = None;
        }
        Ok(())
    }

    /// Take a renewal another device of the app took (Switch wire 7.2 "How an own app reads
    /// it", spec 3.2 step 3): the own `identity.json` lists another certificate than the
    /// one the app presents, and the app holds no `cert.put` for it, which the feed showed
    /// only as a stub once that device's record carried it. Without it every write is
    /// refused `403 not_current`. Taken from the own record in the directory, as after a
    /// restore ([`App::take_listed_cert`]). Only a directory read tells whether that record
    /// carries it yet, so a look that doesn't find it, or fails, is made again at most every
    /// [`super::DOC_CACHE_MS`] while the listing lasts, and the read goes on; a refusal of
    /// the app's record write under the earlier certificate makes the next read look at
    /// once. `None` when no look was due or it failed.
    pub(crate) async fn take_renewal_listed_elsewhere(
        &mut self,
    ) -> Result<Option<Listed>, AppError> {
        let me = self.state.meta.app_id;
        let doc = &self.state.own_doc;
        let Some(listed) = doc.listed_cert(&me) else {
            return Ok(None);
        };
        let held = self
            .state
            .renewal
            .as_ref()
            .is_some_and(|r| r.hash() == listed);
        if listed == self.state.cert.hash() || held || doc.lists_removed(&me) {
            return Ok(None);
        }
        let now = self.now();
        if self
            .renewal_looked_ms
            .is_some_and(|at| now >= at && now - at < super::DOC_CACHE_MS)
        {
            return Ok(None);
        }
        // A look that fails, on the network or with an answer the app won't read, is paced
        // as one that found nothing, and the read goes on: only a record write is refused
        // under the earlier certificate, and the next look may find it.
        let found = match Box::pin(self.take_listed_cert()).await {
            Ok(found) => found,
            Err(AppError::Transport(_) | AppError::Switch(_) | AppError::InvalidData(_)) => {
                self.renewal_looked_ms = Some(now);
                // The look may have failed after it took a newer own document, such as at
                // the key fetch an epoch rise makes, refused for an app that document
                // removes: the read stops at that document all the same.
                if self.not_current_here().is_some() {
                    return Ok(Some(Listed::NotCurrentHere));
                }
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let listed_now = self.state.own_doc.listed_cert(&me);
        self.renewal_looked_ms =
            (listed_now.is_some_and(|l| l != self.state.cert.hash())).then_some(now);
        Ok(Some(found))
    }

    /// What the switch's directory shows it holds for this app, beside the record `batch`
    /// delivers.
    async fn switch_holds(&mut self, batch: &Batch) -> Result<Held, AppError> {
        let record = delivered_record(batch)?;
        let mine = AppRecord::verify(&record, &self.state.meta.identity)?;
        let me = self.state.meta.app_id;
        let result = self.client.directory(None).await;
        let directory = self.take(result).await?;
        let Some(entry) = directory.apps.iter().find(|app| app.app_id == me) else {
            return Ok(Held::Other);
        };
        Ok(if entry.record.signed() == &record {
            Held::This
        } else if entry.record.updated_at() > mine.updated_at() {
            Held::Later(Box::new((entry.record.clone(), directory.identity.clone())))
        } else {
            Held::Other
        })
    }

    /// The listed certificate from the own record in the directory, when the own
    /// `identity.json` lists another certificate than the one the app presents and it holds
    /// no `cert.put` for it (Switch spec 3.2 step 3): taken only if the record is signed
    /// with the app's own signing key, and its certificate renews the one held and has the
    /// listed hash. The service holds that record, so nothing is delivered.
    ///
    /// It runs after a restore, whose own `identity.json` is the backup's: a renewal that
    /// another device of the app took since is listed only in a later one, and its
    /// `cert.put` shows as a stub once the record carries it. So the directory's own
    /// `identity.json` is taken first when it is newer, and the certificate it lists is the
    /// one checked (Switch spec 12.4 step 1 "Certificate"). A newer document that removes
    /// the app or names another generation is taken and nothing more is done here
    /// ([`Listed::NotCurrentHere`]): the read stops, or follows the provider change, and
    /// registers nothing at this switch. Otherwise it returns the own receive key record the
    /// same directory shows, which the restore's key check reads ([`Listed::Key`]).
    pub(crate) async fn take_listed_cert(&mut self) -> Result<Listed, AppError> {
        let me = self.state.meta.app_id;
        let result = self.client.directory(None).await;
        let directory = self.take(result).await?;
        if directory.identity.version() > self.state.own_doc.version() {
            self.take_own_copy(directory.identity.clone()).await?;
        }
        if self.not_current_here().is_some() {
            return Ok(Listed::NotCurrentHere);
        }
        let Some(entry) = directory.apps.into_iter().find(|app| app.app_id == me) else {
            return Ok(Listed::Key(None));
        };
        let key = entry.receive_key.clone();
        let Some(listed) = self.state.own_doc.listed_cert(&me) else {
            return Ok(Listed::Key(key));
        };
        if listed == self.state.cert.hash() {
            return Ok(Listed::Key(key));
        }
        if self
            .state
            .renewal
            .as_ref()
            .is_some_and(|r| r.hash() == listed)
        {
            self.adopt_renewal().await?;
            return Ok(Listed::Key(key));
        }
        let cert = entry.record.cert().clone();
        if cert.signing_key() == self.state.keys.signing_public()
            && cert.bundle_key() == self.state.keys.bundle_public()
            && is_renewal(&self.state.cert, &cert)
            && cert.hash() == listed
        {
            // The switch holds that record: it is the newest it accepted, and the published
            // copy is checked against it. A record change kept under the earlier certificate
            // is signed anew under this one, later than both records, and delivered by the
            // read, as `adopt_renewal` builds on a kept one: sent as it is, it would be
            // refused for its certificate, and read as the app not current.
            let taken = entry.record.signed().clone();
            let kept = self.state.pending_record.is_some();
            let record = if kept {
                let old = AppRecord::verify(&self.state.record, &self.state.meta.identity)?;
                let mut body = old.body().clone();
                body.cert = cert.signed().clone();
                body.accepts = self.protocols.accepts(&cert);
                body.updated_at = self
                    .now()
                    .max(old.updated_at().saturating_add(1))
                    .max(entry.record.updated_at().saturating_add(1));
                AppRecord::sign(&self.state.keys, body)?.signed().clone()
            } else {
                taken.clone()
            };
            self.take_cert(cert, record, kept, Some(taken)).await?;
        }
        Ok(Listed::Key(key))
    }
}

/// What the switch's directory shows for the app, beside a kept `app.put`'s record.
enum Held {
    /// That very record, byte for byte.
    This,
    /// A record of the app with a later `updated_at`, verified for the identity and the
    /// App ID as every directory entry is, with the own `identity.json` the same answer
    /// carried.
    Later(Box<(AppRecord, IdentityDoc)>),
    /// Another record, or none.
    Other,
}

/// What [`App::take_listed_cert`] found.
pub(crate) enum Listed {
    /// The app is current here: the own receive key record the directory shows, if any.
    Key(Option<pubky_switch_core::records::ReceiveKeyRecord>),
    /// The newest own `identity.json` removes the app or names another generation.
    NotCurrentHere,
}

/// The record a kept `app.put` batch delivers.
pub(crate) fn delivered_record(batch: &Batch) -> Result<SignedDoc, AppError> {
    batch
        .ops()
        .iter()
        .find_map(|op| match &op.body().kind {
            OpKind::AppPut { record } => Some(record.clone()),
            _ => None,
        })
        .ok_or_else(|| AppError::InvalidData("a kept app.put batch carries no record".into()))
}
