//! Certificate renewal, the app's side (Switch spec 3.2 steps 3 and 4; Switch wire 3.8).
//!
//! The signer stores the app's renewed certificate at the service (`cert.put`, in the
//! feed), then delivers an `identity.json` listing its hash. The app keeps the certificate
//! from `cert.put` and takes it once its own `identity.json` lists it: it presents it from
//! then on, and delivers its record carrying it (`app.put`), signed once and kept before it
//! is sent. An app without the `cert.put`, such as one restored from a backup older than
//! the renewal, takes the listed certificate from its own record in its directory, under
//! the checks of Switch spec 3.2 step 3.

use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ops::{Condition, OpKind};
use pubky_switch_core::records::{AppCert, AppRecord, is_renewal};
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
        body.accepts = self.protocol.accepts(&renewal);
        body.updated_at = self.now().max(old.updated_at().saturating_add(1));
        let record = AppRecord::sign(&self.state.keys, body)?;
        self.take_cert(renewal, record.signed().clone(), true)
            .await?;
        self.deliver_record().await?;
        Ok(true)
    }

    /// Present `cert` from now on, with `record`; `deliver` signs its `app.put` and keeps it
    /// before it is sent. A certificate that reads a member of a collection of the protocol
    /// the one before didn't owes a listing, in the same commit, so the next read lists it (Switch
    /// spec 8.3, Switch wire 7.4.9): the writes made there before it were stubs in the feed.
    async fn take_cert(
        &mut self,
        cert: AppCert,
        record: SignedDoc,
        deliver: bool,
    ) -> Result<(), AppError> {
        let issued_at = cert.issued_at();
        // Member by member: a scope of the new certificate that reads a collection's member,
        // its fixed read scope or a sub-scope of its family, and that the one before doesn't
        // hold (Switch spec 3.3).
        let collections = self.protocol.collections();
        let widened = cert.scopes().iter().any(|scope| {
            !self.state.cert.holds_scope(scope)
                && collections.iter().any(|c| c.read_by_scope(scope))
        });
        self.state.cert = cert;
        self.rebuild_client()?;
        let mut tx = self.tx()?;
        if widened {
            tx.put(super::records::LIST_DUE, &true)?;
        }
        tx.put(key::CERT, self.state.cert.signed())?;
        tx.put(key::RECORD, &record)?;
        tx.delete(key::CERT_RENEWAL)?;
        if deliver {
            let pending = PendingRecord {
                body: self.record_batch(&record)?.body().to_vec(),
            };
            tx.put(key::PENDING_RECORD, &pending)?;
            self.state.pending_record = Some(pending);
        }
        self.state.record = record;
        self.state.renewal = None;
        self.commit(tx).await?;
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

    /// Send the kept `app.put` until answered. A `409 conflict` naming a record of this app
    /// with an `updated_at` at or after this one's (another device's) is written again
    /// once, later than the held one (Switch spec 4.2). Once the switch holds the record,
    /// an app that publishes owes it to the Homeserver, in the commit that records the
    /// answer, and writes it there (`own_record.rs`).
    pub(crate) async fn deliver_record(&mut self) -> Result<Publication, AppError> {
        let Some(pending) = self.state.pending_record.clone() else {
            return Box::pin(self.publish_owed()).await;
        };
        let mut batch = Batch::from_body(pending.body)?;
        let result = self.submit(&batch).await;
        let held = match result {
            Ok(_) => None,
            Err(AppError::Switch(ClientError::Switch {
                code: ErrorCode::Conflict,
                current,
                ..
            })) => current
                .get("record")
                .and_then(|value| SignedDoc::from_strict_value(value).ok())
                .and_then(|doc| AppRecord::verify(&doc, &self.state.meta.identity).ok()),
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
        self.owe_publish(&delivered, &mut tx)?;
        self.state.pending_record = None;
        self.commit(tx).await?;
        if self.config.publishes_record {
            self.state.pending_publish = Some(delivered);
        }
        Box::pin(self.publish_owed()).await
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
            self.take_cert(cert, entry.record.signed().clone(), false)
                .await?;
        }
        Ok(Listed::Key(key))
    }
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
