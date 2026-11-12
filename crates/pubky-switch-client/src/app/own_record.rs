//! The app's own record and its own signatures: what a protocol changes in the record, and
//! signing under a protocol's own label.
//!
//! **The record** (Switch spec 4.2, Switch wire 3.2). The app record carries one member per
//! protocol under `protocols`, the kinds the app takes in `accepts`, and an `expires_at` of
//! the app's choice. Whenever one of them changes, the app signs a new record with an
//! `updated_at` later than every record of it before, and delivers it to its switch with
//! `app.put` (Switch wire 6.2). An app whose protocol needs public data also publishes the
//! same record on its identity's Homeserver, at `/pub/pubky-switch/v1/apps/<app_id>.json`
//! (Switch spec 3.4, 4.1), as the carrying form of Switch wire 2.2.
//!
//! **Order of the writes.** Each record is signed once and kept (`record`, `pending/record`)
//! before its `app.put` is first sent, and sent again byte for byte until answered. Once the
//! switch holds it, the commit that records the answer keeps it under `pending/publish`, for
//! an app that publishes, and only then is it written to the Homeserver: the record
//! published is the one delivered, in the same bytes (Switch spec 4.2: an app delivers its
//! record with `app.put` before it publishes it, and publishes again a publication that
//! failed; Switch wire 2.1 "Sign once"). A delivery that fails keeps the record and goes
//! again at the next read, before anything is published; a Homeserver write that fails
//! stays owed, and goes again at the next read or with the next change, without failing the
//! read. Until then, readers of the Homeserver see the record published before.
//!
//! **Renewal.** The Switch sets no schedule for renewing a record: `expires_at` is the app's
//! choice (Switch spec 4.2). A protocol whose readers rely on its apps' records picks one
//! and calls [`App::renew_record`] by it.
//!
//! **A protocol's signatures** (Switch spec 1, 13.2; Switch wire 2.3). A protocol's own
//! formats sign `lp(label, fields...)` with the app's signing key under a label of the
//! protocol's, never under a `pubky-switch/v1/` label, so no input of a protocol's format is
//! an input of one of the Switch's.

use pubky_switch_core::labels::is_switch_label;
use pubky_switch_core::records::{AppRecord, AppRecordBody, app_record_path};
use pubky_switch_core::sig::SignedDoc;
use serde_json::{Map, Value};

use super::events::AppEvent;
use super::state::{PendingRecord, key};
use super::{App, AppError, Refusal};
use crate::error::TransportError;
use crate::transport::BoxFuture;

/// Writes the app's public files on its own identity's Homeserver.
///
/// Object-safe; the app holds an `Arc<dyn HomeserverWriter>`. The host implements it on the
/// Pubky session of the app's grant, which covers the app's record path (Switch spec 3.4);
/// tests fake it.
pub trait HomeserverWriter: Send + Sync {
    /// Put `bytes` at `path` on `identity`'s Homeserver, replacing what is there.
    ///
    /// # Errors
    ///
    /// A [`TransportError`] when the Homeserver can't be written now.
    fn put(
        &self,
        identity: [u8; 32],
        path: String,
        bytes: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), TransportError>>;
}

/// Where the app's record stands on the Homeserver after a call (Switch spec 4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Publication {
    /// The app doesn't publish its record ([`super::AppConfig::publishes_record`]): the switch
    /// alone holds it.
    NotPublishing,
    /// The Homeserver holds the record the switch holds: nothing is owed.
    Published,
    /// The switch holds the record, and its Homeserver write failed: it stays owed, and goes
    /// again at the next read or with the next change.
    Owed {
        /// Why the write failed.
        error: TransportError,
    },
}

impl App {
    /// Set the member `protocol` adds to the app's record, or remove it with `None`, and
    /// the record's `expires_at`, `None` for a record that doesn't expire (Switch spec 4.2).
    /// The new record is signed once, kept, delivered with `app.put`, and then published on
    /// the Homeserver by an app that publishes. When neither changes, nothing is signed, and
    /// only what is owed of an earlier record goes.
    ///
    /// The switch checks only the member's form: `protocol` has the syntax of a scope name,
    /// and the member follows the JSON rules of the rest of the record (Switch wire 1.1, 3.2).
    /// What goes inside it, and whether a protocol requires `expires_at`, are the protocol's.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a name or a member the switch would refuse, or a record over
    /// the operation cap, before anything is kept; [`Refusal::Stopped`], [`Refusal::Left`]
    /// or [`Refusal::Gone`]; a store failure; the error of the delivery, after which the
    /// record is kept and goes again at the next read.
    pub async fn set_protocol_member(
        &mut self,
        protocol: &str,
        member: Option<Map<String, Value>>,
        expires_at: Option<u64>,
    ) -> Result<Publication, AppError> {
        // The name's form is the core's check, at signing (Switch wire 3.2).
        let protocol = protocol.to_owned();
        Box::pin(async move {
            let mut body = self.own_record_body().await?;
            match member {
                Some(member) => body.protocols.insert(protocol, member),
                None => body.protocols.remove(&protocol),
            };
            body.expires_at = expires_at;
            self.put_own_record(body, false).await
        })
        .await
    }

    /// Renew the app's record: sign it again with a new `updated_at` and `expires_at`, the
    /// rest unchanged, deliver it and publish it (Switch spec 4.2).
    ///
    /// The Switch sets no schedule for it: when to renew is the protocol's to choose, and a
    /// protocol whose readers rely on its apps' records must choose one, or its records
    /// lapse. Readers trust a record until the earlier of its `expires_at` and its
    /// `updated_at` plus the identity's record age limit (Switch spec 4.3,
    /// `record_max_age`), so a schedule renews within both.
    ///
    /// # Errors
    ///
    /// As [`App::set_protocol_member`].
    pub async fn renew_record(&mut self, expires_at: Option<u64>) -> Result<Publication, AppError> {
        Box::pin(async move {
            let mut body = self.own_record_body().await?;
            body.expires_at = expires_at;
            self.put_own_record(body, true).await
        })
        .await
    }

    /// Bring the record's `accepts` to the kinds [`super::Protocol::accepts`] gives for the
    /// certificate the app presents, which are never wider than what its scopes receive
    /// (Switch spec 3.4). When they differ from the record's, the record is signed again,
    /// delivered and published; otherwise only what is owed goes.
    ///
    /// # Errors
    ///
    /// As [`App::set_protocol_member`].
    pub async fn update_accepts(&mut self) -> Result<Publication, AppError> {
        Box::pin(async move {
            let mut body = self.own_record_body().await?;
            body.accepts = self.protocol.accepts(&self.state.cert);
            self.put_own_record(body, false).await
        })
        .await
    }

    /// Send what is owed of the app's record: its delivery, then its Homeserver write. A read
    /// ([`App::receive`]) does the same.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`], [`Refusal::Left`] or [`Refusal::Gone`]; a store failure; the
    /// error of the delivery.
    pub async fn publish_record(&mut self) -> Result<Publication, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            self.deliver_record().await
        })
        .await
    }

    /// Sign `lp(label, fields...)` with the app's signing key, for a format of a protocol on
    /// the Switch, such as a grant its verifiers check with the key the app's certificate
    /// names (Switch spec 1, 13.2; Switch wire 2.1, 2.3). The fields are encoded as Switch
    /// wire 1.4 gives; the label is the protocol's own. Sign once: the caller keeps the
    /// signature with the bytes it signed, and never signs the same body again.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a `pubky-switch/v1/` label, which only the Switch's formats
    /// use (Switch spec 13.2 "Labels"); [`Refusal::Stopped`], [`Refusal::Left`] or
    /// [`Refusal::Gone`].
    pub fn sign_protocol(&self, label: &str, fields: &[&[u8]]) -> Result<[u8; 64], AppError> {
        self.refuse_when_stopped()?;
        if is_switch_label(label) {
            return Err(Refusal::Usage(
                "Switch spec 13.2: a protocol signs under labels of its own, never a \
                 pubky-switch/v1/ label"
                    .into(),
            )
            .into());
        }
        Ok(self.state.keys.sign(label, fields))
    }

    /// The body of the record the app presents, once the app may change it.
    async fn own_record_body(&mut self) -> Result<AppRecordBody, AppError> {
        self.ready_local().await?;
        self.refuse_when_stopped()?;
        let record = AppRecord::verify(&self.state.record, &self.state.meta.identity)?;
        Ok(record.body().clone())
    }

    /// Sign `body` as the app's next record, unless it is the record held and `renew` is
    /// false; keep it with its `app.put` in one commit, then deliver and publish.
    async fn put_own_record(
        &mut self,
        mut body: AppRecordBody,
        renew: bool,
    ) -> Result<Publication, AppError> {
        let identity = self.state.meta.identity;
        let held = AppRecord::verify(&self.state.record, &identity)?;
        if renew || &body != held.body() {
            // Later than every record of the app before (Switch spec 4.2): the one held is
            // the newest this device delivered or took.
            body.updated_at = self.now().max(held.updated_at().saturating_add(1));
            let record = AppRecord::sign(&self.state.keys, body).map_err(refused)?;
            // The switch reads the record strictly (Switch wire 1.1, 3.2): a member it would
            // refuse is refused here, before anything is kept.
            AppRecord::verify(record.signed(), &identity).map_err(refused)?;
            let batch = self.record_batch(record.signed()).map_err(refused)?;
            let pending = PendingRecord {
                body: batch.body().to_vec(),
            };
            let mut tx = self.tx()?;
            tx.put(key::RECORD, record.signed())?;
            tx.put(key::PENDING_RECORD, &pending)?;
            self.commit(tx).await?;
            self.state.record = record.signed().clone();
            self.state.pending_record = Some(pending);
        }
        self.deliver_record().await
    }

    /// Keep `record`, which the switch now holds, to be published, in `tx`: for an app that
    /// publishes, the commit that records its delivery owes its Homeserver write.
    pub(crate) fn owe_publish(
        &self,
        record: &SignedDoc,
        tx: &mut super::state::Tx,
    ) -> Result<(), AppError> {
        if self.config.publishes_record {
            tx.put(key::PENDING_PUBLISH, record)?;
        }
        Ok(())
    }

    /// Write the owed record to the Homeserver, the bytes the switch holds, and commit that
    /// nothing is owed. A write that fails stays owed and is reported
    /// ([`AppEvent::RecordPublishFailed`]); only the store's failure is an error.
    pub(crate) async fn publish_owed(&mut self) -> Result<Publication, AppError> {
        if !self.config.publishes_record {
            return Ok(Publication::NotPublishing);
        }
        let Some(record) = self.state.pending_publish.clone() else {
            return Ok(Publication::Published);
        };
        let writer = self.publisher()?;
        let bytes = serde_json::to_vec(&record)
            .map_err(|_| AppError::InvalidData("the record doesn't serialize".into()))?;
        let path = app_record_path(&self.state.meta.app_id);
        if let Err(error) = writer.put(self.state.meta.identity, path, bytes).await {
            self.events.push(AppEvent::RecordPublishFailed {
                error: error.to_string(),
            });
            return Ok(Publication::Owed { error });
        }
        let mut tx = self.tx()?;
        tx.delete(key::PENDING_PUBLISH)?;
        self.commit(tx).await?;
        self.state.pending_publish = None;
        Ok(Publication::Published)
    }

    /// The Homeserver writer of an app that publishes its record.
    pub(crate) fn publisher(&self) -> Result<std::sync::Arc<dyn HomeserverWriter>, AppError> {
        check_publisher(&self.env, &self.config)?;
        self.env
            .homeserver_writer
            .clone()
            .ok_or_else(|| Refusal::Usage(NO_WRITER.into()).into())
    }
}

const NO_WRITER: &str = "an app that publishes its record needs a Homeserver writer";

/// An app that publishes its record needs a Homeserver writer in its environment.
pub(crate) fn check_publisher(
    env: &super::AppEnv,
    config: &super::AppConfig,
) -> Result<(), AppError> {
    if config.publishes_record && env.homeserver_writer.is_none() {
        return Err(Refusal::Usage(NO_WRITER.into()).into());
    }
    Ok(())
}

/// A record the core or the switch would refuse is the caller's to fix.
fn refused(error: impl std::fmt::Display) -> AppError {
    Refusal::Usage(format!("the app record: {error}")).into()
}
