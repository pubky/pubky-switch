//! Routing: counterparties' `identity.json` and directories, the receive key checks, and
//! the deliveries of the own `identity.json` to their switches (Switch spec 4.3, 6.1, 8.1,
//! 12.2 step 5; Switch wire 3.8, 7.4.3, 7.4.5, 7.4.10).
//!
//! - **`identity.json`** of a counterparty is the newest copy the app took from any source
//!   (its Homeserver, its switch's directory), under the version floor and the equivocation
//!   check part 1 keeps (`ident/`). A copy older than 10 minutes is read again before a send;
//!   if the Homeserver can't be read the held copy still routes, as a cached directory may.
//! - **A directory** (`dir/<pubky>`) is cached while the counterparty's `identity.json`
//!   names the same switch and generation, and only for the `identity.json` version it was
//!   read under: a newer version, a newer `directory_version` in an append answer, or an
//!   answer naming apps no longer current, has it read again before the next send.
//! - **Recipients** are the current apps whose certificate allows receiving the kind and
//!   whose record lists it in `accepts`, narrowed by the protocol, each with a receive key
//!   record that passes the six checks of Switch spec 8.1 against the highest `n` seen for
//!   the app (`rkn/<pubky>/<app_id>`). An app that fails one counts as unreachable, and the
//!   message goes to the others.
//! - **The own `identity.json`** goes to a counterparty's switch (`PUT /peers`) before the
//!   first append there and whenever an answer shows the switch holds an older version
//!   (`peer/<pubky>`, from `known_version`), and, after an own delivery that removes an app
//!   or closes a renewal, to the switches the app wrote to in the last 30 days.

use pubky_switch_core::enc::{b64, pubky_id, serde_b64, zbase32_encode};
use pubky_switch_core::envelope::Recipient;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::message::Message;
use pubky_switch_core::records::{AppRecord, IdentityDoc, ReceiveKeyRecord, VersionOrder};
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::error::{Alarm, Refusal};
use super::events::AppEvent;
use super::identity::{self, DOC_CACHE_MS, Taken};
use super::state::CachedDoc;
use super::{App, AppError};
use crate::client::answers::Directory;
use crate::client::{Credentials, SwitchClient};
use crate::error::ClientError;

/// How long the app keeps delivering its own `identity.json` to the switches it wrote to:
/// the 30 days senders keep sent messages (Switch spec 12.2 step 5).
pub const PEER_DELIVERY_MS: u64 = 30 * pubky_switch_core::records::DAY_MS;

const DIR_PREFIX: &str = "dir/";
const PEER_PREFIX: &str = "peer/";
const PEERS_DOC: &str = "peers_doc";

fn dir_key(pubky: &[u8; 32]) -> String {
    format!("{DIR_PREFIX}{}", pubky_id(pubky))
}

fn peer_key(pubky: &[u8; 32]) -> String {
    format!("{PEER_PREFIX}{}", pubky_id(pubky))
}

fn highest_n_key(pubky: &[u8; 32], app_id: &[u8; 16]) -> String {
    format!("rkn/{}/{}", pubky_id(pubky), zbase32_encode(app_id))
}

/// One app of a cached directory, as signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CachedApp {
    #[serde(with = "serde_b64")]
    pub(crate) app_id: [u8; 16],
    pub(crate) record: SignedDoc,
    pub(crate) receive_key: Option<SignedDoc>,
}

/// `dir/<pubky>`: a counterparty's directory as the app read it (Switch spec 8.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CachedDirectory {
    pub(crate) origin: String,
    #[serde(with = "serde_b64")]
    pub(crate) service_key: [u8; 32],
    pub(crate) generation: u64,
    /// The `identity.json` version it was read under.
    pub(crate) identity_version: u64,
    pub(crate) directory_version: u64,
    pub(crate) apps_version: u64,
    pub(crate) apps: Vec<CachedApp>,
    /// Read again before the next send.
    pub(crate) stale: bool,
    /// When it was read, app clock.
    pub(crate) read_ms: u64,
}

/// `peer/<pubky>`: what a counterparty's switch holds of the own `identity.json`, and when
/// the app last wrote there.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PeerSwitch {
    /// The version its last answer named (`known_version`); `None` when it holds none.
    pub(crate) known_version: Option<u64>,
    /// When the switch last accepted a message from the app, app clock.
    pub(crate) last_sent_ms: Option<u64>,
}

/// `peers_doc`: the own `identity.json` the deliveries of Switch spec 12.2 step 5 were last
/// judged against: its version, removed apps and closed renewals.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct PeersDoc {
    version: u64,
    removed: Vec<String>,
    closed: Vec<String>,
}

/// One recipient app of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Route {
    pub(crate) app_id: [u8; 16],
    pub(crate) recipient: Recipient,
}

impl App {
    // ---------------------------------------------------------------------------------
    // identity.json of a counterparty

    /// The newest `identity.json` of `pubky`: the own one, or a copy at most 10 minutes old,
    /// read again from the Homeserver otherwise (`force` reads it again whatever its age). A
    /// held copy routes on when the Homeserver can't be read.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotNow`] for an identity seen equivocating, or one the app can get no copy
    /// of.
    pub(crate) async fn peer_identity(
        &mut self,
        pubky: &[u8; 32],
        force: bool,
    ) -> Result<IdentityDoc, AppError> {
        if *pubky == self.state.meta.identity {
            return Ok(self.state.own_doc.clone());
        }
        let reader = self.reader();
        if reader
            .exists(&super::state::key::ident_equivocated(pubky))
            .await?
        {
            return Err(Refusal::NotNow(
                "Switch spec 4.3: the counterparty's identity.json equivocated".into(),
            )
            .into());
        }
        let held = identity::held_copy(&reader, pubky).await?;
        let now = self.now();
        if let Some((doc, fetched)) = &held
            && !force
            && now.saturating_sub(*fetched) < DOC_CACHE_MS
        {
            return Ok(doc.clone());
        }
        match identity::read_homeserver(self.env.homeserver.as_ref(), pubky).await {
            Ok(Some(fetched)) => self.take_peer_copy(pubky, fetched, true).await,
            Ok(None) | Err(_) => held.map(|(doc, _)| doc).ok_or_else(|| {
                AppError::Refused(Refusal::NotNow(
                    "Switch spec 4.3: no identity.json of the counterparty can be read".into(),
                ))
            }),
        }
    }

    /// Take a counterparty's copy, from its Homeserver (`fresh`) or its switch, and return the
    /// newest held.
    async fn take_peer_copy(
        &mut self,
        pubky: &[u8; 32],
        doc: IdentityDoc,
        fresh: bool,
    ) -> Result<IdentityDoc, AppError> {
        let reader = self.reader();
        let held = identity::held_copy(&reader, pubky).await?;
        let now = self.now();
        let mut tx = self.tx()?;
        let held_doc = held.as_ref().map(|(doc, _)| doc);
        let fetched_ms = if fresh {
            now
        } else {
            held.as_ref().map_or(0, |(_, at)| *at)
        };
        let taken = identity::take_copy(&reader, &mut tx, &doc, held_doc, fetched_ms).await?;
        let newest = match taken {
            Err(equivocation) => {
                self.events.push(AppEvent::PeerEquivocation {
                    identity: *pubky,
                    version: equivocation.version,
                });
                self.commit(tx).await?;
                return Err(Refusal::NotNow(
                    "Switch spec 4.3: the counterparty's identity.json equivocated".into(),
                )
                .into());
            }
            Ok(Taken::Newer) => doc,
            Ok(Taken::Same | Taken::Older) => {
                let kept = held_doc.cloned().unwrap_or(doc);
                if fresh {
                    tx.put(
                        &super::state::key::ident_doc(pubky),
                        &CachedDoc {
                            doc: kept.signed().clone(),
                            fetched_ms: now,
                        },
                    )?;
                }
                kept
            }
        };
        self.commit(tx).await?;
        Ok(newest)
    }

    // ---------------------------------------------------------------------------------
    // Directories

    pub(crate) async fn cached_directory(
        &self,
        pubky: &[u8; 32],
    ) -> Result<Option<CachedDirectory>, AppError> {
        self.reader().get(&dir_key(pubky)).await
    }

    /// A client for `pubky`'s account at the switch its `identity.json` names, presenting
    /// the app's certificate (Switch wire 7.2).
    pub(crate) fn peer_client(
        &self,
        pubky: &[u8; 32],
        doc: &IdentityDoc,
    ) -> Result<SwitchClient, AppError> {
        Ok(SwitchClient::new(
            &doc.inbox().url,
            *pubky,
            Credentials::App {
                identity: self.state.meta.identity,
                keys: self.state.keys.clone(),
                cert: self.state.cert.clone(),
            },
            Some(doc.inbox().service_key),
            std::sync::Arc::clone(&self.env.transport),
            std::sync::Arc::clone(&self.env.clock),
        )?)
    }

    /// `pubky`'s directory: the cached one while it still holds (module docs), otherwise
    /// read again. `invite_code` admits a read at a switch that doesn't admit the app yet
    /// (Switch wire 7.4.10).
    ///
    /// # Errors
    ///
    /// As [`App::peer_identity`]; a failed read or commit.
    pub(crate) async fn directory_of(
        &mut self,
        pubky: &[u8; 32],
        invite_code: Option<&str>,
    ) -> Result<CachedDirectory, AppError> {
        let doc = self.peer_identity(pubky, false).await?;
        let cached = self.cached_directory(pubky).await?;
        if let Some(cached) = &cached
            && !cached.stale
            && cached.origin == doc.inbox().url
            && cached.generation == doc.generation()
            && cached.identity_version >= doc.version()
        {
            return Ok(cached.clone());
        }
        self.read_directory(pubky, &doc, cached, invite_code).await
    }

    async fn read_directory(
        &mut self,
        pubky: &[u8; 32],
        doc: &IdentityDoc,
        previous: Option<CachedDirectory>,
        invite_code: Option<&str>,
    ) -> Result<CachedDirectory, AppError> {
        let own = *pubky == self.state.meta.identity;
        let directory: Directory = if own {
            let result = self.client.directory(None).await;
            self.take(result).await?
        } else {
            let client = self.peer_client(pubky, doc)?;
            client.directory(invite_code).await?
        };
        let mut newest = doc.clone();
        if own {
            if directory.identity.compare(doc) == VersionOrder::Newer {
                self.take_own_copy(directory.identity.clone()).await?;
                newest = self.state.own_doc.clone();
            }
        } else {
            let taken = self
                .take_peer_copy(pubky, directory.identity.clone(), false)
                .await?;
            if taken.version() > newest.version() {
                newest = taken;
            }
            self.note_known_version(pubky, directory.known_version)
                .await?;
        }
        let cached = CachedDirectory {
            origin: doc.inbox().url.clone(),
            service_key: doc.inbox().service_key,
            generation: doc.generation(),
            identity_version: newest.version(),
            directory_version: directory.directory_version,
            apps_version: directory.apps_version,
            apps: directory
                .apps
                .iter()
                .map(|app| CachedApp {
                    app_id: app.app_id,
                    record: app.record.signed().clone(),
                    receive_key: app.receive_key.as_ref().map(|k| k.signed().clone()),
                })
                .collect(),
            stale: false,
            read_ms: self.now(),
        };
        let mut tx = self.tx()?;
        tx.put(&dir_key(pubky), &cached)?;
        self.commit(tx).await?;
        // A provider loss since the copy held: the old switch's accepted messages since the
        // previous check are sent again to the new one (Switch spec 8.1).
        if let Some(previous) = previous
            && !own
            && (previous.origin != cached.origin || previous.generation != cached.generation)
            && newest
                .body()
                .recovery_from
                .is_some_and(|lost| lost >= previous.generation)
        {
            self.resend_since(pubky, previous.read_ms).await?;
        }
        Ok(cached)
    }

    /// Drop `pubky`'s cached directory, so the next send reads it again.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn forget_directory(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        self.ready_local().await?;
        let mut tx = self.tx()?;
        tx.delete(&dir_key(pubky))?;
        self.commit(tx).await
    }

    pub(crate) async fn mark_directory_stale(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        if let Some(mut cached) = self.cached_directory(pubky).await? {
            cached.stale = true;
            let mut tx = self.tx()?;
            tx.put(&dir_key(pubky), &cached)?;
            self.commit(tx).await?;
        }
        Ok(())
    }

    /// The apps of `pubky` a message of `kind` would go to now (Switch spec 8.1), reading
    /// its `identity.json` and directory as a send would.
    ///
    /// # Errors
    ///
    /// As a send's directory read.
    pub async fn recipients_for(
        &mut self,
        pubky: &[u8; 32],
        message: &Message,
    ) -> Result<Vec<[u8; 16]>, AppError> {
        self.ready_local().await?;
        let (routes, _) = self.routes(pubky, message, None).await?;
        Ok(routes.into_iter().map(|r| r.app_id).collect())
    }

    /// The recipients of `message` and the `apps_version` they were chosen for. A cached
    /// directory that leaves no app is read again once before the counterparty counts as
    /// unreachable (Switch spec 8.1).
    pub(crate) async fn routes(
        &mut self,
        pubky: &[u8; 32],
        message: &Message,
        invite_code: Option<&str>,
    ) -> Result<(Vec<Route>, u64), AppError> {
        let directory = self.directory_of(pubky, invite_code).await?;
        let routes = self.choose(pubky, &directory, message).await?;
        if !routes.is_empty() {
            return Ok((routes, directory.apps_version));
        }
        let doc = self.peer_identity(pubky, false).await?;
        let directory = self
            .read_directory(pubky, &doc, Some(directory), invite_code)
            .await?;
        let routes = self.choose(pubky, &directory, message).await?;
        if routes.is_empty() {
            return Err(Refusal::NotNow(
                "Switch spec 8.1: no reachable app of the counterparty takes the kind".into(),
            )
            .into());
        }
        Ok((routes, directory.apps_version))
    }

    /// The apps of a directory a message goes to, each with a checked receive key.
    async fn choose(
        &mut self,
        pubky: &[u8; 32],
        directory: &CachedDirectory,
        message: &Message,
    ) -> Result<Vec<Route>, AppError> {
        let doc = self.peer_identity(pubky, false).await?;
        let now = self.now();
        let own = *pubky == self.state.meta.identity;
        let mut routes = Vec::new();
        let mut tx = self.tx()?;
        for app in &directory.apps {
            if own && app.app_id == self.state.meta.app_id {
                continue;
            }
            let Ok(record) = AppRecord::verify(&app.record, pubky) else {
                self.unreachable(pubky, app.app_id);
                continue;
            };
            let cert = record.cert();
            // Switch wire 3.8 checks 1 to 6 for a sender: the certificate the record carries,
            // unexpired now, current with it in the newest identity.json held.
            if cert.app_id() != app.app_id
                || cert.expired_at(now)
                || record.is_ahead(now)
                || !doc.current_now(&app.app_id, &cert.hash())
            {
                continue;
            }
            // Switch spec 3.4: the certificate allows the kind and `accepts` lists it, and
            // the protocol's narrower rule holds.
            if !self.protocol.receives(&message.kind, cert)
                || !record.accepts(&message.kind)
                || !self.protocol.sends_to(message, &record)
            {
                continue;
            }
            let checked = match &app.receive_key {
                Some(signed) => {
                    self.check_receive_key(pubky, &record, signed, &mut tx)
                        .await?
                }
                None => None,
            };
            match checked {
                Some(key) => routes.push(Route {
                    app_id: app.app_id,
                    recipient: Recipient::new(key.x25519()),
                }),
                None => self.unreachable(pubky, app.app_id),
            }
        }
        self.commit(tx).await?;
        Ok(routes)
    }

    fn unreachable(&mut self, pubky: &[u8; 32], app_id: [u8; 16]) {
        self.events.push(AppEvent::UnreachableApp {
            identity: *pubky,
            app_id,
        });
    }

    /// The checks of Switch spec 8.1 on one receive key record: its signature with the
    /// record's key, its identity and App ID, its kid derived from a key not of low order
    /// (the core's [`ReceiveKeyRecord::verify`]), and an `n` not below the highest seen for
    /// the app, which then moves up.
    async fn check_receive_key(
        &mut self,
        pubky: &[u8; 32],
        record: &AppRecord,
        signed: &SignedDoc,
        tx: &mut super::state::Tx,
    ) -> Result<Option<ReceiveKeyRecord>, AppError> {
        let Ok(key) = ReceiveKeyRecord::verify(signed, record.cert()) else {
            return Ok(None);
        };
        if key.body().identity != *pubky {
            return Ok(None);
        }
        let slot = highest_n_key(pubky, &record.cert().app_id());
        let highest: u64 = self.reader().get(&slot).await?.unwrap_or(0);
        if key.n() < highest {
            return Ok(None);
        }
        if key.n() > highest {
            tx.put(&slot, &key.n())?;
        }
        Ok(Some(key))
    }

    /// The records of a `409 stale_key` answer (Switch wire 7.6): each current record is
    /// checked as a directory's and replaces the cached one; apps no longer current leave
    /// the cache; apps added since are checked, against an `identity.json` read again if the
    /// one held doesn't list them, and join it; the `apps_version` moves on.
    pub(crate) async fn take_stale_key(
        &mut self,
        pubky: &[u8; 32],
        current: &Value,
    ) -> Result<(), AppError> {
        let Some(mut cached) = self.cached_directory(pubky).await? else {
            return Ok(());
        };
        let mut tx = self.tx()?;
        for entry in array(current, "receive_keys") {
            let (Some(app_id), Some(signed)) =
                (app_id_of(entry, "app_id"), doc_of(entry, "record"))
            else {
                continue;
            };
            let Some(index) = cached.apps.iter().position(|a| a.app_id == app_id) else {
                continue;
            };
            let Some(app) = cached.apps.get(index) else {
                continue;
            };
            let Ok(record) = AppRecord::verify(&app.record, pubky) else {
                continue;
            };
            if self
                .check_receive_key(pubky, &record, &signed, &mut tx)
                .await?
                .is_some()
                && let Some(app) = cached.apps.get_mut(index)
            {
                app.receive_key = Some(signed);
            }
        }
        let gone: Vec<[u8; 16]> = current
            .get("not_current")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str())
            .filter_map(|text| pubky_switch_core::enc::app_id_decode(text).ok())
            .collect();
        cached.apps.retain(|app| !gone.contains(&app.app_id));
        let added: Vec<([u8; 16], SignedDoc, SignedDoc)> = array(current, "added_apps")
            .filter_map(|entry| {
                Some((
                    app_id_of(entry, "app_id")?,
                    doc_of(entry, "app_record")?,
                    doc_of(entry, "record")?,
                ))
            })
            .collect();
        if !added.is_empty() {
            let mut doc = self.peer_identity(pubky, false).await?;
            let unlisted = added.iter().any(|(app_id, record, _)| {
                AppRecord::verify(record, pubky)
                    .map_or(true, |r| !doc.current_now(app_id, &r.cert().hash()))
            });
            if unlisted {
                doc = self.peer_identity(pubky, true).await?;
            }
            for (app_id, signed_record, receive_key) in added {
                let Ok(record) = AppRecord::verify(&signed_record, pubky) else {
                    continue;
                };
                if record.cert().app_id() != app_id
                    || !doc.current_now(&app_id, &record.cert().hash())
                {
                    continue;
                }
                if self
                    .check_receive_key(pubky, &record, &receive_key, &mut tx)
                    .await?
                    .is_some()
                {
                    cached.apps.retain(|a| a.app_id != app_id);
                    cached.apps.push(CachedApp {
                        app_id,
                        record: signed_record,
                        receive_key: Some(receive_key),
                    });
                }
            }
        }
        if let Some(version) = current.get("apps_version").and_then(Value::as_u64) {
            cached.apps_version = version;
        }
        if !gone.is_empty() {
            cached.stale = true;
        }
        tx.put(&dir_key(pubky), &cached)?;
        self.commit(tx).await
    }

    // ---------------------------------------------------------------------------------
    // The own identity.json at counterparties' switches (Switch spec 6.1, 12.2 step 5)

    pub(crate) async fn peer_switch(&self, pubky: &[u8; 32]) -> Result<PeerSwitch, AppError> {
        Ok(self
            .reader()
            .get(&peer_key(pubky))
            .await?
            .unwrap_or_default())
    }

    /// The version of the own `identity.json` a counterparty's switch named in a signed
    /// answer: its word, which may be lower than what the app delivered (a rollback, a
    /// provider change).
    pub(crate) async fn note_known_version(
        &mut self,
        pubky: &[u8; 32],
        known: Option<u64>,
    ) -> Result<(), AppError> {
        let mut peer = self.peer_switch(pubky).await?;
        if peer.known_version == known {
            return Ok(());
        }
        peer.known_version = known;
        let mut tx = self.tx()?;
        tx.put(&peer_key(pubky), &peer)?;
        self.commit(tx).await
    }

    pub(crate) async fn note_sent(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        let mut peer = self.peer_switch(pubky).await?;
        peer.last_sent_ms = Some(self.now());
        let mut tx = self.tx()?;
        tx.put(&peer_key(pubky), &peer)?;
        self.commit(tx).await
    }

    /// Deliver the own `identity.json` to `pubky`'s switch (`PUT /peers`, Switch wire
    /// 7.4.5) unless its last answer named this version or a later one; `force` delivers
    /// whatever it named, after `409 identity_needed`.
    ///
    /// # Errors
    ///
    /// The equivocation alarm when the switch holds another body of the own document at
    /// this version (Switch wire 7.4.5); a failed call.
    pub(crate) async fn deliver_own_identity(
        &mut self,
        pubky: &[u8; 32],
        invite_code: Option<&str>,
        force: bool,
    ) -> Result<(), AppError> {
        let own = self.state.own_doc.clone();
        let peer = self.peer_switch(pubky).await?;
        if !force && peer.known_version.is_some_and(|v| v >= own.version()) {
            return Ok(());
        }
        let doc = self.peer_identity(pubky, false).await?;
        let client = self.peer_client(pubky, &doc)?;
        match client.put_peers(own.signed(), invite_code).await {
            Ok(answer) => {
                self.note_known_version(pubky, Some(answer.known_version.unwrap_or(answer.version)))
                    .await
            }
            Err(ClientError::Switch {
                code: ErrorCode::StaleIdentity,
                current,
                ..
            }) => self.held_elsewhere(pubky, &own, &current).await,
            Err(error) => Err(error.into()),
        }
    }

    /// `409 stale_identity` at `PUT /peers`: the switch holds another body of the own
    /// document at this version, which is equivocation (an alarm), or a newer version,
    /// which the app reads from its Homeserver.
    async fn held_elsewhere(
        &mut self,
        pubky: &[u8; 32],
        own: &IdentityDoc,
        current: &Value,
    ) -> Result<(), AppError> {
        if let Some(held) = doc_of(current, "identity")
            && let Ok(held) = IdentityDoc::verify(&held, &self.state.meta.identity)
            && held.version() == own.version()
            && held.body_hash() != own.body_hash()
        {
            return Err(self
                .raise(Alarm::Equivocation {
                    version: own.version(),
                })
                .await);
        }
        let version = current.get("version").and_then(Value::as_u64);
        if version.is_some_and(|v| v > own.version()) {
            self.refresh_identity().await?;
        }
        self.note_known_version(pubky, version).await
    }

    /// After an own `identity.json` that removes an app or closes a renewal, deliver it to
    /// the switches the app wrote to in the last 30 days whose copy is older, by the
    /// `known_version` they last answered (Switch spec 12.2 step 5, 3.2). Each failure is
    /// tried again at the next call.
    pub(crate) async fn deliver_to_recent_peers(&mut self) -> Result<(), AppError> {
        let own = self.state.own_doc.clone();
        let judged: PeersDoc = self.reader().get(PEERS_DOC).await?.unwrap_or_default();
        if own.version() <= judged.version {
            return Ok(());
        }
        let removed: Vec<String> = own
            .body()
            .removed
            .iter()
            .map(|r| zbase32_encode(&r.app_id))
            .collect();
        let closed: Vec<String> = own
            .body()
            .renewed
            .iter()
            .filter(|r| r.until.is_some())
            .map(|r| b64(&r.cert))
            .collect();
        // Without an earlier judgement, any removal or closed renewal counts as new.
        let owed = removed.iter().any(|r| !judged.removed.contains(r))
            || closed.iter().any(|c| !judged.closed.contains(c));
        if owed {
            let now = self.now();
            let peers = self.reader().scan::<PeerSwitch>(PEER_PREFIX).await?;
            for (rest, peer) in peers {
                let recent = peer
                    .last_sent_ms
                    .is_some_and(|at| now.saturating_sub(at) < PEER_DELIVERY_MS);
                if !recent || peer.known_version.is_some_and(|v| v >= own.version()) {
                    continue;
                }
                let Ok(pubky) = pubky_switch_core::enc::pubky_key(&rest) else {
                    continue;
                };
                // A switch that can't be reached now gets it at a later call: the judged
                // version stays behind until every delivery went.
                if self
                    .deliver_own_identity(&pubky, None, false)
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
        }
        let mut tx = self.tx()?;
        tx.put(
            PEERS_DOC,
            &PeersDoc {
                version: own.version(),
                removed,
                closed,
            },
        )?;
        self.commit(tx).await
    }
}

fn array<'a>(value: &'a Value, name: &str) -> impl Iterator<Item = &'a Value> {
    value
        .get(name)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn app_id_of(value: &Value, name: &str) -> Option<[u8; 16]> {
    pubky_switch_core::enc::app_id_decode(value.get(name)?.as_str()?).ok()
}

fn doc_of(value: &Value, name: &str) -> Option<SignedDoc> {
    SignedDoc::from_strict_value(value.get(name)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_directory_stale_key_members_read_leniently() {
        let current = json!({ "receive_keys": [ { "app_id": "x", "record": 1 } ],
                              "not_current": ["not-an-id"], "apps_version": 5 });
        assert_eq!(array(&current, "receive_keys").count(), 1);
        let entry = array(&current, "receive_keys").next().unwrap();
        assert!(app_id_of(entry, "app_id").is_none());
        assert!(doc_of(entry, "record").is_none());
        assert_eq!(array(&current, "added_apps").count(), 0);
    }

    #[test]
    fn test_directory_keys_sort_by_identity_and_app() {
        let a = highest_n_key(&[1; 32], &[2; 16]);
        assert!(a.starts_with("rkn/"));
        assert!(dir_key(&[1; 32]).starts_with(DIR_PREFIX));
        assert!(peer_key(&[1; 32]).starts_with(PEER_PREFIX));
    }
}
