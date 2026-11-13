//! Push, the app's side (Switch spec 9; Switch wire 8.1, 8.3).
//!
//! A registration is the app's, at its current service, in three steps:
//!
//! 1. **Start** (`PUT /push` without handles): the service mints a push key, or answers the
//!    registration it holds for the same relay, unchanged. A start replaces a registration
//!    only when it names that registration's push key (`replaces`): that is how the app
//!    rotates its push key or moves to another relay. A start for another relay without
//!    `replaces` is `409 conflict` naming the current key, which the app then names.
//! 2. **Relay**: the device registers its token with the vendor's relay, bound to that push
//!    key, through the host's [`PushRelay`]; the relay answers an opaque handle.
//! 3. **Set** (`PUT /push` with the handles and the push key): a push key that isn't the
//!    current registration's is `409 conflict`, and the app starts again. The list replaces
//!    the service's, so an app on several devices sends the merged list: this device's
//!    handle and those of its other devices bound to the same push key, which the host
//!    shares through its own device sync ([`App::push_handles`],
//!    [`App::take_device_push_handles`]; Switch wire 8.1).
//!
//! Each step is committed as it completes, so a crash resumes with the same requests: a
//! start is idempotent without a nonce. A rotation whose answer was lost is retried naming
//! the key it replaced; the service answers `409 conflict` with the key now current, which
//! the app takes, since the registration is the app's. After a provider change the next
//! service holds no registration, so the app starts afresh there; when the app stops being
//! current the service drops it, and the app drops its setting.

use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::net::{UrlUse, check_url};
use serde::{Deserialize, Serialize};

use super::App;
use super::error::{AppError, Refusal};
use super::events::AppEvent;
use crate::client::answers::PushSetting;
use crate::error::{ClientError, TransportError};
use crate::transport::BoxFuture;

/// The longest handle the app keeps from a relay, its own bound on the opaque handle
/// (Switch spec 9 step 2).
pub const MAX_HANDLE_BYTES: usize = 1024;

/// The most handles one registration holds, one per device (Switch wire 8.1).
pub const MAX_HANDLES: usize = 8;

/// The key of the push setting (`STATE.md`, "Moves, recovery and push").
pub(crate) const KEY: &str = "push";

/// The key of the handles of the app's other devices.
pub(crate) const DEVICES_KEY: &str = "push/devices";

/// Push handles bound to one push key: this device's, from [`App::push_handles`], for the
/// host's device sync to share, and the other devices', given back through
/// [`App::take_device_push_handles`]. Its `Debug` shows no handle.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushHandles {
    /// The push key the handles are bound to.
    #[serde(with = "pubky_switch_core::enc::serde_b64")]
    pub push_key: [u8; 32],
    /// The handles.
    pub handles: Vec<String>,
}

impl std::fmt::Debug for PushHandles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PushHandles({} handles)", self.handles.len())
    }
}

/// The vendor's push relay, as the app registers its device there (Switch spec 9 step 2,
/// Switch wire 8.3). The host implements it; object-safe, the app takes `&dyn PushRelay`.
pub trait PushRelay: Send + Sync {
    /// Register `device_token` with the relay at `relay_url`, bound to `push_key`, the public
    /// half of the push key the app's service minted. Returns the relay's handle, random and
    /// opaque, usable only with that push key.
    ///
    /// # Errors
    ///
    /// A [`TransportError`] when the relay can't be reached or refuses.
    fn register(
        &self,
        relay_url: String,
        device_token: String,
        push_key: [u8; 32],
    ) -> BoxFuture<'_, Result<String, TransportError>>;
}

/// The app's push registration at its current service.
#[derive(Clone, PartialEq, Eq)]
pub struct PushRegistration {
    /// The relay URL.
    pub relay_url: String,
    /// The registration's push key, its public half.
    pub push_key: [u8; 32],
    /// The handles the service keeps.
    pub handles: u64,
}

impl std::fmt::Debug for PushRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PushRegistration({} handles)", self.handles)
    }
}

/// `push`: the push setting, its device token, and where the registration stands. Its
/// `Debug` shows neither the token nor the handle.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PushRecord {
    pub(crate) relay_url: String,
    pub(crate) device_token: String,
    /// The service the registration is at.
    pub(crate) service_key: [u8; 32],
    pub(crate) push_key: Option<[u8; 32]>,
    pub(crate) handle: Option<String>,
    /// The handles are set at the service.
    pub(crate) set: bool,
    /// The handles the service keeps, once set.
    pub(crate) handles: u64,
    /// A start in flight that names this push key in `replaces`.
    pub(crate) replacing: Option<[u8; 32]>,
}

impl std::fmt::Debug for PushRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PushRecord(set: {})", self.set)
    }
}

/// The most starts one registration call makes: a start, one naming the key a conflict
/// shows, and one after the handles' conflict.
const MAX_STARTS: usize = 3;

fn usage(why: &str) -> AppError {
    AppError::Refused(Refusal::Usage(why.into()))
}

/// The push key a `409 conflict` names: `Some(None)` for `null`, `None` when it names none.
fn conflict_key(current: &serde_json::Value) -> Option<Option<[u8; 32]>> {
    match current.get("push_key")? {
        serde_json::Value::Null => Some(None),
        serde_json::Value::String(text) => pubky_switch_core::enc::unb64_array::<32>(text)
            .ok()
            .map(Some),
        _ => None,
    }
}

impl App {
    /// Register this device for pushes at the app's current service, through `relay`
    /// (Switch spec 9 steps 1 to 3). Registering again with the same relay changes nothing at
    /// the service; another relay replaces the app's registration, naming its push key.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a relay URL that isn't `https://` on port 443 without user
    /// info, an empty device token, or a handle the app doesn't keep; a failed call or
    /// commit, after which the same call resumes.
    pub async fn register_push(
        &mut self,
        relay: &dyn PushRelay,
        relay_url: &str,
        device_token: &str,
    ) -> Result<PushRegistration, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let service = self.state.meta.service_key;
            let held = self.push_record().await?;
            let replaces = held
                .filter(|r| r.service_key == service && r.relay_url != relay_url)
                .and_then(|r| r.push_key);
            let result = self
                .push_flow(relay, relay_url, device_token, replaces)
                .await;
            if result.is_err() {
                self.reload = true;
            }
            result
        })
        .await
    }

    /// Rotate the push key: a start naming the current one, then the relay and the handles
    /// again (Switch spec 9 step 1).
    ///
    /// # Errors
    ///
    /// [`Refusal::NotNow`] without a registration at the current service; otherwise as
    /// [`App::register_push`].
    pub async fn rotate_push_key(
        &mut self,
        relay: &dyn PushRelay,
    ) -> Result<PushRegistration, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let service = self.state.meta.service_key;
            let Some(held) = self
                .push_record()
                .await?
                .filter(|r| r.service_key == service)
            else {
                return Err(Refusal::NotNow("no push registration at this service".into()).into());
            };
            // A rotation in flight goes on naming the key it replaces.
            let Some(replaces) = held.replacing.or(held.push_key) else {
                return Err(Refusal::NotNow("no push key to replace".into()).into());
            };
            let result = self
                .push_flow(relay, &held.relay_url, &held.device_token, Some(replaces))
                .await;
            if result.is_err() {
                self.reload = true;
            }
            result
        })
        .await
    }

    /// Register again with the setting the app keeps when its registration isn't set at
    /// its current service: after a provider change (Switch spec 9 "Relay rules"), or a
    /// registration a crash left half done. `None` without a setting.
    ///
    /// # Errors
    ///
    /// As [`App::register_push`].
    pub async fn reregister_push(
        &mut self,
        relay: &dyn PushRelay,
    ) -> Result<Option<PushRegistration>, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let Some(held) = self.push_record().await? else {
                return Ok(None);
            };
            if held.set && held.service_key == self.state.meta.service_key {
                return self.push_registration().await;
            }
            let replaces = held
                .replacing
                .filter(|_| held.service_key == self.state.meta.service_key);
            let result = self
                .push_flow(relay, &held.relay_url, &held.device_token, replaces)
                .await
                .map(Some);
            if result.is_err() {
                self.reload = true;
            }
            result
        })
        .await
    }

    /// The app's push registration at its current service, once set.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn push_registration(&self) -> Result<Option<PushRegistration>, AppError> {
        let service = self.state.meta.service_key;
        Ok(self
            .push_record()
            .await?
            .filter(|r| r.set && r.service_key == service)
            .and_then(|r| {
                Some(PushRegistration {
                    relay_url: r.relay_url,
                    push_key: r.push_key?,
                    handles: r.handles,
                })
            }))
    }

    /// This device's handle and the push key it is bound to, once the relay answered:
    /// what the host's device sync shares with the app's other devices (Switch wire 8.1).
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn push_handles(&self) -> Result<Option<PushHandles>, AppError> {
        Ok(self.push_record().await?.and_then(|r| {
            Some(PushHandles {
                push_key: r.push_key?,
                handles: vec![r.handle?],
            })
        }))
    }

    /// Keep the handles of the app's other devices, from the host's device sync, so the
    /// next set of this device's handles sends the merged list (Switch wire 8.1). They
    /// replace those kept before; only those bound to the push key being set are sent.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for more handles than a registration holds besides this
    /// device's, or a handle the app doesn't keep; a store failure.
    pub async fn take_device_push_handles(&mut self, others: PushHandles) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            if others.handles.len() >= MAX_HANDLES {
                return Err(usage(
                    "Switch wire 8.1: at most 8 handles, this device's included",
                ));
            }
            if others
                .handles
                .iter()
                .any(|h| h.is_empty() || h.len() > MAX_HANDLE_BYTES)
            {
                return Err(usage(
                    "Switch spec 9 step 2: a device's handle isn't one the app keeps",
                ));
            }
            let mut tx = self.tx()?;
            tx.put(DEVICES_KEY, &others)?;
            self.commit(tx).await
        })
        .await
    }

    /// The handles to set for `key`: this device's first, then those of its other devices
    /// bound to the same key, each once.
    async fn merged_handles(&self, key: [u8; 32], own: String) -> Result<Vec<String>, AppError> {
        let mut handles = vec![own];
        if let Some(others) = self.reader().get::<PushHandles>(DEVICES_KEY).await?
            && others.push_key == key
        {
            for handle in others.handles {
                if !handles.contains(&handle) && handles.len() < MAX_HANDLES {
                    handles.push(handle);
                }
            }
        }
        Ok(handles)
    }

    pub(crate) async fn push_record(&self) -> Result<Option<PushRecord>, AppError> {
        self.reader().get(KEY).await
    }

    async fn save_push(&mut self, record: &PushRecord) -> Result<(), AppError> {
        let mut tx = self.tx()?;
        tx.put(KEY, record)?;
        self.commit(tx).await
    }

    /// The three steps, each committed as it completes.
    async fn push_flow(
        &mut self,
        relay: &dyn PushRelay,
        relay_url: &str,
        device_token: &str,
        mut replaces: Option<[u8; 32]>,
    ) -> Result<PushRegistration, AppError> {
        // Switch wire 8.1: https on port 443, no user info; the service checks the host's
        // addresses.
        check_url(relay_url, &UrlUse::Relay)
            .map_err(|_| usage("Switch wire 8.1: the relay URL isn't https on port 443"))?;
        if device_token.is_empty() {
            return Err(usage("Switch spec 9: an empty device token"));
        }
        let mut record = PushRecord {
            relay_url: relay_url.to_owned(),
            device_token: device_token.to_owned(),
            service_key: self.state.meta.service_key,
            push_key: None,
            handle: None,
            set: false,
            handles: 0,
            replacing: replaces,
        };
        self.save_push(&record).await?;
        for _ in 0..MAX_STARTS {
            // Step 1: the start.
            let start = PushSetting {
                relay_url: relay_url.to_owned(),
                handles: Vec::new(),
                push_key: None,
                replaces,
            };
            let result = self.client.put_push(&start).await;
            let key = match self.take(result).await {
                Ok(answer) if answer.relay_url == relay_url => answer.push_key,
                Ok(_) => {
                    return Err(AppError::InvalidData(
                        "Switch wire 8.1: the answer names another relay".into(),
                    ));
                }
                Err(AppError::Switch(ClientError::Switch {
                    code: ErrorCode::Conflict,
                    current,
                    ..
                })) => match (replaces, conflict_key(&current)) {
                    // The key replaced is no longer current: this rotation took, its answer
                    // lost, or another device's did; either way the registration is the
                    // app's.
                    (Some(old), Some(Some(now))) if now != old => now,
                    // A registration for another relay: replace it, naming its key.
                    (None, Some(Some(now))) => {
                        replaces = Some(now);
                        record.replacing = replaces;
                        self.save_push(&record).await?;
                        continue;
                    }
                    // No registration held: start afresh.
                    (Some(_), Some(None)) => {
                        replaces = None;
                        record.replacing = None;
                        self.save_push(&record).await?;
                        continue;
                    }
                    _ => {
                        return Err(AppError::InvalidData(
                            "Switch wire 8.1: a push conflict that names no other key".into(),
                        ));
                    }
                },
                Err(error) => return Err(error),
            };
            record.push_key = Some(key);
            record.replacing = None;
            replaces = None;
            self.save_push(&record).await?;
            // Step 2: the relay.
            let handle = relay
                .register(relay_url.to_owned(), device_token.to_owned(), key)
                .await?;
            if handle.is_empty() || handle.len() > MAX_HANDLE_BYTES {
                return Err(usage(
                    "Switch spec 9 step 2: the relay's handle isn't one the app keeps",
                ));
            }
            record.handle = Some(handle.clone());
            self.save_push(&record).await?;
            // Step 3: the handles, merged with the other devices' (Switch wire 8.1).
            let set = PushSetting {
                relay_url: relay_url.to_owned(),
                handles: self.merged_handles(key, handle).await?,
                push_key: Some(key),
                replaces: None,
            };
            let result = self.client.put_push(&set).await;
            match self.take(result).await {
                Ok(answer) if answer.push_key == key && answer.relay_url == relay_url => {
                    record.set = true;
                    record.handles = answer.handles;
                    self.save_push(&record).await?;
                    self.events.push(AppEvent::PushRegistered {
                        handles: answer.handles,
                    });
                    return Ok(PushRegistration {
                        relay_url: answer.relay_url,
                        push_key: key,
                        handles: answer.handles,
                    });
                }
                Ok(_) => {
                    return Err(AppError::InvalidData(
                        "Switch wire 8.1: the answer is of another registration".into(),
                    ));
                }
                // Another registration replaced this one meanwhile: start again.
                Err(AppError::Switch(ClientError::Switch {
                    code: ErrorCode::Conflict,
                    ..
                })) => {
                    record.push_key = None;
                    record.handle = None;
                    self.save_push(&record).await?;
                }
                Err(error) => return Err(error),
            }
        }
        Err(Refusal::NotNow("the push registration kept changing; try again".into()).into())
    }

    /// After a provider change: the next service holds no registration, so the setting is
    /// kept for [`App::reregister_push`] and reported (Switch spec 9, 12.5 step 4, 12.6 step
    /// 1).
    pub(crate) async fn push_after_provider_change(&mut self) -> Result<(), AppError> {
        let Some(mut record) = self.push_record().await? else {
            return Ok(());
        };
        if record.service_key == self.state.meta.service_key || record.push_key.is_none() {
            return Ok(());
        }
        record.push_key = None;
        record.handle = None;
        record.set = false;
        record.handles = 0;
        record.replacing = None;
        self.save_push(&record).await?;
        self.events.push(AppEvent::PushRemoved);
        Ok(())
    }
}
