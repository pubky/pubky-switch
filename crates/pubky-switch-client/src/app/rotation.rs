//! Receive keys (Switch spec 3.6, 12.4; Switch wire 3.4): rotation, deletion, the
//! registrations of the own app the feed shows, devices, and the restore question.
//!
//! - **Rotation:** at the first read at least the interval after the last rotation, if an
//!   envelope wrapped to the current key was opened since. The new key and its signed
//!   registration batch are committed before the batch is first sent.
//! - **Deletion:** a retired key goes once the cursor has passed the `seq` of the next
//!   key's registration; the cursor's commit comes first.
//! - **Unexpected registrations:** one of the own app with a kid no device of the app made
//!   is a compromise: the app stops, alerts the user, leaves at once and reports the
//!   `distrust_from` to ask the signer for, the service time of the registration's chain
//!   item. So is a `409 conflict` naming such a key; without its chain item, the app gives
//!   the later of the newest verified chain item's and its own last registration's times.
//! - **Devices:** an app that shares its keys across devices learns its devices' kids
//!   through its own device sync ([`App::device_keys`], [`App::take_device_keys`]); a
//!   registration it doesn't know waits for that sync, and one newer than every key it holds
//!   stops its reads until the key arrives.
//! - **After a restore:** a registration after the backup's newest key whose kid the app
//!   doesn't know, up to the key the restored app registers itself, may be its own or a
//!   thief's: the user is asked ([`App::restore_question`]), and no attempt is made until
//!   the answer. One after its own new key is a compromise at once.

use pubky_switch_core::enc::b64;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::keys::ReceiveKey;
use pubky_switch_core::ops::{Condition, OpKind};
use pubky_switch_core::records::{ReceiveKeyBody, ReceiveKeyRecord};
use pubky_switch_core::sig::SignedDoc;

use super::chain::ChainView;
use super::error::{Alarm, Refusal};
use super::events::AppEvent;
use super::state::{Device, HeldKey, KnownKid, RegStatus, Registration, Rotation, Tx, key};
use super::{App, AppError, DeviceKeys, HeldKeyOut, UserConfirmed};
use crate::client::Batch;
use crate::error::ClientError;

/// What a registration of the own app seen in the feed means for the read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RegistrationStep {
    /// Read on.
    Continue,
    /// Read no further: a key another device made and this one lacks.
    Stop,
    /// A registration no device of the app made: the app stops on this alarm.
    Compromise(Alarm),
}

impl App {
    /// The highest `n` the app holds a key for.
    fn current_n(&self) -> Option<u64> {
        self.state.receive_keys.keys().next_back().copied()
    }

    /// Rotate if due (Switch spec 3.6): the interval passed since the last rotation and an
    /// envelope wrapped to the current key was opened since. A push extension's peek never
    /// gets here.
    pub(crate) async fn maybe_rotate(&mut self) -> Result<(), AppError> {
        let rotation = self.state.rotation;
        let due = rotation.last_ms.saturating_add(self.config.rotation_ms());
        if rotation.opened_since && self.now() >= due {
            self.rotate().await?;
        }
        Ok(())
    }

    /// Register a fresh receive key, `n` one higher than the current one (Switch spec 3.6).
    /// Returns `false` when another device of the app registered first and this device
    /// discarded its key.
    ///
    /// # Errors
    ///
    /// A failed call or commit; the key and its batch are kept and sent again.
    pub async fn rotate(&mut self) -> Result<bool, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let current = self
                .current_n()
                .ok_or_else(|| AppError::Refused(Refusal::NotNow("no receive key held".into())))?;
            if let Some(held) = self.state.receive_keys.get(&current)
                && !held.pending.is_empty()
            {
                // A key kept before a crash, its registration not answered yet.
                return self.register(current).await;
            }
            let n = current
                .checked_add(1)
                .ok_or_else(|| AppError::InvalidData("receive key numbers ran out".into()))?;
            self.new_key(n).await?;
            self.register(n).await
        })
        .await
    }

    /// Make and keep key `n` with its signed registration batch, before anything is sent.
    pub(crate) async fn new_key(&mut self, n: u64) -> Result<(), AppError> {
        let key = ReceiveKey::generate(n)?;
        let record = ReceiveKeyRecord::sign(
            &self.state.keys,
            &self.state.cert,
            ReceiveKeyBody::new(&self.state.cert, &key),
        )?;
        // The batch is kept and may be sent again after the cursor moved on: a cursor move
        // in it could take the service's cursor back, so it carries none (Switch spec 8.2).
        let batch = self.sign_ops(
            vec![(
                Vec::<Condition>::new(),
                OpKind::ReceiveKeyPut {
                    record: record.signed().clone(),
                },
            )],
            None,
        )?;
        let held = HeldKey {
            key: key.clone(),
            record: record.signed().clone(),
            reg_seq: None,
            reg_time_ms: None,
            pending: batch.body().to_vec(),
        };
        let mut tx = self.tx()?;
        tx.put(&key::receive_key(n), &held)?;
        tx.put(&key::kid(&key.kid), &KnownKid { n })?;
        self.state.receive_keys.insert(n, held);
        self.state.known_kids.insert(key.kid, n);
        self.commit(tx).await
    }

    /// Send key `n`'s registration batch until answered, and take the answer.
    async fn register(&mut self, n: u64) -> Result<bool, AppError> {
        let Some(held) = self.state.receive_keys.get(&n).cloned() else {
            return Ok(false);
        };
        let batch = Batch::from_body(held.pending.clone())?;
        match self.submit(&batch).await {
            Ok(submitted) => {
                let at = submitted
                    .proofs
                    .first()
                    .map(|p| (p.envelope().seq, p.envelope().server_time));
                self.key_registered(n, at).await?;
                Ok(true)
            }
            Err(AppError::Switch(ClientError::Switch {
                code: ErrorCode::Conflict,
                current,
                ..
            })) => self.registration_conflict(n, &held, &current).await,
            Err(error) => Err(error),
        }
    }

    /// Key `n` is registered: note it with the `seq` and service time of its chain item
    /// when known.
    async fn key_registered(&mut self, n: u64, at: Option<(u64, u64)>) -> Result<(), AppError> {
        let now = self.now();
        let mut tx = self.tx()?;
        if let Some(held) = self.state.receive_keys.get_mut(&n) {
            if let Some((seq, time)) = at {
                held.reg_seq = Some(seq);
                held.reg_time_ms = Some(time);
            }
            held.pending.clear();
            tx.put(&key::receive_key(n), held)?;
        }
        self.state.rotation.last_ms = now;
        self.state.rotation.opened_since = false;
        tx.put(key::ROTATION, &self.state.rotation)?;
        tx.put(key::CURSOR, &self.state.cursor)?;
        if let Some(chain) = self.state.chain.as_mut() {
            chain.write(&mut tx)?;
        }
        self.commit(tx).await?;
        self.events.push(AppEvent::Rotated { n });
        Ok(())
    }

    /// A `409 conflict` on a registration (Switch wire 6.2): its `current.receive_key` is
    /// the key registered. The own key again is a lost answer; another device's makes this
    /// one discard its key; a key no device made is a compromise (Switch spec 3.6).
    async fn registration_conflict(
        &mut self,
        n: u64,
        held: &HeldKey,
        current: &serde_json::Value,
    ) -> Result<bool, AppError> {
        let record = self.conflict_receive_key(current).await?;
        if record.kid() == held.key.kid {
            self.key_registered(n, None).await?;
            return Ok(true);
        }
        self.registered_elsewhere(n, &record).await?;
        Ok(false)
    }

    /// The key a registration's `409 conflict` names in `current.receive_key`, verified
    /// with the app's certificate; without one, the own entry in the directory (Switch wire
    /// 6.2).
    pub(crate) async fn conflict_receive_key(
        &mut self,
        current: &serde_json::Value,
    ) -> Result<ReceiveKeyRecord, AppError> {
        let named = current
            .get("receive_key")
            .and_then(|value| SignedDoc::from_strict_value(value).ok())
            .and_then(|doc| ReceiveKeyRecord::verify(&doc, &self.state.cert).ok());
        let record = match named {
            Some(record) => Some(record),
            None => self.own_directory_key().await?,
        };
        record.ok_or_else(|| {
            AppError::InvalidData(
                "Switch wire 6.2: a registration conflict that names no receive key".into(),
            )
        })
    }

    /// Another key holds the place this device's key `n` was registered for (Switch spec
    /// 3.6): this device discards its own, never registered. A key one of the app's devices
    /// made is adopted; with keys shared across devices, an unknown one waits for the
    /// device sync; any other is a compromise: the app stops, leaves at once and returns
    /// the alarm.
    pub(crate) async fn registered_elsewhere(
        &mut self,
        n: u64,
        record: &ReceiveKeyRecord,
    ) -> Result<(), AppError> {
        let mut tx = self.tx()?;
        tx.delete(&key::receive_key(n))?;
        self.state.receive_keys.remove(&n);
        let known = self.state.known_kids.contains_key(&record.kid());
        if known || self.state.device.multi_device {
            let registration = Registration {
                kid: record.kid(),
                seq: None,
                at_ms: None,
                status: if known {
                    RegStatus::Own
                } else {
                    RegStatus::AwaitingSync
                },
            };
            tx.put(&key::registration(record.n()), &registration)?;
            self.state.registrations.insert(record.n(), registration);
            self.commit(tx).await?;
            self.events.push(if known {
                AppEvent::RotationLost { n: record.n() }
            } else {
                AppEvent::AwaitingDeviceSync { n: record.n() }
            });
            return Ok(());
        }
        // A restore asks the user about it (Switch spec 12.4).
        if self.restore_asks_about(record.n()) {
            self.ask_about_registration(record.n(), record.kid(), None, &mut tx)?;
            self.commit(tx).await?;
            self.push_restore_question();
            return Ok(());
        }
        self.commit(tx).await?;
        let alarm = Alarm::Compromise {
            n: record.n(),
            distrust_from: self.distrust_bound(),
        };
        let error = self.raise(alarm).await;
        self.leave_on_compromise().await;
        Err(error)
    }

    /// Whether a restore asks the user about the registration `n` whose kid no device of
    /// the app made (Switch spec 12.4 "Registrations since the backup"): one after the
    /// backup's newest key, while the restore is held, and, once the restore's key check
    /// has run, below the bound it set: the key it registered, or one above the backup's
    /// newest when the restored key was current, so nothing is asked about then. The one rule wherever such a registration is met: the restore's
    /// key check, the feed, a registration conflict (a fresh key's, a provider loss's), the
    /// re-registration after a move or a key change in place, and the device sync. Such a
    /// registration is unaccounted, and only the user's "no" makes it a compromise
    /// ([`App::refuse_restored_registrations`]); any other is a compromise at once, or, on
    /// an app that shares its keys, waits for the device sync.
    pub(crate) fn restore_asks_about(&self, n: u64) -> bool {
        self.state
            .restore
            .as_ref()
            .is_some_and(|r| n > r.n_floor && r.own_key_n.is_none_or(|own| n < own))
    }

    /// Keep the registration `n` as unaccounted, in `tx` and memory: a restore asks the
    /// user about it ([`App::restore_asks_about`]).
    pub(crate) fn ask_about_registration(
        &mut self,
        n: u64,
        kid: [u8; 8],
        at_ms: Option<u64>,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let registration = Registration {
            kid,
            seq: None,
            at_ms,
            status: RegStatus::Unaccounted,
        };
        tx.put(&key::registration(n), &registration)?;
        self.state.registrations.insert(n, registration);
        Ok(())
    }

    /// Tell the host of the open restore question, once its registrations are committed.
    pub(crate) fn push_restore_question(&mut self) {
        let n = self.restore_question();
        if !n.is_empty() {
            self.events.push(AppEvent::RestoreQuestion { n });
        }
    }

    /// The `distrust_from` for a registration of the own app learned of without its chain
    /// item, from a `409 conflict` or a directory (Switch spec 3.6): the later of the service
    /// times of the newest chain item the app verified and of its own last registration. The
    /// foreign registration lies after both, and service time never goes back, so this
    /// distrusts no less than the registration's own time. `None` when the app holds
    /// neither.
    pub(crate) fn distrust_bound(&self) -> Option<u64> {
        let chain = self.state.chain.as_ref().and_then(ChainView::highest_time);
        let own = self
            .state
            .receive_keys
            .values()
            .filter_map(|held| held.reg_time_ms)
            .max();
        chain.max(own)
    }

    /// The own current receive key record from the directory, verified.
    pub(crate) async fn own_directory_key(&mut self) -> Result<Option<ReceiveKeyRecord>, AppError> {
        let result = self.client.directory(None).await;
        let directory = self.take(result).await?;
        let me = self.state.meta.app_id;
        Ok(directory
            .apps
            .into_iter()
            .find(|app| app.app_id == me)
            .and_then(|app| app.receive_key))
    }

    /// A registration of the own app seen in the feed at `seq`, accepted at `at_ms`.
    pub(crate) fn own_registration(
        &mut self,
        seq: u64,
        at_ms: u64,
        record: &SignedDoc,
        tx: &mut Tx,
    ) -> Result<RegistrationStep, AppError> {
        let Ok(record) = ReceiveKeyRecord::verify(record, &self.state.cert) else {
            return Ok(RegistrationStep::Continue);
        };
        let n = record.n();
        let now = self.now();
        let current = self.current_n();
        if let Some(held) = self.state.receive_keys.get_mut(&n)
            && held.key.kid == record.kid()
        {
            // A registration whose answer was lost shows here: the rotation is done.
            let was_pending = !held.pending.is_empty() || held.reg_seq.is_none();
            held.reg_seq = Some(seq);
            held.reg_time_ms = Some(at_ms);
            held.pending.clear();
            tx.put(&key::receive_key(n), held)?;
            if was_pending && current == Some(n) && n > 0 {
                self.state.rotation.last_ms = now;
                self.state.rotation.opened_since = false;
                tx.put(key::ROTATION, &self.state.rotation)?;
            }
            return Ok(RegistrationStep::Continue);
        }
        let highest = self.current_n().unwrap_or(0);
        let known = self.state.known_kids.contains_key(&record.kid());
        let mut registration = Registration {
            kid: record.kid(),
            seq: Some(seq),
            at_ms: Some(at_ms),
            status: RegStatus::Own,
        };
        let step = if known {
            if n > highest {
                // Made by another device of the app: wait for its key.
                registration.status = RegStatus::AwaitingSync;
                self.events.push(AppEvent::AwaitingDeviceSync { n });
                RegistrationStep::Stop
            } else {
                RegistrationStep::Continue
            }
        } else if !self.state.device.multi_device && self.restore_asks_about(n) {
            registration.status = RegStatus::Unaccounted;
            RegistrationStep::Continue
        } else if self.state.device.multi_device {
            registration.status = RegStatus::AwaitingSync;
            self.events.push(AppEvent::AwaitingDeviceSync { n });
            if n > highest {
                RegistrationStep::Stop
            } else {
                RegistrationStep::Continue
            }
        } else {
            return Ok(RegistrationStep::Compromise(Alarm::Compromise {
                n,
                distrust_from: Some(at_ms),
            }));
        };
        tx.put(&key::registration(n), &registration)?;
        let unaccounted = registration.status == RegStatus::Unaccounted;
        self.state.registrations.insert(n, registration);
        if unaccounted {
            self.events.push(AppEvent::RestoreQuestion {
                n: self.restore_question(),
            });
        }
        Ok(step)
    }

    /// Delete every retired key whose successor's registration the cursor has passed
    /// (Switch spec 3.6). Called after the cursor's commit.
    pub(crate) async fn delete_retired_keys(&mut self) -> Result<(), AppError> {
        let Some(current) = self.current_n() else {
            return Ok(());
        };
        let due: Vec<u64> = self
            .state
            .receive_keys
            .keys()
            .copied()
            .filter(|n| *n != current && self.successor_passed(*n))
            .collect();
        if due.is_empty() {
            return Ok(());
        }
        let mut tx = self.tx()?;
        for n in &due {
            tx.delete(&key::receive_key(*n))?;
        }
        self.commit(tx).await?;
        for n in &due {
            self.state.receive_keys.remove(n);
        }
        self.events.push(AppEvent::KeysDeleted {
            count: u64::try_from(due.len()).unwrap_or(u64::MAX),
        });
        Ok(())
    }

    /// Whether the cursor has passed the `seq` of the registration of a key after `n`: key
    /// `n` is retired and goes, for good (Switch spec 3.6).
    fn successor_passed(&self, n: u64) -> bool {
        let cursor = self.state.cursor.seq;
        let held = self
            .state
            .receive_keys
            .iter()
            .filter_map(|(k, held)| held.reg_seq.map(|seq| (*k, seq)));
        let seen = self
            .state
            .registrations
            .iter()
            .filter_map(|(k, r)| r.seq.map(|seq| (*k, seq)));
        held.chain(seen)
            .filter(|(later, _)| *later > n)
            .map(|(_, seq)| seq)
            .min()
            .is_some_and(|next| cursor >= next)
    }

    /// After a restore, before reading (Switch spec 12.4 step 1): read the own current
    /// receive key record; if the restored key isn't it, register a fresh key, `n` one
    /// higher, and ask about a registration since the backup the app can't account for.
    /// `current` is the own receive key record the directory shows, read with the listed
    /// certificate ([`App::take_listed_cert`]).
    pub(crate) async fn check_key_after_restore(
        &mut self,
        current: Option<ReceiveKeyRecord>,
    ) -> Result<(), AppError> {
        let Some(restore) = self.state.restore.clone() else {
            return Ok(());
        };
        if restore.key_checked {
            return Ok(());
        }
        let mut tx = self.tx()?;
        let mut register = None;
        if let Some(record) = current
            && self
                .state
                .receive_keys
                .get(&record.n())
                .is_none_or(|held| held.key.kid != record.kid())
        {
            let n = record.n();
            if !self.state.known_kids.contains_key(&record.kid())
                && !self.state.device.multi_device
                && self.restore_asks_about(n)
            {
                self.ask_about_registration(n, record.kid(), None, &mut tx)?;
            }
            register = Some(
                n.checked_add(1)
                    .ok_or_else(|| AppError::InvalidData("receive key numbers ran out".into()))?,
            );
        }
        // The check closes what the restore asks about at what it saw: up to the key it
        // registers, or, with the restored key current, nothing above the backup's newest
        // (Switch spec 12.4). A registration met later is judged as at any time.
        if let Some(state) = self.state.restore.as_mut() {
            state.key_checked = true;
            state.own_key_n = Some(register.unwrap_or(restore.n_floor.saturating_add(1)));
            tx.put(key::RESTORE, state)?;
        }
        self.commit(tx).await?;
        self.push_restore_question();
        if let Some(n) = register {
            self.new_key(n).await?;
            if !self.register(n).await? {
                return Err(
                    Refusal::NotNow("another device registered a key meanwhile".into()).into(),
                );
            }
        }
        Ok(())
    }

    /// After a restore: the registrations since the backup the app can't account for, by
    /// `n` (Switch spec 12.4). The user is asked whether the app ran on this device after
    /// the backup; no attempt is made until the answer.
    pub fn restore_question(&self) -> Vec<u64> {
        self.state
            .registrations
            .iter()
            .filter(|(_, r)| r.status == RegStatus::Unaccounted)
            .map(|(n, _)| *n)
            .collect()
    }

    /// The user confirms the app ran on this device after the backup: the registrations
    /// since are its own.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn confirm_restored_registrations(
        &mut self,
        _confirmed: UserConfirmed,
    ) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let mut tx = self.tx()?;
            for (n, registration) in self.state.registrations.iter_mut() {
                if registration.status == RegStatus::Unaccounted {
                    registration.status = RegStatus::Own;
                    tx.put(&key::registration(*n), registration)?;
                    tx.put(&key::kid(&registration.kid), &KnownKid { n: *n })?;
                    self.state.known_kids.insert(registration.kid, *n);
                }
            }
            self.commit(tx).await
        })
        .await
    }

    /// The user says the registrations since the backup weren't the app's, or can't tell:
    /// a compromise. The app stops, leaves at once and asks the signer to revoke it from
    /// the earliest of them (Switch spec 3.6, 12.4).
    ///
    /// # Errors
    ///
    /// [`Refusal::NotNow`] when no question is open; otherwise the alarm.
    pub async fn refuse_restored_registrations(&mut self) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let Some((n, registration)) = self
                .state
                .registrations
                .iter()
                .find(|(_, r)| r.status == RegStatus::Unaccounted)
                .map(|(n, r)| (*n, r.clone()))
            else {
                return Err(Refusal::NotNow("no restore question is open".into()).into());
            };
            let alarm = Alarm::Compromise {
                n,
                distrust_from: registration.at_ms,
            };
            let error = self.raise(alarm).await;
            self.leave_on_compromise().await;
            Err(error)
        })
        .await
    }

    /// Whether the app runs on several devices sharing its keys (Switch spec 3.1).
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn set_multi_device(&mut self, multi_device: bool) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.state.device.multi_device = multi_device;
            let mut tx = self.tx()?;
            tx.put(key::DEVICE, &self.state.device)?;
            self.commit(tx).await
        })
        .await
    }

    /// The receive keys and kids this device shares with the app's other devices through
    /// the app's own device sync (Switch spec 3.6). Sensitive.
    pub fn device_keys(&self) -> DeviceKeys {
        DeviceKeys {
            receive_keys: self
                .state
                .receive_keys
                .values()
                .map(|held| HeldKeyOut {
                    key: held.key.clone(),
                    record: held.record.clone(),
                })
                .collect(),
            known: self
                .state
                .known_kids
                .iter()
                .map(|(kid, n)| (b64(kid), *n))
                .collect(),
            rotation_ms: self.state.rotation.last_ms,
        }
    }

    /// Take what another device of the app shares (Switch spec 3.6): its keys and the kids
    /// its devices made. A registration this device waited on that no device made is a
    /// compromise.
    ///
    /// # Errors
    ///
    /// The compromise alarm; a store failure.
    pub async fn take_device_keys(&mut self, keys: DeviceKeys) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            // Everything is read and checked into locals first, and memory takes it only
            // once the commit is done: a set that fails a check changes nothing.
            let mut kids = Vec::new();
            for (kid, n) in &keys.known {
                let kid = pubky_switch_core::enc::unb64_array::<8>(kid)
                    .map_err(|_| AppError::InvalidData("device sync: a kid doesn't read".into()))?;
                if !self.state.known_kids.contains_key(&kid) && !kids.iter().any(|(k, _)| *k == kid)
                {
                    kids.push((kid, *n));
                }
            }
            let mut held_keys = Vec::new();
            for shared in keys.receive_keys {
                let n = shared.key.n;
                // A retired key this device deleted once the cursor passed its successor's
                // registration doesn't come back from another device (Switch spec 3.6).
                if self.state.receive_keys.contains_key(&n)
                    || held_keys.iter().any(|(m, _)| *m == n)
                    || self.successor_passed(n)
                {
                    continue;
                }
                if ReceiveKeyRecord::verify(&shared.record, &self.state.cert).is_err() {
                    return Err(AppError::InvalidData(
                        "device sync: a receive key record doesn't verify".into(),
                    ));
                }
                let registration = self.state.registrations.get(&n);
                let held = HeldKey {
                    key: shared.key,
                    record: shared.record,
                    reg_seq: registration.and_then(|r| r.seq),
                    reg_time_ms: registration.and_then(|r| r.at_ms),
                    pending: Vec::new(),
                };
                held_keys.push((n, held));
            }
            let known = |kid: &[u8; 8]| {
                self.state.known_kids.contains_key(kid) || kids.iter().any(|(k, _)| k == kid)
            };
            let taken = |n: &u64| held_keys.iter().any(|(m, _)| m == n);
            // One no device made: unaccounted while a restore asks about it, otherwise a
            // compromise (Switch spec 3.6, 12.4).
            let unmade: Vec<(u64, Option<u64>)> = self
                .state
                .registrations
                .iter()
                .filter(|(n, r)| r.status == RegStatus::AwaitingSync && !taken(n) && !known(&r.kid))
                .map(|(n, r)| (*n, r.at_ms))
                .collect();
            let asked: Vec<u64> = unmade
                .iter()
                .map(|(n, _)| *n)
                .filter(|n| self.restore_asks_about(*n))
                .collect();
            let unknown = unmade.into_iter().find(|(n, _)| !asked.contains(n));
            let synced: Vec<u64> = self
                .state
                .registrations
                .iter()
                .filter(|(n, r)| r.status == RegStatus::AwaitingSync && !taken(n) && known(&r.kid))
                .map(|(n, _)| *n)
                .collect();
            let device = Device { multi_device: true };
            let rotation_ms = keys.rotation_ms.max(self.state.rotation.last_ms);
            let mut tx = self.tx()?;
            tx.put(key::DEVICE, &device)?;
            for (kid, n) in &kids {
                tx.put(&key::kid(kid), &KnownKid { n: *n })?;
            }
            for (n, held) in &held_keys {
                tx.put(&key::receive_key(*n), held)?;
                if self.state.registrations.contains_key(n) {
                    tx.delete(&key::registration(*n))?;
                }
            }
            if rotation_ms > self.state.rotation.last_ms {
                let rotation = Rotation {
                    last_ms: rotation_ms,
                    ..self.state.rotation
                };
                tx.put(key::ROTATION, &rotation)?;
            }
            for n in &synced {
                if let Some(registration) = self.state.registrations.get(n) {
                    let own = Registration {
                        status: RegStatus::Own,
                        ..registration.clone()
                    };
                    tx.put(&key::registration(*n), &own)?;
                }
            }
            for n in &asked {
                if let Some(registration) = self.state.registrations.get(n) {
                    let unaccounted = Registration {
                        status: RegStatus::Unaccounted,
                        ..registration.clone()
                    };
                    tx.put(&key::registration(*n), &unaccounted)?;
                }
            }
            self.commit(tx).await?;
            for n in &asked {
                if let Some(registration) = self.state.registrations.get_mut(n) {
                    registration.status = RegStatus::Unaccounted;
                }
            }
            if !asked.is_empty() {
                self.push_restore_question();
            }
            self.state.device = device;
            self.state.known_kids.extend(kids);
            for (n, held) in held_keys {
                self.state.registrations.remove(&n);
                self.state.receive_keys.insert(n, held);
            }
            self.state.rotation.last_ms = rotation_ms;
            for n in synced {
                if let Some(registration) = self.state.registrations.get_mut(&n) {
                    registration.status = RegStatus::Own;
                }
            }
            if let Some((n, at_ms)) = unknown {
                let alarm = Alarm::Compromise {
                    n,
                    distrust_from: at_ms,
                };
                let error = self.raise(alarm).await;
                self.leave_on_compromise().await;
                return Err(error);
            }
            Ok(())
        })
        .await
    }

    /// Refuse a call that would read or write while the app is stopped or gone: `gone`
    /// stops every read (`STATE.md`).
    pub(crate) fn refuse_when_stopped(&self) -> Result<(), AppError> {
        self.refuse_when_halted()?;
        if self.state.gone.is_some() {
            return Err(Refusal::Gone.into());
        }
        Ok(())
    }

    /// Refuse a call while the app is stopped on an alarm or left. A gone app passes: the
    /// read and the provider follow report it as stopped, without asking the service.
    pub(crate) fn refuse_when_halted(&self) -> Result<(), AppError> {
        if self.state.alarm.is_some() {
            return Err(Refusal::Stopped.into());
        }
        if self.state.leave.is_some() {
            return Err(Refusal::Left.into());
        }
        Ok(())
    }
}
