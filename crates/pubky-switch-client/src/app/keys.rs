//! Key bundles and scope keys (Switch spec 3.5; Switch wire 3.5, 7.4.11).
//!
//! The app fetches its key bundle parts and reads them with the core's [`PartReader`]: a
//! list out of order or overlapping is refused whole; a part that doesn't verify or open,
//! is relabelled, holds a key after the next data epoch, carries another naming key (an
//! alert), names a certificate the app doesn't take parts for, or holds other keys than its
//! certificate's keyed scopes over its range is skipped. The keys of the parts taken are
//! merged, each kept as its own record.
//!
//! Afterwards the app works out `keys_through`, the newest data epoch through which it
//! holds every scope key, and asks once for a full bundle when it still lacks a key for an
//! epoch up to the current one; the request clears once nothing is missing.
//!
//! A part stored after the request, seen in the feed, also clears it: it is the signer's
//! answer, so a key still missing once that part is read is asked for again (Switch wire
//! 7.4.11). Otherwise a request kept while the parts that answered it went, such as one a
//! backup carried into a restore, would never be made again. A restore drops the request
//! the backup holds: its answer may have been read and dropped by the device the backup
//! came from, leaving the feed only stubs, so the first read asks again if a key is missing.
//! So the app asks at most once per part stored after its last request: the signer's
//! answers, not a clock, pace the requests, and while no part arrives a request again would
//! keep the service's first time and tell the signer nothing new.

use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::records::{
    AppCert, BundlePart, PartReader, SkipReason, missing_keys, reader_certs,
};

use super::events::AppEvent;
use super::state::key;
use super::{App, AppError};

impl App {
    /// Fetch, read and merge the app's key bundle parts (Switch wire 7.4.11), then ask for a
    /// full bundle if a key is still missing.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`] for a stopped or departed app; a failed
    /// call or commit. A `404` (no part stored) isn't one.
    ///
    /// [`Refusal::Stopped`]: super::Refusal::Stopped
    /// [`Refusal::Left`]: super::Refusal::Left
    pub async fn fetch_key_bundle(&mut self) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            // A full-bundle request is a write through the service (Switch spec 3.5).
            self.refuse_when_halted()?;
            let result = self.client.keys().await;
            let answer = match self.take(result).await {
                Ok(answer) => Some(answer),
                Err(error) if error.code() == Some(ErrorCode::NotFound) => None,
                Err(error) => return Err(error),
            };
            let mut tx = self.tx()?;
            let mut took = false;
            if let Some(answer) = answer {
                let parts: Vec<BundlePart> = answer
                    .bundles
                    .iter()
                    .map(|stored| BundlePart {
                        bundle: stored.bundle.clone(),
                        first_epoch: stored.first_epoch,
                        last_epoch: stored.last_epoch,
                    })
                    .collect();
                let renewals: Vec<AppCert> = self.state.renewal.iter().cloned().collect();
                let certs = reader_certs(&self.state.cert, &renewals, &self.state.own_doc);
                let secret = self.state.keys.bundle_secret();
                let protocol = std::sync::Arc::clone(&self.protocol);
                let has_keys = |scope: &str| protocol.has_keys(scope);
                let reader = PartReader {
                    identity: self.state.meta.identity,
                    app_id: self.state.meta.app_id,
                    bundle_secret: &secret,
                    newest_epoch: self.state.own_doc.data_epoch(),
                    certs: &certs,
                    has_keys: &has_keys,
                };
                match reader.read(&parts, Some(&self.state.naming)) {
                    Err(error) => self.events.push(AppEvent::BundlePartSkipped {
                        range: (0, 0),
                        reason: error.to_string(),
                        alert: false,
                    }),
                    Ok(reading) => {
                        for skipped in &reading.skipped {
                            self.events.push(AppEvent::BundlePartSkipped {
                                range: skipped.range,
                                reason: skip_text(&skipped.reason),
                                alert: skipped.reason.alerts(),
                            });
                        }
                        for scope_key in reading.keys.keys {
                            if self
                                .state
                                .scope_keys
                                .get(scope_key.data_epoch, &scope_key.scope)
                                .is_none()
                            {
                                tx.put(
                                    &key::scope(scope_key.data_epoch, &scope_key.scope),
                                    &scope_key,
                                )?;
                                self.state.scope_keys.keys.push(scope_key);
                                took = true;
                            }
                        }
                    }
                }
            }
            let missing = self.update_keys_through();
            tx.put(key::BUNDLE, &self.state.bundle)?;
            self.commit(tx).await?;
            // A record held unreadable for want of a key taken now opens.
            if took {
                self.reopen_unreadable().await?;
            }
            if missing && self.state.bundle.full_requested_ms.is_none() {
                self.request_full_bundle().await?;
            }
            Ok(())
        })
        .await
    }

    /// Work out `keys_through` from the keys held, clear a full-bundle request that nothing
    /// lacks any more, and return whether a key is missing up to the current epoch.
    pub(crate) fn update_keys_through(&mut self) -> bool {
        let epoch = self.state.own_doc.data_epoch();
        let protocol = std::sync::Arc::clone(&self.protocol);
        let missing = missing_keys(
            &self.state.scope_keys,
            &self.state.cert,
            &|scope| protocol.has_keys(scope),
            epoch,
        );
        let through = missing
            .iter()
            .map(|gap| gap.first_epoch.saturating_sub(1))
            .min()
            .unwrap_or(epoch);
        if through != self.state.bundle.keys_through {
            self.events.push(AppEvent::KeysThrough { epoch: through });
        }
        self.state.bundle.keys_through = through;
        if missing.is_empty() {
            self.state.bundle.full_requested_ms = None;
        }
        !missing.is_empty()
    }

    /// A `key_bundle.put` for this app at service time `at`, seen in the feed: one stored at
    /// or after the full-bundle request answers it, so the request clears, and the fetch the
    /// part leads to asks again if a key is still missing (Switch wire 7.4.11). The fetch's
    /// commit keeps the cleared request. A part stored in the same millisecond as the
    /// request counts as after it: the error is one more request.
    pub(crate) fn part_stored(&mut self, at: u64) {
        if self
            .state
            .bundle
            .full_requested_ms
            .is_some_and(|requested| at >= requested)
        {
            self.state.bundle.full_requested_ms = None;
        }
    }

    /// Ask the signer for a full bundle, once until one arrives (Switch spec 3.5).
    async fn request_full_bundle(&mut self) -> Result<(), AppError> {
        let result = self.client.request_full_bundle().await;
        let requested = self.take(result).await?;
        self.state.bundle.full_requested_ms = Some(requested);
        let mut tx = self.tx()?;
        tx.put(key::BUNDLE, &self.state.bundle)?;
        self.commit(tx).await?;
        self.events.push(AppEvent::FullBundleRequested);
        Ok(())
    }

    /// Fetch the bundle when a key up to the current data epoch is missing and no full
    /// bundle is asked for yet (Switch spec 3.5: an app that doesn't hold the current key
    /// reads older data but writes no sealed data until it has it). A part stored later
    /// shows in the feed, which fetches it.
    pub(crate) async fn ensure_scope_keys(&mut self) -> Result<(), AppError> {
        if self.update_keys_through() && self.state.bundle.full_requested_ms.is_none() {
            self.fetch_key_bundle().await?;
        }
        Ok(())
    }
}

/// The data epochs at which the app lacks a scope key its certificate is given (Switch
/// spec 3.5), as ranges, from epoch 1 through the epoch they were worked out to.
pub(crate) struct KeyGaps {
    gaps: Vec<(u64, u64)>,
}

impl KeyGaps {
    /// Whether a key of `data_epoch` is missing.
    pub(crate) fn covers(&self, data_epoch: u64) -> bool {
        self.gaps
            .iter()
            .any(|(first, last)| *first <= data_epoch && data_epoch <= *last)
    }
}

impl App {
    /// The keys missing through `through`.
    fn key_gaps_through(&self, through: u64) -> KeyGaps {
        let protocol = std::sync::Arc::clone(&self.protocol);
        let gaps = missing_keys(
            &self.state.scope_keys,
            &self.state.cert,
            &|scope| protocol.has_keys(scope),
            through,
        )
        .iter()
        .map(|gap| (gap.first_epoch, gap.last_epoch))
        .collect();
        KeyGaps { gaps }
    }

    /// The keys missing through the current data epoch, or the highest epoch an entry stored
    /// locally waits for ([`super::ParkReason::AwaitingKey`]) when that is later.
    pub(crate) fn key_gaps(&self) -> KeyGaps {
        let through = self
            .state
            .parked
            .values()
            .filter_map(|stored| stored.reason.awaited_epoch())
            .fold(self.state.own_doc.data_epoch(), u64::max);
        self.key_gaps_through(through)
    }

    /// Whether the app holds every key of `data_epoch` its certificate is given.
    pub(crate) fn holds_epoch_keys(&self, data_epoch: u64) -> bool {
        let through = data_epoch.max(self.state.own_doc.data_epoch());
        !self.key_gaps_through(through).covers(data_epoch)
    }

    /// Whether fetching the key bundle now may bring a key of `data_epoch` (Switch spec
    /// 3.5): one is missing at that epoch, which is the current one or before it, and no
    /// full bundle is asked for. While one is asked for, the signer's answer comes as a part
    /// the feed shows, which fetches it; a later epoch's keys come once the epoch rises.
    pub(crate) fn key_may_come_by_fetch(&self, data_epoch: u64) -> bool {
        data_epoch <= self.state.own_doc.data_epoch()
            && self.state.bundle.full_requested_ms.is_none()
            && !self.holds_epoch_keys(data_epoch)
    }
}

fn skip_text(reason: &SkipReason) -> String {
    match reason {
        SkipReason::Unverified => "the identity key's signature doesn't verify".into(),
        SkipReason::Unopened(why) => format!("doesn't open: {why}"),
        SkipReason::Relabelled => "its sealed range isn't the range it names".into(),
        SkipReason::AfterNextEpoch => "a key after the next data epoch".into(),
        SkipReason::OtherNamingKey => "another naming key than the identity's".into(),
        SkipReason::UnknownCert => "made for a certificate the app doesn't take parts for".into(),
        SkipReason::WrongKeys(why) => format!("not its certificate's keys: {why}"),
    }
}
