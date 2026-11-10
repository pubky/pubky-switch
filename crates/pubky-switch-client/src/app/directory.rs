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

use std::collections::{HashMap, HashSet};

use pubky_switch_core::enc::{b64, pubky_id, serde_b64, zbase32_encode};
use pubky_switch_core::envelope::Recipient;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::message::Message;
use pubky_switch_core::records::{AppRecord, IdentityDoc, ReceiveKeyRecord, VersionOrder};
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::context::LocalView;
use super::error::{Alarm, Refusal};
use super::events::AppEvent;
use super::identity::{self, DOC_CACHE_MS, Taken};
use super::state::{CachedDoc, Tx};
use super::{App, AppError};
use crate::client::answers::Directory;
use crate::client::read::Obj;
use crate::client::{Credentials, SwitchClient};
use crate::error::{ClientError, StoreError};

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

/// Write what the app keeps of `pubky`'s switch into `tx`.
pub(crate) fn put_peer(
    tx: &mut super::state::Tx,
    pubky: &[u8; 32],
    peer: &PeerSwitch,
) -> Result<(), AppError> {
    tx.put(&peer_key(pubky), peer)
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
/// judged against: its version, removed apps and closed renewals, and the counterparties
/// whose switches are still owed the delivery.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct PeersDoc {
    version: u64,
    removed: Vec<String>,
    closed: Vec<String>,
    /// The Pubky IDs of the counterparties still owed the delivery, tried again at each
    /// call until it goes or they stop being recent.
    #[serde(default)]
    owed: Vec<String>,
}

/// `ident/<pubky>/sw`: when the app last looked up a counterparty's switch copy of its
/// `identity.json`, and whether the read succeeded (Switch spec 4.3, "The switch's copy").
/// `lookup` is the number the lookup took when it began ([`switch_lookups_key`]): which
/// lookup is the newer is judged by it, not by the clock, which may give two lookups the
/// same millisecond or move back between them. A record kept before the number reads as 0,
/// older than any lookup begun since.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct SwitchRead {
    at_ms: u64,
    read: bool,
    #[serde(default)]
    lookup: u64,
}

fn switch_read_key(pubky: &[u8; 32]) -> String {
    format!("ident/{}/sw", pubky_id(pubky))
}

/// `ident/<pubky>/swn`: the number of the last switch lookup begun for a counterparty, one
/// higher at each. It is kept in the store with the lookup's outcome, so the order holds
/// across restarts as the outcome does.
fn switch_lookups_key(pubky: &[u8; 32]) -> String {
    format!("ident/{}/swn", pubky_id(pubky))
}

/// `ident/<pubky>/reads`: when the app last read a counterparty's `identity.json` from each
/// source that gave it a copy, app clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct SourceReads {
    homeserver_ms: Option<u64>,
    switch_ms: Option<u64>,
}

fn source_reads_key(pubky: &[u8; 32]) -> String {
    format!("ident/{}/reads", pubky_id(pubky))
}

/// Where a counterparty's copy came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CopySource {
    /// Its Homeserver, read now.
    Homeserver,
    /// Its switch's public read (Switch wire 7.4.15), completed at `read_ms`, app clock.
    Switch { read_ms: u64 },
    /// A directory answer of its switch: no fresh read of the document.
    Directory,
}

/// Whether the Homeserver's copy of a counterparty's `identity.json` was read at a lookup
/// ([`App::identity_of`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HomeserverCopy {
    /// Read at this lookup, and taken under the version floor.
    Read,
    /// Not read at this lookup: the Homeserver couldn't be read, or publishes no
    /// `identity.json`. The document stands on the copies held.
    Unavailable,
    /// Not read at this lookup: the copy held and the last switch lookup were under 10
    /// minutes old ([`super::DOC_CACHE_MS`]).
    Held,
}

/// Whether a counterparty's switch confirmed its `identity.json` (Switch spec 4.3, "The
/// switch's copy"). A lookup's answer counts until the next lookup, once the copy is more
/// than 10 minutes old.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SwitchCopy {
    /// The switch's copy was read with the Homeserver's, and the higher version taken.
    Read,
    /// The switch's copy couldn't be read: the document stands on the Homeserver's copy
    /// and the copies held. An action that relies on it goes ahead only as the protocol
    /// allows without the switch's confirmation (Switch spec 4.3, "No silent fallback").
    Unavailable,
    /// The switch's half of this lookup is still running ([`SwitchLookup`]).
    Pending,
}

/// Who starts an action on a counterparty's public app records (Switch spec 4.3, "No
/// silent fallback").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Initiator {
    /// The user starts it, and can confirm it.
    User,
    /// The app acts without the user.
    Automatic,
}

/// Whether an action on a counterparty's public app records may go ahead on a lookup's
/// copy, by Switch spec 4.3, "The switch's copy" ([`PeerIdentity::may_act`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MayAct {
    /// The switch confirmed the copy within the last 10 minutes: act on it.
    Now,
    /// The switch's lookup is still running and the grace hasn't passed: wait for it, at
    /// most until this time, app clock, and ask again.
    WaitUntil(u64),
    /// The switch couldn't confirm the copy in time: the action, which the user started,
    /// goes ahead only once the user explicitly confirms it although the identity's switch
    /// couldn't confirm the identity's apps, and the app records an event for it. A lookup
    /// still running keeps running: an answer that arrives before the action takes effect
    /// is still used ([`App::finish_identity_lookup`]).
    IfUserConfirms,
    /// An action without the user: wait for the switch's lookup, with the client's usual
    /// timeout. It never acts on the Homeserver's copy alone.
    WaitForLookup,
    /// An action without the user, and the switch's lookup failed: it isn't taken on this
    /// copy. It may look up once more ([`App::identity_of`] with `refresh`); if that fails
    /// too, the action isn't taken.
    No,
    /// The copy is more than 10 minutes old: look it up again before acting.
    LookUpAgain,
}

/// A counterparty's `identity.json` as a lookup found it ([`App::identity_of`]), with what
/// was read and when, so a protocol applies Switch spec 4.3 to it ([`PeerIdentity::may_act`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PeerIdentity {
    /// The newest copy held: the higher of the Homeserver's and the switch's, under the
    /// version floor the app keeps.
    pub doc: IdentityDoc,
    /// When the copy held was last read from the Homeserver or the switch, app clock: not
    /// the lookup's time when neither could be read at it.
    pub read_at_ms: u64,
    /// Whether the Homeserver's copy was read at this lookup.
    pub homeserver: HomeserverCopy,
    /// When the Homeserver last gave a copy, app clock; `None` if it never did.
    pub homeserver_read_ms: Option<u64>,
    /// What the last lookup of the switch's copy found: at this lookup, or, with
    /// [`HomeserverCopy::Held`], at the one before.
    pub switch_copy: SwitchCopy,
    /// When the switch was looked up, app clock: when the lookup began while it is
    /// [`SwitchCopy::Pending`], otherwise when its answer, or its failure, came.
    pub switch_lookup_ms: u64,
    /// When the switch last gave its copy, app clock; `None` if it never did.
    pub switch_read_ms: Option<u64>,
}

impl PeerIdentity {
    /// Until when the copy is used without reading it again, app clock: 10 minutes from
    /// the earlier of its last read and the last switch lookup ([`super::DOC_CACHE_MS`]).
    pub fn fresh_until_ms(&self) -> u64 {
        self.read_at_ms
            .min(self.switch_lookup_ms)
            .saturating_add(DOC_CACHE_MS)
    }

    /// Whether an action on the counterparty's public app records, such as paying one of
    /// its public endpoints, may go ahead on this copy now (Switch spec 4.3, "The switch's
    /// copy"): only once the switch confirmed it, unless the switch's lookup failed or
    /// hasn't answered within `grace_ms` after the Homeserver's read, when a user's action
    /// goes ahead on the user's explicit confirmation and an automatic one waits or isn't
    /// taken. A copy more than 10 minutes old is looked up again first; while a lookup
    /// still runs on such a copy, every action waits for it. `now_ms` is the app clock.
    pub fn may_act(&self, now_ms: u64, by: Initiator, grace_ms: u64) -> MayAct {
        let stale = now_ms >= self.fresh_until_ms();
        let grace_end = self.switch_lookup_ms.saturating_add(grace_ms);
        match (self.switch_copy, by) {
            (SwitchCopy::Pending, _) if now_ms < grace_end => MayAct::WaitUntil(grace_end),
            (SwitchCopy::Pending, _) if stale => MayAct::WaitForLookup,
            _ if stale => MayAct::LookUpAgain,
            (SwitchCopy::Read, _) => MayAct::Now,
            (SwitchCopy::Pending | SwitchCopy::Unavailable, Initiator::User) => {
                MayAct::IfUserConfirms
            }
            (SwitchCopy::Pending, Initiator::Automatic) => MayAct::WaitForLookup,
            (SwitchCopy::Unavailable, Initiator::Automatic) => MayAct::No,
        }
    }
}

/// A lookup of a counterparty's `identity.json` for acting on its public app records,
/// begun ([`App::begin_identity_lookup`]): what the Homeserver's read found, and the
/// switch's half, still to run.
#[derive(Debug)]
pub struct IdentityLookup {
    /// The copy as it stands after the Homeserver's read: [`SwitchCopy::Pending`] while
    /// `switch` is to run. With [`HomeserverCopy::Held`] the copy held was fresh, and
    /// nothing is to run.
    pub identity: PeerIdentity,
    /// The switch's half: a future that runs apart from the app, so the caller waits for it
    /// at most a grace and lets it run on (Switch spec 4.3, "No added latency"). Its answer
    /// goes to [`App::finish_identity_lookup`]. `None` when the copy held was fresh.
    pub switch: Option<SwitchLookup>,
}

/// The switch's half of a lookup (Switch wire 7.4.15): the public read of the switch the
/// newest copy names, following a freeze once to the next service. It runs apart from the
/// app, on the caller's executor; dropping it abandons the lookup, which then counts as not
/// made. Its answer carries the app-clock time the read completed.
pub struct SwitchLookup {
    pubky: [u8; 32],
    homeserver: HomeserverCopy,
    lookup: u64,
    clock: std::sync::Arc<dyn crate::clock::Clock>,
    future: crate::transport::BoxFuture<'static, Option<Vec<IdentityDoc>>>,
}

impl std::fmt::Debug for SwitchLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SwitchLookup")
    }
}

impl std::future::Future for SwitchLookup {
    type Output = SwitchAnswer;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<SwitchAnswer> {
        let this = self.get_mut();
        let copies = std::task::ready!(this.future.as_mut().poll(cx));
        std::task::Poll::Ready(SwitchAnswer {
            pubky: this.pubky,
            homeserver: this.homeserver,
            lookup: this.lookup,
            read_ms: this.clock.now_ms(),
            copies,
        })
    }
}

/// What the switch's half of a lookup found ([`SwitchLookup`]), for
/// [`App::finish_identity_lookup`]. Its copies are verified with the identity's key, and
/// still go through the version floor and the equivocation check there. Its freshness
/// counts from when the read completed, however long the answer is held before it is
/// finished (Switch spec 4.3); whether it is newer than another lookup's outcome is judged
/// by the order the lookups began in.
#[derive(Clone, Debug)]
pub struct SwitchAnswer {
    pubky: [u8; 32],
    homeserver: HomeserverCopy,
    lookup: u64,
    read_ms: u64,
    copies: Option<Vec<IdentityDoc>>,
}

impl SwitchAnswer {
    /// The counterparty looked up.
    pub fn identity(&self) -> [u8; 32] {
        self.pubky
    }

    /// Whether the switch gave its copy.
    pub fn read(&self) -> bool {
        self.copies.is_some()
    }

    /// When the read completed, or failed, app clock.
    pub fn read_ms(&self) -> u64 {
        self.read_ms
    }
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
            Ok(Some(fetched)) => {
                self.take_peer_copy(pubky, fetched, CopySource::Homeserver)
                    .await
            }
            Ok(None) | Err(_) => held.map(|(doc, _)| doc).ok_or_else(|| {
                AppError::Refused(Refusal::NotNow(
                    "Switch spec 4.3: no identity.json of the counterparty can be read".into(),
                ))
            }),
        }
    }

    /// A counterparty's `identity.json` for acting on its public app records (Switch spec
    /// 4.3, "The switch's copy"): the copy held while it and the last switch lookup are
    /// under 10 minutes old ([`super::DOC_CACHE_MS`]), unless `refresh`; otherwise the
    /// Homeserver copy, then the public copy of the switch the newest document names
    /// (following a freeze once to the next service), the higher version taken. Every copy
    /// goes through the version floor and the equivocation check the app keeps (Switch spec
    /// 4.3): another body at a version seen marks the identity, reported as
    /// [`super::AppEvent::PeerEquivocation`], and no copy of it is used from then on.
    ///
    /// The call waits for the switch's read to end. A caller that waits for it at most a
    /// grace after the Homeserver's read, as Switch spec 4.3 "No added latency" has it,
    /// uses [`App::begin_identity_lookup`] and [`App::finish_identity_lookup`] instead.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for the own identity ([`App::own_identity`]); [`Refusal::NotNow`]
    /// for an identity seen equivocating, or one the app can get no copy of; a store
    /// failure.
    pub async fn identity_of(
        &mut self,
        pubky: &[u8; 32],
        refresh: bool,
    ) -> Result<PeerIdentity, AppError> {
        Box::pin(async move {
            let lookup = self.begin_inner(pubky, refresh).await?;
            match lookup.switch {
                None => Ok(lookup.identity),
                Some(switch) => {
                    let answer = switch.await;
                    self.finish_inner(answer).await
                }
            }
        })
        .await
    }

    /// The first half of [`App::identity_of`]: the copy held when it is fresh, or else the
    /// Homeserver's copy, read and taken now, and the switch's half as a future that runs
    /// apart from the app (Switch spec 4.3, "No added latency"). The caller races it against
    /// its grace ([`PeerIdentity::may_act`]), lets it run on while the user confirms, and
    /// hands its answer to [`App::finish_identity_lookup`].
    ///
    /// # Errors
    ///
    /// As [`App::identity_of`].
    pub async fn begin_identity_lookup(
        &mut self,
        pubky: &[u8; 32],
        refresh: bool,
    ) -> Result<IdentityLookup, AppError> {
        Box::pin(self.begin_inner(pubky, refresh)).await
    }

    /// The second half of [`App::identity_of`]: take the copies the switch's half read,
    /// under the version floor and the equivocation check, and keep when the switch was
    /// looked up and whether it answered, which counts until the next lookup. The answer
    /// counts from when its read completed ([`SwitchAnswer::read_ms`]), not from this call:
    /// one held more than 10 minutes gives a copy to look up again. An answer of a lookup
    /// begun before the one whose outcome is kept leaves that outcome standing, whatever
    /// the clock read at either.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotNow`] for an identity seen equivocating, or that equivocates now; a
    /// store failure.
    pub async fn finish_identity_lookup(
        &mut self,
        answer: SwitchAnswer,
    ) -> Result<PeerIdentity, AppError> {
        Box::pin(self.finish_inner(answer)).await
    }

    async fn refuse_equivocated(&self, pubky: &[u8; 32]) -> Result<(), AppError> {
        if self
            .reader()
            .exists(&super::state::key::ident_equivocated(pubky))
            .await?
        {
            return Err(Refusal::NotNow(
                "Switch spec 4.3: the counterparty's identity.json equivocated".into(),
            )
            .into());
        }
        Ok(())
    }

    /// The copy held of `pubky`, with what was read and when.
    async fn peer_identity_held(
        &self,
        pubky: &[u8; 32],
        homeserver: HomeserverCopy,
        switch_copy: SwitchCopy,
        switch_lookup_ms: u64,
    ) -> Result<PeerIdentity, AppError> {
        let reader = self.reader();
        let Some((doc, read_at_ms)) = identity::held_copy(&reader, pubky).await? else {
            return Err(Refusal::NotNow(
                "Switch spec 4.3: no identity.json of the counterparty can be read".into(),
            )
            .into());
        };
        let reads: SourceReads = reader
            .get(&source_reads_key(pubky))
            .await?
            .unwrap_or_default();
        Ok(PeerIdentity {
            doc,
            read_at_ms,
            homeserver,
            homeserver_read_ms: reads.homeserver_ms,
            switch_copy,
            switch_lookup_ms,
            switch_read_ms: reads.switch_ms,
        })
    }

    async fn begin_inner(
        &mut self,
        pubky: &[u8; 32],
        refresh: bool,
    ) -> Result<IdentityLookup, AppError> {
        self.ready_local().await?;
        if *pubky == self.state.meta.identity {
            return Err(Refusal::Usage("the own identity.json is the app's own".into()).into());
        }
        self.refuse_equivocated(pubky).await?;
        let reader = self.reader();
        let now = self.now();
        let held = identity::held_copy(&reader, pubky).await?;
        let last: Option<SwitchRead> = reader.get(&switch_read_key(pubky)).await?;
        let fresh = |at: u64| now.saturating_sub(at) < DOC_CACHE_MS;
        if !refresh
            && let (Some((_, fetched)), Some(last)) = (&held, last)
            && fresh(*fetched)
            && fresh(last.at_ms)
        {
            let switch_copy = if last.read {
                SwitchCopy::Read
            } else {
                SwitchCopy::Unavailable
            };
            let identity = self
                .peer_identity_held(pubky, HomeserverCopy::Held, switch_copy, last.at_ms)
                .await?;
            return Ok(IdentityLookup {
                identity,
                switch: None,
            });
        }
        // The Homeserver's copy first; one that can't be read leaves the copy held.
        let (named, homeserver) =
            match identity::read_homeserver(self.env.homeserver.as_ref(), pubky).await {
                Ok(Some(fetched)) => (
                    Some(
                        self.take_peer_copy(pubky, fetched, CopySource::Homeserver)
                            .await?,
                    ),
                    HomeserverCopy::Read,
                ),
                Ok(None) | Err(_) => (held.map(|(doc, _)| doc), HomeserverCopy::Unavailable),
            };
        let Some(named) = named else {
            return Err(Refusal::NotNow(
                "Switch spec 4.3: no identity.json of the counterparty can be read".into(),
            )
            .into());
        };
        // Then the switch's copy, at the switch the newest copy names. The lookup takes the
        // next number now, so a later one is newer whatever the clock does.
        let lookup = self
            .reader()
            .get::<u64>(&switch_lookups_key(pubky))
            .await?
            .unwrap_or(0)
            .saturating_add(1);
        let mut tx = self.tx()?;
        tx.put(&switch_lookups_key(pubky), &lookup)?;
        self.commit(tx).await?;
        let started = self.now();
        let identity = self
            .peer_identity_held(pubky, homeserver, SwitchCopy::Pending, started)
            .await?;
        let switch = self.switch_lookup(pubky, &named, homeserver, lookup);
        Ok(IdentityLookup {
            identity,
            switch: Some(switch),
        })
    }

    async fn finish_inner(&mut self, answer: SwitchAnswer) -> Result<PeerIdentity, AppError> {
        self.ready_local().await?;
        let pubky = answer.pubky;
        self.refuse_equivocated(&pubky).await?;
        let read = answer.copies.is_some();
        let read_ms = answer.read_ms;
        for copy in answer.copies.unwrap_or_default() {
            self.take_peer_copy(&pubky, copy, CopySource::Switch { read_ms })
                .await?;
        }
        // An answer of a lookup begun before the last outcome's changes nothing of it: a
        // lookup begun later, perhaps on a newer copy, that failed still counts until the
        // reader looks up again (Switch spec 4.3). The order is the lookups' numbers, not
        // their times, which may be equal or run backward.
        let last: Option<SwitchRead> = self.reader().get(&switch_read_key(&pubky)).await?;
        let outcome = match last {
            Some(last) if last.lookup >= answer.lookup => last,
            _ => {
                let outcome = SwitchRead {
                    at_ms: read_ms,
                    read,
                    lookup: answer.lookup,
                };
                let mut tx = self.tx()?;
                tx.put(&switch_read_key(&pubky), &outcome)?;
                self.commit(tx).await?;
                outcome
            }
        };
        let switch_copy = if outcome.read {
            SwitchCopy::Read
        } else {
            SwitchCopy::Unavailable
        };
        self.peer_identity_held(&pubky, answer.homeserver, switch_copy, outcome.at_ms)
            .await
    }

    /// The switch's half of a lookup of `pubky`, at the switch `doc` names, and, when it is
    /// frozen, at the next service its freeze names, once (Switch wire 7.4.15). Its copies
    /// are `None` when the lookup failed: a switch that can't be read, or a next service
    /// frozen too. A next service still staged hasn't been named yet, so the frozen one's
    /// copy stands.
    fn switch_lookup(
        &self,
        pubky: &[u8; 32],
        doc: &IdentityDoc,
        homeserver: HomeserverCopy,
        lookup: u64,
    ) -> SwitchLookup {
        let first = self.peer_client(pubky, doc).ok();
        let credentials = Credentials::App {
            identity: self.state.meta.identity,
            keys: self.state.keys.clone(),
            cert: self.state.cert.clone(),
        };
        let transport = std::sync::Arc::clone(&self.env.transport);
        let clock = std::sync::Arc::clone(&self.env.clock);
        let account = *pubky;
        let future = async move {
            let public = first?.public_identity().await.ok()?;
            let mut copies = vec![public.identity];
            // The freeze is verified with the identity's key with the answer.
            if let Some(freeze) = public.freeze {
                let next = SwitchClient::new(
                    &freeze.next().url,
                    account,
                    credentials,
                    Some(freeze.next().service_key),
                    transport,
                    clock,
                )
                .ok()?;
                match next.public_identity().await {
                    Ok(next_public) if next_public.freeze.is_none() => {
                        copies.push(next_public.identity);
                    }
                    Ok(_) => return None,
                    Err(ClientError::Switch {
                        code: ErrorCode::Staged,
                        ..
                    }) => {}
                    Err(_) => return None,
                }
            }
            Some(copies)
        };
        SwitchLookup {
            pubky: *pubky,
            homeserver,
            lookup,
            clock: std::sync::Arc::clone(&self.env.clock),
            future: Box::pin(future),
        }
    }

    /// Take a counterparty's copy, from its Homeserver, its switch's public read or a
    /// directory answer, and return the newest held. A Homeserver or public read is a fresh
    /// read of the document, kept as its source's last read, at the time it completed.
    async fn take_peer_copy(
        &mut self,
        pubky: &[u8; 32],
        doc: IdentityDoc,
        source: CopySource,
    ) -> Result<IdentityDoc, AppError> {
        let reader = self.reader();
        let held = identity::held_copy(&reader, pubky).await?;
        let read_ms = match source {
            CopySource::Switch { read_ms } => read_ms,
            CopySource::Homeserver | CopySource::Directory => self.now(),
        };
        let fresh = source != CopySource::Directory;
        let mut tx = self.tx()?;
        if fresh {
            let mut reads: SourceReads = reader
                .get(&source_reads_key(pubky))
                .await?
                .unwrap_or_default();
            match source {
                CopySource::Homeserver => reads.homeserver_ms = Some(read_ms),
                CopySource::Switch { .. } => reads.switch_ms = Some(read_ms),
                CopySource::Directory => {}
            }
            tx.put(&source_reads_key(pubky), &reads)?;
        }
        let held_doc = held.as_ref().map(|(doc, _)| doc);
        let fetched_ms = if fresh {
            read_ms
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
                            fetched_ms: read_ms,
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
        // Apps whose entry didn't verify are left out of the directory, and the others used
        // (Switch spec 8.1).
        for app_id in &directory.skipped {
            self.unreachable(pubky, *app_id);
        }
        let mut newest = doc.clone();
        if own {
            // The directory's copy is newer than the one held: taken (Switch spec 4.3).
            if doc.compare(&directory.identity) == VersionOrder::Newer {
                self.take_own_copy(directory.identity.clone()).await?;
                newest = self.state.own_doc.clone();
            }
        } else {
            let taken = self
                .take_peer_copy(pubky, directory.identity.clone(), CopySource::Directory)
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
        keep_directory(&mut tx, pubky, &cached)?;
        match self.commit(tx).await {
            // A store that refuses it as too large keeps none either: this send uses it.
            Err(AppError::Store(StoreError::TooLarge { .. })) => {
                self.reload_now().await?;
                let mut tx = self.tx()?;
                tx.delete(&dir_key(pubky))?;
                self.commit(tx).await?;
            }
            committed => committed?,
        }
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
        Box::pin(async move {
            self.ready_local().await?;
            let mut tx = self.tx()?;
            tx.delete(&dir_key(pubky))?;
            self.commit(tx).await
        })
        .await
    }

    pub(crate) async fn mark_directory_stale(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        if let Some(mut cached) = self.cached_directory(pubky).await? {
            cached.stale = true;
            let mut tx = self.tx()?;
            keep_directory(&mut tx, pubky, &cached)?;
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
        Box::pin(async move {
            self.ready_local().await?;
            let (routes, _) = self.routes(pubky, message, None).await?;
            Ok(routes.into_iter().map(|r| r.app_id).collect())
        })
        .await
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
        let mut floors = HashMap::new();
        // Each app is listed once (Switch wire 7.4.10): one listed twice can't be judged,
        // and goes unreachable.
        let mut listed: HashMap<[u8; 16], usize> = HashMap::new();
        for app in &directory.apps {
            let count = listed.entry(app.app_id).or_insert(0);
            *count = count.saturating_add(1);
        }
        for app in &directory.apps {
            if own && app.app_id == self.state.meta.app_id {
                continue;
            }
            match listed.get_mut(&app.app_id) {
                Some(count) if *count > 1 => {
                    // Reported once, every copy skipped.
                    if *count != usize::MAX {
                        *count = usize::MAX;
                        self.unreachable(pubky, app.app_id);
                    }
                    continue;
                }
                _ => {}
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
            if !self.protocol.receives(&message.kind, cert) || !record.accepts(&message.kind) {
                continue;
            }
            let store = std::sync::Arc::clone(self.env.store.store());
            let view = LocalView::new(
                self.state.meta.identity,
                self.state.meta.app_id,
                store.as_ref(),
                &self.ns,
            );
            if !self.protocol.sends_to_with(message, &record, &view) {
                continue;
            }
            let checked = match &app.receive_key {
                Some(signed) => {
                    self.check_receive_key(pubky, &record, signed, &mut floors, &mut tx)
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
    ///
    /// `floors` holds the highest `n` taken so far in this answer, ahead of `tx`'s commit,
    /// so a second record of the same app in one answer is checked against the first: the
    /// floor only goes up (Switch spec 4.4).
    async fn check_receive_key(
        &mut self,
        pubky: &[u8; 32],
        record: &AppRecord,
        signed: &SignedDoc,
        floors: &mut HashMap<String, u64>,
        tx: &mut super::state::Tx,
    ) -> Result<Option<ReceiveKeyRecord>, AppError> {
        let Ok(key) = ReceiveKeyRecord::verify(signed, record.cert()) else {
            return Ok(None);
        };
        if key.body().identity != *pubky {
            return Ok(None);
        }
        let slot = highest_n_key(pubky, &record.cert().app_id());
        let highest: u64 = match floors.get(&slot) {
            Some(highest) => *highest,
            None => self.reader().get(&slot).await?.unwrap_or(0),
        };
        if key.n() < highest {
            floors.insert(slot, highest);
            return Ok(None);
        }
        if key.n() > highest {
            tx.put(&slot, &key.n())?;
        }
        floors.insert(slot, key.n());
        Ok(Some(key))
    }

    /// The records of a `409 stale_key` answer (Switch wire 7.6): each current record is
    /// checked as a directory's and replaces the cached one; apps no longer current leave
    /// the cache; apps added since are checked, against an `identity.json` read again if the
    /// one held doesn't list them, and join it; the `apps_version` moves on. A `current`
    /// whose `receive_keys`, `not_current` and `added_apps` together name an App ID twice is
    /// refused: nothing is taken from it, and the directory is read again. So is one missing
    /// any member the wire lists as required, or holding one as `null`: `receive_keys`,
    /// `not_current`, `unknown_kids`, `added_apps` and `apps_version`. A sender then never
    /// seals again for a set of apps that part of an answer left out.
    pub(crate) async fn take_stale_key(
        &mut self,
        pubky: &[u8; 32],
        current: &Value,
    ) -> Result<(), AppError> {
        if !stale_key_reads(current) || names_an_app_twice(current) {
            return self.mark_directory_stale(pubky).await;
        }
        let Some(mut cached) = self.cached_directory(pubky).await? else {
            return Ok(());
        };
        let mut tx = self.tx()?;
        let mut floors = HashMap::new();
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
                .check_receive_key(pubky, &record, &signed, &mut floors, &mut tx)
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
                    .check_receive_key(pubky, &record, &receive_key, &mut floors, &mut tx)
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
        keep_directory(&mut tx, pubky, &cached)?;
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
    /// `known_version` they last answered (Switch spec 12.2 step 5, 3.2). Every switch owed
    /// is tried; the ones that fail stay owed, each on its own, and are tried again at the
    /// next call, so one unreachable switch holds up no other.
    ///
    /// # Errors
    ///
    /// An alarm or a store failure; a switch's failure only keeps it owed.
    pub(crate) async fn deliver_to_recent_peers(&mut self) -> Result<(), AppError> {
        let own = self.state.own_doc.clone();
        let mut judged: PeersDoc = self.reader().get(PEERS_DOC).await?.unwrap_or_default();
        let now = self.now();
        let recent = |peer: &PeerSwitch| {
            peer.last_sent_ms
                .is_some_and(|at| now.saturating_sub(at) < PEER_DELIVERY_MS)
        };
        if own.version() > judged.version {
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
            let owed_now = removed.iter().any(|r| !judged.removed.contains(r))
                || closed.iter().any(|c| !judged.closed.contains(c));
            let mut owed = std::mem::take(&mut judged.owed);
            if owed_now {
                for (rest, peer) in self.reader().scan::<PeerSwitch>(PEER_PREFIX).await? {
                    if recent(&peer)
                        && peer.known_version.is_none_or(|v| v < own.version())
                        && !owed.contains(&rest)
                    {
                        owed.push(rest);
                    }
                }
            }
            judged = PeersDoc {
                version: own.version(),
                removed,
                closed,
                owed,
            };
        } else if judged.owed.is_empty() {
            return Ok(());
        }
        let mut still = Vec::new();
        for rest in std::mem::take(&mut judged.owed) {
            let Ok(pubky) = pubky_switch_core::enc::pubky_key(&rest) else {
                continue;
            };
            let peer = self.peer_switch(&pubky).await?;
            if !recent(&peer) {
                continue;
            }
            match self.deliver_own_identity(&pubky, None, false).await {
                Ok(()) => {}
                Err(error @ (AppError::Alarm(_) | AppError::Store(_))) => return Err(error),
                // A switch that can't be reached now gets it at a later call.
                Err(_) => still.push(rest),
            }
        }
        judged.owed = still;
        let mut tx = self.tx()?;
        tx.put(PEERS_DOC, &judged)?;
        self.commit(tx).await
    }
}

/// Cache `cached` as `pubky`'s directory, or, when it is over the store's value size, cache
/// none: a directory may take up to 104 MiB at an app limit of 255 (Switch wire 9), and one
/// too large to keep is read again at each send instead, which then still goes.
fn keep_directory(tx: &mut Tx, pubky: &[u8; 32], cached: &CachedDirectory) -> Result<(), AppError> {
    let key = dir_key(pubky);
    let size = super::state::encode(cached)?
        .len()
        .saturating_add(key.len());
    if u64::try_from(size).unwrap_or(u64::MAX) <= crate::store::MAX_VALUE_BYTES {
        tx.put(&key, cached)
    } else {
        tx.delete(&key)
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

/// Whether a `409 stale_key`'s `current` holds every member Switch wire 7.6 lists, none
/// marked optional there: the four lists, present and arrays, and `apps_version`.
fn stale_key_reads(current: &Value) -> bool {
    let Ok(current) = Obj::of(current, "Switch wire 7.6: a stale_key's current") else {
        return false;
    };
    ["receive_keys", "not_current", "unknown_kids", "added_apps"]
        .iter()
        .all(|name| current.required_list(name).is_ok())
        && current.u64("apps_version").is_ok()
}

/// Whether a `409 stale_key`'s `current` names an App ID more than once across its
/// `receive_keys`, `not_current` and `added_apps` (Switch wire 7.6).
fn names_an_app_twice(current: &Value) -> bool {
    let not_current = array(current, "not_current")
        .filter_map(Value::as_str)
        .filter_map(|text| pubky_switch_core::enc::app_id_decode(text).ok());
    let mut seen = HashSet::new();
    array(current, "receive_keys")
        .chain(array(current, "added_apps"))
        .filter_map(|entry| app_id_of(entry, "app_id"))
        .chain(not_current)
        .any(|app_id| !seen.insert(app_id))
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
