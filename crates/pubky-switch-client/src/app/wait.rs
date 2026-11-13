//! Waiting for the feed without holding the app (Switch wire 7.4.4).
//!
//! [`App::feed_wait`] takes a handle with `&self`: an owned [`FeedWait`] with a client of its
//! own, the position to wait from and the wait's length. Its [`FeedWait::wait`] sends at most
//! one long-poll read of the feed and says whether there is something to read; it changes
//! nothing of the app. A host races it against its own events, and calls
//! [`App::receive`] when it wakes with something to read, so the app stays free for its
//! other calls while the read is held. [`WaitPace`] paces the host's loop, so a state in
//! which reads and waits end at once never makes it spin.
//!
//! The handle signs with a copy of the app's keys and its certificate, as current when it
//! was taken. The keys are the app's signing key and the X25519 secret that opens the key
//! bundles addressed to the app (Switch spec 3.5); the handle only signs with them. The
//! copy is zeroized when the handle is dropped and never shown in `Debug`; the handle holds
//! nothing else secret: no scope key, no naming key, no store.

use std::time::Duration;

use pubky_switch_core::ops::Position;

use super::App;
use crate::client::SwitchClient;
use crate::client::answers::FeedQuery;

/// The longest one wait holds its read, in seconds (Switch wire 7.4.4).
pub const MAX_WAIT_SECONDS: u32 = 25;

/// The longest a quiet feed goes without a read, in milliseconds: 10 minutes. A read does
/// upkeep that comes due with time alone: it tries the entries stored locally again,
/// rotates the receive key, checks the app's published record and reads again what it
/// marked to read. A wait that would end this long or longer after the last read ended
/// ends in [`Woken::ReadNow`] when it is quiet. The shortest of those intervals is the
/// published record's check, every 10 minutes ([`super::PUBLISHED_CHECK_MS`]); a rotation
/// comes at most hourly.
pub const UPKEEP_READ_MS: u64 = 10 * 60_000;

/// The first pause of [`WaitPace`], in milliseconds.
pub const MIN_PAUSE_MS: u64 = 1_000;

/// The longest pause of [`WaitPace`], in milliseconds. It bounds how long a host waits to
/// see a state change that no feed wait shows, such as a scope key that arrives for a
/// listing ([`Woken::ReadLater`]).
pub const MAX_PAUSE_MS: u64 = 60_000;

/// What a wait for the feed ended in ([`FeedWait::wait`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Woken {
    /// The feed shows something past the position waited from: the host calls
    /// [`App::receive`] with no wait.
    Ready,
    /// The wait passed with nothing to show: the host takes a fresh handle and waits again.
    Quiet,
    /// The app should read now: the switch refused the wait or couldn't be reached, an
    /// answer didn't verify with the key the app pinned (a recovery in place answers a
    /// held read so, Switch wire 7.4.4), the account is frozen, or a failed call left
    /// state only a read loads again. Or the wait ended with nothing to show when a read
    /// is due all the same: a deferred cursor move fell due, entries are held behind the
    /// cursor or come again from the protocol's store at each read, or the last read ended
    /// [`UPKEEP_READ_MS`] ago. The host calls [`App::receive`] with no wait, once, as
    /// [`WaitPace`] says; when that read fails, it backs off before it reads again. The
    /// handle never retries on its own.
    ReadNow,
    /// Reads stop where the last one did, for something no wait on the feed shows, and the
    /// handle sent nothing: the last read stopped ([`super::ReceiveReport::stopped`]: a key
    /// another device made that this one lacks, a provider change or a move awaited), its
    /// owed listing waits for a scope key ([`super::AppEvent::ListingWaitsForKey`]), or the
    /// app is removed, gone, departed or stopped on an alarm. The host reads again after
    /// the pause [`WaitPace`] gives, not at once. A read that gets further takes the app out
    /// of this state.
    ReadLater,
}

/// Where the next wait starts, as the last read left it ([`App::feed_wait`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum NextWait {
    /// No read since the app was loaded set it: the wait goes from the cursor.
    #[default]
    Cursor,
    /// Past what the read was shown.
    From(WaitFrom),
    /// The read stopped, or its listing waits for a key: [`Woken::ReadLater`].
    Later,
}

/// The position a read was shown through ([`NextWait::From`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WaitFrom {
    /// The position the read was shown through: past entries the cursor stays before.
    pub(crate) position: Position,
    /// The read left work that comes due with time alone, such as entries held behind the
    /// cursor: a quiet wait is [`Woken::ReadNow`].
    pub(crate) again: bool,
}

/// A wait for the feed, taken with [`App::feed_wait`]: owned, `Send` and `'static`, so a
/// host can race [`FeedWait::wait`] against its own events while it goes on calling the
/// app.
///
/// It holds a copy of the app's keys, its signing key and the secret that opens its key
/// bundles, zeroized when it is dropped: a host takes a fresh handle for each wait and
/// doesn't keep handles around. A handle taken before a read that moved the position only
/// wakes early, its read then finding nothing new; one taken before a renewal signs with
/// the earlier certificate until the service refuses it; one taken before a restore wakes
/// at once or meets a refusal. Two handles may wait at once, each with its own read (Switch
/// wire 7.4.4).
///
/// The host's loop, paced with [`WaitPace`] so that no state makes it spin: a removed app,
/// a read that stops, a listing waiting for a key and a switch or proxy that ends every
/// wait at once each give it a pause, doubling to [`MAX_PAUSE_MS`]. A read that says
/// [`super::ReceiveReport::more`] is followed by the next at once, with no pause, by design:
/// each such read made progress its budget allowed, and what is left is finite.
///
/// ```text
/// let mut pace = WaitPace::new();
/// loop {
///     match app.receive(None).await {
///         Ok(report) if report.more => continue,   // a per-call budget stopped the read
///         Ok(_) => {}
///         Err(_) => {                               // Stopped and Left are for good
///             sleep(pace.after_failed_read()).await;
///             continue;
///         }
///     }
///     loop {
///         let wait = app.feed_wait(MAX_WAIT_SECONDS);
///         let asked = wait.seconds();
///         let started = Instant::now();
///         let woken = wait.wait().await;            // or the host's own events first
///         if let Some(pause) = pace.after_wait(woken, asked, started.elapsed()) {
///             sleep(pause).await;
///         }
///         if woken != Woken::Quiet { break; }
///     }
/// }
/// ```
pub struct FeedWait {
    /// What the wait is at once when it sends nothing: [`Woken::ReadNow`] or
    /// [`Woken::ReadLater`].
    held: Result<Held, Woken>,
}

struct Held {
    /// A client of its own: the app's keeps the latest answer's service time.
    client: SwitchClient,
    after: Position,
    seconds: u32,
    /// A wait that ends with nothing to show is [`Woken::ReadNow`].
    read_after: bool,
}

impl std::fmt::Debug for FeedWait {
    // The position and the wait only: no key or certificate.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.held {
            Ok(held) => f
                .debug_struct("FeedWait")
                .field("after", &held.after.to_string())
                .field("seconds", &held.seconds)
                .finish(),
            Err(woken) => write!(f, "FeedWait({woken:?})"),
        }
    }
}

impl FeedWait {
    /// How long the wait asks the switch to hold its read, in seconds: 0 when it sends
    /// none. A wait that ends much sooner was cut short ([`WaitPace::after_wait`]).
    #[must_use]
    pub fn seconds(&self) -> u32 {
        self.held.as_ref().map_or(0, |held| held.seconds)
    }

    /// Send one long-poll read of the feed after the handle's position, at most
    /// [`MAX_WAIT_SECONDS`], and verify its answer with the pinned service key, as every
    /// answer (Switch wire 7.1, 7.4.4). [`Woken::Ready`] for a page with an item or with
    /// `more`, [`Woken::Quiet`] for an empty one, and [`Woken::ReadNow`] for anything else:
    /// a refusal, an answer that doesn't verify, a frozen account, a transport error. A
    /// handle taken when no wait can tell anything sends nothing and is
    /// [`Woken::ReadNow`] or [`Woken::ReadLater`] at once ([`App::feed_wait`]).
    ///
    /// Nothing is parsed into the app's state: no cursor moves, no alarm is raised, no time
    /// sample is taken and nothing is committed. Dropping the future at any point drops the
    /// read and leaves nothing behind.
    pub async fn wait(self) -> Woken {
        Box::pin(async move {
            let held = match self.held {
                Ok(held) => held,
                Err(woken) => return woken,
            };
            let query = FeedQuery {
                after: Some(held.after),
                limit: Some(1),
                wait: Some(held.seconds),
            };
            match held.client.feed(query).await {
                Ok(page) if page.freeze.is_some() => Woken::ReadNow,
                Ok(page) if !page.items.is_empty() || page.more => Woken::Ready,
                Ok(_) if held.read_after => Woken::ReadNow,
                Ok(_) => Woken::Quiet,
                Err(_) => Woken::ReadNow,
            }
        })
        .await
    }
}

/// The pauses of a host's loop of reads and waits ([`FeedWait`]): none while waits are held
/// as long as they ask or wake with something to read, and otherwise a pause that starts at
/// [`MIN_PAUSE_MS`] and doubles to [`MAX_PAUSE_MS`]. With it, a round of the loop that
/// doesn't wait on the feed costs at least a pause, so no state of the app, the switch or a
/// proxy between them makes the loop spin. It holds no timer: the host sleeps the pauses
/// it returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WaitPace {
    pause_ms: u64,
}

impl Default for WaitPace {
    fn default() -> Self {
        Self::new()
    }
}

impl WaitPace {
    /// A pace with no pause owed yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pause_ms: MIN_PAUSE_MS,
        }
    }

    /// The pause after a read that failed, as after any failed call: the host sleeps it,
    /// then reads again. Each one doubles the next, to [`MAX_PAUSE_MS`].
    pub fn after_failed_read(&mut self) -> Duration {
        let pause = Duration::from_millis(self.pause_ms);
        self.pause_ms = self.pause_ms.saturating_mul(2).min(MAX_PAUSE_MS);
        pause
    }

    /// The pause after a wait that asked for `asked` seconds ([`FeedWait::seconds`]),
    /// ended in `woken` and took `took`: `None` to go on at once, otherwise the pause the
    /// host sleeps first. A wait that is [`Woken::Ready`], or that was held at least half
    /// as long as it asked, goes on at once and the pauses start over. One that is
    /// [`Woken::ReadLater`], or a [`Woken::Quiet`] or [`Woken::ReadNow`] that ended sooner,
    /// pauses, as a switch or proxy that ends waits early would otherwise make each round a
    /// wait and a read with nothing between them.
    pub fn after_wait(&mut self, woken: Woken, asked: u32, took: Duration) -> Option<Duration> {
        let held = took.saturating_mul(2) >= Duration::from_secs(u64::from(asked));
        match woken {
            Woken::Ready => {}
            Woken::Quiet | Woken::ReadNow if held => {}
            _ => return Some(self.after_failed_read()),
        }
        self.pause_ms = MIN_PAUSE_MS;
        None
    }
}

impl App {
    /// A wait for the feed that doesn't hold the app ([`FeedWait`]): `seconds`, from 1 to
    /// [`MAX_WAIT_SECONDS`], cut to when a deferred cursor move falls due, never below a
    /// second, exactly as [`App::receive`] cuts its long poll (Switch spec 8.2, wire
    /// 7.4.4). It waits from the position the last read was shown through, past the
    /// entries the cursor stays before, or from the cursor.
    ///
    /// A handle taken when no wait can tell anything sends nothing. It is
    /// [`Woken::ReadNow`] at once after a failed call, whose state the next read loads
    /// again, and for an app not registered yet. It is [`Woken::ReadLater`] at once after a
    /// read that stopped or whose listing waits for a key, until a read gets further, and
    /// for an app removed, gone, departed, stopped on an alarm or no longer current here.
    pub fn feed_wait(&self, seconds: u32) -> FeedWait {
        FeedWait {
            held: self.held_wait(seconds),
        }
    }

    fn held_wait(&self, seconds: u32) -> Result<Held, Woken> {
        if self.reload {
            return Err(Woken::ReadNow);
        }
        if self.refuse_when_stopped().is_err()
            || self.not_current_here().is_some()
            || self.next_wait == NextWait::Later
        {
            return Err(Woken::ReadLater);
        }
        if self.state.chain.is_none() {
            return Err(Woken::ReadNow);
        }
        // Never from behind the cursor: a read records a position at or past it, and a
        // position that isn't is passed over for the cursor.
        let cursor = self.cursor();
        let (after, again) = match self.next_wait {
            NextWait::Later => return Err(Woken::ReadLater),
            NextWait::From(from) if from.position.generation == cursor.generation => {
                let seq = from.position.seq.max(cursor.seq);
                (Position { seq, ..cursor }, from.again)
            }
            NextWait::From(_) | NextWait::Cursor => (cursor, false),
        };
        let (seconds, cut) = self.long_poll_seconds(seconds.max(1));
        // A quiet wait past the upkeep interval is a read; so is one when no read has
        // ended since the app was loaded.
        let ends = self.now().saturating_add(u64::from(seconds) * 1000);
        let upkeep = self
            .read_done_ms
            .is_none_or(|done| ends >= done.saturating_add(UPKEEP_READ_MS));
        let client = Self::client_for(
            &self.env,
            &self.state.meta,
            &self.state.keys,
            &self.state.cert,
        )
        .map_err(|_| Woken::ReadNow)?;
        Ok(Held {
            client,
            after,
            seconds,
            read_after: again || cut || upkeep,
        })
    }

    /// The long poll of a read asked to wait `seconds`: at most [`MAX_WAIT_SECONDS`], and
    /// cut to when a deferred cursor move falls due, never below a second for that cut
    /// (Switch spec 8.2, wire 7.4.4); and whether it ends when the move falls due.
    pub(crate) fn long_poll_seconds(&self, seconds: u32) -> (u32, bool) {
        let seconds = seconds.min(MAX_WAIT_SECONDS);
        let Some(since) = self.state.cursor.deferred_since_ms else {
            return (seconds, false);
        };
        let due = since.saturating_add(self.config.defer_ms());
        let left = due.saturating_sub(self.now()).div_ceil(1000).max(1);
        let left = u32::try_from(left).unwrap_or(u32::MAX);
        (seconds.min(left), left <= seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wait_pace_doubles_to_its_cap_and_starts_over() {
        let mut pace = WaitPace::new();
        let pauses: Vec<u64> = (0..8)
            .map(|_| {
                let pause = pace.after_wait(Woken::ReadLater, 0, Duration::ZERO);
                u64::try_from(pause.unwrap().as_millis()).unwrap()
            })
            .collect();
        assert_eq!(
            pauses,
            [1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000]
        );
        // A wait that wakes with something to read starts the pauses over.
        assert_eq!(pace.after_wait(Woken::Ready, 25, Duration::ZERO), None);
        assert_eq!(
            pace.after_failed_read(),
            Duration::from_millis(MIN_PAUSE_MS)
        );
        assert_eq!(pace.after_failed_read(), Duration::from_secs(2));
        // So does one held as long as it asked, or half of it.
        assert_eq!(
            pace.after_wait(Woken::Quiet, 25, Duration::from_millis(12_500)),
            None
        );
        assert_eq!(
            pace.after_failed_read(),
            Duration::from_millis(MIN_PAUSE_MS)
        );
    }

    #[test]
    fn test_wait_pace_pauses_a_wait_ended_early() {
        let mut pace = WaitPace::new();
        let early = Duration::from_millis(12_499);
        assert_eq!(
            pace.after_wait(Woken::Quiet, 25, early),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            pace.after_wait(Woken::ReadNow, 25, Duration::ZERO),
            Some(Duration::from_secs(2))
        );
        // A handle that sent nothing asked for nothing: its `ReadNow` is a read at once.
        assert_eq!(pace.after_wait(Woken::ReadNow, 0, Duration::ZERO), None);
        // A wait cut to a second by a deferred cursor move, and held for it.
        assert_eq!(
            pace.after_wait(Woken::ReadNow, 1, Duration::from_millis(500)),
            None
        );
    }
}
