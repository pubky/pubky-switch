//! Waiting for the feed without holding the app (Switch wire 7.4.4).
//!
//! [`App::feed_wait`] takes a handle with `&self`: an owned [`FeedWait`] with a client of its
//! own, the position to wait from and the wait's length. Its [`FeedWait::wait`] sends one
//! long-poll read of the feed and says whether there is something to read; it changes
//! nothing of the app. A host races it against its own events, and calls
//! [`App::receive`] when it wakes with something to read, so the app stays free for its
//! other calls while the read is held.
//!
//! The handle signs with a copy of the app's signing keys and its certificate, as current
//! when it was taken. The copy is zeroized when the handle is dropped and never shown in
//! `Debug`; the handle holds nothing else secret: no scope key, no naming key, no store.

use pubky_switch_core::ops::Position;

use super::App;
use crate::client::SwitchClient;
use crate::client::answers::FeedQuery;

/// The longest one wait holds its read, in seconds (Switch wire 7.4.4).
pub const MAX_WAIT_SECONDS: u32 = 25;

/// What a wait for the feed ended in ([`FeedWait::wait`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Woken {
    /// The feed shows something past the position waited from: the host calls
    /// [`App::receive`] with no wait.
    Ready,
    /// The wait passed with nothing to show: the host takes a fresh handle and waits again.
    Quiet,
    /// The app should read now: the switch refused the wait or couldn't be reached, an
    /// answer didn't verify with the key the app pinned (a recovery in place answers a
    /// held read so, Switch wire 7.4.4), the account is frozen, the wait ended when a
    /// deferred cursor move fell due or with entries the app tries again at each read, or
    /// the app's state means only a read can go on. The host calls [`App::receive`] with
    /// no wait, once; when that read fails, it backs off before it waits again, as after
    /// any failed read. The handle never retries on its own.
    ReadNow,
}

/// Where the next wait starts, as the last read left it ([`App::feed_wait`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WaitFrom {
    /// The position the read was shown through: past entries the cursor stays before.
    pub(crate) position: Position,
    /// The read left work that comes due with time alone, such as entries held behind the
    /// cursor or a listing that waits for a key: a quiet wait is [`Woken::ReadNow`].
    pub(crate) again: bool,
}

/// A wait for the feed, taken with [`App::feed_wait`]: owned, `Send` and `'static`, so a
/// host can race [`FeedWait::wait`] against its own events while it goes on calling the
/// app.
///
/// It holds a copy of the app's signing keys, zeroized when it is dropped: a host takes a
/// fresh handle for each wait and doesn't keep handles around. A handle taken before a
/// read that moved the position only wakes early, its read then finding nothing new; one
/// taken before a renewal signs with the earlier certificate until the service refuses
/// it; one taken before a restore wakes at once or meets a refusal. Two handles may wait
/// at once, each with its own read (Switch wire 7.4.4).
///
/// The host's loop:
///
/// ```text
/// loop {
///     let report = app.receive(None).await?;   // on failure: back off, then go on
///     if report.more { continue; }              // a per-call budget stopped the read
///     loop {
///         match app.feed_wait(25).wait().await {
///             Woken::Quiet => continue,          // or the host's own events first
///             Woken::Ready | Woken::ReadNow => break,
///         }
///     }
/// }
/// ```
pub struct FeedWait {
    /// `None` when only a read can go on: the wait is [`Woken::ReadNow`] at once.
    held: Option<Held>,
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
            Some(held) => f
                .debug_struct("FeedWait")
                .field("after", &held.after.to_string())
                .field("seconds", &held.seconds)
                .finish(),
            None => f.write_str("FeedWait(read now)"),
        }
    }
}

impl FeedWait {
    /// Send one long-poll read of the feed after the handle's position, at most
    /// [`MAX_WAIT_SECONDS`], and verify its answer with the pinned service key, as every
    /// answer (Switch wire 7.1, 7.4.4). [`Woken::Ready`] for a page with an item or with
    /// `more`, [`Woken::Quiet`] for an empty one, and [`Woken::ReadNow`] for anything else:
    /// a refusal, an answer that doesn't verify, a frozen account, a transport error.
    ///
    /// Nothing is parsed into the app's state: no cursor moves, no alarm is raised, no time
    /// sample is taken and nothing is committed. Dropping the future at any point drops the
    /// read and leaves nothing behind.
    pub async fn wait(self) -> Woken {
        Box::pin(async move {
            let Some(held) = self.held else {
                return Woken::ReadNow;
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

impl App {
    /// A wait for the feed that doesn't hold the app ([`FeedWait`]): `seconds`, from 1 to
    /// [`MAX_WAIT_SECONDS`], cut to when a deferred cursor move falls due, never below a
    /// second, exactly as [`App::receive`] cuts its long poll (Switch spec 8.2, wire
    /// 7.4.4). It waits from the position the last read was shown through, past the
    /// entries the cursor stays before, or from the cursor.
    ///
    /// A handle taken while only a read can go on is [`Woken::ReadNow`] at once: after a
    /// failed call, whose state the next read loads again, and for an app stopped, left,
    /// gone, not registered or no longer current here.
    pub fn feed_wait(&self, seconds: u32) -> FeedWait {
        FeedWait {
            held: self.held_wait(seconds),
        }
    }

    fn held_wait(&self, seconds: u32) -> Option<Held> {
        if self.reload
            || self.refuse_when_stopped().is_err()
            || self.state.chain.is_none()
            || self.not_current_here().is_some()
        {
            return None;
        }
        // Past the cursor too, which may have passed the app's own writes after the last
        // page (Switch wire 7.4.4 "Passing own writes").
        let cursor = self.cursor();
        let (after, again) = match self.wait_from {
            Some(from) if from.position.generation == cursor.generation => {
                let seq = from.position.seq.max(cursor.seq);
                (Position { seq, ..cursor }, from.again)
            }
            _ => (cursor, false),
        };
        let (seconds, cut) = self.long_poll_seconds(seconds.max(1));
        let client = Self::client_for(
            &self.env,
            &self.state.meta,
            &self.state.keys,
            &self.state.cert,
        )
        .ok()?;
        Some(Held {
            client,
            after,
            seconds,
            read_after: again || cut,
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
