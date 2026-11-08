//! Rate limits in fixed one-minute windows (Switch wire 9.4).
//!
//! A limit of n a minute takes n requests in a window and refuses the next; the refusal's
//! `retry_after` is the seconds to the next window. Windows are fixed minutes of a time the
//! caller passes in: the time base for the failed-authentication limit, kept across
//! accounts (Switch wire 7.2), and an account's service time for the limits of one account.
//! Only the current minute is kept.

use std::{collections::HashMap, hash::Hash};

use parking_lot::Mutex;

use crate::http::source::NetworkSource;

/// A minute in milliseconds.
const MINUTE_MS: u64 = 60_000;

/// Counts per key in the current fixed minute.
#[derive(Debug)]
pub struct MinuteWindows<K> {
    state: Mutex<Window<K>>,
}

#[derive(Debug)]
struct Window<K> {
    minute: u64,
    counts: HashMap<K, u32>,
}

impl<K: Eq + Hash> Default for MinuteWindows<K> {
    fn default() -> Self {
        Self {
            state: Mutex::new(Window {
                minute: 0,
                counts: HashMap::new(),
            }),
        }
    }
}

/// The seconds from `now_ms` to the start of the next minute, at least 1.
pub fn retry_after_s(now_ms: u64) -> u64 {
    let into_minute = now_ms % MINUTE_MS;
    (MINUTE_MS - into_minute).div_ceil(1000).max(1)
}

impl<K: Eq + Hash> MinuteWindows<K> {
    /// The window, moved to the minute of `now_ms`. A time earlier than the window's minute
    /// counts in the window, so a clock that steps back can't open a fresh one.
    fn at(&self, now_ms: u64) -> parking_lot::MutexGuard<'_, Window<K>> {
        let mut window = self.state.lock();
        let minute = now_ms / MINUTE_MS;
        if minute > window.minute {
            window.minute = minute;
            window.counts.clear();
        }
        window
    }

    /// The count of `key` in the current minute.
    pub fn count(&self, key: &K, now_ms: u64) -> u32 {
        self.at(now_ms).counts.get(key).copied().unwrap_or(0)
    }

    /// Count one for `key`, and return its count in the current minute.
    pub fn hit(&self, key: K, now_ms: u64) -> u32 {
        let mut window = self.at(now_ms);
        let count = window.counts.entry(key).or_insert(0);
        *count = count.saturating_add(1);
        *count
    }

    /// Take one of `limit` for `key` in the current minute, or refuse with the seconds to
    /// the next window; a refusal doesn't count.
    pub fn take(&self, key: K, limit: u32, now_ms: u64) -> Result<(), u64> {
        let mut window = self.at(now_ms);
        let count = window.counts.entry(key).or_insert(0);
        if *count >= limit {
            return Err(retry_after_s(now_ms));
        }
        *count += 1;
        Ok(())
    }

    /// Forget every count whose key matches `remove`, as an erasure does.
    pub fn forget(&self, remove: impl Fn(&K) -> bool) {
        self.state.lock().counts.retain(|key, _| !remove(key));
    }

    /// Keys counted in the current window.
    pub fn len(&self) -> usize {
        self.state.lock().counts.len()
    }

    /// Whether nothing is counted in the current window.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A claimed caller: the account, and the `Switch-Identity` and `Switch-App` a request
/// claimed. Counted for monitoring only.
pub type ClaimedCaller = (String, String, Option<String>);

/// The failed-authentication limit (Switch wire 7.2, 9.4).
///
/// Every answer `401` counts against the request's network source, at all accounts
/// together. Once a source has `limit` failures in the current minute of the time base,
/// every further authenticating request from it in that minute is refused with
/// `429 rate_limited` before any signature work. Failures are also counted per claimed
/// caller, for the operator's monitoring, but never refuse a request: anyone can claim any
/// App ID, so such a refusal would let a stranger lock a victim app out.
#[derive(Debug)]
pub struct FailedAuthentications {
    limit: u32,
    per_source: MinuteWindows<NetworkSource>,
    per_claimed: MinuteWindows<ClaimedCaller>,
}

impl FailedAuthentications {
    /// A limit of `limit` failures per source per minute
    /// (`auth_failures_per_source_per_min`).
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            per_source: MinuteWindows::default(),
            per_claimed: MinuteWindows::default(),
        }
    }

    /// Check `source` before any signature work: `Err` with the seconds to the next window
    /// once it has used up its failures this minute. A request whose source the service
    /// can't tell isn't limited here.
    pub fn check(&self, source: Option<NetworkSource>, base_ms: u64) -> Result<(), u64> {
        match source {
            Some(source) if self.per_source.count(&source, base_ms) >= self.limit => {
                Err(retry_after_s(base_ms))
            }
            _ => Ok(()),
        }
    }

    /// Count a failed authentication of a request from `source`, claiming `caller`.
    pub fn record(&self, source: Option<NetworkSource>, caller: ClaimedCaller, base_ms: u64) {
        if let Some(source) = source {
            self.per_source.hit(source, base_ms);
        }
        self.per_claimed.hit(caller, base_ms);
        metrics::counter!("pubky_switch_failed_authentications_total").increment(1);
    }

    /// Failures this minute claiming `caller`, for monitoring.
    pub fn claimed(&self, caller: &ClaimedCaller, base_ms: u64) -> u32 {
        self.per_claimed.count(caller, base_ms)
    }

    /// Forget the counts at `account`, as its erasure does (Switch wire 7.4.16).
    pub fn forget_account(&self, account: &str) {
        self.per_claimed.forget(|(at, _, _)| at == account);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const T0: u64 = 1_767_225_600_000;

    fn source(last: u8) -> Option<NetworkSource> {
        Some(NetworkSource::V4(Ipv4Addr::new(203, 0, 113, last)))
    }

    fn caller(app: &str) -> ClaimedCaller {
        ("account".into(), "identity".into(), Some(app.into()))
    }

    #[test]
    fn test_minute_windows_take_n_and_refuse_the_next() {
        let windows = MinuteWindows::default();
        for _ in 0..3 {
            assert_eq!(windows.take("k", 3, T0 + 10_000), Ok(()));
        }
        assert_eq!(windows.take("k", 3, T0 + 10_000), Err(50));
        // The refusal didn't count, and another key has its own budget.
        assert_eq!(windows.count(&"k", T0 + 10_000), 3);
        assert_eq!(windows.take("other", 3, T0 + 10_000), Ok(()));
        // The next fixed minute starts afresh.
        assert_eq!(windows.take("k", 3, T0 + 60_000), Ok(()));
        assert_eq!(windows.count(&"k", T0 + 60_000), 1);
    }

    #[test]
    fn test_minute_windows_time_going_back_stays_in_window() {
        let windows = MinuteWindows::default();
        assert_eq!(windows.take("k", 1, T0 + 120_000), Ok(()));
        // An earlier time doesn't open a fresh window.
        assert!(windows.take("k", 1, T0 + 60_000).is_err());
    }

    #[test]
    fn test_retry_after_rounds_up_to_the_next_minute() {
        assert_eq!(retry_after_s(T0), 60);
        assert_eq!(retry_after_s(T0 + 59_001), 1);
        assert_eq!(retry_after_s(T0 + 59_999), 1);
        assert_eq!(retry_after_s(T0 + 30_500), 30);
    }

    #[test]
    fn test_failed_authentications_refuse_the_source_past_the_limit() {
        let limiter = FailedAuthentications::new(60);
        for _ in 0..60 {
            assert_eq!(limiter.check(source(1), T0), Ok(()));
            limiter.record(source(1), caller("a"), T0);
        }
        // With the default 60, the 61st is refused, until the next minute.
        assert_eq!(limiter.check(source(1), T0 + 1_000), Err(59));
        assert_eq!(limiter.check(source(2), T0 + 1_000), Ok(()));
        assert_eq!(limiter.check(source(1), T0 + 60_000), Ok(()));
    }

    #[test]
    fn test_failed_authentications_claimed_caller_only_monitors() {
        let limiter = FailedAuthentications::new(2);
        // Failures from many sources claiming one victim app.
        for last in 0..10 {
            limiter.record(source(last), caller("victim"), T0);
        }
        assert_eq!(limiter.claimed(&caller("victim"), T0), 10);
        // The victim, from its own source, isn't refused.
        assert_eq!(limiter.check(source(200), T0), Ok(()));
        limiter.forget_account("account");
        assert_eq!(limiter.claimed(&caller("victim"), T0), 0);
    }

    #[test]
    fn test_failed_authentications_unknown_source_is_not_limited() {
        let limiter = FailedAuthentications::new(1);
        limiter.record(None, caller("a"), T0);
        limiter.record(None, caller("a"), T0);
        assert_eq!(limiter.check(None, T0), Ok(()));
    }
}
