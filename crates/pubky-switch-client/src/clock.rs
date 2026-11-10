//! The client's clock. The core reads no clock; the client takes every time it signs or
//! compares from a [`Clock`], so tests can fix it.

/// A source of the current time in Unix milliseconds.
pub trait Clock: Send + Sync {
    /// The current wall time in Unix milliseconds.
    fn now_ms(&self) -> u64;
}

/// The system's wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        // A clock set before 1970 reads as 0; one past `u64` milliseconds saturates.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

/// A clock that moves only when told to. Test builds only (`test-support`).
#[cfg(feature = "test-support")]
#[derive(Debug)]
pub struct TestClock {
    now: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "test-support")]
impl TestClock {
    /// A clock at `now_ms`.
    pub fn new(now_ms: u64) -> Self {
        Self {
            now: std::sync::atomic::AtomicU64::new(now_ms),
        }
    }

    /// Set the time, forward or back.
    pub fn set_ms(&self, now_ms: u64) {
        self.now.store(now_ms, std::sync::atomic::Ordering::SeqCst);
    }

    /// Move forward by `ms`, saturating.
    pub fn advance_ms(&self, ms: u64) {
        let now = self.now_ms().saturating_add(ms);
        self.set_ms(now);
    }
}

#[cfg(feature = "test-support")]
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.now.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_clock_reads_after_2026() {
        // 2026-01-01T00:00:00Z.
        assert!(SystemClock.now_ms() > 1_767_225_600_000);
    }

    #[test]
    fn test_test_clock_moves_only_when_told() {
        let clock = TestClock::new(1_000);
        assert_eq!(clock.now_ms(), 1_000);
        clock.advance_ms(500);
        assert_eq!(clock.now_ms(), 1_500);
        clock.set_ms(10);
        assert_eq!(clock.now_ms(), 10);
        clock.set_ms(u64::MAX);
        clock.advance_ms(1);
        assert_eq!(clock.now_ms(), u64::MAX);
    }
}
