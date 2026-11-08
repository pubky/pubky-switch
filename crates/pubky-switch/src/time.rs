//! Trusted time (Switch spec 10.1, Switch wire 7.3).
//!
//! The service keeps its newest authenticated time sample, from the operator's choice of
//! source behind the narrow [`TimeSource`] interface, and anchors it to its monotonic
//! clock. Trusted time is the sample plus the monotonic time elapsed since it; its
//! uncertainty is the sample's own plus the elapsed time times the drift bound. A change of
//! the wall clock moves neither.
//!
//! The **time base** is the wall clock while it agrees with trusted time within
//! `max_disagreement_ms`, and trusted time otherwise, which raises an alert. Request
//! timestamps are checked against the time base, and each account stamps it, never going
//! back. Without trusted time (no sample within `max_sample_age_ms`, or an uncertainty
//! above `max_uncertainty_ms`) the service refuses what depends on its time with
//! `503 unavailable`.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// A source of wall time and of monotonic elapsed time.
pub trait Clock: Send + Sync {
    /// Wall time in Unix milliseconds. An operator or NTP may set it, so it can jump.
    fn now_ms(&self) -> u64;

    /// Milliseconds on a monotonic clock: it never goes back, counts only elapsed time and
    /// isn't moved by a change of the wall clock. Its origin is arbitrary.
    fn monotonic_ms(&self) -> u64;
}

/// The system's clocks. The only place the service reads the system time.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, saturating_ms)
    }

    fn monotonic_ms(&self) -> u64 {
        static ORIGIN: OnceLock<Instant> = OnceLock::new();
        saturating_ms(ORIGIN.get_or_init(Instant::now).elapsed())
    }
}

fn saturating_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// A clock that moves only when told to, for tests.
///
/// Advancing moves both readings; [`ManualClock::set_wall_ms`] is a wall-clock jump that
/// leaves the monotonic reading where it is.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub struct ManualClock {
    wall: AtomicU64,
    monotonic: AtomicU64,
}

#[cfg(any(test, feature = "test-util"))]
impl ManualClock {
    /// A clock whose wall time is `start_ms`.
    pub fn new(start_ms: u64) -> Self {
        Self {
            wall: AtomicU64::new(start_ms),
            monotonic: AtomicU64::new(0),
        }
    }

    /// Let `ms` milliseconds elapse, on both readings.
    pub fn advance_ms(&self, ms: u64) {
        self.wall.fetch_add(ms, Ordering::SeqCst);
        self.monotonic.fetch_add(ms, Ordering::SeqCst);
    }

    /// Set the wall time, forward or back; the monotonic reading doesn't move.
    pub fn set_wall_ms(&self, ms: u64) {
        self.wall.store(ms, Ordering::SeqCst);
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.wall.load(Ordering::SeqCst)
    }

    fn monotonic_ms(&self) -> u64 {
        self.monotonic.load(Ordering::SeqCst)
    }
}

/// The trusted time rules (Switch wire 7.3, 9.2), with the wire format's defaults.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrustedTimeConfig {
    /// Require trusted time: without it, refuse what depends on time. On by default; turn
    /// it off only for development, where the wall clock is then taken as trusted.
    pub required: bool,
    /// The most the monotonic clock may drift from true time, in parts per million.
    pub drift_ppm: u64,
    /// The oldest sample, by the monotonic clock, that still gives trusted time.
    pub max_sample_age_ms: u64,
    /// The largest uncertainty trusted time may have.
    pub max_uncertainty_ms: u64,
    /// The most the wall clock may differ from trusted time before the service uses trusted
    /// time instead, and alerts.
    pub max_disagreement_ms: u64,
    /// How often the service asks its time source for a sample. At most an hour (Switch
    /// spec 10.1).
    pub sample_interval_ms: u64,
    /// How long the service waits before asking again after a failed sample.
    pub retry_interval_ms: u64,
}

/// One hour in milliseconds: the longest interval between samples (Switch spec 10.1).
const HOUR_MS: u64 = 3_600_000;

impl Default for TrustedTimeConfig {
    fn default() -> Self {
        Self {
            required: true,
            drift_ppm: 100,
            max_sample_age_ms: 24 * HOUR_MS,
            max_uncertainty_ms: 5 * 60 * 1000,
            max_disagreement_ms: 5 * 60 * 1000,
            sample_interval_ms: 15 * 60 * 1000,
            retry_interval_ms: 60 * 1000,
        }
    }
}

/// A trusted time configuration that breaks a rule.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("trusted_time.{name}: {reason}")]
pub struct TrustedTimeConfigError {
    /// The setting's name.
    pub name: &'static str,
    /// What is wrong with it.
    pub reason: &'static str,
}

impl TrustedTimeConfig {
    /// Check the settings.
    pub fn validate(&self) -> Result<(), TrustedTimeConfigError> {
        let fail = |name, reason| Err(TrustedTimeConfigError { name, reason });
        if self.sample_interval_ms == 0 || self.sample_interval_ms > HOUR_MS {
            return fail("sample_interval_ms", "must be between 1 ms and one hour");
        }
        if self.retry_interval_ms == 0 || self.retry_interval_ms > self.sample_interval_ms {
            return fail(
                "retry_interval_ms",
                "must be at least 1 ms and at most sample_interval_ms",
            );
        }
        if self.max_sample_age_ms < self.sample_interval_ms {
            return fail(
                "max_sample_age_ms",
                "must be at least sample_interval_ms, or trusted time lapses between samples",
            );
        }
        if self.max_uncertainty_ms == 0 {
            return fail("max_uncertainty_ms", "must be at least 1 ms");
        }
        if self.max_disagreement_ms == 0 {
            return fail("max_disagreement_ms", "must be at least 1 ms");
        }
        Ok(())
    }
}

/// One authenticated reading of true time, as a [`TimeSource`] gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeSample {
    /// True time when the answer arrived, in Unix milliseconds.
    pub utc_ms: u64,
    /// How far true time may be from `utc_ms`, including the round trip.
    pub uncertainty_ms: u64,
}

/// Why a time source gave no sample.
#[derive(Debug, thiserror::Error)]
#[error("time source {source_name}: {reason}")]
pub struct TimeSourceError {
    /// The source's name.
    pub source_name: String,
    /// What went wrong.
    pub reason: String,
}

/// A future returned by [`TimeSource::sample`].
pub type SampleFuture<'a> =
    Pin<Box<dyn Future<Output = Result<TimeSample, TimeSourceError>> + Send + 'a>>;

/// An authenticated source of true time, such as Roughtime or NTS-secured NTP.
///
/// A source checks the authenticity of every answer itself and gives only samples it
/// verified. The sampler adds the round trip it measured to the sample's uncertainty.
pub trait TimeSource: Send + Sync {
    /// A short name for logs and metrics.
    fn name(&self) -> &str;

    /// Ask for one sample.
    fn sample(&self) -> SampleFuture<'_>;
}

/// What the service knows about time at one moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeReading {
    /// The time base: the wall clock while it agrees with trusted time, trusted time
    /// otherwise.
    pub base_ms: u64,
    /// Whether the service has trusted time now.
    pub trusted: bool,
    /// The uncertainty of trusted time, if there is a sample.
    pub uncertainty_ms: Option<u64>,
}

/// A sample anchored to the monotonic clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Anchored {
    utc_ms: u64,
    uncertainty_ms: u64,
    monotonic_ms: u64,
}

/// The service's trusted time: its newest sample and the alerts raised.
pub struct TrustedTime {
    config: TrustedTimeConfig,
    clock: Arc<dyn Clock>,
    sample: Mutex<Option<Anchored>>,
    alerts: AtomicU64,
}

impl std::fmt::Debug for TrustedTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedTime")
            .field("config", &self.config)
            .field("sample", &*self.sample.lock())
            .field("alerts", &self.alerts.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl TrustedTime {
    /// Trusted time with no sample yet.
    pub fn new(config: TrustedTimeConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            config,
            clock,
            sample: Mutex::new(None),
            alerts: AtomicU64::new(0),
        }
    }

    /// The configuration.
    pub fn config(&self) -> &TrustedTimeConfig {
        &self.config
    }

    /// The clock trusted time is anchored to.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// Take a verified sample that arrived at the monotonic reading `monotonic_ms`,
    /// replacing an older one.
    pub fn note(&self, sample: TimeSample, monotonic_ms: u64) {
        *self.sample.lock() = Some(Anchored {
            utc_ms: sample.utc_ms,
            uncertainty_ms: sample.uncertainty_ms,
            monotonic_ms,
        });
    }

    /// Alerts raised so far: readings where the wall clock disagreed with trusted time by
    /// more than `max_disagreement_ms`.
    pub fn alerts(&self) -> u64 {
        self.alerts.load(Ordering::Relaxed)
    }

    /// The time for one request. A disagreement beyond the bound raises an alert.
    pub fn read(&self) -> TimeReading {
        let (reading, disagrees) = self.evaluate();
        if disagrees {
            self.alerts.fetch_add(1, Ordering::Relaxed);
            metrics::counter!("pubky_switch_time_disagreement_alerts_total").increment(1);
        }
        reading
    }

    /// The time now, without raising an alert, for health checks and metrics.
    pub fn peek(&self) -> TimeReading {
        self.evaluate().0
    }

    fn evaluate(&self) -> (TimeReading, bool) {
        let wall = self.clock.now_ms();
        if !self.config.required {
            let reading = TimeReading {
                base_ms: wall,
                trusted: true,
                uncertainty_ms: None,
            };
            return (reading, false);
        }
        let Some(sample) = *self.sample.lock() else {
            let reading = TimeReading {
                base_ms: wall,
                trusted: false,
                uncertainty_ms: None,
            };
            return (reading, false);
        };
        let elapsed = self
            .clock
            .monotonic_ms()
            .saturating_sub(sample.monotonic_ms);
        let estimate = sample.utc_ms.saturating_add(elapsed);
        let drift =
            u64::try_from(u128::from(elapsed) * u128::from(self.config.drift_ppm) / 1_000_000)
                .unwrap_or(u64::MAX);
        let uncertainty = sample.uncertainty_ms.saturating_add(drift);
        let trusted = elapsed <= self.config.max_sample_age_ms
            && uncertainty <= self.config.max_uncertainty_ms;
        // A stale sample still corrects a wall clock that jumped: the monotonic clock stays
        // the better reference, but without trusted time nothing that depends on time is
        // decided.
        let disagrees = wall.abs_diff(estimate) > self.config.max_disagreement_ms;
        let reading = TimeReading {
            base_ms: if disagrees { estimate } else { wall },
            trusted,
            uncertainty_ms: Some(uncertainty),
        };
        (reading, disagrees)
    }

    /// Ask `source` for one sample and take it. The round trip is added to the sample's
    /// uncertainty, and the sample is anchored at the moment the answer arrived.
    pub async fn sample_once(&self, source: &dyn TimeSource) -> Result<(), TimeSourceError> {
        let sent = self.clock.monotonic_ms();
        let result = source.sample().await;
        let arrived = self.clock.monotonic_ms();
        match result {
            Ok(sample) => {
                let round_trip = arrived.saturating_sub(sent);
                let sample = TimeSample {
                    utc_ms: sample.utc_ms,
                    uncertainty_ms: sample.uncertainty_ms.saturating_add(round_trip),
                };
                self.note(sample, arrived);
                metrics::counter!("pubky_switch_time_samples_total", "result" => "ok").increment(1);
                self.record_gauges();
                Ok(())
            }
            Err(error) => {
                metrics::counter!("pubky_switch_time_samples_total", "result" => "error")
                    .increment(1);
                self.record_gauges();
                Err(error)
            }
        }
    }

    /// Publish whether the service has trusted time, and its uncertainty.
    pub fn record_gauges(&self) {
        let reading = self.peek();
        metrics::gauge!("pubky_switch_trusted_time_available").set(if reading.trusted {
            1.0
        } else {
            0.0
        });
        if let Some(uncertainty) = reading.uncertainty_ms {
            // Milliseconds are far below the 2^53 a gauge holds exactly.
            #[allow(clippy::cast_precision_loss)]
            metrics::gauge!("pubky_switch_trusted_time_uncertainty_ms").set(uncertainty as f64);
        }
    }

    /// Sample `source` every `sample_interval_ms`, and after a failure every
    /// `retry_interval_ms`, until `shutdown` resolves.
    pub async fn run_sampler(
        self: Arc<Self>,
        source: Arc<dyn TimeSource>,
        shutdown: impl Future<Output = ()>,
    ) {
        tokio::pin!(shutdown);
        loop {
            let wait = match self.sample_once(source.as_ref()).await {
                Ok(()) => {
                    tracing::debug!(source = source.name(), "time sample taken");
                    self.config.sample_interval_ms
                }
                Err(error) => {
                    tracing::warn!(%error, "time sample failed");
                    self.config.retry_interval_ms
                }
            };
            tokio::select! {
                () = tokio::time::sleep(Duration::from_millis(wait)) => {}
                () = &mut shutdown => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const START_MS: u64 = 1_767_225_600_000;

    fn trusted(config: TrustedTimeConfig) -> (Arc<ManualClock>, TrustedTime) {
        let clock = Arc::new(ManualClock::new(START_MS));
        let time = TrustedTime::new(config, clock.clone());
        (clock, time)
    }

    struct FixedSource(Result<TimeSample, ()>);

    impl TimeSource for FixedSource {
        fn name(&self) -> &str {
            "fixed"
        }

        fn sample(&self) -> SampleFuture<'_> {
            let result = self.0.map_err(|()| TimeSourceError {
                source_name: "fixed".into(),
                reason: "no answer".into(),
            });
            Box::pin(async move { result })
        }
    }

    #[test]
    fn test_trusted_time_follows_monotonic_clock() {
        let (clock, time) = trusted(TrustedTimeConfig::default());
        assert!(!time.read().trusted, "no sample yet");
        time.note(
            TimeSample {
                utc_ms: START_MS,
                uncertainty_ms: 0,
            },
            clock.monotonic_ms(),
        );
        clock.advance_ms(20 * 60 * 1000);
        let reading = time.read();
        assert!(reading.trusted);
        assert_eq!(reading.base_ms, START_MS + 1_200_000);
        // A wall-clock jump of an hour either way is overridden, and raises an alert.
        clock.set_wall_ms(START_MS + 1_200_000 + HOUR_MS);
        assert_eq!(time.read().base_ms, START_MS + 1_200_000);
        clock.set_wall_ms(START_MS + 1_200_000 - HOUR_MS);
        assert_eq!(time.read().base_ms, START_MS + 1_200_000);
        assert_eq!(time.alerts(), 2);
        // Past the maximum sample age: no trusted time, though the estimate still corrects
        // the wall clock.
        clock.advance_ms(24 * HOUR_MS);
        let reading = time.read();
        assert!(!reading.trusted);
        assert_eq!(reading.base_ms, START_MS + 1_200_000 + 24 * HOUR_MS);
    }

    #[test]
    fn test_trusted_time_small_jump_moves_time_base() {
        let (clock, time) = trusted(TrustedTimeConfig::default());
        time.note(
            TimeSample {
                utc_ms: START_MS,
                uncertainty_ms: 0,
            },
            0,
        );
        clock.set_wall_ms(START_MS + 4 * 60 * 1000);
        let reading = time.read();
        assert!(reading.trusted);
        assert_eq!(reading.base_ms, START_MS + 4 * 60 * 1000);
        assert_eq!(time.alerts(), 0);
    }

    #[test]
    fn test_trusted_time_uncertainty_bound() {
        let (clock, time) = trusted(TrustedTimeConfig {
            drift_ppm: 10_000,
            ..TrustedTimeConfig::default()
        });
        time.note(
            TimeSample {
                utc_ms: START_MS,
                uncertainty_ms: 0,
            },
            0,
        );
        // 1% drift: 5 minutes of uncertainty after 500 minutes.
        clock.advance_ms(500 * 60 * 1000);
        assert!(time.read().trusted);
        clock.advance_ms(60 * 1000);
        assert!(!time.read().trusted);
    }

    #[test]
    fn test_trusted_time_not_required_uses_wall_clock() {
        let (clock, time) = trusted(TrustedTimeConfig {
            required: false,
            ..TrustedTimeConfig::default()
        });
        let reading = time.read();
        assert!(reading.trusted);
        assert_eq!(reading.base_ms, clock.now_ms());
    }

    #[tokio::test]
    async fn test_trusted_time_sample_adds_round_trip() {
        let (clock, time) = trusted(TrustedTimeConfig::default());
        let source = FixedSource(Ok(TimeSample {
            utc_ms: START_MS,
            uncertainty_ms: 40,
        }));
        time.sample_once(&source).await.expect("sample");
        let reading = time.peek();
        assert!(reading.trusted);
        assert_eq!(reading.uncertainty_ms, Some(40));
        clock.advance_ms(1_000);
        assert_eq!(time.peek().base_ms, START_MS + 1_000);
    }

    #[tokio::test]
    async fn test_trusted_time_failed_sample_leaves_no_trusted_time() {
        let (_clock, time) = trusted(TrustedTimeConfig::default());
        let source = FixedSource(Err(()));
        let error = time.sample_once(&source).await.expect_err("no sample");
        assert_eq!(error.source_name, "fixed");
        assert!(!time.peek().trusted);
    }

    #[test]
    fn test_trusted_time_config_validation() {
        assert_eq!(TrustedTimeConfig::default().validate(), Ok(()));
        let cases = [
            (
                TrustedTimeConfig {
                    sample_interval_ms: HOUR_MS + 1,
                    ..TrustedTimeConfig::default()
                },
                "sample_interval_ms",
            ),
            (
                TrustedTimeConfig {
                    retry_interval_ms: 0,
                    ..TrustedTimeConfig::default()
                },
                "retry_interval_ms",
            ),
            (
                TrustedTimeConfig {
                    max_sample_age_ms: 1_000,
                    ..TrustedTimeConfig::default()
                },
                "max_sample_age_ms",
            ),
            (
                TrustedTimeConfig {
                    max_uncertainty_ms: 0,
                    ..TrustedTimeConfig::default()
                },
                "max_uncertainty_ms",
            ),
        ];
        for (config, name) in cases {
            assert_eq!(config.validate().expect_err(name).name, name);
        }
    }
}
