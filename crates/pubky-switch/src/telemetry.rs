//! Logs and metrics.
//!
//! Logs are structured, one JSON object per line by default. They hold no message content:
//! no envelopes, sealed values, record bodies, signatures or keys. Metrics are exported in
//! the Prometheus text format on the operator listener.

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::config::{LogConfig, LogFormat};

/// The environment variable that overrides `log.filter`.
pub const LOG_FILTER_ENV: &str = "PUBKY_SWITCH_LOG";

/// Why telemetry couldn't start.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// The log filter doesn't parse.
    #[error("log filter: {0}")]
    Filter(String),
    /// A global logger or metrics recorder is already installed.
    #[error("installing the {0}: one is already installed")]
    AlreadyInstalled(&'static str),
}

/// Install the global logger. `PUBKY_SWITCH_LOG`, when set, overrides `log.filter`.
pub fn init_logs(config: &LogConfig) -> Result<(), TelemetryError> {
    let filter = std::env::var(LOG_FILTER_ENV).unwrap_or_else(|_| config.filter.clone());
    let filter =
        EnvFilter::try_new(filter).map_err(|error| TelemetryError::Filter(error.to_string()))?;
    let registry = tracing_subscriber::registry().with(filter);
    let result = match config.format {
        LogFormat::Json => registry
            .with(
                fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(false),
            )
            .try_init(),
        LogFormat::Text => registry.with(fmt::layer()).try_init(),
    };
    result.map_err(|_| TelemetryError::AlreadyInstalled("logger"))
}

/// Install the global metrics recorder, and return the handle that renders its metrics.
pub fn init_metrics() -> Result<PrometheusHandle, TelemetryError> {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|_| TelemetryError::AlreadyInstalled("metrics recorder"))?;
    metrics::gauge!("pubky_switch_build_info", "version" => env!("CARGO_PKG_VERSION")).set(1.0);
    Ok(handle)
}
