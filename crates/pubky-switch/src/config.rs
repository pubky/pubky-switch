//! The service's configuration file.
//!
//! The file is TOML. Every section and setting is optional; what is left out takes its
//! default, and the limits default to the wire format's (Switch wire 9.2). Unknown settings
//! are refused, so a misspelt name fails at start instead of being ignored.

use std::{net::SocketAddr, path::Path};

use serde::{Deserialize, Serialize};

use crate::{keys::KeysConfig, limits::Limits, store::DatabaseConfig, time::TrustedTimeConfig};

/// The whole configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The operator listener: health and metrics.
    pub admin: AdminConfig,
    /// The API listener.
    pub server: crate::http::ServerConfig,
    /// Logs.
    pub log: LogConfig,
    /// Limits, quotas and rates (Switch wire 9.2).
    pub limits: Limits,
    /// Trusted time (Switch wire 7.3).
    pub trusted_time: TrustedTimeConfig,
    /// The database.
    pub database: DatabaseConfig,
    /// The key store.
    pub keys: KeysConfig,
    /// Push (Switch wire 8).
    pub push: PushConfig,
}

/// Push (Switch spec 9, Switch wire 8): registrations, and the webhooks a `notify` entry
/// queues for them, sent by a background worker in each instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PushConfig {
    /// Take push registrations (`PUT /v1/{id}/push`) and send webhooks; off, every
    /// registration is answered `400`, as a service that sends no pushes answers (Switch
    /// wire 8.1), and nothing is queued or sent. Off by default until delivery is fair across
    /// accounts.
    pub enabled: bool,
    /// The most webhooks one instance sends at once; 0 is taken as 1.
    pub concurrency: usize,
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            concurrency: 16,
        }
    }
}

/// The operator listener, which serves health checks and metrics. Keep it off the public
/// network: it isn't authenticated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    /// Address to listen on.
    pub listen: SocketAddr,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 9090)),
        }
    }
}

/// Log output. Logs never hold message content, sealed values, record bodies or keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// One JSON object per line, or human-readable text.
    pub format: LogFormat,
    /// A filter in `tracing` syntax, such as `info` or `info,pubky_switch=debug`.
    pub filter: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Json,
            filter: "info,sqlx::postgres::notice=warn".into(),
        }
    }
}

/// How log lines are written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// One JSON object per line.
    Json,
    /// Human-readable text.
    Text,
}

/// Why a configuration can't be used.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file couldn't be read.
    #[error("reading {path}: {source}")]
    Read {
        /// The file.
        path: String,
        /// The error.
        source: std::io::Error,
    },
    /// The file isn't valid TOML for this configuration.
    #[error("parsing the configuration: {0}")]
    Parse(#[from] toml::de::Error),
    /// A limit breaks a rule of the wire format.
    #[error(transparent)]
    Limit(#[from] crate::limits::LimitError),
    /// A trusted time setting is invalid.
    #[error(transparent)]
    TrustedTime(#[from] crate::time::TrustedTimeConfigError),
    /// A database setting is invalid.
    #[error(transparent)]
    Database(#[from] crate::store::DatabaseConfigError),
    /// A server setting is invalid.
    #[error(transparent)]
    Server(#[from] crate::http::ServerConfigError),
    /// The log filter doesn't parse.
    #[error("log.filter: {0}")]
    LogFilter(String),
}

impl Config {
    /// Parse and check a configuration from TOML text.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    /// Read, parse and check a configuration file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_toml(&text)
    }

    /// Check every section.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.limits.validate()?;
        self.trusted_time.validate()?;
        self.database.validate()?;
        self.server.validate()?;
        tracing_subscriber::EnvFilter::try_new(&self.log.filter)
            .map_err(|error| ConfigError::LogFilter(error.to_string()))?;
        Ok(())
    }

    /// The configuration as TOML, every setting written out.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_empty_file_takes_defaults() {
        let config = Config::from_toml("").expect("empty config");
        assert_eq!(config, Config::default());
        assert!(config.trusted_time.required);
        // Push is off unless the operator turns it on.
        assert!(!config.push.enabled);
        let on = Config::from_toml("[push]\nenabled = true\n").expect("push on");
        assert!(on.push.enabled);
    }

    #[test]
    fn test_config_example_file_is_the_defaults() {
        let text = include_str!("../../../config.example.toml");
        assert_eq!(Config::from_toml(text).expect("example"), Config::default());
    }

    #[test]
    fn test_config_round_trips_through_toml() {
        let mut config = Config::default();
        config.limits.quota_bytes *= 2;
        config.limits.checkpoint_behind = 10_000;
        config.log.format = LogFormat::Text;
        config.database.url = Some("postgres://switch@db/switch".into());
        config.keys.path = Some("/var/lib/pubky-switch/keys".into());
        let text = config.to_toml().expect("serialize");
        assert_eq!(Config::from_toml(&text).expect("parse"), config);
    }

    #[test]
    fn test_config_sets_a_limit() {
        let config = Config::from_toml("[limits]\nquota_bytes = 1048576\n").expect("config");
        assert_eq!(config.limits.quota_bytes, 1_048_576);
        assert_eq!(config.limits.app_limit, 32);
    }

    #[test]
    fn test_config_refuses_unknown_settings() {
        assert!(matches!(
            Config::from_toml("[limits]\nquota_byte = 1\n"),
            Err(ConfigError::Parse(_))
        ));
        assert!(matches!(
            Config::from_toml("[nonsense]\n"),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn test_config_refuses_invalid_values() {
        assert!(matches!(
            Config::from_toml("[limits]\napp_limit = 300\n"),
            Err(ConfigError::Limit(_))
        ));
        assert!(matches!(
            Config::from_toml("[trusted_time]\nsample_interval_ms = 7200000\n"),
            Err(ConfigError::TrustedTime(_))
        ));
        assert!(matches!(
            Config::from_toml("[log]\nfilter = \"info,[\"\n"),
            Err(ConfigError::LogFilter(_))
        ));
        assert!(matches!(
            Config::from_toml("[database]\nurl = \"mysql://db\"\n"),
            Err(ConfigError::Database(_))
        ));
        assert!(matches!(
            Config::from_toml("[admin]\nlisten = \"nowhere\"\n"),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn test_config_load_reports_missing_file() {
        let error = Config::load(Path::new("/nonexistent/pubky-switch.toml")).expect_err("load");
        assert!(matches!(error, ConfigError::Read { .. }));
    }
}
