//! What the service logged during a run.
//!
//! The service answers every failure of its storage `503 unavailable` and gives the reason
//! only in its log (Switch wire 7.6): a connection the database refused, or a wait for a
//! pooled connection or for an account's lock that ran out. A flow that meets such an
//! answer fails on the status alone. So a run keeps the service's warnings and errors, and
//! [`run`](crate::run) fails a run in which the service's storage failed with what the
//! service logged: the test database, which every suite on a machine shares, was the cause,
//! not either switch. Nothing is sent again.
//!
//! The log is kept for one thread: a flow, the service it calls and the service's change
//! listener all run on the flow's thread ([`on_flow_stack`](crate::on_flow_stack)).

use std::fmt::Write as _;
use std::sync::{Arc, Mutex, PoisonError};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Metadata, Subscriber, span};

/// The message of the service's log line for a storage failure it answers `503`.
const STORAGE: &str = "storage";

/// How the service's store names a failure of the database itself in a log line.
const DATABASE: &str = "database: ";

/// The service's warnings and errors of one run, in order.
#[derive(Clone, Debug, Default)]
pub struct ServiceLog {
    lines: Arc<Mutex<Vec<Logged>>>,
}

/// One line the service logged.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Logged {
    level: Level,
    target: String,
    message: String,
    /// The line's other fields, each as ` name=value`.
    fields: String,
}

impl Logged {
    /// Whether the line reports that the service's storage failed.
    fn storage_failed(&self) -> bool {
        self.message == STORAGE || self.fields.contains(DATABASE)
    }
}

impl std::fmt::Display for Logged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            level,
            target,
            message,
            fields,
        } = self;
        write!(f, "{level} {target}: {message}{fields}")
    }
}

/// Keeps a [`ServiceLog`] on the thread it was made on, until it is dropped.
pub struct Keeping {
    _guard: tracing::subscriber::DefaultGuard,
}

impl std::fmt::Debug for Keeping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keeping").finish_non_exhaustive()
    }
}

impl ServiceLog {
    /// Keep what the service logs on this thread, from now until the guard is dropped.
    #[must_use]
    pub fn keep(&self) -> Keeping {
        let keeper = Keeper {
            lines: self.lines.clone(),
        };
        Keeping {
            _guard: tracing::subscriber::set_default(keeper),
        }
    }

    /// Every line kept so far.
    pub fn lines(&self) -> Vec<String> {
        self.kept().iter().map(Logged::to_string).collect()
    }

    /// The lines kept so far that report a failure of the service's storage.
    pub fn storage_failures(&self) -> Vec<String> {
        self.kept()
            .iter()
            .filter(|line| line.storage_failed())
            .map(Logged::to_string)
            .collect()
    }

    fn kept(&self) -> Vec<Logged> {
        self.lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Whether a log line with `target` is the service's: its crate's, and no other crate's
/// whose name starts the same.
fn from_service(target: &str) -> bool {
    target == "pubky_switch" || target.starts_with("pubky_switch::")
}

/// The subscriber that keeps the service's warnings and errors, and nothing else.
struct Keeper {
    lines: Arc<Mutex<Vec<Logged>>>,
}

impl Subscriber for Keeper {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_event() && *metadata.level() <= Level::WARN && from_service(metadata.target())
    }

    // No span is enabled, so none is made, entered or recorded.
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut text = Text::default();
        event.record(&mut text);
        let metadata = event.metadata();
        self.lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Logged {
                level: *metadata.level(),
                target: metadata.target().to_owned(),
                message: text.message,
                fields: text.fields,
            });
    }

    fn enter(&self, _: &span::Id) {}

    fn exit(&self, _: &span::Id) {}
}

/// An event's message and its other fields.
#[derive(Default)]
struct Text {
    message: String,
    fields: String,
}

impl Visit for Text {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // Writing to a string doesn't fail.
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_log_keeps_the_services_warnings_and_errors_only() {
        let log = ServiceLog::default();
        tracing::warn!(target: "pubky_switch::service", "before the log is kept");
        let keeping = log.keep();
        tracing::warn!(
            target: "pubky_switch::service",
            error = %"database: pool timed out while waiting for an open connection",
            "storage"
        );
        tracing::info!(target: "pubky_switch::service", "served");
        tracing::warn!(target: "pubky_switch_other::service", "another crate's");
        tracing::warn!(target: "sqlx::query", "a slow statement");
        tracing::error!(target: "pubky_switch::keys", failure = %"no such file", "the operator key");
        drop(keeping);
        tracing::error!(target: "pubky_switch::service", "after it");

        assert_eq!(
            log.lines(),
            [
                "WARN pubky_switch::service: storage error=database: pool timed out while \
                 waiting for an open connection",
                "ERROR pubky_switch::keys: the operator key failure=no such file",
            ]
        );
    }

    #[test]
    fn test_service_log_tells_a_storage_failure_from_another_line() {
        let log = ServiceLog::default();
        let keeping = log.keep();
        // The account's lock wasn't free in time: no database error, the same answer.
        tracing::warn!(target: "pubky_switch::service", error = %"the account is busy", "storage");
        tracing::error!(
            target: "pubky_switch::service::keyed",
            failure = %"database: error communicating with database",
            "a keyed section"
        );
        tracing::error!(target: "pubky_switch::keys", failure = %"no such file", "the operator key");
        drop(keeping);

        assert_eq!(
            log.storage_failures(),
            [
                "WARN pubky_switch::service: storage error=the account is busy",
                "ERROR pubky_switch::service::keyed: a keyed section failure=database: error \
                 communicating with database",
            ]
        );
    }

    #[test]
    fn test_service_log_is_kept_for_its_own_thread_only() {
        let log = ServiceLog::default();
        let _keeping = log.keep();
        std::thread::scope(|scope| {
            scope.spawn(|| tracing::warn!(target: "pubky_switch::service", "on another thread"));
        });
        assert!(log.lines().is_empty());
    }
}
