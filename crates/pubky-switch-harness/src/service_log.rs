//! What the service logged during a run.
//!
//! The service answers every failure of its storage `503 unavailable` and gives the reason
//! only in its log (Switch wire 7.6). A flow that meets such an answer fails on the status
//! alone. So a run keeps the service's warnings and errors, and [`run`](crate::run) tells
//! two kinds of them apart:
//!
//! - **The database server failed a request**: it refused a connection, or the wait for a
//!   pooled connection or for an account's lock ran out. The test server, which every suite
//!   on a machine shares, was the cause, not either switch, and the run fails as that
//!   ([`ServiceLog::database_failures`]). Nothing is sent again.
//! - **A request failed inside the service for another reason**: a statement the database
//!   refused, a stored value that doesn't fit, a key that can't be read. That is the
//!   service's own, and the run fails as its flow, with the log
//!   ([`ServiceLog::request_failures`]).
//!
//! A line that is about no request fails no run: the store trying its first connection
//! again, or the change listener connecting again. It is shown beside a failed flow's error.
//!
//! The log is kept for one thread: a flow, the service it calls and the service's change
//! listener all run on the flow's thread ([`on_flow_stack`](crate::on_flow_stack)).

use std::fmt::Write as _;
use std::sync::{Arc, Mutex, PoisonError};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Metadata, Subscriber, span};

/// The service's module that answers requests: a line from it, or from a module of it, is
/// about a request.
const REQUESTS: &str = "pubky_switch::service";

/// What a line holds when the database server failed a request, and no statement did:
///
/// - the pool's wait for a connection ran out, or the pool is closed (`sqlx`'s
///   `PoolTimedOut` and `PoolClosed`);
/// - the connection broke (`sqlx`'s `Io`);
/// - the server took no connection: too many clients (SQLSTATE `53300`), or it is starting
///   up, shutting down or recovering (`57P03`);
/// - the wait for an account's lock ran out (the store's `LockTimeout`).
///
/// The log holds each error as text, so they are told by their wording.
const SERVER_FAILED: [&str; 9] = [
    "pool timed out while waiting for an open connection",
    "attempted to acquire a connection on a closed pool",
    "error communicating with database",
    "sorry, too many clients already",
    "remaining connection slots are reserved",
    "the database system is starting up",
    "the database system is shutting down",
    "the database system is in recovery mode",
    "the account is busy",
];

/// The most lines a run keeps: enough to read what went wrong, and no more however many
/// requests fail.
pub const MAX_LINES: usize = 50;

/// The service's warnings and errors of one run, in order.
#[derive(Clone, Debug, Default)]
pub struct ServiceLog {
    kept: Arc<Mutex<Kept>>,
}

/// The lines kept, and how many more there were.
#[derive(Clone, Debug, Default)]
struct Kept {
    /// The first [`MAX_LINES`] lines.
    lines: Vec<Logged>,
    /// How many lines came after those, of each kind.
    more_server: usize,
    more_request: usize,
    more_other: usize,
}

impl Kept {
    /// How many lines about `about` weren't kept.
    fn more(&mut self, about: About) -> &mut usize {
        match about {
            About::Server => &mut self.more_server,
            About::Request => &mut self.more_request,
            About::Other => &mut self.more_other,
        }
    }
}

/// What a line is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum About {
    /// A request the database server failed.
    Server,
    /// A request that failed inside the service for another reason.
    Request,
    /// No request.
    Other,
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
    fn about(&self) -> About {
        let request = self.target == REQUESTS
            || self
                .target
                .strip_prefix(REQUESTS)
                .is_some_and(|rest| rest.starts_with("::"));
        if !request {
            About::Other
        } else if SERVER_FAILED.iter().any(|text| self.fields.contains(text)) {
            About::Server
        } else {
            About::Request
        }
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
            kept: self.kept.clone(),
        };
        Keeping {
            _guard: tracing::subscriber::set_default(keeper),
        }
    }

    /// Every line kept so far: the first [`MAX_LINES`], and how many more there were.
    pub fn lines(&self) -> Vec<String> {
        self.lines_about(&[About::Server, About::Request, About::Other])
    }

    /// The lines kept so far for requests the database server failed: a refused or broken
    /// connection, or a wait for a connection or for an account's lock that ran out.
    pub fn database_failures(&self) -> Vec<String> {
        self.lines_about(&[About::Server])
    }

    /// The lines kept so far for requests that failed inside the service for another reason
    /// than the database server.
    pub fn request_failures(&self) -> Vec<String> {
        self.lines_about(&[About::Request])
    }

    /// The kept lines about any of `about`, and a last line counting those not kept.
    fn lines_about(&self, about: &[About]) -> Vec<String> {
        let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        let mut lines: Vec<String> = kept
            .lines
            .iter()
            .filter(|line| about.contains(&line.about()))
            .map(Logged::to_string)
            .collect();
        let more: usize = about.iter().map(|about| *kept.more(*about)).sum();
        if more > 0 {
            lines.push(format!("and {more} more of the kind, not kept"));
        }
        lines
    }
}

/// Whether a log line with `target` is the service's: its crate's, and no other crate's
/// whose name starts the same.
fn from_service(target: &str) -> bool {
    target == "pubky_switch" || target.starts_with("pubky_switch::")
}

/// The subscriber that keeps the service's warnings and errors, and nothing else.
struct Keeper {
    kept: Arc<Mutex<Kept>>,
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
        let line = Logged {
            level: *metadata.level(),
            target: metadata.target().to_owned(),
            message: text.message,
            fields: text.fields,
        };
        let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        if kept.lines.len() < MAX_LINES {
            kept.lines.push(line);
        } else {
            let more = kept.more(line.about());
            *more = more.saturating_add(1);
        }
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

    /// A line as `store_error` writes it for a request the store failed with `error`.
    fn storage(error: &str) {
        tracing::warn!(target: "pubky_switch::service", %error, "storage");
    }

    #[test]
    fn test_service_log_counts_only_the_servers_failures_as_the_databases() {
        let log = ServiceLog::default();
        let keeping = log.keep();
        // The server, or the wait for it.
        storage("database: pool timed out while waiting for an open connection");
        storage("database: attempted to acquire a connection on a closed pool");
        storage("database: error returned from database: sorry, too many clients already");
        storage("database: error returned from database: the database system is starting up");
        storage("the account is busy");
        tracing::error!(
            target: "pubky_switch::service::keyed",
            failure = %"database: error communicating with database: Connection reset by peer",
            "a keyed section"
        );
        // A statement the database refused, and a stored value that doesn't fit: the
        // service's own.
        storage(
            "database: error returned from database: duplicate key value violates unique constraint",
        );
        storage("corrupt account state: a chain item");
        // No request: the store's first connection tried again, the listener connecting
        // again, and another module whose name starts the same.
        tracing::warn!(
            target: "pubky_switch::store",
            error = %"error communicating with database: Connection refused",
            "the database isn't reachable yet; trying again"
        );
        tracing::warn!(
            target: "pubky_switch::changes",
            error = %"error communicating with database: Connection reset by peer",
            "change notifications"
        );
        tracing::warn!(target: "pubky_switch::services", error = %"the account is busy", "storage");
        drop(keeping);

        let database = log.database_failures();
        assert_eq!(database.len(), 6, "{database:?}");
        assert!(database[5].starts_with("ERROR pubky_switch::service::keyed: a keyed section"));
        assert_eq!(
            log.request_failures(),
            [
                "WARN pubky_switch::service: storage error=database: error returned from \
                 database: duplicate key value violates unique constraint",
                "WARN pubky_switch::service: storage error=corrupt account state: a chain item",
            ]
        );
        assert_eq!(log.lines().len(), 11);
    }

    #[test]
    fn test_service_log_keeps_a_bounded_number_of_lines() {
        let log = ServiceLog::default();
        let keeping = log.keep();
        for _ in 0..MAX_LINES + 3 {
            storage("corrupt account state: a chain item");
        }
        storage("the account is busy");
        storage("the account is busy");
        tracing::warn!(target: "pubky_switch::changes", "change notifications");
        drop(keeping);

        // A failure past the lines kept still counts.
        assert_eq!(
            log.database_failures(),
            ["and 2 more of the kind, not kept"]
        );
        let requests = log.request_failures();
        assert_eq!(requests.len(), MAX_LINES + 1);
        assert_eq!(
            requests.last().map(String::as_str),
            Some("and 3 more of the kind, not kept")
        );
        let all = log.lines();
        assert_eq!(all.len(), MAX_LINES + 1);
        assert_eq!(
            all.last().map(String::as_str),
            Some("and 6 more of the kind, not kept")
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
