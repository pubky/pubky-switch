//! Test harness for the Pubky Switch: client and signer flows against the service, and the
//! same flows against the client's scripted switch, compared.
//!
//! **For tests only.** Nothing depends on this crate; it turns on the service's `test-util`
//! and the client's `test-support`.
//!
//! - [`service`]: the service of this workspace, in process on a test database, behind the
//!   client's [`Transport`](pubky_switch_client::transport::Transport).
//! - [`world`]: a [`World`] to run a flow in, answered by the service or by the scripted
//!   switch, with one surface for both.
//! - [`flows`]: honest flows of the real signer and the real app, each written once.
//! - [`trace`]: what a run showed, in a form two runs with different keys can be compared
//!   in.
//! - [`compare`]: the differences between two runs, judged against the list in [`allowed`].
//! - [`check`]: what the harness verifies itself of every answer of either switch: the
//!   answer's signature, each head, chain stub, feed item and transition proof.
//! - [`service_log`]: the service's warnings and errors of a run, so a run in which the
//!   test database failed says so.
//!
//! [`compare_backends`] runs one flow in both worlds and gives the verdict. A flow's test
//! fails when the scripted switch answers differently from the service anywhere the allowed
//! list doesn't say so.
//!
//! Tests of a faulty or hostile switch stay on the scripted switch, which can roll back, lie
//! and lose answers; the service can't.
//!
//! # What agreement means
//!
//! Two runs that agree made the same calls and got answers alike in every fact [`trace`]
//! keeps, and every check of [`check`] held in both. That is not byte equality, and not a
//! proof that either switch is right: a hash or signature a switch makes itself and gets
//! wrong consistently reads alike in both runs, and is caught only where [`check`], the
//! client or the signer verifies it ([`check`] lists what it covers and what it leaves).

pub mod allowed;
pub mod check;
pub mod compare;
pub mod flows;
pub mod parties;
pub mod service;
pub mod service_log;
pub mod store;
pub mod trace;
pub mod world;

use pubky_switch::store::testing::TEST_DATABASE_URL_ENV;

pub use compare::Verdict;
pub use trace::Trace;
pub use world::{Backend, World};

/// A failure of the harness itself, or of a flow in one world.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HarnessError {
    /// A world that couldn't be set up.
    #[error("setup: {0}")]
    Setup(String),
    /// A flow that failed: an honest flow fails against no switch.
    #[error("the flow failed against {backend:?}: {error}\n{trace}")]
    Flow {
        /// What answered the world's requests.
        backend: Backend,
        /// The flow's error.
        error: String,
        /// What the run showed until then.
        trace: Trace,
    },
    /// A run in which the database server failed a request of the service: it refused a
    /// connection or broke one, or kept a request waiting for one or for an account's lock
    /// until the wait ran out ([`service_log`]). The service answers that `503 unavailable`
    /// (Switch wire 7.6), so whatever the flow showed says nothing about either switch.
    #[error(
        "the test database failed during the run against {backend:?}: the service couldn't \
         reach its storage, which it answers `503 unavailable`. The server \
         {TEST_DATABASE_URL_ENV} names refused or broke a connection, or kept a request \
         waiting too long; another suite using that server at the same time is the usual \
         cause. Nothing was sent again.\n\
         The service logged:\n{logged}\nThe flow ended: {ended}\n{trace}"
    )]
    Database {
        /// What answered the world's requests.
        backend: Backend,
        /// The service's log lines for the failures, one a line.
        logged: String,
        /// How the flow ended: its error, or that it had none.
        ended: String,
        /// What the run showed.
        trace: Trace,
    },
}

/// What a flow returns: an error only for what should fail against no switch.
pub type FlowResult = Result<(), Box<dyn std::error::Error>>;

/// The stack a flow runs on, in bytes.
///
/// A flow's futures nest deeply: the client's and the signer's calls, and under them the
/// service itself, are all polled from the flow's thread, and in a debug build every level
/// takes a large frame. Measured in a debug build, the deepest flow (`third epoch, three
/// readers`, against the service) used 1.9 MiB of stack and two flows in five used more
/// than 1.5 MiB, against the 2 MiB a test's thread has. So a flow gets a thread of its own
/// whose stack doesn't depend on who runs it: 16 MiB, eight times what the deepest flow
/// used. The pages are committed only as they are touched.
pub const FLOW_STACK_BYTES: usize = 16 * 1024 * 1024;

/// Run `work` to its end on a thread of its own with [`FLOW_STACK_BYTES`] of stack, in a
/// runtime of its own, and give what it returned. The calling thread waits for it. A panic
/// in `work` goes on in the caller, and the thread carries the caller's name, so a test
/// reads the same as when it ran the work itself.
///
/// # Errors
///
/// When the thread or its runtime can't be started.
pub fn on_flow_stack<T: Send>(work: impl AsyncFnOnce() -> T + Send) -> Result<T, HarnessError> {
    let name = std::thread::current().name().unwrap_or("flow").to_owned();
    std::thread::scope(|scope| {
        let thread = std::thread::Builder::new()
            .name(name)
            .stack_size(FLOW_STACK_BYTES)
            .spawn_scoped(scope, || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| HarnessError::Setup(format!("a flow's runtime: {error}")))?;
                Ok(runtime.block_on(work()))
            })
            .map_err(|error| HarnessError::Setup(format!("a flow's thread: {error}")))?;
        match thread.join() {
            Ok(done) => done,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}

/// Run `flow` in a world answered by `backend`, and give what the run showed; `None` for
/// the service when no test database is configured. The flow runs on a thread of its own
/// ([`on_flow_stack`]), and the caller's thread waits for it.
///
/// # Errors
///
/// When the world can't be set up, or the flow fails.
pub async fn run(
    backend: Backend,
    flow: impl AsyncFn(&World) -> FlowResult + Sync,
) -> Result<Option<Trace>, HarnessError> {
    on_flow_stack(async || run_here(backend, &flow).await)?
}

/// [`run`], on the calling thread.
async fn run_here(
    backend: Backend,
    flow: impl AsyncFn(&World) -> FlowResult,
) -> Result<Option<Trace>, HarnessError> {
    // Kept on this thread, where the service answers the flow's requests.
    let log = service_log::ServiceLog::default();
    let keeping = log.keep();
    let Some(world) = World::start(backend)? else {
        return Ok(None);
    };
    let outcome = flow(&world).await.map_err(|error| error.to_string());
    let trace = world.trace();
    let closed = world.close().await;
    drop(keeping);
    ended_run(backend, outcome, closed, &log, trace)
}

/// How a run ends: with its trace, or why it failed. `outcome` is the flow's, `closed` what
/// closing the world gave, and `log` what the service logged until then.
fn ended_run(
    backend: Backend,
    outcome: Result<(), String>,
    closed: Result<(), HarnessError>,
    log: &service_log::ServiceLog,
    trace: Trace,
) -> Result<Option<Trace>, HarnessError> {
    let lines = |lines: Vec<String>| -> String {
        lines
            .iter()
            .map(|line| format!("  {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    // With what the service logged, when it logged anything.
    let with_log = |error: String| -> String {
        let logged = log.lines();
        if logged.is_empty() {
            error
        } else {
            format!("{error}\nthe service logged:\n{}", lines(logged))
        }
    };
    // A run in which the database server failed a request shows the test server, not a
    // switch: it fails as that, whatever the flow made of the `503` and however the world
    // closed, and isn't run again.
    let failures = log.database_failures();
    if !failures.is_empty() {
        return Err(HarnessError::Database {
            backend,
            logged: lines(failures),
            ended: outcome.err().unwrap_or_else(|| "with no error".to_owned()),
            trace,
        });
    }
    if let Err(HarnessError::Setup(error)) = closed {
        return Err(HarnessError::Setup(with_log(error)));
    }
    closed?;
    // A request that failed inside the service for another reason is the service's own:
    // the flow fails with the log, also when it made nothing of the answer.
    let outcome = match outcome {
        Ok(()) if log.request_failures().is_empty() => return Ok(Some(trace)),
        Ok(()) => "the flow ended with no error, but a request failed inside the service".into(),
        Err(error) => error,
    };
    Err(HarnessError::Flow {
        backend,
        error: with_log(outcome),
        trace,
    })
}

/// One flow's two runs, and the verdict on their differences.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Comparison {
    /// What the run against the service showed.
    pub service: Trace,
    /// What the run against the scripted switch showed.
    pub scripted: Trace,
    /// The differences, judged against [`allowed::ALLOWED`].
    pub verdict: Verdict,
}

/// Run the flow named `name` against the scripted switch and against the service, and judge
/// the differences against [`allowed::ALLOWED`]; `None` when no test database is configured,
/// once the flow ran against the scripted switch alone.
///
/// # Errors
///
/// When a world can't be set up, or the flow fails in one.
pub async fn compare_backends(
    name: &str,
    flow: impl AsyncFn(&World) -> FlowResult + Sync,
) -> Result<Option<Comparison>, HarnessError> {
    let scripted = run(Backend::Scripted, &flow)
        .await?
        .ok_or_else(|| HarnessError::Setup("the scripted world didn't start".into()))?;
    let Some(service) = run(Backend::Service, &flow).await? else {
        return Ok(None);
    };
    let differences = compare::differences(&service, &scripted);
    let verdict = compare::judge(name, differences, allowed::ALLOWED);
    Ok(Some(Comparison {
        service,
        scripted,
        verdict,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The service's log line for a request its storage failed, as `store_error` writes it.
    fn log_a_storage_failure() {
        tracing::warn!(
            target: "pubky_switch::service",
            error = %"database: pool timed out while waiting for an open connection",
            "storage"
        );
    }

    #[tokio::test]
    async fn test_run_fails_as_the_database_when_the_services_storage_failed() {
        // Whether the flow fails on the `503` or passes it by.
        for flow_fails in [true, false] {
            let ended = run(Backend::Scripted, async |_world| {
                log_a_storage_failure();
                if flow_fails {
                    return Err("the write was answered 503 unavailable".into());
                }
                Ok(())
            })
            .await;
            let Err(error @ HarnessError::Database { .. }) = ended else {
                panic!("the run ended {ended:?}");
            };
            let text = error.to_string();
            assert!(text.starts_with("the test database failed"), "{text}");
            assert!(text.contains(TEST_DATABASE_URL_ENV), "{text}");
            assert!(
                text.contains(
                    "  WARN pubky_switch::service: storage error=database: pool timed out"
                ),
                "{text}"
            );
            let flow = if flow_fails {
                "The flow ended: the write was answered 503 unavailable"
            } else {
                "The flow ended: with no error"
            };
            assert!(text.contains(flow), "{text}");
        }
    }

    #[tokio::test]
    async fn test_run_shows_what_the_service_logged_when_a_flow_fails() {
        let ended = run(Backend::Scripted, async |_world| {
            tracing::error!(target: "pubky_switch::keys", failure = %"no such file", "a key");
            Err("the enrollment was refused".into())
        })
        .await;
        let Err(HarnessError::Flow { error, .. }) = ended else {
            panic!("the run ended {ended:?}");
        };
        assert_eq!(
            error,
            "the enrollment was refused\nthe service logged:\n  ERROR pubky_switch::keys: a \
             key failure=no such file"
        );
        // A run with nothing logged fails and passes as before.
        let quiet = run(Backend::Scripted, async |_world| Err("refused".into())).await;
        assert!(matches!(quiet, Err(HarnessError::Flow { error, .. }) if error == "refused"));
        let passed = run(Backend::Scripted, async |_world| Ok(())).await;
        assert!(matches!(passed, Ok(Some(_))));
    }

    #[tokio::test]
    async fn test_run_fails_as_the_flow_when_a_request_failed_inside_the_service() {
        // A statement the database refused is the service's own, not the test server's:
        // the flow fails with the log, also when it made nothing of the answer.
        let ended = run(Backend::Scripted, async |_world| {
            tracing::warn!(
                target: "pubky_switch::service",
                error = %"database: error returned from database: duplicate key value",
                "storage"
            );
            Ok(())
        })
        .await;
        let Err(HarnessError::Flow { error, .. }) = ended else {
            panic!("the run ended {ended:?}");
        };
        assert_eq!(
            error,
            "the flow ended with no error, but a request failed inside the service\nthe \
             service logged:\n  WARN pubky_switch::service: storage error=database: error \
             returned from database: duplicate key value"
        );
    }

    #[test]
    fn test_ended_run_names_the_database_before_a_world_that_didnt_close() {
        // A server that failed a request often fails the drop of the database too: the
        // run is the database's all the same, with the service's line.
        let log = service_log::ServiceLog::default();
        let keeping = log.keep();
        log_a_storage_failure();
        drop(keeping);
        let closed = Err(HarnessError::Setup("database: the drop failed".into()));
        let ended = ended_run(Backend::Service, Ok(()), closed, &log, Trace::default());
        let Err(HarnessError::Database { logged, ended, .. }) = ended else {
            panic!("the run ended {ended:?}");
        };
        assert!(logged.contains("pool timed out"), "{logged}");
        assert_eq!(ended, "with no error");
    }

    #[test]
    fn test_ended_run_keeps_the_log_when_the_world_didnt_close() {
        let log = service_log::ServiceLog::default();
        let keeping = log.keep();
        tracing::warn!(target: "pubky_switch::changes", "change notifications");
        drop(keeping);
        let closed = || Err(HarnessError::Setup("database: the drop failed".into()));
        let ended = ended_run(Backend::Service, Ok(()), closed(), &log, Trace::default());
        let Err(HarnessError::Setup(error)) = ended else {
            panic!("the run ended {ended:?}");
        };
        assert_eq!(
            error,
            "database: the drop failed\nthe service logged:\n  WARN pubky_switch::changes: \
             change notifications"
        );
        // With nothing logged, the close's own error.
        let quiet = service_log::ServiceLog::default();
        let ended = ended_run(Backend::Service, Ok(()), closed(), &quiet, Trace::default());
        assert!(
            matches!(&ended, Err(HarnessError::Setup(error)) if error == "database: the drop failed"),
            "{ended:?}"
        );
    }

    #[tokio::test]
    async fn test_run_passes_a_flow_whose_service_logged_about_no_request() {
        // The store's first connection, tried again, and the listener connecting again
        // answer no request `503`.
        let ended = run(Backend::Scripted, async |_world| {
            tracing::warn!(
                target: "pubky_switch::store",
                error = %"error communicating with database: Connection refused",
                "the database isn't reachable yet; trying again"
            );
            tracing::warn!(target: "pubky_switch::changes", "change notifications");
            Ok(())
        })
        .await;
        assert!(matches!(ended, Ok(Some(_))), "{ended:?}");
    }

    /// Use about `bytes` of stack, a 64 KiB frame a level, and give 1 back.
    #[inline(never)]
    fn deep(bytes: usize) -> u8 {
        const STEP: usize = 64 * 1024;
        let mut frame = [0u8; STEP];
        // By reference: moved by value, a frame would cost its size several times over.
        std::hint::black_box(&mut frame)[STEP - 1] = 1;
        if bytes <= STEP {
            frame[STEP - 1]
        } else {
            deep(bytes - STEP).min(frame[STEP - 1])
        }
    }

    #[test]
    fn test_flow_stack_holds_more_than_a_test_thread_has() {
        // Twice a test thread's 2 MiB, which would abort the test there.
        let reached = on_flow_stack(async || deep(4 * 1024 * 1024));
        assert!(matches!(reached, Ok(1)));
    }

    #[test]
    fn test_flow_stack_thread_carries_its_callers_name_and_runs_a_runtime() {
        let here = std::thread::current().name().map(str::to_owned);
        let there = on_flow_stack(async || {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            std::thread::current().name().map(str::to_owned)
        });
        assert!(here.is_some());
        assert!(matches!(there, Ok(name) if name == here));
    }

    #[test]
    fn test_flow_stack_panic_goes_on_in_the_caller() {
        let caught = std::panic::catch_unwind(|| {
            on_flow_stack(async || {
                if std::hint::black_box(true) {
                    std::panic::panic_any("the flow's own panic");
                }
            })
        });
        let payload = caught.err().and_then(|panic| panic.downcast::<&str>().ok());
        assert_eq!(payload.as_deref(), Some(&"the flow's own panic"));
    }
}
