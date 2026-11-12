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
pub mod store;
pub mod trace;
pub mod world;

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
}

/// What a flow returns: an error only for what should fail against no switch.
pub type FlowResult = Result<(), Box<dyn std::error::Error>>;

/// Run `flow` in a world answered by `backend`, and give what the run showed; `None` for
/// the service when no test database is configured.
///
/// # Errors
///
/// When the world can't be set up, or the flow fails.
pub async fn run(
    backend: Backend,
    flow: impl AsyncFn(&World) -> FlowResult,
) -> Result<Option<Trace>, HarnessError> {
    let Some(world) = World::start(backend)? else {
        return Ok(None);
    };
    let outcome = flow(&world).await.map_err(|error| error.to_string());
    let trace = world.trace();
    world.close().await?;
    match outcome {
        Ok(()) => Ok(Some(trace)),
        Err(error) => Err(HarnessError::Flow {
            backend,
            error,
            trace,
        }),
    }
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
    flow: impl AsyncFn(&World) -> FlowResult,
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
