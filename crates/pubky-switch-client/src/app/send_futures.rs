//! The futures of the app's entry points a host may spawn are `Send`: a host runs them on a
//! multi-threaded runtime (`tokio::spawn`), and a future that holds a non-`Send` value, such
//! as a borrowed iterator, across an await can't be spawned. The checks are at compile time:
//! the function below is never called, and building the tests fails if one of them isn't.

use std::sync::Arc;

use pubky_switch_core::ops::Condition;

use super::{
    App, AppBackup, AppConfig, AppEnv, ClaimOp, JoinRequest, LeaveMode, ObligationDeadline,
    OpBatch, OutgoingMessage, Protocol, RecordTarget,
};

fn is_send<T: Send>(_: T) {}

/// Every call below is a future the host may spawn; none is awaited.
#[allow(dead_code, clippy::too_many_arguments)]
fn app_futures_are_send(
    app: &mut App,
    env: AppEnv,
    protocol: Arc<dyn Protocol>,
    config: AppConfig,
    request: JoinRequest,
    backup: &AppBackup,
    message: OutgoingMessage,
    target: &RecordTarget,
    claim: ClaimOp,
    batch: OpBatch,
    conditions: Vec<Condition>,
) {
    is_send(App::join(
        env.clone(),
        Arc::clone(&protocol),
        config.clone(),
        request,
    ));
    is_send(App::load(env.clone(), Arc::clone(&protocol), config.clone(), [0; 16]));
    is_send(App::restore(env, protocol, config, backup));
    is_send(app.receive(None));
    is_send(app.send(message));
    is_send(app.flush_outbox());
    is_send(app.put_record(target, &[], conditions.clone()));
    is_send(app.read_record(target));
    is_send(app.read_record_fresh(target));
    is_send(app.list_collections());
    is_send(app.write_claim(claim, conditions, ObligationDeadline::NotKnown));
    is_send(app.read_claim(&[0; 32]));
    is_send(app.submit_batch(batch));
    is_send(app.refresh_identity());
    is_send(app.follow_provider());
    is_send(app.check_for_move());
    is_send(app.ask_to_connect(&[0; 32]));
    is_send(app.connect_requests());
    is_send(app.backup());
    is_send(app.leave(LeaveMode::TwoStep));
}
