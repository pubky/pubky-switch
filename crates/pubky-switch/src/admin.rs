//! The operator listener: health checks and metrics.
//!
//! - `GET /health/live` answers `200` while the process runs.
//! - `GET /health/ready` answers `200` when every readiness check passes, and `503`
//!   otherwise, with each check's result in a JSON body. Trusted time is reported but never
//!   makes the service unready: without it the service still serves everything that
//!   doesn't depend on time (Switch wire 7.3).
//! - `GET /metrics` renders the metrics in the Prometheus text format.
//!
//! The listener isn't authenticated. Keep it on a private network.

use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};

use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::Serialize;

use crate::time::TrustedTime;

/// A future returned by [`ReadinessCheck::check`].
pub type CheckFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// Something the service needs before it can take requests, such as its database.
pub trait ReadinessCheck: Send + Sync {
    /// A short name, shown in the readiness answer.
    fn name(&self) -> &str;

    /// `Ok` when ready, or why not. The reason is shown to the operator, so it holds no
    /// secrets.
    fn check(&self) -> CheckFuture<'_>;
}

/// What the operator listener reports on.
#[derive(Clone)]
pub struct AdminState {
    checks: Vec<Arc<dyn ReadinessCheck>>,
    time: Arc<TrustedTime>,
    metrics: Option<PrometheusHandle>,
}

impl AdminState {
    /// Report on `time`, with `metrics` rendered at `/metrics` when given.
    pub fn new(time: Arc<TrustedTime>, metrics: Option<PrometheusHandle>) -> Self {
        Self {
            checks: Vec::new(),
            time,
            metrics,
        }
    }

    /// Add a readiness check.
    pub fn with_check(mut self, check: Arc<dyn ReadinessCheck>) -> Self {
        self.checks.push(check);
        self
    }
}

/// The readiness answer.
#[derive(Debug, Serialize)]
struct Readiness {
    ready: bool,
    checks: BTreeMap<String, String>,
    trusted_time: bool,
}

/// The operator listener's routes.
pub fn router(state: AdminState) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/metrics", get(render_metrics))
        .with_state(state)
}

async fn live() -> &'static str {
    "ok"
}

async fn ready(State(state): State<AdminState>) -> impl IntoResponse {
    let mut checks = BTreeMap::new();
    let mut ready = true;
    for check in &state.checks {
        let result = match check.check().await {
            Ok(()) => "ok".to_string(),
            Err(reason) => {
                ready = false;
                reason
            }
        };
        checks.insert(check.name().to_string(), result);
    }
    state.time.record_gauges();
    let body = Readiness {
        ready,
        checks,
        trusted_time: state.time.peek().trusted,
    };
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body))
}

async fn render_metrics(State(state): State<AdminState>) -> impl IntoResponse {
    state.time.record_gauges();
    match &state.metrics {
        Some(handle) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            handle.render(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::{ManualClock, TrustedTimeConfig};
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;

    struct Fixed(&'static str, Result<(), String>);

    impl ReadinessCheck for Fixed {
        fn name(&self) -> &str {
            self.0
        }

        fn check(&self) -> CheckFuture<'_> {
            let result = self.1.clone();
            Box::pin(async move { result })
        }
    }

    fn state() -> AdminState {
        let clock = Arc::new(ManualClock::new(1_767_225_600_000));
        let time = Arc::new(TrustedTime::new(TrustedTimeConfig::default(), clock));
        AdminState::new(time, None)
    }

    async fn get_json(router: Router, path: &str) -> (StatusCode, serde_json::Value) {
        let response = router
            .oneshot(Request::get(path).body(Body::empty()).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    #[tokio::test]
    async fn test_admin_live_answers_ok() {
        let (status, _) = get_json(router(state()), "/health/live").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_ready_with_passing_checks() {
        let state = state().with_check(Arc::new(Fixed("database", Ok(()))));
        let (status, body) = get_json(router(state), "/health/ready").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ready"], true);
        assert_eq!(body["checks"]["database"], "ok");
        // Without a sample there is no trusted time, which is reported but not unready.
        assert_eq!(body["trusted_time"], false);
    }

    #[tokio::test]
    async fn test_admin_ready_with_failing_check() {
        let state = state()
            .with_check(Arc::new(Fixed("database", Err("unreachable".into()))))
            .with_check(Arc::new(Fixed("keys", Ok(()))));
        let (status, body) = get_json(router(state), "/health/ready").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["ready"], false);
        assert_eq!(body["checks"]["database"], "unreachable");
        assert_eq!(body["checks"]["keys"], "ok");
    }

    #[tokio::test]
    async fn test_admin_metrics_without_recorder_is_not_found() {
        let (status, _) = get_json(router(state()), "/metrics").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_admin_metrics_renders_prometheus_text() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            metrics::counter!("pubky_switch_test_total").increment(2);
        });
        let mut state = state();
        state.metrics = Some(handle);
        let response = router(state)
            .oneshot(
                Request::get("/metrics")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let text = String::from_utf8(body.to_vec()).expect("utf-8");
        assert!(text.contains("pubky_switch_test_total 2"), "{text}");
    }
}
