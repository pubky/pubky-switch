//! The service behind the client's transport: a request takes the service's own path, with
//! its routing, its body caps and its signed refusals.

// Helpers of tests fail the test on any error.
#![allow(clippy::expect_used)]

use std::sync::Arc;

use pubky_switch::limits::Limits;
use pubky_switch_client::TransportError;
use pubky_switch_client::clock::TestClock;
use pubky_switch_client::testing::START_MS;
use pubky_switch_client::transport::{Request, Response, Transport};
use pubky_switch_core::http::header;
use pubky_switch_harness::service::RealSwitch;

const ORIGIN: &str = "https://switch.example";

/// A service with no account, or `None` when no test database is configured.
async fn switch() -> Option<RealSwitch> {
    let clock = Arc::new(TestClock::new(START_MS));
    RealSwitch::start(ORIGIN, clock, vec![[1; 32]], [2; 32], Limits::default())
        .await
        .expect("a service")
}

fn request(method: &str, origin: &str, path: &str, body: Vec<u8>) -> Request {
    Request {
        method: method.into(),
        origin: origin.into(),
        path_and_query: path.into(),
        headers: Vec::new(),
        body,
    }
}

fn code(answer: &Response) -> String {
    let body: serde_json::Value = serde_json::from_slice(&answer.body).expect("json");
    body["code"].as_str().expect("a code").to_owned()
}

#[tokio::test]
async fn test_service_transport_answers_an_unknown_route_as_the_service_does() {
    let Some(switch) = switch().await else {
        return;
    };
    let answer = switch
        .transport()
        .send(request("GET", ORIGIN, "/v1/someone/nowhere", Vec::new()))
        .await
        .expect("an answer");
    // The operator's signed `404` (Switch wire 7.3 step 1).
    assert_eq!((answer.status, code(&answer).as_str()), (404, "not_found"));
    assert!(answer.header(header::SERVICE_SIGNATURE).is_some());
    assert!(answer.header(header::SERVER_TIME).is_some());
    assert_eq!(answer.header("content-type"), Some("application/json"));
    switch.close().await.expect("closed");
}

#[tokio::test]
async fn test_service_transport_refuses_a_body_over_its_cap() {
    let Some(switch) = switch().await else {
        return;
    };
    // A `GET` takes no body (Switch wire 7.1).
    let answer = switch
        .transport()
        .send(request("GET", ORIGIN, "/v1/someone/feed", vec![b'x']))
        .await
        .expect("an answer");
    assert_eq!((answer.status, code(&answer).as_str()), (413, "too_large"));
    switch.close().await.expect("closed");
}

#[tokio::test]
async fn test_service_transport_reaches_only_its_origin() {
    let Some(switch) = switch().await else {
        return;
    };
    let elsewhere = request(
        "GET",
        "https://other.example",
        "/v1/someone/feed",
        Vec::new(),
    );
    let error = switch
        .transport()
        .send(elsewhere)
        .await
        .expect_err("no service there");
    assert!(matches!(error, TransportError::Connect(_)), "{error:?}");
    switch.close().await.expect("closed");
}

#[tokio::test]
async fn test_service_time_follows_the_clock_with_a_fresh_sample() {
    let clock = Arc::new(TestClock::new(START_MS));
    let Some(switch) = RealSwitch::start(
        ORIGIN,
        clock.clone(),
        vec![[1; 32]],
        [2; 32],
        Limits::default(),
    )
    .await
    .expect("a service") else {
        return;
    };
    let server_time = |answer: &Response| answer.header(header::SERVER_TIME).map(str::to_owned);
    let transport = switch.transport();
    let ask = || transport.send(request("GET", ORIGIN, "/v1/someone/nowhere", Vec::new()));
    let first = ask().await.expect("an answer");
    assert_eq!(
        server_time(&first).as_deref(),
        Some("2026-01-01T00:00:00.000Z")
    );
    // Two days on, past the oldest sample the service trusts: a fresh sample keeps its time.
    clock.advance_ms(2 * 24 * 3_600_000);
    switch.sample_time();
    let later = ask().await.expect("an answer");
    assert_eq!(
        server_time(&later).as_deref(),
        Some("2026-01-03T00:00:00.000Z")
    );
    switch.close().await.expect("closed");
}
