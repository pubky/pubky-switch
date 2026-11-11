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
async fn switch(clock: Arc<TestClock>) -> Option<RealSwitch> {
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

/// One service, asked four things in turn: one test database for them all.
#[tokio::test]
async fn test_service_transport_takes_the_services_own_path() {
    let clock = Arc::new(TestClock::new(START_MS));
    let Some(switch) = switch(clock.clone()).await else {
        return;
    };
    let transport = switch.transport();
    let ask = |method: &str, origin: &str, path: &str, body: Vec<u8>| {
        transport.send(request(method, origin, path, body))
    };

    // No such route: the operator's signed `404` (Switch wire 7.3 step 1).
    let answer = ask("GET", ORIGIN, "/v1/someone/nowhere", Vec::new())
        .await
        .expect("an answer");
    assert_eq!((answer.status, code(&answer).as_str()), (404, "not_found"));
    assert!(answer.header(header::SERVICE_SIGNATURE).is_some());
    assert_eq!(
        answer.header(header::SERVER_TIME),
        Some("2026-01-01T00:00:00.000Z")
    );
    assert_eq!(answer.header("content-type"), Some("application/json"));

    // A body over its call's cap: a `GET` takes none (Switch wire 7.1).
    let answer = ask("GET", ORIGIN, "/v1/someone/feed", vec![b'x'])
        .await
        .expect("an answer");
    assert_eq!((answer.status, code(&answer).as_str()), (413, "too_large"));

    // Another origin: no service there.
    let error = ask(
        "GET",
        "https://other.example",
        "/v1/someone/feed",
        Vec::new(),
    )
    .await
    .expect_err("no service there");
    assert!(matches!(error, TransportError::Connect(_)), "{error:?}");

    // Two days on, past the oldest sample the service trusts: a fresh sample keeps its
    // time with the clock's.
    clock.advance_ms(2 * 24 * 3_600_000);
    switch.sample_time();
    let answer = ask("GET", ORIGIN, "/v1/someone/nowhere", Vec::new())
        .await
        .expect("an answer");
    assert_eq!(
        answer.header(header::SERVER_TIME),
        Some("2026-01-03T00:00:00.000Z")
    );

    drop(transport);
    switch.close().await.expect("closed");
}
