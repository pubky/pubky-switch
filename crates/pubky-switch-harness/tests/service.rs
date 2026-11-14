//! The service behind the client's transport: a request takes the service's own path, with
//! its routing, its body caps and its signed refusals.

// Helpers of tests fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use pubky_switch::limits::Limits;
use pubky_switch::store::testing::TEST_DATABASE_URL_ENV;
use pubky_switch_client::TransportError;
use pubky_switch_client::clock::TestClock;
use pubky_switch_client::testing::START_MS;
use pubky_switch_client::transport::{Request, Response, Transport};
use pubky_switch_core::http::header;
use pubky_switch_harness::service::RealSwitch;
use pubky_switch_harness::service_log::ServiceLog;
use pubky_switch_harness::{Backend, HarnessError, run};

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
        timeout: pubky_switch_client::transport::TimeoutClass::default(),
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
    let name = switch.database_name().to_owned();
    switch.close().await.expect("closed");
    assert!(!database_exists(&name).await, "{name} was left behind");
}

/// A request the service's storage fails: the service answers `503 unavailable` under the
/// operator key, and its log, which a run keeps, says that it was the database.
#[tokio::test]
async fn test_service_storage_failure_is_a_503_whose_cause_the_log_names() {
    let Some(switch) = switch(Arc::new(TestClock::new(START_MS))).await else {
        return;
    };
    let identity = pubky_switch_core::keys::IdentityKey::from_secret([7; 32]);
    let id = pubky_switch_core::enc::zbase32_encode(&identity.public());
    let read = request("GET", ORIGIN, &format!("/v1/{id}/identity"), Vec::new());
    let log = ServiceLog::default();
    let keeping = log.keep();

    // With its database: no such account, and nothing logged.
    let answer = switch
        .transport()
        .send(read.clone())
        .await
        .expect("an answer");
    assert_eq!((answer.status, code(&answer).as_str()), (404, "not_found"));
    assert!(log.lines().is_empty(), "{:?}", log.lines());

    // Without a connection to it.
    switch.close_connections().await;
    let answer = switch.transport().send(read).await.expect("an answer");
    drop(keeping);
    assert_eq!(
        (answer.status, code(&answer).as_str()),
        (503, "unavailable")
    );
    assert!(answer.header(header::SERVICE_SIGNATURE).is_some());
    let failures = log.database_failures();
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(
        failures[0].starts_with("WARN pubky_switch::service: storage error=database: "),
        "{failures:?}"
    );

    switch.close().await.expect("closed");
}

/// A run against the service whose database takes no connection ends as the database's
/// failure, with the service's line for it, whether the flow fails on the `503` or passes
/// it by.
#[tokio::test]
async fn test_run_at_the_service_fails_as_the_database_when_it_takes_no_connection() {
    for flow_fails in [true, false] {
        let ended = run(Backend::Service, async |world| {
            let alice = world.identity("alice")?;
            world.add_switch(ORIGIN, &[&alice]).await?;
            let read = format!("/v1/{}/identity", alice.key().id());
            let answer = world.request("GET", ORIGIN, &read).await?;
            if answer.status != 404 {
                return Err(
                    format!("with its database the read was answered {}", answer.status).into(),
                );
            }
            world.close_database_connections(ORIGIN).await;
            let answer = world.request("GET", ORIGIN, &read).await?;
            if flow_fails {
                return Err(format!("the read was answered {}", answer.status).into());
            }
            Ok(())
        })
        .await;
        let (logged, flow) = match ended {
            Ok(None) => {
                eprintln!("skipped: no test database to run against the service");
                return;
            }
            Err(HarnessError::Database {
                backend: Backend::Service,
                logged,
                ended,
                ..
            }) => (logged, ended),
            other => panic!("the run ended {other:?}"),
        };
        assert_eq!(
            logged,
            "  WARN pubky_switch::service: storage error=database: attempted to acquire a \
             connection on a closed pool"
        );
        let expected = if flow_fails {
            "the read was answered 503"
        } else {
            "with no error"
        };
        assert_eq!(flow, expected);
    }
}

/// Whether the test server holds a database named `name`.
async fn database_exists(name: &str) -> bool {
    use std::str::FromStr;

    use sqlx::Connection;

    let url = std::env::var(TEST_DATABASE_URL_ENV).expect("the test database's URL");
    let options = sqlx::postgres::PgConnectOptions::from_str(&url).expect("options");
    let mut admin = sqlx::PgConnection::connect_with(&options)
        .await
        .expect("a connection");
    let found: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM pg_database WHERE datname = $1")
        .bind(name)
        .fetch_optional(&mut admin)
        .await
        .expect("the query");
    admin.close().await.expect("closed");
    found.is_some()
}

/// A switch that is dropped without being closed, as when its test panics, leaves no
/// database behind.
#[tokio::test]
async fn test_service_dropped_without_close_drops_its_database() {
    let Some(switch) = switch(Arc::new(TestClock::new(START_MS))).await else {
        return;
    };
    let name = switch.database_name().to_owned();
    assert!(database_exists(&name).await);
    // The unwinding of a panic drops it like this.
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _held = switch;
        panic!("a failing test");
    }));
    assert!(unwound.is_err());
    assert!(!database_exists(&name).await, "{name} was left behind");
}
