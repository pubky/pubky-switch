//! The service, in process, behind the client's [`Transport`].
//!
//! [`ServiceTransport`] hands each request to the service's own router
//! ([`pubky_switch::http::router`]), so a request takes the path a network request takes:
//! routing, the body caps, the refusals before the handler, and the handler's processing
//! order (Switch wire 7.1 to 7.4). No socket is opened.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request as HttpRequest, header};
use pubky_switch::changes::{ChangeHub, ChangeListener};
use pubky_switch::http::source::ProxyConfig;
use pubky_switch::keys::{FileKeyStore, FixedKeys};
use pubky_switch::limits::Limits;
use pubky_switch::service::{Resolver, Service};
use pubky_switch::store::Store;
use pubky_switch::store::testing::{
    REQUIRE_DB_ENV, TEST_DATABASE_URL_ENV, TestDatabase, test_database,
};
use pubky_switch::time::{Clock as ServiceClock, TimeSample, TrustedTime, TrustedTimeConfig};
use pubky_switch_client::TransportError;
use pubky_switch_client::clock::{Clock, TestClock};
use pubky_switch_client::transport::{BoxFuture, Header, Request, Response, Transport};
use tower::ServiceExt;

use crate::HarnessError;

/// The largest answer the adapter reads: above every page and directory the service builds.
const MAX_ANSWER_BYTES: usize = 256 * 1024 * 1024;

/// The address requests seem to come from: the service's source-based limits count them as
/// one network source (Switch wire 9.4).
const PEER: ([u8; 4], u16) = ([127, 0, 0, 1], 4000);

/// The address every relay host resolves to at the service: a public one, as a relay URL
/// must resolve only to public addresses (Switch wire 8.1, 8.2), and the documentation
/// ranges aren't public there. Nothing connects to it: no world runs the service's webhook
/// delivery, and a flow that delivered would have to route it in process through
/// `Service::with_relay_route`.
const RELAY_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14));

/// A resolver that answers [`RELAY_ADDRESS`] for every host, so a flow's relay URL needs no
/// DNS name.
fn relay_resolver() -> Resolver {
    Arc::new(|_host: String| Box::pin(async { Ok(vec![RELAY_ADDRESS]) }))
}

/// The service's clock, read from the test clock the client and the signer use, so one clock
/// moves every party.
struct SharedClock {
    clock: Arc<TestClock>,
    start_ms: u64,
}

impl ServiceClock for SharedClock {
    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    fn monotonic_ms(&self) -> u64 {
        self.clock.now_ms().saturating_sub(self.start_ms)
    }
}

/// Whether a test database is configured: `false` when the service's half of a test is to be
/// skipped, as the service's own tests are (see [`pubky_switch::store::testing`]).
///
/// # Errors
///
/// When a test database is required and not configured.
pub fn database_configured() -> Result<bool, HarnessError> {
    if std::env::var(TEST_DATABASE_URL_ENV).is_ok_and(|url| !url.is_empty()) {
        return Ok(true);
    }
    if std::env::var_os(REQUIRE_DB_ENV).is_some() {
        return Err(HarnessError::Setup(format!(
            "{REQUIRE_DB_ENV} is set, but {TEST_DATABASE_URL_ENV} is not"
        )));
    }
    Ok(false)
}

/// A [`Transport`] to a service in this process.
#[derive(Clone)]
pub struct ServiceTransport {
    origin: String,
    router: axum::Router,
}

impl std::fmt::Debug for ServiceTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServiceTransport({})", self.origin)
    }
}

impl ServiceTransport {
    /// A transport to `service`, which serves `origin`.
    pub fn new(origin: &str, service: Service) -> Self {
        let router = pubky_switch::http::router(Arc::new(service), ProxyConfig::default())
            .layer(MockConnectInfo(SocketAddr::from(PEER)));
        Self {
            origin: origin.to_owned(),
            router,
        }
    }

    async fn carry(&self, request: Request) -> Result<Response, TransportError> {
        if request.origin != self.origin {
            return Err(TransportError::Connect(format!(
                "no service at {}",
                request.origin
            )));
        }
        let invalid = |error: axum::http::Error| TransportError::InvalidRequest(error.to_string());
        let mut builder = HttpRequest::builder()
            .method(request.method.as_str())
            .uri(request.path_and_query.as_str())
            .header(header::CONTENT_LENGTH, request.body.len());
        for Header { name, value } in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let request = builder.body(Body::from(request.body)).map_err(invalid)?;
        let answer = match self.router.clone().oneshot(request).await {
            Ok(answer) => answer,
            Err(never) => match never {},
        };
        let status = answer.status().as_u16();
        let mut headers = Vec::with_capacity(answer.headers().len());
        for (name, value) in answer.headers() {
            let value = value
                .to_str()
                .map_err(|_| TransportError::Other("an answer header that isn't text".into()))?;
            headers.push(Header::new(name.as_str(), value));
        }
        let body = axum::body::to_bytes(answer.into_body(), MAX_ANSWER_BYTES)
            .await
            .map_err(|error| TransportError::Other(error.to_string()))?;
        Ok(Response {
            status,
            headers,
            body: body.to_vec(),
        })
    }
}

impl Transport for ServiceTransport {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        Box::pin(self.carry(request))
    }
}

/// A service at one origin, on its own test database, with the keys and the clock a test
/// gives it.
pub struct RealSwitch {
    origin: String,
    /// The test database, until it is dropped.
    database: Option<TestDatabase>,
    time: Arc<TrustedTime>,
    clock: Arc<SharedClock>,
    transport: Arc<ServiceTransport>,
    /// The task that forwards the database's change notifications to the service, which
    /// wake its waiting feed reads (Switch wire 7.4.4), as the service's own `main` runs it.
    listening: Option<tokio::task::JoinHandle<()>>,
    /// The service's hub of waiting feed reads.
    changes: Arc<ChangeHub>,
    _key_dir: tempfile::TempDir,
}

impl std::fmt::Debug for RealSwitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RealSwitch({}, {})", self.origin, self.database_name())
    }
}

impl RealSwitch {
    /// A service at `origin` on a fresh test database, or `None` when no test database is
    /// configured and the test is to be skipped (see [`pubky_switch::store::testing`]).
    ///
    /// Its accounts take `service_secrets` as their service keys, in order, then random
    /// ones; answers it can't tie to an account are signed with `operator_secret`. It
    /// requires trusted time, as in production, and holds a sample taken from `clock`.
    ///
    /// # Errors
    ///
    /// When the key store can't be made, or the change listener can't connect.
    pub async fn start(
        origin: &str,
        clock: Arc<TestClock>,
        service_secrets: Vec<[u8; 32]>,
        operator_secret: [u8; 32],
        limits: Limits,
    ) -> Result<Option<Self>, HarnessError> {
        let Some(database) = test_database().await else {
            return Ok(None);
        };
        let key_dir =
            tempfile::tempdir().map_err(|error| HarnessError::Setup(error.to_string()))?;
        let store = FileKeyStore::open(key_dir.path())
            .map_err(|error| HarnessError::Setup(error.to_string()))?;
        let keys = Arc::new(FixedKeys::new(
            store,
            service_secrets,
            Some(operator_secret),
        ));
        let start_ms = clock.now_ms();
        let clock = Arc::new(SharedClock { clock, start_ms });
        let time = Arc::new(TrustedTime::new(
            TrustedTimeConfig::default(),
            clock.clone(),
        ));
        let service = Service::new(
            origin.to_owned(),
            database.store().clone(),
            keys,
            time.clone(),
            limits,
        )
        .with_resolver(relay_resolver());
        let listener = ChangeListener::connect(database.store())
            .await
            .map_err(|error| HarnessError::Setup(error.to_string()))?;
        let changes = service.changes();
        let listening = tokio::spawn(listener.run(changes.clone(), std::future::pending()));
        let switch = Self {
            origin: origin.to_owned(),
            database: Some(database),
            time,
            clock,
            transport: Arc::new(ServiceTransport::new(origin, service)),
            listening: Some(listening),
            changes,
            _key_dir: key_dir,
        };
        switch.sample_time();
        Ok(Some(switch))
    }

    /// The origin it serves.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The transport to it.
    pub fn transport(&self) -> Arc<ServiceTransport> {
        self.transport.clone()
    }

    /// Give the service a time sample that agrees with the clock, as its time source would
    /// (Switch spec 10.1). Call it after moving the clock, so the sample never gets too old.
    pub fn sample_time(&self) {
        self.time.note(
            TimeSample {
                utc_ms: self.clock.now_ms(),
                uncertainty_ms: 0,
            },
            self.clock.monotonic_ms(),
        );
    }

    /// How many accounts have a feed read held at the service now, waiting for a change
    /// (Switch wire 7.4.4 `wait`). A read counts from before its first look at the account,
    /// so a change made once it counts is one the read sees.
    pub fn held_reads(&self) -> usize {
        self.changes.waiting()
    }

    /// Close the service's connections to its database, as a server that takes no more:
    /// every later request fails in the service's storage. For a test of how that shows.
    pub async fn close_connections(&self) {
        if let Some(store) = self.store() {
            store.close().await;
        }
    }

    /// The service's store; `None` once its database is dropped.
    pub(crate) fn store(&self) -> Option<Store> {
        self.database
            .as_ref()
            .map(|database| database.store().clone())
    }

    /// The test database's name; empty once it is dropped.
    pub fn database_name(&self) -> &str {
        self.database.as_ref().map_or("", TestDatabase::name)
    }

    /// Drop the test database, and wait until it is gone. A switch that goes away without
    /// this, as when its test panics, still drops its database: the test database drops
    /// itself ([`pubky_switch::store::testing::TestDatabase`]).
    ///
    /// # Errors
    ///
    /// When the server refuses.
    pub async fn close(mut self) -> Result<(), HarnessError> {
        // The listener goes first: left running, it would try to connect to a database
        // that is gone.
        if let Some(listening) = self.listening.take() {
            listening.abort();
            // Its end, aborted or not, is all this waits for.
            let _ = listening.await;
        }
        match self.database.take() {
            Some(database) => database
                .drop_database()
                .await
                .map_err(|error| HarnessError::Setup(error.to_string())),
            None => Ok(()),
        }
    }
}

impl Drop for RealSwitch {
    fn drop(&mut self) {
        // A switch dropped without `close`, as when its test panics: the listener stops
        // with it.
        if let Some(listening) = self.listening.take() {
            listening.abort();
        }
    }
}
