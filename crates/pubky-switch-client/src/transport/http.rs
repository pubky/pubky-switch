//! The HTTPS transport on reqwest and rustls (`http` feature).
//!
//! A switch origin comes from an `identity.json` someone else controls, so the transport
//! connects only where Switch wire 7.1 allows: `https`, no user info, path, query or
//! fragment, port 443 or a port the operator allows, an address literal that is public, and a
//! host name every address of which is public (Switch wire 8.2). The host is judged as
//! reqwest's URL parser reads it, since that is where it connects; a host the parser reads
//! as another one, such as `127.1`, is refused. The resolver refuses a host with any address
//! that isn't public and hands the connector only the addresses it checked, at every new
//! connection, so DNS rebinding can't move a connection to a private address. Redirects
//! aren't followed.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use pubky_switch_core::net::{UrlUse, check_addresses, check_url};
use reqwest::header::{HeaderName, HeaderValue};

use super::{BoxFuture, Header, Request, Response, TimeoutClass, Transport, TransportError};

/// The settings of an [`HttpTransport`].
///
/// Each call has a timeout for the whole of it, from connecting to the last byte of the
/// answer, by the class the client picked for it ([`TimeoutClass`], Switch wire 7.1 "Answer
/// sizes"):
///
/// - **[`TimeoutClass::Ordinary`]:** [`HttpConfig::request_timeout_ms`], and a share of what
///   the long timeout adds to it, in proportion to the request body: about the short timeout
///   for a body of a few KiB, the long one from a mebibyte on. So a slow uplink that sends a
///   mebibyte within the long timeout's extra time sends every smaller body too.
/// - **[`TimeoutClass::Bulk`]:** [`HttpConfig::long_timeout_ms`]. A batch of operations that
///   writes a shared record is one, whatever its size: its `409 conflict` carries the
///   record's view, up to about 950 KB, and a batch kept for a resend meets the same answer
///   every time, so the short timeout would hold it, and the writes behind it, on a slow
///   downlink.
/// - **[`TimeoutClass::LongPoll`]:** the wait the request names, then
///   [`HttpConfig::long_timeout_ms`] for the page.
///
/// At the limits some bulk calls carry tens of megabytes: a host on a slow network raises
/// the settings.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpConfig {
    /// The timeout of a small call, in milliseconds: 10 s by default.
    pub request_timeout_ms: u64,
    /// The timeout of a call that can carry megabytes, and what the feed's long poll has
    /// after its wait, in milliseconds: 40 s by default.
    pub long_timeout_ms: u64,
    /// The connection timeout, in milliseconds.
    pub connect_timeout_ms: u64,
    /// The ports other than 443 a switch origin may use, as the client's operator allows
    /// (Switch wire 7.1).
    pub extra_ports: Vec<u16>,
    /// The largest answer body read, in bytes; a larger one fails with
    /// [`TransportError::TooLarge`].
    pub max_response_bytes: u64,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            request_timeout_ms: 10_000,
            long_timeout_ms: 40_000,
            connect_timeout_ms: 10_000,
            extra_ports: Vec::new(),
            max_response_bytes: 32 << 20,
        }
    }
}

/// An address that the resolver refused, named in the error it returns.
#[derive(Debug)]
struct NotPublic(String);

impl std::fmt::Display for NotPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NotPublic {}

/// The resolver of the checked transport: it refuses a host with any address that isn't
/// public (Switch wire 8.2) and returns only the addresses it checked.
struct PublicOnly;

impl reqwest::dns::Resolve for PublicOnly {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let found: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            let ips: Vec<IpAddr> = found.iter().map(SocketAddr::ip).collect();
            check_addresses(&ips).map_err(|error| -> Box<dyn std::error::Error + Send + Sync> {
                Box::new(NotPublic(error.to_string()))
            })?;
            let addrs: reqwest::dns::Addrs = Box::new(found.into_iter());
            Ok(addrs)
        })
    }
}

/// The HTTPS transport.
pub struct HttpTransport {
    client: reqwest::Client,
    /// The origin policy; `None` only for the loopback test constructor.
    origin_use: Option<UrlUse>,
    max_response_bytes: u64,
    request_timeout: Duration,
    long_timeout: Duration,
}

/// The body size from which an ordinary call gets the long timeout.
const LONG_BODY_BYTES: usize = 1 << 20;

/// The timeout of `request` by its class ([`HttpConfig`]): for an ordinary call `short`
/// and the share of `long - short` its body is of [`LONG_BODY_BYTES`], at most `long`; for
/// a bulk call `long`; for a long poll its wait, then `long`.
fn call_timeout(request: &Request, short: Duration, long: Duration) -> Duration {
    match request.timeout {
        TimeoutClass::Ordinary => {
            let extra = long.saturating_sub(short).as_millis() * request.body.len() as u128
                / LONG_BODY_BYTES as u128;
            short
                .saturating_add(Duration::from_millis(
                    u64::try_from(extra).unwrap_or(u64::MAX),
                ))
                .min(long.max(short))
        }
        TimeoutClass::Bulk => long,
        TimeoutClass::LongPoll { wait_s } => {
            long.saturating_add(Duration::from_secs(u64::from(wait_s)))
        }
    }
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport")
            .field("checks_origins", &self.origin_use.is_some())
            .finish()
    }
}

fn builder(config: &HttpConfig) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .use_rustls_tls()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
        .tcp_nodelay(true)
}

fn built(builder: reqwest::ClientBuilder) -> Result<reqwest::Client, TransportError> {
    builder
        .build()
        .map_err(|error| TransportError::Other(error.without_url().to_string()))
}

impl HttpTransport {
    /// A transport for switch origins read from `identity.json` documents (Switch wire 7.1):
    /// every origin is checked before anything is sent, every host name is resolved by a
    /// resolver that refuses any address that isn't public, and redirects aren't followed.
    /// Proxies from the environment aren't used.
    ///
    /// # Errors
    ///
    /// [`TransportError::Other`] if the HTTP client can't be built.
    pub fn new(config: HttpConfig) -> Result<Self, TransportError> {
        let client = built(
            builder(&config)
                .https_only(true)
                .dns_resolver(Arc::new(PublicOnly)),
        )?;
        Ok(Self {
            client,
            origin_use: Some(UrlUse::SwitchOrigin {
                extra_ports: config.extra_ports.clone(),
            }),
            max_response_bytes: config.max_response_bytes,
            request_timeout: Duration::from_millis(config.request_timeout_ms),
            long_timeout: Duration::from_millis(config.long_timeout_ms),
        })
    }

    /// A transport that checks no origin and no address, and allows plain `http`, for test
    /// runs against a switch on loopback only. Never use it for an origin read from an
    /// `identity.json`: it would connect to private addresses (Switch wire 7.1).
    ///
    /// # Errors
    ///
    /// [`TransportError::Other`] if the HTTP client can't be built.
    pub fn without_address_checks_for_loopback_tests(
        config: HttpConfig,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            client: built(builder(&config))?,
            origin_use: None,
            max_response_bytes: config.max_response_bytes,
            request_timeout: Duration::from_millis(config.request_timeout_ms),
            long_timeout: Duration::from_millis(config.long_timeout_ms),
        })
    }

    async fn call(&self, request: Request) -> Result<Response, TransportError> {
        if !request.path_and_query.starts_with('/') {
            return Err(TransportError::InvalidRequest(
                "the path doesn't start with '/'".into(),
            ));
        }
        let url = match &self.origin_use {
            Some(origin_use) => checked_destination(&request.origin, &request.url(), origin_use)?,
            None => reqwest::Url::parse(&request.url())
                .map_err(|_| TransportError::InvalidRequest("the URL doesn't parse".into()))?,
        };
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|_| TransportError::InvalidRequest("the method".into()))?;
        let timeout = call_timeout(&request, self.request_timeout, self.long_timeout);
        let mut call = self.client.request(method, url).timeout(timeout);
        for Header { name, value } in &request.headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| TransportError::InvalidRequest("a header name".into()))?;
            let value = HeaderValue::from_str(value)
                .map_err(|_| TransportError::InvalidRequest("a header value".into()))?;
            call = call.header(name, value);
        }
        if !request.body.is_empty() {
            call = call.body(request.body);
        }
        let mut response = call.send().await.map_err(map_error)?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                Some(Header {
                    name: name.as_str().to_owned(),
                    value: value.to_str().ok()?.to_owned(),
                })
            })
            .collect();
        if response
            .content_length()
            .is_some_and(|len| len > self.max_response_bytes)
        {
            return Err(TransportError::TooLarge(self.max_response_bytes));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(map_error)? {
            let len = u64::try_from(body.len().saturating_add(chunk.len())).unwrap_or(u64::MAX);
            if len > self.max_response_bytes {
                return Err(TransportError::TooLarge(self.max_response_bytes));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}

/// The URL a request goes to, checked (Switch wire 7.1, 8.2): the origin's text passes the
/// core's check, and `url`, as reqwest's parser reads it, names the same scheme, host and
/// port, with no user info. reqwest connects to an address literal without the resolver, so
/// the literal is checked here as the parsed URL holds it; a spelling the two parsers read
/// as different hosts is refused.
fn checked_destination(
    origin: &str,
    url: &str,
    origin_use: &UrlUse,
) -> Result<reqwest::Url, TransportError> {
    let refused = |reason: &str| TransportError::Refused(format!("Switch wire 7.1: {reason}"));
    let checked = check_url(origin, origin_use)
        .map_err(|error| TransportError::Refused(error.to_string()))?;
    let url = reqwest::Url::parse(url).map_err(|_| refused("the URL doesn't parse"))?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(refused("the URL isn't https without user info"));
    }
    if url.port_or_known_default() != Some(checked.port) {
        return Err(refused("the URL's port reads differently"));
    }
    let ip = match url.host() {
        Some(url::Host::Domain(name)) if name == checked.host => None,
        Some(url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
        _ => return Err(refused("the URL's host reads differently")),
    };
    if let Some(ip) = ip {
        if checked.host.parse::<IpAddr>().ok() != Some(ip) {
            return Err(refused("the URL's host reads differently"));
        }
        check_addresses(&[ip]).map_err(|error| TransportError::Refused(error.to_string()))?;
    }
    Ok(url)
}

/// A reqwest error as a transport error, without the URL.
fn map_error(error: reqwest::Error) -> TransportError {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(current) = source {
        if let Some(refused) = current.downcast_ref::<NotPublic>() {
            return TransportError::Refused(refused.0.clone());
        }
        source = current.source();
    }
    if error.is_timeout() {
        TransportError::Timeout
    } else if error.is_connect() {
        TransportError::Connect(error.without_url().to_string())
    } else {
        TransportError::Other(error.without_url().to_string())
    }
}

impl Transport for HttpTransport {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        Box::pin(self.call(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(origin: &str) -> Request {
        Request {
            method: "GET".into(),
            origin: origin.into(),
            path_and_query: "/v1/x/directory".into(),
            headers: Vec::new(),
            body: Vec::new(),
            timeout: TimeoutClass::Ordinary,
        }
    }

    #[tokio::test]
    async fn test_http_transport_refuses_origins_that_arent_public() {
        let transport = HttpTransport::new(HttpConfig::default()).unwrap();
        for origin in [
            "http://127.0.0.1:1",
            "https://127.0.0.1",
            "https://[::1]",
            "https://[::ffff:10.0.0.1]",
            "https://[64:ff9b::a9fe:a9fe]",
            "https://inbox.example:6379",
            "https://user@inbox.example",
            "https://inbox.example/path",
            "https://localhost",
        ] {
            let error = transport.send(request(origin)).await.unwrap_err();
            assert!(
                matches!(error, TransportError::Refused(_)),
                "{origin}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_http_transport_refuses_other_spellings_of_private_addresses() {
        let transport = HttpTransport::new(HttpConfig::default()).unwrap();
        for origin in [
            "https://127.1",
            "https://2130706433",
            "https://0x7f000001",
            "https://0177.0.0.1",
            "https://127.0.0.1.",
            "https://localhost.",
            "https://LOCALHOST",
            "https://[::ffff:127.0.0.1]",
            "https://[0:0:0:0:0:0:0:1]",
            "https://[fe80::1%25eth0]",
            "https://127%2E0%2E0%2E1",
        ] {
            let error = transport.send(request(origin)).await.unwrap_err();
            assert!(
                matches!(error, TransportError::Refused(_)),
                "{origin}: {error:?}"
            );
        }
    }

    #[test]
    fn test_http_destination_is_the_parsed_url() {
        let origin = UrlUse::SwitchOrigin {
            extra_ports: vec![8443],
        };
        let check = |origin_text: &str, url: &str| checked_destination(origin_text, url, &origin);
        // The URL reqwest parses names the same host and port as the origin's text.
        assert!(check("https://Inbox.Example", "https://inbox.example/v1").is_ok());
        assert!(
            check(
                "https://inbox.example:8443",
                "https://inbox.example:8443/v1"
            )
            .is_ok()
        );
        assert!(
            check(
                "https://[2606:4700::1111]",
                "https://[2606:4700:0::1111]/v1"
            )
            .is_ok()
        );
        // A URL that reads as another destination than the origin is refused.
        for (origin_text, url) in [
            ("https://inbox.example", "https://other.example/v1"),
            ("https://inbox.example", "https://inbox.example:8443/v1"),
            ("https://inbox.example", "https://127.0.0.1/v1"),
            ("https://1.1.1.1", "https://1.1.1.2/v1"),
            ("https://1.1.1.1", "https://[::ffff:1.1.1.1]/v1"),
            ("https://inbox.example", "https://user@inbox.example/v1"),
            ("https://inbox.example", "http://inbox.example/v1"),
        ] {
            let error = check(origin_text, url).unwrap_err();
            assert!(
                matches!(error, TransportError::Refused(_)),
                "{origin_text} {url}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_http_transport_allows_an_operator_port() {
        let config = HttpConfig {
            extra_ports: vec![8443],
            connect_timeout_ms: 1,
            request_timeout_ms: 1,
            ..HttpConfig::default()
        };
        let transport = HttpTransport::new(config).unwrap();
        // A port the operator allows passes the origin check; the address check still
        // refuses a private literal.
        let error = transport
            .send(request("https://10.0.0.1:8443"))
            .await
            .unwrap_err();
        assert!(matches!(error, TransportError::Refused(_)), "{error:?}");
    }

    #[tokio::test]
    async fn test_http_transport_for_loopback_tests_connects_anywhere() {
        let transport = HttpTransport::without_address_checks_for_loopback_tests(HttpConfig {
            connect_timeout_ms: 2_000,
            ..HttpConfig::default()
        })
        .unwrap();
        // Nothing listens on port 1: the connection fails, but it was tried.
        let error = transport
            .send(request("http://127.0.0.1:1"))
            .await
            .unwrap_err();
        assert!(!matches!(error, TransportError::Refused(_)), "{error:?}");
    }

    fn call(timeout: TimeoutClass, body: usize) -> Request {
        Request {
            method: "POST".into(),
            path_and_query: "/v1/x/ops".into(),
            body: vec![b'x'; body],
            timeout,
            ..request("https://inbox.example")
        }
    }

    #[test]
    fn test_http_timeout_follows_the_class_the_client_picked() {
        let (short, long) = (Duration::from_secs(10), Duration::from_secs(40));
        let timeout = |class, body| call_timeout(&call(class, body), short, long);
        // An ordinary call's timeout grows with its body, from the short to the long one.
        assert_eq!(timeout(TimeoutClass::Ordinary, 0), short);
        assert!(timeout(TimeoutClass::Ordinary, 4 << 10) < Duration::from_millis(10_200));
        assert_eq!(
            timeout(TimeoutClass::Ordinary, LONG_BODY_BYTES / 2),
            Duration::from_secs(25)
        );
        assert_eq!(timeout(TimeoutClass::Ordinary, LONG_BODY_BYTES), long);
        assert_eq!(timeout(TimeoutClass::Ordinary, 4 * LONG_BODY_BYTES), long);
        // A bulk call has the long one whatever it sends: its answer is what is large.
        assert_eq!(timeout(TimeoutClass::Bulk, 0), long);
        assert_eq!(timeout(TimeoutClass::Bulk, LONG_BODY_BYTES), long);
        // A long poll has its wait, then the long one.
        assert_eq!(
            timeout(TimeoutClass::LongPoll { wait_s: 25 }, 0),
            Duration::from_secs(65)
        );
        assert_eq!(timeout(TimeoutClass::LongPoll { wait_s: 0 }, 0), long);
        // The path decides nothing: the same class has the same timeout at any path.
        let feed = Request {
            method: "GET".into(),
            path_and_query: "/v1/x/feed?after=1:2&limit=100&wait=25".into(),
            ..call(TimeoutClass::Ordinary, 0)
        };
        assert_eq!(call_timeout(&feed, short, long), short);
        // A long timeout set below the short one never shortens an ordinary call.
        assert_eq!(
            call_timeout(&call(TimeoutClass::Ordinary, LONG_BODY_BYTES), long, short),
            long
        );
    }

    #[tokio::test]
    async fn test_http_timeout_ends_each_class_at_its_own_time() {
        // A server that takes every connection and never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut open = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                open.push(socket);
            }
        });
        let transport = HttpTransport::without_address_checks_for_loopback_tests(HttpConfig {
            request_timeout_ms: 100,
            long_timeout_ms: 700,
            ..HttpConfig::default()
        })
        .unwrap();
        let timed = |class: TimeoutClass| {
            let request = Request {
                origin: origin.clone(),
                method: "GET".into(),
                path_and_query: "/v1/x/feed?after=1:0&limit=0".into(),
                ..call(class, 0)
            };
            let transport = &transport;
            async move {
                let started = std::time::Instant::now();
                let error = transport.send(request).await.unwrap_err();
                assert!(matches!(error, TransportError::Timeout), "{error:?}");
                started.elapsed()
            }
        };
        // The read of the service time, an ordinary call, ends long before a page would.
        assert!(timed(TimeoutClass::Ordinary).await < Duration::from_millis(600));
        let bulk = timed(TimeoutClass::Bulk).await;
        assert!(bulk >= Duration::from_millis(700), "{bulk:?}");
        assert!(bulk < Duration::from_millis(1_600), "{bulk:?}");
        // A long poll outlasts its wait by the long timeout.
        let poll = timed(TimeoutClass::LongPoll { wait_s: 1 }).await;
        assert!(poll >= Duration::from_millis(1_700), "{poll:?}");
        server.abort();
    }

    #[tokio::test]
    async fn test_http_transport_refuses_a_bad_header() {
        let transport =
            HttpTransport::without_address_checks_for_loopback_tests(HttpConfig::default())
                .unwrap();
        let mut bad = request("http://127.0.0.1:1");
        bad.headers.push(Header::new("switch-identity", "a\nb"));
        assert!(matches!(
            transport.send(bad).await.unwrap_err(),
            TransportError::InvalidRequest(_)
        ));
    }
}
