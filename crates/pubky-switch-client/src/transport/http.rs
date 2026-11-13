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

use super::{BoxFuture, Header, Request, Response, Transport, TransportError};

/// The settings of an [`HttpTransport`].
///
/// Each call has a timeout for the whole of it, from connecting to the last byte of the
/// answer, sized by what it can carry (Switch wire 7.1 "Answer sizes"). A call whose
/// request or answer can pass a mebibyte gets the long one, [`HttpConfig::long_timeout_ms`]:
/// a feed read, whose long poll holds it up to 25 s and whose page may take 8 MiB (Switch
/// wire 7.4.4), a records listing (7.4.9), the directory (7.4.10), the apps and an app's
/// key bundle parts (7.4.11, 7.4.12), a claim's entries (7.4.8), the admission lists
/// (7.4.6), a batch of operations whose body passes a mebibyte (6.4), an append, whose
/// `409 stale_key` carries the directory (7.6), a recovery upload (7.4.14), the handover
/// (7.4.17), an enrollment (7.4.1), and a move's export and import (10.2 to 10.4). A batch
/// of at most a mebibyte gets [`HttpConfig::request_timeout_ms`] and a share of what the
/// long timeout adds to it, in proportion to its body: about the short timeout for a batch
/// of a few KiB, the long one for a batch of a mebibyte. So a slow uplink that sends a
/// mebibyte within the long timeout's extra time sends every smaller batch too. The share
/// grows with the request body only, not with the answer: a small batch whose answer is a
/// `409 conflict` carrying a large record's view, up to about 950 KB (7.1 "Answer sizes"),
/// gets the short timeout all the same. On a downlink below about 1 Mbit/s such an answer
/// doesn't arrive in time, so the batch stays kept, each resend meets the same conflict
/// and times out the same way, and the writes behind it wait until its answer window ends
/// (`KEPT_BATCH_ANSWER_MS`): a host on such a link raises [`HttpConfig::request_timeout_ms`].
/// Every
/// other call gets [`HttpConfig::request_timeout_ms`], the time sample a write takes first
/// among them: a feed read of one item with no wait. At the limits some long calls carry
/// tens of megabytes: a host on a slow network raises the settings.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpConfig {
    /// The timeout of every call but the long ones, in milliseconds: 10 s by default.
    pub request_timeout_ms: u64,
    /// The timeout of a call that can carry megabytes, the feed's long poll among them, in
    /// milliseconds: 40 s by default, above the longest wait of 25 s.
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

/// The body size past which a batch of operations gets the long timeout.
const LONG_BODY_BYTES: usize = 1 << 20;

/// The timeout of `request` ([`HttpConfig`]): `long` for a long call, `short` for a short
/// one, and for a batch of operations of at most [`LONG_BODY_BYTES`] `short` and the share
/// of `long - short` its body is of [`LONG_BODY_BYTES`].
fn call_timeout(request: &Request, short: Duration, long: Duration) -> Duration {
    if is_long_call(request) {
        return long;
    }
    let path = request
        .path_and_query
        .split_once('?')
        .map_or(request.path_and_query.as_str(), |(path, _)| path);
    let batch = request.method == "POST"
        && path
            .strip_prefix("/v1/")
            .and_then(|rest| rest.split_once('/'))
            .is_some_and(|(_, rest)| rest == "ops");
    if !batch {
        return short;
    }
    let extra = long.saturating_sub(short).as_millis() * request.body.len() as u128
        / LONG_BODY_BYTES as u128;
    short.saturating_add(Duration::from_millis(
        u64::try_from(extra).unwrap_or(u64::MAX),
    ))
}

/// Whether `request` is a call whose request or answer can pass a mebibyte, or the feed's
/// long poll ([`HttpConfig`]): judged by its method, its path after `/v1/{id}/` and, for a
/// feed read, its query.
fn is_long_call(request: &Request) -> bool {
    let (path, query) = request
        .path_and_query
        .split_once('?')
        .unwrap_or((request.path_and_query.as_str(), ""));
    // An enrollment may name thousands of purged App IDs (Switch wire 7.1 "Answer sizes").
    if path == "/v1/enroll" {
        return true;
    }
    let Some(rest) = path
        .strip_prefix("/v1/")
        .and_then(|rest| rest.split_once('/'))
        .map(|(_, rest)| rest)
    else {
        return false;
    };
    match request.method.as_str() {
        // A feed read of one item with no wait, the time sample a write takes first, is
        // short. It reads after the cursor, and its page runs to the end of a batch whose
        // items it starts (Switch wire 7.4.4): while the cursor is behind, at a batch of
        // many items, the page may carry up to about 5 MiB under the short timeout. On a
        // slow link that sample can time out; the write then fails before its own batch
        // is sent, as its error says, until a read moves the cursor on.
        "GET" if rest == "feed" => {
            let mut params = query.split('&');
            params.clone().any(|param| param.starts_with("wait="))
                || !params.any(|param| param == "limit=1")
        }
        "GET" => {
            matches!(
                rest,
                "records" | "directory" | "apps" | "allow" | "handover" | "export"
            ) || rest.starts_with("export/chunks/")
                || rest.starts_with("claims/")
                || (rest.starts_with("apps/") && rest.ends_with("/keys"))
        }
        // A batch's items take up to 5 MiB: one whose body passes a mebibyte is long. A
        // smaller one's answer is its proofs and a head, or a `409 conflict` with one
        // record's view (under 1 MiB), and its timeout grows with its body
        // (`call_timeout`). An append's `409 stale_key` carries the directory,
        // and an import's start its manifest.
        "POST" if rest == "ops" => request.body.len() > LONG_BODY_BYTES,
        "POST" => matches!(rest, "inbox" | "recovery/upload" | "import"),
        "PUT" => rest == "handover" || rest.starts_with("import/chunks/"),
        _ => false,
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

    fn call(method: &str, path_and_query: &str) -> Request {
        Request {
            method: method.into(),
            path_and_query: path_and_query.into(),
            ..request("https://inbox.example")
        }
    }

    #[test]
    fn test_http_long_timeout_is_for_the_feed_and_the_large_calls() {
        for (method, path) in [
            ("GET", "/v1/x/feed?after=1:2&limit=100&wait=25"),
            ("GET", "/v1/x/feed?after=1:2&limit=1&wait=25"),
            ("GET", "/v1/x/feed?after=1:2&limit=100"),
            ("GET", "/v1/x/feed?after=1:2&limit=10"),
            ("GET", "/v1/x/feed"),
            ("GET", "/v1/x/records?collection=c&after=k&limit=1000"),
            ("GET", "/v1/x/directory"),
            ("GET", "/v1/x/apps"),
            ("GET", "/v1/x/apps/a/keys"),
            ("GET", "/v1/x/claims/k"),
            ("GET", "/v1/x/allow"),
            ("GET", "/v1/x/handover"),
            ("PUT", "/v1/x/handover"),
            ("POST", "/v1/x/inbox?apps_version=1"),
            ("POST", "/v1/x/recovery/upload"),
            ("POST", "/v1/enroll"),
            ("GET", "/v1/x/export"),
            ("GET", "/v1/x/export/chunks/c1"),
            ("POST", "/v1/x/import"),
            ("PUT", "/v1/x/import/chunks/c1"),
        ] {
            assert!(is_long_call(&call(method, path)), "{method} {path}");
        }
        // Every other call has the short one, the time sample a write takes first included.
        for (method, path) in [
            ("GET", "/v1/x/feed?after=1:2&limit=1"),
            ("GET", "/v1/x/records/k"),
            ("PUT", "/v1/x/identity"),
            ("POST", "/v1/x/apps/a/keys"),
            ("POST", "/v1/x/apps/a/leave"),
            ("POST", "/v1/x/connect"),
            ("POST", "/v1/x/import/activate"),
            ("POST", "/v1/x/feed"),
            ("GET", "/v1/x/feeds"),
            ("GET", "/feed"),
        ] {
            assert!(!is_long_call(&call(method, path)), "{method} {path}");
        }
        // A batch is long only once its body passes a mebibyte.
        let batch = |bytes: usize| Request {
            body: vec![b'x'; bytes],
            ..call("POST", "/v1/x/ops")
        };
        assert!(!is_long_call(&batch(LONG_BODY_BYTES)));
        assert!(is_long_call(&batch(LONG_BODY_BYTES + 1)));
        // A smaller one's timeout grows with its body, from the short to the long one.
        let (short, long) = (Duration::from_secs(10), Duration::from_secs(40));
        let timeout = |request: &Request| call_timeout(request, short, long);
        assert_eq!(timeout(&batch(0)), short);
        assert_eq!(
            timeout(&batch(LONG_BODY_BYTES / 2)),
            Duration::from_secs(25)
        );
        assert_eq!(timeout(&batch(LONG_BODY_BYTES)), long);
        assert_eq!(timeout(&batch(LONG_BODY_BYTES + 1)), long);
        assert!(timeout(&batch(4 << 10)) < Duration::from_millis(10_200));
        let other = Request {
            body: vec![b'x'; LONG_BODY_BYTES / 2],
            ..call("POST", "/v1/x/apps/a/leave")
        };
        assert_eq!(timeout(&other), short);
        // The time sample, as a write sends it.
        let sample = crate::client::answers::FeedQuery {
            after: Some(pubky_switch_core::ops::Position {
                generation: 1,
                seq: 2,
            }),
            limit: Some(1),
            wait: None,
        };
        let path = format!("/v1/x/{}", sample.path());
        assert!(!is_long_call(&call("GET", &path)), "{path}");
    }

    #[tokio::test]
    async fn test_http_short_timeout_ends_a_call_the_long_poll_outlasts() {
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
            long_timeout_ms: 1_500,
            ..HttpConfig::default()
        })
        .unwrap();
        // The time sample a write takes first: a feed read of one item with no wait.
        let started = std::time::Instant::now();
        let error = transport
            .send(Request {
                origin: origin.clone(),
                ..call("GET", "/v1/x/feed?after=1:0&limit=1")
            })
            .await
            .unwrap_err();
        assert!(matches!(error, TransportError::Timeout), "{error:?}");
        assert!(started.elapsed() < Duration::from_millis(1_000));
        let started = std::time::Instant::now();
        let error = transport
            .send(Request {
                origin: origin.clone(),
                ..call("GET", "/v1/x/feed?after=1:0&limit=1&wait=25")
            })
            .await
            .unwrap_err();
        assert!(matches!(error, TransportError::Timeout), "{error:?}");
        assert!(started.elapsed() >= Duration::from_millis(1_500));
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
