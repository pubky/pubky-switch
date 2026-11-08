//! The HTTPS transport on reqwest and rustls (`http` feature).
//!
//! A switch origin comes from an `identity.json` someone else controls, so the transport
//! connects only where Switch wire 7.1 allows: `https`, no user info, path, query or
//! fragment, port 443 or a port the operator allows, an address literal that is public, and a
//! host name every address of which is public (Switch wire 8.2). The resolver refuses a host
//! with any address that isn't public and hands the connector only the addresses it checked,
//! at every new connection, so DNS rebinding can't move a connection to a private address.
//! Redirects aren't followed.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use pubky_switch_core::net::{UrlUse, check_addresses, check_url};
use reqwest::header::{HeaderName, HeaderValue};

use super::{BoxFuture, Header, Request, Response, Transport, TransportError};

/// The settings of an [`HttpTransport`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpConfig {
    /// The whole call's timeout, from connecting to the last byte of the answer, in
    /// milliseconds. A long-poll read (`wait` up to 25 s, Switch wire 7.4.4) needs more.
    pub request_timeout_ms: u64,
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
            request_timeout_ms: 40_000,
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
        .timeout(Duration::from_millis(config.request_timeout_ms))
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
                extra_ports: config.extra_ports,
            }),
            max_response_bytes: config.max_response_bytes,
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
        })
    }

    async fn call(&self, request: Request) -> Result<Response, TransportError> {
        if let Some(origin_use) = &self.origin_use {
            check_url(&request.origin, origin_use)
                .map_err(|error| TransportError::Refused(error.to_string()))?;
        }
        if !request.path_and_query.starts_with('/') {
            return Err(TransportError::InvalidRequest(
                "the path doesn't start with '/'".into(),
            ));
        }
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|_| TransportError::InvalidRequest("the method".into()))?;
        let mut call = self.client.request(method, request.url());
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
