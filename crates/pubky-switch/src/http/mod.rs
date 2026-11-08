//! The HTTP API's transport (Switch wire 7).
//!
//! This module carries requests between the network and the service: it routes each
//! request (Switch wire 7.4), refuses a body over its call's cap before reading it
//! (Switch wire 7.1), finds the request's network source (Switch wire 7.2), and hands the
//! request to a [`Handler`], which runs the processing order of Switch wire 7.3 and signs
//! every answer. The method, path and query reach the handler exactly as sent, since the
//! request signature covers them.

pub mod error;
pub mod route;
pub mod source;

use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc, time::Instant};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use self::{
    route::Route,
    source::{NetworkSource, ProxyConfig},
};

/// The API listener's settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// The switch origin, exactly as `identity.json` names it in `inbox.url`, such as
    /// `https://switch.example`. Requests sign it (Switch wire 7.1). Required to serve.
    pub origin: Option<String>,
    /// Address to listen on. TLS is terminated in front of the service.
    pub listen: SocketAddr,
    /// Allow an `http://` origin, for development only.
    pub allow_insecure_origin: bool,
    /// Reverse proxies whose report of the client's address the service believes.
    pub proxy: ProxyConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            origin: None,
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            allow_insecure_origin: false,
            proxy: ProxyConfig::default(),
        }
    }
}

/// A server setting that breaks a rule.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("server.{name}: {reason}")]
pub struct ServerConfigError {
    /// The setting's name.
    pub name: &'static str,
    /// What is wrong with it.
    pub reason: &'static str,
}

impl ServerConfig {
    /// Check the settings.
    pub fn validate(&self) -> Result<(), ServerConfigError> {
        if let Some(origin) = &self.origin {
            check_origin(origin, self.allow_insecure_origin).map_err(|reason| {
                ServerConfigError {
                    name: "origin",
                    reason,
                }
            })?;
        }
        if self.proxy.header.is_empty() || HeaderName::try_from(&self.proxy.header).is_err() {
            return Err(ServerConfigError {
                name: "proxy.header",
                reason: "not a header name",
            });
        }
        Ok(())
    }
}

/// Check a switch origin: `https://` and a host with an optional port, and nothing else
/// (no user info, path, query or fragment), so it is compared byte for byte with the
/// origin `identity.json` names (Switch wire 7.1).
pub fn check_origin(origin: &str, allow_insecure: bool) -> Result<(), &'static str> {
    let authority = match origin.strip_prefix("https://") {
        Some(rest) => rest,
        None if allow_insecure => origin
            .strip_prefix("http://")
            .ok_or("must start with https:// or http://")?,
        None => return Err("must start with https://"),
    };
    if authority.is_empty() {
        return Err("has no host");
    }
    if authority
        .chars()
        .any(|c| matches!(c, '/' | '?' | '#' | '@') || c.is_whitespace() || c.is_control())
    {
        return Err("must be scheme and host only, without a path, query, fragment or user");
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !authority.ends_with(']') => {
            port.parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or("has an invalid port")?;
            host
        }
        _ => authority,
    };
    if host.is_empty() {
        return Err("has no host");
    }
    if host.chars().any(|c| c.is_ascii_uppercase()) {
        return Err("must be lower case");
    }
    Ok(())
}

/// A routed request, for the [`Handler`].
#[derive(Debug)]
pub struct SwitchRequest {
    /// The route.
    pub route: Route,
    /// The method, upper case.
    pub method: String,
    /// The path and query exactly as sent.
    pub path_and_query: String,
    /// The headers.
    pub headers: HeaderMap,
    /// The body, within its call's cap.
    pub body: Bytes,
    /// The network source; `None` when the service can't tell it.
    pub source: Option<NetworkSource>,
}

/// An answer from the [`Handler`].
#[derive(Debug, Default)]
pub struct SwitchResponse {
    /// The HTTP status.
    pub status: u16,
    /// Headers, such as `Switch-Service-Signature`, `Switch-Server-Time` and `Switch-Head`.
    /// `Content-Type: application/json` is added when absent.
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// The body.
    pub body: Vec<u8>,
}

/// A request the transport refuses before the handler runs it. The handler still answers
/// it, so that the answer is signed like every other.
#[derive(Debug)]
pub enum Refusal {
    /// No such route: `404`, signed with the operator key (Switch wire 7.3 step 1).
    UnknownRoute {
        /// The request's signature header, if any, which the answer's signature covers.
        headers: HeaderMap,
    },
    /// A body over its call's cap: `413 too_large`, before the body is read (Switch wire 7.1).
    TooLarge {
        /// The route, if the request had one.
        route: Option<Route>,
        /// The request's headers.
        headers: HeaderMap,
        /// The cap.
        cap: u64,
    },
}

/// A future returned by a [`Handler`].
pub type HandlerFuture<'a> = Pin<Box<dyn Future<Output = SwitchResponse> + Send + 'a>>;

/// The service behind the transport: it runs a request's processing order and signs every
/// answer.
pub trait Handler: Send + Sync + 'static {
    /// Answer a routed request.
    fn handle(&self, request: SwitchRequest) -> HandlerFuture<'_>;

    /// Answer a request the transport refused.
    fn refuse(&self, refusal: Refusal) -> HandlerFuture<'_>;
}

#[derive(Clone)]
struct Shared {
    handler: Arc<dyn Handler>,
    proxy: Arc<ProxyConfig>,
}

/// The API's routes, all through `handler`. Serve it with
/// `into_make_service_with_connect_info::<SocketAddr>()`, since each request needs its peer
/// address.
pub fn router(handler: Arc<dyn Handler>, proxy: ProxyConfig) -> Router {
    Router::new().fallback(dispatch).with_state(Shared {
        handler,
        proxy: Arc::new(proxy),
    })
}

async fn dispatch(
    State(shared): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
) -> Response {
    let started = Instant::now();
    let (parts, body) = request.into_parts();
    let method = parts.method.as_str().to_string();
    let path_and_query = parts.uri.path_and_query().map_or_else(
        || parts.uri.path().to_string(),
        |pq| pq.as_str().to_string(),
    );
    let routed = route::route(&method, &path_and_query);
    let call = routed.as_ref().map_or("unknown", |route| route.call.name());
    let cap = route::body_cap(&method, &path_and_query, routed.as_ref());

    let declared = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let answer = if declared.is_some_and(|length| length > cap) {
        shared
            .handler
            .refuse(Refusal::TooLarge {
                route: routed,
                headers: parts.headers,
                cap,
            })
            .await
    } else {
        let limit = usize::try_from(cap).unwrap_or(usize::MAX);
        match axum::body::to_bytes(body, limit).await {
            Err(_) => {
                shared
                    .handler
                    .refuse(Refusal::TooLarge {
                        route: routed,
                        headers: parts.headers,
                        cap,
                    })
                    .await
            }
            Ok(body) => match routed {
                None => {
                    shared
                        .handler
                        .refuse(Refusal::UnknownRoute {
                            headers: parts.headers,
                        })
                        .await
                }
                Some(route) => {
                    let client = shared.proxy.client_ip(peer.ip(), &parts.headers);
                    shared
                        .handler
                        .handle(SwitchRequest {
                            route,
                            method,
                            path_and_query,
                            headers: parts.headers,
                            body,
                            source: Some(NetworkSource::of(client)),
                        })
                        .await
                }
            },
        }
    };

    let status = StatusCode::from_u16(answer.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    metrics::counter!(
        "pubky_switch_http_requests_total",
        "call" => call,
        "status" => status.as_str().to_string()
    )
    .increment(1);
    metrics::histogram!("pubky_switch_http_request_seconds", "call" => call)
        .record(started.elapsed().as_secs_f64());
    tracing::debug!(call, status = status.as_u16(), "request");
    to_response(status, answer)
}

fn to_response(status: StatusCode, answer: SwitchResponse) -> Response {
    let mut response = (status, Body::from(answer.body)).into_response();
    let headers = response.headers_mut();
    for (name, value) in answer.headers {
        headers.append(name, value);
    }
    headers
        .entry(header::CONTENT_TYPE)
        .or_insert(HeaderValue::from_static("application/json"));
    response
}

/// Serve `router` on `listener` until `shutdown` resolves, with each connection's peer
/// address.
pub async fn serve(
    listener: tokio::net::TcpListener,
    router: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    // Small JSON answers: no Nagle delay.
    let listener = axum::serve::ListenerExt::tap_io(listener, |tcp| {
        if let Err(error) = tcp.set_nodelay(true) {
            tracing::debug!(%error, "TCP_NODELAY");
        }
    });
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{error::ApiError, route::Call};
    use axum::{body::to_bytes, extract::connect_info::MockConnectInfo, http::Request};
    use parking_lot::Mutex;
    use std::net::{IpAddr, Ipv4Addr};
    use tower::ServiceExt;

    /// A handled request: its call, path and query, body length and source.
    type Handled = (Call, String, usize, Option<NetworkSource>);

    #[derive(Default)]
    struct Recorder {
        handled: Mutex<Vec<Handled>>,
        refused: Mutex<Vec<String>>,
    }

    impl Handler for Recorder {
        fn handle(&self, request: SwitchRequest) -> HandlerFuture<'_> {
            self.handled.lock().push((
                request.route.call.clone(),
                request.path_and_query.clone(),
                request.body.len(),
                request.source,
            ));
            Box::pin(async move {
                SwitchResponse {
                    status: 200,
                    headers: vec![(
                        HeaderName::from_static("switch-server-time"),
                        HeaderValue::from_static("2026-01-01T00:00:00.000Z"),
                    )],
                    body: b"{}".to_vec(),
                }
            })
        }

        fn refuse(&self, refusal: Refusal) -> HandlerFuture<'_> {
            let error = match &refusal {
                Refusal::UnknownRoute { .. } => ApiError::not_found("7.3: no such route"),
                Refusal::TooLarge { cap, .. } => ApiError::body_too_large(*cap),
            };
            self.refused.lock().push(error.code.as_str().to_string());
            Box::pin(async move {
                SwitchResponse {
                    status: error.status(),
                    headers: Vec::new(),
                    body: error.body(),
                }
            })
        }
    }

    fn app(recorder: Arc<Recorder>, proxy: ProxyConfig, peer: [u8; 4]) -> Router {
        router(recorder, proxy).layer(MockConnectInfo(SocketAddr::from((peer, 4000))))
    }

    async fn send(router: Router, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let response = router.oneshot(request).await.expect("response");
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), 1 << 20).await.expect("body");
        (status, headers, body.to_vec())
    }

    #[tokio::test]
    async fn test_http_hands_the_request_to_the_handler() {
        let recorder = Arc::new(Recorder::default());
        let request = Request::post("/v1/abc/ops?x=%41")
            .body(Body::from(vec![b'{'; 100]))
            .expect("request");
        let (status, headers, body) = send(
            app(recorder.clone(), ProxyConfig::default(), [203, 0, 113, 9]),
            request,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"{}");
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(headers["switch-server-time"], "2026-01-01T00:00:00.000Z");
        let handled = recorder.handled.lock();
        assert_eq!(handled.len(), 1);
        let (call, path, length, source) = &handled[0];
        assert_eq!(*call, Call::Ops);
        // The path and query reach the handler exactly as sent.
        assert_eq!(path, "/v1/abc/ops?x=%41");
        assert_eq!(*length, 100);
        assert_eq!(
            *source,
            Some(NetworkSource::V4(Ipv4Addr::new(203, 0, 113, 9)))
        );
    }

    #[tokio::test]
    async fn test_http_unknown_route_is_refused() {
        let recorder = Arc::new(Recorder::default());
        let request = Request::get("/v1/abc/nowhere")
            .body(Body::empty())
            .expect("request");
        let (status, _, body) = send(
            app(recorder.clone(), ProxyConfig::default(), [127, 0, 0, 1]),
            request,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(body["code"], "not_found");
        assert!(recorder.handled.lock().is_empty());
    }

    #[tokio::test]
    async fn test_http_declared_length_over_cap_is_refused_unread() {
        let recorder = Arc::new(Recorder::default());
        let request = Request::post("/v1/abc/inbox")
            .header(header::CONTENT_LENGTH, "65537")
            .body(Body::from(vec![0u8; 65_537]))
            .expect("request");
        let (status, _, body) = send(
            app(recorder.clone(), ProxyConfig::default(), [127, 0, 0, 1]),
            request,
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(body["code"], "too_large");
        assert!(recorder.handled.lock().is_empty());
    }

    #[tokio::test]
    async fn test_http_streamed_body_over_cap_is_refused() {
        let recorder = Arc::new(Recorder::default());
        let chunks = vec![
            Ok::<_, std::io::Error>(Bytes::from(vec![0u8; 40_000])),
            Ok(Bytes::from(vec![0u8; 40_000])),
        ];
        let request = Request::post("/v1/abc/inbox")
            .body(Body::from_stream(futures_util::stream::iter(chunks)))
            .expect("request");
        let (status, _, _) = send(
            app(recorder.clone(), ProxyConfig::default(), [127, 0, 0, 1]),
            request,
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(recorder.handled.lock().is_empty());
    }

    #[tokio::test]
    async fn test_http_body_at_cap_is_taken() {
        let recorder = Arc::new(Recorder::default());
        let request = Request::post("/v1/abc/inbox")
            .body(Body::from(vec![0u8; 65_536]))
            .expect("request");
        let (status, _, _) = send(
            app(recorder.clone(), ProxyConfig::default(), [127, 0, 0, 1]),
            request,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(recorder.handled.lock()[0].2, 65_536);
    }

    #[tokio::test]
    async fn test_http_get_with_a_body_is_refused() {
        let recorder = Arc::new(Recorder::default());
        let request = Request::get("/v1/abc/feed")
            .body(Body::from("x"))
            .expect("request");
        let (status, _, _) = send(
            app(recorder.clone(), ProxyConfig::default(), [127, 0, 0, 1]),
            request,
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_http_source_from_trusted_proxy() {
        let recorder = Arc::new(Recorder::default());
        let proxy = ProxyConfig {
            trusted: vec!["10.0.0.0/8".parse().expect("net")],
            ..ProxyConfig::default()
        };
        let request = Request::get("/v1/abc/feed")
            .header("x-forwarded-for", "192.0.2.1, 198.51.100.7")
            .body(Body::empty())
            .expect("request");
        send(app(recorder.clone(), proxy, [10, 0, 0, 2]), request).await;
        let source = recorder.handled.lock()[0].3;
        assert_eq!(
            source,
            Some(NetworkSource::of(IpAddr::V4(Ipv4Addr::new(
                198, 51, 100, 7
            ))))
        );
    }

    #[test]
    fn test_server_origin_rules() {
        for good in [
            "https://switch.example",
            "https://switch.example:8443",
            "https://[2001:db8::1]",
            "https://[2001:db8::1]:8443",
        ] {
            assert_eq!(check_origin(good, false), Ok(()), "{good}");
        }
        assert_eq!(check_origin("http://127.0.0.1:8080", true), Ok(()));
        for bad in [
            "http://switch.example",
            "switch.example",
            "https://",
            "https://switch.example/",
            "https://switch.example/v1",
            "https://switch.example?x",
            "https://switch.example#x",
            "https://user@switch.example",
            "https://switch.example:0",
            "https://switch.example:99999",
            "https://Switch.example",
            "https://:443",
        ] {
            assert!(check_origin(bad, false).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_server_config_validation() {
        assert_eq!(ServerConfig::default().validate(), Ok(()));
        let config = ServerConfig {
            origin: Some("http://localhost:8080".into()),
            ..ServerConfig::default()
        };
        assert_eq!(config.validate().expect_err("insecure").name, "origin");
        let config = ServerConfig {
            allow_insecure_origin: true,
            ..config
        };
        assert_eq!(config.validate(), Ok(()));
        let config = ServerConfig {
            proxy: ProxyConfig {
                header: "bad header".into(),
                ..ProxyConfig::default()
            },
            ..ServerConfig::default()
        };
        assert_eq!(config.validate().expect_err("header").name, "proxy.header");
    }
}
