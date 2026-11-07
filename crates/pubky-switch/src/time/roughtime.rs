//! Roughtime (RFC 10049): an authenticated time source for trusted time (Switch spec 10.1).
//!
//! The service asks several Roughtime servers at once. Each answer is checked in full
//! before it counts: its version is one the request offered, its nonce is the request's,
//! the server's long-term key signed the delegation, the delegated key signed the answer,
//! the answer's Merkle path leads from the request to the signed root, and the midpoint
//! lies within the delegation's validity. Each checked answer says true time lies in
//! `[MIDP - RADI, MIDP + RADI]`. The sample is the window where at least `min_agreeing`
//! of those intervals overlap (Marzullo's algorithm), so a minority of wrong or hostile
//! servers can't move it outside what the others vouch for.
//!
//! The wire format comes from `roughenough-protocol`; the checks are this module's.
//! Servers built to the drafts before the RFC (version `0x8000000c`) are answered too,
//! with their own signature contexts.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use roughenough_protocol::{
    FromFrame, ToFrame,
    cursor::ParseCursor,
    header::find_value_range,
    request::{MAX_RESPONSE_SIZE, Request},
    response::Response,
    tag::Tag,
    tags::{Nonce, ProtocolVersion, SrvCommitment},
    wire::FRAME_OVERHEAD,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use parking_lot::Mutex;

use super::{Clock, SampleFuture, SystemClock, TimeSample, TimeSource, TimeSourceError};

/// The versions every request offers, in ascending wire order (RFC 10049 5.1.1).
const OFFERED: [ProtocolVersion; 2] = [ProtocolVersion::RFC, ProtocolVersion::DRAFT];

/// Signature contexts of RFC 10049 (5.2.1, 5.2.6).
const RFC_SREP_CONTEXT: &[u8] = b"Roughtime v1 response signature\x00";
const RFC_DELE_CONTEXT: &[u8] = b"Roughtime v1 delegation signature\x00";
/// Signature contexts of the drafts before the RFC, version `0x8000000c`.
const DRAFT_SREP_CONTEXT: &[u8] = b"RoughTime v1 response signature\x00";
const DRAFT_DELE_CONTEXT: &[u8] = b"RoughTime v1 delegation signature\x00";

/// Merkle tree prefixes (RFC 10049 5.3), and the SRV commitment's (5.1.4).
const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;
const SRV_PREFIX: u8 = 0xff;

/// The Roughtime settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoughtimeConfig {
    /// The servers to ask. Empty: no Roughtime source.
    pub servers: Vec<RoughtimeServerConfig>,
    /// How many checked answers must agree for a sample.
    pub min_agreeing: usize,
    /// How long to wait for one server's answer.
    pub timeout_ms: u64,
    /// How many times to ask one server within one sample.
    pub attempts: u32,
    /// How long a server may keep failing, its answers refused or missing, before the
    /// service alerts its operator. A refused answer often means the server rotated its
    /// long-term key, and its pinned key needs updating before agreement is lost.
    pub alert_after_ms: u64,
}

/// One Roughtime server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoughtimeServerConfig {
    /// A name for logs and metrics.
    pub name: String,
    /// `host:port`, reached over UDP.
    pub address: String,
    /// The server's long-term Ed25519 public key, in base64.
    pub public_key: String,
}

impl Default for RoughtimeConfig {
    fn default() -> Self {
        let server = |name: &str, address: &str, public_key: &str| RoughtimeServerConfig {
            name: name.into(),
            address: address.into(),
            public_key: public_key.into(),
        };
        Self {
            servers: vec![
                server(
                    "int08h",
                    "roughtime.int08h.com:2002",
                    "AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=",
                ),
                server(
                    "roughtime.se",
                    "roughtime.se:2002",
                    "S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI=",
                ),
                server(
                    "txryan",
                    "time.txryan.com:2002",
                    "iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=",
                ),
            ],
            min_agreeing: 2,
            timeout_ms: 2_000,
            attempts: 2,
            alert_after_ms: 3_600_000,
        }
    }
}

/// The most attempts per server per sample.
const MAX_ATTEMPTS: u32 = 5;

impl RoughtimeConfig {
    /// Check the settings. Returns the setting's name and what is wrong with it.
    pub fn validate(&self) -> Result<(), (&'static str, &'static str)> {
        if self.servers.is_empty() {
            return Ok(());
        }
        if self.min_agreeing == 0 || self.min_agreeing > self.servers.len() {
            return Err((
                "roughtime.min_agreeing",
                "must be at least 1 and at most the number of servers",
            ));
        }
        if self.timeout_ms == 0 {
            return Err(("roughtime.timeout_ms", "must be at least 1"));
        }
        if self.attempts == 0 || self.attempts > MAX_ATTEMPTS {
            return Err(("roughtime.attempts", "must be between 1 and 5"));
        }
        if self.alert_after_ms == 0 {
            return Err(("roughtime.alert_after_ms", "must be at least 1"));
        }
        let mut names = std::collections::BTreeSet::new();
        for server in &self.servers {
            if server.name.is_empty() || !names.insert(server.name.as_str()) {
                return Err(("roughtime.servers.name", "must be set and unique"));
            }
            let port = server
                .address
                .rsplit_once(':')
                .and_then(|(host, port)| (!host.is_empty()).then_some(port))
                .and_then(|port| port.parse::<u16>().ok());
            if port.is_none_or(|port| port == 0) {
                return Err(("roughtime.servers.address", "must be host:port"));
            }
            if parse_public_key(&server.public_key).is_none() {
                return Err((
                    "roughtime.servers.public_key",
                    "must be a base64 Ed25519 public key",
                ));
            }
        }
        Ok(())
    }
}

/// Decode a base64 Ed25519 public key.
fn parse_public_key(text: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = STANDARD.decode(text).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// Why a server gave no usable answer.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RoughtimeError {
    /// The answer doesn't parse, or is over the size an answer may have.
    #[error("malformed answer: {0}")]
    Malformed(String),
    /// The answer's version wasn't offered.
    #[error("version {0:#x} wasn't offered")]
    UnofferedVersion(u32),
    /// The answer names another nonce.
    #[error("the answer is for another nonce")]
    NonceMismatch,
    /// The server's long-term key didn't sign the delegation.
    #[error("the delegation's signature doesn't verify")]
    BadDelegationSignature,
    /// The delegated key didn't sign the answer.
    #[error("the answer's signature doesn't verify")]
    BadResponseSignature,
    /// The delegated key is not a valid Ed25519 key.
    #[error("the delegated key is invalid")]
    BadDelegatedKey,
    /// The midpoint lies outside the delegation's validity.
    #[error("the midpoint lies outside the delegation's validity")]
    OutsideDelegation,
    /// The Merkle path doesn't lead from the request to the signed root.
    #[error("the request isn't in the signed Merkle tree")]
    NotInTree,
    /// No answer in time.
    #[error("no answer in time")]
    Timeout,
    /// The network failed.
    #[error("network: {0}")]
    Network(String),
    /// No randomness for a nonce.
    #[error("no randomness for a nonce")]
    Random,
}

/// How one attempt to ask a server ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// An answer that passed every check.
    Verified,
    /// An answer that arrived and failed a check: a signature, the nonce, the Merkle path,
    /// the delegation's validity, or the format.
    Refused,
    /// No answer in time.
    Timeout,
    /// The server couldn't be reached.
    Unreachable,
    /// The service couldn't make a request.
    Internal,
}

impl Outcome {
    /// The outcome's name in metrics and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Refused => "refused",
            Self::Timeout => "timeout",
            Self::Unreachable => "unreachable",
            Self::Internal => "internal",
        }
    }
}

impl RoughtimeError {
    /// The outcome this error ends an attempt with.
    pub fn outcome(&self) -> Outcome {
        match self {
            Self::Timeout => Outcome::Timeout,
            Self::Network(_) => Outcome::Unreachable,
            Self::Random => Outcome::Internal,
            Self::Malformed(_)
            | Self::UnofferedVersion(_)
            | Self::NonceMismatch
            | Self::BadDelegationSignature
            | Self::BadResponseSignature
            | Self::BadDelegatedKey
            | Self::OutsideDelegation
            | Self::NotInTree => Outcome::Refused,
        }
    }
}

/// The interval a checked answer vouches for, in Unix milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval {
    /// `MIDP - RADI`.
    pub earliest_ms: u64,
    /// `MIDP + RADI`.
    pub latest_ms: u64,
}

/// `SHA-512(parts)[0..32]`, the hash of RFC 10049 5.3.
fn hash32(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// The SRV commitment to a server's long-term key (RFC 10049 5.1.4).
pub fn srv_commitment(server_key: &VerifyingKey) -> [u8; 32] {
    hash32(&[&[SRV_PREFIX], server_key.as_bytes()])
}

/// A request to `server_key`'s server with `nonce`, framed and padded (RFC 10049 5.1).
pub fn build_request(
    nonce: [u8; 32],
    server_key: &VerifyingKey,
) -> Result<Vec<u8>, RoughtimeError> {
    let request = Request::new_with_server_and_versions(
        &Nonce::from(nonce),
        &SrvCommitment::from(srv_commitment(server_key)),
        &OFFERED,
    );
    request
        .as_frame_bytes()
        .map_err(|error| RoughtimeError::Malformed(error.to_string()))
}

/// The Merkle root a path leads to from `request` at `index`, or `None` when the index
/// has bits beyond the path (RFC 10049 5.3).
fn merkle_root<'a>(
    mut index: u32,
    request: &[u8],
    path: impl Iterator<Item = &'a [u8]>,
) -> Option<[u8; 32]> {
    let mut hash = hash32(&[&[LEAF_PREFIX], request]);
    for sibling in path {
        hash = if index & 1 == 0 {
            hash32(&[&[NODE_PREFIX], &hash, sibling])
        } else {
            hash32(&[&[NODE_PREFIX], sibling, &hash])
        };
        index >>= 1;
    }
    (index == 0).then_some(hash)
}

/// Check `response`, the answer of `server_key`'s server to `request` with `nonce`, and
/// return the interval it vouches for (RFC 10049 5.4). Signatures are checked over the
/// bytes as received.
pub fn verify_response(
    server_key: &VerifyingKey,
    nonce: &[u8; 32],
    request: &[u8],
    response: &[u8],
) -> Result<Interval, RoughtimeError> {
    let malformed =
        |error: roughenough_protocol::error::Error| RoughtimeError::Malformed(error.to_string());
    if response.len() > MAX_RESPONSE_SIZE {
        return Err(RoughtimeError::Malformed("over the size limit".into()));
    }
    let mut buffer = response.to_vec();
    let parsed = Response::from_frame(&mut ParseCursor::new(&mut buffer)).map_err(malformed)?;

    let version = *parsed.srep().ver();
    if !OFFERED.contains(&version) {
        return Err(RoughtimeError::UnofferedVersion(version.as_u32()));
    }
    let (srep_context, dele_context) = if version == ProtocolVersion::RFC {
        (RFC_SREP_CONTEXT, RFC_DELE_CONTEXT)
    } else {
        (DRAFT_SREP_CONTEXT, DRAFT_DELE_CONTEXT)
    };
    if parsed.nonc().as_ref() != nonce.as_slice() {
        return Err(RoughtimeError::NonceMismatch);
    }

    // The message as framed: the frame's declared length bounds it, so trailing bytes
    // after the frame can't change what the signatures cover.
    let declared = response
        .get(8..FRAME_OVERHEAD)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
        .and_then(|len| usize::try_from(len).ok())
        .ok_or_else(|| RoughtimeError::Malformed("no frame length".into()))?;
    let message = response
        .get(FRAME_OVERHEAD..FRAME_OVERHEAD.saturating_add(declared))
        .ok_or_else(|| RoughtimeError::Malformed("short frame".into()))?;
    let value = |path: &[Tag]| -> Result<&[u8], RoughtimeError> {
        let range = find_value_range(message, path).map_err(malformed)?;
        message
            .get(range)
            .ok_or_else(|| RoughtimeError::Malformed("tag out of range".into()))
    };

    // The long-term key signed the delegation.
    let dele = value(&[Tag::CERT, Tag::DELE])?;
    let dele_signature = Signature::from_slice(parsed.cert().sig().as_ref())
        .map_err(|_| RoughtimeError::BadDelegationSignature)?;
    server_key
        .verify_strict(&[dele_context, dele].concat(), &dele_signature)
        .map_err(|_| RoughtimeError::BadDelegationSignature)?;

    // The midpoint lies within the delegation's validity.
    let delegation = parsed.cert().dele();
    let midpoint = parsed.srep().midp();
    if midpoint < delegation.mint() || midpoint > delegation.maxt() {
        return Err(RoughtimeError::OutsideDelegation);
    }

    // The request is in the signed tree.
    let root = merkle_root(parsed.indx(), request, parsed.path().elements())
        .ok_or(RoughtimeError::NotInTree)?;
    if root.as_slice() != parsed.srep().root().as_ref().as_slice() {
        return Err(RoughtimeError::NotInTree);
    }

    // The delegated key signed the answer.
    let delegated: [u8; 32] = delegation
        .pubk()
        .as_ref()
        .try_into()
        .map_err(|_| RoughtimeError::BadDelegatedKey)?;
    let delegated =
        VerifyingKey::from_bytes(&delegated).map_err(|_| RoughtimeError::BadDelegatedKey)?;
    let srep = value(&[Tag::SREP])?;
    let srep_signature = Signature::from_slice(parsed.sig().as_ref())
        .map_err(|_| RoughtimeError::BadResponseSignature)?;
    delegated
        .verify_strict(&[srep_context, srep].concat(), &srep_signature)
        .map_err(|_| RoughtimeError::BadResponseSignature)?;

    let radius_ms = u64::from(parsed.srep().radi()).saturating_mul(1_000);
    let midpoint_ms = midpoint.saturating_mul(1_000);
    Ok(Interval {
        earliest_ms: midpoint_ms.saturating_sub(radius_ms),
        latest_ms: midpoint_ms.saturating_add(radius_ms),
    })
}

/// The window where the most intervals overlap, with how many overlap there, if at least
/// `min` do (Marzullo's algorithm). Intervals are closed: two that touch overlap.
pub fn agree(intervals: &[Interval], min: usize) -> Option<(Interval, usize)> {
    // Starts sort before ends at the same time, so touching intervals overlap.
    let mut events: Vec<(u64, u8)> = intervals
        .iter()
        .flat_map(|interval| [(interval.earliest_ms, 0), (interval.latest_ms, 1)])
        .collect();
    events.sort_unstable();
    let mut count = 0usize;
    let mut best: Option<(Interval, usize)> = None;
    for (index, (time, kind)) in events.iter().enumerate() {
        if *kind == 0 {
            count += 1;
            if best.is_none_or(|(_, most)| count > most) {
                let end = events.get(index + 1).map_or(*time, |(next, _)| *next);
                best = Some((
                    Interval {
                        earliest_ms: *time,
                        latest_ms: end,
                    },
                    count,
                ));
            }
        } else {
            count = count.saturating_sub(1);
        }
    }
    best.filter(|(_, most)| *most >= min.max(1))
}

/// A future returned by [`Exchange::exchange`].
pub type ExchangeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, RoughtimeError>> + Send + 'a>>;

/// Sends one request to a server and returns its answer.
pub trait Exchange: Send + Sync {
    /// Send `request` to `address` and wait at most `timeout` for the answer.
    fn exchange<'a>(
        &'a self,
        address: &'a str,
        request: &'a [u8],
        timeout: Duration,
    ) -> ExchangeFuture<'a>;
}

/// Roughtime over UDP: one datagram each way, from a socket connected to the server, so
/// datagrams from elsewhere are dropped.
#[derive(Clone, Copy, Debug, Default)]
pub struct UdpExchange;

impl Exchange for UdpExchange {
    fn exchange<'a>(
        &'a self,
        address: &'a str,
        request: &'a [u8],
        timeout: Duration,
    ) -> ExchangeFuture<'a> {
        Box::pin(async move {
            let network = |error: std::io::Error| RoughtimeError::Network(error.to_string());
            let exchange = async {
                let target = tokio::net::lookup_host(address)
                    .await
                    .map_err(network)?
                    .next()
                    .ok_or_else(|| RoughtimeError::Network("no address".into()))?;
                let local = if target.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let socket = tokio::net::UdpSocket::bind(local).await.map_err(network)?;
                socket.connect(target).await.map_err(network)?;
                socket.send(request).await.map_err(network)?;
                let mut buffer = vec![0u8; MAX_RESPONSE_SIZE + 1];
                let received = socket.recv(&mut buffer).await.map_err(network)?;
                if received > MAX_RESPONSE_SIZE {
                    return Err(RoughtimeError::Malformed("over the size limit".into()));
                }
                buffer.truncate(received);
                Ok(buffer)
            };
            tokio::time::timeout(timeout, exchange)
                .await
                .map_err(|_| RoughtimeError::Timeout)?
        })
    }
}

/// Makes the nonce for a request to the named server.
pub type NonceSource = Arc<dyn Fn(&str) -> Result<[u8; 32], RoughtimeError> + Send + Sync>;

/// Fresh random nonces.
fn random_nonces() -> NonceSource {
    Arc::new(|_| {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| RoughtimeError::Random)?;
        Ok(nonce)
    })
}

#[derive(Clone)]
struct Server {
    name: String,
    address: String,
    key: VerifyingKey,
}

/// A [`TimeSource`] that asks several Roughtime servers and takes the window where enough
/// checked answers agree.
pub struct RoughtimeSource {
    servers: Vec<Server>,
    min_agreeing: usize,
    timeout: Duration,
    attempts: u32,
    alert_after_ms: u64,
    exchange: Arc<dyn Exchange>,
    nonces: NonceSource,
    clock: Arc<dyn Clock>,
    health: Mutex<Vec<Health>>,
}

/// A server's run of failed samples.
#[derive(Clone, Debug, Default)]
struct Health {
    /// The monotonic reading of the first failed sample of the current run.
    failing_since_ms: Option<u64>,
    /// How the last failed sample ended, and why.
    last_failure: Option<(Outcome, String)>,
    /// Whether the run has raised its alert.
    alerted: bool,
}

/// A server's health, for the operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerStatus {
    /// The server's name.
    pub name: String,
    /// How long its samples have been failing; `None` when its last one was verified, or
    /// it hasn't been asked yet.
    pub failing_for_ms: Option<u64>,
    /// How its last failed sample ended, and why.
    pub last_failure: Option<(Outcome, String)>,
    /// Whether the failures have lasted `alert_after_ms`, and raised an alert.
    pub alerted: bool,
}

impl std::fmt::Debug for RoughtimeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoughtimeSource")
            .field(
                "servers",
                &self.servers.iter().map(|s| &s.name).collect::<Vec<_>>(),
            )
            .field("min_agreeing", &self.min_agreeing)
            .finish_non_exhaustive()
    }
}

impl RoughtimeSource {
    /// A source for `config`'s servers over UDP; `None` when it names none.
    pub fn new(config: &RoughtimeConfig) -> Result<Option<Self>, (&'static str, &'static str)> {
        Self::with_exchange(config, Arc::new(UdpExchange), random_nonces())
    }

    /// A source that reaches servers through `exchange`, with nonces from `nonces`.
    pub fn with_exchange(
        config: &RoughtimeConfig,
        exchange: Arc<dyn Exchange>,
        nonces: NonceSource,
    ) -> Result<Option<Self>, (&'static str, &'static str)> {
        config.validate()?;
        if config.servers.is_empty() {
            return Ok(None);
        }
        let servers = config
            .servers
            .iter()
            .map(|server| {
                parse_public_key(&server.public_key)
                    .map(|key| Server {
                        name: server.name.clone(),
                        address: server.address.clone(),
                        key,
                    })
                    .ok_or((
                        "roughtime.servers.public_key",
                        "must be a base64 Ed25519 public key",
                    ))
            })
            .collect::<Result<_, _>>()?;
        let health = Mutex::new(vec![Health::default(); config.servers.len()]);
        Ok(Some(Self {
            servers,
            min_agreeing: config.min_agreeing,
            timeout: Duration::from_millis(config.timeout_ms),
            attempts: config.attempts,
            alert_after_ms: config.alert_after_ms,
            exchange,
            nonces,
            clock: Arc::new(SystemClock),
            health,
        }))
    }

    /// Measure how long servers fail on `clock`'s monotonic reading instead of the
    /// system's.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Each server's health.
    pub fn health(&self) -> Vec<ServerStatus> {
        let now = self.clock.monotonic_ms();
        self.servers
            .iter()
            .zip(self.health.lock().iter())
            .map(|(server, health)| ServerStatus {
                name: server.name.clone(),
                failing_for_ms: health
                    .failing_since_ms
                    .map(|since| now.saturating_sub(since)),
                last_failure: health.last_failure.clone(),
                alerted: health.alerted,
            })
            .collect()
    }

    /// Record how a server's sample ended. A run of failures lasting `alert_after_ms`
    /// raises one alert, until the server is verified again.
    fn note(&self, index: usize, result: &Result<Interval, RoughtimeError>) {
        let Some(server) = self.servers.get(index) else {
            return;
        };
        let now = self.clock.monotonic_ms();
        let mut all = self.health.lock();
        let Some(health) = all.get_mut(index) else {
            return;
        };
        let name = server.name.clone();
        match result {
            Ok(_) => {
                if health.alerted {
                    tracing::warn!(server = %name, "roughtime server verified again");
                }
                *health = Health::default();
                metrics::gauge!("pubky_switch_roughtime_server_failing_ms", "server" => name.clone())
                    .set(0.0);
                metrics::gauge!("pubky_switch_roughtime_server_alert", "server" => name).set(0.0);
            }
            Err(error) => {
                let since = *health.failing_since_ms.get_or_insert(now);
                let failing_for = now.saturating_sub(since);
                let outcome = error.outcome();
                health.last_failure = Some((outcome, error.to_string()));
                // Milliseconds are far below the 2^53 a gauge holds exactly.
                #[allow(clippy::cast_precision_loss)]
                metrics::gauge!("pubky_switch_roughtime_server_failing_ms", "server" => name.clone())
                    .set(failing_for as f64);
                if failing_for >= self.alert_after_ms && !health.alerted {
                    health.alerted = true;
                    metrics::counter!("pubky_switch_roughtime_alerts_total", "server" => name.clone())
                        .increment(1);
                    metrics::gauge!("pubky_switch_roughtime_server_alert", "server" => name.clone())
                        .set(1.0);
                    let hint = if outcome == Outcome::Refused {
                        "its answers fail verification: check whether it rotated its long-term \
                         key, and update its pinned public key"
                    } else {
                        "it doesn't answer: check that it is still running and reachable"
                    };
                    tracing::error!(
                        alert = "roughtime_server_failing",
                        server = %name,
                        outcome = outcome.as_str(),
                        %error,
                        failing_for_s = failing_for / 1_000,
                        "roughtime server failing: {hint}"
                    );
                }
            }
        }
    }

    /// Ask one server, up to `attempts` times, each with a fresh nonce.
    async fn ask(&self, server: &Server) -> Result<Interval, RoughtimeError> {
        let mut last = RoughtimeError::Timeout;
        for _ in 0..self.attempts {
            let nonce = (self.nonces)(&server.name)?;
            let request = build_request(nonce, &server.key)?;
            let answer = self
                .exchange
                .exchange(&server.address, &request, self.timeout)
                .await
                .and_then(|response| verify_response(&server.key, &nonce, &request, &response));
            let outcome = answer
                .as_ref()
                .map_or_else(RoughtimeError::outcome, |_| Outcome::Verified);
            metrics::counter!(
                "pubky_switch_roughtime_answers_total",
                "server" => server.name.clone(),
                "result" => outcome.as_str()
            )
            .increment(1);
            match answer {
                Ok(interval) => return Ok(interval),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    async fn sample_all(&self) -> Result<TimeSample, TimeSourceError> {
        let answers = futures_util::future::join_all(
            self.servers
                .iter()
                .map(|server| async move { (server, self.ask(server).await) }),
        )
        .await;
        let mut intervals = Vec::new();
        let mut checked = Vec::new();
        for (index, (server, answer)) in answers.into_iter().enumerate() {
            self.note(index, &answer);
            match answer {
                Ok(interval) => {
                    intervals.push(interval);
                    checked.push((server, interval));
                }
                Err(error) => {
                    tracing::warn!(
                        server = %server.name,
                        outcome = error.outcome().as_str(),
                        %error,
                        "roughtime server"
                    );
                }
            }
        }
        let Some((window, agreeing)) = agree(&intervals, self.min_agreeing) else {
            return Err(TimeSourceError {
                source_name: "roughtime".into(),
                reason: format!(
                    "{} of {} servers answered with a checked time, and fewer than {} agree",
                    intervals.len(),
                    self.servers.len(),
                    self.min_agreeing
                ),
            });
        };
        for (server, interval) in &checked {
            if interval.latest_ms < window.earliest_ms || interval.earliest_ms > window.latest_ms {
                tracing::warn!(server = %server.name, "roughtime server disagrees with the others");
            }
        }
        tracing::debug!(agreeing, "roughtime sample");
        let width = window.latest_ms - window.earliest_ms;
        Ok(TimeSample {
            utc_ms: window.earliest_ms + width / 2,
            uncertainty_ms: width.div_ceil(2),
        })
    }
}

impl TimeSource for RoughtimeSource {
    fn name(&self) -> &str {
        "roughtime"
    }

    fn sample(&self) -> SampleFuture<'_> {
        Box::pin(self.sample_all())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use parking_lot::Mutex;
    use roughenough_protocol::{
        ToWire,
        tags::{
            Certificate, Delegation, MerklePath, MerkleRoot, PublicKey, Signature as SigTag,
            SignedResponse, SupportedVersions,
        },
    };
    use std::collections::HashMap;

    /// A recorded exchange with a live server.
    struct Fixture {
        name: String,
        address: String,
        public_key: String,
        nonce: [u8; 32],
        request: Vec<u8>,
        response: Vec<u8>,
        earliest_ms: u64,
        latest_ms: u64,
    }

    impl Fixture {
        fn key(&self) -> VerifyingKey {
            parse_public_key(&self.public_key).expect("key")
        }

        fn config(&self) -> RoughtimeServerConfig {
            RoughtimeServerConfig {
                name: self.name.clone(),
                address: self.address.clone(),
                public_key: self.public_key.clone(),
            }
        }
    }

    fn fixture(text: &str) -> Fixture {
        let json: serde_json::Value = serde_json::from_str(text).expect("fixture");
        let field = |name: &str| json[name].as_str().expect(name).to_string();
        let bytes = |name: &str| hex::decode(field(name)).expect(name);
        Fixture {
            name: field("name"),
            address: field("address"),
            public_key: field("public_key"),
            nonce: bytes("nonce").try_into().expect("nonce"),
            request: bytes("request"),
            response: bytes("response"),
            earliest_ms: json["earliest_ms"].as_u64().expect("earliest"),
            latest_ms: json["latest_ms"].as_u64().expect("latest"),
        }
    }

    fn fixtures() -> Vec<Fixture> {
        [
            include_str!("../../tests/fixtures/roughtime/int08h.json"),
            include_str!("../../tests/fixtures/roughtime/roughtime.se.json"),
            include_str!("../../tests/fixtures/roughtime/txryan.json"),
        ]
        .into_iter()
        .map(fixture)
        .collect()
    }

    fn verify(f: &Fixture, response: &[u8]) -> Result<Interval, RoughtimeError> {
        verify_response(&f.key(), &f.nonce, &f.request, response)
    }

    /// The range of a tag's value within a response packet.
    fn value_range(response: &[u8], path: &[Tag]) -> std::ops::Range<usize> {
        let range = find_value_range(&response[FRAME_OVERHEAD..], path).expect("tag");
        range.start + FRAME_OVERHEAD..range.end + FRAME_OVERHEAD
    }

    #[test]
    fn test_roughtime_recorded_answers_verify() {
        for f in fixtures() {
            let interval = verify(&f, &f.response).unwrap_or_else(|e| panic!("{}: {e}", f.name));
            assert_eq!(interval.earliest_ms, f.earliest_ms, "{}", f.name);
            assert_eq!(interval.latest_ms, f.latest_ms, "{}", f.name);
            // The recorder built its request the way the source does.
            assert_eq!(
                build_request(f.nonce, &f.key()).expect("request"),
                f.request
            );
        }
    }

    #[test]
    fn test_roughtime_recorded_answers_agree() {
        let intervals: Vec<Interval> = fixtures()
            .iter()
            .map(|f| verify(f, &f.response).expect("verify"))
            .collect();
        let (window, agreeing) = agree(&intervals, 2).expect("agree");
        assert_eq!(agreeing, 3);
        assert!(window.earliest_ms <= window.latest_ms);
        for interval in intervals {
            assert!(interval.earliest_ms <= window.earliest_ms);
            assert!(interval.latest_ms >= window.latest_ms);
        }
    }

    #[test]
    fn test_roughtime_tampered_signature_is_refused() {
        let f = &fixtures()[0];
        let mut response = f.response.clone();
        let sig = value_range(&response, &[Tag::SIG]);
        response[sig.start] ^= 1;
        assert_eq!(
            verify(f, &response),
            Err(RoughtimeError::BadResponseSignature)
        );
    }

    #[test]
    fn test_roughtime_tampered_delegation_is_refused() {
        let f = &fixtures()[0];
        let mut response = f.response.clone();
        let dele = value_range(&response, &[Tag::CERT, Tag::DELE]);
        response[dele.end - 1] ^= 1;
        assert_eq!(
            verify(f, &response),
            Err(RoughtimeError::BadDelegationSignature)
        );
    }

    #[test]
    fn test_roughtime_tampered_midpoint_is_refused() {
        let f = &fixtures()[0];
        let mut response = f.response.clone();
        let srep = value_range(&response, &[Tag::SREP]);
        // The last byte of the signed answer: changing it breaks its signature, or the
        // Merkle root it carries, whichever it falls in.
        response[srep.end - 1] ^= 1;
        assert!(matches!(
            verify(f, &response),
            Err(RoughtimeError::BadResponseSignature | RoughtimeError::NotInTree)
        ));
    }

    #[test]
    fn test_roughtime_wrong_server_key_is_refused() {
        let all = fixtures();
        let (f, other) = (&all[0], &all[1]);
        assert_eq!(
            verify_response(&other.key(), &f.nonce, &f.request, &f.response),
            Err(RoughtimeError::BadDelegationSignature)
        );
    }

    #[test]
    fn test_roughtime_answer_to_another_request_is_refused() {
        let f = &fixtures()[0];
        let mut nonce = f.nonce;
        nonce[0] ^= 1;
        assert_eq!(
            verify_response(&f.key(), &nonce, &f.request, &f.response),
            Err(RoughtimeError::NonceMismatch)
        );
        // Same nonce, other request bytes: the request isn't the tree's leaf.
        let mut request = f.request.clone();
        let last = request.len() - 1;
        request[last] ^= 1;
        assert_eq!(
            verify_response(&f.key(), &f.nonce, &request, &f.response),
            Err(RoughtimeError::NotInTree)
        );
    }

    #[test]
    fn test_roughtime_malformed_answers_are_refused() {
        let f = &fixtures()[0];
        for response in [
            Vec::new(),
            vec![0u8; 12],
            f.response[..f.response.len() / 2].to_vec(),
            vec![0xa5; 1_000],
            vec![0u8; MAX_RESPONSE_SIZE + 1],
        ] {
            assert!(
                matches!(verify(f, &response), Err(RoughtimeError::Malformed(_))),
                "{} bytes",
                response.len()
            );
        }
    }

    #[test]
    fn test_roughtime_bytes_after_the_frame_are_ignored() {
        let f = &fixtures()[0];
        let mut response = f.response.clone();
        response.extend_from_slice(&[0u8; 8]);
        assert_eq!(
            verify(f, &response).map(|i| i.earliest_ms),
            Ok(f.earliest_ms)
        );
    }

    /// What a test server puts in a signed answer.
    struct Answer {
        version: ProtocolVersion,
        midpoint_s: u64,
        radius_s: u32,
        mint_s: u64,
        maxt_s: u64,
        index: u32,
        path: Vec<[u8; 32]>,
    }

    impl Default for Answer {
        fn default() -> Self {
            Self {
                version: ProtocolVersion::RFC,
                midpoint_s: 1_800_000_000,
                radius_s: 3,
                mint_s: 1_799_000_000,
                maxt_s: 1_801_000_000,
                index: 0,
                path: Vec::new(),
            }
        }
    }

    fn wire<T: ToWire>(value: &T) -> Vec<u8> {
        let mut buffer = vec![0u8; value.wire_size()];
        value
            .to_wire(&mut ParseCursor::new(&mut buffer))
            .expect("encode");
        buffer
    }

    /// An answer to `request` signed by `long_term`, as a server following RFC 10049 would
    /// sign it.
    fn signed_answer(
        long_term: &SigningKey,
        nonce: [u8; 32],
        request: &[u8],
        a: Answer,
    ) -> Vec<u8> {
        let (srep_context, dele_context) = if a.version == ProtocolVersion::RFC {
            (RFC_SREP_CONTEXT, RFC_DELE_CONTEXT)
        } else {
            (DRAFT_SREP_CONTEXT, DRAFT_DELE_CONTEXT)
        };
        let delegated = SigningKey::from_bytes(&[7u8; 32]);
        let mut dele = Delegation::default();
        dele.set_pubk(PublicKey::from(delegated.verifying_key().to_bytes()));
        dele.set_mint(a.mint_s);
        dele.set_maxt(a.maxt_s);
        let dele_sig = long_term.sign(&[dele_context, &wire(&dele)].concat());
        let cert = Certificate::new(SigTag::from(dele_sig.to_bytes()), dele);

        let root =
            merkle_root(a.index, request, a.path.iter().map(|p| p.as_slice())).unwrap_or([0u8; 32]);
        let mut srep = SignedResponse::default();
        srep.set_ver(a.version);
        srep.set_radi(a.radius_s);
        srep.set_midp(a.midpoint_s);
        srep.set_vers(&SupportedVersions::new(&[a.version]));
        srep.set_root(&MerkleRoot::from(root));
        let srep_sig = delegated.sign(&[srep_context, &wire(&srep)].concat());

        let mut path = MerklePath::default();
        for element in &a.path {
            path.push_element(element);
        }
        let mut response = Response::default();
        response.set_sig(SigTag::from(srep_sig.to_bytes()));
        response.set_nonc(Nonce::from(nonce));
        response.set_path(path);
        response.set_srep(srep);
        response.set_cert(cert);
        response.set_indx(a.index);
        response.as_frame_bytes().expect("frame")
    }

    fn test_server() -> (SigningKey, [u8; 32], Vec<u8>) {
        let long_term = SigningKey::from_bytes(&[42u8; 32]);
        let nonce = [9u8; 32];
        let request = build_request(nonce, &long_term.verifying_key()).expect("request");
        (long_term, nonce, request)
    }

    #[test]
    fn test_roughtime_signed_answers_of_both_versions_verify() {
        let (long_term, nonce, request) = test_server();
        for version in [ProtocolVersion::RFC, ProtocolVersion::DRAFT] {
            let answer = Answer {
                version,
                ..Answer::default()
            };
            let response = signed_answer(&long_term, nonce, &request, answer);
            let interval = verify_response(&long_term.verifying_key(), &nonce, &request, &response)
                .expect("verify");
            assert_eq!(
                interval,
                Interval {
                    earliest_ms: 1_799_999_997_000,
                    latest_ms: 1_800_000_003_000,
                }
            );
        }
    }

    #[test]
    fn test_roughtime_signature_context_must_match_the_version() {
        let (long_term, nonce, request) = test_server();
        // Signed with the draft contexts, but claiming the RFC's version.
        let mut response = signed_answer(
            &long_term,
            nonce,
            &request,
            Answer {
                version: ProtocolVersion::DRAFT,
                ..Answer::default()
            },
        );
        let srep = value_range(&response, &[Tag::SREP]);
        let ver = find_value_range(&response[srep.clone()], &[Tag::VER]).expect("VER");
        let at = srep.start + ver.start;
        response[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(verify_response(&long_term.verifying_key(), &nonce, &request, &response).is_err());
    }

    #[test]
    fn test_roughtime_midpoint_outside_delegation_is_refused() {
        let (long_term, nonce, request) = test_server();
        for (mint_s, maxt_s) in [
            (1_800_000_001, 1_801_000_000),
            (1_799_000_000, 1_799_999_999),
        ] {
            let response = signed_answer(
                &long_term,
                nonce,
                &request,
                Answer {
                    mint_s,
                    maxt_s,
                    ..Answer::default()
                },
            );
            assert_eq!(
                verify_response(&long_term.verifying_key(), &nonce, &request, &response),
                Err(RoughtimeError::OutsideDelegation)
            );
        }
    }

    #[test]
    fn test_roughtime_merkle_path_of_a_batch() {
        let (long_term, nonce, request) = test_server();
        let path = vec![[1u8; 32], [2u8; 32]];
        // The request is the third of four in the server's batch.
        let response = signed_answer(
            &long_term,
            nonce,
            &request,
            Answer {
                index: 2,
                path: path.clone(),
                ..Answer::default()
            },
        );
        assert!(verify_response(&long_term.verifying_key(), &nonce, &request, &response).is_ok());
        // An index with bits beyond the path can't be in the tree.
        let response = signed_answer(
            &long_term,
            nonce,
            &request,
            Answer {
                index: 4,
                path,
                ..Answer::default()
            },
        );
        assert_eq!(
            verify_response(&long_term.verifying_key(), &nonce, &request, &response),
            Err(RoughtimeError::NotInTree)
        );
    }

    fn interval(earliest_ms: u64, latest_ms: u64) -> Interval {
        Interval {
            earliest_ms,
            latest_ms,
        }
    }

    #[test]
    fn test_roughtime_agreement_window() {
        // Three agree, one is far off.
        let intervals = [
            interval(100, 110),
            interval(104, 120),
            interval(90, 106),
            interval(500, 510),
        ];
        assert_eq!(agree(&intervals, 2), Some((interval(104, 106), 3)));
        assert_eq!(agree(&intervals, 3), Some((interval(104, 106), 3)));
        assert_eq!(agree(&intervals, 4), None);
        // Touching intervals overlap at the point they share.
        assert_eq!(
            agree(&[interval(0, 10), interval(10, 20)], 2),
            Some((interval(10, 10), 2))
        );
        // Two disjoint pairs: the earlier window with the most wins, and both have two.
        assert_eq!(
            agree(
                &[
                    interval(0, 2),
                    interval(1, 3),
                    interval(10, 12),
                    interval(11, 13)
                ],
                2
            ),
            Some((interval(1, 2), 2))
        );
        assert_eq!(agree(&[], 1), None);
        assert_eq!(agree(&[interval(5, 7)], 1), Some((interval(5, 7), 1)));
        assert_eq!(agree(&[interval(0, 1), interval(5, 6)], 2), None);
    }

    /// Answers recorded exchanges, and times out for anything else.
    /// A recorded request and the answer to it.
    type Recorded = (Vec<u8>, Vec<u8>);

    #[derive(Default)]
    struct Replay {
        answers: Mutex<HashMap<String, Recorded>>,
        /// Calls to time out first, per address.
        drop_first: Mutex<HashMap<String, u32>>,
        calls: Mutex<u32>,
    }

    impl Exchange for Replay {
        fn exchange<'a>(
            &'a self,
            address: &'a str,
            request: &'a [u8],
            _timeout: Duration,
        ) -> ExchangeFuture<'a> {
            *self.calls.lock() += 1;
            let dropped = self.drop_first.lock().get_mut(address).is_some_and(|left| {
                let drop = *left > 0;
                *left = left.saturating_sub(1);
                drop
            });
            let recorded = self.answers.lock().get(address).cloned();
            let answer = match recorded {
                _ if dropped => Err(RoughtimeError::Timeout),
                Some((recorded, response)) if recorded == request => Ok(response),
                Some(_) => Err(RoughtimeError::Network("unexpected request".into())),
                None => Err(RoughtimeError::Timeout),
            };
            Box::pin(async move { answer })
        }
    }

    fn replay_source(
        fixtures: &[Fixture],
        replayed: &[&str],
        min_agreeing: usize,
    ) -> (RoughtimeSource, Arc<Replay>) {
        let mut replay = Replay::default();
        let mut nonces = HashMap::new();
        for f in fixtures {
            nonces.insert(f.name.clone(), f.nonce);
            if replayed.contains(&f.name.as_str()) {
                replay
                    .answers
                    .get_mut()
                    .insert(f.address.clone(), (f.request.clone(), f.response.clone()));
            }
        }
        let replay = Arc::new(replay);
        let config = RoughtimeConfig {
            servers: fixtures.iter().map(Fixture::config).collect(),
            min_agreeing,
            ..RoughtimeConfig::default()
        };
        let source = RoughtimeSource::with_exchange(
            &config,
            replay.clone(),
            Arc::new(move |name| nonces.get(name).copied().ok_or(RoughtimeError::Random)),
        )
        .expect("config")
        .expect("servers");
        (source, replay)
    }

    #[tokio::test]
    async fn test_roughtime_source_samples_from_agreeing_servers() {
        let all = fixtures();
        let names: Vec<&str> = all.iter().map(|f| f.name.as_str()).collect();
        let (source, _) = replay_source(&all, &names, 2);
        let sample = source.sample().await.expect("sample");
        let intervals: Vec<Interval> = all
            .iter()
            .map(|f| interval(f.earliest_ms, f.latest_ms))
            .collect();
        let (window, _) = agree(&intervals, 2).expect("agree");
        assert_eq!(
            sample.utc_ms,
            window.earliest_ms + (window.latest_ms - window.earliest_ms) / 2
        );
        assert_eq!(
            sample.uncertainty_ms,
            (window.latest_ms - window.earliest_ms).div_ceil(2)
        );
    }

    #[tokio::test]
    async fn test_roughtime_source_tolerates_a_silent_server() {
        let all = fixtures();
        let (source, replay) = replay_source(&all, &[&all[0].name, &all[2].name], 2);
        let sample = source.sample().await.expect("two of three agree");
        assert!(sample.uncertainty_ms <= 3_000);
        // The silent server was asked `attempts` times.
        assert_eq!(
            *replay.calls.lock(),
            2 + RoughtimeConfig::default().attempts
        );
    }

    #[tokio::test]
    async fn test_roughtime_source_retries_a_lost_answer() {
        let all = fixtures();
        let names: Vec<&str> = all.iter().map(|f| f.name.as_str()).collect();
        let (source, replay) = replay_source(&all, &names, 3);
        replay.drop_first.lock().insert(all[1].address.clone(), 1);
        source.sample().await.expect("the retry answers");
    }

    #[tokio::test]
    async fn test_roughtime_source_without_agreement_gives_no_sample() {
        let all = fixtures();
        let (source, _) = replay_source(&all, &[&all[0].name], 2);
        let error = source.sample().await.expect_err("one answer isn't enough");
        assert_eq!(error.source_name, "roughtime");
        assert!(error.reason.contains("1 of 3"), "{}", error.reason);
    }

    #[tokio::test]
    async fn test_roughtime_source_ignores_a_forged_answer() {
        let all = fixtures();
        let names: Vec<&str> = all.iter().map(|f| f.name.as_str()).collect();
        let mut replay = Replay::default();
        let mut nonces = HashMap::new();
        for f in &all {
            nonces.insert(f.name.clone(), f.nonce);
            let mut response = f.response.clone();
            if f.name == names[0] {
                // An on-path attacker's answer: the recorded one with its signature broken.
                let sig = value_range(&response, &[Tag::SIG]);
                response[sig.start] ^= 1;
            }
            replay
                .answers
                .get_mut()
                .insert(f.address.clone(), (f.request.clone(), response));
        }
        let config = RoughtimeConfig {
            servers: all.iter().map(Fixture::config).collect(),
            min_agreeing: 3,
            ..RoughtimeConfig::default()
        };
        let source = RoughtimeSource::with_exchange(
            &config,
            Arc::new(replay),
            Arc::new(move |name| nonces.get(name).copied().ok_or(RoughtimeError::Random)),
        )
        .expect("config")
        .expect("servers");
        assert!(source.sample().await.is_err(), "only two checked answers");
    }

    fn forged(f: &Fixture) -> Vec<u8> {
        let mut response = f.response.clone();
        let sig = value_range(&response, &[Tag::SIG]);
        response[sig.start] ^= 1;
        response
    }

    const HOUR_MS: u64 = 3_600_000;

    #[tokio::test]
    async fn test_roughtime_silent_server_alerts_after_a_while() {
        let all = fixtures();
        let names: Vec<&str> = all.iter().map(|f| f.name.as_str()).collect();
        let (source, replay) = replay_source(&all, &names[1..], 2);
        let clock = Arc::new(crate::time::ManualClock::new(0));
        let source = source.with_clock(clock.clone());
        let silent = all[0].name.clone();
        let status = |source: &RoughtimeSource| {
            source
                .health()
                .into_iter()
                .find(|s| s.name == silent)
                .expect("status")
        };

        source.sample().await.expect("two still agree");
        let first = status(&source);
        assert_eq!(first.failing_for_ms, Some(0));
        assert_eq!(
            first.last_failure.as_ref().map(|(outcome, _)| *outcome),
            Some(Outcome::Timeout)
        );
        assert!(!first.alerted);

        // Still failing just short of the bound: no alert yet.
        clock.advance_ms(HOUR_MS - 1);
        source.sample().await.expect("sample");
        assert!(!status(&source).alerted);

        // Failing for the whole bound: the alert, once.
        clock.advance_ms(1);
        source.sample().await.expect("sample");
        let alerted = status(&source);
        assert!(alerted.alerted);
        assert_eq!(alerted.failing_for_ms, Some(HOUR_MS));

        // The others are healthy throughout.
        for other in source.health().into_iter().filter(|s| s.name != silent) {
            assert_eq!(other.failing_for_ms, None, "{}", other.name);
            assert!(!other.alerted);
        }

        // It answers again: the run ends, and a later failure starts a new one.
        replay.answers.lock().insert(
            all[0].address.clone(),
            (all[0].request.clone(), all[0].response.clone()),
        );
        clock.advance_ms(1_000);
        source.sample().await.expect("sample");
        let recovered = status(&source);
        assert_eq!(recovered.failing_for_ms, None);
        assert_eq!(recovered.last_failure, None);
        assert!(!recovered.alerted);
    }

    #[tokio::test]
    async fn test_roughtime_refused_answers_alert_as_refused() {
        let all = fixtures();
        let names: Vec<&str> = all.iter().map(|f| f.name.as_str()).collect();
        let (source, replay) = replay_source(&all, &names, 2);
        // The server now signs with a key that isn't the pinned one, as after a rotation.
        replay.answers.lock().insert(
            all[2].address.clone(),
            (all[2].request.clone(), forged(&all[2])),
        );
        let clock = Arc::new(crate::time::ManualClock::new(0));
        let source = source.with_clock(clock.clone());
        source.sample().await.expect("two still agree");
        clock.advance_ms(HOUR_MS);
        source.sample().await.expect("two still agree");
        let status = source
            .health()
            .into_iter()
            .find(|s| s.name == all[2].name)
            .expect("status");
        assert!(status.alerted);
        let (outcome, reason) = status.last_failure.expect("failure");
        assert_eq!(outcome, Outcome::Refused);
        assert!(reason.contains("signature"), "{reason}");
    }

    #[test]
    fn test_roughtime_metrics_count_answers_and_alerts() {
        let all = fixtures();
        let names: Vec<&str> = all.iter().map(|f| f.name.as_str()).collect();
        let (source, replay) = replay_source(&all, &names[..2], 2);
        replay.answers.lock().insert(
            all[1].address.clone(),
            (all[1].request.clone(), forged(&all[1])),
        );
        let config = RoughtimeConfig {
            servers: all.iter().map(Fixture::config).collect(),
            ..RoughtimeConfig::default()
        };
        assert_eq!(config.alert_after_ms, HOUR_MS);
        let clock = Arc::new(crate::time::ManualClock::new(0));
        let source = source.with_clock(clock.clone());
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        metrics::with_local_recorder(&recorder, || {
            runtime.block_on(async {
                // Only one server verifies: no sample, but every answer is counted.
                assert!(source.sample().await.is_err());
                clock.advance_ms(HOUR_MS);
                assert!(source.sample().await.is_err());
            });
        });
        let text = handle.render();
        let line = |needle: &str| {
            text.lines()
                .find(|line| line.starts_with(needle))
                .unwrap_or_else(|| panic!("no {needle} in\n{text}"))
                .to_string()
        };
        let verified = format!(
            "pubky_switch_roughtime_answers_total{{server=\"{}\",result=\"verified\"}}",
            all[0].name
        );
        assert!(line(&verified).ends_with(" 2"));
        let refused = format!(
            "pubky_switch_roughtime_answers_total{{server=\"{}\",result=\"refused\"}}",
            all[1].name
        );
        // Two attempts in each of two samples.
        assert!(line(&refused).ends_with(" 4"));
        let timeout = format!(
            "pubky_switch_roughtime_answers_total{{server=\"{}\",result=\"timeout\"}}",
            all[2].name
        );
        assert!(line(&timeout).ends_with(" 4"));
        for (index, alert) in [(0, " 0"), (1, " 1"), (2, " 1")] {
            let gauge = format!(
                "pubky_switch_roughtime_server_alert{{server=\"{}\"}}",
                all[index].name
            );
            assert!(line(&gauge).ends_with(alert), "{gauge}");
        }
    }

    #[test]
    fn test_roughtime_outcomes() {
        assert_eq!(RoughtimeError::Timeout.outcome(), Outcome::Timeout);
        assert_eq!(
            RoughtimeError::Network("refused".into()).outcome(),
            Outcome::Unreachable
        );
        for refused in [
            RoughtimeError::Malformed("x".into()),
            RoughtimeError::UnofferedVersion(2),
            RoughtimeError::NonceMismatch,
            RoughtimeError::BadDelegationSignature,
            RoughtimeError::BadResponseSignature,
            RoughtimeError::BadDelegatedKey,
            RoughtimeError::OutsideDelegation,
            RoughtimeError::NotInTree,
        ] {
            assert_eq!(refused.outcome(), Outcome::Refused, "{refused}");
        }
        assert_eq!(RoughtimeError::Random.outcome(), Outcome::Internal);
    }

    #[test]
    fn test_roughtime_config_validation() {
        assert_eq!(RoughtimeConfig::default().validate(), Ok(()));
        assert_eq!(RoughtimeConfig::default().servers.len(), 3);
        let empty = RoughtimeConfig {
            servers: Vec::new(),
            ..RoughtimeConfig::default()
        };
        assert_eq!(empty.validate(), Ok(()));
        assert!(
            RoughtimeSource::new(&empty).expect("valid").is_none(),
            "no servers, no source"
        );
        let with = |change: &dyn Fn(&mut RoughtimeConfig)| {
            let mut config = RoughtimeConfig::default();
            change(&mut config);
            config.validate().expect_err("invalid").0
        };
        assert_eq!(with(&|c| c.min_agreeing = 0), "roughtime.min_agreeing");
        assert_eq!(with(&|c| c.min_agreeing = 4), "roughtime.min_agreeing");
        assert_eq!(with(&|c| c.timeout_ms = 0), "roughtime.timeout_ms");
        assert_eq!(with(&|c| c.attempts = 6), "roughtime.attempts");
        assert_eq!(with(&|c| c.alert_after_ms = 0), "roughtime.alert_after_ms");
        assert_eq!(
            with(&|c| c.servers[1].name = c.servers[0].name.clone()),
            "roughtime.servers.name"
        );
        assert_eq!(
            with(&|c| c.servers[0].address = "no-port".into()),
            "roughtime.servers.address"
        );
        assert_eq!(
            with(&|c| c.servers[0].address = ":2002".into()),
            "roughtime.servers.address"
        );
        assert_eq!(
            with(&|c| c.servers[0].public_key = "AAAA".into()),
            "roughtime.servers.public_key"
        );
    }
}
