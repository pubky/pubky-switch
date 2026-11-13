//! Push delivery (Switch spec 9 step 4, Switch wire 8.2): the webhooks a `notify` entry
//! owes its target apps' handles, sent from the queue the append filled (`store::push_queue`)
//! by a worker in each instance, never during the append.
//!
//! - **One attempt** claims a due row, leased so no other instance sends it meanwhile, and
//!   holds its registration while the webhook is signed: the registration must still name the
//!   row's push key and handle, the key must not be owed deleting, and the account must still
//!   serve at this service (its newest `identity.json` names it). Otherwise the row goes
//!   unsent, and the registration stays as it is. A service with `push.enabled` off claims
//!   nothing. The body is made at each attempt: `ts` is the service time when sent, and the
//!   nonce is fresh, since a relay refuses a `ts` more than 5 minutes off and a nonce it saw
//!   in the last 10 (8.3), so an attempt sent again after a timeout the relay did take must
//!   not repeat one. It is signed with the registration's push key, never the service key.
//! - **Connecting:** the relay's host is resolved again, refused if any address isn't public
//!   (`check_addresses`, as at registration), and the connection goes to an address checked,
//!   on port 443, with TLS checking the host name, never through a proxy the environment
//!   names. Redirects aren't followed. The whole
//!   attempt, resolution included, has 5 s.
//! - **Outcomes:** any 2xx is a delivery and the row goes. Anything else, a redirect or a
//!   timeout is a failure, retried 20 s later, at most 3 attempts within 1 minute of the
//!   entry; then the row goes.
//! - **Without trusted time** nothing is sent: `ts` would be a time the service doesn't
//!   trust (Switch wire 7.3), and the rows wait, then go once their minute has passed.
//!
//! Logs and metrics hold counts and failure kinds only: never a handle, a relay URL, a key
//! or anything of a message.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use pubky_switch_core::{
    enc::b64,
    http::{header, sign_webhook, webhook_body},
    net::{UrlUse, check_addresses, check_url},
};

use pubky_switch_core::records::IdentityDoc;

use super::{Service, rules::names_this_service};
use crate::{
    keys::ServiceSigner,
    store::{HeldRegistration, QueuedPush, StoreError},
};

/// How long one attempt may take, resolution included (Switch wire 8.2: 5 s).
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long after a failure the next attempt is due (Switch wire 8.2: 20 s). It is also the
/// lease of a claimed row, longer than an attempt can take.
const RETRY_MS: u64 = 20_000;

/// How long after its entry a delivery may be attempted (Switch wire 8.2: 1 minute).
const WINDOW_MS: u64 = 60_000;

/// How long the worker waits for due rows when a round found fewer than it can send.
const POLL: Duration = Duration::from_secs(1);

/// Where webhooks connect in tests: the plain-HTTP listener a checked address maps to.
#[cfg(any(test, feature = "test-util"))]
pub type RelayRoute = Arc<dyn Fn(IpAddr) -> Option<SocketAddr> + Send + Sync>;

/// Why an attempt failed: all that is logged of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    /// The host didn't resolve.
    Unresolved,
    /// The host resolved to an address that isn't public, or the URL fails its checks.
    Refused,
    /// The relay didn't answer within 5 s.
    Timeout,
    /// No connection, or the request failed.
    Connect,
    /// A 3xx answer, which isn't followed.
    Redirect,
    /// Another answer that isn't 2xx.
    Status,
    /// The push key couldn't be read, or the database failed.
    Internal,
}

impl Failure {
    fn kind(self) -> &'static str {
        match self {
            Self::Unresolved => "unresolved",
            Self::Refused => "refused",
            Self::Timeout => "timeout",
            Self::Connect => "connect",
            Self::Redirect => "redirect",
            Self::Status => "status",
            Self::Internal => "internal",
        }
    }
}

/// What one round of delivery did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PushRound {
    /// Webhooks a relay took (2xx).
    pub delivered: usize,
    /// Attempts that failed, retried or not.
    pub failed: usize,
    /// Deliveries that went unsent: their registration changed, or their time ran out.
    pub dropped: usize,
}

/// A webhook to `handle` at `relay_url`, sent at `sent_at_ms` with `nonce`, signed with the
/// push key `signer` (Switch wire 8.2): its body and its `Switch-Signature`.
fn signed_webhook(
    signer: &ServiceSigner,
    relay_url: &str,
    handle: &str,
    sent_at_ms: u64,
    nonce: &[u8; 16],
) -> Option<(Vec<u8>, String)> {
    let body = webhook_body(handle, sent_at_ms, nonce);
    let signature = sign_webhook(signer, relay_url, &body).ok()?;
    Some((body, b64(&signature)))
}

/// A test's route: the listener each checked address maps to, over plain HTTP, at the
/// first one's port.
#[cfg(any(test, feature = "test-util"))]
fn routed(
    route: &RelayRoute,
    mut url: reqwest::Url,
    addresses: &[IpAddr],
) -> Result<(reqwest::Url, Vec<SocketAddr>, bool), Failure> {
    let targets: Vec<SocketAddr> = addresses.iter().filter_map(|ip| route(*ip)).collect();
    let port = targets.first().map(SocketAddr::port);
    if port.is_none() || url.set_scheme("http").is_err() || url.set_port(port).is_err() {
        return Err(Failure::Connect);
    }
    Ok((url, targets, false))
}

impl Service {
    /// Send due webhooks until `shutdown` resolves (Switch wire 8.2): a round at once, the
    /// next as soon as a full one ends, otherwise after a second. Several instances may run
    /// it against one database: each row is sent by one at a time. Run by the service's
    /// binary while `push.enabled` is on.
    pub async fn deliver_pushes_until(self: Arc<Self>, shutdown: impl Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            let round = tokio::select! {
                () = &mut shutdown => return,
                round = self.deliver_pushes() => round,
            };
            if round.delivered + round.failed + round.dropped < self.push_concurrency {
                tokio::select! {
                    () = &mut shutdown => return,
                    () = tokio::time::sleep(POLL) => {}
                }
            }
        }
    }

    /// One round: the rows whose time ran out go, then at most `push.concurrency` due rows
    /// are claimed and attempted at once (Switch wire 8.2).
    pub async fn deliver_pushes(&self) -> PushRound {
        let mut round = PushRound::default();
        // A service that sends no pushes claims and sends nothing: the rows wait, and go
        // unsent once their minute has passed, at the first round of a service that does.
        if !self.push_enabled {
            return round;
        }
        let reading = self.time.read();
        if !reading.trusted {
            return round;
        }
        let now = reading.base_ms;
        match self.store.drop_stale_pushes(now, WINDOW_MS).await {
            Ok(gone) => round.dropped = usize::try_from(gone).unwrap_or(usize::MAX),
            Err(error) => {
                tracing::warn!(%error, "push deliveries: dropping stale rows");
                return round;
            }
        }
        let claimed = match self
            .store
            .claim_pushes(
                now,
                WINDOW_MS,
                now.saturating_add(RETRY_MS),
                self.push_concurrency,
            )
            .await
        {
            Ok(claimed) => claimed,
            Err(error) => {
                tracing::warn!(%error, "push deliveries: claiming rows");
                return round;
            }
        };
        let attempts = claimed.iter().map(|push| self.attempt(push));
        let outcomes = futures_util::future::join_all(attempts).await;
        for (push, outcome) in claimed.iter().zip(outcomes) {
            let done = match outcome {
                Ok(true) => {
                    round.delivered += 1;
                    metrics::counter!("pubky_switch_push_webhooks_total", "result" => "delivered")
                        .increment(1);
                    true
                }
                Ok(false) => {
                    round.dropped += 1;
                    true
                }
                Err(failure) => {
                    round.failed += 1;
                    metrics::counter!("pubky_switch_push_webhooks_total", "result" => failure.kind())
                        .increment(1);
                    tracing::info!(
                        kind = failure.kind(),
                        attempt = push.attempts,
                        "push deliveries: a webhook failed"
                    );
                    let retry_at = self.time.read().base_ms.saturating_add(RETRY_MS);
                    let last = push.attempts >= 3
                        || retry_at >= push.entry_at_ms.saturating_add(WINDOW_MS);
                    if !last && let Err(error) = self.store.retry_push(push.id, retry_at).await {
                        tracing::warn!(%error, "push deliveries: scheduling a retry");
                    }
                    last
                }
            };
            if done && let Err(error) = self.store.finish_push(push.id).await {
                tracing::warn!(%error, "push deliveries: dropping a row");
            }
        }
        if round != PushRound::default() {
            tracing::debug!(
                delivered = round.delivered,
                failed = round.failed,
                dropped = round.dropped,
                "push deliveries"
            );
        }
        round
    }

    /// `push`'s registration, held while its webhook is signed, if it may be sent: the
    /// registration still names its push key and handle, the key isn't owed deleting, and
    /// the account still serves at this service, its newest `identity.json` naming this
    /// service's origin and the account's service key (Switch wire 3.7). `None` otherwise:
    /// nothing is sent, and the registration stays as it is.
    async fn sendable(&self, push: &QueuedPush) -> Result<Option<HeldRegistration>, Failure> {
        // Held, so the key can't be owed deleting, and so deleted, until the signature is
        // made (`store::push_queue`).
        let held = self
            .store
            .hold_push_registration(push)
            .await
            .map_err(|error: StoreError| {
                tracing::warn!(%error, "push deliveries: reading a registration");
                Failure::Internal
            })?;
        let Some(held) = held else {
            return Ok(None);
        };
        let identity = held
            .identity
            .as_ref()
            .and_then(|doc| IdentityDoc::verify(doc, &held.identity_key).ok());
        let service_key = self
            .keys
            .public_key(&held.service_key)
            .await
            .map_err(|failure| {
                tracing::error!(%failure, "push deliveries: the account's service key");
                Failure::Internal
            })?;
        if !names_this_service(identity.as_ref(), &self.origin, &service_key) {
            return Ok(None);
        }
        Ok(Some(held))
    }

    /// One attempt of `push`: `Ok(true)` delivered, `Ok(false)` not to be sent
    /// ([`Service::sendable`]).
    async fn attempt(&self, push: &QueuedPush) -> Result<bool, Failure> {
        let Some(held) = self.sendable(push).await? else {
            return Ok(false);
        };
        let signer = self.keys.signer(&push.push_key).await.map_err(|failure| {
            tracing::error!(%failure, "push deliveries: a push key");
            Failure::Internal
        })?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| Failure::Internal)?;
        let sent_at = self.time.read().base_ms;
        let (body, signature) =
            signed_webhook(&signer, &held.relay_url, &push.handle, sent_at, &nonce)
                .ok_or(Failure::Refused)?;
        let relay_url = held.relay_url.clone();
        drop(held);
        tokio::time::timeout(ATTEMPT_TIMEOUT, self.post(&relay_url, &signature, body))
            .await
            .map_err(|_| Failure::Timeout)?
            .map(|()| true)
    }

    /// POST the webhook to `relay_url`, connecting only to an address checked now.
    async fn post(&self, relay_url: &str, signature: &str, body: Vec<u8>) -> Result<(), Failure> {
        let host = check_url(relay_url, &UrlUse::Relay)
            .map_err(|_| Failure::Refused)?
            .host;
        let addresses = match host.parse::<IpAddr>() {
            // An address literal was judged by `check_url`.
            Ok(ip) => vec![ip],
            Err(_) => (self.resolver)(host.clone())
                .await
                .map_err(|_| Failure::Unresolved)?,
        };
        check_addresses(&addresses).map_err(|_| Failure::Refused)?;
        let url = reqwest::Url::parse(relay_url).map_err(|_| Failure::Refused)?;
        let targets: Vec<SocketAddr> = addresses
            .iter()
            .map(|ip| SocketAddr::new(*ip, 443))
            .collect();
        #[cfg(any(test, feature = "test-util"))]
        let (url, targets, https_only) = match &self.relay_route {
            Some(route) => routed(route, url, &addresses)?,
            None => (url, targets, true),
        };
        #[cfg(not(any(test, feature = "test-util")))]
        let https_only = true;
        // No proxy from the environment (`HTTPS_PROXY` and the like): a proxy would resolve
        // the host itself, and the connection would go to an address never checked.
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(https_only)
            .pool_max_idle_per_host(0)
            .timeout(ATTEMPT_TIMEOUT)
            .resolve_to_addrs(&host, &targets)
            .build()
            .map_err(|_| Failure::Internal)?;
        let answer = client
            .post(url)
            .header("content-type", "application/json")
            .header(header::SIGNATURE, signature)
            .body(body)
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    Failure::Timeout
                } else {
                    Failure::Connect
                }
            })?;
        let status = answer.status();
        if status.is_success() {
            Ok(())
        } else if status.is_redirection() {
            Err(Failure::Redirect)
        } else {
            Err(Failure::Status)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors(name: &str) -> serde_json::Value {
        let path = format!("{}/../../spec/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(path).expect("vectors");
        serde_json::from_str(&text).expect("json")
    }

    fn text<'a>(value: &'a serde_json::Value, name: &str) -> &'a str {
        value[name].as_str().expect(name)
    }

    #[test]
    fn test_webhook_signed_as_the_vector() {
        let webhook = vectors("http.json")["webhook"].clone();
        // The fixed service key standing in for a push key, by its public half.
        let keys = vectors("keys.json");
        let key = keys["service_keys"]
            .as_array()
            .expect("service keys")
            .iter()
            .find(|key| key["public"] == webhook["service_key"])
            .expect("the service key");
        let secret: [u8; 32] = hex::decode(text(key, "secret_hex"))
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        let signer = ServiceSigner::new(Arc::new(ed25519_dalek::SigningKey::from_bytes(&secret)));
        let body: serde_json::Value =
            serde_json::from_str(text(&webhook, "body")).expect("body json");
        let nonce: [u8; 16] = pubky_switch_core::enc::unb64(text(&body, "nonce"))
            .expect("b64")
            .try_into()
            .expect("16 bytes");
        let sent_at = pubky_switch_core::time::parse_rfc3339(text(&body, "ts")).expect("ts");
        let (made, signature) = signed_webhook(
            &signer,
            text(&webhook, "relay_url"),
            text(&body, "handle"),
            sent_at,
            &nonce,
        )
        .expect("signed");
        assert_eq!(made, text(&webhook, "body").as_bytes());
        assert_eq!(signature, text(&webhook["headers"], "switch-signature"));
    }
}
