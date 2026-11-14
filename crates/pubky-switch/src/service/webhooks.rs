//! Push delivery (Switch spec 9 step 4, Switch wire 8.2): the webhooks a `notify` entry
//! owes its target apps' handles, sent from the queue the append filled (`store::push_queue`)
//! by a worker of the service, never during the append.
//!
//! - **Fair across accounts:** at most `push.concurrency` attempts run at once, as a stream,
//!   not in rounds: as one ends, the next due row is claimed, so a relay that never answers
//!   holds one slot, not the others' turn. An account has at most 8 rows in flight at once,
//!   (`store::push_queue`), so one account's slow relay leaves the other slots to the
//!   others.
//! - **One attempt** claims a due row, leased so no other process sends it in an overlap, and
//!   holds its registration while the webhook is signed: the registration must still name the
//!   row's push key and handle, the key must not be owed deleting, and the account must still
//!   serve at this service (its newest `identity.json` names it). Otherwise the row goes
//!   unsent, and the registration stays as it is. A service with `push.enabled` off claims
//!   nothing. The body is made at each attempt: `ts` is the service time when sent, and the
//!   nonce is fresh, since a relay refuses a `ts` more than 5 minutes off and a nonce it saw
//!   in the last 10 (8.3), so an attempt sent again after a timeout the relay did take must
//!   not repeat one. It is signed with the registration's push key, never the service key.
//! - **One deadline:** an attempt ends within 10 s of its claim, 20 s before its lease does.
//!   Its hold, key loads and signing get the first 5 s, and past them the webhook isn't sent
//!   and the attempt fails; the connection gets the next 5 s. Attempts keep running while the
//!   worker waits on its own statements (the claim, the drops, the settles), so their
//!   deadlines and holds don't wait for those. At most a quarter of the request pool's
//!   connections hold registrations at once, and the worker's own statements take one more,
//!   so requests keep the rest.
//! - **Connecting:** the relay's host is resolved again, refused if any address isn't public
//!   (`check_addresses`, as at registration), and the connection goes to an address checked,
//!   on port 443, with TLS checking the host name, never through a proxy the environment
//!   names. Redirects aren't followed. The connection, resolution included, has 5 s.
//! - **Outcomes:** any 2xx is a delivery and the row goes. Anything else, a redirect or a
//!   timeout is a failure, retried 20 s later, at most 3 attempts, each claimed within 1
//!   minute of the entry, so the last ends at most 70 s after it; then the row goes.
//! - **Without trusted time** nothing is sent: `ts` would be a time the service doesn't
//!   trust (Switch wire 7.3). The rows wait, and go once their minute has passed by the
//!   database's clock, which needs no trusted time.
//!
//! Logs and metrics hold counts and failure kinds only: never a handle, a relay URL, a key
//! or anything of a message.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use futures_util::stream::{FuturesUnordered, StreamExt};
use pubky_switch_core::{
    enc::b64,
    http::{header, sign_webhook, webhook_body},
    net::{UrlUse, check_addresses, check_url},
};
use tokio::time::Instant;

use pubky_switch_core::records::IdentityDoc;

use super::{Service, rules::names_this_service};
use crate::{
    keys::ServiceSigner,
    store::{HeldRegistration, PUSH_LEASE_MS, PUSH_RETRY_MS, QueuedPush, StoreError},
};

/// How long one connection may take, resolution included (Switch wire 8.2: 5 s).
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long an attempt may take from its claim, everything included: the first 10 s of its
/// lease, while its row counts as in flight (`store::push_queue`), and 20 s before the lease
/// ends, so no other process claims the row while it runs in an overlap.
const ATTEMPT_DEADLINE_MS: i64 = 10_000;
const _: () = assert!(ATTEMPT_DEADLINE_MS <= PUSH_LEASE_MS - PUSH_RETRY_MS);
const _: () = assert!(ATTEMPT_DEADLINE_MS <= PUSH_LEASE_MS - 5_000);

/// How long after its claim an attempt may still send: the deadline less the connection's
/// time, so the connection ends by the deadline.
const SEND_BY: Duration =
    Duration::from_millis(ATTEMPT_DEADLINE_MS.unsigned_abs()).saturating_sub(ATTEMPT_TIMEOUT);

/// How long the worker waits for due rows when it found fewer than it can send, and how
/// often rows past their minute are dropped.
const POLL: Duration = Duration::from_secs(1);

/// Await `work`, a statement of the worker's own, while still running the attempts under
/// way, keeping those that end in `ended`: so an attempt's deadline and its registration's
/// hold don't wait for the worker's statements, which may wait for a connection.
async fn polling<T, A>(
    work: impl Future<Output = T>,
    attempts: &mut FuturesUnordered<A>,
    ended: &mut Vec<A::Output>,
) -> T
where
    A: Future,
{
    tokio::pin!(work);
    loop {
        tokio::select! {
            out = &mut work => return out,
            Some(done) = attempts.next(), if !attempts.is_empty() => ended.push(done),
        }
    }
}

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
    /// The attempt's time to send ran out first: its registration's lock, the database or
    /// the key store was slow.
    Late,
    /// The push key couldn't be read, the database failed, or trusted time was gone.
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
            Self::Late => "late",
            Self::Internal => "internal",
        }
    }
}

/// What a run of [`Service::deliver_pushes`] did.
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
    /// Send due webhooks until `shutdown` resolves (Switch wire 8.2): a run of
    /// [`Service::deliver_pushes`], then another a second after it finds nothing left.
    /// One process runs it per database. In an overlap in a restart or failover, each row is
    /// still sent by one at a time.
    /// Run by the service's binary while `push.enabled` is on.
    pub async fn deliver_pushes_until(self: Arc<Self>, shutdown: impl Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => return,
                _ = self.deliver_pushes() => {}
            }
            tokio::select! {
                () = &mut shutdown => return,
                () = tokio::time::sleep(POLL) => {}
            }
        }
    }

    /// Send due webhooks until none is due and none in flight (Switch wire 8.2): rows past
    /// their minute go, with or without trusted time, and then, with it, due rows are claimed
    /// and attempted, at most `push.concurrency` at once, a free slot claiming the next at
    /// once.
    pub async fn deliver_pushes(&self) -> PushRound {
        let mut round = PushRound::default();
        // A service that sends no pushes claims and sends nothing: the rows wait, and go
        // unsent once their minute has passed, at the first run of a service that does.
        if !self.push_enabled {
            return round;
        }
        let mut dropped_at: Option<Instant> = None;
        let mut attempts = FuturesUnordered::new();
        // Attempts that ended while the worker waited on the database, to settle.
        let mut ended = Vec::new();
        loop {
            if dropped_at.is_none_or(|at| at.elapsed() >= POLL) {
                dropped_at = Some(Instant::now());
                let dropped =
                    polling(self.store.drop_stale_pushes(), &mut attempts, &mut ended).await;
                match dropped {
                    Ok(gone) => {
                        round.dropped += usize::try_from(gone).unwrap_or(usize::MAX);
                    }
                    Err(error) => tracing::warn!(%error, "push deliveries: dropping stale rows"),
                }
            }
            let free = self.push_concurrency.saturating_sub(attempts.len());
            // Nothing is sent without trusted time: `ts` would be untrusted (Switch wire 7.3).
            if free > 0 && self.time.read().trusted {
                // Before the claim, so each deadline ends before its lease does.
                let claimed_at = Instant::now();
                let claim = self.store.claim_pushes(free);
                match polling(claim, &mut attempts, &mut ended).await {
                    Ok(claimed) => {
                        for push in claimed {
                            attempts.push(async move {
                                let outcome = self.attempt(&push, claimed_at).await;
                                (push, outcome)
                            });
                        }
                    }
                    Err(error) => tracing::warn!(%error, "push deliveries: claiming rows"),
                }
            }
            while let Some((push, outcome)) = ended.pop() {
                let settle = self.settle(&push, outcome, &mut round);
                polling(settle, &mut attempts, &mut ended).await;
            }
            if attempts.is_empty() {
                break;
            }
            // The next attempt to end frees a slot; without one within a second, rows due
            // meanwhile are looked for.
            tokio::select! {
                Some(done) = attempts.next() => ended.push(done),
                () = tokio::time::sleep(POLL) => {}
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

    /// Record how `push`'s attempt went: the row goes, or is retried 20 s later.
    async fn settle(
        &self,
        push: &QueuedPush,
        outcome: Result<bool, Failure>,
        round: &mut PushRound,
    ) {
        let failure = match outcome {
            Ok(delivered) => {
                if delivered {
                    round.delivered += 1;
                    metrics::counter!("pubky_switch_push_webhooks_total", "result" => "delivered")
                        .increment(1);
                } else {
                    round.dropped += 1;
                }
                if let Err(error) = self.store.finish_push(push.id).await {
                    tracing::warn!(%error, "push deliveries: dropping a row");
                }
                return;
            }
            Err(failure) => failure,
        };
        round.failed += 1;
        metrics::counter!("pubky_switch_push_webhooks_total", "result" => failure.kind())
            .increment(1);
        tracing::info!(
            kind = failure.kind(),
            attempt = push.attempts,
            "push deliveries: a webhook failed"
        );
        if let Err(error) = self.store.fail_push(push.id).await {
            tracing::warn!(%error, "push deliveries: scheduling a retry");
        }
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

    /// One attempt of `push`, claimed at `claimed_at`: `Ok(true)` delivered, `Ok(false)`
    /// not to be sent ([`Service::sendable`]). It ends within 10 s of its claim: what comes
    /// before the connection has until 5 s, past which nothing is sent, and the connection
    /// has 5 s.
    async fn attempt(&self, push: &QueuedPush, claimed_at: Instant) -> Result<bool, Failure> {
        let send_by = claimed_at + SEND_BY;
        let signed = tokio::time::timeout_at(send_by, self.signed(push))
            .await
            .map_err(|_| Failure::Late)??;
        let Some((relay_url, signature, body)) = signed else {
            return Ok(false);
        };
        // Checked again: the worker may poll this attempt late, while it claims or settles.
        let now = Instant::now();
        if now > send_by {
            return Err(Failure::Late);
        }
        let deadline = claimed_at + Duration::from_millis(ATTEMPT_DEADLINE_MS.unsigned_abs());
        let post = self.post(&relay_url, &signature, body);
        tokio::time::timeout_at((now + ATTEMPT_TIMEOUT).min(deadline), post)
            .await
            .map_err(|_| Failure::Timeout)?
            .map(|()| true)
    }

    /// `push`'s webhook, signed while its registration is held: the relay URL to send it
    /// to, its `Switch-Signature` and its body. `None` when it isn't to be sent.
    async fn signed(
        &self,
        push: &QueuedPush,
    ) -> Result<Option<(String, String, Vec<u8>)>, Failure> {
        // A hold keeps a connection of the request pool: a few at most (`push_holds`).
        let _turn = self
            .push_holds
            .acquire()
            .await
            .map_err(|_| Failure::Internal)?;
        // A webhook of an account a restored database brought back after its erasure is
        // never sent: the account is erased again first (Switch spec 6.5). Only an identity
        // the ledger holds is looked up.
        if self
            .keys
            .erasure(&push.account)
            .await
            .map_err(|_| Failure::Internal)?
            .is_some()
        {
            let found = self
                .store
                .lookup(&push.account)
                .await
                .map_err(|_| Failure::Internal)?;
            let Some(found) = found else {
                return Ok(None);
            };
            if self
                .erase_if_restored(&push.account, found.created_at_ms)
                .await
                .map_err(|_| Failure::Internal)?
            {
                return Ok(None);
            }
        }
        let Some(held) = self.sendable(push).await? else {
            return Ok(None);
        };
        let signer = self.keys.signer(&push.push_key).await.map_err(|failure| {
            tracing::error!(%failure, "push deliveries: a push key");
            Failure::Internal
        })?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| Failure::Internal)?;
        let reading = self.time.read();
        if !reading.trusted {
            return Err(Failure::Internal);
        }
        let (body, signature) = signed_webhook(
            &signer,
            &held.relay_url,
            &push.handle,
            reading.base_ms,
            &nonce,
        )
        .ok_or(Failure::Refused)?;
        Ok(Some((held.relay_url.clone(), signature, body)))
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
