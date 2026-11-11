//! The Switch client: signed requests, checked answers and a typed call for every endpoint
//! (Switch wire 7, 8.1, 10).
//!
//! A [`SwitchClient`] acts with one set of [`Credentials`] on one account at one switch
//! origin. It signs every request (Switch wire 7.1, 7.2) and checks every answer with the
//! service key it pinned before it uses anything in it. Without a pinned key it sends only
//! an enrollment, whose answer names the key, and the public read, checked with the key its
//! verified `identity.json` names; every other call fails closed before it is sent (Switch
//! wire 7.1, Switch spec 6.1).
//!
//! - [`answers`]: the answer and body types of the calls.
//! - [`Batch`]: signed operations kept with their exact request body, so a retry resends the
//!   same bytes (Switch wire 2.1, 6.4).

pub mod answers;
mod batch;
mod calls;
pub(crate) mod read;

pub use batch::{Batch, Submitted};

use std::sync::{Arc, Mutex, PoisonError};

use pubky_switch_core::chain::{ChainError, SignedHead};
use pubky_switch_core::enc::{b64, pubky_id, zbase32_encode};
use pubky_switch_core::http::{
    self, ErrorCode, RequestHeaders, RequestTarget, TransferHeaders, header,
};
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::labels;
use pubky_switch_core::records::{AppCert, ExportTransfer, IdentityDoc};
use pubky_switch_core::signing::Signs;
use pubky_switch_core::time::{parse_rfc3339, rfc3339_seconds};
use serde_json::Value;

use crate::clock::Clock;
use crate::error::ClientError;
use crate::transport::{Header, Request, Response, Transport};

/// Who signs the requests (Switch wire 7.2).
#[derive(Clone)]
pub enum Credentials {
    /// An app: its identity, its static keys and its certificate, which goes in
    /// `Switch-Cert` when it calls another identity's account.
    App {
        /// The app's identity.
        identity: [u8; 32],
        /// The app's signing and bundle keys.
        keys: AppKeys,
        /// The app's certificate.
        cert: AppCert,
    },
    /// The signer, with the identity key.
    Signer {
        /// The identity.
        identity: [u8; 32],
        /// The identity key, behind the signing interface.
        key: Arc<dyn Signs + Send + Sync>,
    },
    /// The next service of a cooperative move, fetching export chunks from the old service
    /// under the signer's export transfer (Switch wire 3.11, 7.2).
    NextService {
        /// The account's identity.
        identity: [u8; 32],
        /// The next service's key for the account, the one the transfer names in `to`.
        key: Arc<dyn Signs + Send + Sync>,
        /// The signer's export transfer.
        transfer: ExportTransfer,
    },
}

impl std::fmt::Debug for Credentials {
    // Names the caller only: keys never appear.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credentials::App { identity, keys, .. } => f
                .debug_struct("App")
                .field("identity", &pubky_id(identity))
                .field("app_id", &keys.app_id())
                .finish(),
            Credentials::Signer { identity, .. } => f
                .debug_struct("Signer")
                .field("identity", &pubky_id(identity))
                .finish(),
            Credentials::NextService { identity, .. } => f
                .debug_struct("NextService")
                .field("identity", &pubky_id(identity))
                .finish(),
        }
    }
}

impl Credentials {
    /// The caller's identity.
    pub fn identity(&self) -> [u8; 32] {
        match self {
            Credentials::App { identity, .. }
            | Credentials::Signer { identity, .. }
            | Credentials::NextService { identity, .. } => *identity,
        }
    }

    /// The calling app's App ID; `None` for the signer and the next service.
    pub fn app_id(&self) -> Option<[u8; 16]> {
        match self {
            Credentials::App { keys, .. } => Some(keys.app_id_bytes()),
            Credentials::Signer { .. } | Credentials::NextService { .. } => None,
        }
    }

    /// Check that the keys are the ones the identity, the certificate or the transfer name.
    fn check(&self) -> Result<(), ClientError> {
        let ok = match self {
            Credentials::App {
                identity,
                keys,
                cert,
            } => cert.identity() == *identity && cert.signing_key() == keys.signing_public(),
            Credentials::Signer { identity, key } => key.public_key() == *identity,
            Credentials::NextService {
                identity,
                key,
                transfer,
            } => {
                transfer.body().identity == *identity
                    && transfer.body().to.service_key == key.public_key()
            }
        };
        if ok {
            Ok(())
        } else {
            Err(ClientError::Usage(
                "the credentials' keys aren't the ones their identity, certificate or transfer \
                 names"
                    .into(),
            ))
        }
    }

    fn sign(&self, label: &str, fields: &[Vec<u8>]) -> [u8; 64] {
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        match self {
            Credentials::App { keys, .. } => keys.sign_fields(label, &refs),
            Credentials::Signer { key, .. } | Credentials::NextService { key, .. } => {
                key.sign_fields(label, &refs)
            }
        }
    }
}

/// A key behind `dyn Signs`, as a `Sized` signer for the core's generic signing functions.
pub(crate) struct DynSigner<'a>(pub(crate) &'a (dyn Signs + Send + Sync));

impl Signs for DynSigner<'_> {
    fn public_key(&self) -> [u8; 32] {
        self.0.public_key()
    }

    fn sign_fields(&self, label: &str, fields: &[&[u8]]) -> [u8; 64] {
        self.0.sign_fields(label, fields)
    }
}

/// How a request is authenticated, beyond the caller's credentials.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Auth<'a> {
    /// `Switch-Invite-Code`.
    pub(crate) invite_code: Option<&'a str>,
    /// Send `Switch-Cert` even at the caller's own account: the staged head upload (Switch
    /// wire 7.2).
    pub(crate) with_cert: bool,
    /// The unauthenticated public read: no `Switch-*` header at all (Switch wire 7.4.15).
    pub(crate) public: bool,
    /// The signing time to send instead of the clock's: the `current.server_time` of a
    /// `401 stale_timestamp`, for its one retry (Switch wire 7.1).
    pub(crate) timestamp_ms: Option<u64>,
    /// The key that signs a `2xx` answer instead of the pinned one: the pending key named by
    /// a delivery that starts a generation (Switch wire 7.4.2). Other statuses are still
    /// checked with the pinned key.
    pub(crate) success_key: Option<[u8; 32]>,
}

/// The `Content-Type` of a request body (Switch wire 7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Body {
    /// No body.
    Empty,
    /// A JSON body.
    Json,
    /// An envelope.
    Octets,
}

/// A signed request, with its signature as the response signature covers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRequest {
    /// The request.
    pub request: Request,
    /// The 64 bytes of its `Switch-Signature`; `None` for the unauthenticated public read.
    pub signature: Option<[u8; 64]>,
}

/// An answer whose response signature verified with the pinned service key (Switch wire
/// 7.1), with a `2xx` status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedResponse {
    /// The HTTP status.
    pub status: u16,
    /// The body bytes.
    pub body: Vec<u8>,
    /// `Switch-Server-Time`, the identity's service time, in Unix milliseconds.
    pub server_time_ms: u64,
    /// `Switch-Head`, where present and verified with the service key; `None` for one that
    /// doesn't read or verify, which the response signature doesn't cover (Switch wire 7.1).
    pub head: Option<SignedHead>,
}

/// Check a response with the pinned service key before anything in it is used (Switch wire
/// 7.1): its signature over the status, the request signature, `Switch-Server-Time` and the
/// body; then `Switch-Server-Time`; then `Switch-Head`, where present, as a head the service
/// key signed for `account` (Switch wire 6.7). An error status is read into
/// [`ClientError::Switch`].
///
/// The response signature doesn't cover `Switch-Head` (Switch wire 7.1), so anything on the
/// way may change or add one: a header head that doesn't read or doesn't verify is ignored,
/// never evidence against the service. The heads the chain view checks come from the
/// signed bodies.
///
/// `request_signature` is the 64 bytes of the request's `Switch-Signature`, `None` for a
/// request without one.
///
/// # Errors
///
/// [`ClientError::BadServiceSignature`] for a signature that is missing or doesn't verify,
/// [`ClientError::InvalidResponse`] for a server time that doesn't read, and
/// [`ClientError::Switch`] for an error answer.
pub fn check_response(
    service_key: &[u8; 32],
    account: &[u8; 32],
    request_signature: Option<&[u8; 64]>,
    response: &Response,
) -> Result<CheckedResponse, ClientError> {
    let status = response.status;
    let unauthenticated = ClientError::BadServiceSignature { status };
    let signature = response
        .header(header::SERVICE_SIGNATURE)
        .and_then(|text| http::decode_signature(text).ok())
        .ok_or_else(|| unauthenticated.clone())?;
    let server_time = response
        .header(header::SERVER_TIME)
        .ok_or_else(|| unauthenticated.clone())?;
    http::verify_response(
        service_key,
        status,
        request_signature,
        server_time,
        &response.body,
        &signature,
    )
    .map_err(|_| unauthenticated)?;
    // From here on the answer is the service's.
    let server_time_ms = parse_rfc3339(server_time).map_err(|_| {
        ClientError::InvalidResponse("Switch wire 7.1: Switch-Server-Time doesn't parse".into())
    })?;
    let head = verified_head(service_key, account, response);
    if !(200..300).contains(&status) {
        return Err(parse_error(status, &response.body));
    }
    Ok(CheckedResponse {
        status,
        body: response.body.clone(),
        server_time_ms,
        head,
    })
}

/// Verify a head with the service key (Switch wire 6.7).
pub(crate) fn verify_head(
    head: &SignedHead,
    service_key: &[u8; 32],
    account: &[u8; 32],
) -> Result<(), ClientError> {
    head.verify(service_key, account)
        .map_err(|error| ClientError::Chain(ChainError::Signature(error.to_string())))
}

/// `Switch-Head`, where present and verified with the service key for `account`.
fn verified_head(
    service_key: &[u8; 32],
    account: &[u8; 32],
    response: &Response,
) -> Option<SignedHead> {
    response
        .header(header::HEAD)
        .and_then(|text| SignedHead::from_header(text).ok())
        .filter(|head| verify_head(head, service_key, account).is_ok())
}

/// Read a checked error body: `{ "code", "message", "current", "known_version",
/// "retry_after" }` (Switch wire 7.1, 7.6). The code must be one the wire format defines,
/// with the status it fixes.
pub(crate) fn parse_error(status: u16, body: &[u8]) -> ClientError {
    let invalid =
        |why: &str| ClientError::InvalidResponse(format!("Switch wire 7.6: an error body {why}"));
    let Ok(value) = pubky_switch_core::json::parse_json::<Value>(body) else {
        return invalid("isn't strict JSON");
    };
    let Some(code) = value.get("code").and_then(Value::as_str) else {
        return invalid("has no code");
    };
    let Some(code) = ErrorCode::parse(code) else {
        return invalid("names a code the wire format doesn't define");
    };
    if code.status() != status {
        return invalid("has a code of another status");
    }
    let Some(message) = value.get("message").and_then(Value::as_str) else {
        return invalid("has no message");
    };
    ClientError::Switch {
        status,
        code,
        message: message.to_owned(),
        current: value.get("current").cloned().unwrap_or(Value::Null),
        known_version: value.get("known_version").and_then(Value::as_u64),
        retry_after: value.get("retry_after").and_then(Value::as_u64),
    }
}

/// The `current.server_time` of a verified `401 stale_timestamp`: the service's time base,
/// for the one retry's timestamp (Switch wire 7.1, 7.6). It isn't the identity's service
/// time, and counts as no verified service time (Switch spec 10.1).
fn stale_timestamp_hint(checked: &Result<CheckedResponse, ClientError>) -> Option<u64> {
    match checked {
        Err(ClientError::Switch {
            code: ErrorCode::StaleTimestamp,
            current,
            ..
        }) => current
            .get("server_time")
            .and_then(Value::as_str)
            .and_then(|text| parse_rfc3339(text).ok()),
        _ => None,
    }
}

/// Whether a text is safe as a header value and a path segment: visible ASCII without the
/// characters a path or query gives meaning to.
fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
}

/// A client for one account at one switch, acting with one set of credentials.
pub struct SwitchClient {
    origin: String,
    account: [u8; 32],
    credentials: Credentials,
    pinned: Mutex<Option<[u8; 32]>>,
    last_server_time: Mutex<Option<u64>>,
    latest_server_time: Mutex<Option<u64>>,
    transport: Arc<dyn Transport>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for SwitchClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwitchClient")
            .field("origin", &self.origin)
            .field("account", &pubky_id(&self.account))
            .field("credentials", &self.credentials)
            .field("pinned", &self.pinned_key().map(|key| b64(&key)))
            .finish()
    }
}

impl SwitchClient {
    /// A client acting with `credentials` on the account of `account` at the switch
    /// `origin`, exactly as `identity.json` names it in `inbox.url` (Switch wire 7.1).
    ///
    /// `pinned_key` is the account's service key the caller pinned: from the `identity.json`
    /// naming the service or, for the signer, from its enrollment answer or the freeze naming
    /// the next service (Switch wire 7.1). Without one, the client sends only an enrollment
    /// and the public read.
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] if the credentials' keys aren't the ones their identity,
    /// certificate or transfer names, or the next service's credentials name another account
    /// or an origin other than the transfer's old service.
    pub fn new(
        origin: &str,
        account: [u8; 32],
        credentials: Credentials,
        pinned_key: Option<[u8; 32]>,
        transport: Arc<dyn Transport>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ClientError> {
        credentials.check()?;
        if let Credentials::NextService { transfer, .. } = &credentials
            && (credentials.identity() != account || transfer.body().from.url != origin)
        {
            return Err(ClientError::Usage(
                "Switch wire 3.11: the next service fetches from the old service the transfer \
                 names, for its own account"
                    .into(),
            ));
        }
        Ok(Self {
            origin: origin.to_owned(),
            account,
            credentials,
            pinned: Mutex::new(pinned_key),
            last_server_time: Mutex::new(None),
            latest_server_time: Mutex::new(None),
            transport,
            clock,
        })
    }

    /// The switch origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The account's identity.
    pub fn account(&self) -> [u8; 32] {
        self.account
    }

    /// The credentials.
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// The pinned service key, if any.
    pub fn pinned_key(&self) -> Option<[u8; 32]> {
        *self.pinned.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Pin the account's service key, replacing any pinned before: after a key change, the
    /// signer pins the key the delivered `identity.json` names (Switch wire 3.3, 3.7).
    pub fn pin(&self, service_key: [u8; 32]) {
        *self.pinned.lock().unwrap_or_else(PoisonError::into_inner) = Some(service_key);
    }

    /// The `Switch-Server-Time` of the latest answer this client checked with the pinned key
    /// that carries the identity's stamped service time, in Unix milliseconds: a success, or
    /// an error answered once the request verified; `None` before any. An app keeps the
    /// highest service time it verified and measures it against its own clock (Switch spec
    /// 10.1).
    ///
    /// A refusal answered before the request verified carries no stamped time: the service
    /// answers it before the account's lock, with the last time it committed, which may be
    /// days old on an idle account (Switch wire 7.1, 7.2 Order). Such refusals are those
    /// without a verified `Switch-Head` (Switch wire 7.1 "`Switch-Head` on refusals"): every
    /// `401`, among them `stale_timestamp`, a `429` before authentication, a first call
    /// nothing verified, and the `503` of an account behind its key's mark; to an app of
    /// another identity, which is shown no head, every refusal. They count for nothing
    /// here, and so does a `stale_timestamp`'s `current.server_time`.
    pub fn last_server_time(&self) -> Option<u64> {
        *self
            .last_server_time
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The stamped service time of this client's latest call, as
    /// [`SwitchClient::last_server_time`] counts it: `None` when that call got no answer
    /// checked with the pinned key, or one that carries no stamped time. The clock bound is
    /// measured from it (Switch spec 10.1).
    pub(crate) fn latest_server_time(&self) -> Option<u64> {
        *self
            .latest_server_time
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn set_latest(&self, time: Option<u64>) {
        *self
            .latest_server_time
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = time;
    }

    fn note_server_time(
        &self,
        key: &[u8; 32],
        checked: &Result<CheckedResponse, ClientError>,
        response: &Response,
    ) {
        let time = match checked {
            Ok(answer) => Some(answer.server_time_ms),
            // An error answer verified with the pinned key carries the stamped time only once
            // the request verified, which its head shows (Switch wire 7.1).
            Err(ClientError::Switch { .. })
                if verified_head(key, &self.account, response).is_some() =>
            {
                response
                    .header(header::SERVER_TIME)
                    .and_then(|text| parse_rfc3339(text).ok())
            }
            Err(_) => None,
        };
        self.set_latest(time);
        if let Some(time) = time {
            *self
                .last_server_time
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(time);
        }
    }

    /// Whether the account is another identity's than the caller's, so an app sends
    /// `Switch-Cert` (Switch wire 7.1, 7.2).
    pub fn is_foreign(&self) -> bool {
        self.credentials.identity() != self.account
    }

    /// The path `/v1/{id}/{rest}` of this account.
    pub(crate) fn path(&self, rest: &str) -> String {
        format!("/v1/{}/{rest}", pubky_id(&self.account))
    }

    /// The calling app's App ID, for the calls only an app makes.
    pub(crate) fn own_app_id(&self) -> Result<[u8; 16], ClientError> {
        self.credentials
            .app_id()
            .ok_or_else(|| ClientError::Usage("only an app makes this call".into()))
    }

    /// Refuse a call only the signer makes.
    pub(crate) fn signer_only(&self) -> Result<(), ClientError> {
        match self.credentials {
            Credentials::Signer { .. } => Ok(()),
            _ => Err(ClientError::Usage("only the signer makes this call".into())),
        }
    }

    /// Build and sign a request at the client's clock (Switch wire 7.1, 7.2).
    ///
    /// The timestamp is the clock's time to the second. An app calling another identity's
    /// account sends `Switch-Cert`; the next service signs over the transfer label.
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] for an invite code that isn't a token.
    pub fn sign_request(
        &self,
        method: &str,
        path_and_query: &str,
        body: Vec<u8>,
        invite_code: Option<&str>,
    ) -> Result<SignedRequest, ClientError> {
        let content = if body.is_empty() {
            Body::Empty
        } else {
            Body::Json
        };
        self.build(
            method,
            path_and_query,
            body,
            content,
            Auth {
                invite_code,
                ..Auth::default()
            },
        )
    }

    pub(crate) fn build(
        &self,
        method: &str,
        path_and_query: &str,
        body: Vec<u8>,
        content: Body,
        auth: Auth<'_>,
    ) -> Result<SignedRequest, ClientError> {
        let method = method.to_ascii_uppercase();
        let mut headers = Vec::new();
        match content {
            Body::Empty => {}
            Body::Json => headers.push(Header::new("content-type", "application/json")),
            Body::Octets => headers.push(Header::new("content-type", "application/octet-stream")),
        }
        if auth.public {
            return Ok(SignedRequest {
                request: Request {
                    method,
                    origin: self.origin.clone(),
                    path_and_query: path_and_query.to_owned(),
                    headers,
                    body,
                },
                signature: None,
            });
        }
        if let Some(code) = auth.invite_code
            && !is_token(code)
        {
            return Err(ClientError::Usage(
                "Switch wire 1.7: an invite code is a base64url token".into(),
            ));
        }
        let timestamp = rfc3339_seconds(auth.timestamp_ms.unwrap_or_else(|| self.clock.now_ms()));
        let identity = pubky_id(&self.credentials.identity());
        let target = RequestTarget {
            method: &method,
            path_and_query,
            body: &body,
            origin: &self.origin,
        };
        let signature = match &self.credentials {
            Credentials::NextService { transfer, .. } => {
                let transfer_headers = TransferHeaders {
                    timestamp: timestamp.clone(),
                    identity: identity.clone(),
                    transfer: transfer.signed().compact(),
                };
                let signature = self.credentials.sign(
                    labels::sig::TRANSFER_REQUEST,
                    &http::transfer_request_fields(&target, &transfer_headers),
                );
                headers.push(Header::new(header::IDENTITY, &identity));
                headers.push(Header::new(header::TRANSFER, &transfer_headers.transfer));
                signature
            }
            Credentials::App { keys, cert, .. } => {
                let request_headers = RequestHeaders {
                    timestamp: timestamp.clone(),
                    identity: identity.clone(),
                    app: Some(keys.app_id()),
                    cert: (self.is_foreign() || auth.with_cert).then(|| cert.signed().compact()),
                    invite_code: auth.invite_code.map(str::to_owned),
                };
                let signature = self.credentials.sign(
                    labels::sig::HTTP,
                    &http::request_fields(&target, &request_headers),
                );
                push_request_headers(&mut headers, &request_headers);
                signature
            }
            Credentials::Signer { .. } => {
                let request_headers = RequestHeaders {
                    timestamp: timestamp.clone(),
                    identity: identity.clone(),
                    invite_code: auth.invite_code.map(str::to_owned),
                    ..RequestHeaders::default()
                };
                let signature = self.credentials.sign(
                    labels::sig::HTTP,
                    &http::request_fields(&target, &request_headers),
                );
                push_request_headers(&mut headers, &request_headers);
                signature
            }
        };
        headers.push(Header::new(header::TIMESTAMP, &timestamp));
        headers.push(Header::new(header::SIGNATURE, &b64(&signature)));
        Ok(SignedRequest {
            request: Request {
                method,
                origin: self.origin.clone(),
                path_and_query: path_and_query.to_owned(),
                headers,
                body,
            },
            signature: Some(signature),
        })
    }

    /// Sign, send and check a call with the pinned key. Without a pinned key nothing is
    /// sent but the public read (Switch wire 7.1). A verified `401 stale_timestamp` that
    /// carries `current.server_time` is retried once, the same call signed at that time; the
    /// time is used for nothing else, and a second `stale_timestamp` is the answer.
    pub(crate) async fn call(
        &self,
        method: &str,
        path_and_query: &str,
        body: Vec<u8>,
        content: Body,
        auth: Auth<'_>,
    ) -> Result<CheckedResponse, ClientError> {
        let key = match self.pinned_key() {
            Some(key) => key,
            None if auth.public => {
                return self.unpinned_public_read(method, path_and_query).await;
            }
            None => return Err(ClientError::Unpinned),
        };
        self.set_latest(None);
        let retry_body = body.clone();
        let signed = self.build(method, path_and_query, body, content, auth)?;
        let checked = self.send_checked(signed, key, auth.success_key).await?;
        let Some(at) = stale_timestamp_hint(&checked) else {
            return checked;
        };
        let auth = Auth {
            timestamp_ms: Some(at),
            ..auth
        };
        let signed = self.build(method, path_and_query, retry_body, content, auth)?;
        self.send_checked(signed, key, auth.success_key).await?
    }

    /// Send a signed request and check its answer: a `2xx` with `success_key` where given,
    /// anything else with `key`. The outer error is the transport's.
    async fn send_checked(
        &self,
        signed: SignedRequest,
        key: [u8; 32],
        success_key: Option<[u8; 32]>,
    ) -> Result<Result<CheckedResponse, ClientError>, ClientError> {
        let response = self.transport.send(signed.request).await?;
        let key = match success_key {
            Some(success) if (200..300).contains(&response.status) => success,
            _ => key,
        };
        let checked = check_response(&key, &self.account, signed.signature.as_ref(), &response);
        self.note_server_time(&key, &checked, &response);
        Ok(checked)
    }

    /// The public read without a pinned key (Switch wire 7.1 "An unpinned public read",
    /// 7.4.15). The `identity.json` in the answer is verified with the account's identity key
    /// and nothing else is used before the response signature verifies with the service key
    /// that document names, which it does only when the document names this origin. That key
    /// is then pinned. Any answer that can't be checked so, an error included, is
    /// [`ClientError::BadServiceSignature`]: a failed lookup, never a sign that the service
    /// holds no document.
    async fn unpinned_public_read(
        &self,
        method: &str,
        path_and_query: &str,
    ) -> Result<CheckedResponse, ClientError> {
        self.set_latest(None);
        let auth = Auth {
            public: true,
            ..Auth::default()
        };
        let signed = self.build(method, path_and_query, Vec::new(), Body::Empty, auth)?;
        let response = self.transport.send(signed.request).await?;
        let key =
            self.named_service_key(&response.body)
                .ok_or(ClientError::BadServiceSignature {
                    status: response.status,
                })?;
        let checked = check_response(&key, &self.account, None, &response);
        self.note_server_time(&key, &checked, &response);
        if checked.is_ok() {
            self.pin(key);
        }
        checked
    }

    /// The service key an unchecked public-read body names for this origin: that of its
    /// `identity`, once it verifies with the account's identity key; `None` otherwise.
    fn named_service_key(&self, body: &[u8]) -> Option<[u8; 32]> {
        let value: Value = pubky_switch_core::json::parse_json(body).ok()?;
        let signed = read::doc(value.get("identity")?)?;
        let doc = IdentityDoc::verify(&signed, &self.account).ok()?;
        (doc.inbox().url == self.origin).then_some(doc.inbox().service_key)
    }

    /// Send a request this client signed, as built by [`SwitchClient::sign_request`], and
    /// check its answer with the pinned key.
    ///
    /// # Errors
    ///
    /// [`ClientError::Unpinned`] without a pinned key, before anything is sent; otherwise as
    /// [`check_response`].
    pub async fn send(&self, signed: SignedRequest) -> Result<CheckedResponse, ClientError> {
        let key = self.pinned_key().ok_or(ClientError::Unpinned)?;
        self.set_latest(None);
        self.send_checked(signed, key, None).await?
    }

    pub(crate) fn transport(&self) -> &dyn Transport {
        self.transport.as_ref()
    }

    /// The App ID as a path segment.
    pub(crate) fn app_segment(app_id: &[u8; 16]) -> String {
        zbase32_encode(app_id)
    }

    /// Check a path segment the caller supplies, such as a chunk ID.
    pub(crate) fn segment(text: &str) -> Result<&str, ClientError> {
        if is_token(text) {
            Ok(text)
        } else {
            Err(ClientError::Usage(
                "a path segment holds only base64url characters".into(),
            ))
        }
    }
}

fn push_request_headers(headers: &mut Vec<Header>, request: &RequestHeaders) {
    headers.push(Header::new(header::IDENTITY, &request.identity));
    if let Some(app) = &request.app {
        headers.push(Header::new(header::APP, app));
    }
    if let Some(cert) = &request.cert {
        headers.push(Header::new(header::CERT, cert));
    }
    if let Some(code) = &request.invite_code {
        headers.push(Header::new(header::INVITE_CODE, code));
    }
}

#[cfg(test)]
mod tests;
