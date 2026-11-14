//! How requests reach the switch: plain [`Request`] and [`Response`] types and the
//! [`Transport`] trait, with the HTTPS transport (`http` feature) and a scripted one for
//! tests (`test-support`).
//!
//! A transport only carries bytes. Signing requests and checking answers is the client's
//! (Switch wire 7.1); the transport's own duty is where it connects (Switch wire 7.1, 8.2).

#[cfg(feature = "http")]
mod http;
#[cfg(feature = "test-support")]
mod mock;

#[cfg(feature = "http")]
pub use http::{HttpConfig, HttpTransport};
#[cfg(feature = "test-support")]
pub use mock::MockTransport;

use std::future::Future;
use std::pin::Pin;

pub use crate::error::TransportError;

/// A boxed future that can move between threads.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One header of a request or a response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// The name, in lower case as the switch sends them; names are case-insensitive (Switch
    /// wire 7.1).
    pub name: String,
    /// The value, exactly as sent.
    pub value: String,
}

impl Header {
    /// A header.
    pub fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }
}

/// The value of the header `name` in `headers`, compared case-insensitively. A header that
/// appears more than once reads as absent, so no check is made against one copy while
/// another is used.
pub fn header_value<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    let mut found = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name));
    let first = found.next()?;
    if found.next().is_some() {
        return None;
    }
    Some(first.value.as_str())
}

/// How long a call may take, by what it can carry. The client picks the class of every
/// call it makes ([`Request::timeout`]), from the call itself, never from its path; a
/// transport gives each class a timeout (`HttpConfig` for the HTTPS transport).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TimeoutClass {
    /// A small request with a small answer: a write of a document or a setting, a read of
    /// one small value, the read of the signed service time (a feed page with no items,
    /// Switch wire 7.4.4), and a batch of operations that writes no shared record (its
    /// answer is its proofs, or a refusal with at most a claim's view).
    #[default]
    Ordinary,
    /// A request or an answer that can carry about a mebibyte or more (Switch wire 7.1
    /// "Answer sizes"): a paged or listing read, a shared record's view, an upload, and a
    /// batch of operations that writes a shared record, whose `409 conflict` carries the
    /// record's view (Switch wire 7.6).
    Bulk,
    /// The feed's long poll (Switch wire 7.4.4): the service holds the read for up to
    /// `wait_s` seconds, then answers a page as a [`TimeoutClass::Bulk`] read does.
    LongPoll {
        /// The longest the service holds the read, in seconds: the request's `wait`.
        wait_s: u32,
    },
}

/// A request to the switch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The method, in upper case.
    pub method: String,
    /// The switch origin, `https://host[:port]`, which the request signature covers.
    pub origin: String,
    /// The path and query, exactly as signed and sent; the query is never re-encoded (Switch
    /// wire 7.1).
    pub path_and_query: String,
    /// The headers.
    pub headers: Vec<Header>,
    /// The body bytes.
    pub body: Vec<u8>,
    /// How long the call may take: the class the client picked for it. It isn't sent.
    pub timeout: TimeoutClass,
}

impl Request {
    /// The value of the header `name`; see [`header_value`].
    pub fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }

    /// The URL the request goes to: the origin, then the path and query.
    pub fn url(&self) -> String {
        format!("{}{}", self.origin, self.path_and_query)
    }
}

/// A response of the switch, not yet checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The HTTP status.
    pub status: u16,
    /// The headers.
    pub headers: Vec<Header>,
    /// The body bytes.
    pub body: Vec<u8>,
}

impl Response {
    /// The value of the header `name`; see [`header_value`].
    pub fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }
}

/// Carries requests to a switch and their responses back.
///
/// Object-safe, so a client holds an `Arc<dyn Transport>`. An implementation follows no
/// redirects and connects only where the switch origin rules allow (Switch wire 7.1).
pub trait Transport: Send + Sync {
    /// Send one request and return its response, whatever its status.
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_value_is_case_insensitive() {
        let headers = vec![Header::new("Switch-Server-Time", "t")];
        assert_eq!(header_value(&headers, "switch-server-time"), Some("t"));
        assert_eq!(header_value(&headers, "switch-head"), None);
    }

    #[test]
    fn test_header_value_refuses_a_repeated_header() {
        let headers = vec![
            Header::new("switch-head", "a"),
            Header::new("Switch-Head", "b"),
        ];
        assert_eq!(header_value(&headers, "switch-head"), None);
    }
}
