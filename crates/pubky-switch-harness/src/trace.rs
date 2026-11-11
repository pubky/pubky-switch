//! What a run showed: every request, its answer, and the outcomes the flow noted.
//!
//! Two runs of one flow never give the same bytes: keys, nonces and signatures differ. So a
//! [`Trace`] keeps, for each request and answer, the facts that should be the same against
//! any switch that follows the wire format:
//!
//! - who called, the method, and the path with each known ID replaced by its name;
//! - the status and, of an error, its `code` (Switch wire 7.6);
//! - which answer headers are present, and what a signed head in `Switch-Head` says;
//! - of each JSON body, every member's name and type, the length of each array, and the
//!   value of each integer, boolean and time. Both runs use one set of key seeds and one
//!   clock, so sequence numbers, versions, counters and service times must agree;
//! - of each string, its length; its value where it is too short to be key material
//!   (under [`SHORT`] characters: positions, scope names, item types) or where the member is
//!   one of the wire format's fixed words ([`WORDS`]);
//! - inside each signed document and each base64url JSON value, the same facts again.
//!
//! An error's `message` is for people (Switch wire 7.6): it isn't kept.
//!
//! Member order is free (Switch wire 1.1), so a reader never depends on it. It is kept all
//! the same, as a fact of its own per object of an answer's body ([`MEMBER_ORDER`]), so
//! that where two switches write their members in different orders the allowed list says
//! so once, instead of the comparison passing over it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use pubky_switch::http::route::route;
use pubky_switch_client::TransportError;
use pubky_switch_client::transport::{BoxFuture, Request, Response, Transport};
use pubky_switch_core::enc::unb64;
use pubky_switch_core::http::header;
use pubky_switch_core::time::parse_rfc3339;
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

/// The members whose string value is one of the wire format's fixed words or a name the
/// flow chose, kept by value whatever its length: error codes, document kinds, operations,
/// policies, origins, scopes and message kinds.
pub const WORDS: [&str; 14] = [
    "accepts",
    "admission",
    "caps",
    "code",
    "kind",
    "op",
    "origin",
    "permissions",
    "scopes",
    "state",
    "status",
    "step",
    "type",
    "url",
];

/// Strings shorter than this are kept by value: no key, hash, signature or ID of the wire
/// format is this short in text (the shortest, a kid, is 11 characters).
pub const SHORT: usize = 11;

/// What ends the name of the fact that holds an object's member names in the order written.
pub const MEMBER_ORDER: &str = " (member order)";

/// The answer headers whose presence is kept (Switch wire 7.1).
const HEADERS: [&str; 4] = [
    header::HEAD,
    header::SERVER_TIME,
    header::SERVICE_SIGNATURE,
    header::RETRY_AFTER,
];

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The names of the IDs a run uses: Pubky IDs and App IDs, each replaced by its name
/// wherever it shows, so two runs with different keys read alike.
#[derive(Debug, Default)]
pub struct Names {
    names: Mutex<BTreeMap<String, String>>,
}

impl Names {
    /// Call `id` (a Pubky ID or an App ID, as text) `name` from now on.
    pub fn add(&self, id: &str, name: &str) {
        lock(&self.names).insert(id.to_owned(), name.to_owned());
    }

    /// The name of `id`, if it has one.
    pub fn of(&self, id: &str) -> Option<String> {
        lock(&self.names).get(id).cloned()
    }

    /// `text` with every `/`-separated segment that is a known ID replaced by `{name}`.
    fn path(&self, text: &str) -> String {
        text.split('/')
            .map(|segment| match self.of(segment) {
                Some(name) => format!("{{{name}}}"),
                None => segment.to_owned(),
            })
            .collect::<Vec<_>>()
            .join("/")
    }
}

/// One line of a trace: a request with its answer, or an outcome the flow noted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    /// What the line is about: `"<caller> <METHOD> <path>"` for a request, with IDs replaced
    /// by names, or `"outcome <name>"`.
    pub label: String,
    /// The facts kept, by where each was found, such as `status`, `header switch-head` or
    /// `body.head.seq`.
    pub facts: BTreeMap<String, String>,
    /// For a request, the service's name of the call it routes to
    /// ([`pubky_switch::http::route::Call::name`]); `None` for an outcome and for a request
    /// to no route. Not compared: the label says as much.
    pub call: Option<&'static str>,
}

/// Everything one run showed, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trace {
    /// The lines.
    pub lines: Vec<Line>,
}

impl std::fmt::Display for Trace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, line) in self.lines.iter().enumerate() {
            writeln!(f, "{index:3} {}", line.label)?;
            for (fact, value) in &line.facts {
                writeln!(f, "      {fact} = {value}")?;
            }
        }
        Ok(())
    }
}

/// A [`Transport`] that sends each request on and keeps a [`Line`] of it and its answer.
pub struct Recorder {
    inner: Arc<dyn Transport>,
    names: Arc<Names>,
    lines: Mutex<Vec<Line>>,
    distortion: Mutex<Option<Distortion>>,
}

/// A change made to what the trace keeps of an answer.
type Distortion = Box<dyn Fn(&Request, &mut Response) + Send + Sync>;

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Recorder({} lines)", lock(&self.lines).len())
    }
}

impl Recorder {
    /// A recorder in front of `inner`, naming IDs with `names`.
    pub fn new(inner: Arc<dyn Transport>, names: Arc<Names>) -> Self {
        Self {
            inner,
            names,
            lines: Mutex::new(Vec::new()),
            distortion: Mutex::new(None),
        }
    }

    /// Keep each answer in the trace as `distort` changes it, as if the switch had answered
    /// so; the caller gets the answer unchanged. For the harness's own tests, which check
    /// that a switch answering differently is noticed where the client itself accepts it.
    pub fn distort(&self, distort: impl Fn(&Request, &mut Response) + Send + Sync + 'static) {
        *lock(&self.distortion) = Some(Box::new(distort));
    }

    /// Add an outcome line: what a party returned or raised at this point of the flow.
    /// `value` is kept as a body is, but every string by its value: a flow writes names
    /// and states there, never keys or IDs.
    pub fn outcome(&self, name: &str, value: &Value) {
        let mut facts = BTreeMap::new();
        Facts {
            names: &self.names,
            out: &mut facts,
            plain: true,
        }
        .value("outcome", None, value);
        lock(&self.lines).push(Line {
            label: format!("outcome {name}"),
            facts,
            call: None,
        });
    }

    /// The trace so far.
    pub fn trace(&self) -> Trace {
        Trace {
            lines: lock(&self.lines).clone(),
        }
    }

    fn label(&self, request: &Request) -> String {
        let name = |id: &str| self.names.of(id).unwrap_or_else(|| "?".to_owned());
        let caller = match (
            request.header(header::IDENTITY),
            request.header(header::APP),
        ) {
            (None, _) => "public".to_owned(),
            (Some(identity), None) => format!("{{{}}}", name(identity)),
            (Some(identity), Some(app)) => format!("{{{}/{}}}", name(identity), name(app)),
        };
        let (path, _) = request
            .path_and_query
            .split_once('?')
            .unwrap_or((&request.path_and_query, ""));
        format!("{caller} {} {}", request.method, self.names.path(path))
    }

    fn request_facts(&self, request: &Request, out: &mut BTreeMap<String, String>) {
        let mut facts = Facts {
            names: &self.names,
            out,
            plain: false,
        };
        if let Some((_, query)) = request.path_and_query.split_once('?') {
            for pair in query.split('&').filter(|pair| !pair.is_empty()) {
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                let at = format!("request query {name}");
                facts.string(&at, Some(name), value);
            }
        }
        for name in [header::CERT, header::INVITE_CODE] {
            if request.header(name).is_some() {
                facts
                    .out
                    .insert(format!("request header {name}"), "present".into());
            }
        }
        facts.body("request body", &request.body);
    }

    fn answer_facts(&self, answer: &Response, out: &mut BTreeMap<String, String>) {
        let mut facts = Facts {
            names: &self.names,
            out,
            plain: false,
        };
        facts.out.insert("status".into(), answer.status.to_string());
        for name in HEADERS {
            match answer.header(name) {
                None => {
                    facts.out.insert(format!("header {name}"), "absent".into());
                }
                Some(value) => {
                    let at = format!("header {name}");
                    facts.out.insert(at.clone(), "present".into());
                    if name != header::SERVICE_SIGNATURE {
                        facts.string(&at, None, value);
                    }
                }
            }
        }
        facts.body("body", &answer.body);
        if answer.status >= 400 {
            // For people, not for programs (Switch wire 7.6).
            facts.out.remove("body.message");
        }
        if let Ok(written) = serde_json::from_slice::<Written>(&answer.body) {
            written.orders("body", facts.out);
        }
    }
}

impl Transport for Recorder {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        Box::pin(async move {
            let label = self.label(&request);
            let mut facts = BTreeMap::new();
            self.request_facts(&request, &mut facts);
            let call =
                route(&request.method, &request.path_and_query).map(|route| route.call.name());
            let sent = request.clone();
            let answer = self.inner.send(request).await;
            match &answer {
                Ok(answer) => {
                    let mut kept = answer.clone();
                    if let Some(distort) = lock(&self.distortion).as_ref() {
                        distort(&sent, &mut kept);
                    }
                    self.answer_facts(&kept, &mut facts);
                }
                Err(error) => {
                    let kind = match error {
                        TransportError::Refused(_) => "refused",
                        TransportError::Connect(_) => "connect",
                        TransportError::Timeout => "timeout",
                        TransportError::TooLarge(_) => "too large",
                        TransportError::InvalidRequest(_) => "invalid request",
                        _ => "other",
                    };
                    facts.insert("transport error".into(), kind.into());
                }
            }
            lock(&self.lines).push(Line { label, facts, call });
            answer
        })
    }
}

/// Collects the facts of JSON values.
struct Facts<'a> {
    names: &'a Names,
    out: &'a mut BTreeMap<String, String>,
    /// Keep every string by its value.
    plain: bool,
}

impl Facts<'_> {
    /// The facts of a body: of its JSON, or its length when it isn't JSON.
    fn body(&mut self, at: &str, bytes: &[u8]) {
        if bytes.is_empty() {
            self.out.insert(at.to_owned(), "empty".into());
            return;
        }
        match serde_json::from_slice::<Value>(bytes) {
            Ok(value) => self.value(at, None, &value),
            Err(_) => {
                self.out
                    .insert(at.to_owned(), format!("{} bytes, not JSON", bytes.len()));
            }
        }
    }

    /// The facts of `value`, found at `at`; `member` is its name in its object.
    fn value(&mut self, at: &str, member: Option<&str>, value: &Value) {
        match value {
            Value::Null => {
                self.out.insert(at.to_owned(), "null".into());
            }
            Value::Bool(flag) => {
                self.out.insert(at.to_owned(), format!("bool {flag}"));
            }
            Value::Number(number) => {
                self.out.insert(at.to_owned(), format!("number {number}"));
            }
            Value::String(text) => self.string(at, member, text),
            Value::Array(items) => {
                self.out
                    .insert(at.to_owned(), format!("array of {}", items.len()));
                for (index, item) in items.iter().enumerate() {
                    self.value(&format!("{at}[{index}]"), member, item);
                }
            }
            Value::Object(members) => {
                // No count: each member that only one run shows is a difference of its own.
                self.out.insert(at.to_owned(), "object".into());
                for (name, member) in members {
                    self.value(&format!("{at}.{name}"), Some(name), member);
                }
            }
        }
    }

    /// The facts of a string: a known ID's name, a time's value, the value of a short string
    /// or a fixed word, the facts of the JSON it carries in base64url (alone, or as a compact
    /// signed document's body), or its length.
    fn string(&mut self, at: &str, member: Option<&str>, text: &str) {
        if let Some(name) = self.names.of(text) {
            self.out.insert(at.to_owned(), format!("id {{{name}}}"));
        } else if parse_rfc3339(text).is_ok() {
            self.out.insert(at.to_owned(), format!("time {text}"));
        } else if self.plain
            || text.len() < SHORT
            || member.is_some_and(|member| WORDS.contains(&member))
        {
            self.out.insert(at.to_owned(), format!("text {text}"));
        } else if let Some(carried) = carried_json(text) {
            self.out
                .insert(at.to_owned(), "string carrying JSON".to_owned());
            self.value(&format!("{at}~"), None, &carried);
        } else if let Some((body, sig)) = text.split_once('.')
            && let Some(carried) = carried_json(body)
        {
            // A compact signed document (Switch wire 2.2).
            self.out.insert(
                at.to_owned(),
                format!("compact signed document, signature of {}", sig.len()),
            );
            self.value(&format!("{at}~"), None, &carried);
        } else {
            self.out
                .insert(at.to_owned(), format!("string of {}", text.len()));
        }
    }
}

/// A JSON value as written: its objects' members in the order of the text, which a
/// [`Value`] doesn't keep.
enum Written {
    Object(Vec<(String, Written)>),
    Array(Vec<Written>),
    Other,
}

impl Written {
    /// A [`MEMBER_ORDER`] fact for each object with two members or more, found at `at`.
    fn orders(&self, at: &str, out: &mut BTreeMap<String, String>) {
        match self {
            Written::Object(members) => {
                if members.len() > 1 {
                    let names: Vec<&str> = members.iter().map(|(name, _)| name.as_str()).collect();
                    out.insert(format!("{at}{MEMBER_ORDER}"), names.join(", "));
                }
                for (name, member) in members {
                    member.orders(&format!("{at}.{name}"), out);
                }
            }
            Written::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    item.orders(&format!("{at}[{index}]"), out);
                }
            }
            Written::Other => {}
        }
    }
}

impl<'de> Deserialize<'de> for Written {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AsWritten;

        impl<'de> Visitor<'de> for AsWritten {
            type Value = Written;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON value")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Written, A::Error> {
                let mut members = Vec::new();
                while let Some(member) = map.next_entry::<String, Written>()? {
                    members.push(member);
                }
                Ok(Written::Object(members))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Written, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element::<Written>()? {
                    items.push(item);
                }
                Ok(Written::Array(items))
            }

            fn visit_bool<E>(self, _: bool) -> Result<Written, E> {
                Ok(Written::Other)
            }

            fn visit_i64<E>(self, _: i64) -> Result<Written, E> {
                Ok(Written::Other)
            }

            fn visit_u64<E>(self, _: u64) -> Result<Written, E> {
                Ok(Written::Other)
            }

            fn visit_f64<E>(self, _: f64) -> Result<Written, E> {
                Ok(Written::Other)
            }

            fn visit_str<E>(self, _: &str) -> Result<Written, E> {
                Ok(Written::Other)
            }

            fn visit_unit<E>(self) -> Result<Written, E> {
                Ok(Written::Other)
            }
        }

        deserializer.deserialize_any(AsWritten)
    }
}

/// The JSON object `text` carries in base64url, if it carries one.
fn carried_json(text: &str) -> Option<Value> {
    // The base64url of `{"`.
    if !text.starts_with("eyJ") {
        return None;
    }
    let bytes = unb64(text).ok()?;
    serde_json::from_slice::<Value>(&bytes)
        .ok()
        .filter(Value::is_object)
}

#[cfg(test)]
mod tests {
    use pubky_switch_core::enc::b64;
    use serde_json::json;

    use super::*;

    fn facts_of(value: &Value) -> BTreeMap<String, String> {
        let names = Names::default();
        names.add("ybndrfg8ejkmcpqxot1uwisza345h769", "alice");
        let mut out = BTreeMap::new();
        Facts {
            names: &names,
            out: &mut out,
            plain: false,
        }
        .value("body", None, value);
        out
    }

    #[test]
    fn test_facts_keep_names_types_lengths_and_plain_values() {
        let facts = facts_of(&json!({
            "seq": 7,
            "frozen": false,
            "recovery": null,
            "server_time": "2026-01-01T00:00:00.000Z",
            "identity": "ybndrfg8ejkmcpqxot1uwisza345h769",
            "code": "not_current",
            "kid": "AAAAAAAAAAA",
            "next": "1.4",
            "apps": [{"n": 1}, {"n": 2}],
        }));
        let fact = |at: &str| facts.get(at).map(String::as_str);
        assert_eq!(fact("body"), Some("object"));
        assert_eq!(fact("body.seq"), Some("number 7"));
        assert_eq!(fact("body.frozen"), Some("bool false"));
        assert_eq!(fact("body.recovery"), Some("null"));
        assert_eq!(
            fact("body.server_time"),
            Some("time 2026-01-01T00:00:00.000Z")
        );
        assert_eq!(fact("body.identity"), Some("id {alice}"));
        assert_eq!(fact("body.code"), Some("text not_current"));
        // A byte string: its length, never its value.
        assert_eq!(fact("body.kid"), Some("string of 11"));
        // Too short to be one: its value.
        assert_eq!(fact("body.next"), Some("text 1.4"));
        assert_eq!(fact("body.apps"), Some("array of 2"));
        assert_eq!(fact("body.apps[1].n"), Some("number 2"));
    }

    #[test]
    fn test_facts_read_inside_signed_documents() {
        let body = b64(br#"{"seq":3,"chain_hash":"AAAA"}"#);
        let sig = b64(&[7; 64]);
        let carrying = facts_of(&json!({ "head": { "body": body, "sig": sig } }));
        assert_eq!(
            carrying.get("body.head.body~.seq").map(String::as_str),
            Some("number 3")
        );
        assert_eq!(
            carrying.get("body.head.sig").map(String::as_str),
            Some("string of 86")
        );
        let compact = facts_of(&json!({ "cert": format!("{body}.{sig}") }));
        assert_eq!(
            compact.get("body.cert").map(String::as_str),
            Some("compact signed document, signature of 86")
        );
        assert_eq!(
            compact.get("body.cert~.seq").map(String::as_str),
            Some("number 3")
        );
    }

    #[test]
    fn test_facts_of_a_string_that_only_looks_like_carried_json() {
        // Starts like base64url JSON, and isn't: kept by its length.
        let facts = facts_of(&json!({ "value": "eyJ-not-json" }));
        assert!(carried_json("eyJ-not-json").is_none());
        assert_eq!(
            facts.get("body.value").map(String::as_str),
            Some("string of 12")
        );
    }

    #[test]
    fn test_member_order_is_kept_as_written_for_each_object() {
        let text = br#"{"type":"entry","seq":6,"cert":{"sig":"s","body":"b"},"list":[{"b":1,"a":2}],"one":{"only":1}}"#;
        let written: Written = serde_json::from_slice(text).unwrap();
        let mut facts = BTreeMap::new();
        written.orders("body", &mut facts);
        let fact = |at: &str| facts.get(at).map(String::as_str);
        assert_eq!(
            fact("body (member order)"),
            Some("type, seq, cert, list, one")
        );
        assert_eq!(fact("body.cert (member order)"), Some("sig, body"));
        assert_eq!(fact("body.list[0] (member order)"), Some("b, a"));
        // One member has no order.
        assert_eq!(fact("body.one (member order)"), None);
        assert_eq!(facts.len(), 3);
    }

    #[test]
    fn test_outcome_keeps_strings_by_value() {
        let recorder = Recorder::new(
            Arc::new(pubky_switch_client::transport::MockTransport::new()),
            Arc::new(Names::default()),
        );
        recorder.outcome("received", &json!({ "events": ["MessageReceived"] }));
        let trace = recorder.trace();
        assert_eq!(trace.lines[0].label, "outcome received");
        assert_eq!(
            trace.lines[0]
                .facts
                .get("outcome.events[0]")
                .map(String::as_str),
            Some("text MessageReceived")
        );
    }

    #[test]
    fn test_names_replace_known_path_segments_only() {
        let names = Names::default();
        names.add("abc", "alice");
        assert_eq!(
            names.path("/v1/abc/apps/xyz/keys"),
            "/v1/{alice}/apps/xyz/keys"
        );
    }
}
