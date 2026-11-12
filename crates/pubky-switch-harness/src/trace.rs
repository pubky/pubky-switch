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
//! - of each string, its value where it is too short to be key material (under [`SHORT`]
//!   characters: positions, scope names, item types) or where the member is one of the wire
//!   format's fixed words ([`WORDS`]);
//! - of every other string (a key, a hash, a signature, an ID without a name), its length
//!   and which string of the run it is: the same value gets the same number wherever it
//!   shows. The values differ from run to run, so the comparison doesn't compare the
//!   numbers themselves; it checks that two strings are the same in one run exactly where
//!   they are the same in the other ([`crate::compare`]). A `prev` that isn't the hash
//!   delivered before, a head whose `chain_hash` isn't the proof's, or a listed certificate
//!   that isn't the one the record carries, shows;
//! - inside each signed document and each base64url JSON value, the same facts again.
//!
//! What this can't tell: a long string a switch makes itself, echoing nothing a party sent
//! (a chain hash, an item hash, a signature of its own), that is wrong from its first
//! appearance and repeated consistently wherever the right one would show. Two runs read
//! alike then. [`crate::check`] verifies those the harness has the means to verify, in both
//! runs; the rest is checked only as far as the client and the signer check it.
//!
//! An error's `message` is for people (Switch wire 7.6): it isn't kept.
//!
//! Member order is free (Switch wire 1.1), so a reader never depends on it. It is kept all
//! the same, as a fact of its own per object of an answer's body ([`MEMBER_ORDER`]), so
//! that where two switches write their members in different orders the allowed list says
//! so once, instead of the comparison passing over it.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use pubky_switch::http::route::route;
use pubky_switch_client::TransportError;
use pubky_switch_client::transport::{BoxFuture, Request, Response, Transport};
use pubky_switch_core::enc::unb64;
use pubky_switch_core::http::header;
use pubky_switch_core::time::parse_rfc3339;
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use crate::HarnessError;
use crate::check::Checker;

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

/// What starts the name of a fact that holds a check of [`crate::check`] that failed. The
/// comparison reports every such fact, also one both runs show.
pub const VIOLATION: &str = "violation";

/// The fact that says which key an answer's signature verified with.
const SIGNED_WITH: &str = "answer signed with";

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
    /// Call `id` (a Pubky ID or an App ID, as text) `name` from now on. Naming it so again
    /// changes nothing.
    ///
    /// # Errors
    ///
    /// When `name` already stands for another ID, or `id` already has another name: two
    /// IDs under one name would read as one in the trace.
    pub fn add(&self, id: &str, name: &str) -> Result<(), HarnessError> {
        let mut names = lock(&self.names);
        if let Some((other, _)) = names.iter().find(|(_, held)| *held == name)
            && other != id
        {
            return Err(HarnessError::Setup(format!(
                "the name {name} already stands for another ID"
            )));
        }
        if let Some(held) = names.get(id)
            && held != name
        {
            return Err(HarnessError::Setup(format!(
                "the ID named {name} is already named {held}"
            )));
        }
        names.insert(id.to_owned(), name.to_owned());
        Ok(())
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
    checker: Arc<Checker>,
    lines: Mutex<Vec<Line>>,
    /// The number of each long string the run showed, by its value, in order of appearance.
    strings: Mutex<HashMap<String, usize>>,
    distortion: Mutex<Option<Distortion>>,
    /// The faults to apply, each once, in the order added.
    faults: Mutex<Vec<Fault>>,
    /// The enrollments sent, in order, as they were sent.
    enrollments: Mutex<Vec<Request>>,
    /// The requests held back on their way: the method, and a part of the path.
    held_back: Mutex<Option<HeldBack>>,
    /// How many requests are held back now.
    waiting: Mutex<usize>,
}

/// A fault of the network between a party and its switch, applied to the next request of
/// its method whose path contains its text. Either switch can be reached through it: the
/// fault is the transport's, not the switch's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    /// The request reaches the switch and is answered, and the answer is lost on its way:
    /// the caller sees a timeout. The trace keeps what the switch answered.
    LoseAnswer {
        /// The method.
        method: String,
        /// A part of the path.
        path: String,
    },
    /// The request doesn't reach the switch: the caller fails to connect, and nothing is
    /// applied.
    Unreachable {
        /// The method.
        method: String,
        /// A part of the path.
        path: String,
        /// How many matching requests go through first.
        after: usize,
    },
    /// The request doesn't reach the switch, and an error answer comes back in its place
    /// that no key signs, as an intermediary can make one: the caller can't take it for the
    /// switch's word.
    Refuse {
        /// The method.
        method: String,
        /// A part of the path.
        path: String,
        /// The status of the answer.
        status: u16,
        /// Its error `code`.
        code: String,
    },
}

impl Fault {
    fn matches(&self, request: &Request) -> bool {
        let (Fault::LoseAnswer { method, path }
        | Fault::Unreachable { method, path, .. }
        | Fault::Refuse { method, path, .. }) = self;
        request.method == *method && request.path_and_query.contains(path.as_str())
    }
}

/// The requests held back on their way: of this method, their path containing this text.
#[derive(Clone, Debug)]
struct HeldBack {
    method: String,
    path: String,
    /// Whether only the next such request is held.
    only_next: bool,
    /// Whether a request was held under it yet.
    taken: bool,
}

/// The fact that says what a fault did to a request.
const FAULT: &str = "fault";

/// The fact a request's line holds until its answer comes, or its failure.
const UNANSWERED: &str = "unanswered";

/// A change made to what the trace keeps of an answer.
type Distortion = Box<dyn Fn(&Request, &mut Response) + Send + Sync>;

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Recorder({} lines)", lock(&self.lines).len())
    }
}

impl Recorder {
    /// A recorder in front of `inner`, naming IDs with `names` and verifying each answer
    /// with `checker`.
    pub fn new(inner: Arc<dyn Transport>, names: Arc<Names>, checker: Arc<Checker>) -> Self {
        Self {
            inner,
            names,
            checker,
            lines: Mutex::new(Vec::new()),
            strings: Mutex::new(HashMap::new()),
            distortion: Mutex::new(None),
            faults: Mutex::new(Vec::new()),
            enrollments: Mutex::new(Vec::new()),
            held_back: Mutex::new(None),
            waiting: Mutex::new(0),
        }
    }

    /// Keep each answer in the trace as `distort` changes it, as if the switch had answered
    /// so; the caller gets the answer unchanged. For the harness's own tests, which check
    /// that a switch answering differently is noticed where the client itself accepts it.
    pub fn distort(&self, distort: impl Fn(&Request, &mut Response) + Send + Sync + 'static) {
        *lock(&self.distortion) = Some(Box::new(distort));
    }

    /// Apply `fault` to the next request it matches, once.
    pub fn fail_next(&self, fault: Fault) {
        lock(&self.faults).push(fault);
    }

    /// The `nth` enrollment sent through this recorder, from 0, as it was sent.
    pub fn enrollment(&self, nth: usize) -> Option<Request> {
        lock(&self.enrollments).get(nth).cloned()
    }

    /// Hold back every request of `method` whose path contains `path`, from now until
    /// [`Recorder::let_go`]: the caller's request waits on its way, as on a slow network,
    /// while other calls go on. For a flow in which one party's step must not overtake
    /// another's answer.
    pub fn hold_back(&self, method: &str, path: &str) {
        *lock(&self.held_back) = Some(HeldBack {
            method: method.to_owned(),
            path: path.to_owned(),
            only_next: false,
            taken: false,
        });
    }

    /// As [`Recorder::hold_back`], for the next such request only: those after it go
    /// through while it waits. For two parties' requests of one kind that race, where the
    /// flow decides which arrives first.
    pub fn hold_back_next(&self, method: &str, path: &str) {
        *lock(&self.held_back) = Some(HeldBack {
            method: method.to_owned(),
            path: path.to_owned(),
            only_next: true,
            taken: false,
        });
    }

    /// Let the requests [`Recorder::hold_back`] holds go, and hold none back from now on.
    pub fn let_go(&self) {
        *lock(&self.held_back) = None;
    }

    /// How many requests are held back now.
    pub fn held_back_now(&self) -> usize {
        *lock(&self.waiting)
    }

    /// Whether `request` is one to hold back: every matching one, or the first of them.
    fn holds_back(&self, request: &Request) -> bool {
        let mut held = lock(&self.held_back);
        let Some(held) = held.as_mut() else {
            return false;
        };
        let matches =
            request.method == held.method && request.path_and_query.contains(held.path.as_str());
        if !matches || (held.only_next && held.taken) {
            return false;
        }
        held.taken = true;
        true
    }

    /// How many different enrollments were sent through this recorder.
    pub fn enrollments_sent(&self) -> usize {
        lock(&self.enrollments).len()
    }

    /// The faults added and not applied yet.
    pub fn faults_left(&self) -> usize {
        lock(&self.faults).len()
    }

    /// Add an outcome line: what a party returned or raised at this point of the flow.
    /// `value` is kept as a body is, but every string by its value: a flow writes names
    /// and states there, never keys or IDs.
    pub fn outcome(&self, name: &str, value: &Value) {
        let mut facts = BTreeMap::new();
        Facts {
            names: &self.names,
            strings: &self.strings,
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

    /// Give a request its line, holding what was sent, and return where it is.
    fn place(
        &self,
        label: &str,
        facts: &BTreeMap<String, String>,
        call: Option<&'static str>,
    ) -> usize {
        let mut facts = facts.clone();
        facts.insert(UNANSWERED.into(), "the request is in flight".into());
        let mut lines = lock(&self.lines);
        lines.push(Line {
            label: label.to_owned(),
            facts,
            call,
        });
        lines.len() - 1
    }

    /// Put a request's finished line where [`Recorder::place`] put it.
    fn fill(&self, at: usize, line: Line) {
        if let Some(placed) = lock(&self.lines).get_mut(at) {
            *placed = line;
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
            // An app's name carries its identity's.
            (Some(identity), Some(app)) => match self.names.of(app) {
                Some(app) => format!("{{{app}}}"),
                None => format!("{{{}/?}}", name(identity)),
            },
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
            strings: &self.strings,
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
            strings: &self.strings,
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
            // Held back, the request isn't on its way yet: it takes its place in the trace
            // when it goes.
            if self.holds_back(&request) {
                *lock(&self.waiting) += 1;
                while lock(&self.held_back).is_some() {
                    tokio::task::yield_now().await;
                }
                *lock(&self.waiting) -= 1;
            }
            let label = self.label(&request);
            let mut facts = BTreeMap::new();
            self.request_facts(&request, &mut facts);
            let call =
                route(&request.method, &request.path_and_query).map(|route| route.call.name());
            let sent = request.clone();
            if request.method == "POST" && request.path_and_query == "/v1/enroll" {
                let mut enrollments = lock(&self.enrollments);
                // One sent again is the same enrollment, not another.
                if !enrollments.contains(&request) {
                    enrollments.push(request.clone());
                }
            }
            // The line takes its place now, and its answer's facts when the answer comes:
            // of two calls in flight at once, the one sent first comes first in the trace,
            // whichever is answered first.
            let at = self.place(&label, &facts, call);
            let fault = {
                let mut faults = lock(&self.faults);
                let at = faults.iter().position(|fault| fault.matches(&request));
                match at.and_then(|at| faults.get_mut(at)) {
                    // Not yet: this request goes through.
                    Some(Fault::Unreachable { after, .. }) if *after > 0 => {
                        *after -= 1;
                        None
                    }
                    _ => at.map(|at| faults.remove(at)),
                }
            };
            if let Some(Fault::Unreachable { .. }) = fault {
                facts.insert(FAULT.into(), "the request didn't reach the switch".into());
                self.fill(at, Line { label, facts, call });
                return Err(TransportError::Connect("the switch is unreachable".into()));
            }
            if let Some(Fault::Refuse { status, code, .. }) = &fault {
                let refusal = Response {
                    status: *status,
                    headers: Vec::new(),
                    body: serde_json::json!({ "code": code, "message": "not the switch's" })
                        .to_string()
                        .into_bytes(),
                };
                facts.insert(
                    FAULT.into(),
                    "an answer no key signs came back in the switch's place".into(),
                );
                self.answer_facts(&refusal, &mut facts);
                self.fill(at, Line { label, facts, call });
                return Ok(refusal);
            }
            let answer = self.inner.send(request).await;
            match &answer {
                Ok(answer) => {
                    let mut violations = Vec::new();
                    // The signature is of the answer as the switch sent it.
                    let signed = match self.checker.signature(&sent, answer) {
                        Ok(with) => {
                            facts.insert(SIGNED_WITH.into(), with.to_string());
                            Some(with)
                        }
                        Err(violation) => {
                            violations.push(violation);
                            None
                        }
                    };
                    let mut kept = answer.clone();
                    if let Some(distort) = lock(&self.distortion).as_ref() {
                        distort(&sent, &mut kept);
                    }
                    self.answer_facts(&kept, &mut facts);
                    violations.extend(self.checker.contents(&sent, &kept, signed));
                    for (index, violation) in violations.into_iter().enumerate() {
                        facts.insert(format!("{VIOLATION} {}", index + 1), violation);
                    }
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
            if fault.is_some() {
                // The switch answered, and the caller never sees it.
                facts.insert(FAULT.into(), "the answer was lost".into());
                self.fill(at, Line { label, facts, call });
                return Err(TransportError::Timeout);
            }
            self.fill(at, Line { label, facts, call });
            answer
        })
    }
}

/// Collects the facts of JSON values.
struct Facts<'a> {
    names: &'a Names,
    strings: &'a Mutex<HashMap<String, usize>>,
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
            self.out
                .insert(at.to_owned(), "compact signed document".to_owned());
            self.long(&format!("{at} signature"), sig);
            self.value(&format!("{at}~"), None, &carried);
        } else {
            self.long(at, text);
        }
    }

    /// The fact of a long string: its length, and its number among the run's long strings,
    /// the same wherever the same value shows ([`string_number`] reads it back).
    fn long(&mut self, at: &str, text: &str) {
        let number = {
            let mut strings = lock(self.strings);
            let next = strings.len() + 1;
            *strings.entry(text.to_owned()).or_insert(next)
        };
        self.out.insert(
            at.to_owned(),
            format!("string of {}{NUMBER}{number}", text.len()),
        );
    }
}

/// What sets a long string's number off from its length, as in `string of 43 #12`.
const NUMBER: &str = " #";

/// A long string's fact without its number, and the number: `("string of 43", 12)` of
/// `string of 43 #12`. `None` for any other fact.
pub fn string_number(fact: &str) -> Option<(&str, usize)> {
    let (kept, number) = fact.rsplit_once(NUMBER)?;
    if !kept.starts_with("string of ") {
        return None;
    }
    Some((kept, number.parse().ok()?))
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
        names
            .add("ybndrfg8ejkmcpqxot1uwisza345h769", "alice")
            .unwrap();
        let mut out = BTreeMap::new();
        let strings = Mutex::new(HashMap::new());
        Facts {
            names: &names,
            strings: &strings,
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
        // A byte string: its length and its number in the run, never its value.
        assert_eq!(fact("body.kid"), Some("string of 11 #1"));
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
            Some("string of 86 #1")
        );
        let compact = facts_of(&json!({ "cert": format!("{body}.{sig}") }));
        assert_eq!(
            compact.get("body.cert").map(String::as_str),
            Some("compact signed document")
        );
        assert_eq!(
            compact.get("body.cert signature").map(String::as_str),
            Some("string of 86 #1")
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
            Some("string of 12 #1")
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

    /// A recorder in front of a transport that answers every request `200 {}`.
    fn recorder() -> (Recorder, Arc<pubky_switch_client::transport::MockTransport>) {
        let inner = Arc::new(pubky_switch_client::transport::MockTransport::with_handler(
            |_| {
                Ok(Response {
                    status: 200,
                    headers: Vec::new(),
                    body: b"{}".to_vec(),
                })
            },
        ));
        let recorder = Recorder::new(
            inner.clone(),
            Arc::new(Names::default()),
            Arc::new(Checker::default()),
        );
        (recorder, inner)
    }

    fn post(path: &str) -> Request {
        Request {
            method: "POST".into(),
            origin: "https://switch.example".into(),
            path_and_query: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_fault_lost_answer_reaches_the_switch_and_times_out_once() {
        let (recorder, inner) = recorder();
        recorder.fail_next(Fault::LoseAnswer {
            method: "POST".into(),
            path: "/ops".into(),
        });
        // Another call isn't touched.
        assert!(recorder.send(post("/v1/abc/inbox")).await.is_ok());
        let lost = recorder.send(post("/v1/abc/ops")).await;
        assert!(matches!(lost, Err(TransportError::Timeout)), "{lost:?}");
        assert_eq!(inner.requests().len(), 2, "the switch got the request");
        assert!(recorder.send(post("/v1/abc/ops")).await.is_ok(), "once");
        assert_eq!(recorder.faults_left(), 0);
        let trace = recorder.trace();
        let fact = |line: usize, fact: &str| trace.lines[line].facts.get(fact).cloned();
        assert_eq!(fact(1, "fault").as_deref(), Some("the answer was lost"));
        // The trace keeps what the switch answered.
        assert_eq!(fact(1, "status").as_deref(), Some("200"));
        assert_eq!(fact(2, "fault"), None);
    }

    #[tokio::test]
    async fn test_fault_unreachable_applies_nothing() {
        let (recorder, inner) = recorder();
        recorder.fail_next(Fault::Unreachable {
            method: "POST".into(),
            path: "/ops".into(),
            after: 0,
        });
        let failed = recorder.send(post("/v1/abc/ops")).await;
        assert!(
            matches!(failed, Err(TransportError::Connect(_))),
            "{failed:?}"
        );
        assert!(inner.requests().is_empty(), "nothing reached the switch");
        let trace = recorder.trace();
        assert_eq!(
            trace.lines[0].facts.get("fault").map(String::as_str),
            Some("the request didn't reach the switch")
        );
        assert_eq!(trace.lines[0].facts.get("status"), None);
        assert!(recorder.send(post("/v1/abc/ops")).await.is_ok(), "once");
    }

    #[tokio::test]
    async fn test_fault_unreachable_after_lets_the_first_requests_through() {
        let (recorder, inner) = recorder();
        recorder.fail_next(Fault::Unreachable {
            method: "POST".into(),
            path: "/ops".into(),
            after: 2,
        });
        assert!(recorder.send(post("/v1/abc/ops")).await.is_ok());
        assert!(recorder.send(post("/v1/abc/ops")).await.is_ok());
        assert_eq!(recorder.faults_left(), 1);
        assert!(
            recorder.send(post("/v1/abc/ops")).await.is_err(),
            "the third"
        );
        assert_eq!(inner.requests().len(), 2);
        assert_eq!(recorder.faults_left(), 0);
    }

    #[tokio::test]
    async fn test_fault_refuse_answers_unsigned_in_the_switchs_place_once() {
        let (recorder, inner) = recorder();
        recorder.fail_next(Fault::Refuse {
            method: "POST".into(),
            path: "/v1/enroll".into(),
            status: 409,
            code: "conflict".into(),
        });
        // Another call isn't touched.
        let other = recorder.send(post("/v1/abc/ops")).await.unwrap();
        assert_eq!(other.status, 200);
        let refused = recorder.send(post("/v1/enroll")).await.unwrap();
        assert_eq!(refused.status, 409);
        let body: Value = serde_json::from_slice(&refused.body).unwrap();
        assert_eq!(body["code"], "conflict");
        assert!(
            refused.header(header::SERVICE_SIGNATURE).is_none(),
            "no key signs it"
        );
        assert_eq!(inner.requests().len(), 1, "it didn't reach the switch");
        assert_eq!(recorder.faults_left(), 0);
        assert_eq!(
            recorder.send(post("/v1/enroll")).await.unwrap().status,
            200,
            "once"
        );
        let trace = recorder.trace();
        let fact = |line: usize, fact: &str| trace.lines[line].facts.get(fact).cloned();
        assert_eq!(
            fact(1, "fault").as_deref(),
            Some("an answer no key signs came back in the switch's place")
        );
        assert_eq!(fact(1, "status").as_deref(), Some("409"));
        assert_eq!(fact(1, "body.code").as_deref(), Some("text conflict"));
        assert_eq!(fact(1, SIGNED_WITH), None, "the checker isn't asked");
        assert_eq!(fact(2, "fault"), None);
    }

    #[tokio::test]
    async fn test_held_back_request_goes_when_let_go_and_takes_its_place_then() {
        let (recorder, inner) = recorder();
        recorder.hold_back("POST", "/ops");
        let held = recorder.send(post("/v1/abc/ops"));
        let other = async {
            // Another call goes on meanwhile, and nothing of the held one reached the switch.
            let answered = recorder.send(post("/v1/abc/inbox")).await;
            let reached = inner.requests().len();
            recorder.let_go();
            (answered.map(|answer| answer.status), reached)
        };
        let (held, (other, reached)) = futures_util::future::join(held, other).await;
        assert_eq!(other, Ok(200));
        assert_eq!(reached, 1, "only the other call had reached the switch");
        assert_eq!(held.map(|answer| answer.status), Ok(200));
        assert_eq!(inner.requests().len(), 2);
        let labels: Vec<String> = recorder
            .trace()
            .lines
            .iter()
            .map(|line| line.label.clone())
            .collect();
        assert_eq!(
            labels,
            ["public POST /v1/abc/inbox", "public POST /v1/abc/ops"].map(String::from)
        );
        // Nothing is held back afterwards.
        assert!(recorder.send(post("/v1/abc/ops")).await.is_ok());
    }

    #[tokio::test]
    async fn test_held_back_next_holds_one_request_and_lets_the_like_through() {
        let (recorder, inner) = recorder();
        recorder.hold_back_next("POST", "/ops");
        let first = recorder.send(post("/v1/abc/ops"));
        let second = async {
            // The first is waiting; another of its kind goes through.
            while recorder.held_back_now() == 0 {
                tokio::task::yield_now().await;
            }
            let answered = recorder.send(post("/v1/xyz/ops")).await;
            let reached: Vec<String> = inner
                .requests()
                .iter()
                .map(|request| request.path_and_query.clone())
                .collect();
            recorder.let_go();
            (answered.map(|answer| answer.status), reached)
        };
        let (first, (second, reached)) = futures_util::future::join(first, second).await;
        assert_eq!(second, Ok(200));
        assert_eq!(reached, ["/v1/xyz/ops"], "the held one hadn't arrived");
        assert_eq!(first.map(|answer| answer.status), Ok(200));
        assert_eq!(recorder.held_back_now(), 0);
        assert_eq!(inner.requests().len(), 2);
    }

    #[test]
    fn test_outcome_keeps_strings_by_value() {
        let recorder = Recorder::new(
            Arc::new(pubky_switch_client::transport::MockTransport::new()),
            Arc::new(Names::default()),
            Arc::new(Checker::default()),
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
    fn test_long_strings_are_numbered_by_value() {
        let facts = facts_of(&json!({
            "first": "AAAAAAAAAAAAAAAAAAAAAA",
            "other": "BBBBBBBBBBBBBBBBBBBBBB",
            "same": "AAAAAAAAAAAAAAAAAAAAAA",
        }));
        let fact = |at: &str| facts.get(at).map(String::as_str);
        assert_eq!(fact("body.first"), Some("string of 22 #1"));
        assert_eq!(fact("body.other"), Some("string of 22 #2"));
        assert_eq!(fact("body.same"), Some("string of 22 #1"));
        assert_eq!(string_number("string of 22 #2"), Some(("string of 22", 2)));
        assert_eq!(string_number("text 1.4"), None);
        assert_eq!(string_number("number 4"), None);
    }

    #[test]
    fn test_names_refuse_one_name_for_two_ids_and_two_names_for_one() {
        let names = Names::default();
        names.add("abc", "alice/wallet").unwrap();
        names.add("abc", "alice/wallet").unwrap();
        assert!(names.add("xyz", "alice/wallet").is_err());
        assert!(names.add("abc", "bob/wallet").is_err());
        assert_eq!(names.of("abc").as_deref(), Some("alice/wallet"));
    }

    #[test]
    fn test_names_replace_known_path_segments_only() {
        let names = Names::default();
        names.add("abc", "alice").unwrap();
        assert_eq!(
            names.path("/v1/abc/apps/xyz/keys"),
            "/v1/{alice}/apps/xyz/keys"
        );
    }
}
