//! Strict JSON (Switch wire 1.1).
//!
//! Every Switch document is one UTF-8 JSON value without a byte order mark, with no
//! duplicate member names at any depth (compared after unescaping), no lone surrogates, and
//! every number an integer from 0 to 2^53 - 1 written without sign, fraction or exponent.
//! The number rule runs on the whole document when it is parsed, before any field is read,
//! and skips only the opaque members the document names by path.

use std::collections::HashSet;

use serde::de::{self, DeserializeOwned, DeserializeSeed, Visitor};

use crate::error::{Error, Result, invalid};

/// The largest integer a Switch document may carry, 2^53 - 1, so every binding reads it
/// exactly (Switch wire 1.1).
pub const MAX_INT: u64 = (1 << 53) - 1;

/// A member of a message body that a protocol names as opaque (Switch wire 1.1).
///
/// An opaque member, and everything below it, may hold any JSON number; the switch and its
/// readers never read it as a number. The Switch names no opaque member of message bodies
/// itself: each protocol names its own (Switch spec 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpaqueMember<'a> {
    /// The message `kind` the rule applies to, or `None` for every kind.
    pub kind: Option<&'a str>,
    /// The member of the message's `body` that is opaque.
    pub member: &'a str,
}

/// The document a JSON text is read as, which names its opaque members (Switch wire 1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Doc<'a> {
    /// No opaque members: certificates, records, `identity.json`, key bundle plaintexts,
    /// shared record values, requests and most answers.
    Plain,
    /// A message (Switch wire 5.1), with the opaque members of its `body` that its protocol
    /// names.
    Message(&'a [OpaqueMember<'a>]),
    /// An operation body (Switch wire 6.1): `context` when `op` is `invite_code.put`.
    Op,
    /// A service transition body (Switch wire 6.5): `context` when `type` is
    /// `conversation.add`.
    ServiceOp,
    /// A signed document's body read before its signature names its kind: the rules of
    /// [`Doc::Op`] and [`Doc::ServiceOp`], which no other signed document matches.
    SignedBody,
    /// A `GET /feed` page (Switch wire 7.5): the `context` of an `entry` or `chain` item.
    FeedPage,
    /// A `GET /allow` answer (Switch wire 7.4.6): each conversation entry's `context`.
    AllowList,
    /// An export chunk (Switch wire 10.3): the `context` of a `chain`, `entry`,
    /// `conversation` or `invite_code` part.
    ExportChunk,
}

impl Doc<'_> {
    /// The document an answer's body is, by the call it answers: a feed page and the
    /// lists carry invite code contexts; other answers have no opaque members.
    pub fn of_answer(method: &str, path: &str) -> Doc<'static> {
        let path = path.split('?').next().unwrap_or_default();
        match (method, path.rsplit('/').next().unwrap_or_default()) {
            ("GET", "feed") => Doc::FeedPage,
            ("GET", "allow") => Doc::AllowList,
            _ => Doc::Plain,
        }
    }
}

/// Check `bytes` as a strict JSON document without opaque members, then decode it.
///
/// # Errors
///
/// [`Error::Invalid`] if the bytes break a rule of Switch wire 1.1 or don't decode as `T`.
pub fn parse_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    parse_json_as(bytes, Doc::Plain)
}

/// Check `bytes` as a strict JSON document read as `doc`, then decode it.
///
/// # Errors
///
/// [`Error::Invalid`] if the bytes break a rule of Switch wire 1.1 or don't decode as `T`.
pub fn parse_json_as<T: DeserializeOwned>(bytes: &[u8], doc: Doc<'_>) -> Result<T> {
    check_json_as(bytes, doc)?;
    Ok(serde_json::from_slice(bytes)?)
}

/// Check that `bytes` are a strict JSON document without opaque members (Switch wire 1.1).
///
/// # Errors
///
/// [`Error::Invalid`] naming the rule that failed.
pub fn check_json(bytes: &[u8]) -> Result<()> {
    check_json_as(bytes, Doc::Plain)
}

/// Check that `bytes` are a strict JSON document read as `doc` (Switch wire 1.1).
///
/// # Errors
///
/// [`Error::Invalid`] naming the rule that failed: a byte order mark, anything after the
/// value but whitespace, a duplicate member name, a lone surrogate, or a number outside the
/// opaque members that isn't an integer from 0 to 2^53 - 1.
pub fn check_json_as(bytes: &[u8], doc: Doc<'_>) -> Result<()> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return invalid("Switch wire 1.1: JSON with a byte order mark");
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let outcome = Strict {
        node: Node::Top(doc),
        capture: false,
    }
    .deserialize(&mut deserializer)?;
    deserializer.end()?;
    // Every condition is decided at the object that holds it; one left over can only come
    // from a malformed document.
    if let Some((_, why)) = outcome.pending.into_iter().next() {
        return Err(Error::Invalid(why));
    }
    Ok(())
}

/// The bytes a top-level member's value takes in a JSON object as written, from its first
/// byte to its last, whitespace and escapes inside it included (Switch wire 6.2 measures an
/// invite code's `context` so, never a re-serialization). `None` if `bytes` isn't an object
/// or has no such member. Meant for a document the strict reader took, which has no
/// duplicate member names.
pub(crate) fn member_span(bytes: &[u8], name: &str) -> Option<std::ops::Range<usize>> {
    let mut i = skip_whitespace(bytes, 0);
    if bytes.get(i) != Some(&b'{') {
        return None;
    }
    i = i.saturating_add(1);
    loop {
        i = skip_whitespace(bytes, i);
        match bytes.get(i)? {
            b'}' => return None,
            b',' => {
                i = i.saturating_add(1);
                continue;
            }
            _ => {}
        }
        let key_end = skip_string(bytes, i)?;
        let key: String = serde_json::from_slice(bytes.get(i..key_end)?).ok()?;
        i = skip_whitespace(bytes, key_end);
        if bytes.get(i) != Some(&b':') {
            return None;
        }
        let start = skip_whitespace(bytes, i.saturating_add(1));
        let end = skip_value(bytes, start)?;
        if key == name {
            return Some(start..end);
        }
        i = end;
    }
}

fn skip_whitespace(bytes: &[u8], mut i: usize) -> usize {
    while matches!(bytes.get(i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        i = i.saturating_add(1);
    }
    i
}

/// The index just after the string that starts at `i`.
fn skip_string(bytes: &[u8], i: usize) -> Option<usize> {
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    let mut j = i.saturating_add(1);
    loop {
        match bytes.get(j)? {
            b'\\' => j = j.saturating_add(2),
            b'"' => return Some(j.saturating_add(1)),
            _ => j = j.saturating_add(1),
        }
    }
}

/// The index just after the value that starts at `i`.
fn skip_value(bytes: &[u8], i: usize) -> Option<usize> {
    match bytes.get(i)? {
        b'"' => skip_string(bytes, i),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut j = i;
            loop {
                match bytes.get(j)? {
                    b'"' => {
                        j = skip_string(bytes, j)?;
                        continue;
                    }
                    b'{' | b'[' => depth = depth.saturating_add(1),
                    b'}' | b']' => {
                        depth = depth.checked_sub(1)?;
                        if depth == 0 {
                            return Some(j.saturating_add(1));
                        }
                    }
                    _ => {}
                }
                j = j.saturating_add(1);
            }
        }
        _ => {
            let mut j = i;
            while bytes
                .get(j)
                .is_some_and(|b| !matches!(b, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r'))
            {
                j = j.saturating_add(1);
            }
            Some(j)
        }
    }
}

/// Check that `text` is a lower-case UUID version 4: `8-4-4-4-12` hex, version nibble 4,
/// variant bits `10` (Switch wire 1.7).
///
/// # Errors
///
/// [`Error::Invalid`] for any other form, upper case and other versions included.
pub fn check_uuid_v4(text: &str) -> Result<()> {
    let bytes = text.as_bytes();
    let hyphens = [8, 13, 18, 23];
    let shape = bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| {
            if hyphens.contains(&i) {
                *b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(b)
            }
        });
    if !shape
        || bytes.get(14) != Some(&b'4')
        || !matches!(bytes.get(19), Some(b'8' | b'9' | b'a' | b'b'))
    {
        return invalid("Switch wire 1.7: not a lower-case UUID v4");
    }
    Ok(())
}

/// Refuse a JSON object with a member outside `allowed`, for the documents where an
/// unknown member must never be skipped silently (Switch wire 1.1).
///
/// # Errors
///
/// [`Error::Invalid`] if `value` isn't an object or holds a member `allowed` doesn't list.
pub fn reject_unknown_members(
    value: &serde_json::Value,
    allowed: &[&str],
    what: &str,
) -> Result<()> {
    let Some(object) = value.as_object() else {
        return invalid(format!("Switch wire 1.1: {what} isn't a JSON object"));
    };
    // The member's name is the refused document's text, so the reason doesn't repeat it.
    if object.keys().any(|k| !allowed.contains(&k.as_str())) {
        return invalid(format!("Switch wire 1.1: an unknown member in {what}"));
    }
    Ok(())
}

/// Where the strict check is within a document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Node<'a> {
    /// Checked, with no opaque member at or below it.
    Checked,
    /// Opaque: any number.
    Opaque,
    /// Opaque only if the condition holds. It is decided at an object at or above this one,
    /// by a member that may come later, so a number that isn't an integer is noted and
    /// judged there.
    Unless(Cond<'a>),
    /// The top level of a document.
    Top(Doc<'a>),
    /// A message's `body`, with its protocol's opaque members.
    MessageBody(&'a [OpaqueMember<'a>]),
    /// A feed page's `items`, and one item.
    FeedItems,
    FeedItem,
    /// A `GET /allow` answer's `conversations`, and one entry.
    Conversations,
    Conversation,
    /// An export chunk's `parts`, and one part.
    Parts,
    Part,
}

/// What makes a member opaque, decided by a member beside it or above it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cond<'a> {
    /// The message's `kind` is one its protocol names for this body member.
    MessageKind(&'a str),
    /// The operation's `op` is `invite_code.put`.
    InviteCodePut,
    /// The transition's `type` is `conversation.add`.
    ConversationAdd,
    /// Either of the two above.
    InviteContext,
    /// The feed item's `type` is `entry` or `chain`.
    FeedContext,
    /// The export part's `part` is `chain`, `entry`, `conversation` or `invite_code`.
    PartContext,
}

impl<'a> Node<'a> {
    /// The node of member `key` of an object at this node.
    fn member(self, key: &str) -> Node<'a> {
        match (self, key) {
            (Node::Opaque, _) => Node::Opaque,
            (Node::Unless(cond), _) => Node::Unless(cond),
            (Node::Top(Doc::Message(rules)), "body") => Node::MessageBody(rules),
            (Node::MessageBody(rules), _) => {
                let mut any_kind = false;
                let mut named = None;
                for rule in rules.iter().filter(|r| r.member == key) {
                    match rule.kind {
                        None => any_kind = true,
                        Some(_) => named = Some(rule.member),
                    }
                }
                match (any_kind, named) {
                    (true, _) => Node::Opaque,
                    (false, Some(member)) => Node::Unless(Cond::MessageKind(member)),
                    (false, None) => Node::Checked,
                }
            }
            (Node::Top(Doc::Op), "context") => Node::Unless(Cond::InviteCodePut),
            (Node::Top(Doc::ServiceOp), "context") => Node::Unless(Cond::ConversationAdd),
            (Node::Top(Doc::SignedBody), "context") => Node::Unless(Cond::InviteContext),
            (Node::Top(Doc::FeedPage), "items") => Node::FeedItems,
            (Node::FeedItem, "context") => Node::Unless(Cond::FeedContext),
            (Node::Top(Doc::AllowList), "conversations") => Node::Conversations,
            (Node::Conversation, "context") => Node::Opaque,
            (Node::Top(Doc::ExportChunk), "parts") => Node::Parts,
            (Node::Part, "context") => Node::Unless(Cond::PartContext),
            _ => Node::Checked,
        }
    }

    /// The node of an element of an array at this node.
    fn element(self) -> Node<'a> {
        match self {
            Node::Opaque => Node::Opaque,
            Node::Unless(cond) => Node::Unless(cond),
            Node::FeedItems => Node::FeedItem,
            Node::Conversations => Node::Conversation,
            Node::Parts => Node::Part,
            _ => Node::Checked,
        }
    }

    /// Whether member `key` of an object at this node decides a condition, so its text is
    /// kept.
    fn decides_by(self, key: &str) -> bool {
        matches!(
            (self, key),
            (Node::Top(Doc::Message(_)), "kind")
                | (Node::Top(Doc::Op | Doc::SignedBody), "op")
                | (Node::Top(Doc::ServiceOp | Doc::SignedBody), "type")
                | (Node::FeedItem, "type")
                | (Node::Part, "part")
        )
    }

    /// Whether `cond` holds, if an object at this node decides it, given the texts of its
    /// deciding members.
    fn decide(self, cond: Cond<'_>, texts: &[(String, String)]) -> Option<bool> {
        let is = |key: &str, values: &[&str]| {
            texts
                .iter()
                .any(|(k, v)| k == key && values.contains(&v.as_str()))
        };
        match (self, cond) {
            (Node::Top(Doc::Message(rules)), Cond::MessageKind(member)) => {
                Some(rules.iter().any(|rule| {
                    rule.member == member && rule.kind.is_some_and(|kind| is("kind", &[kind]))
                }))
            }
            (Node::Top(Doc::Op), Cond::InviteCodePut) => Some(is("op", &["invite_code.put"])),
            (Node::Top(Doc::ServiceOp), Cond::ConversationAdd) => {
                Some(is("type", &["conversation.add"]))
            }
            (Node::Top(Doc::SignedBody), Cond::InviteContext) => {
                Some(is("op", &["invite_code.put"]) || is("type", &["conversation.add"]))
            }
            (Node::FeedItem, Cond::FeedContext) => Some(is("type", &["entry", "chain"])),
            (Node::Part, Cond::PartContext) => Some(is(
                "part",
                &["chain", "entry", "conversation", "invite_code"],
            )),
            _ => None,
        }
    }
}

/// What checking one value found: numbers under a condition not decided yet (the condition
/// and why the number isn't an integer), and the value's text when its object keeps it to
/// decide a condition.
#[derive(Default)]
struct Outcome<'a> {
    pending: Vec<(Cond<'a>, String)>,
    text: Option<String>,
}

/// The strict checker: no duplicate names at any depth, and every number a wire integer
/// outside the opaque members.
struct Strict<'a> {
    node: Node<'a>,
    capture: bool,
}

impl<'a> Strict<'a> {
    /// A number that isn't a wire integer: refused where checked, noted under a condition,
    /// accepted where opaque.
    fn number<E: de::Error>(&self, why: &str) -> std::result::Result<Outcome<'a>, E> {
        match self.node {
            Node::Opaque => Ok(Outcome::default()),
            Node::Unless(cond) => Ok(Outcome {
                pending: vec![(cond, why.to_owned())],
                text: None,
            }),
            _ => Err(E::custom(why)),
        }
    }
}

impl<'de, 'a> DeserializeSeed<'de> for Strict<'a> {
    type Value = Outcome<'a>;
    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Outcome<'a>, D::Error> {
        deserializer.deserialize_any(self)
    }
}

// The reasons below never repeat a value or a name: the document may be decrypted plaintext.
impl<'de, 'a> Visitor<'de> for Strict<'a> {
    type Value = Outcome<'a>;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON")
    }
    fn visit_bool<E>(self, _: bool) -> std::result::Result<Outcome<'a>, E> {
        Ok(Outcome::default())
    }
    // serde_json gives a negative integer as i64, a non-negative one as u64, and a number
    // with a fraction or an exponent, or one beyond u64, as f64.
    fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Outcome<'a>, E> {
        if value < 0 {
            return self.number("Switch wire 1.1: a negative integer");
        }
        Ok(Outcome::default())
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Outcome<'a>, E> {
        if value > MAX_INT {
            return self.number("Switch wire 1.1: an integer above 2^53 - 1");
        }
        Ok(Outcome::default())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Outcome<'a>, E> {
        self.number("Switch wire 1.1: a number with a fraction or an exponent")
    }
    fn visit_str<E>(self, value: &str) -> std::result::Result<Outcome<'a>, E> {
        Ok(Outcome {
            pending: Vec::new(),
            text: self.capture.then(|| value.to_owned()),
        })
    }
    fn visit_unit<E>(self) -> std::result::Result<Outcome<'a>, E> {
        Ok(Outcome::default())
    }
    fn visit_seq<A: de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Outcome<'a>, A::Error> {
        let mut pending = Vec::new();
        let element = self.node.element();
        while let Some(outcome) = seq.next_element_seed(Strict {
            node: element,
            capture: false,
        })? {
            pending.extend(outcome.pending);
        }
        Ok(Outcome {
            pending,
            text: None,
        })
    }
    fn visit_map<A: de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<Outcome<'a>, A::Error> {
        let mut keys = HashSet::new();
        let mut texts = Vec::new();
        let mut pending = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(
                    "Switch wire 1.1: a duplicate member name",
                ));
            }
            let capture = self.node.decides_by(&key);
            let outcome = map.next_value_seed(Strict {
                node: self.node.member(&key),
                capture,
            })?;
            pending.extend(outcome.pending);
            if let Some(text) = outcome.text {
                texts.push((key, text));
            }
        }
        // Decide here what this object decides; the rest goes up.
        let mut undecided = Vec::new();
        for (cond, why) in pending {
            match self.node.decide(cond, &texts) {
                Some(true) => {}
                Some(false) => return Err(de::Error::custom(why)),
                None => undecided.push((cond, why)),
            }
        }
        Ok(Outcome {
            pending: undecided,
            text: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &[OpaqueMember<'static>] = &[
        OpaqueMember {
            kind: None,
            member: "metadata",
        },
        OpaqueMember {
            kind: Some("sample.proof"),
            member: "proof",
        },
    ];

    #[test]
    fn test_member_span_measures_the_value_as_written() {
        let text = br#" { "a" : 1, "c\u006fntext" : { "k" : [ "x\"}" , 2 ] } , "b":null}"#;
        let span = member_span(text, "context").unwrap();
        assert_eq!(&text[span], br#"{ "k" : [ "x\"}" , 2 ] }"#);
        assert_eq!(&text[member_span(text, "a").unwrap()], b"1");
        assert_eq!(&text[member_span(text, "b").unwrap()], b"null");
        assert_eq!(member_span(text, "d"), None);
        assert_eq!(member_span(b"[1]", "a"), None);
        assert_eq!(member_span(br#"{"a":"#, "a"), None);
    }

    #[test]
    fn test_strict_json_refuses_duplicates_and_trailing_values() {
        assert!(check_json(br#"{"a":1,"b":{"c":2}}"#).is_ok());
        assert!(check_json(br#"{"a":1,"a":2}"#).is_err());
        assert!(check_json(br#"{"a":1,"a":2}"#).is_err());
        assert!(check_json(br#"{"a":1} {"b":2}"#).is_err());
        assert!(check_json(b"{\"a\":1}\n").is_ok());
        assert!(check_json(&[0xEF, 0xBB, 0xBF, b'{', b'}']).is_err());
    }

    #[test]
    fn test_strict_json_refuses_numbers_outside_the_integer_range() {
        assert!(check_json(br#"{"n":9007199254740991}"#).is_ok());
        for bad in [
            r#"{"n":9007199254740992}"#,
            r#"{"n":-1}"#,
            r#"{"n":1.0}"#,
            r#"{"n":1e3}"#,
        ] {
            assert!(check_json(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_strict_json_opaque_members_take_any_number() {
        let any = br#"{"kind":"x.y","body":{"metadata":{"rate":1.5e2}}}"#;
        assert!(check_json_as(any, Doc::Message(RULES)).is_ok());
        assert!(check_json(any).is_err());
        let proof = br#"{"kind":"sample.proof","body":{"proof":{"n":1e30}}}"#;
        assert!(check_json_as(proof, Doc::Message(RULES)).is_ok());
        // The rule names `proof` for one kind only, wherever `kind` comes in the object.
        let other = br#"{"body":{"proof":{"n":1.5}},"kind":"x.y"}"#;
        assert!(check_json_as(other, Doc::Message(RULES)).is_err());
        let later = br#"{"body":{"proof":{"n":1.5}},"kind":"sample.proof"}"#;
        assert!(check_json_as(later, Doc::Message(RULES)).is_ok());
        let op = br#"{"op":"invite_code.put","context":{"rate":-2.5}}"#;
        assert!(check_json_as(op, Doc::Op).is_ok());
        let other_op = br#"{"op":"record.put","context":{"rate":-2.5}}"#;
        assert!(check_json_as(other_op, Doc::Op).is_err());
    }

    #[test]
    fn test_uuid_v4_form() {
        assert!(check_uuid_v4("1b4e28ba-2fa1-41d2-883f-0016d3cca427").is_ok());
        assert!(check_uuid_v4("1B4E28BA-2FA1-41D2-883F-0016D3CCA427").is_err());
        assert!(check_uuid_v4("1b4e28ba-2fa1-11d2-883f-0016d3cca427").is_err());
        assert!(check_uuid_v4("1b4e28ba-2fa1-41d2-c83f-0016d3cca427").is_err());
        assert!(check_uuid_v4("1b4e28ba2fa141d2883f0016d3cca427").is_err());
    }

    #[test]
    fn test_reject_unknown_members() {
        let value = serde_json::json!({"a": 1, "b": 2});
        assert!(reject_unknown_members(&value, &["a", "b"], "doc").is_ok());
        assert!(reject_unknown_members(&value, &["a"], "doc").is_err());
        assert!(reject_unknown_members(&serde_json::json!([1]), &["a"], "doc").is_err());
    }
}
