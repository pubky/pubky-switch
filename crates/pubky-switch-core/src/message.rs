//! Messages (Switch wire 4.5, 5.1, Switch spec 5.2, 5.3): the signed plaintext an envelope
//! carries, and a message's common fields.
//!
//! ```text
//! sender App ID (16) | signature (64) | u32_be(len(JSON)) | message JSON | zero padding
//! ```
//!
//! The sender app signs `lp("pubky-switch/v1/msg", recipient identity, message JSON bytes)`.
//! The JSON is kept as the sender wrote it: the signature and the message hash cover those
//! exact bytes, and a re-send seals the same plaintext again (Switch spec 11).
//!
//! A message's `kind` and `body` belong to the sender's protocol. The Switch reads the common
//! fields only; a protocol names the opaque members of its bodies ([`OpaqueMember`]) and
//! parses each body by its kind.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::enc::{app_id_decode, b64, hash, pubky_id, pubky_key, random_bytes, unb64_array};
use crate::envelope::{self, Recipient, check_padding};
use crate::error::{Error, Result, invalid};
use crate::json::{Doc, OpaqueMember, check_uuid_v4, parse_json_as};
use crate::keys::AppKeys;
use crate::labels;
use crate::sig;
use crate::time::{parse_rfc3339, rfc3339};

/// The fixed part of a message plaintext: the sender's App ID, the signature and the JSON
/// length, 84 bytes (Switch wire 4.5).
pub const PLAINTEXT_PREFIX_LEN: usize = APP_ID_LEN + SIGNATURE_LEN + LEN_PREFIX;

const APP_ID_LEN: usize = 16;
const SIGNATURE_LEN: usize = 64;
const LEN_PREFIX: usize = 4;

/// The longest message JSON an envelope to `recipients` recipients carries: `65536 - 40 -
/// 88n - 24 - 16 - 84` bytes, 65,284 for one recipient (Switch wire 5.1). A protocol may bound
/// its kinds further.
///
/// `None` for a recipient count outside 1 to 255.
pub const fn max_json_len(recipients: usize) -> Option<usize> {
    match envelope::max_plaintext_len(recipients) {
        // At least 43,016 bytes: no underflow.
        Some(plaintext) => Some(plaintext - PLAINTEXT_PREFIX_LEN),
        None => None,
    }
}

/// The message hash: `hash(message JSON bytes)`, as `refs` name messages (Switch wire 1.5,
/// 5.1).
pub fn message_hash(json: &[u8]) -> [u8; 32] {
    hash(json)
}

/// A fresh `msg_id`: a lower-case UUID v4 from 16 random bytes (Switch wire 1.7, 5.1).
///
/// # Errors
///
/// [`Error::Crypto`] if the secure random generator fails.
pub fn new_msg_id() -> Result<String> {
    let mut bytes = random_bytes::<16>()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut out = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// Check a message kind's form: `<protocol>.<name>`, both parts non-empty (Switch wire 5.1).
/// Which kinds exist is the protocol's; recipients drop kinds they don't know.
///
/// # Errors
///
/// [`Error::Invalid`] for a kind without a protocol or a name.
pub fn check_kind(kind: &str) -> Result<()> {
    match kind.split_once('.') {
        Some((protocol, name)) if !protocol.is_empty() && !name.is_empty() => Ok(()),
        _ => invalid("Switch wire 5.1: a kind isn't <protocol>.<name>"),
    }
}

/// A message's sender: `from` (Switch wire 5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sender {
    /// The sender identity's Ed25519 public key.
    pub identity: [u8; 32],
    /// The sender app's App ID bytes.
    pub app_id: [u8; 16],
}

/// A message's common fields, read from its JSON (Switch wire 5.1, Switch spec 5.3). `v` is
/// 1. The body is the protocol's, parsed by its kind.
///
/// This is a reading of the signed bytes, never a source of new ones: the bytes a sender
/// signed are kept in its [`MessagePlaintext`].
#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    /// The kind, `<protocol>.<name>`.
    pub kind: String,
    /// The message ID, a lower-case UUID v4; with the sender identity, the deduplication
    /// key (Switch spec 11).
    pub msg_id: String,
    /// `created_at`, in Unix milliseconds; informational (Switch spec 5.3).
    pub created_at_ms: u64,
    /// The sender.
    pub from: Sender,
    /// The recipient identity's Ed25519 public key.
    pub to: [u8; 32],
    /// The hashes of the messages this one refers to, in the order its kind fixes; empty
    /// when the member is absent.
    pub refs: Vec<[u8; 32]>,
    /// The body, as the kind's protocol defines it.
    pub body: Map<String, Value>,
}

impl std::fmt::Debug for Message {
    // The body and the parties are message content, which stays out of logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Message({}, {}, ..)", self.kind, self.msg_id)
    }
}

/// The common fields as they are written.
#[derive(Serialize)]
struct WireOut<'a> {
    v: u64,
    kind: &'a str,
    msg_id: &'a str,
    created_at: String,
    from: WireFrom,
    to: String,
    refs: Vec<String>,
    body: &'a Map<String, Value>,
}

/// The common fields as they are read: unknown members are ignored (Switch wire 1.1), and
/// `null` counts as absent.
#[derive(Deserialize)]
struct WireIn {
    v: u64,
    kind: String,
    msg_id: String,
    created_at: String,
    from: WireFrom,
    to: String,
    #[serde(default)]
    refs: Option<Vec<String>>,
    body: Map<String, Value>,
}

#[derive(Serialize, Deserialize)]
struct WireFrom {
    identity: String,
    app_id: String,
}

impl Message {
    /// A new message with a fresh `msg_id` (Switch wire 5.1).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a kind that isn't `<protocol>.<name>`; [`Error::Crypto`] if the
    /// random generator fails.
    pub fn new(
        kind: &str,
        from: Sender,
        to: [u8; 32],
        created_at_ms: u64,
        refs: Vec<[u8; 32]>,
        body: Map<String, Value>,
    ) -> Result<Self> {
        check_kind(kind)?;
        Ok(Self {
            kind: kind.to_owned(),
            msg_id: new_msg_id()?,
            created_at_ms,
            from,
            to,
            refs,
            body,
        })
    }

    /// Read a message's JSON strictly and check its common fields (Switch wire 1.1, 5.1): `v`
    /// is 1, `kind` is `<protocol>.<name>`, `msg_id` a lower-case UUID v4, `created_at` a
    /// time, `from` a Pubky ID and an App ID, `to` a Pubky ID, each of `refs` 32 bytes and
    /// `body` an object. `opaque` names the opaque members of the protocol's bodies.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] naming the rule that failed; the text never quotes the JSON.
    pub fn parse(json: &[u8], opaque: &[OpaqueMember<'_>]) -> Result<Self> {
        let wire: WireIn = parse_json_as(json, Doc::Message(opaque))?;
        if wire.v != 1 {
            return invalid("Switch wire 1.1: a message whose v isn't 1");
        }
        check_kind(&wire.kind)?;
        check_uuid_v4(&wire.msg_id)?;
        let refs = wire
            .refs
            .unwrap_or_default()
            .iter()
            .map(|text| unb64_array::<32>(text))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            kind: wire.kind,
            msg_id: wire.msg_id,
            created_at_ms: parse_rfc3339(&wire.created_at)?,
            from: Sender {
                identity: pubky_key(&wire.from.identity)?,
                app_id: app_id_decode(&wire.from.app_id)?,
            },
            to: pubky_key(&wire.to)?,
            refs,
            body: wire.body,
        })
    }

    /// Write the message's JSON: compact, with the members in the order of Switch wire 5.1,
    /// `created_at` with three fraction digits and `refs` always written (Switch wire 1.6,
    /// 5.1).
    ///
    /// A writer does this once and signs those bytes ([`Message::sign`]); a reader never
    /// writes a message again to check one.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a kind or a `msg_id` of the wrong form, or a body that doesn't
    /// serialize.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        check_kind(&self.kind)?;
        check_uuid_v4(&self.msg_id)?;
        let wire = WireOut {
            v: 1,
            kind: &self.kind,
            msg_id: &self.msg_id,
            created_at: rfc3339(self.created_at_ms),
            from: WireFrom {
                identity: pubky_id(&self.from.identity),
                app_id: crate::enc::zbase32_encode(&self.from.app_id),
            },
            to: pubky_id(&self.to),
            refs: self.refs.iter().map(|r| b64(r)).collect(),
            body: &self.body,
        };
        Ok(serde_json::to_vec(&wire)?)
    }

    /// Write the message's JSON and sign it for its recipient `to` with the sender app's
    /// key (Switch wire 4.5, 5.1).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `from.app_id` isn't the signing app's, for a JSON
    /// [`Message::to_json`] refuses, or one too large for any envelope.
    pub fn sign(&self, app: &AppKeys) -> Result<MessagePlaintext> {
        if self.from.app_id != app.app_id_bytes() {
            return invalid("Switch wire 5.1: from.app_id isn't the signing app's");
        }
        MessagePlaintext::sign_bytes(app, &self.to, self.to_json()?)
    }

    /// Whether the message comes from an app of its recipient's own identity, which a
    /// protocol allows only for its kinds sent between own apps (Switch wire 5.1 check 6,
    /// Switch spec 7).
    pub fn is_from_own_app(&self) -> bool {
        self.from.identity == self.to
    }
}

/// What a verified certificate says about a message's sender, as the recipient checks it
/// (Switch wire 3.8, 5.1 checks 2 and 3): the identity it was verified for, its App ID and
/// its signing key.
///
/// Building one is the caller's part: the certificate must verify as a certificate of the
/// inbox entry's `sender` identity and must not have expired at the entry's `accepted_at`.
/// [`crate::receive::receive`] does both, and runs the whole check order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedSender {
    /// The identity the certificate was verified for.
    pub identity: [u8; 32],
    /// The certificate's `app_id`, as bytes.
    pub app_id: [u8; 16],
    /// The certificate's signing key.
    pub signing_key: [u8; 32],
}

impl VerifiedSender {
    /// What `cert` says about the sender. The caller verified it for the entry's `sender`
    /// identity and checked that it hadn't expired at the entry's `accepted_at` (Switch wire
    /// 5.1 checks 2 and 3), as [`crate::receive::receive`] does.
    pub fn from_cert(cert: &crate::records::AppCert) -> Self {
        Self {
            identity: cert.identity(),
            app_id: cert.app_id(),
            signing_key: cert.signing_key(),
        }
    }
}

/// The signed plaintext of a message (Switch wire 4.5, Switch spec 5.2): the sender's App ID,
/// its signature and the exact message JSON bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct MessagePlaintext {
    sender_app_id: [u8; 16],
    signature: [u8; 64],
    json: Vec<u8>,
}

impl std::fmt::Debug for MessagePlaintext {
    // The JSON is message content, which stays out of logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MessagePlaintext({}, {} bytes)",
            app_id_text(&self.sender_app_id),
            self.json.len()
        )
    }
}

fn app_id_text(bytes: &[u8; 16]) -> String {
    crate::enc::zbase32_encode(bytes)
}

impl MessagePlaintext {
    /// Sign message JSON bytes the caller wrote, for their recipient, with the sender app's
    /// key (Switch wire 4.5, 5.1). The JSON is read first, so it must be a message from this
    /// app; `opaque` names the opaque members of the protocol's bodies.
    ///
    /// Sign each message once and keep the result: a re-send seals this plaintext again
    /// (Switch wire 2.1, Switch spec 11).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for JSON [`Message::parse`] refuses, a `from.app_id` that isn't the
    /// signing app's, or JSON too large for any envelope.
    pub fn sign_json(app: &AppKeys, json: Vec<u8>, opaque: &[OpaqueMember<'_>]) -> Result<Self> {
        let message = Message::parse(&json, opaque)?;
        if message.from.app_id != app.app_id_bytes() {
            return invalid("Switch wire 5.1: from.app_id isn't the signing app's");
        }
        Self::sign_bytes(app, &message.to, json)
    }

    fn sign_bytes(app: &AppKeys, recipient_identity: &[u8; 32], json: Vec<u8>) -> Result<Self> {
        check_json_len(&json)?;
        Ok(Self {
            sender_app_id: app.app_id_bytes(),
            signature: app.sign(labels::sig::MSG, &[recipient_identity, &json]),
            json,
        })
    }

    /// A plaintext from its parts, as a sender kept them.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for JSON too large for any envelope.
    pub fn from_parts(sender_app_id: [u8; 16], signature: [u8; 64], json: Vec<u8>) -> Result<Self> {
        check_json_len(&json)?;
        Ok(Self {
            sender_app_id,
            signature,
            json,
        })
    }

    /// The sender's App ID bytes, as the plaintext names them.
    pub fn sender_app_id(&self) -> [u8; 16] {
        self.sender_app_id
    }

    /// The signature.
    pub fn signature(&self) -> [u8; 64] {
        self.signature
    }

    /// The exact message JSON bytes.
    pub fn json(&self) -> &[u8] {
        &self.json
    }

    /// The message hash (Switch wire 5.1).
    pub fn hash(&self) -> [u8; 32] {
        message_hash(&self.json)
    }

    /// The plaintext bytes before padding; sealing pads them with zeros (Switch wire 4.5).
    pub fn encode(&self) -> Vec<u8> {
        // The constructors bound the JSON to an envelope's size, so its length fits 32 bits.
        let len = u32::try_from(self.json.len()).unwrap_or(u32::MAX);
        let mut out = Vec::with_capacity(PLAINTEXT_PREFIX_LEN.saturating_add(self.json.len()));
        out.extend_from_slice(&self.sender_app_id);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.json);
        out
    }

    /// Read an opened envelope's plaintext (Switch wire 4.3 step 6, 4.5): the length must not
    /// run past the plaintext, and every padding byte must be zero.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a plaintext shorter than its 84-byte prefix, a length that runs
    /// past it, or a non-zero padding byte.
    pub fn decode(plaintext: &[u8]) -> Result<Self> {
        let short = || Error::Invalid("Switch wire 4.5: a message plaintext too short".into());
        let (sender_app_id, rest) = plaintext
            .split_first_chunk::<APP_ID_LEN>()
            .ok_or_else(short)?;
        let (signature, rest) = rest
            .split_first_chunk::<SIGNATURE_LEN>()
            .ok_or_else(short)?;
        let (len, rest) = rest.split_first_chunk::<LEN_PREFIX>().ok_or_else(short)?;
        let len = usize::try_from(u32::from_be_bytes(*len)).unwrap_or(usize::MAX);
        let (json, padding) = rest.split_at_checked(len).ok_or_else(|| {
            Error::Invalid("Switch wire 4.5: a length that runs past the plaintext".into())
        })?;
        check_padding(padding)?;
        Self::from_parts(*sender_app_id, *signature, json.to_vec())
    }

    /// Seal the plaintext to the receive keys of apps of `recipient_identity`, the message's
    /// `to` (Switch wire 4.3). A re-send seals the same plaintext again, to the current
    /// receive keys (Switch spec 11).
    ///
    /// # Errors
    ///
    /// As [`envelope::seal`]; the JSON may be too large for this many recipients.
    pub fn seal(
        &self,
        recipient_identity: &[u8; 32],
        recipients: &[Recipient],
        notify: bool,
    ) -> Result<Vec<u8>> {
        envelope::seal(recipient_identity, recipients, &self.encode(), notify)
    }

    /// Open an envelope with one of the own app's receive secrets and read its plaintext:
    /// check 1 of Switch wire 5.1.
    ///
    /// # Errors
    ///
    /// As [`envelope::open`] and [`MessagePlaintext::decode`].
    pub fn open(
        envelope: &[u8],
        own_identity: &[u8; 32],
        receive_secret: &[u8; 32],
    ) -> Result<Self> {
        let plaintext = envelope::open(envelope, own_identity, receive_secret)?;
        Self::decode(&plaintext)
    }

    /// Verify the signature with the sender's signing key over the own identity and the JSON
    /// bytes (Switch wire 5.1 check 4).
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] if it doesn't verify.
    pub fn verify_signature(&self, signing_key: &[u8; 32], own_identity: &[u8; 32]) -> Result<()> {
        sig::verify(
            signing_key,
            labels::sig::MSG,
            &[own_identity, &self.json],
            &self.signature,
        )
    }

    /// The recipient checks of Switch wire 5.1 that need the sender's verified certificate
    /// but not the sender identity's `identity.json`, in their order:
    ///
    /// - check 4: the signature verifies with the certificate's signing key over the own
    ///   identity and the JSON bytes;
    /// - check 5: the JSON is strict and its common fields have their forms, `v` 1 included
    ///   ([`Message::parse`]);
    /// - check 6: the plaintext's App ID, `from.app_id` and the certificate's App ID are
    ///   equal; `from.identity` is the certificate's identity and the entry's `sender`; and
    ///   `to` is the own identity.
    ///
    /// Before it, the caller opens the envelope (check 1, [`MessagePlaintext::open`]) and
    /// verifies the entry's certificate (checks 2 and 3, [`VerifiedSender`]). After it come
    /// the protocol's own-app kind rule of check 6 ([`Message::is_from_own_app`]), the
    /// sender's standing in its `identity.json` (7), the scopes of the kind (8),
    /// deduplication by (sender identity, `msg_id`) with [`MessagePlaintext::hash`] (9) and
    /// the body (10). A failed check drops the entry.
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] for check 4, [`Error::Invalid`] naming the rule for checks 5 and
    /// 6.
    pub fn check(
        &self,
        own_identity: &[u8; 32],
        entry_sender: &[u8; 32],
        sender: &VerifiedSender,
        opaque: &[OpaqueMember<'_>],
    ) -> Result<Message> {
        self.verify_signature(&sender.signing_key, own_identity)?;
        let message = Message::parse(&self.json, opaque)?;
        if self.sender_app_id != message.from.app_id || message.from.app_id != sender.app_id {
            return invalid(
                "Switch wire 5.1 check 6: the plaintext's App ID, from.app_id and the certificate's differ",
            );
        }
        if message.from.identity != sender.identity || message.from.identity != *entry_sender {
            return invalid(
                "Switch wire 5.1 check 6: from.identity isn't the certificate's identity and the entry's sender",
            );
        }
        if message.to != *own_identity {
            return invalid("Switch wire 5.1 check 6: the message is to another identity");
        }
        Ok(message)
    }
}

/// Bound message JSON to the largest an envelope carries (Switch wire 5.1).
fn check_json_len(json: &[u8]) -> Result<()> {
    if max_json_len(1).is_none_or(|max| json.len() > max) {
        return invalid("Switch wire 5.1: a message too large for any envelope");
    }
    Ok(())
}

impl Sender {
    /// The sender app's App ID text (Switch wire 1.3).
    pub fn app_id_text(&self) -> String {
        app_id_text(&self.app_id)
    }

    /// The sender of messages from `app`, an app of `identity`.
    pub fn of_app(identity: [u8; 32], app: &AppKeys) -> Self {
        Self {
            identity,
            app_id: app.app_id_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ReceiveKey;

    const ALICE: [u8; 32] = [0x0a; 32];

    fn app() -> AppKeys {
        AppKeys::from_secrets([1; 32], [2; 32])
    }

    fn bob() -> [u8; 32] {
        crate::sig::public_of(&[3; 32])
    }

    fn message() -> Message {
        let mut body = Map::new();
        body.insert("note".into(), Value::String("hello".into()));
        let mut message = Message::new(
            "sample.kind",
            Sender::of_app(bob(), &app()),
            ALICE,
            1_767_225_600_000,
            vec![[5; 32]],
            body,
        )
        .unwrap();
        // One fixed ID, so that every call gives the same message.
        message.msg_id = "1b4e28ba-2fa1-41d2-883f-0016d3cca427".into();
        message
    }

    fn sender() -> VerifiedSender {
        VerifiedSender {
            identity: bob(),
            app_id: app().app_id_bytes(),
            signing_key: app().signing_public(),
        }
    }

    #[test]
    fn test_message_writes_and_reads_its_common_fields() {
        let message = message();
        let json = message.to_json().unwrap();
        let text = String::from_utf8(json.clone()).unwrap();
        assert!(
            text.starts_with(r#"{"v":1,"kind":"sample.kind","msg_id":""#),
            "{text}"
        );
        assert!(text.contains(r#""created_at":"2026-01-01T00:00:00.000Z""#));
        assert_eq!(Message::parse(&json, &[]).unwrap(), message);
        assert!(!message.is_from_own_app());
    }

    #[test]
    fn test_message_ids_are_fresh_uuid_v4() {
        let (one, two) = (new_msg_id().unwrap(), new_msg_id().unwrap());
        check_uuid_v4(&one).unwrap();
        assert_ne!(one, two);
    }

    #[test]
    fn test_message_kind_form() {
        check_kind("sample.kind").unwrap();
        check_kind("sample.kind.sub").unwrap();
        for bad in ["", "kind", ".kind", "sample."] {
            assert!(check_kind(bad).is_err(), "{bad}");
        }
        assert!(Message::new("kind", message().from, ALICE, 0, vec![], Map::new()).is_err());
    }

    #[test]
    fn test_message_parse_refuses_each_bad_field() {
        let json = String::from_utf8(message().to_json().unwrap()).unwrap();
        let msg_id = message_msg_id(&json);
        let cases = [
            json.replace(r#""v":1"#, r#""v":2"#),
            json.replace("sample.kind", "samplekind"),
            json.replace(&msg_id, &msg_id.to_uppercase()),
            json.replace("2026-01-01T00:00:00.000Z", "2026-01-01 00:00:00Z"),
            json.replace(&pubky_id(&ALICE), "alice"),
            json.replace(r#""refs":["#, r#""refs":["AAAA","#),
            json.replace(r#""body":{"note":"hello"}"#, r#""body":[]"#),
            json.replace(r#""v":1,"#, r#""v":1,"v":1,"#),
            json.replace(r#""v":1,"#, r#""v":1,"x":1.5,"#),
            json.replace(r#""v":1,"#, ""),
        ];
        for case in cases {
            assert!(Message::parse(case.as_bytes(), &[]).is_err(), "{case}");
        }
        // Unknown members are ignored, `refs` may be absent or null, and the body's opaque
        // members take any number.
        let extra = json.replace(r#""v":1,"#, r#""v":1,"extra":"x","#);
        assert!(Message::parse(extra.as_bytes(), &[]).is_ok());
        let without_refs = json.replace(&format!(r#""refs":["{}"],"#, b64(&[5; 32])), "");
        assert!(
            Message::parse(without_refs.as_bytes(), &[])
                .unwrap()
                .refs
                .is_empty()
        );
        let null_refs = json.replace(&format!(r#"["{}"]"#, b64(&[5; 32])), "null");
        assert!(
            Message::parse(null_refs.as_bytes(), &[])
                .unwrap()
                .refs
                .is_empty()
        );
        let rate = json.replace(r#""note":"hello""#, r#""rate":1.5"#);
        let opaque = [OpaqueMember {
            kind: None,
            member: "rate",
        }];
        assert!(Message::parse(rate.as_bytes(), &[]).is_err());
        assert!(Message::parse(rate.as_bytes(), &opaque).is_ok());
    }

    fn message_msg_id(json: &str) -> String {
        let start = json.find(r#""msg_id":""#).unwrap() + 10;
        json[start..start + 36].to_owned()
    }

    #[test]
    fn test_message_plaintext_round_trips_through_an_envelope() {
        let receive = ReceiveKey::from_secret(0, [7; 32]);
        let plaintext = message().sign(&app()).unwrap();
        let envelope = plaintext
            .seal(&ALICE, &[Recipient::new(receive.public)], true)
            .unwrap();
        let opened = MessagePlaintext::open(&envelope, &ALICE, &receive.secret()).unwrap();
        assert_eq!(opened, plaintext);
        assert_eq!(opened.hash(), message_hash(plaintext.json()));
        let checked = opened.check(&ALICE, &bob(), &sender(), &[]).unwrap();
        assert_eq!(checked, message());
    }

    #[test]
    fn test_message_plaintext_decode_refuses_bad_frames() {
        let plaintext = message().sign(&app()).unwrap();
        let mut padded = plaintext.encode();
        assert_eq!(padded.len(), 84 + plaintext.json().len());
        padded.extend_from_slice(&[0; 10]);
        assert_eq!(MessagePlaintext::decode(&padded).unwrap(), plaintext);
        let mut dirty = padded.clone();
        dirty.push(1);
        assert!(MessagePlaintext::decode(&dirty).is_err());
        let mut long = padded.clone();
        long[80..84].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(MessagePlaintext::decode(&long).is_err());
        assert!(MessagePlaintext::decode(&padded[..83]).is_err());
        assert!(MessagePlaintext::from_parts([0; 16], [0; 64], vec![b' '; 65_285]).is_err());
        assert!(MessagePlaintext::from_parts([0; 16], [0; 64], vec![b' '; 65_284]).is_ok());
        assert_eq!(max_json_len(1), Some(65_284));
    }

    #[test]
    fn test_message_check_refuses_each_mismatch() {
        let plaintext = message().sign(&app()).unwrap();
        let ok = sender();
        assert!(plaintext.check(&ALICE, &bob(), &ok, &[]).is_ok());
        // Check 4: another identity, or another key.
        let other = [0x0b; 32];
        assert!(matches!(
            plaintext.check(&other, &bob(), &ok, &[]),
            Err(Error::Signature(_))
        ));
        let wrong_key = VerifiedSender {
            signing_key: crate::sig::public_of(&[9; 32]),
            ..ok
        };
        assert!(matches!(
            plaintext.check(&ALICE, &bob(), &wrong_key, &[]),
            Err(Error::Signature(_))
        ));
        // Check 6: the certificate names another app or identity, the entry another sender.
        let other_app = VerifiedSender {
            app_id: [0; 16],
            ..ok
        };
        assert!(plaintext.check(&ALICE, &bob(), &other_app, &[]).is_err());
        let other_identity = VerifiedSender {
            identity: other,
            ..ok
        };
        assert!(
            plaintext
                .check(&ALICE, &bob(), &other_identity, &[])
                .is_err()
        );
        assert!(plaintext.check(&ALICE, &other, &ok, &[]).is_err());
        // The plaintext names another App ID than `from`.
        let renamed =
            MessagePlaintext::from_parts([0; 16], plaintext.signature(), plaintext.json().to_vec())
                .unwrap();
        assert!(renamed.check(&ALICE, &bob(), &ok, &[]).is_err());
        // Check 6: `to` isn't the own identity, though the signature names it.
        let mut misaddressed = message();
        misaddressed.to = other;
        let json = misaddressed.to_json().unwrap();
        let signature = app().sign(labels::sig::MSG, &[&ALICE, &json]);
        let forged = MessagePlaintext::from_parts(app().app_id_bytes(), signature, json).unwrap();
        let refused = forged.check(&ALICE, &bob(), &ok, &[]).unwrap_err();
        assert!(
            refused.to_string().contains("another identity"),
            "{refused}"
        );
        // Check 5: a signed document that isn't a message.
        let json = b"{\"v\":1}".to_vec();
        let signature = app().sign(labels::sig::MSG, &[&ALICE, &json]);
        let not_message =
            MessagePlaintext::from_parts(app().app_id_bytes(), signature, json).unwrap();
        assert!(matches!(
            not_message.check(&ALICE, &bob(), &ok, &[]),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn test_message_sign_requires_the_sending_app() {
        let other = AppKeys::from_secrets([8; 32], [8; 32]);
        assert!(message().sign(&other).is_err());
        let json = message().to_json().unwrap();
        assert!(MessagePlaintext::sign_json(&other, json.clone(), &[]).is_err());
        let signed = MessagePlaintext::sign_json(&app(), json, &[]).unwrap();
        assert_eq!(signed, message().sign(&app()).unwrap());
        assert!(MessagePlaintext::sign_json(&app(), b"{}".to_vec(), &[]).is_err());
    }

    #[test]
    fn test_message_own_app_and_debug() {
        let mut own = message();
        own.to = own.from.identity;
        assert!(own.is_from_own_app());
        let debug = format!("{:?} {:?}", message(), message().sign(&app()).unwrap());
        assert!(!debug.contains("hello"), "{debug}");
    }
}
