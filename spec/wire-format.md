# Pubky Switch wire format

**Status.** Complete; a review candidate, with the Pubky Switch spec. The wire format of `spec/spec.md` ("the spec"). The spec decides behaviour; this document decides bytes. It settles every wire detail the spec leaves open, taking the reference prototype as the source of truth, so that a second team can build an interoperable switch, signer or app without reading the prototype. Where this document had to choose something the prototype doesn't fix, Appendix A says so.

**Test vectors.** `spec/vectors/` holds the Switch's test vectors for every encoding, signature, derivation, envelope and state transition below; its `README.md` lists the files. Every example in this document comes from those files and uses the fixed keys of `keys.json` (identities alice and bob, alice's apps `wallet`, `phone` and `executor`, bob's apps `shop` and `cap`), except the `429 quota_exceeded` body of 9.3, which is the reference prototype's answer and says so. The JSON samples in this document, like the test vectors and the prose, use the scopes, message kinds, collections and app record member of the spec's sample protocol, `tasks` (spec 1). The switch treats every protocol's names as opaque. The reference prototype, shared separately, computes every vector from its code, but for the cases the vectors README lists as `pubky-switch-core`'s, which that crate's tests compute.

**Conventions.**

- "Section N" means this document; "spec N" means the Pubky Switch spec.
- Field tables have the columns Field, Type, Req (required), Constraints and Notes.
- Types:

  | Type | Meaning |
  |---|---|
  | `int` | JSON integer, 0 to 2^53 - 1 (1.1) |
  | `string`, `bool`, `object`, `array<T>` | JSON types |
  | `b64(n)` | base64url of exactly n bytes (1.2); `b64` is any length |
  | `pubky` | Pubky ID (1.3) |
  | `app-id` | App ID (1.3) |
  | `time` | RFC 3339 time (1.6) |
  | `uuid` | UUID v4 string (1.7) |
  | `signed<T>` | a signed document whose body is a T (2.2) |
  | `T \| null` | nullable |

- **Absent and null.** "Req: no" means the member may be missing. Writers omit absent optional members, except where a table says the member is always written; shared record values follow their protocol's rule, and a protocol may let its writers write every member with `null` for absent, as the reference prototype's writers do. Readers treat `null` like a missing member, unless the table says `null` has its own meaning. That is for optional members. A member whose Req is "yes, always written" must be present, and may be `null` where its type allows: a reader refuses a document without it, as it refuses one without any required member. These are an app record's `expires_at` (3.2), `identity.json`'s `recovery_from` and a `renewed` entry's `until` (3.3), an operation's `app_id` (6.1) and a manifest's `checkpoint` (10.2).
- Examples of signed documents show the decoded body. Long base64url values are cut short with `...` in a few examples; the vector files have them in full.
- **Rejection vectors.** Where a vector file lists inputs to refuse, what is normative is that the input is refused, and the HTTP status and `code` where this document fixes one. An `error` or `message` text in a vector, such as `chain.json`'s "incomplete batch: <id>", is that of the implementation that generated the case (vectors README, "How the files were generated") and only informative.

## 1. Encodings

### 1.1 JSON

- **Text.** Every JSON document is UTF-8 without a byte order mark, and is exactly one JSON value. JSON whitespace may follow the value; anything else after it makes the document invalid.
- **Duplicate member names** at any depth make a document invalid. Names are compared after unescaping, so `{"a":1,"\u0061":2}` is a duplicate. The service answers `400 bad_request`; apps drop the document.
- **Lone surrogates** (`\ud800` not followed by a low surrogate, or a low surrogate alone) make a document invalid.
- **Unknown members** are rejected in conditions (6.3), operation bodies (6.1, 6.2), app certificates (3.1), receive key records (3.4), app requests (3.9), export transfers (3.11) and the erasure body (7.4.16), so a future restriction there is never silently skipped (spec 13.1): the service answers `400 bad_request`, and a reader drops the document. This holds at every depth: an object nested in one of these refuses unknown members as its top level does, such as an operation's `batch`, `expected_version`, `value_sealed` and `id_inputs`, a condition and its inner object, the carrying form (2.2) of a signed document an operation carries (`record`, `cert`), the key bundle object of `key_bundle.put` (3.5), each `suite_keys` entry of a certificate or a receive key record (3.1, 3.4), and an export transfer's `from` and `to`. So does each entry of a `POST /ops` body (6.4): a signed operation's carrying form has `body` and `sig` only, and a `cursor.set` has `op` and `position` only. Only opaque members are exempt: the `context` of `invite_code.put` holds any JSON. A signed document carried inside keeps its own rule: a certificate refuses unknown members, an app record ignores them. Everywhere else readers ignore them: message bodies, records, `identity.json`, the key bundle plaintext, shared record values and export parts. Vectors: `operations.json` `unknown_members`, one top-level case and nested ones, and in `batch_entries` members beside a batch entry's own.
- **Version.** Every document with a `v` member has `v: 1`. Readers reject other values.
- **Exact bytes.** Signatures and hashes cover the exact bytes a writer produced. Readers never re-serialize JSON to check a signature or a hash, and anything forwarded keeps its bytes: a signed document's `body`, a message's JSON inside its plaintext, a chain envelope. Writers may use any member order and whitespace (the reference prototype: compact JSON, a message body's members sorted by name).
- **Integers** are JSON numbers without sign, fraction or exponent, from 0 to 2^53 - 1 (9007199254740991). Every binding reads such a number exactly. Readers reject a larger or negative value, and a fraction or exponent, `1.0` and `1e3` included. The rule runs on the whole document when it is parsed, before any of its fields is read, and covers every number outside the opaque members below, in members readers ignore too: the service answers `400 bad_request`, and an app drops the document. Switch documents carry no other numbers. With integers in this range, a duration added to a time in milliseconds (an `orphan_after` of 2^53 - 1 seconds, say) can't overflow 64 bits; a sum past the last time 1.6 can write means "never". Inside `lp()` an integer is 8 bytes big-endian (1.4). Times are never integers on the wire, except the `_ms` and `_s` members of export parts (Section 10) and those a protocol names.
- **Opaque members** are opaque to the switch and its readers, which never read them as numbers. They, and everything at any depth below them, may hold any JSON number. They are named by their path in the document that holds them:
  - an invite code's `context`: in `invite_code.put` (6.2), in a conversation entry (the `conversation.add` transition of 6.5, the `conversations` of `GET /allow` in 7.4.6, and the export's `conversation` part in 10.3), and where a feed item (7.5) or an export `chain`, `entry` or `invite_code` part (10.3) repeats it.
  - the members a protocol names as opaque in its message bodies.

  Every other member is checked, whatever its name. Vectors: `encoding.json` `json` (the cases with `read_as` are read as that document) and `operations.json` `integer_bounds`.
- **Strings** may use JSON escapes; comparisons use the decoded text. A field documented as "no control characters" rejects U+0000 to U+001F and U+007F.

### 1.2 Binary values

- Binary values in JSON and in headers are **base64url without padding** (RFC 4648 section 5).
- Decoders reject `=` padding, the characters `+` and `/`, whitespace, lengths of the form 4k + 1, and non-zero trailing bits. So each byte string has exactly one text.
- Lengths:

  | Bytes | Characters | Used for |
  |---|---|---|
  | 8 | 11 | kid |
  | 16 | 22 | `attempt_id`, batch ID, the nonces of enrollments, freezes and webhooks, `entry_id` |
  | 24 | 32 | XChaCha20-Poly1305 nonce of a sealed value |
  | 32 | 43 | keys, hashes, obligations, record keys, collection IDs |
  | 64 | 86 | Ed25519 signatures |

- Vectors: `encoding.json` `base64url`.

### 1.3 Pubky IDs and App IDs

- **z-base-32**, alphabet `ybndrfg8ejkmcpqxot1uwisza345h769`, bits taken most significant first, the last group filled with zero bits, no padding characters, lower case only.
- **Pubky ID:** the identity's 32-byte Ed25519 public key, 52 characters. The last character carries one bit, so it is `y` or `o`.
- **App ID:** the first 16 bytes of `BLAKE3(app signing public key)`, 26 characters.
- Decoders reject a wrong length, a character outside the alphabet (upper case included) and non-zero trailing bits, so each key has one ID.
- Vectors: `encoding.json` `zbase32`, `identifiers.json` `app_id`.

### 1.4 `lp()` and field encodings

`lp(x1, ..., xn) = u32_be(len(x1)) || x1 || ... || u32_be(len(xn)) || xn`. `lp()` of no parts is empty. Every signature input, derivation input, AAD and HPKE `info` uses it.

| Field | Bytes inside `lp` |
|---|---|
| Identity, counterparty, any Pubky ID | the 32-byte Ed25519 public key, decoded from z-base-32 |
| App ID | its 16 bytes |
| kid | its 8 bytes |
| Integer | `u64` big-endian, 8 bytes |
| Label, scope name, collection name, HTTP method, path and query, origin | UTF-8 text |
| `msg_id` | UTF-8 text of the UUID (36 bytes) |
| Request header values (`Switch-Timestamp`, `Switch-Identity`, `Switch-App`, `Switch-Cert`, `Switch-Invite-Code`) | the exact header text, UTF-8, empty when the header is absent. The identity and app headers are signed as their z-base-32 text, not as key bytes |
| `Switch-Server-Time` | its exact text |
| Hashes, obligations, record keys, keys | raw bytes |
| A document or message body | its exact bytes |
| An absent value | empty (length 0) |

Vectors: `encoding.json` `lp` and `u64_be`.

### 1.5 Hashes and `derive()`

- `hash(x)` is BLAKE3 with a 32-byte output.
- `derive(label, parts...) = BLAKE3-derive_key(context = label, key material = lp(parts...))`, 32 bytes. Every label is a fixed ASCII constant. The switch's derivations use `pubky-switch/v1/` labels; a protocol's own use labels of its own, such as `tasks/v1/`.
- Some values hash an `lp()` whose first part is a label, with plain BLAKE3: policy hashes, chain item hashes and chain hashes. Sealed values and HPKE put the label first in their `lp()` the same way.

| Value | Computation |
|---|---|
| kid | first 8 bytes of `derive("pubky-switch/v1/kid", X25519 public key)` for a suite 1 key; for a key of a later suite `s` in `suite_keys` (3.1, 3.4), first 8 bytes of `derive("pubky-switch/v1/kid", u64(s), key bytes)` (spec 13.3) |
| App ID | first 16 bytes of `hash(Ed25519 signing public key)` |
| Switch root | `switch_root = derive("pubky-switch/v1/scope-root", identity secret)`, the identity secret being the 32-byte Ed25519 secret key (seed). Only the signer computes it; it is never granted or delivered |
| Scope key | `scope_key(e, s) = derive("pubky-switch/v1/scope-key", switch_root, u64(e), s)`, for data epoch `e` and scope name `s` |
| Sub-scope key | `sub_scope_key(e, name:<sub>) = derive("pubky-switch/v1/sub-scope-key", scope_key(e, name), sub)`, the key of the sub-scope `name:<sub>` (3.1) at data epoch `e`: its scope key wherever a key of that scope is meant (3.5, 6.2). The key of a labelled sub-scope such as `tasks_assign:team1` is one. An app holding `name` derives it; others get it in key bundles |
| Backup key | the X25519 secret `derive("pubky-switch/v1/backup-key", identity secret)`, clamped (RFC 7748), and its public key, which the signer's backup is sealed to (3.13). Only a holder of the identity key derives it |
| Naming key | `naming_key = derive("pubky-switch/v1/naming", switch_root)`, one per identity; it never rotates |
| Blinded input | `blind(x) = derive("pubky-switch/v1/name", naming_key, x)`, for the natural keys and obligation inputs below |
| Key commitment | `derive("pubky-switch/v1/key-commit", content key)` |
| HPKE `info` | `lp("pubky-switch/v1/hpke", recipient identity, kid)` (72 bytes) |
| Document hash (certificate hash, freeze hash, enrollment hash) | `hash(signed document bytes)` (2.2) |
| Policy hash | `hash(lp("pubky-switch/v1/policy", read_scope, u64(n), write_scope_1, ..., write_scope_n))`, write scopes sorted ascending by bytes, no duplicates, n at least 1 |
| Collection ID | `derive("pubky-switch/v1/collection", collection name, identity)` |
| Record key | `derive("pubky-switch/v1/record", collection name, blind(natural key), policy hash)`; the creating `record.put` carries `blind(natural key)` in `id_inputs` (6.2) |
| Chain item hash | `hash(lp("pubky-switch/v1/item", item type, signed document bytes))` (6.6) |
| Chain hash | `hash(lp("pubky-switch/v1/chain", previous chain hash, chain envelope bytes))` (6.6) |
| Invite code hash | `hash(code bytes)`, the code decoded from base64url (1.7) |

- **Whose naming key.** Record keys, and a protocol's claim keys, are blinded with the naming key of the identity whose Pubky Switch holds them. Equal inputs give equal outputs within one identity, so all its apps find the same record and claim, and the stored keys name neither the counterparty nor the other inputs. That protects stored state and exports, not against a live operator, which links records and claims to senders through batches and timing (spec 15).

Vectors: `encoding.json` `derive`; `keys.json` the Switch root, naming key and backup key of each identity, `scope_keys` and `sub_scope_keys`; `identifiers.json` `blinded_inputs` and every value of the table, with the blinded inputs of each record key; the record keys use the collections and natural keys of `tasks`.

### 1.6 Times

- **Grammar:** `YYYY-MM-DDTHH:MM:SS[.F]Z`, with a four-digit year, upper-case `T` and `Z`, and an optional fraction of 1 to 9 digits. Times are UTC. Times before 1970 and leap seconds (`:60`) are invalid.
- **Writers:**
  - every time in documents, messages, records and response bodies, and `Switch-Server-Time`: exactly three fraction digits, for example `2026-01-01T00:00:00.000Z`;
  - `Switch-Timestamp`: no fraction, for example `2026-01-01T00:05:00Z`.
- **Readers** accept every form of the grammar, fractions of 1 to 9 digits included, and reject a fraction of 0 or more than 9 digits and a leap second. A space instead of `T`, and numeric offsets such as `+01:00`, are a reader's choice, not part of the grammar: writers never produce them, so a reader may reject them and loses nothing (the reference prototype: its parser accepts both).
- **Comparisons** use the instant at millisecond precision; further digits are truncated, not rounded (`.9999` is 999 ms). Two spellings of one instant are equal. The spelling is still part of the signed bytes.
- Vectors: `encoding.json` `rfc3339`, with fractions of 1, 3, 4 and 9 digits and the lenient forms under `lenient_reader_only`.

### 1.7 Identifiers

| Value | Form | Length | Notes |
|---|---|---|---|
| Pubky ID | z-base-32 | 52 | 1.3 |
| App ID | z-base-32 | 26 | 1.3 |
| kid | `b64(8)` | 11 | 1.5 |
| Obligation, record key, collection ID, hashes | `b64(32)` | 43 | 1.5 |
| `msg_id` | UUID v4 | 36 | lower-case hex, `8-4-4-4-12`, version nibble 4, variant bits `10`; a MUST: readers reject upper case and other versions |
| `attempt_id` | `b64(16)` | 22 | random |
| Batch ID | `b64(16)` | 22 | random, 6.4 |
| Nonces of enrollments, freezes and webhooks | `b64(16)` | 22 | random |
| `entry_id` | `b64(16)` | 22 | random, opaque to senders |
| Invite code | base64url of at least 16 random bytes | 22 or more | shown as `pubky://<id>?switch=invite&code=<code>` |
| Invite code hash | `b64(32)` | 43 | `hash(code bytes)` |
| Push handle | string | any | chosen by the relay; the reference relay uses `b64(16)` |
| Push key | `b64(32)` | 43 | the public half of a registration's push key (8.1) |
| Feed position, cursor | `<generation>:<seq>` | | two decimal integers, for example `1:1042` |
| Record version | `{ "generation": int, "version": int }` | | the (generation, `seq`) of the write that produced it (6.2); `{0, 0}` names no record |
| Service time | `time` | | three fraction digits |

## 2. Signatures and signed documents

### 2.1 Algorithm

- Ed25519 (RFC 8032). Public keys are 32 bytes, signatures 64 bytes.
- **Verification** (spec 13.2). With A the 32-byte public key, R the signature's first 32 bytes, S its last 32 read as a little-endian integer, M the signature input below, B the base point and L the group order (2^252 + 27742317777372353535851937790883648493), a verifier accepts only if every step holds, in this order:
  1. S < L.
  2. A decodes to a curve point (RFC 8032 5.1.3) whose encoding (5.1.2) is again exactly A's 32 bytes; the same for R. This refuses the encodings y + p of a point, which some decoders reduce silently (ed25519-dalek 3's `VerifyingKey::from_bytes` takes them for y = 3, 4, 5, 6, 9, 10, 14, 15, 16 and 18), and a set sign bit with x = 0.
  3. Neither A nor R is of small order: `[8]A` and `[8]R` aren't the identity point.
  4. `k = SHA-512(R || A || M)`, read as a 64-byte little-endian integer and reduced mod L, and the encoding of `[S]B - [k]A` equals R's 32 bytes (cofactorless, compared as bytes).

  A mixed-order A (order 8L) is accepted: nothing requires it to be torsion-free. A verifier that multiplies by the cofactor (`[8][S]B = [8]R + [8][k]A`), or skips step 2 or 3, isn't compliant, since it accepts signatures this one refuses. ed25519-dalek's `verify_strict` does steps 1, 3 and 4 and step 2 for R only (the reference prototype: it adds the check of A, `wire::verify`).
- **Vectors:** `signatures.json` `rejections` has signatures a verifier must refuse: S not reduced (S + L), a small-order public key (the identity point) with R the identity point and S = 0 (which a non-strict verifier accepts for any message), a signature checked under another label, and the edge cases built from known scalars and the points of order 8 (in the manner of "Taming the many EdDSAs", Chalkias et al. 2020): the cofactored equation only (a mixed-order key with k = 1 mod 8), a small-order R for which the cofactorless equation holds (ed25519-dalek's non-strict `verify` takes it), the identity point written as y + p as R, the point y = 3 written as y + p as A, and a public key of order 8. Each says, in `reason`, the step that refuses it (the reference prototype: in its words). `accepted` has the mixed-order key that step 3 lets through, with k a multiple of 8 so both equations hold. Every case is checked under one label; the label doesn't change which step refuses it.
- **Signature input:** `lp(label, field1, ..., fieldn)`, with the label and fields of 2.3. Nothing else is signed, and nothing is canonicalized.
- **Sign once** (spec 13.2). A writer signs each document, operation and message once, keeps the signed bytes and sends exactly those bytes again: on a retry, in a re-delivery, in a later batch's answer check, when publishing what it delivered. It never signs the same body again or re-serializes it. Batch retries (6.4), the no-ops (6.4), `PUT /identity` retries and compare-and-swap (7.4.2) and every document hash compare whole signed bytes, so a second signature of one body is another document there; only equivocation compares bodies (3.3). Deterministic RFC 8032 signing is recommended, not required: a signer with random nonces is compliant as long as it keeps the bytes. (The reference prototype: it keeps a batch's signed operations with the batch, `client::Batch`, the signed `identity.json` of each version, `Signer::signed_doc`, and each receive key's signed record with the key, and its conformance test signs with random nonces throughout.)
- **What the identity key signs** (spec 13.2): only the identity-key rows of 2.3, the approval's companion claim (3.10) and Pubky's own formats for the same key. Every `lp()` input of 2.3 the identity key signs starts with `00 00 00` and the label's length, then `pubky-switch/v1/`; the companion claim's input starts with the text `x-pubky-switch-claim|` (first byte `0x78`); Pubky's auth tokens start their signed bytes with `PUBKY:AUTH`, its grants are JWS (base64url text) and PKARR packets start with `3:seq`, so no input of one is an input of another. Signers expose no signing of caller-supplied bytes.

### 2.2 Signed documents

- **Carrying form:** a JSON object `{ "body": "<base64url of the exact JSON bytes>", "sig": "<base64url of the signature>" }`. Readers ignore other members, except in a carrying form inside an operation body or as an entry of a `POST /ops` body (6.4), which has these two only (1.1).
- **Compact form:** `<body>.<sig>`, the two base64url texts joined by one `.`. It is used where a signed document travels in a header (`Switch-Cert`). A reader splits at the first `.`.
- **Signed document bytes:** `lp(body bytes, signature bytes)`, that is `u32_be(len(body)) || body || 00 00 00 40 || signature`.
- **Document hash:** `hash(signed document bytes)`. It is the certificate hash in `identity.json`, the freeze hash, the enrollment hash and the item bytes of chain items (6.6). It never covers re-serialized JSON.
- **Reading:** verify the signature first, then parse the body strictly (1.1). For an app record, the key is inside the body: a reader parses the body only to find `signing_key`, verifies, and then checks the certificate (3.2).
- Vectors: `documents.json`, with the body, both forms, the document bytes and the hash of every document of Section 3.

### 2.3 Signature labels and inputs

Every signature of the Switch. Fields are encoded as in 1.4. The formats the Pubky Switch defines sign under `pubky-switch/v1/` labels; a protocol's own sign under labels of its own.

| Object | Label | Signed by | Fields after the label | Where the signature travels |
|---|---|---|---|---|
| App certificate | `pubky-switch/v1/app-cert` | identity key | body | signed document |
| App record | `pubky-switch/v1/app-record` | app signing key | body | signed document |
| Receive key record | `pubky-switch/v1/receive-key` | app signing key | body | signed document |
| `identity.json` | `pubky-switch/v1/identity` | identity key | body | signed document |
| Enrollment | `pubky-switch/v1/enroll` | identity key | body | signed document |
| App request | `pubky-switch/v1/app-request` | the requesting app's signing key | body | signed document (3.9) |
| Key bundle | `pubky-switch/v1/key-bundle` | identity key | identity, target app ID, envelope bytes | `sig` of the key bundle (3.5) |
| Signer hand-over | `pubky-switch/v1/signer-handover` | identity key | identity, the new signer's App ID, `u32_be(n)`, the bytes of each of the n envelopes, in order | `sig` of the hand-over (3.12) |
| Signer backup | `pubky-switch/v1/signer-backup` | identity key | identity, `u32_be(n)`, the bytes of each of the n envelopes, in order | `sig` of the backup (3.13) |
| Approval's companion claim | none: the claim identifiers `x-pubky-switch-claim` and `pubky-switch.v1.approval` start the input (3.10) | identity key | not `lp()`: the identifiers' text, then the SHA-256 of the auth request's decoded secret, then the approval's JSON bytes, as `specs/pubky-auth-companion-claims.md` defines | appended to the claim's payload (3.10) |
| Freeze | `pubky-switch/v1/freeze` | identity key | body | signed document |
| Unfreeze | `pubky-switch/v1/unfreeze` | identity key | identity, freeze hash | `sig` of the unfreeze (3.6) |
| Import discarded | `pubky-switch/v1/discarded` | the next service's key, the one the freeze names | identity, freeze hash | `sig` of the discard answer (3.6) |
| Export transfer | `pubky-switch/v1/export-transfer` | identity key | body | signed document (3.11) |
| Next service's export request | `pubky-switch/v1/transfer-request` | the next service's key, the one the export transfer names | method, path and query, `hash(body)`, `Switch-Timestamp`, switch origin (the old service's), `Switch-Identity`, `Switch-Transfer` | `Switch-Signature` header (7.2) |
| Message | `pubky-switch/v1/msg` | sender app signing key | recipient identity, message JSON bytes | the plaintext's signature (4.5) |
| Request to the switch | `pubky-switch/v1/http` | app signing key, or the identity key | method, path and query, `hash(body)`, `Switch-Timestamp`, switch origin, `Switch-Identity`, `Switch-App`, `Switch-Cert`, `Switch-Invite-Code` | `Switch-Signature` header (7.1) |
| Response from the switch | `pubky-switch/v1/http-response` | the account's service key, or the operator key | `u64(status)`, `hash(request signature bytes)`, `Switch-Server-Time` text, `hash(body)` | `Switch-Service-Signature` header (7.1) |
| Operation | `pubky-switch/v1/op` | writer app, or the identity key | identity, body | signed document (6.1) |
| Service transition | `pubky-switch/v1/service-op` | service key | identity, body | signed document (6.5) |
| Transition proof | `pubky-switch/v1/proof` | service key | identity, body | signed document (6.5) |
| Signed head | `pubky-switch/v1/head` | service key | identity, `u64(chain_version)`, `u64(generation)`, `u64(seq)`, chain hash | `sig` of the head (6.7) |
| Export manifest | `pubky-switch/v1/export-manifest` | the old service's key | identity, body | signed document (10.2) |
| Push webhook | `pubky-switch/v1/push` | the registration's push key, never the service key | relay origin, body bytes | `Switch-Signature` header of the webhook (8.2) |

- **Identity** in a field list is always the account's identity: the identity whose inbox, records and chain these are. For a message it is the recipient's.
- **Request signature bytes** are the 64 bytes decoded from `Switch-Signature`. When the request has no decodable signature (a `401 bad_signature`, or an unknown route), the field is `hash` of the empty string.
- Vectors: `signatures.json` has one case per label, with each field, the exact signed bytes and the signature, and the rejections of 2.1; `http.json` adds requests and responses of every caller kind; `export.json` the export manifest, signed with the fixed service key of `keys.json`.

## 3. Records

### 3.1 App certificate

Signed by the identity key (label `pubky-switch/v1/app-cert`). The signer delivers it in the approval (3.10), the companion claim of the app's Pubky grant approval (spec 3.2). Apps send it in `Switch-Cert` to other identities' switches, inside their app record, inside every inbox entry they send (the feed's `cert`), and inside documents of their protocol.

| Field | Type | Req | Constraints | Notes |
|---|---|---|---|---|
| `v` | int | yes | 1 | |
| `kind` | string | yes | `pubky-switch.app_cert` | |
| `identity` | pubky | yes | the signer's identity | |
| `app_id` | app-id | yes | equals the App ID of `signing_key` | |
| `signing_key` | `b64(32)` | yes | Ed25519 public key | |
| `bundle_key` | `b64(32)` | yes | X25519 public key | key bundles are sealed to it (3.5) |
| `scopes` | `array<string>` | yes | at most 32, each once, each `name` or `name:<sub>` (Scope names, below), never a `name` beside one of its `name:<sub>` | the protocol's scope names, which the switch reads only as policy strings |
| `permissions` | `array<string>` | yes | the app's switch permissions, each a switch permission (below), each once, in their order | the switch authorizes by exactly these, never by `scopes`, which it reads only as policy strings. It is the union of what every scope in `scopes` needs, which may be the scopes of several protocols (Several protocols, below) |
| `issued_at` | time | yes | | |
| `expires_at` | time | yes | after `issued_at`, at most 730 days (2 years) after it | the signer sets it 365 days after `issued_at` by default (spec 3.2). Expired when the checker's clock is at or past it |
| `suite_keys` | `array<suite key>` | no | 1 to 4 entries, suites strictly ascending | bundle keys of later suites (spec 3.2); writers of this version omit it. A suite key is `{ "suite": int, "key": b64 }`, `suite` from 2 to 255 (the envelope suite byte, 4.1), `key` 1 to 4096 bytes; unknown members in an entry are refused (1.1). Readers ignore the keys of suites they don't support, which in this version is every suite; its kid is derived over suite and key (1.5) |

A verifier checks: the signature with the key of the identity it expects; `v` and `kind`; that the body has no unknown members (1.1); that `identity` is that identity; that `app_id` is derived from `signing_key`; that both keys are 32 bytes, that `bundle_key` isn't an X25519 key of low order (4.2), and both times parse; that `suite_keys`, if present, has the form above; that `scopes` follows the scope rule (Scope names, below); that `permissions` holds only switch permissions (below), each once and in their order; and that `expires_at` is present, not `null`, later than `issued_at` and at most 730 days after it. A certificate that fails any of these is invalid at every reader: the switch and every app. The switch then enforces exactly `permissions`. A protocol's verifiers also check its own scope rules and the permissions its scopes need (Several protocols, below); a certificate that fails these is invalid at those verifiers, though the switch takes it. Expiry is checked against the verifier's clock (the service uses its own time, 7.2). For the claim rules an app whose certificate has expired isn't current, so its open attempts are orphaned (6.8).

**Scope names** (spec 3.3). The switch knows no scope names, only this rule. A scope is `name` or `name:<sub>`: `name` is 1 to 32 characters of `a-z`, `0-9`, `_` and `-`, starting with a letter or digit, and `<sub>` is 1 to 32 characters of `a-z`, `0-9` and `-`, starting with a letter or digit. Wherever a scope is compared, for a record's `read_scope` and `write_scopes` (6.2, 7.4.9, 7.5) and for the keys an app holds (3.5), holding `name` covers every `name:<sub>`: a certificate holding `name` holds every one of its sub-scopes, and one holding `name:<sub>` holds only that one. That is the one rule of hierarchy among scopes, and the switch applies it. So a certificate never holds both `name` and a `name:<sub>`: holding both would say nothing more, and every verifier refuses such a certificate. A certificate holds at most 32 scopes in all; a protocol may keep lower bounds of its own. A sub-scope's key derives from its parent's (1.5). Vectors: `documents.json` `scope_rule`.

**Switch permissions** (spec 3.2). The switch permissions are these names, in this order: `claims.read`, `claims.write`, `lists.read`, `lists.manage`, `conversation.add`.

A list with a name not among them, one repeated or out of order is malformed, and every reader refuses it, the switch included. A well-formed list is enforced exactly as signed: the switch doesn't check the signer's derivation, so a signer that grants too much is honoured by the switch and refused by every verifier that understands all the certificate's scopes (Several protocols, below), and the signer is trusted with everything anyway. Vectors: `documents.json` `permission_rejections`.

**Several protocols** (spec 3.2). One certificate may hold the scopes of several protocols, so one app takes part in each of them under one App ID. The signer knows every scope a request names (3.9) and sets `permissions` to the union of the permissions each of them needs, in their order. A verifier understands the scopes of the protocols it knows, by their roots (Scope roots, below), and applies one rule: `permissions` holds every permission the scopes it understands need, and, when it understands every scope in the certificate, is exactly that list. So a verifier that knows every protocol of the certificate checks the exact union, one that knows only some of them checks that their permissions are present, and each applies its protocols' scope rules in full to their scopes and counts only them against their bounds. A scope of another protocol, and the switch permissions it brings, authorize nothing in the verifier's protocols: each of a protocol's messages and documents still needs the scope that protocol names for it.

**Scope roots** (spec 3.3). A scope's root is its `name`, the part before any `:`. Each protocol has a name, the one it uses under `protocols` in app records (3.2) and as the prefix of its kinds (5.1), and each root belongs to one protocol, so a reader never takes one protocol's scope for another's:

- A protocol's name is 1 to 32 characters of `a-z` and `0-9`, starting with a letter, without `_` or `-`. The rule is the same for every protocol: no name or root is set aside for one.
- Its roots are its name, or its name followed by `_` or `-` and more characters, such as `chat` and `chat_read` for a protocol named `chat`. A root's protocol is therefore the part before its first `_` or `-`, so no protocol's root is another's.
- A signer refuses to take a protocol whose name breaks these rules, or that claims a root other than its own, so two independent signers can't give one root to two protocols, even where only one of them is installed.
- A reader takes a root that isn't one of its own protocols' as another protocol's.

Kind prefixes follow the same rule: a kind's prefix, the part before its first `.`, is its protocol's name, or its name followed by `-` and more characters, such as `tasks-cap` for a protocol named `tasks`. A kind's protocol is therefore the part of its prefix before any `-`, so no protocol's kind is another's. The `kind` of the switch's own signed documents, such as `pubky-switch.app`, isn't a message kind, and this rule doesn't apply to it: signature labels keep documents and messages apart (2.3).


Example (`wallet`):

```json
{
  "v": 1,
  "kind": "pubky-switch.app_cert",
  "identity": "8y3qy4g9q7y9ownd18hskdoxdxzueutiu3f391rnnuxznxmqp5bo",
  "app_id": "w8amtmn13m6p5bwnmj9wejbq4c",
  "signing_key": "zBRPZWGzwLZBL6JkbhAtcqenmOAvuaEARhizaATmEOY",
  "bundle_key": "vX0u3QBiY5h9MwfEYToLHubYCoCUxY3XAnbnl5vrFQA",
  "scopes": [
    "tasks",
    "tasks_people",
    "tasks_people_admin"
  ],
  "permissions": [
    "claims.read",
    "claims.write",
    "lists.read",
    "lists.manage",
    "conversation.add"
  ],
  "issued_at": "2025-12-01T00:00:00.000Z",
  "expires_at": "2026-12-01T00:00:00.000Z"
}
```

### 3.2 App record

Signed by the app's signing key (label `pubky-switch/v1/app-record`). Delivered with `app.put` (6.2), served by the directory (7.4), and, for an app whose protocol needs it, published at `/pub/pubky-switch/v1/apps/<app_id>.json` on the Homeserver as the carrying form of 2.2.

| Field | Type | Req | Constraints | Notes |
|---|---|---|---|---|
| `v` | int | yes | 1 | |
| `kind` | string | yes | `pubky-switch.app` | |
| `identity` | pubky | yes | | |
| `app_id` | app-id | yes | equals the certificate's | |
| `signing_key` | `b64(32)` | yes | equals the certificate's | the key that verifies this record |
| `cert` | `signed<AppCert>` | yes | carrying form, signed by `identity` | |
| `accepts` | `array<string>` | yes | full kind strings of the app's protocol, such as `tasks.assignment` or an extension kind such as `tasks-cap.offer` | may narrow the certificate's scopes, never widen them (spec 3.4). The app signs its record, so it adds a kind under a scope it holds, such as an extension kind, without a new certificate |
| `protocols` | object | no | each member named by a protocol, with the syntax of a scope `name` (3.1); each value an object | default empty, and written as `{}` when the app's protocols add nothing. The members the app's protocols add to its record, each defined by its protocol, such as `tasks` for the `tasks` protocol. The switch checks only their form (Protocols' members, below) |
| `label` | `string \| null` | no | | display only |
| `updated_at` | time | yes | | the later `updated_at` wins between two copies; two different bodies with one `updated_at` are a conflict (Equal times, below; spec 4.2) |
| `expires_at` | `time \| null` | yes, always written | | chosen by the app; `null` means the record doesn't expire. A protocol may require one |

A verifier reads `signing_key` from the body, verifies the signature with it, then checks `v`, `kind` and `identity`, verifies `cert` for that identity, checks that the certificate names the same `app_id` and `signing_key`, and checks the form of `protocols` (below). A record that fails any of these is invalid at every reader, the switch included.

- **Protocols' members** (spec 4.2). `protocols` holds what the app's protocols add to its record: one member per protocol, under the protocol's name, such as `tasks`. A member's name has the syntax of a scope `name` (3.1): 1 to 32 characters of `a-z`, `0-9`, `_` and `-`, starting with a letter or digit. A protocol's own name is narrower, without `_` or `-` and starting with a letter, by the Scope roots rule (3.1), which signers apply. The switch checks only the form: `protocols` is an object, each name has that syntax, and each value is an object, or `null`, which is no member (Absent and null). Every reader refuses a record that breaks this, the switch included. Inside a member the rules of 1.1 hold as in the rest of the record: duplicate names, the integer rule, and unknown members, which readers ignore. The operation cap bounds the record with its members (6.1). The switch never reads inside a member, and a reader ignores the member of a protocol it doesn't know. A protocol's rules on its member, and on `expires_at`, are its own: a record that breaks them is invalid at that protocol's readers, though the switch takes it. Vectors: the app records of `documents.json` carry the member of `tasks`, `protocols.tasks`; the apps of `claims.json` belong to no protocol, and their records carry an empty `protocols`; `documents.json` `app_record_protocols` holds records that only the form check refuses, and two that every reader takes.
- **Equal times** (spec 4.2): each new record of an app has an `updated_at` later than every record of it the app delivered or published, on any of its devices. Two records of one app with the same `updated_at` and different body bytes are a conflict for every reader, wherever it read them. A reader uses neither record and tells the user; it goes on using an earlier record of that app it holds, if any, and can still use the identity's other apps. A record with a strictly later `updated_at` ends the conflict. The same body twice is one record. The switch refuses the second record of such a pair (6.2 `app.put`). A record whose `updated_at` is more than the clock tolerance, 5 minutes (spec 11), ahead of the reader's clock isn't used at all, so it takes part in no comparison. Vectors: `documents.json` `app_record_conflict`.
- **Deliver, then publish** (spec 4.2). The app delivers each new record to the service first (`app.put`) and publishes it on the Homeserver only after the service accepts it. If a publication fails, or the Homeserver copy differs from the newest record the service accepted from the app, the app publishes that newest record again, never an older one and never over a Homeserver copy with a later `updated_at`, until it deletes that record to leave, or leaves (spec 12.3).

Example (`shop`, with a public board and its 30-day `expires_at`):

```json
{
  "v": 1,
  "kind": "pubky-switch.app",
  "identity": "43xz73bjzs8c84sw4sigu5bm3x93mj17ywjy1oa3dbnriiymcw4o",
  "app_id": "ye9a6d8e43cq3f69kto91csqqe",
  "signing_key": "gmF0xGQzye0xpTkrPbj7ioEf0rf9CaPpEBCasQzNRPA",
  "cert": {
    "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLmFw...",
    "sig": "ohhwX8z64fjy4uk6QOqgDKOElHAm8HVBJgrAZzCJrydTkvwG6wWNMA2r5suhSQz4NpA3xcm47H73sCUPUC1uAQ"
  },
  "accepts": [
    "tasks.acceptance",
    "tasks.rejection",
    "tasks.cancellation",
    "tasks.done",
    "tasks.list_request",
    "tasks.resend_request",
    "tasks.share_proposal",
    "tasks.share_acceptance",
    "tasks.share_rejection",
    "tasks.share_end"
  ],
  "protocols": {
    "tasks": {
      "features": {
        "board_kinds": [
          "kanban",
          "checklist"
        ]
      },
      "public_boards": {
        "home": "board-7f3a"
      }
    }
  },
  "label": "bob shop",
  "updated_at": "2025-12-31T00:00:00.000Z",
  "expires_at": "2026-01-30T00:00:00.000Z"
}
```

### 3.3 `identity.json`

Signed by the identity key (label `pubky-switch/v1/identity`). Published at `/pub/pubky-switch/v1/identity.json` on the Homeserver as the carrying form of 2.2, delivered to the own switch with `PUT /v1/{id}/identity` and to other switches with `PUT /v1/{id}/peers`, and returned by the directory.

| Field | Type | Req | Constraints | Notes |
|---|---|---|---|---|
| `v` | int | yes | 1 | |
| `kind` | string | yes | `pubky-switch.identity` | |
| `identity` | pubky | yes | the signer | |
| `version` | int | yes | at least 1, increases on every update | |
| `generation` | int | yes | at least 1, increases on each provider change | |
| `signer` | `b64(16)` | yes | 16 bytes | the signer ID of the install that signs for the identity, picked at random when it first signs. Only the install the newest version names signs; an install that holds the identity key but isn't named refuses every signing call until it takes over (3.12, 3.13). A hand-over or a restore sets it to the new install's ID in its first delivery. Readers check its form and otherwise ignore it: the identity key's signature is what authorizes |
| `inbox` | object | yes | `{ "url": origin, "service_key": b64(32) }` | `url` is the switch origin exactly as requests sign it: `https://host[:port]`, no path, no trailing slash. `service_key` is the account's key from enrollment. Clients connect to it only as 7.1 "Switch origins" allows |
| `policy` | object | yes | see below | |
| `apps` | `array<object>` | yes | `{ "app_id": app-id, "cert": b64(32) }`, at most the app limit (3.7) | `cert` is the document hash of the app's certificate |
| `removed` | `array<object>` | yes | `{ "app_id": app-id, "distrust_from": time }` | |
| `data_epoch` | int | yes | at least 1, only increases | |
| `recovery_from` | `int \| null` | yes, always written | the generation lost in the most recent provider loss | |
| `record_max_age` | int | no | at least 1; absent when the identity sets none | the longest time, in seconds, that a reader relying on the identity's app records trusts one after its `updated_at` (spec 4.3); absent means 90 days (7776000) |
| `service_keys` | `array<object>` | no | `{ "generation": int, "key": b64(32) }` each, ascending by `generation`, each generation once, every one before this document's `generation`, at most 256; writers leave it out when empty, and readers treat a present `[]` as none | the service keys of earlier generations that kept proofs need (below); the current one is `inbox.service_key` |
| `renewed` | `array<object>` | no | below; absent when empty | earlier certificates of listed apps (3.8) |

`policy`:

| Field | Type | Req | Constraints |
|---|---|---|---|
| `admission` | string | yes | `contacts_and_conversations`, the only mode of v0.2 |
| `connect_requests` | object | yes | `{ "enabled": bool, "max_pending": int, "push": bool }`, each member required and none `null`; a signer writes `false`, `50` and `false` when the user sets none. `max_pending` is any `int`; the service caps it at its `max_connect_pending` (9.2) |

**Service keys** (spec 4.3). Each generation has one service key (3.7). The switch keeps transition proofs that are checked with their generation's key: the proof of each current record's write (7.4.9), and the proof of each entry of a live claim (6.8), which an export carries and the next service checks (10.5). These are its kept proofs here. It reports, in `GET /apps` (7.4.12), `proof_generations`: every generation that some kept proof names, its own included. In the document that starts the next generation, at every move and every key change in place, the signer lists in `service_keys` the key of every generation in the latest report other than the new one, the outgoing generation's included when it is reported, and drops only generations the report doesn't name. Without a report it drops nothing: it lists every key its last document listed, the outgoing generation's `inbox.service_key` added. It never drops a reported key: if the reported generations need more than 256 entries, or one whose key it doesn't hold, it refuses the move or key change, with an error that names the reason and an alarm shown to the user, until the records are rewritten or deleted, which moves their proofs to the current generation, and the claims are finished, which leaves tombstones without entries (6.8). The switch enforces the same at `PUT /identity` (below). A provider loss adds no key: the lost generation's proofs date nothing, so the report and the signer leave out every generation `recovery_from` declares lost. The identity key signs the list, so any reader, an app added after the change included, checks a transition proof of an earlier generation with it (6.2 step 2). Readers reject a document whose list breaks the constraints above. Vectors: `documents.json` "alice identity.json after the move to the next service", and `http.json` "signer: identity.json at generation 2 that leaves out generation 1's service key" with its `409 conflict`.

**Lists** (spec 4.3). An App ID appears at most once in `apps` and at most once in `removed`, and never in both; a reader rejects a document that breaks this. An App ID once in `removed` is never listed in `apps` again: an app holding a version that lists it as removed refuses a later version that lists it in `apps`, and alerts the user. Likewise `data_epoch` only increases: an app holding a version refuses a later version with a lower `data_epoch`, and alerts the user. The switch doesn't check `data_epoch` (below); the apps' check enforces it.

Rules the service enforces at `PUT /identity` (7.4.2):

- the document verifies for the account's identity;
- it lists at most the app limit announced at enrollment, else `400 bad_request`;
- it names the service key of every generation that a kept proof names (Service keys, above), in `inbox.service_key` or `service_keys`: the key itself, so a generation counts as left out unless every kept proof of it verifies with the key the document gives for it. Else `409 conflict` with `current.proof_generations`, the generations it leaves out; generations the document declares lost, its `recovery_from` and earlier, are exempt, since their proofs date nothing;
- the first document of an account enrolled without one has `version` 1, `generation` 1 and `data_epoch` 1, or carries `recovery_from`, its `generation` less one (a provider loss, spec 12.6), at any generation above 1, else `400 bad_request` (vectors: alice's version 1, delivered in `http.json` and chained at `chain.json` seq 1). A staged account holding no document takes its generation from that document: its chain starts with the `recovery` transition at that generation, `seq` 1 (7.4.2). A first document above generation 1 without `recovery_from` is `400 bad_request`. A reader learns nothing new from a first document at a generation above any it saw: as for every document, the identity key signed it, and the highest version at the highest generation wins (spec 4.3);
- **compare-and-swap** (spec 4.3): the delivery names, as `prev`, the document hash of the version it builds on, and that must be the newest version the service holds, else `409 stale_identity` with that copy (7.4.2); the first delivery to an account that holds none names `null`. The delivery that starts a provider loss's generation in place (below) is exempt: the loss may have taken the very versions the signer built on, so whatever version its `prev` names, or none, it needs only a higher version than the one held, its identity's signature, the pending key and the generation step bounding it. The same bytes as the newest version held succeed again without a new chain item, whatever `prev` they name (a retry), and answer with the original delivery's transition proof (7.4.2); an older version delivered again is `409 stale_identity`;
- a later document has a higher `version` and no lower `generation`, else `409 stale_identity`;
- a new `generation` is accepted only by an account that the newest document doesn't name yet (a staged account), or in place at a serving account: the document is at the next generation exactly and names this service's origin and the pending key an enrollment here answered (3.7); else `400 bad_request`. With `recovery_from` naming the generation that ends, it is a provider loss at the same service: the account starts afresh with the recovery record (7.4.2), keeping only its service time, its directory's `directory_version` and `apps_version` (7.4.10), its revoked and departed App IDs, and those the enrollments answered with the pending key named (3.7). Without, it is a key rotation: the sequence and chain continue under the new generation, signed with the new key. Either way the old key signs nothing more: the delivery is answered with the new key, and a request in flight that loaded the old key is answered as after the change, the operator's `503`, which its retry gets past under the new key, unless its answer was signed before the change's;
- `apps` lists no App ID that the version held lists in `removed`, and no App ID the service revoked or saw depart unless the version held still lists it (a departure awaiting its rotation), else `400 bad_request`. The service keeps those App IDs for good (9.1), so a revoked app is never current again, even after the signer purges it from `removed`;
- it doesn't check that `data_epoch` only increases: apps refuse a version that lowers it (Lists, above).

**The signer and the copies** (spec 4.3):

- **Deliver, then publish.** The signer delivers each new version to the service first and publishes it on the Homeserver only after the service accepts. If the Homeserver copy differs from the service's, the signer republishes the service's copy (the one `409 stale_identity` carries).
- **Never back** (spec 4.3). The signer keeps the generation, version and document hash of the newest version a service accepted from it, or that it adopted, a version it restored from its backup (3.13) included. It never adopts or republishes a copy with a lower version or generation, or another body at that version, whichever service or answer shows it: that is a rollback or an equivocation, which it shows the user as an alarm instead of building on it. A copy with a higher version, another signer's, it may adopt.
- **Equivocation.** Two documents with the same `version` and different body bytes are equivocation: an app that sees both, from any source, makes no attempt that relies on that identity and alerts the user. Apps keep `hash(body bytes)` of each `(identity, version)` they have seen. The same body under another signature isn't equivocation: it shows a signer that signed one version twice, against 2.1, and the service still treats it as another document (7.4.2). A switch that holds one body refuses a peer delivery of another at that version and answers with its copy (7.4.5), so the sender holds both.
- **Two copies.** A reader that holds both the Homeserver copy and the copy in the identity's directory (7.4.10) uses the one with the higher `version`.
- **The switch's copy** (spec 4.3). A reader about to act on an identity's public app records that holds no copy of the identity's document fresher than 10 minutes reads the Homeserver copy, then, in parallel with the app record reads that need only that document, the copy the identity's switch holds (7.4.15, at the `inbox.url` the Homeserver copy names). It waits for that answer at most until its record reads finish plus a short grace (the reference prototype: 500 ms), and uses the higher `version`: the same body at an equal version, and another body there is equivocation (above). A lower copy changes nothing, and still counts as an answer. The switch's copy is fetched now, so it counts as a fresh copy (spec 4.3), for 10 minutes like any other, whether it came from the service or from a cache (7.4.15). An app that only the newer copy lists has its record read then, one more read in that case only.
  - **A freeze in the answer** (7.4.15): the reader checks it as a freeze (3.6) with the identity's key, then reads the public read once more, at the freeze's `inbox.url`, and uses the higher of all the copies it holds. That answer without a freeze completes the lookup; `503 staged` there means the move isn't published, and the first answer's copy stands; a second freeze isn't followed, and the lookup has failed. A freeze that doesn't verify fails the lookup.
  - **No answer:** a lookup that hasn't answered after the grace keeps running. If, when the app is about to act, it has failed (no answer after the client's retries, an error status, a copy that doesn't verify) or still hasn't answered, an action the user starts goes ahead only with the user's explicit confirmation that the identity's switch couldn't confirm the identity's apps, given before the app writes anything for the action, and the app records an event for it; an answer that arrives first is used, before the app checks the records it acts on. An action without the user waits for the lookup, with the client's usual request timeout (the reference prototype: 5 s) and one retry, and isn't taken if it fails; it never acts on the Homeserver copy alone. A failed lookup counts until the reader looks up again, once its copy is more than 10 minutes old.
- **Revocations reach counterparties** (spec 12.2 step 5): when an own app sees, in its feed, a delivery whose `removed` adds an app, or whose `renewed` sets an `until` (a closed renewal, 3.8), it delivers that document with `PUT /peers` (7.4.5) to the switches it sent messages to that were accepted in the last 30 days, skipping a switch whose `known_version` (7.1) is already that version or newer.

**`renewed`** lists the earlier certificates of apps in `apps`, during and after a renewal (3.8). An entry:

| Field | Type | Req | Constraints | Notes |
|---|---|---|---|---|
| `app_id` | app-id | yes | | an entry whose app isn't in `apps` counts for nothing: it goes with its app when the app moves to `removed` |
| `cert` | `b64(32)` | yes | the document hash of an earlier certificate of that app | |
| `until` | `time \| null` | yes, always written | `null` while the renewal is in progress | the time the service took the app's record carrying the new certificate (`record_at`, 7.4.12) plus the 5-minute clock tolerance (3.8 step 4); for a reduction, the time the service took the renewing `identity.json` plus the tolerance, set at once (3.8 "Reductions") |

- **Bytes.** Writers put `renewed` last, after `recovery_from` and `record_max_age`, and omit it when it is empty, so a document without renewals has the same bytes as one written before renewals existed. Likewise they omit `record_max_age` when the identity sets none. Readers accept it anywhere (1.1); the spec's schematic example places it elsewhere, which means the same document.
- **Entries.** One per earlier certificate: a second renewal of the same app adds an entry for the certificate it replaces and keeps the older ones. Each takes about 100 bytes.
- **Purging** is the signer's choice (spec 4.3): only once it expects no more messages carrying that certificate, as stored requests keep theirs in use (the reference prototype: it never purges).
- **Meaning** (3.8, check 5): while `until` is `null` the earlier certificate counts like the listed one; once `until` is set it counts only for messages an inbox accepted before `until`.
- **At `PUT /identity`** the service checks only that each `cert` decodes to 32 bytes and each `until` parses (`400 bad_request`).

Example of the record age limit: `documents.json` "alice identity.json, record age limit (version 6)" is alice's version 3 document at version 6 with `"record_max_age": 2592000` (30 days) after `recovery_from`.

Example: alice's version 4 during a renewal of `wallet` (`documents.json` "alice identity.json, wallet renewal in progress"). The renewal drops `tasks_people_admin` and expires earlier, so it is a reduction, and since `tasks_people_admin` has keys it rotates the data epoch (3.8 Reductions). Its members are those of the version 3 example below, except `version`, which is 4, `data_epoch`, which is 3, and the hash `apps` lists for `wallet`, which is now the renewed certificate's (`m9qO1CMcSOGDUYWn26M2RJ4vNRJcXJdM6bhBatyn_08`). After `recovery_from` comes the `renewed` member below. Version 5 ("... renewal closed") is the same with `until` set to `2026-01-01T00:08:00.000Z`: the service took version 4 at `00:03:00`, and the signer closed the reduction at once, adding the 5-minute tolerance (3.8 Reductions).

```json
{
  "renewed": [
    {
      "app_id": "w8amtmn13m6p5bwnmj9wejbq4c",
      "cert": "D7UeJkS3FxHaOrpvgTVoD7ft790HEp2wiEceSAogOhE",
      "until": null
    }
  ]
}
```

Example (alice, version 3, with a removed app):

```json
{
  "v": 1,
  "kind": "pubky-switch.identity",
  "identity": "8y3qy4g9q7y9ownd18hskdoxdxzueutiu3f391rnnuxznxmqp5bo",
  "version": 3,
  "generation": 1,
  "signer": "zxbf_4P_t4vlYbtZ2ZuLNQ",
  "inbox": {
    "url": "https://inbox.example",
    "service_key": "L6IOM-v3HiTYgBIMYK5KXA6oVE6lcRcBsruRMkqbGjI"
  },
  "policy": {
    "admission": "contacts_and_conversations",
    "connect_requests": {
      "enabled": false,
      "max_pending": 50,
      "push": false
    }
  },
  "apps": [
    {
      "app_id": "w8amtmn13m6p5bwnmj9wejbq4c",
      "cert": "D7UeJkS3FxHaOrpvgTVoD7ft790HEp2wiEceSAogOhE"
    },
    {
      "app_id": "c1utah9jitjs43etzdkj6cqdwr",
      "cert": "wxm2nzYAOo4eQH7VN1N9aNQlf3cDLAoLU9y6rBbsp0A"
    },
    {
      "app_id": "f4dtxinwdkb55gdwksph85m18w",
      "cert": "fy6JFZbVm8eQkZLbGn_6diR4CqWG_k-n-dhhJ2j5Bwk"
    }
  ],
  "removed": [
    {
      "app_id": "jiksqs9ixqfbgtingdjqh3sosc",
      "distrust_from": "2025-12-15T00:00:00.000Z"
    }
  ],
  "data_epoch": 2,
  "recovery_from": null
}
```

### 3.4 Receive key record

Signed by the app's signing key (label `pubky-switch/v1/receive-key`). Registered with `receive_key.put` (6.2) and served by the directory.

| Field | Type | Req | Constraints | Notes |
|---|---|---|---|---|
| `v` | int | yes | 1 | |
| `kind` | string | yes | `pubky-switch.receive_key` | |
| `identity` | pubky | yes | the app's identity | |
| `app_id` | app-id | yes | the signing app | |
| `n` | int | yes | 0 for an app's first key at a service, then exactly one more each time; after a provider loss, the first record at the new service has any `n` higher than every `n` the app has registered (6.2) | |
| `kid` | `b64(8)` | yes | equals the kid of `x25519` | |
| `x25519` | `b64(32)` | yes | X25519 public key, not of low order (4.2) | |
| `suite_keys` | `array<suite key>` | no | as in 3.1; no entry's kid equals `kid` | receive keys of later suites (spec 4.4); writers of this version omit it, readers ignore suites they don't support |

Senders check a record before wrapping to it, in the order of spec 8.1: its signature with the app record's `signing_key`; the app record's certificate; that the app is current with that certificate; that `identity` and `app_id` name that identity and app; that `n` isn't lower than the highest seen for that app; that `kid` is derived from `x25519`, which isn't of low order; and that `suite_keys`, if present, has its form. Unknown members make the record invalid (1.1). A record that fails is skipped: the sender seals the message to the identity's other apps (spec 8.1).

**Unexpected registrations** (spec 3.6). An app watches the `receive_key.put` items of its own app in its feed, and the current record a `409 conflict` names. A registration whose kid it doesn't know, and that no device of the app announced through the app's own device sync, is a compromise: someone holding the app's signing key, from a copied state or a backup, registered a key of its own. The app stops (no attempts, no further reads), alerts the user, calls `leave` at once (7.4.12) and asks the signer to revoke it with `distrust_from` at the `server_time` of the registration's chain item. An app run on several devices holds an unknown registration as pending until its device sync shows whether one of its devices made it (the reference prototype: `known_kids` holds the kids it registered, `pending_registrations` those pending).

**After a restore** (spec 3.6, 12.4). The backup knows the app's kids up to its newest key, of number `b`. A registration with `n > b` whose kid the restored app doesn't know, up to the key the restored app registers itself, may be its own or a thief's: the app asks the user, makes no attempts until the answer, and on a "no" proceeds as above. A registration after its own new key that it doesn't know is a compromise at once. (The reference prototype: `b` is `restored_n_floor`, the open question `restore_unaccounted`.)

Example (`wallet`, its first key):

```json
{
  "v": 1,
  "kind": "pubky-switch.receive_key",
  "identity": "8y3qy4g9q7y9ownd18hskdoxdxzueutiu3f391rnnuxznxmqp5bo",
  "app_id": "w8amtmn13m6p5bwnmj9wejbq4c",
  "n": 0,
  "kid": "U0tWwIxdGyk",
  "x25519": "s5JU_dJRw_bydtQ51Glju9Fd6kTGSLGR0j2tHpDca3Q"
}
```

### 3.5 Key bundle

A key bundle is a JSON object, not a signed document:

| Field | Type | Req | Notes |
|---|---|---|---|
| `envelope` | b64 | yes | an envelope (Section 4) with one recipient: the target app's bundle key |
| `sig` | `b64(64)` | yes | identity key signature, label `pubky-switch/v1/key-bundle`, over `lp(label, identity, target app ID (16 bytes), envelope bytes)` |

- **Envelope:** recipient identity is the identity itself, so the HPKE `info` is `lp("pubky-switch/v1/hpke", identity, kid of the bundle key)`; the kid is that of the bundle key; `notify` is 0.
- **Plaintext:** `u32_be(len(JSON)) || JSON || zero padding` (4.5), with this JSON:

  | Field | Type | Req | Notes |
  |---|---|---|---|
  | `v` | int | yes | 1 |
  | `kind` | string | yes | `pubky-switch.key_bundle` |
  | `naming_key` | `b64(32)` | yes | the identity's naming key (1.5) |
  | `cert` | `b64(32)` | yes | the document hash (2.2) of the app certificate (3.1) the bundle or part was made for: the approval's certificate at approval (3.10), the new one at a renewal (spec 3.2 step 1), otherwise the app's current certificate |
  | `first_epoch` | int | yes | the first data epoch the bundle, or the part (below), holds keys for; 1 for a full bundle and its first part |
  | `last_epoch` | int | yes | the last data epoch the bundle or the part holds keys for; for a bundle in one part, or a bundle's last part, the data epoch it was made for; at least `first_epoch` |
  | `keys` | `array<scope key>` | yes | exactly one for each keyed scope of the certificate `cert` names and each data epoch from `first_epoch` to `last_epoch`, and no other. A keyed scope is a scope of the certificate that its protocol gives keys (spec 3.5); a sub-scope's keys are its sub-scope keys (1.5). No certificate holds both a name and one of its sub-scopes (3.1), so this has one meaning: a part for a certificate holding a name carries no keys of its sub-scopes, which its app derives, and one for a certificate holding sub-scopes only carries exactly their keys. A keyed scope that a later version of a protocol adds needs a new certificate version (`v`), as a change to the protocol's permission table does, so a reader never meets keys for a scope name it doesn't know |

  A scope key is `{ "data_epoch": int, "scope": string, "key": b64(32) }`: `scope_key(data_epoch, scope)` (1.5). A key outside `first_epoch..last_epoch`, a key for a scope that isn't a keyed scope of that certificate, a `(scope, data_epoch)` pair twice, or a pair of the certificate's keyed scopes and the range missing makes the bundle or part invalid, and the reader skips it (Reading, below). Unknown members are ignored (1.1). The bundle's signature covers the identity, the target and the envelope, not the epochs `key_bundle.put` and `GET /keys` name in the clear, so a reader compares those with these (Reading, below).
- **At approval** (spec 3.2, 3.5) the app gets its scope keys for every data epoch so far and the naming key as a full bundle of this format, sealed to its certified bundle key, inside the approval (3.10). No Pubky grant carries them, and the companion claim's plaintext holds none either (the reference prototype: it hands the approval over in process).
- **Incremental bundles** (spec 3.5). A bundle holds only the epochs the app lacks: those after the newest epoch through which the app holds every key (`keys_through` in `GET /apps`, 7.4.12), up to the current one. The signer reads `keys_through`; when the service shows none (a new app before any bundle, or after a provider loss), it stores a full bundle. A bundle that replaces one the app never fetched starts where the app's holdings end, so nothing is skipped.
- **Full bundles on request.** An app that, after fetching its bundle, still lacks a scope key for some data epoch up to the current one (after a restore from an old backup) asks once with `POST /v1/{id}/apps/{app_id}/keys` (7.4.11); the signer, when next online, stores a full bundle for each app with a pending request, a bounded number each run, the oldest requests first, made for the app's current certificate, in parts when it is large: every epoch from 1 to the current one, whatever the parts it stored for that certificate already cover. The app that asks may have lost what those parts gave it, and the request is answered only by a put that completes the range, so storing only the ranges not yet covered would leave a request made while every epoch is covered pending for good. The service shows only the ranges of the stored parts (`bundle_ranges`, 7.4.12), so the signer keeps which certificate each part it stored names, and passes that on in a hand-over or a backup (`bundle_parts`, 3.12); a range whose part names another certificate, or one it can't tell, counts as missing. The new parts replace every part made for another certificate, which the app skipped. When the app's record at the service carries a certificate other than the current one (`record_cert`, 7.4.12), the signer also stores the current certificate with `cert.put`, in the batch of the first part, as at a renewal (3.8 step 1): an app restored from a backup older than its renewal, or one at a new service after a provider loss, may never have seen that `cert.put`, and takes the parts once it holds the certificate. The request stays pending until the stored parts together cover every epoch from 1 to the current one.
- **Size:** each scope key takes 81 to 160 bytes of compact JSON, by the length of its `scope` and its `data_epoch`, so one 64 KiB envelope holds about 400 to 800 of them. The keys of the vectors' apps take about 90 bytes each, about 700 to an envelope (708 with the executor's three scopes). Incremental bundles stay small while the app keeps up.
- **Parts** (spec 3.5). A bundle whose envelope would exceed 64 KiB, such as a full bundle of three scopes over 300 data epochs, or the delta of an app offline through many rotations, is stored as several bundles, each a `key_bundle.put` (6.2) covering a contiguous range `[first_epoch, last_epoch]` and each within 64 KiB. Each part is signed and sealed on its own, with the naming key and the scope keys of its range only, so an app opens it without the others. (The reference prototype: it seals the whole range, and halves a range whose envelope doesn't fit until each half does.) The parts stored for an app never overlap; the app fetches them all (7.4.11) and merges their keys. A delivery cut short leaves whole parts stored, and the signer resumes it from where it stopped, with the rest of the parts it signed, which it keeps until they are sent. Every renewal stores, with its `cert.put`, a full bundle made for the new certificate (spec 3.2 step 1): its range, from epoch 1 to the current one, or to the next one for a renewal that rotates the data epoch (3.8 Reductions), covers every part stored for the app, so its parts replace them all, and every part stored for an app names its newest certificate. A renewal cut short between two parts leaves parts made for the earlier certificate; the app skips them and asks for a full bundle. No part holds `switch_root` or a key for an epoch after the one it was made for: the current one, or during a rotation the next one, whose parts the signer stores before it publishes the document that raises the epoch (spec 3.2 and 12.2 step 2).
- **Reading** (7.4.11): for each part the app verifies `sig` with the identity key, opens the envelope with its bundle secret, checks `v`, `kind` and the epoch range and that the naming key is the one it holds, and merges the keys into its state. The naming key never changes (spec 3.5): the app keeps the one it was approved with. `key_bundle.put` names `first_epoch` and `last_epoch` in the clear (6.2), since data epochs are public in `identity.json`. For the parts of a `GET /keys` answer:
  - The app refuses the whole answer when its parts, by the ranges they name in the clear, are out of `first_epoch` order or overlap, since merging them would pick between two keys. It takes no part from it. An empty `bundles` is none.
  - It skips a part that doesn't verify or open, and also:
    - a part whose plaintext `first_epoch` and `last_epoch` aren't the range it names in the clear, since the signature doesn't cover the clear epochs, so a service could relabel a part;
    - a part with a key for an epoch after the next one, the newest `data_epoch` the app knows plus one (Parts, above). At approval there is no next one: a part with a key after the approval document's `data_epoch` is refused (3.10);
    - a part whose naming key differs from an earlier part's or from the one the app holds, since an identity has one naming key; the app alerts the user, since taking it would split its obligation IDs and record keys from the other apps';
    - a part whose `cert` names neither the certificate the app presents nor a renewal of it (a later certificate for the same App ID, signing key and bundle key, with a later `issued_at`, 3.8) that the app's newest `identity.json` lists for its App ID, whose body the app has from `cert.put` in its feed or from its own record (3.8 step 3): a stale part, or one the app can't check;
    - a part whose keys aren't exactly one for each keyed scope of that certificate and each data epoch of its range: a key of another scope, a pair twice, or a pair missing. Taking it could give the app a key its certificate doesn't grant, or leave it to choose between two keys for one pair.

    The other parts still count. A part made for a renewal that the app's newest `identity.json` doesn't list yet is skipped like a stale one; the app reads it again when it next lacks a key, once it holds that `identity.json`.
  - A data epoch that no part the app takes covers isn't a reason to skip anything: after merging, its keys show as lacking, which leads to `POST /keys` (Full bundles on request, above).

  Vectors: `envelopes.json` `key_bundle` (a part naming the executor's certificate) and `key_bundle_rejections` (an extra scope, a pair twice with conflicting keys, a pair missing, and a certificate the reader doesn't hold).

Example plaintext JSON (the `executor` app's incremental bundle at data epoch 2, `envelopes.json` `key_bundle`; `cert` is the `doc_hash` of `documents.json`'s executor certificate, whose three scopes it holds a key each for):

```json
{
  "v": 1,
  "kind": "pubky-switch.key_bundle",
  "naming_key": "o1_nXfz228_ODE-GMGVszj3o5IhKlx7hOH3uYl6TI8M",
  "cert": "fy6JFZbVm8eQkZLbGn_6diR4CqWG_k-n-dhhJ2j5Bwk",
  "first_epoch": 2,
  "last_epoch": 2,
  "keys": [
    {
      "data_epoch": 2,
      "scope": "tasks",
      "key": "-wIBL-ZWhO2cPb_611j056TqFoL4vfgIc7F-X6ndyUI"
    },
    {
      "data_epoch": 2,
      "scope": "tasks_share",
      "key": "BfCsE-uaNYgXje2vqrt2SlBP3BQ9A8uPOWMYOcNqBcY"
    },
    {
      "data_epoch": 2,
      "scope": "tasks_share_run",
      "key": "Nzu-x2K_G6GApK4vSpDhytDCfuupJScBmg012fqLCqs"
    }
  ]
}
```

### 3.6 Freeze and unfreeze

The freeze is a signed document (label `pubky-switch/v1/freeze`), sent as the body of `POST /v1/{id}/freeze` (7.4).

| Field | Type | Req | Constraints | Notes |
|---|---|---|---|---|
| `v` | int | yes | 1 | |
| `kind` | string | yes | `pubky-switch.freeze` | |
| `identity` | pubky | yes | the account's identity | |
| `inbox` | object | yes | `{ "url", "service_key" }` of the new service N | as in `identity.json` |
| `next_generation` | int | yes | the current generation plus one | |
| `issued_at` | time | yes | | |
| `nonce` | `b64(16)` | yes | random | |

Its **freeze hash** is the document hash (2.2).

- **Kept before it is sent:** the signer keeps the signed freeze before it sends it and sends those same bytes again until it has an answer, so a lost answer never leaves it without the freeze the service may have applied. The service answers the same freeze again with its original proof (7.4.13).
- **Used once:** a freeze an unfreeze cancelled is never applied again (`409 conflict`), so a replay can't freeze the account after an abort. A new move signs a new freeze, with a new `nonce`.
- **Shown to readers:** while the account is frozen, its public read of `identity.json` carries the freeze beside the document (7.4.15), so a reader holding an old document that names this service finds the next one.

The unfreeze, the body of `POST /v1/{id}/unfreeze`, is a JSON object:

| Field | Type | Req | Notes |
|---|---|---|---|
| `freeze_hash` | `b64(32)` | yes | the freeze it cancels |
| `sig` | `b64(64)` | yes | identity key, label `pubky-switch/v1/unfreeze`, over `lp(label, identity, freeze hash)` |
| `discarded` | object | at the old service, required | N's discard answer, below; absent in the unfreeze sent to N |

**Discard answer** (spec 12.5 Abort). The signer sends the unfreeze to N first. N discards the import bound to that freeze and answers, in the body of its `200`, with a JSON object signed with N's service key, the key the freeze names:

| Field | Type | Req | Notes |
|---|---|---|---|
| `discarded` | `b64(32)` | yes | the freeze hash |
| `sig` | `b64(64)` | yes | label `pubky-switch/v1/discarded`, over `lp(label, identity, freeze hash)` |

The signer then sends the unfreeze to O with that answer as `discarded`. O checks it with the service key the freeze names and resumes only then (`409 conflict` without it, or when it doesn't verify), so O and N never both accept writes (10.6).

Example freeze:

```json
{
  "v": 1,
  "kind": "pubky-switch.freeze",
  "identity": "8y3qy4g9q7y9ownd18hskdoxdxzueutiu3f391rnnuxznxmqp5bo",
  "inbox": {
    "url": "https://inbox.next.example",
    "service_key": "6FWRmADt_5se6vWPbPzsmizJDM9aLablPEpo5K-drd8"
  },
  "next_generation": 2,
  "issued_at": "2026-04-11T00:00:00.000Z",
  "nonce": "LXeO2-_LVf4L1TLryxRHWA"
}
```

Example unfreeze (as sent to N; `documents.json` `discarded` has N's answer, signed with the key of seed `service/alice/next`, and the unfreeze carrying it):

```json
{
  "freeze_hash": "k38YxzhWMzgCiPkN4jU2cXzCIAA4IRK8zYvrFH6kLQA",
  "sig": "IqdY0k5nHtitP6FH6YKzd9z8Q5L1h0IcF2qu3fMHDaDaD81zsD3NmvqxGwMNBCOsTkAwLobit4w3k-4ujr9zCg"
}
```

### 3.7 Enrollment request and answer

`POST /v1/enroll` (spec 4.3, 6.2). The request is signed by the identity key like any signer request (7.1), and its body carries a separately signed enrollment, so a retry sends the same enrollment under a new request signature.

**Enrollment** (signed document, label `pubky-switch/v1/enroll`):

| Field | Type | Req | Constraints | Notes |
|---|---|---|---|---|
| `v` | int | yes | 1 | |
| `kind` | string | yes | `pubky-switch.enroll` | |
| `identity` | pubky | yes | equals `Switch-Identity` | |
| `origin` | string | yes | the service's origin | a service refuses an enrollment naming another origin |
| `nonce` | `b64(16)` | yes | random, fresh per enrollment | |
| `policy` | object | yes | as in `identity.json` | the policy of the delivered `identity.json` applies; this one is informational while the account is staged |
| `identity_doc` | `signed<IdentityDoc>` | no | the current `identity.json` | present for a new provider (spec 12.5); absent for a new identity and after a provider loss. The enrollment's body travels base64url-encoded inside the signed enrollment (2.2), so the `identity_doc` it carries takes about a third more than in `PUT /identity`. A signer keeps every version it signs small enough that a move's enrollment carrying it, with `revoked_apps`, fits `POST /enroll`'s 256 KiB body cap (7.1), as well as `PUT /identity`'s; otherwise the identity can't move |
| `revoked_apps` | `array<app-id>` | no | unique, ascending by their text (as 10.3 sorts part keys, not by the bytes they decode to, since z-base-32's alphabet isn't in ASCII order); absent when empty | every App ID the signer revoked or saw depart, which it keeps for good (spec 12.5, 12.6). At a provider loss, an App ID the recovery's document still lists, revoked but not removed yet, is left out: the document would be refused, and the signer revokes the app at the new service right after the delivery (spec 12.6 step 1). A new account keeps each as a tombstone from the start (9.1), dated by the enrollment, so it never serves or lists them, also after a provider loss, when no export carries them; an import's activation keeps them so (10.5) |

**Request body:** `{ "enrollment": signed<Enrollment> }`.

**Answer** (`200`), signed by the response signature with the new account's service key:

| Field | Type | Notes |
|---|---|---|
| `service_key` | `b64(32)` | the account's service key; the signer verifies the response signature with it |
| `limits` | object | see below |
| `identity` | pubky | the enrollment's |
| `origin` | string | the enrollment's |
| `nonce` | `b64(16)` | the enrollment's |
| `enrollment` | `b64(32)` | the document hash of the signed enrollment it answers; the signer checks it |

`limits`:

| Field | Type | Default (9.2) | Meaning |
|---|---|---|---|
| `app_limit` | int | 32 | most apps in `identity.json`, never above 255 |
| `max_envelope` | int | 65536 | envelope cap in bytes |
| `max_sealed_value` | int | 262144 | sealed value plaintext cap in bytes |
| `quota_bytes` | int | 67108864 | inbox quota (Section 9) |
| `max_batch` | int | 8 | entries per batch |
| `record_quota_bytes` | int | 67108864 | shared record quota (Section 9) |
| `max_import_bytes` | int | 4294967296 | the largest export this service imports (9.2); a signer moves an identity only to a service whose import limit is at least its current one's (7.4.13). An answer without it stands for the default |

**Further limits.** `limits` carries only the seven members above. The retention and quota limits of Section 9 (record keys, claims, attempts per claim, lists, invite codes, connect requests, retired receive keys, peer copies, enrollment answers, the operation rate, the chunk size) aren't announced yet. Until they are, a client assumes the defaults of Section 9.2. When a service announces them, it adds them to `limits` under the names of the Name column of 9.2 (Appendix A5); clients ignore members they don't use (1.1).

- The same enrollment again gets the same answer, byte for byte, while the key it names is the account's or its pending key. Once a delivery has started a generation under another key (3.3), the key that enrollment's answer named signs nothing more, so the same enrollment again is `409 conflict`, signed with the operator key like every enrollment error (7.4.1). To tell it from an enrollment it never answered, the service keeps, for every enrollment it answered for the account, the enrollment's hash and the generation of the key its answer named; at a generation change it deletes the answers themselves only in the commit that keeps that record of them. It keeps at most `max_enrollments` such records, the oldest dropping: the same enrollment again after its record dropped is answered as a new enrollment, which the signer takes as well. The signer takes this `409` as "enroll again": it signs a new enrollment, with a new nonce, and sends it.
- Another enrollment for an existing account gets the same key and limits, with its own `nonce` and `enrollment`, and changes nothing, while the account is staged. At an account the newest `identity.json` names (a serving account), it gets instead a pending key for the next generation, the same for every such enrollment until a document names it (3.3), signed with that key; each service key serves one generation. That is how a provider loss is declared at the same service, and how the signer rotates the service key.
- The account stays staged (`503 staged`, 7.3) until it holds an `identity.json` whose `inbox.url` and `inbox.service_key` name it.
- Enrollment errors are signed with the operator key (7.1), at an account that exists too (7.4.1).
- An enrollment whose `revoked_apps` holds a member that isn't an App ID, isn't unique and ascending by text, or is present but empty, is `400`. An enrollment for an existing account changes nothing by itself. At a staged account its `revoked_apps` count for nothing: the account keeps those of its first enrollment. At a serving account, the `revoked_apps` of every enrollment answered with the pending key are held with that key, and join the account's tombstones when the delivery naming the key starts the new generation (3.3); if no such delivery comes, nothing changes.

Example enrollment:

```json
{
  "v": 1,
  "kind": "pubky-switch.enroll",
  "identity": "8y3qy4g9q7y9ownd18hskdoxdxzueutiu3f391rnnuxznxmqp5bo",
  "origin": "https://inbox.example",
  "nonce": "y6aw9gQLsoxRMM6deQh0gA",
  "policy": {
    "admission": "contacts_and_conversations",
    "connect_requests": {
      "enabled": false,
      "max_pending": 50,
      "push": false
    }
  }
}
```

Example answer:

```json
{
  "service_key": "L6IOM-v3HiTYgBIMYK5KXA6oVE6lcRcBsruRMkqbGjI",
  "limits": {
    "app_limit": 32,
    "max_envelope": 65536,
    "max_sealed_value": 262144,
    "quota_bytes": 67108864,
    "max_batch": 8,
    "record_quota_bytes": 67108864,
    "max_import_bytes": 4294967296
  },
  "identity": "8y3qy4g9q7y9ownd18hskdoxdxzueutiu3f391rnnuxznxmqp5bo",
  "origin": "https://inbox.example",
  "nonce": "y6aw9gQLsoxRMM6deQh0gA",
  "enrollment": "lC6Xmj6jfvx2H_zixYqVwcHKlpdT6Mn87HJLx8TmrEY"
}
```

### 3.8 Certificate check order and renewal

**Check order** (spec 3.4). The service, recipients, senders and other readers of app records check an app in this order and stop at the first check that fails:

| # | Check | At the service | A recipient, sender or other reader |
|---|---|---|---|
| 1 | The certificate verifies with the identity key (3.1) | `401 bad_signature` | drops the message, or skips the app |
| 2 | Its `identity` and `app_id` are the expected identity and app, `app_id` derives from `signing_key`, and that key is the one the request, message or record is checked with | `401 bad_signature` | as 1 |
| 3 | It hasn't expired: `expires_at` is later than the service's time for a request, the entry's `accepted_at` for a message, the reader's clock for sending or for acting on a record | `403 cert_expired` | as 1 |
| 4 | The request (7.1), message (4.5) or app record (3.2) signature verifies with `signing_key` | `401 bad_signature` | as 1 |
| 5 | The certificate's standing (below) in the newest `identity.json` held counts | own app: `403 not_current`; another identity's app: `409 identity_needed`, or `403 not_current` when the certificate's renewal has closed; an app that copy lists in `removed` is answered exactly like a stranger (7.2) | as 1 |
| 6 | The app record is signed with `signing_key` and carries this certificate, or an earlier one of the same app with the same `signing_key` and `bundle_key` | `403 not_current` | skips the app |

Then come scopes and switch permissions (`403 permission_missing`; recipients drop the message), admission (spec 7) and each endpoint's own checks. The service takes the checks in the order of 7.2: the timestamp first, and for an app of another identity check 3 after check 4, so that signature work comes before the checks that read its state; a request that passes every check is treated the same either way.

- **The timestamp** (7.1) is checked right after check 4, so a stale request is refused only once it is authenticated.
- **Why 4 before 5.** Checks 1 to 3 need only what the caller presents and a clock; check 4 authenticates the caller before the service consults anything it holds for the account. If check 5 came first, anyone holding an app's public certificate could learn, without that app's key, whether this switch holds its identity's `identity.json`, which shows that the two identities correspond.
- **Which certificate.** The service checks an own app against the renewed certificate it stored with `cert.put` once the newest `identity.json` lists that certificate's hash, and otherwise against the one in the app's record (from `app.put`, or from the `app.put` in the body of the app's first call, 7.2). For an app of another identity it checks the one in `Switch-Cert`. A recipient checks the one the inbox entry carries (the feed's `cert`), a sender the one in the app record it read in a directory (7.4.10), another reader the one in the record it acts on.
- **Standing** of a certificate with hash h for app a in an `identity.json` D (check 5):

  | Standing | When | Counts for a message accepted at t | Makes the app current now |
  |---|---|---|---|
  | listed | D's `apps` lists a with h | yes | yes |
  | renewed, open | D's `apps` lists a with another hash, and `renewed` has an entry for a and h with `until: null` | yes | yes |
  | renewed, closed | as above, with `until` set | if t is more than 5 minutes before `until` (5.1 check 7) | no |
  | removed | D's `removed` lists a | if t is at least 5 minutes before `distrust_from` (5.1 check 7) | no |
  | none | otherwise | no | no |

  "Current now" decides wherever the app acts at present: the service serving its requests and accepting its appends, a sender wrapping to it, a reader acting on its record. "Counts at t" decides for a message, with t its `accepted_at` (spec 11).
- **Check 6** applies where a record is involved: the record the service holds for each own app, the records a sender reads in a directory, and the public record another reader acts on (spec 4.2).
- **Readers acting on a record** refuse it once its app's listed certificate has expired (check 3 at the reader's clock).

**Renewal** (spec 3.2). A renewed certificate is a new certificate for the same app: the same `app_id`, `signing_key` and `bundle_key`, and a later `issued_at`; `scopes`, `permissions` and `expires_at` may change. Other keys make a new app (spec 12.1).

1. The signer stores the new certificate with `cert.put` (6.2), in the same batch as the first `key_bundle.put` of a full bundle made for it (3.5). The bundle's parts replace every part stored for the app, whether the renewal adds scopes, removes them or keeps them, so every stored part names the newest certificate. Both operations target an app the newest `identity.json` lists, whatever its certificate's expiry (6.2), since that document lists the new certificate only from step 2.
2. It delivers and then publishes `identity.json` with a higher `version` (3.3), listing the new certificate's hash for the app and adding the earlier hash to `renewed` with `until: null` (3.3). From this delivery the service checks the app against the stored renewed certificate: its expiry, switch permissions and scopes apply at once, also to requests the app signed earlier.
3. The app reads `cert.put` in its feed (7.5) and takes the certificate once its own `identity.json` lists its hash. An app that holds an earlier certificate and no `cert.put` for the listed one, such as one restored from a backup older than a renewal it took (the `cert.put` keeps only its stub once the record carries the new certificate, 7.5), reads its own entry in `GET /directory` (7.4.10). It takes the record's certificate only if the record verifies with its own signing key (3.2) and the certificate verifies for the identity (3.1), names its own `app_id`, `signing_key` and `bundle_key`, has a later `issued_at` than the one it holds, and has the hash `identity.json` lists for the app; it takes that record as its own too, since the service already holds it. It does this before it reads its key bundle parts. From then on it presents it (`Switch-Cert`, the `cert` its inbox entries carry, documents of its protocol), follows its scopes, and delivers its record carrying it with `app.put`. An app that publishes its record republishes it on the Homeserver.
4. `GET /apps` (7.4.12) shows, for each app, `record_cert`, the certificate hash of the record the service holds, and `record_at`, when the service took it. Once `record_cert` is the new hash, the signer sets the entry's `until` to `record_at` plus the clock tolerance, 5 minutes (spec 3.2 step 4), in its next `identity.json` and delivers it. A renewal isn't a distrust event, so the tolerance goes on the side that keeps the app's last messages: recipients count the earlier certificate for a message accepted more than 5 minutes before `until` (5.1 check 7), that is, before `record_at`, when the app stopped presenting it.

- **Reductions** (spec 3.2). A renewal is a reduction when the new certificate lacks a scope or a switch permission of the earlier one, or expires earlier. Its cutoff doesn't wait for the app: right after the delivery of step 2, the signer delivers a further `identity.json` that sets `until` of every renewed entry of the app still `null` to the service time at which the service took that delivery, plus the 5-minute tolerance, and then publishes it. The time is the `server_time` of the chain envelope in the delivery's transition proof (6.5). A retry of a delivery whose answer was lost gets that proof again (7.4.2), so the time is always the service's, never the signer's clock. Step 4 doesn't apply. Recipients count the earlier certificate for a message accepted more than the tolerance before `until`, so before that delivery (5.1 check 7). Renewals that only add scopes or extend the expiry follow steps 3 and 4.
- **A removed scope's keys rotate** (spec 3.2, 12.2). A reduction whose new certificate lacks a scope with keys of the earlier one rotates the data epoch from e to e+1: a keyed scope (3.5), such as a sub-scope with keys of its own, or a name replaced by some of its sub-scopes, whose key derives every sub-scope's (in the `tasks` protocol: `tasks`, `tasks_assign:team1`, or `tasks_assign` replaced by `tasks_assign:team1`). One that removes only scopes without keys, a switch permission or expiry doesn't, and neither does dropping a sub-scope that its name in the new certificate covers (such as `tasks_assign:team1` when the new certificate holds `tasks_assign`). The full bundle of step 1 runs from epoch 1 to e+1 and is made for the new certificate, so it holds no key of the removed scope; then the signer stores each other current app's bundle for e+1, with its own scopes' keys, as at a revocation (spec 12.2 step 2); then step 2's delivery lists the new certificate and raises `data_epoch` to e+1, in one `identity.json`, as a revocation's delivery moves the app and raises it. The closing delivery follows as above. From that delivery the service takes sealed fields only at e+1 (`409 stale_epoch`), so the reduced app holds no key for anything written under the removed scope after it, whoever hands it the ciphertext. Vectors: the wallet renewal of `documents.json`, which removes `tasks_people_admin`, raises `data_epoch` from 2 to 3 in version 4, and `envelopes.json` `reduction_key_bundle` is the wallet's full bundle for it.
- **A closing delivery owed.** A signer stopped between the renewing delivery and the closing one leaves the earlier certificate open until it returns. At its next run, before any other delivery and before a provider change, it finds the closing delivery it owes from the newest `identity.json` the service holds (`GET /apps`, 7.4.12): every `renewed` entry still `null` whose renewal was a reduction, which it judges from the certificates it issued. It delivers that version again, a retry: it is still the renewing delivery, so the answer carries that delivery's proof, and the signer closes from its time as above. After a provider loss the lost service can't answer, so the document that starts the recovery closes it instead (spec 12.6 step 1).
- **In between.** While `until` is `null` the earlier certificate counts wherever the app presents it: other inboxes accept appends carrying it, recipients accept its messages, and senders and other readers use the record that carries it. Once `until` is set, a switch refuses a request presenting it (`403 not_current`), and recipients accept a message carrying it only if its inbox accepted it more than the 5-minute tolerance before `until` (5.1 check 7), so before `record_at`, or for a reduction before the renewing delivery. A sender skips an app whose record carries a certificate whose renewal has closed (check 5, "current now"), until the app delivers its record with the new certificate.
- **Directory caches** (spec 8.1): a sender's cached directory belongs to the `identity.json` version it was read under; once the sender holds a newer version, it reads the directory again before its next send, so an app given a scope receives its kinds as soon as its new record is delivered. An app that lost a receiving scope receives its kinds no longer from each sender's next send after that sender sees the closing version: through the Homeserver event stream, an append answer whose `directory_version` is newer (7.4.3), or its re-fetch of a copy more than 10 minutes old (spec 8.1). Until then the sender's appends may still wrap those kinds to the app, and the inbox can't refuse them, since kinds are sealed and `apps_version` doesn't change on a renewal. So a removed receiving scope stops at most the sender's directory cache lifetime after the cutoff. A removed sending scope has no such delay: recipients reject a message carrying the earlier certificate that their inbox accepted after the cutoff (5.1 check 7).
- **Earlier messages** keep the authority they were sent with: a message stored in a record still verifies and can be acted on (spec 11).
- **Removing a scope** applies at once at the service and, since the reduction closes the earlier certificate in the same signer step, at recipients: a switch holding the closing `identity.json` refuses the earlier certificate (`403 not_current`), recipient apps checking against it reject messages accepted after the cutoff (5.1 check 7), and senders stop wrapping to the app from their next send after they see the closing document (Directory caches, above). Own apps deliver the closing document to the switches they wrote to in the last 30 days, as after a revocation (3.3). The app keeps that scope's keys for every data epoch so far, so the removal of a scope with keys also rotates the data epoch (A removed scope's keys rotate, above).
- **An expired certificate** fails check 3, so the service refuses every request of that app, its feed read included. A renewal the signer stores and lists brings it back without anything from the app: the service takes the signer's `cert.put` and key bundle for it although its certificate has expired (step 1, 6.2), and from the delivery of step 2 it checks the app against the renewed certificate, so the app's next request, its feed read included, passes check 3. The app then reads the `cert.put` in its feed and takes the certificate (step 3).
- **At the service** a stored renewed certificate is dropped once the app's record carries it (its `cert.put` item keeps only its stub, 7.5), or replaced by a newer `cert.put`. At most one is kept per app (Section 9).

### 3.9 App request

How an app asks the signer to approve it (spec 3.2, 12.1 step 1). It travels with the app's Pubky auth request (`specs/pubky-auth-companion-claims.md`). It is a signed document (2.2), signed with the app's signing key (label `pubky-switch/v1/app-request`), so it proves the app holds that key: nobody can ask for a certificate naming another app's signing key with a bundle key of their own.

| Field | Type | Req | Constraints | Notes |
|---|---|---|---|---|
| `v` | int | yes | 1 | |
| `kind` | string | yes | `pubky-switch.app_request` | |
| `app_id` | app-id | yes | equals the App ID of `signing_key` | |
| `signing_key` | `b64(32)` | yes | Ed25519 public key | it verifies this request |
| `bundle_key` | `b64(32)` | yes | X25519 public key | |
| `scopes` | `array<string>` | yes | scopes as in 3.1, as the protocols the app takes part in define them under their roots (3.1), each once and each with the scopes it requires, and never a name beside its own sub-scope | a name the signer doesn't know is refused, though a certificate's reader would ignore it |
| `client_id` | string | yes | the auth request's client ID (`cid`) | |
| `client_key` | `b64(32)` | yes | the auth request's client key (`cpk`) | the key the Pubky grant is bound to |
| `caps` | string | yes | the auth request's capabilities, exactly as it carries them | |
| `secret_hash` | `b64(32)` | yes | `hash(secret)` of the auth request's 32-byte secret | binds the request to one handshake |

It names no identity: the user picks the identity in the signer. Unknown members make it invalid (1.1).

**The signer checks**, in this order, and refuses the request at the first failure:

1. It verifies with `signing_key`; `v` and `kind` are right; `app_id` derives from `signing_key`; both keys, `client_key` and `secret_hash` are 32 bytes; `bundle_key` isn't an X25519 key of low order (4.2), since every reader refuses a certificate naming one (3.1); the scopes are valid (3.1), no name is named beside one of its sub-scopes, and none is a name the signer doesn't know.
2. `client_id`, `client_key` and `caps` are the auth request's, and `secret_hash` is the hash of its secret.
3. `caps` names exactly the app's own paths (spec 3.4), each `path:rw`, joined by `,`, each once: its record `/pub/pubky-switch/v1/apps/<app_id>.json`, always; its backup folder `/priv/pubky-switch/v1/apps/<app_id>/`, optionally; and the paths the app's protocol adds, only as that protocol allows. Anything else is refused, and so is any path that covers `/pub/pubky-switch/v1/identity.json` or the signer's backup `/pub/pubky-switch/v1/signer-backup.json` (3.13): that path or a folder it lies in, such as `/pub/pubky-switch/` or a root grant.
4. The App ID isn't one the signer revoked or saw depart, which it keeps for good (spec 12.2), and isn't in `removed`.
5. The App ID isn't listed, unless the request names exactly the `signing_key` and `bundle_key` it is listed with: approving it then renews the app's certificate (3.8). A listed App ID is never given other keys.
6. A new App ID fits the app limit (3.7).

The signer then shows the user the App ID, the scopes and the capabilities, with what each path a protocol added is for. The user may decline any of those paths, as that protocol's rule on its paths allows: a protocol may require some of its paths together, which the user then allows or declines as one (spec 3.4). The signer refuses a request whose paths from a protocol already break that protocol's rule, a decline of any other path, the app's record and backup folder included, and a set of declines that breaks a protocol's rule. On approval it issues the certificate, with the scopes asked for whatever was declined, delivers and publishes the `identity.json` that lists it (3.3), grants the Pubky capabilities checked less the declined paths, in the order the auth request names them, and nothing else, and answers with the approval (3.10). A request from a listed app that renews it (step 5) is approved the same way: its grant covers what that request names less what the user declines there, and a path it leaves out isn't declined (spec 3.4).

Example (`wallet`, `documents.json` "wallet app request"; `documents.json` `auth_request` has the auth request it binds):

```json
{
  "v": 1,
  "kind": "pubky-switch.app_request",
  "app_id": "w8amtmn13m6p5bwnmj9wejbq4c",
  "signing_key": "zBRPZWGzwLZBL6JkbhAtcqenmOAvuaEARhizaATmEOY",
  "bundle_key": "vX0u3QBiY5h9MwfEYToLHubYCoCUxY3XAnbnl5vrFQA",
  "scopes": [
    "tasks",
    "tasks_people",
    "tasks_people_admin"
  ],
  "client_id": "wallet.example",
  "client_key": "ZdRdUHBwBGPRoRiu68ae07U7yZsZQA9R8hYN7csdtvw",
  "caps": "/pub/pubky-switch/v1/apps/w8amtmn13m6p5bwnmj9wejbq4c.json:rw",
  "secret_hash": "E25R1Ja9oaRFvsz-oM635SOXcvEuxtuJ0tTDWq3zg4k"
}
```

### 3.10 Approval

What the signer returns to an approved app, as the companion claim of its Pubky grant approval (spec 3.2, 3.5). It carries only public material and one sealed key bundle. Whoever holds the auth request's secret, and so can read the claim from the relay, learns no key: the secret protects only the handshake. A JSON object:

| Field | Type | Req | Notes |
|---|---|---|---|
| `v` | int | yes | 1 |
| `kind` | string | yes | `pubky-switch.approval` |
| `request` | `b64(32)` | yes | the document hash (2.2) of the app request it answers (3.9) |
| `cert` | `signed<AppCert>` | yes | the app's certificate (3.1) |
| `identity` | `signed<IdentityDoc>` | yes | the `identity.json` version that lists the certificate, as delivered to the service (3.3) |
| `bundles` | `array<object>` | yes | the app's full key bundle (3.5), as parts `{ "bundle": key bundle, "first_epoch": int, "last_epoch": int }` in `first_epoch` order, from epoch 1 to the document's `data_epoch` |

Readers ignore unknown members (1.1). The bundle is the format of 3.5: sealed to the certified `bundle_key`, signed by the identity key, holding the naming key and the app's scope keys, in parts when it doesn't fit one envelope.

**The companion claim** (`specs/pubky-auth-companion-claims.md`). The approval's JSON bytes are the claim's unsigned payload. The app's auth request announces the claim with the query pair `x-pubky-switch-claim=pubky-switch.v1.approval`: query parameter `x-pubky-switch-claim`, claim type `pubky-switch.v1.approval`. Claim identifiers allow only letters, digits, `-`, `_` and `.`, so the switch's label is written with dots. The identity key signs `UTF8("x-pubky-switch-claim|pubky-switch.v1.approval|") || SHA-256(decoded auth secret) || approval JSON bytes`, and the claim's plaintext is those JSON bytes followed by the 64-byte signature. That input starts with `x`, so it is no input of any other format the identity key signs (2.1). The app checks the signature with the identity key before it reads the approval. No vector covers it (the reference prototype: it hands the approval over in process and signs no claim).

**The app checks**, and refuses the approval at the first failure:

1. `v` and `kind` are right, and `request` is the hash of the request it sent.
2. `cert` verifies for the identity (3.1) and names the app's own App ID, `signing_key` and `bundle_key`.
3. `identity` verifies for the identity and lists the certificate's hash for the app.
4. It reads `bundles` by the rules of 3.5 "Reading", as it reads every later bundle, holding no naming key yet: the first part it takes sets it, and every other part must carry the same one. Every part's `cert` must be the document hash of the approval's `cert`, and every part must be taken, so each holds exactly one key for each keyed scope of the certificate (3.5) and each data epoch of its range, and together they cover every data epoch from 1 to the document's `data_epoch`. No part goes past it: the signer makes the approval's bundle for the document the approval carries, so here the next epoch of 3.5 Reading is that `data_epoch` itself, and a part with a key for `data_epoch + 1` is refused.

It then keeps the certificate, the scope keys and the naming key, and follows spec 12.1 step 2.

The approval is the same whichever paths the user allowed. The app learns which it holds from its Pubky session, which lists the capabilities the Homeserver granted it; a path it asked for and lacks was declined (spec 3.4).

Example (`documents.json` `approval`, the wallet's at data epoch 2, its signed members shortened):

```json
{
  "v": 1,
  "kind": "pubky-switch.approval",
  "request": "9koaj3xs6EwmTHvNRYdqIrfV90Zlf_f54RcF2WCgwfs",
  "cert": { "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLmFw...", "sig": "3SnTaXtQ..." },
  "identity": { "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLmlk...", "sig": "ysIV9UOQ..." },
  "bundles": [
    {
      "bundle": { "envelope": "UFNXMQEBAAEISgTv...", "sig": "btIAmTAm..." },
      "first_epoch": 1,
      "last_epoch": 2
    }
  ]
}
```

### 3.11 Export transfer

The signer's authorization for the next service N to fetch one export's chunks from the old service O itself, so the export doesn't pass through the signer's device (spec 12.5 step 3). A signed document (2.2) under the identity key, label `pubky-switch/v1/export-transfer`, signed over `lp(label, body)`. The signer signs it once per manifest and keeps it (2.1, Sign once).

| Field | Type | Req | Constraints | Notes |
|---|---|---|---|---|
| `v` | int | yes | 1 | |
| `kind` | string | yes | `pubky-switch.export_transfer` | |
| `identity` | pubky | yes | the account's identity | |
| `freeze_hash` | `b64(32)` | yes | the document hash of the signed freeze (3.6) | |
| `manifest_hash` | `b64(32)` | yes | the document hash of O's signed manifest (10.2) | |
| `from` | object | yes | `{ "url", "service_key" }` of O: its origin and the account's key there | as in `identity.json` |
| `to` | object | yes | `{ "url", "service_key" }` of N, as the freeze names it | |
| `issued_at` | time | yes | | informational |

Unknown members are refused (1.1).

- **N presents it** to O in the header `Switch-Transfer`, in compact form (2.2), on `GET /v1/{id}/export/chunks/{chunk_id}`, signing the request with `to.service_key` (label `pubky-switch/v1/transfer-request`, 7.2). It takes the transfer only at `POST /import` (10.4).
- **O serves the chunk** only if the transfer verifies with the identity key, `identity` is the account, `freeze_hash` is the freeze the account is frozen with, `from` is O's own origin and the account's key, `to` is the next service the freeze names, `manifest_hash` is the hash of the manifest O built for that freeze, and the request verifies with `to.service_key` (7.2). Otherwise `401 bad_signature` (a signature) or `403 not_admitted` (a transfer that doesn't name this export). Under a transfer, a caller may fetch chunks and nothing else (`403 permission_missing`).
- It needs no expiry: it names one freeze and one manifest, and both end with an abort (10.6) or the move.
- Vectors: `documents.json` "alice export transfer", `signatures.json` (both labels), `http.json` "next service: export chunk fetch under the export transfer" and its answer.

### 3.12 Signer hand-over

How a signer hands the identity to a new signer (spec 12.8). The new signer is a current app of the identity, and the hand-over is sealed to the bundle key its certificate names, as a key bundle is (3.5). It travels through the switch: the old signer stores it for the target app with `PUT /v1/{id}/handover`, and the target app fetches it with `GET` (7.4.17). A JSON object, not a signed document:

| Field | Type | Req | Notes |
|---|---|---|---|
| `envelopes` | `array<b64>` | yes | 1 to 128 envelopes (Section 4, `max_handover_parts` of 9.2), in order, each with one recipient: the new signer's certified bundle key. The recipient identity is the identity itself, so the HPKE `info` is `lp("pubky-switch/v1/hpke", identity, kid of the bundle key)`; `notify` is 0 |
| `sig` | `b64(64)` | yes | identity key signature, label `pubky-switch/v1/signer-handover`, over `lp(label, identity, the new signer's App ID (16 bytes), u32_be(n), envelope_1 bytes, ..., envelope_n bytes)`, n the number of envelopes, so it binds the count and the order |

- **Parts:** the JSON below is split into n parts, in order, and part i is the plaintext of envelope i: `u32_be(len(part)) || part || zero padding` (4.5). The sender splits where it likes, each part fitting one envelope: at most 65,364 bytes, the 65,368 bytes of plaintext a one-recipient envelope holds less the length. With at most 128 parts the JSON is at most 128 x 65,364 = 8,366,592 bytes.
- **The bound holds every state the other limits allow.** `identity_doc` fits `PUT /identity`'s 256 KiB body cap (7.1), so it is at most 262,119 bytes here as the `identity_doc` member. A move's enrollment, which carries it again inside its base64url-encoded body (3.7), keeps it smaller still; the bound takes the larger. That document references at most 1,884 certificates: 255 apps, the most `app_limit` allows, and as many `renewed` entries as the rest of it holds. A certificate is at most 3,599 bytes here, the largest the Switch allows in compact JSON: 32 scopes of the longest form, `name:<sub>` with 32 characters on each side (3.1), all five switch permissions, times with three fraction digits (1.6), and no `suite_keys`, which writers of this version omit: 6,780,516 bytes for all of them. The number of certificates doesn't depend on their size, since `identity_doc` names each by its hash. `revoked_apps` fits an enrollment within the same body cap, since the signer names it in every enrollment (3.7): at most 6,766 App IDs, 196,214 bytes. `bundle_parts` holds at most 2,048 entries of at most 153 bytes, 315,409 bytes with its member name. With the other members the JSON is at most 7,554,688 bytes, 116 parts; a backup's `prev` (3.13) adds 53 bytes, and `pending_distrust`, at most one entry of 82 bytes for each of the 255 listed apps, 21,186 bytes. So `max_handover_parts` is 128 (9.2): 8,366,592 bytes, with 790,665 to spare.
- **Plaintext:** the parts, concatenated in order, are this JSON:

  | Field | Type | Req | Notes |
  |---|---|---|---|
  | `v` | int | yes | 1 |
  | `kind` | string | yes | `pubky-switch.signer_handover` |
  | `identity` | pubky | yes | the identity handed over |
  | `identity_secret` | `b64(32)` | yes | the identity key's 32-byte Ed25519 secret (seed) |
  | `identity_doc` | `signed<IdentityDoc>` | yes | the newest `identity.json` a service accepted from the old signer (3.3): its version, generation and document hash are the old signer's high-water mark, and its `inbox.service_key` and `service_keys` the service keys the signer keeps |
  | `revoked_apps` | `array<app-id>` | yes | every App ID the old signer revoked or saw depart (3.7), kept for good: unique and ascending by text, as in 3.7, and `[]` when there are none. The new signer reads it as a set |
  | `certs` | `array<signed<AppCert>>` | yes | the certificates `identity_doc` references, and no other: that of every app it lists in `apps` and each earlier one in its `renewed` |
  | `limits` | object | yes | the `limits` of the switch's enrollment answer (3.7) |
  | `bundle_parts` | `array<object>` | yes | the key bundle parts the signer stored at the switch for each app `identity_doc` lists, made for that app's listed certificate: `{ "app_id": app-id, "first_epoch": int, "last_epoch": int, "cert": b64(32) }`, at most 2,048, `[]` when there are none. The receiver counts these ranges as stored for that certificate (3.5 Full bundles); a part left out is one it can't tell, so it only stores it again. Entries for an app or a certificate `identity_doc` doesn't list are ignored, and so are repeated entries; ranges aren't checked against the data epoch, since a part left out is simply stored again |
  | `prev` | `b64(32)` | no | in a backup only (3.13): the document hash of the version `identity_doc` builds on; absent in a hand-over |
  | `pending_distrust` | `array<object>` | no | for each revocation the signer asked for and no version carried out yet, a member of `revoked_apps` that `identity_doc` still lists, the earlier `distrust_from` the user picked (spec 12.2): `{ "app_id": app-id, "distrust_from": time }`, unique and ascending by App ID text; absent when there are none. A reader ignores an entry for any other App ID; records without the member give each pending revocation the switch's revocation time. A hand-over's is always absent: no hand-over starts while a revocation it asked for is owed, which it would carry as records rather than send. In an in-place restore, where the install's own records and the backup both hold a time for an App ID, the earlier one counts |

  Unknown members are ignored (1.1).
- **Only referenced certificates:** the new signer acts on certificates only through `identity.json`. It renews a listed app, closes a listed renewal and judges a reduction against the listed certificate (3.8). A certificate that `identity.json` no longer references plays no part in its decisions: a removed or revoked app is handled by App ID (`removed`, `revoked_apps`), and readers judge old writes and messages from the certificates the records and messages carry, never from the signer. So `certs` stays within the bound however long the identity lives.
- **The old signer** seals it only to an app its newest `identity.json` lists as current, with that app's certificate, once that version is delivered and no closing delivery is owed (3.8), and not during a move (Section 10). It stores the hand-over at the switch for the new signer (7.4.17), which keeps it until the next `identity.json` version. From then on it is handing over: it signs nothing for the identity but an abort or a take-back (below), and keeps the key and these records. A signer that can't tell whether the switch stored the hand-over, after a lost answer, is handing over all the same, and aborts as for a lost target. It stores the hand-over again, the same bytes, only while the switch's copy is still `identity_doc`: once the switch holds a newer version, a hand-over stored again would only offer a new signer an export that has already taken effect or been aborted. The hand-over takes effect when the new signer's delivery wins the compare-and-swap (below). While handing over, the old signer writes nothing to the Homeserver, neither `identity.json` nor its backup, until its abort or its take-back (below) has won, so it never republishes the switch's copy (3.3 "Deliver, then publish"). It deletes the key, then these records, only on proof that another install holds the identity (spec 12.8):
  - the switch's copy (`GET /apps` `identity`, 7.4.12, or the `current` of a `409 stale_identity` answering its abort or take-back) verifies for the identity, is newer than `identity_doc`, names another install (3.3), and isn't its own abort, documents compared whole (1.5); and
  - the signer backup on the Homeserver (3.13) opens with the identity's backup key, verifies, and holds as its `identity_doc` a version newer than the handed-over one naming that same install.

  Only a holder of the identity key can make that backup, and the new signer writes it only once its key is stored (below), so neither the switch nor the Homeserver, alone or together, can make both the old and the new signer delete the key. Until it sees that proof, the old signer keeps the key and these records, and signs nothing but an abort or a take-back. A newer copy that is neither that proof nor its own abort or take-back is judged as at a delivery (3.3): the old signer stops, as an install that isn't named, keeps the key, and looks for the proof again at each run. Its own abort or take-back at the switch means that delivery won.
- **The new signer checks**, and refuses the hand-over at the first failure:
  1. `envelopes` holds 1 to 128 envelopes; `sig` verifies with the identity key over its own App ID, their number and their bytes, in order; every envelope opens with its bundle secret, and their parts, concatenated in order, parse as the JSON; `v`, `kind` and `identity` are right; and `identity_secret` is the secret of the identity's key. So parts swapped, a part missing or added, or a count that isn't the parts', refuse it.
  2. `identity_doc` verifies for the identity (3.3) and lists the new signer's app; every certificate it lists, in `apps` and `renewed`, is among `certs`, and each of `certs` verifies for the identity (3.1). A certificate of `certs` that `identity_doc` doesn't reference, which a sender of this version doesn't include, is ignored: it plays no part in the new signer's decisions.
  3. The switch's copy of `identity.json` (`GET /apps` `identity`, 7.4.12) is `identity_doc` itself, and the Homeserver's is neither newer than `identity_doc`, by version or generation, nor another document at its version. A switch copy that is newer, older or missing refuses the hand-over: a newer one shows an abort or another signer got ahead, and an older one or none shows the switch went back, where a delivery built on `identity_doc` would be refused. Documents compare whole, by document hash (1.5): the same body under another signature is another document, as at `PUT /identity` (7.4.2), so such a copy refuses the hand-over too.

  It then takes as revoked the App IDs of `revoked_apps`, of `identity_doc`'s `removed` and those `GET /apps` shows revoked or departed, and delivers the next version of `identity.json`, `identity_doc`'s version plus 1, with `prev` the hash of `identity_doc` (7.4.2) and `signer` its own install's ID (3.3). A member of `revoked_apps` that `identity_doc` still lists is a revocation the old signer asked for and no version carried out: it is pending again, and the new signer revokes the app at the switch and delivers the version that removes it (spec 12.2). The hand-over takes effect when that delivery succeeds, and the switch then deletes the stored hand-over.
  - **Kept until decided:** from before it first sends its delivery until the delivery is decided and its key is stored, the new signer keeps the hand-over it fetched, the install ID it picked and the signed delivery in storage as spec 3.1 requires: the switch deletes its copy of the hand-over once it takes the next version (7.4.17). Checks 1 to 3 are made once, before that first send, and so is a check that its secure storage can take the key: one that holds another key refuses the hand-over, nothing stored. From then on only the answers to the delivery, sent again with the same bytes, decide.
  - **The answers:** a `409 stale_identity` whose copy is the delivery itself, compared whole (1.5), means it won and the answer was lost. A `409 stale_identity` cancels the hand-over only when its copy verifies for the identity, is at or above the delivery's version and names another install (3.3): an abort or another signer got ahead. Any other answer, or no answer, decides nothing, a `409` with no copy, an older one or one that doesn't verify among them: the delivery is sent again, the same bytes, and nothing is deleted. A definite refusal that repeats, such as `400`, `403` or `409 conflict`, leaves the hand-over undecided; the new signer tells the user it can't take over yet, and the old signer's abort is the way out. Once its delivery has won, nothing cancels the hand-over, and the new signer never deletes the key on any later answer.
  - **After the win,** in this order: it stores `identity_secret` in its secure storage, reads it back and checks it is the identity's key; it writes its backup (3.13); once the backup is written, it publishes the version, the republishing of 3.3 "Deliver, then publish" included. Until the key is stored, the secret lives only in the hand-over it keeps. A store or read-back that fails keeps that hand-over, and the new signer tries again; until it succeeds it is the named signer without a usable key, while the old signer keeps the key (above, with the take-back as the way out if it never succeeds). A backup write that fails stays owed (3.13), and publication waits for it. The old signer's deletion relies on this order.

  A second hand-over of the same export, or one another signer got ahead of, fails step 3, or the compare-and-swap of that delivery. A new signer that refuses a hand-over once an envelope has opened, at check 1, 2 or 3, for any reason, or whose delivery is cancelled, deletes `identity_secret` and the records it received, and tells the user that the hand-over was refused or cancelled. So whether check 3 or the compare-and-swap stops it after an abort that won, it keeps no copy of the identity key. A refusal or a cancellation deletes only what that hand-over brought, never a key the install held before it arrived, in its secure storage or in another hand-over it keeps: an install that already signed for the identity, or held its key, keeps it whatever hand-over it fetches. So a hand-over stored again, or served again by a faulty switch, after it took effect, costs nothing.
- **Abort** (spec 12.8): until the hand-over takes effect, the old signer may abort it, on the user's choice. It signs the abort only while the switch's copy is still `identity_doc`, compared whole (1.5): once the switch holds a newer version, it signs nothing and judges that copy as above, since an abort at that version plus 2 could be another document at a version the new signer has since signed. It delivers `identity_doc`'s content again at `identity_doc`'s version plus 2, with `prev` the hash of `identity_doc`; once the abort has won, it writes its backup (3.13) and then publishes it, and the switch deletes the stored hand-over, as at any new version. The new signer's first version is `identity_doc`'s plus 1. The abort uses plus 2 so that it never has the same version as that first version: two different documents at one version would be equivocation (3.3), and the same bytes would be answered as a retry (7.4.2). With both building on `identity_doc`'s hash, exactly one wins the compare-and-swap. An abort that wins kills the export: the new signer fails check 3, or its delivery gets `409 stale_identity`, and either way deletes what it received (above). The old signer is the signer again, and may seal a new hand-over from the abort's version, to another app or the same one. An abort that loses gets `409 stale_identity` naming another install's version: the old signer stops, and deletes the key and its records once it sees the proof above. An abort whose answer was lost is sent again, the same bytes, a retry; the old signer never takes its own abort, held at the switch, for the new signer's version.
- **Take-back** (spec 12.8): an old signer whose switch copy verifies, is at `identity_doc`'s version plus 1 and names another install, but that sees no proof (above), may take the identity back, on the user's confirmation that that install is lost. It delivers that copy's content naming its own install as `signer`, with `prev` that copy's hash, at a version above that copy's and above every version it signed, its abort included, so it never signs two documents at one version (3.3). Once that delivery has won, it writes its backup (3.13) and then publishes, and the old signer is the signer again, as after an abort; a take-back that loses leaves it stopped, keeping the key. A take-back whose answer was lost is sent again, the same bytes, as an abort is. The compare-and-swap decides a race with a new signer that is still alive, which then finds itself not named (3.3) and stops, keeping its key. Both installs then hold the key and neither deletes it, so each tells the user.
- Vectors: `envelopes.json` `signer_handover` (alice's signer to her phone app, in two parts, with fixed randomness), `signer_handover_rejections` (the parts swapped, a part missing, and a signature whose count isn't the parts') and `signatures.json` (its label). The abort of that hand-over is `documents.json` "alice identity.json, hand-over abort (version 5)"; `http.json` "signer: hand-over delivery after an abort won" is the phone's take-over delivery of version 4 that it got ahead of, and its answer `409 stale_identity` names version 5. `http.json` "signer: store the hand-over to the phone at the switch" and "own app: the phone fetches the hand-over stored for it" carry `signer_handover` through the switch, with their answers.

### 3.13 Signer backup

The signer's records, backed up as a hand-over addressed to the identity itself (spec 12.8). It lives on the Homeserver at `/pub/pubky-switch/v1/signer-backup.json`, which only the signer writes and no app's grant covers (3.9). It is public ciphertext: anyone sees its size and when it changes. A JSON object, the form of 3.12:

| Field | Type | Req | Notes |
|---|---|---|---|
| `envelopes` | `array<b64>` | yes | 1 to 128 envelopes (Section 4), in order, each with one recipient: the identity's backup key (1.5). The recipient identity is the identity itself, so the HPKE `info` is `lp("pubky-switch/v1/hpke", identity, kid of the backup key)`; `notify` is 0 |
| `sig` | `b64(64)` | yes | identity key signature, label `pubky-switch/v1/signer-backup`, over `lp(label, identity, u32_be(n), envelope_1 bytes, ..., envelope_n bytes)` |

- **Parts and plaintext:** as in 3.12: the parts, concatenated in order, are a hand-over's plaintext, with `identity_doc` the newest version the signer signed, and with `prev`, the document hash of the version `identity_doc` builds on, absent for a first version. The bound of 3.12 holds.
- **When it is written:** before each delivery of a new version of `identity.json`, holding that version, so it is never behind the switch's copy; and after the signer stores key bundle parts, holding the same version, so `bundle_parts` lists them. A write that fails stops the delivery. The deliveries that race another signer, a new signer's first one after a hand-over (3.12) or a restore (below), an abort and a take-back (3.12), write it once they have won instead, so a delivery that loses never overwrites the winner's backup; a write that fails then stays owed, the signer tells the user, and the next attempt writes it, with the checks every write makes ("Another install's backup", below).
- **Size:** at the limits a backup is 128 envelopes of 64 KiB, 11,185,390 bytes of JSON (the largest state of 3.12 fills 116 of them), so the signer's Homeserver must accept a file that large. A Homeserver that refuses the write stops the delivery, as any failed write does: the backup is written first, so the signer changes nothing, and it tells the user.
- **Another install's backup:** before it writes, the signer opens the backup it finds. One that names another install (3.3) at or past this signer's high-water mark (3.3: the newest version a service accepted from it, or that it adopted, a restored one included) shows that install has taken over: the signer writes nothing and refuses this and every later signing call, as an install that isn't named (3.3). The exception is a losing delivery's backup: one whose `identity_doc` builds on the same document as the mark (its `prev` is the mark's `prev`, compared whole) and isn't the mark itself. The service accepted the mark on that `prev`, so it accepted no other document on it, whatever that one's version; the signer is still the signer, and its write replaces that backup. A take-over never looks like this: it builds on the newest version the service held, or on one after it, never on what that version built on. A restored mark that is still the source install's own document, held by the source's backup, is that backup itself, not a losing one, so it shows the source still signs. The rule holds because the only mark a signer holds without a backup of its own on the Homeserver is the first version it won by racing another signer (a restore's, a new signer's first one after a hand-over, an abort, or a take-back), since every other version is backed up before it is delivered; and what an install that lost that race built on is what the winner built on. A backup that doesn't open or verify, or none where the signer has written one, can't show who signs. The signer then reads the switch's copy (`GET /apps` `identity`, 7.4.12). If it is the newest version this signer delivered, compared whole as in 3.12, no install has taken over, since one that takes over or restores delivers before it writes its backup; the signer writes its own backup and tells the user the earlier one was unreadable or missing. Any other copy is judged as at a delivery (3.3 "Never back"): a newer one shows another install took over, an older one or none is a rollback, and either way it writes nothing.
- **Restoring** (spec 12.8), with the identity key and on the user's confirmation: the install reads the backup, derives the backup key, and checks it as a new signer checks a hand-over (3.12), with these changes. Check 1 uses the backup's label and fields and its own backup key. Check 2 doesn't ask that `identity_doc` list an app of its own. Check 3 asks that the switch's copy (`GET /apps` `identity`, 7.4.12) be `identity_doc` itself, or the version whose document hash is `prev`, and that the Homeserver's copy be neither newer than `identity_doc` nor another one at its version, compared whole as in 3.12. A switch at `prev` means the signer stopped between writing the backup and delivering: the restore delivers `identity_doc` first, on that copy. A switch that holds no copy counts as being at `prev` only when the backup has none (`identity_doc` is the account's first document, which the restore then delivers first); a switch with no copy under a backup that names a `prev` has lost the state the backup builds on, and the restore is refused. Any other copy makes the backup stale, and the restore is refused. A backup whose `identity_doc` has `recovery_from` the generation before its own and no `prev` was written mid-recovery (spec 12.6 step 1), and its switch holds no document until it takes that one: a switch that answers `503 staged` or can't be reached counts as holding no copy, and the restore is that recovery in progress again. A recovery declared at the service that served the lost generation names the pending key that service's enrollment answered, and until the service takes `identity_doc` it answers under the key it served the lost generation with (7.4.1, 7.4.2). So when an answer under `identity_doc`'s key fails its signature check, the install reads `GET /apps` again under that earlier key, which it takes only from a copy of `identity.json` that the identity key signed at the lost generation, naming the same origin, at a version below `identity_doc`'s, which is the Homeserver's copy. Under that key, the switch's copy at the lost generation below `identity_doc`'s version, and a signed `503 unavailable`, count as holding no copy, and the restore is that recovery in progress again, with that earlier key pinned while the service still serves the lost generation (7.4.2); an answer under any other key is refused. A later version of that generation keeps `recovery_from` and has a `prev`, and restores as any other. That restore delivers `identity_doc` first; when the switch doesn't take it, the install keeps `identity_doc` as its newest version and declares the loss again, at that switch or another, and its next document keeps `identity_doc`'s generation and `recovery_from`. When a later run delivers `identity_doc` instead, which names the install the backup came from, the install then delivers the next version naming itself, as below. The install then takes as revoked the App IDs of `revoked_apps`, of `identity_doc`'s `removed` and those `GET /apps` shows revoked or departed, delivers the next version with `prev` the hash of `identity_doc` and `signer` its own install's ID, publishes it, and writes its backup once that delivery has won. A member of `revoked_apps` that `identity_doc` still lists is a revocation the signer asked for and no version carried out: it is pending again, so the install revokes the app at the switch and delivers the version that removes it (spec 12.2), as a new signer does (3.12). A delivery that gets `409 stale_identity` cancels the restore.
- Vectors: `envelopes.json` `signer_backup` (alice's backup in one part, with fixed randomness), `keys.json` (each identity's backup key) and `signatures.json` (its label).

## 4. The binary envelope

### 4.1 Layout

An envelope carries one plaintext to 1 to 255 recipient apps of one identity (spec 5.1). With `n` recipients:

| Offset | Length | Field | Value |
|---|---|---|---|
| 0 | 4 | magic | `PSW1` (`50 53 57 31`) |
| 4 | 1 | version | 1 |
| 5 | 1 | suite | 1 |
| 6 | 1 | flags | bit 0 is `notify`; every other bit is 0 |
| 7 | 1 | recipient count `n` | 1 to 255 |
| 8 | 32 | key commitment | `derive("pubky-switch/v1/key-commit", content key)` |
| 40 | 88 per recipient | recipient wraps | `kid (8) \|\| enc (32) \|\| wrapped content key (48)`, in the sender's order |
| 40 + 88n | 24 | nonce | random |
| 64 + 88n | the rest | ciphertext | XChaCha20-Poly1305 of the padded plaintext, with its 16-byte tag |

- The **header** is bytes 0 to 40 + 88n. The **HPKE AAD** is its first 40 bytes (magic through key commitment).
- The total length is exactly one of the **buckets** 1024, 4096, 16384 and 65536 bytes. The padded plaintext is `bucket - (40 + 88n) - 24 - 16` bytes long.
- A sender chooses the smallest bucket with `40 + 88n + 24 + len(plaintext) + 16 <= bucket`. A plaintext that fits none is too large: 65368 bytes is the most one recipient can carry.

### 4.2 Suite 1

- **Content:** a fresh random 32-byte content key; XChaCha20-Poly1305 with a random 24-byte nonce; AAD is the whole header.
- **Key wrap**, one per recipient app: HPKE (RFC 9180) base mode with DHKEM(X25519, HKDF-SHA256) (KEM `0x0020`), HKDF-SHA256 (KDF `0x0001`) and ChaCha20-Poly1305 (AEAD `0x0003`), single-shot:
  - recipient key: the app's current receive key, or its bundle key for a key bundle (3.5);
  - `info`: `lp("pubky-switch/v1/hpke", recipient identity, kid)`, where the recipient identity is the message's `to`, or the identity itself for a key bundle;
  - `aad`: the first 40 bytes of the header;
  - plaintext: the 32-byte content key, so the wrapped content key is 32 + 16 = 48 bytes;
  - `enc`: the 32-byte ephemeral public key.
  - **All-zero abort** (RFC 9180 7.1.4): DHKEM(X25519) fails when the X25519 output is all zero. That happens exactly when the other side's key, or `enc` for a recipient, is of low order: a point of order 1, 2, 4 or 8 on the curve or its twist, whose u-coordinate, read as RFC 7748 decodes it (top bit cleared, then mod p), is 0, 1, p - 1 or one of the two points of order 8, `325606250916557431795983626356110631294008115727848805560023387167927233504` and `39382357235489614581723060781553021112529911719440698176882885853963445705823`. Since every clamped X25519 secret is a multiple of 8, X25519 with any secret is all zero for those keys and for no other. Such a key is refused at registration (6.2), makes a certificate invalid as its bundle key (3.1), and a sender skips its app (3.4); a recipient refuses an envelope whose `enc` for it is one of them.
- **Randomness:** the content key, the nonce, and per recipient the 32 bytes of ephemeral keying material `ikmE` from which HPKE derives the ephemeral key (`DeriveKeyPair`). Implementations draw all three from the operating system's secure random generator and take none from their callers. The vectors fix all three (the reference prototype: only its test-only `hazmat` module can, `hazmat::seal_with`).

### 4.3 Sealing and opening

**Sealing:**

1. Draw the content key; write the header's first 40 bytes with the key commitment.
2. For each recipient, append `kid`, then the HPKE `enc` and wrapped content key.
3. Pad the plaintext with zero bytes to the bucket's plaintext length and encrypt it under the content key, with the nonce and the whole header as AAD.

**Opening** (a recipient app with receive key `kid`):

1. Check magic, version 1, suite 1, no unknown flag bits, `n` at least 1, and that the length covers the header, the nonce and a tag.
2. Find the wrap whose `kid` is the app's; none means the envelope isn't for this key.
3. Open the HPKE wrap with the receive secret, the `info` for the own identity and that kid, and the first 40 header bytes as AAD. The result must be 32 bytes.
4. Reject the envelope if `derive("pubky-switch/v1/key-commit", content key)` differs from the header's key commitment. This makes every recipient open the same plaintext or none.
5. Decrypt the body with the whole header as AAD.
6. Parse the plaintext (4.5) and check that its padding is all zeros.

The inbox reads only the header: it checks steps 1 and the size (4.4), and that every kid is the current receive key of a current app (7.4). A recipient doesn't check that the length is a bucket: the inbox refused anything else, and the key commitment and AEAD tag already bind every byte.

### 4.4 Size rules at the inbox

- More than 65536 bytes: `413 too_large`.
- A header that doesn't parse: `400 bad_request`.
- A length that isn't one of the four buckets: `400 bad_request`.
- One app wrapped to twice: `400 bad_request`.

### 4.5 Plaintext formats

- **Message** (spec 5.2):

  | Offset | Length | Field |
  |---|---|---|
  | 0 | 16 | sender App ID bytes |
  | 16 | 64 | signature, label `pubky-switch/v1/msg`, over `lp(label, recipient identity, message JSON bytes)` |
  | 80 | 4 | `u32_be(len(JSON))` |
  | 84 | len | message JSON bytes (5.1) |
  | 84 + len | the rest | zero padding |

- **Key bundle:** `u32_be(len(JSON)) || JSON || zero padding` (3.5).
- A reader rejects a length that runs past the plaintext and any non-zero padding byte.

Vectors: `envelopes.json` seals messages from bob's `shop` to alice's apps, to one and to three recipients in every bucket (a `tasks.cancellation` in the 1 KiB bucket, a `tasks.resend_request` padded with `msg_ids` in the others), with every input and intermediate value: content key, key commitment, nonce, each recipient's `ikmE`, `skE`, `info`, `enc` and wrapped key, the header, and the envelope. It also has the bucket boundaries, the key bundle, and three envelopes that must be rejected: a flipped `notify` bit, the wrong recipient identity, and a forged second content key that fails the key commitment.

## 5. Messages

### 5.1 Common fields

Every message is one JSON object (spec 5.3):

| Field | Type | Req | Constraints | Notes |
|---|---|---|---|---|
| `v` | int | yes | 1 | |
| `kind` | string | yes | a kind of the sender's protocol, `<prefix>.<name>`, whose prefix is the protocol's name or an extension of it (3.1 Kind prefixes), such as `tasks.assignment` | recipients drop kinds they don't know |
| `msg_id` | uuid | yes | fresh per message | deduplication key with the sender identity (spec 11); a re-send keeps it |
| `created_at` | time | yes | | informational (spec 5.3), except for provider-loss recovery (spec 12.6) |
| `from` | object | yes | `{ "identity": pubky, "app_id": app-id }` | must match the certificate of the inbox entry and the plaintext's App ID |
| `to` | pubky | yes | the recipient identity | must be the identity the signature names |
| `refs` | `array<b64(32)>` | no, always written | message hashes (1.5) | default `[]`; each kind fixes its order |
| `body` | object | yes | per kind, as the protocol defines it | unknown members ignored |

- **Signed plaintext:** the sender app signs `lp("pubky-switch/v1/msg", recipient identity, message JSON bytes)` and puts the signature in the plaintext (4.5). The message hash is `hash(message JSON bytes)`.
- **Sizes:** the plaintext must fit the envelope (4.1): with `n` recipients the JSON is at most `65536 - 40 - 88n - 24 - 16 - 84` bytes. A protocol may bound its kinds further.
- **Re-sends** reuse the signed plaintext, and so the `msg_id` and the exact bytes, sealed again to the current receive keys (spec 11). A re-sent copy is a new entry with a new `accepted_at`, and the checks below judge it at that time: only the signing app can send it again (check 6: the entry's certificate must be the plaintext's app), and a copy that a removed app sends after its `distrust_from` fails check 7 however old the message.

**Recipient checks**, in this order, which is the order of 3.8 for a message:

1. Open the envelope (4.3) and parse the plaintext (4.5).
2. Verify the inbox entry's certificate (`cert` in the feed item, 7.5) as a certificate of the entry's `sender` identity (3.1; 3.8 checks 1 and 2).
3. Check that it hadn't expired at the entry's `accepted_at` (check 3).
4. Verify the signature with the certificate's signing key over the own identity and the JSON bytes (check 4).
5. Parse the JSON strictly (1.1) and check `v`.
6. Check that the plaintext's App ID, `from.app_id` and the certificate's `app_id` are equal; that `from.identity` is the certificate's identity and the entry's `sender`; and that `to` is the own identity. A message from an own app must be of a kind its protocol sends between own apps (spec 7).
7. Check the certificate's standing in the sender identity's newest `identity.json` at the entry's `accepted_at` (check 5, spec 11), with the clock tolerance against the sender: listed; renewed and open; renewed and closed with `accepted_at + 5 min < until`; or removed with `accepted_at + 5 min <= distrust_from`. `distrust_from` and `until` are times on the sender's service, `accepted_at` on the recipient's, so a message accepted less than 5 minutes before the cut-off is rejected too ("after `distrust_from`" in the spec is rejected; at it, minus the tolerance, still counts).
8. Check scopes: the sender's certificate holds a scope that sends the kind, and the own certificate a scope that receives it, by the table of the kind's protocol, with the protocol's narrower rules.
9. Deduplicate by (sender identity, `msg_id`) with the message hash.
10. Parse the body as its kind's body, as the kind's protocol defines it, once; later steps use the parsed body. The members the recipient reads must have their types, and the rules the protocol states for the kind must hold. A kind the recipient doesn't handle fails this check.

- **A failed check** drops the entry. After check 10 the recipient also keeps the (sender identity, `msg_id`) pair with the message hash as processed (spec 11), so the cursor moves past the entry and the same message isn't checked again: one message that can't be used never holds up the feed.
- **A sender that can't be checked** (its `identity.json` unreachable, or its identity seen to equivocate, spec 11) holds the entry, with later entries processed past it (spec 8.2). After a bounded wait, which the app chooses, it MUST store the entry locally and move its cursor past it, checking it later (the reference prototype: 24 hours by default, `DEFAULT_PARK_UNVERIFIABLE_MS`).
- **An entry that needs a scope key the app doesn't hold yet** (spec 3.5, 8.2), to open a record sealed at a data epoch whose key hasn't reached the app or to seal a write at the current one, isn't held behind the cursor: the app stores the entry locally at once, moves its cursor past it, and processes it again once a key bundle part (3.5) brings that key. It fetches its parts at most once for the entry, and asks for a full bundle as 3.5 gives, so a key that never comes costs one full-bundle request, not one for each entry. Such entries count with those whose sender couldn't be checked against the bounds of spec 8.2, in the order it gives, with neither kind ranked before the other: past them the app drops one without processing it and tells its protocol.
- **The standing is checked once** (spec 8.2): when the message is recorded, against the sender identity's `identity.json` current then. A stored message isn't checked again against later versions, so a signer that purges `removed` or `renewed` entries doesn't invalidate stored evidence; a protocol may have its apps check that app against the current document before acting (spec 8.2).
- **A write the service refuses** for a per-kind limit or the storage quota (`429 quota_exceeded`), or because it would take the record over the 256 KiB value limit (`413 too_large`, 9.2), MUST NOT stall the feed (spec 8.2): the app stores the entry locally, moves its cursor past it, and writes the record once room frees. A write refused for good, or one that doesn't fit one batch, is stored and passed the same way, and the app tells its protocol instead of sending it again (spec 8.2).

Example (`envelopes.json`'s message in the 1 KiB bucket, a `tasks.cancellation` from bob's `shop` to alice):

```json
{
  "v": 1,
  "kind": "tasks.cancellation",
  "msg_id": "4cc9d48b-b1d1-4e90-8b51-16e9ad89cc56",
  "created_at": "2026-02-10T00:00:00.000Z",
  "from": {
    "identity": "43xz73bjzs8c84sw4sigu5bm3x93mj17ywjy1oa3dbnriiymcw4o",
    "app_id": "ye9a6d8e43cq3f69kto91csqqe"
  },
  "to": "8y3qy4g9q7y9ownd18hskdoxdxzueutiu3f391rnnuxznxmqp5bo",
  "refs": [
    "KUXRO3VXukWmEtyK77jTHohDxrD75xJjsVq9P3DxXnk"
  ],
  "body": {
    "reason": "no_longer_needed"
  }
}
```

## 6. Operations, proofs and the chain

### 6.1 Signed operations

Every operation except `cursor.set` is a signed document (2.2) whose body names its type in `op`. The writer signs `lp("pubky-switch/v1/op", identity, body)`: an app with its signing key, the signer with the identity key. A signed operation takes at most 524,288 bytes (512 KiB) in its carrying form, else `413 too_large` (6.4 step 2). The service measures the compact form, `{"body":"<body>","sig":"<sig>"}` with no whitespace: 20 bytes plus the lengths of the two base64url texts, whatever whitespace or escapes the request itself uses (1.1). So at the cap, beside a 64-byte signature (86 characters), the body's text is 524,182 characters. A `record.put` of a 256 KiB value takes about 456 KiB, so the cap bounds what else one operation carries, its conditions or an app record, and every chain item, record and claim entry fits one export chunk (10.3 Part sizes).

| Field | Type | Req | Constraints | Notes |
|---|---|---|---|---|
| `op` | string | yes | a type of 6.2 | |
| `identity` | pubky | yes | the account's identity | else `400` |
| `app_id` | `app-id \| null` | yes, always written | the calling app; `null` for the signer | else `400` |
| `generation` | int | yes | the account's current generation | else `409 stale_generation` |
| `batch` | object | yes | `{ "id": b64(16), "count": int }` | the same in every operation of the batch; `count` is the number of signed operations in it |
| `conditions` | `array<Condition>` | no | 6.3 | omitted when empty |
| ... | | | the type's fields, at the top level | |

Unknown members are `400 bad_request` at the top level and in every nested object: `batch`, each condition and its inner object, `expected_version`, `value_sealed`, `id_inputs`, the carrying form of `record` or `cert`, and `bundle` (1.1). The opaque `context` of `invite_code.put` is exempt.

Example (`operations.json` `claim attempt`: an `attempt` with a deadline, conditioned on the request record at version (1, 6), its create in `chain.json`):

```json
{
  "identity": "8y3qy4g9q7y9ownd18hskdoxdxzueutiu3f391rnnuxznxmqp5bo",
  "app_id": "w8amtmn13m6p5bwnmj9wejbq4c",
  "generation": 1,
  "batch": {
    "id": "ytmXw2Y65nm811vKBpkAQQ",
    "count": 2
  },
  "conditions": [
    {
      "record_version": {
        "key": "kOVu6mp0YaO9wsEJ2gf9TG7n3cf3KMFu_RaRvlaEkFM",
        "generation": 1,
        "version": 6
      }
    }
  ],
  "op": "claim",
  "claim_key": "LOElfduZJYjUJFjB4crU2il4lVN2oKRo6BnTap10GqA",
  "type": "attempt",
  "expected_step": 0,
  "attempt_id": "P37OWgXQlGXLccI0TFBpwg",
  "orphan_after": 86400,
  "deadline": "2026-01-02T00:00:00.001Z"
}
```

### 6.2 Operation types

**The signer's operations.** The signer (`app_id` `null`, 6.1) writes `key_bundle.put` and `cert.put` and no other type: any other operation it signs is `403 permission_missing`, at the operation's permission check (6.4 step 9), and a `cursor.set` in its batch is `400 bad_request`, since the signer has no cursor. Apps write every other type, as each one's permission allows.

**`claim`** (spec 10.2). Needs `claims.write`.

| Field | Type | Req | Constraints |
|---|---|---|---|
| `claim_key` | `b64(32)` | yes | names the claim; opaque to the service |
| `type` | string | yes | `attempt`, `done`, `failed` or `unknown` |
| `expected_step` | int | yes | the claim's step: the number of entries so far, 0 for a claim key the service holds nothing for; a tombstone keeps its step |
| `attempt_id` | `b64(16)` | yes | every type names one |
| `orphan_after` | int | on `attempt`, required; on another type `400` | seconds; any value |
| `deadline` | time | on `attempt` only, optional | `d + 1 ms`, where `d` is the last instant at which the protocol takes an attempt, truncated to milliseconds (spec 10.2); on another type `400` |
| `basis` | string | on `done`, required; on another type `400` | `owner`, `evidence` or `reconcile` |
| `evidence_ref` | `b64(32)` | on `done` with basis `evidence`, required; with `owner` or `reconcile`, optional; on another type `400` | hash of the evidence: with `evidence` the counterparty's confirmation, with `owner` or `reconcile` the app's own proof |

A `done` names at most one piece of evidence, by `evidence_ref` (spec 10.2). A type other than `done` carrying it is `400`, and so is basis `evidence` without it. The service never interprets `attempt_id` or `evidence_ref`. 6.8 gives the rules each type follows.

**`record.put`** (spec 10.3). Needs one of the record's `write_scopes`; a scope's name covers each of its sub-scopes (3.1).

| Field | Type | Req | Constraints |
|---|---|---|---|
| `key` | `b64(32)` | yes | the record key (1.5) |
| `collection` | `b64(32)` | yes | the collection ID (1.5), not the name |
| `read_scope` | string | yes | |
| `write_scopes` | `array<string>` | yes | at least one, sorted ascending by bytes, no duplicates |
| `expected_version` | Record version | yes | `{ "generation", "version" }` of the version the writer read (1.7); `{0, 0}` to create |
| `value_sealed` | Sealed value | yes | below |
| `id_inputs` | object | when `expected_version` is `{0, 0}`, and only then | `{ "collection": collection name, "blinded_key": b64(32) }`, the blinded natural key `blind(natural key)` (1.5). On any other write it is refused, `400 bad_request`, as part of the operation's shape (6.4 step 9), so before the compare-and-swap |

- **Versions** (spec 10.3): a record's version is the (generation, `seq`) of the write that produced it, given by the service; the transition proof's `state` shows it (6.5). Versions are ordered by generation, then `seq`, so they only grow across the account, whoever writes. A writer can't know its new version before the service gives it.
- **Compare-and-swap:** `expected_version` must be the record's current version, else `409 conflict` (7.6). `{0, 0}` matches a record that is absent, forgotten or deleted, so a writer that holds or follows a delete (one it refused that the switch shows as current, spec 8.2) names `{0, 0}`, never needing to know whether the service has forgotten the key, which would refuse the delete's own version for good.
- **At creation** (`expected_version` `{0, 0}`) the service recomputes `key` from `id_inputs` and the operation's policy hash, and `collection` from the name and the identity; a mismatch is `400`. The service sees only the blinded natural key, so the key names neither the counterparty nor the request; a live operator still links it to a sender through the batch and its timing (spec 15).
- **Later writes** repeat `collection`, `read_scope` and `write_scopes` exactly; a difference is `400`. A write to a deleted record that names its delete's version continues it too.
- **One write per record per batch** (spec 13.5): a batch that writes one record twice is `400 bad_request`, since the second write couldn't name the first one's version.
- **A conflict carries the current write**: when the writer holds the record's read scope, the `409` answer's `current` holds `record` (`key`, `generation`, `version`) and `record_view`, the current write as `GET /records/{key}` returns it (7.4.9). The writer drops or redoes its write without reading the record again. A writer without the read scope gets `current: {}`.
- **Sealed value:**

  | Field | Type | Req | Notes |
  |---|---|---|---|
  | `data_epoch` | int | yes | the current data epoch, else `409 stale_epoch` (outside recovery uploads) |
  | `scope` | string | yes | equals `read_scope`, else `400` |
  | `nonce` | `b64(24)` | yes | random |
  | `ct` | b64 | yes | ciphertext and 16-byte tag: 16 bytes (a delete), or a bucket below plus 16; more than 262160 bytes is `413`, any other length `400` |

  The cipher is XChaCha20-Poly1305 under `scope_key(data_epoch, scope)` (1.5, spec 3.5), its sub-scope key for a sub-scope, such as `tasks_assign:team1`, with AAD `lp("pubky-switch/v1/sealed", identity, scope, record key)`.
- **Padding** (spec 13.4). The plaintext sealed is `u32_be(len(JSON)) || JSON || zero padding`, as long as the smallest of these buckets that holds `4 + len(JSON)`: 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608 and 262144 bytes (2^k for k from 9 to 18, and 3 * 2^k for k from 8 to 16). Each bucket is at most half again the one below, so padding adds at most half a value's size, under a fifth on average, and at least 512 bytes are stored per value. A value is therefore at most 262140 bytes of JSON. A larger one fits no bucket, so it isn't sealed: the writer refuses it, as the service would refuse it, and handles it as a value over the cap (`413`). Should a writer seal one anyway, unpadded, the service tells it by its length alone: a `ct` over 262160 bytes is `413` (above). Readers check, after opening, that the length fits and the padding is all zeros; a value that fails is a value that "doesn't open" (step 7 below). The stored length shows only the bucket (spec 15). Vectors: `sealed.json` `padded_len`.
- **Delete:** a write whose sealed value is a sealed empty plaintext, unpadded, so `ct` is the 16-byte tag only. It passes every check of a write, and gets a newer version like any write. The key keeps its policy while the service remembers it.
- **Forgotten deletes** (spec 10.3): the service may forget a deleted key once nothing refers to it (9.1). A forgotten key's delete keeps only its chain stub, and a later create at the key, with `{0, 0}`, gets a version newer than any the key had, since versions are `seq`s.
- **Accepting a write** (spec 10.3): an app acts on a `record.put` it reads, from the feed (7.5), `GET /records`, a list page or a `409`'s `record_view`, only after these checks:
  1. The writer's certificate: one that verifies for the identity (3.1) and names the operation's `app_id`, from the record view's `cert` (7.4.9), the certificate the service checked the write against, or else the app's own, or the app records it keeps from the directory (7.4.10) and `app.put` items. The operation's signature verifies with its `signing_key`, and `identity` is the account's. Without a certificate, or with a writer the app's `identity.json` doesn't name, the app first reads its `identity.json` and directory again. A write names no certificate: every certificate of its writer has the `signing_key` that verifies it, so the record view's `cert` is the one the service chose. The write counts when a certificate of the writer the app holds, the view's `cert` among them, was in force at the write's time (step 4) and holds a write scope of the record (step 5), and is judged with the view's `cert` when that one counts, so a renewal later doesn't change what an earlier write is judged with; a write without a view, such as a feed item, with the writer's certificate that counts. An app that doesn't hold a certificate the newest own `identity.json` names for the writer as in force at that time, and holds none that counts, reads the record's view (7.4.9) and judges the write with its `cert` too. When that doesn't count either, it reads its directory again for the writer's listed certificate, once for each the directory answers for while it runs, a read that fails being made again by a later write's judging, at most once a minute; while it still lacks the one in force then, a failure of steps 4 and 5 is only the service's choice of certificate, and the write is ignored, naming no app.
  2. A feed item matches its stub (6.6); a stub the app verified in its chain dates the write and gives its version, including the stubs of the page just read whose hashes the page's checkpoint prunes. A transition proof that verifies with the current service key must have a stub whose `item_hash` is the operation's and whose generation is the operation's `generation`, an `object` that is `key`, a `state` whose `generation` and `version` are the stub's, and must not contradict a chain hash the app verified; it then gives the version if no stub did. A proof of an earlier generation, as a switch keeps it with a record after a key change or carries it after a move, gives no version, but dates the write for step 4 when it verifies with the key the newest own `identity.json` lists for the generation its stub names in `service_keys` (3.3), and its stub's `item_hash` and generation are the operation's. A generation the list doesn't name dates nothing; an honest signer lists every generation a current record's proof names (3.3).
  3. `key` is the one read; `collection` is a collection of the reading app's protocol, and the policy one that protocol fixes for it; `value_sealed.scope` is `read_scope`; a create's `key` derives from `id_inputs` (1.5).
  4. Standing: in the newest own `identity.json` the app holds, the certificate is listed; or it is an earlier certificate of a listed app in `renewed`, with `until` `null` or after the write's time; or the app is in `removed` and the write's time is at or before `distrust_from`. Only a proof (step 2) or a verified stub gives the write's time. An earlier certificate whose `until` is set counts only when one does and puts the write before `until`. Without one it doesn't count, and since the service keeps the proof of every current write (7.4.9), the missing date is the service's word: a write that no other certificate counts for (step 1) is ignored, naming no app. A removed app's write without a time counts as doubtful (spec 12.2 step 3). A certificate expired at the write's time doesn't count.
  5. The certificate holds one of `write_scopes`.
  6. The version: from step 2 when a proof or a verified stub gives it (authenticated); otherwise the record view's (unauthenticated). Either way its generation is the operation's `generation` and it is after `expected_version`.
  7. The content: `value_sealed` opened with the scope key of its `data_epoch` (1.5, spec 13.4), and its padding removed (above). An empty plaintext is a delete, and nothing else is: a `deleted` flag or a 16-byte `ct` alone proves nothing. Without that epoch's key the value is unreadable; a value that doesn't open with the key, whose length or padding is wrong, or that isn't JSON, fails.

  Signed evidence of misbehaviour (an item that doesn't match its stub, a proof that names another operation or object, or contradicts the verified chain) is a rollback (spec 10.1). Some failures are only the service's word, not the writer's: a write whose signature doesn't verify with a certificate of its writer the app finds, or that is of another `key` than the one read, or of a collection of another protocol (steps 1 and 3), the certificate the service shows with it or a missing date (steps 1 and 4), and a version that fails step 6. Each leaves the write ignored, naming no app, which loses nothing a service withholding the write couldn't take. A write signed with the reading app's own key is that app's own (spec 3.1): steps 4 and 5 don't apply to it, but for a removed app's `distrust_from`, since a lost device holds the key too (spec 12.2 step 3), and a failure of steps 3 to 6 leaves it ignored, naming no app. A value that doesn't open (step 7) names the app that signed it, the reading app included, since the signature covers `value_sealed`. Any other failure leaves the write ignored and shown with the app it names (spec 8.2). The app shows each such write once, by its item hash (6.6), at the version it was last shown at, and keeps at most eight for a record, the one shown at the lowest version dropped first. A write ignored only for the certificate the service shows or a missing date, whose version passes step 6, is followed, naming nobody: the app builds its next write on it, as on a flagged write, and the record doesn't read as flagged. Any other write ignored without naming an app isn't followed: the app builds its next write on the version it holds (spec 8.2). A write at the key read that its writer signed for another collection or policy fails step 3 and names its writer; from the feed, which reads no key, a write whose collection and policy name no collection of the app's protocol is ignored, naming no app. The app takes an accepted write in place of the one it holds only if it is newer: with both versions authenticated, the higher one; with the new version unauthenticated, only if its `expected_version` is the held version or later; with the held version unauthenticated, the held write counts as just after its own `expected_version`. The same write again, with an authenticated version, makes the held one authenticated. The AAD stays `lp("pubky-switch/v1/sealed", identity, scope, record key)`: the operation's signature binds the writer.

Example (`operations.json` `record.put create`, which `chain.json` applies at `seq` 6, giving the record version (1, 6); `ct`, cut short, seals a `task_items` record holding bob's assignment):

```json
{
  "identity": "8y3qy4g9q7y9ownd18hskdoxdxzueutiu3f391rnnuxznxmqp5bo",
  "app_id": "w8amtmn13m6p5bwnmj9wejbq4c",
  "generation": 1,
  "batch": {
    "id": "XjPa0rAnB2ReUhZEv0mVSg",
    "count": 1
  },
  "op": "record.put",
  "key": "kOVu6mp0YaO9wsEJ2gf9TG7n3cf3KMFu_RaRvlaEkFM",
  "collection": "rThZDAv1FHRMIiUn6S8h7HBHF_-gTlmA13cC8V-Prug",
  "read_scope": "tasks",
  "write_scopes": [
    "tasks"
  ],
  "expected_version": {
    "generation": 0,
    "version": 0
  },
  "value_sealed": {
    "data_epoch": 2,
    "scope": "tasks",
    "nonce": "a6aRD9-0Omz67vnFzFd06S8lEny5XdcL",
    "ct": "-aKYccxUt-Wo9TE4LEE1W9_bYgftquiAzTBtdv0oe_Ht-h242sDhGtQ..."
  },
  "id_inputs": {
    "collection": "task_items",
    "blinded_key": "oZHk8WYT151d-gC9U5twKugX1w360FV7vxhdXIVVeTQ"
  }
}
```

**`allow.put`, `allow.delete`** (spec 7): `{ "pubky": pubky, "kind": "contact" | "conversation" }`. Contacts need `lists.manage`; adding a conversation entry needs `conversation.add`, removing one `lists.manage`. Adding an entry that exists changes nothing (a conversation entry keeps its first writer) but is still chained. Adding an entry of either kind for the sender of a pending connect request removes the request (7.4.7).

**`deny.put`, `deny.delete`**: `{ "pubky": pubky }`. Need `lists.manage`. Denying removes a pending connect request.

**`invite_code.put`** (spec 7). Needs `conversation.add`.

| Field | Type | Req | Constraints |
|---|---|---|---|
| `code_hash` | `b64(32)` | yes | `hash(code bytes)` (1.7); registering it again is `409 conflict` |
| `expires_at` | time | yes | |
| `max_uses` | int | yes | 1 to the service's `max_invite_uses` (100 by default, 9.2), else `400` (spec 7): a code for one order or counterparty has 1 |
| `context` | any JSON | yes | at most 1024 bytes as the writer serialized it: the bytes of its value within the signed body, from its first byte to its last, whitespace and escapes inside it included, never a re-serialization; else `413`; stored and shown in the clear, so the operator reads it (spec 7, 15): an opaque reference, never personal data |

**`invite_code.delete`**: `{ "code_hash": b64(32) }`. Needs `conversation.add`. An unknown code is `404`.

**`app.put`** (spec 4.2, 12.1): `{ "record": signed<AppRecord> }`. For the calling app only. Its certificate must be the one the newest `identity.json` lists, else `403 not_current`. The record the service already holds, byte for byte, is unchanged (6.4 no-ops). Any other record must have an `updated_at` later than the held record's, else `409 conflict` with `current: { "record": <the held signed record> }`. So a replayed or delayed older record, such as one naming a destination since withdrawn, never replaces the current one, and the switch never holds a second record at a time readers have seen another body at (3.2 Equal times). A device of the app that gets this answer for a record of its own writes it again with an `updated_at` later than the held record's. Readers apply the same rule (3.2: the later `updated_at` wins). Vectors: the `app_put` steps of `claims.json`.

**`receive_key.put`** (spec 3.6): `{ "record": signed<ReceiveKeyRecord> }`. For the calling app only, after its `app.put` (earlier in the same batch, or before), else `400`.

- The first record of an app at a service has `n` 0; at an account recovering from a provider loss, any `n`, and apps send one higher than every `n` they have registered (spec 3.6), so they register a new record rather than re-deliver their current one. Each later record has `n` exactly one more than the current one. The current record again, byte for byte, is unchanged (6.4 no-ops). Anything else is `409 conflict` with `current.receive_key`, which the app checks for an unexpected registration (3.4).
- A kid already registered, by any app, is `400` (spec 3.6: kids are unique in the account).
- A key of low order (4.2), a `suite_keys` of the wrong form (3.4) or a record that fails 3.4's checks otherwise is `400`.

**`key_bundle.put`** (spec 3.5): `{ "target_app_id": app-id, "bundle": key bundle (3.5), "first_epoch": int, "last_epoch": int }`. Signer only (`app_id: null`), else `403 permission_missing`. The target must be an app the newest `identity.json` lists in `apps` and the service holds neither revoked nor departed, else `403 not_current`, whatever its certificate's expiry and whichever certificate the document lists for it, so a renewal's bundle is taken for an app whose certificate has expired (3.8 "An expired certificate"); an app in `removed`, or in neither list, isn't one. A bundle whose signature fails is `401 bad_signature`. `first_epoch` and `last_epoch` repeat, in the clear, the epochs the sealed bundle holds (3.5; `first_epoch` at most `last_epoch`, `400` otherwise); the service uses them for `keys_through` (7.4.12) and clears a pending full-bundle request once the parts it stores for the target cover every data epoch from 1 to the current one. A bundle may be one part of several (3.5). The service stores the target's parts so that they never overlap: a new part replaces every stored part whose range it overlaps, and, unless a full-bundle request is in force, the parts the target's cursor has passed and that `keys_through` covers go. A request is in force from the `POST /keys` (7.4.11) until the target's cursor has passed the part that completed it, or the part that replaced that one, after `full_bundle_requested` ends: until then the app hasn't read the parts it asked for, which may include ones it passed before a restore. A part identical to one stored, with the same epochs, changes nothing (6.4 no-ops).

**`cursor.set`** (spec 8.3): `{ "op": "cursor.set", "position": "<generation>:<seq>" }`, unsigned, not a signed document, and outside the batch count. The request signature covers it. Apps only; at most one per batch. The position's generation is the current one (or, after a cooperative move, the one the sequence continues from), and its `seq` is at most the newest the service gave out before the batch, so a cursor never names the batch's own items; else `400`. A position behind the app's cursor, or at it, changes nothing and is no error: the cursor only moves forward, so a batch sent again, or replayed within the timestamp window (7.1), can't move it back. Positions are compared by `seq`, which a cooperative move and a key change in place continue. A move drops the app's key bundle parts under `key_bundle.put`'s rule (above): unless a full-bundle request is in force, the parts its cursor has now passed and that `keys_through` covers go. The move that passes the part completing a request, or the part that replaced that one, ends the request's force, and may drop at once. A part passed before the gap below it was filled isn't covered yet; it goes at a later move, once `keys_through` covers it.

**`cert.put`** (spec 3.2; 3.8): `{ "target_app_id": app-id, "cert": signed<AppCert> }`, the target's renewed certificate. Signer only (`app_id: null`), else `403 permission_missing`.

- The certificate must verify for the identity and name `target_app_id` (`400`).
- The target must be an app the newest `identity.json` lists in `apps`, not revoked or departed, that has delivered its record (`404`), whatever its certificate's expiry: the same target as `key_bundle.put`'s.
- It keeps the record's certificate's `signing_key` and `bundle_key` (`400`: other keys make a new app).
- Its `issued_at` is later than that of the record's certificate and of any renewed certificate already stored for the app (`409 conflict`); the stored renewed certificate, or without one the certificate the record carries, again byte for byte, is unchanged (6.4 no-ops).
- It replaces a renewed certificate stored earlier, whose chain item then keeps only its stub. It is a control operation (Section 9).

Example (`operations.json` `cert.put`; certificate cut short):

```json
{
  "identity": "8y3qy4g9q7y9ownd18hskdoxdxzueutiu3f391rnnuxznxmqp5bo",
  "app_id": null,
  "generation": 1,
  "batch": {
    "id": "qgStjlRCdUE1jWm6iZ4hSg",
    "count": 1
  },
  "op": "cert.put",
  "target_app_id": "w8amtmn13m6p5bwnmj9wejbq4c",
  "cert": {
    "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLmFw...",
    "sig": "pJsCU4UIXeHk1QS_UqlP76nqXpyny7dRJCU8w55_8JB8FfZXgKzfQt3TedrTbeg7-RcxzzhKP9B0PgKep_SjDA"
  }
}
```

### 6.3 Conditions

Each condition is an object with one member, checked against the state before the batch (spec 10.1):

| Condition | Form | Holds when |
|---|---|---|
| `record_version` | `{ "record_version": { "key": b64(32), "generation": int, "version": int } }` | the record's current version is (`generation`, `version`), its version being the (generation, `seq`) of its current write (6.2). A record that doesn't exist, or whose key the service forgot, is at version 0, whatever the generation named. `version: 0` holds then, and also for a record whose current write is its delete, to a caller that holds the record's read scope, as `expected_version` `{0, 0}` matches a record that is absent, forgotten or deleted (6.2): a writer that holds or follows a delete names it with `{0, 0}`, whether or not the service has forgotten the key since. To a caller without the read scope, a deleted record fails `version: 0` as a live one does, since its feed shows it both as stubs. The delete's own version holds too, while the service keeps it |
| `claim_step` | `{ "claim_step": { "claim_key": b64(32), "step": int } }` | the claim's step is `step` (0 when the service holds nothing for it) |
| `server_time_in` | `{ "server_time_in": { "start": time \| null, "end": time \| null } }` | the service's time when it applies the batch is in `[start, end)`; a `null` bound is open |

A failed condition is `409 conflict`, with the current value the caller may read (7.6). Unknown members, in the condition object or inside it, are `400`.

### 6.4 Batches

- **Request:** `POST /v1/{id}/ops` with body `{ "ops": [entry, ...] }`, 1 to 8 entries, each a signed operation in carrying form or one `cursor.set`. The cursor counts toward the 8. An entry has only its own members: `body` and `sig`, or `cursor.set`'s `op` and `position` (1.1).
- **Processing order:**
  1. Callers: own apps and the signer; apps of other identities get `403 not_admitted`.
  2. Parse; 0 or more than 8 entries, or an entry with a member besides its own, is `400`, and a signed operation over 512 KiB is `413 too_large`, before any signature is checked. The size is that of the operation's compact carrying form (6.1), 20 bytes plus its `body` and `sig` texts, not of the bytes the request carries for it.
  3. For each signed operation: its signature with the caller's key (`401 bad_signature`), then `identity` and `app_id`, and no unknown members at any depth (`400`, 6.1).
  4. Batch: no record written twice (6.2); `id` is 16 bytes; every operation has the same `id` and `count`, and `count` is the number of signed operations (`400`).
  5. Retry: a batch whose ID the service holds with the same signed operations returns the original proofs and the newest head for `batch_proofs_ms` (30 days, Section 9) after the batch. After that, whether or not the sweep has dropped the proofs yet (9.1), and with other operations at any time, it is `409 conflict`. The service holds a batch's ID and operation hash as long as the proofs, and also while any of the batch's chain stubs is kept (9.1). The batch record goes once both have ended: its proofs are gone and none of its stubs is kept. An app's verifier takes a new batch for a repeat when its ID is that of an earlier batch and `t_new - t_old < 30 days` (2,592,000,000 ms), `t_new` and `t_old` being the `server_time` of each batch's first stub (6.6). The service holds a batch's ID at least until 30 days after its first stub's `server_time`, and refuses the ID while it holds it. So the service never accepts a batch an honest app would take for a repeat, and an app never compares an ID the service has forgotten. Nobody can replay a batch, list operations included, which carry no expected version (`allow.*`, `deny.*`, `invite_code.*`): a request is accepted only within 5 minutes of its signed timestamp (7.1), so a batch can come again later only in a new request, which only its app can sign, and apps resend a batch only in their immediate retries.
  6. Generation: an operation naming another generation is `409 stale_generation`, with `current.generation`. A retry recognized in step 5 never reaches this check, and neither does a batch whose ID the service holds without its proofs, which step 5 answers `409 conflict`. So a batch signed for the generation before a cooperative move or a key change in place, sent again unchanged, is answered by what became of it: its original proofs after a key change in place, which keeps them, each checked with the key of the generation its stub names; `409 conflict` after an import, which carries the batch's ID and operation hash without proofs (10.3); and `409 stale_generation` only when the service holds no batch of that ID, so it was never applied. An app that can't tell from its own chain whether such a batch was applied sends it again unchanged before it signs its operations again, and signs them again only on `409 stale_generation` (spec 12.5 Kept batches). After a provider loss the new sequence holds no earlier batch, so there this answer says nothing about the lost service (spec 12.6).
  7. No-ops, time and rates: a batch without `cursor.set` whose every signed operation is unchanged (below) is a no-op; without trusted time, a batch that depends on time is `503 unavailable` (7.3); then the operation and control rates (below): `429 rate_limited`. The no-op decision comes before the conditions (step 8) and before each operation's permission and rules (step 9), since a no-op changes nothing and answers only `{ "proofs": [], "head" }`, which no caller reads as a guard having held. So a no-op batch whose operations would fail there gets that answer, such as one carrying a failing condition. (An `app.put` whose certificate the newest `identity.json` no longer lists never gets this far: authentication checks a batch carrying the caller's `app.put` against that record's certificate, 7.2.) A batch carrying `cursor.set` is never a no-op, since the cursor move changes something: its operations go through steps 8 and 9 whether unchanged or not.
  8. Conditions of every operation, against the state before the batch.
  9. Operations in order, each against the state the earlier ones left, so one batch can write two entries of one claim (but not two writes of one record, 6.2). For each operation, in this order: its permission (`403 permission_missing`), its shape (`400`: field lengths, a claim's `orphan_after`, `deadline`, `basis` and `evidence_ref`), the per-kind limits (`429 quota_exceeded`, Section 9), then its own rules (6.2, 6.8; `409`).
  10. The cursor, only once every condition and operation has passed, and only forward (6.2). When every signed operation of the batch is unchanged, it then adds no chain item and no batch record, and the answer is `{ "proofs": [], "head" }`.
  11. Commit, or nothing at all.
- **Response:** `{ "proofs": [transition proof, ...], "head": signed head }`, one proof per signed operation, in order. For example (two proofs, cut short):

```json
{
  "proofs": [
    {
      "body": "eyJjaGFpbiI6eyJlbnZlbG9wZSI6ImV5SmphR0Zw...",
      "sig": "Z3_U3AsxoDiMQTgRCZ8fF9E_P0Ex2tL8skLWlSRytVy7NoyzEuWBFXlvnWZ8pOe_v4IOVclvBlEPZkT_Q61jBw"
    },
    {
      "body": "eyJjaGFpbiI6eyJlbnZlbG9wZSI6ImV5SmphR0Zw...",
      "sig": "svZhsiF2IRrW30xJK0hM9m3784FyWv9LoTeA8gBblYIH6CHdzoHoWgVJU99bdzE62W6eBccnxjyQCnlZMWmACg"
    }
  ],
  "head": {
    "chain_version": 1,
    "generation": 1,
    "seq": 9,
    "chain_hash": "muYjBhuz6UI1RX8upIrIIMIBpI_3gRvfhwQtrDldImA",
    "sig": "b23xHVPZCR7bOgQ96HIIVCo2SbATzUQfj0rxYuBdkO-b79ebvDt9YOOwHTf0tNLlS-4YLxu2lJknsQCZIwO2BA"
  }
}
```

- A batch of only `cursor.set` has no batch ID, takes no `seq` and is applied again on every retry.
- The operations of one batch take consecutive `seq`s, and their chain envelopes carry the batch ID and count (6.6).
- **No-ops** (spec 6.3). An `app.put` of the record the service holds for the app, a `receive_key.put` of the app's current receive key record, a signer's `cert.put` of the renewed certificate the service stores (or of the certificate the app's record carries), and a signer's `key_bundle.put` of a part it stores with the same epochs, each byte for byte, are unchanged. A batch whose every signed operation is unchanged, an **unchanged batch**, creates no chain item and no batch record and counts against no rate, and its answer, when it succeeds, is `{ "proofs": [], "head" }`. Without `cursor.set` it is a no-op, answered before the conditions and checks (step 7). With `cursor.set` it isn't a no-op: its conditions and operations are checked first, as in any batch, and the cursor moves only if they all pass (step 10); a failing condition is `409 conflict`, and the cursor stays. Vectors: the `noop_batch` steps of `claims.json`. In a batch with any other operation, an unchanged one is chained like the others, since the batch's `count` names it, and changes nothing: an unchanged `receive_key.put` registers nothing, and its proof shows the current `n` and `kid`.
- **Operation and control rates** (Section 9). A batch from an own app that carries an ordinary operation, or a repeatable control mutation, counts against that app's operation rate: `ops_per_min`, 3,000 batches a minute by default. A batch that carries a repeatable control mutation also counts against its control rate, `control_per_min`, 60 a minute by default. The repeatable control mutations are an `app.put` or a `receive_key.put` that changes what the service holds (a new app record, a new registration), and a `record.put` that deletes, an `allow.delete` or a `deny.delete` of something that isn't there. An unchanged `app.put` or `receive_key.put` (No-ops, above) counts against no rate, also in a batch with other operations, where it is chained like them. Both "unchanged" and "something that isn't there" are judged against the state before the batch, as the conditions are (step 8), so an `allow.put` and an `allow.delete` of one entry in one batch count the delete as removing nothing. Both rates use fixed one-minute windows of service time; beyond one the batch is `429 rate_limited`, with `retry_after` the seconds to the next window. The other control operations never count: `cursor.set`, a claim entry other than `attempt`, a `record.put`, `allow.delete` or `deny.delete` that removes something, and `invite_code.delete`. Signer batches never count. Together the two rates bound how fast chain stubs and batch records grow, while a full inbox can still be drained, an existing attempt reconciled and an abusive app revoked.

Example (the registration batch of spec 12.1 step 2: `app.put`, the first `receive_key.put` and the cursor):

```json
{
  "ops": [
    {
      "body": "eyJpZGVudGl0eSI6Ijh5M3F5NGc5cTd5OW93bmQx...",
      "sig": "_yTDzcX99n7F-4c5R39619aNnDuSEZMTMCYtQ_RdfbUPBfE04MGc9FIiHqYGd5kPDUnJWpn4-nKgGEnPElmsDw"
    },
    {
      "body": "eyJpZGVudGl0eSI6Ijh5M3F5NGc5cTd5OW93bmQx...",
      "sig": "NQubEwL3PW59A3Yq2M44KzHI1Kjp809ENWYyUgrQMwUrHtMHHdBjD3xQLjTkwPaWp9H-dCKjjHx8WUkWkaTQDw"
    },
    {
      "op": "cursor.set",
      "position": "1:0"
    }
  ]
}
```

### 6.5 Transition proofs and service transitions

**Transition proof:** a signed document (label `pubky-switch/v1/proof`, fields: identity, body) with this body:

| Field | Type | Req | Notes |
|---|---|---|---|
| `chain` | stub | yes | the item's chain stub (6.6) |
| `object` | string | yes | per item, below |
| `step` | int | no | claims: the claim's step after the entry |
| `version` | int | no | per item, below |
| `state` | object | yes | per item, below |

| Item | `object` | `step` / `version` | `state` |
|---|---|---|---|
| `claim` | the claim key | `step` | the claim view (6.8) |
| `record.put` | the record key | `version`: the write's `seq`, the record's new version | `{ "generation", "version", "deleted" }`: the new version (6.2) |
| `allow.put`, `allow.delete` | the Pubky ID | | `{ "kind", "present" }` |
| `deny.put`, `deny.delete` | the Pubky ID | | `{ "denied" }` |
| `invite_code.put` | the code hash | | `{ "max_uses", "uses": 0 }` |
| `invite_code.delete` | the code hash | | `{ "withdrawn": true }` |
| `app.put` | the App ID | | `{ "app_id" }` |
| `receive_key.put` | the App ID | `version`: `n` | `{ "n", "kid" }` |
| `key_bundle.put` | the target App ID | | `{ "bundle_seq" }` |
| `cert.put` | the target App ID | | `{ "cert" }`: the renewed certificate's document hash |
| `identity.json` delivery | the literal string `identity` | `version`: the document's | `{ "version", "generation", "data_epoch" }` |
| service transition | per transition, below | | the transition body |

**Binding**: an answer to `POST /ops` is verified only when its proofs bind the batch: one proof per signed operation, in order, or none for an unchanged batch (6.4): a no-op, or a batch with `cursor.set` whose unchanged operations passed their checks. Only `app.put`, `receive_key.put`, `key_bundle.put` and `cert.put` can be unchanged. Each proof verifies with the service key, its stub's `item_hash` is that of its operation, and its `object` is the operation's per the table above. Before carrying out the attempt, the proof of the app's `attempt` must also show `step` one more than the `expected_step`, and a claim view with `state` `ATTEMPTING`, `owner` and `attempt_id` the app's own, and that attempt `open`; it verifies with the service key the app's own `identity.json` names, and its stub's `generation` is the one that document names (spec 12.5 Fencing). An answer that fails these checks is unverified, so no attempt is carried out on it, and as a signed contradiction it is misbehaviour, handled as a rollback (spec 10.1); an `attempt` whose proof binds the operation but shows another state is written `failed`. A proof that comes with a feed item or a record view is checked the same way (6.2 Accepting a write).

**Binding of the other writes.** Every other write that answers with a proof is bound the same way. Its answer carries at most one proof, which verifies with the service key that signed the answer, and:

- for `PUT /identity` (7.4.2), the stub's `item_type` is `identity`, its `item_hash` is that of the delivered document's bytes (6.6), and the proof's `object` is `identity`;
- for `POST /apps/{app_id}/leave` and `POST /apps/{app_id}/revoke` (7.4.12), the stub's `item_type` is `service` and the proof's `object` is the App ID of the path;
- for `POST /freeze`, `POST /unfreeze` at the old service (7.4.13), `POST /recovery/admission` and `POST /recovery/upload` after a provider loss (7.4.14), the stub's `item_type` is `service` and the proof's `object` is `freeze`, `unfreeze`, `admission` or `upload`.

An answer whose proof doesn't bind its request this way is unverified and, as a signed contradiction, misbehaviour (spec 10.1). An answer that may carry no proof, a retry of a version the service didn't take by that call (7.4.2) or the revocation of an app already revoked (7.4.12), shows only its head.

**Service transition:** a signed document (label `pubky-switch/v1/service-op`, fields: identity, body), a chain item of type `service` that the service writes itself. Bodies:

| `type` | Other fields | Proof `object` | Written by |
|---|---|---|---|
| `revoke` | `app_id`, `at` | the App ID | `POST /apps/{app_id}/revoke` |
| `leave` | `app_id`, `at` | the App ID | `POST /apps/{app_id}/leave` |
| `freeze` | `freeze_hash`, `next_generation`, `inbox`, `at` | `freeze` | `POST /freeze` |
| `unfreeze` | `freeze_hash`, `at` | `unfreeze` | `POST /unfreeze` |
| `recovery` | `recovery_from`, `at` | `recovery` | the first item at a new account after a provider loss |
| `admission` | `by: "signer"`, `at` | `admission` | `POST /recovery/admission` |
| `upload` | `by` (App ID), `changes` (7.4), `proofs` (count), `at` | `upload` | `POST /recovery/upload` |
| `conversation.add` | `pubky`, `code_hash`, `context`, `at` | (no proof is returned) | the first append admitted by an invite code |

**Import.** A provider move writes `freeze` (and, on an abort, `unfreeze`) at O; the import writes no transition of its own (Section 10). N's imported chain is O's chain, ending at O's `freeze` transition, which the manifest's head names. N's first own item is the delivery of the `identity.json` naming it, at generation g+1: it continues O's `seq` and chain hash, so an app's cursor and newest head stay valid (7.4.4). An abort at N writes nothing.

Example proof (`chain.json` "claim attempt (seq 7)", the `attempt` of 6.1; the claim view shows the deadline it pinned):

```json
{
  "chain": {
    "envelope": "eyJjaGFpbl92ZXJzaW9uIjoxLCJnZW5lcmF0aW9u...",
    "chain_hash": "39Z4TXAiQunrwwnx_BUO46H96vxegqPZNl261qJJ8Qo"
  },
  "object": "LOElfduZJYjUJFjB4crU2il4lVN2oKRo6BnTap10GqA",
  "step": 1,
  "state": {
    "attempt_id": "P37OWgXQlGXLccI0TFBpwg",
    "attempts": [
      {
        "attempt_id": "P37OWgXQlGXLccI0TFBpwg",
        "duplicate": false,
        "opened_at": "2026-01-01T00:00:03.000Z",
        "orphan_after": 86400,
        "orphaned": false,
        "outcome": "open",
        "owner": "w8amtmn13m6p5bwnmj9wejbq4c",
        "possibly_duplicate": false
      }
    ],
    "claim_key": "LOElfduZJYjUJFjB4crU2il4lVN2oKRo6BnTap10GqA",
    "deadline": "2026-01-02T00:00:00.001Z",
    "divergent": false,
    "next_possibly_duplicate": false,
    "owner": "w8amtmn13m6p5bwnmj9wejbq4c",
    "state": "ATTEMPTING",
    "step": 1,
    "tombstone": false
  }
}
```

### 6.6 Chain envelopes and hashes

Every signed operation, every `identity.json` delivery and every service transition is a chain item (spec 8.3, 13.6). Inbox entries and cursor moves are not, so the `seq`s of chain items may have gaps.

- **Item hash:** `hash(lp("pubky-switch/v1/item", item type, item bytes))`, with item type `op`, `identity` or `service`, and item bytes the signed document bytes (2.2).
- **Chain envelope**, written by the service and kept as exact bytes:

  | Field | Type | Req | Notes |
  |---|---|---|---|
  | `chain_version` | int | yes | 1 |
  | `generation` | int | yes | |
  | `seq` | int | yes | the item's position in the sequence |
  | `prev_chain_hash` | `b64(32)` | yes | the previous chain item's chain hash; 32 zero bytes before the first item |
  | `server_time` | time | yes | when the service applied it |
  | `item_type` | string | yes | `op`, `identity` or `service` |
  | `item_hash` | `b64(32)` | yes | |
  | `batch_id` | `b64(16)` | operations only | |
  | `batch_count` | int | operations only | |

- **Chain hash:** `hash(lp("pubky-switch/v1/chain", prev_chain_hash, envelope bytes))`.
- **Stub:** `{ "envelope": "<base64url of the exact envelope bytes>", "chain_hash": b64(32) }`.
- **Checks** an app makes on each stub, in feed order: the chain hash follows from the envelope; `seq` is above the last one; `prev_chain_hash` is the last chain hash; the generation is the one followed, or higher after a cooperative move or a key change in place; `server_time` isn't before the previous stub's, else it is a rollback, since the service never stamps earlier than the last time it committed (spec 10.1), though equal times are fine, as a batch's stubs may share one; a batch's items have consecutive `seq`s with one ID and count until `count` items are seen; a new batch's ID isn't that of an earlier batch with `t_new - t_old < 30 days`, exactly 2,592,000,000 ms, `t_new` and `t_old` being the `server_time` of each batch's first stub (the reference prototype: `BATCH_IDS_COMPARED_FOR_MS`); at 30 days or more the earlier batch isn't compared, and the app forgets it, whatever checkpoints it sees (6.4 step 5, spec 13.5). `chain.json` `batch_id_window` has the cases 1 ms before, at and 1 ms after 30 days. Right after an app continues from a checkpoint it has no previous time, so the next stub's isn't compared (7.4.4). A full item must match its stub's `item_type` and `item_hash`; one that doesn't is a rollback (spec 10.1), and the app doesn't act on it.

Example envelope (the `attempt` of 6.1, at `seq` 7: an inbox entry at `seq` 5, the record's create at `seq` 6):

```json
{
  "chain_version": 1,
  "generation": 1,
  "seq": 7,
  "prev_chain_hash": "jjMkxY3N9g4KTZ5l0nIgjk9pCBnf0fLun1aMA8OWYPw",
  "server_time": "2026-01-01T00:00:03.000Z",
  "item_type": "op",
  "item_hash": "bMl6YsCP6NVSV_gLdAJvf38hivvMXRL9dhQFc6pG8X4",
  "batch_id": "ytmXw2Y65nm811vKBpkAQQ",
  "batch_count": 2
}
```

### 6.7 Signed heads

A signed head is a JSON object (not a signed document):

| Field | Type | Notes |
|---|---|---|
| `chain_version` | int | 1 |
| `generation` | int | |
| `seq` | int | the newest chain item's `seq`, 0 before any |
| `chain_hash` | `b64(32)` | its chain hash; 32 zero bytes before any item |
| `sig` | `b64(64)` | service key, label `pubky-switch/v1/head`, over `lp(label, identity, u64(chain_version), u64(generation), u64(seq), chain hash)` |

- In a header (`Switch-Head`) the head travels as base64url of its JSON bytes.
- An app keeps the newest head it has seen. A head with a lower `seq` must match the chain hash the app verified at that `seq`; a head beyond the chain verified so far is kept until the stubs reach it, and is a rollback if a read that reaches the end of the feed still hasn't reached it (spec 10.1).

```json
{
  "chain_hash": "muYjBhuz6UI1RX8upIrIIMIBpI_3gRvfhwQtrDldImA",
  "chain_version": 1,
  "generation": 1,
  "seq": 9,
  "sig": "b23xHVPZCR7bOgQ96HIIVCo2SbATzUQfj0rxYuBdkO-b79ebvDt9YOOwHTf0tNLlS-4YLxu2lJknsQCZIwO2BA"
}
```

Vectors: `chain.json` builds a chain of eight items with a gap (the first is the account's first `identity.json`, 3.3), their envelopes, hashes and proofs, two heads, and chains the verifier must reject: a partial batch and a repeated batch ID, both with intact links, so only the batch rules reject them; a batch cut off at the end of a page; a gap that breaks the link; and a forked head. A verifier checks in the order of the list above, so a broken link is reported before a batch rule.

### 6.8 Claim states

The **claim view** is the `state` of claim proofs, the `claim` of `GET /claims` and the `current.claim` of conflicts:

| Field | Type | Notes |
|---|---|---|
| `claim_key` | `b64(32)` | |
| `state` | string | `FREE`, `ATTEMPTING` or `SETTLED` |
| `owner` | app-id | while `ATTEMPTING`: the current attempt's owner |
| `attempt_id` | `b64(16)` | while `ATTEMPTING`: the current attempt |
| `step` | int | the number of entries |
| `attempts` | `array<object>` | every attempt, oldest first, below |
| `tombstone` | bool | a compacted finished claim |
| `deadline` | time | the deadline the first `attempt` pinned, on a claim or a tombstone; absent when none was pinned or the pin is "none" |
| `divergent` | bool | uploads after a provider loss conflict (spec 12.6); default `false` |
| `rebuilt` | bool | rebuilt from uploads after a provider loss (7.4.14): its upload steps have no entry (7.4.8); written only when `true`, so absent means `false` |
| `next_possibly_duplicate` | bool | the next `attempt` would be flagged `possibly_duplicate` (row 1), so no app attempts it automatically; default `false`. Always `false` on a SETTLED claim, live or a tombstone, since row 7 refuses every later attempt |

An attempt: `attempt_id`, `owner` (app-id), `outcome` (`open`, `done`, `failed` or `unknown`), `opened_at` (time of its `attempt` entry), `orphan_after` (seconds), `orphaned` (bool, at the time of the answer), `possibly_duplicate` (bool), `duplicate` (bool), and `resolved_by` (app-id, absent while open): the app that wrote its outcome.

The rules (spec 10.2):

| # | Entry | Applies when | Writer | Effect |
|---|---|---|---|---|
| 1 | `attempt` | no attempt is open and not SETTLED; `attempt_id` new for the claim; the service's time is before `deadline`; `deadline` equals the pinned one, if any | any app with `claims.write` | a new open attempt, current; the first one pins the claim's deadline, "none" included; `possibly_duplicate` if an earlier attempt is `unknown`, or its `failed` or `unknown` was written by an app other than its owner. A `done` attempt, by any basis, settles the claim, so no attempt follows it (row 7) |
| 2 | `done`, basis `owner` | the attempt is `open` or `unknown`; or `failed` on a claim rebuilt from uploads after a provider loss | its owner | done; SETTLED; `duplicate` if another attempt is done |
| 3 | `done`, basis `evidence` | the attempt is `open`, `unknown` or `failed`, on a claim or a tombstone | any app with `claims.write` | as row 2 |
| 4 | `done`, basis `reconcile` | the attempt is `open` and orphaned | any app with `claims.write` | as row 2 |
| 5 | `failed` | the attempt is `open` or `unknown` | its owner, or any app once the owner isn't current | failed; FREE if it was the current attempt |
| 6 | `unknown` | the attempt is `open` and orphaned, not SETTLED | any app with `claims.write` | unknown; FREE |
| 7 | `attempt` or `unknown` | SETTLED | | `409 conflict` |

- **Orphaned:** an open attempt whose owner isn't current (revoked, departed, not listed, or with an expired certificate), or whose `orphan_after` has passed (`now >= opened_at + orphan_after`), or which came from a recovery upload.
- **Conflicts** (`409 conflict` with `current.claim`): a stale `expected_step`; an `attempt` while another is open; an `attempt` naming another deadline than the pinned one, or none where one is pinned; a writer the row doesn't allow; an entry for an unknown `attempt_id`; a repeated `done` for a done attempt, which also stops the rest of its batch; any entry on a tombstone other than row 3.
- **Deadline:** an `attempt` at or after its `deadline` on the service clock is `409 conflict` with `current.server_time` and `current.claim`, whatever the claim's state. This check comes first, before `expected_step` and the row rules. Apps don't send an `attempt` once its deadline is at or before the highest service time they have verified, and a transition proof stamping an `attempt` (6.6 `server_time`) at or after its deadline is misbehaviour (spec 10.2).
- **Pinned deadline and evidence** (spec 10.2): an app keeps evidence for an obligation, its SETTLED and tombstone proofs, until the later of the bounds that apply:
  - the later of the pinned `deadline` and the one it computes itself, where there is one, plus the 30-day reconciliation window during which the service keeps the tombstone (below);
  - with a pin to "none", `max_claim_age` (400 days) after the proof's time, the time its stub carries, as the service keeps that tombstone 400 days after its last entry, which is no earlier.

  So with a pin to "none" beside a deadline of its own, it keeps the evidence to the later of its deadline plus 30 days and the proof's time plus 400 days. A pinned deadline where it computes none (it holds what created the obligation, such as a `tasks.assignment` without a deadline) is an early pin (below), and it keeps that evidence for good: it may still attempt the obligation, and the evidence shows it done once the service has deleted the tombstone. It drops the evidence only once every bound lies before the earlier of the highest verified service time and its device clock plus 24 hours: it is kept at the boundary itself and dropped from the next millisecond. Until then it compares the evidence with the claim and uploads it in a move (7.4.14) or after a provider loss. A service that shows nothing for it is a rollback, except from the moment the service may delete the tombstone, the pinned deadline plus 30 days, or with a pin to "none" the proof's time plus 400 days, though the app still holds the evidence at that instant. From then until the app drops the evidence, the pin differs from the app's own deadline, early or "none" beside a deadline: the app alerts, and the evidence still shows the obligation done, so it doesn't attempt it again. A pin earlier than the app's own deadline is an alert and makes the obligation doubtful.
- **Order of the checks** for one entry: permission and shape (6.4 step 9), then for an `attempt` the claim limits (Per app, below), then the deadline, then `expected_step`, then the row rules in table order.
- **A SETTLED claim with an open attempt** (evidence settled another attempt while one was open) keeps the open attempt: its owner may still report `done` (flagged `duplicate`) or `failed`, and it isn't compacted until every attempt is `done` or `failed`.
- **Malformed** (`400`): `attempt` without `orphan_after`, and `orphan_after` on another type; `done` without `basis`, and `basis` on another type; basis `evidence` without `evidence_ref`; `evidence_ref` on a type other than `done`; `deadline` on another type; a claim key or attempt ID of the wrong length.
- **Tombstones** (spec 6.3): a claim that is SETTLED with every attempt `done` or `failed` is compacted at once. It keeps its step and attempts; its deadline is the pinned deadline. Its entries lose their documents: from then on the feed shows them as stubs to every app, the writer of the settling entry included (7.5), and its read (`GET /claims`) returns no entries, so an app that didn't write the settling entry holds no settling proof and relies on the read's own signed answer. An `attempt` is refused from that deadline itself (above), but the service keeps the tombstone for the reconciliation window, 30 days (2,592,000,000 ms; the reference prototype: `CLAIM_RECONCILIATION_MS`), and deletes it once the time base, with trusted time, reaches the deadline plus that window (7.3 step 4, Appendix A); then `GET /claims` is `404`. A tombstone pinned to "none" is kept until the time base, with trusted time, reaches its last entry plus `max_claim_age` (34,560,000,000 ms, 400 days; the reference prototype: `MAX_CLAIM_AGE_MS`), and deleted the same way.
- **Failed claims** (spec 6.3): a claim that never settled, whose every attempt is `failed`, is kept the same way: to its pinned deadline plus 30 days, so late evidence, such as the counterparty's `tasks.receipt`, can still record `done` on a `failed` attempt (row 3); then it is deleted. One pinned to "none" is kept 400 days after its last entry, then deleted. A claim with an open or `unknown` attempt is never deleted by age. After the window late evidence can't be recorded, and a protocol says what its apps do with it.
- **Doubtful claims:** apps never attempt automatically a claim with an `unknown` or orphaned attempt, or with `next_possibly_duplicate` (spec 10.2).
- **Per app** (spec 6.3, 10.2): the app whose `attempt` creates a claim is its creator, which the service records and an export carries (10.3): the owner of the claim's first attempt, also for a claim rebuilt from uploads. The claims one app created, live and tombstones, are at most its **claim share**, `floor(max_claims * claim_share_percent / 100)` claims (250,000 at the defaults; 3 for `max_claims` 12, and 2 for `max_claims` 10). The attempts one app owns that are `open` or `unknown` are at most `open_attempts_per_app` (1,000), counting every live claim. Outcomes are never refused. An `attempt` is checked against the claim limits in this order, after its permission and shape and before the deadline and the claim rules (6.4 step 9), and the first it would exceed answers `429 quota_exceeded` (9.3) with that limit in `current.limit`:
  1. `claims`: it would create a claim (its key is neither a live claim nor a tombstone), and the live claims and tombstones number `max_claims`;
  2. `claim_share`: it would create a claim, and the claims its app created number its claim share;
  3. `attempts`: the live claim holds `max_attempts_per_claim` (64) attempts;
  4. `open_attempts`: its app owns `open_attempts_per_app` attempts `open` or `unknown`.

  So a new claim within its app's share gets `open_attempts` when the app is at that limit, and `claim_share_percent` 100 turns the share off, since `claims` answers first. A revoked app's open attempts stay, orphaned, until an own app resolves each (rows 3 to 6).
- **The record shows it done**: a claim pinned to "none" is gone 400 days after its last entry, so a re-sent copy of what created it, such as a `tasks.assignment`, finds the claim FREE. An app never attempts an obligation whose record it holds shows it done, so the record, not the claim, stops a second attempt from then on, and the app therefore never deletes its record of a done obligation without a deadline (spec 10.2).

Vectors: `claims.json` runs 69 steps through every row above, the deadline pin and the reconciliation window (a failed claim kept past its deadline, settled by a late receipt, and deleted at the deadline plus 30 days), with the expected claim view or error after each one; its `noop_batch` steps are the no-op cases of 6.4, and its `app_put` steps those of `app.put` (6.2). Its `quota` steps run the two per-app limits on a switch of their own, with `max_claims` 12 and `open_attempts_per_app` 2: an app's third open attempt is `429 open_attempts`, its fourth claim `429 claim_share`, and another app creates that claim.

## 7. HTTP API

### 7.1 Requests and responses

**Transport.** HTTPS. Paths start with `/v1/`; `{id}` is the account's Pubky ID. JSON bodies are sent as `application/json`; the body of an append is the raw envelope (`application/octet-stream`). Header names are case-insensitive (the reference prototype: it sends them in lower case).

**Switch origins** (spec 6.1). A client connecting to a switch origin it read from an `identity.json` checks it with the classifier of 8.2: `https` only, no user info, path, query or fragment; port 443, or another port only where the client's operator allows it; an address literal, and every address the host resolves to, globally reachable (8.2); the connection goes to an address it checked, and redirects aren't followed. (The reference prototype: `transport::Http::public_only` does this, its resolver refusing a host with any address that isn't public; `Http::new` doesn't, for runs on loopback.)

**Query parameters** are `name=value` pairs joined by `&`. The service percent-decodes names and values. The request signature covers the path and query exactly as sent, so a client builds the query once and doesn't re-encode it.

**Request headers:**

| Header | Sent by | Value |
|---|---|---|
| `Switch-Identity` | every caller | the caller's identity, as a Pubky ID |
| `Switch-App` | apps | the calling App ID; absent for signer calls |
| `Switch-Cert` | apps calling another identity's account, and the staged head upload of 7.2 | the app's certificate in compact form (2.2) |
| `Switch-Invite-Code` | optional (spec 7) | an invite code (1.7) |
| `Switch-Transfer` | the next service fetching export chunks | the signer's export transfer in compact form (2.2, 3.11) |
| `Switch-Timestamp` | every caller | the signing time, `YYYY-MM-DDTHH:MM:SSZ` (1.6) |
| `Switch-Signature` | every caller | `b64(64)`, the request signature |

**Request signature** (label `pubky-switch/v1/http`): `lp(label, method, path and query, hash(body), Switch-Timestamp, switch origin, Switch-Identity, Switch-App, Switch-Cert, Switch-Invite-Code)`. A next service's request carries `Switch-Transfer` and no `Switch-App`, and is signed over `lp("pubky-switch/v1/transfer-request", method, path and query, hash(body), Switch-Timestamp, switch origin, Switch-Identity, Switch-Transfer)`.

- The method is upper case; the body hash is over the raw body bytes, so a request without a body signs `hash` of the empty string.
- The **switch origin** is the service's origin exactly as `identity.json` names it in `inbox.url` (for an enrollment, the origin the signer enrolls at), for example `https://inbox.example`. It isn't sent; both sides know it.
- Header values are signed as their exact text, and an absent header as an empty field.

**Timestamp:** an unparsable or missing `Switch-Timestamp` is `400 bad_request`; one more than 5 minutes from the service's time base (7.3) is `401 stale_timestamp`. The time base is trusted time, or the wall clock while it agrees with trusted time; not the identity's stamped time, which never goes back, so neither a jump of the service's wall clock nor a corrected one locks out apps with correct clocks (spec 10.1). The answer's `current.server_time` (7.6) is that time base, for the client to set its retry's timestamp from; `Switch-Server-Time` stays the identity's service time, the last it committed, which a request refused before the account's lock (7.2 Order) doesn't move.

**Response headers:**

| Header | Present | Value |
|---|---|---|
| `Switch-Service-Signature` | every response | `b64(64)`, the response signature |
| `Switch-Server-Time` | every response | the identity's service time, three fraction digits (1.6) |
| `Switch-Head` | responses to own apps and the signer, refusals included once the request has verified (below), except to an enrollment (7.4.1) and an erasure (7.4.16) | base64url of the newest signed head's JSON (6.7) |
| `Retry-After` | `429` | seconds |
| `Content-Type` | every response | `application/json` |

**`Switch-Head` on refusals.** The service shows its head only to a caller it has authenticated. So a refusal to an own app or the signer carries the head once the request has verified with the caller's key (7.2): a `403 not_current` or `403 cert_expired` answered after that check, and every later refusal. A `401` carries none, nor does a `429` answered before authentication (7.2 Failed authentications), nor the refusal of a first call that nothing verified, for which the service holds no key (7.2), nor the `503` of an account behind its key's mark (7.3 step 10).

**Response signature** (label `pubky-switch/v1/http-response`): `lp(label, u64(status), hash(request signature bytes), Switch-Server-Time text, hash(body))`.

- The request signature bytes are the 64 bytes decoded from the request's `Switch-Signature`, or empty when it has none that decodes (2.3).
- It is made with the account's service key. A response the service can't tie to an account (an unknown account or route, or an enrollment error before the account exists) is signed with an operator key no client knows, and clients treat it as unauthenticated.
- The signature covers the server time but not `Switch-Head`, which carries its own signature, nor `Retry-After`, whose value is repeated in the body.
- A client checks the signature before it uses anything in the response. For example, a client takes `at` from `Switch-Server-Time` only once it has checked it.
- **Pinned key** (spec 6.1): a client checks with the account's service key it pinned, from the `identity.json` naming the service or, for the signer, from its enrollment answer (3.7) or the freeze naming the next service (3.6). A client without a pinned key sends only an enrollment and the public read of 7.4.15; any other call fails closed before it is sent, and no answer is ever used unchecked. (The reference prototype: its `InboxClient` answers such a call with `ClientError::Unpinned`.)
- **An unpinned public read.** A reader without a pinned key may make the public read (7.4.15): the `identity` and `freeze` it answers are signed by the identity key, which needs no pin. The reader verifies each with that key and uses nothing else of the answer until the response signature has verified: not the status, not `Switch-Server-Time`, not an error or its `retry_after`, and not the absence of `freeze`. When the document it verified names this origin, the reader checks the response signature with the `inbox.service_key` that document names, and from then on holds that key as its pin, as from any `identity.json` naming the service. An answer it can't check this way, an error included, counts as a failed lookup (3.3 "The switch's copy"), never as a sign that the service holds no document or doesn't host the identity.

**Body caps.** Each call takes a body of at most its cap; a larger one is `413 too_large`, before the body is read or anything else is checked:

| Calls | Cap |
|---|---|
| `POST /inbox` | 65536 bytes (the envelope cap) |
| `POST /ops`, `POST /import` | 4 MiB |
| `POST /enroll`, `PUT /identity`, `PUT /peers` | 256 KiB |
| `PUT /import/chunks/{chunk_id}` | 1 MiB (the chunk size) |
| `POST /recovery/upload` | 16 MiB |
| `PUT /handover` | 12 MiB (128 envelopes in base64url, 3.12) |
| `POST /freeze`, `POST /unfreeze`, `POST /import/activate`, `POST /recovery/admission`, `POST /apps/{app_id}/revoke`, `POST /apps/{app_id}/leave`, `POST /apps/{app_id}/keys`, `PUT /push`, `POST /erase` | 16 KiB |
| every `GET`, `POST /connect`, `DELETE /connect/{pubky}` | none (0 bytes) |

**Answer sizes.** No answer has a cap of its own; its size follows from the limits on what it carries (Section 9). A paged answer is bounded by a byte budget: a feed page (7.4.4) and a list page (7.4.9) end before the item that would take their items past `max_page_bytes`, 8 MiB (9.2), and always hold at least one. A single item is under 1 MiB (a record view is the largest, 951,215 bytes by the `record` part's bound, 10.3), and a batch's items together under 5 MiB, so a page with its other members stays under 8.1 MiB. The other answers aren't paged. At the default limits (9.2) the largest are:

| Answer | At most | What bounds it |
|---|---|---|
| an export chunk (10.3) | 1.4 MiB | a chunk of 1 MiB in base64url |
| `GET /apps` (7.4.12) | 4 MiB, and more with the account's history | 32 apps with 1,000 open attempts each, and `identity.json`: 4 MiB. It then grows for the identity's life, with no fixed bound: about 360 bytes for each purged App ID, which the service keeps for good (9.1), and one `bundle_ranges` pair, of at most 36 bytes, for each key bundle part it stores for an app, at most one part for each data epoch. A new account starts with at most 6,766 purged App IDs, the most one enrollment can name (3.12), which add 2.4 MiB; the service sets no limit on those it adds afterwards |
| `GET /handover` (7.4.17) | 12 MiB | the body cap of its `PUT` |
| `GET /directory` (7.4.10), and a `409 stale_key`'s `current` (7.6) | 13.2 MiB | `identity.json` (262,119 bytes) and 32 apps, each with an app record (392,924) and a receive key record (about 30,000; 10.3 Part sizes); 104 MiB at an app limit of 255 |
| `GET /claims/{claim_key}` (7.4.8) | 134 MiB | 256 entries, four for each of 64 attempts, each an operation of 512 KiB with its proof (24,522); under 7 MiB when the operations are of ordinary size, about 1 KB |
| `GET /allow` (7.4.6) | 134 MiB | 100,000 contacts and 100,000 deny entries of 55 bytes each, and 100,000 conversation entries of up to 1,292 bytes with a full context; about 28 MiB when no entry has a context |

So the largest answer the limits bound is under 135 MiB at the default limits, and the bounded answers not listed are smaller there. These answers have no fixed bound, since they grow with the account's history: `GET /apps`, as the table says; an app's key bundle parts (7.4.11), which grow by one part of at most 87,645 bytes with each rotation the app missed; and, during a move, the export's manifest (10.2) and an import's list of missing chunks (10.4), which name one chunk for each mebibyte or so of the account's state. A client may refuse a bounded answer that is larger than the bound of its call without reading it to the end, as it refuses a malformed one. For those without a bound, their only readers, the signer and, for its key bundle parts, the app itself, set a cap of their own with room for that growth. A client that sets itself a lower cap and refuses an answer for its size treats the call as failed.

**Body rules:**

- Every body is a JSON object.
- Responses to apps of other identities never carry a `seq`, a head or other activity data. A `2xx` answer and a `409 identity_needed` get a member `known_version`: the `version` of the caller's identity's `identity.json` that the service holds, or `null` (spec 6.1). A reader takes a missing `known_version` and a `null` one alike, as no version held (Absent and null). Other errors don't, so they tell the caller nothing of what the service holds for its identity. An app that copy lists in `removed` gets `null`, or the version it delivered (7.4.5), as a stranger would (7.2).
- Error bodies are `{ "code": string, "message": string, "current": object (where 8.6 says), "known_version": ... (only in `409 identity_needed`), "retry_after": int (on `429 rate_limited`) }`.
- Writes by own apps and the signer return `{ "proofs": [...], "head": signed head }`, the transition proofs of the chain items they wrote, in order.

Vectors: `http.json` has signed requests from an own app, an app of another identity (with `Switch-Cert`, an invite code and `apps_version`) and the signer, and signed responses: two feed pages, a directory, a write answer, a `409 stale_key` and a `429` to another identity's app, the enrollment answer, and an operator-signed `404` to a request without a signature. The signer's erasure and its answer (7.4.16) are among them, and a key change that leaves out a needed service key with its `409 conflict` (7.4.2).

Example request headers (an append from bob's `shop` to alice's inbox):

```
POST /v1/8y3qy4g9q7y9ownd18hskdoxdxzueutiu3f391rnnuxznxmqp5bo/inbox?apps_version=4
Switch-Identity: 43xz73bjzs8c84sw4sigu5bm3x93mj17ywjy1oa3dbnriiymcw4o
Switch-App: ye9a6d8e43cq3f69kto91csqqe
Switch-Cert: eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLmFw...
Switch-Invite-Code: YMXqc5UxVVGogjCsEo424Q
Switch-Timestamp: 2026-01-01T00:05:01Z
Switch-Signature: A_wDd8-ZdLJEFUjHwmTDsr1ILsvXaW1uZGn-9FzrGIx53zp_UV4qbcCtmBDrNy53CQKxi2ZXMIzgV0V0E8piCg
```

### 7.2 Callers and authentication

The service tells callers apart by the headers:

| `Switch-Identity` | `Switch-App` | Caller | Verified with |
|---|---|---|---|
| the account's identity | absent | the signer | the identity key |
| the account's identity | present | an own app | the signing key of the app record it delivered with `app.put` |
| another identity | present | an app of another identity | the signing key of the certificate in `Switch-Cert` |
| another identity | absent | | `403 not_admitted` |
| the account's identity, with `Switch-Transfer` | absent | the next service of a cooperative move, fetching export chunks | the next service's key the export transfer names (3.11) |
| absent | absent | anyone, for `GET /identity` only (7.4.15) | nothing |

- **An own app's first call** is a `POST /ops` whose batch carries its `app.put` (spec 12.1). The service looks only at the batch's first `app.put` naming the caller (a body of 1 to 8 entries), checks that its record's `signing_key` gives the caller's App ID (1.3) and that the request verifies with that key, and only then verifies the app record, its certificate and the operation's signature (`401 bad_signature` at the first that fails; a later `app.put` naming the caller doesn't count). Any other first call is `403 not_current`.
- **An own app** must be current: not revoked or departed, and listed with its certificate in the newest `identity.json` the service holds (`403 not_current`); its certificate must not have expired (`403 cert_expired`).
- **Where an own app gets `403 not_current`.** With `Switch-Head`, the request verified (7.1): the app is revoked or departed; the newest `identity.json` the service holds lists neither its certificate nor an open renewal of it, so it lists the app with another certificate, in `removed`, or not at all (3.8); the record the service holds doesn't carry the certificate (check 6); an `app.put` whose record carries another certificate than the listed one (6.2). Without `Switch-Head`, before anything verified: the service holds no record of the app to check the request with, and the call isn't a `POST /ops` carrying its `app.put` (An own app's first call, above). That is an app that never registered at this service, such as one at a new service after a provider loss or a move whose re-registration hasn't applied or was refused there, a recovery upload before the app's `app.put` included (7.4.14), since the account starts afresh at a recovery and holds no app record until each app's `app.put`; an app purged from `removed` after its revocation or departure, whose record is gone while its App ID is kept for good (9.1); and an App ID an enrollment named in `revoked_apps` (3.7). Outside an own app's calls, the signer gets it for a `key_bundle.put` whose target isn't current (6.2), and an app of another identity whose certificate's renewal has closed at an append or a connect request (3.8, 7.4.3, 7.4.7); each reads it as those sections give.
- **How an own app reads it.** The answer is checked like any other (7.1): one whose service signature doesn't verify is no answer. Then the app reads the newest `identity.json` of its identity (spec 4.3), and the answer counts only from the service and generation that document names. Listed there with another certificate than the one it holds, the app waits for a renewal: it takes that certificate (3.8 step 3) and sends the request again. Listed in `removed`, or not listed, it is revoked, departed or dropped, and it stops (spec 12.2, 12.3), with the head or without. Listed with the certificate it holds and not in `removed`, an answer with the head is final too: the service counts the app as revoked or departed, or holds a record without that certificate, and the app stops. An answer without the head says only that this service holds no record of the app: the call fails, nothing ends, and a registration the app owes there, such as a provider loss's or a move's, goes again at its next call. An app that can't read the newest document takes neither answer as final yet, and asks again at its next call.
- **An app of another identity** must send `Switch-Cert` (`400`). The certificate must verify for `Switch-Identity` and name `Switch-App` (`401 bad_signature`), the request must verify with its key (`401`), and it must not have expired (`403 cert_expired`). Admission (spec 7) and the listing check (`409 identity_needed`, 7.6) apply per endpoint.
- **A removed app is answered like a stranger** (spec 6.1). An app of another identity that the service's copy of that identity's `identity.json` lists in `removed` (and, at `PUT /peers`, one the delivered document lists there) gets, at every endpoint it may call, exactly the answer an app of an identity the service doesn't admit and holds no copy of would get: admission counts only an invite code, never a contact or conversation entry; appends and connect requests then get `409 identity_needed` with `current: { "version": null }` and `known_version: null`; `PUT /peers` answers as 7.4.5 says. So a revoked app's key can't learn which switches hold its identity's document, and so which identities correspond with it. Residual: a switch that still holds an older document listing the app treats it as current until it gets the newer one (spec 12.2 step 5); certificate expiry (3.1) bounds that too.
- **A staged head upload** (spec 12.5 step 3): before an import, a staged service holds no app records. An app then authenticates `POST /recovery/upload` with `Switch-Cert`: the certificate must verify for the identity, name the app and its signing key, and be listed in the `identity.json` the service was enrolled with.
- **Invite codes** are checked and used only when nothing else admits the sender, and only an admitted append uses one; directory reads and `PUT /peers` use none.

**Order** (3.8). Cheap checks come before signature work, and signature work before anything that needs the account's state, so an unauthenticated request costs little and holds no lock: first the body cap (7.1), then, at an account the service holds, the network source's failed-authentication limit (`429 rate_limited`, below), then `Switch-Identity` and `Switch-Signature` decode (`400`, `401`) and the timestamp (`400`, `401 stale_timestamp`), then for every caller the order below, stopping at the first failure:

- **Signer:** the request signature with the identity key (`401 bad_signature`).
- **Own app:** for a batch carrying its `app.put`, the first-call order above; otherwise check 4 with the `signing_key` of the certificate it checks the app against (a stored renewed certificate once the newest `identity.json` lists it, else the record's). Then checks 1 to 3 on that certificate, not revoked or departed, and the certificate listed or in an open renewal (check 5, `403 not_current`), then check 6 on the record it holds (`403 not_current`).
- **App of another identity:** checks 1 and 2 on `Switch-Cert` and check 4, then check 3 at the identity's service time. Check 5, against the service's copy of that identity's `identity.json`, comes per endpoint, for appends and connect requests (7.4.3, 7.4.7); an app whose renewal has closed gets `403 not_current` there. An app that copy lists in `removed` is answered like a stranger at every endpoint, before admission (above).
- **Staged head upload:** checks 1 to 4 on `Switch-Cert`, then check 5 against the `identity.json` the service was enrolled with.
- **Next service:** `Switch-Identity` is the account's and `Switch-App` absent (`400` otherwise); the export transfer in `Switch-Transfer` verifies with the identity key (`401 bad_signature`), then the request with the transfer's `to.service_key` over `pubky-switch/v1/transfer-request` (`401 bad_signature`). Under the lock O checks that the transfer names this export (3.11, `403 not_admitted`); the call must be a chunk fetch (`403 permission_missing`). Its failed authentications are counted as a claim of their own, for monitoring.
- **Public read:** `GET /identity` (7.4.15) is answered with no authentication at all, after the body cap, before step 5 of 7.3, limited per network source and per account (9.4).
- **Failed authentications** (9.4): until a request verifies, nothing it claims is trusted, so the service limits it only by network source, an IPv4 address or an IPv6 /64, an IPv4 address mapped into IPv6 counting as the IPv4 address. Once a source has had `auth_failures_per_source_per_min` failed authentications in the current minute, at any accounts, the service answers every further authenticating request from it in that minute with `429 rate_limited` (so with the default 60, the 61st is refused). The check comes right after the body cap and the account lookup (7.3 steps 1 and 2), before any header is decoded, and applies to every call but the enrollment and the public read (7.4.15). Every answer `401` counts, whatever the step: a malformed `Switch-Signature`, `401 stale_timestamp`, a signature that doesn't verify, the first-call checks and the next service's `401`s included; `400`, `403` and `429` answers don't count. The minutes are fixed minutes of the time base (7.3 Trusted time), the same for all accounts, not an account's stamped service time. The service also counts failed authentications per claimed caller (its `Switch-Identity` and `Switch-App`) at each account, for its operator's monitoring, but never refuses a request because of that count: anyone can claim any App ID, so such a refusal would let a stranger lock a victim app out. The limits per caller (9.4) apply only once a request has verified. A service that can't tell the source (the reference prototype: its in-process transport) applies no limit here; behind a reverse proxy the source is the address the proxy reports.
- **Outside the lock:** everything up to the request signature needs no account state but an own app's key, so a service may run it before taking its state lock, looking up only that key under a brief lock, and check under the lock that the key it verified with is still the one it holds (the reference prototype: it does).

Scopes and switch permissions come after authentication, then the endpoint's checks. Renewal (3.8) changes which certificate an own app is checked against from the delivery of the `identity.json` that lists the renewed one.

### 7.3 Processing order

For every request the service:

1. Routes it; an unknown route is `404`, signed with the operator key.
2. Finds the account; an unknown account is `404`, signed with the operator key. `POST /v1/enroll` is handled here (7.4).
3. Takes the identity's service time: the time base (below), or the last time it stamped if the time base is earlier (spec 10.1).
4. **With trusted time only** (below), and only for a caller that has verified (7.2), so an unauthenticated request or the public read pays for none of it: deletes tombstones and failed claims whose deadline plus the reconciliation window has passed (6.8), by the time base, not by the stamped time of step 3, which a reading without trusted time may have moved ahead and which never goes back. At most once a minute of service time it also runs the sweeps of 9.1: deleted keys that may be forgotten, invite codes that expired or ran out, and batch proofs past `batch_proofs_ms`. Each is bounded per run and leaves the rest to a later request.
5. Authenticates the caller (7.2).
6. Records an own app's last-seen time.
7. **Staged:** an account that the newest `identity.json` doesn't name answers everything except `PUT /identity`, `POST /import`, `PUT /import/chunks/{chunk_id}`, `POST /import/activate`, `POST /unfreeze` (an abort, 10.6), `POST /recovery/upload` and `POST /erase` (7.4.16) with `503 staged`.
8. **Frozen:** a frozen account answers every write with `410 moved`, whose `current.freeze` is the signed freeze. Writes are `POST /inbox`, `PUT /peers`, `POST /connect`, `DELETE /connect/{pubky}`, `POST /ops` (including the record and cursor batch of receiving), `POST /apps/{app_id}/keys` (7.4.11; a request taken after the export's manifest would never reach the next service, so the app asks there, after following the freeze), `POST /apps/{app_id}/leave`, `POST /apps/{app_id}/revoke`, `POST /recovery/upload`, `PUT /push` and `PUT /handover`. Reads go on, and so do the export (`GET /export`, `GET /export/chunks/{chunk_id}`), `POST /unfreeze` and `POST /erase` (7.4.16). Feed pages of a frozen account carry the freeze (7.4.4), so an app that only reads learns of the move.
9. Runs the endpoint.
10. **Durable, then answered** (spec 6.5): an answer carrying a `seq`, a transition proof or a signed head goes out only once what the request committed is durable (synced, or committed synchronously to every replica that could be promoted). The account's service key keeps, apart from the restorable state, the newest head it signed (generation, `seq`, chain hash); for a serving account whose state is behind that head, or at that `seq` with another chain hash, the service answers every request with `503 unavailable` (its message saying a new generation is needed), signed with the account key and carrying no head, except the signer's enrollment (answered with the pending key of the next generation, 3.7), the `PUT /identity` that delivers the next generation naming that key (3.3) and an erasure (7.4.16), whose answer carries no head. An erasure's answer carries none of these, and still goes out only once the deletion it confirms is durable (7.4.16). A staged account acknowledges no app operation (the reference prototype: it checks the mark before step 5 and again before signing the answer, and only for serving accounts). A checkpoint (7.4.4) is a head at an earlier `seq` of the same chain, not a state behind the newest head: the service signs one, and drops chain stubs behind it, only while the account's state is at or past the key's newest head (the reference prototype: it checks the mark at step 4 before either).

**Trusted time** (spec 10.1). The service keeps its newest authenticated time sample, from the operator's choice of source, such as NTS-secured NTP or Roughtime, taken at least hourly, with the reading of its monotonic clock at that moment. Trusted time is the sample plus the monotonic time elapsed since; its uncertainty is the sample's own plus the elapsed time times the drift bound (`trusted_time.drift_ppm`, 100 ppm by default). There is trusted time while the sample is at most `trusted_time.max_sample_age_ms` old (24 hours) and the uncertainty at most 5 minutes.

- **Time base.** While the wall clock agrees with trusted time within 5 minutes, the time base is the wall clock; otherwise it is trusted time, and the service alerts its operator. Request timestamps are checked against the time base (7.1), and step 3 stamps it, never going back per identity. A wall-clock jump of more than 5 minutes either way therefore moves neither the service time nor the timestamp check. A smaller jump stays within the agreement, so it moves the time base, and with it the timestamp check, by up to 5 minutes; stamped time still never goes back. Service time keeps moving between samples.
- **Without trusted time** (no sample within the maximum age, or an uncertainty above 5 minutes), the service answers `503 unavailable` to exactly these requests, whose outcome depends on its time:
  - a batch with an `attempt`, or with a `server_time_in` condition (6.3);
  - a batch with an outcome that only an attempt's orphan age or its owner's certificate expiry allows: an outcome by an app other than the attempt's owner while the owner is current (6.8). A certificate's expiry can't be judged without trusted time, so "current" here means that the newest `identity.json` makes the owner current (3.8: listed, or renewed and still open) and that it is neither revoked nor departed;
  - an append, directory read or `PUT /peers` admitted only by an invite code, whose expiry is a time.

  Deletions at a deadline (9.1 sweeps) wait. Everything else is served as usual: reads, cursor moves, appends and `PUT /peers` admitted otherwise, record writes without a time condition, list and invite code changes, the owner's outcomes and `done` by evidence, outcomes for an attempt whose owner isn't current in the sense above or that came from uploads, deletes and removals, and revocation. Request timestamps, certificate expiry and rate windows are then checked against the time base, which is the wall clock, corrected by the last sample where they disagree by more than 5 minutes.
- `trusted_time.required` is on by default (9.2), as a production service has trusted time (spec 10.1). (The reference prototype: off, since it has no time source of its own; its tests turn it on where they need it and give it samples.)

### 7.4 Endpoints

| Call | Caller | Section |
|---|---|---|
| `POST /v1/enroll` | signer | 7.4.1 |
| `PUT /v1/{id}/identity` | signer | 7.4.2 |
| `POST /v1/{id}/inbox` | admitted app of another identity; own app, for the kinds its protocol sends between own apps | 7.4.3 |
| `GET /v1/{id}/feed` | own app | 7.4.4 |
| `PUT /v1/{id}/peers` | admitted app of another identity, for its own identity; own app, for a counterparty | 7.4.5 |
| `GET /v1/{id}/allow` | own app with `lists.read` | 7.4.6 |
| `POST /v1/{id}/connect` | app of another identity, where the policy allows it | 7.4.7 |
| `GET /v1/{id}/connect` | own app with `lists.read` | 7.4.7 |
| `DELETE /v1/{id}/connect/{pubky}` | own app with `conversation.add` | 7.4.7 |
| `POST /v1/{id}/ops` | own app, signer | 6.4 |
| `GET /v1/{id}/claims/{claim_key}` | own app with `claims.read` | 7.4.8 |
| `GET /v1/{id}/records/{key}`, `GET /v1/{id}/records` | own app | 7.4.9 |
| `GET /v1/{id}/directory` | own app, admitted app of another identity | 7.4.10 |
| `GET /v1/{id}/apps/{app_id}/keys` | that app | 7.4.11 |
| `POST /v1/{id}/apps/{app_id}/keys` | that app | 7.4.11 |
| `PUT /v1/{id}/push` | own app | 8.1 |
| `POST /v1/{id}/apps/{app_id}/leave` | that app | 7.4.12 |
| `GET /v1/{id}/apps` | signer | 7.4.12 |
| `POST /v1/{id}/apps/{app_id}/revoke` | signer | 7.4.12 |
| `POST /v1/{id}/freeze` | signer | 7.4.13 |
| `POST /v1/{id}/unfreeze` | signer, at the old service and at the next one | 7.4.13, 10.6 |
| `GET /v1/{id}/export` | signer, at a frozen account | 10.3 |
| `GET /v1/{id}/export/chunks/{chunk_id}` | signer, or the next service under the signer's export transfer, at a frozen account | 10.3 |
| `POST /v1/{id}/import` | signer, at a staged account | 10.4 |
| `PUT /v1/{id}/import/chunks/{chunk_id}` | signer, at a staged account | 10.4 |
| `POST /v1/{id}/import/activate` | signer, at a staged account | 10.5 |
| `POST /v1/{id}/recovery/admission` | signer | 7.4.14 |
| `POST /v1/{id}/recovery/upload` | own app | 7.4.14 |
| `GET /v1/{id}/identity` | anyone, unauthenticated | 7.4.15 |
| `POST /v1/{id}/erase` | signer | 7.4.16 |
| `PUT /v1/{id}/handover` | signer | 7.4.17 |
| `GET /v1/{id}/handover` | the hand-over's target app, the signer | 7.4.17 |

#### 7.4.1 `POST /v1/enroll`

- **Body:** `{ "enrollment": signed<Enrollment> }` (3.7). Signed by the identity key, without `Switch-App` (`403 permission_missing` otherwise).
- **Answer:** the enrollment answer of 3.7, signed with the key it names, without `Switch-Head`: a new or staged account serves no chain yet (7.3 step 7), and at a serving account the answer names a pending key (3.7), which has signed no head. The signer gets the first head with its next answer, such as the one to the `identity.json` delivery that makes the account serve (7.4.2).
- **Which key signs.** A new account's answer is signed with the key the service made for it; a staged account's, with that same key again; a serving account's, with its pending key for the next generation, not the key it serves under (3.7). The signer checks the answer with the key the answer names, whatever key it has pinned, and with the answer's `enrollment`, `identity`, `origin` and `nonce`. It pins a new or staged account's key from the answer. At a serving account it keeps its pin until the delivery naming the pending key is accepted (7.4.2).
- **Errors**, signed with the operator key at every account, new, staged or serving, since an enrollment is handled before the service acts for any account (7.3 step 2). No client can check them (7.1), so the signer takes none of them as the service's word: it changes nothing on one, and sends the same enrollment again or shows the failure, but for `409 conflict`, on which it enrolls anew (3.7). They are: `400` for a malformed body, an enrollment naming another identity or origin, a nonce that isn't 16 bytes, or an `identity_doc` that doesn't verify; `401 bad_signature` for a request or enrollment the identity didn't sign; `401 stale_timestamp`; `409 conflict` for an enrollment the service answered with a key a generation change has since retired (3.7).

#### 7.4.2 `PUT /v1/{id}/identity`

- **Body**: `{ "identity": signed<IdentityDoc>, "prev": b64(32) | null }`. `prev` is the document hash (2.2) of the version this one builds on, the newest the signer knows the service holds; `null` for the first delivery to an account that holds none.
- **Answer:** `{ "proofs": [the delivery's proof], "head" }`. The same document bytes again, whatever `prev` names, are a retry: they change nothing and answer with the original delivery's proof and the newest head, as a batch retry does (6.4 step 5), so a signer whose answer was lost still learns the service time at which its delivery was taken (3.8 Reductions). The service keeps that proof with the version, while it is the newest it holds. A version it didn't take by this call, the one it was enrolled or imported with, has none, and a retry of it answers `{ "proofs": [], "head" }`; a signer closes any reduction it owes before it enrolls a new service (3.8), so it never needs one.
- **Compare-and-swap** (spec 4.3): the service accepts a new version only if `prev` is the hash of the newest version it holds, but for the delivery that starts a provider loss in place, which needs only a higher version (3.3). Otherwise, and for a version that isn't higher or a lower generation, it answers `409 stale_identity` with `current: { "version", "generation", "hash", "identity" }`: the copy it holds, its document hash and the signed document, so the signer can republish that copy and build its next version on it. A `prev` at an account that holds nothing is `409 stale_identity` with `current: null`.
- **Then publish.** The signer publishes the document on the Homeserver only after this call succeeds (3.3).
- **Errors:** `403 permission_missing` for a caller that isn't the signer; `400` for a document that doesn't verify, too many apps, a wrong first document, or a new generation at an account the newest document already names, unless it names that account's pending key at the next generation (3.3); `409 stale_identity` as above; `409 conflict` with `current: { "proof_generations": [int] }` for a document that leaves out the service key of a generation a kept proof still names (3.3), or gives it a key those proofs don't verify with (3.3 "Service keys"), listing those generations, ascending, so the signer adds their keys and delivers again; at a staged account in a cooperative move, `409 conflict` while an uploaded head shows that the import doesn't extend the chain an app saw.
- A delivery that names this service and a generation with `recovery_from` = generation - 1, at an empty account, starts the recovery: the account takes the document's generation, and the new chain's first item is the `recovery` transition (6.5), at that generation, `seq` 1. So does one at a serving account that names its pending key (3.3, 3.7); the account starts afresh first.
- **Which key signs the answer.** A delivery that starts a new generation at a serving account, naming its pending key, is answered under the new generation: the response signature, the delivery's proof and the head are signed with that key, the account's service key from this delivery on, and the old key signs nothing more (3.3). A refusal of such a delivery starts no generation, so it is signed with the key the account served under, like any other answer. So the signer checks a `200` with the pending key its enrollment answer named, and pins that key once the `200` verifies; it checks any other status with the key it has pinned, and keeps that pin. While the account still serves the lost generation, between the enrollment that answered the pending key and that `200`, every answer of the account but the delivery's `200` and an enrollment's answer (7.4.1) is signed with the key it served under, `GET /apps` included: the signer keeps that key pinned for every call there, after a restore too (3.13), and takes no answer under any other key but one. An answer under the key the version names shows that version taken, by this install or another, or the account one the enrollment made, which serves no lost generation: so when an answer other than a `200` fails under the pinned key, the signer reads `GET /apps` once under the version's key, and an answer that key signs ends the earlier key's pin, the delivery then sent again under the version's key alone. An answer neither key signs may come from that service under a key an earlier declaration's enrollment answered there, once it took that declaration's version: the signer reads `GET /apps` under each such key too, as spec 12.6 step 1 says, whatever the refusal. A `200` of the delivery under the key the account served under is not the new generation's, and an answer under a third key is not the service's. Once the `200` verifies, the pending key is the only one. The same document again is a retry, answered under the key it named. A first delivery to a staged account is answered with the account's own key, the one the signer pinned from the enrollment answer (7.4.1).
- Vectors: `http.json` "signer: identity.json delivery" has this body for the account's first delivery, `prev` `null`: alice's version 1, since she enrolled without a document (3.3). `chain.json` chains it at seq 1, and her version 3 at seq 2. "signer: identity.json at generation 2 that leaves out generation 1's service key" is a key change in place whose version 4 names her pending key but not the key of generation 1, which the proofs of `chain.json`'s records name; its answer, "signer: 409 conflict, a needed service key left out", carries `current: { "proof_generations": [1] }`. The pending key comes from the seed label `service/alice/pending`, by the rule of `keys.json` (the reference prototype: the generator replays the delivery on its service, whose keys are drawn at random, and takes the body from its answer).
- An app dropped from `apps` stops being current at once, which may release inbox entries (spec 6.3).

#### 7.4.3 `POST /v1/{id}/inbox`

- **Query:** `apps_version=<int>`, required: the recipient's `apps_version` (7.4.10) the envelope was sealed for. An append without it is `400 bad_request`.
- **Body:** the envelope bytes.
- **Answer:** `{ "entry_id": b64(16), "accepted_at": time, "directory_version": int, "known_version": int | null }`.
- **Checks, in order:**
  1. Retry by content: an envelope the service still holds from the same sender identity returns the stored original answer, before any other check.
  2. For an app of another identity: admission (spec 7; `403 not_admitted`, or `503 staged` while a recovering account restores its allowlist), then the listing of the app with its certificate in the service's copy of its identity's `identity.json` (`409 identity_needed`, or `403 not_current` when its renewal has closed). An app that copy lists as removed is admitted only by an invite code and then gets `409 identity_needed` as if no copy were held, like a stranger (7.2).
  3. Size and header (4.4).
  4. Rate limits per sender identity and per sender app, with a tighter one per identity when `notify` is set (`429 rate_limited`); a hit on the per-app limit flags the sender identity like any other (7.4.6).
  5. Targets: every kid must be the current receive key of a current app, and with `apps_version`, every app added since must be among the targets; else `409 stale_key` (7.6).
  6. The inbox quota, then the sender's share of it (`429 quota_exceeded`, `current.limit` `inbox` or `sender_share`; Section 9). One sender identity's unread entries, envelope and overhead, hold at most `sender_share_percent` of `quota_bytes`; beyond it only that sender is refused.
  7. An invite code that admitted the sender is used, atomically with the append, and creates a conversation entry written by the service (the `conversation.add` transition, 6.5).
- An own app may append to its own inbox only the kinds its protocol sends between own apps; recipients drop other kinds from an own app (spec 7). Own apps aren't rate-limited per app.
- **After a revocation** (spec 12.2): the revoked app's invite codes are withdrawn, and a switch that received the sender identity's newer `identity.json` (3.3) refuses the revoked app as it refuses a stranger (7.2). Own apps treat every chain item a removed app wrote after its `distrust_from` as doubtful: no automatic attempt relies on it.

#### 7.4.4 `GET /v1/{id}/feed`

- **Query:**

  | Parameter | Default | Meaning |
  |---|---|---|
  | `after` | the start | a position `<generation>:<seq>`; the page starts after it. A position from another sequence (a lost generation) reads from the start of the current one; after a cooperative move the previous generation's positions stay valid |
  | `limit` | 100 | items per page, 1 to 500 |
  | `wait` | 0 | long-poll seconds, at most 25 (below) |

- **Answer:**

  | Field | Type | Notes |
  |---|---|---|
  | `items` | `array<feed item>` | 7.5 |
  | `next` | position | `scanned_through` as a position, to pass as the next `after` |
  | `scanned_through` | int | the last `seq` this page examined, shown or not |
  | `more` | bool | whether items follow `scanned_through` |
  | `cursor` | int | the `seq` of the caller's cursor the service holds, 0 before its first move, as an export's `cursor` (10.3); the caller's own, never another app's (spec 8.3) |
  | `head` | signed head | the newest one, also in `Switch-Head` |
  | `checkpoint` | signed head | the service's latest checkpoint (below); absent when none |
  | `freeze` | `signed<Freeze>` | the freeze of a frozen account (spec 12.5 step 2), absent otherwise; an app that sees it treats its writes as `410 moved` would |

- **Paging:** a page ends after `limit` items, after examining 1000 positions, or before an item that would take the bytes of its `items` past `max_page_bytes`, 8 MiB (8,388,608 bytes, 9.2), whichever comes first, but never inside a batch: it runs on to the batch's last item (103). For the byte budget a batch's items count together: a page ends before a batch that wouldn't fit whole, and a batch always fits, since its items take under 5 MiB. The first item or batch of a page is shown whatever its size, so a page always holds at least one. A page the budget ends tells the reader so exactly as one `limit` ends: `more` is set, and `next` and `scanned_through` name the last position it covered. An app always moves its position to `next`, so a page of hidden items still makes progress.
- **Long-poll:** with `wait` above 0, the service answers at once when the page has an item or `more` is set; otherwise it waits until the account changes or `wait` seconds pass, and then answers with the page as it is then, possibly empty. A foreground app reads again after each answer. A read held while the account's service key changes, as at a recovery in place (spec 12.6 step 1), is answered `503 unavailable` with the operator key and no head, since the key it was read under signs nothing more; the app, which can't check it (7.1), learns the new key from its own `identity.json` (spec 12.6 step 1) and reads from the start of the new sequence. An app may hold more than one read at a time; each is a read like any other, and a read whose connection closes ends with nothing changed.
- **The held cursor** (spec 8.3): `cursor` is read from the page's own snapshot, so it is the cursor the service held at the page's head; a long-poll answers with the cursor as it is when it answers. The response signature covers it with the rest of the body (7.1). It is a `seq`, which the app compares with its committed read position, or at a read other than a restore's the furthest position it committed or sent (spec 8.3), and only for a position of the current sequence: positions of a generation a cooperative move or a key change in place continued compare by their `seq`, and one at or before the generation the newest `identity.json`'s `recovery_from` names, from a sequence a provider loss ended, compares with nothing. Readers ignore unknown members of an answer (1.1), so a client of an earlier version reads the page as before, and a client takes a page without `cursor`, from a service of an earlier version, as no report; the member needs no version change.
- **Start of a new app:** the first `seq` of the batch that registered its first receive key (spec 8.3). The app anchors its chain view on that batch's answer: the proof of the batch's first operation carries its stub (6.5), whose envelope names the previous chain hash (6.6), and the app takes that hash as its verified chain at the `seq` before the batch. Its first feed read starts there, and its stubs must extend that hash. A new app doesn't start in reconcile mode: it has verified nothing earlier and holds no attempt of its own, so it starts from the shared state it reads (spec 8.3), anchored on what the service shows it (spec 10.1).
- **Cursor moves** (spec 8.2): an app may defer a cursor move that applies nothing and send it with its next batch, for at most a few seconds while it runs, and sends a deferred move before it stops reading (for example when a phone app goes to the background). (The reference prototype: at most `cursor_defer_ms`, 2 s, and `suspend()` sends the move.)
- **Passing own writes**: every transition proof carries its operation's chain stub (6.5). When the `seq` of a write the app made directly follows its read position, and the stub extends the chain the app verified, the app may check the stub as it checks feed stubs and move its read position past it without reading the feed; with anything in between, or a stub that doesn't extend the chain, it reads the feed as before.
- **Checkpoints** (spec 8.3): the service may drop chain stubs that are older than a checkpoint, a signed head (6.7) it keeps for that purpose, and that the cursor of every current app has passed or that are at least 30 days old in service time (`cursor_hold_ms`), by the `server_time` of their envelopes (6.6). It drops them oldest first, so the stubs it keeps run unbroken from the oldest one to the head, and it keeps the `seq` and chain hash of the newest stub it dropped (9.1), which an export's checkpoint signs (10.2). Reads alone hold no stub back, only cursors, and only for 30 days. The current apps are those the held `identity.json` lists, listed or in an open renewal and neither revoked nor departed. One not registered here yet holds no stub, since its first read starts at its registration (below); one registered whose cursor hasn't moved holds those from its registration, for 30 days at most (the reference prototype: every stub, since it keeps no registration `seq`). A read from a position behind the oldest stub the service keeps shows no stub before that one, and its page carries the checkpoint. So the stubs from an app's verified position are kept while the chain item there is less than 30 days old, since every later stub is younger, and an app that reads without moving its cursor, or stays more than 30 days behind, doesn't pin chain retention. Feed pages carry the latest checkpoint. An app checks its signature with the account's service key, and then:
  - behind the checkpoint the app accepted before from the same service, it can't be matched, since the app keeps no chain hashes behind that one: it is a rollback (spec 10.1). After a cooperative move the app compares N's checkpoints only with those it accepted from N, since N's first is the export's (10.2), which may lie behind one it accepted from O;
  - at or behind its verified position, and not behind a checkpoint it accepted from an earlier service, the checkpoint must match the chain hash the app verified at that `seq`, else it is a rollback. Behind that one the app keeps no chain hash, so the checkpoint can't be matched and isn't compared. That holds for N's first checkpoint, the export's, and for any later one N signs behind the one the app accepted from O;
  - beyond it, the app accepts it only once the page's stubs extend its verified chain through the checkpoint's `seq` and the checkpoint matches the chain hash there (a mismatch is a rollback); while they extend it and `more` is set before the checkpoint, the checkpoint waits for the next page;
  - beyond it without those stubs (the first stub after its position doesn't link to its chain, or the page reaches the checkpoint's position with none), it depends on the app. For an app whose verified chain item is less than 30 days old, by the `server_time` of its envelope on the app's clock less the 5-minute clock tolerance (the reference prototype: `STUBS_KEPT_FOR_MS`), that wasn't restored since, and whose devices don't share its cursor, the service rule above keeps the stubs from its position, so their absence is evidence of a rollback. How often the app reads doesn't matter. After a restore the service may hold the app's cursor past the backup's position, so the rule holds again only once the service holds a cursor the restored app moved and the app has read a page after that. The same holds for an app more than 30 days behind, and not restored since, that holds a signed head or a transition proof of its own write at a `seq` in (its verified position, the checkpoint], from an answer whose `Switch-Server-Time` is less than 30 days old by the same measure: the service keeps that item's stub behind the app's cursor, so its absence is a rollback, not a gap to continue over. Neither rule holds for an app whose devices share its cursor, since another device may have moved it past those stubs, which then went honestly: a device of such an app behind a checkpoint without the stubs continues from it in reconcile mode, unless the app syncs its devices' chain views. Such an app gives that evidence up: a dishonest service can drop or hide the recent chain between a device's position and a checkpoint it signs, and the device only reconciles. What it keeps is a page's head behind the newest head it saw, a checkpoint behind one it accepted, a checkpoint that doesn't match the chain hash it verified there, and stubs after the checkpoint that don't extend it: each is a rollback for it too. (The reference prototype: up to 256 such marks, `ChainView::note_held`.) For an app more than 30 days behind, or restored, the stubs may otherwise be gone honestly, and the app has no evidence of continuity, since the checkpoint's signer is the service being checked. It enters "continuity unverified", which is reconcile mode (spec 12.4): no automatic attempts, every obligation checked against the SETTLED proofs and claims it keeps before attempting, shown to the user. Only as that recovery decision does it continue from the checkpoint's chain hash, with no time for its verified item until the next stub; reconciliation ends the state, but doesn't prove the missing chain's continuity. A new app doesn't take this path: its registration anchors it (Start of a new app, above).

  Behind the checkpoint an app keeps no chain hashes, and heads at or before it are no longer compared; it drops claim evidence behind it as spec 12.6 allows (10.6). Batch IDs don't follow checkpoints: the app compares each for 30 days of the chain, by its stubs' `server_time`, and then forgets it, whatever checkpoints it sees (6.6). How often the service signs a checkpoint, and at which item, is the operator's choice (spec 8.3), since apps verify from their cursor whatever the checkpoint: whenever the stubs it could drop would free a useful amount. But never inside a batch: the service signs a checkpoint only at a batch's last chain item or at an item of no batch, and drops stubs only up to such an item, so the stubs it keeps, and an export's `chain` parts (10.2), never begin with part of a batch, which apps and the activation would refuse as a partial batch (6.6, 10.5). Where a cursor, which may lie inside a batch, or the 30-day rule would let it go further, it stops at the item before that batch. So a checkpoint may lie ahead of stubs the service still keeps, and an export carries those too (10.2). By default the service signs one once `checkpoint_behind` chain items, 1,000 (9.2), may go, at the newest of them, and drops every stub behind it. With `checkpoint_at_head`, off by default, it signs one at the newest chain item once `checkpoint_behind` items were added since the last, and drops behind it only what the rule above lets go. (The reference prototype keeps these defaults.) After a cooperative move N signs the export's checkpoint again with its own key (10.5).
- **Lagging apps** (spec 6.3): an app whose unread entries exceed its share of the inbox quota (the quota divided among current apps) is marked lagging (7.4.12), and entries no longer wait for it, but only while another current app is reading. A current app is reading when it isn't marked and its unread entries are within its share. When no current app is reading, none is marked, marks set before end, and entries wait as before, so the quota refuses senders; so no state has every current app marked, and a single current app is never marked, since no other app reads while it lags. Marks are set, with trusted time only, at the requests that bring the pressure: an append to the account's inbox, and an `identity.json` delivery, a revocation or a leave that changes the set of current apps (and with it the shares). A delivery that leaves the set of current apps as it was judges no marks. At an append the marks are judged before its quota check, so an append that finds a reader back frees what a lagging app held, and then passes or is refused on what is left. At a revocation, a leave or a delivery, entries wait for every current target until the marks are judged again for the new set of current apps, in the same request, so a mark set for the old shares deletes nothing. The mark ends when the app reads a feed page, and when it departs or is revoked, and the app's own reads and cursor moves never set it, so an app working through its backlog is marked again only if new entries arrive while it is still over its share. A request without trusted time neither sets marks nor writes `missed` items, and the entries it would delete wait for lagging targets as for any other.
- **Unreadable items** (spec 8.2): at a revocation, a leave, or an `identity.json` delivery after which an app is no longer current, in that request and after its chain item, each entry left with no current target becomes an `unreadable` item at a new `seq`. Its envelope is deleted; it keeps the entry's `entry_id`, `sender` and `accepted_at`. It waits for every current app, lagging ones included (9.1).
- **`missed` items:** when the service deletes an entry a lagging target hasn't read, it records the miss in a `missed` item for that app, which takes a new `seq` like an unreadable entry, so the app's cursor reaches it whatever its position. A later miss replaces an item the app hasn't passed with one covering both. On a `missed` item the app asks the counterparties of its unfinished records to re-send what their inboxes accepted from the later of the item's `accepted_from` and its cursor's time, less the clock tolerance, by its protocol's re-send, and lists its collections again (7.4.9), to check what it holds after the gap; no key it hasn't read past the delete of is forgotten meanwhile (9.1). It owes that listing from the commit that passes the item and makes it before it hands any entry to its protocol, a stored one included, so no entry is judged on records the listing would change. An item whose times don't parse asks for no re-send, but still owes the listing.
- **Errors:** `403 permission_missing` for callers that aren't own apps; `400` for a malformed `after`.

Example page (alice's `wallet` after `1:4`: bob's entry at `seq` 5; the record's create at `seq` 6 as its stub, since the attempt batch's write at `seq` 8 supersedes it (7.5); the attempt batch's two operations; and a service transition; long values cut short):

```json
{
  "items": [
    {
      "type": "entry",
      "seq": 5,
      "entry_id": "YfEG-ssKoaUNx40eATBsyg",
      "sender": "43xz73bjzs8c84sw4sigu5bm3x93mj17ywjy1oa3dbnriiymcw4o",
      "cert": {
        "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLmFw...",
        "sig": "ohhwX8z64fjy4uk6QOqgDKOElHAm8HVBJgrAZzCJrydTkvwG6wWNMA2r5suhSQz4NpA3xcm47H73sCUPUC1uAQ"
      },
      "accepted_at": "2026-01-01T00:00:02.000Z",
      "envelope": "UFNXMQEBAQFDyTFC9V6clYCvyk8-AtxlrRQYynxH..."
    },
    {
      "type": "stub",
      "seq": 6,
      "stub": {
        "envelope": "eyJjaGFpbl92ZXJzaW9uIjoxLCJnZW5lcmF0aW9u...",
        "chain_hash": "jjMkxY3N9g4KTZ5l0nIgjk9pCBnf0fLun1aMA8OWYPw"
      }
    },
    {
      "type": "chain",
      "seq": 7,
      "stub": {
        "envelope": "eyJjaGFpbl92ZXJzaW9uIjoxLCJnZW5lcmF0aW9u...",
        "chain_hash": "39Z4TXAiQunrwwnx_BUO46H96vxegqPZNl261qJJ8Qo"
      },
      "item_type": "op",
      "item": {
        "body": "eyJpZGVudGl0eSI6Ijh5M3F5NGc5cTd5OW93bmQx...",
        "sig": "uyEJk2QGiGpoJ9FO8iyrmaJoPu175snD9GvnGQf4nPP5NvbpN5_FLYq7tG_-fxJghSV_1qpB9ISWSTk6yklqCA"
      },
      "proof": {
        "body": "eyJjaGFpbiI6eyJlbnZlbG9wZSI6ImV5SmphR0Zw...",
        "sig": "Z3_U3AsxoDiMQTgRCZ8fF9E_P0Ex2tL8skLWlSRytVy7NoyzEuWBFXlvnWZ8pOe_v4IOVclvBlEPZkT_Q61jBw"
      }
    },
    {
      "type": "chain",
      "seq": 8,
      "stub": {
        "envelope": "eyJjaGFpbl92ZXJzaW9uIjoxLCJnZW5lcmF0aW9u...",
        "chain_hash": "L0v5_hmltlaZgDMwk4pDQeO0KqqDwXeRvtBGVY5z0Q4"
      },
      "item_type": "op",
      "item": {
        "body": "eyJpZGVudGl0eSI6Ijh5M3F5NGc5cTd5OW93bmQx...",
        "sig": "MJnPcjmxKygWKsQud4bULoc8pwfT6ISIr1kM6O_O4H_PnGkhcvoR5Wl2_sEB20B3-XEkueQS-p-ZKqi58HHRBg"
      },
      "proof": {
        "body": "eyJjaGFpbiI6eyJlbnZlbG9wZSI6ImV5SmphR0Zw...",
        "sig": "svZhsiF2IRrW30xJK0hM9m3784FyWv9LoTeA8gBblYIH6CHdzoHoWgVJU99bdzE62W6eBccnxjyQCnlZMWmACg"
      }
    },
    {
      "type": "chain",
      "seq": 9,
      "stub": {
        "envelope": "eyJjaGFpbl92ZXJzaW9uIjoxLCJnZW5lcmF0aW9u...",
        "chain_hash": "muYjBhuz6UI1RX8upIrIIMIBpI_3gRvfhwQtrDldImA"
      },
      "item_type": "service",
      "item": {
        "body": "eyJhcHBfaWQiOiJjMXV0YWg5aml0anM0M2V0emRr...",
        "sig": "vxSfwR3sT3q2yyGXVYV8AEEhDSbC84WzTRlTTBQc81vai8jiEOTcDyxc0SrQ3dPNbMuHSVAAIow1BC_FJQ7BBw"
      }
    }
  ],
  "next": "1:9",
  "scanned_through": 9,
  "more": false,
  "cursor": 0,
  "head": {
    "chain_version": 1,
    "generation": 1,
    "seq": 9,
    "chain_hash": "muYjBhuz6UI1RX8upIrIIMIBpI_3gRvfhwQtrDldImA",
    "sig": "b23xHVPZCR7bOgQ96HIIVCo2SbATzUQfj0rxYuBdkO-b79ebvDt9YOOwHTf0tNLlS-4YLxu2lJknsQCZIwO2BA"
  }
}
```

#### 7.4.5 `PUT /v1/{id}/peers`

- **Body:** a `signed<IdentityDoc>` of another identity.
- **Answer:** `{ "version": int }`, the version the service now holds, and `known_version` for apps of other identities.
- **Rules:** an app of another identity delivers only its own identity's document (`403 not_admitted` otherwise), and must be admitted, or asking to connect where the policy allows it (`403 not_admitted`; `503 staged` during a recovery's staged admission). An own app delivers counterparties' documents, never its own identity's (`400`). The service keeps one copy per identity per account, the highest version: a delivery at the version it holds is judged first, by the next bullet, whatever its generation; otherwise a lower version or generation is `409 stale_identity` with `current: { "version" }`.
- **The held version again** (3.3): a delivery at the version the service holds is a no-op only with the held copy's body bytes, whatever the signature: the service keeps its copy and answers its version. Another body at that version is equivocation. The service keeps its copy and answers `409 stale_identity` with `current: { "version", "identity" }`, the held signed document. The sender then holds both documents and acts as 3.3 says: it makes no attempt that relies on that identity, or none at all when the document is its own identity's, and alerts the user. This holds for an app of another identity delivering its own identity's document and for an own app delivering a counterparty's.
- **Limits** (9.4): a delivery admitted by an invite code counts against that code's rate, shared with directory reads admitted by it (`invite_reads_per_min`); one admitted only because connect requests are on counts against the account's stranger rate (`stranger_per_min`), shared with connect requests. Beyond either, `429 rate_limited`.
- **Floors** (9.1): when the service drops the copy of an admitted identity (a contact or conversation) beyond `max_peers`, it keeps that copy's version, generation and body hash. Until a copy of that identity is held again, a delivery below that version or generation, or another body at that version, is `409 stale_identity` naming the floor's version, `current: { "version" }`: the service keeps the floor's hash, not the document. That answer carries no document, so it shows the sender nothing to compare and proves nothing: the sender doesn't treat it as equivocation, and keeps acting on the documents it holds.
- **Denied senders** (spec 7): where connect requests are on, a denied sender's delivery is answered and kept exactly like a stranger's (a peer copy admits nothing), so its connect request is answered alike too (7.4.7); where they are off, both get `403 not_admitted`.
- **From a removed app** (7.2): an app that the held copy or the delivered document lists in `removed` is answered like a stranger. Admitted only by an invite code or where the policy allows connect requests (`403 not_admitted` otherwise), it gets `{ "version": v, "known_version": v }` with v the version it delivered, whatever the service holds. The service still keeps a delivered document that is newer than the copy it holds, or, holding none, one it would keep from a stranger; it never goes back. This answer compares no bodies: another body at the version held gets it too, and isn't kept.
- Vectors: `http.json` "app of another identity: identity.json at the version the switch holds, the same body" is alice's wallet delivering her version 3 (`documents.json` "alice identity.json") to bob's switch, which holds it, signed for bob's origin; its answer, "app of another identity: the version held again with the same body, a no-op", is `{"known_version":3,"version":3}`, signed with bob's service key. "..., another body" delivers her version 3 with connect requests on, signed with her key; its answer, "app of another identity: 409 stale_identity, another body at the version held, current the held copy", carries `current: { "version": 3, "identity" }` with the version 3 held, and no `known_version` (7.1).

#### 7.4.6 `GET /v1/{id}/allow`

- **Answer:**

  | Field | Type | Notes |
  |---|---|---|
  | `contacts` | `array<pubky>` | |
  | `conversations` | `array<object>` | `{ "pubky", "written_by": app-id or "service", "code_hash"?, "context"?, "at": time, "last_used"?: time }`. `last_used` is the service time of the last append the entry admitted, absent until one; apps with `lists.manage` prune idle entries by it (spec 7 "Pruning") |
  | `deny` | `array<pubky>` | |
  | `flagged` | `array<object>` | `{ "pubky", "hits": int }`: senders that hit rate limits at least 3 times (spec 7) |
  | `invite_codes` | `array<object>` | the live invite codes, `{ "code_hash", "expires_at": time, "max_uses": int, "uses": int, "written_by": app-id }`, without their contexts, so an app can compare them with the codes it registered after a move (spec 12.5 step 4) |

#### 7.4.7 Connect requests

- **`POST /v1/{id}/connect`** (an app of another identity), empty body. Answer `{ "pending": true, "known_version" }`, also to a denied sender, whose request isn't kept, so the answer doesn't reveal the deny list (spec 7). The service judges it in this order, answering with the first that holds:
  1. the caller's own checks (7.2);
  2. a frozen account: `410 moved` (7.3);
  3. while a recovery stages admission, every sender: `503 staged`, as at `PUT /peers` (spec 12.6 step 2);
  4. the policy turns connect requests off: `403 not_admitted`;
  5. the service's copy of the sender's `identity.json` doesn't list the app with its certificate, or a renewal of it still open: `409 identity_needed`, also to an app the held copy lists as removed, answered like a stranger with no copy held; a renewal of it that has closed is `403 not_current` (7.2);
  6. `429 rate_limited` past `connect_per_min` for the sender, then past `stranger_per_min` for the account, all strangers together, their `PUT /peers` deliveries included;
  7. a sender already pending, or one a contact or a conversation entry admits, is answered `pending`, full or not; nothing is kept for the admitted one, since an admission answers a request, so the two never hold together. A sender holding an unused invite code isn't on the lists yet and asks as a stranger;
  8. `429 quota_exceeded` with `current.limit` `connect_requests` when `max_pending` requests are pending (the policy's, at most `max_connect_pending`; 0 refuses every new sender), checked before the deny list, so a denied sender gets this same answer while the list is full;
  9. a denied sender is answered `pending` and nothing is kept;
  10. the request is kept, with the service time of its commit as `at`.

  The requests already pending stay; none is dropped to make room, and a cap lowered below the number pending drops none either: the list stays full until the user clears it. Only the `connect_per_min` refusal of step 6 counts a hit for the sender's flag (9.4), as an append's rate refusals do, each of them the sender's own; the `stranger_per_min` refusal belongs to the whole account, so a flood of fresh identities flags nobody else, and a denied sender answered `pending` counts none. With `policy.connect_requests.push`, the current apps holding `lists.read` get a push, queued like an entry's webhooks (8.2), at most once per app in 60 seconds of service time, however many requests arrive.
- **Answering:** a request goes in the transaction of whatever answers it: an `allow.put` of either kind for its sender, the conversation entry the service writes at an invite code's first admitted append from it (7.4.3), a `deny.put` for it, a contact or deny list entry for it that a recovery upload's list merge writes (7.4.14), or `DELETE /connect/{pubky}`. With the policy turned off, `POST` is refused, but the requests pending stay, `GET` and `DELETE` keep serving them and these answers still remove them; turned on again, the policy shows them. Pending requests don't outlive a provider loss: the account starts afresh (spec 12.6 step 1), at a recovery in place too, and senders ask again once admission is no longer staged.
- **`GET /v1/{id}/connect`** (own app with `lists.read`). Answer `{ "requests": [ { "pubky", "at": time } ], "max_pending": int, "full": bool }`: the requests oldest first, the cap that applies, and whether the list is full, so the app can offer the user to clear it or block senders.
- **`DELETE /v1/{id}/connect/{pubky}`** (own app with `conversation.add`). Answer `{ "declined": pubky }`; `404` when no request is pending from it.

#### 7.4.8 `GET /v1/{id}/claims/{claim_key}`

- **Answer:** `{ "claim": claim view (7.8), "entries": [ { "step": int, "seq": int, "op": signed operation, "proof": transition proof } ] }`, an entry's `step` being the claim's step before it, its operation's `expected_step`. A tombstone has no entries. A claim rebuilt from uploads after a provider loss (7.4.14) lists the entries written at the service, before its rebuild and after it: an upload's change is no entry, so their `step`s skip the one each upload took. `404` when the service holds nothing for the claim key.
- **Readers** check the entries as any operation they read (6.2, 6.5): each is a `claim` operation of this claim key at its `step`, signed by its writer where the reader knows the writer's certificate, and its proof names it, with `step` one more. Each proof is checked with the service key of its own generation, the one its stub names: the current key, or the key `identity.json` lists for an earlier generation in `service_keys` (3.3). A proof of the current generation that doesn't verify is misbehaviour. A proof of an earlier generation that can't be checked, because no key is listed for it or it doesn't verify with the listed one, counts as no evidence: the reader takes nothing from it, neither a state nor a time, and judges the entry by its signed operation and the claim view alone. The claim's `step` is one more than the last entry's, or later on a claim rebuilt from uploads after a provider loss (7.4.14), whose upload steps have no entry: a reader takes a later `step` only on a claim whose view is `rebuilt`, for an identity whose `identity.json` carries `recovery_from`, which it keeps from then on (10.5). A signed answer that fails these checks is misbehaviour (spec 10.1).

#### 7.4.9 `GET /v1/{id}/records/{key}` and `GET /v1/{id}/records`

- A **record view**:

  | Field | Type | Notes |
  |---|---|---|
  | `key` | `b64(32)` | |
  | `collection` | `b64(32)` | the collection ID |
  | `read_scope`, `write_scopes` | | the policy |
  | `generation`, `version` | int | the current version |
  | `seq` | int | the write's `seq`; for a record taken from a recovery upload, the `upload` transition's (7.4.14) |
  | `deleted` | bool | the current write is a delete |
  | `writer` | app-id | |
  | `op` | signed operation | the `record.put` that wrote the current version, with its sealed value |
  | `divergent` | bool | uploads after a provider loss conflict with it (spec 12.6) |
  | `proof` | transition proof | the proof that gives this version and dates the write (spec 10.3), kept with the record for as long as this write is current, whatever its batch's proof retention (9.1), on every record view: `GET /records/{key}`, list pages and a `409`'s `record_view`. After a cooperative move or a key change it may be an earlier generation's proof, which N carried over (10.3). Absent for a record taken from a recovery upload (7.4.14) |
  | `cert` | `signed<AppCert>` | the writer's certificate the service checked the current write against, kept with the record (for an upload, the certificate it came with, 7.4.14); for a record written before the service kept it, the one the record the service holds for `writer` carries. A renewal or revocation later doesn't change it. Readers check the write with it (6.2 Accepting a write): an earlier certificate in `renewed` counts for a write `proof` dates before its `until`, and for none that nothing dates (step 4), so an app that reads later still takes the writer's earlier writes under a scope a renewal dropped, and no write after the cutoff |

- **`GET /records/{key}`** needs the record's `read_scope`, which a certificate holding its name covers for a sub-scope (3.1) (`403 permission_missing`); `404` for an unknown key. A deleted record is returned with `deleted: true`.
- **`GET /records?collection=<collection ID>&after=<key>&limit=<n>`**: the current records of the collection the caller may read, deleted ones left out, ordered by the base64url text of their keys compared as ASCII. `after` is exclusive; `limit` is 1 to 1000, default 1000. A page also ends before a record view that would take the bytes of its `records` past `max_page_bytes`, 8 MiB (9.2); its first record view is shown whatever its size, so a page with records to show holds at least one. Answer `{ "records": [record view], "seq": int, "next": key | null }`: `seq` is the newest `seq` when the page was read; `next` is the last key of a page that has more after it, whether `limit` or the byte budget ended it, to pass as `after`. `collection` is required (`400`).
- An app catching up lists every collection it may read, then follows the feed from its starting point; a record write it then sees applies only if it is newer (spec 8.3). An app that was lagging, or that finds a `missed` item, lists again (7.4.4).
- A forgotten key (6.2) is `404`, like a key that never existed.
- **Readers** take nothing from a record view on trust: the writer, the version, `deleted` and the content come from the checks of 6.2 (Accepting a write). A view without `proof`, or with an earlier service's, gives an unauthenticated version. The `409` answer's `record_view` (6.2) is a record view too, with `cert`.

#### 7.4.10 `GET /v1/{id}/directory`

- **Callers:** own apps, and apps of other identities admitted as in spec 7, while admission is staged after a provider loss one it can't otherwise admit getting `503 staged`, as at the inbox (7.4.14); an invite code admits a read without using it, and reads with one code are rate-limited per code (the reference prototype: 30 a minute, `429 rate_limited` beyond). An app that the service's copy of its identity's `identity.json` lists as removed is admitted only by an invite code, like a stranger (7.2).
- **Answer:**

  | Field | Type | Notes |
  |---|---|---|
  | `identity` | `signed<IdentityDoc>` | the newest one the service holds |
  | `apps` | `array<object>` | the current apps: `{ "app_id", "record": signed<AppRecord>, "receive_key": signed<ReceiveKeyRecord> \| null }` |
  | `directory_version` | int | changes whenever the directory changes; reveals no `seq` |
  | `apps_version` | int | changes only when an app becomes reachable (current, with a receive key) or stops being reachable |

  Apps of other identities also get `known_version`. `404` before the account holds an `identity.json`.
- **The versions are the account's, not a generation's.** `directory_version` and `apps_version` go on counting across a recovery in place (3.3) and never restart for an account that isn't erased, so a value a sender holds from before the loss is never met again for another set of apps (7.4.3 step 5).
- **Each App ID once:** `apps` names each App ID at most once. A reader refuses a directory that repeats one: it uses none of it, and reads again later.
- **Two copies of `identity.json`:** a reader holding both this copy and the Homeserver's uses the one with the higher `version`; two copies with one `version` and different body bytes are equivocation (3.3).
- **Records expire** as their protocols say (3.2).

Example (bob's `shop` reading alice's directory; signed documents cut short):

```json
{
  "apps": [
    {
      "app_id": "w8amtmn13m6p5bwnmj9wejbq4c",
      "receive_key": {
        "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLnJl...",
        "sig": "2v-AMIqAxitgORsPtoQGTK8uaVwNV_F0zs6A-5a3Ad787xX2Lpghv9ICS39ofJT5_q5ticrDWj0mKXn7vkl2Bw"
      },
      "record": {
        "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLmFw...",
        "sig": "soHnAkpU7U2ovHwh3rpcP-UlAgRUZFE0SOWUwzbrcoWMIYkueFEF0uL1L2P7uViYpyru26Lkipx-i1t02MneCQ"
      }
    },
    {
      "app_id": "c1utah9jitjs43etzdkj6cqdwr",
      "receive_key": {
        "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLnJl...",
        "sig": "EPbFVAY6CLyzPBnizLl9BzSadKS-N5yCwxRlWdov679J_-DMa6uls-bRqhFf95p-k0ML8hIhocoqK_7rAlbcCg"
      },
      "record": {
        "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLmFw...",
        "sig": "M-2HJw3X_8STEphe67IcgEjAcSQCDo6xzoZn-4heZF2NWsRkpRTxgNZ1hINObcUFo39gZ6bFX4ZkGTxr1BDxCA"
      }
    },
    {
      "app_id": "f4dtxinwdkb55gdwksph85m18w",
      "receive_key": {
        "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLnJl...",
        "sig": "mu0brcgLPTdH7gwX7gmGugeUJU8ioD4wQNZ-TOWbBa35HwRVuI8hk2ZP39GH3JxAXJmreIFkGCKq-b3J0szpBA"
      },
      "record": {
        "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLmFw...",
        "sig": "cZqYi_BOCmqHIY80XwzbE2L5DPdsie1e5Zv6Il2EvKhavdUXmup0lG01pmVdc4Tap7I-WaNL_DXmLDbQQbRbAg"
      }
    }
  ],
  "apps_version": 4,
  "directory_version": 7,
  "identity": {
    "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLmlk...",
    "sig": "ysIV9UOQnZRttQbBzDKXLUVCRTBLWEE4V7un_LPwFGkK9M4awl2lNkZPt4Wl5t9mCCYhZczlBxFCAmgovYX2Aw"
  },
  "known_version": 1
}
```

#### 7.4.11 `GET` and `POST /v1/{id}/apps/{app_id}/keys`

- **`GET`:** only that app (`403 permission_missing`). Answer `{ "bundles": [ { "bundle": key bundle (3.5), "seq": int, "first_epoch": int, "last_epoch": int } ] }`: every part the service stores for the app, ordered by `first_epoch`, never overlapping; `seq` is that of the part's `key_bundle.put`. `404` when the service holds none. The app opens every part and merges the keys, by the rules of 3.5 "Reading": it refuses an answer whose parts are out of order or overlap; it skips a part that doesn't verify or open, whose plaintext range isn't the range it names in the clear, that holds a key after the next data epoch, whose naming key differs from an earlier part's, that names a certificate other than its own or a listed renewal of it, or whose keys aren't exactly those of that certificate's keyed scopes over its range (3.5), and the others still count. A key that no part it takes holds shows as lacking afterwards, which leads to `POST`.
- **`POST`** (spec 3.5): only that app, empty body; it asks the signer for a full key bundle. The service records the time of the first request and shows it in `GET /apps` as `full_bundle_requested` until the parts it stores for the app cover every data epoch from 1 to the current one; a repeated request keeps the first time. Answer `{ "requested": time }`. An app asks once, when after fetching its current bundle it still lacks a scope key for some data epoch up to the current one.

#### 7.4.12 Apps: leave, list, revoke

- **`POST /v1/{id}/apps/{app_id}/leave`**: the app itself (`403 permission_missing` otherwise), empty body. The service records the departure and answers with the `leave` transition's proof.
- **`POST /v1/{id}/apps/{app_id}/revoke`**: the signer, empty body. Answers with the `revoke` transition's proof; revoking a revoked app again answers `{ "proofs": [], "head" }`; `404` for an app the service and `identity.json` don't know.
- **`GET /v1/{id}/apps`**: the signer. Answer `{ "apps": [status], "identity": signed<IdentityDoc> | null, "recovery": object | null, "proof_generations": [int] }`. `identity` is the newest `identity.json` the service holds for the account, as the signer delivered it (7.4.2), `null` when it holds none; unlike the public read (7.4.15) it is authenticated, signed with the service key like every answer and never cached, so the signer's checks of who signs read it here (3.12, 3.13). `proof_generations` lists, ascending, every generation that some kept proof names (3.3): a current record's (7.4.9) or a live claim's entry's (6.8), but those the newest `identity.json` declares lost (`recovery_from` and earlier), absent when none: the generations whose service keys `identity.json` keeps (3.3). The answer, `identity` included, is given while the account is frozen too, so the signer reads it from O before a move; N derives the same set from the proofs of the record and `claim_entry` parts once it has imported them (10.3). A status:

  | Field | Type | Notes |
  |---|---|---|
  | `app_id` | app-id | every app the service knows or `identity.json` lists, a purged app's kept App ID included (`current` false) |
  | `current` | bool | |
  | `last_seen` | `time \| null` | |
  | `revoked_at`, `departed_at` | `time \| null` | |
  | `awaiting_rotation` | bool | a departure whose rotation isn't done: done once a delivered `identity.json` lists the app in `removed` with a higher `data_epoch` than at its departure |
  | `open_attempts` | `array<object>` | `{ "claim_key", "attempt_id", "outcome": "open" \| "unknown" }` |
  | `unread_entries` | int | inbox entries targeting it that it hasn't read |
  | `sole_target_unread` | int | of those, the ones it is the only current target of |
  | `record_cert` | `b64(32) \| null` | the document hash of the certificate the app record the service holds carries (3.8 Renewal) |
  | `record_at` | `time \| null` | when the service took that record; the signer writes it plus the 5-minute clock tolerance as `renewed[].until` (3.8 step 4) |
  | `lagging` | bool | marked lagging (7.4.4); its entries no longer wait for it |
  | `keys_through` | `int \| null` | the newest data epoch through which the app holds every scope key: the epoch of the first `identity.json` listing it, raised to a part's `last_epoch` once the app's cursor has passed that part's item, for each part that starts at most one epoch after what the app holds (or at 1 when that is unknown); `null` when unknown (the signer then stores a full bundle). It is evaluated again at each cursor move over every part the cursor has passed, in `first_epoch` order, so a part passed before the gap below it was filled raises it once the gap is filled |
  | `full_bundle_requested` | `time \| null` | a pending `POST /keys` (7.4.11) |
  | `bundle_ranges` | `array<[int, int]>` | `[first_epoch, last_epoch]` of each key bundle part the service stores for the app, in order (3.5). A signer resumes a delivery cut short from `keys_through` + 1 to the epoch it delivers for, storing only what these ranges don't show yet as parts it stored for the app's current certificate (3.5). It starts from 1 only with a pending full-bundle request or without `keys_through`, since the parts the app has passed and holds are gone |
  | `cert_expires_at` | `time \| null` | the `expires_at` of the certificate the service checks the app against; signers warn before letting it lapse while the app owns open attempts |

  `recovery`: `{ "recovery_from": int, "declared_at": time, "admission_staged": bool }` from the delivery that starts a recovery (7.4.2) for as long as the account serves that generation, and `null` before it and after the next generation change. `declared_at` is the `recovery` transition's time. `admission_staged` is the part that ends (7.4.14): `true` while staged admission lasts, then `false` for good. The answer also carries `identity`, the newest `identity.json` the service holds, so the signer can build on it (3.3).

#### 7.4.13 Freeze and unfreeze

- **`POST /v1/{id}/freeze`**: body `signed<Freeze>` (3.6). Answer: the `freeze` transition's proof. The same freeze again, byte for byte, while the account is frozen by it, gets that same proof with the newest head; the signer resends its kept freeze after a lost answer (3.6). Errors: `401 bad_signature` when the identity didn't sign it; `400` for another identity or kind, or a `next_generation` other than the current one plus one; `409 conflict` with `current: { "freeze": signed<Freeze> }` when frozen by another freeze (a signer that signed it, another device of its, adopts it if it names the same next service and generation); `409 conflict` for a freeze an unfreeze cancelled (3.6: used once); `409 conflict` while admission is staged after a provider loss (7.4.14, spec 12.6 step 2), since an export doesn't carry staged admission, so the move waits until the lists are restored or the signer ends the staging.
- **While frozen,** the public read of `identity.json` answers with the account's last document and the freeze (7.4.15); after an unfreeze at the old service it carries no freeze again.
- **Before it freezes** the signer completes the rotations that departures still owe (spec 12.3), and checks that the next service's announced `max_import_bytes` (3.7) is at least the current one's; otherwise it doesn't freeze.
- **`POST /v1/{id}/unfreeze`**: body the unfreeze of 3.6. At a staged next service it is the abort of 10.6, sent first: N discards the import and answers with its signed discard answer (3.6). At the frozen old service the body must carry that answer as `discarded`, signed with the service key the freeze names (`409 conflict` without it or when it doesn't verify); the answer is the `unfreeze` transition's proof, and the same unfreeze again gets the same proof with the newest head. Errors: `401 bad_signature`; `409 conflict` for another freeze; `404` when not frozen and never frozen by that freeze.

#### 7.4.14 Recovery

- **Staged admission** (spec 12.6 step 2) starts at the `recovery` transition whenever the recovery document lists at least one current app: the service can't see permissions then, since certificates reach it only with each app's `app.put` or `cert.put`. A document that lists no app stages nothing. It ends at the first upload that carries `lists.contacts` from an app with `lists.manage`, or at `POST /recovery/admission`, and doesn't start again for that generation, whatever app joins later. The signer ends it itself, with `POST /recovery/admission` once the recovery's document is delivered and published, when none of the listed apps holds `lists.manage`, since no upload could ever end it; the call is a step of its recovery flow, sent again after a crash. Until it ends, senders it can't otherwise admit get `503 staged` and retry, denied ones included, at the inbox (7.4.3), at `PUT /peers` (7.4.5) and at the directory (7.4.10), so the staging doesn't reveal the deny list. What the user's apps add at the new service, contacts, conversation entries and invite codes, admits as usual.
- **`POST /v1/{id}/recovery/admission`**: the signer, empty body. Ends staged admission; answers with the `admission` transition's proof; `404` without a recovery. At an account whose admission isn't staged, or no longer is, it chains no transition and answers `{ "proofs": [], "head" }`, so the signer's retry after a lost answer, or a call where no listed app staged anything, succeeds.
- **`POST /v1/{id}/recovery/upload`**: an own app. Body:

  | Field | Type | Notes |
  |---|---|---|
  | `lost_identity` | `signed<IdentityDoc>` | an `identity.json` of the lost generation; it names the old service key that signed the proofs |
  | `records` | `array<uploaded op>` | `record.put` operations with their sealed values |
  | `claims` | `array<uploaded op>` | claim entries |
  | `heads` | `array<signed head>` | the old service's heads |
  | `proofs` | `array<signed<proof>>` | the old service's transition proofs |
  | `lists` | object | `{ "contacts": array<pubky>, "deny": array<pubky> }`: contacts from an app with `lists.manage`; deny entries also from an app with `lists.read`, since they only restrict admission |

  An uploaded op is `{ "op": signed operation, "cert": signed<AppCert> (its writer's certificate), "proof": transition proof (optional, the old service's) }`. An operation of an app now listed in `removed` counts only with a proof that dates it before the app's `distrust_from`.
  An app gets the certificate of every writer of the claim entries it keeps while the old service can still be read: for a writer the own `identity.json` lists whose certificate it doesn't hold, it reads its own directory (7.4.10) and keeps a certificate that verifies with the identity's key and that the document gives a standing (3.8), as for a record write's writer (6.2). It uploads an entry only with a certificate that verifies it. An entry whose writer's certificate it never got, such as one by an app removed before it saw the entry, can't be uploaded: the app counts it, and the writer's own app uploads it if it still holds it.
- **Members by stage.** No member is required: a missing one counts as empty, and `lists` as absent, so an app sends only what it holds. Which members the service reads depends on the stage:
  - **After a provider loss** it reads every member. `lost_identity` is what lets the old service's material count: its `inbox.service_key` is the key the uploaded `proofs`, `heads` and each uploaded op's `proof` are checked with. Without it, or with one that doesn't verify for the identity or isn't of the lost generation, they aren't checked and count for nothing, and an uploaded op is judged as one without a proof. `lists` may come alone, as the admission upload does (spec 12.6 step 2).
  - **In a cooperative move,** at the staged service before the import, after the activation and after the move is published (below), it reads only `heads` and `proofs`, and checks them with the old service's key, which the `identity.json` it was enrolled with names. It needs no `lost_identity`, and ignores it and the other members.
- **Which stage.** An account is after a provider loss for the whole generation that began with a `recovery` transition (6.5, spec 12.6 step 1). Uploads count at any point in it, so an app that follows late still brings its evidence; the next generation, after a move or a key change, begins with no `recovery` transition, so it ends the stage. An account in neither stage answers `404`, as `POST /recovery/admission` does without a recovery.
- **What an upload after a provider loss is refused for:** only the call and the body, never an item.
  - The caller is an own app under the checks of 7.2, so its `app.put` comes first (`403 not_current` before it). The rest of the order in the last bullet below is the app's to keep; the merge holds whatever the order, since writes at N win.
  - A body that doesn't read as the table above is `400`.
  - `contacts` from an app without `lists.manage`, or `deny` from one with neither `lists.read` nor `lists.manage`, is `403 permission_missing` for the whole upload, and nothing merges: the permission is the caller's, not an item's.
  - Past `uploads_per_app_per_hour` an upload is `429 rate_limited` (9.4). Every upload from an own app whose request verifies counts against it, one refused for another reason included, since its slot is taken before its items are judged; and one sent while another of the same app is still being judged is `429` too, with `retry_after` 1. The refusals stay in the order above.
  - An uploaded item that fails a check is counted in the answer (below) and left out, and the rest merges: apps upload whatever they kept, and one stale item mustn't block the rest.
  - The merge checks no time condition (spec 12.6 step 3) and uploaded attempts are orphaned whatever their age (6.8), so it needs no trusted time (7.3).
- **One transition for each upload.** Every upload accepted after a provider loss appends exactly one `upload` transition (6.5), with empty changes too, so its answer always carries the proof that binds it (6.5, Binding of the other writes). A retry merges nothing new and gets a transition of its own.
- **Answer** after a provider loss: `{ "result": changes, "proof": the upload transition's proof, "head" }`, where `changes` is `{ "records": [key], "divergent": [key], "claims": [claim key], "divergent_claims": [claim key], "unverified": int, "distrusted": int, "refused": int, "heads": int, "lists": bool }`. Its members:
  - `records`, `claims`: the keys whose state at N this upload changed: filled in, replaced, rebuilt, reopened or settled;
  - `divergent`, `divergent_claims`: the keys that became divergent, or gained a divergent upload, through this upload, a divergent upload past `max_divergent_uploads` included;
  - `unverified`: the uploaded items that count for nothing: an operation whose signature or certificate doesn't verify for the identity, whose certificate lacks the scope its kind needs (`claims.write`, or one of the record's write scopes), that isn't of the lost generation or an earlier one (Records, below), that isn't of its array's type (`record.put` in `records`, `claim` in `claims`), or that a service would refuse for its shape (6.4 step 9), for building on a later generation than its own, or for a lower bound (Records, below) past 2^53 - 1, which no record view could carry (1.1); a head or a `proofs` entry that doesn't verify with the lost generation's service key, every one of them when `lost_identity` is missing or doesn't count (Members by stage);
  - `distrusted`: operations of an app now listed in `removed` that no proof dates before its `distrust_from`;
  - `refused`: claim entries without a proof from O that the live writer rules refuse (below);
  - `heads`: the heads that verified;
  - `lists`: whether `lists` added an entry.
- **Writer rules for claims** (spec 12.6 step 3): an uploaded claim entry that carries no transition proof from O counts only if the live writer rules allow it: `done` with basis `owner`, and `failed`, only from the attempt's owner. Others are counted in `refused` and left out. Two outcomes for one attempt make the claim divergent instead of applying `failed`; a divergent claim clears once every attempt on it that isn't final is resolved by its owner, evidence or a user-confirmed outcome. On a claim rebuilt from uploads the owner may record `done` on a `failed` attempt (6.8 row 2). Three readings of spec 12.6 step 3:
  - two outcomes for one attempt are two different outcomes from entries that both count;
  - an uploaded writer-signed `done` settles an attempt even when it is `failed` at N, flagged `duplicate` if another attempt is done;
  - an uploaded open attempt that N lacks, on an obligation SETTLED at N, is added orphaned and doesn't make it divergent, since it can't move the obligation away from SETTLED.
- **How a claim merges** (spec 12.6 step 3):
  - **Order:** an upload's entries for one claim key apply in `expected_step` order, so an attempt comes before its outcomes.
  - **An `attempt` entry** for an attempt N holds changes nothing. One N lacks is added, marked `from_upload` and owned by its writer, opened at its proof's time, else at the upload's service time:
    - on a claim N holds nothing for, as a new claim with that attempt current, the entry's deadline pinned and its writer the creator;
    - on a FREE claim, as its current attempt;
    - beside an open attempt, making the claim divergent;
    - on a SETTLED claim, beside the others;
    - on a tombstone, after reopening it.

    Past `max_attempts_per_claim` it is dropped and the claim listed in `divergent_claims`. N lacks evidence of an attempt, so the claim is made divergent while an attempt on it is open or `unknown`; with none, it takes no further attempt at N anyway, since the attempt limit refuses it (6.8).
  - **An outcome entry** for an attempt N doesn't hold first adds the attempt from its proof's claim view. Without a proof that shows the attempt, the entry is left out and counted in `refused`: neither the attempt's owner nor its members are known.
    - A `done` settles the attempt: `done`, resolved by its writer, `duplicate` if another attempt is done.
    - A `failed` or `unknown` applies to an open attempt. On an attempt with another outcome it makes the claim divergent instead. The same outcome again changes nothing.
    - Divergence clears as after any entry, once no attempt on the claim is open or `unknown` (6.8).
  - **Each upload that changes a claim** marks it `rebuilt` and moves its `step` by one, so a write at N that read the step before is stale (`409 conflict`). Its last entry time becomes the upload's. A finished claim is compacted to a tombstone, as after any entry.
  - **A tombstone rebuilt from a SETTLED proof** takes the proof's attempts, marked `from_upload`, its deadline, its first attempt's owner as creator, and the proof's time as its last entry time.
  - **A removed app's operation** counts when its proof dates it at or before the app's `distrust_from`, as a removed app's write does (spec 10.3).
- **Records** (spec 12.6 step 3): an uploaded record's version is the one O's transition proof gives it; without that proof, the version it built on plus one is a lower bound. It fills in a record N lacks; two different uploads that build on one version are divergent; a write at N conflicts with an upload newer than the uploaded version the writes at N built on, or with any upload if they built on none.
  - **The proof that gives a version** is the operation's own `proof`, or a `proofs` entry whose stub's `item_hash` is the operation's, either one verifying with the lost generation's service key.
  - **Generations:** an operation of the lost generation or an earlier one counts. A proof counts only when it verifies with the lost generation's key, so an earlier generation's proof counts as none, and its operation gets the lower bound. An operation of N's generation or a later one is `unverified`: it belongs in `POST /ops`. Uploaded operations aren't checked against the current `data_epoch` (6.2).
  - **Comparing:** a lower bound counts as its value, the least version of the operation's own generation above the one it built on.
    - An upload strictly newer than a record N holds only from uploads replaces it. An older one changes nothing and is counted nowhere.
    - One at the same version with another operation, or one building on the same version as the held one with another operation, is divergent; two creates at one key, both building on `{0, 0}`, build on one version. So is one whose collection or policy isn't the held record's: a write with them is refused (6.2), so it can't build on the record.
    - The same operation again, byte for byte, changes nothing, unless it comes with a proof where the record held only a lower bound; the version is then the proof's.
    - They are judged in this order: the same operation first, as the record's or as a kept divergent upload, which changes nothing (or only makes the record's version exact); then another operation at the same version or on the same base, which is divergent; then a newer or an older one.
  - **Writes at N win.** A write at N builds on the record view's `generation` and `version`, as for any record. The uploaded version the first write at N on an upload-taken record built on is the one later uploads are compared with; an upload at that version itself isn't newer, so it changes nothing. Nor does an upload of the operation that write built on, with or without a proof: it is that operation again. An upload that conflicts with writes at N is never refused and never supersedes them: it is kept as a divergent upload, and the record's view shows `divergent: true`, until a writer writes a newer version at N, which clears the record's divergent uploads.
  - **Past `max_divergent_uploads`** (9.2), a record's further divergent uploads are dropped, and still listed in `divergent`.
  - **A record taken from an upload** has no `record.put` chain item at N. Its view's `seq` is the `upload` transition's, which lists its key, and it carries no `proof` (7.4.9). Apps learn of it from that transition in the feed, and read it with `GET /records`.
  - **What apps do with the transition.** Each app, the uploader included, reads again the records the transition lists that it may read, with `GET /records`, taking each write by the checks of spec 10.3, and the claims it lists that the app holds, with `GET /claims`; an app that doesn't hold a claim learns it from the conflict its first attempt gets. A record the app holds whose view is `divergent` keeps its current write, which the app takes as any other, and is held divergent until a view shows it isn't or a newer write at N clears it; what to do about it is the protocol's. A divergent claim is doubtful: no automatic attempt (spec 12.6 step 3).
- **`heads` and `proofs` after a provider loss** are evidence N checks and uses, not state it keeps. A head is verified and counted, never stored: O's heads show order, not authority (spec 12.6 step 3). A `proofs` entry is used in the merge: a SETTLED proof rebuilds the tombstone of an obligation N holds nothing for; one for an obligation N holds open and unsettled makes it divergent (doubtful, no automatic attempt), as after a published move (below), so an app that attempted again at N is warned by another app's settled evidence; one N holds settled changes nothing. A record version proof dates an uploaded operation (above). The transition's `proofs` counts the entries that verified.
- **Lists after a provider loss** add to what N holds and never remove from it, since N may hold list changes newer than the app's copy. Entries past `max_contacts` or `max_deny` are dropped: an upload counts against no per-kind limit (9.3), and the list holds no more. An upload whose `lists` carries `contacts`, an empty array included, from an app with `lists.manage` ends staged admission in the same transaction (spec 12.6 step 2); a deny-only upload doesn't.
- **Recovery in place** (spec 12.6 step 1): N may be O's own operator and origin; the delivery of an `identity.json` with a new generation and `recovery_from` then starts the new generation in the existing account.
- **At a staged service in a cooperative move** (before the import, spec 12.5 step 3) the body carries `heads` and `proofs`: after reading O's feed to its end, an app uploads its newest head and the evidence it holds, the SETTLED and tombstone proofs it keeps and the transition proofs of the record versions it holds, each checked with the old service's key (`401 bad_signature` otherwise). An app whose continuity is unverified (7.4.4) uploads no head until it has reconciled, since it hasn't verified the chain the head would vouch for; it still uploads its evidence. The evidence includes the transition proofs of the app's own attempts still open. The answer is `{ "heads": int, "proofs": int }`, the proofs counting those kept. At activation N checks the import against them (10.5).
- **After the activation**, while the move is unpublished, N checks each upload at once, with the old service's key: a head at or after the imported checkpoint that the imported chain doesn't extend, a proof not bound to the imported chain (its stub after the imported head, or with another chain hash at a `seq` N holds), and a proof the imported state doesn't meet by the evidence rules of 10.5 are each an import conflict: `409 conflict`, with `current: { "conflicts": [string] }`, which also blocks the `identity.json` delivery that would activate the service until the signer aborts (10.6). An older head is ignored, as at activation. The answer is `{ "heads": int, "proofs": int }`, the proofs counting those checked.
- **After the move is published**, an app that holds the old service's SETTLED proofs uploads them again once it follows (spec 12.5 step 4), so the evidence of an app that missed the move still counts. N checks each with the old service's key, which it keeps from the activation, and merges the proofs bound to the imported chain under the rules of spec 12.6 step 3: a SETTLED proof for an obligation N holds nothing for rebuilds its tombstone; one for an obligation N holds open and unsettled makes it divergent (doubtful, no automatic attempt); one N holds settled changes nothing. Any other proof the imported state doesn't meet, and a proof not bound to the imported chain, is refused: `409 conflict` with `current: { "conflicts": [string] }`, and nothing changes. When something merged, N appends an `upload` transition listing it, as after a provider loss. The answer is `{ "heads": int, "proofs": int, "merged": changes, "head" }`, with `changes` as above. N never answers success for a proof it didn't check or keep.
- An app sends its `app.put` and first `receive_key.put` before it uploads, and uploads before any other write at the new service: its first record write, claim entry or list change (spec 12.6 step 3).

#### 7.4.15 `GET /v1/{id}/identity`

The newest `identity.json` the service holds for the account's own identity, as the signer delivered it (7.4.2, spec 4.3), so a reader can compare it with the Homeserver copy (3.3, "The switch's copy").

- **Request:** unauthenticated: no `Switch-Identity`, `Switch-App` or `Switch-Signature`, so it names no reader; a client sends none. No body. A reader needs no pinned key for it (7.1).
- **Answer:** `{ "identity": signed<IdentityDoc>, "freeze": signed<Freeze> }`, with `freeze` only while the account is frozen (3.6, 7.4.13), signed with the account's service key like every answer (the request signature field is `hash` of the empty string, 7.1), with no `Switch-Head`, `seq` or `known_version`. The document and the freeze are signed by the identity key, so a reader verifies them as any `identity.json` (3.3) and any freeze (3.6) and needs nothing else from the answer. How a reader uses it: 3.3, "The switch's copy".
- **Caching:** a `200` carries `Cache-Control: public, max-age=60`. The answer is the same for every reader, since its signature covers the hash of the empty string as the request signature, so a cache may serve it for up to 60 seconds. Error answers carry none.
- **Limits** (9.4): per network source, an IPv4 address or an IPv6 /64, `identity_reads_per_source_per_min` reads a minute per account; and per account, from all sources together, `identity_reads_per_min`, a higher backstop. Reads that a source's limit refuses don't count against the account's. A service that can't tell the source (the reference prototype: its in-process transport) applies only the account's limit; behind a reverse proxy the source is the address the proxy reports.
- **Errors:** `404` for an unknown account (operator key) or one holding no document; `503 staged` for an account the newest document doesn't name yet (7.3 step 7); `429 rate_limited` past either limit (9.4).
- **A frozen account** answers with its last document and the freeze. After a move the old service keeps both, and answers so, for at least the identity's record age limit (`record_max_age`, 90 days when absent) after the move, after which no reader that applies it uses an app record from before the move. It doesn't see the move published, so it counts from the last export call it answered, plus a day. (The reference prototype: it deletes a frozen account only when the signer erases it, 7.4.16.) After an unfreeze (10.6) the answer carries no freeze.
- It reveals nothing the Homeserver doesn't publish. The service sees the reader's network address and when it looked the identity up, so it learns that someone is about to act on its public app records (spec 15).
- Vectors: `http.json` "anyone: the public identity.json read" and "anyone: a frozen service's public identity.json read, with the freeze".

#### 7.4.16 `POST /v1/{id}/erase`

The signer erases the identity's account at this service (spec 12.7).

- **Request:** a signer call (7.2): signed with the identity key, without `Switch-App`, over the switch origin and `Switch-Timestamp` like every request. So an app's call is `403 permission_missing`, another identity's key `403 not_admitted`, a signature for another service's origin `401 bad_signature`, and a timestamp more than 5 minutes from the service's time `401 stale_timestamp`. Body `{ "service_key": b64(32), "identity_hash": b64(32) }`: the account's service key, the one the signer pinned, and the document hash (2.2) of the newest `identity.json` the signer holds, its mark (spec 4.3). `identity_hash` is optional; any other member is `400 bad_request` (1.1). Another key is `409 conflict`, so a replay within those 5 minutes can't erase a later account of the identity here, which has a new key. Then, with `identity_hash`, the account's newest `identity.json` must have that hash: another one is `409 conflict` too, and nothing is deleted. So an erasure can't follow a delivery that came after the signer last checked the switch's copy, such as another install's take-over. A signer sends `identity_hash` when its mark names this account's service key, that is, once it has delivered a version here; a body without it, as an older signer's or one erasing an account it delivered nothing to, is checked as before, the key only. An account holding no `identity.json` yet is a staged one between its enrollment and its first delivery (a new identity, or a new account after a provider loss or an erasure): a hash there can't match, so it is `409 conflict` as well; no signer that follows this rule sends one. An erasure sent again after a request in doubt carries the same body, the same hash: once the first request has erased the account, the retry finds no account and gets the operator's `404` (Afterwards, below), never a `409`. Both `409`s are signed with the account's service key, so the request isn't in doubt (The signer's `404`, below): the signer reads the switch's copy (`GET /apps`) and judges it as every copy (spec 4.3), so a newer one naming another install ends the erasure without erasing.
- **Refused during a move** (`409 conflict`): at a frozen account whose export isn't finished, that is, with no manifest built yet (10.2) or a chunk of it never fetched, by the next service or the signer (10.3); and at a staged account holding an import, partial or activated, until the signer aborts it (10.6), since the old service resumes only with this service's discard answer (3.6). The service doesn't wait for the pointer window of 7.4.15: once the export is finished it takes the erasure, and it is the signer that waits for the window (spec 12.7). After a move given up for a provider loss (spec 12.6), the signer finishes the old service's export by fetching its manifest and every chunk itself, then erases there.
- **Answer:** `{ "erased": true }`, signed with the account's service key. It is the last answer that key signs. No answer to an erasure, an error included, carries `Switch-Head`. The service then deletes everything it holds for the identity: every kind of 9.1, "for good" ones included, the chain with its stubs, checkpoints and batch records, the freeze, the export or the staged import, a stored hand-over (7.4.17), the enrollment answers, the pending key of the next generation (3.7), the rate-limit and failed-authentication counts (9.4), and the account's service key with its mark (7.3 step 10). An account whose state is behind its key's mark still takes the erasure, since the answer carries no head.
- **Order:** the service signs the answer first, while it still holds the key; then it commits the deletion of all of it, the state, the service key and the mark, durably (7.3 step 10); only then does it release the answer. So a crash after the answer can't leave the erased account recoverable. If the deletion can't be committed, the service answers `503 unavailable`, signed with the account's service key, without a head, having deleted nothing, and the signer retries. A service whose key store deletes the key apart from the state commits, with the state's deletion, that the key is owed, and releases the `200` only once the key is gone. Until then it answers the operator's `503 unavailable`, without a head, and deletes the owed key at a later attempt. A retry after a committed erasure finds no account: it gets the `404` of the next bullet, signed with the operator key, once no key of the erased account is owed. While one is, a signer call for the identity, a request whose signature verifies with the identity key without `Switch-App`, gets the operator's `503` instead. The signature is checked over the request's own `Switch-Timestamp`, whatever its skew: at an erased account no signed `stale_timestamp` can tell a signer whose clock is off to retry at the service's time, as it would at a hosted account (7.1). A retried erasure among those calls whose timestamp is within the 5 minutes deletes the owed key, a few times a minute at most for the identity, since a replay within the 5 minutes verifies too; a stale one deletes nothing. So the signer never gets that `404` while the key still exists. Every other request gets the `404` at once. The cost: anyone who saw a signer request can replay it, at any later time, to learn that the identity's erased account still owes a key.
- **The signer's `404`:** an erasure request is in doubt when no answer came back, or an answer the pinned key didn't sign that isn't a `404`, since a gateway's `502`, `503` or `504` can hide a request it forwarded. After a request in doubt, the operator's `404` for the account it asked to erase, to the retry or to any signer call it makes for the account, such as `GET /apps`, is how an erasure that landed looks. The signer takes it as the erasure done only once every such call has met it for 24 hours, as an app takes an erasure (spec 12.7 step 5). Meanwhile the erasure stays in progress, erased but unconfirmed: the signer keeps, durably, when the first of those `404`s came, reads the switch again at each run, and signs nothing else. A try that gets no answer, or an answer the pinned key didn't sign other than a `404`, neither counts nor ends the wait. An answer the pinned key signs ends it: the account is there, so the erasure goes on as before its request, which it sends again, with the same body; a signed `200` to the request ends the erasure at once. The signer can't authenticate the `404`, but a signed `200` proves no more: a service that keeps the data could sign one anyway (spec 12.7). What remains: an intermediary that answers `404` to every call for 24 hours after a request in doubt ends an erasure that never landed. A switch that never answers again leaves the erasure in progress, in doubt; the way out is a provider loss (spec 12.6). A `404` is never itself a lost answer: with no request in doubt before it, the operator's means the account wasn't there when the service answered, and an intermediary's that the request wasn't routed. Either way the signer erased nothing, and it keeps its records and state.
- **Afterwards** every request for the account is answered as for an account the service doesn't host: `404`, signed with the operator key (7.3 step 2), the public read and the erasure itself included, once no key of the erased account is owed (Order, above). A request in flight when the erasure lands is answered the same way, unless its answer was signed before the erasure's: a write it committed went with the account, and a signer call gets the `503` while a key is owed, as above. `POST /v1/enroll` creates a new, staged account with a new key. The signer names in it the App IDs it revoked or saw depart, as in every enrollment (3.7), and starts the account as after a provider loss: an `identity.json` at the next generation with `recovery_from` (7.4.2), so its version and generation stay above any a reader has seen.
- **Not erased:** other accounts' state that names the identity, such as their contacts, conversation entries, deny lists and peer copies of its `identity.json`, belongs to them.
- **Backups** (spec 6.5): the operator lets the account's data age out of its backups and erases it again after any restore from a backup taken before the erasure.
- Vectors: `http.json` "signer: account erasure, naming the account's service key" and its answer; "signer: account erasure, naming the account's service key and the identity.json it follows", whose `identity_hash` names alice's version 3, and its answer; and "signer: account erasure naming an identity.json the account doesn't hold" (her version 1) and its `409 conflict`. Its `service_key` is `keys.json`'s fixed key for alice (the reference prototype: the generator replays it on its service, where the account's key is drawn at random, so there it names that key).

#### 7.4.17 `PUT` and `GET /v1/{id}/handover`

The signer hand-over travels through the switch (3.12, spec 12.8), as key bundle parts do.

- **`PUT`, by the signer:** body `{ "app_id": app-id, "handover": { "envelopes": [...], "sig": b64(64) } }`, the target app and the hand-over of 3.12; unknown members are `400` (1.1). The switch checks, without opening anything: the target is a current app (`409 conflict` otherwise); `envelopes` holds 1 to 128 envelopes, each within the envelope cap (4.4) with exactly one recipient, whose kid is that of the bundle key of the certificate the switch checks the target against (`400`); and `sig` verifies with the identity key over the target's App ID, the number of envelopes and their bytes, under `pubky-switch/v1/signer-handover` (`400`). It keeps it, replacing any hand-over it holds: one per account, of at most 128 parts. Answer: `{ "app_id": app-id, "parts": int }`, with `Switch-Head` as every answer to the signer.
- **`GET`, by the target app or the signer:** the body of the `PUT` the switch holds. Any other own app, or a call when none is held, gets `404 not_found`, so an app learns nothing of a hand-over to another. The target checks it as 3.12 says.
- **Deletion:** the switch deletes the stored hand-over when it takes the next `identity.json` version (7.4.2), whichever signer delivered it: the new signer's, so the hand-over took effect, or the old signer's abort. It deletes it on erasure (7.4.16) too. It isn't exported: there is no hand-over during a move (3.12). It counts against no quota; the body cap is 12 MiB (7.1).
- Vectors: `http.json` "signer: store the hand-over to the phone at the switch" and "own app: the phone fetches the hand-over stored for it", with their answers.

### 7.5 Feed items and visibility

Each feed item has a `type`:

| `type` | Fields | Shown to |
|---|---|---|
| `entry` | `seq`, `entry_id`, `sender` (pubky), `cert` (the sender app's certificate), `accepted_at`, `context` (the invite code's, if one admitted it), `envelope` (b64) | its target apps |
| `unreadable` | `seq`, `entry_id`, `sender`, `accepted_at` | the current apps, for an entry no current app can open after its targets departed; it takes a new `seq` at the departure |
| `missed` | `seq`, `entries` (int), `accepted_from`, `accepted_until` (times) | the lagging app it was made for: how many entries targeting it the service deleted before it read them, and the first and last of their acceptance times (7.4.4) |
| `chain` | `seq`, `stub`, `item_type`, `item` (the signed document), `context` (for a service-written conversation entry), `proof` (for a signed operation: its transition proof) | apps that may read the item, below, while the service keeps it |
| `stub` | `seq`, `stub` | apps that may not read the item, and every app once the item's document is deleted |

A reader skips a feed item whose `type` it doesn't know: it takes nothing from it and moves past its `seq`, as past a position a page shows nothing for (7.4.4). If the item carries a `stub`, the reader still checks that stub in the chain like any other (6.6), so an item of a later version never hides a chain item or breaks the chain it verifies.

Who may read a chain item in full:

| Item | Readers |
|---|---|
| `identity.json` deliveries, `app.put`, `receive_key.put`, `cert.put`, service transitions other than `conversation.add` | every own app |
| `claim` | apps with `claims.read` |
| `record.put` | apps holding the record's `read_scope` |
| `allow.*`, `deny.*`, and the service's `conversation.add` | apps with `lists.read` |
| `invite_code.*` | apps with `lists.read` or `conversation.add` |
| `key_bundle.put` | the target app |

Superseded record writes and key bundles, superseded app records, renewed certificates replaced or carried by the app's record, and the entries of compacted claims lose their document and show as stubs. So do the entries of a deleted claim, and a forgotten key's delete. The service deletes such a document, and an operation's transition proof with it, in the transaction that supersedes it: the write that replaces it, the request that compacts or deletes the claim, forgets the key or stops storing the part. Only the stub stays, which is all any app is shown of the item from then on, whoever reads and wherever its cursor stands. Nothing anyone checks needs the document: the chain, signed heads and checkpoints verify by stubs; an app holding the document checks it against the stub's `item_hash`; the proofs apps hold verify as before; and the service answers retries and reads from the batch, record and claim it keeps (6.4 step 5, 7.4.8, 7.4.9). A move's export carries the documents O still keeps (10.1), so none of these. (The reference prototype: the documents chained before it deleted them are checked at the account's next requests, 64 a request, oldest first, and those already superseded go then.)

A stub names no object: its envelope gives the item's type (6.6), not the claim, record or app it was about, and naming one would show a claim's key to apps without `claims.read`. So an app reads a claim it follows again (`GET /claims`) at the end of any read whose feed shows the stub of an operation (`item_type` `op`), whoever wrote it, its own included, until it holds that claim as finished: SETTLED with every attempt `done` or `failed`, the state that compacts it (6.8). The stub may be an entry of that claim, compacted since, and a SETTLED claim with an attempt still open stays live, so that attempt's outcome comes as a stub too.

### 7.6 Errors

| HTTP | `code` | When | `current` |
|---|---|---|---|
| 400 | `bad_request` | malformed request, document or operation; unknown members where 1.1 rejects them; a missing or unparsable `Switch-Timestamp` or `Switch-Identity`; an append without `apps_version`; an envelope size that isn't a bucket; a policy or collection that differs from the record's; a batch writing one record twice; an `evidence_ref` on a claim entry other than `done` | |
| 401 | `bad_signature` | a request, operation, certificate, freeze, unfreeze or key bundle signature that doesn't verify | |
| 401 | `stale_timestamp` | `Switch-Timestamp` more than 5 minutes from the service's clock | `{ "server_time" }`: the service's time base when it checked the timestamp (7.1) |
| 403 | `not_admitted` | a sender not admitted or denied; a connect request where they are off; a signer of another identity. An admission refusal has one message, `7: sender not admitted`, whatever the reason (denied, unknown, an unknown, expired or used-up code) | |
| 403 | `permission_missing` | the caller's certificate lacks the switch permission or scope; a call only another caller may make | |
| 403 | `not_current` | the calling app is revoked, departed or not listed with its certificate, also once it is purged (its App ID is kept for good, 9.1), or the service holds no record of it, before the request verified and without `Switch-Head` (7.2 "Where an own app gets `403 not_current`"); an app of another identity whose certificate's renewal has closed (3.8). An app the sender's `identity.json` lists as removed gets a stranger's answer instead (7.2) | |
| 403 | `cert_expired` | the caller's certificate has expired | |
| 404 | `not_found` | no such account, route, claim, record, key bundle, invite code, connect request or freeze | |
| 409 | `conflict` | a condition fails | `{ "record_version": { "key", "generation", "version" } }`, `{ "claim_step": { "claim_key", "step" }, "claim": view \| null }` or `{ "server_time": time }` |
| 409 | `conflict` | a claim entry is refused (6.8) | `{ "claim": view \| null }`, plus `"server_time"` for a passed deadline |
| 409 | `conflict` | a `record.put`'s `expected_version` isn't the current version | `{ "record": { "key", "generation", "version" }, "record_view": record view }` to a writer with the read scope, else `{}` |
| 409 | `conflict` | a receive key's `n` isn't the next one | `{ "receive_key": signed record \| null }` |
| 409 | `conflict` | a batch ID in the chain with other operations, or a retry whose proofs were dropped; an invite code registered twice; a `cert.put` not issued after the certificate it renews; a second freeze, or an unfreeze of another freeze; an unfreeze at the old service without N's discard answer (3.6); an import that doesn't extend an uploaded head, or that doesn't settle what an uploaded SETTLED proof shows or holds a record older than an uploaded version (10.5); the export and import errors of Section 10; an erasure naming another service key, or during a move (7.4.16) | `{ "chunk": chunk ref }` for a chunk that doesn't match the manifest; `{ "missing": [chunk id] }` for an activation with chunks missing (10.4, 10.5) |
| 409 | `conflict` | a delivered `identity.json` leaves out the service key of a generation a kept proof names (3.3), or gives it a key those proofs don't verify with (`PUT /identity`, 3.3) | `{ "proof_generations": [int] }`, the generations it leaves out, ascending |
| 409 | `stale_epoch` | a sealed value at another data epoch | `{ "data_epoch": int }` |
| 409 | `stale_generation` | an operation naming another generation | `{ "generation": int }` |
| 409 | `stale_key` | an envelope wrapped to a receive key that isn't current, or sealed for an `apps_version` older than an app added since | below |
| 409 | `stale_identity` | a delivered `identity.json` that isn't newer (at `PUT /peers`, a lower version or generation, or another body at the version held), or (`PUT /identity`) doesn't build on the version the service holds | `{ "version", "generation", "hash", "identity" }`, the copy held (`PUT /identity`, `null` when it holds none); at `PUT /peers`, `{ "version" }`, or `{ "version", "identity" }` with the held signed document for another body at the version held (7.4.5) |
| 409 | `identity_needed` | the service's copy of the sender identity's `identity.json` doesn't list the app; also, as to a stranger, an app that copy lists as removed (7.2) | `{ "version": int \| null }`, the version it holds; `null` for an app the copy lists as removed |
| 410 | `moved` | the account is frozen | `{ "freeze": signed<Freeze> }` |
| 413 | `too_large` | an envelope over 64 KiB, a sealed value over its cap, a signed operation over 512 KiB, an invite code context over 1024 bytes, a chunk over 1 MiB, an export over the import limit | |
| 429 | `rate_limited` | too many requests from the sender identity or sender app, invite-code directory reads, or batches from the app (Section 9) | body `retry_after` and header `Retry-After` |
| 429 | `quota_exceeded` | a quota or a per-kind limit is full (Section 9) | `{ "limit": string }`, the budget that is full (9.3) |
| 503 | `staged` | the account isn't named by its `identity.json` yet, or a recovering account restores its allowlist | |
| 503 | `unavailable` | a temporary failure; without trusted time, a request whose outcome depends on the service's time (7.3); an account whose state is behind its key's mark, until a new generation (7.3 step 10) | |

- **What `current` reveals**: a record's version only to a caller holding its read scope, or when the record doesn't exist; a claim only to a caller with `claims.read`. Otherwise `current` is `{}`.
- **`stale_key`'s `current`**:

  | Field | Type | Notes |
  |---|---|---|
  | `receive_keys` | `array<object>` | `{ "app_id", "record": signed<ReceiveKeyRecord> }`: the current record of each target app whose key was stale |
  | `not_current` | `array<app-id>` | targets that are no longer current |
  | `unknown_kids` | `array<b64(8)>` | kids the service never registered |
  | `added_apps` | `array<object>` | `{ "app_id", "app_record": signed<AppRecord>, "record": signed<ReceiveKeyRecord> }`: apps reachable since `apps_version` that the envelope left out |
  | `apps_version` | int | the current one |

  The sender checks each record (3.4), seals the same signed plaintext again and re-sends. `receive_keys`, `not_current` and `added_apps` together name each App ID at most once; a sender refuses a `current` that repeats one, takes nothing from it and reads the directory again (7.4.10).
- **Retry** column of spec 6.4 applies, with its rule for sending the same bytes again: a kept batch or envelope goes again after `401 stale_timestamp`, `409 identity_needed`, `410 moved`, `429` and `503`, and is final for those bytes after `409 conflict`, `stale_epoch`, `stale_generation` and `stale_key`. `429 rate_limited` uses fixed one-minute windows, per sender identity, per sender app or per invite code, or per own app for batches (Section 9); `retry_after` is the seconds to the next window. `429 quota_exceeded` carries no `retry_after`, and frees up per limit (spec 6.4): the inbox quota as the recipient's apps read their feed; the storage quota after deletions; the record key limit after deletions, at once, since it counts live keys only (6.2); other limits after a deletion or removal. A receiving app whose record write gets it stores the entry and moves on (5.1).

Example (`409 stale_key`, records cut short):

```json
{
  "code": "stale_key",
  "message": "3.7: envelope wrapped to a receive key that isn't current",
  "current": {
    "added_apps": [
      {
        "app_id": "c1utah9jitjs43etzdkj6cqdwr",
        "app_record": {
          "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLmFw...",
          "sig": "M-2HJw3X_8STEphe67IcgEjAcSQCDo6xzoZn-4heZF2NWsRkpRTxgNZ1hINObcUFo39gZ6bFX4ZkGTxr1BDxCA"
        },
        "record": {
          "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLnJl...",
          "sig": "EPbFVAY6CLyzPBnizLl9BzSadKS-N5yCwxRlWdov679J_-DMa6uls-bRqhFf95p-k0ML8hIhocoqK_7rAlbcCg"
        }
      }
    ],
    "apps_version": 5,
    "not_current": [],
    "receive_keys": [
      {
        "app_id": "w8amtmn13m6p5bwnmj9wejbq4c",
        "record": {
          "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLnJl...",
          "sig": "2v-AMIqAxitgORsPtoQGTK8uaVwNV_F0zs6A-5a3Ad787xX2Lpghv9ICS39ofJT5_q5ticrDWj0mKXn7vkl2Bw"
        }
      }
    ],
    "unknown_kids": []
  }
}
```

## 8. Push

### 8.1 `PUT /v1/{id}/push`

An own app sets its own relay and handles in two steps (spec 9):

| Field | Type | Req | Constraints |
|---|---|---|---|
| `relay_url` | string | yes | `https://` URL on port 443, with no user info; its host must resolve only to public addresses |
| `handles` | `array<string>` | yes | at most 8, one per device; `[]` when starting a registration; with the handles the account's other apps hold at the same relay host, at most 8 |
| `push_key` | `b64(32)` | no | absent to start a registration; present to set the handles of the registration it names |
| `replaces` | `b64(32)` | no | only on a start: the push key of the app's current registration, which the start replaces (a rotation or another relay); absent otherwise |

1. **Start a registration.** The app sends its relay URL, no handles and no `push_key`; a start with handles is `400`. A start is idempotent without a nonce or replay cache (spec 6.1, 9):
   - the app holds no registration: the service mints a new **push key**, an Ed25519 key for this registration that appears in no public document, and answers its public half; a start naming `replaces` is then `409 conflict` with `current: { "push_key": null }`;
   - the app holds one, and the start names no `replaces` and the same `relay_url`: the answer is the current registration, unchanged, with its handles;
   - the app holds one, and `replaces` is its push key: the service mints a new push key, replacing the registration and its handles;
   - otherwise (another `relay_url` without `replaces`, or `replaces` naming another key): `409 conflict` with `current: { "push_key": the current one }`.

   So a retried start, or a replay within the timestamp window, changes nothing, and a replay of an earlier rotation names a key that is no longer current.
2. **Register with the relay.** Each device sends its device token and that push key to the relay, which returns a handle bound to the push key (8.3).
3. **Set the handles.** The app sends the relay URL, the handles and the `push_key`. The list replaces the one the service holds, so it is always the whole list. An app that runs on several devices keeps its handles with the state its devices share through its own sync, as it keeps its receive keys and its cursor (spec 3.6): a device that adds, replaces or drops its own handle sends the merged list of all of them. A `push_key` that isn't the current registration's, or another relay URL, is `409 conflict` with `current: { "push_key": the current one, or null }`; the app starts a new registration.

- **Answer:** `{ "relay_url": string, "handles": int, "push_key": b64(32) }`: the handles kept and the registration's push key.
- **Errors:** `400` for more than 8 handles, handles on a start, `replaces` with `push_key`, a URL that fails the checks, a service that sends no pushes, or handles that, with those of the account's other apps at the same relay host (the URL's host, lowercase), would make more than 8 there, since an entry sends at most 8 webhooks toward one host (8.2); `409 conflict` as above.
- A start naming the current push key in `replaces` is how an app rotates its push key or moves to another relay. The setting belongs to the calling app and is removed when the app stops being current: at its revocation or departure, and at the delivery of an `identity.json` under which it isn't current (7.2). A recovery in place removes every registration with the generation, and an erasure with the account (7.4.16). A replaced or removed registration's push key is deleted with it. No export part carries a registration or a push key (10.3): after a provider change, apps register again with the new service, which mints new push keys (spec 12.5, 12.6).
- **Checks.** The body's `400`s come after the caller's own checks (7.2) and the staged gate (7.3 step 7), then the `409`s, then the `400` for more than 8 handles at one relay host, which is judged on the registrations held. The service resolves the relay's host at each `PUT /push`, within 5 s, and refuses (`400`) a host that doesn't resolve or resolves to any address that isn't public (8.2); delivery resolves it again at each connection.
- **What the relay learns** (spec 15): which handles share a push key, so which devices belong to one app, but not the identity, since push keys appear in no public document.

### 8.2 Webhook

When a `notify` entry targets an app, the service sends one webhook per handle, at most 8 for the entry toward one relay host, however many of the account's apps name it, which the limit of 8.1 keeps every handle within:

```
POST <relay_url>
Content-Type: application/json
Switch-Signature: <b64(64)>

{"v":1,"handle":"<handle>","ts":"<time>","nonce":"<b64(16)>"}
```

| Field | Type | Notes |
|---|---|---|
| `v` | int | 1 |
| `handle` | string | the handle, and nothing about the message |
| `ts` | time | the service time when sent, three fraction digits |
| `nonce` | `b64(16)` | random, fresh per webhook |

- **Signature:** the registration's push key (8.1), never the service key, label `pubky-switch/v1/push`, over `lp(label, relay origin, body bytes)`. The relay origin is `https://` followed by the URL's host, without port or path: `https://push.example` for `https://push.example/v1/hook`.
- **Delivery:** from a background queue, never during the append. Each connection resolves the host again, refuses the host if any address isn't public, and connects to the address it checked. Redirects aren't followed. Each attempt is a webhook of its own, with the time it is sent and a fresh nonce, so a retry after a timeout the relay did take isn't refused as a replay (8.3). A queued webhook whose registration has gone or been replaced, or whose handle has left the list, isn't sent, and its push key signs nothing once the service owes its deletion. Nor is one for an account whose newest `identity.json` names another service (7.3). A webhook needs trusted time (7.3): without it none is sent, and a `notify` entry's webhooks wait, sent if trusted time is back within the entry's minute and dropped once past it.
- **Public addresses** (spec 9; the reference prototype: `netcheck`), for relay URLs and switch origins (7.1) alike. Refused, from the IANA special-purpose registries: IPv4 `0.0.0.0/8`, `10/8`, `100.64/10`, `127/8`, `169.254/16`, `172.16/12`, `192.0.0.0/24` (except `.9` and `.10`), `192.0.2/24`, `192.88.99/24`, `192.168/16`, `198.18/15`, `198.51.100/24`, `203.0.113/24`, `224/4` (multicast), `240/4`, `255.255.255.255`; IPv6 `::/96` (unspecified, loopback and IPv4-compatible), `64:ff9b:1::/48`, `100::/64`, `100:0:0:1::/64`, `2001::/23` except its globally reachable blocks (`2001:1::1` to `::3`, `2001:3::/32`, `2001:4:112::/48`, `2001:20::/28`, `2001:30::/28`), so Teredo `2001::/32` with it, `2001:db8::/32`, `3fff::/20`, `5f00::/16`, `fc00::/7`, `fe80::/10`, `fec0::/10`, `ff00::/8`. Judged by the IPv4 address they embed: IPv4-mapped `::ffff:0:0/96` (the low 32 bits), NAT64 `64:ff9b::/96` (the low 32 bits), 6to4 `2002::/16` (bits 16 to 47). Everything else is public. A relay URL uses port 443 only. Timeout 5 s; a failure is retried 20 s later, at most 3 attempts, each claimed within 1 minute of the entry, so the last ends at most 70 s after it.
- Any 2xx answer is a delivery; any other answer, a redirect or a timeout is a failure.

Example (vectors `http.json` `webhook`, signed there with the fixed service key of `keys.json` standing in for a push key, since the signature input is the same):

```
POST https://push.example/v1/hook
Content-Type: application/json
Switch-Signature: yf38KwoGUEG-DWIt_eTjVx_E7dca-MzSOGhiQV-yoO4xITjyfNErlKcU2xJyoZo4lRy-K3i_dijEWpU76EBdCQ

{"v":1,"handle":"iUsOsTv5mB7OMLMdQZi8QA","ts":"2026-01-01T00:06:00.000Z","nonce":"vX9AwGixjY0MiVA86rs3Gw"}
```

### 8.3 Relay rules

A relay registers a device token for one push key and returns a random handle bound to that key (spec 9 step 2). It accepts a webhook only when:

1. the body is a webhook with `v` 1 (else `400`);
2. the handle is known (else `404`);
3. `Switch-Signature` verifies with the push key bound to the handle, over the relay's own origin and the body (else `401`);
4. `ts` is within 5 minutes of the relay's clock (else `401`);
5. the nonce wasn't seen in the last 10 minutes (else `409`);
6. the handle is under its per-minute push limit (else `429`).

Then it pushes to the device and answers `200`.

## 9. Retention and quotas

Spec 6.3. For every kind of state the service keeps, how long it keeps it, which budget it counts against and its limit. (The reference prototype: its table is `service::retention`.) Defaults are for one identity on a shared service; an operator may raise them.

### 9.1 What the service keeps

| Kind | Kept for | Counts against | Default limit | When full |
|---|---|---|---|---|
| Inbox entry | until every current target's cursor has passed it, not waiting for targets marked lagging (7.4.4); no expiry | inbox quota: its envelope bytes plus `entry_overhead_bytes` (256) | `quota_bytes` 64 MiB; 64 KiB per envelope (4.4) | the append is `429 quota_exceeded` (`inbox`) |
| `missed` item (7.5) | until its app's cursor has passed it | nothing; never refused | one per lagging app; a later miss replaces it | - |
| Unreadable entry (7.5) | until every current app's cursor has passed it | inbox quota: `entry_overhead_bytes` only | - | never refused: the service creates it |
| Shared record value | while current, with the operation, certificate and transition proof of its current write (7.4.9); a superseded value is deleted at once | storage quota: its sealed `ct` bytes, ciphertext and tag as decoded from base64url (not the text), 0 for a delete; the certificate and proof are bounded by `max_record_keys`, not counted: at most 33,950 bytes, the largest certificate of 10.3 and a proof of 1,078, and about 1.6 KB for the vectors' apps | `record_quota_bytes` 64 MiB; 256 KiB per value (6.2) | a `record.put` that grows the stored bytes is `429` (`storage`) |
| Shared record key | while live; once deleted, until the service forgets it (below) | record key limit: live keys only | `max_record_keys` 100,000 live keys | a `record.put` creating a key, or writing a deleted one again, is `429` (`record_keys`) |
| Live claim | until finished, then compacted to a tombstone at once (6.8) | claim limit, with tombstones; its creator's share of it (6.8) | `max_claims` 1,000,000; `max_attempts_per_claim` 64; `claim_share_percent` 25; `open_attempts_per_app` 1,000 | only `attempt` is refused: on a new claim key (`claims`, or `claim_share` beyond its app's share), beyond 64 on one (`attempts`), or beyond its app's open attempts (`open_attempts`) |
| Tombstone | until the time base, with trusted time, reaches its pinned deadline plus the 30-day reconciliation window (6.8), then deleted at a request to the account (7.3 step 4); when pinned to "none", until it reaches its last entry plus `max_claim_age_ms` (400 days), then deleted the same way | claim limit, its creator's share | as above | - |
| Failed claim (6.8) | a claim whose every attempt is `failed`: until the time base, with trusted time, reaches its pinned deadline plus the 30-day reconciliation window, then deleted like a tombstone; when pinned to "none", until its last entry plus `max_claim_age_ms`; a claim with an open or `unknown` attempt is never deleted by age | claim limit, its creator's share | as above | - |
| Chain stub, and the item's document while some app may read it in full (7.5) | within the generation, until it is older than a checkpoint and either every current app's cursor has passed it or it is `cursor_hold_ms` (30 days) old (7.4.4); dropped oldest first, so the kept ones run unbroken to the head; a cooperative move carries every kept one on (10.2) | control reserve | grows only as fast as the operation and control rates allow (9.4); unchanged control operations add none (6.4); no cursor holds a stub back once it is 30 days old | - |
| Checkpoint (7.4.4) | the latest one | control reserve | one | replaced by a newer one |
| Newest dropped stub (7.4.4) | its `seq` and chain hash, until a newer stub is dropped; an export's checkpoint signs them (10.2) | control reserve | one | replaced by the next one dropped |
| Batch record | its transition proofs `batch_proofs_ms` (30 days), for retries (6.4), until the minute's sweep at a later request (below); its ID and operation hash as long, and also while any of the batch's chain stubs is kept (row above). | control reserve | proofs: bounded by the rates over 30 days; IDs: one per batch of the last 30 days or with a chain stub kept, so bounded like the proofs and the stubs | - |
| Contact | until removed | list limit | `max_contacts` 100,000 | `allow.put` of a new contact is `429` (`contacts`) |
| Conversation entry | until removed | list limit | `max_conversations` 100,000 | `allow.put` of a new entry is `429` (`conversations`); an append admitted by an invite code is `429` (`conversations`) and waits |
| Deny list entry | until removed | list limit | `max_deny` 100,000 | `deny.put` of a new entry is `429` (`deny`) |
| Invite code | until it expires, runs out or is withdrawn; an expired or used-up one admits nothing and is deleted at the minute's sweep at a later request (below) | invite code limit, live codes only | `max_invite_codes` 1,000 | `invite_code.put` is `429` (`invite_codes`) |
| Connect request | until answered (a contact, a conversation entry, a deny list entry or `DELETE /connect`, 7.4.7) | the policy's `max_pending` | `max_connect_pending` 1,000 caps `max_pending` | a sender with no pending request gets `429 quota_exceeded`, `connect_requests` (7.4.7); none drops |
| A frozen account's last `identity.json` and freeze | while frozen, and after a move at least `record_max_age` (7.4.15) | - | one of each | - |
| Sender flag | while among the most frequent | - | `max_flags` 1,000 | the least frequent drop |
| App record, current receive key record, key bundle parts | while the app is listed in `apps` or `removed`, or awaits its rotation; a key bundle part only until the app's cursor has passed it and `keys_through` covers it, unless a full-bundle request is in force: from the `POST /keys` until the app's cursor has passed the part that completed it, or the part that replaced that one (6.2) | app limit (3.7) | one record and one current receive key record per app; key bundle parts that never overlap (6.2), so at most one key per scope and data epoch | - |
| Signer hand-over (7.4.17) | until the next `identity.json` version the service takes, whichever signer delivered it, or the erasure | nothing | `max_handover_parts` 128 envelopes; one per account, a new one replacing it | - |
| Retired receive key record | until `max_retired_keys` newer ones exist | control reserve | 8 per app | the oldest drops; an envelope wrapped to it gets `409 stale_key` with its kid in `unknown_kids` |
| Renewed certificate (3.8) | until the app's record carries it, or a newer `cert.put` | control reserve | one per app | replaced |
| Departure, revoked app | its record, receive key records, key bundles, cursor and last-seen time until the signer purges it from `removed` (it is in neither list), after its rotation, and it owns no open or `unknown` attempt; its App ID with its revocation or departure time, and the kids of its receive key records (spec 3.6), for good, the App ID exported as its `app` part (10.3), whose `receive_keys` a purged app no longer holds, so a move doesn't carry its kids yet; likewise each App ID an enrollment names in `revoked_apps` (3.7), dated by the enrollment | app limit, until purged; then nothing | - | - |
| Cursor, last-seen time | while the app is kept | control reserve | one per app | - |
| Push registration and its push key (8.1) | while the app is current; replaced by a new registration | - | one per app, 8 handles | `400` |
| Queued webhook (8.2) | until delivered, or after its last attempt, at most 1 minute after its entry; it goes with its registration, and with its handle | - | one per handle of each target app for each `notify` entry, so 8 per app per entry and 8 per relay host per entry; `notify_per_min` bounds the entries per sender identity | - |
| Full-bundle request (7.4.11) | until the stored parts cover every data epoch from 1 to the current one | control reserve | one per app | the first time is kept |
| Evidence uploaded in a move (7.4.14) | until the `identity.json` naming the service arrives, or an abort | - | the proofs apps upload | duplicates are kept once |
| Peer copy of `identity.json` | the newest per identity | peer limit | `max_peers` 10,000 | the least recently delivered drops, never the one just delivered; its sender gets `409 identity_needed` and delivers it again. Strangers' copies (neither contact nor conversation) drop first; a stranger's new copy never pushes out an admitted identity's, it drops itself instead; a dropped admitted copy leaves a floor (version, generation, body hash, 7.4.5) until a copy is held again, one per admitted identity, bounded by the list limits. Floors are exported as `peer_floor` parts (10.3), so the next service keeps them |
| Enrollment answer | one per distinct enrollment | - | `max_enrollments` 16 per account | the oldest drops; that enrollment again gets the same answer, built again |
| Staged import (Section 10) | until the `identity.json` naming the service arrives, or an abort | import limit | `max_import_bytes` 4 GiB; `max_chunk_bytes` 1 MiB per chunk | `POST /import` is `413 too_large`; the signer aborts the move (10.6) |
| Uploaded head (7.4.14) | until the `identity.json` naming the service arrives, or an abort | - | the newest per app | replaced |
| Divergent upload (spec 12.6) | until a newer write at the service | - | `max_divergent_uploads` 8 per record | further uploads are dropped |
| Rate-limit window | the current minute | - | - | - |

**Erasure** (7.4.16, spec 12.7). Every kind in this table, "for good" ones included, goes with the account when the signer erases it, and so do the key's mark (7.3 step 10) and the failed-authentication counts (9.4).

**Forgetting deleted keys** (spec 10.3). The service may forget a deleted key once nothing refers to it: its current write is the delete; the cursor of every app the held `identity.json` lists, listed or in an open renewal and neither revoked nor departed, is at or past the delete's `seq`, lagging or not, an app with no cursor here yet, or not registered here yet, holding every key; no divergent upload names the key; and the account isn't frozen (the export carries it). A forgotten key's delete keeps only its chain stub. The service may forget a key, and need not: an account no request reaches keeps its deleted keys, with no value, only the key, its collection and policy, and the delete. (The reference prototype: at the minute's sweep below, at most 256 keys a minute, the oldest deletes first, up to the lowest cursor the key waits for. Not yet: the frozen-account condition, which has nothing to check while freezes aren't served; it comes with the cooperative move.) Every such app is waited for because nothing else would tell it of the delete: a listing shows the records the service holds, not one it forgot, so an app that hadn't read the delete would keep the record live; and after a provider loss an app that hasn't registered yet may upload its copy of the record, which a key forgotten here would let back in (7.4.14). An app that stops reading only delays forgetting, which is the service's choice, not a promise; the signer's removal of that app frees its keys.

**Sweeps.** Tombstones and failed claims past their deadline plus the reconciliation window, or pinned to no deadline and past their last entry plus `max_claim_age_ms`, are deleted at requests to the account, with trusted time only and by the time base (7.3 step 4); checkpoints are signed at the same time (lagging marks and `missed` items come at the requests 7.4.4 names); then the stubs behind the latest checkpoint that the chain stub row lets go are dropped, oldest first, and with them each batch record whose proofs are gone and none of whose stubs is kept (6.4 step 5). One request reads at most `retention_per_request` stubs for this and drops no more, oldest first, so an account long unswept catches up over several requests. None is dropped, and no checkpoint signed, while the account is staged or frozen, so an export carries the stubs kept when it froze (12.5) (the reference prototype: not yet for a frozen account, since it serves no freeze; the check comes with the cooperative move). At most once a minute of service time, also at a request, the service forgets deleted keys that may be forgotten (above), and drops invite codes that expired or ran out, batch proofs past `batch_proofs_ms` (the whole record when none of the batch's stubs is kept any more), past rate-limit windows and flags beyond `max_flags`. An account no request reaches isn't swept: what these sweeps delete goes at the minute's sweep at a later request, one with trusted time and a caller that has verified (7.3 step 4), and nothing here promises an earlier time. Revoked and departed apps are purged, down to their App ID, revocation or departure time and kids, which stay for good, at the request that makes the last of their retention row's conditions hold: the `identity.json` delivery that leaves them in neither list, the revocation of an app the newest document lists in neither, or the batch or recovery upload that resolves the last open or `unknown` attempt they own; retired receive key records beyond the limit go when a new one is registered; peer copies and enrollment answers beyond their limits go when a new one is added.

### 9.2 Limits and their names

| Name | Default | Meaning | Announced at enrollment (3.7) |
|---|---|---|---|
| `app_limit` | 32 | most apps in `identity.json`, never above 255 | yes |
| `max_envelope` | 65536 | envelope cap in bytes | yes |
| `max_sealed_value` | 262144 | sealed value plaintext cap in bytes | yes |
| `max_batch` | 8 | entries per batch | yes |
| `quota_bytes` | 67108864 | inbox quota in bytes | yes |
| `record_quota_bytes` | 67108864 | storage quota in bytes | yes |
| `entry_overhead_bytes` | 256 | bytes each inbox entry counts besides its envelope | not yet |
| `max_record_keys` | 100000 | live shared record keys | not yet |
| `max_claims` | 1000000 | live claims plus tombstones | not yet |
| `max_attempts_per_claim` | 64 | attempts on one claim | not yet |
| `open_attempts_per_app` | 1000 | attempts one app holds `open` or `unknown` at once (6.8) | not yet |
| `claim_share_percent` | 25 | the share of `max_claims` that the claims one app created, live and tombstones, may hold: `floor(max_claims * claim_share_percent / 100)` claims (6.8); 100 turns it off | not yet |
| `max_claim_age_ms` | 34560000000 | how long a finished or failed claim pinned to no deadline is kept after its last entry (400 days); an operator may raise it but not lower it, since apps judge a missing claim by it (6.8) | not yet |
| `max_contacts`, `max_conversations`, `max_deny` | 100000 each | list entries | not yet |
| `max_invite_codes` | 1000 | live invite codes | not yet |
| `max_connect_pending` | 1000 | the highest `max_pending` a policy may name | not yet |
| `max_retired_keys` | 8 | retired receive key records per app | not yet |
| `max_peers` | 10000 | peers' `identity.json` copies | not yet |
| `max_enrollments` | 16 | enrollment answers kept | not yet |
| `max_flags` | 1000 | flagged senders kept | not yet |
| `batch_proofs_ms` | 2592000000 | how long a batch's proofs, and at least its ID, are kept (30 days); an operator may raise it but not lower it, since apps compare batch IDs over 30 days (6.6) | not yet |
| `ops_per_min` | 3000 | batches with an ordinary operation or a repeatable control mutation, per app per minute | not yet |
| `control_per_min` | 60 | batches with a repeatable control mutation, per app per minute (6.4) | not yet |
| `cursor_hold_ms` | 2592000000 | how long an app's cursor holds a chain stub back: a stub this old (30 days) may be dropped behind a checkpoint even if a cursor hasn't passed it (7.4.4) | not yet |
| `max_divergent_uploads` | 8 | divergent uploads per record | not yet |
| `uploads_per_app_per_hour` | 60 | `POST /recovery/upload` calls per app per hour (7.4.14) | not yet |
| `max_handover_parts` | 128 | envelopes of the one hand-over an account holds (7.4.17), and of the signer's backup (3.13): the bound of 3.12 with room; fixed | not yet |
| `max_import_bytes` | 4294967296 | bytes of one staged import; it covers the export of an account at every default limit, with room for the stubs and batch IDs it keeps (Appendix A34) | yes |
| `max_chunk_bytes` | 1048576 | bytes of one export chunk; fixed | not yet |
| `sender_per_min` | 120 | appends per sender identity per minute | not yet |
| `sender_app_per_min` | 120 | appends per sender app per minute | not yet |
| `invite_reads_per_min` | 30 | directory reads and peer deliveries with one invite code per minute | not yet |
| `auth_failures_per_source_per_min` | 60 | failed authentications per network source (an IPv4 address or an IPv6 /64) per minute, at all accounts together; the only limit before a request verifies (7.2) | not yet |
| `stranger_per_min` | 60 | connect requests and peer deliveries of senders admitted only because connect requests are on, per account per minute | not yet |
| `sender_share_percent` | 25 | the share of `quota_bytes` one sender identity's unread entries may hold (9.3); 100 turns it off | not yet |
| `max_invite_uses` | 100 | the most uses an `invite_code.put` may name (6.2); more is `400` | not yet |
| `identity_reads_per_min` | 6000 | public reads of `identity.json` (7.4.15) per account per minute, from all sources together: the backstop above the per-source limit | not yet |
| `identity_reads_per_source_per_min` | 60 | public reads of `identity.json` per network source (an IPv4 address or an IPv6 /64) per account per minute | not yet |
| `list_page` | 1000 | most records per `GET /records` page (7.4.9) | not yet |
| `max_page_bytes` | 8388608 | most bytes of the items of one feed page (7.4.4) and of the record views of one `GET /records` page (7.4.9), 8 MiB; a page still holds its first item, or its first batch, whatever its size | not yet |
| `checkpoint_behind` | 1000 | chain items that may go before the service signs a checkpoint, or with `checkpoint_at_head` chain items added since the last one (7.4.4) | not yet |
| `retention_per_request` | 1000 | chain stubs one request reads and drops for chain stub retention, oldest first (9.1) | not yet |
| `chain_retention` | on | sign checkpoints and drop chain stubs by the chain stub row (9.1, 7.4.4); off keeps every stub and signs no checkpoint | not yet |
| `checkpoint_at_head` | off | sign each checkpoint at the newest chain item, and drop behind it only the stubs the chain stub row lets go (7.4.4) (the reference prototype: off by default too) | not yet |
| `mark_lagging` | on | mark lagging apps (7.4.4) | not yet |
| `trusted_time.required` | on | require trusted time: without it, refuse what depends on time with `503 unavailable` (7.3). A production service has trusted time (spec 10.1) (the reference prototype: off, since it has no time source of its own, and its tests give it samples) | not yet |
| `trusted_time.drift_ppm` | 100 | drift bound of the monotonic clock, parts per million (7.3) | not yet |
| `trusted_time.max_sample_age_ms` | 86400000 | the oldest time sample that still gives trusted time (24 hours) | not yet |
| `trusted_time.max_uncertainty_ms` | 300000 | the largest uncertainty trusted time may have (5 minutes) | not yet |
| `trusted_time.max_disagreement_ms` | 300000 | the most the wall clock may differ from trusted time before the service uses trusted time and alerts (5 minutes) | not yet |
| `notify_per_min` | 20 | appends with `notify` per sender identity per minute | not yet |
| `connect_per_min` | 5 | connect requests per sender identity per minute | not yet |

"Not yet": a limit services don't announce yet (the reference prototype: none of these); until a service does, clients assume its default. A service that announces one names it as here, as a `limits` member (Appendix A5).

### 9.3 Quotas, per-kind limits and the control reserve

- **Two quotas.** The **inbox quota** counts inbox entries, each with `entry_overhead_bytes` beside its envelope, so it bounds their number as well as their bytes; it blocks only appends. The **storage quota** counts current shared record values; it blocks only a `record.put` that makes them larger, so a deletion or a rewrite that doesn't grow always passes. They are separate, so a full inbox never blocks the record writes that drain it.
- **Each sender's share** (spec 6.3). The inbox quota is the identity's, so one admitted sender within its rate limit could fill it while the identity's apps are offline, and every other sender would then get `429`. So one sender identity's unread entries hold at most `sender_share_percent` of the inbox quota (a quarter by default): an append past it gets `429 quota_exceeded` with `current.limit` `sender_share`, for that sender only, retried as `inbox` is. Unreadable entries and `missed` items, which the service makes itself, count for no sender.
- **Per-kind limits** refuse only the write that would create something new: a live record key (a new one, or a deleted one written again), an `attempt` on a new claim key or beyond the limit on one, or beyond its app's share of the claim limit or its open attempts (6.8; an `attempt` beyond several of these gets the first of `claims`, `claim_share`, `attempts` and `open_attempts`, in that order), a contact, a conversation entry, a deny list entry, an invite code. A write to an existing object always passes, and so do outcomes, deletions and removals.
- **Receivers never stall** (spec 8.2): an app whose record write for an entry gets `429 quota_exceeded` for a per-kind limit or the storage quota stores the entry locally, moves its cursor past it, and writes the record once room frees (5.1).
- **Control reserve.** Control operations count against neither quota and no per-kind limit: cursor moves, deletions and removals, claim outcomes (`done`, `failed`, `unknown`), `app.put`, `receive_key.put`, `key_bundle.put`, `cert.put`, `identity.json` deliveries, revocation, leave, freeze, unfreeze, the export and the import, and recovery uploads. What they create is bounded as follows; the operator plans that capacity apart from the quotas:
  - an unchanged `app.put`, `receive_key.put`, `cert.put` or `key_bundle.put` creates nothing (6.4): a batch made only of them is a no-op, or with `cursor.set` it is checked and then moves only the cursor;
  - a repeatable control mutation (an `app.put` or `receive_key.put` that changes what the service holds, a delete or removal of something that isn't there before the batch, 6.4) counts against its app's control rate, 60 batches a minute, and its operation rate (9.4), so chain stubs grow at most that fast, and are dropped behind a checkpoint, oldest first, which no cursor holds back from a stub 30 days old (7.4.4);
  - batch proofs go after 30 days, and a batch record, ID included, goes once its proofs are gone and none of its stubs is kept (6.4 step 5);
  - receive key records, key bundle parts, cursors and push registrations are bounded per app (9.1).
  - recovery uploads come at most `uploads_per_app_per_hour` an hour per app, each within its body cap (7.1, 16 MiB). Each leaves at most one current write and `max_divergent_uploads` divergent uploads per record key, list entries up to `max_contacts` and `max_deny`, and one `upload` transition.

  Cursor moves, claim outcomes on existing attempts, deletes and removals of something present, and revocation and leave are never rate-limited, so a full inbox can still be drained, an existing attempt reconciled and an abusive app revoked.
- **`429 quota_exceeded`** names the full budget in `current.limit`: `inbox`, `sender_share`, `storage`, `record_keys`, `claims`, `claim_share`, `attempts`, `open_attempts`, `contacts`, `conversations`, `deny`, `invite_codes` or `connect_requests`. It carries no `retry_after`. Retry per limit (7.6): `inbox` and `sender_share` as the recipient's apps read their feed; `storage` after deletions; `record_keys` after deletions: it counts live keys only, so a delete frees room at once, whether or not the service forgets the key later; `connect_requests` once the recipient answers pending requests, which the sender can't see, so a sender asks again much later or not at all; `open_attempts` once the app's own attempts are resolved; `claim_share` once claims the app created are deleted, at their deadline plus 30 days or, without one, 400 days after their last entry; the others after a deletion or removal frees room. Vectors: the `quota` steps of `claims.json` hold the `open_attempts` and `claim_share` answers. An example (the reference prototype: its answer when the claim limit is full, which no vector holds):

  ```json
  {
    "code": "quota_exceeded",
    "message": "6.3: the identity holds its limit of claims",
    "current": {
      "limit": "claims"
    }
  }
  ```

### 9.4 Rate limits

| Limit | Counts | Per | Default | Answer |
|---|---|---|---|---|
| Appends | every `POST /inbox`, an own app's included | sender identity | `sender_per_min` 120 a minute | `429 rate_limited` |
| Appends per app | every `POST /inbox` from an app of another identity | sender app | `sender_app_per_min` 120 a minute | `429 rate_limited` |
| Invite-code reads | `GET /directory` and `PUT /peers` admitted by an invite code | invite code | `invite_reads_per_min` 30 a minute | `429 rate_limited` |
| Strangers | `POST /connect`, and `PUT /peers` admitted only because connect requests are on, from all senders together | account | `stranger_per_min` 60 a minute | `429 rate_limited` |
| Notifying appends | appends with `notify` set, besides the above | sender identity | `notify_per_min` 20 a minute | `429 rate_limited` |
| Connect requests | `POST /connect` | sender identity | `connect_per_min` 5 a minute | `429 rate_limited` |
| Failed authentications | requests answered `401` (7.2 Order), checked before any signature work; counted per claimed caller too, for monitoring only | network source (an IPv4 address or an IPv6 /64), all accounts together | `auth_failures_per_source_per_min` 60 a minute | `429 rate_limited` |
| Public `identity.json` reads per source | `GET /identity` (7.4.15), unauthenticated | network source (an IPv4 address or an IPv6 /64) per account | `identity_reads_per_source_per_min` 60 a minute | `429 rate_limited` |
| Public `identity.json` reads, backstop | the same, a source's refused reads not counted | account, all sources together | `identity_reads_per_min` 6,000 a minute | `429 rate_limited` |
| Operations | `POST /ops` batches from an own app carrying an ordinary operation or a repeatable control mutation (6.4) | app | `ops_per_min` 3,000 a minute | `429 rate_limited` |
| Control mutations | `POST /ops` batches from an own app carrying a repeatable control mutation (6.4) | app | `control_per_min` 60 a minute | `429 rate_limited` |
| Recovery uploads | `POST /recovery/upload` (7.4.14) | app | `uploads_per_app_per_hour` 60 an hour | `429 rate_limited` |

- **Windows** are fixed minutes of service time, and fixed hours for recovery uploads; the failed-authentication limit, kept across accounts, uses fixed minutes of the time base (7.2). A limit of n a window takes n requests in a window and refuses the next. `retry_after` in the body and the `Retry-After` header give the seconds to the next window.
- **Flags.** Each refusal by a rate of the sender's own counts a hit for the sender identity: an append's (per sender identity, per sender app, notifying) and a connect request's `connect_per_min`. A rate the whole account shares, `stranger_per_min`, counts none, and no other refusal does; nor does any refusal of an append from one of the account's own apps, which is no sender of another identity; one with at least 3 hits (`flag_after`) shows in `GET /allow` `flagged` (7.4.6). The service never blocks a sender on its own (spec 7); apps apply the spam rule (5.1). Operation refusals aren't flagged.
- **Where they apply.** For an append, after admission, the listing and the size checks, before the targets and the quota (7.4.3). For a batch, after the retry and generation checks, before the conditions (6.4). Every limit keyed by a caller, an app, an invite code or an account applies only to a request that has verified. Before that only the failed-authentication limit applies, by network source (7.2), and the public read's limits (7.4.15), the one call without authentication.

### 9.5 The 429 answers of each call

| Call | `429 rate_limited` | `429 quota_exceeded`, `current.limit` |
|---|---|---|
| `POST /inbox` | appends, appends per app, notifying appends | `sender_share`, `inbox`; `conversations` for an append admitted by an invite code |
| `POST /connect` | connect requests, strangers | `connect_requests`, while `max_pending` requests are pending, to a sender with none (7.4.7) |
| `POST /ops` | operations, control mutations | `record_keys` (a `record.put` creating a key), `storage` (a `record.put` growing the stored bytes), `claims`, `claim_share`, `attempts` and `open_attempts` (`attempt`), `contacts` and `conversations` (`allow.put`), `deny` (`deny.put`), `invite_codes` (`invite_code.put`) |
| `GET /directory` | invite-code reads | never |
| `GET /identity` | public reads | never |
| `POST /recovery/upload` | recovery uploads | never |
| every other call | never | never |

Any call that authenticates can also get `429 rate_limited` before its signature is checked, once its network source has had `auth_failures_per_source_per_min` failed authentications in the current minute (7.2).

### 9.6 Dropping is safe

- A sender whose peer copy dropped gets `409 identity_needed` at its next append and delivers its `identity.json` again, never lower than the dropped copy's floor (7.4.5).
- An enrollment repeated after its answer dropped gets the same answer, since the answer is built from the account and the enrollment alone.
- A batch retried within 30 days gets its original answer. After that its proofs are gone and it gets `409 conflict`, as does another batch carrying its ID, for as long as the service holds the ID: while any of the batch's chain stubs is kept. An app's verifier takes a batch for a repeat only when `t_new - t_old < 30 days`, by the `server_time` of each batch's first stub (6.6), and the service holds every ID at least that long, so no batch the service accepts makes an honest chain look rolled back. The service forgets the ID once both have ended, when none of the batch's stubs is kept; by then no app compares it. Requests are accepted only within 5 minutes of their signed timestamp, so nobody can replay a batch, list operations included, which carry no expected version and could otherwise undo a later change: it can come again only in a new request, which only its app can sign, and apps resend a batch only in their immediate retries.
- An envelope to a dropped retired receive key gets `409 stale_key`, and the sender seals it again.
- A tombstone or failed claim deleted 30 days after its deadline is safe because no compliant app can start an attempt once the service's time reaches the pinned deadline (6.8): every `attempt` carries the same deadline. This assumes the first `attempt` pinned the deadline every app computes from what created the obligation, such as a `tasks.assignment`; an app that finds an earlier pin keeps its evidence to its own deadline plus 30 days and treats the obligation as doubtful (6.8). The 30 days are for late evidence (6.8 Failed claims). So a claim with a short deadline loses its tombstone 30 days after that deadline, rather than 400 days after its last entry.
- A finished or failed claim pinned to no deadline, deleted 400 days after its last entry, leaves its obligation FREE at the service, so a re-sent copy of what created it could be attempted again. No compliant app does: it never attempts an obligation whose record shows it done, and it never deletes its record of a done obligation without a deadline (6.8). The trade-off: after 400 days the app's record, not the claim, prevents a second attempt, at the cost of one record per obligation without a deadline for the identity's life. Claims with an open or `unknown` attempt are never deleted by age, so no unresolved obligation is lost, and an app keeps its evidence of such a claim as long as the service may keep the claim (6.8).
- A forgotten deleted key is safe because a record created there again gets a newer version than any the key had (6.2), every app that may still read or upload the record has read past its delete, and a `record_version` condition of `{0, 0}` matches a forgotten key as it matches a held delete (6.3).
- Chain stubs dropped behind a checkpoint are safe because every current app's cursor has passed them, or they are 30 days old. An app whose verified chain item is less than 30 days old therefore still has the stubs after it, and reports a rollback if they are missing; an app more than 30 days behind, or restored from a backup, can't verify continuity across them and continues from the checkpoint head only as an explicit recovery in reconcile mode (7.4.4). A cooperative move drops none of them: the export carries every stub O keeps (10.2). In a move N ignores such an app's head when it is older than the checkpoint, and the app uploads none while its continuity is unverified (7.4.14, 10.5).

## 10. Export and import

Spec 12.5 step 3 and Abort. The frozen old service O exports the account as a manifest and chunks; the staged next service N fetches the chunks from O under the signer's export transfer (3.11), or the signer moves them as a fallback, and N activates the import in one step. Every step can be repeated with the same result, so an interrupted signer resumes by asking N what it lacks.

### 10.1 Overview

1. After the freeze (7.4.13) the signer reads O's manifest (`GET /export`) and checks it: O's service key signed it, and it names the signer's freeze.
2. It signs the export transfer (3.11) and starts the import at N with the manifest, the signed freeze and the transfer (`POST /import`). N fetches each chunk it lacks from O (`GET /export/chunks/{chunk_id}` under the transfer, 7.2), checks its length and hash against the manifest and stores it, then answers with the chunks it still lacks (10.4).
3. Fallback, for each chunk still missing (N couldn't reach O, or stopped at a failure): the signer fetches the chunk from O itself (`GET /export/chunks/{chunk_id}`), checks its length and hash against the manifest, and stores it at N (`PUT /import/chunks/{chunk_id}`), in any order, as often as needed. Without a transfer in the start, N fetches nothing and the signer moves every chunk.
4. It activates the import (`POST /import/activate`). N rebuilds and verifies the state, then makes it live.
5. It delivers the `identity.json` naming N, generation g+1, and then publishes it (spec 12.5 step 4). N refuses that document (`409 conflict`) before the activation.

After the freeze, apps read O's feed to its end (its pages carry the freeze, 7.4.4), then upload to N their newest signed head and the evidence they hold (7.4.14); the activation checks the chain against each head and the state against the evidence (10.5). An abort (10.6) cancels at both services, N first.

**What the export holds:** the account's state, as parts (10.3): its `identity.json`, sequence and directory counters, every chain item's stub with its document while O keeps it, pending inbox entries, apps (records, receive key records with their `seq`s, key bundles, cursors, last-seen times, departures, renewed certificates), live claims and tombstones, shared records with the transition proof of each current write, batch records (IDs, operation hashes and times, not their proofs), contacts, conversation entries, the deny list, invite codes, connect requests, flags, peers' `identity.json` copies, the floors dropped peer copies left, and divergent uploads. Each operation travels once, since a shared record names the chain part that holds its operation instead of carrying it again, and no batch proofs travel: they serve only a retry at O, and N couldn't serve them as its own. A record's proof does travel, since it dates the record's current write for readers (spec 10.3), who check it with its generation's key, O's or one `service_keys` lists (3.3). **Not exported:** O's service key (N has its own), enrollment answers, rate-limit windows, push registrations (apps register again with N, spec 9), peer delivery order and staged state. N rebuilds its kid index and reachable apps from the parts.

### 10.2 Manifest

A signed document (2.2) under O's service key, label `pubky-switch/v1/export-manifest`, signed over `lp(label, identity, body)`. Its **manifest hash** is its document hash.

| Field | Type | Req | Notes |
|---|---|---|---|
| `v` | int | yes | 1 |
| `kind` | string | yes | `pubky-switch.export_manifest` |
| `identity` | pubky | yes | the account's identity |
| `freeze_hash` | `b64(32)` | yes | the document hash of the signed freeze this export belongs to |
| `generation` | int | yes | g, the exported generation |
| `next_generation` | int | yes | g+1, as the freeze names it |
| `last_time` | time | yes | the last service time O committed for the identity when it built the export, so at or after the time of the freeze transition (the head's item), its `at`, which N checks (10.5); N continues from it (spec 10.1) |
| `head` | signed head | yes | O's head at the end of the export, at the freeze's own chain item: the `freeze` transition (6.5) of the freeze this export belongs to, which N checks (10.5) |
| `checkpoint` | `signed head \| null` | yes, always written | a head O signs for the newest stub it dropped, at the `seq` and chain hash it keeps for it (9.1). O drops stubs oldest first, so that is the chain item just before the oldest stub it keeps, and its chain hash is that stub's `prev_chain_hash`; the `chain` parts start at that stub, from this chain hash instead of 32 zero bytes. `null` when O keeps the whole chain: they start at the first item. It lies at a batch's last chain item or at an item of no batch (7.4.4), so the `chain` parts never begin inside a batch. It needn't be O's latest checkpoint (7.4.4), which may lie ahead of stubs O keeps. An export leaves out none of them, so every app whose stubs O's cursor rule keeps finds them at N |
| `parts` | int | yes | the number of parts |
| `bytes` | int | yes | the sum of the chunks' `len` |
| `chunks` | `array<object>` | yes | the chunks in part order, below |

A chunk reference:

| Field | Type | Notes |
|---|---|---|
| `id` | string | opaque, used in the chunk URLs (the reference prototype: the chunk's index in five decimal digits, `00000`) |
| `len` | int | the chunk's byte length, at most `max_chunk_bytes` (1 MiB) |
| `hash` | `b64(32)` | `hash(chunk bytes)` |
| `first`, `last` | int | the indexes of its first and last part; the first chunk starts at 0, each next one at the previous `last` + 1, and the last ends at `parts` - 1 |

- **Once per freeze.** O builds the export at the first `GET /export` or chunk fetch after the freeze and keeps it while frozen: every retry gets the same manifest bytes and the same chunk bytes. An unfreeze discards it.
- **Packing.** Parts go into chunks in order, each chunk up to O's chunk size (1 MiB by default; the reference prototype: 64 KiB in its tests); a part larger than that gets a chunk of its own. Every part fits one chunk of 1 MiB with the chunk's own members (10.3 Part sizes), so every account the other limits allow can move.
- **Vectors**: `export.json` is a complete export of alice's account, frozen right after `chain.json`'s last item, with a manifest signed with the fixed service key of `keys.json`. It activates under 10.5 at a next service enrolled with her current `identity.json` (version 3) whose trusted time is the freeze's. Its one chunk holds the meta part; the chain items of `chain.json`, the superseded `record.put` of `seq` 6 as a stub only; the freeze transition at `seq` 10, which the head names; an `app` part for each app the `identity.json` lists; the live claim of `seq` 7 and its one entry, a `claim_entry` part; the record at (1, 8), its `op` by reference; and a `batch` part, without proofs, for each of the three batches the stubs name. `last_time` is the freeze transition's time. A real service draws each account's key at random (10.7), so this is the only export with a reproducible signature.

### 10.3 Chunks, parts and the export calls

A **chunk** is the exact bytes of one JSON document (1.1):

| Field | Type | Notes |
|---|---|---|
| `v` | int | 1 |
| `kind` | string | `pubky-switch.export_chunk` |
| `index` | int | its position in the manifest's `chunks` |
| `first` | int | the index of its first part, as the manifest says |
| `parts` | `array<part>` | consecutive parts |

A **part** is an object whose `part` member names its kind; the other members follow. N refuses an unknown kind (`400`).

**Part order.** Each kind is a group of its own, and the groups come in this order: `meta` (exactly one, first); `chain` (by `seq`); `entry` (by `seq`); `app` (by `app_id`), each followed by its `key_bundle` parts (by `first_epoch`); `claim` (by `claim_key`), each followed by its `claim_entry` parts (by `step`); `tombstone` (by `claim_key`); `record` (by `record.key`); `batch` (by `id`); `contact` (by `pubky`); `conversation` (by `pubky`); `deny` (by `pubky`); `invite_code` (by `code_hash`); `connect` (oldest first, by `at`); `flag` (by `pubky`); `peer` (by the `identity` its document names); `peer_floor` (by `identity`); `divergent` (by `key`, then `index`). So `claim` and `tombstone` are two groups, and so are `contact`, `conversation` and `deny`. Within a group a `seq` sorts as a number, and every other key by the bytes of its text as the part writes it (the base64url or z-base-32 string, compared as ASCII), not by the bytes it decodes to; keys ascend strictly, so each appears once. An app's `key_bundle` parts come right after its `app` part, before the next app's, with `first_epoch` strictly ascending; a live claim's `claim_entry` parts right after its `claim` part, with `step` strictly ascending; and the `divergent` parts of one record one after another, `index` 0, 1, 2 and so on. `connect` parts are in non-decreasing order of `at`, compared as instants (1.6). N refuses parts out of this order, a `key_bundle` or `claim_entry` part that doesn't follow its app's or claim's part, and a record's `divergent` parts whose indexes don't run 0, 1, 2 in order or that number more than 8 (`400 bad_request`, 10.5).

Parts carry the service's own state in this form (the reference prototype: its own): times in Unix milliseconds in members named `_ms`, durations in seconds in members named `_s`, and objects with the service's bookkeeping. A member without such a suffix that holds a time, such as `at` and `expires_at`, is a time of 1.6, an RFC 3339 string.

Every listed member is present, except where the table says otherwise: a member marked "or `null`" may also be absent, which reads as `null`, and one marked "absent otherwise" is present only in the case named.

| Part | Members |
|---|---|
| `meta` | `identity` (the newest signed `identity.json`), `generation` (g), `seq` (the last `seq` given out, entries and chain items), `directory_version`, `apps_version`, `app_added_at` (each app reachable now, current with a receive key (7.4.10), by App ID, to the `apps_version` at which it became reachable; at most the app limit, since the service keeps no entry for an app that isn't reachable) |
| `chain` | one for every stub O keeps, from the oldest (10.2): `seq`, `stub` (6.6), `item_type` (`op`, `identity` or `service`), `doc` (the signed document, or `null` once O dropped it, 7.5), `context` (the invite code context of a service-written conversation entry, or `null`) |
| `entry` | `seq`, `sender`, `cert` (the sender app's certificate), `accepted_at_ms`, `context` (or `null`), `envelope` (`b64`; empty for an unreadable entry), `targets` (App IDs), `result` (the original append answer `{ entry_id, accepted_at, directory_version }`, which a retry by content gets, 7.4.3), `unreadable` (bool), `missed` (`{ entries, from_ms, until_ms }` for a `missed` item, 7.5; absent otherwise) |
| `app` | `app_id`, `record` (signed app record, or `null`), `record_seq` and `record_at_ms` (its `app.put`, or `null`), `receive_keys` (pairs `[signed receive key record, seq]`, oldest first, the last current), `cursor` (a `seq`, 0 before the app's first cursor move), `last_seen_ms`, `revoked_at_ms`, `departed_at_ms`, `departure_epoch` (each `int` or `null`), `rotated` (bool), `renewed_cert` (`[signed certificate, seq]` of a `cert.put` the record doesn't carry yet, or `null`), `lagging` (bool), `keys_through` (`int` or `null`), `full_bundle_requested_ms` (`int` or `null`) (7.4.12). A purged app's App ID is exported the same way, as its tombstone: `revoked_at_ms` or `departed_at_ms` set, `record` and `record_seq` `null`, no receive keys, and no `key_bundle` parts (9.1). The app's stored key bundle parts are `key_bundle` parts of their own, right after this one; an `app` part with a `key_bundles` member, as an earlier form carried them, is refused (`400`), whatever the member holds, so an earlier exporter's parts never vanish unseen |
| `key_bundle` | `app_id`, `bundle` (one key bundle part stored for that app, 3.5), `seq` (its `key_bundle.put`), `first_epoch`, `last_epoch`: one part for each part the service stores for the app, so an app offline through many rotations never makes one export part large |
| `claim` | `claim_key`, `claim`: `step`, `attempts` (below), `current` (the current attempt ID, or `null`), `settled` (bool), `divergent` (bool), `pinned_deadline` (absent before any attempt, `null` for a pin to "none", else Unix milliseconds), `rebuilt` (bool: rebuilt from uploads after a provider loss), `creator` (the App ID whose `attempt` created the claim, 6.8: the owner of its first attempt, `null` only for a claim without one), `last_entry_ms` (the service time at which its last entry was applied, or `null`; for a claim not rebuilt, the `server_time` of its last `claim_entry` part's proof stub). N checks both (10.5). Its entries are `claim_entry` parts, right after it; a `claim` part with an `entries` member is refused (`400`), as an `app` part with `key_bundles` is |
| `claim_entry` | `claim_key`, `step` (the claim's step before the entry), `seq` (its chain item), `op` (the signed claim entry) and `proof` (its transition proof), both always present, and `cert` (the writer's certificate the service checked the entry against, or `null` when it is the one the record in the writer's `app` part carries, as in a `record` part; 10.5): one part for each entry of the live claim, since each proof carries the claim view and a claim near its attempt limit would not fit one part |
| `tombstone` | `claim_key`, `tombstone`: `step`, `attempts` (below), `deadline_ms` (the pinned deadline, or `null`), `creator` and `last_entry_ms` (as in `claim`; without a deadline the tombstone goes `max_claim_age_ms` after `last_entry_ms`, 6.8). N checks `creator` against the tombstone's first attempt, and takes `last_entry_ms` as written, since a tombstone keeps no entries (10.5) |
| `record` | `record`: `key`, `collection`, `read_scope`, `write_scopes`, `generation`, `version` (the `seq` of its current write in `generation`, 6.2), `op` (the signed `record.put` of the current version, with its sealed value, or `null` when the `chain` part at `seq` carries it; always carried for a record at or behind the `checkpoint` and one taken from a recovery upload. An exporter writes `null` there; N takes a part that carries it anyway when it is the chain part's operation byte for byte, and refuses another one, `409 conflict`), `seq` (the chain item at this service that holds `op`: equal to `version` for a write made here, and the upload's `seq` for a record taken from a recovery upload), `deleted`, `writer` (App ID), `from_upload` (bool, set by a recovery upload), `upload_base` (`[generation, version]`, the uploaded version that writes at N built on, 7.4.14, or `null`), `size` (its bytes for the storage quota, 9.1: its `ct` decoded, 0 for a delete), `cert` (the writer's certificate the service checked the write against, 7.4.9, or `null` when it is the one the record in the writer's `app` part carries), `proof` (the transition proof of the current write that O keeps with the record, 7.4.9, signed by O or, after an earlier move or key change, by the service of the write's generation; absent for a record taken from a recovery upload, and required otherwise, 10.5). N derives every member but `op`, `seq`, `upload_base`, `cert` and `proof` from the operation and checks they match (10.5) |
| `batch` | `id`, `record`: `ops_hash` (`hash(lp(signed document bytes of each operation, in order))`, which recognizes a retry, 6.4), `proofs` (always empty in an export: N answers a retry of the batch as one whose proofs are gone, 6.4; a batch part with proofs is refused, `400`), `at_ms` |
| `contact`, `deny` | `pubky` |
| `conversation` | `pubky`, `written_by` (App ID or `service`), `code_hash` and `context` (when an invite code created it; absent otherwise), `at` (time, 1.6: when the entry was written), `last_used` (time of the last append it admitted; absent until one) |
| `invite_code` | `code_hash`, `expires_at`, `expires_at_ms` (ignored on import: N recomputes it from `expires_at`), `max_uses`, `uses`, `context` (any JSON value, `null` included), `written_by` (the App ID that registered it) |
| `connect` | `pubky`, `at` (time, 1.6: when the request arrived) |
| `flag` | `pubky`, `hits` |
| `peer` | `doc`: the signed `identity.json` of another identity |
| `peer_floor` | `identity` (pubky), `version`, `generation`, `body_hash` (`b64(32)`): the floor a dropped peer copy left (7.4.5, 9.1). O holds no floor for an identity whose copy it holds, so a `peer_floor` beside a `peer` part of the same identity is refused (`400`). A floor is O's word, like the admission lists: one set too high makes N refuse that identity's older deliveries, as O would have |
| `divergent` | `key`, `index` (its place among the record's divergent uploads, from 0), `upload`: one uploaded signed `record.put` that conflicts with the record (spec 12.6). One part for each divergent upload, at most 8 for a record (9.1) |

An **attempt**, in claims and tombstones: `attempt_id`, `owner` (App ID), `outcome` (`open`, `done`, `failed` or `unknown`), `opened_at_ms`, `orphan_after_s`, `possibly_duplicate`, `duplicate`, `deadline_ms` (or `null`), `from_upload` (bool: rebuilt from a recovery upload, always orphaned), `resolved_by` (the App ID that wrote its outcome, or absent).

Deleted record keys are exported while the account is frozen (9.1), so N holds every delete an app may still need to see.

**Part sizes.** Every part fits one chunk of 1 MiB (1,048,576 bytes) with the chunk's own members, which take at most 103 bytes. The largest JSON of each kind, at the default caps (9.2), with every integer at 2^53 - 1 but a `divergent` part's `index`, which is at most 7 since a record holds at most 8 divergent uploads, and every certificate and receive key record carrying 4 suite keys of 4,096 bytes, each certificate otherwise the largest of 3.12 (32,872 and 29,701 bytes signed):

| Part | At most (bytes) | What bounds it |
|---|---|---|
| `meta` | 274,016 | its `identity.json` within `PUT /identity`'s 256 KiB body (262,119 bytes), and `app_added_at` for at most 255 reachable apps |
| `chain` | 906,360 | the stub (554), a context (1,024) and the document: an operation (512 KiB, 6.1), an `identity.json` (262,119), or a service transition, of which an `upload` is the largest: each item of the 16 MiB upload takes at least 1,138 bytes, so it names at most 14,742 keys (904,694) |
| `entry` | 129,092 | the envelope (64 KiB, 87,382 in base64url), the sender's certificate, 255 targets and a context |
| `app` | 693,729 | the app record, which its `app.put` bounds (392,924), the current and 8 retired receive key records and a renewed certificate |
| `key_bundle` | 87,645 | one key bundle part, an envelope of at most 64 KiB |
| `claim` | 19,558 | 64 attempts, each `unknown` with `resolved_by`, so none is current, and each after the first `possibly_duplicate` (6.8 row 1) |
| `tombstone` | 19,494 | 64 attempts, each `done` or `failed` with `resolved_by`, one at least `done` |
| `claim_entry` | 581,832 | the entry (512 KiB), its proof, whose claim view holds at most 64 attempts (24,522, ATTEMPTING with 63 of them `unknown`), and the writer's certificate (32,872) |
| `record` | 951,215 | its operation when carried (512 KiB; a 256 KiB value takes 466,897), its `read_scope` and `write_scopes` again (at most what the operation leaves, 392,563), the certificate and the proof (1,078) |
| `divergent` | 524,380 | one uploaded operation |
| `peer` | 262,153 | a peer's `identity.json` within `PUT /peers`' 256 KiB body |
| `batch`, `contact`, `conversation`, `deny`, `invite_code`, `connect`, `flag`, `peer_floor` | 1,292 | identifiers, times, counts and a context of at most 1,024 bytes |

The largest, a `record` part, takes 951,318 bytes of a chunk. Three kinds that could outgrow a chunk are split into parts of their own: an app's stored key bundle parts, which grow with the data epochs an offline app missed (`key_bundle`); a live claim's entries, up to four for each of 64 attempts, each proof carrying the claim view (`claim_entry`); and a record's divergent uploads, eight values of up to 256 KiB (`divergent`, one each).

**`GET /v1/{id}/export`** (signer). Answer `{ "manifest": signed<Manifest> }`. Errors: `403 permission_missing` for another caller; `409 conflict` when the account isn't frozen; `404` without an `identity.json`.

**`GET /v1/{id}/export/chunks/{chunk_id}`** (signer, or the next service under the export transfer). Answer `{ "id": string, "data": b64 }`, `data` the exact chunk bytes. Errors: as `GET /export`, `404` for a chunk ID the manifest doesn't list, and for the next service those of 3.11. Whoever fetches it checks `len` and `hash` before the chunk is stored at N. The answer to the next service carries no head.

### 10.4 Import

**`POST /v1/{id}/import`** (signer, at a staged account). Body `{ "manifest": signed<Manifest>, "freeze": signed<Freeze>, "transfer": signed<ExportTransfer> }`, `transfer` optional (3.11). N checks, in order:

1. The caller is the signer (`403 permission_missing`), and the account is staged (`409 conflict`).
2. The freeze verifies with the identity key (`401 bad_signature`) and names this identity and this service's origin and service key (`400`); its hash isn't one an abort cancelled here (`409 conflict`).
3. The manifest verifies with the service key of the `identity.json` N holds, the one it was enrolled with (`401 bad_signature`; `409 conflict` without one).
4. An import already in progress: the same manifest hash returns its status, after N has checked the start's `transfer`, if it carries one, kept it and fetched under it, all as step 7 says; steps 5 and 6 held at the first start. Another manifest is refused (`409 conflict`) while the import is activated or bound to a freeze at least as new (`issued_at`); a manifest bound to a newer freeze replaces a partial import.
5. The manifest is bound to this move: its `identity`, its `freeze_hash` is the freeze's, its `generation` is the held `identity.json`'s generation g, and its `next_generation` and the freeze's are g+1 (`400`).
6. Its chunk list is well formed: unique IDs, part ranges as in 10.2, `bytes` the sum of `len` (`400`); no chunk is over 1 MiB, and `bytes` is within `max_import_bytes` (`413 too_large`).
7. A `transfer` verifies with the identity key (`401 bad_signature`) and is for this move: its `freeze_hash` is the freeze's, its `manifest_hash` the manifest's, its `from` the origin and key of O as the held `identity.json` names them, and its `to` this service and the account's key here (`400`). N keeps it for the import, a later start with a valid one replacing it (step 4), and before it answers fetches from O each chunk it lacks, under it, one at a time, storing each as `PUT /import/chunks` would; a failed fetch stops there. The state lock isn't held while it fetches. A production service may fetch in the background instead, once it has answered; the signer then polls by sending the same start again, which step 4 answers with the import status (the reference prototype: it fetches before it answers, A36).

Answer, the **import status**:

| Field | Type | Notes |
|---|---|---|
| `manifest` | `b64(32)` | the manifest hash |
| `chunks` | int | the number of chunks in the manifest |
| `missing` | `array<string>` | the IDs of the chunks N doesn't hold yet, in manifest order |
| `activated` | bool | |
| `pulled` | int | how many chunks N fetched from O under the transfer, 0 without one |
| `pull_error` | string | present when N's last fetch from O stopped: which chunk and why, so the signer moves what is missing itself |

**`PUT /v1/{id}/import/chunks/{chunk_id}`** (signer, at a staged account). Body: the exact chunk bytes. Checks: the body is at most 1 MiB (`413`); an import is in progress (`409 conflict`); the manifest lists the chunk (`404`); its length and hash are the manifest's (`409 conflict`, `current: { "chunk": chunk reference }`, and nothing changes); a chunk not held yet parses as a chunk whose `index`, `first` and number of parts are where the manifest puts it (`400`). A chunk already held is a no-op. Answer: the import status. Nothing is live yet.

### 10.5 Activation

**`POST /v1/{id}/import/activate`** (signer, at a staged account). Body `{ "manifest": b64(32) }`, the manifest hash.

1. An import is in progress and is for that manifest, else `409 conflict`. Once it is activated, the same body gets the same answer.
2. Every chunk is held, else `409 conflict` with `current: { "missing": [chunk ID, ...] }`. N has trusted time (spec 10.1), else `503 unavailable`, since it bounds `last_time` by it.
3. N reads every part (`400` for one whose members don't read as 10.3 gives them, a listed member left out included). It then rebuilds the state from the parts, in order, gathering each app's `key_bundle` parts into its stored key bundle parts, each live claim's `claim_entry` parts into its entries and each record's `divergent` parts into its divergent uploads, as the parts of 10.3 hold them, and verifies it with the checks below, in the order listed, answering with the first that fails. A `chain` part out of `seq` order, which breaks both the order and the links, is therefore refused by the order check (`400`), before the link check (`409`). The checks:
   - the parts are in the order of 10.3 (`400`);
   - the first part, and only the first, is `meta`, and its `identity.json` verifies for the identity (`400`, or `401 bad_signature`);
   - that `identity.json` has the generation g and at least the version of the one N was enrolled with, and is that very document at that version (`409 conflict`), so O can't hand N an older version, such as one still listing an app the signer revoked, which the signer would be told to build on;
   - the manifest's head verifies with O's key (`401 bad_signature`), and so does its `checkpoint`, if any (`401 bad_signature`);
   - O chooses the checkpoint, so N checks where it lies: in generation g, or an earlier one the chain continued from, and before the head (`409 conflict`);
   - the meta part's `generation` is g and its `seq` is the head's (`409 conflict`): a frozen account gives out no `seq` after its freeze transition, and a `seq` behind it would make N give one out twice;
   - each `chain` part's chain hash follows from its envelope, its `seq` is the part's and above the previous one, and its `prev_chain_hash` is the previous chain hash, from the checkpoint's chain hash, or 32 zero bytes without one; the parts pass the other checks an app makes on each stub (6.6), the stamp order and the batch rules included, with no previous time right after the checkpoint, and generations that never go back and end at g (the stubs O keeps may begin in an earlier generation, after an earlier move), so the apps O kept stubs for read them at N without a rollback; a part with its document matches its stub's item type and hash (`409 conflict`);
   - the chain ends at the head: its last chain hash and `seq` are the head's, and the head's generation is g (`409 conflict`);
   - the head is the freeze transition: the last `chain` part, at the head's `seq`, is a `service` item with its document, a `freeze` transition (6.5) that verifies with O's key and names the manifest's `freeze_hash` (`409 conflict`). An export that ends earlier could leave out what O chained before the freeze;
   - the meta part's `identity.json` is the newest `identity` item of the `chain` parts, by item hash, when they hold one (`409 conflict`);
   - the manifest's `last_time` is at or after that transition's time, its `at` (6.5), else `409 conflict`. O sets `at` to the service time at which it chains the transition, so it equals the `server_time` of the transition's chain envelope (6.6). N continues from `last_time`, so an earlier one would put its time before what O chained last;
   - neither `last_time` nor that `at` is more than the clock tolerance (5 minutes) ahead of N's own time (`409 conflict`). N continues from `last_time`, so a time further ahead would move its clock ahead for good: certificates expiring, deadlines passing and sweeps deleting early;
   - every head an app uploaded at or after the checkpoint is at or before that end and has the chain hash the chain has at its `seq` (`409 conflict`). A head older than the checkpoint can't be checked against the chain parts, which start after it, so N ignores it: it is neither evidence for nor against the import. An honest app holds one only if O dropped the stubs after its position, as O may for an app more than 30 days behind, or for one restored from a backup whose position its cursor at O had passed (7.4.4). Such an app uploads no head while its continuity is unverified (7.4.14);
   - the apps: there is an `app` part for every app the imported `identity.json` lists in `apps`, and for every app whose `app.put` or `receive_key.put` a `chain` part holds with its document (`409 conflict`), so O can't leave an app out; app records, receive key records and renewed certificates verify (`400`, or `401 bad_signature`); the record and the renewed certificate name the part's App ID (`400`), and each key bundle part carries the identity's signature (`401 bad_signature`); an app's receive key records come in strictly increasing `n` and `seq`, each one after the checkpoint is the `receive_key.put` chain item at its `seq` with that record, and the newest `receive_key.put` the chain parts hold for the app is its last one, unless the app is a purged app's tombstone that the imported `identity.json` doesn't list (`409 conflict`), so O can't make an older key current; a `leave` or `revoke` transition in the chain parts makes the app departed or revoked at N, whatever its part says: N adds those flags from the chain and never clears one, and a departed app still listed awaits its rotation. The meta part's `apps_version` and `app_added_at` are taken as written: they decide only which current apps an append must also be wrapped to (7.4.3 step 5), never an app's standing, an attempt's orphaning, a claim or a record, so a false value can only make senders wrap to an app again or let an append leave one out, as an O that dropped entries could;
   - every shared record is derived from its signed operation, its `op` or the `chain` part at its `seq`, never taken as written. The operation verifies with a certificate whose App ID is the operation's writer, its `app_id`: the part's `cert`, or else the one in the writer's `app` part (`401 bad_signature`, also for a certificate of another app, since the writer comes from the operation itself; neither is there, `409 conflict`), and that certificate holds one of its write scopes; `key`, `collection`, the policy, `writer`, `deleted` and `size` are the operation's, and `generation` is the operation's, at most g (`409 conflict`). A write made at O after the checkpoint is the full chain item at its `seq` (a part that carries `op` as well carries those very bytes), in that item's generation, its `version` is that `seq`, and no later `record.put` of its key is in the chain parts; one at or behind the checkpoint, which no chain part covers, has a version at or before the checkpoint and no `record.put` of its key in the chain parts; one O took from a recovery upload (spec 12.6 step 3, when O was itself a recovering service) is of an earlier generation and listed by the `upload` transition at its `seq`. And every `record.put` the chain parts hold with its document is the current write of its key, since a superseded write keeps only its stub (`409 conflict`). Every part but one taken from a recovery upload carries `proof`, and an upload's carries none (`409 conflict` otherwise). The proof names that write: its stub's `item_hash` is the operation's at the part's `seq`, and its stub's generation is the one the operation names, the record's, since a service applies only operations of its own generation (6.4 step 6); its `object` is `key` and its state shows the part's `generation` and `version`; and it verifies with that generation's service key: O's for g, else the one the imported `identity.json` lists for it in `service_keys` (3.3) (`409 conflict` for either). A proof of a generation that list doesn't name is refused too (`409 conflict`): an honest signer lists every generation that O reports a current record's proof names (3.3). The one exception is a generation the imported `identity.json` declares lost (`recovery_from` and earlier): its proofs date nothing, so N keeps the record without one. Vectors: `export.json` `record_rejections` (no proof, a signature that doesn't verify, the proof of another write). So O can't relabel a record's version, generation, policy or size, or pass an older write off as current while the chain holds the newer one in full;
   - every live claim is replayed from its entries: their steps strictly increase; each entry's operation verifies with a certificate whose App ID is the operation's writer, its `app_id`: the part's `cert`, or else the one the record in the writer's `app` part carries (`401 bad_signature`, also for a certificate of another app, since the writer comes from the operation itself; neither is there, `409 conflict`), is a `claim` of this identity for this claim at the entry's step, and that certificate holds `claims.write` (`409 conflict`), as for a record's operation, so O can't make up an entry, such as a `failed` that frees an open attempt, nor pass an entry one app signed under its own certificate off as another app's; each entry's proof is of the generation the entry's operation names, since a service applies only operations of its own generation (6.4 step 6), and verifies with that generation's service key, O's for g, else the one the imported `identity.json` lists for it in `service_keys`, which the signer keeps for every generation a live claim's entry names (3.3); a proof of another generation, or of a generation that list doesn't name, is refused (`409 conflict`), so no entry's time or state is taken unchecked, behind the checkpoint either; the proof names the claim, and is that entry's (its stub's item hash is the entry's operation, at the entry's `seq`, and its `step` the entry's plus one); after the checkpoint each entry is the chain item at its `seq`, with the chain hash the chain parts give it; and every `claim` operation for the claim's key that the chain parts hold with its document, from the claim's first entry on, is one of its entries (`409 conflict`), so O can't leave an entry out, such as the newest, to roll the claim back. The claim's `step` is after its last entry and, unless the claim was rebuilt from recovery uploads (`rebuilt`, below), exactly one after it. A claim not rebuilt is replayed from nothing: N applies each entry's effect in order, by the rows of 6.8, at the time its proof's stub carries, and the state after each entry is the state that entry's proof shows, leaving out what depends on when it is read (`orphaned`, `next_possibly_duplicate`) (`409 conflict`). Whether a row applied when O took the entry, which depends on which apps were current then and which attempts were orphaned, isn't judged again: N can't tell, and the entry's writer signed it. The claim's `creator` is the owner of its first attempt, and unless it was rebuilt its `last_entry_ms` is the service time of its last entry, the `server_time` that entry's proof stub carries (`409 conflict`), so O can't charge another app's share of the claim limit, nor bring forward the deletion of a claim pinned to "none". And the claim is the state its entries lead to, member for member, those no claim view shows included, such as an attempt's `deadline_ms` and `from_upload` (`409 conflict`). So an open attempt can't be exported as `failed`, even under a proof O signs again to match. **Rebuilt claims:** only a provider loss rebuilds a claim from uploads (spec 12.6), and the `identity.json` keeps the generation it lost in `recovery_from` from then on, so N accepts a claim marked `rebuilt` only when the imported `identity.json`'s `recovery_from` isn't `null` (`409 conflict`). Uploads merge per attempt, only add attempts or settle them, and may fall anywhere between the claim's entries, and the export carries none of them, so N checks a rebuilt claim attempt by attempt, whatever the order its uploads came in (`409 conflict` for each rule): every attempt an entry names is one the claim holds; every attempt it holds is exactly one of these: marked `from_upload`; the one an `attempt` entry of the claim wrote, with the members that entry gives (its writer as `owner`, its stub's time as `opened_at_ms`, its `orphan_after` and its `deadline`); or one a reopened tombstone kept (below); and each attempt's outcome is the one the latest entry naming it wrote, with that entry's writer as `resolved_by`, or `open` when only its `attempt` entry names it. An attempt marked `from_upload` may be `done` instead, since an uploaded `done` settles an attempt whatever its outcome; one that no entry names keeps its outcome as written, and the uploaded evidence checks it (below). An attempt ID is random (1.7), so no upload names an attempt an `attempt` entry wrote. **Reopened tombstones:** evidence for an obligation N holds only as a tombstone reopens it (spec 12.6 step 3): the claim is live again, marked `rebuilt`, with the tombstone's step and attempts, each with the members the tombstone kept, while compaction removed their entries (6.8), whose chain items show as stubs (7.5). A tombstone is SETTLED and holds only `done` and `failed` attempts, and the claim it reopens stays SETTLED, so it refuses every `attempt` from then on (6.8 row 7). So N takes an attempt neither marked `from_upload` nor written by an `attempt` entry as one a reopened tombstone kept only when the attempt is `done` or `failed`, the claim is SETTLED and none of its entries is an `attempt`; its members are taken as written, as a tombstone's are, and its outcome is still the one the latest entry naming it wrote, when one does, such as its owner's `done` on a `failed` one (6.8 row 2). What only uploads change is taken as written: `divergent`, `last_entry_ms`, the pin, each attempt's `possibly_duplicate` and `duplicate`, and the states the entries' proofs show, which include the uploads merged between them; each proof is still that entry's. Within the bounds that hold whatever the order: the claim is SETTLED exactly when one of its attempts is `done`; its `current` is `null` or an open attempt it holds; and two open attempts make it `divergent`, since an upload opens a second attempt only beside an open one and only resolving them clears it. A tombstone's `last_entry_ms` is taken as written, since it keeps no entries, while each tombstone's `creator` must be the owner of its own first attempt (`409 conflict`). Vectors: `export.json` `claim_rejections` (another creator, another last entry time, the open attempt shown `failed` under a proof signed again, a `failed` entry O signed itself, a `failed` entry the executor signed under its own certificate naming the wallet as its writer, and the claim marked `rebuilt` on an account without a provider loss);
   - each inbox entry's `seq` is one O gave out (at most the meta part's `seq`), no chain item's, and appears once; every batch ID a kept stub names has its `batch` part, since O keeps a batch's ID while any of its stubs is kept (6.4) (`409 conflict`);
   - **the uploaded evidence** (spec 12.5 step 3): a claim an uploaded proof shows SETTLED is SETTLED in the import, live or as a tombstone, unless the proof's deadline plus the 30-day reconciliation window (6.8) is at or before `last_time`, or, for a proof without a deadline, its time plus `max_claim_age_ms` is; a claim an uploaded proof shows with an attempt (the proof of an app's own open attempt) is held, live or as a tombstone, with that attempt, at that step or a later one; a live claim at that step or a later one gives each attempt that the proof shows of the uploading app's own the outcome the proof shows, unless one of the claim's entries at or after the proof's step writes another for it (a `done`, `failed` or `unknown` naming it), or, on a rebuilt claim, the attempt is marked `from_upload` and `done`, which a later upload may have made it, or is one a reopened tombstone kept, whose entries compaction removed; so an uploaded attempt taken as written can't contradict its owner's evidence: one its owner's proof shows open isn't `failed` or `unknown` in the import unless a verified entry made it so. Another app's attempts in a proof aren't compared, since an upload may have changed them after the proof without the uploading app seeing it. A tombstone keeps no entries, and is SETTLED, so what it holds frees no obligation, and neither does what a reopened tombstone kept, on a claim that stays SETTLED; a record an uploaded proof shows at version v is that very write, by the proof's item hash, or one whose signed `expected_version` is v or later, or absent when v is a delete (`409 conflict`, naming the app whose evidence fails). The checks compare what the operations signed, not version numbers O wrote;
   - peers' `identity.json` copies verify (`400`, or `401 bad_signature`); a `peer_floor` names a Pubky ID with no `peer` part and a 32-byte body hash (`400`).
4. Only then N swaps the state in, in one step: O's sequence, chain, records, claims, tombstones, entries, apps and lists. By the checks above, the `identity.json` N holds never goes back on the one it was enrolled with. The App IDs its enrollment named in `revoked_apps` (3.7) stay tombstones, whatever the export carries for them. It signs the manifest's checkpoint again with its own service key, at the same `seq` and chain hash, since apps verify feed pages with the key of the `identity.json` naming N, and keeps them as those of its newest dropped stub (9.1). That is N's latest checkpoint, which may lie behind one an app accepted from O; such an app keeps no chain hash there, so it doesn't compare it (7.4.4). Its service time continues from at least `last_time`. It stays staged until the `identity.json` naming it arrives, which continues O's `seq` and chain under generation g+1 (6.5).

**Residual risk** (spec 12.5): N checks the import against the chain and the evidence apps uploaded. A faulty or malicious O that omits state, such as a tombstone or a shared record, is detected only by apps holding evidence of it: their uploads, before the activation and after it (7.4.14, where a SETTLED proof rebuilds an omitted tombstone), the SETTLED proofs they compare before attempting, and a protocol's own evidence. Admission state an app can't vouch for, such as a contact no own app was seen adding, is shown to the user, not removed (spec 12.5 step 4).

Answer:

| Field | Type | Notes |
|---|---|---|
| `activated` | `b64(32)` | the manifest hash |
| `imported` | int | the last `seq` imported |
| `head` | signed head | N's head over the imported chain, under N's service key (generation g) |

After the activation an app's upload is checked against the imported chain and state at once, and a mismatch is an import conflict; once the move is published, N still merges the old service's SETTLED proofs an app uploads (7.4.14). When the `identity.json` naming N arrives, N drops the staged chunks, the uploaded heads and the uploaded evidence; it keeps the old service's key, the generation and the head the import ended at, to check later evidence.

### 10.6 Abort

While N holds no `identity.json` naming it, the signer may cancel the move with the unfreeze of 3.6 (`POST /v1/{id}/unfreeze`), sent to N first (spec 12.5 Abort):

- **At N**, a staged account: the unfreeze must verify with the identity key (`401 bad_signature`); N must not be named yet (`409 conflict`, the move is published); an import here must belong to the freeze it names (`409 conflict`). N discards that import, partial or activated, and puts back the state it was enrolled with; it forgets the uploaded heads and evidence, and refuses any manifest bound to that freeze from then on (10.4 step 2). Answer: the discard answer of 3.6, `{ "discarded": "<freeze hash>", "sig": "<N's signature>" }`, signed with N's service key; the same unfreeze again gets the same answer. N writes no chain item.
- **At O**, with N's answer as `discarded`: it is the unfreeze of 7.4.13. O checks the answer with the service key the freeze names and only then resumes, so O and N never both accept writes; apps submit their queued writes there. From then on its public read of `identity.json` carries no freeze (7.4.15). The cancelled freeze is used up: sent again, O refuses it (3.6).
- **N unreachable:** the move can't be cancelled; the signer completes it to N, or, if N is gone, declares a provider loss (the reference prototype: it automates neither).
- **Pruning behind the checkpoint**: apps keep claim evidence and chain bookkeeping only as 7.4.4 says; they upload what they kept.

### 10.7 Examples

The examples of this section are taken from `export.json`: alice's account frozen right after `chain.json`'s last item, exported as one chunk of 19 parts. Each is the vector's JSON pretty-printed, its members in the vector's order. A value longer than 64 characters is cut short to its first 40 and `...`, and the parts left out are named. `export.json` has no `entry` or `tombstone` part: its one inbox entry was read and deleted before the freeze, and its one claim is live. 10.3 gives their members.

The manifest body:

```json
{
  "v": 1,
  "kind": "pubky-switch.export_manifest",
  "identity": "8y3qy4g9q7y9ownd18hskdoxdxzueutiu3f391rnnuxznxmqp5bo",
  "freeze_hash": "k38YxzhWMzgCiPkN4jU2cXzCIAA4IRK8zYvrFH6kLQA",
  "generation": 1,
  "next_generation": 2,
  "last_time": "2026-04-11T00:00:01.000Z",
  "head": {
    "chain_version": 1,
    "generation": 1,
    "seq": 10,
    "chain_hash": "HDiFHOlPNQId9KGGr1CcEfpCfks1oxSkDba9uRxfO58",
    "sig": "AxFJFQnl71N8EFGYMpWPkFBwQdAJOK_IJz2nWZsS..."
  },
  "checkpoint": null,
  "parts": 19,
  "bytes": 28982,
  "chunks": [
    {
      "id": "00000",
      "len": 28982,
      "hash": "dG2Xe-sx30GQlHT3YT6ennfz_Q5-2pL7199woRB_vbo",
      "first": 0,
      "last": 18
    }
  ]
}
```

The chunk, with its first two parts, the `meta` part and the `chain` part at `seq` 1 (the other 17 left out):

```json
{
  "v": 1,
  "kind": "pubky-switch.export_chunk",
  "index": 0,
  "first": 0,
  "parts": [
    {
      "part": "meta",
      "identity": {
        "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLmlk...",
        "sig": "ysIV9UOQnZRttQbBzDKXLUVCRTBLWEE4V7un_LPw..."
      },
      "generation": 1,
      "seq": 10,
      "directory_version": 7,
      "apps_version": 4,
      "app_added_at": {
        "w8amtmn13m6p5bwnmj9wejbq4c": 1
      }
    },
    {
      "part": "chain",
      "seq": 1,
      "stub": {
        "envelope": "eyJjaGFpbl92ZXJzaW9uIjoxLCJnZW5lcmF0aW9u...",
        "chain_hash": "0joOBYIoI36HB5DGDTSm8KaMaGxa9oOfhGW6X2PnqVE"
      },
      "item_type": "identity",
      "doc": {
        "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLmlk...",
        "sig": "BlYsoTmSrf4pCW8U_2TOJRew9L2ISRaSRHjpZ3-O..."
      },
      "context": null
    }
  ]
}
```

The `claim` part, the live claim of `seq` 7, and its one `claim_entry` part, the `attempt` of `seq` 7 with its proof, which follows it; its `cert` is `null`, since the wallet's `app` part carries the certificate the entry was checked against:

```json
{
  "part": "claim",
  "claim_key": "LOElfduZJYjUJFjB4crU2il4lVN2oKRo6BnTap10GqA",
  "claim": {
    "attempts": [
      {
        "attempt_id": "P37OWgXQlGXLccI0TFBpwg",
        "deadline_ms": 1767312000001,
        "duplicate": false,
        "from_upload": false,
        "opened_at_ms": 1767225603000,
        "orphan_after_s": 86400,
        "outcome": "open",
        "owner": "w8amtmn13m6p5bwnmj9wejbq4c",
        "possibly_duplicate": false
      }
    ],
    "creator": "w8amtmn13m6p5bwnmj9wejbq4c",
    "current": "P37OWgXQlGXLccI0TFBpwg",
    "divergent": false,
    "last_entry_ms": 1767225603000,
    "pinned_deadline": 1767312000001,
    "rebuilt": false,
    "settled": false,
    "step": 1
  }
}
```

```json
{
  "part": "claim_entry",
  "claim_key": "LOElfduZJYjUJFjB4crU2il4lVN2oKRo6BnTap10GqA",
  "step": 0,
  "seq": 7,
  "op": {
    "body": "eyJpZGVudGl0eSI6Ijh5M3F5NGc5cTd5OW93bmQx...",
    "sig": "uyEJk2QGiGpoJ9FO8iyrmaJoPu175snD9GvnGQf4..."
  },
  "proof": {
    "body": "eyJjaGFpbiI6eyJlbnZlbG9wZSI6ImV5SmphR0Zw...",
    "sig": "Z3_U3AsxoDiMQTgRCZ8fF9E_P0Ex2tL8skLWlSRy..."
  },
  "cert": null
}
```

The `record` part, with the proof of its current write (`chain.json` `seq` 8); `op` and `cert` are `null`, since the `chain` part at `seq` 8 and the wallet's `app` part carry them:

```json
{
  "part": "record",
  "record": {
    "cert": null,
    "collection": "rThZDAv1FHRMIiUn6S8h7HBHF_-gTlmA13cC8V-Prug",
    "deleted": false,
    "from_upload": false,
    "generation": 1,
    "key": "kOVu6mp0YaO9wsEJ2gf9TG7n3cf3KMFu_RaRvlaEkFM",
    "op": null,
    "proof": {
      "body": "eyJjaGFpbiI6eyJlbnZlbG9wZSI6ImV5SmphR0Zw...",
      "sig": "svZhsiF2IRrW30xJK0hM9m3784FyWv9LoTeA8gBb..."
    },
    "read_scope": "tasks",
    "seq": 8,
    "size": 4112,
    "upload_base": null,
    "version": 8,
    "write_scopes": [
      "tasks"
    ],
    "writer": "w8amtmn13m6p5bwnmj9wejbq4c"
  }
}
```

The wallet's `app` part:

```json
{
  "part": "app",
  "app_id": "w8amtmn13m6p5bwnmj9wejbq4c",
  "record": {
    "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLmFw...",
    "sig": "soHnAkpU7U2ovHwh3rpcP-UlAgRUZFE0SOWUwzbr..."
  },
  "record_seq": 3,
  "record_at_ms": 1767225601000,
  "receive_keys": [
    [
      {
        "body": "eyJ2IjoxLCJraW5kIjoicHVia3ktc3dpdGNoLnJl...",
        "sig": "2v-AMIqAxitgORsPtoQGTK8uaVwNV_F0zs6A-5a3..."
      },
      4
    ]
  ],
  "cursor": 9,
  "last_seen_ms": 1767225604000,
  "revoked_at_ms": null,
  "departed_at_ms": null,
  "departure_epoch": null,
  "rotated": false,
  "renewed_cert": null,
  "lagging": false,
  "keys_through": 1,
  "full_bundle_requested_ms": null
}
```

The first `batch` part:

```json
{
  "part": "batch",
  "id": "43lMSHQ8vKwdwxES7T9SUw",
  "record": {
    "at_ms": 1767225601000,
    "ops_hash": "piV-jr-g2YX_JlSqnH26awNUBwM1TpMuhq6DnsJ1gPE",
    "proofs": []
  }
}
```

## Appendix A. Choices this document made

The prototype fixes every other detail above. These it leaves open, so this document chose:

| # | Detail | Choice | Prototype |
|---|---|---|---|
| A1 | Range of JSON integers | 0 to 2^53 - 1, larger values rejected (1.1) | `u64`, unchecked |
| A2 | Time spellings | writers: three fraction digits, `Switch-Timestamp` none; readers: every form of the grammar, fractions of 1 to 9 digits; accepting offsets or a space for `T` is the reader's choice, and no writer produces them (1.6) | writes these forms; its parser also accepts offsets and a space |
| A3 | `inbox.url` | the origin `https://host[:port]`, no path or trailing slash (3.3) | compares the text with its configured origin |
| A4 | `msg_id` | lower-case UUID v4 with version and variant bits (1.7); the spec now makes it a MUST | checks the form (`wire::check_uuid_v4`) |
| A5 | Names of the further limits in the enrollment answer | the configuration names of 9.2, as `limits` members, when a service announces them (3.7) | doesn't announce them |
| A6 | Chunk IDs | opaque path-safe strings that N takes from the manifest (10.2) | writes the chunk's index as five decimal digits |
| A7 | Switch root input | the identity's 32-byte Ed25519 secret key (seed), not its expanded form (1.5) | the same |
| A8 | `PUT /identity` body | `{ "identity", "prev" }`, `prev` the document hash or `null`; a retry of the same bytes passes whatever `prev` it names and gets the original delivery's proof; the `409 stale_identity` carries the held copy and its hash (7.4.2) | the same |
| A9 | Key bundle plaintext | flat `keys` list with `naming_key`, `first_epoch` and `last_epoch`; the old nesting (`keys.keys`) dropped (3.5) | the same |
| A10 | Asking for a full bundle | `POST /v1/{id}/apps/{app_id}/keys`, empty body; `full_bundle_requested` and `keys_through` in `GET /apps` (7.4.11, 7.4.12) | the same |
| A11 | Discard answer | `{ "discarded", "sig" }` under N's service key, label `pubky-switch/v1/discarded`, carried as `discarded` in the unfreeze at O (3.6) | the same |
| A12 | Push registration | two `PUT /push` calls: without `push_key` to start one, with it to set handles; `409 conflict` for another key or relay (8.1) | the same |
| A13 | `missed` feed item | `{ entries, accepted_from, accepted_until }`, one per lagging app, replaced while unread; it waits for its target even while lagging (7.4.4, 7.5) | the same |
| A14 | Lagging when no app is reading | no app is marked, a single current app never; entries wait and the quota refuses senders (7.4.4) | the same |
| A15 | Checkpoint | the latest one in each feed page; N signs the export's checkpoint again with its own key after an import (7.4.4, 10.5); signed once `checkpoint_behind` items, 1,000 by default (9.2), may go, behind every cursor or 30 days old | off by default (`checkpoint_behind` unset), set by its tests; with `checkpoint_at_head`, signed at the newest item, keeping behind it the stubs a cursor holds |
| A16 | Feed of a frozen account | carries the signed `freeze` (7.4.4) | the same |
| A17 | Unverifiable sender | store locally and move on after 24 hours (5.1) | `DEFAULT_PARK_UNVERIFIABLE_MS` |
| A18 | "Counterparties recently written to" | switches whose inbox accepted a message from the app in the last 30 days, skipped when their `known_version` is already current (3.3) | the same |
| A19 | Clock tolerance comparisons | removed: counts when `accepted_at + 5 min <= distrust_from`; renewed and closed: when `accepted_at + 5 min < until` (5.1) | the same |
| A20 | Tombstone deletion "passes" | at the deadline plus the 30-day reconciliation window (`now >= deadline + 2592000000 ms`, `now` the time base with trusted time, 7.3 step 4), for tombstones and failed claims alike; an `attempt` is refused from the deadline itself (6.8) | the same |
| A21 | `evidence_ref` | one field for either piece of evidence: required with basis `evidence`, optional with `owner` or `reconcile`, refused on other types (6.2) | the same, `400` otherwise |
| A22 | Cursor deferral bound | at most 2 s while running, sent before the app stops reading (7.4.4) | `cursor_defer_ms`, `suspend()` |
| A23 | Order of per-operation checks | permission, shape, per-kind limit, then the type's rules; for a claim the deadline before `expected_step` (6.4, 6.8) | the same |
| A24 | Trusted time | required by default (`trusted_time.required` on, 9.2): an authenticated sample anchored to the monotonic clock, with a drift bound and a maximum sample age; the wall clock while it agrees within 5 minutes; `503 unavailable` for what depends on time without it (spec 10.1) | opt-in (`trusted_time.required`), as the prototype has no time source; tests give samples (`note_time_sample`), and the test clock's wall reading can jump without moving its monotonic one |
| A25 | How a record view gives readers the writer's certificate | one optional `cert` member, the certificate of the record the service holds for the writer, also after a revocation; the reader checks the write's standing with it at the write's time, and a renewal's earlier certificate is replaced by the record's new one (7.4.9, 6.2). A per-write certificate or a cert hash in the chain envelope was not chosen: one more member in the view is the smallest change, and feed readers already hold the records of the identity's apps | the same |
| A26 | The O/N clock offset in the residual window | the difference between (last service time verified from O minus the device clock then) and (the first from N minus the device clock then); twice the clock tolerance without one from O (spec 12.6) | the same (`RecoveryState.clock_offset_ms`) |
| A27 | App request and approval | the fields of 3.9 and 3.10; the request is a signed document under its own label; the approval names the request by document hash and carries the bundle as `GET /keys` parts without `seq` | the same; the Pubky auth request is modelled (`records::AuthRequest`) and the approval is handed over in process |
| A28 | When the signer renews a certificate before it expires | at its first run once less than half the certificate's lifetime remains, with that certificate's lifetime from then; after two such renewals in a row that no record of the app took up, not again until the user renews it or a record carries the newest certificate (3.1, spec 3.1) | `Signer::renew_expiring` |
| A29 | Certificate lifetime bounds | `expires_at` later than `issued_at` and at most 730 days after it; "1 year" is 365 days (3.1) | `records::CERT_LIFETIME_MS`, `MAX_CERT_LIFETIME_MS` |
| A30 | Sealed value buckets | 2^k bytes for k from 9 to 18 and 3 * 2^k for k from 8 to 16, of `u32_be(len) || JSON || zeros`; a delete unpadded; the service refuses any other length with `400`, more than 256 KiB with `413` (6.2) | `sealed::BUCKETS`, `pad`, `unpad`, `SealedValue::check_shape` |
| A31 | The reserved `suite_keys` member | 1 to 4 entries `{ suite, key }`, suites 2 to 255 strictly ascending, keys 1 to 4096 bytes; in a receive key record no entry's kid equals the record's; readers ignore unsupported suites (3.1, 3.4) | `records::SuiteKey`, `check_suite_keys` |
| A32 | The kid of a later suite's key | first 8 bytes of `derive("pubky-switch/v1/kid", u64(suite), key)`; suite 1 keeps `derive("pubky-switch/v1/kid", key)`, so no existing kid changes (1.5) | `wire::suite_kid` |
| A33 | Ed25519 verification and low-order X25519 keys | the four steps of 2.1; a key is of low order when X25519 with a clamped secret gives all zeros (4.2) | `wire::verify`, `wire::x25519_low_order` |
| A34 | The import limit | 4 GiB. Part sizes measured on the vectors' apps, each operation once and no batch proofs (10.3 gives the largest): a shared record about 1.2 KB with the transition proof of its current write (0.9 KB), plus its chain item with its operation about 2.5 KB (at the smallest sealed value), a tombstone with one attempt 0.4 KB, a live claim 2.5 KB, a chain stub alone about 0.5 KB, a batch part 0.15 KB. An account at every default limit (100,000 records within the 64 MiB record quota, 1,000,000 claims and tombstones, a full 64 MiB inbox, 100,000 entries in each list, 10,000 peer copies) exports under 1 GiB; the other 3 GiB hold about 5 million kept chain stubs with their batch parts. A service whose rates and stub retention keep more raises it, and a signer moves an identity only to a service whose limit is at least its current one's (7.4.13) | `retention::KindLimits::max_import_bytes`, `lifecycle::Limits` |
| A35 | The clock bound for automatic attempts (spec 10.1) | 5 minutes, the clock tolerance, either way: the offset between the service's signed time and the device clock at the latest verified answer, or the highest verified service time ahead of the device clock now | `App::clock_skew_ms`, `check_clock`: an automatic attempt is refused, a manual one goes on with the event `clock_skew_warning` |
| A36 | How the next service fetches the export | during `POST /import`, before it answers, one chunk at a time, stopping at the first failure; the status counts `pulled` and names `pull_error`; the signer moves what is missing | `InboxService::serve`, `set_peer_transport`; `Signer::transfer` (direct, with the fallback) and `transfer_relayed` |
| A37 | The sender's share of the inbox quota | `sender_share_percent` 25 | the same |
| A38 | The switch's copy of `identity.json` | the grace after the Homeserver reads: 500 ms, after which the lookup keeps running and a manual attempt it hasn't answered for needs the user's confirmation before the attempt; an automatic attempt's lookup: 5 s per try and one retry; `identity_reads_per_source_per_min` 60 per IPv4 address or IPv6 /64, `identity_reads_per_min` 6,000 per account; `Cache-Control: public, max-age=60`; a failed lookup counts until the reader's copy is 10 minutes old | `INBOX_IDENTITY_GRACE_MS`, `INBOX_LOOKUP_TIMEOUT_MS`, `with_grace`, `lookup_with_retry`, `App::settle_lookup`; `check_unconfirmed` (event `identity_unconfirmed`); `directory::source_key`, `IDENTITY_CACHE_CONTROL` |
| A39 | How long a frozen service answers the public read with its freeze | while frozen, and after a move at least `record_max_age` counted from the last export call it answered, plus a day; the reader follows a freeze once | the prototype deletes a frozen account only when the signer erases it (7.4.16, `directory::public_identity`); `inbox_identity` |
| A40 | A full connect request list | refused with `429 quota_exceeded` `connect_requests`, checked before the deny list; `GET /connect` reports `max_pending` and `full` | `connect::post_connect`, `get_connect`, `ConnectList` |
| A41 | The cap on an invite code's uses | `max_invite_uses` 100 | the same |

The vector files follow these choices wherever the prototype has a value to compute.
