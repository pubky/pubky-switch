# What the scripted switch fakes or leaves out

The scripted switch (`switch.rs`) applies every batch, submitted with `POST /ops` or
injected with `app_op` and `signer_op`, through the core's rules (Switch wire 6.4). Where it
differs from the spec and the service, it is listed here. Tests of these rules belong to the
service.

## Batches

- **Request authentication** (Switch wire 7.1, 7.2): no request signature, timestamp or
  `Switch-Identity` check; the caller is the `Switch-App` header as sent, and an app of
  another identity is the `Switch-Identity` header as sent. Each operation's signature is
  verified, and an own app must be current with an unexpired certificate.
- **Rates** (Switch wire 6.4 step 7, 9.4): no operation, control, per-caller or
  failed-authentication limits; never `429 rate_limited`.
- **Quotas and per-kind limits** (Switch wire 9.3): only the claim limits, at the core's
  defaults, and `max_invite_uses`; never `429 quota_exceeded` otherwise.
- **Trusted time** (Switch wire 7.3, Switch spec 10.1): the test clock is trusted and may go
  back; a batch that depends on time is never `503 unavailable`.
- **Proof states** (Switch wire 6.5) are built by the switch from each operation and the
  state after it, as the core has no function for that; a claim's is the core's claim
  view.
- **`invite_code.delete`** of a code the switch doesn't hold is `404`; the core has no rule
  for it.
- **Key bundle parts** the target's cursor passed are never dropped (Switch wire 6.2).

## State and retention

- **Durability** (Switch spec 6.5): everything is in memory, answered at once; the service
  key's mark isn't kept. Per-account order is a mutex.
- **Retention and sweeps** (Switch wire 9.1): entries never expire; `missed` items,
  checkpoints and dropped stubs exist only when a test scripts them; claims are deleted only
  when `GET /claims` finds them deletable; batch records are never dropped, and their proofs
  go only when a retry finds them past `batch_proofs_ms`.
- **Invite codes**: a revoked app's codes aren't withdrawn (Switch wire 7.4.3 "After a
  revocation"); a code planted for a faulty export never expires.
- **Lists**: `flagged` is always empty; connect requests are never full. Conversation
  entries carry no `last_used`, and those the service wrote carry no `context`.
- **Records**: `divergent` is always `false`.
- **Directory** (Switch wire 7.4.10): an app is reachable from its first receive key until
  it is revoked or leaves; one that stops being current otherwise, with an expired or
  closed certificate, stays reachable, and `apps_version` doesn't move for it.

## Other calls

- **Injected entries**: `send` and `send_envelope` add entries without admission, quotas,
  size buckets or `409 stale_key`; entry IDs are made up from the `seq`.
- **`POST /inbox`** (Switch wire 7.4.3), in `switch/inbox.rs`, from apps of other
  identities and own apps:
  - the sender's `Switch-Cert` is verified against its identity, but its expiry and the
    sender identity's service time aren't checked (Switch wire 7.2 checks 3 and 4);
  - an app whose renewal has closed gets `409 identity_needed`, never `403 not_current`;
    an app the peer copy lists as removed isn't answered like a stranger before
    admission, only refused with `409 identity_needed`;
  - no size check (step 3), rate limits (step 4) or quotas and sender shares (step 6);
    only the envelope's header is parsed;
  - an own app's append uses its record's certificate, and isn't checked for being
    current;
  - retries by content are answered for as long as the switch lives, and `import_into`
    doesn't carry the stored answers, so a retry after a move appends again.
- **`PUT /peers`** (Switch wire 7.4.5) keeps every copy it takes: no peer limit, but for
  `forget_peer_copy`.
- **`open_admission`** (`admit_everyone`) admits every sender the deny list doesn't hold, a
  test switch only.
- **App currency outside batches**: other routes check only that the app hasn't departed.
- **`POST /v1/enroll`** (Switch wire 3.7, 7.4.1), in `switch/signer.rs`: only at
  [`SWITCH_ORIGIN`], with the default limits. A switch made with `unenrolled` answers every
  other call with the operator's `404` until then; the same enrollment again gets the same
  answer. A serving account answers no pending key for the next generation, so no key change
  in place or provider loss at the same service.
- **`PUT /identity`** (Switch wire 3.3, 7.4.2), in `switch/signer.rs`: judged by the core's
  `check_delivery`, but with no kept proofs (`proof_keys` empty) and no pending key, so it
  never answers `409 conflict` for a left-out service key and takes no generation change at
  a serving account. The test call `deliver_identity` takes any document, without those
  checks, for scripting what another signer or a faulty service did.
- **`GET /apps`** (Switch wire 7.4.12): the apps the switch holds or the newest document
  lists, with `current`, `record_cert` and `bundle_ranges`; no last-seen times, attempts,
  unread counts, `keys_through`, departures or `proof_generations`.
- **Moves and recovery** (Switch spec 12.5, 12.6, Switch wire 10): `import_into` copies the
  account in memory, with no manifest, chunks or export transfer; a recovery upload is kept
  and answered with fixed changes, merging nothing.
- **Revocation, freeze and unfreeze** are test calls, not routes.
- **Erasure** (Switch wire 7.4.16) is a flag; its answers are signed with a fixed operator
  key.
- **Push** (Switch wire 8.1): registrations only; nothing is sent to a relay.
