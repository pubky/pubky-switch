# What the scripted switch fakes or leaves out

The scripted switch (`switch.rs`) applies every batch, submitted with `POST /ops` or
injected with `app_op` and `signer_op`, through the core's rules (Switch wire 6.4). Where it
differs from the spec and the service, it is listed here. Tests of these rules belong to the
service.

## Batches

- **Request authentication** (Switch wire 7.1, 7.2): no request signature or
  `Switch-Identity` check; the caller is the `Switch-App` header as sent, and an app of
  another identity is the `Switch-Identity` header as sent. A `Switch-Timestamp` more than 5
  minutes from the switch's clock is `401 stale_timestamp`, with `current.server_time` and
  the last stamped time in `Switch-Server-Time`, as at the service; a missing or unparsable
  one isn't refused. Every other request stamps the clock's time. Answers to own apps and
  the signer carry `Switch-Head`, refusals included, but a `401`, the enrollment and the
  erasure. An injected `401` fault is answered as before the lock, with the last stamped
  time and no head; other injected faults with the clock's time and the head. Each operation's signature is
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
- **`keys_through`** (Switch wire 7.4.12) counts every stored part as fetched, whatever the
  app's cursor: the epoch of the first version listing the app, raised by each part that
  continues it.

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
- **App currency outside batches**: a feed read is checked as a batch is, for an app that
  delivered its record: current, with an unexpired certificate, the stored renewed one once
  the newest `identity.json` lists it (Switch wire 7.2, 3.8). Other routes check only that
  the app hasn't departed.
- **`POST /v1/enroll`** (Switch wire 3.7, 7.4.1), in `switch/signer.rs`: only at
  [`SWITCH_ORIGIN`], with the default limits unless a test sets others
  (`set_enroll_limits`), and without checking the request signature. A
  switch made with `unenrolled` answers every other call with the operator's `404` until
  then. As at the service, the enrollment that makes the account sets its kept App IDs, and
  every later one gets the same key and changes nothing. Unlike the service:
  - an enrollment's `identity_doc` isn't held, so the account starts with no document and
    at the switch's own generation, whatever the enrollment names;
  - a serving account is answered `400`, never a pending key for the next generation, so
    there is no key change in place and no provider loss at the same service.
- **`PUT /identity`** (Switch wire 3.3, 7.4.2), in `switch/signer.rs`: judged by the core's
  `check_delivery`, like the service, with the kept proofs taken from what it holds: each held
  record's current write proof and each live claim's entry proofs, by the generation each
  names, with the key of that generation (its own, or the earlier service's that
  `import_into` carried). Unlike the service: there is no pending key, so no
  generation change at a serving account; and a first document carrying `recovery_from`, or
  at another generation than the switch's, is chained where the service answers `503`. The test call `deliver_identity` takes any document, without those
  checks, for scripting what another signer or a faulty service did. `forget_delivery_proof`
  makes a retry answer with no proof.
- **`GET /apps`** (Switch wire 7.4.12): the apps the switch holds or the newest document
  lists, with `current`, `record_cert`, `record_at`, `revoked_at`, `departed_at`,
  `awaiting_rotation`, `full_bundle_requested`, `bundle_ranges`, `keys_through` and
  `cert_expires_at`, and the
  account's `identity`, `recovery` (`declared_at` its recovery record's time) and
  `proof_generations`, from the same kept proofs as the delivery; no last-seen times,
  attempts, unread counts or departures.
- **Moves and recovery** (Switch spec 12.5, 12.6, Switch wire 10): `import_into` copies the
  account in memory, with no manifest, chunks or export transfer; a recovery upload is kept
  and answered with fixed changes, merging nothing.
- **Revocation** is `POST /apps/{app_id}/revoke` from the signer, and the test call
  `revoke`; an app that left is answered as one revoked already, with no proof. `leave` and
  `request_full_bundle` are test calls for the app's own routes, and `forget_removal_time`
  scripts a faulty service that shows no time for a removal. Freeze and
  unfreeze are test calls, not routes.
- **`lose_identity`** scripts a faulty service that lost the account's `identity.json`.
- **The signer hand-over** (Switch wire 7.4.17): `PUT /handover` runs the core's checks of a
  stored hand-over (`SignerHandover::check_stored`) for a current target with a checked
  certificate, and keeps one, replacing any it held; `GET /handover` serves it to the signer
  and to its target; the next `identity.json` version, whoever delivered it, drops it.
  `stored_handover` names the target held.
- **Erasure** (Switch wire 7.4.16) is a flag; its answers are signed with a fixed operator
  key.
- **Push** (Switch wire 8.1): registrations only; nothing is sent to a relay.

## Signer flows tested only here

The service in this workspace doesn't serve `GET /apps`, `POST /apps/{app_id}/leave` or
`POST /apps/{app_id}/keys` yet, and the signer reads `GET /apps` before every signing step.
So these signer flows run only against the scripted switch; re-run them against the service
once it serves those calls:

- approval, renewals and reductions, their closings, and epoch completion
  (`crates/pubky-switch-signer/tests/approval.rs`, `renewal.rs`);
- revocations, departures, removal times and their bounds, full-bundle requests, purge and
  record cleanup (`revocation.rs`);
- the one-signer checks, alarms and their clearing, records behind, and publication
  (`flows.rs`);
- restore from the signer backup, in place and on a new install (`restore.rs`);
- the hand-over both ways, the abort, the take-over's checks and its lost answers, and which
  copies delete a key (`handover.rs`).
