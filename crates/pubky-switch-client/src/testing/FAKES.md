# What the scripted switch fakes or leaves out

The scripted switch (`switch.rs`) applies every batch, submitted with `POST /ops` or
injected with `app_op` and `signer_op`, through the core's rules (Switch wire 6.4). Where it
differs from the spec and the service, it is listed here. Tests of these rules belong to the
service.

Where the scripted switch answers an honest flow differently from the service, the list is
`crates/pubky-switch-harness/src/allowed.rs`. That crate runs flows of the real signer and
the real app against both, and its tests fail on a difference the list doesn't hold. This
file lists what the scripted switch fakes or leaves out beyond those flows.

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
- **`GET /records/{key}` and `GET /records`** (Switch wire 7.4.9), in `switch/shared.rs`:
  order, `after`, `limit`, the byte budget with its first view shown, `next`, and deleted
  records shown by key and left out of lists are the service's. Unlike the service:
  - a record by key is served `200` to any own app, without checking its `read_scope`
    (the service answers `403 permission_missing`);
  - the signer is served too, and its list shows every record (the service answers `403
    permission_missing` to both);
  - a view's `cert` is the writer's current certificate, not the one the write was checked
    against, which a renewal or revocation later doesn't change (7.4.9);
  - a list without `collection` falls through to the switch's other routes rather than
    `400`, and `after` is compared as raw text, never refused as a malformed key.
- **`open_admission`** (`admit_everyone`) admits every sender the deny list doesn't hold, a
  test switch only.
- **App currency outside batches**: a feed read is checked as a batch is, for an app that
  delivered its record: current, with an unexpired certificate, the stored renewed one once
  the newest `identity.json` lists it (Switch wire 7.2, 3.8). Other routes check only that
  the app hasn't departed. The key bundle routes (`GET` and `POST /apps/{app_id}/keys`)
  answer `403 not_current` to an app that isn't current by its record, as the service does,
  and keep nothing for it; they don't check the certificate's expiry (the service answers
  `403 cert_expired`), take any body, and answer `404` ("no route") for another app's path or
  the signer, where the service answers `403 permission_missing` (Switch wire 7.4.11).
- **`POST /v1/enroll`** (Switch wire 3.7, 7.4.1), in `switch/signer.rs`: at the switch's
  origin, [`SWITCH_ORIGIN`] unless it was made with `unenrolled_at`, with the default limits
  unless a test sets others (`set_enroll_limits`), and without checking the request
  signature. A switch made with `unenrolled` or `unenrolled_at` answers every other call
  with the operator's `404` until then. As at the service, the enrollment that makes the account sets its kept App IDs, and
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
- **`GET /apps`** (Switch wire 7.4.12), in `switch/signer.rs`: by the service's rules, member
  by member, but `last_seen`, `unread_entries`, `sole_target_unread` and `recovery` (below):
  - every app the switch holds, every App ID it keeps for good, and every app the newest
    document lists. An App ID an enrollment named shows `revoked_at` at the enrollment's time;
  - `current` in spec 3.4's sense, as the service reports it, once the app has a record: listed with its certificate, or
    renewed and open, and never once revoked, departed or kept. Expiry isn't part of it:
    `cert_expires_at` carries that, and a signer that serves an app checks both. An app with
    no record is current while it is listed and not kept;
  - `last_seen`: the time of the app's latest request past authentication, a staged
    account's refusal and its `leave` included. The scripted switch doesn't authenticate an own app's
    requests one by one: it takes any app with a record that isn't revoked, departed or kept
    as authenticated. So, unlike the service, it counts an app whose certificate expired or
    isn't listed, which the service refuses at authentication (`cert_expired`,
    `not_current`) before recording anything, and it counts any scripted error other than a
    `401`;
  - `revoked_at`, `departed_at`, and `awaiting_rotation` for a departure until a delivered
    version removes it at a higher data epoch. That stays done after a purge;
  - `open_attempts`: the attempts the app owns that are open or `unknown`;
  - `record_cert`, `record_at`, `full_bundle_requested`, `bundle_ranges` and
    `cert_expires_at`;
  - `keys_through` by the core's rule, counting only the stored parts the app's cursor has
    passed. It starts at the epoch of the first version that listed the app, kept only for an
    app with no row and no stored part then, as the service keeps it; otherwise the start is
    unknown, and only parts from epoch 1 count. A row is an entry in the switch's apps, which
    an `app.put`, a revocation, a departure, a `cert.put` and some test calls create;
  - the account's `identity`, `recovery` as the spec's object (`declared_at` its recovery
    record's time), where the service sends `null` until it serves recoveries, and
    `proof_generations` from the same kept proofs as the delivery, the member left out when
    there are none.

  `unread_entries` and `sole_target_unread` are always 0, where the service counts them over
  the current targets, expired certificates included; no signer or app code reads them.
  `lagging` is false, as on the service. The test call `forget_bundle_parts` scripts a faulty service
  that lost an app's stored parts.
- **Moves and recovery** (Switch spec 12.5, 12.6, Switch wire 10): `import_into` copies the
  account in memory, with no manifest, chunks or export transfer, to serve at the origin the
  freeze names (`import_into_at` names one for a move a test scripts without a freeze); a recovery upload is kept
  and answered with fixed changes, merging nothing.
- **Revocation** is `POST /apps/{app_id}/revoke` from the signer, and the test call
  `revoke`; an app that left is answered as one revoked already, with no proof. `leave` is a
  test call and also a route, `POST /apps/{app_id}/leave`, which checks only that the app
  hasn't departed: it takes any body, departs an app with no record or one whose certificate
  has expired or isn't listed, keeps the app's invite codes, push registration and inbox
  entries, and stamps the test clock's time. The service refuses another app's path and the
  signer with `403 permission_missing`, where this switch answers `404`, and an app of
  another identity with `403 permission_missing`, where this switch answers `403
  not_admitted` (Switch wire 7.4.12). `request_full_bundle` is a test call for the app's own
  route, and `forget_removal_time`
  scripts a faulty service that shows no time for a removal. Freeze and
  unfreeze are test calls, not routes.
- **`lose_identity`** scripts a faulty service that lost the account's `identity.json`.
- **The signer hand-over** (Switch wire 7.4.17), without the 12 MiB body cap of `PUT /handover`: `PUT /handover` runs the core's checks of a
  stored hand-over (`SignerHandover::check_stored`) for a current target with a checked
  certificate, and keeps one, replacing any it held; `GET /handover` serves it to the signer
  and to its target, also when that target isn't current, where the service answers `403
  not_current` (Switch wire 7.2): so a test can script a faulty switch that serves a
  hand-over while holding no copy of the version handed over; the next `identity.json`
  version, whoever delivered it, drops it. Unlike the service, it serves the body it parsed
  again as JSON, not the bytes the signer sent; it answers an own app's `PUT` `404` ("no
  route") where the service answers `403 permission_missing` with the head, and an app of
  another identity `403 not_admitted` where the service answers `403 permission_missing`.
  `stored_handover` names the target held; `stored_handover_body` and
  `store_handover_again` script a hand-over stored or served again after it was dropped.
- **`Fault::LeaveOut`** scripts a faulty service whose answer to an own app or the signer
  leaves out a top-level member, such as a feed page's `items`.
- **Erasure** (Switch wire 7.4.16), in `switch/signer.rs`: `POST /erase` checks the body names
  the account's service key (`409 conflict` for another) and refuses during a move (`409
  conflict`): at any frozen account, since this switch keeps no export to tell whether it was
  fetched, and at a staged one holding an import (not one staged for a key change in place).
  An app's call is `403 permission_missing`. Then every call, the retry included, gets the
  `404` signed with a fixed operator key. `erased` tells a test it happened; app tests set the
  flag directly.
- **Push** (Switch wire 8.1): registrations only; nothing is sent to a relay.

## Signer flows tested only here

These signer flows run only against the scripted switch, whose `GET /apps` follows the
service's rules (above). The service in this workspace serves `GET /apps`, `GET` and `POST
/apps/{app_id}/keys` and `POST /apps/{app_id}/leave`, so the full-bundle requests, reading the
stored parts, the departures and the hand-over can run against it now (`PUT` and `GET
/handover` too); the erasure waits for `POST /erase`:

- approval, renewals and reductions, their closings, and epoch completion
  (`crates/pubky-switch-signer/tests/approval.rs`, `renewal.rs`);
- revocations, departures, removal times and their bounds, full-bundle requests, purge and
  record cleanup (`revocation.rs`);
- the one-signer checks, alarms and their clearing, records behind, and publication
  (`flows.rs`);
- restore from the signer backup, in place and on a new install (`restore.rs`);
- the hand-over both ways, the abort, the take-over's checks and its lost answers, and which
  copies delete a key (`handover.rs`), save the scripted faults;
- the account's erasure, its lost answer, retry and refusal (`erasure.rs`): the service
  doesn't serve `POST /erase` yet.
