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
  one isn't refused. An enrollment's timestamp is checked the same way, before the
  enrollment is looked at, and its `401` is the operator's, with the clock's time in both
  places. Every other request stamps the clock's time. Answers to own apps and
  the signer carry `Switch-Head`, refusals included, but a `401`, the enrollment and the
  erasure. An injected `401` fault is answered as before the lock, with the last stamped
  time and no head; other injected faults with the clock's time and the head. A request an
  `Unreachable` fault stops keeps its body, which the test call `unreached_bodies` returns,
  in order. Each operation's signature is
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
- **Key bundle parts** go as the service drops them, by the core's `parts_to_drop`: at a
  `key_bundle.put` and at the `cursor.set` that passes them, the parts the target's cursor
  has passed and its `keys_through` covers, unless a full-bundle request is in force: from
  the `POST /keys` until the target's cursor has passed the part that completed it, or the
  part that replaced that one, judged at a put as before the part (Switch wire 6.2). Where
  `keys_through` starts rises to the height the dropped parts gave. `keys_through` itself is
  the core's (7.4.12), over the parts the cursor passed.
- **A cursor of an earlier generation** is a bare `seq` here, so after `change_key_into` or
  `import_into` the drop, the request's force and `keys_through` compare it as it is. The
  service counts such a cursor as 0 until the app moves it: nothing drops, a request stays
  in force, and `keys_through` reads low.

## State and retention

- **Durability** (Switch spec 6.5): everything is in memory, answered at once; the service
  key's mark isn't kept, so there is no state behind it: the service's `503` "a new
  generation is needed" (Switch wire 7.3 step 10), and the recovery delivery exempt from it,
  aren't modelled. Per-account order is a mutex.
- **Waiting reads** (Switch wire 7.4.4 `wait`): the transport of `holding_transport` holds a
  feed read with `wait` that has nothing to show its app, until the account's sequence
  grows or the wait has passed. The wait passes by the switch's clock, a test clock that
  wakes nobody: a held read notices at the next request to the switch or at
  `release_held_reads`, where the service answers by itself when its time is up. The
  transport of `transport` holds nothing and answers such a read at once. A `wait` that
  isn't an integer from 0 to 25 is `400`. A read is held only for a current app of an
  account that serves it: one that is gone, staged, or otherwise refuses the call answers at
  once. The read is admitted when it arrives, as at the service: its app is seen then and
  not again when the read is answered, and its app's lagging mark ends then. The switch's
  lock isn't held across the wait, and every request to the switch lets the held reads look
  again. A read held while its app is revoked or leaves is woken and refused `403
  not_current`, and one held while its account is erased gets the operator's `404`, never a
  page under the erased account's key (Switch wire 7.4.16). Unlike the service, a held read
  looks again only for something to show, the erasure and its time: an app whose
  certificate expires while its read is held is refused once the read is answered, where
  the service refuses it at the account's next commit; the answer is the same. Faults and
  the stale-timestamp check apply when the read is answered, not when it arrives.
  `held_reads` counts the reads held and not woken since they last looked.
- **Retention and sweeps** (Switch wire 9.1, 7.4.4): an entry goes once every current
  target that isn't lagging has passed it, as at the service, judged at cursor moves, at
  appends and at deliveries, revocations and leaves (`keep_passed_entries` turns that off
  for a test that reads an entry again); entries never expire by time. An app whose unread
  entries pass its share of the inbox quota (`set_inbox_quota`, 64 MiB unless set) is
  marked lagging while another current app reads, the mark ending at its feed read or its
  departure, and it gets a `missed` item for what goes unread, replaced while unpassed; an
  entry left with no current target at a delivery, revocation or leave becomes an
  `unreadable` item with the entry's `entry_id`. The quota refuses nothing here: no append
  is `429 quota_exceeded`, so a full inbox with no app reading, where the service refuses
  senders, isn't shown. Marks are judged at every such request, the switch's clock being
  trusted. A scripted `missed` item (`push_missed`) is shown to every app and a scripted
  `unreadable` item (`push_unreadable`) has an `entry_id` of its own, and both stay
  whatever the cursors. Checkpoints and dropped stubs exist only when a test scripts them;
  claims are deleted only when `GET /claims` finds them deletable; batch records are never
  dropped, and their proofs go only when a retry finds them past `batch_proofs_ms`.
- **Invite codes**: a revoked app's codes aren't withdrawn (Switch wire 7.4.3 "After a
  revocation"); a code planted for a faulty export never expires.
- **Lists**: `flagged` is always empty; connect requests are never full.
- **Records**: `divergent` is always `false`.
- **Directory** (Switch wire 7.4.10): an app is reachable from its first receive key until
  it is revoked or leaves; one that stops being current otherwise, with an expired or
  closed certificate, stays reachable, and `apps_version` doesn't move for it.

## Other calls

- **Queries** are read as the service reads them (`crates/pubky-switch/src/http/route.rs`,
  `parse_query`; Switch wire 7.1): names and values percent-decoded, and a bad escape or a
  parameter given twice `400` before the endpoint's checks, at `GET /feed` (after the
  signer's refusal, as at the service), `POST /inbox` (before the retry by content) and
  `GET /records`, and at the peer switch's `POST /inbox`. The feed's `limit` (1 to 500) and
  `wait` (at most 25) and the inbox's `apps_version` are digits only.
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
  as at the service (`crates/pubky-switch/src/service/records.rs`): a list's query is
  percent-decoded, and a parameter given twice is `400`, before the caller is judged; only
  own apps read (the signer gets `403 permission_missing`); a key, `collection` (required)
  and `after` must be `b64(32)`, and `limit` digits from 1 to 1000 (`400`); a record by key
  needs its `read_scope` (`403 permission_missing`, with the head), and a list shows only
  the records whose `read_scope` the reader holds, by the certificate the switch checks the
  app against. Unlike the service, which answers an own app it holds no certificate for
  `401` at authentication, this switch serves it as one holding no scope: `403` by key and
  an empty list. Order by the key text, `after`
  as a key's text, `next`, the byte budget with its first view shown, deleted records shown
  by key and left out of lists, and a view's `cert`, the certificate the write was checked
  against, kept with the record whatever a renewal or revocation later changes, are the
  service's.
- **`GET /claims/{claim_key}`** (Switch wire 7.4.8), in `switch/shared.rs`: only an own app
  holding `claims.read`, checked before the key, as at the service
  (`crates/pubky-switch/src/service/claims.rs`); then a key that isn't `b64(32)` is `400`.
- **Calls of an app of another identity it doesn't make** (`switch/inbox.rs`), as at the
  service (`crates/pubky-switch/src/service/rules.rs`, `other_app_refusal`; Switch wire
  7.4, 7.6): `403 permission_missing` at the reads only own apps make (`GET /feed`, `GET
  /claims/{claim_key}`, `GET /allow`, `GET /records/{key}`, `GET /records`), the key bundle
  calls, a leave, the hand-over and the signer's calls (`PUT /identity`, revoke, `GET
  /apps`, `POST /recovery/admission`, `POST /erase`); a batch and every other route `403
  not_admitted`.
- **`409 identity_needed`** to an app of another identity carries `known_version` beside
  `current`, `null` for no copy held or as to a stranger (Switch wire 7.1, 7.6), at the
  inbox, here and at the peer switch (`peer.rs`). Both also serve `POST /connect` and
  answer it so; the service doesn't serve it yet (`503 unavailable`).
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
  every later one gets the same key and changes nothing. As at the service, the same
  enrollment again gets its kept answer first, with no other effect, signed with the key it
  names. At a serving account, as at the service, a new enrollment is answered with a
  pending key for the next generation, the same
  for every such enrollment, signed with that key, and the App IDs it names are held with
  it. Once a delivery starts a generation under the pending key, an enrollment the outgoing
  key answered is `409 conflict` again, and one the pending key answered gets its answer
  again. Unlike the service:
  - an enrollment's `identity_doc` isn't held, so the account starts with no document and
    at the switch's own generation, whatever the enrollment names;
  - the pending key is derived from the account's, not random.

  Its errors, injected ones and the `409 conflict` included, are signed with the operator
  key, as at the service.
- **`PUT /identity`** (Switch wire 3.3, 7.4.2), in `switch/signer.rs`: judged by the core's
  `check_delivery`, like the service, with the kept proofs taken from what it holds: each held
  record's current write proof and each live claim's entry proofs, by the generation each
  names, with the key of that generation (its own, or the earlier service's that
  `import_into` carried). A first document carrying `recovery_from` starts the recovery as
  at the service: the account takes its generation, and its chain starts with the `recovery`
  transition, unless the switch was made `recovering`, which chained it already. A document
  naming the pending key with `recovery_from` is a provider loss in place, refused with
  `400` when it lists an App ID held with that key: the account starts afresh under that
  key, keeping its service time, its enrollments and the App IDs
  to refuse, those held with the pending key among them. Unlike the service: a key change
  in place, without `recovery_from`, is answered `400`; and a staged account's generation
  change, a move's, is chained where the service answers `503`. The test call `deliver_identity` takes any document, without those
  checks, for scripting what another signer or a faulty service did. `forget_delivery_proof`
  makes a retry answer with no proof.
- **Staged admission** (Switch spec 12.6 step 2, wire 7.4.14), in `switch/signer.rs` and
  `switch/inbox.rs`: as at the service, staged at a recovery whose first document lists an
  app; while it lasts, a sender not otherwise admitted, a stranger asking to connect
  included, gets `503 staged` at `PUT /peers`, at the inbox and at the directory;
  `POST /recovery/admission` ends it with the `admission` transition's proof, answers no
  proof when it isn't staged, and `404` without a recovery. Unlike the service: a switch
  made `recovering` doesn't stage admission. Neither ends it at a recovery upload yet: the
  service serves no upload, and this switch's takes no part in admission.
- **`GET /apps`** (Switch wire 7.4.12), in `switch/signer.rs`: by the service's rules, member
  by member, but `last_seen` and `recovery` (below):
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
    record's time, `admission_staged` as below), as the service sends it, and
    `proof_generations` from the same kept proofs as the delivery, the member left out when
    there are none.

  `unread_entries`, `sole_target_unread` and `lagging` are counted and set as at the
  service (Retention and sweeps, above). The test call `forget_bundle_parts` scripts a
  faulty service that lost an app's stored parts.
- **Moves and recovery** (Switch spec 12.5, 12.6, Switch wire 10): `import_into` copies the
  account in memory, with no manifest, chunks or export transfer, to serve at the origin the
  freeze names (`import_into_at` names one for a move a test scripts without a freeze); a recovery upload is kept
  and answered with fixed changes, merging nothing.
- **Revocation** is `POST /apps/{app_id}/revoke` from the signer, and the test call
  `revoke`; an app that left is answered as one revoked already, with no proof. `leave` is a
  test call and also a route, `POST /apps/{app_id}/leave`, which checks only that the app
  hasn't departed: it takes any body, departs an app with no record or one whose certificate
  has expired or isn't listed, keeps the app's invite codes and push registration, and
  stamps the test clock's time. The service refuses another app's path and the
  signer with `403 permission_missing`, where this switch answers `404` (Switch wire
  7.4.12). `request_full_bundle` is a test call for the app's own
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
  route") where the service answers `403 permission_missing` with the head.
  `stored_handover` names the target held; `stored_handover_body` and
  `store_handover_again` script a hand-over stored or served again after it was dropped.
- **`Fault::LeaveOut`** scripts a faulty service whose answer to an own app or the signer
  leaves out a top-level member, such as a feed page's `items`.
- **Erasure** (Switch wire 7.4.16), in `switch/signer.rs`: `POST /erase` checks the body names
  the account's service key (`409 conflict` for another) and, when it names one, the hash of
  the `identity.json` this switch holds (`409 conflict` for another, or for none held), and
  refuses during a move (`409 conflict`): at any frozen account, since this switch keeps no
  export to tell whether it was fetched, and at a staged one holding an import (not one
  staged for a key change in place).
  An app's call is `403 permission_missing`. Then every call, the retry included, gets the
  `404` signed with a fixed operator key. `erased` tells a test it happened; app tests set the
  flag directly. The service keeps no freeze or import state yet, so it refuses no erasure for
  a move; and after an erasure it takes `POST /v1/enroll` again, creating a
  new staged account, where this switch answers it with the operator's `404` too. That account
  serves from its first `identity.json`, at the next generation with `recovery_from` (Switch
  wire 7.4.16), which starts its recovery.
  This switch deletes everything at once and owes no key: its `404` comes right after the
  erasure. The service can owe the erased account's key when its key store fails, and until
  the key is gone it answers a request signed with the identity key, whatever its timestamp,
  with the operator's `503` in place of that `404`; every other caller gets the `404` at once.
- **Push** (Switch wire 8.1): registrations only; nothing is sent to a relay.

## Signer flows tested only here

These signer flows run only against the scripted switch, whose `GET /apps` follows the
service's rules (above). The service in this workspace serves `GET /apps`, `GET` and `POST
/apps/{app_id}/keys` and `POST /apps/{app_id}/leave`, so the full-bundle requests, reading the
stored parts, the departures, the hand-over (`PUT` and `GET /handover`) and the erasure can run
against it now:

- approval, renewals and reductions, their closings, and epoch completion
  (`crates/pubky-switch-signer/tests/approval.rs`, `renewal.rs`);
- revocations, departures, removal times and their bounds, full-bundle requests, purge and
  record cleanup (`revocation.rs`);
- the one-signer checks, alarms and their clearing, records behind, and publication
  (`flows.rs`);
- restore from the signer backup, in place and on a new install (`restore.rs`);
- the hand-over both ways, the abort, the take-over's checks and its lost answers, and which
  copies delete a key (`handover.rs`), save the scripted faults;
- the account's erasure, its lost answer, retry and refusal (`erasure.rs`), save the scripted
  faults;
- the provider loss: declaring it, at a new service and in place, declaring it again, the
  staged admission's end, a refused recovery, and a restore mid-recovery (`recovery.rs`),
  save the scripted faults;
- the warnings about an app's open attempts at a revocation and before a lapse
  (`revocation.rs`, `renewal.rs`), whose attempts the test calls `open_attempt` and
  `fail_attempt` script directly, with no entry or proof held and without the permission or
  writer checks the service makes; `open_attempt` refuses, as the service does, a second open
  attempt on a claim and any on a SETTLED one, and `fail_attempt` names the app resolving it.
