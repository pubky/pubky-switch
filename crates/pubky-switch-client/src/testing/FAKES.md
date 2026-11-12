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
- **Injected faults** (`fail_next`) script a network or a service that fails: an error
  answer, a lost answer (the request applied, the caller sees a timeout), a connection that
  fails, or an answer with a member left out. A lost answer or a failed connection can let a
  number of matching requests through first (`LoseAnswerAfter`, `Unreachable`), so a test
  can pick one request of several to the same path.
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
  page under the erased account's key (Switch wire 7.4.16). One held while its account
  recovers in place is woken by the recovery and answered `503 unavailable` with the operator
  key and no head, as at the service: the key it was read under signs nothing more (Switch
  wire 7.4.4); `recover_in_place` recovers the account through its own `PUT /identity`, for
  tests. Unlike the service, a held read looks again only for something to show, the
  erasure, the account's service key and its time: if a recovery in place and then an
  erasure both land before a woken read looks again, it gets the `503` where the service
  answers `404` (no flow of one task reaches it). An app whose
  certificate expires while its read is held is refused once the read is answered, where
  the service refuses it at the account's next commit; the answer is the same. Faults and
  the stale-timestamp check apply when the read is answered, not when it arrives.
  `held_reads` counts the reads held and not woken since they last looked. Unlike the
  service, every request the switch answers first wakes every held read to look again
  (`wake_held`), and a read with nothing to show then waits on. So a missing specific wake
  (at a chained item, `start_afresh` or an erasure) is covered by the next request's: a test
  sees it only if nothing else reaches the switch while the read is held.
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
  trusted. A scripted `missed` item (`push_missed`, or `push_missed_unparsable` for one whose times don't parse) is shown to every app and a scripted
  `unreadable` item (`push_unreadable`) has an `entry_id` of its own, and both stay
  whatever the cursors. Checkpoints and dropped stubs exist only when a test scripts them;
  claims are deleted only when `GET /claims` finds them deletable; batch records are never
  dropped, and their proofs go only when a retry finds them past `batch_proofs_ms`.
- **Invite codes**: a revoked app's codes aren't withdrawn (Switch wire 7.4.3 "After a
  revocation"); a code planted for a faulty export never expires.
- **Lists**: `flagged` is always empty.
- **Connect requests** (Switch wire 7.4.7), in `switch/inbox.rs` `connect` and
  `switch/shared.rs`: as at the service (`crates/pubky-switch/src/service/connect.rs`), in its
  order: `503 staged` while admission is staged, whatever the policy; `403 not_admitted` with
  the policy off; check 5 by the sender's certificate: the copy lists the app with it, or
  a renewal of it still open, a closed renewal being `403 not_current`, and otherwise `409
  identity_needed` naming the held version, or none when the copy lists the app as
  removed; a sender already pending answered `pending`; the policy's `max_pending`, capped at the
  wire's default `max_connect_pending` (1,000), refusing a new sender `429 quota_exceeded`
  before the deny list; a denied sender answered `pending`, its request not kept. `GET
  /connect` needs `lists.read`, `DELETE /connect/{pubky}` `conversation.add`, and an own app's
  or the signer's `POST /connect` is `403 permission_missing`. A contact, a conversation
  entry or a deny list entry for the sender answers its request, the entry an invite code's
  first append writes and the entries a recovery upload's list merge writes included. Unlike the service: no `connect_per_min` or
  `stranger_per_min` (no rates, above), and no flag hits. A sender the allowlist admits is
  answered `pending` with nothing kept, as at the service. Neither switch sends the push
  `policy.connect_requests.push` asks for yet: push isn't served.
- **Records**: `divergent` is set by divergent uploads after a provider loss and cleared
  by a write here, as at the service (Recovery uploads, below).
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
  app against. An own app it holds no record for meets the first-call refusal below, as
  at the service, before its query or key is read. Order by the key text, `after`
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
  /apps`, `POST /recovery/admission`, `POST /erase`) and every other call of Switch wire 7.4,
  a recovery upload, push, the connect reads and the move's included; a batch `403
  not_admitted`; and a route that isn't one `404`.
- **`409 identity_needed`** to an app of another identity carries `known_version` beside
  `current`, `null` for no copy held or as to a stranger (Switch wire 7.1, 7.6), at the
  inbox, here and at the peer switch (`peer.rs`). Both also serve `POST /connect` and
  answer it so.
- **`open_admission`** (`admit_everyone`) admits every sender the deny list doesn't hold, a
  test switch only.
- **An own app's first call** (Switch wire 7.1 "`Switch-Head` on refusals", 7.2), as at
  the service (`crates/pubky-switch/src/service/batch/mod.rs`, `verify_own_app`): an own
  app the switch holds no record for, at any call but a `POST /ops` whose batch carries its
  `app.put` or doesn't parse, gets `403 not_current`
  at authentication, before the account's lock and before a staged or frozen account's
  answer (Switch wire 7.3 steps 5 to 8), whatever the route: no `Switch-Head`,
  `Switch-Server-Time` the last time stamped, and the app not seen. A departed app that
  delivered its record keeps it, so it goes on to the route's checks, as at the service,
  until the test call `purge` frees it, as a service may once the signer purges the app
  from `removed` (Switch wire 9.1): then it meets the first call's refusal, without the
  head. The service keeps a purged app's record, so it answers that app with the head.
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
  to refuse, those held with the pending key among them, and, as the service does, its upload
  limits, its hourly upload counts, the directory's `apps_version` and
  `directory_version`, which go on counting, and what a test set of its configuration (the
  feed's page limits, kept passed entries, open admission). Unlike the service: a key change
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
  made `recovering` doesn't stage admission. An upload carrying contacts from an app holding
  `lists.manage` ends it, as at the service.
- **Recovery uploads after a provider loss** (Switch wire 7.4.14), in `switch.rs`
  `loss_upload` and `switch/shared.rs` `merge_upload`: the core's checks
  (`UploadBody::parse`, `check_permissions`, `check_upload`) and merge
  (`merge_checked_record`, `merge_upload_claim`), as at the service, so the counts and the
  changes are the service's, one `upload` transition each; `uploads_per_app_per_hour`
  (`429 rate_limited` until the next hour of the switch's clock; every upload from an app
  the switch holds a record for takes a slot, one refused for its body or its lists, as
  `not_current`, or with `404` at an account in neither stage included, and the refusals
  keep the wire's order past the limit; the `429` repeats `retry_after` in `Retry-After`, as every `429` of this switch
  does), `max_contacts` and
  `max_deny` as at the service, the wire's defaults unless a test sets them; and `404` at an
  account in neither stage. Unlike the service: `max_divergent_uploads` and
  `max_attempts_per_claim` are the wire's defaults, and `GET /claims` lists whatever entries
  the switch kept, with no check that a claim holds one at each step.
  For tests of what an app does with an `upload` transition, `chain_upload` chains one
  listing the changes as written, merging nothing: the test makes the merge itself, or none.
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
  freeze names (`import_into_at` names one for a move a test scripts without a freeze); a recovery upload at a staged
  service or after a move is kept and answered with fixed changes, merging nothing.
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
  leaves out a top-level member, such as a feed page's `items`; **`Fault::Replace`** one
  whose answer carries another value for it, such as `GET /apps`' `identity` replaced by a
  copy that doesn't verify; **`Fault::SignWith`** one that applies the request and signs
  its answer with another key, such as a third key, or the key a recovery in place leaves,
  signing the delivery that starts the new generation; **`Fault::ErrorSignedWith`** an
  error answer under another key, applying nothing.
- **Erasure** (Switch wire 7.4.16), in `switch/signer.rs`: `POST /erase` checks the body names
  the account's service key (`409 conflict` for another) and, when it names one, the hash of
  the `identity.json` this switch holds (`409 conflict` for another, or for none held), and
  refuses during a move (`409 conflict`): at any frozen account, since this switch keeps no
  export to tell whether it was fetched, and at a staged one holding an import (not one
  staged for a key change in place).
  An app's call is `403 permission_missing`. Then every call, the retry included, gets the
  `404` signed with a fixed operator key. `erased` tells a test it happened; app tests set the
  flag directly. The service keeps no freeze or import state yet, so it refuses no erasure for
  a move. After an erasure both take `POST /v1/enroll` again and make a new account under
  another service key, which signs that answer and every answer after it; nothing of the
  erased account stays, its kept App IDs included, which the new enrollment names again.
  That account serves from its first `identity.json`, at the next generation with
  `recovery_from` (Switch wire 7.4.16), which starts its recovery.
  This switch deletes everything at once and owes no key: its `404` comes right after the
  erasure. The service can owe the erased account's key when its key store fails, and until
  the key is gone it answers a request signed with the identity key, whatever its timestamp,
  with the operator's `503` in place of that `404`; every other caller gets the `404` at once.
- **Push** (Switch wire 8.1): registrations only; nothing is sent to a relay.

## Signer flows: what runs against the service too

The signer's own tests run against the scripted switch. The harness
(`crates/pubky-switch-harness`) runs some of the honest paths of the same flows against the
service as well and compares the two, so for these groups a difference between the scripted
switch and the service shows there:

- approval, renewals and reductions, a reduction's closing with its publication failing,
  rotations over several epochs, and an epoch completed after a rotation was given up at a
  batch (`crates/pubky-switch-signer/tests/approval.rs`, `renewal.rs`);
- an approval with a protocol's grant paths declined, the paths allowed at a later
  request, and a decline the protocol's rule refuses (`grant_paths.rs`);
- revocations and departures, the time a removal counts from, full-bundle requests, the
  record's cleanup and the purge, a revocation past a read that failed and one asked for
  during a recovery (`revocation.rs`, `recovery.rs`);
- publication put right, the alarm for another document on the Homeserver and its
  clearing, another install signing, and records behind (`flows.rs`);
- restore from the signer backup, in place and on a new install, with a version never
  delivered and with a revocation only the switch holds (`restore.rs`); two installs
  restored at once, the second delivery refused `409 stale_identity`, which the signer's
  own tests don't run;
- the hand-over both ways, its abort, and the abort racing the take-over with either
  arriving first (`handover.rs`), the account's erasure and its
  lost answer (`erasure.rs`), and the provider loss: declared at a new service and in
  place, declared again, refused, its staged admission ended, and restored mid-recovery
  (`recovery.rs`).

A grant path the user declines at an approval (Switch spec 3.4) needs nothing here: the
declines change only the Pubky grant the host approves, never the certificate, the version
or the key bundle, so the switch's traffic is the same as for an approval that allows them.

Not every honest path has a flow there. Among those without one: a stale backup refused at
a restore, a Homeserver that holds another body at a restore, a restore in place below
the signer's mark (`restore.rs`), and a restore on a new install from a backup a recovery in
place wrote before its version reached the service, which answers under the key it served
with until then (`recovery.rs`): the scripted switch serves under the account's key and holds
the pending key apart, as the service does, so it needs nothing more for it.

What stays only on the scripted switch, and why:

- **A switch that misbehaves.** A removal time reported before the app was listed or after
  the answer that reports it; a copy of `identity.json` that doesn't verify, is older than
  the signer's mark, or has another body at it; an answer signed with the wrong key or
  with a member left out. The service does none of these, so only a scripted fault shows
  what the signer does about them.
- **A delivery refused for good,** other than a recovery's version over the service's app
  limit: a `400` to any other version (an ordinary or a renewing version, a restore's next
  version), a take-over refused `400`, or a `413 too_large`. No conforming signer meets
  these at the service, so the tests script the refusal.
- **Exact timing.** A crash at each commit of a flow, a store that fails or can't tell
  whether it committed, and an answer lost at one chosen call among several alike: the
  tests place these by a commit's or a request's number.
- **A backup that doesn't open or is missing,** and a Homeserver that is down for a whole
  call: the Homeserver's faults in the harness are a single failed write or deletion.
- **The warnings about an app's open attempts** at a revocation and before a lapse
  (`revocation.rs`, `renewal.rs`), whose attempts the test calls `open_attempt` and
  `fail_attempt` script directly, with no entry or proof held and without the permission or
  writer checks the service makes; `open_attempt` refuses, as the service does, a second open
  attempt on a claim and any on a SETTLED one, and `fail_attempt` names the app resolving it.

## The test Homeserver

`homeserver.rs` holds public files in memory, as a Homeserver serves them, with no
authentication: an app's writes through `HomeserverWriter` go to any path of the identity it
names, where a Homeserver checks the app's grant (Switch spec 3.4). `set_down` makes every
read and write fail to connect, and `identity_reads` counts the reads of an identity's
`identity.json`, those that failed included, so a test can bound how often the app reads a
counterparty's document. `fail_writes` fails the next writes, refused or with the answer
lost after the file is written, and `writes` counts the writes of a path.
