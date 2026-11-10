# App state in the store

The app layer keeps all of one app's durable state in the host's `StateStore`, namespace
`client/<app_id>` (the App ID in z-base-32). One record per key; no blob is rewritten whole.
Every value is `{"v":2,"d":<record>}` (`SCHEMA_VERSION`): a reader refuses an earlier `v`
as an old schema (`StoreError::OldSchema`) and any other as corrupt, so a later
schema adds a migration instead of reading old bytes wrongly. Keys are ASCII. Numbers in keys
are zero-padded to 20 digits so keys sort numerically. The record types are in `state.rs`.

## Rules for every change

- **Sign once, commit, send, commit the outcome.** A signed artifact goes into the store
  before it is first sent, and is resent byte for byte until answered (Switch wire 2.1).
  Examples: the join batch (`join`), a registration (`rk/<n>.pending`), a received message's
  effect (`pending/effect`), a record delivery (`pending/record`).
- **The cursor moves only with, or after, what it covers** (Switch spec 8.2, 11). The
  effect's batch carries the cursor move, with the record writes and claim entries the
  protocol added through its receive context. The processed pair, what the batch's
  operations settle (record writes cached at their proofs' versions, claim proofs kept), the
  protocol's local writes and the cursor are committed together with the answer. A claim
  the receive step asks for (`Outcome::Need`) is read and kept (`claim/`, `clent/`) in a
  commit of its own, which moves no cursor; the step then runs again. A step that ends in
  `Outcome::Retry` commits nothing of its own: only, with the page, its count under
  `retry/`, and the entry under `parked/` once the cursor passes it.
- **A batch refused with `409 stale_epoch`** is gone from `opq/` with the refusal; the app
  takes the newer `identity.json` and key bundle, each in its own commit, and the batch
  sealed again is signed and kept under a new batch ID before it is first sent.
- **A retired receive key goes only after the cursor's commit** that passes the next key's
  registration (Switch spec 3.6).
- **Any commit carries everything read before it.** A page's writes go in the next commit
  point, so no commit records a cursor past items whose writes it lacks.
- **After a failed commit the app reloads** from the store before its next call.
- **A kept batch or effect is never sent again past its window**, whatever the
  generation: 30 days from when it was kept, less an hour, both ends in verified service
  time, erring older. It is kept at the earlier of the device clock and the service time
  verified in the call that keeps it, which a one-item feed read fetches first when
  no answer of the call brought one; its age is judged at the later of the device clock
  and a service time verified in the call that sends it again, fetched the same way; a
  time verified more than 10 minutes before by the device clock, or with the device clock
  gone back since, is read again. One past the window by the clocks at hand already, the
  device clock or the service time held, needs no reading. Past
  it a retry would get `409 conflict` once the service dropped its proofs, or be taken as
  new once it forgot the ID (Switch wire 6.4 step 5): the effect's entry is parked as
  uncertain, the batch dropped with its attempts, unsent.
- **A refusal of a batch sent again tells only from the batch ID lookup on** (Switch wire
  6.4 step 5). One made before it is about the caller, such as `403 cert_expired`, or about
  these bytes, such as `400`. About the caller, it tells nothing of the batch: a kept effect
  or batch stays as it is, to go again unchanged once the service accepts the app's
  requests, and a renewed certificate is taken before a kept effect goes again; past the
  window it is parked or dropped as uncertain. About these bytes, it will come again: the
  effect's entry is parked as uncertain, or the batch dropped with its attempts, at once.
  The codes are classified in one place (`refusal_place`).
- **A duty event goes in the commit of what it reports** (`duty/<id>`), and is reported
  only once that commit is done: a failed commit reports nothing, and a crash after it
  loses nothing, since every load reports the kept duty events again. A commit that
  answers `StoreError::Unknown` may have been applied: the reload after it reports every
  kept duty event no call reported yet. An acknowledgement removes only events handed to
  the host since the app was loaded, by `take_events`, a call's report or
  `unacknowledged_events`.
- **Only the host's acknowledgement removes a duty event.** The app sets no cap on
  `duty/`: a cap would have to lose a duty event, or stop reading the feed (which never
  stalls, Switch spec 8.2), giving up undeliverable messages (Switch spec 11) or following
  a provider change (Switch spec 12.5, 12.6). A host acknowledges each one once its
  protocol has kept what it says.
- **A restore is one commit:** the namespace cleared, the app's restored state and the
  protocol's backup layer under `p/`, both checked before it, so a failure leaves neither.
  A backup with a layer also carries `seen/`, `parked/` and `proc/` of the same moment,
  which the layer may reflect, so no entry is handed to the protocol twice.
- **A layered backup reads one moment:** `App::backup_layered` is several store reads in
  sequence, and they agree because the call takes `&mut self`, so no call of the app commits
  between them, and the store allows one writer per namespace (`StateStore`, rule 4), so no
  other process does.

## Keys

| Key | Holds | Sensitive |
|---|---|---|
| `meta` | identity, App ID, switch origin, pinned service key, generation followed | |
| `keys` | the app's signing and bundle secrets (`AppKeys`) | yes |
| `cert` | the certificate the app presents (signed) | |
| `cert/renewal` | a renewed certificate from `cert.put`, until its `identity.json` lists it | |
| `record` | the app record the service holds or is being given (signed) | |
| `naming` | the naming key | yes |
| `scope/<epoch>/<scope>` | one scope key | yes |
| `bundle` | `keys_through`, and when a full bundle was requested | |
| `ident/<pubky>/doc` | the newest `identity.json` taken for an identity, own or a sender's, and when it was read | |
| `ident/<pubky>/floor` | the highest version and generation seen | |
| `ident/<pubky>/body/<version>` | the body hash seen at a version, for equivocation | |
| `ident/<pubky>/equivocated` | the version at which another body was seen | |
| `ident/<pubky>/sw` | when a counterparty's switch copy was last looked up, whether the read succeeded, and the lookup's number | |
| `ident/<pubky>/swn` | the number of the last switch lookup begun for a counterparty, which orders the lookups whatever the clock reads | |
| `ident/<pubky>/reads` | when a counterparty's `identity.json` was last read from its Homeserver, and from its switch | |
| `rk/<n>` | a held receive key: secret, signed record, registration `seq` and service time, pending batch | yes |
| `kid/<kid>` | a kid this app or one of its devices made, kept after the key is deleted | |
| `reg/<n>` | a registration of the own app whose key this device doesn't hold: own, awaiting device sync, or unaccounted after a restore | |
| `rotation` | the last rotation's time, and whether an envelope to the current key was opened since | |
| `device` | whether the app shares its keys across devices | |
| `cursor` | the processed position, the cursor the service holds, the deferral, the cursor's time | |
| `chain` | the chain view's small fields: tip, open batch, pending heads and checkpoint, newest head, the continuity gap, held marks, restore state | |
| `chain/at/<seq>` | the verified chain hash at a `seq`, from a little behind the cursor on: the hashes behind it are forgotten in steps | |
| `chain/batch/<id>` | a batch ID in the 30-day window, with its first stub's time | |
| `proc/<sender>/<msg_id>` | a processed message's hash and time | |
| `proct/<time>/<sender>/<msg_id>` | the time index for pruning processed pairs | |
| `seen/<seq>` | an entry processed past a held one | |
| `held/<seq>` | an entry held because its sender can't be checked, since when | |
| `retry/<seq>` | an entry whose receive step the protocol's store or the host kept from finishing (`Outcome::Retry`): the reads in a row that ended so, and when the first was; kept while the entry is stored locally too, and it goes once the entry is processed | |
| `parked/<seq>` | an entry stored locally and passed: the opened plaintext, sender, certificate, time, reason (an unverifiable sender, a quota or a store failure of the receive step, tried again; an effect refused for good, over one batch, carrying an operation the app layer builds itself, or kept past the window in which its resend tells whether it was applied, not tried again) | yes |
| `asked/<seq>` | a re-send was handed to the protocol for this item | |
| `parkn` | where the retries of entries stored locally stand in their round: its number and the next `seq`. The round covers the entries stored in an earlier round, each `parked/` record naming the round it was stored in, not by `seq`, which a provider loss renumbers; each read tries at most `PARKED_RETRIES_PER_READ`, in `seq` order, and an entry stored later waits for the next round, so every entry is tried within two rounds | |
| `owed/<generation>/<seq>` | a re-send or missed-entries call about this item that the protocol answered with an error: written in the commit that passes the item, made again at the start of each read, each call on its own, and gone in the commit of its answer's writes; `App::owed_protocol_calls` counts them. The key names the generation the item was read at | |
| `departed/<app_id>` | another own app's departure verified in the chain, and its time | |
| `join` | the join step: the registration batch while it is owed | |
| `pending/effect` | a received message's effect batch and its outcome writes, with the deadlines of the claims it writes, and the opened entry, to store it locally if the batch outlives the batch ID window | yes |
| `pending/record` | an `app.put` batch | |
| `alarm` | the alarm that stopped the app | |
| `restore` | after a restore: the backup's highest `n`, the key check, the app's own new key, reconcile mode | |
| `leave` | a leave in progress or done | |
| `service_time` | the highest service time verified, its key, the offset from the device clock | |
| `p/...` | the protocol's own local state (`LocalWrite`) | the protocol's |
| `duty/<id>` | a duty event (`AppEvent::is_duty`), written in the commit of the change it reports, until the host acknowledges it (`App::ack_events`); one per entry stored for good, kept batch or `attempt` dropped, kept batch refused for good, or outbox message given up. Only acknowledgements remove them: nothing bounds them for a host that never acknowledges | |
| `dutyn` | the counter the next duty event takes; it only goes up in one store, and a restore in place keeps it | |
| `dutye` | the store's event epoch, random, chosen once when the store starts empty (the first join, or a restore onto a store without one); every duty event ID carries it with its counter | |

Deleting the keys on a leave removes `keys`, `naming`, `rk/`, `scope/`, `parked/`,
`pending/`, `p/`, `duty/` and `owed/`, and marks `leave`.

## Extending the schema

- New records take new keys under a prefix of their own; existing keys keep their meaning.
- A changed record type bumps `SCHEMA_VERSION` with a migration that runs on load.
- `SCHEMA_VERSION` 2: `pending/effect` keeps the opened entry it is for, a required field.
  No migration reads a store of schema 1; such a store fails to load as an old schema, and
  a backup an earlier schema wrote (schema 1, or a layered backup of version 2) is refused
  the same way (`StoreError::OldSchema`). A store or backup of an earlier schema has no way
  forward but a new join; no tagged or pinned build wrote schema 1.
- Protocol state stays under `p/`, written only through `LocalWrite`.

## Moves, recovery and push

`provider.rs` follows a cooperative move or a key change in place, and keeps that the app
isn't current any more; `recovery.rs` follows a provider loss and keeps the evidence for
uploads; `push.rs` holds the push registration. The peek (`peek.rs`) writes nothing.

| Key | Holds | Sensitive |
|---|---|---|
| `mv` | a move in progress: the signed freeze (none for a key change), the generation left, the step, the re-registration batch signed once | |
| `gens/<generation>` | a generation the app left: its origin and service key, and the last own `identity.json` taken there | |
| `loss` | a provider loss followed: the step, the old newest head, the cursor's time there, the declaration time, the clocks' offset, the new key's `n`, the batch of the current step, the conversation entries still to add back | |
| `ev/op/<hash>` | a kept `record.put` or claim entry, with its writer's certificate and its proof when held | |
| `ev/proof/<hash>` | a kept transition proof | |
| `lc/contact/<pubky>`, `lc/deny/<pubky>` | the app's copy of the contacts and deny list, from the feed | |
| `lc/code/<hash>` | an invite code this app registered, from the feed | |
| `push` | the push setting: relay, device token, the service it is at, the push key, the handle, whether set, a rotation in flight | the device token |
| `push/devices` | the handles of the app's other devices and the push key they are bound to, from the host's device sync, merged into the handles this device sets | the handles |
| `gone` | the app isn't current any more, or its account is gone, and since when | |
| `erasing` | since when every try met an unsigned `404` and no published `identity.json`, the last try counted and how many were | |

- **A move** commits each step: `Seen` (the freeze verified and kept), `Read` (the old feed
  read to its end, its chain view saved), `Uploaded` (the evidence sent to the next
  service), `Switched` (`meta`, the cursor's generation, the chain view and the
  re-registration batch, in one commit), `Registered`; then `mv` goes. The old feed is read
  by its pages' `next`, apart from the verified chain position. Of the batches signed for
  the old generation, `pending/record` and a pending receive key registration go at the
  switch, since the record and the newest key go in the re-registration. A kept
  `pending/effect` or `opq/<batch_id>` whose batch ID the old chain holds was applied: its
  outcome commits at the switch. Otherwise the effect goes, and its entry is read again;
  a kept `opq/` batch is signed again for the new generation under a new batch ID. A
  frozen service's `410 moved` keeps them for the switch. A move the app never saw frozen,
  or a key change in place, didn't read the old feed to its end: its kept batches and
  effect stay unchanged and go again first, and the answer decides (original proofs or
  `409 conflict`: applied; `409 stale_generation`: signed again). Past 30 days less the
  clock tolerance from when it was kept, at the switch or at any later resend, or with no
  time kept, `409 stale_generation` decides nothing: a batch goes, reported as dropped,
  and an effect's entry is parked in the commit that drops the effect, never applied
  again, and the protocol is told (`EffectUncertain`).
- **A newer own `identity.json`** that names a later generation, a loss of the generation
  moved from, or another service than the freeze, supersedes a move or a loss at any step,
  a stuck one included: after a step fails at a service the app reads its `identity.json`
  from the Homeserver, gives the change up and follows the newer document.
- **A loss** starts in one commit, before any call: `meta`, a cursor and chain view from the
  start of the new sequence, a fresh receive key with its registration batch, the
  registrations of the old service cleared, the kept writes judged against the old chain
  view as at a move (a kept batch holding an `attempt` goes instead of being signed
  again), `restore.reconcile` on, and `loss`. Each step then commits as done; the
  protocol's re-send writes commit with their step, once. A registration another device
  of the app made first is adopted, and the record then goes alone. A protocol that answers
  the re-send step with an error leaves the loss at that step, to be asked again.
- **`gone`** stops every read; `push` goes with it. It is kept only once the newest verified
  own `identity.json` removes the app or doesn't list it, a `403 not_current` came while it
  lists the app with the certificate the app holds, or the account is erased: an unsigned
  `404` and no published `identity.json` at every try, counted at 5 tries at least 6 hours
  apart by the app's clock, which `erasing` times. Any answer the account's key signs, or a
  published `identity.json`, ends `erasing`. An erased account seen alive again, its
  `identity.json` published and listing the app, ends `gone`: its `push` setting is kept,
  no longer set, and the other devices' handles too; an app that isn't current drops both.

## Sending, admission, records and claims

| Key | Holds | Sensitive |
|---|---|---|
| `out/<msg_id>` | a queued message, queued alone or with the answer of the batch that carried it: its signed plaintext, signed once, the envelope sealed for one try with its `apps_version`, its jobs (conversation entry, delivery, record) and where each stands, a re-send owed, when it was refused for good, and when a delivery was first and last answered `403 not_admitted` or `403 not_current`, with the answers counted at least 7.5 days apart; a failed one goes after the sent-message retention, an undeliverable one when a try is answered so again 30 days after that first answer and 5 answers were counted, or at the first flush 45 days after it in any case | yes |
| `sent/<msg_id>` | a message the recipient's inbox accepted, written in the commit that records the acceptance, kept 30 days from its first acceptance for re-sends | yes |
| `sentt/<time>/<msg_id>` | the time index for pruning sent messages | |
| `dir/<pubky>` | a counterparty's directory as signed, the switch, generation and `identity.json` version it was read under, its versions, and whether it is read again before the next send | |
| `rkn/<pubky>/<app_id>` | the highest receive key `n` seen for a counterparty's app | |
| `peer/<pubky>` | the version of the own `identity.json` a counterparty's switch last named, and when the app last wrote there | |
| `peers_doc` | the own `identity.json` the deliveries to recent peers were last judged against, and the counterparties still owed it | |
| `lc/conv/<pubky>` | a conversation entry in the app's copy of the lists, from its writes, the feed and `GET /allow`; its writes and `GET /allow` also keep `lc/contact/`, `lc/deny/` and `lc/code/` | |
| `invite/<code_hash>` | the code of an invite code the app registered, to show it again | yes |
| `opq/<batch_id>` | a batch of operations, signed and kept before it is sent, with what its answer settles: the protocol's local writes and the signed messages it puts in the outbox; it goes with its answer or a refusal for good, and stays through anything else | the messages' |
| `list_due` | a listing of the collections is owed: after joining, a restore or a `missed` item | |
| `rec/<key>` | the shared record write the app took: the signed operation, certificate and proof, its version and whether a proof gave it, the opened value, and the refused write it follows | yes |
| `recname/<key>` | the collection name of a record the app creates outside the protocol's collections, from a write or an effect, until its write is answered | |
| `hw/<key>` | the protocol's mark of what the app has seen in a record | the protocol's |
| `flag/<key>/<generation>/<version>` | a write the app refused, with the app it names and the rule | |
| `ocert/<app_id>/<cert_hash>` | a certificate of an own app, for checking its writes | |
| `claim/<claim_key>` | the newest claim view, the proof that shows it SETTLED, the newest entry's time and the deadline the app computes, kept until the evidence's retention ends | |
| `clent/<claim_key>/<step>` | a signed claim entry and its proof | |

Deleting the keys on a leave also removes `rec/`, `hw/`, `recname/`, `out/`, `sent/`,
`sentt/`, `invite/` and `opq/`. A restore replaces the namespace, these keys included, and
sets `list_due`. `rec/`, `clent/` and `claim/` hold the evidence of the shared state that
uploads carry (`App::shared_evidence`).

## What the app owes its protocol: restores and provider changes

`duty/<id>`, `dutyn`, `dutye` and `owed/<generation>/<seq>` hold what the app still has to
tell its protocol, so neither a restore nor a provider change drops them.

- **A backup carries none of them.** They are the store's, not the app's keys or position.
- **A restore in place** (into a store that holds an epoch) keeps `dutye`, sets `dutyn` to
  the higher of the store's counter and the highest kept counter plus one, and carries
  `duty/` and `owed/` across the namespace's replacement, all in its one commit: the duty
  events keep their IDs and are delivered again, and the owed calls are made by the next
  read. The restored cursor may meet the same items again; the protocol then hears of them
  twice, which it tolerates.
- **A restore in place is the way out of a damaged store.** A store that can't be read
  now fails it, to be tried again. A duty event or owed call whose value reads but
  doesn't decode is left behind, and the protocol told how many with `RestoreLeftBehind`,
  a duty event in the restore's commit. A damaged `dutye` or `dutyn` starts a new epoch,
  the readable duty events kept under it.
- **A restore on another device, or onto a wiped store** (one without an epoch), starts a new random epoch at the first counter, with none of them:
  their facts stayed with the lost store. Its IDs can't equal any the host acknowledged
  before, whatever the counters or the clock, since an ID is its epoch and its counter.
- **IDs compare only within one store.** `App::ack_events` refuses an ID of another epoch
  and acknowledges nothing.
- **A provider change keeps them** (a move, a key change in place, a provider loss). The
  duty events report facts that stay true. An owed call is still made at the generation
  followed: a re-send call names a sender and acceptance times, which the counterparty
  answers wherever the app reads now, and a missed-entries call names the item's `seq` at
  the generation in its key, which the protocol takes as information only. After a loss
  the protocol is also asked for the loss's re-sends; a request twice is answered once,
  since re-sends are deduplicated by `msg_id` (Switch spec 11).
