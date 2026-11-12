# App state in the store

The app layer keeps all of one app's durable state in the host's `StateStore`, namespace
`client/<app_id>` (the App ID in z-base-32). One record per key; no blob is rewritten whole.
Every value is `{"v":3,"d":<record>}` (`SCHEMA_VERSION`): a reader refuses an earlier `v`
as an old schema (`StoreError::OldSchema`) and any other as corrupt, so a later
schema adds a migration instead of reading old bytes wrongly. Keys are ASCII. Numbers in keys
are zero-padded to 20 digits so keys sort numerically. The record types are in `state.rs`.

## Rules for every change

- **Sign once, commit, send, commit the outcome.** A signed artifact goes into the store
  before it is first sent, and is resent byte for byte until answered (Switch wire 2.1).
  Examples: the join batch (`join`), a registration (`rk/<n>.pending`), a received message's
  effect (`pending/effect`), a record delivery (`pending/record`). A record is published on
  the Homeserver only once its delivery's answer is committed (`pending/publish`), in the
  bytes the switch holds.
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
- **A kept batch has one ID for its whole life:** the batch ID it is first kept under
  (`opq/<batch_id>`). Signed again for a later generation, its bytes carry a new batch ID
  and stay under the same key, so `AppError::Kept`, every event about it and
  `App::kept_batch` name the first one; the wire ID is in the record's body. The commit
  that applies or drops it writes its end (`kb/<batch_id>`, `kbt/`) with that change, so
  no crash leaves a batch neither kept nor ended.
- **A passed entry keeps nothing** (`Outcome::Pass`): the cursor moves past it as past a
  processed one, or `seen/<seq>` marks it past a held one, and nothing else is written: no
  `proc/` or `proct/` pair, so a re-send of the message is delivered again (Switch spec
  11), no `parked/` entry, no `duty/` event, nothing the context added. An entry stored
  locally that the protocol passes stays as it is under `parked/`, with its `sretry/` count.
- **A retired receive key goes only after the cursor's commit** that passes the next key's
  registration (Switch spec 3.6).
- **Any commit carries everything read before it.** A page's writes go in the next commit
  point, so no commit records a cursor past items whose writes it lacks.
- **After a failed commit the app reloads** from the store before its next call.
- **A kept batch or effect is never sent again past its window**, whatever the generation:
  30 days from its first send, less an hour, both ends in verified service time, erring
  older. Its first send is stamped (`kept_ms`) at the earlier of the device clock and a
  service time verified in that call, which a one-item feed read fetches first when no
  answer of the call brought one, and the stamp is committed before the request leaves; a
  batch never sent has no stamp and no window, can't be ambiguous, and is never judged for
  age, and a call that can't verify a time leaves it kept and unsent. An effect is stamped
  the same way when it is kept, right before its first send. Its age is judged at the later
  of the device clock and a service time verified in the call that sends it again, fetched
  the same way; a time verified more than 10 minutes before by the device clock, or with the
  device clock gone back since, is read again. One past the window by the clocks at hand
  already, the device clock or the service time held, needs no reading. Past it a retry
  would get `409 conflict` once the service dropped its proofs, or be taken as new once it
  forgot the ID (Switch wire 6.4 step 5): the effect's entry is parked as uncertain, the
  batch dropped with its attempts, unsent.
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
- **Only the host's acknowledgement removes a duty event,** with one exception: the commit
  that takes an erased account back (`AccountBack`, Switch spec 12.7) removes the
  `AccountGone` events not yet acknowledged, which no longer hold. The app sets no cap on
  `duty/`: a cap would have to lose a duty event, or stop reading the feed (which never
  stalls, Switch spec 8.2), giving up undeliverable messages (Switch spec 11) or following
  a provider change (Switch spec 12.5, 12.6). A host acknowledges each one once its
  protocol has kept what it says.
- **A restore is one commit:** the namespace cleared, the app's restored state and the
  protocol's backup layer under `p/`, both checked before it, so a failure leaves neither.
  A backup with a layer also carries `seen/`, `parked/` and `proc/` of the same moment,
  which the layer may reflect, so no entry is handed to the protocol twice. A kept
  effect's entry goes in as a stored uncertain copy with its `seq` in `seen`, as the app
  passes an entry it stores: its processed pair ages out after 30 days, and the `seq`
  keeps a restore from an older backup from handing it over again unless the host
  releases the copy.
- **A layered backup reads one moment:** `App::backup_layered` is several store reads in
  sequence, and they agree because the call takes `&mut self`, so no call of the app commits
  between them, and the store allows one writer per namespace (`StateStore`, rule 4), so no
  other process does. Before those reads it commits the bound's drops of entries stored
  unverified, so it needs a writable store, and the drops stay committed if the backup is
  then refused; an app halted by an alarm, left, or no longer current here skips them and
  only reads. It makes no network call: the entry a kept effect (`pending/effect`) belongs
  to, stored or read from the feed, goes into the backup as `Uncertain`, its flags kept,
  with the processed pair of its message, since a restore never carries the kept effect;
  the live store keeps the effect as it is. An entry read from the feed takes a local ID the
  live store reserves first by moving `parkid` on, on a halted app too (the backup's one
  write of its own; its commit also keeps a service time not yet committed), so no later
  entry of the live store takes it.

- **A backup carries the outbox:** every `out/` record as it stands, a message refused for
  good included, so the restored app reports it failed until it is forgotten; oldest queued
  first, within `MAX_CARRIED_OUTBOX_BYTES` (8 MiB), so the restore's one commit fits, the
  messages past it named so the restore keeps a `MessageUndelivered` duty event for each;
  and the backup's time, the device's and the highest service time verified then. Both
  kinds of backup read it from the store, a layered one in the same moment as the rest, and
  both check that the restore fits one commit before they return. A restore writes the
  records back in its one commit, so a message queued before the backup goes after the
  restore with the same `msg_id`, signed plaintext and last sealed envelope.
- **A restored delivery has a replay deadline** (`replay_until_ms` on its record): the
  backup's verified service time, or its device time without one, less the clock tolerance,
  plus `SENT_RETENTION_MS` (30 days), or a message's first acceptance plus 30 days when it
  was accepted before, whichever is earlier, and never later than one it carries already.
  A copy the device the backup came from delivered since is harmless until then: the
  recipient's switch answers a retry of the same envelope with its first answer while it
  holds the entry (Switch wire 7.4.3 step 1), and the recipient's apps drop a copy taken as
  new by its processed pair, kept 30 days and the tolerance from processing, which is at or
  after the first acceptance (Switch spec 11). Every try checks it before the delivery, at
  the later of the device clock and a service time verified in the call, which a one-item
  feed read fetches when the device clock says the deadline hasn't passed: past it the
  delivery is given up in one commit with a `MessageUndelivered` duty event, a message never
  accepted deleted, one accepted before kept for its owed record job, its sealed envelope
  dropped. A later backup carries the deadline and a later restore keeps the earlier of it
  and its own.
- **A backup doesn't carry `opq/`, `sent/` or `sentt/`.** A kept batch's messages go into
  the outbox only with the batch's answer, so a restored app neither sends the batch nor
  delivers the messages it would have queued; the restore's reconcile mode reads the shared
  records and claims, and the protocol queues what it still owes again. Nor does it carry
  the ends of kept batches and their indexes (`kb/`, `kbt/`, `kbm/`, `kba/`): a restored
  app's `App::kept_batch`, `App::kept_attempt` and `App::delivery` know nothing of a batch
  kept before the restore. A restored app
  answers re-send requests only for what it delivers after the restore.

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
| `bundle` | `keys_through`, and when a full bundle was requested (the service's `requested` time), until no key is missing or the feed shows a part stored at or after that time, which asks again for a key still missing: at most once per such part (Switch wire 7.4.11). A backup carries it and a restore drops it, so the restored app's first read fetches and asks once if a key is still missing | |
| `ident/<pubky>/doc` | the newest `identity.json` taken for an identity, own or a sender's, and when it was read | |
| `ident/<pubky>/floor` | the highest version and generation seen | |
| `ident/<pubky>/body/<version>` | the body hash seen at a version, for equivocation | |
| `ident/<pubky>/equivocated` | the version at which another body was seen | |
| `ident/<pubky>/sw` | when a counterparty's switch copy was last looked up, whether the read succeeded, and the lookup's number | |
| `ident/<pubky>/swn` | the number of the last switch lookup begun for a counterparty, which orders the lookups whatever the clock reads | |
| `ident/<pubky>/reads` | when a counterparty's `identity.json` was last read from its Homeserver, and from its switch | |
| `rk/<n>` | a held receive key: secret, signed record, registration `seq` and service time, pending batch | yes |
| `kid/<kid>` | a kid this app or one of its devices made, kept after the key is deleted | |
| `reg/<n>` | a registration of the own app whose key this device doesn't hold: own, awaiting device sync, or unaccounted after a restore. One rule judges a registration no device of the app made wherever it is met (the restore's key check, the feed, a registration conflict, a provider loss's, the re-registration after a move or a key change in place, and the device sync): while the `restore` record is held, one after the backup's newest key and before the key the restored app registered is unaccounted, and only the user's "no" is a compromise (Switch spec 12.4); any other is a compromise at once, or awaits the device sync on an app that shares its keys. The record is in the store, so it holds across a crash between following a provider change and the restore's key check | |
| `rotation` | the last rotation's time, and whether an envelope to the current key was opened since | |
| `device` | whether the app shares its keys across devices | |
| `cursor` | the processed position, the cursor the service holds, the deferral, the cursor's time | |
| `chain` | the chain view's small fields: tip, open batch, pending heads and checkpoint, newest head, the continuity gap, held marks, restore state | |
| `chain/at/<seq>` | the verified chain hash at a `seq`, from a little behind the cursor on: the hashes behind it are forgotten in steps | |
| `chain/batch/<id>` | a batch ID in the 30-day window, with its first stub's time | |
| `proc/<sender>/<msg_id>` | a processed message's hash and time. The protocol may forget one (`ReceiveContext::forget_processed`, in the step's commit with its other writes, or `App::forget_processed`, in one commit with the protocol's local writes): the pair and its `proct/` entry go, so a re-send is delivered again and nothing is left to prune; refused while the message's effect is kept (`pending/effect`) or an entry stored locally holds it | |
| `proct/<time>/<sender>/<msg_id>` | the time index for pruning processed pairs | |
| `seen/<seq>` | an entry processed past a held one | |
| `held/<seq>` | an entry held because its sender can't be checked, since when | |
| `retry/<seq>` | an entry on the feed whose receive step the protocol's store or the host kept from finishing (`Outcome::Retry`): the reads in a row that ended so, and when the first was; it goes once the entry is processed, or moves to `sretry/<id>` when the entry is stored locally | |
| `sretry/<id>` | the same count for the entry stored locally at local ID `id`, until it is processed or stored for good | |
| `parked/<id>` | an entry stored locally and passed, keyed by its local ID, which never changes: the `seq` and generation it was read at, the opened plaintext, sender, certificate, time, reason (an unverifiable sender, a quota or a store failure of the receive step, tried again; an effect refused for good, over one batch, too large for the store to keep or commit, carrying an operation the app layer builds itself, or kept past the window in which its resend tells whether it was applied, not tried again; one the host released after such a window, `Released`, tried again). The host forgets any one (`App::forget_parked`) while no unacknowledged duty event names it or another entry stored for its message, and no kept effect (`pending/effect`) is one of theirs: in one commit with those entries, their `sretry/` counts and, unless none of them had its sender's standing checked and read as a message, its processed pair if none is kept, so a re-send stays a duplicate. Or the host releases an uncertain one (`App::release_parked`), in one commit that removes its processed pair, and marks it `released`, which it keeps whatever it is stored for again, through a backup and a restore, so each later run is handed over as released; a run of it that ends as a duplicate keeps a `ReleasedDuplicate` duty event. Entries stored as `Unverifiable` are bounded at the start of every read, before the retries, and before a layered backup of an app that is running, those stored before included (Switch spec 8.2): kept at most `MAX_UNVERIFIED_AGE_MS` (21 days) from acceptance on the highest verified service time, `MAX_UNVERIFIED_PER_SENDER` (64) per sender identity and `MAX_UNVERIFIED_TOTAL` (128) in all; one past a bound goes, accepted earliest, of its sender or, for the total, of the identity holding the most (of those holding as many, the one whose newest entry is newest), with its `sretry/` count and a `StoredEntryDropped` duty event in the same commit, at most `UNVERIFIED_DROPS_PER_COMMIT` (64) per commit. The entry a kept effect (`pending/effect`) belongs to is neither counted nor dropped until the effect settles. Entries stored for other reasons aren't counted | yes |
| `asked/<seq>` | a re-send was handed to the protocol for this item | |
| `parkn` | where the retries of entries stored locally stand in their round: its number and the next local ID. The round covers the entries stored in an earlier round, each `parked/` record naming the round it was stored in; each read tries at most `PARKED_RETRIES_PER_READ`, in local ID order, and an entry stored later waits for the next round, so every entry is tried within two rounds | |
| `parkid` | the local ID the next entry stored locally takes: it only goes up, and is never below one past the highest `parked/` key, so no ID is used twice in one store. A backup carries it; a restore starts past the backup's, the one of the store it restores in place (past that store's `parked/` and `sretry/` keys when its counter doesn't read), and every ID a carried duty event names | |
| `retell` | after a restore that brought back entries stored for good: the next local ID to tell the protocol of again and the end of the restored IDs (Switch spec 12.4). Each step after the restore's commit keeps a `Parked` duty event for at most 64 of them not already named by a kept duty event, and moves the next ID past them in the same commit; the last step deletes it. A read finishes what a crash left | |
| `owed/<generation>/<seq>` | a re-send or missed-entries call about this item that the protocol answered with an error: written in the commit that passes the item, made again at the start of each read, each call on its own, and gone in the commit of its answer's writes, or, for an answer whose writes are over `MAX_STEP_LOCAL_BYTES`, in the commit of the duty event that refuses them; `App::owed_protocol_calls` counts them. The key names the generation the item was read at | |
| `departed/<app_id>` | another own app's departure verified in the chain, and its time | |
| `join` | the join step: the registration batch while it is owed | |
| `pending/effect` | a received message's effect batch and its outcome writes, the keys of the processed pairs its step forgets (`forget`) among them, with the deadlines of the claims it writes, and the opened entry, to store it locally if the batch outlives the batch ID window; its local writes are kept in base64 (`kept_local`), and the form with arrays of numbers written before still reads | yes |
| `pending/record` | an `app.put` batch | |
| `pending/publish` | a publication is owed, for an app that publishes its record: written with `record/accepted`, gone once the Homeserver copy is the newest accepted record, or a later one of the app's, which is never written over | |
| `record/accepted` | the newest record the switch accepted from the app, the one a publication writes: written in the commit that records an accepted `app.put` (a delivery, the join's registration, a re-registration at a new service), and set from a backup's record at a restore; never from a refused one | |
| `alarm` | the alarm that stopped the app | |
| `restore` | after a restore: the backup's highest `n`, the key check, the end of the registrations the restore asks about (set at the key check: the key it registered, or one above the backup's highest when the restored key was current), reconcile mode; it goes when reconciliation ends with the key check done, and no registration is judged by the restore rule after. Before the key check the app reads its directory: it takes the own `identity.json` there if newer than the backup's, and the certificate that lists from its own record, under the renewal checks, so a renewal another device of the app took since, whose `cert.put` is a stub by then, is taken at the first read | |
| `leave` | a leave in progress or done | |
| `service_time` | the highest service time verified, its key, the offset from the device clock | |
| `p/...` | the protocol's own local state (`LocalWrite`) | the protocol's |
| `duty/<id>` | a duty event (`AppEvent::is_duty`), written in the commit of the change it reports, until the host acknowledges it (`App::ack_events`); one per entry stored for good, kept batch or `attempt` dropped, kept batch refused for good, outbox message given up, outbox record job given up (`RecordJobDropped`), protocol call whose local writes were over the bound (`LocalWritesRefused`), record write whose mark was over its bound (`RecordUncheckable`), entry stored unverified that was dropped past its bounds (`StoredEntryDropped`), released entry that ran as a duplicate (`ReleasedDuplicate`), or account taken as erased (`AccountGone`, in the commit that writes `gone`, and removed unacknowledged in the commit that takes the account back). Only acknowledgements remove them, apart from that: nothing bounds them for a host that never acknowledges | |
| `dutyn` | the counter the next duty event takes; it only goes up in one store, and a restore in place keeps it | |
| `dutye` | the store's event epoch, random, chosen once when the store starts empty (the first join, or a restore onto a store without one); every duty event ID carries it with its counter | |

Deleting the keys on a leave removes `keys`, `naming`, `rk/`, `scope/`, `parked/`,
`pending/`, `p/`, `duty/` and `owed/`, and marks `leave`.

## Extending the schema

- New records take new keys under a prefix of their own; existing keys keep their meaning.
- A changed record type bumps `SCHEMA_VERSION` with a migration that runs on load.
- `SCHEMA_VERSION` 3: entries stored locally are keyed by a local ID (`parked/<id>`, `parkid`) instead of the `seq` they were read at, which they keep as fields with its generation; a provider loss no longer writes them again. `pending/effect` names its entry's local ID (`stored`) and generation, and retries of stored entries count under `sretry/<id>`. A layered backup carries version 4. No migration reads a store of schema 2: it fails to load as an old schema, and so does a backup of schema 2 or a layered backup of version 3. No released build wrote schema 2. A build of schema 2 refuses every record of a schema 3 store from its version alone, as a later schema (`StoreError::Corrupt`), before it reads the record's shape: a store holding what that build doesn't know (`ParkReason::Released` or `EffectTooLarge`, a `LocalWritesRefused`, `RecordUncheckable` or `ReleasedDuplicate` duty event) is refused whole, never misread.
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
| `loss` | a provider loss followed: the step, the old newest head, the cursor's time there, the declaration time, the clocks' offset, the new key's `n`, the batch of the current step, the conversation entries still to add back (at most `MAX_LOSS_CONVERSATIONS`, the first in key order) and how many past it were left out, shown in `RecoveryInfo::conversations_left_out` | |
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
  a kept `opq/` batch is signed again for the new generation, its bytes under a new wire
  batch ID, still kept under the ID it was first kept under. A
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
  start of the new sequence, `lc/lists_at` and `lc/too_large` removed, a fresh receive key with its registration batch, the
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
| `out/<msg_id>` | a queued message, queued alone or with the answer of the batch that carried it: its signed plaintext, signed once, the envelope sealed for one try with its `apps_version`, its jobs (conversation entry, delivery, record) and where each stands, a re-send owed, when it was refused for good, and when a delivery was first and last answered `403 not_admitted` or `403 not_current`, which of the two the last answer was (`UndeliverableReason`), with the answers counted at least 7.5 days apart; a failed one goes after the sent-message retention, and so does a record job still owed then, from the first acceptance, given up with a `RecordJobDropped` duty event in that commit; an undeliverable one when a try is answered so again 30 days after that first answer and 5 answers were counted, or at the first flush 45 days after it in any case | yes |
| `sent/<msg_id>` | a message the recipient's inbox accepted, written in the commit that records the acceptance, kept 30 days from its first acceptance for re-sends | yes |
| `sentt/<time>/<msg_id>` | the time index for pruning sent messages | |
| `dir/<pubky>` | a counterparty's directory as signed, the switch, generation and `identity.json` version it was read under, its versions, and whether it is read again before the next send; for a directory over the store's value size, only its stub: the switch, generation, versions and read time, no apps, always stale, so each send reads it again and a provider loss since is still found | |
| `rkn/<pubky>/<app_id>` | the highest receive key `n` seen for a counterparty's app | |
| `peer/<pubky>` | the version of the own `identity.json` a counterparty's switch last named, and when the app last wrote there | |
| `peers_doc` | the own `identity.json` the deliveries to recent peers were last judged against, and the counterparties still owed it | |
| `lc/conv/<pubky>` | a conversation entry in the app's copy of the lists, from its writes, the feed and `GET /allow`; its writes and `GET /allow` also keep `lc/contact/`, `lc/deny/` and `lc/code/` | |
| `lc/flag/<pubky>` | a flagged sender in the app's copy of the lists, from `GET /allow` only, which replaces it with `lc/contact/`, `lc/conv/`, `lc/deny/` and `lc/code/` in one commit; kept whole, as the answer holds it, bounded by the transport's answer cap and the store's batch size as the other lists are (at most `max_flags`, 1,000, at the default limits), and never cut, since a cut list would read a flagged sender as not flagged | |
| `lc/lists_at` | the service time of the `GET /allow` answer the copy of the lists was last replaced from, written in that commit; absent until the first, after a restore, and from the commit that starts a provider loss, which keeps `lc/flag/`; while it is absent the copy isn't known to be complete, and a read by an app with `lists.read` refreshes it first, best effort, outside a move or a loss in progress | |
| `lc/too_large` | the service time of the last `GET /allow` answer whose lists didn't fit one commit, in a commit of its own; while it is less than `LISTS_TOO_LARGE_RETRY_MS` (a day) old by the highest service time verified, which each read's page moves on, a read doesn't refresh the copy it owes; `allow_list()` always does; a refresh that fits, a provider change (the commit that switches the service, or that starts a loss) and a restore remove it | |
| `invite/<code_hash>` | the code of an invite code the app registered, to show it again | yes |
| `opq/<batch_id>` | a batch of operations, signed and kept before it is sent, under the batch ID it was first kept under, whatever batch ID its body carries once signed again, with what its answer settles and, from its first send on, when that left (`kept_ms`, absent while never sent): the protocol's local writes, kept in base64 as in `pending/effect`, and the signed messages it puts in the outbox; it goes with its answer or a refusal for good, and stays through anything else, except that one never sent that holds an `attempt` goes unsent, reported as dropped with its attempts, when it would be sent while the app may not attempt (reconcile mode, Switch spec 12.4). All of them together take at most `MAX_KEPT_BATCHES_BYTES` (12 MiB), so a provider change carries them in its one commit: `submit_batch` keeps no batch past it | the messages' |
| `kb/<batch_id>` | the end of a batch kept under `opq/`, written in the commit that applies or drops it: when (app clock), applied or dropped and why (refused for good with its code, dropped never sent, or dropped once sent, uncertain), and the `msg_id`s and attempts it named; `App::kept_batch` answers it until `SENT_RETENTION_MS` (30 days) from that time, and the next `flush_outbox` after forgets it with `kbt/` and the `kbm/` and `kba/` entries still naming it | |
| `kbt/<time>/<batch_id>` | the time index for forgetting those ends | |
| `kbm/<msg_id>` | the batch kept last that queues this message, written in the commit that keeps it: `App::delivery` answers `Kept` while the batch is kept, `Failed` with the drop's time once it is dropped | |
| `kba/<claim_key>/<attempt_id>` | the batch kept last that carries this attempt, written in the commit that keeps it, for `App::kept_attempt` | |
| `list_due` | a listing of the collections is owed: after joining, a restore, a `missed` item (one whose times don't parse too), a certificate taken (a renewal, or the listed one from the own record) that reads a collection of the protocol the one before didn't, in the commit that takes it, or an `upload` transition that would mark more records than `MAX_RECORD_MARKS`, in the commit that passes it. While it is owed nothing is handed to the protocol: a read lists before it retries entries stored locally or owed calls, and an item that owes it mid-read ends the page there, the read listing and then reading on from the item; `missed` items side by side share one listing. A read lists at most once: a later item that owes another ends it, and the next read lists first. A listing that fails ends the read there. It stays while the certificate lacks the key, at the current data epoch, of a scope that reads a collection, even after fetching the key bundle: the read then reads no feed and hands nothing over, reports `ListingWaitsForKey`, asks for the full key bundle again once `KEY_REQUEST_RETRY_MS` (an hour, in memory) has passed since it last asked, and still deletes retired keys, rotates and flushes a due cursor move; the read after the key arrives lists. `App::listing_owed` reads it, for a protocol to tell that its copy may be incomplete | |
| `rec/<key>` | the shared record write the app took: the signed operation, certificate and proof, its version and whether a proof gave it, the opened value, or why it isn't open: its key not held yet (`Unreadable`, the form written before, its data epoch read from the operation), or not opening with its key held (`DoesNotOpen`, flagged); and the refused write it follows. A value whose key isn't held is opened again from the kept operation when a fetch takes a scope key, and whenever the same write is read again; one that doesn't open with its key isn't tried again; neither is tried at every read | yes |
| `recname/<key>` | the collection name of a record the app creates outside the protocol's collections, from a write or an effect, until its write is answered | |
| `hw/<key>` | the protocol's mark of what the app has seen in a record, in base64, at most `MAX_SEEN_MARK_BYTES` (64 KiB) before it. A longer one is never kept: an own write whose mark won't fit is refused before it is built; another app's write leaves the mark held as it is and keeps a `RecordUncheckable` duty event; an own write found over the bound once taken deletes the mark held and keeps the same event | the protocol's |
| `flag/<key>/<generation>/<version>` | a write the app refused, with the app it names and the rule, cut to `MAX_REGRESSION_REASON_BYTES` (256 bytes) | |
| `ocert/<app_id>/<cert_hash>` | a certificate of an own app, for checking its writes | |
| `claim/<claim_key>` | the newest claim view, the proof that shows it SETTLED, the newest entry's time and the deadline the app computes, kept until the evidence's retention ends | |
| `clent/<claim_key>/<step>` | a signed claim entry and its proof | |
| `clstub` | the feed showed the stub of an operation since the claims the app follows were last marked: written with the page that passes the stub, by an app with `claims.read`, and removed in the commit that marks them (Switch wire 7.5) | |
| `clread/<claim_key>` | a claim to read again, with the device time it was marked: one the app holds and doesn't hold as finished (SETTLED with every attempt `done` or `failed`), after a stub, or one the app holds that an `upload` transition in the feed lists (Switch wire 7.4.14), by an app with `claims.read`, in the commit that passes the transition, again if already marked, so these marks are bounded by the claims the app holds; read at the end of a read, at most `CLAIM_REREADS_PER_READ` (16) per read, oldest mark first, and removed in the commit of any read of the claim, a `404` included, or when its evidence goes | |
| `rcread/<key>` | a record an `upload` transition in the feed lists, changed or divergent (Switch wire 7.4.14), to read again, with the device time it was marked, in the commit that passes the transition, again if already marked; read at the end of a read that didn't stop, at most `RECORD_REREADS_PER_READ` (16) per read, oldest mark first, with `GET /records/{key}`, and removed in the commit of what it read, a `404`, a `403 permission_missing` or a view of another key included; any other failure stops the reads and keeps the marks. At most `MAX_RECORD_MARKS` (1,000) are kept: a transition that would mark past them, counting those held, removes them and sets `list_due` instead, keeping the marks of records the app holds outside the protocol's collections, which the listing doesn't read | |
| `rcdiv/<key>` | the latest view the app read of a record it holds shows `divergent`, judged after the view's write and only for the key asked for: `RecordDivergent` was raised once, when it was written, and `SharedRecord::divergent` reads it; removed by a view that doesn't, by a newer write taken, the app's own or one from the feed, and in the commit that starts a provider loss | |
| `clcert/<app_id>` | a writer of kept claim entries whose certificate the app doesn't hold in standing, one the own `identity.json` lists (so at most the app limit), written in the commit that keeps the entry, with the document version it was last looked for at (0 before the first look); at the end of a read that didn't stop, the own directory is read once when a mark is owed a look at the current version, and only certificates that verify with the identity's key and that the document gives a standing are kept; removed once the certificate is held or the document no longer lists the writer, and stamped with the version when the directory didn't show it; a failed read keeps it owed | |

Deleting the keys on a leave also removes `rec/`, `hw/`, `recname/`, `out/`, `sent/`,
`sentt/`, `invite/` and `opq/`, and the ends of kept batches and their indexes (`kb/`,
`kbt/`, `kbm/`, `kba/`): a left app flushes no outbox, so nothing would prune them after. A restore replaces the namespace, these keys included, but
for the `out/` records its backup carries, and sets `list_due`. `rec/`, `clent/` and `claim/` hold the evidence of the shared state that
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
- **A restore in place carries the store's unacknowledged duty events and owed calls in its
  one commit, beside the backup;** past the 32 MiB batch size with them, the restore is
  refused (`Refusal::CarriedTooLarge`, with how many of each it would carry) and nothing
  is written. The host acknowledges the duty events it has acted on (`App::ack_events`),
  lets the protocol answer the owed calls, or restores onto an empty store, then restores
  again. A backup too large on its own is refused as `StoreError::TooLarge` instead, and
  `App::backup_layered` refuses only that one: what a store would carry at a restore in
  place doesn't refuse the backup.
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
