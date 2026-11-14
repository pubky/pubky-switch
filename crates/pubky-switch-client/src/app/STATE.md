# App state in the store

The app layer keeps all of one app's durable state in the host's `StateStore`, namespace
`client/<app_id>` (the App ID in z-base-32). One record per key; no blob is rewritten whole.
Every value is `{"v":1,"d":<record>}` (`SCHEMA_VERSION`): any other `v` is corrupt. A
backup carries the same `v`, with or without protocol layers. Keys are ASCII. Numbers in keys
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
  `retry/`, and the entry under `parked/` once the cursor passes it. A step that waits for
  a scope key (`Outcome::AwaitKey`, or an effect applied with a write the context couldn't
  seal for want of the current data epoch's key) commits nothing of its own either: after
  at most one fetch of the key bundle, its own commits, the entry goes under `parked/` as
  `AwaitingKey` with the page, and the cursor passes it (Switch spec 3.5, 8.2).
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
  older. Its first send is stamped (`kept_ms`) at the earlier of the device clock and the
  highest service time verified with the current service key, and the stamp is committed
  before the request leaves. The service's stamped time never goes back, so that stamp is
  at or before the time the service applies the batch however old the held time is; the
  app reads a time first only when it holds none of the current key, or one more than a day
  behind the device clock, so that the window doesn't end much sooner than it could. The
  read is of a feed page with no items (`limit=0`, Switch wire 7.4.4). A batch never sent
  has no stamp and no window, can't be ambiguous, and is never judged for age, and a call
  that needs a time and can't verify one leaves it kept and unsent. An effect is stamped
  the same way when it is kept, right before its first send. Its age is judged at the later
  of the device clock and a service time verified in the call that sends it again, which
  the same read fetches when no answer of the call brought one; a time verified more than
  10 minutes before by the device clock, or with the device clock gone back since, is read
  again. One past the window by the clocks at hand
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
- **A restore is one commit:** the namespace cleared, the app's restored state and each
  registered protocol's backup layer under its `p/<name>/`, all checked before it, so a
  failure leaves none of them. A layer of a protocol not registered refuses the restore,
  and a registered protocol without a layer is handed none. A layered backup also carries
  `seen/`, `parked/` and `proc/` of the same moment (`beyond_cursor`), which the layers
  may reflect, so no entry is handed to a protocol twice. A kept
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
  the later of the device clock and a service time verified in the call, which a read of a
  feed page with no items fetches when the device clock says the deadline hasn't passed: past it the
  delivery is given up in one commit with a `MessageUndelivered` duty event, a message never
  accepted deleted, one accepted before kept for its owed record job, its sealed envelope
  dropped. A later backup carries the deadline and a later restore keeps the earlier of it
  and its own.
- **A backup doesn't carry `opq/`, `sent/` or `sentt/`.** A kept batch's messages go into
  the outbox only with the batch's answer, so a restored app neither sends the batch nor
  delivers the messages it would have queued; the restore's reconcile mode reads the shared
  records and claims, and the protocol queues what it still owes again: a message such a
  batch queued, when the batch was applied and a record it wrote stores the message, goes
  again from that record's signed plaintext through `App::queue_stored`, with the same
  bytes and `msg_id`, its replay deadline 30 days from its `created_at`, less the clock
  tolerance (Switch spec 11). Nor does it carry
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
| `cert/renewal` | a renewed certificate from `cert.put`, until its `identity.json` lists it. A listed certificate the app holds no `cert.put` for, a renewal another device took whose `cert.put` the feed showed only as a stub once that device's record carried it, is taken at a read's start from the own record in the directory, under the renewal checks, as after a restore; a look that doesn't find it, or fails, is made again at most every `DOC_CACHE_MS` (10 minutes, in memory) while the listing lasts, and the read goes on; a `403 not_current` refusal of the app's record write makes the next read look at once. A take keeps a later renewal held from `cert.put` that renews the certificate taken; a record change kept under the earlier certificate is signed anew under the taken one, later than both, and delivered; the taken record is noted as accepted (`record/accepted`) and the published copy checked against it | |
| `record` | the app record the service holds or is being given (signed) | |
| `naming` | the naming key | yes |
| `scope/<epoch>/<scope>` | one scope key | yes |
| `bundle` | `keys_through`, and when a full bundle was requested (the service's `requested` time), until no key is missing or the feed shows a part stored at or after that time, which asks again for a key still missing: at most once per such part (Switch wire 7.4.11). While it is requested, an entry that waits for a key fetches nothing: the answer comes as a part the feed shows. A backup carries it and a restore drops it, so the restored app's first read fetches and asks once if a key is still missing | |
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
| `retry/<seq>` | an entry on the feed whose receive step the protocol's store or the host kept from finishing (`Outcome::Retry`): the reads in a row that ended so, and when the first was; it goes once the entry is processed or stored to wait for a key, or moves to `sretry/<id>` when the entry is stored locally for another reason | |
| `sretry/<id>` | the same count for the entry stored locally at local ID `id`, until it is processed, stored for good or stored again to wait for a key | |
| `parked/<id>` | an entry stored locally and passed, keyed by its local ID, which never changes: the `seq` and generation it was read at, the opened plaintext, sender, certificate, time, reason (an unverifiable sender, a quota or a store failure of the receive step, tried again; a scope key the receive step waits for, with its data epoch (`AwaitingKey`) and how many scope keys the app held when its step last ran (`keys_at`), tried again only once the app holds every key of that epoch its certificate is given and holds another number of keys than then, so a key the certificate is never given runs its step again only when a key comes; one whose step waits again for the same epoch stays stored as it is, its count brought up to date, with no event; one whose step ran while a reopening was owed (`reopen`), such as after a key its page or its own fetch took, keeps no count; none is tried while a reopening is owed, which its step may read, so its count stays and it is due once the reopening is done: at the retries at the start of a read, or, for one a fetch later in the read brought the keys of, at the end of a read that doesn't stop and owes no listing, at most `PARKED_RETRIES_PER_READ` there, so one whose key never comes costs a read nothing; an effect refused for good, over one batch, too large for the store to keep or commit, carrying an operation the app layer builds itself, or kept past the window in which its resend tells whether it was applied, not tried again; one the host released after such a window, `Released`, tried again). The host forgets any one (`App::forget_parked`) while no unacknowledged duty event names it or another entry stored for its message, and no kept effect (`pending/effect`) is one of theirs: in one commit with those entries, their `sretry/` counts and, unless none of them had its sender's standing checked and read as a message, its processed pair if none is kept, so a re-send stays a duplicate. Or the host releases an uncertain one (`App::release_parked`), in one commit that removes its processed pair, and marks it `released`, which it keeps whatever it is stored for again, through a backup and a restore, so each later run is handed over as released; a run of it that ends as a duplicate keeps a `ReleasedDuplicate` duty event. Entries stored as `Unverifiable` or `AwaitingKey`, counted together, are bounded at the start of every read, before the retries, and before a layered backup of an app that is running, those stored before included (Switch spec 8.2): kept at most `MAX_UNVERIFIED_AGE_MS` (21 days) from acceptance on the highest verified service time, `MAX_UNVERIFIED_PER_SENDER` (64) per sender identity and `MAX_UNVERIFIED_TOTAL` (128) in all; one past a bound goes, accepted earliest, of its sender or, for the total, of the identity holding the most (of those holding as many, the one whose newest entry is newest), with its `sretry/` count and a `StoredEntryDropped` duty event in the same commit, at most `UNVERIFIED_DROPS_PER_COMMIT` (64) per commit. The entry a kept effect (`pending/effect`) belongs to is neither counted nor dropped until the effect settles. Entries stored for other reasons aren't counted | yes |
| `asked/<seq>` | a re-send was handed to the protocol for this item | |
| `parkn` | where the retries of entries stored locally stand in their round: its number and the next local ID. The round covers the entries stored in an earlier round, each `parked/` record naming the round it was stored in; each read tries at most `PARKED_RETRIES_PER_READ`, in local ID order, and an entry stored later waits for the next round, so every entry is tried within two rounds | |
| `parkid` | the local ID the next entry stored locally takes: it only goes up, and is never below one past the highest `parked/` key, so no ID is used twice in one store. A backup carries it; a restore starts past the backup's, the one of the store it restores in place (past that store's `parked/` and `sretry/` keys when its counter doesn't read), and every ID a carried duty event names | |
| `retell` | after a restore that brought back entries stored for good: the next local ID to tell the protocol of again and the end of the restored IDs (Switch spec 12.4). Each step after the restore's commit keeps a `Parked` duty event for at most 64 of them not already named by a kept duty event, and moves the next ID past them in the same commit; the last step deletes it. A read finishes what a crash left | |
| `owed/<generation>/<seq>` | a re-send, missed-entries or deny list change call about this item, with the protocols it is owed to (`to`, written by every writer): each that answered with an error, or that owed an earlier call when the item came, since a protocol takes its calls in feed order; a protocol that answers is taken out in the commit of its writes, so no protocol is handed a call twice. A protocol owed a re-send or missed-entries call is handed nothing later until it takes it: its later entries are held and its later calls owed, while the read goes on for the other protocols. A deny list change owed to any protocol stops the read for every protocol, as below. With the times it names (a missed-entries call kept in the form written before, without its last acceptance time, reads as having no end), or a deny list change whose writer's certificate couldn't be looked up yet (`DenyUnverified`, with its operation, owed to every protocol, checked again: handed, refused with an event, or a gap): written in the commit that passes the item, after which the page stops; made again at the start of each read before anything else, in feed order; one that fails again holds every later one of its protocols back, of any kind, and the read hands those protocols nothing while one at or behind the cursor is owed to them. One ahead of the cursor in its sequence waits while the feed hands what comes before its item, up to that item, which the feed passes unhanded, the call being its notice; one keyed at a generation not followed yet waits while the feed is read on. A restore in place carries every whole one owed to a protocol it registers, each keeping only those protocols: one past the cursor waits for the feed to reach its item, which the feed doesn't hand again, and the feed stops before anything later, so it goes in feed order, once; a re-send or missed-entries call behind the cursor, as from a newer backup, is made when the next read begins, before those at and after the cursor, though the feed handed later items before it. Each is gone in the commit of the last answer's writes, or, for an answer whose writes are over `MAX_STEP_LOCAL_BYTES`, in the commit of the duty event that refuses them; `App::owed_protocol_calls` counts them. The key names the generation the item was read at; feed order is by sequence, not by key: a cooperative move and a key change in place continue the sequence, so the calls of the current sequence go by `seq` whatever generation their keys name, those of a sequence a provider loss ended go before them, among themselves by (generation, `seq`), and one keyed at a generation past the newest own `identity.json` the app holds waits until the app follows it (`App::feed_order`); the deny list gap the loss leaves is told after them, with the full list. A key that names no feed position, or a `DenyUnverified` whose operation doesn't parse or isn't the change kept beside it, is a corrupt store: the read fails, nothing is made or dropped; a restore in place doesn't carry such an entry, nor one owed to no protocol it registers, and counts it in `RestoreLeftBehind`. An owed deny list change at the cursor is applied to the copy of the lists (`lc/deny/`) in the commit that hands it, so the copy and the protocols never disagree after a crash; without `lists.read`, as after a renewal removed it, it is applied to the copy and gone, handed to no protocol. One behind the cursor (`Deny` or `DenyUnverified`), as a restore in place from a newer backup carries, or one of a lost sequence once the cursor follows the next, is neither handed nor applied: in one commit it is gone and a deny list gap is noted at the cursor (`dgap`), told with the full list; a `DenyUnverified` one is checked first, and one that isn't genuine is refused with `DenyListChangeRefused` and gone, one that can't be checked yet stays owed and holds the rest. A backup carries the re-send and missed-entries calls (`AppBackup::owed`), each with its `to`, and every restore takes them, checked as above and kept for the protocols it registers, a restore in place adding the store's own (see "What the app owes its protocol"); a backup carries no deny list call nor `dgap`: every restore notes its own deny list gap at the restored cursor instead (`dgap`) | |
| `dgap` | a gap in the deny list's history not told to every protocol yet (after a checkpoint past the cursor, a provider loss, a change whose writer the directory no longer lists, a restore, which notes one at the restored cursor in its own commit, whatever the backup held, after the namespace's delete takes the store's `dgap`, or a copy of the lists not known complete, as after a join, a renewal that added `lists.read` or a gap told without the list (`App::refresh_lists_if_owed`), or `App::allow_list`, which commits it on its own before it replaces the copy): the position the history is complete through, the earliest owed, and the protocols not told yet (`to`), written with `lc/lists_at` deleted, by a restore with the namespace's delete, by every other writer in the same commit (`App::note_deny_gap`). Every protocol takes deny list changes and gaps, so a gap noted is owed to every registered protocol, also to one that took a gap still owed to another. Told after the owed calls, with the lists read for it, in a commit of its own (`Protocol::deny_list_gap`) that takes out each protocol told; one that fails keeps it owed, and the read holds; the commit that tells the last one deletes it, and the copy of the lists is then taken from the same answer, best effort. Whenever the copy is taken whole from a list read, every protocol gets that list as a gap: `App::allow_list`'s copy is followed by its gap's tell, which takes the copy again from the list it tells. An answer that verifies but can't be read tells it without the list (`list_read` false): while another protocol is still owed it, the gap stays owed to the ones told too, and the commit that tells the last deletes `lc/lists_at` as well, so the next read owes a gap again: such a protocol is told `list_read` false at each read for as long as the answer can't be read. While it is owed the read hands nothing. Every gap noted is told, also at a position a gap was told at before, whose list may predate what the new one covers; a gap told again hands each protocol the full list again, which sets the same state | |
| `departed/<app_id>` | another own app's departure verified in the chain, and its time | |
| `join` | the join step: the registration batch while it is owed | |
| `pending/effect` | a received message's effect batch and its outcome writes, the keys of the processed pairs its step forgets (`forget`) among them, with the deadlines of the claims it writes, and the opened entry, to store it locally if the batch outlives the batch ID window; its local writes are kept in base64 (`kept_local`) | yes |
| `pending/record` | an `app.put` batch | |
| `pending/publish` | a publication is owed, for an app that publishes its record: written with `record/accepted`, and by a check that found the Homeserver copy missing or different when the repair's write failed, or when the copy is missing on an app whose devices share its keys and the call hasn't shown the app current (written back only once the switch has: in a read, after its feed, or right after the switch accepts the app's `app.put`); gone once the Homeserver copy is the newest accepted record, or a later one of the app's, which is never written over. While it is held every read tries the publication once, without waiting out `PUBLISHED_CHECK_MS`: right after a delivery the switch accepted at the read's start, or else after its feed, once the feed shows the app current; a read whose owed listing waits for a key reads no feed, and publishes as a call outside a read does. A check counts against the interval only once what it found is committed | |
| `record/accepted` | the newest record the switch accepted from the app, the one a publication writes: written in the commit that records an accepted `app.put` (a delivery, the join's registration, a re-registration at a new service), and never from a refused one. A `409 conflict` naming no record is an acceptance only when the switch's directory shows it holds the very record; one whose directory shows a later record of the app, another device's, drops `pending/record` as superseded and, when the later record carries the certificate the app presents, takes it here and as `record`, in the same commit: the app's next record builds on it, so the dropped body is never signed again. One carrying a renewal another device took that the newest `identity.json` lists is first taken with that certificate, as after a restore, and then so; one under any other certificate, which only a faulty switch shows, is never taken: `pending/record` is dropped alone. A backup carries it apart from `record`, which may hold a record whose `app.put` was refused or never answered, and a restore takes it from there, never from `record` (none from a backup without it); the record held then goes to the switch only with the next change, signed anew, and is never published before the switch accepts it. A provider loss deletes it until the new service accepts the re-registration | |
| `alarm` | the alarm that stopped the app | |
| `restore` | after a restore: the backup's highest `n`, the key check, the end of the registrations the restore asks about (set at the key check: the key it registered, or one above the backup's highest when the restored key was current), whether the key check found the restored key current (`key_current`, for the held cursor's verdict; null before the key check), reconcile mode; it goes when reconciliation ends with the key check done, and no registration is judged by the restore rule after. Before the key check the app reads its directory: it takes the own `identity.json` there if newer than the backup's, and the certificate that lists from its own record, under the renewal checks, so a renewal another device of the app took since, whose `cert.put` is a stub by then, is taken at the first read | |
| `hcur` | the last restore's check of the cursor the service holds (Switch spec 12.4 "The held cursor"): the backup's committed position, when the restore ran, and the verdict (`HeldCursor`), settled at the first page that isn't a frozen service's read once the own `identity.json` was confirmed after the restore, `Unknown` at once if a batch carrying a cursor move is sent first; written in the restore's commit and in the settling page's, and deleted with `restore` when reconciliation ends with the key check done. A clean verdict turns ahead when a later page reports a cursor ahead of the furthest position the app committed or sent, for an app whose devices don't share its cursor, and reads unknown once the backup's generation is no longer of the current sequence | |
| `hgap` | the generation and held `seq` of the last gap ahead handed to the protocol as a `missed` item, in the commit of the page that handed it, so each higher report is handed once | |
| `leave` | a leave in progress or done, committed before a publishing app deletes its Homeserver record: from then on nothing is published, across a restart too. A two-step leave calls `leave` only once the delete is made; an immediate leave and a compromise's call it whatever the delete's outcome, the call's mode deciding, so also after a two-step leave whose delete failed | |
| `service_time` | the highest service time verified, its key, the offset from the device clock | |
| `protos` | the names of the protocols the app was set up with, written by a join and a restore: a load refuses a set of protocols that lacks one of them or registers another, before it writes anything | |
| `p/<name>/...` | the local state of the protocol `name` (`LocalWrite`): every write a protocol hands over, through a callback, a batch (`OpBatch::for_protocol`), `App::protocol_commit` or `App::forget_processed`, is qualified where it enters the app, and kept so in `pending/effect` and `opq/`, so one protocol's writes, a `DeletePrefix` of its whole key space included, never reach another's | the protocol's |
| `rcd` | the protocols that ended the reconcile mode under way (`App::end_reconcile_for`); the mode ends, and `rcd` goes, when the last registered protocol ends it | |
| `rexp` | the expiry each protocol asked of the app's record, by name, `null` for none (`App::set_protocol_member`, `App::renew_record`), written in the commit that keeps the record it signs, or alone when the record doesn't change: the record's `expires_at` is the earliest of them, `null` while none asked for one (Switch spec 4.2, wire 3.2). A backup carries it (`record_expiries`), and a restore writes it back, refusing one of a protocol it doesn't register | |
| `duty/<id>` | a duty event (`AppEvent::is_duty`) with the protocols it is for (`to`, written by every writer: the protocol of the kind or the stored entry it names, of the kept batch, or of the call whose writes were refused; every registered protocol otherwise), written in the commit of the change it reports, until each of them acknowledges it (`App::ack_events_for` takes one name out, rewriting the event or removing it with the last; `App::ack_events` removes it for all); one per entry stored for good, kept batch or `attempt` dropped, kept batch refused for good, outbox message given up, outbox record job given up (`RecordJobDropped`), protocol call whose local writes were over the bound (`LocalWritesRefused`), record write whose mark was over its bound (`RecordUncheckable`), record a view first showed divergent (`RecordDivergent`, in the commit that writes `rcdiv/<key>`, kept after the mark is removed), entry stored unverified or waiting for a key that was dropped past their bounds (`StoredEntryDropped`, with the epoch it waited for), released entry that ran as a duplicate (`ReleasedDuplicate`), or account taken as erased (`AccountGone`, in the commit that writes `gone`, and removed unacknowledged in the commit that takes the account back). Only acknowledgements remove them, apart from that: nothing bounds them for a host that never acknowledges | |
| `dutyn` | the counter the next duty event takes; it only goes up in one store, and a restore in place keeps it | |
| `dutye` | the store's event epoch, random, chosen once when the store starts empty (the first join, or a restore onto a store without one); every duty event ID carries it with its counter | |

Deleting the keys on a leave removes `keys`, `naming`, `rk/`, `scope/`, `parked/`,
`pending/`, `p/` (every protocol's), `duty/` and `owed/`, and marks `leave`.

## Extending the schema

- New records take new keys under a prefix of their own; existing keys keep their meaning.
- A changed record type bumps `SCHEMA_VERSION` with a migration that runs on load.
- Protocol state stays under `p/<name>/`, written only through `LocalWrite`.

## Moves, recovery and push

`provider.rs` follows a cooperative move or a key change in place, and keeps that the app
isn't current any more; `recovery.rs` follows a provider loss and keeps the evidence for
uploads; `push.rs` holds the push registration. The peek (`peek.rs`) writes nothing.

| Key | Holds | Sensitive |
|---|---|---|
| `mv` | a move in progress: the signed freeze (none for a key change), the generation left, the step, the re-registration batch signed once | |
| `gens/<generation>` | a generation the app left: its origin and service key, and the last own `identity.json` taken there | |
| `loss` | a provider loss followed: the step, the old newest head, the cursor's time there, the declaration time, the clocks' offset, the new key's `n`, the batch of the current step, the conversation entries still to add back, every protocol's merged (at most `MAX_LOSS_CONVERSATIONS`, the first in key order) and how many past it were left out, shown in `RecoveryInfo::conversations_left_out`; and the protocols whose answers the re-send step committed so far (`asked`, written by every writer): each protocol's answer commits with its name, and the step asks only the others, so a protocol that fails is asked again and none twice; the last one's commit ends the step and empties it | |
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
| `out/<msg_id>` | a queued message, queued alone, with the answer of the batch that carried it, or again from its stored signed plaintext (`App::queue_stored`, with a replay deadline): its signed plaintext, signed once, the envelope sealed for one try with its `apps_version`, its jobs (conversation entry, delivery, record) and where each stands, a re-send owed, when it was refused for good, and when a delivery was first and last answered `403 not_admitted` or `403 not_current`, which of the two the last answer was (`UndeliverableReason`), with the answers counted at least 7.5 days apart; a failed one goes after the sent-message retention, and so does a record job still owed then, from the first acceptance, given up with a `RecordJobDropped` duty event in that commit; an undeliverable one when a try is answered so again 30 days after that first answer and 5 answers were counted, or at the first flush 45 days after it in any case | yes |
| `sent/<msg_id>` | a message the recipient's inbox accepted, written in the commit that records the acceptance, kept 30 days from its first acceptance for re-sends, with the replay deadline of the outbox item it came from (a restore's put-back, `App::queue_stored`'s copy), the earliest of those it was accepted from: a re-send queued from it goes only by that deadline, and is given up past it | yes |
| `outgone/<msg_id>` | a message whose delivery the app gave up and deleted from the outbox, in the commit that gives it up and keeps `MessageUndelivered`, or that a restore left out: `App::queue_stored` refuses it (`WontDeliver::GivenUp`) until the time it holds, 30 days on, past which the message's replay deadline refuses it; removed when pruning sent messages after that time | |
| `outnext` | where flushing the outbox stands, committed after each message's try and at the flush's end: the queue time and `msg_id` of the last message tried, from which the next flush goes on round the queue, so a message that keeps failing holds up none behind it; whether a pass a budget stopped is under way (`open`), and the first message it tried, so the next flush tries only the messages of the pass it hasn't reached. A try a failure or a crash cut short goes again first. The flush that ends the pass, and the deliveries' pass with it (`peers_doc`), says `more` false | |
| `outhold/<pubky>` | a counterparty whose messages the host holds (`App::hold_queued`), until `App::release_queued`: no delivery of a message to it is tried, a first one or a re-send, those a kept batch puts in the outbox once it settles included; a held message's replay deadline still runs, and its record job goes. Carried by a backup; a restore in place also keeps the store's own; deleted on a leave. `App::withdraw_queued` gives those messages up instead, with `outgone/` marks | |
| `sentt/<time>/<msg_id>` | the time index for pruning sent messages | |
| `dir/<pubky>` | a counterparty's directory as signed, the switch, generation and `identity.json` version it was read under, its versions, and whether it is read again before the next send; for a directory over the store's value size, only its stub: the switch, generation, versions and read time, no apps, always stale, so each send reads it again and a provider loss since is still found | |
| `rkn/<pubky>/<app_id>` | the highest receive key `n` seen for a counterparty's app | |
| `peer/<pubky>` | the version of the own `identity.json` a counterparty's switch last named, and when the app last wrote there | |
| `peers_doc` | the own `identity.json` the deliveries to recent peers were last judged against, and the counterparties still owed it: those the pass under way hasn't tried first (`untried`, how many), then those whose delivery failed, in the order they failed, so one slow failing switch holds up no other | |
| `lc/conv/<pubky>` | a conversation entry in the app's copy of the lists, from its writes, the feed and `GET /allow`; its writes and `GET /allow` also keep `lc/contact/`, `lc/deny/` and `lc/code/` | |
| `lc/flag/<pubky>` | a flagged sender in the app's copy of the lists, from `GET /allow` only, which replaces it with `lc/contact/`, `lc/conv/`, `lc/deny/` and `lc/code/` in one commit; kept whole, as the answer holds it, bounded by the transport's answer cap and the store's batch size as the other lists are (at most `max_flags`, 1,000, at the default limits), and never cut, since a cut list would read a flagged sender as not flagged | |
| `lc/lists_at` | the service time of the `GET /allow` answer the copy of the lists was last replaced from, written in that commit; absent until the first, after a restore, from the commit that starts a provider loss, which keeps `lc/flag/`, from the commit of a renewal that adds `lists.read`, from the commit of every gap noted (`App::note_deny_gap`, `App::allow_list`'s own commit before it replaces the copy) and from the commit that tells a gap without the list; while it is absent the copy isn't known to be complete, and a read by an app with `lists.read` notes a deny list gap at the cursor (`dgap`), outside a move or a loss in progress, and tells it after the owed calls, the copy taken from the same answer: the copy and the protocol are set from one list. `App::allow_list` commits a gap at the cursor first, then replaces the copy, so whatever stops between them the protocol is owed the list | |
| `lc/too_large` | the service time of the last `GET /allow` answer whose lists didn't fit one commit, in a commit of its own; while it is less than `LISTS_TOO_LARGE_RETRY_MS` (a day) old by the highest service time verified, which each read's page moves on, a read doesn't note the gap a copy not known complete owes; a gap owed is still told with the lists read for it, which tries the copy once more; `allow_list()` always fetches them; a refresh that fits, a provider change (the commit that switches the service, or that starts a loss), a restore and a renewal that adds `lists.read` remove it | |
| `invite/<code_hash>` | the code of an invite code the app registered, to show it again | yes |
| `opq/<batch_id>` | a batch of operations, signed and kept before it is sent, under the batch ID it was first kept under, whatever batch ID its body carries once signed again, with what its answer settles and, from its first send on, when that left (`kept_ms`, absent while never sent): the protocol's local writes, kept in base64 as in `pending/effect`, and the signed messages it puts in the outbox; it goes with its answer or a refusal for good, and stays through anything else, except that one never sent that holds an `attempt` goes unsent, reported as dropped with its attempts, when it would be sent while the app may not attempt (reconcile mode, Switch spec 12.4). All of them together take at most `MAX_KEPT_BATCHES_BYTES` (12 MiB), so a provider change carries them in its one commit: `submit_batch` keeps no batch past it | the messages' |
| `keptn` | the next creation number of a kept batch (`queued_n` in `opq/`, written in the commit that keeps the batch): kept batches go in that order, whether sent before or not, so no write overtakes an earlier one. A write sends at most one kept batch again before its own (`KEPT_RESENDS_PER_WRITE`); with more kept, its own is kept unsent behind them (`Refusal::KeptBatchesAhead`) | |
| `kb/<batch_id>` | the end of a batch kept under `opq/`, written in the commit that applies or drops it: when (app clock), applied or dropped and why (refused for good with its code, dropped never sent, or dropped once sent, uncertain), and the `msg_id`s and attempts it named; `App::kept_batch` answers it until `SENT_RETENTION_MS` (30 days) from that time, and the next `flush_outbox` after forgets it with `kbt/` and the `kbm/` and `kba/` entries still naming it | |
| `kbt/<time>/<batch_id>` | the time index for forgetting those ends | |
| `kbm/<msg_id>` | the batch kept last that queues this message, written in the commit that keeps it: `App::delivery` answers `Kept` while the batch is kept, `Failed` with the drop's time once it is dropped | |
| `kba/<claim_key>/<attempt_id>` | the batch kept last that carries this attempt, written in the commit that keeps it, for `App::kept_attempt` | |
| `list_due` | a listing of the collections is owed: after joining, a restore, a `missed` item (one whose times don't parse too), a certificate taken (a renewal, or the listed one from the own record) that reads a collection of the protocol the one before didn't, in the commit that takes it, or an `upload` transition that would mark more records than `MAX_RECORD_MARKS`, in the commit that passes it. While it is owed nothing is handed to the protocol: a read lists before it retries entries stored locally or owed calls, and a read that ends owing one doesn't retry the entries waiting for a key at its end, and an item that owes it mid-read ends the page there, the read listing and then reading on from the item; `missed` items side by side share one listing. A read lists at most once: a later item that owes another ends it, and the next read lists first. A listing that fails ends the read there. It stays while the certificate lacks the key, at the current data epoch, of a scope that reads a collection, even after fetching the key bundle: the read then reads no feed and hands nothing over, reports `ListingWaitsForKey`, asks for the full key bundle again once `KEY_REQUEST_RETRY_MS` (an hour, in memory) has passed since it last asked, and still deletes retired keys, rotates and flushes a due cursor move; the read after the key arrives lists. A read asks for at most `LISTING_PAGES_PER_READ` (4) listing pages; a listing that needs more ends the read before any entry, `list_at` keeping how far it got, and the next read goes on from there. `App::listing_owed` reads it, for a protocol to tell that its copy may be incomplete | |
| `list_at` | how far an owed listing, or an unfinished `App::list_collections`, got: the collections listed to their end and the last key of the collection being listed, in the commit of each page it takes; deleted with `list_due`, and in the commit of every new obligation that sets `list_due`, so a listing owed again starts from the beginning: a renewal taken between reads that widens the certificate lists the collections a listing under way had listed to their end | |
| `listc/<collection>` | how far an `App::list_collection` of one collection that its budget stopped got: the last key of its last page, in the commit of each page; deleted by the call that reaches the collection's end, and by a leave | |
| `feed_at` | where a read that its budget stopped went on to (`FEED_PAGES_PER_READ` pages, or `AppConfig::call_budget_ms` once a page or item is processed), or one that stopped for a listing a `missed` item owes (a second one, or a listing past its pages), with the lowest held `seq` of that read: in the commit after the page it stopped on; the next read of the same generation goes on from there instead of the cursor, so the entries held behind the cursor don't take each read's budget again. Deleted by a read that reaches the feed's end, and passed over when the cursor is past it or the generation changed | |
| `rec/<key>` | the shared record write the app took: the signed operation, certificate and proof, its version and whether a proof gave it, the opened value, or why it isn't open: its key not held yet (`Unreadable`, its data epoch read from the operation), or not opening with its key held (`DoesNotOpen`, flagged); and the refused write it follows, with whether that write names its writer (`follow_named`): one refused only for the certificate the service shows or a missing date names nobody and reads as not flagged. A value whose key isn't held is opened again from the kept operation when a fetch takes a scope key, and whenever the same write is read again; one that doesn't open with its key isn't tried again; neither is tried at every read | yes |
| `reopen` | the records held `Unreadable` are owed a reopening: written in the commit that takes a scope key, which reopens nothing itself. The reopening runs only while no page's writes are open, after each page's commit and at the start and end of a read, so a record a page takes `Unreadable` before an item of the same page brings its key opens too. It commits as a listing does, a commit whenever one more record might not fit, and only the last removes the mark. A reopening that fails keeps the mark, is reported (`ReopeningOwed`) and is made again at the next try, at most `REOPEN_TRIES_PER_READ` (2) tries a read, the rest left to the next read; it doesn't fail the read, which goes on from the store as committed (Switch spec 3.5), but for an alarm it raises, or a failure once one is raised: that ends the read, so nothing is handed over or sent after it | |
| `recname/<key>` | the collection name of a record the app creates outside the protocol's collections, from a write or an effect, until its write is answered | |
| `hw/<key>` | the protocol's mark of what the app has seen in a record, in base64, at most `MAX_SEEN_MARK_BYTES` (64 KiB) before it. A longer one is never kept: an own write whose mark won't fit is refused before it is built; another app's write leaves the mark held as it is and keeps a `RecordUncheckable` duty event; an own write found over the bound once taken deletes the mark held and keeps the same event. The app's own delete leaves the mark held as it is: what the app saw stays seen (Switch spec 8.2), so another app's write that brings the record back without it is checked against it. So the mark of a deleted record is kept with no expiry at every own app, the deleting one included, until a later own write, or another app's write that is taken, replaces it, or a leave or restore clears the store: for a protocol whose mark is the record's whole value, a delete doesn't remove that content from the deleting device. A write by this app, from this device or another, is never checked against the mark, also when the feed or a view shows it before its answer, and is marked from the value written; one this device can't read yet, waiting for its scope key, leaves the mark as it is until the record reopens with the key, and is marked from its value then | the protocol's |
| `flag/<key>/<write>` | a write the app refused, by its item hash, which its writer signed: with the version it was last shown at, the app it names and the rule, cut to `MAX_REGRESSION_REASON_BYTES` (256 bytes); the same write shown again replaces its entry, and a record keeps at most eight, the one shown at the lowest version dropped first | |
| `ocert/<app_id>/<cert_hash>` | a certificate of an own app, for checking its writes | |
| `claim/<claim_key>` | the newest claim view, the proof that shows it SETTLED, the newest entry's time and the deadline the app computes, kept until the evidence's retention ends | |
| `clent/<claim_key>/<step>` | a signed claim entry and its proof | |
| `clstub` | the feed showed the stub of an operation since the claims the app follows were last marked: written with the page that passes the stub, by an app with `claims.read`, and removed in the commit that marks them (Switch wire 7.5) | |
| `clread/<claim_key>` | a claim to read again, with the device time it was marked: one the app holds and doesn't hold as finished (SETTLED with every attempt `done` or `failed`), after a stub, or one the app holds that an `upload` transition in the feed lists (Switch wire 7.4.14), by an app with `claims.read`, in the commit that passes the transition, again if already marked, so these marks are bounded by the claims the app holds; read at the end of a read, at most `CLAIM_REREADS_PER_READ` (16) per read, oldest mark first, and removed in the commit of any read of the claim, a `404` included, or when its evidence goes | |
| `rcread/<key>` | a record an `upload` transition in the feed lists, changed or divergent (Switch wire 7.4.14), to read again, with the device time it was marked, in the commit that passes the transition, again if already marked; read at the end of a read that didn't stop, at most `RECORD_REREADS_PER_READ` (16) per read, oldest mark first, with `GET /records/{key}`, and removed in the commit of what it read, a `404`, a `403 permission_missing` or a view of another key included; any other failure stops the reads and keeps the marks. At most `MAX_RECORD_MARKS` (1,000) are kept: a transition that would mark past them, counting those held, removes them and sets `list_due` instead, keeping the marks of records the app holds outside the protocol's collections, which the listing doesn't read | |
| `rcdiv/<key>` | the latest view the app read of a record it holds shows `divergent`, judged after the view's write and only for the key asked for: `RecordDivergent`, a duty event, was kept once, in the commit that writes it, and `SharedRecord::divergent` reads it; removed by a view that doesn't, by a newer write taken, the app's own or one from the feed, and in the commit that starts a provider loss. A restore, in place or from a backup, replaces the marks: the listing it owes reads the records again, and a view that still shows a record divergent raises the event again, with a new ID. A restore in place also keeps the unacknowledged ones, so one divergence may come with two IDs. | |
| `clcert/<app_id>` | a writer of kept claim entries whose certificate the app doesn't hold in standing, one the own `identity.json` lists (so at most the app limit), written in the commit that keeps the entry, with the document version it was last looked for at (0 before the first look); at the end of a read that didn't stop, the own directory is read once when a mark is owed a look at the current version, and only certificates that verify with the identity's key and that the document gives a standing are kept; removed once the certificate is held or the document no longer lists the writer, and stamped with the version when the directory didn't show it; a failed read keeps it owed | |

Deleting the keys on a leave also removes `rec/`, `hw/`, `recname/`, `out/`, `sent/`,
`sentt/`, `invite/` and `opq/`, and the ends of kept batches and their indexes (`kb/`,
`kbt/`, `kbm/`, `kba/`): a left app flushes no outbox, so nothing would prune them after. A restore replaces the namespace, these keys included, but
for the `out/` records its backup carries, and sets `list_due`. `rec/`, `clent/` and `claim/` hold the evidence of the shared state that
uploads carry (`App::shared_evidence`).

## What the app owes its protocol: restores and provider changes

`duty/<id>`, `dutyn`, `dutye`, `owed/<generation>/<seq>` and `dgap` hold what the app still
has to tell its protocols, each with the protocols it is for, so neither a restore nor a
provider change drops them.

- **A backup carries the owed re-send and missed-entries calls, and nothing else of
  them** (`AppBackup::owed`, by key after `owed/`, with each value as stored, its `to`
  among it, set by both `App::backup` and `App::backup_layered`). Most are at or behind
  the backup's cursor, which the restored feed never shows again; one may be ahead of it,
  carried ahead by an earlier restore in place, and waits for the feed to reach its item.
  Deny list calls are left out: the restore's own gap (below) covers them. The duty events
  are the store's, not the app's keys or position.
- **Every restore owes every protocol one deny list gap** (`dgap` at the restored cursor,
  its `to` every registered protocol, written in the restore's one commit, for an app
  holding `lists.read`), whatever the backup held: a deny list change or gap owed when the
  backup was taken isn't in it, and the feed doesn't hand again what the backup's cursor
  passed. Each protocol is told the full list after the carried calls up to the cursor,
  and the copy of the lists is taken from the same answer once the last is told.
- **A restore in place** (into a store that holds an epoch) keeps `dutye`, sets `dutyn` to
  the higher of the store's counter and the highest kept counter plus one, and carries
  `duty/` and `owed/` across the namespace's replacement, all in its one commit: the duty
  events keep their IDs and are delivered again, and the owed calls are made by the next
  read. Each keeps only the protocols the restore registers; one for none of them is left
  behind and counted (`RestoreLeftBehind`). The restored cursor may meet the same items
  again; the protocol then hears of them twice, which it tolerates.
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
- **A restore on another device, or onto a wiped store** (one without an epoch), starts a new random epoch at the first counter, with no duty event:
  their facts stayed with the lost store. Its IDs can't equal any the host acknowledged
  before, whatever the counters or the clock, since an ID is its epoch and its counter.
- **Every restore takes the backup's owed calls**, each checked as a carried one is
  (`owed_place`, decode, `kept_op_body`), in the restore's commit, each keeping only the
  protocols the restore registers; one that isn't whole, or is owed to none of them, is
  left behind and counted in `RestoreLeftBehind`. The restore replaces each protocol's
  local state with its layer, or with nothing, so a call the store made after the backup
  is made again: its writes went with that state. A restore in place adds the store's own
  calls, the store's value winning for a key both hold. A call at or behind the
  restored cursor is made by the next read before the restore's deny list gap is told;
  one ahead of it, as one an earlier restore in place carried ahead, waits for the feed to
  reach its item, after the gap.
- **IDs compare only within one store.** `App::ack_events` refuses an ID of another epoch
  and acknowledges nothing.
- **A provider change keeps them** (a move, a key change in place, a provider loss). The
  duty events report facts that stay true. An owed call is still made at the generation
  followed: a re-send call names a sender and acceptance times, which the counterparty
  answers wherever the app reads now, and a missed-entries call names the item's `seq` at
  the generation in its key, which the protocol takes as information only. After a loss
  the protocol is also asked for the loss's re-sends; a request twice is answered once,
  since re-sends are deduplicated by `msg_id` (Switch spec 11).
