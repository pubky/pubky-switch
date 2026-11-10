# App state in the store

The app layer keeps all of one app's durable state in the host's `StateStore`, namespace
`client/<app_id>` (the App ID in z-base-32). One record per key; no blob is rewritten whole.
Every value is `{"v":1,"d":<record>}`: a reader refuses another `v` as corrupt, so a later
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
  commit of its own, which moves no cursor; the step then runs again.
- **A batch refused with `409 stale_epoch`** is gone from `opq/` with the refusal; the app
  takes the newer `identity.json` and key bundle, each in its own commit, and the batch
  sealed again is signed and kept under a new batch ID before it is first sent.
- **A retired receive key goes only after the cursor's commit** that passes the next key's
  registration (Switch spec 3.6).
- **Any commit carries everything read before it.** A page's writes go in the next commit
  point, so no commit records a cursor past items whose writes it lacks.
- **After a failed commit the app reloads** from the store before its next call.
- **A duty event goes in the commit of what it reports** (`duty/<id>`), and is reported
  only once that commit is done: a failed commit reports nothing, and a crash after it
  loses nothing, since every load reports the kept duty events again.

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
| `parked/<seq>` | an entry stored locally and passed: the opened plaintext, sender, certificate, time, reason (an unverifiable sender or a quota, tried again; an effect refused for good, over one batch, or kept past the window in which its resend tells whether it was applied, not tried again) | yes |
| `uncert/<sender>/<msg_id>` | a message whose kept effect may have been applied, kept without its entry by an earlier build: its entry is parked when the feed shows it again, and the protocol told in that commit | |
| `asked/<seq>` | a re-send was handed to the protocol for this item | |
| `owed/<generation>/<seq>` | a re-send or missed-entries call about this item that the protocol answered with an error: written in the commit that passes the item, made again at the start of each read, and gone in the commit of its answer's writes | |
| `departed/<app_id>` | another own app's departure verified in the chain, and its time | |
| `join` | the join step: the registration batch while it is owed | |
| `pending/effect` | a received message's effect batch and its outcome writes, with the deadlines of the claims it writes, and the opened entry, to store it locally if the batch outlives the batch ID window | yes |
| `pending/record` | an `app.put` batch | |
| `alarm` | the alarm that stopped the app | |
| `restore` | after a restore: the backup's highest `n`, the key check, the app's own new key, reconcile mode | |
| `leave` | a leave in progress or done | |
| `service_time` | the highest service time verified, its key, the offset from the device clock | |
| `p/...` | the protocol's own local state (`LocalWrite`) | the protocol's |
| `duty/<id>` | a duty event (`AppEvent::is_duty`), written in the commit of the change it reports, until the host acknowledges it (`App::ack_events`); one per entry stored for good, kept batch or `attempt` dropped, or outbox message given up | |
| `dutyn` | the ID the next duty event takes; a restore keeps it, so an ID is never given twice | |

Deleting the keys on a leave removes `keys`, `naming`, `rk/`, `scope/`, `parked/`,
`pending/`, `p/`, `duty/` and `owed/`, and marks `leave`.

## Extending the schema

- New records take new keys under a prefix of their own; existing keys keep their meaning.
- A changed record type bumps `SCHEMA_VERSION` with a migration that runs on load.
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
| `out/<msg_id>` | a queued message, queued alone or with the answer of the batch that carried it: its signed plaintext, signed once, the envelope sealed for one try with its `apps_version`, its jobs (conversation entry, delivery, record) and where each stands, a re-send owed, when it was refused for good, and when a delivery was first and last answered `403 not_admitted` or `403 not_current`, with the answers counted at least 7.5 days apart; a failed one goes after the sent-message retention, an undeliverable one when a try is answered so again 30 days after that first answer and 5 answers were counted | yes |
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
