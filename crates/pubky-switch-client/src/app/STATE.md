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
  effect's batch carries the cursor move. The processed pair, the protocol's local writes and
  the cursor are committed together with the answer.
- **A retired receive key goes only after the cursor's commit** that passes the next key's
  registration (Switch spec 3.6).
- **Any commit carries everything read before it.** A page's writes go in the next commit
  point, so no commit records a cursor past items whose writes it lacks.
- **After a failed commit the app reloads** from the store before its next call.

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
| `rk/<n>` | a held receive key: secret, signed record, registration `seq`, pending batch | yes |
| `kid/<kid>` | a kid this app or one of its devices made, kept after the key is deleted | |
| `reg/<n>` | a registration of the own app whose key this device doesn't hold: own, awaiting device sync, or unaccounted after a restore | |
| `rotation` | the last rotation's time, and whether an envelope to the current key was opened since | |
| `device` | whether the app shares its keys across devices | |
| `cursor` | the processed position, the cursor the service holds, the deferral, the cursor's time | |
| `chain` | the chain view's small fields: tip, open batch, pending heads and checkpoint, newest head, the continuity gap, held marks, restore state | |
| `chain/at/<seq>` | the verified chain hash at a `seq` | |
| `chain/batch/<id>` | a batch ID in the 30-day window, with its first stub's time | |
| `proc/<sender>/<msg_id>` | a processed message's hash and time | |
| `proct/<time>/<sender>/<msg_id>` | the time index for pruning processed pairs | |
| `seen/<seq>` | an entry processed past a held one | |
| `held/<seq>` | an entry held because its sender can't be checked, since when | |
| `parked/<seq>` | an entry stored locally and passed: the opened plaintext, sender, certificate, time, reason | yes |
| `asked/<seq>` | a re-send was handed to the protocol for this item | |
| `departed/<app_id>` | another own app's departure verified in the chain, and its time | |
| `join` | the join step: the registration batch while it is owed | |
| `pending/effect` | a received message's effect batch and its outcome writes | |
| `pending/record` | an `app.put` batch | |
| `alarm` | the alarm that stopped the app | |
| `restore` | after a restore: the backup's highest `n`, the key check, the app's own new key, reconcile mode | |
| `leave` | a leave in progress or done | |
| `service_time` | the highest service time verified, its key, the offset from the device clock | |
| `p/...` | the protocol's own local state (`LocalWrite`) | the protocol's |

Deleting the keys on a leave removes `keys`, `naming`, `rk/`, `scope/`, `parked/`,
`pending/` and `p/`, and marks `leave`.

## Extending the schema

- New records take new keys under a prefix of their own; existing keys keep their meaning.
- A changed record type bumps `SCHEMA_VERSION` with a migration that runs on load.
- Protocol state stays under `p/`, written only through `LocalWrite`.

## What the next parts add, and where

- **Sending and admission:** an outbox under `out/<msg_id>` (the envelope, signed once, and
  its delivery and record jobs), sent messages kept 30 days under `sent/`, counterparties'
  directories under `dir/<pubky>`, and the deliveries of the own `identity.json` to the
  switches the app wrote to (Switch spec 12.2 step 5). The protocol's re-send requests,
  queued today by `Protocol::resend_needed` and `Protocol::missed` in `p/`, go out through
  it. A deferred cursor move already rides on the next batch (`App::sign_ops`).
- **Shared records and claims:** the records layer reads and caches collections, takes
  `record.put` and `claim` items from the feed (today passed by `feed.rs` as chain items with
  no app-layer effect), lists collections at join and after a `missed` item, and keeps proofs
  and evidence for uploads. Effects already carry their operations with the cursor move.
- **Moves, provider loss and recovery:** `AppEvent::Moved` and `AppEvent::ProviderChanged`
  stop the read today; the provider-change flow follows the newest `identity.json`, updates
  `meta`, starts a new chain view and cursor, re-registers, and uploads evidence. Reconcile
  mode (`restore.reconcile`, the chain gap) is where its reconciliation plugs in.
- **Push:** the push registration under `push`, and a peek that runs the receive checks
  read-only on a copy of the chain view.

## Sending, admission, records and claims

| Key | Holds | Sensitive |
|---|---|---|
| `out/<msg_id>` | a queued message: its signed plaintext, signed once, the envelope sealed for one try with its `apps_version`, its jobs (conversation entry, delivery, record) and where each stands | yes |
| `sent/<msg_id>` | a message the recipient's inbox accepted, kept 30 days from its first acceptance for re-sends | yes |
| `sentt/<time>/<msg_id>` | the time index for pruning sent messages | |
| `dir/<pubky>` | a counterparty's directory as signed, the switch, generation and `identity.json` version it was read under, its versions, and whether it is read again before the next send | |
| `rkn/<pubky>/<app_id>` | the highest receive key `n` seen for a counterparty's app | |
| `peer/<pubky>` | the version of the own `identity.json` a counterparty's switch last named, and when the app last wrote there | |
| `peers_doc` | the own `identity.json` the deliveries to recent peers were last judged against | |
| `lc/conv/<pubky>` | a conversation entry in the app's copy of the lists, from its writes, the feed and `GET /allow`; its writes and `GET /allow` also keep `lc/contact/`, `lc/deny/` and `lc/code/` | |
| `invite/<code_hash>` | the code of an invite code the app registered, to show it again | yes |
| `opq/<batch_id>` | a batch of operations, signed and kept before it is sent, with what its answer settles | |
| `list_due` | a listing of the collections is owed: after joining, a restore or a `missed` item | |
| `rec/<key>` | the shared record write the app took: the signed operation, certificate and proof, its version and whether a proof gave it, the opened value, and the refused write it follows | yes |
| `recname/<key>` | the collection name of a record the app creates, until its write is answered | |
| `hw/<key>` | the protocol's mark of what the app has seen in a record | the protocol's |
| `flag/<key>/<generation>/<version>` | a write the app refused, with the app it names and the rule | |
| `ocert/<app_id>/<cert_hash>` | a certificate of an own app, for checking its writes | |
| `claim/<claim_key>` | the newest claim view, the proof that shows it SETTLED, the newest entry's time and the deadline the app computes, kept until the evidence's retention ends | |
| `clent/<claim_key>/<step>` | a signed claim entry and its proof | |

Deleting the keys on a leave also removes `rec/`, `hw/`, `recname/`, `out/`, `sent/`,
`sentt/`, `invite/` and `opq/`. A restore replaces the namespace, these keys included, and
sets `list_due`. `rec/`, `clent/` and `claim/` hold the evidence of the shared state that
uploads carry (`App::shared_evidence`).
