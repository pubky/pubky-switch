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
- **Moves, provider loss and recovery, and push:** in place; their records are below.

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
| `gone` | the app isn't current any more, or its account is gone, and since when | |

- **A move** commits each step: `Seen` (the freeze verified and kept), `Read` (the old feed
  read to its end, its chain view saved), `Uploaded` (the evidence sent to the next
  service), `Switched` (`meta`, the cursor's generation, the chain view and the
  re-registration batch, in one commit), `Registered`; then `mv` goes. Batches signed for the
  old generation (`pending/effect`, `pending/record`, a pending receive key registration)
  are dropped at the switch: their entries are read again, and the record and the newest
  key go in the re-registration.
- **A loss** starts in one commit, before any call: `meta`, a cursor and chain view from the
  start of the new sequence, a fresh receive key with its registration batch, the
  registrations of the old service cleared, `restore.reconcile` on, and `loss`. Each step
  then commits as done; the protocol's re-send writes commit with their step, once.
- **`gone`** stops every read; `push` goes with it.
