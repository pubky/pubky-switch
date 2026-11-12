# pubky-switch-harness

Tests only. Runs flows of the real signer and the real app against the Switch service of
this workspace, in process on PostgreSQL, and against the client's scripted switch, and
compares what the two answered. Nothing depends on this crate, and it isn't among the
workspace's default members: `cargo test --workspace` takes it in.

```sh
export PUBKY_SWITCH_TEST_DATABASE_URL=postgres://switch:switch@127.0.0.1:5432/postgres
cargo test -p pubky-switch-harness
cargo run -p pubky-switch-harness --example trace -- join          # a flow's calls, both runs
cargo run -p pubky-switch-harness --example trace -- join facts    # every fact kept
```

Without the variable the service's half is skipped; with `PUBKY_SWITCH_REQUIRE_DB` set it
fails instead.

- `src/flows/`: the flows, each written once. `flows::FLOWS` names them, and
  `flows::flow_of` says which flow sends each call the service routes.
- `src/allowed.rs`: where the scripted switch answers an honest flow differently from the
  service, and why. A flow's test fails on a difference the list doesn't hold, and on an
  entry that no longer shows.
- `src/check.rs`: what the harness verifies itself in both runs (answer signatures, heads,
  chain stubs, feed items, transition proofs), and what it leaves to the client and the
  signer. A failed check fails the flow's test and no allowed entry can cover it,
  so every answer of the service and of the scripted switch passes these checks in every
  flow.

## Retries

`World::lose_answer`, `World::unreachable` and `World::refuse` put a fault of the network in
front of either switch: an answer lost after the switch took the request, a request that
never arrives, or a refusal that comes back in the switch's place with no signature.
`World::hold_back` keeps a request waiting on its way until `World::let_go`, where one
party's step must not overtake another's answer at either switch.
`World::fail_homeserver_write` and `World::fail_homeserver_deletion` fail a signer's next
write or deletion of one file at its own Homeserver, once. The Homeserver is no switch, so
such a fault is the same in both runs.
The retry flows send each of these again, and the service and the scripted switch answer
every one alike:

| Sent again | After | The answer to the retry |
|---|---|---|
| `POST /v1/enroll`, the same enrollment | a lost answer | the same service key |
| `PUT /v1/{id}/identity`, the same bytes | a lost answer | the proof of the first try |
| `PUT /v1/{id}/identity` | a failed connection | its proof |
| the signer's `POST /v1/{id}/ops` (`cert.put`, `key_bundle.put`), the same batch | a lost answer | the original proofs |
| an app's registration (`app.put`, `receive_key.put`), the same batch | a lost answer | the original proofs |
| an app's `POST /v1/{id}/ops` (`allow.put`), the same batch | a lost answer | the original proof, at the current head |
| a `cursor.set` alone | a lost answer | no proofs |
| an app's `POST /v1/{id}/ops` (`allow.put`) | a failed connection | its proof |
| `POST /v1/{id}/inbox`, the same envelope | a lost answer | the same `entry_id` and `accepted_at` |
| a `claim` batch, the same batch | a lost answer | the original proof |
| a second `attempt` at the step the first took | the first try's lost answer | `409 conflict`, the claim in `current` |
| `POST /v1/{id}/apps/{app_id}/leave` | a lost answer | `403 not_current` |
| `PUT /v1/{id}/peers` | a lost answer | `200` again |
| `GET /v1/{id}/feed` | a lost answer | the same page |
| `POST /v1/{id}/apps/{app_id}/revoke` | a lost answer, and a failed read of the apps | `200`, no proofs, the head |
| a `claim` `done` batch, the same batch | a lost answer | the original proof, which settles the claim for the app |
| a second `done` at the step the first took | the first try's lost answer | `409 conflict`, the settled claim in `current` |
| `PUT /v1/{id}/handover`, the same hand-over | a lost answer | `200` again, the same app and parts |

A revocation whose answer was lost isn't sent again while the signer can read the switch: it
reads the account's apps and finds it done.

An erasure whose answer was lost isn't sent again either (Switch wire 7.4.16): the signer's
next read of the account's apps gets the operator's `404`, which nobody can authenticate, so
it holds the account as erased but unconfirmed. It concludes the account is erased at its
first run 24 hours after that `404`, every read in between having met it too. The flow moves
the world's clock, which is the signer's device clock, by those 24 hours.

An app of an erased account waits too (Switch spec 12.7 step 5): its reads meet the
operator's `404` and no `identity.json` on the Homeserver, which the signer's erasure took
off, and it takes the account as gone at the fifth read, each at least 6 hours after the one
before, 24 hours after the first. Both erasure flows run that wait, and a read short of the
24 hours that raises nothing.

## Not covered

The flows send every call the service serves, each at both switches. What they leave out:

- **Calls the service doesn't serve yet**, eleven of the thirty-three of Switch wire 7.4:
  the connection requests (`POST`, `GET` and `DELETE /connect`), `PUT /push`, `POST /freeze`
  and `/unfreeze`, `GET /export` and its chunks, and `POST /import` with its chunks and
  activation. So no flow moves an account or changes its key in place, and no upload is
  sent in a cooperative move. `flows::flow_of` lists them, and the test fails once one is
  served without a flow.
- **More of a recovery upload** (Switch wire 7.4.14). The upload flows bring records, a
  claim and the lists to the new service, and send the refusals in their order. They leave
  to the service's own tests: an operation of a removed app (`distrusted`), items that
  don't verify (`unverified`) and claim entries the writer rules refuse (`refused`), which
  no app of the client crate uploads; a claim made divergent by uploads; the caps
  (`max_divergent_uploads`, `max_contacts`, `max_deny`, `max_attempts_per_claim`); and an
  upload from an app that hasn't registered at the new service yet.
- **Faults in front of most reads.** The retries above are the ones covered. No answer is
  lost and no connection fails in front of `GET /allow`, `/claims/{claim_key}`,
  `/directory`, `/apps/{app_id}/keys`, `/records`, `/records/{key}`, `/handover` or the
  public `/identity`, nor in front of `POST /apps/{app_id}/keys` or a record write.
- **A list that `limit` ends.** The `pages` flow reads a feed in pages that `limit` ends
  and that the byte budget ends, and a records list in pages the byte budget ends; a
  records list that `limit` ends takes more than a thousand records, and no flow writes
  that many. The directory has no pages (Switch wire 7.4.10).
- **A wait that runs out, and a held read after a leave.** The `waiting read` flows' reads
  are answered by a write, by an erasure and by the reader's revocation. A read whose wait
  passes with nothing written takes real seconds at the service, and no flow sends one;
  nor one held while its app leaves, which the app itself would have to send while it
  waits.
- **A full inbox.** The `lagging app`, `missed item` and `unreadable after a revoke` flows
  run with an app that falls behind while another reads. An inbox no app reads, where the
  quota refuses senders, an unreadable item at a leave or at a delivery, and a lagging app
  that still finds entries to read are left to the service's own tests.
- **More of the lists:** an invite code withdrawn or used several times, an invite, a
  conversation entry pruned, a connection request.
- **Longer lives:** a renewal that adds a scope, a claim that runs out by time, an
  identity that enrolls again after an erasure.
- **More of a signer's copies and installs.** The install flows put the published copy
  right, clear the alarm for another document at the published version, take over on a
  new install, and restore in place. A switch that shows an older copy or another body
  (a rollback or an equivocation at the switch), a backup that doesn't open, and two
  installs whose deliveries race stay with the signer's tests on the scripted switch.
- **More of a removal.** The removal flows date a revocation and a departure, clean up
  after one, purge its entry, and send a revocation past a read that failed or during a
  recovery. A removal time a switch reports before the app was listed or after its own
  answer, and a switch's copy that doesn't verify, take a switch that misbehaves: they
  stay with the signer's tests on the scripted switch.

Not this crate's to cover: refusals, limits, rates, quotas and retention, which the
service's own tests hold, and a faulty or hostile switch, which stays on the scripted
switch. Around the service, the flows don't touch TLS, the listener, the proxy's
client-address header, the client's HTTPS transport, the time source (trusted time comes
from the test clock), key generation (accounts take keys from fixed seeds), or more than one
instance on a database. Of a service's limits, a world carries only the inbox quota, the
app limit and the hourly limit of recovery uploads to the scripted switch
(`World::add_switch_with`): a flow that leaned on
another would compare a service so set with a scripted switch at its defaults. `src/check.rs`
says what of an answer the harness verifies itself
and what it leaves to the client and the signer.

## Adding a flow

Write it in `src/flows/` against `World`, using only the real `Signer` and `App`; note what
they return and raise with `World::outcome`; add it to `FLOWS` and its calls to `flow_of`.
Run the `trace` example to see what the two switches answered, and list each difference in
`allowed.rs` with its wire clause, one step and one member per entry.

## Run time and databases

Each flow's run against the service makes one test database and drops it, also when its
test panics; the flows run one after another. Sixty flows take about three minutes in a
debug build. If that grows too long, the service's halves could share one service and one
database, with identities of their own per flow: a later option, not needed yet.
