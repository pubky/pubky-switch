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

`World::lose_answer` and `World::unreachable` put a fault of the network in front of either
switch: an answer lost after the switch took the request, or a request that never arrives.
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
next read of the account's apps gets the operator's `404`, and it concludes the account is
erased.

## Not covered

The flows send every call the service serves, each at both switches. What they leave out:

- **Calls the service doesn't serve yet**, thirteen of the thirty-three of Switch wire 7.4:
  the connection requests (`POST`, `GET` and `DELETE /connect`), `PUT /push`, `POST /freeze`
  and `/unfreeze`, `GET /export` and its chunks, `POST /import` with its chunks and
  activation, and `POST /recovery/admission` and `/recovery/upload`. So no flow moves an
  account, changes its key in place, or recovers from a lost provider. `flows::flow_of`
  lists them, and the test fails once one is served without a flow.
- **Faults in front of most reads.** The retries above are the ones covered. No answer is
  lost and no connection fails in front of `GET /allow`, `/claims/{claim_key}`,
  `/directory`, `/apps/{app_id}/keys`, `/records`, `/records/{key}`, `/handover` or the
  public `/identity`, nor in front of `POST /apps/{app_id}/keys` or a record write.
- **A list that `limit` ends.** The `pages` flow reads a feed in pages that `limit` ends
  and that the byte budget ends, and a records list in pages the byte budget ends; a
  records list that `limit` ends takes more than a thousand records, and no flow writes
  that many. The directory has no pages (Switch wire 7.4.10).
- **A waiting read, compared.** `flows::waiting_read` sends a feed read with `wait`, which
  a write of another app answers. It runs against each switch on its own: the scripted
  switch doesn't hold a read, so the two runs make their calls in different orders, which
  the comparison can't set side by side. Its test holds what each switch does.
- **A feed with gaps:** a lagging app, a `missed` item, an item an app can't read after a
  revocation.
- **Lists in use:** an invite code issued and used, and a deny list entry that refuses a
  sender.
- **Longer lives:** a renewal that changes an app's scopes, a second renewal, a data epoch
  past 2, a claim that runs out by time, an app with several collections, an identity that
  enrolls again after an erasure.
- **More than one switch with traffic between them:** the identities of a flow share one
  origin.

Not this crate's to cover: refusals, limits, rates, quotas and retention, which the
service's own tests hold, and a faulty or hostile switch, which stays on the scripted
switch. Around the service, the flows don't touch TLS, the listener, the proxy's
client-address header, the client's HTTPS transport, the time source (trusted time comes
from the test clock), key generation (accounts take keys from fixed seeds), or more than one
instance on a database. `src/check.rs` says what of an answer the harness verifies itself
and what it leaves to the client and the signer.

## Adding a flow

Write it in `src/flows/` against `World`, using only the real `Signer` and `App`; note what
they return and raise with `World::outcome`; add it to `FLOWS` and its calls to `flow_of`.
Run the `trace` example to see what the two switches answered, and list each difference in
`allowed.rs` with its wire clause, one step and one member per entry.

## Run time and databases

Each flow's run against the service makes one test database and drops it, also when its
test panics; the flows run one after another. Twenty-two flows take about a minute in a
debug build. If that grows too long, the service's halves could share one service and one
database, with identities of their own per flow: a later option, not needed yet.
