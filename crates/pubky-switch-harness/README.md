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

A revocation whose answer was lost isn't sent again while the signer can read the switch: it
reads the account's apps and finds it done.

An erasure whose answer was lost isn't sent again either (Switch wire 7.4.16): the signer's
next read of the account's apps gets the operator's `404`, and it concludes the account is
erased.

## Adding a flow

Write it in `src/flows/` against `World`, using only the real `Signer` and `App`; note what
they return and raise with `World::outcome`; add it to `FLOWS` and its calls to `flow_of`.
Run the `trace` example to see what the two switches answered, and list each difference in
`allowed.rs` with its wire clause, one step and one member per entry.

## Run time and databases

Each flow's run against the service makes one test database and drops it, also when its
test panics; the flows run one after another. Twenty-one flows take about a minute in a
debug build. If that grows too long, the service's halves could share one service and one
database, with identities of their own per flow: a later option, not needed yet.
