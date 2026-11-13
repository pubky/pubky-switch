# Configuring and running the Pubky Switch

## Running

```sh
pubky-switch --config /etc/pubky-switch/config.toml
pubky-switch check-config --config /etc/pubky-switch/config.toml
```

- `run`, the default command, starts the service. It needs a database (`database.url` or `PUBKY_SWITCH_DATABASE_URL`) and a key store (`keys.path`), applies pending schema migrations, and stops on `SIGTERM` or Ctrl-C.
- `check-config` checks a file and prints it with every default written out.
- `--config` may also be given as `PUBKY_SWITCH_CONFIG`. Without a file, every setting takes its default.

### Container

```sh
docker build -t pubky-switch .
docker run -p 127.0.0.1:9090:9090 \
  -e PUBKY_SWITCH_DATABASE_URL=postgres://switch:...@db/switch \
  -v switch-keys:/var/lib/pubky-switch/keys \
  pubky-switch
```

The image runs as a non-root user. Its default configuration, [`docker/config.toml`](../docker/config.toml), listens on every interface inside the container and keeps the key store in the `/var/lib/pubky-switch/keys` volume; mount your own file at `/etc/pubky-switch/config.toml` to change it.

## The configuration file

The file is TOML. Every section and setting is optional, and unknown settings are refused, so a misspelt name fails at start. [`config.example.toml`](../config.example.toml) lists every setting with its default.

### `[admin]`

The operator listener.

| Setting | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:9090` | address of the operator listener |

It serves:

- `GET /health/live`: `200` while the process runs.
- `GET /health/ready`: `200` when every readiness check passes, `503` otherwise, with a JSON body `{ "ready", "checks", "trusted_time" }`. Missing trusted time is reported, but doesn't make the service unready: it still serves everything that doesn't depend on time.
- `GET /metrics`: metrics in the Prometheus text format.

The listener isn't authenticated. Keep it on a private network.

### `[server]`

The API listener.

| Setting | Default | Meaning |
|---|---|---|
| `origin` | none | the switch origin, exactly as `identity.json` names it in `inbox.url`: `https://` and the host, with an optional port, no path or trailing slash. Requests sign it (Switch wire 7.1). Without it the API listener stays off |
| `listen` | `127.0.0.1:8080` | address of the API listener; terminate TLS in front of it |
| `allow_insecure_origin` | `false` | allow an `http://` origin, for development only |
| `proxy.trusted` | `[]` | reverse proxies whose `proxy.header` the service believes, as addresses or networks such as `10.0.0.0/8` |
| `proxy.header` | `x-forwarded-for` | the header those proxies append the client's address to |

A request's network source, which the failed-authentication and public-read limits count by, is an IPv4 address or an IPv6 /64 (Switch wire 7.2). Behind a trusted proxy it is the nearest address in the header that isn't a trusted proxy; otherwise it is the connection's peer.

Served so far: `POST /v1/enroll`; `PUT /v1/{id}/identity` and the public `GET /v1/{id}/identity`; `POST /v1/{id}/ops`; `GET /v1/{id}/feed`; `GET /v1/{id}/claims/{key}`; `GET /v1/{id}/apps` and `POST /v1/{id}/apps/{app_id}/revoke`; `PUT /v1/{id}/peers`; `POST /v1/{id}/inbox`; `GET /v1/{id}/directory`; `GET` and `POST /v1/{id}/apps/{app_id}/keys`; `POST /v1/{id}/apps/{app_id}/leave`; `GET /v1/{id}/allow`; `GET /v1/{id}/records/{key}` and `GET /v1/{id}/records`; `PUT` and `GET /v1/{id}/handover`; `POST /v1/{id}/erase`; `PUT /v1/{id}/push`, whose registrations get a webhook per handle for each `notify` entry (push for connect requests isn't sent yet). Every other call is answered `503 unavailable` until its endpoint lands. `GET /v1/{id}/apps` answers `recovery: null` until recovery is served. The sweeps of Switch wire 9.1 run once a minute at a request to the account, with one part not yet: forgetting a deleted key doesn't check that the account isn't frozen, since freezes aren't served (it comes with the cooperative move).

### `[log]`

| Setting | Default | Meaning |
|---|---|---|
| `format` | `json` | `json`, one object per line, or `text` |
| `filter` | `info,sqlx::postgres::notice=warn` | a `tracing` filter, such as `info,pubky_switch=debug`; `PUBKY_SWITCH_LOG` overrides it |

Logs never hold message content: no envelopes, sealed values, record bodies, signatures or keys.

### `[limits]`

Limits, quotas and rates, under their Switch wire 9.2 names, with the wire format's defaults. The defaults are for one identity on a shared service; an operator may raise them. The service refuses a file that breaks the wire format's rules:

- `app_limit` is between 1 and 255;
- `max_claim_age_ms` (400 days) and `batch_proofs_ms` (30 days) may be raised but not lowered, since apps rely on them;
- `claim_share_percent` and `sender_share_percent` are between 1 and 100;
- the other limits are at least 1.

**Chain stub retention** (Switch wire 7.4.4 "Checkpoints", 9.1) is on by default. At each request to an account with trusted time from a verified caller, the service signs a checkpoint and drops the chain stubs behind it that no current app needs. A stub goes once every current app's cursor has passed it or once it is `cursor_hold_ms` old (30 days). It is never cut inside a batch, the head never goes, and nothing goes while the account's state is behind its key's mark. A checkpoint is signed once `checkpoint_behind` stubs (1,000) may go past the last one, at the newest of them, or, with `checkpoint_at_head`, at the head once that many chain items were added since. The batch records whose proofs are gone go with their stubs. The settings:

- `chain_retention = false` keeps every stub and signs no checkpoint;
- `checkpoint_behind` and `cursor_hold_ms` set the two thresholds;
- `retention_per_request` (1,000) bounds the work: one request reads at most that many stubs, without their documents, and drops and deletes at most that many. It must be at least `checkpoint_behind` and 8, a batch's most items, so a batch at the start of a request's read is always whole in it.

Like the documents check of `0022_superseded_documents`, the first requests after an upgrade catch up a bounded amount at a time. At an account with an old chain, the first request with trusted time signs a checkpoint once 1,000 of its oldest stubs may go. It then drops those stubs, and each later request drops the next ones, oldest first, once `checkpoint_behind` more may go, until it reaches stubs a current app still needs. Those are the stubs past the lowest cursor of a listed app that isn't revoked or departed, and every stub while a registered app hasn't moved its cursor, as long as they are younger than 30 days. What goes is each stub's envelope and chain hash, and the item's document where it was still kept. Current records, claims and key bundle parts keep their own operations and proofs, so they read the same. An app reading from behind the oldest kept stub gets pages that carry the checkpoint and show no stub before it, and it continues as Switch wire 7.4.4 says: from the checkpoint, or in reconcile mode.

**Upgrading to chain stub retention.** Stop every instance on the code from before `0027_chain_retention` before an instance on this code serves. Or start every instance on this code with `chain_retention = false` (the earlier code refuses the setting, so set it only on the new one) until every instance runs this code, and then turn it on. An instance on the earlier code serves pages without the `checkpoint` member. An app reading past stubs this code dropped from such a page sees a chain that doesn't link and no checkpoint, and raises a rollback alarm, which its user clears only by moving to another provider or declaring a provider loss (Switch spec 10.1). That is any app that would continue from the checkpoint at this code: one more than 30 days behind, one restored from an older backup, and a device of an app whose devices share its cursor. A configuration that raised `checkpoint_behind` above 1,000 must raise `retention_per_request` with it: the service refuses to start otherwise, naming `retention_per_request`.

Values the wire format fixes aren't configurable: the envelope cap (64 KiB), the sealed value cap (256 KiB), 8 entries per batch, 128 hand-over parts (a 12 MiB `PUT /handover` body), 1 MiB export chunks, feed pages of at most 500 items and 1000 positions, the 25-second long-poll and the 5-minute timestamp window.

### `[trusted_time]`

Trusted time (Switch spec 10.1, Switch wire 7.3).

| Setting | Default | Meaning |
|---|---|---|
| `required` | `true` | without trusted time, refuse what depends on time with `503 unavailable`; turn off only for development, where the wall clock is taken as trusted |
| `drift_ppm` | `100` | the monotonic clock's drift bound, in parts per million |
| `max_sample_age_ms` | `86400000` (24 hours) | the oldest sample that still gives trusted time |
| `max_uncertainty_ms` | `300000` (5 minutes) | the largest uncertainty trusted time may have |
| `max_disagreement_ms` | `300000` (5 minutes) | how far the wall clock may be from trusted time before the service uses trusted time and alerts |
| `sample_interval_ms` | `900000` (15 minutes) | how often the service samples its time source; at most an hour |
| `retry_interval_ms` | `60000` | how long it waits after a failed sample |

Without trusted time the service serves reads and everything else that doesn't depend on time, and refuses the rest. The `pubky_switch_trusted_time_available` metric shows whether it has trusted time, and `pubky_switch_time_disagreement_alerts_total` counts the times its wall clock disagreed with trusted time.

#### `[trusted_time.roughtime]`

The service samples trusted time from Roughtime servers (RFC 10049), asking all of them at once over UDP.

| Setting | Default | Meaning |
|---|---|---|
| `servers` | three public servers, listed in [`config.example.toml`](../config.example.toml) | each `{ name, address = "host:port", public_key = base64 Ed25519 key }`; an empty list means no time source |
| `min_agreeing` | `2` | how many checked answers must agree for a sample; at most the number of servers |
| `timeout_ms` | `2000` | how long to wait for one server's answer |
| `attempts` | `2` | how many times to ask one server per sample, each with a fresh nonce; at most 5 |
| `alert_after_ms` | `3600000` (1 hour) | how long a server may keep failing before the service alerts |

Every answer is checked before it counts:

- its version is one the request offered, RFC 10049 version 1 or the earlier draft `0x8000000c`;
- its nonce is the request's;
- the server's long-term key signed the delegation, and the delegated key signed the answer;
- the Merkle path leads from the request to the signed root;
- the midpoint lies within the delegation's validity.

Each checked answer vouches that true time lies within its midpoint plus or minus its radius. The sample is the window where at least `min_agreeing` of those intervals overlap. So a minority of wrong or hostile servers can't move it, and a server that disagrees with the others is logged. The sample's uncertainty is half that window plus the time the queries took.

Choose servers run by independent operators, and review the list before production: the public keys are pinned here, and a server that rotates its long-term key stops counting until the key is updated.

**Server health.** Every answer is counted by outcome in `pubky_switch_roughtime_answers_total{server,result}`:

- `verified`;
- `refused`, an answer that arrived and failed a check;
- `timeout`;
- `unreachable`.

When a server's samples keep failing for `alert_after_ms`, the service raises one alert:

- an `error` log line with `alert = "roughtime_server_failing"`, the server and the outcome;
- the gauge `pubky_switch_roughtime_server_alert{server}` set to 1;
- `pubky_switch_roughtime_alerts_total{server}` counted.

The alert clears when the server is verified again. A refused server most often rotated its long-term key: check its published key and update the pinned one. Act on the alert while the other servers still agree, before agreement is lost. A Prometheus rule:

```yaml
- alert: PubkySwitchRoughtimeServerFailing
  expr: pubky_switch_roughtime_server_alert == 1
  annotations:
    summary: "Roughtime server {{ $labels.server }} has failed for over an hour"
- alert: PubkySwitchNoTrustedTime
  expr: pubky_switch_trusted_time_available == 0
  for: 5m
```

### `[database]`

PostgreSQL.

| Setting | Default | Meaning |
|---|---|---|
| `url` | none | the connection URL; `PUBKY_SWITCH_DATABASE_URL` overrides it, and keeps the password out of the file |
| `max_connections` | `16` | most connections in the request pool. The keyed section that signs an answer once its request's transaction has ended (a commit, or a refusal before the lock) takes one of them for a moment, so a request uses up to two in turn, never two at once. The first goes back to the pool only after sqlx's return-to-pool check, a ping, so a keyed section with every other connection taken may wait that one round trip. Each instance also opens one more, outside the pool, for the change listener that wakes feed long-polls: size PostgreSQL's `max_connections` for `instances × (max_connections + 1)` |
| `acquire_timeout_ms` | `5000` | how long a request waits for a free connection |
| `lock_timeout_ms` | `10000` | how long a request waits for its account's lock before it gives up with `503 unavailable`; also how long an answer's keyed section waits for an erasure or a key change holding the account's keying lock, and how long an erasure waits for the keyed sections in progress, each answered `503 unavailable` past it |
| `migrate_on_start` | `true` | apply pending schema migrations at start; safe with several instances |
| `snapshot_readers` | `4` | most reads at once that run after the account's lock on a snapshot of the state under it (`GET /allow`, a `GET /records` page), each on a connection of its own on top of `max_connections`; a request waits for one before it takes the lock |
| `connect_retry_ms` | `30000` | how long the service keeps trying to reach the database at start, while it refuses connections or is still starting up, before it exits. It covers the request pool only: the change listener connects once the pool is up, without this retry, and a failure there stops the service |

**Migrations on a large database.** Each migration runs in one transaction, and some take exclusive locks for their duration. `0008_feed` backfills every operation's proof into `chain_items` and builds two indexes without `CONCURRENTLY`, so `chain_items`, `shared_records` and `claim_entries` take no writes until it finishes, and since its `ALTER TABLE` holds an exclusive lock on `chain_items` until it commits, feed reads wait for it too. It is sized for a small database. On a large one, run it in a maintenance window, with `migrate_on_start` off on every instance but one. `0011_inbox` adds a `CHECK` constraint to `list_entries`, which scans the whole table under an exclusive lock while the migration runs, so list reads and writes (and appends, whose admission reads the lists) wait for it; on a large `list_entries`, the same maintenance window applies. `0014_record_key_text` adds a stored generated column to `shared_records`, which rewrites the whole table under an exclusive lock, and builds its index without `CONCURRENTLY`; until it commits, record reads and writes (every `POST /ops` that names a record, feed pages, which read the records' current versions, `GET /records`, and `GET /apps` and `PUT /identity`, which read the generations of the records' kept proofs) wait for it. On a large `shared_records`, the same maintenance window applies. `0015_full_bundle_completed` adds a nullable column to `apps` with a `CHECK`, which rewrites nothing but validates the table once under an exclusive lock (21.7 ms on 500,000 rows), so app reads and writes wait that long. `0016_lagging` adds columns to `apps` and `inbox_entries` with constant defaults and `CHECK`s and relaxes `inbox_entries`' `NOT NULL`s; that rewrites nothing, but validates `inbox_entries` once under an exclusive lock (107 ms on 500,000 entries), so whatever reads or writes the inbox (appends, feed pages, cursor moves, `GET /apps`' unread counts) waits that long. `0019_recovery_uploads` adds columns to `shared_records` with constant defaults and a `CHECK`, relaxes its `proof`'s `NOT NULL`, and creates the empty `divergent_uploads`; that rewrites nothing, but validates `shared_records` once under an exclusive lock (about 255 ms on 500,000 records), so record reads and writes (the same calls as for `0014_record_key_text`) wait that long. `divergent_uploads` bounds each record's uploads by `limits.max_divergent_uploads` in code, not by a `CHECK`, since the limit is configurable (Switch wire 9.2); an export carries at most 8 for a record (10.3), so with a value above 8 a record can hold more than the next service's import takes. `0021_sweeps` first builds two partial indexes without `CONCURRENTLY`: one over `shared_records`' deleted rows, which scans `shared_records` once while record writes wait, and one over the `batches` that keep their proofs, which scans `batches` once while every write that records a batch waits. On a large `shared_records` or `batches`, the same maintenance window applies. Last it adds a nullable column to `accounts` with a `CHECK`, which rewrites nothing but validates the table once under an exclusive lock held until the migration commits, so every request waits that long (`accounts` holds one row an account). `0022_superseded_documents` adds a nullable column to `chain_items` with a `NOT VALID` check, which reads no row, and two columns to `accounts` with constant defaults and `CHECK`s, then sets one of them on every account. Its `ALTER TABLE`s hold exclusive locks until it commits: `chain_items` only for the two quick statements and the rest of the transaction, so feed reads and writes that chain an item wait that long, and `accounts` through the `CHECK`s' validation and the `UPDATE` of every row, so every request, which locks its account's row, waits that long. It deletes no document itself: the documents chained before it are checked at the requests with trusted time from a verified caller (step 4), 64 a request (Switch wire 7.5). Stop every instance on the code from before it before it runs: an instance on that code after it chains items that name no app and notes nothing it supersedes, past where the check ends, so their documents stay for good. `0025_chain_items_by_doc_app` builds a partial index over that column without `CONCURRENTLY`, in a transaction of its own: the build scans `chain_items` once under a `SHARE` lock, so every write that chains an item waits for it (reads don't), and on a large `chain_items` the same maintenance window applies. `0023_push_registrations` creates the empty `push_registrations` and replaces the `CHECK` on `erased_keys`, which validates that small table once. `0024_push_deliveries` creates the empty `push_deliveries`. `0027_chain_retention` creates the empty `chain_retention` and builds two indexes over `batches` without `CONCURRENTLY`, each scanning `batches` once under a `SHARE` lock, so every write that records a batch waits for them; on a large `batches` the same maintenance window applies. It deletes nothing itself: chain stubs go at later requests, as above. Stop every instance on the earlier code before one on this code serves, or upgrade with `chain_retention = false` (Upgrading to chain stub retention, above).

### `[push]`

Push (Switch wire 8).

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `true` | take push registrations (`PUT /v1/{id}/push`) and send webhooks; off, every registration is answered `400`, as a service that sends no pushes answers (Switch wire 8.1), and nothing is queued or sent; rows queued while it was on wait, and go unsent once their minute has passed |
| `concurrency` | `16` | the most webhooks one instance sends at once; 0 is taken as 1. One account has at most 8 in flight at once across instances, so keep it above 8 for one account's slow relay to leave room for the others |

The service keeps each own app's registration: its relay URL, at most 8 handles and a push key the service mints for it. An account's apps hold at most 8 handles at one relay host between them: a list of handles past that is answered `400`, since an entry sends at most 8 webhooks toward one host. An account that registered more there under an earlier version, before the limit, can only set a list that brings it down to 8 in one step; none was deployed. The relay URL must be `https://` on port 443 without user info, and its host must resolve only to public addresses, which the service checks with its system resolver at each registration, within 5 seconds.

**Delivery** (Switch wire 8.2). A `notify` entry queues one webhook per handle of each target app's registration (at most 8 toward one relay host, as registration keeps them) in the append's transaction; a worker in every instance sends them, never during the append. The queue is timed by the database's clock, never an instance's own: when a row was queued, when it is due, its lease and its minute, so instances whose clocks disagree still agree on them; the service's trusted time is only the webhook's `ts`. Several instances share one queue: claims take turns under an advisory lock, a row is claimed with `FOR UPDATE SKIP LOCKED` and leased for 30 seconds, and its attempt ends within 10 seconds of the claim, so while it runs no other instance claims the row and one instance sends it at a time. That needs the database's clock not to step (slew it, as NTP does): a step forward of more than 20 seconds makes leased rows due while their attempts run, so two instances can send one row at once, and a step past a minute drops every queued row unsent. A claim counts each account's rows in flight once, reading the due rows and those in flight, and is cut off after 2 seconds (`statement_timeout`), so no claim holds the others' turn past an attempt's time to send. A claim takes about 20 ms at 25,000 queued rows and 60 ms at 100,000, but a queue of about 2,000,000 due rows makes every claim reach its 2 seconds: then nothing is sent for any account, the log shows a warning `push deliveries: claiming rows` at every claim and `pubky_switch_push_webhooks_total` stops growing. It recovers on its own: rows past their minute go each second whether or not a claim succeeds, so the claims are quick again within about a minute of the queue's growth stopping. An instance that stops mid-attempt (a crash, a kill) leaves its row to be claimed again when the lease ends: the attempt counts as one of the 3, and a webhook the relay took just before is sent again, so delivery is at least once. Attempts run as a stream of at most `concurrency`, not in rounds, so a relay that never answers holds one slot and the next due row takes each slot that frees; one account has at most 8 rows in flight at once, across instances, and a free slot goes to the account with the fewest in flight first, the oldest row breaking ties. That bounds what accounts whose relays never answer take, not how many such accounts there are: with about 190 of them, one instance of 16 slots can serve a third account's webhook past its minute; enrolling an account is what bounds that. Within an account, one app whose relay never answers takes the account's 8 slots, so its other apps' webhooks wait behind it. Each attempt signs a fresh body (`ts` the time sent, a new nonce) with the registration's push key, under a share lock on the registration that waits at most 1 second, so a replacement or a removal waits for the signature and the key store deletes no key that is signing; at most a quarter of `database.max_connections` attempts (at least one) hold a registration at once, and the worker's own statements (the claims, the drops, the settles) take one connection more, so with `max_connections` at 4 or more requests keep the rest of the pool. Attempts keep running while the worker waits on its own statements. What comes before the connection has until 5 seconds after the claim, and past that the webhook isn't sent and the attempt fails. The connection resolves the relay's host again, refuses it if any address isn't public, and connects to an address it checked, with TLS checking the host name; it follows no redirect, and has 5 seconds. A 2xx answer is a delivery. Anything else is retried 20 seconds later, at most 3 attempts, each claimed within a minute of the entry, so the last ends at most 70 seconds after it; then the row goes. A row whose registration no longer names its push key or handle, whose key is owed deleting, or whose account no longer serves here (its newest `identity.json` names another service) goes unsent; the registration stays as it is. Without trusted time nothing is sent, but rows are still queued, sent once trusted time is back within their minute, and dropped once past it. Rows go with their registration, at a replacement, and when their handle leaves the list. The queue is bounded by time: every row goes within about a minute of its entry, with or without trusted time, so it holds at most 8 rows per app for each `notify` entry of the last minute, which `limits.notify_per_min` bounds per sender identity.

Neither relay URLs, handles nor keys are logged: delivery logs counts and failure kinds (`unresolved`, `refused`, `timeout`, `connect`, `redirect`, `status`, `late`, `internal`) only, and `pubky_switch_push_webhooks_total` counts attempts by `result` (`delivered` or a failure kind). The HTTP client's own debug logs name the hosts it connects to: keep `reqwest` and `hyper_util` at `info` or above in `log.filter`.

**Rolling upgrades.** Turn push on only once every instance runs a version that has it: an older instance's sweep would read a `push` row as an erasure and delete the key without the row lock, its erasure would drop registrations without owing their keys, and its revocations and recoveries in place would leave registrations of apps no longer current. Since `enabled` defaults to on, set it to `false` while an upgrade from a version without push (any version before `0023_push_registrations`) rolls out, and back once every instance runs this one.

### `[keys]`

| Setting | Default | Meaning |
|---|---|---|
| `path` | none | the directory of the key store |

## Storage and durability

The service keeps its state in two places, and they are backed up differently.

- **The database** holds every account's state. Every request to an account runs in one transaction that locks the account, so one account's operations are serialized, and a request either commits whole or leaves no trace. An answer carrying a `seq`, a transition proof or a signed head goes out only once its commit is durable (Switch spec 6.5). The service refuses a database with `fsync` off or `synchronous_commit` off. With synchronous replicas, use `synchronous_commit = on` or `remote_apply`, so a commit is durable on every replica that could be promoted; never promote an asynchronous replica to serve writes.
- **The key store** holds each account's service key, its **mark** (the newest head the key signed), the erasure ledger, and one push key for each push registration (Switch wire 8.1). A push key has no mark and signs only its registration's webhooks; the database holds its public half and its ID. An app holds at most one registration, so the key store holds at most `limits.app_limit` push keys per account (32 by default), times the accounts, plus those of the requests under way: a key a start minted and no registration took, or one a request let go, is deleted when the request ends, even when its client hangs up first, since the mint, and the commit with the deletions it owes, run to their end on their own. A push key the service lets go, at a replacement, when its app stops being current, at a recovery in place or at an erasure, is owed deleting in the same transaction and deleted after the commit; one minted for a start is owed deleting before it is generated, until the committed registration names it, so a failure or a crash leaves no key behind for good: one whose deletion failed goes at the next sweep, at an erasure, a recovery in place and at start. Keep it on a disk that database backups don't cover, and back it up on its own, often: losing it loses every account's service key. The key signs nothing behind its mark, so after a database restore the accounts whose state went back stop with `503 unavailable` instead of serving a history that lost acknowledged writes.

### No restore and continue

Restoring a database backup, failing over to a replica that may lag, or replaying an incomplete log is a loss of committed state (Switch spec 6.5). The service never continues from it under the same generation:

1. The key's mark stops the affected accounts on their own, and the readiness answer stays up for the others.
2. Find the accounts whose state is behind their mark; their requests answer `503 unavailable`.
3. Tell their users, through the signer's operator channel, that a provider loss must be declared. The signer declares it, here or at another service, and the account starts a new generation with a new service key.
4. Never serve the lost generation again, and never reuse its service key.

Database backups are for disaster recovery only: after a restore, every account whose state went back takes the steps above.

## Metrics

| Metric | Type | Meaning |
|---|---|---|
| `pubky_switch_build_info{version}` | gauge | always 1 |
| `pubky_switch_trusted_time_available` | gauge | 1 with trusted time, 0 without |
| `pubky_switch_trusted_time_uncertainty_ms` | gauge | the uncertainty of trusted time |
| `pubky_switch_time_samples_total{result}` | counter | time samples, `ok` or `error` |
| `pubky_switch_time_disagreement_alerts_total` | counter | readings where the wall clock disagreed with trusted time beyond `max_disagreement_ms` |
| `pubky_switch_roughtime_answers_total{server,result}` | counter | Roughtime answers by outcome: `verified`, `refused`, `timeout`, `unreachable` |
| `pubky_switch_roughtime_server_failing_ms{server}` | gauge | how long the server's samples have been failing; 0 when healthy |
| `pubky_switch_roughtime_server_alert{server}` | gauge | 1 while the server has failed for `alert_after_ms`, 0 otherwise |
| `pubky_switch_roughtime_alerts_total{server}` | counter | alerts raised for the server |
