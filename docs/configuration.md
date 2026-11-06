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
- the other limits are at least 1; `checkpoint_behind` is absent (no checkpoints) or at least 1.

Values the wire format fixes aren't configurable: the envelope cap (64 KiB), the sealed value cap (256 KiB), 8 entries per batch, 64 hand-over parts, 1 MiB export chunks, feed pages of at most 500 items and 1000 positions, the 25-second long-poll and the 5-minute timestamp window.

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

Every answer is checked before it counts:

- its version is one the request offered, RFC 10049 version 1 or the earlier draft `0x8000000c`;
- its nonce is the request's;
- the server's long-term key signed the delegation, and the delegated key signed the answer;
- the Merkle path leads from the request to the signed root;
- the midpoint lies within the delegation's validity.

Each checked answer vouches that true time lies within its midpoint plus or minus its radius. The sample is the window where at least `min_agreeing` of those intervals overlap. So a minority of wrong or hostile servers can't move it, and a server that disagrees with the others is logged. The sample's uncertainty is half that window plus the time the queries took.

Choose servers run by independent operators, and review the list before production: the public keys are pinned here, and a server that rotates its long-term key stops counting until the key is updated.

### `[database]`

PostgreSQL.

| Setting | Default | Meaning |
|---|---|---|
| `url` | none | the connection URL; `PUBKY_SWITCH_DATABASE_URL` overrides it, and keeps the password out of the file |
| `max_connections` | `16` | most connections in the pool |
| `acquire_timeout_ms` | `5000` | how long a request waits for a free connection |
| `lock_timeout_ms` | `10000` | how long a request waits for its account's lock before it gives up with `503 unavailable` |
| `migrate_on_start` | `true` | apply pending schema migrations at start; safe with several instances |

### `[keys]`

| Setting | Default | Meaning |
|---|---|---|
| `path` | none | the directory of the key store |

## Storage and durability

The service keeps its state in two places, and they are backed up differently.

- **The database** holds every account's state. Every request to an account runs in one transaction that locks the account, so one account's operations are serialized, and a request either commits whole or leaves no trace. An answer carrying a `seq`, a transition proof or a signed head goes out only once its commit is durable (Switch spec 6.5). The service refuses a database with `fsync` off or `synchronous_commit` off. With synchronous replicas, use `synchronous_commit = on` or `remote_apply`, so a commit is durable on every replica that could be promoted; never promote an asynchronous replica to serve writes.
- **The key store** holds each account's service key, its **mark** (the newest head the key signed) and the erasure ledger. Keep it on a disk that database backups don't cover, and back it up on its own, often: losing it loses every account's service key. The key signs nothing behind its mark, so after a database restore the accounts whose state went back stop with `503 unavailable` instead of serving a history that lost acknowledged writes.

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
| `pubky_switch_roughtime_answers_total{server,result}` | counter | Roughtime answers, `ok` when checked, `error` otherwise |
