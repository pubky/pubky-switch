# What the scripted switch fakes or leaves out

The scripted switch (`switch.rs`) applies every batch, submitted with `POST /ops` or
injected with `app_op` and `signer_op`, through the core's rules (Switch wire 6.4). Where it
differs from the spec and the service, it is listed here. Tests of these rules belong to the
service.

## Batches

- **Request authentication** (Switch wire 7.1, 7.2): no request signature, timestamp or
  `Switch-Identity` check; the caller is the `Switch-App` header as sent. Each operation's
  signature is verified, and an own app must be current with an unexpired certificate.
- **Rates** (Switch wire 6.4 step 7, 9.4): no operation, control, per-caller or
  failed-authentication limits; never `429 rate_limited`.
- **Quotas and per-kind limits** (Switch wire 9.3): only the claim limits, at the core's
  defaults, and `max_invite_uses`; never `429 quota_exceeded` otherwise.
- **Trusted time** (Switch wire 7.3, Switch spec 10.1): the test clock is trusted and may go
  back; a batch that depends on time is never `503 unavailable`.
- **Proof states** (Switch wire 6.5) are built by the switch from each operation and the
  state after it, as the core has no function for that; a claim's is the core's claim
  view.
- **`invite_code.delete`** of a code the switch doesn't hold is `404`; the core has no rule
  for it.
- **Key bundle parts** the target's cursor passed are never dropped (Switch wire 6.2).

## State and retention

- **Durability** (Switch spec 6.5): everything is in memory, answered at once; the service
  key's mark isn't kept. Per-account order is a mutex.
- **Retention and sweeps** (Switch wire 9.1): entries never expire; `missed` items,
  checkpoints and dropped stubs exist only when a test scripts them; claims are deleted only
  when `GET /claims` finds them deletable; batch records are never dropped, and their proofs
  go only when a retry finds them past `batch_proofs_ms`.
- **Invite codes** are never used and never expire; `expires_at` shows the read time.
- **Lists**: `flagged` is always empty; connect requests are never full.
- **Records**: `divergent` is always `false`.
- **Directory**: `directory_version` is the last `seq`, `apps_version` always 1.

## Other calls

- **Inbox appends** (Switch wire 7.4.3): `send` and `send_envelope` add entries without
  admission, quotas, size buckets or `409 stale_key`; entry IDs are made up from the `seq`.
- **App currency outside batches**: other routes check only that the app hasn't departed.
- **`PUT /identity`** (Switch wire 7.4.2): `deliver_identity` takes any document, without
  the version and `prev` checks.
- **Moves and recovery** (Switch spec 12.5, 12.6, Switch wire 10): `import_into` copies the
  account in memory, with no manifest, chunks or export transfer; a recovery upload is kept
  and answered with fixed changes, merging nothing.
- **Revocation, freeze and unfreeze** are test calls, not routes.
- **Erasure** (Switch wire 7.4.16) is a flag; its answers are signed with a fixed operator
  key.
- **Push** (Switch wire 8.1): registrations only; nothing is sent to a relay.
