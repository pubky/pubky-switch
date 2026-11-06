# Pubky Switch

Inbox and coordination service for Pubky identities.

A Pubky Switch holds a sealed inbox for each identity it hosts, and the claims and shared records that the identity's own apps coordinate through. Senders append signed, encrypted messages to an identity's inbox; the identity's apps read them from an ordered feed. The same apps keep their shared state at the Switch, so that two apps of one identity never carry out the same obligation twice.

One Switch serves many identities, each with its own account, in the way one Homeserver serves many users. Each identity uses one Switch at a time, named in its signed `identity.json`, and can move to another one, with or without the old operator's help.

> **Status:** under construction. This repository holds the workspace and its rules; the service itself lands in the following pull requests.

## What the Switch does

- **Inbox:** admitted senders append envelopes sealed to the recipient apps' current receive keys. The Switch stores them and serves them, in order, through each app's feed and cursor. It never sees message content.
- **Admission:** a sender must be on the identity's allowlist: a contact, a conversation an app of the identity started, or an invite. Strangers may ask to connect where the identity allows it. Deny lists, quotas and per-sender shares bound what any one sender can do.
- **Claims and shared records:** batches of signed operations, applied all or nothing under their conditions, each answered with a service-signed transition proof and a signed head of the identity's hash chain.
- **Directory:** the identity's newest `identity.json`, its current apps' records, their receive keys and key bundles.
- **Provider changes:** freeze, export, import and activation at the next Switch, recovery after a provider loss, and account erasure.
- **Push:** content-free, signed webhooks to the push relay that each app registers.

The Switch is trusted for coordination (ordering, time, availability and delivery), not for content. An operator must keep every write it acknowledged: it answers only once what it committed is durable, and it never restores a backup and serves on.

## Protocols

[Paykit v0.2](https://github.com/pubky/paykit-rs/tree/master/specs/v0.2) is the first protocol the Switch serves, and its specification defines the Switch today:

- `spec.md`, Section 6, describes the Switch;
- `wire-format.md`, Sections 6 to 11, fixes its records, operations, HTTP API, push, limits, and export and import;
- `vectors/` holds the shared test vectors the Switch must reproduce byte for byte.

The service itself speaks of identities, apps, inboxes, claims and records, not of payments. What is specific to Paykit (its scopes and their permissions, the fixed policies of its collections, and its message kinds) lives in its own crate, so that other protocols can use the Switch later.

## Repository layout

| Path | What it is |
|---|---|
| `crates/pubky-switch` | The service: storage, the HTTP API, and operations. |
| `crates/pubky-switch-paykit` | The Paykit v0.2 profile the service is configured with. |

## Building

You need Rust 1.91.1 or later.

```sh
cargo build --workspace
cargo test --workspace
```

Before a pull request, run the same checks as CI:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

## License

MIT. See [LICENSE](LICENSE).
