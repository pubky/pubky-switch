# Pubky Switch

Inbox and coordination service for Pubky identities.

A Pubky Switch holds a sealed inbox for each identity it hosts, and the claims and shared records that the identity's own apps coordinate through. Apps of other identities append signed, encrypted messages to an identity's inbox; the identity's own apps read them from one ordered feed. The same apps keep their shared state at the Switch, so that two apps of one identity never carry out the same obligation twice.

One Switch serves many identities, each with its own account, in the way one Homeserver serves many users. Each identity uses one Switch at a time, named in its signed `identity.json`, and can move to another one, with or without the old operator's help.

The Switch reads no message and no shared data, and knows nothing of what a protocol does with them. Protocols are built on top of it: each brings its own scopes, message kinds and collections, which the Switch treats as opaque. Paykit, for payments between Pubky identities, is the first; it lives in [`pubky/paykit-rs`](https://github.com/pubky/paykit-rs).

> **Status:** under construction. This repository holds the workspace and its rules; the crates are filled in by the following pull requests.

## What the Switch does

- **Inbox:** admitted senders append envelopes sealed to the recipient apps' current receive keys. The Switch stores them and serves them, in order, through each app's feed and cursor.
- **Admission:** a sender must be on the identity's allowlist: a contact, a conversation an app of the identity started, or an invite. Strangers may ask to connect where the identity allows it. Deny lists, quotas and per-sender shares bound what any one sender can do.
- **Claims and shared records:** batches of signed operations, applied all or nothing under their conditions, each answered with a service-signed transition proof and a signed head of the identity's hash chain.
- **Directory:** the identity's newest `identity.json`, its current apps' records, their receive keys and key bundles.
- **Identity management:** enrollment, app approval and revocation, and the hand-over of the identity to another signer.
- **Provider changes:** freeze, export, import and activation at the next Switch, recovery after a provider loss, and account erasure.
- **Push:** content-free, signed webhooks to the push relay that each app registers.

The Switch is trusted for coordination (ordering, time, availability and delivery), not for content. An operator must keep every write it acknowledged: it answers only once what it committed is durable, and it never restores a backup and serves on.

## Specification

The Switch is specified in [`spec/`](spec/):

- `spec.md` decides behaviour;
- `wire-format.md` decides bytes: encodings, signatures, records, operations, the HTTP API, push, limits, and export and import;
- `vectors/` holds the test vectors every implementation reproduces byte for byte.

## Repository layout

| Path | What it is |
|---|---|
| `crates/pubky-switch-core` | Formats, encodings, signatures and verification, shared by the other three crates. |
| `crates/pubky-switch-client` | The client side, for apps that act for an identity. |
| `crates/pubky-switch-signer` | Identity management, for the signer that holds the identity key. |
| `crates/pubky-switch` | The service: storage, the HTTP API, and operations. |

## Running

```sh
cargo run -p pubky-switch -- --config config.example.toml
docker build -t pubky-switch .
```

[`docs/configuration.md`](docs/configuration.md) describes the configuration file, the container image, the health endpoints and the metrics.

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
