# Repository Guidelines

## What this repo is
- The Pubky Switch: an inbox and coordination service for Pubky identities. One Switch hosts many identities, each with its own account.
- Its specification, in `spec/`, and four crates under `crates/`:
  - `pubky-switch-core`: formats, encodings, signatures and verification, shared by the other three;
  - `pubky-switch-client`: the client side, for apps that act for an identity;
  - `pubky-switch-signer`: identity management, for the signer that holds the identity key;
  - `pubky-switch`: the service (storage, HTTP API, operations).

## The specification
- **The authority:** `spec/` in this repo. `spec.md` decides behaviour, `wire-format.md` decides bytes, and `vectors/` holds the test vectors.
- **The vectors are normative:** every crate reproduces the vectors it covers byte for byte, with the vectors' fixed keys and times. The service replays `http.json`, `claims.json`, `chain.json`, `operations.json` and `export.json`.
- **The spec wins:** where code and spec disagree, the spec is right. Never diverge silently: follow the spec, or stop and ask for a spec change.
- **Spec changes come first:** a spec change goes to `spec/` in its own PR, before the code that depends on it. Vectors change only through such a PR.
- **Cite the spec in code:** comments name the section they implement, for example `(Switch wire 7.3)` or `(Switch spec 6.5)`.

## The Switch knows no protocol
- Protocols are built on top of the Switch and depend on it, never the reverse. Scopes, message kinds and collections are opaque strings to the Switch; it applies only the generic rules its spec gives (Switch spec 1, 3.3).
- **No Paykit anywhere in this repo:** no Paykit names, types, scopes, kinds or collections in code, tests, configuration, logs or metrics, and no dependency on a Paykit crate. The spec's examples and vectors use Paykit's values as sample data; code treats them as opaque strings and never gives them meaning. Where a test needs a scope or a collection of its own, use a neutral name. Outside `spec/`, the only mention of Paykit is the README's note that it is a protocol built on the Switch.
- **Labels stay as specified:** signature labels, header names and paths fixed by the wire format (`pubky-switch/v1/...`, the `Switch-*` headers, `/v1/...`) are kept exactly. Renaming one is a spec change.

## The core types
- Formats, signatures and verification come from `pubky-switch-core` in this workspace. The service, the client and the signer use it and never re-implement or copy its types.
- If the core lacks something another crate needs, add it to `pubky-switch-core`.

## Project structure
- Workspace root `Cargo.toml` holds shared package settings, lints and dependency versions; members live under `crates/`.
- Schema migrations live in the repo, next to the storage code, and run in order; never edit a migration that has been merged.

## Service rules
These are the conditions of a consistent Switch (Switch spec 6.5). Breaking one makes the service non-compliant.
- **Durable, then answered** (Switch wire 7.3): no answer that carries a `seq`, a transition proof or a signed head leaves the service until what it committed is durable.
- **Order per account:** one account's operations are serialized.
- **The key's mark:** the newest head a service key signed is kept with the key, apart from state a backup restores; the key signs nothing behind or beside it (Switch spec 6.5, Switch wire 7.3).
- **No restore and continue:** a recovery that may have dropped an acknowledged item ends that generation for the account; code paths never serve on from restored state (Switch spec 6.5).
- **Trusted time:** time comes from an authenticated source behind a narrow interface; an account's stamped time never goes back; what depends on time is refused when trusted time is missing (Switch spec 10.1, Switch wire 7.3).
- **Limits:** source-based limits apply before authentication and do no signature work; per-caller limits apply only after a request verifies (Switch spec 6.5, Switch wire 9). Configured limits default to the spec's.
- **Service keys:** key storage sits behind an interface ready for an HSM or KMS. Never log or serialize a secret key.
- **Logs hold no message content:** no envelopes, sealed values, record bodies or key material in logs, metrics or error messages.

## Code quality
- `cargo fmt --all`, then `cargo clippy --workspace --all-targets --all-features -- -D warnings`, then `cargo test --workspace --all-features`, then `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`. CI runs all four, plus a check on the minimum supported Rust version (1.91.1).
- **No panics on network input:** no `unwrap`, `expect`, `panic!`, unchecked indexing or unchecked arithmetic on anything a caller, a peer or storage supplies. Workspace lints deny `unwrap_used`, `expect_used` and `panic` outside tests.
- **Errors:** map every failure to the error answer the wire format fixes (Switch wire 7.6); never leak internal detail in a response body.
- Public items carry `///` docs; `missing_docs` is denied.
- No `unsafe` code.
- Keep files ASCII. Follow Rust defaults: snake_case functions and modules, UpperCamelCase types, SCREAMING_SNAKE_CASE constants.

## Testing
- Every rule gets a test, with at least one failure-path test next to the positive one.
- Name tests `test_<feature>_<case>()`.
- Storage tests run against PostgreSQL and cover a crash before commit, durability before the answer, and per-account ordering.
- Vector tests load the files in `spec/vectors/` and compare bytes.
- **Test-only code stays test-only:** fault injection, fixed randomness and deterministic signing for vectors go behind `cfg(test)` or a test-only feature that no production build enables.

## What never goes into this repo
These rules cover code, comments, docs, commit messages and PR descriptions.
- **Private reference material** shared alongside the spec stays private: port behaviour from it, never copy its files in, and never name its location.
- **Internal review and work identifiers, and process words:** no such IDs (letter-and-number codes such as those used in review records), no "plan", "phase", "finding" or "prototype only" wording, and no reviewer names. Cite spec sections instead.
- **Earlier material:** no security details of earlier protocol versions, and no references to older internal PRs.
- **Secrets:** no real service keys, identity keys or credentials; tests use fixed test keys from the vectors or keys generated at run time.

## Commits and pull requests
- Imperative, present-tense commit titles of at most 72 characters (for example `Add the account store`).
- Work on feature branches with PRs into `main`.
- Each PR describes its motivation, the spec sections it implements, and any spec questions it raises; include the fmt, clippy, test and doc results, or say which were skipped.
