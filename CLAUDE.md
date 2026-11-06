# Repository Guidelines

## What this repo is
- The Pubky Switch: an inbox and coordination service for Pubky identities. One Switch hosts many identities, each with its own account.
- It is general Pubky infrastructure, not a Paykit component. Paykit v0.2 is its first protocol.

## The specification
- **The authority:** `specs/v0.2/` on `pubky/paykit-rs` `master`: `spec.md` decides behaviour, `wire-format.md` decides bytes, and `vectors/` holds the shared test vectors.
  - The Switch is spec Section 6 and wire Sections 6, 7, 8, 10 and 11, with push in spec 9 and wire 9.
- **The vectors are normative:** the service reproduces every service vector (`http.json`, `claims.json`, `chain.json`, `operations.json`, `export.json`) byte for byte, with the vectors' fixed keys and times.
- **The spec wins:** where code and spec disagree, the spec is right. Never diverge silently: either follow the spec, or stop and raise a spec change.
- **Spec changes come first:** a spec change goes in its own PR to `specs/v0.2/` in `pubky/paykit-rs`, before the code here that depends on it. Vectors change only through such a PR.
- **Cite the spec in code:** comments name the section they implement, for example `(wire 8.3)` or `(spec 6.5)`.

## Keep the Switch general
- **Naming:** crates, the binary, configuration, logs, metrics and docs speak of the Switch, identities, apps, inboxes, claims and records, not of Paykit or payments.
- **Paykit's rules in one place:** everything specific to Paykit lives in `crates/pubky-switch-paykit`, which the service is configured with. That covers the scope names and their permission table (wire 3.1), the fixed record policies of Paykit's collections (wire 6.1), and Paykit's message kinds. The service crate never names a Paykit scope, collection or kind.
- **Labels stay as specified:** signature labels, header names and paths fixed by the wire format (`paykit/v1/...`, `Paykit-Signature`, and so on) are kept exactly. Renaming one is a spec change.
- **Spec questions:** where the spec ties the Switch to Paykit in a way that blocks other uses, record it as a question for a later spec change, and implement the spec as written.

## The protocol core
- Shared types, encodings, signatures and verification come from `paykit-lib` on the `v0.2` branch of `pubky/paykit-rs`, as a git dependency pinned to a commit (`rev = "..."`).
- Never fork, copy or re-implement the core types here. If the core lacks something the Switch needs, add it to `paykit-lib` in its own PR.

## Project structure
- Workspace root `Cargo.toml` holds shared package settings, lints and dependency versions; members live under `crates/`.
- `crates/pubky-switch`: the service (storage, HTTP API, operations).
- `crates/pubky-switch-paykit`: the Paykit v0.2 profile.
- Schema migrations live in the repo, next to the storage code, and run in order; never edit a migration that has been merged.

## Service rules
These are the conditions of a consistent Switch (spec 6.5). Breaking one makes the service non-compliant.
- **Durable, then answered** (wire 8.3): no answer that carries a `seq`, a transition proof or a signed head leaves the service until what it committed is durable.
- **Order per account:** one account's operations are serialized.
- **The key's mark:** the newest head a service key signed is kept with the key, apart from state a backup restores; the key signs nothing behind or beside it (spec 6.5, wire 8.3).
- **No restore and continue:** a recovery that may have dropped an acknowledged item ends that generation for the account; code paths never serve on from restored state (spec 6.5, 17).
- **Trusted time:** time comes from an authenticated source behind a narrow interface; an account's stamped time never goes back; what depends on time is refused when trusted time is missing (wire 8.3, 10.1).
- **Limits:** source-based limits apply before authentication and do no signature work; per-caller limits apply only after a request verifies (spec 6.5, wire 10). Configured limits default to the wire format's.
- **Service keys:** key storage sits behind an interface ready for an HSM or KMS. Never log or serialize a secret key.
- **Logs hold no message content:** no envelopes, sealed values, record bodies or key material in logs, metrics or error messages.

## Code quality
- `cargo fmt --all`, then `cargo clippy --workspace --all-targets --all-features -- -D warnings`, then `cargo test --workspace --all-features`, then `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`. CI runs all four, plus a check on the minimum supported Rust version (1.91.1).
- **No panics on network input:** no `unwrap`, `expect`, `panic!`, unchecked indexing or unchecked arithmetic on anything a caller, a peer or storage supplies. Workspace lints deny `unwrap_used`, `expect_used` and `panic` outside tests.
- **Errors:** map every failure to the error answer wire 8.6 fixes; never leak internal detail in a response body.
- Public items carry `///` docs; `missing_docs` is denied.
- No `unsafe` code.
- Keep files ASCII. Follow Rust defaults: snake_case functions and modules, UpperCamelCase types, SCREAMING_SNAKE_CASE constants.

## Testing
- Every rule gets a test, with at least one failure-path test next to the positive one.
- Name tests `test_<feature>_<case>()`.
- Storage tests run against PostgreSQL and cover a crash before commit, durability before the answer, and per-account ordering.
- Vector replay tests load the vector files from `pubky/paykit-rs` and compare bytes.
- **Test-only code stays test-only:** fault injection, fixed randomness and deterministic signing for vectors go behind `cfg(test)` or a test-only feature that no production build enables.

## What never goes into this repo
These rules cover code, comments, docs, commit messages and PR descriptions.
- **Private reference material** shared alongside the spec stays private: port behaviour from it, never copy its files in, and never name its location.
- **Internal review identifiers and process words:** no review IDs (letter-and-number codes such as those used in review records), no "plan", "phase", "finding" or "prototype only" wording, and no reviewer names. Cite spec and wire sections instead.
- **Earlier material:** no security details of Paykit v0.1, and no references to older internal PRs.
- **Secrets:** no real service keys, identity keys or credentials; tests use fixed test keys from the vectors or keys generated at run time.

## Commits and pull requests
- Imperative, present-tense commit titles of at most 72 characters (for example `Add the account store`).
- Work on feature branches with PRs into `main`.
- Each PR describes its motivation, the spec and wire sections it implements, and any spec questions it raises; include the fmt, clippy, test and doc results, or say which were skipped.
