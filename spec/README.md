# Pubky Switch

Status: review candidate, not frozen.

The Pubky Switch is an inbox and coordination service for Pubky identities. Each identity uses one switch at a time, which its signed `identity.json` names. Other identities' apps write sealed, signed messages to its inbox. The identity's own apps read them from one ordered feed and coordinate through two generic primitives, claims and shared records. The switch reads no message and no shared data.

A protocol uses the Switch through its scopes, the switch permissions they need, its message kinds and its collections; the spec's Section 1 says how. Paykit, payments between Pubky identities, is the first protocol on the Switch: [Paykit v0.2](https://github.com/pubky/paykit-rs/tree/master/specs/v0.2) ([spec](https://github.com/pubky/paykit-rs/blob/master/specs/v0.2/spec.md), [wire format](https://github.com/pubky/paykit-rs/blob/master/specs/v0.2/wire-format.md)).

The design is still open to review. It may change before it is frozen. The spec's Section 19 lists the open questions and the decisions that are the switch's.

## Files

| File | What it is for |
| --- | --- |
| [`spec.md`](spec.md) | The specification. It decides behaviour: identities, apps and their keys, certificates and scopes, messages, the service and its API, admission, claims and shared records, push, delivery, the lifecycle of apps and identities (revocation, restore, moves, erasure, the hand-over to another signer and its backup), threat model and guarantees. Start here. |
| [`wire-format.md`](wire-format.md) | The wire format. It decides bytes: encodings, signatures, documents, envelopes, operations, the chain, the HTTP API, push, limits, and export and import, so that a second team can build a compatible switch, signer or app. |
| [`vectors/`](vectors/) | Test vectors for the wire format, as JSON files. Its `README.md` lists the files and how they were made. Paykit's vectors build on them. |

## Shared separately

The reference prototype, which implements this spec and Paykit's, its results and an independent implementation aren't in this folder. They are shared separately. The documents name them but give no paths.
