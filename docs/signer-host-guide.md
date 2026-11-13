# Signer host guide

For any app that hosts `pubky-switch-signer`: what the host provides, the calls behind each management screen, what the user is shown before each call that cuts something off, and how a lost device is replaced. The rules behind it are in the Switch spec (`spec/spec.md`) and the wire format (`spec/wire-format.md`); the crate's design is in `docs/signer-design.md`.

## 1. What the host provides

A `SignerEnv` and an `IdentityKeyring`, once per identity:

| Part | What the host gives | Where it is described |
|---|---|---|
| `SecretVault` | the identity secret, in device-bound storage that isn't backed up: one keychain item of a `...ThisDeviceOnly` class on iOS, a Keystore-wrapped file excluded from backups on Android. `add` stores only into an empty vault, as one atomic step | `key.rs` "For hosts", spec 3.1 |
| `StateStore` (`store`) | the signer's records and flow, committed atomically, excluded from device and cloud backups and encrypted at rest | design note 4.6 |
| `Homeserver` | `get`, `put` and `delete` of the identity's own files through its own Pubky session: `identity.json` under `/pub`, the signer's backup under `/priv` | `homeserver.rs`, wire 3.3, 3.13 |
| `transport`, `clock` | the HTTP transport to the switches, and the clock requests are signed with | `pubky-switch-client` |
| `Protocols` | the protocols the host supports, each owning its scope names; a scope no registered protocol owns is refused in a request | `protocol.rs`, spec 3.3 |

The identity secret itself is the host's to back up, for example as a seed phrase; the signer backs up its own records, without the key, on the Homeserver. Call `run_due` at each start and on a schedule of the host's: it finishes the flow in progress, closes owed reductions, completes revocations and departures, renews certificates past half their lifetime, answers full-bundle requests and republishes `identity.json` where the Homeserver's copy differs (design note 4.5). Each run is bounded; when `RunDue::more_due()` is set, call it again soon, a minute later say.

## 2. Screens and their calls

| Screen | Calls | What it shows |
|---|---|---|
| First start | `Signer::create(env, keyring, origin)`, then `resume` | the switch chosen; the identity is set up once its first `identity.json` is accepted (`SignerStatus::Enrolling`, then `Signing`) |
| Start | `Signer::open(env, keyring)`, then `resume` | `status()` and `alerts()` |
| New device of the same identity | `Signer::restore_new(env, keyring, confirmed)` with the identity key from the user's own backup of it | section 3 |
| Apps | `apps()` | each app's standing (`Listed`, `Revoking { at_switch }`, `Removed`), its certificate's scopes, switch permissions and expiry, whether a renewal is open, the protocols that own its scopes and any scope none owns, `distrust_from`, the automatic renewals no record took up, and the alerts that name it |
| Approve an app | `review(request, auth)`, `AppReview::decline(paths)`, `approve(review)`, `approved(request)`, `claim_delivered(request)` | the App ID, the scopes, the switch permissions, each grant path with its purpose and a decline toggle, and "renews" when the request renews an app. Once `approve` or later `approved` gives an `ApprovedRequest`, deliver its claim to the auth request's relay, then approve the Pubky grant for exactly `ApprovedRequest::caps` with the Pubky SDK's `approve_auth_with_capabilities` (never `approve_auth`, never `asked_caps`), then call `claim_delivered` |
| Change an app | `renew(app_id, CertChange)` | the new scopes, permissions and expiry; that removing a scope with keys rotates the identity's keys. Adding a grant path needs a new auth request from the app |
| Revoke an app | `open_attempts(app_id)`, then `revoke(app_id, distrust_from, confirmed)` | section 3 |
| Hand the identity to another signer | `hand_over_to(to_app, confirmed)`, `abort_hand_over(confirmed)`, `take_back(confirmed)` | `SignerStatus::HandingOver { to_app }` until it takes effect; then this install deletes its key |
| Receive the identity | `Signer::receive_hand_over(env, app, vault)`, `resume_take_over` | `SignerStatus::TakingOver` until its first delivery wins |
| Restore in place | `restore(confirmed)` | after `SignerStatus::RecordsBehind` or `ManagedBy { install }` |
| Provider loss | `declare_provider_loss(origin, confirmed)`, `declare_provider_loss_confirming_records(origin, confirmed)`, `end_staged_admission()` | `SignerStatus::Recovering { origin }`; the apps rebuild their state at the new service |
| Close the account | `close_account(confirmed)`, `abort_erasure()` | `SignerStatus::Erasing`, `ErasedUnconfirmed { since_ms }`, `Erased` |
| Settings | `set_record_max_age(seconds)`, `set_connect_requests(settings)` | each makes a new version of `identity.json` |
| Alerts | `alerts()`, `clear_alert(alert)` | each alert carries the facts to show; the wording is the host's (`alert.rs`) |

## 3. What the user sees before each confirmation

`UserConfirmed::shown_and_confirmed()` is made by the host only after it has shown the consequence. The calls that take one, and what to show first, are the table in design note section 5; in short:

- `revoke`: the app, that it is cut off for good, its open and `unknown` attempts (`open_attempts`, or "unknown" when the switch can't be reached), and, after a compromise, the earlier time from which its messages are distrusted.
- `close_account`: that for the identity's apps this is a provider loss, that `identity.json` and the app records leave the Homeserver, and that each app's grant is the user's to revoke.
- `hand_over_to`, `abort_hand_over`, `take_back`: the app taking over and that this install stops and deletes its key; that the hand-over is called off; that the new signer is taken to be lost.
- `restore`, `restore_new`: whether the device the backup came from is still the user's, and that the backup's records replace this install's.
- `declare_provider_loss` and its `_confirming_records` form: the new service, and that apps rebuild there; for the second, that no other install signs.

## 4. Replacing a lost device

A device holds one or more apps, and perhaps the signer. Spec 3.1 "Several devices": with one app per device, losing the device means revoking that app; an app whose keys several devices share is one principal, so losing any of them means revoking it and approving it again on the devices that remain.

1. **Revoke each app the device held**, from the signer on another device: `open_attempts(app_id)`, show the confirmation of section 3, then `revoke(app_id, distrust_from, confirmed)`. Pass `distrust_from` when the device may have been used against the user: the time from which that app's messages are distrusted, earlier than the revocation. `apps()` shows the app `Revoking` until the switch has answered and a version removes it, then `Removed`; `run_due` completes a revocation the switch couldn't take at once.
2. **Revoke its Homeserver grants.** The signer deletes the app's record itself and raises `Alert::GrantRevocationOwed { app_id }`: the host revokes every grant naming `/pub/pubky-switch/v1/apps/<app_id>.json` through the Pubky SDK's grant manager, or asks the user to in the Homeserver's settings, then clears the alert. The signer never revokes grants itself.
3. **Approve the replacement as a new app.** A revoked App ID is never approved again (spec 12.2), so the app on the new device asks with new keys and is approved as in section 2. An app that derives its keys from a secret it backs up, as spec 3.1 "Derived keys" recommends, derives them with the next index; the index it has used is the app's to keep, not the signer's. If that secret was on the lost device, a new index doesn't help: whoever holds the secret derives every index, so the app starts from a new secret.
4. **If the lost device was the signer,** the user sets the signer up on another device with the identity key from their own backup of it, `restore_new`, which reads the signer's backup from the Homeserver, then revokes the lost device's apps from there as above. A lost signer that may be in someone else's hands holds the identity key itself: revoking apps doesn't take the key back, and this signer has no call that replaces it.

## 5. Grants

Grant revocation stays the host's, through Pubky: the signer approves no grant beyond `ApprovedRequest::caps` and revokes none. It reminds the user, with `GrantRevocationOwed`, for each removed app and when the account is erased.
