# Signer host guide

For the developers of a host app, for example a wallet app acting as signer, that embeds the `pubky-switch-signer` crate. It lists every case the signer can put in front of the host, how the host learns of it, what the user must see and do, and then every screen the host needs, as a checklist. The rules behind it are in the Switch spec (`spec/spec.md`) and wire format (`spec/wire-format.md`); the crate's design is in `docs/signer-design.md`.

## 1. What the signer does, and what the host supplies

The signer holds the identity key on behalf of the user. It enrolls the identity at a switch, approves apps and signs their certificates, keeps `identity.json` signed, delivered and published, renews, reduces and revokes apps, recovers from a lost provider, erases the account, and hands the identity to another signer. It signs only what it builds itself, and it commits every step to the host's store before it sends it, so a crash never makes it sign twice.

The host supplies, once per identity:

- **A key vault,** a `SecretVault`: the 32-byte identity secret in device-bound secure storage that isn't backed up, for example a platform keychain item of a this-device-only class, or a file wrapped by a hardware-backed key store and excluded from backups. `add` stores only into an empty vault, as one atomic step for every caller. The host opens it with `IdentityKeyring::create` (a new identity) or `IdentityKeyring::open`.
- **A `SignerEnv`:** a durable, atomic, device-bound `store`; the `clock` requests are signed with; the `transport` to the switches; the identity's `homeserver`; and the `protocols` it supports.
- **A Homeserver session,** behind the `Homeserver` trait (`get`, `put`, `delete`), whose capabilities cover, for read and write, `/pub/pubky-switch/v1/` and `/priv/pubky-switch/v1/signer-backup.json`. A root session does. Request deadlines are the host's.
- **The protocols,** a `Protocols` set built with `Protocols::new` from every `Protocol` the host supports, each owning its scope names (for example the sample protocol `tasks` owning `tasks` and `tasks_sync`). A scope no registered protocol owns is refused in requests.
- **A schedule:** call `Signer::resume` after every `Signer::create` or `Signer::open`, and `Signer::run_due` at each start and on a schedule of the host's. A run is bounded in work and time, so it can be called often. When `RunDue::more_due()` is true, call `run_due` again soon, a minute later say, not at once.

The identity secret itself is the host's to back up for the user, for example as a seed phrase. The signer backs up its own records, without the key, on the Homeserver. Each alert carries the facts to show; the wording is the host's. `UserConfirmed::shown_and_confirmed()` is made by the host only after the user has seen the consequence of the call and confirmed it.

Types the signer takes or returns that come from the other crates of this repository: `IdentityDoc`, `AppCert`, `SignedDoc` and `ConnectRequests` from `pubky-switch-core`, and `AuthRequest`, `AppKeys`, the store, the clock and the transport from `pubky-switch-client`.

## 2. The cases

Every error a call returns is a `SignerError`; a refusal a rule made is `SignerError::Refused` carrying a `Refusal`. "Alerts" are what `Signer::alerts()` returns until `Signer::clear_alert` removes them; "status" is `Signer::status()`. Read both after every call, whether it succeeded or failed.

### 2.1 First set-up and enrollment

| The case | How the host learns of it | What the UI must show | What to do | What not to do |
|---|---|---|---|---|
| A new identity is set up | `IdentityKeyring::create(vault)` returns a keyring; `Signer::create(env, keyring, origin)` returns the signer; `Signer::status()` is `SignerStatus::Enrolling` | the chosen switch, "setting up" | call `Signer::resume`; on success the status is `SignerStatus::Signing` | do not show the identity as ready while `SignerStatus::Enrolling` |
| The enrollment couldn't be sent yet | `Signer::resume` returns `SignerError::Switch` or `SignerError::Homeserver`; status stays `SignerStatus::Enrolling` | "not reached yet, will retry" | call `resume` again later, or let `run_due` do it | do not call `Signer::create` again: the flow is kept and resent unchanged |
| The store already holds this identity | `Signer::create`, `Signer::restore_new` or `Signer::receive_hand_over` returns `Refusal::AlreadySetUp` | nothing new; open the existing signer | call `Signer::open` | do not delete the store's records to start over |
| The store holds no signer for this identity | `Signer::open` returns `Refusal::NotSetUp`; other calls before the first version return it too | the set-up or restore choice | offer `Signer::create` (new) or `Signer::restore_new` (from the backup) | do not create a new identity over a vault that already holds one |
| A switch origin that isn't valid | `Signer::create` returns `SignerError::InvalidData` | "not a valid switch address" | ask for another origin | do not retry the same origin |
| The Homeserver holds a signer backup this install can't open, before its first delivery | `Signer::resume` returns `Refusal::UnreadableBackup`, with `Alert::UnreadableBackupBeforeEnrollment` | that another install may already sign for this identity, or the backup is damaged; nothing is delivered | the user restores on the install that wrote it, or, sure that no other install signs, removes the backup from the Homeserver; then call `resume` | do not delete the backup on the user's behalf; do not clear the alert as a fix |

### 2.2 The key vault

| The case | How the host learns of it | What the UI must show | What to do | What not to do |
|---|---|---|---|---|
| `add` stored the secret | the host's `SecretVault::add` returns `AddOutcome::Stored` | nothing | `load` must return it from then on, also after a crash | do not return `Stored` before the write is durable |
| `add` found a secret already there | the host's `add` returns `AddOutcome::Occupied`; the signer then returns `KeyError::Occupied` | "this device already holds an identity" | keep the held secret; open it with `IdentityKeyring::open` | do not overwrite, update, or delete-then-add the held secret |
| The vault can't be read or written, for example while the device is locked | `SignerError::Key` carrying `KeyError::Vault` | "unlock the device to go on" | retry once the device is unlocked | do not treat it as a missing key; do not offer a new identity |
| The vault holds no secret | `IdentityKeyring::open` returns `KeyError::Missing` | the set-up or restore choice, unless this install received a hand-over | when this install received a hand-over (`Signer::receive_hand_over` was called for the identity and didn't end in a refusal), call `Signer::resume_take_over(env, identity, keys, vault)` with the identity's public key and the `ReceivingApp::keys` it was given: the vault stays empty until the take-over wins; otherwise offer to create, or to restore with the key from the user's backup | do not create a new identity silently; do not offer the set-up choice over a take-over in progress |
| A hand-over from this install took effect | `Signer::open` (or any later call) returns `SignerError::HandedOver` with `install`, once it deleted the key and the records left; at the next start the vault holds no secret | that the identity is now with another install, and this one deleted its key | close the signer for this identity | do not offer a restore with the deleted key; do not treat it as a fault |
| The secret isn't this identity's | `KeyError::Mismatch` | "the key on this device isn't this identity's" | stop; ask the user which identity and key to use | do not sign with it or replace it automatically |
| The vault returned bytes that aren't 32 long | `IdentitySecret::from_slice` returns `KeyError::Malformed` | a fault of the vault | fix the vault code | do not pad or truncate the bytes |
| The secure random generator failed | `KeyError::Crypto` | a device fault | retry later | do not fall back to another random source |
| The secret leaves the vault | only for `ExportReason::HandOver`, inside `Signer::hand_over_to`; the host never receives it | the hand-over confirmation (2.12) | nothing beyond the hand-over | do not export the secret any other way; the signer's backup holds none |

### 2.3 Protocols

| The case | How the host learns of it | What the UI must show | What to do | What not to do |
|---|---|---|---|---|
| No protocol registered | `Protocols::new` returns `ProtocolError::NoProtocols` | nothing to the user: a fault of the host's set-up | register at least one protocol | do not ship a build that fails here |
| A protocol name that isn't 1 to 32 of `a-z` and `0-9` starting with a letter | `ProtocolError::BadName` | as above | fix the protocol's name | do not rename it per device: every install must judge the same way |
| A protocol declares a scope outside its own root | `ProtocolError::ForeignRoot` | as above | declare only its name, or its name followed by `_` or `-` and more | do not claim another protocol's root |
| Two protocols under one name | `ProtocolError::DuplicateProtocol` | as above | register each once | do not register one protocol from two code paths |
| A protocol that owns no scope | `ProtocolError::NoScopes` | as above | give it at least one scope | do not register a protocol only for its name |
| A scope name that isn't a plain scope name | `ProtocolError::BadScopeName` | as above | declare roots without sub-scopes | do not declare `name:<sub>` forms |
| One scope declared twice | `ProtocolError::ScopeClaimedTwice` | as above | give each scope to one protocol | do not let two protocols share a scope |
| A protocol adds a grant path the Switch's rules don't allow | `ProtocolError::BadGrantPath`, at `Signer::review` or later inside `SignerError::Protocol` | as above | fix the protocol's `grant_paths` | do not add paths inside the Switch's own folders |
| A protocol answered with something malformed during a call | `SignerError::Protocol` | "this app version can't handle the request" | fix the protocol | do not retry the call unchanged |

### 2.4 The Homeserver and the store

| The case | How the host learns of it | What the UI must show | What to do | What not to do |
|---|---|---|---|---|
| The Homeserver can't be read or written | `SignerError::Homeserver` | "can't reach your storage, will retry" | retry with `resume` or `run_due`; check the session's capabilities cover the backup path | do not drop the backup capability: without it every delivery stops |
| The host's store failed | `SignerError::Store` | a device storage fault | retry; the signer reads its records again after an unsure commit | do not edit the signer's namespace by hand |
| The signer's records don't read | `SignerError::Records` | "this install's records are damaged" | offer a restore from the backup on an empty store (`Signer::restore_new`) | do not delete the records silently |
| Data from the network that doesn't verify | `SignerError::InvalidData` | "the service sent data that doesn't check out" | retry later; if it persists, consider a provider loss (2.9) | do not show the data as trusted |
| The switch can't be reached or answered an error | `SignerError::Switch` | "can't reach the service, will retry" | `resume` and `run_due` resend the same bytes | do not build a new request in its place |

### 2.5 Adding an app (approval)

| The case | How the host learns of it | What the UI must show | What to do | What not to do |
|---|---|---|---|---|
| An app asks to be approved | the host receives an app request and its auth request; `Signer::review(request, auth)` returns an `AppReview` | the App ID, its scopes, its switch permissions, the keyed scopes, each grant path with its purpose and a decline toggle, and "renews" when `AppReview::renews` is true | let the user decline paths with `AppReview::decline`; keep a clone of the `AppReview`, then call `Signer::approve` with it; keep the clone until the claim is delivered | do not grant `AppReview::asked_caps`: show it, never grant it |
| The scopes break the Switch's scope rule | `Refusal::Scopes` | the rule that failed, as its reason names it | turn the request down | do not approve a trimmed set the app didn't ask for |
| Scopes no registered protocol owns | `Refusal::UnknownScopes` | which scopes, and that this app version lacks support for them | turn the request down, or update the host app | do not register a placeholder protocol for them |
| A protocol's own rule refused the scopes or the paths left | `Refusal::ProtocolRule` | the protocol's name and reason | change the declines, or turn the request down | do not hide the protocol's reason |
| A decline of a path that can't be declined | `AppReview::decline` returns `Refusal::NotDeclinable` | that path stays granted | offer only `AppReview::grant_paths` as toggles; the set stays as it was | do not offer the app's record or backup paths as toggles |
| The request fails a check | `Refusal::AppRequest`, its reason naming the step | "this request isn't valid" | turn it down | do not retry the same request |
| The App ID was revoked or is being revoked | `Refusal::AppRequest` at `Signer::review`; `Refusal::CutOff` at a renewal | "this app was removed for good" | the app asks again with new keys, as a new app | do not approve the old App ID again |
| The device clock is off the switch's time | `Signer::approve` or `Signer::renew` returns `Refusal::ClockOff` with `device_ms` and `switch_ms` | both times, and "set the device clock" | approve again once the clock is right | do not approve with the clock off |
| The approval is delivered and its claim released | `Signer::approve` returns an `ApprovedRequest`, or later `Signer::approved(&hash)` returns one, `hash` being the kept clone's `AppReview::request_hash()` | "approved" | deliver `ApprovedRequest::claim` to the auth request's relay, approve the Homeserver grant for exactly `ApprovedRequest::caps` with `approve_auth_with_capabilities`, then call `Signer::claim_delivered(&approved.request)` with its `ApprovedRequest::request`, the same 32 bytes | do not call `approve_auth` or grant the auth request's own capabilities |
| The approval's version is delivered but the claim is held | `Signer::approve` returns `Refusal::ClaimHeld`, naming the alarm's alert when still held | "approved, waiting for the service to be confirmed" | clear the alarm (2.15), then poll `Signer::approved(&kept.request_hash())` | do not send any claim or grant until `approved` returns one |
| The delivery didn't finish, or `approve` failed before it committed | `approve` returns a switch or Homeserver error; `approve` reads the switch before it commits, so an error there leaves no claim | "approval pending" | call `resume`; then `Signer::approved(&kept.request_hash())`; if it returns `None` after a `resume` that succeeded, call `approve` again with the kept clone, which keeps the user's declines | do not ask the user for a new approval of the same request, and do not call `Signer::review` again for it: a fresh `AppReview` declines nothing |
| A request that renews an app that hasn't joined | `approve` returns `Refusal::NotJoined` | "the app hasn't connected to the service yet" | the app joins first, then asks again | do not retry automatically |
| The newest version would be too large | `Refusal::IdentityTooLarge` with `SizedBody::Delivery` or `SizedBody::Enrollment` | the size and the cap | remove or purge apps (2.7, 2.10) first | do not retry unchanged |

### 2.6 Renewal and reductions

| The case | How the host learns of it | What the UI must show | What to do | What not to do |
|---|---|---|---|---|
| The user changes an app's scopes or expiry | `Signer::renew(app_id, CertChange)` returns the renewing version | the new scopes, permissions and expiry; that removing a scope with keys rotates the identity's keys | confirm the change with the user first | do not add a grant path here: that needs a new request from the app |
| The app isn't listed | `Refusal::NotListed` | "this app isn't connected" | refresh the app list | do not retry with the same App ID |
| The app hasn't joined | `Refusal::NotJoined` | "the app hasn't connected to the service yet" | wait for the app | do not retry in a loop |
| The App ID is revoked or departing | `Refusal::CutOff` | "this app was removed" | nothing | do not offer renew for an `AppStanding::Revoking` or `AppStanding::Removed` app |
| Another install's newer version was adopted meanwhile | `Refusal::Superseded` with the adopted version | "the identity changed elsewhere; try again" | show the refreshed app, let the user ask again | do not repeat the change automatically |
| The switch refused the renewal for good | the call's error, with `Alert::RenewalRefused` (`reduction`, `by_user`) | that the app keeps its listed certificate; for a reduction, that the access was NOT reduced | offer renew, reduce again, or revoke | do not show the reduction as done |
| A reduction's closing can't be delivered now | `Alert::ReductionNotClosed` naming the apps | that their earlier certificates aren't cut off yet | clear an alarm if one is held; otherwise any change the user makes closes it; revoking cuts off at once | do not hide it: `clear_alert` keeps it until the closing is made |
| A certificate past half its lifetime isn't renewed by itself | `Alert::RenewalSkipped` with `RenewalSkip::UnownedScopes`, `RenewalSkip::PermissionsChanged` or `RenewalSkip::ScopesRefused` | which reason: scopes no protocol owns (for example `tasks` no longer registered), the permissions held and those it would get now, or the protocol and rule that refuse the scopes | the user renews it with the change shown, or removes it | do not renew it silently with other permissions |
| Two automatic renewals in a row no record took up | `Alert::RenewalsStopped` with `expires_at` | that the app lapses at that time unless renewed | offer renew or revoke | do not keep renewing it from the host |
| Such an app still owns open attempts | `Alert::LapsingWithOpenAttempts` with the count | the count and the expiry | offer renew, which keeps them its own | do not resolve the attempts for the user |
| The device clock is off the switch's time | `Alert::ClockOff`; `Refusal::ClockOff` on a user renewal | "set the device clock" | fix the clock; the alert clears itself at the next run | do not clear it and carry on |
| A rotation left an app without its new keys | `Alert::RotationSkipped` with the unowned scopes | which protocol support is missing | update the host app, or reduce the app to owned scopes | do not tell the user the app is up to date |
| A full-bundle request was refused by the switch | `Alert::FullBundleRefused` | the app may lack keys | the app asks again | do not resend from the host |

### 2.7 Revocation

| The case | How the host learns of it | What the UI must show | What to do | What not to do |
|---|---|---|---|---|
| The user revokes an app | `Signer::open_attempts(app_id)` gives the count; `Signer::revoke(app_id, distrust_from, confirmed)` returns the version that removes it | the app; that it is cut off for good; the count of its open and `unknown` attempts (or "unknown" when the switch can't be reached); after a compromise, the earlier time from which its messages are distrusted | confirm, then revoke; once the revocation is kept, revoke its Homeserver grants at once (the row "The app is removed"): when `revoke` returned `Ok`, `Refusal::Recovering`, `SignerError::Alarm`, `Refusal::SwitchUnconfirmed`, or a switch or Homeserver error, and after any other error when `Signer::apps()` shows the app `AppStanding::Revoking` or `AppStanding::Removed` | do not let a failed `open_attempts` block the revocation; do not revoke the grants after a refusal that commits nothing (`Refusal::NotListed`, `Refusal::HandingOver`, `Refusal::TakingOver`, `Refusal::FlowInProgress`, `Refusal::NotSetUp`, `SignerError::NotNamed`, `Refusal::RecordsBehind`, `Refusal::Erased`): the app stays listed |
| The revocation is asked but no version removes the app yet | `Alert::RevocationPending` (`at_switch`); `Signer::apps()` shows `AppStanding::Revoking` | "being removed"; with `at_switch` true, "no longer served" | let `run_due` finish it | do not offer approve, renew or hand-over to it |
| The switch took the revocation but gave no time | `Alert::RevocationUnconfirmed` | "cut off at the service, not confirmed" | each run retries; if it keeps happening, consider another provider | do not show the app as removed yet |
| The revoked app owns open attempts | `Alert::RevokedWithOpenAttempts` with the count | the count, left for other apps or the user | nothing; it clears itself once it owns none | do not resolve the attempts for the user |
| The app is removed | `apps()` shows `AppStanding::Removed`; `Alert::GrantRevocationOwed` | "revoke its storage access" | revoke every Homeserver grant naming `/pub/pubky-switch/v1/apps/<app_id>.json`, then clear the alert | do not clear it before the grants are revoked; the signer revokes no grant itself |
| The app isn't listed | `Refusal::NotListed` | "this app isn't connected" | refresh | do not offer revoke for it again |
| A hand-over, take-over, erasure or recovery is in progress | `Refusal::HandingOver`, `Refusal::TakingOver`, `Refusal::FlowInProgress` (erasure), `Refusal::Recovering` (kept, with `Alert::RevocationPending`) | why it waits; during a recovery, that the revocation is kept for the new service | for a hand-over, abort it first, then revoke; during a recovery, revoke the grants at once | do not show it as done; do not revoke the grants on `Refusal::HandingOver`, `Refusal::TakingOver` or `Refusal::FlowInProgress`, which keep nothing |
| A removed app's entry is no longer needed | `Signer::purge_removed(app_id)` returns a version | nothing | purge once no more messages carrying its certificate are expected | do not purge an app not in `removed`: `Refusal::NotRemoved` |
| A device holding apps is lost | the user says so | the apps it held | revoke each from the signer, with `distrust_from` if it may be misused; revoke its grants at once once the revocation is kept (the first row); approve the replacement as a new app | do not re-approve a revoked App ID |

### 2.8 An app leaving, and removals at the switch

| The case | How the host learns of it | What the UI must show | What to do | What not to do |
|---|---|---|---|---|
| The switch shows an app revoked or departed that this signer didn't ask for | `Alert::RemovedAtSwitch` (`left` true when it left by itself) | the app, and that it is gone for good | the user checks it was meant to go; `run_due` removes it in the next version | do not re-approve that App ID |
| An app that left is still listed | `apps()` shows `AppStanding::Listed` with the alert above | "leaving" | let `run_due` complete the removal | do not offer renew for it |
| The switch reported a removal time before a version that lists the app | `Alert::RemovalTimeBounded` (`reported`, `distrust_from`) | that the service's time was bounded; the service may be faulty | nothing, or declare a provider loss if it repeats | do not hide it |

### 2.9 Provider loss and recovery

| The case | How the host learns of it | What the UI must show | What to do | What not to do |
|---|---|---|---|---|
| The user declares the provider lost | `Signer::declare_provider_loss(origin, confirmed)` returns the new generation's version | the new service, and that apps rebuild their state there | confirm, then declare; it is allowed while an alarm is held, on an erased account, and during an erasure, which it ends | do not declare on a passing outage |
| The recovery's version isn't taken yet | `SignerStatus::Recovering` with `origin`; other calls return `Refusal::Recovering` | "moving to the new service" | `resume`; declaring again replaces it; revoke stays offered, kept for the new service with `Alert::RevocationPending` | do not offer other changes meanwhile |
| The new service refused it for good | `SignerStatus::RecoveryRefused` with `origin` | that this service refused | the user declares again, at that service or another | do not resend to it |
| The Homeserver's `identity.json` is missing or doesn't verify | `Refusal::HomeserverCopyMissing` or `Refusal::HomeserverCopyUnreadable` | that the user must confirm no other install signs | `Signer::declare_provider_loss_confirming_records(origin, confirmed)` | do not call it without that confirmation |
| An owed end of the staged admission failed | `Alert::AdmissionNotEnded` | that new contacts are still held at the new service | nothing: it stays owed and `run_due` sends it again; the alert goes once the switch shows the wait ended | do not call `Signer::end_staged_admission` for it |
| The end of the staged admission is left to the user | no alert or status names it: once the recovery's version is delivered (the status is no longer `SignerStatus::Recovering`), `Signer::apps()` lists an app whose `cert` grants the switch permission `lists.manage`, or whose `cert` is `None`, so the signer can't tell whether that app ends the wait | that new contacts may be held at the new service until that app, or the user, ends the wait | `Signer::end_staged_admission()` on the user's word, for example once the app that manages lists is gone for good; a call when no wait is staged sends nothing | do not call it while `Refusal::Recovering` or `Refusal::FlowInProgress` |
| Another flow is in progress | `Refusal::FlowInProgress` | "finishing a step first" | `resume`, then try again | do not start another step meanwhile |
| The service doesn't host the account | `Alert::AccountNotHosted` | that the account may have been erased elsewhere | a restore or an enrollment elsewhere; it clears itself at a signed answer | do not delete anything because of it |

### 2.10 Moving to another provider

| The case | How the host learns of it | What the UI must show | What to do | What not to do |
|---|---|---|---|---|
| The user wants another provider | no move call exists in this signer | the provider-loss path (2.9) | declare a provider loss at the new service | do not offer a cooperative move |
| The version is near the size an enrollment at another service may carry | `Alert::IdentityNearLimit` (`bytes`, `limit`) | the size and cap | remove or purge apps; renewals' entries grow it | do not ignore it: past the cap nothing can be delivered |
| A change would not fit | `Refusal::IdentityTooLarge` with `SizedBody::Enrollment` | the size and cap | as above | do not retry unchanged |

### 2.11 Erasure

| The case | How the host learns of it | What the UI must show | What to do | What not to do |
|---|---|---|---|---|
| The user closes the account | `Signer::close_account(confirmed)` | that for the apps this is a provider loss and lookups fail closed; that `identity.json` and the app records leave the Homeserver; that each app's grant is the user's to revoke | confirm, then call; the erasure raises `Alert::GrantRevocationOwed` for each app still listed: revoke those grants once the status is `SignerStatus::Erased`, not before | do not erase without the confirmation; do not revoke a listed app's grants while the erasure can still be aborted or refused |
| The erasure is in progress | `SignerStatus::Erasing` | "closing the account" | `resume`; `Signer::abort_erasure()` ends it on the user's word; a provider loss declared meanwhile (2.9) ends it too | do not offer revocations meanwhile |
| A request may have landed | `abort_erasure` returns `Refusal::ErasureUnanswered` | "may already be erased; checking" | `resume` | do not abort again in a loop |
| The account looks erased, unconfirmed | `SignerStatus::ErasedUnconfirmed` with `since_ms`, by the device clock; `Refusal::ErasureUnconfirmed` | "looks closed, not confirmed yet", with no definite time | keep calling `run_due`: the first run at least 24 hours after `since_ms` that still meets the switch's unsigned `404` confirms it; an answer the pinned service key signs meanwhile ends the wait, and the status goes back to `SignerStatus::Erasing` | do not show it erased yet; do not show a time at which it will be |
| The switch refused the erasure, or the user aborted it | `Refusal::ErasureRefused`, or `abort_erasure` returning | "not erased"; `identity.json` is published again | tell the user; the signer withdraws the `Alert::GrantRevocationOwed` it raised for apps still listed | do not retry automatically; do not revoke those apps' grants |
| No erasure to abort | `Refusal::NotErasing` | nothing | refresh the status | do not show an error to the user |
| The account is erased | `SignerStatus::Erased`; calls return `Refusal::Erased` | "account closed"; that a provider loss can bring the identity to a service again | show the app list read-only; revoke the grants each `Alert::GrantRevocationOwed` names; offer `Signer::declare_provider_loss` (2.9), which is allowed on an erased account | do not offer restore or revoke |

### 2.12 Hand-over to another signer install, and take-over

| The case | How the host learns of it | What the UI must show | What to do | What not to do |
|---|---|---|---|---|
| The user hands the identity over | `Signer::hand_over_to(to_app, confirmed)`; status `SignerStatus::HandingOver` | the app taking over; that this install then stops and deletes its key; for a key derived from a wallet seed, that deletion can't make it unrecoverable | confirm, then call; tell the user to open the new app | do not offer other changes: they return `Refusal::HandingOver` |
| A reduction's closing is owed | `Refusal::ClosingOwed` | "finish the pending change first" | let `run_due` close it | do not offer the hand-over until it is closed |
| A revocation isn't delivered yet | `Refusal::RevocationOwed` | "finish removing the app first" | let `run_due` finish it | do not offer the hand-over until it is done |
| The target isn't current at the switch | `Refusal::TargetNotCurrent`; `Refusal::NotListed` for an app not listed | "that app can't take over now" | pick a current app | do not offer a revoked, expired or unlisted app |
| The switch refused to store the hand-over | `Alert::HandOverRefused` with `to_app` | the hand-over stays in progress | abort it unless that app takes over | do not show the hand-over as ended |
| The user calls it off | `Signer::abort_hand_over(confirmed)` returns `AbortOutcome::Aborted` with the version | "this device signs again" | nothing more | do not show the hand-over as in progress |
| The abort is sent but hasn't won yet | `abort_hand_over` returns `Refusal::HandingOver` | "calling off the hand-over" | `resume` or `run_due` sends it again; calling `abort_hand_over` again resends the same abort; it ends as `AbortOutcome::Aborted` or `AbortOutcome::SucceededBy` | do not show this device as signing again yet |
| The hand-over took effect first | `AbortOutcome::SucceededBy`, or `SignerError::HandedOver`, from any call | that the identity is now with another install, and this one deleted its key | close the signer for this identity | do not offer a restore with the deleted key |
| No hand-over to abort | `Refusal::NotHandingOver` | nothing | refresh | do not show an error to the user |
| Another install's version without its proof yet | `Refusal::SuccessorUnproven` with `install`, from `abort_hand_over`, `resume` or `run_due`, and `Alert::ManagedByOtherInstall` | "waiting for the new signer" | wait; if the new signer is lost, offer take-back | do not delete the key from the host |
| The new signer is lost | `Signer::take_back(confirmed)` returns a version, with `Alert::TakenBack` | that the new signer is taken to be lost; if it still runs it holds the key too | confirm, then call | do not offer it before `Refusal::SuccessorUnproven` shows; on `Refusal::NothingToTakeBack` hide it |
| The new app takes over | `Signer::receive_hand_over(env, app, vault)` on the new install; status `SignerStatus::TakingOver` | "taking over" | `resume`; after a restart, `Signer::resume_take_over(env, identity, keys, vault)` with the identity's public key and the same `ReceivingApp::keys`, since the vault stays empty until the take-over wins (2.2) | do not call it with a vault holding another identity: `KeyError::Occupied` |
| The hand-over isn't the switch's version | `Refusal::StaleHandOver` | "this hand-over is out of date" | nothing is kept; ask the old signer | do not retry the same hand-over |
| The take-over lost to an abort | `Refusal::TakeOverCancelled` | "the hand-over was called off" | nothing is kept | do not retry it |
| The switch refused the take-over's first delivery | `Alert::TakeOverRefused` | "taking over keeps failing" | the old signer aborts | do not delete what was received |
| The vault didn't take the received key | `Alert::KeyNotInstalled` | "finishing" | `resume` puts the key in again | do not clear the vault |
| No take-over in the store | `Refusal::NotTakingOver` | nothing | `Signer::open` | do not call `receive_hand_over` again on a set-up store |

### 2.13 Backup and restore

| The case | How the host learns of it | What the UI must show | What to do | What not to do |
|---|---|---|---|---|
| A new device of the same identity | `Signer::restore_new(env, keyring, confirmed)` with the key from the user's backup | whether the device the backup came from is still the user's; that the backup's records replace this install's | confirm, then call | do not use it while the old device still signs unless the user wants this one to take over |
| Records behind a newer own version | `SignerStatus::RecordsBehind`; `Alert::RecordsBehind` (`source`, `version`); `Refusal::RecordsBehind` | that this install's records are behind | `Signer::restore(confirmed)` | do not clear the alert as a fix: it stays until the restore |
| Another install signs | `SignerStatus::ManagedBy`; `Alert::ManagedByOtherInstall`; `SignerError::NotNamed` | which install signs; offer to take over here | `restore(confirmed)` on the user's word | do not sign from this install meanwhile |
| No backup | `Refusal::NoBackup` | "no backup found" | the old device, if still the user's, makes a change so it writes one; else set up anew | do not create a new identity over the same key |
| Unreadable backup | `Refusal::UnreadableBackup` | "backup can't be opened" | restore on the install that wrote it, or check the key is this identity's | do not delete the backup |
| Stale backup | `Refusal::StaleBackup` | "backup is out of date" | retry later, once the newer version's backup is written | do not force a restore |
| The backup after the restore couldn't be written | `Alert::BackupNotWritten` | that the next change writes it | nothing | do not repeat the restore |
| A restore bounded a claimed epoch | `Alert::EpochFloorBounded` (`claimed`, `kept`) | a service or backup fault | nothing | do not repeat the restore |
| The backup didn't open or was missing, and was rewritten | `Alert::BackupUnreadable`, `Alert::BackupMissing` | the backup was rewritten | nothing | do not treat it as another install signing |
| The signer device itself is lost | the user says so | that revoking apps doesn't take the identity key back from whoever holds the lost device | `restore_new` on another device with the key from the user's backup; then revoke the lost device's apps | do not promise the key is safe |

### 2.14 Periodic work

| The case | How the host learns of it | What the UI must show | What to do | What not to do |
|---|---|---|---|---|
| A run left work | `Signer::run_due` returns a `RunDue` whose `more_due()` is true | nothing | run again soon, a minute later say | do not call it in a tight loop |
| A run met an error | `run_due` returns the first error after the other steps ran | the error's case above | carry on; the failed step goes last next time | do not stop scheduling runs |
| A settings change | `Signer::set_record_max_age`, `Signer::set_connect_requests` return the version | the new setting | on `Refusal::FlowInProgress`, call `resume` first, then again | do not change settings during a hand-over, recovery or erasure |

### 2.15 Alarms

| The case | How the host learns of it | What the UI must show | What to do | What not to do |
|---|---|---|---|---|
| A rollback | `Alert::Rollback` (`source`: `Source::Switch`, `Source::Homeserver` or `Source::Backup`), `SignerError::Alarm`, `SignerStatus::Alarm` | where it was seen, its version and the high-water version | the user clears it with `clear_alert`; the signer then delivers its newest version again | do not hide the alarm or work past it |
| An equivocation | `Alert::Equivocation` (`source`, `version`) | as above | as above | as above |
| A rollback where the switch held no copy at all (`version` is `None`) | `Alert::Rollback` with `Source::Switch` | that the service lost the account's state | clear it; the signer reads the switch's copy, and if none, raises it again: declare a provider loss (2.9) | do not expect a retry to fix it |
| Cleared, but the switch not confirmed yet | `Refusal::SwitchUnconfirmed` | "checking the service" | `resume`; if the alarm returns, consider a provider loss | do not clear the alert again in a loop |

## 3. The screens

Every screen that changes something reads `Signer::status()` and `Signer::alerts()` again once its call returns, whether it succeeded or failed, and refreshes the status banner and the alerts inbox. Every screen handles the general failures of 2.4 (`SignerError::Switch`, `SignerError::Homeserver`, `SignerError::Store`, `SignerError::Records`, `SignerError::InvalidData`, `SignerError::Key`) the same way: show that the step will be retried, and leave the retry to `Signer::resume` or `Signer::run_due`.

### 3.1 Set-up

- [ ] Shows the choice: a new identity, or this identity from its key backup.
- [ ] New identity: calls `IdentityKeyring::create(vault)`; handles `KeyError::Occupied` (open the held identity instead with `IdentityKeyring::open`), `KeyError::Vault`, `KeyError::Crypto`, `KeyError::Missing` and `KeyError::Mismatch` (the vault lost the write).
- [ ] Asks for the switch origin, then calls `Signer::create(env, keyring, origin)`; handles `SignerError::InvalidData` (origin not valid) and `Refusal::AlreadySetUp` (call `Signer::open`).
- [ ] Calls `Signer::resume`; shows "setting up" while `SignerStatus::Enrolling`, done at `SignerStatus::Signing`.
- [ ] Handles `Refusal::UnreadableBackup` with `Alert::UnreadableBackupBeforeEnrollment`: shows that another install may sign for this identity, and offers the restore on that install, or the removal of the backup by the user.
- [ ] Asks the user to back up the identity key itself, and says the signer's backup on the Homeserver doesn't hold it.
- [ ] At every later start: `IdentityKeyring::open`; on `KeyError::Missing` when this install received a hand-over, `Signer::resume_take_over(env, identity, keys, vault)` (3.9) in place of the next two steps, and the set-up choice otherwise; `Signer::open` (handles `Refusal::NotSetUp`, `SignerError::Records`, and `SignerError::HandedOver`: a hand-over from this install took effect and its key and records are deleted, so it shows that the identity is with another install and closes this identity's screens); `Signer::resume`; `Signer::run_due`.
- [ ] Confirmed by the user: nothing beyond the choice and the origin.

### 3.2 Approve an app

- [ ] Calls `Signer::review(request, auth)` and shows the `AppReview`: the App ID, the scopes, the switch permissions, the scopes with keys, each grant path with its purpose and a decline toggle, and "renews this app" when `AppReview::renews` is true.
- [ ] Shows `AppReview::asked_caps` for information only.
- [ ] Handles at `review`: `Refusal::Scopes`, `Refusal::UnknownScopes` (name the missing protocol support), `Refusal::ProtocolRule`, `Refusal::AppRequest`, `Refusal::NotSetUp`, `SignerError::Protocol`.
- [ ] On each toggle calls `AppReview::decline(paths)`; handles `Refusal::NotDeclinable` and `Refusal::ProtocolRule` by putting the toggle back.
- [ ] Confirmed by the user: the approval, with the declines shown.
- [ ] Keeps a clone of the `AppReview` until the claim is delivered, then calls `Signer::approve` with the `AppReview`; handles `Refusal::ClockOff` (show both times), `Refusal::ClaimHeld` (wait for the alarm, 3.11), `Refusal::NotJoined`, `Refusal::CutOff`, `Refusal::IdentityTooLarge`, `Refusal::FlowInProgress`, `Refusal::Recovering`, `Refusal::HandingOver`, `Refusal::TakingOver`, `Refusal::SwitchUnconfirmed`, `Refusal::Erased`, `Refusal::RecordsBehind`, `SignerError::NotNamed`, `SignerError::Alarm`.
- [ ] After a switch or Homeserver error from `approve`: calls `Signer::resume`, then `Signer::approved(&kept.request_hash())`; when it returns `None` after a `resume` that succeeded, nothing was committed, so it calls `Signer::approve` again with the kept clone. It never asks the user for a new approval of the same request.
- [ ] With the `ApprovedRequest` (from `approve`, or later from `Signer::approved(&kept.request_hash())`): delivers `ApprovedRequest::claim` to the auth request's relay, approves the Homeserver grant for exactly `ApprovedRequest::caps` with `approve_auth_with_capabilities`, then calls `Signer::claim_delivered(&approved.request)`, `ApprovedRequest::request` being the same 32 bytes as `AppReview::request_hash()`.
- [ ] Never grants with `approve_auth`, never `AppReview::asked_caps`, never before a claim is returned.

### 3.3 App list and app detail

- [ ] Calls `Signer::apps()` and lists each `AppSummary`, the listed apps first, then the removed ones.
- [ ] Shows the standing: `AppStanding::Listed`, `AppStanding::Revoking` (with "no longer served" when `at_switch` is true), `AppStanding::Removed`.
- [ ] Detail: the certificate's scopes, switch permissions, `issued_at` and `expires_at`; whether a renewal is open; the protocols that own its scopes and any scope none owns; `distrust_from`; the automatic renewals no record took up; the alerts that name it (`AppSummary::alerts`).
- [ ] For a listed app whose `cert` is `None` (a version adopted from another install), shows its scopes as unknown here.
- [ ] Offers renew, reduce and revoke on a listed app only; offers `Signer::purge_removed` on a removed one; handles `Refusal::NotRemoved`.
- [ ] Read-only while the status isn't `SignerStatus::Signing`, but for revoke on a listed app, which stays offered at `SignerStatus::Alarm` (the app is revoked at the switch, its version waits for the alarm) and at `SignerStatus::Recovering` (kept for the new service with `Alert::RevocationPending`).
- [ ] Confirmed by the user: nothing; the actions open their own screens.

### 3.4 Renew / reduce

- [ ] Shows the current terms and the new ones: scopes, switch permissions (from `Protocols::terms`), expiry; says that removing a scope with keys rotates the identity's keys, and that removing a scope no protocol owns rotates too.
- [ ] Confirmed by the user: the change.
- [ ] Calls `Signer::renew(app_id, CertChange)`; handles `Refusal::NotListed`, `Refusal::NotJoined`, `Refusal::CutOff`, `Refusal::Superseded` (show the refreshed app), `Refusal::ClockOff`, `Refusal::UnknownScopes`, `Refusal::Scopes`, `Refusal::ProtocolRule`, `Refusal::IdentityTooLarge`, `Refusal::FlowInProgress`, `SignerError::InvalidData` (expiry refused).
- [ ] On a refusal by the switch, shows `Alert::RenewalRefused`, and for a reduction that the access was not reduced.
- [ ] After a reduction, shows `Alert::ReductionNotClosed` while the earlier certificate isn't cut off yet.
- [ ] Offers renew from `Alert::RenewalsStopped`, `Alert::RenewalSkipped` and `Alert::LapsingWithOpenAttempts`.

### 3.5 Revoke

- [ ] Calls `Signer::open_attempts(app_id)`; shows the count, or "unknown" when the call fails.
- [ ] Shows that the app is cut off for good, and asks whether it may have been used against the user; if so, asks the earlier time from which its messages are distrusted.
- [ ] Confirmed by the user: the revocation, with the count and the time shown.
- [ ] Calls `Signer::revoke(app_id, distrust_from, UserConfirmed::shown_and_confirmed())`; handles `Refusal::NotListed`, `Refusal::HandingOver` (abort first), `Refusal::TakingOver`, `Refusal::FlowInProgress` (an erasure), `Refusal::NotSetUp`, `SignerError::NotNamed`, `Refusal::RecordsBehind`, `Refusal::Erased`, `Refusal::Recovering` (kept, shown pending), `SignerError::Alarm` (revoked at the switch, the version waits), `Refusal::SwitchUnconfirmed` (kept, the version waits).
- [ ] Revokes every Homeserver grant naming the app's record path at once, or asks the user to, only once the revocation is kept: `revoke` returned `Ok`, `Refusal::Recovering`, `SignerError::Alarm`, `Refusal::SwitchUnconfirmed`, or a switch or Homeserver error; after any other error, only when `Signer::apps()` shows the app `AppStanding::Revoking` or `AppStanding::Removed`. After `Refusal::NotListed`, `Refusal::HandingOver`, `Refusal::TakingOver`, `Refusal::FlowInProgress`, `Refusal::NotSetUp`, `SignerError::NotNamed`, `Refusal::RecordsBehind` or `Refusal::Erased` nothing is committed, the app stays listed, and the grants stay.
- [ ] Shows `Alert::RevocationPending`, `Alert::RevocationUnconfirmed`, `Alert::RevokedWithOpenAttempts`, and clears `Alert::GrantRevocationOwed` once the grants are revoked.

### 3.6 Recover from a provider loss

- [ ] Asks the new service's origin.
- [ ] Shows the new service and that apps rebuild their state there.
- [ ] Confirmed by the user: the declaration.
- [ ] Calls `Signer::declare_provider_loss(origin, confirmed)`; handles `Refusal::HomeserverCopyMissing` and `Refusal::HomeserverCopyUnreadable` by asking the user to confirm also that no other install signs, then calls `Signer::declare_provider_loss_confirming_records(origin, confirmed)`.
- [ ] Handles `Refusal::NotSetUp`, `SignerError::NotNamed`, `Refusal::RecordsBehind`, `Refusal::HandingOver`, `Refusal::TakingOver`, `Refusal::FlowInProgress`, `Refusal::IdentityTooLarge`, `SignerError::InvalidData` (origin not valid).
- [ ] Shows `SignerStatus::Recovering` while the version waits, and `SignerStatus::RecoveryRefused` with a button to declare again.
- [ ] Once the recovery's version is delivered, while `Signer::apps()` lists an app whose `cert` grants `lists.manage` or whose `cert` is `None` (the wait the signer leaves to the user, 2.9), offers `Signer::end_staged_admission()` for when the user says the waiting contacts may come in; handles `Refusal::Recovering` and `Refusal::FlowInProgress`.
- [ ] Shows `Alert::AdmissionNotEnded` with no action: `run_due` sends the owed end again.

### 3.7 Move

- [ ] Says that this signer has no cooperative move, and opens 3.6 for the new provider.
- [ ] Shows `Alert::IdentityNearLimit` and `Refusal::IdentityTooLarge` with `SizedBody::Enrollment`, and offers to remove or purge apps first.

### 3.8 Erase the account

- [ ] Shows that for the apps this is a provider loss and lookups of the identity fail closed; that `identity.json` and the app records leave the Homeserver; that each app's grant is the user's to revoke.
- [ ] Confirmed by the user: the erasure.
- [ ] Calls `Signer::close_account(confirmed)`; handles `Refusal::Erased`, `Refusal::ErasureRefused`, `Refusal::FlowInProgress`, `Refusal::HandingOver`, `Refusal::TakingOver`, `Refusal::Recovering`, `Refusal::RecordsBehind`, `Refusal::SwitchUnconfirmed`, `SignerError::NotNamed`, `SignerError::Alarm`.
- [ ] Shows `SignerStatus::Erasing`, `SignerStatus::ErasedUnconfirmed` and `SignerStatus::Erased`. For `SignerStatus::ErasedUnconfirmed` it shows "looks closed, not confirmed yet" and no definite time: the first run at least 24 hours after `since_ms` (device clock) that still meets the switch's unsigned `404` confirms it, and an answer the pinned service key signs meanwhile ends the wait, the status going back to `SignerStatus::Erasing`.
- [ ] Lists each `Alert::GrantRevocationOwed`; for an app the erasure found still listed, revokes the grant only once the status is `SignerStatus::Erased` (an aborted or refused erasure withdraws those alerts); clears each alert once its grant is revoked.
- [ ] Offers `Signer::abort_erasure()` while `SignerStatus::Erasing`; handles `Refusal::ErasureUnanswered` and `Refusal::NotErasing`.
- [ ] At `SignerStatus::Erased`, and during an erasure, offers a provider loss (3.6): `Signer::declare_provider_loss` is allowed on an erased account and ends an erasure in progress.

### 3.9 Hand over / take over

- [ ] Old signer: lists the current apps that can take over; shows the app taking over and that this install then stops and deletes its key (and, for a key derived from a wallet seed, that the deletion can't make it unrecoverable).
- [ ] Confirmed by the user: the hand-over.
- [ ] Calls `Signer::hand_over_to(to_app, confirmed)`; handles `Refusal::ClosingOwed`, `Refusal::RevocationOwed`, `Refusal::NotListed`, `Refusal::TargetNotCurrent`, `Refusal::Recovering`, `Refusal::TakingOver`, `Refusal::SwitchUnconfirmed`, `SignerError::NotNamed`, `SignerError::Alarm`.
- [ ] Shows `SignerStatus::HandingOver` and `Alert::HandOverRefused`; tells the user to open the new app.
- [ ] Offers abort, confirmed by the user: `Signer::abort_hand_over(confirmed)`; handles `AbortOutcome::Aborted`, `AbortOutcome::SucceededBy`, `Refusal::HandingOver` (the abort is sent but hasn't won yet: shown as calling off, sent again by `resume` and `run_due`), `Refusal::SuccessorUnproven`, `Refusal::NotHandingOver`.
- [ ] On `Refusal::SuccessorUnproven`, from `abort_hand_over`, `resume` or `run_due`, offers take-back, confirmed by the user that the new signer is lost: `Signer::take_back(confirmed)`; handles `Refusal::NothingToTakeBack`, `SignerError::HandedOver`, and shows `Alert::TakenBack`.
- [ ] On `SignerError::HandedOver` from any call: shows that the identity is with another install now, and closes this identity's screens.
- [ ] New signer: calls `Signer::receive_hand_over(env, app, vault)` with an empty vault; shows `SignerStatus::TakingOver`; handles `Refusal::AlreadySetUp`, `KeyError::Occupied`, `SignerError::InvalidData`, `Refusal::StaleHandOver`, `Refusal::TakeOverCancelled`; keeps the identity's public key and the `ReceivingApp::keys`; after a restart, with the vault still empty until the take-over wins, calls `Signer::resume_take_over(env, identity, keys, vault)` and handles `Refusal::NotTakingOver` and `Refusal::NotSetUp`; shows `Alert::TakeOverRefused` and `Alert::KeyNotInstalled`.

### 3.10 Restore

- [ ] Shows whether the device the backup came from is still the user's, and that the backup's records replace this install's.
- [ ] Confirmed by the user: the restore.
- [ ] On a new device: `IdentityKeyring` from the user's key backup, then `Signer::restore_new(env, keyring, confirmed)`.
- [ ] In place, offered at `SignerStatus::RecordsBehind` or `SignerStatus::ManagedBy`: `Signer::restore(confirmed)`.
- [ ] Handles `Refusal::NoBackup`, `Refusal::UnreadableBackup`, `Refusal::StaleBackup`, `Refusal::Erased`, `Refusal::FlowInProgress`, `Refusal::HandingOver`, `Refusal::TakingOver`, `Refusal::AlreadySetUp`.
- [ ] Shows `Alert::BackupNotWritten` and `Alert::EpochFloorBounded` when raised.

### 3.11 Alerts inbox

- [ ] Lists `Signer::alerts()`, oldest first, each with its facts.
- [ ] On dismissal calls `Signer::clear_alert(alert)`; for `Alert::Rollback` and `Alert::Equivocation`, handles the alarm coming back (`SignerError::Alarm`) and `Refusal::SwitchUnconfirmed`.
- [ ] Keeps showing `Alert::ReductionNotClosed` and `Alert::RecordsBehind` after a dismissal, since the signer keeps them until their cause is gone.
- [ ] For `Alert::GrantRevocationOwed`, dismisses only after the grants are revoked.
- [ ] Never dismisses an alert the user hasn't seen.

### 3.12 Status banner

- [ ] Shows `Signer::status()` after every call: `SignerStatus::Enrolling`, `SignerStatus::Signing` (no banner), `SignerStatus::ManagedBy` (offer restore), `SignerStatus::RecordsBehind` (offer restore), `SignerStatus::HandingOver` (offer abort), `SignerStatus::TakingOver`, `SignerStatus::Alarm` (open the alerts inbox), `SignerStatus::Erasing` (offer abort), `SignerStatus::ErasedUnconfirmed`, `SignerStatus::Erased`, `SignerStatus::Recovering`, `SignerStatus::RecoveryRefused` (offer to declare again).
- [ ] Turns the app list read-only whenever the status isn't `SignerStatus::Signing`, but for revoke, which stays offered at `SignerStatus::Alarm` and `SignerStatus::Recovering` (3.3).
