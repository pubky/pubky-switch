# `pubky-switch-signer`: design note

Status: for review, before any code. Scope: identity management on the Pubky Switch (spec Sections 2, 3, 4.3 and 12, decision 24; wire Sections 2, 3 and 7). Section numbers below are the Switch spec's (`spec/spec.md`) and wire format's (`spec/wire-format.md`).

## 1. What the crate is

`pubky-switch-signer` manages one Pubky identity on the Switch. It holds the identity key through the host, approves apps, signs and versions `identity.json`, derives and seals key bundles, enrolls at a switch, and runs the lifecycle flows of spec 12, among them the hand-over to another signer and the backup of its own records. Any app can be its identity's signer through it (decision 24). Bitkit is the first.

**It knows no protocol.** A protocol on the Switch (spec 1) tells it which scopes exist, which switch permissions each needs and which have Shared Data Keys. The signer applies the Switch's generic rules on top of that (section 3).

**Dependencies:**
- `pubky-switch-core`: documents, signatures, derivations, envelopes, the scope rule and chain verification. It is pure, and time is passed in.
- `pubky-switch-client`: the Switch client (request signing, response and proof verification, batches), the `StateStore` trait and the clock.
- **The identity's Homeserver,** through a `Homeserver` trait (`get` and `put` of the identity's own public files) that the host implements on its Pubky session for the identity, as the client reads Homeserver files through `HomeserverReader`. The signer writes `identity.json` and the backup there, which no app's grant covers (spec 3.4).

So the direction is `pubky-switch-signer -> pubky-switch-client -> pubky-switch-core`. The bindings expose it alongside a protocol's SDK, which is how "the signer core ships in the SDK" holds.

**What it never does:** it never signs bytes a caller supplies (spec 13.2, wire 2.1). Every signature it makes with the identity key is over an input it builds itself, for one of these:
- an identity-key row of wire 2.3;
- the approval's companion claim (wire 3.10);
- one of Pubky's own formats for the same key.

## 2. The identity key interface

From the moment an install becomes the signer, keeping the key safe and backed up is its job (spec 12.8). The core's document builders all take its `IdentityKey`, a secret held in memory, and neither the Secure Enclave nor the Android Keystore supports Ed25519, so the key has to be in software while it signs. The interface has two layers.

### 2.1 `SecretVault` (host callback, what Bitkit implements)

```rust
pub trait SecretVault: Send + Sync {
    fn load(&self) -> Result<Option<IdentitySecret>, VaultError>;     // per operation, zeroized after
    fn add(&self, secret: &IdentitySecret) -> Result<AddOutcome, VaultError>; // store only into an empty vault
    fn delete(&self) -> Result<(), VaultError>;
}

pub enum AddOutcome { Stored, Occupied }
```

- **`add` never replaces a secret.** It stores one only when the vault holds none, and the check and the write are one atomic step for every caller sharing the vault: every handle, thread and process that reads or writes the same stored secret. Of two `add` calls on an empty vault, exactly one returns `Stored`; the other returns `Occupied` and the held secret is unchanged. So two identities created at once can't both succeed while one of their keys is lost.
  - **iOS:** `SecItemAdd` on one item with a fixed service, account and access group; `errSecDuplicateItem` is `Occupied`. Never `SecItemUpdate`, or a delete followed by an add.
  - **Android:** check and write under one lock every handle and process takes (a `FileChannel` lock on a lock file together with an in-process mutex), or write a temporary file and link it into place with a call that fails when the target exists (`Os.link`). A replacing rename doesn't qualify.
- **No caller overwrites.** Creating an identity, taking over, restoring from the backup and receiving a hand-over all go through `add`. A received key that is already held, as after a retry, counts as stored; any other held secret is `Occupied`, and the host resolves it explicitly, for example by deleting an identity the user gave up. An install that isn't named but holds the key takes over without writing the vault.

- **`IdentitySecret`** is the 32-byte Ed25519 secret (seed). It zeroizes on drop and `Debug` never shows it; the host builds one from the bytes it keeps and reads them back with `as_bytes` to store them.
- **Synchronous:** Swift and Kotlin implement the three calls without async callbacks. After `add` returns `Stored`, `load` returns that secret, also after a crash; after an error the vault holds what it held before.
- **Where it lives:** on iOS, one keychain item of a `...ThisDeviceOnly` class. On Android, a Keystore-wrapped file excluded from backups (spec 3.1).
- **What the host code does:** Swift and Kotlin never sign, derive or parse anything. They move 32 opaque bytes.
- **Hosts that derive the key:** a host that already controls the key, for example one that derives it from a wallet seed, implements `load` as that derivation, and `add` answers `Occupied`. It implements `delete` by its own policy. For a derived key, `delete` can't make the key unrecoverable, and the host tells the user so at a hand-over (spec 12.8, "The limit").
- **Backups:** the identity key itself is the host's to back up. The signer's records are backed up by the crate (section 4.4).

### 2.2 `IdentityKeyring` (the crate's side)

```rust
impl IdentityKeyring {
    pub fn open(vault: Arc<dyn SecretVault>) -> Result<Self, KeyError>;    // an existing identity
    pub fn create(vault: Arc<dyn SecretVault>) -> Result<Self, KeyError>;  // a new one, the vault empty
    pub fn public_key(&self) -> [u8; 32];
    pub fn pubky_id(&self) -> String;
    pub fn backup_public(&self) -> Result<([u8; 32], [u8; 8]), KeyError>;  // backup key and kid

    pub(crate) fn install(vault, identity, secret) -> Result<Self, KeyError>; // a received key
    pub(crate) fn with_key<T>(&self, use_key: impl FnOnce(&IdentityKey) -> T) -> Result<T, KeyError>;
    pub(crate) fn for_export<T>(&self, reason: ExportReason,
                                seal: impl FnOnce(ExportReason, &IdentityKey) -> T) -> Result<T, KeyError>;
    pub(crate) fn destroy(&self) -> Result<(), KeyError>;
}

pub enum ExportReason { HandOver { to_app: [u8; 16] }, Backup }
```

- **It holds no secret.** It holds the vault and the identity's public key. Each use loads the secret, checks that its public key is still this identity's, makes the core's `IdentityKey` for one operation and drops it, zeroized.
- **No signing in the public API.** `with_key` is the crate's alone. The crate calls it only to sign inputs it builds, through the core's builders, for the identity-key rows of wire 2.3 and the approval's companion claim (wire 3.10), and for the derivations of spec 13.3: the Switch root and the keys it yields, and the backup key. The core's builders sign Pubky's own formats from typed inputs too.
- **The secret leaves for two reasons only.** `for_export` is the one place the secret bytes may be read, and only to seal them at once, in a hand-over to `to_app` (wire 3.12) or in the signer's backup (wire 3.13).
- **Received keys:** `install` adds the secret of a hand-over or a backup to the vault only when it is the identity's key. A vault that already holds that same secret, as after a retry, is fine; another secret is `Occupied`.
- **`KeyError`** says which of these went wrong: the vault failed, it holds no secret, it already holds one, the secret isn't this identity's, the bytes aren't 32 long, or the random generator failed.

## 3. Protocols

Approval takes the protocol's scopes and permission table from the caller, as a description the host registers when it opens the signer. It isn't an argument to `approve`, because the signer needs the same knowledge long after an approval:
- renewing certificates at `run_due`;
- judging reductions and keyed-scope removals;
- making every app's bundle at each epoch rotation;
- checking a received hand-over or a restored backup.

```rust
/// What a protocol on the Switch tells the signer (spec 1).
pub trait Protocol: Send + Sync {
    /// For messages and errors only.
    fn name(&self) -> &str;
    /// The scope names it owns, each with whether it has Shared Data Keys
    /// (spec 3.3, 3.5). Read once, when the set is built. A sub-scope has keys
    /// exactly when its name does.
    fn scopes(&self) -> Vec<ScopeDef>;
    /// Its own rule on a requested set of its scopes, beyond the Switch's scope
    /// rule (wire 3.9 step 1), such as two scopes that never go together.
    fn check_scopes(&self, scopes: &[&str]) -> Result<(), String>;
    /// Its permission table (spec 3.2): the switch permissions these scopes need.
    fn permissions(&self, scopes: &[&str]) -> Vec<Permission>;
    /// Paths it adds to the grant of an app holding these scopes, each shown to
    /// the user for consent (wire 3.9 step 3). None by default.
    fn grant_paths(&self, app_id: &[u8; 16], scopes: &[&str]) -> Vec<GrantPath>;
}
```

- **Several protocols:** the signer holds a `Protocols` set. Building it refuses an empty set, a malformed or repeated protocol name, a protocol that owns no scope, a scope name that breaks the scope rule or has a sub-scope, and one name declared twice. An app may hold scopes of several protocols: each protocol sees only its own, the permissions are the union, written in the Switch's fixed order (wire 3.1), and the keyed scopes are those whose owner marks them.
- **What the set gives:** `terms(scopes)` checks a request and returns its permissions and keyed scopes; `knows_scope` and `has_keys` are the predicates the core's app request check and key bundle functions take; `grant_paths` gives the paths for the core's caps check; `unowned` lists the scopes no registered protocol owns.
- **The Switch's own rules stay in the signer and the core:**
  - the scope rule and the 32-scope bound, and no name beside its own sub-scope;
  - grants exactly the app's own paths, and a protocol's grant paths lie outside the Switch's own folders;
  - no grant covering `identity.json` or the signer's backup;
  - the app limit.
- **Unknown scopes:** a scope no registered protocol owns is refused in a request (wire 3.9 step 1). A received hand-over or a restored backup whose certificates hold one is refused, naming those scopes so the host can tell the user which protocol support is missing. A certificate already in the records that holds one blocks every step that needs that app's keys and raises an alert, instead of guessing (decision 2).

## 4. State

### 4.1 Durable records (`SignerRecords`)

| Item | Why | Spec |
|---|---|---|
| identity; current service (origin, service key, enrollment `limits`) | requests, app limit, import limit check | 4.3, wire 3.7 |
| install ID: 16 random bytes, picked when it first signs | the `signer` member of every version it signs | 4.3, wire 3.3 |
| high-water mark: generation, version, document hash, body hash | never adopt a lower copy or another body at a version; raise an alarm instead | 4.3, wire 3.3 |
| the working `identity.json`: signed bytes, `prev`, delivered and published flags | sign once, deliver then publish, compare-and-swap | wire 2.1, 7.4.2 |
| certificates the newest document references (listed and `renewed`) | renewals, owed closings, hand-over and backup contents | 3.2, wire 3.12 |
| tombstones: every App ID revoked or seen departing, kept for good | refusing approvals; `revoked_apps` in every enrollment | 12.2, wire 3.7 |
| stored key bundle parts per app: range and certificate hash | resuming cut-short deliveries, full-bundle requests, `bundle_parts` | wire 3.5 |
| the last backup: its signed bytes, the version it holds and its `prev` | sign once; rewriting after key bundle parts | wire 3.13 |
| `managed_by`: another install's ID, when a newer document names it | refuse every signing call, offer take-over | 4.3 |
| settings: certificate lifetime, `record_max_age`, policy | | 3.2, 4.3 |
| the flow in progress (below) and its signed artifacts | crash recovery | |
| the previous service and its pointer window | offering erasure | 12.5, 12.7 |
| pending alerts | the user is told even after a restart | |

The list of apps isn't stored separately: it comes from the newest document and the referenced certificates.

### 4.2 Persistence

The signer uses the client's `StateStore` (atomic batches, durable writes) under its own namespace, `signer/<identity>`, so a host that is both an app and the signer has one store. The records and the flow in progress are two values there, always committed together; the identity key is never among them. Every network effect follows one rule:

1. Build and sign the artifact, and commit it together with the flow's next step in one atomic write.
2. Send those bytes, again and again until there is an answer. The Switch treats them as a retry.
3. Commit the outcome.

A crash anywhere resends the same bytes, so nothing is ever signed twice (wire 2.1 "Sign once"). Nothing in the spec fixes how a signer persists its records; this is the crate's own rule.

### 4.3 Flows

At most one flow is in progress. A new one is refused until it ends, except an abort, which applies only to its own flow.

```text
Flow = Approve     { request_hash, cert, step }
     | Renew       { app, new_cert, reduction, rotates_epoch, step }
     | Revoke      { app, distrust_from, step }        // also completes a departure
     | Rotate      { epoch, step }                     // bare data-epoch rotation
     | KeyChange   { pending_key, step }               // service key in place
     | Move        { next, freeze, manifest, transfer, step }
     | Loss        { next, step }
     | Erase       { service, step }
     | HandingOver { to_app, version, doc_hash, abort: Option<signed doc> }
     | TakingOver  { source: HandOver | Backup | NotNamed, version, step }
```

Each step is one idempotent call. `Revoke`, for example, runs these steps:
1. Revoke at the switch.
2. Store each remaining app's bundle for e+1.
3. Write the backup.
4. Deliver `identity.json` with the app in `removed` and `data_epoch` e+1.
5. Publish.
6. Delete the app's Homeserver record and revoke its grant.

### 4.4 Delivering a version, with the backup

Every new version takes the same path (spec 4.3, 12.8; wire 3.3, 3.13):

1. **Check this install may sign.** If `managed_by` is set, refuse.
2. **Sign** the version, naming this install as `signer`, and commit it.
3. **Read the backup** on the Homeserver. If it names another install at or past the high-water mark, set `managed_by` and stop (wire 3.13 "Another install's backup").
4. **Write the backup** holding the new version and its `prev`, sealed to the backup key. A failed write stops the delivery.
5. **Deliver** with `PUT /identity`. Compare-and-swap answers go to the high-water rules: an alarm, or adopting a strictly newer copy.
6. **Update the high-water mark**, then publish on the Homeserver.

Two exceptions:
- **After storing key bundle parts,** the signer writes the backup again, at the same version, so that `bundle_parts` lists them.
- **Racing deliveries** write the backup only once their delivery has won: a take-over after a hand-over, a restore, and an abort. A failed write then leaves an alarm, and the next write repairs it.

### 4.5 What runs at each start

`Signer::run_due()` runs these steps in order. Each is a no-op when nothing is owed.

1. Check that this install is the one named (`identity` in `GET /apps`, and the backup). If not, set `managed_by` and stop.
2. Finish the flow in progress.
3. Close every owed reduction (wire 3.8 "A closing delivery owed"), before any other delivery or provider change.
4. Complete the departures the switch reports (`awaiting_rotation`).
5. Set `until` for cooperative renewals whose app record now carries the new certificate (`record_cert`, `record_at`).
6. Serve full-bundle requests, resuming from `bundle_ranges`, with `cert.put` where `record_cert` lags.
7. Renew certificates past half their lifetime.
8. Check a pending hand-over. If the switch holds a newer version this signer didn't deliver, finish: destroy the key and the records.
9. Republish the switch's copy if the Homeserver copy differs.

It returns a report and refreshes the alerts.

### 4.6 The `StateStore` trait (proposal)

`pubky-switch-client` defines the trait, and the signer uses it. The host app implements it once per install, for example on SQLite.

```rust
pub trait StateStore: Send + Sync {
    /// The value at `key` in `ns`, or `None`.
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError>;

    /// The entries of `ns` whose keys start with `prefix`, in ascending byte order
    /// of key, starting after `after`, at most `limit` of them.
    fn scan(&self, ns: &str, prefix: &[u8], after: Option<&[u8]>, limit: u32)
        -> Result<Vec<(Vec<u8>, Vec<u8>)>, StoreError>;

    /// Apply every write of `batch`, or none of them.
    fn commit(&self, batch: WriteBatch) -> Result<(), StoreError>;
}

pub struct WriteBatch { pub writes: Vec<Write> }

pub enum Write {
    Put { ns: String, key: Vec<u8>, value: Vec<u8> },
    Delete { ns: String, key: Vec<u8> },
    DeletePrefix { ns: String, prefix: Vec<u8> },
}
```

- **Plain types:** the trait is synchronous, so Swift and Kotlin implement it without async callbacks. The crates call it off the async executor.
- **Bytes in, bytes out:** keys and values are opaque bytes. The crates encode their own records with a schema version, so the host never parses them.
- **Namespaces:** the crates name them, for example `signer` and `client/<app_id>`. Each crate writes only its own.

**Guarantees the host gives:**
1. **Atomic:** a `commit` applies all of its writes or none, also across a crash or power loss. `Err` means none were applied. A store that can't tell after an error returns `StoreError::Unknown`, and the crate reads its state again before going on.
2. **Durable:** `commit` returns `Ok` only once the writes are on stable storage (for SQLite, `synchronous=FULL`). After `Ok` they survive a process kill and a power loss.
3. **Ordered and consistent:** commits apply in the order they are made. A read sees every commit that returned before it and never part of a batch.
4. **One writer per namespace:** only one process at a time writes a namespace, for example the main app and not a push extension. The crates serialize their own commits.
5. **Device-bound:** the store is excluded from device and cloud backups and is encrypted at rest under a key kept like the app's keys, as spec 3.1 asks of local state. The signer stores no secret key in it (the identity key stays in the `SecretVault`), but its records hold the signed hand-over and backup.
6. **Real deletion:** `Delete` and `DeletePrefix` remove the data from the store's files, not only from its index (for SQLite, `secure_delete`). A signer that hands over deletes its records "in every copy it keeps" (spec 12.8, 3.1).
7. **Sizes:** a value up to 16 MiB and a batch up to 32 MiB. The largest value is a hand-over or a backup kept as signed bytes: at most 128 envelopes, 11,185,390 bytes of JSON at the limits (wire 3.12, 3.13). A commit holds at most one such value with the flow step it belongs to, so a 32 MiB batch leaves room for two.

**What the crates add:** an in-memory store for tests, and a fault-injecting store behind a test-only feature, which fails or stops before and after any commit, for the crash tests.

## 5. Public API (sketch)

Async at the edges, plain types, and no lifetimes in public structs, so it binds cleanly.

```rust
impl Signer {
    // Setup
    async fn create(env: SignerEnv, keyring: IdentityKeyring, switch: Origin) -> Result<Self>;    // wire 3.7, 7.4.1-2
    async fn open(env: SignerEnv, keyring: IdentityKeyring) -> Result<Self>;                     // load records, no network
    async fn restore(env: SignerEnv, keyring: IdentityKeyring, ok: UserConfirmed) -> Result<Self>; // from the backup, wire 3.13
    async fn take_over(&mut self, ok: UserConfirmed) -> Result<()>;                                // this install isn't named: restore in place

    async fn run_due(&mut self) -> Result<RunReport>;
    fn status(&self) -> SignerStatus;   // Signing | ManagedBy { install } | HandingOver { to_app } | Succeeded { by_app }
    fn alerts(&self) -> Vec<Alert>;
    async fn apps(&self) -> Result<Vec<AppView>>;  // GET /apps with the document: last seen, idle, expiry, open attempts

    // Apps
    fn review(&self, request: SignedDoc, auth: AuthRequest) -> Result<AppReview>;           // wire 3.9 checks 1-6
    async fn approve(&mut self, review: AppReview) -> Result<ApprovedRequest>;      // cert, version, approval and claim
    fn approved(&self, request: &[u8; 32]) -> Result<Option<ApprovedRequest>>;     // the claim, once its version is delivered
    async fn claim_delivered(&mut self, request: &[u8; 32]) -> Result<()>;          // the host sent the claim and the grant
    async fn renew(&mut self, app: AppId, change: CertChange) -> Result<RenewalOutcome>;     // reductions included
    async fn revoke(&mut self, app: AppId, distrust_from: Option<Time>, ok: UserConfirmed) -> Result<Rotation>;
    async fn purge_removed(&mut self, app: AppId) -> Result<()>;

    // Settings
    async fn set_record_max_age(&mut self, seconds: Option<u64>) -> Result<()>;
    async fn set_connect_requests(&mut self, policy: ConnectRequests) -> Result<()>;

    // Provider
    async fn rotate_service_key(&mut self) -> Result<()>;
    async fn move_to(&mut self, origin: Origin) -> Result<MoveProgress>;   // resumable: enroll, freeze, transfer, activate, publish
    async fn abort_move(&mut self) -> Result<()>;
    async fn declare_provider_loss(&mut self, origin: Origin, ok: UserConfirmed) -> Result<()>;
    async fn end_staged_admission(&mut self) -> Result<()>;
    async fn erase_previous(&mut self, ok: UserConfirmed) -> Result<()>;
    async fn close_account(&mut self, ok: UserConfirmed) -> Result<()>;    // spec 12.7 step 5, second case

    // Hand-over, sending side
    async fn hand_over_to(&mut self, app: AppId, ok: UserConfirmed) -> Result<()>; // seal, PUT /handover
    async fn abort_hand_over(&mut self, ok: UserConfirmed) -> Result<AbortOutcome>; // aborted | already succeeded
}

/// Hand-over, receiving side: run by the target app with its own app keys.
async fn receive_hand_over(env: SignerEnv, app: AppCredentials, vault: Arc<dyn SecretVault>)
    -> Result<Signer, HandOverRefused>;   // GET /handover, checks 1-3, the version + 1 delivery
```

- **`UserConfirmed`** is a token the host makes only after it has shown the user the consequence: a revocation, a loss, an erasure, a hand-over or a take-over.
- **`SignerEnv`** bundles the store, the clock, the Switch client factory, the Pubky handles and the `Protocols`.
- **Approval:** `approve` signs the certificate, the version that lists it, the approval with the app's full key bundle and its companion claim, commits them together, then delivers. The claim is released only once the switch took that version. The host delivers it to the auth request's relay and then approves the Pubky grant for exactly the capabilities checked, which include the protocols' grant paths the review showed; the user's approval covers them, since the grant can't be narrowed below the auth request's capabilities.
- **`receive_hand_over`:**
  - After any refusal, it destroys whatever it opened (wire 3.12).
  - A delivery that loses the compare-and-swap counts as a refusal.
  - On success, it stores the secret in the vault only once its delivery has won.

### 5.1 Alerts

```text
Alert = Equivocation { version, ours, theirs }      // stop, show
      | Rollback { source, seen, high_water }
      | Refused { action, reason }                  // e.g. service_keys over 256, import limit too low
      | ImportConflict { conflicts }
      | ManagedByOtherInstall { install }           // offer take-over
      | HandOverPending { to_app, since } | HandOverTookEffect { by_app } | HandOverRefused { reason }
      | BackupWriteFailed                           // after a racing delivery won
      | UnknownScope { app, scope }                 // no registered protocol owns it
      | AppIdle { app, last_seen }                  // suggest removal after 90 days
      | CertLapsingWithOpenAttempts { app, expires_at }
      | GrantRevocationOwed { app }
      | PreviousServiceErasable { origin }
```

Each alert carries the facts to show. The wording is the host's.

### 5.2 Errors

`SignerError` has typed variants, not strings:
- `Switch(ClientError)`, `Homeserver(..)`, `Key(KeyError)`, `Store(StoreError)`;
- `NotNamed { install }`: this install isn't the signer;
- `Refused(Refusal)`, when a rule said no;
- `Alarm(Alert)`, for a rollback or an equivocation;
- `InvalidData`, for network data that doesn't verify.

`Refusal` covers a revoked App ID, an App ID listed with other keys, the app limit, a grant that isn't the app's own paths, an unknown scope, a flow in progress, a hand-over in progress, a move in progress, `service_keys` over 256, and the import limit.

There are no panics on network input, and all arithmetic is checked.

## 6. Flows, mapped to calls

| Area | Main calls | Notes |
|---|---|---|
| 1 Enrollment | `create`, `move_to`, `declare_provider_loss` | the enrollment is kept signed and resent unchanged; `revoked_apps` comes from the tombstones; the high-water mark after every accepted delivery; `signer` set to this install |
| 2 App approval | `review`, `approve` | permissions from the `Protocols`; the approval is built from the delivered document; the full bundle in parts; the companion claim delivered before the grant; the approval kept by request hash until the claim is delivered, so a crash resends it |
| 3 Renewals and reductions | `renew`, `run_due` | `cert.put` with the first bundle part; a reduction closes from the delivery proof's `server_time`; a removed keyed scope rotates the epoch, with the other apps' e+1 bundles stored before the delivery |
| 4 Revocations and departures | `revoke`, `run_due` | the switch first, then bundles, delivery, publish, and the record and grant cleanup; departures completed from `GET /apps`; tombstones kept for good |
| 5 Service keys | `rotate_service_key`, `move_to` | `service_keys` from `proof_generations`; refused past 256, or for a reported generation whose key it lacks |
| 6 Provider moves | `move_to`, `abort_move` | rotations owed done first; import limit check; the freeze kept before it is sent; direct transfer under the export transfer, with a relay fallback; the abort sends the unfreeze to N, then to O with N's discard answer |
| 7 Provider loss | `declare_provider_loss`, `end_staged_admission` | a new generation with `recovery_from`; no service key added |
| 8 Erasure | `erase_previous`, `close_account` | refused during a move; a lost `200` followed by a `404` counts as done |
| 9 Hand-over | `hand_over_to`, `abort_hand_over`, `receive_hand_over` | up to 128 envelopes through `PUT`/`GET /handover`; the abort at version + 2; checks 1 to 3 on the receiving side, then the version + 1 delivery; a refusal destroys the received secret |
| 10 Backup and the one-signer rule | section 4.4, `restore`, `take_over`, `status` | written before each delivery and after bundle parts; another install's backup or document stops signing |
| 11 Key interface | section 2 | |
| 12 Telling the user | `alerts`, `status` | section 5.1 |

## 7. Tests

- **Unit tests per module,** each rule with a positive and a failure-path test:
  - the refusals of wire 3.9;
  - the high-water mark and equivocation;
  - computing missing ranges;
  - detecting reductions and keyed-scope removals, through a test protocol;
  - the `service_keys` rules;
  - the `Protocols` set's ownership and permission union;
  - sealing a hand-over and every rejection of it;
  - the backup checks: another install, a stale backup, a switch at `prev`.
- **Switch vectors,** the signer's cases reproduced byte for byte from `spec/vectors/`:
  - `envelopes.json`: `signer_handover` and `signer_handover_rejections`, `signer_backup`, `reduction_key_bundle`;
  - `keys.json`: the backup keys;
  - `documents.json`: the `identity.json` documents with `signer`, the renewal in progress and closed, the hand-over abort at version 5, the document after the move, the export transfer, the approval and `discarded`;
  - `signatures.json`: the identity-key labels;
  - `http.json`: the signer's rows, the hand-over store and fetch, and the take-over delivery that loses to the abort.

  The fixed randomness sits behind a test-only feature.
- **Crash tests:** a fault-injecting store and client stop at every step of every flow. On reopen the flow finishes and nothing is signed twice.
- **Ported flow tests:** approval, renewal, revocation, departure, moves and abort, recovery, erasure, the hand-over both ways, and backup and restore, including the end-to-end ones. They run against the Switch service in this workspace. Until it serves these calls, they are marked so that CI skips them.

## 8. PR order (into `main`)

1. This note.
2. Errors, the key interface and `Protocols`, on the types of `pubky-switch-core`.
3. Records and store, `identity.json` versioning (sign once, compare-and-swap, the high-water mark, publish), the install ID, the backup write and check, and enrollment.
4. Approval: review, certificates, bundles and parts, the companion claim and the grant.
5. Renewals, reductions, owed closings and `run_due`.
6. Revocations, departures, epoch rotation and full-bundle requests.
7. Service key change, moves and abort, provider loss, and erasure.
8. The hand-over sending and receiving, restore, and take-over.
9. Alerts, end-to-end tests against the service and a Homeserver, and the integration guide for Bitkit.

PR 2 starts once `pubky-switch-core` has the types it needs, and the network flows build on `pubky-switch-client`.

## 9. Settled in the spec

The Switch spec answers four questions a signer has to settle:
- **The companion claim:** it is on the list of what the identity key signs (spec 13.2, wire 2.1, 2.3 and 3.10).
- **The hand-over transport:** it goes through the switch (`PUT` and `GET /handover`, wire 7.4.17).
- **Restoring the signer:** from the sealed backup on the Homeserver (wire 3.13).
- **Two devices:** `signer` in `identity.json` names the one install that signs, and the others offer to take over (spec 4.3, 12.8).

## 10. Decisions

1. **Key bundles follow the neutral rule.** Wire 3.5, 3.8, 3.10 and 7.4.11 word a bundle part's keys in one protocol's terms, where spec 3.5 leaves the choice of keyed scopes to each protocol, and spec 12.7 step 5 names one protocol too. The signer implements the neutral rule through `Protocol::has_keys`, which gives the same bytes for the vectors. A follow-up spec PR fixes the wording.
2. **A scope no registered protocol owns.** `receive_hand_over` and `restore` refuse unless a registered protocol owns every scope of every listed certificate, and tell the user which protocol is missing. Elsewhere, for example after a protocol is unregistered, the signer raises `UnknownScope` and blocks only the steps that need that app's keys.
3. **Finding a waiting hand-over.** No feed item announces one (wire 7.4.17), so the user drives it. The old signer tells the user to open the new app, and the new app calls `GET /handover` at start and when the user asks; a `404` costs little.
4. **Revoking Pubky grants.** Revocations and leaves revoke the app's grant (spec 3.4, 12.2 step 1). Until the Pubky SDK offers a revocation call, the signer records each revocation as owed and raises `GrantRevocationOwed`. The rest of the flow doesn't wait for it.
5. **The `StateStore`:** proposed in section 4.6, to be agreed together with `pubky-switch-client`.

## 11. Known limits

- **A lagging switch with an unreadable or missing backup.** When the backup on the Homeserver doesn't open, or is missing where this signer wrote one, the signer writes its own only if the switch's copy (`GET /apps` `identity`) is still its high-water version (wire 3.13). A switch whose `GET /apps` lags its own writes can show that version after another install's delivery has won. The signer then writes its backup over the winner's. Its own delivery still fails at the switch's compare-and-swap, so the identity stays with the winner; the winner's next backup write repairs the file.
- **An unreadable backup before the first version.** A new install that finds a backup it can't open, before any switch accepted a version from it, has no copy to judge the switch by. It writes and delivers nothing, raises `UnreadableBackupBeforeEnrollment` and refuses with `UnreadableBackup`. The user restores from that backup on the install that wrote it, or, sure that no other install signs for the identity, removes the file from the Homeserver; `resume` then goes on.
- **A newer `identity.json` on the Homeserver.** Before it publishes, the signer reads the Homeserver's copy. A newer one, verified for the identity, is handled as a newer copy from the switch: another install's is adopted, and this install stops as an install that isn't named, so the take-over flow is how it signs again. Newer means a higher version at no lower generation. This install's own, which the switch doesn't hold, as after its records went back, isn't published over, since readers would keep the higher version: the newest version is signed again above it, in the same call, and the switch takes it and it is published, with `HomeserverAhead`. So a change never returns `Ok` while readers don't see it. A copy that doesn't verify, or isn't newer, is written over.
- **The window between the read and the write.** `Homeserver::put` is unconditional: another install can publish `identity.json`, or write the backup, between this signer's read and its write, and this signer then writes over it. The switch's compare-and-swap still decides who signs, and the winner's next write repairs the file. The Homeserver has no conditional write: it takes `If-None-Match` and `If-Modified-Since` on reads only, with no `If-Match` or other precondition on a write. So `Homeserver::put` stays unconditional, and this window stays.
