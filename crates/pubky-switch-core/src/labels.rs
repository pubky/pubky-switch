//! The Switch's signature and derivation labels (Switch wire 1.5, 2.3).
//!
//! Every format the Pubky Switch defines signs and derives under a `pubky-switch/v1/` label.
//! A protocol on the Switch uses labels of its own, never one of these (Switch spec 1).

/// Signature labels (Switch wire 2.3).
pub mod sig {
    /// App certificate, signed by the identity key.
    pub const APP_CERT: &str = "pubky-switch/v1/app-cert";
    /// App record, signed by the app's signing key.
    pub const APP_RECORD: &str = "pubky-switch/v1/app-record";
    /// Receive key record, signed by the app's signing key.
    pub const RECEIVE_KEY: &str = "pubky-switch/v1/receive-key";
    /// `identity.json`, signed by the identity key.
    pub const IDENTITY: &str = "pubky-switch/v1/identity";
    /// Enrollment, signed by the identity key.
    pub const ENROLL: &str = "pubky-switch/v1/enroll";
    /// App request, signed by the requesting app's signing key (Switch wire 3.9).
    pub const APP_REQUEST: &str = "pubky-switch/v1/app-request";
    /// Key bundle, signed by the identity key (Switch wire 3.5).
    pub const KEY_BUNDLE: &str = "pubky-switch/v1/key-bundle";
    /// Signer hand-over, signed by the identity key (Switch wire 3.12).
    pub const SIGNER_HANDOVER: &str = "pubky-switch/v1/signer-handover";
    /// Signer backup, signed by the identity key (Switch wire 3.13).
    pub const SIGNER_BACKUP: &str = "pubky-switch/v1/signer-backup";
    /// Freeze, signed by the identity key (Switch wire 3.6).
    pub const FREEZE: &str = "pubky-switch/v1/freeze";
    /// Unfreeze, signed by the identity key (Switch wire 3.6).
    pub const UNFREEZE: &str = "pubky-switch/v1/unfreeze";
    /// Import discarded, signed by the next service's key (Switch wire 3.6).
    pub const DISCARDED: &str = "pubky-switch/v1/discarded";
    /// Export transfer, signed by the identity key (Switch wire 3.11).
    pub const EXPORT_TRANSFER: &str = "pubky-switch/v1/export-transfer";
    /// The next service's export request, signed by its key (Switch wire 7.2).
    pub const TRANSFER_REQUEST: &str = "pubky-switch/v1/transfer-request";
    /// Message, signed by the sender app (Switch wire 4.5).
    pub const MSG: &str = "pubky-switch/v1/msg";
    /// Request to the switch, signed by an app or the identity key (Switch wire 7.1).
    pub const HTTP: &str = "pubky-switch/v1/http";
    /// Response from the switch, signed by the service or operator key (Switch wire 7.1).
    pub const HTTP_RESPONSE: &str = "pubky-switch/v1/http-response";
    /// Operation, signed by its writer (Switch wire 6.1).
    pub const OP: &str = "pubky-switch/v1/op";
    /// Service transition, signed by the service key (Switch wire 6.5).
    pub const SERVICE_OP: &str = "pubky-switch/v1/service-op";
    /// Transition proof, signed by the service key (Switch wire 6.5).
    pub const PROOF: &str = "pubky-switch/v1/proof";
    /// Signed head, signed by the service key (Switch wire 6.7).
    pub const HEAD: &str = "pubky-switch/v1/head";
    /// Export manifest, signed by the old service's key (Switch wire 10.2).
    pub const EXPORT_MANIFEST: &str = "pubky-switch/v1/export-manifest";
    /// Push webhook, signed by the registration's push key (Switch wire 8.2).
    pub const PUSH: &str = "pubky-switch/v1/push";
}

/// Derivation labels and the labels that start a hashed `lp()` (Switch wire 1.5).
pub mod derive {
    /// The kid of an X25519 key.
    pub const KID: &str = "pubky-switch/v1/kid";
    /// An envelope's key commitment (Switch wire 4.3).
    pub const KEY_COMMIT: &str = "pubky-switch/v1/key-commit";
    /// HPKE `info`, the first part of its `lp()` (Switch wire 4.3).
    pub const HPKE: &str = "pubky-switch/v1/hpke";
    /// Collection IDs.
    pub const COLLECTION: &str = "pubky-switch/v1/collection";
    /// Record keys.
    pub const RECORD: &str = "pubky-switch/v1/record";
    /// Policy hashes, the first part of their `lp()`.
    pub const POLICY: &str = "pubky-switch/v1/policy";
    /// A sealed value's AAD, the first part of its `lp()` (Switch wire 6.2).
    pub const SEALED: &str = "pubky-switch/v1/sealed";
    /// The Switch root, from the identity secret.
    pub const SCOPE_ROOT: &str = "pubky-switch/v1/scope-root";
    /// Scope keys, from the Switch root.
    pub const SCOPE_KEY: &str = "pubky-switch/v1/scope-key";
    /// Sub-scope keys, from their parent scope's key.
    pub const SUB_SCOPE_KEY: &str = "pubky-switch/v1/sub-scope-key";
    /// The naming key, from the Switch root.
    pub const NAMING: &str = "pubky-switch/v1/naming";
    /// Blinded inputs, under the naming key.
    pub const NAME: &str = "pubky-switch/v1/name";
    /// The signer backup's X25519 secret, from the identity secret.
    pub const BACKUP_KEY: &str = "pubky-switch/v1/backup-key";
    /// Chain item hashes, the first part of their `lp()` (Switch wire 6.6).
    pub const ITEM: &str = "pubky-switch/v1/item";
    /// Chain hashes, the first part of their `lp()` (Switch wire 6.6).
    pub const CHAIN: &str = "pubky-switch/v1/chain";
}
