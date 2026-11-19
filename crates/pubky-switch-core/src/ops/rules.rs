//! The per-operation checks of Switch wire 6.4 step 9: the writer's permission, the shape of
//! the operation, and the rules of each type of Switch wire 6.2 that compare it with what the
//! service holds, which the caller passes in.

use serde_json::json;

use super::Refusal;
use super::body::{InviteCodePut, KeyBundlePut, OpBody, OpKind, RecordPut, carrying};
use crate::error::{Error, Result};
use crate::http::ErrorCode;
use crate::json::parse_json;
use crate::records::{
    AppCert, AppRecord, IdentityDoc, ReceiveKeyBody, ReceiveKeyRecord, check_suite_keys,
};
use crate::scopes::Permission;
use crate::sig::SignedDoc;

/// `max_invite_uses`: the most uses an `invite_code.put` names, by default (Switch wire 6.2,
/// 9.2).
pub const MAX_INVITE_USES: u64 = 100;

/// The longest invite code context, as its writer serialized it (Switch wire 6.2): else `413
/// too_large`.
pub const MAX_INVITE_CONTEXT_BYTES: usize = 1024;

/// The writer of an operation, as the service authenticated it (Switch wire 7.2).
#[derive(Clone, Copy, Debug)]
pub enum Writer<'a> {
    /// The signer, with the identity key.
    Signer,
    /// An own app, with the certificate the service checks it against.
    App(&'a AppCert),
}

/// What an operation needs of its writer (Switch wire 6.2, Switch spec 13.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Need {
    /// An app holding this switch permission.
    Permission(Permission),
    /// An app holding one of these scopes, plain `name` covering every `name:<sub>`.
    AnyScope(Vec<String>),
    /// The app itself, for its own record or receive key.
    App,
    /// The signer only.
    Signer,
}

impl Need {
    /// What `kind` needs.
    pub fn of(kind: &OpKind) -> Self {
        use crate::ops::AllowKind;
        match kind {
            OpKind::Claim(_) => Need::Permission(Permission::ClaimsWrite),
            OpKind::RecordPut(put) => {
                Need::AnyScope(put.policy.write_scopes_for(put.expected_version).to_vec())
            }
            OpKind::AllowPut {
                kind: AllowKind::Conversation,
                ..
            } => Need::Permission(Permission::ConversationAdd),
            OpKind::AllowPut { .. }
            | OpKind::AllowDelete { .. }
            | OpKind::DenyPut { .. }
            | OpKind::DenyDelete { .. } => Need::Permission(Permission::ListsManage),
            OpKind::InviteCodePut(_) | OpKind::InviteCodeDelete { .. } => {
                Need::Permission(Permission::ConversationAdd)
            }
            OpKind::AppPut { .. } | OpKind::ReceiveKeyPut { .. } => Need::App,
            OpKind::KeyBundlePut(_) | OpKind::CertPut { .. } => Need::Signer,
        }
    }
}

/// The writer's permission for an operation (Switch wire 6.4 step 9, first): the switch
/// permission or a write scope its certificate holds, and the signer-only types. The signer
/// writes only `key_bundle.put` and `cert.put`, which no app may write.
///
/// # Errors
///
/// `403 permission_missing`.
pub fn check_permission(kind: &OpKind, writer: Writer<'_>) -> std::result::Result<(), Refusal> {
    let allowed = match (Need::of(kind), writer) {
        (Need::Signer, Writer::Signer) => true,
        (Need::Signer, Writer::App(_)) | (_, Writer::Signer) => false,
        (Need::App, Writer::App(_)) => true,
        (Need::Permission(p), Writer::App(cert)) => cert.has_permission(p),
        (Need::AnyScope(scopes), Writer::App(cert)) => scopes.iter().any(|s| cert.holds_scope(s)),
    };
    if allowed {
        Ok(())
    } else {
        Err(Refusal::new(
            ErrorCode::PermissionMissing,
            format!(
                "Switch wire 6.2: {} needs a permission or scope the writer lacks",
                kind.name()
            ),
        ))
    }
}

/// An operation's shape (Switch wire 6.4 step 9, after the permission), as far as it needs
/// no state:
///
/// - `claim`: the malformed cases of Switch wire 6.8;
/// - `record.put`: write scopes sorted ascending without duplicates and at least one; the
///   sealed value's scope is the read scope and its `ct` a length the rule allows (`413`
///   past the cap); on every write the key and the
///   collection recomputed from them, the policy hash and the identity; and, at a
///   permanent policy, its rule ([`check_permanent`]);
/// - `invite_code.put`: at least one use, and its context at most 1024 bytes (`413`);
/// - `receive_key.put`: a record whose key isn't of low order and whose `suite_keys` has the
///   right form;
/// - `key_bundle.put`: `first_epoch` at most `last_epoch`, and the bundle's signature (`401
///   bad_signature`);
/// - `cert.put`: a certificate that verifies for the identity and names the target.
///
/// The body's `identity` is the account's, which [`super::SignedOp::verify`] checked.
///
/// # Errors
///
/// `400 bad_request`, `401 bad_signature` or `413 too_large`, naming the rule.
pub fn check_shape(body: &OpBody) -> std::result::Result<(), Refusal> {
    let identity = &body.identity;
    let bad = |why: &str| Err(Refusal::bad_request(format!("Switch wire 6.2: {why}")));
    match &body.kind {
        OpKind::Claim(fields) => fields.check().map(drop),
        OpKind::RecordPut(put) => {
            // A record's scopes follow the scope rule, as every scope the switch compares
            // (Switch wire 3.1 "Scope names"): another string names no scope, and would
            // reach the service's storage unchecked.
            let policy = &put.policy;
            if !crate::scopes::is_scope(&policy.read_scope) {
                return bad("record.put: read_scope isn't a scope (wire 3.1)");
            }
            if !policy
                .write_scopes
                .iter()
                .all(|s| crate::scopes::is_scope(s))
            {
                return bad("record.put: a write_scopes entry isn't a scope (wire 3.1)");
            }

            put.value_sealed.check_shape(&put.policy.read_scope)?;
            check_permanent(put, body.generation)?;
            put.check_address(identity)?;
            Ok(())
        }
        OpKind::InviteCodePut(put) => {
            if put.max_uses == 0 {
                return bad("an invite code's max_uses is at least 1");
            }
            // Measured as the writer wrote it, whitespace and escapes included, so that the
            // service and every reader count the same bytes.
            if put.context.written_len() > MAX_INVITE_CONTEXT_BYTES {
                return Err(Refusal::new(
                    ErrorCode::TooLarge,
                    "Switch wire 6.2: an invite code context over 1024 bytes as written",
                ));
            }
            Ok(())
        }
        OpKind::ReceiveKeyPut { record } => {
            let shape = || -> Result<()> {
                let value: serde_json::Value = parse_json(&record.body_bytes()?)?;
                let read: ReceiveKeyBody = serde_json::from_value(value)?;
                if crate::enc::x25519_low_order(&read.x25519) {
                    return crate::error::invalid("Switch wire 3.4: a key of low order");
                }
                if let Some(keys) = &read.suite_keys {
                    check_suite_keys(keys)?;
                }
                Ok(())
            };
            shape().map_err(|e| Refusal::bad_request(reason(e)))
        }
        OpKind::KeyBundlePut(put) => {
            // Data epochs start at 1 (Switch spec 4.3), and a part's range runs from its
            // first epoch to its last (Switch wire 3.5).
            if put.first_epoch == 0 {
                return bad("key_bundle.put: first_epoch is at least 1 (wire 3.5)");
            }
            if put.first_epoch > put.last_epoch {
                return bad("key_bundle.put: first_epoch above last_epoch");
            }
            // Each part's envelope is within the envelope cap, which bounds the epochs one
            // part holds (Switch wire 3.5 "Parts", 4.4, 7.6).
            if put.bundle.envelope().len() > crate::envelope::MAX_ENVELOPE_LEN {
                return Err(Refusal::new(
                    ErrorCode::TooLarge,
                    "Switch wire 3.5: a key bundle part's envelope over 64 KiB",
                ));
            }
            put.bundle
                .verify(identity, &put.target_app_id)
                .map_err(|e| Refusal::new(ErrorCode::BadSignature, reason(e)))
        }
        OpKind::CertPut {
            target_app_id,
            cert,
        } => {
            let checked =
                AppCert::verify(cert, identity).map_err(|e| Refusal::bad_request(reason(e)))?;
            if &checked.app_id() != target_app_id {
                return bad("cert.put: the certificate names another app");
            }
            Ok(())
        }
        OpKind::AllowPut { .. }
        | OpKind::AllowDelete { .. }
        | OpKind::DenyPut { .. }
        | OpKind::DenyDelete { .. }
        | OpKind::InviteCodeDelete { .. }
        | OpKind::AppPut { .. } => Ok(()),
    }
}

/// The rule of a permanent policy (Switch wire 6.2 "Permanent policies", Switch spec
/// 10.3.1), for a `record.put` signed for `generation`, its operation's own: a delete (its
/// `ct` the 16-byte tag alone) only when `generation` is above the generation the policy
/// names, so never when it names none; a create (`expected_version` `{0, 0}`) only in the
/// generation the policy names, when it names one. An ordinary policy passes.
///
/// It reads the operation alone, so the service ([`check_shape`]), a recovery upload's
/// check, an import, an app before it sends and a reader all judge one write alike.
///
/// # Errors
///
/// `400 bad_request`, naming the rule.
pub fn check_permanent(put: &RecordPut, generation: u64) -> std::result::Result<(), Refusal> {
    let Some(permanent) = put.policy.permanent else {
        return Ok(());
    };
    if put.value_sealed.looks_like_delete()
        && permanent.generation.is_none_or(|named| generation <= named)
    {
        return Err(Refusal::bad_request(
            "Switch wire 6.2: a delete at a permanent policy, in a generation it doesn't pass",
        ));
    }
    if put.expected_version.is_none()
        && permanent
            .generation
            .is_some_and(|named| named != generation)
    {
        return Err(Refusal::bad_request(
            "Switch wire 6.2: a create at a permanent policy, in another generation than it names",
        ));
    }
    Ok(())
}

fn reason(error: Error) -> String {
    match error {
        Error::Invalid(why) | Error::Signature(why) | Error::Crypto(why) => why,
    }
}

/// What an `app.put` does (Switch wire 6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppPutEffect {
    /// The service holds no record for the app: the record is its first.
    New,
    /// A record with a later `updated_at` replaces the held one.
    Replaces,
    /// The held record, byte for byte (Switch wire 6.4 "No-ops").
    Unchanged,
}

/// The rules of `app.put` (Switch wire 6.2) for a record the service verified (Switch wire
/// 7.2): for the calling app only; its certificate the one the newest `identity.json` lists
/// for it (`listed_cert`); the held record again, byte for byte, is unchanged; any other
/// record has a later `updated_at` than the held one.
///
/// # Errors
///
/// `400` for another app's record, `403 not_current` for a certificate `identity.json`
/// doesn't list, `409 conflict` with `current: { "record": <the held signed record> }` for a
/// record that isn't later.
pub fn check_app_put(
    app_id: &[u8; 16],
    record: &AppRecord,
    listed_cert: Option<[u8; 32]>,
    held: Option<&AppRecord>,
) -> std::result::Result<AppPutEffect, Refusal> {
    if &record.cert().app_id() != app_id {
        return Err(Refusal::bad_request(
            "Switch wire 6.2: app.put is for the calling app only",
        ));
    }
    if listed_cert != Some(record.cert().hash()) {
        return Err(Refusal::new(
            ErrorCode::NotCurrent,
            "Switch wire 6.2: the record's certificate isn't the one identity.json lists",
        ));
    }
    let Some(held) = held else {
        return Ok(AppPutEffect::New);
    };
    if held.signed() == record.signed() {
        return Ok(AppPutEffect::Unchanged);
    }
    if record.updated_at() > held.updated_at() {
        return Ok(AppPutEffect::Replaces);
    }
    Err(Refusal::conflict(
        "Switch wire 6.2: the record's updated_at isn't later than the held one's",
    )
    .with_current(json!({ "record": signed_value(held.signed()) })))
}

/// A signed document's carrying form as a JSON value.
fn signed_value(doc: &SignedDoc) -> serde_json::Value {
    serde_json::from_slice(&carrying(doc)).unwrap_or(serde_json::Value::Null)
}

/// What a `receive_key.put` does (Switch wire 6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveKeyEffect {
    /// A new registration.
    Registers,
    /// The current record again, byte for byte (Switch wire 6.4 "No-ops").
    Unchanged,
}

/// The rules of `receive_key.put` (Switch wire 6.2, Switch spec 3.6) for a record verified
/// against the calling app's certificate:
///
/// - the app delivered its record before, or earlier in the batch (`has_app_record`), else
///   `400`;
/// - the current record again, byte for byte, is unchanged;
/// - the first record has `n` 0, or any `n` at an account recovering from a provider loss
///   (`recovering`); each later one exactly one more than the current one; else `409
///   conflict` with `current.receive_key`, the current record or `null`;
/// - a kid any app registered already (`kid_registered`) is `400`.
///
/// # Errors
///
/// As above.
pub fn check_receive_key_put(
    record: &ReceiveKeyRecord,
    current: Option<&ReceiveKeyRecord>,
    has_app_record: bool,
    recovering: bool,
    kid_registered: bool,
) -> std::result::Result<ReceiveKeyEffect, Refusal> {
    if !has_app_record {
        return Err(Refusal::bad_request(
            "Switch wire 6.2: receive_key.put before the app's app.put",
        ));
    }
    if current.is_some_and(|c| c.signed() == record.signed()) {
        return Ok(ReceiveKeyEffect::Unchanged);
    }
    let follows = record.follows(current) || (current.is_none() && recovering);
    if !follows {
        let held = current.map_or(serde_json::Value::Null, |c| signed_value(c.signed()));
        return Err(
            Refusal::conflict("Switch wire 6.2: the receive key's n isn't the next one")
                .with_current(json!({ "receive_key": held })),
        );
    }
    if kid_registered {
        return Err(Refusal::bad_request(
            "Switch spec 3.6: the kid is registered already in the account",
        ));
    }
    Ok(ReceiveKeyEffect::Registers)
}

/// What a `cert.put` does (Switch wire 6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertPutEffect {
    /// The renewed certificate is stored, replacing one stored before.
    Stores,
    /// The stored renewed certificate, or without one the record's, again byte for byte
    /// (Switch wire 6.4 "No-ops").
    Unchanged,
}

/// Whether `app_id` is a target of the signer's `cert.put` and `key_bundle.put` (Switch wire
/// 6.2, 3.8; Switch spec 3.2): an app the newest `identity.json` the service holds
/// (`newest`) lists in `apps`, and that the service holds neither revoked nor departed
/// (`withdrawn`). Its certificate's expiry doesn't count, nor does the standing of the
/// certificate its record carries: the signer's renewal brings an app whose certificate has
/// expired back without anything from the app, and its first step stores the new
/// certificate and key bundle before the delivery that lists the new certificate. An app the
/// document lists in `removed`, or in neither list, isn't one.
pub fn is_signer_target(newest: Option<&IdentityDoc>, app_id: &[u8; 16], withdrawn: bool) -> bool {
    !withdrawn && newest.is_some_and(|doc| doc.listed_cert(app_id).is_some())
}

/// The rules of `cert.put` (Switch wire 6.2, 3.8) for a certificate [`check_shape`] verified:
///
/// - the target is the signer's ([`is_signer_target`], whatever its certificate's expiry)
///   and delivered its record (`record_cert`, the certificate its record carries), else
///   `404`;
/// - the stored renewed certificate, or without one the record's, again is unchanged;
/// - it keeps the record's certificate's signing and bundle keys, else `400`;
/// - its `issued_at` is later than the record's certificate's and any stored renewed one's,
///   else `409 conflict`.
///
/// # Errors
///
/// As above.
pub fn check_cert_put(
    cert: &AppCert,
    record_cert: Option<&AppCert>,
    newest: Option<&IdentityDoc>,
    withdrawn: bool,
    stored_renewed: Option<&AppCert>,
) -> std::result::Result<CertPutEffect, Refusal> {
    let target = is_signer_target(newest, &cert.app_id(), withdrawn);
    let Some(record_cert) = record_cert.filter(|_| target) else {
        return Err(Refusal::new(
            ErrorCode::NotFound,
            "Switch wire 6.2: cert.put for an app the service doesn't serve",
        ));
    };
    let unchanged_against = stored_renewed.unwrap_or(record_cert);
    if unchanged_against.signed() == cert.signed() {
        return Ok(CertPutEffect::Unchanged);
    }
    if !cert.same_app_and_keys(record_cert) {
        return Err(Refusal::bad_request(
            "Switch wire 6.2: a renewed certificate keeps the app's signing and bundle keys",
        ));
    }
    let latest = stored_renewed.map_or(record_cert.issued_at(), |r| {
        r.issued_at().max(record_cert.issued_at())
    });
    if cert.issued_at() <= latest {
        return Err(Refusal::conflict(
            "Switch wire 6.2: cert.put isn't issued after the certificate it renews",
        ));
    }
    Ok(CertPutEffect::Stores)
}

/// What a `key_bundle.put` does (Switch wire 6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyBundleEffect {
    /// The part is stored, replacing the stored parts at these indexes, whose ranges it
    /// overlaps, so that the stored parts never overlap.
    Stores {
        /// Indexes into the stored parts.
        replaces: Vec<usize>,
    },
    /// A part stored already with the same epochs, byte for byte (Switch wire 6.4 "No-ops").
    Unchanged,
}

/// The rules of `key_bundle.put` (Switch wire 6.2): the target is the signer's
/// ([`is_signer_target`], whatever its certificate's expiry), else `403 not_current`; a part
/// identical to one stored, with the same epochs, changes nothing; a new
/// part replaces every stored part whose range it overlaps. Which parts the target's cursor
/// lets go is the service's to decide.
///
/// # Errors
///
/// `403 not_current`.
pub fn check_key_bundle_put(
    put: &KeyBundlePut,
    newest: Option<&IdentityDoc>,
    withdrawn: bool,
    stored: &[KeyBundlePut],
) -> std::result::Result<KeyBundleEffect, Refusal> {
    if !is_signer_target(newest, &put.target_app_id, withdrawn) {
        return Err(Refusal::new(
            ErrorCode::NotCurrent,
            "Switch wire 6.2: key_bundle.put for an app identity.json doesn't list, or one revoked or departed",
        ));
    }
    if stored.iter().any(|part| part == put) {
        return Ok(KeyBundleEffect::Unchanged);
    }
    let replaces = stored
        .iter()
        .enumerate()
        .filter(|(_, part)| {
            part.first_epoch <= put.last_epoch && put.first_epoch <= part.last_epoch
        })
        .map(|(i, _)| i)
        .collect();
    Ok(KeyBundleEffect::Stores { replaces })
}

/// The rules of `invite_code.put` that need the service's settings and state (Switch wire
/// 6.2): `max_uses` at most the service's `max_invite_uses`, else `400`; a code hash
/// registered already is `409 conflict`.
///
/// # Errors
///
/// As above.
pub fn check_invite_code_put(
    put: &InviteCodePut,
    max_invite_uses: u64,
    registered: bool,
) -> std::result::Result<(), Refusal> {
    if put.max_uses == 0 || put.max_uses > max_invite_uses {
        return Err(Refusal::bad_request(
            "Switch wire 6.2: max_uses is 1 to the service's max_invite_uses",
        ));
    }
    if registered {
        return Err(Refusal::conflict(
            "Switch wire 6.2: the invite code is registered already",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::{ClaimFields, ClaimType};
    use crate::ident::{NamingKey, Policy, collection_id, record_key_from_blinded};
    use crate::keys::{AppKeys, ReceiveKey};
    use crate::ops::body::{BatchRef, IdInputs, InviteContext, RecordPut, RecordVersion};
    use crate::records::KeyBundle;
    use crate::records::{AppCertBody, AppRecordBody, DEFAULT_CERT_LIFETIME_MS};
    use crate::sealed::SealedValue;

    const ISSUED: u64 = 1_767_225_600_000;

    fn identity() -> crate::keys::IdentityKey {
        crate::keys::IdentityKey::from_secret([1; 32])
    }

    fn app() -> AppKeys {
        AppKeys::from_secrets([2; 32], [3; 32])
    }

    fn cert_at(issued: u64, permissions: &[Permission]) -> AppCert {
        let a = app();
        let body = AppCertBody::new(
            identity().public(),
            a.signing_public(),
            a.bundle_public(),
            vec!["scope-a".into()],
            permissions,
            issued,
            issued + DEFAULT_CERT_LIFETIME_MS,
        );
        AppCert::issue(&identity(), body).unwrap()
    }

    /// An `identity.json` of the identity listing `app_id` with the certificate `cert`.
    fn listing_app(app_id: [u8; 16], cert: [u8; 32]) -> IdentityDoc {
        use crate::records::{IdentityBody, IdentityPolicy, Inbox, ListedApp};
        let mut body = IdentityBody::first(
            identity().public(),
            [9; 16],
            Inbox::new("https://switch.example", [4; 32]),
            IdentityPolicy::default(),
        );
        body.apps.push(ListedApp { app_id, cert });
        IdentityDoc::sign(&identity(), body).unwrap()
    }

    /// An `identity.json` listing `cert`'s app with it.
    fn listing(cert: &AppCert) -> IdentityDoc {
        listing_app(cert.app_id(), cert.hash())
    }

    fn cert() -> AppCert {
        cert_at(
            ISSUED,
            &[Permission::ClaimsWrite, Permission::ConversationAdd],
        )
    }

    fn body(kind: OpKind) -> OpBody {
        OpBody {
            identity: identity().public(),
            app_id: Some(app().app_id_bytes()),
            generation: 1,
            batch: BatchRef {
                id: [7; 16],
                count: 1,
            },
            conditions: Vec::new(),
            kind,
        }
    }

    fn record_put(expected: RecordVersion) -> RecordPut {
        let id = identity();
        let naming = NamingKey::from_root(&id.switch_root());
        let policy = Policy::new("scope-a", &["scope-a"]);
        let blinded = naming.blind(b"natural");
        let key = record_key_from_blinded("sample.collection", &blinded, &policy.hash().unwrap());
        let scope_key = id.scope_key(1, "scope-a");
        let sealed =
            SealedValue::seal(&scope_key, &id.public(), 1, "scope-a", &key, b"{}").unwrap();
        RecordPut {
            key,
            collection: collection_id("sample.collection", &id.public()),
            policy,
            expected_version: expected,
            value_sealed: sealed,
            id_inputs: IdInputs {
                collection: "sample.collection".into(),
                blinded_key: blinded,
            },
        }
    }

    #[test]
    fn test_permission_by_type_and_writer() {
        let writes = cert();
        let reads = cert_at(ISSUED, &[Permission::ClaimsRead]);
        let claim = OpKind::Claim(ClaimFields {
            claim_key: vec![1; 32],
            kind: ClaimType::Failed,
            expected_step: 1,
            attempt_id: vec![1; 16],
            orphan_after: None,
            deadline: None,
            basis: None,
            evidence_ref: None,
        });
        assert!(check_permission(&claim, Writer::App(&writes)).is_ok());
        let refused = check_permission(&claim, Writer::App(&reads)).unwrap_err();
        assert_eq!(refused.code, ErrorCode::PermissionMissing);
        assert!(check_permission(&claim, Writer::Signer).is_err());
        let put = OpKind::RecordPut(record_put(RecordVersion::NONE));
        assert!(check_permission(&put, Writer::App(&writes)).is_ok());
        let cert_put = OpKind::CertPut {
            target_app_id: [1; 16],
            cert: writes.signed().clone(),
        };
        assert!(check_permission(&cert_put, Writer::Signer).is_ok());
        assert!(check_permission(&cert_put, Writer::App(&writes)).is_err());
        let conversation = OpKind::AllowPut {
            pubky: [1; 32],
            kind: crate::ops::AllowKind::Conversation,
        };
        assert!(check_permission(&conversation, Writer::App(&writes)).is_ok());
        let removal = OpKind::AllowDelete {
            pubky: [1; 32],
            kind: crate::ops::AllowKind::Conversation,
        };
        assert!(check_permission(&removal, Writer::App(&writes)).is_err());
        // The signer writes key_bundle.put and cert.put only: every other type it signs is
        // 403 permission_missing.
        let record =
            AppRecord::sign(&app(), AppRecordBody::new(&writes, Vec::new(), ISSUED)).unwrap();
        for kind in [
            claim.clone(),
            put.clone(),
            conversation.clone(),
            removal.clone(),
            OpKind::DenyPut { pubky: [1; 32] },
            OpKind::DenyDelete { pubky: [1; 32] },
            OpKind::InviteCodePut(InviteCodePut {
                code_hash: [1; 32],
                expires_at: ISSUED,
                max_uses: 1,
                context: InviteContext::new(json!(null)),
            }),
            OpKind::InviteCodeDelete { code_hash: [1; 32] },
            OpKind::AppPut {
                record: record.signed().clone(),
            },
            OpKind::ReceiveKeyPut {
                record: record.signed().clone(),
            },
        ] {
            let refused = check_permission(&kind, Writer::Signer).unwrap_err();
            assert_eq!(
                refused.code,
                ErrorCode::PermissionMissing,
                "{}",
                kind.name()
            );
        }
    }

    /// A `record.put` at the policy `scope-a` / `scope-a` made permanent naming `named`,
    /// signed for `generation`: built on `expected`, its key derived for that policy, and a
    /// delete when `delete`.
    fn permanent_body(
        named: Option<Option<u64>>,
        generation: u64,
        expected: RecordVersion,
        delete: bool,
    ) -> OpBody {
        let id = identity();
        let mut put = record_put(expected);
        if let Some(named) = named {
            put.policy = put.policy.permanent(named);
        }
        let blinded = NamingKey::from_root(&id.switch_root()).blind(b"natural");
        put.key =
            record_key_from_blinded("sample.collection", &blinded, &put.policy.hash().unwrap());
        let value: &[u8] = if delete { b"" } else { b"{}" };
        put.value_sealed = SealedValue::seal(
            &id.scope_key(1, "scope-a"),
            &id.public(),
            1,
            "scope-a",
            &put.key,
            value,
        )
        .unwrap();
        let mut body = body(OpKind::RecordPut(put));
        body.generation = generation;
        body
    }

    #[test]
    fn test_permanent_rule_by_generation() {
        let create = RecordVersion::NONE;
        let update = RecordVersion::new(1, 6);
        // (policy, operation generation, expected_version, delete, taken)
        let cases = [
            (None, 1, update, true, true),
            (Some(None), 1, create, false, true),
            (Some(None), 7, create, false, true),
            (Some(None), 1, update, false, true),
            (Some(None), 1, update, true, false),
            (Some(None), 9, update, true, false),
            (Some(None), 1, create, true, false),
            (Some(Some(2)), 2, create, false, true),
            (Some(Some(2)), 1, create, false, false),
            (Some(Some(2)), 3, create, false, false),
            (Some(Some(2)), 3, update, false, true),
            (Some(Some(2)), 2, update, true, false),
            (Some(Some(2)), 1, update, true, false),
            (Some(Some(2)), 3, update, true, true),
        ];
        for (named, generation, expected, delete, taken) in cases {
            let body = permanent_body(named, generation, expected, delete);
            let outcome = check_shape(&body);
            let case = format!("{named:?} at {generation}, {expected:?}, delete {delete}");
            match outcome {
                Ok(()) => assert!(taken, "{case}"),
                Err(refused) => {
                    assert!(!taken, "{case}: {refused}");
                    assert_eq!(refused.code, ErrorCode::BadRequest, "{case}");
                }
            }
            let OpKind::RecordPut(put) = &body.kind else {
                unreachable!()
            };
            assert_eq!(check_permanent(put, generation).is_ok(), taken, "{case}");
        }
    }

    #[test]
    fn test_permanent_generation_above_the_integer_range_isnt_signed() {
        // A writer refuses to sign an `int` above 2^53 - 1 (Switch wire 1.1), the
        // generation a permanent policy names among them.
        let update = RecordVersion::new(1, 6);
        let largest = permanent_body(Some(Some(crate::json::MAX_INT)), 1, update, false);
        assert!(crate::ops::SignedOp::sign(&app(), largest).is_ok());
        let above = permanent_body(Some(Some(crate::json::MAX_INT + 1)), 1, update, false);
        assert!(matches!(
            crate::ops::SignedOp::sign(&app(), above),
            Err(Error::Invalid(why)) if why.contains("2^53 - 1")
        ));
    }

    #[test]
    fn test_permanent_member_read_strictly() {
        let body = permanent_body(Some(Some(4)), 4, RecordVersion::NONE, false);
        let bytes = body.to_json().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        let member = r#""permanent":{"generation":4}"#;
        assert!(text.contains(&format!(
            r#""write_scopes":["scope-a"],{member},"expected_version""#
        )));
        assert_eq!(OpBody::parse(&bytes).unwrap(), body);
        let none = permanent_body(Some(None), 4, RecordVersion::NONE, false);
        let none_bytes = none.to_json().unwrap();
        assert!(
            String::from_utf8_lossy(&none_bytes).contains(r#""permanent":{"generation":null}"#)
        );
        assert_eq!(OpBody::parse(&none_bytes).unwrap(), none);
        for refused in [
            r#""permanent":null"#,
            r#""permanent":{}"#,
            r#""permanent":{"generation":4,"other":1}"#,
            r#""permanent":{"generation":"4"}"#,
            r#""permanent":[4]"#,
        ] {
            let changed = text.replace(member, refused);
            assert!(OpBody::parse(changed.as_bytes()).is_err(), "{refused}");
        }
        // Generation 0 reads, but names no generation: its hash, and so the shape, refuse it.
        let zero = OpBody::parse(
            text.replace(member, r#""permanent":{"generation":0}"#)
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(check_shape(&zero).unwrap_err().code, ErrorCode::BadRequest);
    }

    #[test]
    fn test_shape_of_a_record_put_scopes() {
        let with = |read: &str, writes: &[&str]| {
            let mut put = record_put(RecordVersion::new(1, 6));
            put.policy = Policy::new(read, writes);
            put.key = record_key_from_blinded(
                &put.id_inputs.collection,
                &put.id_inputs.blinded_key,
                &put.policy.hash().unwrap(),
            );
            let id = identity();
            put.value_sealed = SealedValue::seal(
                &id.scope_key(1, read),
                &id.public(),
                1,
                read,
                &put.key,
                b"{}",
            )
            .unwrap();
            check_shape(&body(OpKind::RecordPut(put)))
        };
        assert!(with("notes", &["notes", "notes:a"]).is_ok());
        for (read, writes) in [
            ("no\u{0}tes", &["notes"][..]),
            ("", &["notes"]),
            ("Notes", &["notes"]),
            ("notes:", &["notes"]),
            ("notes", &["notes", "bad scope"]),
            ("notes", &["no\u{0}tes"]),
            ("notes", &["notes:A"]),
        ] {
            let refused = with(read, writes).unwrap_err();
            assert_eq!(refused.code, ErrorCode::BadRequest, "{read:?} {writes:?}");
        }
    }

    #[test]
    fn test_record_put_requires_named_inputs_and_a_valid_create_scope() {
        let mut put = record_put(RecordVersion::NONE);
        put.policy = put.policy.with_create_scope("tasks_create");
        let op = body(OpKind::RecordPut(put));
        let bytes = op.to_json().unwrap();
        assert_eq!(OpBody::parse(&bytes).unwrap(), op);
        let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["create_scope"] = serde_json::Value::Null;
        assert!(OpBody::parse(&serde_json::to_vec(&json).unwrap()).is_err());
        json["create_scope"] = serde_json::json!("tasks_create");
        json.as_object_mut().unwrap().remove("id_inputs");
        assert!(OpBody::parse(&serde_json::to_vec(&json).unwrap()).is_err());
    }

    #[test]
    fn test_shape_of_a_record_put() {
        for expected in [RecordVersion::NONE, RecordVersion::new(1, 6)] {
            let put = record_put(expected);
            assert!(check_shape(&body(OpKind::RecordPut(put.clone()))).is_ok());
            let mut wrong_name = put.clone();
            wrong_name.id_inputs.collection.push('x');
            assert!(check_shape(&body(OpKind::RecordPut(wrong_name))).is_err());
            let mut wrong_blind = put;
            wrong_blind.id_inputs.blinded_key[0] ^= 1;
            assert!(check_shape(&body(OpKind::RecordPut(wrong_blind))).is_err());
        }
        let mut other_key = record_put(RecordVersion::NONE);
        other_key.key[0] ^= 1;
        assert!(check_shape(&body(OpKind::RecordPut(other_key))).is_err());
        let mut unsorted = record_put(RecordVersion::new(1, 6));
        unsorted.policy.write_scopes = vec!["scope-b".into(), "scope-a".into()];
        assert!(check_shape(&body(OpKind::RecordPut(unsorted))).is_err());
        let mut big = record_put(RecordVersion::new(1, 6));
        big.value_sealed.ct = vec![0; crate::sealed::MAX_CT_LEN + 1];
        assert_eq!(
            check_shape(&body(OpKind::RecordPut(big)))
                .unwrap_err()
                .status(),
            413
        );
        let mut scope = record_put(RecordVersion::new(1, 6));
        scope.value_sealed.scope = "scope-b".into();
        assert!(check_shape(&body(OpKind::RecordPut(scope))).is_err());
    }

    #[test]
    fn test_shape_of_an_invite_and_a_bundle() {
        let invite = |uses: u64, context: serde_json::Value| {
            OpKind::InviteCodePut(InviteCodePut {
                code_hash: [1; 32],
                expires_at: ISSUED,
                max_uses: uses,
                context: InviteContext::new(context),
            })
        };
        assert!(check_shape(&body(invite(1, json!({"ref": "x"})))).is_ok());
        assert_eq!(
            check_shape(&body(invite(0, json!(null))))
                .unwrap_err()
                .status(),
            400
        );
        let long = json!("x".repeat(1100));
        assert_eq!(
            check_shape(&body(invite(1, long))).unwrap_err().status(),
            413
        );
        // Measured as written in the signed body: 1,024 bytes pass, and a context whose
        // whitespace takes it past 1,024 bytes is refused, though compacted it would pass.
        let at_limit = |pad: usize| {
            let written = format!(r#"{{{}"ref":"{}"}}"#, " ".repeat(pad), "x".repeat(1000));
            let text = String::from_utf8(body(invite(1, json!({}))).to_json().unwrap())
                .unwrap()
                .replace(r#""context":{}"#, &format!(r#""context":{written}"#));
            OpBody::parse(text.as_bytes()).unwrap()
        };
        let compact_len = 1000 + r#"{"ref":""}"#.len();
        let fits = at_limit(MAX_INVITE_CONTEXT_BYTES - compact_len);
        assert!(check_shape(&fits).is_ok());
        let over = at_limit(MAX_INVITE_CONTEXT_BYTES - compact_len + 1);
        let OpKind::InviteCodePut(put) = &over.kind else {
            unreachable!()
        };
        assert_eq!(put.context.written_len(), MAX_INVITE_CONTEXT_BYTES + 1);
        assert!(serde_json::to_vec(put.context.value()).unwrap().len() < MAX_INVITE_CONTEXT_BYTES);
        assert_eq!(check_shape(&over).unwrap_err().status(), 413);
        let id = identity();
        let target = [5u8; 16];
        let envelope = vec![1u8, 2, 3];
        let sig = id.sign(
            crate::labels::sig::KEY_BUNDLE,
            &[&id.public(), &target, &envelope],
        );
        let mut put = KeyBundlePut {
            target_app_id: target,
            bundle: KeyBundle::from_parts(envelope, sig),
            first_epoch: 1,
            last_epoch: 2,
        };
        let mut signer = body(OpKind::KeyBundlePut(put.clone()));
        signer.app_id = None;
        assert!(check_shape(&signer).is_ok());
        put.first_epoch = 3;
        signer.kind = OpKind::KeyBundlePut(put.clone());
        assert_eq!(check_shape(&signer).unwrap_err().status(), 400);
        // Data epochs start at 1: a range from 0 is refused, whatever its last epoch.
        for last in [0, 2] {
            put.first_epoch = 0;
            put.last_epoch = last;
            signer.kind = OpKind::KeyBundlePut(put.clone());
            assert_eq!(
                check_shape(&signer).unwrap_err().status(),
                400,
                "0 to {last}"
            );
        }
        put.last_epoch = 2;
        put.first_epoch = 1;
        // A part's envelope is within the envelope cap: at it, taken; one byte over, 413.
        for (len, status) in [
            (crate::envelope::MAX_ENVELOPE_LEN, None),
            (crate::envelope::MAX_ENVELOPE_LEN + 1, Some(413)),
        ] {
            let envelope = vec![1u8; len];
            let sig = id.sign(
                crate::labels::sig::KEY_BUNDLE,
                &[&id.public(), &target, &envelope],
            );
            let mut large = put.clone();
            large.bundle = KeyBundle::from_parts(envelope, sig);
            signer.kind = OpKind::KeyBundlePut(large);
            assert_eq!(
                check_shape(&signer).err().map(|r| r.status()),
                status,
                "{len}"
            );
        }
        put.target_app_id = [6; 16];
        signer.kind = OpKind::KeyBundlePut(put);
        assert_eq!(check_shape(&signer).unwrap_err().status(), 401);
    }

    #[test]
    fn test_shape_of_a_cert_put_and_a_receive_key() {
        let c = cert();
        let mut signer = body(OpKind::CertPut {
            target_app_id: c.app_id(),
            cert: c.signed().clone(),
        });
        signer.app_id = None;
        assert!(check_shape(&signer).is_ok());
        signer.kind = OpKind::CertPut {
            target_app_id: [9; 16],
            cert: c.signed().clone(),
        };
        assert_eq!(check_shape(&signer).unwrap_err().status(), 400);
        let key = ReceiveKey::from_secret(0, [9; 32]);
        let record = ReceiveKeyRecord::sign(&app(), &c, ReceiveKeyBody::new(&c, &key)).unwrap();
        assert!(
            check_shape(&body(OpKind::ReceiveKeyPut {
                record: record.signed().clone()
            }))
            .is_ok()
        );
        let mut low = ReceiveKeyBody::new(&c, &key);
        low.x25519 = [0; 32];
        let doc = app().sign_doc(crate::labels::sig::RECEIVE_KEY, &[], low.to_json().unwrap());
        assert_eq!(
            check_shape(&body(OpKind::ReceiveKeyPut { record: doc }))
                .unwrap_err()
                .status(),
            400
        );
    }

    fn app_record(updated_at: u64, label: Option<&str>) -> AppRecord {
        let mut b = AppRecordBody::new(&cert(), Vec::new(), updated_at);
        b.label = label.map(str::to_owned);
        AppRecord::sign(&app(), b).unwrap()
    }

    #[test]
    fn test_app_put_rules() {
        let a = app().app_id_bytes();
        let held = app_record(ISSUED, None);
        let listed = Some(cert().hash());
        assert_eq!(
            check_app_put(&a, &held, listed, None).unwrap(),
            AppPutEffect::New
        );
        assert_eq!(
            check_app_put(&a, &held, listed, Some(&held)).unwrap(),
            AppPutEffect::Unchanged
        );
        let later = app_record(ISSUED + 1, None);
        assert_eq!(
            check_app_put(&a, &later, listed, Some(&held)).unwrap(),
            AppPutEffect::Replaces
        );
        let same_time = app_record(ISSUED, Some("other"));
        let refused = check_app_put(&a, &same_time, listed, Some(&held)).unwrap_err();
        assert_eq!(refused.status(), 409);
        assert_eq!(refused.current.unwrap()["record"]["sig"], held.signed().sig);
        assert_eq!(
            check_app_put(&a, &held, None, None).unwrap_err().code,
            ErrorCode::NotCurrent
        );
        assert_eq!(
            check_app_put(&[0; 16], &held, listed, None)
                .unwrap_err()
                .status(),
            400
        );
    }

    #[test]
    fn test_receive_key_put_rules() {
        let c = cert();
        let record = |n: u64| {
            let key = ReceiveKey::from_secret(n, [n as u8 + 9; 32]);
            ReceiveKeyRecord::sign(&app(), &c, ReceiveKeyBody::new(&c, &key)).unwrap()
        };
        let (first, second, third) = (record(0), record(1), record(2));
        assert_eq!(
            check_receive_key_put(&first, None, true, false, false).unwrap(),
            ReceiveKeyEffect::Registers
        );
        assert!(check_receive_key_put(&first, None, false, false, false).is_err());
        assert_eq!(
            check_receive_key_put(&first, Some(&first), true, false, false).unwrap(),
            ReceiveKeyEffect::Unchanged
        );
        assert!(check_receive_key_put(&second, Some(&first), true, false, false).is_ok());
        let refused = check_receive_key_put(&third, Some(&first), true, false, false).unwrap_err();
        assert_eq!(refused.status(), 409);
        assert!(refused.current.unwrap()["receive_key"].is_object());
        let refused = check_receive_key_put(&third, None, true, false, false).unwrap_err();
        assert_eq!(
            refused.current.unwrap()["receive_key"],
            serde_json::Value::Null
        );
        assert!(check_receive_key_put(&third, None, true, true, false).is_ok());
        assert_eq!(
            check_receive_key_put(&second, Some(&first), true, false, true)
                .unwrap_err()
                .status(),
            400
        );
    }

    #[test]
    fn test_cert_put_rules() {
        let old = cert();
        let doc = listing(&old);
        let doc = Some(&doc);
        let renewed = cert_at(ISSUED + 1, &[Permission::ClaimsWrite]);
        assert_eq!(
            check_cert_put(&renewed, Some(&old), doc, false, None).unwrap(),
            CertPutEffect::Stores
        );
        assert_eq!(
            check_cert_put(&old, Some(&old), doc, false, None).unwrap(),
            CertPutEffect::Unchanged
        );
        assert_eq!(
            check_cert_put(&renewed, Some(&old), doc, false, Some(&renewed)).unwrap(),
            CertPutEffect::Unchanged
        );
        assert_eq!(
            check_cert_put(&renewed, None, doc, false, None)
                .unwrap_err()
                .status(),
            404
        );
        assert_eq!(
            check_cert_put(&renewed, Some(&old), doc, true, None)
                .unwrap_err()
                .status(),
            404
        );
        let earlier = cert_at(ISSUED - 1, &[Permission::ClaimsWrite]);
        assert_eq!(
            check_cert_put(&earlier, Some(&old), doc, false, None)
                .unwrap_err()
                .status(),
            409
        );
        let newer = cert_at(ISSUED + 2, &[Permission::ClaimsRead]);
        assert_eq!(
            check_cert_put(&old, Some(&old), doc, false, Some(&newer))
                .unwrap_err()
                .status(),
            409
        );
        // Other keys make a new app.
        let other = AppKeys::from_secrets([2; 32], [8; 32]);
        let moved = AppCertBody::new(
            identity().public(),
            other.signing_public(),
            other.bundle_public(),
            vec!["scope-a".into()],
            &[Permission::ClaimsWrite],
            ISSUED + 3,
            ISSUED + 3 + DEFAULT_CERT_LIFETIME_MS,
        );
        let moved = AppCert::issue(&identity(), moved).unwrap();
        assert_eq!(
            check_cert_put(&moved, Some(&old), doc, false, None)
                .unwrap_err()
                .status(),
            400
        );
    }

    #[test]
    fn test_signer_target_whatever_the_certificate_expiry() {
        use crate::records::{IdentityBody, RemovedApp};
        let old = cert();
        let app_id = old.app_id();
        let listed = listing(&old);
        // Listed, with the certificate the record carries, expired or not: the expiry isn't
        // judged here, nor which certificate the document lists.
        assert!(is_signer_target(Some(&listed), &app_id, false));
        let renewed = cert_at(ISSUED + 1, &[Permission::ClaimsWrite]);
        let relisted = listing(&renewed);
        assert!(is_signer_target(Some(&relisted), &app_id, false));
        // Revoked or departed at the service, in `removed`, in neither list, or no document.
        assert!(!is_signer_target(Some(&listed), &app_id, true));
        let mut body: IdentityBody = listed.body().clone();
        body.version += 1;
        body.apps.clear();
        let neither = IdentityDoc::sign(&identity(), body.clone()).unwrap();
        assert!(!is_signer_target(Some(&neither), &app_id, false));
        body.removed.push(RemovedApp {
            app_id,
            distrust_from: ISSUED,
        });
        let removed = IdentityDoc::sign(&identity(), body).unwrap();
        assert!(!is_signer_target(Some(&removed), &app_id, false));
        assert!(!is_signer_target(None, &app_id, false));
        // Both signer operations follow it: a renewal's batch is taken for an expired app,
        // and refused for a removed one.
        let put = KeyBundlePut {
            target_app_id: app_id,
            bundle: KeyBundle::from_parts(vec![1], [1; 64]),
            first_epoch: 1,
            last_epoch: 1,
        };
        assert!(check_cert_put(&renewed, Some(&old), Some(&listed), false, None).is_ok());
        assert!(check_key_bundle_put(&put, Some(&listed), false, &[]).is_ok());
        assert_eq!(
            check_cert_put(&renewed, Some(&old), Some(&removed), false, None)
                .unwrap_err()
                .status(),
            404
        );
        assert_eq!(
            check_key_bundle_put(&put, Some(&removed), false, &[])
                .unwrap_err()
                .code,
            ErrorCode::NotCurrent
        );
    }

    #[test]
    fn test_key_bundle_put_rules() {
        let part = |first: u64, last: u64, byte: u8| KeyBundlePut {
            target_app_id: [5; 16],
            bundle: KeyBundle::from_parts(vec![byte], [byte; 64]),
            first_epoch: first,
            last_epoch: last,
        };
        let stored = vec![part(1, 2, 1), part(3, 4, 2), part(5, 6, 3)];
        let doc = listing_app([5; 16], [6; 32]);
        let doc = Some(&doc);
        assert_eq!(
            check_key_bundle_put(&part(3, 4, 2), doc, false, &stored).unwrap(),
            KeyBundleEffect::Unchanged
        );
        assert_eq!(
            check_key_bundle_put(&part(2, 3, 9), doc, false, &stored).unwrap(),
            KeyBundleEffect::Stores {
                replaces: vec![0, 1]
            }
        );
        assert_eq!(
            check_key_bundle_put(&part(7, 7, 9), doc, false, &stored).unwrap(),
            KeyBundleEffect::Stores { replaces: vec![] }
        );
        assert_eq!(
            check_key_bundle_put(&part(1, 1, 9), doc, true, &stored)
                .unwrap_err()
                .code,
            ErrorCode::NotCurrent
        );
    }

    #[test]
    fn test_invite_code_put_rules() {
        let put = |uses: u64| InviteCodePut {
            code_hash: [1; 32],
            expires_at: ISSUED,
            max_uses: uses,
            context: InviteContext::new(json!({})),
        };
        assert!(check_invite_code_put(&put(100), MAX_INVITE_USES, false).is_ok());
        assert_eq!(
            check_invite_code_put(&put(101), MAX_INVITE_USES, false)
                .unwrap_err()
                .status(),
            400
        );
        assert_eq!(
            check_invite_code_put(&put(1), MAX_INVITE_USES, true)
                .unwrap_err()
                .status(),
            409
        );
    }
}
