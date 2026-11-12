//! What the parties of a flow share: a neutral protocol, and the step between a signer's
//! approval and an app's join that a host carries out.

use std::sync::Arc;

use pubky_switch_client::app::{Collection, JoinRequest};
use pubky_switch_client::testing::{ProtocolSpec, TestProtocol};
use pubky_switch_core::ident::Policy;
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::{
    AppRequest, AppRequestBody, ApprovalClaim, AuthRequest, app_record_path,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_signer::{ApprovedRequest, GrantPath, Protocol, ScopeDef};

use crate::HarnessError;

/// The scope of the [`Notes`] protocol, which has Shared Data Keys.
pub const NOTES: &str = "notes";

/// The message kind the notes apps accept.
pub const NOTE_KIND: &str = "example.note";

/// A scope of the [`Notes`] protocol without keys, whose apps hold `lists.manage` alone:
/// they change the lists and can't read them.
pub const NOTES_LISTS: &str = "notes_lists";

/// A second scope of the [`Notes`] protocol with Shared Data Keys, for a collection of its
/// own. Its apps hold `lists.manage` alone, as those of [`NOTES_LISTS`] do.
pub const NOTES_JOURNAL: &str = "notes_journal";

/// A scope of the [`Notes`] protocol without keys, whose apps hold `lists.read` alone: they
/// read the lists and can't change them.
pub const NOTES_READER: &str = "notes_reader";

/// A path the [`Notes`] protocol adds to the grant of an app holding [`NOTES`], which the
/// user may decline (Switch spec 3.4): it goes only together with [`NOTES_PROFILE_FILES`].
pub const NOTES_PROFILE: &str = "/pub/notes/profile.json";

/// The folder of [`NOTES_PROFILE`]'s files, added and declined with it.
pub const NOTES_PROFILE_FILES: &str = "/pub/notes/profile-files/";

/// A neutral protocol, the signer's side of it. Its scope [`NOTES`] has keys and needs every
/// switch permission, so its apps read and change the lists and write claims; its scope
/// [`NOTES_LISTS`] has no keys and needs `lists.manage` alone; its scope [`NOTES_READER`]
/// has no keys and needs `lists.read` alone. It adds [`NOTES_PROFILE`] and
/// [`NOTES_PROFILE_FILES`] to the grant of an app holding [`NOTES`], both or neither.
#[derive(Clone, Copy, Debug, Default)]
pub struct Notes;

impl Protocol for Notes {
    fn name(&self) -> &str {
        "notes"
    }

    fn scopes(&self) -> Vec<ScopeDef> {
        vec![
            ScopeDef::keyed(NOTES),
            ScopeDef::unkeyed(NOTES_LISTS),
            ScopeDef::keyed(NOTES_JOURNAL),
            ScopeDef::unkeyed(NOTES_READER),
        ]
    }

    fn check_scopes(&self, _: &[&str]) -> Result<(), String> {
        Ok(())
    }

    fn permissions(&self, scopes: &[&str]) -> Vec<Permission> {
        if scopes.contains(&NOTES) {
            Permission::ALL.to_vec()
        } else if scopes.contains(&NOTES_READER) {
            vec![Permission::ListsRead]
        } else {
            vec![Permission::ListsManage]
        }
    }

    fn grant_paths(&self, _: &[u8; 16], scopes: &[&str]) -> Vec<GrantPath> {
        if !scopes.contains(&NOTES) {
            return Vec::new();
        }
        vec![
            GrantPath {
                path: NOTES_PROFILE.to_owned(),
                purpose: "Edit the notes profile".to_owned(),
            },
            GrantPath {
                path: NOTES_PROFILE_FILES.to_owned(),
                purpose: "Store the notes profile's files".to_owned(),
            },
        ]
    }

    fn check_grant_paths(&self, allowed: &[&str]) -> Result<(), String> {
        if allowed.contains(&NOTES_PROFILE) == allowed.contains(&NOTES_PROFILE_FILES) {
            Ok(())
        } else {
            Err("the notes profile and its files go together".to_owned())
        }
    }
}

/// The app's side of the [`Notes`] protocol: a protocol that records what it receives.
pub fn notes_protocol() -> Arc<TestProtocol> {
    Arc::new(TestProtocol::new(ProtocolSpec {
        keyed_scopes: vec![NOTES.to_owned()],
        accepts: vec![NOTE_KIND.to_owned()],
        ..ProtocolSpec::default()
    }))
}

/// The collection of shared records the [`Notes`] protocol's apps keep, read and written
/// with the [`NOTES`] scope.
pub fn notes_collection() -> Collection {
    Collection::new("example.items", Policy::new(NOTES, &[NOTES]))
}

/// A second collection of the [`Notes`] protocol's apps, read and written with the
/// [`NOTES_JOURNAL`] scope.
pub fn journal_collection() -> Collection {
    Collection::new(
        "example.journal",
        Policy::new(NOTES_JOURNAL, &[NOTES_JOURNAL]),
    )
}

/// The app's side of the [`Notes`] protocol with both its collections, for an app that
/// holds the keyed scopes `keyed`: it lists, when it joins, the collections it may read.
pub fn notes_protocol_with_both_collections(keyed: &[&str]) -> Arc<TestProtocol> {
    Arc::new(TestProtocol::new(ProtocolSpec {
        keyed_scopes: keyed.iter().map(|scope| (*scope).to_owned()).collect(),
        accepts: vec![NOTE_KIND.to_owned()],
        collections: vec![notes_collection(), journal_collection()],
    }))
}

/// The app's side of the [`Notes`] protocol with its [`notes_collection`]: an app with it
/// lists the collection's records when it joins.
pub fn notes_protocol_with_records() -> Arc<TestProtocol> {
    Arc::new(TestProtocol::new(ProtocolSpec {
        keyed_scopes: vec![NOTES.to_owned()],
        accepts: vec![NOTE_KIND.to_owned()],
        collections: vec![notes_collection()],
    }))
}

/// An app that asks to be approved: its keys, its request for one scope, and the auth
/// request the request binds (Switch wire 3.9).
#[derive(Clone, Debug)]
pub struct Asking {
    /// The app's keys.
    pub keys: AppKeys,
    /// The Pubky auth request its app request travels with.
    pub auth: AuthRequest,
    /// The app request.
    pub request: AppRequest,
}

impl Asking {
    /// The request of the app with `keys` for the [`NOTES`] scope and the grant of its own
    /// record's path.
    ///
    /// # Errors
    ///
    /// When the request doesn't sign.
    pub fn new(keys: AppKeys) -> Result<Self, HarnessError> {
        Self::for_scope(keys, NOTES)
    }

    /// The same, for `scope`.
    ///
    /// # Errors
    ///
    /// When the request doesn't sign.
    pub fn for_scope(keys: AppKeys, scope: &str) -> Result<Self, HarnessError> {
        Self::for_scopes(keys, &[scope])
    }

    /// The same, for several scopes.
    ///
    /// # Errors
    ///
    /// When the request doesn't sign.
    pub fn for_scopes(keys: AppKeys, scopes: &[&str]) -> Result<Self, HarnessError> {
        Self::for_scopes_with_paths(keys, scopes, &[], [9; 32])
    }

    /// The same, asking for the grant of its own record's path and then of `paths`, such as
    /// [`NOTES_PROFILE`] and [`NOTES_PROFILE_FILES`], with the auth request's `secret`: a
    /// second request of a listed app takes another one, as a new auth request does.
    ///
    /// # Errors
    ///
    /// When the request doesn't sign.
    pub fn for_scopes_with_paths(
        keys: AppKeys,
        scopes: &[&str],
        paths: &[&str],
        secret: [u8; 32],
    ) -> Result<Self, HarnessError> {
        let caps = std::iter::once(app_record_path(&keys.app_id_bytes()))
            .chain(paths.iter().map(|path| (*path).to_owned()))
            .map(|path| format!("{path}:rw"))
            .collect::<Vec<_>>()
            .join(",");
        let auth = AuthRequest {
            client_id: "app.example".into(),
            client_key: [8; 32],
            caps,
            secret,
        };
        let scopes = scopes.iter().map(|scope| (*scope).to_owned()).collect();
        let body = AppRequestBody::new(&keys, scopes, &auth);
        let request = AppRequest::sign(&keys, body)
            .map_err(|error| HarnessError::Setup(error.to_string()))?;
        Ok(Self {
            keys,
            auth,
            request,
        })
    }

    /// What the app joins with once `identity`'s signer approved it: the host's step of
    /// reading the companion claim and checking its signature (Switch wire 3.10).
    ///
    /// # Errors
    ///
    /// When the claim doesn't read or verify.
    pub fn join_request(
        &self,
        identity: [u8; 32],
        approved: &ApprovedRequest,
    ) -> Result<JoinRequest, HarnessError> {
        let failed = |error: pubky_switch_core::Error| HarnessError::Setup(error.to_string());
        let claim = ApprovalClaim::from_plaintext(&approved.claim).map_err(failed)?;
        let approval = claim.verify(&identity, &self.auth).map_err(failed)?;
        Ok(JoinRequest {
            identity,
            keys: self.keys.clone(),
            request: self.request.clone(),
            approval: approval.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_notes_profile_paths_go_together() {
        let keys = AppKeys::from_secrets([3; 32], [4; 32]);
        let id = keys.app_id_bytes();
        assert_eq!(
            Notes
                .grant_paths(&id, &[NOTES])
                .iter()
                .map(|p| p.path.as_str())
                .collect::<Vec<_>>(),
            [NOTES_PROFILE, NOTES_PROFILE_FILES]
        );
        assert!(Notes.grant_paths(&id, &[NOTES_LISTS]).is_empty());
        assert!(Notes.check_grant_paths(&[]).is_ok());
        assert!(
            Notes
                .check_grant_paths(&[NOTES_PROFILE, NOTES_PROFILE_FILES])
                .is_ok()
        );
        assert!(Notes.check_grant_paths(&[NOTES_PROFILE]).is_err());
        assert!(Notes.check_grant_paths(&[NOTES_PROFILE_FILES]).is_err());
    }

    #[test]
    fn test_notes_asking_with_paths_names_the_record_first() {
        let keys = AppKeys::from_secrets([3; 32], [4; 32]);
        let record = app_record_path(&keys.app_id_bytes());
        let asking =
            Asking::for_scopes_with_paths(keys.clone(), &[NOTES], &[NOTES_PROFILE], [7; 32])
                .unwrap();
        assert_eq!(asking.auth.caps, format!("{record}:rw,{NOTES_PROFILE}:rw"));
        assert_eq!(asking.auth.secret, [7; 32]);
        assert_eq!(asking.request.body().caps, asking.auth.caps);
        let plain = Asking::for_scopes(keys, &[NOTES]).unwrap();
        assert_eq!(plain.auth.caps, format!("{record}:rw"));
    }
}
