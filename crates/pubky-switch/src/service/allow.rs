//! `GET /v1/{id}/allow` (Switch wire 7.4.6): the lists an own app with `lists.read` reads,
//! each whole: contacts, conversation entries, the deny list, flagged senders and live
//! invite codes. All five are always present, empty or not, since the client refuses an
//! answer missing one and reads a missing or cut `flagged` as "not flagged".

use pubky_switch_core::{
    enc::{b64, pubky_id, zbase32_encode},
    records::AppCert,
    scopes::Permission,
    time::rfc3339,
};

use super::{Answer, Service, store_error};
use crate::{
    http::error::{ApiError, ErrorCode},
    keys::ServiceSigner,
    store::{AccountTxn, AllowEntry, AllowInvite, ListName},
};

/// A JSON string: the encodings this answer writes (a Pubky ID, an App ID, b64, a time)
/// are ASCII with nothing to escape.
fn string(out: &mut Vec<u8>, text: &str) {
    out.push(b'"');
    out.extend_from_slice(text.as_bytes());
    out.push(b'"');
}

/// `[ "pubky", ... ]`.
fn pubkys(out: &mut Vec<u8>, entries: &[AllowEntry]) {
    out.push(b'[');
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        string(out, &pubky_id(&entry.pubky));
    }
    out.push(b']');
}

/// A conversation entry, in the order of 7.4.6's row: `pubky`, `written_by` (an App ID or
/// `"service"`), `code_hash` and `context` on an entry the service wrote, `at`, and
/// `last_used` once an append it admitted. The context is the invite code's as its writer
/// wrote it (Switch wire 1.1).
fn conversation(out: &mut Vec<u8>, entry: &AllowEntry) {
    out.extend_from_slice(b"{\"pubky\":");
    string(out, &pubky_id(&entry.pubky));
    out.extend_from_slice(b",\"written_by\":");
    match &entry.written_by {
        Some(app) => string(out, &zbase32_encode(app)),
        None => string(out, "service"),
    }
    if let Some(code_hash) = &entry.code_hash {
        out.extend_from_slice(b",\"code_hash\":");
        string(out, &b64(code_hash));
    }
    if let Some(context) = &entry.context {
        out.extend_from_slice(b",\"context\":");
        out.extend_from_slice(context);
    }
    out.extend_from_slice(b",\"at\":");
    string(out, &rfc3339(entry.at_ms));
    if let Some(last_used) = entry.last_used_ms {
        out.extend_from_slice(b",\"last_used\":");
        string(out, &rfc3339(last_used));
    }
    out.push(b'}');
}

/// A live invite code, without its context: `code_hash`, `expires_at`, `max_uses`, `uses`,
/// `written_by`.
fn invite(out: &mut Vec<u8>, invite: &AllowInvite) {
    out.extend_from_slice(b"{\"code_hash\":");
    string(out, &b64(&invite.code_hash));
    out.extend_from_slice(b",\"expires_at\":");
    string(out, &rfc3339(invite.expires_at_ms));
    out.extend_from_slice(format!(",\"max_uses\":{}", invite.max_uses).as_bytes());
    out.extend_from_slice(format!(",\"uses\":{}", invite.uses).as_bytes());
    out.extend_from_slice(b",\"written_by\":");
    string(out, &zbase32_encode(&invite.writer));
    out.push(b'}');
}

/// The answer, in the order of 7.4.6's table: `contacts`, `conversations`, `deny`,
/// `flagged`, `invite_codes`.
fn answer_body(
    contacts: &[AllowEntry],
    conversations: &[AllowEntry],
    deny: &[AllowEntry],
    flagged: &[([u8; 32], u64)],
    invites: &[AllowInvite],
) -> Vec<u8> {
    let mut out = b"{\"contacts\":".to_vec();
    pubkys(&mut out, contacts);
    out.extend_from_slice(b",\"conversations\":[");
    for (i, entry) in conversations.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        conversation(&mut out, entry);
    }
    out.extend_from_slice(b"],\"deny\":");
    pubkys(&mut out, deny);
    out.extend_from_slice(b",\"flagged\":[");
    for (i, (pubky, hits)) in flagged.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"pubky\":");
        string(&mut out, &pubky_id(pubky));
        out.extend_from_slice(format!(",\"hits\":{hits}}}").as_bytes());
    }
    out.extend_from_slice(b"],\"invite_codes\":[");
    for (i, code) in invites.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        invite(&mut out, code);
    }
    out.extend_from_slice(b"]}");
    out
}

impl Service {
    /// `GET /v1/{id}/allow` (Switch wire 7.4.6) under the lock, for the own app `reader`,
    /// which needs `lists.read` (`403 permission_missing`).
    ///
    /// The lists are read in the request's own transaction, under the account's lock, so
    /// they are the state at its stamped service time `time_ms`, the `Switch-Server-Time`
    /// the answer is signed at, which the client keeps as the time its copy of the lists
    /// is as of. Each list is whole and never cut: `flagged` holds every sender with at least
    /// `flag_after` hits, bounded by `max_flags` (9.4), and `invite_codes` every code with
    /// uses left and unexpired at `time_ms`.
    pub(super) async fn get_allow(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        reader: Option<&AppCert>,
        time_ms: u64,
    ) -> Result<Answer, ApiError> {
        if !reader.is_some_and(|cert| cert.has_permission(Permission::ListsRead)) {
            return Err(ApiError::new(
                ErrorCode::PermissionMissing,
                "7.4.6: reading the lists needs lists.read",
            ));
        }
        let contacts = txn
            .allow_entries(ListName::Contact)
            .await
            .map_err(|e| store_error(&e))?;
        let conversations = txn
            .allow_entries(ListName::Conversation)
            .await
            .map_err(|e| store_error(&e))?;
        let deny = txn
            .allow_entries(ListName::Deny)
            .await
            .map_err(|e| store_error(&e))?;
        let flagged = txn
            .flagged_senders(u64::from(self.limits.flag_after))
            .await
            .map_err(|e| store_error(&e))?;
        let invites = txn
            .live_invite_codes(time_ms)
            .await
            .map_err(|e| store_error(&e))?;
        let body = answer_body(&contacts, &conversations, &deny, &flagged, &invites);
        let head = self
            .head(txn, signer)
            .await
            .ok_or_else(|| ApiError::unavailable("7.6: a temporary failure"))?;
        Ok(Answer::ok(body).with_head(Some(head)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_answer_has_every_list_in_table_order() {
        let empty = String::from_utf8(answer_body(&[], &[], &[], &[], &[])).expect("utf-8");
        assert_eq!(
            empty,
            "{\"contacts\":[],\"conversations\":[],\"deny\":[],\"flagged\":[],\"invite_codes\":[]}"
        );
        let service_entry = AllowEntry {
            pubky: [1; 32],
            written_by: None,
            at_ms: 0,
            code_hash: Some([2; 32]),
            context: Some(b"{\"n\":1.50}".to_vec()),
            last_used_ms: Some(1_000),
        };
        let app_entry = AllowEntry {
            pubky: [3; 32],
            written_by: Some([4; 16]),
            at_ms: 0,
            code_hash: None,
            context: None,
            last_used_ms: None,
        };
        let body = String::from_utf8(answer_body(
            &[],
            &[service_entry, app_entry],
            &[],
            &[([5; 32], 3)],
            &[],
        ))
        .expect("utf-8");
        let value: serde_json::Value = serde_json::from_str(&body).expect("json");
        let conversations = value["conversations"].as_array().expect("array");
        assert_eq!(conversations[0]["written_by"], "service");
        // The context as written, byte for byte: 1.50 stays 1.50.
        assert!(body.contains("\"context\":{\"n\":1.50}"));
        assert!(conversations[1].get("code_hash").is_none());
        assert!(conversations[1].get("last_used").is_none());
        assert_eq!(value["flagged"][0]["hits"], 3);
    }
}
