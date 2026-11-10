//! Admission at the own switch, the app's side (Switch spec 7; Switch wire 6.2, 7.4.6,
//! 7.4.7).
//!
//! - **Contacts and the deny list** (`allow.put`, `allow.delete`, `deny.put`,
//!   `deny.delete`), with `lists.manage`.
//! - **Conversation entries**: an invite is a conversation entry before any message
//!   (`conversation.add`); a first message adds one itself ([`super::send`]).
//! - **Invite codes**: the app makes a code of 32 random bytes, registers its hash with an
//!   expiry, a number of uses and an opaque context (`invite_code.put`), shows it as
//!   `pubky://<id>?switch=invite&code=<code>`, and may withdraw it.
//! - **Connect requests**: asking a stranger's switch to be invited, and listing, allowing
//!   (an invite) and declining the requests at the own switch.
//!
//! The app keeps what it knows of the lists from its own writes and, with `lists.read`,
//! from the feed, in the copy of the lists under `lc/` (`lc/contact/`, `lc/conv/`,
//! `lc/deny/`, `lc/code/`), and the codes themselves
//! it registered, `invite/<code_hash>`. A send consults them to skip a conversation entry
//! the identity already holds. The flagged senders (`lc/flag/`), which no feed item
//! carries, come only from `GET /allow` ([`App::allow_list`]), which also keeps when the
//! copy was last replaced (`lc/lists_at`).

use pubky_switch_core::enc::{b64, pubky_id, random_bytes, serde_b64};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ident::{invite_code_hash, invite_code_uri};
use pubky_switch_core::ops::{AllowKind, InviteCodePut, InviteContext, OpKind, SignedOp};
use pubky_switch_core::scopes::Permission;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::batch::OpBatch;
use super::error::Refusal;
use super::state::Tx;
use super::{App, AppError};
use crate::client::answers::{AllowList, ChainItem, ConnectList};
use crate::error::ClientError;

/// The random bytes in an invite code the app makes (Switch spec 7: at least 16).
pub const INVITE_CODE_BYTES: usize = 32;

const INVITE_PREFIX: &str = "invite/";

/// The app's copy of the lists lives under `lc/`, shared with the moves and recovery code,
/// which uploads it after a provider loss: `lc/contact/<pubky>`, `lc/deny/<pubky>` and
/// `lc/code/<code_hash>` there, and `lc/conv/<pubky>` here, each holding `()`.
pub(crate) fn allow_key(kind: AllowKind, pubky: &[u8; 32]) -> String {
    let kind = match kind {
        AllowKind::Contact => "contact",
        AllowKind::Conversation => "conv",
    };
    format!("lc/{kind}/{}", pubky_id(pubky))
}

pub(crate) fn deny_key(pubky: &[u8; 32]) -> String {
    format!("lc/deny/{}", pubky_id(pubky))
}

/// A flagged sender in the copy of the lists, from `GET /allow` only (Switch wire 7.4.6).
pub(crate) fn flag_key(pubky: &[u8; 32]) -> String {
    format!("lc/flag/{}", pubky_id(pubky))
}

/// When [`App::allow_list`] last replaced the copy of the lists: the service time of its
/// answer, Unix milliseconds. Absent until the first.
pub(crate) const LISTS_AT: &str = "lc/lists_at";

/// An invite code this app registered, in the copy of the lists.
pub(crate) fn code_key(code_hash: &[u8; 32]) -> String {
    format!("lc/code/{}", b64(code_hash))
}

/// The code itself, which only this app holds, to show it again.
pub(crate) fn invite_key(code_hash: &[u8; 32]) -> String {
    format!("{INVITE_PREFIX}{}", b64(code_hash))
}

/// An invite code the app registered. Its `Debug` shows only the hash: the code is a
/// bearer secret (Switch spec 7).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteCode {
    /// The code, base64url.
    pub code: String,
    /// `hash(code bytes)`.
    #[serde(with = "serde_b64")]
    pub code_hash: [u8; 32],
    /// When it expires, Unix milliseconds.
    pub expires_at: u64,
    /// How many appends it admits.
    pub max_uses: u64,
    /// The opaque context the switch stores in the clear.
    pub context: Value,
}

impl std::fmt::Debug for InviteCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InviteCode({})", b64(&self.code_hash))
    }
}

/// Keep a registered code once the switch took it.
pub(crate) fn keep_invite(tx: &mut Tx, put: &InviteCodePut, code: &str) -> Result<(), AppError> {
    tx.put(&code_key(&put.code_hash), &())?;
    tx.put(
        &invite_key(&put.code_hash),
        &InviteCode {
            code: code.to_owned(),
            code_hash: put.code_hash,
            expires_at: put.expires_at,
            max_uses: put.max_uses,
            context: put.context.value().clone(),
        },
    )
}

impl InviteCode {
    /// The link that shows it: `pubky://<identity>?switch=invite&code=<code>` (Switch spec
    /// 7).
    pub fn uri(&self, identity: &[u8; 32]) -> String {
        invite_code_uri(identity, &self.code)
    }
}

impl App {
    fn need(&self, permission: Permission) -> Result<(), AppError> {
        if self.state.cert.has_permission(permission) {
            Ok(())
        } else {
            Err(Refusal::Usage(format!(
                "Switch spec 3.2: the certificate lacks {}",
                permission.as_str()
            ))
            .into())
        }
    }

    // ---------------------------------------------------------------------------------
    // Contacts, conversation entries and the deny list

    /// Save `pubky` as a contact (`allow.put` contact, `lists.manage`).
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] without the permission; as [`App::submit_batch`].
    pub async fn add_contact(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.need(Permission::ListsManage)?;
            self.list_op(OpKind::AllowPut {
                pubky: *pubky,
                kind: AllowKind::Contact,
            })
            .await
        })
        .await
    }

    /// Remove a contact (`allow.delete` contact, `lists.manage`).
    ///
    /// # Errors
    ///
    /// As [`App::add_contact`].
    pub async fn remove_contact(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.need(Permission::ListsManage)?;
            self.list_op(OpKind::AllowDelete {
                pubky: *pubky,
                kind: AllowKind::Contact,
            })
            .await
        })
        .await
    }

    /// Invite `pubky`: a conversation entry before any message, so it can write first
    /// (`allow.put` conversation, `conversation.add`). It also allows a pending connect
    /// request from it (Switch wire 6.2).
    ///
    /// # Errors
    ///
    /// As [`App::add_contact`], with `conversation.add`.
    pub async fn invite(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.need(Permission::ConversationAdd)?;
            self.list_op(OpKind::AllowPut {
                pubky: *pubky,
                kind: AllowKind::Conversation,
            })
            .await
        })
        .await
    }

    /// Remove a conversation entry (`allow.delete` conversation, `lists.manage`), as when
    /// pruning idle entries (Switch spec 7).
    ///
    /// # Errors
    ///
    /// As [`App::add_contact`].
    pub async fn remove_conversation(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.need(Permission::ListsManage)?;
            self.list_op(OpKind::AllowDelete {
                pubky: *pubky,
                kind: AllowKind::Conversation,
            })
            .await
        })
        .await
    }

    /// Block `pubky`: the deny list overrides every entry, and removes a pending connect
    /// request from it (`deny.put`, `lists.manage`).
    ///
    /// # Errors
    ///
    /// As [`App::add_contact`].
    pub async fn deny(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.need(Permission::ListsManage)?;
            self.list_op(OpKind::DenyPut { pubky: *pubky }).await
        })
        .await
    }

    /// Unblock `pubky` (`deny.delete`, `lists.manage`).
    ///
    /// # Errors
    ///
    /// As [`App::add_contact`].
    pub async fn undeny(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.need(Permission::ListsManage)?;
            self.list_op(OpKind::DenyDelete { pubky: *pubky }).await
        })
        .await
    }

    async fn list_op(&mut self, kind: OpKind) -> Result<(), AppError> {
        self.submit_batch(OpBatch::new().op(kind)).await?;
        Ok(())
    }

    /// Whether the app knows `pubky` to be a contact or to hold a conversation entry.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn admits(&self, pubky: &[u8; 32]) -> Result<bool, AppError> {
        let reader = self.reader();
        Ok(!reader.exists(&deny_key(pubky)).await?
            && (reader.exists(&allow_key(AllowKind::Contact, pubky)).await?
                || reader
                    .exists(&allow_key(AllowKind::Conversation, pubky))
                    .await?))
    }

    /// The lists the switch holds (`GET /allow`, `lists.read`, Switch wire 7.4.6): contacts,
    /// conversation entries with their writers, the deny list, flagged senders and the live
    /// invite codes. What the app keeps of them is replaced in one commit: the contacts,
    /// conversation entries, deny list, flagged senders and its own invite codes, with the
    /// answer's service time (`lc/lists_at`).
    ///
    /// Each list is kept whole, as the answer holds it. At the default limits that is at
    /// most `max_flags`, 1,000, flagged senders (Switch wire 9.2); beyond the limits, the
    /// answer's size and the store's batch size bound it, as they bound the other lists, and
    /// a copy over the batch size fails the commit and leaves the copy as it was.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] without `lists.read`; a failed call or commit.
    pub async fn allow_list(&mut self) -> Result<AllowList, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            self.need(Permission::ListsRead)?;
            let result = self.client.allow().await;
            let list = self.take(result).await?;
            // The answer's own stamped time (Switch spec 10.1). For an answer without one, the
            // highest service time verified before it, which is older, so a protocol refreshes
            // no later than it means to; the device clock only when the app verified none.
            let as_of = self
                .client
                .latest_server_time()
                .or_else(|| self.highest_service_time())
                .unwrap_or_else(|| self.now());
            let me = self.state.meta.app_id;
            let mut tx = self.tx()?;
            for prefix in [
                "lc/contact/",
                "lc/conv/",
                "lc/deny/",
                "lc/flag/",
                "lc/code/",
            ] {
                tx.delete_prefix(prefix)?;
            }
            for pubky in &list.contacts {
                tx.put(&allow_key(AllowKind::Contact, pubky), &())?;
            }
            for entry in &list.conversations {
                tx.put(&allow_key(AllowKind::Conversation, &entry.pubky), &())?;
            }
            for pubky in &list.deny {
                tx.put(&deny_key(pubky), &())?;
            }
            for flagged in &list.flagged {
                tx.put(&flag_key(&flagged.pubky), &())?;
            }
            tx.put(LISTS_AT, &as_of)?;
            for code in list.invite_codes.iter().filter(|c| c.written_by == me) {
                tx.put(&code_key(&code.code_hash), &())?;
            }
            self.commit(tx).await?;
            Ok(list)
        })
        .await
    }

    /// A conversation entry added or removed in the feed (with `lists.read`): the copy of
    /// the lists follows it, so a pruned entry is written again before the next message to
    /// its counterparty (Switch spec 7 "Pruning"). Contacts, the deny list and invite codes
    /// in the feed are the copy's own hook's, with the moves and recovery code.
    pub(crate) fn feed_list_change(&self, item: &ChainItem, tx: &mut Tx) -> Result<(), AppError> {
        let Ok(op) = SignedOp::peek(&item.item) else {
            return Ok(());
        };
        match &op.body().kind {
            OpKind::AllowPut {
                pubky,
                kind: AllowKind::Conversation,
            } => tx.put(&allow_key(AllowKind::Conversation, pubky), &()),
            OpKind::AllowDelete {
                pubky,
                kind: AllowKind::Conversation,
            } => tx.delete(&allow_key(AllowKind::Conversation, pubky)),
            _ => Ok(()),
        }
    }

    // ---------------------------------------------------------------------------------
    // Invite codes

    /// Make and register an invite code (`invite_code.put`, `conversation.add`): 32 random
    /// bytes, its hash, `expires_at`, `max_uses` and an opaque `context` the switch stores
    /// in the clear, so the context holds nothing the operator shouldn't read (Switch spec
    /// 7). The app keeps the code to show it again ([`InviteCode::uri`]).
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] without the permission or for `max_uses` 0; a failing random
    /// generator; as [`App::submit_batch`].
    pub async fn register_invite_code(
        &mut self,
        expires_at: u64,
        max_uses: u64,
        context: Value,
    ) -> Result<InviteCode, AppError> {
        Box::pin(async move {
            self.need(Permission::ConversationAdd)?;
            if max_uses == 0 {
                return Err(
                    Refusal::Usage("Switch wire 6.2: max_uses is at least 1".into()).into(),
                );
            }
            let code = b64(&random_bytes::<INVITE_CODE_BYTES>()?);
            let code_hash = invite_code_hash(&code)?;
            let put = InviteCodePut {
                code_hash,
                expires_at,
                max_uses,
                context: InviteContext::new(context.clone()),
            };
            self.submit_batch(
                OpBatch::new()
                    .op(OpKind::InviteCodePut(put))
                    .invite(&code_hash, &code),
            )
            .await?;
            Ok(InviteCode {
                code,
                code_hash,
                expires_at,
                max_uses,
                context,
            })
        })
        .await
    }

    /// Withdraw an invite code (`invite_code.delete`, `conversation.add`).
    ///
    /// # Errors
    ///
    /// As [`App::register_invite_code`]; `404` for a code the switch doesn't hold.
    pub async fn withdraw_invite_code(&mut self, code_hash: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.need(Permission::ConversationAdd)?;
            self.list_op(OpKind::InviteCodeDelete {
                code_hash: *code_hash,
            })
            .await
        })
        .await
    }

    /// The invite codes the app registered and hasn't withdrawn.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn invite_codes(&self) -> Result<Vec<InviteCode>, AppError> {
        Ok(self
            .reader()
            .scan::<InviteCode>(INVITE_PREFIX)
            .await?
            .into_iter()
            .map(|(_, code)| code)
            .collect())
    }

    // ---------------------------------------------------------------------------------
    // Connect requests

    /// Ask `pubky`'s switch to be invited (`POST /connect`, Switch wire 7.4.7), delivering the
    /// own `identity.json` there first when its switch doesn't hold it. Returns whether the
    /// request is pending.
    ///
    /// # Errors
    ///
    /// `403 not_admitted` where the identity takes no connect requests; `429` when its list
    /// is full; a failed call.
    pub async fn ask_to_connect(&mut self, pubky: &[u8; 32]) -> Result<bool, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let mut delivered = false;
            loop {
                let doc = self.peer_identity(pubky, false).await?;
                let client = self.peer_client(pubky, &doc)?;
                match client.connect().await {
                    Ok(answer) => {
                        self.note_known_version(pubky, answer.known_version).await?;
                        return Ok(answer.pending);
                    }
                    Err(ClientError::Switch {
                        code: ErrorCode::IdentityNeeded,
                        ..
                    }) if !delivered => {
                        delivered = true;
                        self.deliver_own_identity(pubky, None, true).await?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        })
        .await
    }

    /// The connect requests pending at the own switch (`GET /connect`, `lists.read`).
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] without the permission; a failed call.
    pub async fn connect_requests(&mut self) -> Result<ConnectList, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            self.need(Permission::ListsRead)?;
            let result = self.client.connect_requests().await;
            self.take(result).await
        })
        .await
    }

    /// Allow a connect request: an invite, which removes it (Switch spec 7).
    ///
    /// # Errors
    ///
    /// As [`App::invite`].
    pub async fn allow_connect(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move { self.invite(pubky).await }).await
    }

    /// Decline a connect request (`DELETE /connect/{pubky}`, `conversation.add`).
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] without the permission; `404` when none is pending from it.
    pub async fn decline_connect(&mut self, pubky: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            self.need(Permission::ConversationAdd)?;
            let result = self.client.decline_connect(pubky).await;
            self.take(result).await?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admission_keys_name_the_list() {
        assert!(allow_key(AllowKind::Contact, &[1; 32]).starts_with("lc/contact/"));
        assert!(allow_key(AllowKind::Conversation, &[1; 32]).starts_with("lc/conv/"));
        assert!(deny_key(&[1; 32]).starts_with("lc/deny/"));
        assert!(flag_key(&[1; 32]).starts_with("lc/flag/"));
        assert!(code_key(&[1; 32]).starts_with("lc/code/"));
    }

    #[test]
    fn test_admission_invite_code_debug_hides_the_code() {
        let code = InviteCode {
            code: "secret-code".into(),
            code_hash: [1; 32],
            expires_at: 1,
            max_uses: 1,
            context: Value::Null,
        };
        assert!(!format!("{code:?}").contains("secret"));
        assert!(
            code.uri(&[2; 32])
                .contains("switch=invite&code=secret-code")
        );
    }
}
