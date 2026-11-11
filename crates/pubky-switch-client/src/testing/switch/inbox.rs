//! The scripted switch as a sender at another identity sees it: admission, the directory
//! with `known_version`, the peer copies of senders' `identity.json`, connect requests, and
//! the inbox, with its retry by content, `identity_needed`, `stale_key` and invite codes
//! (Switch spec 7; Switch wire 7.4.3, 7.4.5, 7.4.7, 7.4.10). Own apps append to it too, for
//! the kinds their protocol sends between own apps. It checks what a sender relies on, and
//! nothing the service alone answers for, such as rate limits and quotas; `FAKES.md` lists
//! what it leaves out.

use std::collections::BTreeSet;

use pubky_switch_core::chain::ServiceTransition;
use pubky_switch_core::enc::{app_id_decode, b64, pubky_key, unb64_array, zbase32_encode};
use pubky_switch_core::envelope::parse_header;
use pubky_switch_core::http::{ErrorCode, header};
use pubky_switch_core::ident::invite_code_hash;
use pubky_switch_core::ops::AllowKind;
use pubky_switch_core::records::{AppCert, IdentityDoc};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::rfc3339;
use serde_json::{Value, json};

use super::{Answer, Inner, Item, ScriptedSwitch, bad};
use crate::testing::ScriptError;
use crate::transport::Request;

/// Who a request to the inbox routes comes from.
pub(super) struct Sender {
    /// The sender identity.
    pub(super) identity: [u8; 32],
    /// The sender app.
    pub(super) app: Option<[u8; 16]>,
    /// The invite code it presents.
    pub(super) code: Option<String>,
}

impl Sender {
    /// The caller of `request` when it is an app of another identity than `account`.
    pub(super) fn foreign(request: &Request, account: &[u8; 32]) -> Option<Self> {
        let identity = request
            .header(header::IDENTITY)
            .and_then(|text| pubky_key(text).ok())?;
        if identity == *account {
            return None;
        }
        Some(Self {
            identity,
            app: request
                .header(header::APP)
                .and_then(|text| app_id_decode(text).ok()),
            code: request.header(header::INVITE_CODE).map(str::to_owned),
        })
    }
}

impl ScriptedSwitch {
    /// Admit every sender, or only those the lists and invite codes admit (Switch spec 7),
    /// the default.
    pub fn admit_everyone(&self, open: bool) {
        self.lock().open_admission = open;
    }

    /// The peer copy of `identity`'s `identity.json` the switch holds (Switch wire 7.4.5).
    pub fn peer_copy(&self, identity: &[u8; 32]) -> Option<IdentityDoc> {
        self.lock().peers.get(identity).cloned()
    }

    /// How many entries the inbox accepted from `sender`.
    pub fn entries_from(&self, sender: &[u8; 32]) -> usize {
        self.lock()
            .items
            .iter()
            .filter(|item| matches!(item, Item::Entry { sender: s, .. } if s == sender))
            .count()
    }

    /// Drop the peer copy of `identity`'s `identity.json`, as a switch beyond its peer
    /// limit does: its apps' next appends get `409 identity_needed` (Switch wire 7.4.5).
    pub fn forget_peer_copy(&self, identity: &[u8; 32]) {
        self.lock().peers.remove(identity);
    }

    /// The `apps_version`: how often an app became reachable or stopped being so (Switch
    /// wire 7.4.10).
    pub fn apps_version(&self) -> u64 {
        self.lock().apps_version
    }

    /// The uses left of the invite code `code`, if the switch holds it.
    pub fn invite_uses_left(&self, code: &str) -> Option<u64> {
        let hash = invite_code_hash(code).ok()?;
        self.lock()
            .shared
            .invites
            .get(&hash)
            .map(|invite| invite.max_uses.saturating_sub(invite.uses))
    }
}

impl Inner {
    /// The routes an app of another identity calls; `not_admitted` for every other one
    /// (Switch wire 6.4 step 1, 7.2).
    pub(super) fn route_foreign(
        &mut self,
        request: &Request,
        sender: &Sender,
        rest: &str,
    ) -> Result<Answer, ScriptError> {
        let (route, query) = rest.split_once('?').unwrap_or((rest, ""));
        Ok(match (request.method.as_str(), route) {
            ("GET", "directory") => {
                if !self.admits(sender, false) {
                    return Ok(not_admitted());
                }
                let (status, mut body) = self.directory();
                body["known_version"] = self.known(&sender.identity);
                (status, body)
            }
            // Where connect requests are on, a stranger delivers its document too, and asks
            // to connect (Switch wire 7.4.5, 7.4.7).
            ("PUT", "peers") => {
                // While admission is staged, a sender it can't otherwise admit waits, a
                // stranger asking to connect included (Switch spec 12.6 step 2).
                if !self.admits(sender, false)
                    && (self.admission_staged || !self.connect_requests_on())
                {
                    return Ok(self.not_admitted_now());
                }
                self.peers_put(&sender.identity, &request.body)
            }
            ("POST", "inbox") => self.append(request, Some(sender), query)?,
            ("POST", "connect") => self.connect(sender),
            _ => not_admitted(),
        })
    }

    /// The version of `sender`'s `identity.json` the switch holds, for `known_version`.
    fn known(&self, sender: &[u8; 32]) -> Value {
        self.peers
            .get(sender)
            .map_or(Value::Null, |doc| json!(doc.version()))
    }

    /// The allowlist and deny list (Switch spec 7): whether `pubky` is a contact or has a
    /// conversation entry, an app's or the service's, and whether it is denied.
    fn listed(&self, pubky: &[u8; 32]) -> (bool, bool) {
        let listed = self.shared.allowed(pubky, AllowKind::Contact)
            || self.shared.allowed(pubky, AllowKind::Conversation);
        (listed, self.shared.denied(pubky))
    }

    /// The invite code `sender` presents, when it is live: its hash.
    fn live_code(&self, sender: &Sender) -> Option<[u8; 32]> {
        let hash = invite_code_hash(sender.code.as_deref()?).ok()?;
        let invite = self.shared.invites.get(&hash)?;
        (invite.uses < invite.max_uses && self.now() < invite.expires_at).then_some(hash)
    }

    /// The answer to a sender not admitted: `503 staged` while admission is staged after a
    /// provider loss, so it retries, `403 not_admitted` otherwise (Switch spec 12.6 step 2).
    fn not_admitted_now(&self) -> Answer {
        if self.admission_staged {
            bad(
                ErrorCode::Staged,
                "admission is staged after a provider loss",
                json!(null),
            )
        } else {
            not_admitted()
        }
    }

    /// Whether `sender` is admitted (Switch spec 7): a contact, a conversation entry or a live
    /// invite code, the deny list overriding all three. `by_code_only` asks whether only its
    /// code admits it.
    fn admits(&self, sender: &Sender, by_code_only: bool) -> bool {
        let (listed, denied) = self.listed(&sender.identity);
        if denied {
            return false;
        }
        if by_code_only {
            return !listed && !self.open_admission && self.live_code(sender).is_some();
        }
        self.open_admission || listed || self.live_code(sender).is_some()
    }

    /// `PUT /peers` from an app of another identity (Switch wire 7.4.5).
    fn peers_put(&mut self, sender: &[u8; 32], body: &[u8]) -> Answer {
        let Ok(signed) = serde_json::from_slice::<SignedDoc>(body) else {
            return bad(ErrorCode::BadRequest, "peers", json!(null));
        };
        let Ok(doc) = IdentityDoc::verify(&signed, sender) else {
            return not_admitted();
        };
        if let Some(held) = self.peers.get(sender) {
            if held.version() == doc.version() && held.body_hash() != doc.body_hash() {
                return bad(
                    ErrorCode::StaleIdentity,
                    "equivocation",
                    json!({ "version": held.version(), "identity": held.signed() }),
                );
            }
            if held.version() > doc.version() || held.generation() > doc.generation() {
                return bad(
                    ErrorCode::StaleIdentity,
                    "older",
                    json!({ "version": held.version() }),
                );
            }
        }
        let version = doc.version();
        self.peers.insert(*sender, doc);
        (200, json!({ "version": version, "known_version": version }))
    }

    /// Whether the peer copy of `sender`'s `identity.json` lists `app` with `cert` and not
    /// as removed.
    fn listed_in_copy(&self, sender: &[u8; 32], app: &[u8; 16], cert: &[u8; 32]) -> bool {
        self.peers
            .get(sender)
            .is_some_and(|doc| doc.listed_cert(app) == Some(*cert) && !doc.lists_removed(app))
    }

    /// Whether the account's `identity.json` turns connect requests on (Switch spec 7).
    fn connect_requests_on(&self) -> bool {
        self.doc
            .as_ref()
            .is_some_and(|doc| doc.body().policy.connect_requests.enabled)
    }

    /// `POST /connect` (Switch wire 7.4.7): kept once per sender, never a denied one's;
    /// `not_admitted` while the policy turns connect requests off.
    fn connect(&mut self, sender: &Sender) -> Answer {
        if !self.connect_requests_on() {
            return not_admitted();
        }
        let listed = sender.app.is_some_and(|app| {
            self.peers
                .get(&sender.identity)
                .is_some_and(|doc| doc.listed_cert(&app).is_some() && !doc.lists_removed(&app))
        });
        if !listed {
            return bad(
                ErrorCode::IdentityNeeded,
                "identity needed",
                json!({ "version": null }),
            );
        }
        let (_, denied) = self.listed(&sender.identity);
        let now = self.now();
        if !denied
            && !self
                .shared
                .connect
                .iter()
                .any(|(pubky, _)| *pubky == sender.identity)
        {
            self.shared.connect.push((sender.identity, now));
        }
        (
            200,
            json!({ "pending": true, "known_version": self.known(&sender.identity) }),
        )
    }

    /// The app holding receive key `kid`, current or not.
    fn holder_of(&self, kid: &[u8; 8]) -> Option<[u8; 16]> {
        self.kids.get(kid).copied()
    }

    /// The current kid of `app`'s receive key.
    fn current_kid(&self, app: &[u8; 16]) -> Option<[u8; 8]> {
        let record = self.apps.get(app)?.receive_key.as_ref()?;
        let value: Value = record.peek().ok()?;
        unb64_array::<8>(value["kid"].as_str()?).ok()
    }

    /// The apps a sender reaches: current, with a receive key.
    fn reachable(&self) -> Vec<[u8; 16]> {
        self.apps
            .iter()
            .filter(|(_, app)| !app.departed && app.receive_key.is_some())
            .map(|(id, _)| *id)
            .collect()
    }

    /// `POST /inbox` (Switch wire 7.4.3), from an app of another identity (`sender`) or an
    /// own app. `query` carries the `apps_version` the envelope was sealed for.
    pub(super) fn append(
        &mut self,
        request: &Request,
        sender: Option<&Sender>,
        query: &str,
    ) -> Result<Answer, ScriptError> {
        let identity = match sender {
            Some(sender) => sender.identity,
            None => self.identity.public(),
        };
        let app = match sender {
            Some(sender) => sender.app,
            None => request
                .header(header::APP)
                .and_then(|text| app_id_decode(text).ok()),
        };
        let Some(app) = app else {
            return Ok(bad(ErrorCode::BadRequest, "no app", json!(null)));
        };
        // Step 1: a retry by content returns the original answer.
        if let Some(answer) = self.appended.get(&(identity, request.body.clone())) {
            return Ok((200, answer.clone()));
        }
        let Some(sealed_for) = query
            .split('&')
            .find_map(|pair| match pair.split_once('=') {
                Some(("apps_version", value)) => value.parse::<u64>().ok(),
                _ => None,
            })
        else {
            return Ok(bad(ErrorCode::BadRequest, "apps_version", json!(null)));
        };
        // The sender app's certificate, which the entry carries.
        let cert = match sender {
            Some(_) => {
                let cert = request
                    .header(header::CERT)
                    .and_then(|text| SignedDoc::from_compact(text).ok())
                    .and_then(|signed| AppCert::verify(&signed, &identity).ok());
                match cert {
                    Some(cert) if cert.app_id() == app => cert,
                    _ => return Ok(bad(ErrorCode::BadRequest, "Switch-Cert", json!(null))),
                }
            }
            None => match self.apps.get(&app).and_then(|held| held.cert.clone()) {
                Some(cert) => cert,
                None => return Ok(bad(ErrorCode::NotCurrent, "not current", json!(null))),
            },
        };
        // Step 2: admission, then the listing in the peer copy (Switch wire 7.4.3).
        let mut by_code = None;
        if let Some(sender) = sender {
            if !self.admits(sender, false) {
                return Ok(self.not_admitted_now());
            }
            if self.admits(sender, true) {
                by_code = self.live_code(sender);
            }
            if !self.listed_in_copy(&identity, &app, &cert.hash()) {
                let version = self
                    .peers
                    .get(&identity)
                    .filter(|doc| !doc.lists_removed(&app))
                    .map(IdentityDoc::version);
                return Ok(bad(
                    ErrorCode::IdentityNeeded,
                    "identity needed",
                    json!({ "version": version }),
                ));
            }
        }
        // Step 3: the header.
        let Ok(parsed) = parse_header(&request.body) else {
            return Ok(bad(ErrorCode::BadRequest, "envelope", json!(null)));
        };
        let kids: Vec<[u8; 8]> = parsed.kids().collect();
        // Step 5: every kid the current key of a current app, every app added since among
        // the targets.
        let mut stale = Vec::new();
        let mut not_current = BTreeSet::new();
        let mut unknown = Vec::new();
        let mut targets = Vec::new();
        for kid in &kids {
            match self.holder_of(kid) {
                Some(holder) if self.apps.get(&holder).is_some_and(|a| a.departed) => {
                    not_current.insert(zbase32_encode(&holder));
                }
                Some(holder) if self.current_kid(&holder) == Some(*kid) => {
                    targets.push(holder);
                }
                Some(holder) => {
                    let record = self.apps.get(&holder).and_then(|a| a.receive_key.clone());
                    stale.push(json!({ "app_id": zbase32_encode(&holder), "record": record }));
                }
                None => unknown.push(b64(kid)),
            }
        }
        let added: Vec<Value> = self
            .reachable()
            .into_iter()
            .filter(|reached| {
                self.reachable_since
                    .get(reached)
                    .is_some_and(|since| *since > sealed_for)
                    && !targets.contains(reached)
                    && !(sender.is_none() && *reached == app)
            })
            .filter_map(|reached| {
                let held = self.apps.get(&reached)?;
                Some(json!({ "app_id": zbase32_encode(&reached),
                             "app_record": held.record.clone()?,
                             "record": held.receive_key.clone()? }))
            })
            .collect();
        if !stale.is_empty() || !not_current.is_empty() || !unknown.is_empty() || !added.is_empty()
        {
            return Ok(bad(
                ErrorCode::StaleKey,
                "stale key",
                json!({ "receive_keys": stale, "not_current": not_current,
                        "unknown_kids": unknown, "added_apps": added,
                        "apps_version": self.apps_version }),
            ));
        }
        // The append brings the pressure: the lagging marks are judged first, so a lagging
        // app stops holding the quota before it is counted (Switch wire 7.4.4).
        self.judge_lagging();
        // Step 7: a code that admitted the sender is used, and the service writes its
        // conversation entry (the `conversation.add` transition, Switch wire 6.5).
        let mut context = None;
        if let Some(hash) = by_code
            && let Some(invite) = self.shared.invites.get_mut(&hash)
        {
            invite.uses = invite.uses.saturating_add(1);
            context = Some(invite.context.clone());
            let invite_context = invite.context.clone();
            let at = self.now();
            self.shared
                .service_conversations
                .insert(identity, (hash, at, invite_context.clone()));
            self.service_transition(ServiceTransition::ConversationAdd {
                pubky: identity,
                code_hash: hash,
                context: invite_context.clone(),
                at,
            })?;
            // The feed shows the entry with its code's context (Switch wire 7.5).
            if let Some(Item::Chain { context, .. }) = self.items.last_mut() {
                *context = Some(invite_context);
            }
        } else if sender.is_some() {
            // An append a conversation entry may have admitted: its time is the entry's
            // `last_used` (Switch wire 7.4.6). The append a code admits writes the entry,
            // and counts for none.
            let at = self.now();
            self.shared.note_conversation_used(&identity, at);
        }
        let seq = self.next_seq();
        let accepted_at = self.now();
        self.items.push(Item::Entry {
            seq,
            sender: identity,
            cert: cert.signed().clone(),
            accepted_at,
            envelope: request.body.clone(),
            targets,
            context,
        });
        // And judged again with the entry in.
        self.judge_lagging();
        let answer = json!({
            "entry_id": Self::entry_id(seq),
            "accepted_at": rfc3339(accepted_at),
            "directory_version": self.directory_version,
            "known_version": if sender.is_some() { self.known(&identity) } else { Value::Null },
        });
        self.appended
            .insert((identity, request.body.clone()), answer.clone());
        Ok((200, answer))
    }
}

/// `403 not_admitted`, which carries no `current` (Switch wire 7.6).
fn not_admitted() -> Answer {
    bad(ErrorCode::NotAdmitted, "not admitted", json!(null))
}
