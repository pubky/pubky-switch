//! What the harness verifies itself of every answer, in both runs.
//!
//! The comparison ([`crate::compare`]) sets one run beside the other. It can't tell a hash,
//! a signature or a key that a switch makes itself, echoing nothing a party sent, from the
//! right one: if such a value is wrong from its first appearance and repeated consistently
//! wherever the right one would show, the two runs still read alike. The client and the
//! signer verify much of it, and a flow fails where they refuse. This module checks the
//! rest of what the harness holds the means to check, on every answer of either switch:
//!
//! - the answer's signature (Switch wire 7.1), with the account's service key, or the
//!   operator key for an answer the switch can't tie to an account;
//! - every signed head, in `Switch-Head` and in a body's `head` (Switch wire 6.7): its
//!   signature, and its chain hash against the stub of its `seq` where the run showed one;
//! - every chain stub (Switch wire 6.6): its chain hash follows from its envelope, the stub
//!   at one `seq` is always the same, and its `prev_chain_hash` is the chain hash of the
//!   `seq` before where the run showed it;
//! - every feed item shown in full: its document hashes to its envelope's `item_hash`;
//! - every transition proof (Switch wire 6.5): its signature, and its stub as above.
//!
//! A check that fails is a `violation` fact on the answer's line, and the comparison
//! reports every violation as a difference, also one both runs show.
//!
//! Still unchecked, by the harness and so only as far as the client and the signer check
//! them: the signatures of documents a party signed and the switch only carries, sealed
//! values, and whether a proof's state is the right one for its operation, which the
//! comparison covers by setting the two runs' states side by side.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, MutexGuard, PoisonError};

use pubky_switch_client::transport::{Request, Response};
use pubky_switch_core::chain::{
    ChainEnvelope, ItemType, SignedHead, Stub, TransitionProof, Verifier, ZERO_HASH,
};
use pubky_switch_core::enc::unb64_array;
use pubky_switch_core::http::{header, request_signature_of, verify_response};
use pubky_switch_core::sig::SignedDoc;
use serde_json::Value;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An account the checker knows: its identity key and its service key.
#[derive(Clone, Copy)]
struct Account {
    identity: [u8; 32],
    service_key: [u8; 32],
}

/// Verifies what a run's answers carry.
#[derive(Default)]
pub struct Checker {
    /// The accounts, by Pubky ID.
    accounts: Mutex<HashMap<String, Account>>,
    /// The operator key of the run's switches.
    operator_key: Mutex<Option<[u8; 32]>>,
    /// The chain hash the run showed at each `seq`, by account.
    chains: Mutex<HashMap<String, BTreeMap<u64, [u8; 32]>>>,
}

impl std::fmt::Debug for Checker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Checker({} accounts)", lock(&self.accounts).len())
    }
}

/// Which key an answer's signature verified with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedWith {
    /// The account's service key.
    ServiceKey,
    /// The operator key.
    OperatorKey,
}

impl Checker {
    /// The answers of the account `id` (a Pubky ID), of the identity `identity`, are
    /// signed with `service_key`.
    pub fn account(&self, id: &str, identity: [u8; 32], service_key: [u8; 32]) {
        lock(&self.accounts).insert(
            id.to_owned(),
            Account {
                identity,
                service_key,
            },
        );
    }

    /// Answers the switch can't tie to an account are signed with `operator_key`.
    pub fn operator(&self, operator_key: [u8; 32]) {
        *lock(&self.operator_key) = Some(operator_key);
    }

    /// The account a request is for: the one its path names, or for an enrollment the one
    /// it is signed for.
    fn account_of(&self, request: &Request) -> Option<(String, Account)> {
        let id = match request.path_and_query.strip_prefix("/v1/")? {
            rest if rest == "enroll" || rest.starts_with("enroll?") => {
                request.header(header::IDENTITY)?
            }
            rest => rest.split(['/', '?']).next()?,
        };
        let account = *lock(&self.accounts).get(id)?;
        Some((id.to_owned(), account))
    }

    /// Verify `answer`'s signature as the switch sent it.
    ///
    /// # Errors
    ///
    /// What is wrong with it.
    pub fn signature(&self, request: &Request, answer: &Response) -> Result<SignedWith, String> {
        let signature = answer
            .header(header::SERVICE_SIGNATURE)
            .and_then(|text| unb64_array::<64>(text).ok())
            .ok_or("the answer carries no service signature")?;
        let server_time = answer
            .header(header::SERVER_TIME)
            .ok_or("the answer carries no service time")?;
        let request_signature = request_signature_of(request.header(header::SIGNATURE));
        let verifies = |key: &[u8; 32]| {
            verify_response(
                key,
                answer.status,
                request_signature.as_ref(),
                server_time,
                &answer.body,
                &signature,
            )
            .is_ok()
        };
        if let Some((_, account)) = self.account_of(request)
            && verifies(&account.service_key)
        {
            return Ok(SignedWith::ServiceKey);
        }
        if let Some(operator) = *lock(&self.operator_key)
            && verifies(&operator)
        {
            return Ok(SignedWith::OperatorKey);
        }
        Err(
            "the answer's signature verifies with neither the account's service key nor the \
             operator key"
                .into(),
        )
    }

    /// Verify what `answer` carries: its heads, stubs, items and proofs. Returns what is
    /// wrong, nothing when all of it holds or the request is for no account the checker
    /// knows.
    pub fn contents(&self, request: &Request, answer: &Response) -> Vec<String> {
        let Some((id, account)) = self.account_of(request) else {
            return Vec::new();
        };
        let mut found = Found {
            checker: self,
            id: &id,
            account,
            violations: Vec::new(),
        };
        if let Some(text) = answer.header(header::HEAD) {
            match SignedHead::from_header(text) {
                Ok(head) => found.head(&head, "Switch-Head"),
                Err(error) => found.violation(format!("Switch-Head doesn't read: {error}")),
            }
        }
        if let Ok(body) = serde_json::from_slice::<Value>(&answer.body) {
            found.value("body", &body);
        }
        found.violations
    }
}

/// The checks of one answer.
struct Found<'a> {
    checker: &'a Checker,
    id: &'a str,
    account: Account,
    violations: Vec<String>,
}

impl Found<'_> {
    fn violation(&mut self, text: String) {
        self.violations.push(text);
    }

    /// Walk a JSON value, checking each head, stub, feed item and proof found in it.
    fn value(&mut self, at: &str, value: &Value) {
        match value {
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    self.value(&format!("{at}[{index}]"), item);
                }
            }
            Value::Object(members) => {
                let is = |names: &[&str]| {
                    members.len() == names.len() && names.iter().all(|n| members.contains_key(*n))
                };
                if is(&["envelope", "chain_hash"]) {
                    match Stub::from_value(value) {
                        Ok(stub) => {
                            self.stub(&stub, at);
                        }
                        Err(error) => self.violation(format!("{at}: a stub doesn't read: {error}")),
                    }
                    return;
                }
                if let (Some(stub), Some(item), Some(item_type)) = (
                    members.get("stub"),
                    members.get("item"),
                    members.get("item_type").and_then(Value::as_str),
                ) {
                    self.item(stub, item, item_type, at);
                }
                for (name, member) in members {
                    let at = format!("{at}.{name}");
                    match name.as_str() {
                        "head" if member.is_object() => match SignedHead::from_value(member) {
                            Ok(head) => self.head(&head, &at),
                            Err(error) => {
                                self.violation(format!("{at}: a head doesn't read: {error}"));
                            }
                        },
                        "proof" if member.is_object() => self.proof(member, &at),
                        "proofs" => {
                            for (index, proof) in
                                member.as_array().into_iter().flatten().enumerate()
                            {
                                self.proof(proof, &format!("{at}[{index}]"));
                            }
                        }
                        _ => self.value(&at, member),
                    }
                }
            }
            _ => {}
        }
    }

    /// A signed head: its signature, and its chain hash where the run showed its `seq`.
    fn head(&mut self, head: &SignedHead, at: &str) {
        if head
            .verify(&self.account.service_key, &self.account.identity)
            .is_err()
        {
            self.violation(format!(
                "{at}: the head's signature doesn't verify with the account's service key"
            ));
        }
        let shown = lock(&self.checker.chains)
            .get(self.id)
            .and_then(|chain| chain.get(&head.seq).copied());
        let expected = match shown {
            Some(hash) => Some(hash),
            None if head.seq == 0 => Some(ZERO_HASH),
            None => None,
        };
        if expected.is_some_and(|hash| hash != head.chain_hash) {
            self.violation(format!(
                "{at}: the head's chain hash isn't that of the stub the run showed at seq {}",
                head.seq
            ));
        }
    }

    /// A chain stub: its chain hash follows from its envelope, and it links to what the run
    /// showed before. Returns its envelope when it reads.
    fn stub(&mut self, stub: &Stub, at: &str) -> Option<ChainEnvelope> {
        let envelope = match stub.open() {
            Ok(envelope) => envelope,
            Err(error) => {
                self.violation(format!("{at}: {error}"));
                return None;
            }
        };
        let (same_seq, before) = {
            let mut chains = lock(&self.checker.chains);
            let chain = chains.entry(self.id.to_owned()).or_default();
            let same_seq = chain.insert(envelope.seq, stub.chain_hash);
            let before = envelope
                .seq
                .checked_sub(1)
                .and_then(|seq| chain.get(&seq).copied());
            (same_seq, before)
        };
        if same_seq.is_some_and(|hash| hash != stub.chain_hash) {
            self.violation(format!(
                "{at}: another chain hash at seq {} than the run showed before",
                envelope.seq
            ));
        }
        if before.is_some_and(|hash| hash != envelope.prev_chain_hash) {
            self.violation(format!(
                "{at}: the stub at seq {} doesn't follow the one the run showed before it",
                envelope.seq
            ));
        }
        Some(envelope)
    }

    /// A feed item shown in full: its document hashes to its envelope's item hash.
    fn item(&mut self, stub: &Value, item: &Value, item_type: &str, at: &str) {
        let item_type = match item_type {
            "op" => ItemType::Op,
            "identity" => ItemType::Identity,
            "service" => ItemType::Service,
            other => {
                self.violation(format!("{at}: an item of the unknown type {other}"));
                return;
            }
        };
        // The stub itself is checked where the walk reaches it.
        let Some(envelope) = Stub::from_value(stub)
            .ok()
            .and_then(|stub| stub.open().ok())
        else {
            return;
        };
        let bytes = serde_json::from_value::<SignedDoc>(item.clone())
            .ok()
            .and_then(|doc| doc.doc_bytes().ok());
        match bytes {
            Some(bytes) => {
                if Verifier::check_item(&envelope, item_type, &bytes).is_err() {
                    self.violation(format!(
                        "{at}: the item at seq {} doesn't hash to its envelope's item hash",
                        envelope.seq
                    ));
                }
            }
            None => self.violation(format!("{at}: an item that isn't a signed document")),
        }
    }

    /// A transition proof: its signature, and its stub.
    fn proof(&mut self, proof: &Value, at: &str) {
        let Ok(signed) = serde_json::from_value::<SignedDoc>(proof.clone()) else {
            self.violation(format!("{at}: a proof that isn't a signed document"));
            return;
        };
        match TransitionProof::verify(&signed, &self.account.service_key, &self.account.identity) {
            Ok(proof) => {
                self.stub(&proof.body().chain, &format!("{at}, its stub"));
            }
            Err(_) => self.violation(format!(
                "{at}: the proof's signature doesn't verify with the account's service key"
            )),
        }
    }
}
