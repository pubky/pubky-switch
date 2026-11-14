//! The operator's check of every account's chain head against its service key's mark, after
//! a database restore or before a failover (Switch spec 6.5): `pubky-switch check-marks`.
//!
//! A serving account whose head is behind its key's mark, or beside it, fails stop with
//! `503 unavailable` until its signer starts a new generation (Switch spec 6.5, 12.6). This
//! check finds those accounts without the service: it reads the database on one read-only
//! connection ([`heads`]) and the key store through a [`KeyStoreView`], and writes nothing
//! to either, so it runs beside a running service, or against a standby to choose the
//! database to fail over to.
//!
//! **No false `behind` beside a running service.** A mark moves only after the head it
//! names is committed (Switch wire 7.3 step 10), so the check reads a page of accounts'
//! service keys, then their marks from the files, and only then their heads: a head read
//! after its mark is at the mark or past it, unless state was lost. An account whose service
//! key changed between the two reads is read again on its own; one gone by then is skipped.

use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    str::FromStr,
};

use pubky_switch_core::{records::IdentityDoc, sig::SignedDoc};
use serde::Serialize;
use sqlx::{Connection, PgConnection, postgres::PgConnectOptions};

use crate::{
    config::Config,
    keys::{KeyId, KeyStoreError, KeyStoreView, Mark, MarkCheck, check_mark},
    service::rules::names_this_service,
    store::{
        StoreError,
        heads::{self, StoredHead},
    },
};

/// The environment variable that names the replica `--replica` checks.
pub const REPLICA_URL_ENV: &str = "PUBKY_SWITCH_REPLICA_URL";

/// How many accounts one page reads.
const PAGE: u32 = 500;

/// How many times an account whose service key keeps changing under the check is read
/// again before the check gives up on it.
const SETTLE_TRIES: usize = 5;

/// How an account's chain head compares with its service key's mark.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarkState {
    /// The erasure ledger holds an erasure of the identity at or after the account's
    /// creation: a restored database brought it back, and the service erases it again at
    /// start (Switch spec 6.5).
    ErasedInLedger,
    /// The key store has no key file for the account's service key.
    KeyMissing,
    /// The head is at the mark.
    Current,
    /// The head extends the mark, as a stop before the mark moved leaves it.
    Ahead,
    /// The head is behind the mark: acknowledged chain positions are missing.
    Behind,
    /// The head is at the mark's `seq` with another chain hash.
    Fork,
    /// The mark is of another generation than the account's.
    OtherGeneration,
    /// No chain and no mark: the key has signed nothing yet.
    Unmarked,
    /// A chain, and no mark file for its key: the mark was lost, or the mark of the
    /// account's first head never landed.
    MarkLost,
}

impl MarkState {
    /// Every state, in the order the summary lists them.
    pub const ALL: [Self; 9] = [
        Self::ErasedInLedger,
        Self::KeyMissing,
        Self::Current,
        Self::Ahead,
        Self::Behind,
        Self::Fork,
        Self::OtherGeneration,
        Self::Unmarked,
        Self::MarkLost,
    ];
}

/// What the check observed of one account: its head from the database, its key and mark
/// from the key store, and the ledger's erasure of its identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observed {
    /// The generation the account serves.
    pub generation: u64,
    /// When the account was created, in service time.
    pub created_at_ms: u64,
    /// The newest chain item's `seq` and chain hash; `None` before the first.
    pub chain: Option<(u64, [u8; 32])>,
    /// Whether the key store has the service key's file.
    pub key_present: bool,
    /// The service key's mark; `None` without a mark file.
    pub mark: Option<Mark>,
    /// The ledger's latest erasure of the identity, if any.
    pub erased_at_ms: Option<u64>,
}

/// The state of one account, with what the state reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The state.
    pub state: MarkState,
    /// For [`MarkState::Behind`]: how many acknowledged chain positions are missing, the
    /// mark's `seq` less the head's (0 for no chain).
    pub lost: Option<u64>,
    /// For [`MarkState::Ahead`]: how many `seq`s the head is past the mark.
    pub ahead_by: Option<u64>,
    /// For [`MarkState::ErasedInLedger`]: the erasure's time.
    pub erased_at_ms: Option<u64>,
}

impl Verdict {
    fn of(state: MarkState) -> Self {
        Self {
            state,
            lost: None,
            ahead_by: None,
            erased_at_ms: None,
        }
    }
}

/// Classify one account. The comparison is [`check_mark`]'s, the service's own, and a
/// missing chain is judged as the service's mark check judges it: a mark of the account's
/// generation over no chain is behind it (Switch spec 6.5).
pub fn classify(observed: &Observed) -> Verdict {
    // The same rule as the restored-erasure check at start: an account created at or
    // before the erasure is the erased one (Switch spec 6.5).
    if let Some(at) = observed.erased_at_ms
        && observed.created_at_ms <= at
    {
        return Verdict {
            erased_at_ms: Some(at),
            ..Verdict::of(MarkState::ErasedInLedger)
        };
    }
    if !observed.key_present {
        return Verdict::of(MarkState::KeyMissing);
    }
    let head = observed.chain.map(|(seq, chain_hash)| Mark {
        generation: observed.generation,
        seq,
        chain_hash,
    });
    match (head, observed.mark) {
        (Some(head), mark) => match check_mark(mark.as_ref(), &head) {
            MarkCheck::Unmarked => Verdict::of(MarkState::MarkLost),
            MarkCheck::Current => {
                let ahead = mark.map_or(0, |mark| head.seq.saturating_sub(mark.seq));
                if ahead == 0 {
                    Verdict::of(MarkState::Current)
                } else {
                    Verdict {
                        ahead_by: Some(ahead),
                        ..Verdict::of(MarkState::Ahead)
                    }
                }
            }
            MarkCheck::Behind => Verdict {
                lost: Some(mark.map_or(0, |mark| mark.seq.saturating_sub(head.seq))),
                ..Verdict::of(MarkState::Behind)
            },
            MarkCheck::Fork => Verdict::of(MarkState::Fork),
            MarkCheck::OtherGeneration => Verdict::of(MarkState::OtherGeneration),
        },
        (None, None) => Verdict::of(MarkState::Unmarked),
        (None, Some(mark)) if mark.generation == observed.generation => Verdict {
            lost: Some(mark.seq),
            ..Verdict::of(MarkState::Behind)
        },
        (None, Some(_)) => Verdict::of(MarkState::OtherGeneration),
    }
}

/// Whether the account serves: its held `identity.json`, verified with the identity's key,
/// names this service's `origin` and the account's service key (Switch wire 3.7). Only a
/// serving account is held to its mark. `false` without a document, without an origin,
/// without the key, or for a document that doesn't decode or verify (the service answers
/// such an account `503 unavailable` all the same).
pub fn judge_serving(
    identity_doc: Option<&[u8]>,
    identity_key: &[u8; 32],
    origin: Option<&str>,
    service_key: Option<&[u8; 32]>,
) -> bool {
    let (Some(bytes), Some(origin), Some(service_key)) = (identity_doc, origin, service_key) else {
        return false;
    };
    let Ok(signed) = serde_json::from_slice::<SignedDoc>(bytes) else {
        return false;
    };
    let Ok(held) = IdentityDoc::verify(&signed, identity_key) else {
        return false;
    };
    names_this_service(Some(&held), origin, service_key)
}

/// Whether an account needs the operator: a serving one the service refuses on its mark,
/// one the service erases again at start, and one whose service key is gone, serving or
/// not: without the key, whether the account serves can't be told (its `identity.json`
/// names the key's public half), and the account can sign nothing.
pub fn needs_attention(state: MarkState, serving: bool) -> bool {
    match state {
        MarkState::ErasedInLedger | MarkState::KeyMissing => true,
        MarkState::Behind | MarkState::Fork | MarkState::OtherGeneration | MarkState::MarkLost => {
            serving
        }
        MarkState::Current | MarkState::Ahead | MarkState::Unmarked => false,
    }
}

/// Which database the check read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseChoice {
    /// The configured one (`database.url`, or `PUBKY_SWITCH_DATABASE_URL`).
    Configured,
    /// The one `--replica` named.
    Replica,
}

/// What the check reads.
#[derive(Clone, Debug)]
pub struct CheckOptions {
    /// The database to read.
    pub database: PgConnectOptions,
    /// Which one it is, for the summary.
    pub choice: DatabaseChoice,
    /// The key store's directory.
    pub key_dir: PathBuf,
    /// This service's origin (`server.origin`), to tell serving accounts; none, and no
    /// account serves.
    pub origin: Option<String>,
    /// Report every account, not only those that need attention.
    pub all: bool,
}

impl CheckOptions {
    /// The options `config` gives, reading `replica` instead of the configured database
    /// when one is named.
    pub fn from_config(
        config: &Config,
        replica: Option<&str>,
        all: bool,
    ) -> Result<Self, CheckError> {
        let key_dir = config.keys.path.clone().ok_or(CheckError::NoKeyStore)?;
        let (url, choice) = match replica.filter(|url| !url.is_empty()) {
            Some(url) => (url.to_string(), DatabaseChoice::Replica),
            None => (
                config.database.effective_url().ok_or(StoreError::NoUrl)?,
                DatabaseChoice::Configured,
            ),
        };
        Ok(Self {
            database: PgConnectOptions::from_str(&url).map_err(StoreError::from)?,
            choice,
            key_dir,
            origin: config.server.origin.clone(),
            all,
        })
    }
}

/// What the check can fail at.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    /// No key store is configured.
    #[error("no key store: set keys.path")]
    NoKeyStore,
    /// The key store failed to read.
    #[error("key store: {0}")]
    Keys(#[from] KeyStoreError),
    /// The database failed to read.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// An account's service key changed at every read.
    #[error("account {0}: its service key kept changing while it was read")]
    Unsettled(String),
    /// The report didn't encode.
    #[error("writing the report: {0}")]
    Encode(#[from] serde_json::Error),
}

/// One account's line of the report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AccountReport {
    /// The identity's Pubky ID.
    pub account: String,
    /// The generation the account serves.
    pub generation: u64,
    /// Whether the account serves ([`judge_serving`]).
    pub serving: bool,
    /// Its state.
    pub state: MarkState,
    /// The head's `seq`; `None` before the first chain item.
    pub head_seq: Option<u64>,
    /// The mark's `seq`; `None` without a mark.
    pub mark_seq: Option<u64>,
    /// For `behind`: the acknowledged chain positions missing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lost: Option<u64>,
    /// For `ahead`: the `seq`s the head is past the mark.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ahead_by: Option<u64>,
    /// For `erased_in_ledger`: the erasure's time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub erased_at_ms: Option<u64>,
}

impl AccountReport {
    /// Whether the account needs attention ([`needs_attention`]).
    pub fn needs_attention(&self) -> bool {
        needs_attention(self.state, self.serving)
    }
}

/// The counts of a check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// The database read.
    pub database: DatabaseChoice,
    /// The accounts checked.
    pub accounts: u64,
    /// Of them, the serving ones.
    pub serving: u64,
    /// Of them, those that need attention.
    pub needs_attention: u64,
    /// The accounts in each state, every state listed.
    pub states: BTreeMap<MarkState, u64>,
}

impl Summary {
    fn new(database: DatabaseChoice) -> Self {
        Self {
            database,
            accounts: 0,
            serving: 0,
            needs_attention: 0,
            states: MarkState::ALL.iter().map(|state| (*state, 0)).collect(),
        }
    }
}

/// The result of a check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The accounts reported: those that need attention, or every one with
    /// [`CheckOptions::all`], in the order of their IDs.
    pub accounts: Vec<AccountReport>,
    /// The counts over every account checked.
    pub summary: Summary,
}

impl Report {
    /// Whether any account needs attention.
    pub fn needs_attention(&self) -> bool {
        self.summary.needs_attention > 0
    }

    /// The report as JSON lines: one object per account reported, then the summary.
    pub fn to_json_lines(&self) -> Result<String, CheckError> {
        #[derive(Serialize)]
        struct SummaryLine<'a> {
            summary: &'a Summary,
        }
        let mut out = String::new();
        for account in &self.accounts {
            out.push_str(&serde_json::to_string(account)?);
            out.push('\n');
        }
        out.push_str(&serde_json::to_string(&SummaryLine {
            summary: &self.summary,
        })?);
        out.push('\n');
        Ok(out)
    }

    fn add(&mut self, account: AccountReport, all: bool) {
        let summary = &mut self.summary;
        summary.accounts = summary.accounts.saturating_add(1);
        if account.serving {
            summary.serving = summary.serving.saturating_add(1);
        }
        let attention = account.needs_attention();
        if attention {
            summary.needs_attention = summary.needs_attention.saturating_add(1);
        }
        let count = summary.states.entry(account.state).or_insert(0);
        *count = count.saturating_add(1);
        if attention || all {
            self.accounts.push(account);
        }
    }
}

/// A key's files as the check read them.
#[derive(Clone, Copy, Debug, Default)]
struct KeyFiles {
    public: Option<[u8; 32]>,
    mark: Option<Mark>,
}

fn read_key_files(view: &KeyStoreView, key: &KeyId) -> Result<KeyFiles, KeyStoreError> {
    Ok(KeyFiles {
        public: view.public_key(key)?,
        mark: view.mark(key)?,
    })
}

/// Run the check. It writes nothing: the key store is opened as a [`KeyStoreView`], before
/// the database, so a key store that isn't there fails the check before it connects.
pub async fn run(options: &CheckOptions) -> Result<Report, CheckError> {
    let view = KeyStoreView::open(&options.key_dir)?;
    let mut conn = heads::open_read_only_with(&options.database).await?;
    let result = check(&mut conn, &view, options).await;
    let _ = conn.close().await;
    result
}

async fn check(
    conn: &mut PgConnection,
    view: &KeyStoreView,
    options: &CheckOptions,
) -> Result<Report, CheckError> {
    let mut report = Report {
        accounts: Vec::new(),
        summary: Summary::new(options.choice),
    };
    let origin = options.origin.as_deref();
    let mut after: Option<String> = None;
    loop {
        // (a) The page's service keys, (b) their marks, (c) then their heads: a head read
        // after its mark is at the mark or past it (Switch wire 7.3 step 10).
        let page = heads::service_keys_after(conn, after.as_deref(), PAGE).await?;
        let Some((last, _)) = page.last() else {
            break;
        };
        after = Some(last.clone());
        let mut files = HashMap::with_capacity(page.len());
        for (_, key) in &page {
            files.insert(key.clone(), read_key_files(view, key)?);
        }
        let ids: Vec<String> = page.iter().map(|(id, _)| id.clone()).collect();
        let mut found: HashMap<String, StoredHead> = heads::heads(conn, &ids)
            .await?
            .into_iter()
            .map(|head| (head.id.clone(), head))
            .collect();
        for (id, key) in &page {
            // Gone since the page was read: erased, nothing to report.
            let Some(head) = found.remove(id) else {
                continue;
            };
            let settled = if head.service_key == *key {
                Some((head, files.get(key).copied().unwrap_or_default()))
            } else {
                settle(conn, view, id).await?
            };
            if let Some((head, files)) = settled {
                report.add(assess(&head, files, view, origin), options.all);
            }
        }
        if page.len() < usize::try_from(PAGE).unwrap_or(usize::MAX) {
            break;
        }
    }
    Ok(report)
}

/// Read account `id` again on its own, (a) to (c), until its service key holds still
/// between the reads; `None` once it is gone.
async fn settle(
    conn: &mut PgConnection,
    view: &KeyStoreView,
    id: &str,
) -> Result<Option<(StoredHead, KeyFiles)>, CheckError> {
    let ids = [id.to_string()];
    for _ in 0..SETTLE_TRIES {
        let Some(before) = heads::heads(conn, &ids).await?.into_iter().next() else {
            return Ok(None);
        };
        let files = read_key_files(view, &before.service_key)?;
        let Some(head) = heads::heads(conn, &ids).await?.into_iter().next() else {
            return Ok(None);
        };
        if head.service_key == before.service_key {
            return Ok(Some((head, files)));
        }
    }
    Err(CheckError::Unsettled(id.to_string()))
}

fn assess(
    head: &StoredHead,
    files: KeyFiles,
    view: &KeyStoreView,
    origin: Option<&str>,
) -> AccountReport {
    let verdict = classify(&Observed {
        generation: head.generation,
        created_at_ms: head.created_at_ms,
        chain: head.chain,
        key_present: files.public.is_some(),
        mark: files.mark,
        erased_at_ms: view.erasure(&head.id),
    });
    AccountReport {
        account: head.id.clone(),
        generation: head.generation,
        serving: judge_serving(
            head.identity_doc.as_deref(),
            &head.identity_key,
            origin,
            files.public.as_ref(),
        ),
        state: verdict.state,
        head_seq: head.chain.map(|(seq, _)| seq),
        mark_seq: files.mark.map(|mark| mark.seq),
        lost: verdict.lost,
        ahead_by: verdict.ahead_by,
        erased_at_ms: verdict.erased_at_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_switch_core::{
        keys::IdentityKey,
        records::{IdentityBody, IdentityPolicy, Inbox},
    };

    const ORIGIN: &str = "https://switch.example";

    fn mark(generation: u64, seq: u64, hash: u8) -> Mark {
        Mark {
            generation,
            seq,
            chain_hash: [hash; 32],
        }
    }

    fn observed(chain: Option<(u64, u8)>, mark: Option<Mark>) -> Observed {
        Observed {
            generation: 1,
            created_at_ms: 1_000,
            chain: chain.map(|(seq, hash)| (seq, [hash; 32])),
            key_present: true,
            mark,
            erased_at_ms: None,
        }
    }

    fn state(observed: &Observed) -> MarkState {
        classify(observed).state
    }

    #[test]
    fn test_check_marks_current_and_ahead() {
        let at = classify(&observed(Some((5, 1)), Some(mark(1, 5, 1))));
        assert_eq!(at, Verdict::of(MarkState::Current));
        let ahead = classify(&observed(Some((8, 2)), Some(mark(1, 5, 1))));
        assert_eq!(ahead.state, MarkState::Ahead);
        assert_eq!(ahead.ahead_by, Some(3));
        assert_eq!(ahead.lost, None);
    }

    #[test]
    fn test_check_marks_behind_reports_lost() {
        let behind = classify(&observed(Some((3, 1)), Some(mark(1, 10, 1))));
        assert_eq!(behind.state, MarkState::Behind);
        assert_eq!(behind.lost, Some(7));
        assert_eq!(behind.ahead_by, None);
    }

    #[test]
    fn test_check_marks_fork_and_other_generation() {
        assert_eq!(
            state(&observed(Some((5, 2)), Some(mark(1, 5, 1)))),
            MarkState::Fork
        );
        assert_eq!(
            state(&observed(Some((9, 1)), Some(mark(2, 5, 1)))),
            MarkState::OtherGeneration
        );
    }

    #[test]
    fn test_check_marks_missing_chain() {
        // A mark of the account's generation over no chain: every position it names is lost.
        let behind = classify(&observed(None, Some(mark(1, 4, 1))));
        assert_eq!(behind.state, MarkState::Behind);
        assert_eq!(behind.lost, Some(4));
        assert_eq!(
            state(&observed(None, Some(mark(2, 4, 1)))),
            MarkState::OtherGeneration
        );
        assert_eq!(state(&observed(None, None)), MarkState::Unmarked);
    }

    #[test]
    fn test_check_marks_mark_lost_and_key_missing() {
        assert_eq!(state(&observed(Some((2, 1)), None)), MarkState::MarkLost);
        let missing = Observed {
            key_present: false,
            ..observed(Some((5, 1)), Some(mark(1, 5, 1)))
        };
        assert_eq!(state(&missing), MarkState::KeyMissing);
    }

    #[test]
    fn test_check_marks_erased_in_ledger_takes_precedence() {
        // Over a missing key and a state behind the mark alike.
        let erased = Observed {
            key_present: false,
            erased_at_ms: Some(1_000),
            ..observed(Some((1, 1)), Some(mark(1, 5, 1)))
        };
        let verdict = classify(&erased);
        assert_eq!(verdict.state, MarkState::ErasedInLedger);
        assert_eq!(verdict.erased_at_ms, Some(1_000));
        // An account created after its identity's erasure is a new one.
        let later = Observed {
            erased_at_ms: Some(999),
            ..observed(Some((5, 1)), Some(mark(1, 5, 1)))
        };
        assert_eq!(state(&later), MarkState::Current);
    }

    #[test]
    fn test_check_marks_needs_attention() {
        for state in [
            MarkState::Behind,
            MarkState::Fork,
            MarkState::OtherGeneration,
            MarkState::MarkLost,
        ] {
            assert!(needs_attention(state, true), "{state:?}");
            assert!(!needs_attention(state, false), "{state:?}");
        }
        assert!(needs_attention(MarkState::ErasedInLedger, false));
        // Without its key an account can't be told serving, and signs nothing.
        assert!(needs_attention(MarkState::KeyMissing, false));
        for state in [MarkState::Current, MarkState::Ahead, MarkState::Unmarked] {
            assert!(!needs_attention(state, true), "{state:?}");
        }
    }

    #[test]
    fn test_check_marks_judge_serving() {
        let identity = IdentityKey::from_secret([1; 32]);
        let service_key = [9u8; 32];
        let doc = |origin: &str| {
            let body = IdentityBody::first(
                identity.public(),
                [4; 16],
                Inbox::new(origin, service_key),
                IdentityPolicy::default(),
            );
            serde_json::to_vec(IdentityDoc::sign(&identity, body).expect("sign").signed())
                .expect("encode")
        };
        let named = doc(ORIGIN);
        let key = identity.public();
        assert!(judge_serving(
            Some(&named),
            &key,
            Some(ORIGIN),
            Some(&service_key)
        ));
        // Another origin or another key names another service.
        assert!(!judge_serving(
            Some(&doc("https://other.example")),
            &key,
            Some(ORIGIN),
            Some(&service_key)
        ));
        assert!(!judge_serving(
            Some(&named),
            &key,
            Some(ORIGIN),
            Some(&[8; 32])
        ));
        // No document, no origin, no key, a document under another identity or one that
        // doesn't decode: not serving.
        assert!(!judge_serving(None, &key, Some(ORIGIN), Some(&service_key)));
        assert!(!judge_serving(Some(&named), &key, None, Some(&service_key)));
        assert!(!judge_serving(Some(&named), &key, Some(ORIGIN), None));
        assert!(!judge_serving(
            Some(&named),
            &[3; 32],
            Some(ORIGIN),
            Some(&service_key)
        ));
        assert!(!judge_serving(
            Some(b"not json"),
            &key,
            Some(ORIGIN),
            Some(&service_key)
        ));
    }

    #[test]
    fn test_check_marks_json_lines() {
        let mut report = Report {
            accounts: Vec::new(),
            summary: Summary::new(DatabaseChoice::Replica),
        };
        let line = |state, serving, lost| AccountReport {
            account: "aaa".into(),
            generation: 1,
            serving,
            state,
            head_seq: Some(3),
            mark_seq: Some(5),
            lost,
            ahead_by: None,
            erased_at_ms: None,
        };
        report.add(line(MarkState::Behind, true, Some(2)), false);
        report.add(line(MarkState::Current, true, None), false);
        assert!(report.needs_attention());
        let text = report.to_json_lines().expect("encode");
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("json"))
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            serde_json::json!({
                "account": "aaa", "generation": 1, "serving": true, "state": "behind",
                "head_seq": 3, "mark_seq": 5, "lost": 2
            })
        );
        let summary = &lines[1]["summary"];
        assert_eq!(summary["database"], "replica");
        assert_eq!(summary["accounts"], 2);
        assert_eq!(summary["serving"], 2);
        assert_eq!(summary["needs_attention"], 1);
        assert_eq!(summary["states"]["behind"], 1);
        assert_eq!(summary["states"]["current"], 1);
        assert_eq!(summary["states"]["mark_lost"], 0);
        assert_eq!(
            summary["states"].as_object().map(|states| states.len()),
            Some(9)
        );
    }
}
