//! The bounds on entries stored because their sender's standing couldn't be checked
//! (Switch spec 8.2, 12.4): 21 days on verified service time, 64 per sender identity, 128 in
//! all from the identity that holds the most, applied at every read, in bounded steps.

use std::sync::{Arc, Mutex};

use pubky_switch_core::keys::IdentityKey;
use pubky_switch_core::message::{Message, Sender};
use pubky_switch_core::records::DAY_MS;
use serde_json::{Map, Value, json};

use super::moves::has;
use super::*;
use crate::app::state::ParkedEntry;
use crate::app::{
    AppEvent, DropReason, MAX_UNVERIFIED_AGE_MS, MAX_UNVERIFIED_PER_SENDER, MAX_UNVERIFIED_TOTAL,
    ParkReason, UNVERIFIED_DROPS_PER_COMMIT,
};
use crate::clock::Clock;
use crate::error::StoreError;
use crate::store::{KeyValue, Write, WriteBatch};

/// The sample protocol, with a backup layer.
#[derive(Default)]
struct BackedUp {
    sample: SampleProtocol,
}

impl Protocol for BackedUp {
    fn has_keys(&self, scope: &str) -> bool {
        self.sample.has_keys(scope)
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.sample.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String> {
        self.sample.check_scopes(message, sender, own)
    }

    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        self.sample.accepts(cert)
    }

    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        self.sample.check_body(message)
    }

    fn receive(&self, message: &ReceivedMessage) -> Outcome {
        self.sample.receive(message)
    }

    fn resend_needed(
        &self,
        needed: &ResendNeeded,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.sample.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.sample.missed(missed)
    }

    fn backup_name(&self) -> Option<String> {
        Some("sample.bound".into())
    }
}

/// A device clock `offset_ms` off the world's, ahead or behind.
struct Skewed {
    world: Arc<crate::clock::TestClock>,
    offset_ms: i64,
}

impl Clock for Skewed {
    fn now_ms(&self) -> u64 {
        self.world.now_ms().saturating_add_signed(self.offset_ms)
    }
}

/// A store that counts, for each commit, the entries stored locally it deletes.
struct Counting {
    inner: Arc<MemoryStore>,
    deleted: Mutex<Vec<usize>>,
}

impl StateStore for Counting {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.get(ns, key)
    }

    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<KeyValue>, StoreError> {
        self.inner.scan(ns, prefix, after, limit)
    }

    fn commit(&self, batch: WriteBatch) -> Result<(), StoreError> {
        let parked = batch
            .writes
            .iter()
            .filter(
                |write| matches!(write, Write::Delete { key, .. } if key.starts_with(b"parked/")),
            )
            .count();
        self.deleted.lock().unwrap().push(parked);
        self.inner.commit(batch)
    }
}

/// A sender identity other than alice's, with one app.
struct Peer {
    identity: IdentityKey,
    keys: AppKeys,
    cert: AppCert,
}

fn peer(w: &World, name: &str) -> Peer {
    let identity = IdentityKey::from_secret(seed(&format!("{name}/identity")));
    let keys = app_keys(&format!("{name}-app"));
    let cert = cert_for(&identity, &keys, w.clock.now_ms(), &["scope-a"]);
    Peer {
        identity,
        keys,
        cert,
    }
}

/// Alice's wallet on `env`.
async fn wallet(w: &World, env: AppEnv) -> App {
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    App::join(env, Arc::new(BackedUp::default()), World::config(), request)
        .await
        .unwrap()
}

/// `n` notes from each of `peers`, a millisecond apart, held while their senders' Homeservers
/// can't be reached and stored as unverifiable after the bounded wait. Returns their
/// `seq`s, by peer.
async fn stored_unverified(w: &World, app: &mut App, peers: &[(&Peer, usize)]) -> Vec<Vec<u64>> {
    w.homeserver.set_down(true);
    let mut seqs = Vec::new();
    for (peer, n) in peers {
        let mut sent = Vec::new();
        for _ in 0..*n {
            w.clock.advance_ms(1);
            let (seq, _) = w
                .switch
                .send(
                    &peer.identity,
                    &peer.keys,
                    &peer.cert,
                    "sample.note",
                    json!({ "text": "unverified" }),
                    &[app.app_id()],
                )
                .unwrap();
            sent.push(seq);
        }
        seqs.push(sent);
    }
    app.receive(None).await.unwrap();
    w.clock.advance_ms(World::config().park_after_ms + 1);
    app.receive(None).await.unwrap();
    for seq in seqs.iter().flatten() {
        assert_eq!(
            app.stored_at(*seq).map(|stored| stored.reason),
            Some(ParkReason::Unverifiable),
            "{seq}"
        );
    }
    seqs
}

/// The entries dropped, by `seq`, with why, in `events`.
fn dropped(events: &[AppEvent]) -> Vec<(u64, DropReason)> {
    events
        .iter()
        .filter_map(|e| match e {
            AppEvent::StoredEntryDropped { seq, reason, .. } => Some((*seq, *reason)),
            _ => None,
        })
        .collect()
}

/// An entry stored as `reason` by a build before the bounds, written to the store as it
/// is: a note signed by `peer`, accepted at `accepted_at_ms`.
fn entry_of(
    w: &World,
    peer: &Peer,
    seq: u64,
    accepted_at_ms: u64,
    reason: ParkReason,
) -> ParkedEntry {
    let mut body = Map::new();
    body.insert("text".into(), Value::from("stored before"));
    let message = Message::new(
        "sample.note",
        Sender::of_app(peer.identity.public(), &peer.keys),
        w.alice.public(),
        accepted_at_ms,
        vec![],
        body,
    )
    .unwrap();
    ParkedEntry {
        seq,
        generation: 1,
        sender: peer.identity.public(),
        cert: peer.cert.signed().clone(),
        accepted_at_ms,
        plaintext: message.sign(&peer.keys).unwrap().encode(),
        context: None,
        reason,
        round: 0,
    }
}

/// Write `entries` to `app`'s store, as an earlier build left them, under the next IDs.
async fn write_stored(app: &mut App, entries: Vec<ParkedEntry>) -> Vec<u64> {
    let mut ids = Vec::new();
    for chunk in entries.chunks(64) {
        let mut tx = app.tx().unwrap();
        for entry in chunk {
            let id = app.state.next_stored_id;
            app.state.next_stored_id += 1;
            tx.put(&crate::app::state::key::parked(id), entry).unwrap();
            app.state.parked.insert(id, entry.clone());
            ids.push(id);
        }
        tx.put(
            crate::app::state::key::STORED_NEXT,
            &app.state.next_stored_id,
        )
        .unwrap();
        app.commit(tx).await.unwrap();
    }
    ids
}

#[tokio::test]
async fn test_unverified_bound_age_is_judged_on_verified_time_with_the_device_ahead() {
    let w = World::new();
    let env = AppEnv {
        clock: Arc::new(Skewed {
            world: Arc::clone(&w.clock),
            offset_ms: 30 * DAY_MS as i64,
        }),
        ..w.env()
    };
    let mut app = wallet(&w, env).await;
    let h = peer(&w, "honest");
    let seqs = stored_unverified(&w, &mut app, &[(&h, 1)]).await;
    // The device clock is 30 days ahead: the entry is past 21 days by it, not by the
    // service time verified, so it stays.
    let report = app.receive(None).await.unwrap();
    assert!(dropped(&report.events).is_empty(), "{:?}", report.events);
    assert!(app.stored_at(seqs[0][0]).is_some());
    // Past 21 days of service time, it goes.
    w.clock.advance_ms(MAX_UNVERIFIED_AGE_MS);
    app.receive(None).await.unwrap();
    let report = app.receive(None).await.unwrap();
    let events = [report.events, app.kept_duties().await.unwrap()].concat();
    assert!(
        dropped(&events).contains(&(seqs[0][0], DropReason::Age)),
        "{events:?}"
    );
    assert!(app.stored_at(seqs[0][0]).is_none());
}

#[tokio::test]
async fn test_unverified_bound_age_is_judged_on_verified_time_with_the_device_behind() {
    let w = World::new();
    let env = AppEnv {
        clock: Arc::new(Skewed {
            world: Arc::clone(&w.clock),
            offset_ms: -30 * DAY_MS as i64,
        }),
        ..w.env()
    };
    let mut app = wallet(&w, env).await;
    let h = peer(&w, "honest");
    let seqs = stored_unverified(&w, &mut app, &[(&h, 1)]).await;
    // 21 days of service time later the device clock is still before the acceptance, but
    // the service time the app verified is past the bound: the entry goes.
    w.clock.advance_ms(MAX_UNVERIFIED_AGE_MS);
    app.receive(None).await.unwrap();
    app.receive(None).await.unwrap();
    let kept = app.kept_duties().await.unwrap();
    assert!(
        dropped(&kept).contains(&(seqs[0][0], DropReason::Age)),
        "{kept:?}"
    );
    assert!(app.stored_at(seqs[0][0]).is_none());
}

#[tokio::test]
async fn test_unverified_bound_drop_keeps_a_duty_event_naming_the_entry() {
    let w = World::new();
    let mut app = wallet(&w, w.env()).await;
    let h = peer(&w, "honest");
    let seqs = stored_unverified(&w, &mut app, &[(&h, 1)]).await;
    let seq = seqs[0][0];
    let stored = app.stored_at(seq).unwrap().clone();
    let id = app.stored_id_at(seq).unwrap();
    w.clock.advance_ms(MAX_UNVERIFIED_AGE_MS);
    app.receive(None).await.unwrap();
    app.receive(None).await.unwrap();
    // Kept, so it is delivered again after a reload until acknowledged; the entry and its
    // retry count went in the same commit.
    let mut app = App::load(
        w.env(),
        Arc::new(BackedUp::default()),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    let kept = app.unacknowledged_events().await.unwrap();
    assert!(
        has(&kept, |e| matches!(
            e,
            AppEvent::StoredEntryDropped {
                id: _,
                stored_id,
                seq: s,
                generation: 1,
                sender,
                accepted_at_ms,
                reason: DropReason::Age,
            } if *stored_id == id
                && *s == seq
                && *sender == h.identity.public()
                && *accepted_at_ms == stored.accepted_at_ms
        )),
        "{kept:?}"
    );
    assert!(app.stored_at(seq).is_none());
    assert!(app.no_retries());
}

#[tokio::test]
async fn test_unverified_bound_per_sender_drops_the_accepted_earliest() {
    let w = World::new();
    let mut app = wallet(&w, w.env()).await;
    let h = peer(&w, "honest");
    let seqs = stored_unverified(&w, &mut app, &[(&h, MAX_UNVERIFIED_PER_SENDER + 1)]).await;
    // The next read applies the bound: the one accepted earliest goes.
    let report = app.receive(None).await.unwrap();
    assert_eq!(
        dropped(&report.events),
        vec![(seqs[0][0], DropReason::PerSender)]
    );
    assert!(app.stored_at(seqs[0][0]).is_none());
    assert!(seqs[0][1..].iter().all(|seq| app.stored_at(*seq).is_some()));
}

#[tokio::test]
async fn test_unverified_bound_total_drops_from_the_largest_holder_not_an_honest_sender() {
    let w = World::new();
    let mut app = wallet(&w, w.env()).await;
    // An honest sender in an outage, its genuine entries stored first; then two hostile
    // identities, their own Homeservers unreachable, send 64 each.
    let h = peer(&w, "honest");
    let a1 = peer(&w, "hostile-1");
    let a2 = peer(&w, "hostile-2");
    let seqs = stored_unverified(
        &w,
        &mut app,
        &[
            (&h, 10),
            (&a1, MAX_UNVERIFIED_PER_SENDER),
            (&a2, MAX_UNVERIFIED_PER_SENDER),
        ],
    )
    .await;
    assert_eq!(app.stored_seqs().len(), 138);
    let report = app.receive(None).await.unwrap();
    let drops = dropped(&report.events);
    assert_eq!(drops.len(), 138 - MAX_UNVERIFIED_TOTAL);
    assert!(drops.iter().all(|(_, reason)| *reason == DropReason::Total));
    // The honest sender's entries all stay; the hostile ones' accepted earliest go, five
    // each, the largest holder in turn.
    assert!(seqs[0].iter().all(|seq| app.stored_at(*seq).is_some()));
    let mut expected: Vec<u64> = seqs[1][..5].iter().chain(&seqs[2][..5]).copied().collect();
    let mut got: Vec<u64> = drops.iter().map(|(seq, _)| *seq).collect();
    expected.sort_unstable();
    got.sort_unstable();
    assert_eq!(got, expected);
}

#[tokio::test]
async fn test_unverified_bound_leaves_entries_stored_for_other_reasons() {
    let w = World::new();
    let mut app = wallet(&w, w.env()).await;
    let h = peer(&w, "honest");
    // Far more than the bounds, and older than 21 days, but stored for other reasons.
    let old = w.clock.now_ms();
    let others: Vec<ParkedEntry> = (0..MAX_UNVERIFIED_TOTAL as u64 + 10)
        .map(|n| {
            let reason = if n % 2 == 0 {
                ParkReason::Refused
            } else {
                ParkReason::Uncertain
            };
            entry_of(&w, &h, 1_000 + n, old, reason)
        })
        .collect();
    let ids = write_stored(&mut app, others).await;
    w.clock.advance_ms(MAX_UNVERIFIED_AGE_MS + DAY_MS);
    app.receive(None).await.unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(dropped(&report.events).is_empty(), "{:?}", report.events);
    assert!(dropped(&app.kept_duties().await.unwrap()).is_empty());
    assert!(ids.iter().all(|id| app.state.parked.contains_key(id)));
}

#[tokio::test]
async fn test_unverified_bound_applies_at_a_read_to_entries_stored_before_in_steps() {
    let w = World::new();
    let counting = Arc::new(Counting {
        inner: Arc::clone(&w.store),
        deleted: Mutex::new(Vec::new()),
    });
    let mut app = wallet(&w, w.env_on(Arc::clone(&counting) as Arc<dyn StateStore>)).await;
    w.homeserver.set_down(true);
    let h = peer(&w, "honest");
    // 200 of one sender, as a build before the bounds left them: 136 over.
    let now = w.clock.now_ms();
    let entries: Vec<ParkedEntry> = (0..200u64)
        .map(|n| entry_of(&w, &h, 1_000 + n, now + n, ParkReason::Unverifiable))
        .collect();
    let ids = write_stored(&mut app, entries).await;
    counting.deleted.lock().unwrap().clear();
    let report = app.receive(None).await.unwrap();
    // The first read drops them all, in commits of at most the step size, the accepted
    // earliest first.
    let drops = dropped(&report.events);
    assert_eq!(drops.len(), 200 - MAX_UNVERIFIED_PER_SENDER);
    let deleted = counting.deleted.lock().unwrap().clone();
    let steps: Vec<usize> = deleted.into_iter().filter(|n| *n > 0).collect();
    assert!(steps.len() >= 3, "{steps:?}");
    assert!(
        steps.iter().all(|n| *n <= UNVERIFIED_DROPS_PER_COMMIT),
        "{steps:?}"
    );
    assert!(
        ids[..136]
            .iter()
            .all(|id| !app.state.parked.contains_key(id))
    );
    assert!(
        ids[136..]
            .iter()
            .all(|id| app.state.parked.contains_key(id))
    );
}

#[tokio::test]
async fn test_unverified_bound_reapplies_to_entries_a_restore_brings_back() {
    let w = World::new();
    let mut app = wallet(&w, w.env()).await;
    let h = peer(&w, "honest");
    let seqs = stored_unverified(&w, &mut app, &[(&h, 1)]).await;
    let seq = seqs[0][0];
    // A backup while the entry is stored; then it is dropped past 21 days, and the host
    // acknowledges the event.
    let backup = app.backup_layered().await.unwrap();
    w.clock.advance_ms(MAX_UNVERIFIED_AGE_MS);
    app.receive(None).await.unwrap();
    app.receive(None).await.unwrap();
    assert!(app.stored_at(seq).is_none());
    let events = app.unacknowledged_events().await.unwrap();
    assert!(dropped(&events).contains(&(seq, DropReason::Age)));
    let last = events.iter().filter_map(AppEvent::id).next_back().unwrap();
    app.ack_events(last).await.unwrap();
    drop(app);
    // Restored from the older backup: the entry is back, and the next read drops it
    // again and tells the protocol again.
    let mut restored = App::restore(
        w.env(),
        Arc::new(BackedUp::default()),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert!(restored.stored_at(seq).is_some());
    restored.receive(None).await.unwrap();
    assert!(restored.stored_at(seq).is_none());
    let kept = restored.kept_duties().await.unwrap();
    assert!(dropped(&kept).contains(&(seq, DropReason::Age)), "{kept:?}");
}

#[tokio::test]
async fn test_unverified_bound_runs_before_the_retries() {
    let w = World::new();
    let mut app = wallet(&w, w.env()).await;
    let bob = Peer {
        identity: w.bob.clone(),
        keys: w.bob_keys.clone(),
        cert: w.bob_cert.clone(),
    };
    let seqs = stored_unverified(&w, &mut app, &[(&bob, MAX_UNVERIFIED_PER_SENDER + 1)]).await;
    // Bob can be checked again: the next read's retries would process his entries, the one
    // accepted earliest first. The bound goes before them and drops that one instead.
    w.homeserver.set_down(false);
    let report = app.receive(None).await.unwrap();
    assert_eq!(
        dropped(&report.events),
        vec![(seqs[0][0], DropReason::PerSender)]
    );
    assert!(!has(&report.events, |e| matches!(
        e,
        AppEvent::MessageReceived { seq, .. } if *seq == seqs[0][0]
    )));
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::MessageReceived { seq, .. } if *seq == seqs[0][1]
    )));
}

#[tokio::test]
async fn test_unverified_bound_applies_before_a_layered_backup() {
    let w = World::new();
    let mut app = wallet(&w, w.env()).await;
    let h = peer(&w, "honest");
    let a1 = peer(&w, "hostile-1");
    let a2 = peer(&w, "hostile-2");
    // 138 stored by one read, 10 over the total, and a backup taken before any other read.
    stored_unverified(
        &w,
        &mut app,
        &[
            (&h, 10),
            (&a1, MAX_UNVERIFIED_PER_SENDER),
            (&a2, MAX_UNVERIFIED_PER_SENDER),
        ],
    )
    .await;
    assert_eq!(app.stored_seqs().len(), 138);
    let backup = app.backup_layered().await.unwrap();
    // The backup holds what the bounds leave, and the drops were kept as duty events.
    assert_eq!(app.stored_seqs().len(), MAX_UNVERIFIED_TOTAL);
    let kept = app.kept_duties().await.unwrap();
    assert_eq!(dropped(&kept).len(), 138 - MAX_UNVERIFIED_TOTAL);
    let restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        Arc::new(BackedUp::default()),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert_eq!(restored.stored_seqs().len(), MAX_UNVERIFIED_TOTAL);
}
