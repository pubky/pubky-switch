//! Inbox retention under pressure, as the service applies it (Switch wire 7.4.4, 9.1): an
//! entry goes once every current target that isn't lagging has passed it; an app whose
//! unread entries pass its share of the inbox quota is marked lagging while another app
//! reads; a lagging app is told what went unread in a `missed` item; and an entry left with
//! no current target becomes an `unreadable` item.

use std::collections::BTreeMap;

use super::{Inner, Item};

/// The bytes an entry counts besides its envelope, and an unreadable item in all (Switch
/// wire 9.2 `entry_overhead_bytes`).
const ENTRY_OVERHEAD_BYTES: u64 = 256;

/// The entries one release deleted that a lagging target hadn't read.
#[derive(Clone, Copy, Debug)]
struct Misses {
    entries: u64,
    from: u64,
    until: u64,
}

impl Inner {
    /// The apps current now (Switch spec 3.4), expired ones included: the targets an entry
    /// waits for, and the apps the inbox quota is shared among.
    pub(super) fn current_app_ids(&self) -> Vec<[u8; 16]> {
        self.apps
            .keys()
            .filter(|app| {
                !self.kept_app_ids.contains(*app) && self.app_current_by(&self.apps, app, false)
            })
            .copied()
            .collect()
    }

    fn cursor_of(&self, app: &[u8; 16]) -> u64 {
        self.apps.get(app).map_or(0, |held| held.cursor)
    }

    fn marked_lagging(&self, app: &[u8; 16]) -> bool {
        self.apps.get(app).is_some_and(|held| held.lagging)
    }

    fn set_lagging(&mut self, apps: &[[u8; 16]], lagging: bool) {
        for app in apps {
            if let Some(held) = self.apps.get_mut(app) {
                held.lagging = lagging;
            }
        }
    }

    /// The bytes of the inbox `app` hasn't read, as its lagging is measured: each entry
    /// targeting it and each unreadable item past its cursor; `missed` items count for
    /// nothing.
    fn unread_bytes(&self, app: &[u8; 16]) -> u64 {
        let cursor = self.cursor_of(app);
        self.items
            .iter()
            .filter(|item| item.seq() > cursor)
            .map(|item| match item {
                Item::Entry {
                    envelope, targets, ..
                } if targets.contains(app) => u64::try_from(envelope.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(ENTRY_OVERHEAD_BYTES),
                Item::Unreadable { .. } => ENTRY_OVERHEAD_BYTES,
                _ => 0,
            })
            .fold(0, u64::saturating_add)
    }

    /// Each app's unread entries, and of those the ones it is the only current target of
    /// (Switch wire 7.4.12 `unread_entries`, `sole_target_unread`).
    pub(super) fn unread_counts(&self, app: &[u8; 16]) -> (u64, u64) {
        let current = self.current_app_ids();
        let cursor = self.cursor_of(app);
        let (mut unread, mut sole) = (0_u64, 0_u64);
        for item in &self.items {
            if let Item::Entry { seq, targets, .. } = item
                && *seq > cursor
                && targets.contains(app)
            {
                unread += 1;
                let current_targets = targets.iter().filter(|t| current.contains(t)).count();
                if current_targets == 1 && current.contains(app) {
                    sole += 1;
                }
            }
        }
        (unread, sole)
    }

    /// Set lagging marks, at a request that brings the pressure: an append, before and
    /// after it, or a change of the current apps (Switch wire 7.4.4). An app whose unread
    /// bytes exceed its share, the quota divided among the current apps, is marked, but
    /// only while another current app is reading: unmarked, and within its share. When none
    /// is, none is marked and the marks set before end. Entries only marked apps were
    /// holding go now, each in its app's `missed` item.
    pub(super) fn judge_lagging(&mut self) {
        let current = self.current_app_ids();
        if current.is_empty() {
            return;
        }
        let apps = u64::try_from(current.len()).unwrap_or(u64::MAX).max(1);
        let share = self.enroll_limits.quota_bytes / apps;
        let over: Vec<[u8; 16]> = current
            .iter()
            .filter(|app| self.unread_bytes(app) > share)
            .copied()
            .collect();
        let reading = current
            .iter()
            .any(|app| !over.contains(app) && !self.marked_lagging(app));
        if !reading {
            self.set_lagging(&current, false);
            return;
        }
        self.set_lagging(&over, true);
        self.release_passed(&current, true);
    }

    /// After a cursor moved: entries left with no current target become unreadable items,
    /// and what every reader an item waits for has passed goes.
    pub(super) fn after_cursor_move(&mut self) {
        let current = self.current_app_ids();
        self.convert_unreadable(&current);
        self.release_passed(&current, true);
        self.forget_deleted_keys(&current);
    }

    /// Forget the deleted keys nothing refers to, `current` holding the App IDs current now
    /// (Switch spec 10.3, wire 9.1), as the service does: the record's current write is
    /// its delete, written here, not taken from a recovery upload; the cursor of every app
    /// of `current` is at or past it, but for a lagging app with a `missed` item it hasn't
    /// passed (its own, or one [`super::ScriptedSwitch::push_missed`] scripted for every app),
    /// which lists its collections again as it passes the item; and no divergent
    /// upload names the key. The record goes, so its delete shows as its stub, its reads are
    /// `404`, and a create at the key starts afresh.
    fn forget_deleted_keys(&mut self, current: &[[u8; 16]]) {
        let to_list = |app: &[u8; 16]| {
            self.marked_lagging(app)
                && self.items.iter().any(|item| {
                    matches!(item, Item::Missed { seq, app: of, .. }
                        if of.is_none_or(|of| of == *app) && *seq > self.cursor_of(app))
                })
        };
        let waited: Vec<u64> = current
            .iter()
            .filter(|app| !to_list(app))
            .map(|app| self.cursor_of(app))
            .collect();
        let shared = &mut self.shared;
        let divergent = &shared.divergent;
        shared.records.retain(|key, held| {
            !held.state.deleted
                || held.uploaded.is_some()
                || divergent.contains_key(key)
                || waited.iter().any(|cursor| *cursor < held.seq)
        });
    }

    /// The sweep the service runs once a minute of service time (Switch wire 9.1), at the
    /// first request a minute after the last: invite codes that expired or ran out go.
    pub(super) fn minute_sweep(&mut self) {
        let now = self.now();
        let shared = &mut self.shared;
        if shared
            .swept_at
            .is_some_and(|at| now < at.saturating_add(60_000))
        {
            return;
        }
        shared.swept_at = Some(now);
        shared
            .invites
            .retain(|_, invite| invite.uses < invite.max_uses && now < invite.expires_at);
    }

    /// After the chain item of a delivery, a revocation or a leave, `was` holding the apps
    /// current before it: an app it no longer makes current stops holding entries, each
    /// entry left with no current target becomes an unreadable item, a departed app's mark
    /// ends, and when the set of current apps changed, and with it the shares, the marks
    /// are judged again.
    pub(super) fn after_departure(&mut self, mut was: Vec<[u8; 16]>) {
        let mut current = self.current_app_ids();
        self.release_passed(&current, false);
        self.convert_unreadable(&current);
        let gone: Vec<[u8; 16]> = self
            .apps
            .iter()
            .filter(|(app, held)| held.lagging && !current.contains(*app))
            .map(|(app, _)| *app)
            .collect();
        self.set_lagging(&gone, false);
        was.sort_unstable();
        current.sort_unstable();
        if was != current {
            self.judge_lagging();
        }
    }

    /// Release what every reader it waits for has passed (Switch wire 9.1), for the apps
    /// `current`; with `marks`, entries don't wait for the ones of them marked lagging:
    /// - an entry with a current target goes once every current target that isn't lagging
    ///   has its cursor at or past it, and a lagging target that hadn't read it gets a
    ///   `missed` item for it;
    /// - an unreadable item goes once every current app has passed it;
    /// - a `missed` item goes once its app has passed it, or isn't current.
    fn release_passed(&mut self, current: &[[u8; 16]], marks: bool) {
        let lagging: Vec<[u8; 16]> = current
            .iter()
            .filter(|app| marks && self.marked_lagging(app))
            .copied()
            .collect();
        let cursors: BTreeMap<[u8; 16], u64> = current
            .iter()
            .map(|app| (*app, self.cursor_of(app)))
            .collect();
        let passed = |app: &[u8; 16], seq: u64| cursors.get(app).is_some_and(|at| *at >= seq);
        let mut misses: BTreeMap<[u8; 16], Misses> = BTreeMap::new();
        let keep = self.keep_passed;
        self.items.retain(|item| {
            let Item::Entry {
                seq,
                targets,
                accepted_at,
                ..
            } = item
            else {
                return true;
            };
            let held = keep
                || !targets.iter().any(|target| current.contains(target))
                || targets.iter().any(|target| {
                    current.contains(target) && !lagging.contains(target) && !passed(target, *seq)
                });
            if held {
                return true;
            }
            for target in targets
                .iter()
                .filter(|target| lagging.contains(target) && !passed(target, *seq))
            {
                misses
                    .entry(*target)
                    .and_modify(|missed| {
                        missed.entries = missed.entries.saturating_add(1);
                        missed.from = missed.from.min(*accepted_at);
                        missed.until = missed.until.max(*accepted_at);
                    })
                    .or_insert(Misses {
                        entries: 1,
                        from: *accepted_at,
                        until: *accepted_at,
                    });
            }
            false
        });
        for (app, missed) in misses {
            self.record_missed(app, missed);
        }
        self.items.retain(|item| match item {
            Item::Unreadable { seq, scripted, .. } => {
                *scripted || current.is_empty() || !current.iter().all(|app| passed(app, *seq))
            }
            Item::Missed {
                seq,
                app: Some(app),
                ..
            } => current.contains(app) && !passed(app, *seq),
            _ => true,
        });
    }

    /// Record `missed` for `app`: a `missed` item at a new `seq`, replacing one the app
    /// hasn't passed with one covering both.
    fn record_missed(&mut self, app: [u8; 16], mut missed: Misses) {
        let cursor = self.cursor_of(&app);
        self.items.retain(|item| match item {
            Item::Missed {
                seq,
                app: Some(of),
                entries,
                from,
                until,
            } if *of == app && *seq > cursor => {
                missed.entries = missed.entries.saturating_add(*entries);
                missed.from = missed.from.min(*from);
                missed.until = missed.until.max(*until);
                false
            }
            _ => true,
        });
        let seq = self.next_seq();
        self.items.push(Item::Missed {
            seq,
            app: Some(app),
            entries: missed.entries,
            from: missed.from,
            until: missed.until,
        });
    }

    /// Turn each entry left with no current target into an unreadable item at a new `seq`,
    /// in their order (Switch wire 7.4.4, spec 8.2): its envelope goes, and it keeps its
    /// entry ID, sender and acceptance time.
    fn convert_unreadable(&mut self, current: &[[u8; 16]]) {
        let mut left = Vec::new();
        self.items.retain(|item| match item {
            Item::Entry {
                seq,
                sender,
                accepted_at,
                targets,
                ..
            } if !targets.iter().any(|target| current.contains(target)) => {
                left.push((*seq, *sender, *accepted_at));
                false
            }
            _ => true,
        });
        for (entry_seq, sender, accepted_at) in left {
            let seq = self.next_seq();
            self.items.push(Item::Unreadable {
                seq,
                entry_id: Self::entry_id(entry_seq),
                sender,
                accepted_at,
                scripted: false,
            });
        }
    }
}
