//! A feed read that waits (Switch wire 7.4.4 `wait`): an app with nothing to read asks the
//! switch to hold its read, and a write of another app answers it.

use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use pubky_switch_client::app::{App, AppConfig, AppError, RecordTarget};
use pubky_switch_client::error::ClientError;
use pubky_switch_core::records::IDENTITY_PATH;
use pubky_switch_signer::UserConfirmed;
use serde_json::json;

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::joined_with;
use super::recovery::{ended, expect_upload, follow_recovery};
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, notes_collection, notes_protocol_with_records};
use crate::{FlowResult, World};

/// How long the watch asks the switch to hold its read, in seconds: the most a read may
/// ask for.
const WAIT_S: u32 = 25;

/// How long the read and the write may take together. It is well short of the wait, so a
/// read that is held and then answered within it was answered by the write, not by its
/// wait running out; and long enough for one write at any runner's pace.
const STEP_TIMEOUT: Duration = Duration::from_secs(15);

/// alice's watch has read its feed to the end. It reads again and asks the switch to wait;
/// while the read is held, her wallet writes a record. The write answers the read: the
/// watch gets the record without asking again, and a read after that finds nothing new.
///
/// The two calls are in flight at once. The write starts when the switch holds the read
/// ([`World::held_reads`]): it waits on that state, not for a time. A read answered before
/// the write started wasn't held, and fails the flow.
///
/// Calls: `GET /v1/{id}/feed` with `wait`, answered by another app's `POST /v1/{id}/ops`.
///
/// # Errors
///
/// When a step that should succeed against any switch fails; when the switch answers the
/// read without holding it; or when the read and the write together take 15 seconds, well
/// short of the wait: the write didn't answer the read.
pub async fn waiting_read(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let asking = |name: &str| -> Result<Asking, crate::HarnessError> {
        Asking::new(world.app_keys(&alice, name)?)
    };
    let (mut wallet, _) = joined_with(
        world,
        &alice,
        &mut signer,
        asking("wallet")?,
        notes_protocol_with_records(),
        AppConfig::default(),
    )
    .await?;
    let (mut watch, _) = joined_with(
        world,
        &alice,
        &mut signer,
        asking("watch")?,
        notes_protocol_with_records(),
        AppConfig::default(),
    )
    .await?;
    look(world, &mut wallet, "the wallet before the wait").await?;
    look(world, &mut watch, "the watch before the wait").await?;

    let target = RecordTarget::new(notes_collection(), b"shopping list");
    let answered = Cell::new(false);
    let held_at_the_write = Cell::new(false);
    let read = async {
        let report = watch.receive(Some(WAIT_S)).await;
        answered.set(true);
        report
    };
    let write = async {
        // Until the switch holds the read, or answered it without holding it.
        while world.held_reads() == 0 && !answered.get() {
            tokio::task::yield_now().await;
        }
        held_at_the_write.set(world.held_reads() > 0);
        wallet
            .put_record(&target, br#"{"items":["milk"]}"#, Vec::new())
            .await
    };
    let both = each_on_its_own_wake(read, write);
    let Ok((read, written)) = tokio::time::timeout(STEP_TIMEOUT, both).await else {
        return Err("the write didn't answer the waiting read: the read is still held".into());
    };
    written?;
    let report = read?;
    if !held_at_the_write.get() {
        return Err("the switch answered the waiting read without holding it".into());
    }
    world.outcome(
        "the watch's waiting read, answered by the wallet's write",
        &json!({
            "held_when_the_wallet_wrote": held_at_the_write.get(),
            "events": events(&report.events),
            "stopped": report.stopped,
            "app": app_status(&mut watch),
        }),
    );
    world.advance_ms(STEP_MS);
    look(world, &mut watch, "the watch's next read").await?;
    look(world, &mut wallet, "the wallet after its write").await?;
    Ok(())
}

/// What tells a future of a pair that its own waker fired.
struct OwnWake {
    /// Set when the future's waker fires, and at the start.
    fired: AtomicBool,
    /// The waker of whoever polls the pair.
    pair: Mutex<Option<Waker>>,
}

impl Wake for OwnWake {
    fn wake(self: Arc<Self>) {
        self.fired.store(true, Ordering::SeqCst);
        let pair = self.pair.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(pair) = pair.as_ref() {
            pair.wake_by_ref();
        }
    }
}

/// A future polled once at the start, and then only after its own waker fired.
struct OnOwnWake<F> {
    inner: Pin<Box<F>>,
    wake: Arc<OwnWake>,
}

impl<F: Future> OnOwnWake<F> {
    fn new(inner: F) -> Self {
        Self {
            inner: Box::pin(inner),
            wake: Arc::new(OwnWake {
                fired: AtomicBool::new(true),
                pair: Mutex::new(None),
            }),
        }
    }
}

impl<F: Future> Future for OnOwnWake<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        *self
            .wake
            .pair
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(cx.waker().clone());
        if !self.wake.fired.swap(false, Ordering::SeqCst) {
            return Poll::Pending;
        }
        let own = Waker::from(Arc::clone(&self.wake));
        self.inner.as_mut().poll(&mut Context::from_waker(&own))
    }
}

/// Run a held read and the call that is to wake it to their ends, each polled only when
/// its own waker fires. Joined as they are, the read would be polled again whenever the
/// other call moved, and a switch that never woke it would pass.
async fn each_on_its_own_wake<A, B>(
    read: impl Future<Output = A>,
    act: impl Future<Output = B>,
) -> (A, B) {
    futures_util::future::join(OnOwnWake::new(read), OnOwnWake::new(act)).await
}

/// `app` follows its feed to the end and moves its cursor: the events it raises at this
/// read, and where it stands.
async fn look(world: &World, app: &mut App, name: &str) -> FlowResult {
    let report = app.receive(None).await?;
    app.flush_cursor().await?;
    world.outcome(
        name,
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "app": app_status(app),
        }),
    );
    world.advance_ms(STEP_MS);
    Ok(())
}

/// A waiting read held while the signer closes the account (Switch wire 7.4.16). alice's
/// watch, her only app, has read its feed to the end and reads again with `wait`: nothing
/// is pending, and the switch holds the read. The erasure, the account's first change since
/// the read arrived, wakes it, and it is answered as for an account the switch doesn't
/// host: the operator's `404`, never a page under the erased account's key.
///
/// The flow notes that the read was held when the signer acted. How the read ended for
/// the app isn't noted; the trace holds what the switch answered it.
///
/// Calls: `GET /v1/{id}/feed` with `wait`, answered by `POST /v1/{id}/erase`.
///
/// # Errors
///
/// As [`waiting_read`].
pub async fn waiting_read_erased(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut watch, _) = joined_with(
        world,
        &alice,
        &mut signer,
        Asking::new(world.app_keys(&alice, "watch")?)?,
        notes_protocol_with_records(),
        AppConfig::default(),
    )
    .await?;
    look(world, &mut watch, "the watch before the wait").await?;

    let answered = Cell::new(false);
    let held_then = Cell::new(false);
    let read = async {
        let report = watch.receive(Some(WAIT_S)).await;
        answered.set(true);
        report.is_ok()
    };
    let erase = async {
        // Until the switch holds the read, or answered it without holding it.
        while world.held_reads() == 0 && !answered.get() {
            tokio::task::yield_now().await;
        }
        held_then.set(world.held_reads() > 0);
        signer
            .close_account(UserConfirmed::shown_and_confirmed())
            .await
    };
    let both = each_on_its_own_wake(read, erase);
    let Ok((_, erased)) = tokio::time::timeout(STEP_TIMEOUT, both).await else {
        return Err("the held read wasn't answered: it is still held".into());
    };
    erased?;
    if !held_then.get() {
        return Err("the switch answered the waiting read without holding it".into());
    }
    world.outcome(
        "the signer closed the account while the watch's read was held",
        &json!({ "held_when_the_signer_acted": held_then.get(), "signer": status(&signer)? }),
    );
    Ok(())
}

/// A waiting read held while the signer revokes its reader (Switch spec 12.2 step 1,
/// Switch wire 7.4.4). alice's watch has read its feed to the end and reads again with
/// `wait`; the switch holds the read. Her signer revokes the watch: the revocation wakes
/// the read, and the switch refuses it `403 not_current`, as it refuses every call of an
/// app that is no longer current, under the head the revocation left.
///
/// The signer goes on to deliver the version that removes the watch. That delivery is
/// held back until the read is answered, so that at either switch the watch learns of its
/// revocation before the removal is published, whatever the order the two calls would
/// otherwise finish in.
///
/// Calls: `GET /v1/{id}/feed` with `wait`, answered by `POST /v1/{id}/apps/{app_id}/revoke`.
///
/// # Errors
///
/// As [`waiting_read`], or when the held read is answered anything but `403 not_current`
/// under the revocation's head.
pub async fn waiting_read_revoked(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut watch, _) = joined_with(
        world,
        &alice,
        &mut signer,
        Asking::new(world.app_keys(&alice, "watch")?)?,
        notes_protocol_with_records(),
        AppConfig::default(),
    )
    .await?;
    look(world, &mut watch, "the watch before the wait").await?;

    let app_id = watch.app_id();
    let answered = Cell::new(false);
    let held_then = Cell::new(false);
    world.hold_back("PUT", "/identity");
    let read = async {
        let report = watch.receive(Some(WAIT_S)).await;
        answered.set(true);
        world.let_go();
        report
    };
    let revoke = async {
        // Until the switch holds the read, or answered it without holding it.
        while world.held_reads() == 0 && !answered.get() {
            tokio::task::yield_now().await;
        }
        held_then.set(world.held_reads() > 0);
        signer
            .revoke(app_id, None, UserConfirmed::shown_and_confirmed())
            .await
    };
    let both = each_on_its_own_wake(read, revoke);
    let both = tokio::time::timeout(STEP_TIMEOUT, both).await;
    world.let_go();
    let Ok((report, revoked)) = both else {
        return Err("the held read wasn't answered: it is still held".into());
    };
    revoked?;
    if !held_then.get() {
        return Err("the switch answered the waiting read without holding it".into());
    }
    world.outcome(
        "the signer revoked the watch while its read was held",
        &json!({
            "held_when_the_signer_acted": held_then.get(),
            "the read ended well": report.is_ok(),
            "events": events(&watch.take_events()),
            "signer": status(&signer)?,
        }),
    );
    // The read is refused, under the head the revocation left: the one its answer shows.
    let read = "{alice/watch} GET /v1/{alice}/feed";
    let revocation = "{alice} POST /v1/{alice}/apps/{alice/watch}/revoke";
    let refused = (
        world.last_fact(read, "status"),
        world.last_fact(read, "body.code"),
        world.last_fact(read, "header switch-head~.seq"),
    );
    let expected = (
        Some("403".to_owned()),
        Some("text not_current".to_owned()),
        world.last_fact(revocation, "body.head.seq"),
    );
    if refused != expected || expected.2.is_none() {
        return Err(format!("the held read was answered {refused:?}, not {expected:?}").into());
    }
    Ok(())
}

/// A feed read held across a recovery in place (Switch wire 7.4.4, 3.3, Switch spec 12.6
/// step 1). alice's watch reads its feed with a wait, and the switch holds the read. Her
/// signer declares the service's generation lost there and recovers in place: the version
/// that names the pending key starts the account afresh. That wakes the read. The account
/// no longer names the key the read was held under, so the read is answered `503
/// unavailable`, signed with the operator key and with no head. The watch can't take that
/// answer as the account's. The new document's publication fails once, so the woken watch
/// finds nothing to follow yet; once the signer's next run has published it, the watch
/// learns the new key from alice's `identity.json` and follows the recovery: it registers
/// again, reads the new sequence from its start, and uploads what it holds.
///
/// Calls: `GET /v1/{id}/feed?wait=` held while the account recovers in place, and the
/// feed read from the start of the next generation after it.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the switch answers the read
/// without holding it or leaves it held, the read is answered otherwise than `503
/// unavailable` under the operator key with no head, the watch takes that answer for more
/// than a read that failed for its signature, or its next read isn't the new chain's
/// first item.
pub async fn waiting_read_recovered(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut watch, _) = joined_with(
        world,
        &alice,
        &mut signer,
        Asking::new(world.app_keys(&alice, "watch")?)?,
        notes_protocol_with_records(),
        AppConfig::default(),
    )
    .await?;
    look(world, &mut watch, "the watch before the wait").await?;

    // The new document reaches the Homeserver only with the signer's next run, so the watch,
    // woken before it, finds nothing to follow yet: at either switch, however its answer
    // and the signer's are ordered.
    world.fail_homeserver_write(&alice, IDENTITY_PATH);
    let sent = world.trace().lines.len();
    let answered = Cell::new(false);
    let held_then = Cell::new(false);
    let read = async {
        let report = watch.receive(Some(WAIT_S)).await;
        answered.set(true);
        report.map(|_| ())
    };
    let recover = async {
        // Until the switch holds the read, or answered it without holding it.
        while world.held_reads() == 0 && !answered.get() {
            tokio::task::yield_now().await;
        }
        held_then.set(world.held_reads() > 0);
        signer
            .declare_provider_loss(ORIGIN, UserConfirmed::shown_and_confirmed())
            .await
    };
    let both = each_on_its_own_wake(read, recover);
    let Ok((report, recovered)) = tokio::time::timeout(STEP_TIMEOUT, both).await else {
        return Err("the held read wasn't answered: it is still held".into());
    };
    if !held_then.get() {
        return Err("the switch answered the waiting read without holding it".into());
    }
    let delivered = signer
        .identity_doc()?
        .ok_or("the signer holds no document")?;
    let raised = watch.take_events();
    world.outcome(
        "the signer recovered in place while the watch's read was held",
        &json!({
            "held_when_the_signer_acted": held_then.get(),
            "the read": ended(&report),
            "events": events(&raised),
            "the recovery": ended(&recovered),
            "generation": delivered.generation(),
            "signer": status(&signer)?,
        }),
    );
    if recovered.is_ok() || world.homeserver_faults_left() != 0 || delivered.generation() != 2 {
        return Err(format!(
            "the recovery's version wasn't delivered with its publication failing: it ended \
             {} at generation {}",
            ended(&recovered),
            delivered.generation()
        )
        .into());
    }
    // The held read is answered, not left held, and not under the account's key or a head:
    // the account it was held for is the one the recovery replaced.
    let held = {
        let trace = world.trace();
        let fact = |line: &crate::trace::Line, name: &str| line.facts.get(name).cloned();
        trace.lines[sent..]
            .iter()
            .find(|line| line.label == "{alice/watch} GET /v1/{alice}/feed")
            .map(|line| {
                (
                    fact(line, "status"),
                    fact(line, "body.code"),
                    fact(line, "answer signed with"),
                    fact(line, "header switch-head"),
                )
            })
    };
    let unavailable = (
        Some("503".to_owned()),
        Some("text unavailable".to_owned()),
        Some("the operator key".to_owned()),
        Some("absent".to_owned()),
    );
    if held.as_ref() != Some(&unavailable) || world.held_reads() != 0 {
        return Err(format!(
            "the held read was answered {held:?} (status, code, key, head), with {} reads \
             still held",
            world.held_reads()
        )
        .into());
    }
    // The watch takes that answer for nothing of the account's: its read ends in an error,
    // it raises no event, and it stands where it stood, in the generation it knew.
    // The error is the answer's own: a `503` whose signature isn't the account's.
    let stands = watch.cursor().generation;
    let unsigned_for_it = matches!(
        report.as_ref().map_err(AppError::unkept),
        Err(AppError::Switch(ClientError::BadServiceSignature {
            status: 503
        }))
    );
    if !unsigned_for_it || !raised.is_empty() || stands != 1 {
        return Err(format!(
            "the watch's read ended {} with the events {:?}, and it stands in generation \
             {stands}",
            ended(&report),
            events(&raised)
        )
        .into());
    }
    world.advance_ms(STEP_MS);

    signer.run_due().await?;
    let published = world
        .files()
        .identity_doc(&alice.public())
        .map(|doc| doc.generation());
    world.outcome(
        "the signer's run published the recovery's version",
        &json!({ "published_generation": published, "signer": status(&signer)? }),
    );
    if published != Some(2) {
        return Err(format!("the Homeserver holds generation {published:?}, not 2").into());
    }
    world.advance_ms(STEP_MS);

    // The watch learns the new key from the document, registers again, and reads the new
    // sequence from its start: the `recovery` transition at `seq` 1.
    follow_recovery(world, &mut watch, "watch", 1).await?;
    expect_upload(world, "watch", false)?;
    look(world, &mut watch, "the watch after the recovery").await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pending at its first poll without keeping its waker; done at a second poll.
    struct NeverWoken<'a>(&'a Cell<u32>);

    impl Future for NeverWoken<'_> {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            self.0.set(self.0.get() + 1);
            if self.0.get() > 1 {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    #[tokio::test]
    async fn test_own_wake_pair_leaves_a_future_no_one_woke_unpolled() {
        let polls = Cell::new(0);
        let moves = async {
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
        };
        let both = each_on_its_own_wake(NeverWoken(&polls), moves);
        let ended = tokio::time::timeout(Duration::from_millis(200), both).await;
        assert!(ended.is_err(), "the future no one woke was polled again");
        assert_eq!(polls.get(), 1);
    }

    #[tokio::test]
    async fn test_own_wake_pair_runs_each_future_to_its_end() {
        let counts = async {
            let mut steps = 0;
            for _ in 0..3 {
                tokio::task::yield_now().await;
                steps += 1;
            }
            steps
        };
        let sleeps = async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            "slept"
        };
        // A wrapper that never polled a future again would wait for good.
        let both = each_on_its_own_wake(counts, sleeps);
        let ended = tokio::time::timeout(Duration::from_secs(10), both).await;
        assert_eq!(ended.ok(), Some((3, "slept")));
    }
}
