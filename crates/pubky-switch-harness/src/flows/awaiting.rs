//! An entry that waits for a scope key the app doesn't hold yet (Switch spec 3.5, 8.2;
//! Switch wire 5.1): stored locally with the cursor past it, and taken once a rotation's
//! key bundle brings the key.

use std::sync::{Arc, Mutex};

use pubky_switch_client::app::{
    App, AppConfig, Collection, Effect, LocalWrite, MissedEntries, Outcome, Protocol,
    ReceiveContext, ReceivedMessage, RecordTarget, ResendNeeded, StoreFailure,
};
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::{ProtocolSpec, TestIdentity};
use pubky_switch_core::message::Message;
use pubky_switch_core::records::AppCert;
use pubky_switch_signer::{Signer, UserConfirmed};
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::{joined, joined_as};
use super::{ORIGIN, STEP_MS};
use crate::parties::{
    Asking, NOTE_KIND, NOTES, notes_collection, notes_protocol, notes_protocol_with_records,
};
use crate::{FlowResult, World};

/// The notes protocol, whose receive step takes a note once the app holds the scope key of
/// the data epoch the note's body names (`epoch`): without it, the step waits for that key
/// ([`Outcome::AwaitKey`]). With `records`, the protocol keeps a collection and the step
/// writes a record for each note, named by its `msg_id`.
struct EpochNotes {
    spec: ProtocolSpec,
    /// Whether the protocol keeps shared records.
    records: bool,
    /// The `msg_id` of every step run, in order.
    runs: Mutex<Vec<String>>,
}

impl EpochNotes {
    fn runs(&self) -> usize {
        self.runs.lock().map_or(0, |runs| runs.len())
    }
}

impl Protocol for EpochNotes {
    fn has_keys(&self, scope: &str) -> bool {
        self.spec.has_keys(scope)
    }

    fn sent_between_own_apps(&self, _kind: &str) -> bool {
        false
    }

    fn check_scopes(&self, message: &Message, _: &AppCert, _: &AppCert) -> Result<(), String> {
        if message.kind == NOTE_KIND {
            Ok(())
        } else {
            Err("epoch notes: a kind it doesn't accept".into())
        }
    }

    fn accepts(&self, _cert: &AppCert) -> Vec<String> {
        vec![NOTE_KIND.to_owned()]
    }

    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        match message.message.body.get("epoch").and_then(Value::as_u64) {
            Some(_) => Ok(()),
            None => Err("epoch notes: body.epoch isn't a number".into()),
        }
    }

    fn receive(&self, message: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        let msg_id = message.message.msg_id.clone();
        if let Ok(mut runs) = self.runs.lock() {
            runs.push(msg_id.clone());
        }
        let data_epoch = message
            .message
            .body
            .get("epoch")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        if !cx.holds_scope_key(NOTES, data_epoch) {
            return Outcome::AwaitKey { data_epoch };
        }
        if !self.records {
            return Outcome::Apply(Effect::default());
        }
        let target = RecordTarget::new(notes_collection(), msg_id.as_bytes());
        let value = json!({ "note": msg_id }).to_string();
        match cx.put_record(&target, value.as_bytes(), Vec::new()) {
            Ok(_) => Outcome::Apply(Effect::default()),
            Err(error) => Outcome::Drop {
                reason: format!("epoch notes: {error}"),
            },
        }
    }

    fn resend_needed(&self, _: &ResendNeeded) -> Result<Vec<LocalWrite>, StoreFailure> {
        Ok(Vec::new())
    }

    fn missed(&self, _: &MissedEntries) -> Result<Vec<LocalWrite>, StoreFailure> {
        Ok(Vec::new())
    }

    fn collections(&self) -> Vec<Collection> {
        if self.records {
            vec![notes_collection()]
        } else {
            Vec::new()
        }
    }
}

/// `identity`'s wallet, approved by `signer` for the [`NOTES`] scope and joined with
/// `protocol`.
async fn joined_wallet(
    world: &World,
    identity: &TestIdentity,
    signer: &mut Signer,
    protocol: &Arc<EpochNotes>,
) -> Result<App, Box<dyn std::error::Error>> {
    let asking = Asking::new(world.app_keys(identity, "wallet")?)?;
    let review = signer.review(asking.request.signed(), &asking.auth)?;
    let approved = signer.approve(review).await?;
    signer.claim_delivered(&approved.request).await?;
    world.advance_ms(STEP_MS);
    let mut app = App::join(
        world.app_env(Arc::new(MemoryStore::new())),
        Arc::clone(protocol) as Arc<dyn Protocol>,
        AppConfig::default(),
        asking.join_request(identity.public(), &approved)?,
    )
    .await?;
    app.receive(None).await?;
    world.outcome("the wallet joined", &app_status(&mut app));
    world.advance_ms(STEP_MS);
    Ok(app)
}

/// The wallet reads its feed: what it raised, why each entry it stores is stored, how many
/// steps ran, and whether it holds the record of `msg_id`.
async fn read(
    world: &World,
    wallet: &mut App,
    protocol: &EpochNotes,
    msg_id: &str,
    name: &str,
) -> FlowResult {
    let report = wallet.receive(None).await?;
    let target = RecordTarget::new(notes_collection(), msg_id.as_bytes());
    let held = wallet.shared_record(&wallet.record_key(&target)?).await?;
    let stored = wallet
        .parked_entries()
        .await?
        .iter()
        .map(|entry| format!("{:?}", entry.reason))
        .collect::<Vec<_>>();
    world.outcome(
        name,
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "stored": stored,
            "steps_run": protocol.runs(),
            "record_written": held
                .and_then(|record| record.content.value().map(<[u8]>::to_vec))
                .is_some_and(|value| value == json!({ "note": msg_id }).to_string().into_bytes()),
            "app": app_status(wallet),
        }),
    );
    world.advance_ms(STEP_MS);
    Ok(())
}

/// bob's shop sends alice's wallet a note about the second data epoch, which the wallet's
/// protocol can't take before it holds that epoch's key. The wallet stores the entry with
/// its cursor past it, asks for no key, and reads on without running the step again. Then
/// alice's signer revokes her phone, which rotates the data keys to the second epoch: the
/// wallet's next read brings the key bundle part, and takes the entry, once.
///
/// Calls: `GET /v1/{id}/feed` with an entry that waits for a key, and with the key bundle
/// part that brings it; `POST /v1/{id}/ops` with the waiting entry's record write and no
/// cursor move.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the wallet asks for a key
/// while it waits, or the entry isn't taken exactly once.
pub async fn awaiting_key(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice, &bob]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let protocol = Arc::new(EpochNotes {
        spec: notes_protocol().spec().clone(),
        records: true,
        runs: Mutex::new(Vec::new()),
    });
    let mut wallet = joined_wallet(world, &alice, &mut alice_signer, &protocol).await?;
    let (phone, _) = joined_as(
        world,
        &alice,
        &mut alice_signer,
        Asking::new(world.app_keys(&alice, "phone")?)?,
        notes_protocol_with_records(),
    )
    .await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;
    wallet.add_contact(&bob.public()).await?;
    world.advance_ms(STEP_MS);

    let mut body = serde_json::Map::new();
    body.insert("epoch".into(), json!(2));
    let (msg_id, _) = shop
        .send(pubky_switch_client::app::OutgoingMessage::new(
            alice.public(),
            NOTE_KIND,
            body,
        ))
        .await?;
    world.advance_ms(STEP_MS);

    let mark = world.trace().lines.len();
    read(
        world,
        &mut wallet,
        &protocol,
        &msg_id,
        "the wallet stores the note",
    )
    .await?;
    read(
        world,
        &mut wallet,
        &protocol,
        &msg_id,
        "the wallet reads again",
    )
    .await?;
    let key_calls = world
        .trace()
        .lines
        .iter()
        .skip(mark)
        .filter(|line| line.label.ends_with("/keys"))
        .count();
    if protocol.runs() != 1 || key_calls != 0 {
        return Err(format!(
            "before the key came the step ran {} times, and the wallet made {key_calls} key \
             calls",
            protocol.runs()
        )
        .into());
    }

    let removing = alice_signer
        .revoke(phone.app_id(), None, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer revoked the phone",
        &json!({
            "data_epoch": removing.body().data_epoch,
            "signer": status(&alice_signer)?,
        }),
    );
    world.advance_ms(STEP_MS);
    read(
        world,
        &mut wallet,
        &protocol,
        &msg_id,
        "the wallet takes the note",
    )
    .await?;
    read(
        world,
        &mut wallet,
        &protocol,
        &msg_id,
        "the wallet reads once more",
    )
    .await?;
    if protocol.runs() != 2 || !wallet.parked_entries().await?.is_empty() {
        return Err(format!(
            "the step ran {} times, and the entry isn't taken once",
            protocol.runs()
        )
        .into());
    }
    alice_signer.run_due().await?;
    world.outcome("alice's signer ran what is due", &status(&alice_signer)?);
    Ok(())
}

/// How many `GET` and `POST` calls for key bundles the run made from trace line `mark` on.
fn key_calls(world: &World, mark: usize) -> (usize, usize) {
    let trace = world.trace();
    let calls = |method: &str| {
        trace
            .lines
            .iter()
            .skip(mark)
            .filter(|line| line.label.ends_with("/keys") && line.label.contains(method))
            .count()
    };
    (calls(" GET "), calls(" POST "))
}

/// An entry that needs a scope key of the current data epoch, which its app lacks. alice's
/// wallet takes a backup. Her signer revokes her phone, which rotates the data keys to the
/// second epoch; the wallet reads the key bundle part and moves its cursor past it, so the
/// switch stores the part no longer. The wallet's device is lost and the wallet is
/// restored from the backup: it holds the first epoch's keys only.
///
/// bob's shop sends a note about the second epoch. The restored wallet's next read learns
/// the epoch from its own `identity.json`, fetches its key bundle, finds no part and asks
/// the signer for a full bundle, all before it reads its feed. The feed then brings the
/// note: its step waits for the key, and with the request out the wallet asks for nothing
/// more and stores the entry with its cursor past it. A further read asks for nothing
/// either. The signer's routine run answers the request, and the read that brings the part
/// takes the entry, once.
///
/// The wallet's protocol keeps no records here. With a collection to list, a restored app
/// that lacks a key reads no feed until the key comes, so no entry would wait.
///
/// An honest signer writes an app's part before the version that raises the epoch, so an
/// app that reads its feed in order holds the key when it learns of the epoch. Only an app
/// put back behind its part lacks it, and that app asks as above, before any entry does.
///
/// Calls: `GET /v1/{id}/apps/{app_id}/keys` (`404`) and `POST /v1/{id}/apps/{app_id}/keys`
/// by an app that an entry then finds waiting for the key; `GET /v1/{id}/feed` with that
/// entry, and with the part that answers the request.
///
/// # Errors
///
/// When a step that should succeed against any switch fails; when the read that stores
/// the entry doesn't fetch the bundle and ask for a full one, each once; when a later read
/// asks again; or when the entry isn't taken exactly once after the part came.
pub async fn awaiting_current_key(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice, &bob]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let protocol = Arc::new(EpochNotes {
        spec: notes_protocol().spec().clone(),
        records: false,
        runs: Mutex::new(Vec::new()),
    });
    let mut wallet = joined_wallet(world, &alice, &mut alice_signer, &protocol).await?;
    let (phone, _) = joined_as(
        world,
        &alice,
        &mut alice_signer,
        Asking::new(world.app_keys(&alice, "phone")?)?,
        notes_protocol_with_records(),
    )
    .await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;
    wallet.add_contact(&bob.public()).await?;
    wallet.receive(None).await?;
    wallet.flush_cursor().await?;
    let backup = wallet.backup().await?;
    world.outcome("the wallet took a backup", &app_status(&mut wallet));
    world.advance_ms(STEP_MS);

    // The rotation. The wallet reads its part and passes it: the switch drops the part.
    let removing = alice_signer
        .revoke(phone.app_id(), None, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer revoked the phone",
        &json!({
            "data_epoch": removing.body().data_epoch,
            "signer": status(&alice_signer)?,
        }),
    );
    world.advance_ms(STEP_MS);
    wallet.receive(None).await?;
    wallet.flush_cursor().await?;
    world.outcome("the wallet read the rotation", &app_status(&mut wallet));
    world.advance_ms(STEP_MS);
    // The device is lost with what the wallet learned since the backup.
    drop(wallet);
    let mut restored = App::restore(
        world.app_env(Arc::new(MemoryStore::new())),
        Arc::clone(&protocol) as Arc<dyn Protocol>,
        AppConfig::default(),
        &backup,
    )
    .await?;
    world.outcome("the wallet was restored", &app_status(&mut restored));
    world.advance_ms(STEP_MS);

    let mut body = serde_json::Map::new();
    body.insert("epoch".into(), json!(removing.body().data_epoch));
    let (msg_id, _) = shop
        .send(pubky_switch_client::app::OutgoingMessage::new(
            alice.public(),
            NOTE_KIND,
            body,
        ))
        .await?;
    world.advance_ms(STEP_MS);

    // The read that reaches the note: the bundle fetched and a full one asked for, once
    // each, and the note stored.
    let mark = world.trace().lines.len();
    let stores = "the restored wallet stores the note";
    read(world, &mut restored, &protocol, &msg_id, stores).await?;
    let asked = key_calls(world, mark);
    let waiting = restored.parked_entries().await?.len();
    if asked != (1, 1) || protocol.runs() != 1 || waiting != 1 {
        return Err(format!(
            "the read that reached the note made {asked:?} key calls (fetches, requests), \
             ran the step {} times and left {waiting} entries stored",
            protocol.runs()
        )
        .into());
    }
    let mark = world.trace().lines.len();
    let again = "the restored wallet reads again";
    read(world, &mut restored, &protocol, &msg_id, again).await?;
    let asked = key_calls(world, mark);
    if asked != (0, 0) || protocol.runs() != 1 {
        return Err(format!(
            "with the request out, a read made {asked:?} key calls and the step ran {} times",
            protocol.runs()
        )
        .into());
    }

    // The signer answers the request; the part takes the entry.
    alice_signer.run_due().await?;
    world.outcome("alice's signer ran what is due", &status(&alice_signer)?);
    world.advance_ms(STEP_MS);
    let takes = "the restored wallet takes the note";
    read(world, &mut restored, &protocol, &msg_id, takes).await?;
    let once_more = "the restored wallet reads once more";
    read(world, &mut restored, &protocol, &msg_id, once_more).await?;
    if protocol.runs() != 2 || !restored.parked_entries().await?.is_empty() {
        return Err(format!(
            "after the part came the step had run {} times, and {} entries are stored",
            protocol.runs(),
            restored.parked_entries().await?.len()
        )
        .into());
    }
    Ok(())
}
