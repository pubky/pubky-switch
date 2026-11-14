//! Two protocols on one app (Switch spec 3.2, Switch wire 3.1 "Several protocols"): each
//! message goes to the protocol its kind names, each protocol keeps its own state, and a
//! backup carries one layer per protocol, which a restore puts back apart (Switch spec
//! 12.4).

use std::sync::Arc;

use pubky_switch_client::app::{App, AppConfig, OutgoingMessage, ProtocolSet};
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::{TestIdentity, TestProtocol};
use pubky_switch_signer::Signer;
use serde_json::{Value, json};

use super::enrollment::enroll;
use super::join::{app_status, events};
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, CHAT, TASKS, sample_protocol};
use crate::{FlowResult, World};

/// `tasks` and `chat`, in that order.
fn both() -> (Arc<TestProtocol>, Arc<TestProtocol>) {
    (sample_protocol(TASKS), sample_protocol(CHAT))
}

fn set_of(tasks: &Arc<TestProtocol>, chat: &Arc<TestProtocol>) -> Result<ProtocolSet, String> {
    ProtocolSet::new(vec![
        Arc::clone(tasks) as Arc<dyn pubky_switch_client::app::Protocol>,
        Arc::clone(chat) as Arc<dyn pubky_switch_client::app::Protocol>,
    ])
    .map_err(|error| error.to_string())
}

/// `identity`'s app `name`, approved by `signer` for the scopes of `tasks` and `chat` and
/// joined with both.
async fn joined_with_both(
    world: &World,
    identity: &TestIdentity,
    signer: &mut Signer,
    name: &str,
    protocols: ProtocolSet,
) -> Result<App, Box<dyn std::error::Error>> {
    let asking = Asking::for_scopes(world.app_keys(identity, name)?, &[TASKS, CHAT])?;
    let review = signer.review(asking.request.signed(), &asking.auth)?;
    let approved = signer.approve(review).await?;
    signer.claim_delivered(&approved.request).await?;
    world.advance_ms(STEP_MS);
    let mut app = App::join(
        world.app_env(Arc::new(MemoryStore::new())),
        protocols,
        AppConfig::default(),
        asking.join_request(identity.public(), &approved)?,
    )
    .await?;
    app.receive(None).await?;
    world.outcome("joined", &app_status(&mut app));
    world.advance_ms(STEP_MS);
    Ok(app)
}

/// What each protocol of `app` keeps: the kinds under its own key space, in key order.
async fn kept(app: &App) -> Result<Value, Box<dyn std::error::Error>> {
    let mut of = serde_json::Map::new();
    for name in [TASKS, CHAT] {
        let state = app.protocol_scan(name, b"").await?;
        let kinds: Vec<String> = state
            .into_iter()
            .map(|(_, kind)| String::from_utf8_lossy(&kind).into_owned())
            .collect();
        of.insert(name.to_owned(), json!(kinds));
    }
    Ok(Value::Object(of))
}

/// alice's wallet and bob's shop each run `tasks` and `chat` on one app. alice admits bob,
/// whose shop sends her messages of both protocols, interleaved; the wallet reads them in
/// one read, each handed to the protocol its kind names, which keeps it under its own key
/// space. A layered backup carries one layer per protocol; the wallet restored from it on
/// a new device puts each layer back under its own protocol, and reads on.
///
/// Calls, beyond the join's and the messaging flow's: none of their own; `POST
/// /v1/{id}/inbox` of two protocols' kinds to one app, and `GET /v1/{id}/feed` with them.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn two_protocols(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice, &bob]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let (tasks, chat) = both();
    let mut wallet = joined_with_both(
        world,
        &alice,
        &mut alice_signer,
        "wallet",
        set_of(&tasks, &chat)?,
    )
    .await?;
    let (shop_tasks, shop_chat) = both();
    let mut shop = joined_with_both(
        world,
        &bob,
        &mut bob_signer,
        "shop",
        set_of(&shop_tasks, &shop_chat)?,
    )
    .await?;
    let record = pubky_switch_core::records::AppRecord::verify(wallet.record(), &alice.public())?;
    world.outcome("the wallet's record accepts", &json!(record.body().accepts));

    wallet.add_contact(&bob.public()).await?;
    world.outcome("contact saved", &app_status(&mut wallet));
    world.advance_ms(STEP_MS);

    // Interleaved: each protocol's messages between the other's.
    for (n, kind) in [TASKS, CHAT, TASKS, CHAT].iter().enumerate() {
        let mut body = serde_json::Map::new();
        body.insert("n".into(), json!(n));
        let (_, delivery) = shop
            .send(OutgoingMessage::new(
                alice.public(),
                &format!("{kind}.item"),
                body,
            ))
            .await?;
        world.outcome(
            &format!("sent {kind}.item"),
            &json!({ "delivery": format!("{delivery:?}").split(' ').next() }),
        );
        world.advance_ms(STEP_MS);
    }

    let report = wallet.receive(None).await?;
    wallet.flush_cursor().await?;
    let before = kept(&wallet).await?;
    let kinds = |protocol: &TestProtocol| -> Vec<String> {
        protocol
            .received()
            .iter()
            .map(|message| message.message.kind.clone())
            .collect()
    };
    world.outcome(
        "received",
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "tasks": kinds(&tasks),
            "chat": kinds(&chat),
            "kept": before,
            "app": app_status(&mut wallet),
        }),
    );
    world.advance_ms(STEP_MS);
    // Each message went to its own protocol, which keeps it under its own key space.
    let items = |kind: &str| vec![format!("{kind}.item"); 2];
    if kinds(&tasks) != items(TASKS)
        || kinds(&chat) != items(CHAT)
        || before != json!({ TASKS: items(TASKS), CHAT: items(CHAT) })
    {
        return Err("each protocol takes and keeps its own messages alone".into());
    }

    let backup = wallet.backup_layered().await?;
    let layers: Vec<String> = backup
        .layers()?
        .iter()
        .map(|layer| layer.protocol.clone())
        .collect();
    world.outcome("backed up", &json!({ "layers": layers }));
    world.advance_ms(STEP_MS);
    // The device is lost.
    drop(wallet);

    let (tasks, chat) = both();
    let mut restored = App::restore(
        world.app_env(Arc::new(MemoryStore::new())),
        set_of(&tasks, &chat)?,
        AppConfig::default(),
        &backup,
    )
    .await?;
    let after = kept(&restored).await?;
    world.outcome(
        "restored",
        &json!({
            "kept": after,
            "app": app_status(&mut restored),
        }),
    );
    if after != before {
        return Err("the restore puts each layer back under its own protocol".into());
    }
    world.advance_ms(STEP_MS);

    // A message of each protocol after the restore goes to its own protocol, once.
    for kind in [CHAT, TASKS] {
        shop.send(OutgoingMessage::new(
            alice.public(),
            &format!("{kind}.item"),
            serde_json::Map::new(),
        ))
        .await?;
        world.advance_ms(STEP_MS);
    }
    let report = restored.receive(None).await?;
    world.outcome(
        "the restored wallet read on",
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "tasks": kinds(&tasks),
            "chat": kinds(&chat),
            "kept": kept(&restored).await?,
        }),
    );
    if kinds(&tasks) != [format!("{TASKS}.item")] || kinds(&chat) != [format!("{CHAT}.item")] {
        return Err("each protocol takes its own message after the restore, once".into());
    }
    Ok(())
}
