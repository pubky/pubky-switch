//! An app's push registration, and its end with the app (Switch spec 9, Switch wire 8.1).

use pubky_switch_client::TransportError;
use pubky_switch_client::app::{
    AppError, LeaveMode, MAX_HANDLES, PushHandles, PushRegistration, PushRelay,
};
use pubky_switch_client::transport::BoxFuture;
use pubky_switch_core::http::ErrorCode;
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::join::app_status;
use super::messaging::joined;
use super::removal::result;
use super::{ORIGIN, STEP_MS};
use crate::{FlowResult, World};

/// The relay every app of the flow registers at: one relay host.
const RELAY_URL: &str = "https://push.example/v1/hook";

/// A relay that binds each device token to a handle of its own, the same for the same
/// token, whatever push key it is bound to (Switch spec 9 step 2, Switch wire 8.3).
struct Relay;

impl PushRelay for Relay {
    fn register(
        &self,
        _relay_url: String,
        device_token: String,
        _push_key: [u8; 32],
    ) -> BoxFuture<'_, Result<String, TransportError>> {
        Box::pin(async move { Ok(format!("{device_token} at the relay")) })
    }
}

/// What a registration call ended with, for the trace: the handles the switch keeps, or the
/// error.
fn registered(registration: &Result<PushRegistration, AppError>) -> Value {
    match registration {
        Ok(registration) => json!({ "ok": true, "handles": registration.handles }),
        Err(_) => result(registration),
    }
}

/// An app registers for pushes, and the registration goes when the app leaves (Switch wire
/// 8.1: "removed when the app stops being current"). alice's phone registers its handle at
/// a relay. Her wallet registers its own there, then sets the handles of its seven other
/// devices too: eight of its own and the phone's one would be more than an entry sends
/// toward one relay host (Switch wire 8.2), so the switch refuses the list. The phone
/// leaves, and its registration with it: the wallet's eight are then taken.
///
/// Calls: `PUT /v1/{id}/push`, a start that mints a push key, a start the switch answers
/// with the registration it holds, the handles set, and a list refused with `400`.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the wallet's list is taken
/// while the phone's registration holds, or refused once the phone left.
pub async fn push_registration(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (mut phone, _) = joined(world, &alice, &mut signer, "phone").await?;

    let phone_registered = phone.register_push(&Relay, RELAY_URL, "phone").await;
    world.outcome("the phone registered", &registered(&phone_registered));
    if phone_registered?.handles != 1 {
        return Err("the switch keeps another number of the phone's handles".into());
    }
    world.advance_ms(STEP_MS);

    let first = wallet.register_push(&Relay, RELAY_URL, "wallet").await;
    world.outcome("the wallet registered", &registered(&first));
    let first = first?;
    world.advance_ms(STEP_MS);

    // The wallet's other devices, from its host's device sync, bound to the same push key.
    let others = (1..MAX_HANDLES)
        .map(|device| format!("wallet device {device} at the relay"))
        .collect();
    wallet
        .take_device_push_handles(PushHandles {
            push_key: first.push_key,
            handles: others,
        })
        .await?;
    let refused = wallet.register_push(&Relay, RELAY_URL, "wallet").await;
    world.outcome(
        "the wallet set eight handles beside the phone's",
        &registered(&refused),
    );
    match &refused {
        Err(error) if error.code() == Some(ErrorCode::BadRequest) => {}
        _ => return Err("nine handles at one relay host weren't refused".into()),
    }
    world.advance_ms(STEP_MS);

    let left = phone.leave(LeaveMode::TwoStep).await?;
    world.outcome("the phone left", &json!({ "report": format!("{left:?}") }));
    world.advance_ms(STEP_MS);

    let taken = wallet.register_push(&Relay, RELAY_URL, "wallet").await;
    world.outcome(
        "the wallet set eight handles after the phone left",
        &json!({
            "registration": registered(&taken),
            "same_push_key": taken.as_ref().is_ok_and(|now| now.push_key == first.push_key),
            "wallet": app_status(&mut wallet),
        }),
    );
    let taken = taken?;
    if taken.handles != 8 || taken.push_key != first.push_key {
        return Err("the wallet's eight handles weren't taken under its push key".into());
    }
    world.advance_ms(STEP_MS);

    signer.run_due().await?;
    world.outcome("signer ran what is due", &status(&signer)?);
    Ok(())
}
