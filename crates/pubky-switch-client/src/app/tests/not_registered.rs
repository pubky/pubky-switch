//! A `403 not_current` an own app gets before its request verified, with no `Switch-Head`,
//! is the refusal of a first call: the service holds no record of the app to verify it
//! with (Switch wire 7.1 "`Switch-Head` on refusals", 7.2). It says the app isn't
//! registered there, not that it was revoked or departed, so the app doesn't take itself as
//! removed on it. A `403 not_current` with the head comes after the request verified, and
//! is (Switch spec 12.2, 12.3).

use super::moves::has;
use super::*;
use crate::app::{AppError, AppEvent};
use crate::testing::Fault;
use crate::transport::{BoxFuture, Request, Response, Transport};
use crate::{TransportError, error::ClientError};
use pubky_switch_core::http::{ErrorCode, header};

/// The switch, every `403` answered without its head, as before the request verified.
struct Headless(Arc<dyn Transport>);

impl Transport for Headless {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        Box::pin(async move {
            let mut response = self.0.send(request).await?;
            if response.status == 403 {
                response
                    .headers
                    .retain(|h| !h.name.eq_ignore_ascii_case(header::HEAD));
            }
            Ok(response)
        })
    }
}

fn not_current() -> Fault {
    Fault::Error {
        path: "feed".into(),
        code: ErrorCode::NotCurrent,
        current: json!(null),
    }
}

#[tokio::test]
async fn test_not_registered_headless_not_current_isnt_a_removal() {
    let w = World::new();
    let me = w.join("wallet").await.app_id();
    let env = AppEnv {
        transport: Arc::new(Headless(w.switch.transport())),
        ..w.env()
    };
    let mut app = App::load(env, w.protocol.clone(), World::config(), me)
        .await
        .unwrap();
    w.switch.fail_next(not_current());
    let error = app.receive(None).await.unwrap_err();
    assert!(
        matches!(
            &error,
            AppError::Switch(ClientError::Switch {
                code: ErrorCode::NotCurrent,
                ..
            })
        ),
        "{error:?}"
    );
    assert!(!has(&app.take_events(), |e| matches!(e, AppEvent::Removed)));
    // Not gone: the next read goes on.
    let report = app.receive(None).await.unwrap();
    assert!(!report.stopped, "{:?}", report.events);
    assert!(!has(&report.events, |e| matches!(e, AppEvent::Removed)));
}

#[tokio::test]
async fn test_not_registered_not_current_with_the_head_is_a_removal() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.switch.fail_next(not_current());
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(has(&report.events, |e| matches!(e, AppEvent::Removed)));
}
