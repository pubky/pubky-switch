//! Honest flows: what the real signer and the real app do when nothing goes wrong, each
//! written once and run in a [`World`] of either kind.
//!
//! A flow returns an error only where it should succeed against any switch. What a party
//! returned or raised goes into the trace with [`World::outcome`], so the two runs are
//! compared on it too.
//!
//! [`FLOWS`] names every flow, and [`flow_of`] says which flow sends each call the service
//! routes.

mod claim;
mod enrollment;
mod join;
mod lists;
mod messaging;
mod removal;
mod renewal;
mod restore;
mod retries;
mod watching;

use std::future::Future;
use std::pin::Pin;

use pubky_switch::http::route::Call;

pub use claim::claim;
pub use enrollment::enrollment;
pub use join::join;
pub use lists::lists_without_read;
pub use messaging::messaging;
pub use removal::{departure, revocation};
pub use renewal::renewal;
pub use restore::restore;
pub use retries::{app_retries, append_retry, signer_retries};
pub use watching::watching;

use crate::{FlowResult, World};

/// The origin of the flows' switch: the one the scripted switch enrolls at.
pub const ORIGIN: &str = pubky_switch_client::testing::SWITCH_ORIGIN;

/// The time a flow lets pass between its steps: not a whole number of seconds, so each step
/// has its own time and a time cut to the second, or taken from the wrong step, shows.
pub const STEP_MS: u64 = 61_250;

/// A flow, as a plain function.
pub type Flow = for<'a> fn(&'a World) -> Pin<Box<dyn Future<Output = FlowResult> + 'a>>;

/// Every flow, by the name the allowed-differences list and [`flow_of`] know it by.
pub const FLOWS: &[(&str, Flow)] = &[
    ("enrollment", |world| Box::pin(enrollment(world))),
    ("join", |world| Box::pin(join(world))),
    ("messaging", |world| Box::pin(messaging(world))),
    ("lists without read", |world| {
        Box::pin(lists_without_read(world))
    }),
    ("claim", |world| Box::pin(claim(world))),
    ("renewal", |world| Box::pin(renewal(world))),
    ("revocation", |world| Box::pin(revocation(world))),
    ("departure", |world| Box::pin(departure(world))),
    ("watching", |world| Box::pin(watching(world))),
    ("restore", |world| Box::pin(restore(world))),
    ("signer retries", |world| Box::pin(signer_retries(world))),
    ("app retries", |world| Box::pin(app_retries(world))),
    ("append retry", |world| Box::pin(append_retry(world))),
];

/// The flow that sends `call` to the service; `None` for a call the service doesn't serve
/// yet, or that a later flow will send. The routes test fails when the service serves a call
/// that has no flow here, and when a flow named here doesn't send its call.
pub fn flow_of(call: &Call) -> Option<&'static str> {
    match call {
        Call::Enroll | Call::PutIdentity | Call::GetIdentity | Call::GetApps => Some("enrollment"),
        Call::Ops | Call::Feed | Call::GetKeys(_) | Call::GetAllow => Some("join"),
        Call::Append | Call::PutPeers | Call::Directory => Some("messaging"),
        Call::GetClaim(_) => Some("claim"),
        Call::Revoke(_) => Some("revocation"),
        Call::Leave(_) => Some("departure"),
        // Served, and waiting for its flow: an app asks for a full bundle only when it
        // lacks an epoch's keys, and no honest flow leaves it lacking one while the service
        // keeps every bundle part (the restore flow shows it).
        Call::RequestKeys(_) => None,
        // Served, and waiting for their flow: the watching flow's shared record, which an
        // app whose protocol has collections lists when it joins.
        Call::GetRecord(_) | Call::ListRecords => None,
        // Not served yet.
        Call::PostConnect
        | Call::GetConnect
        | Call::DeleteConnect(_)
        | Call::PutPush
        | Call::Freeze
        | Call::Unfreeze
        | Call::Export
        | Call::ExportChunk(_)
        | Call::Import
        | Call::ImportChunk(_)
        | Call::ImportActivate
        | Call::RecoveryAdmission
        | Call::RecoveryUpload
        | Call::Erase
        | Call::PutHandover
        | Call::GetHandover => None,
    }
}

/// One request per call of Switch wire 7.4: the method, and the path with `{id}` for the
/// account, `{app}` for an App ID and `{key}` for any other parameter.
pub const CALLS: &[(&str, &str)] = &[
    ("POST", "/v1/enroll"),
    ("PUT", "/v1/{id}/identity"),
    ("GET", "/v1/{id}/identity"),
    ("POST", "/v1/{id}/inbox"),
    ("GET", "/v1/{id}/feed"),
    ("PUT", "/v1/{id}/peers"),
    ("GET", "/v1/{id}/allow"),
    ("POST", "/v1/{id}/connect"),
    ("GET", "/v1/{id}/connect"),
    ("DELETE", "/v1/{id}/connect/{key}"),
    ("POST", "/v1/{id}/ops"),
    ("GET", "/v1/{id}/claims/{key}"),
    ("GET", "/v1/{id}/records/{key}"),
    ("GET", "/v1/{id}/records"),
    ("GET", "/v1/{id}/directory"),
    ("GET", "/v1/{id}/apps/{app}/keys"),
    ("POST", "/v1/{id}/apps/{app}/keys"),
    ("PUT", "/v1/{id}/push"),
    ("POST", "/v1/{id}/apps/{app}/leave"),
    ("GET", "/v1/{id}/apps"),
    ("POST", "/v1/{id}/apps/{app}/revoke"),
    ("POST", "/v1/{id}/freeze"),
    ("POST", "/v1/{id}/unfreeze"),
    ("GET", "/v1/{id}/export"),
    ("GET", "/v1/{id}/export/chunks/{key}"),
    ("POST", "/v1/{id}/import"),
    ("PUT", "/v1/{id}/import/chunks/{key}"),
    ("POST", "/v1/{id}/import/activate"),
    ("POST", "/v1/{id}/recovery/admission"),
    ("POST", "/v1/{id}/recovery/upload"),
    ("POST", "/v1/{id}/erase"),
    ("PUT", "/v1/{id}/handover"),
    ("GET", "/v1/{id}/handover"),
];
