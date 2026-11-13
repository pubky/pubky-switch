//! Honest flows: what the real signer and the real app do when nothing goes wrong, each
//! written once and run in a [`World`] of either kind.
//!
//! A flow returns an error only where it should succeed against any switch. What a party
//! returned or raised goes into the trace with [`World::outcome`], so the two runs are
//! compared on it too.
//!
//! [`FLOWS`] names every flow, and [`flow_of`] says which flow sends each call the service
//! routes.

mod admission;
mod awaiting;
mod claim;
mod collections;
mod connect;
mod enrollment;
mod epochs;
mod erasure;
mod grants;
mod handover;
mod installs;
mod join;
mod lagging;
mod lists;
mod messaging;
mod own_record;
mod pages;
mod records;
mod recovery;
mod reduction;
mod removal;
mod renewal;
mod restore;
mod retries;
mod revocations;
mod upload;
mod waiting;
mod watching;

use std::future::Future;
use std::pin::Pin;

use pubky_switch::http::route::Call;

pub use admission::{deny_list, invite_code};
pub use awaiting::awaiting_key;
pub use claim::claim;
pub use collections::two_collections;
pub use connect::{
    connect_request, connect_request_full, connect_request_recovered,
    connect_request_recovered_in_place, connect_request_turned_off,
};
pub use enrollment::enrollment;
pub use epochs::{epochs_three_readers, rotation_given_up, third_epoch};
pub use erasure::{erasure, erasure_answer_lost, erasure_enrolled_again};
pub use grants::{grant_paths_decline_refused, grant_paths_declined};
pub use handover::{hand_over, hand_over_abort_late, hand_over_aborted, hand_over_take_over_late};
pub use installs::{
    publication_other_document, publication_repaired, signer_new_install, signer_records_behind,
    signer_restore_revocation, signer_restore_undelivered, signer_two_installs_race,
};
pub use join::join;
pub use lagging::{lagging_app, missed_item, unreadable_after_revoke};
pub use lists::lists_without_read;
pub use messaging::messaging;
pub use own_record::own_record;
pub use pages::pages;
pub use records::records;
pub use recovery::{
    provider_loss, provider_loss_in_place, provider_loss_in_place_restored,
    provider_loss_in_place_sender, provider_loss_refusals_in_transit, provider_loss_refused,
    provider_loss_restored, provider_loss_revocation_meanwhile, provider_loss_same_origin_refused,
    provider_loss_sender_admitted,
};
pub use reduction::{reduction_unpublished, renewal_drops_scope};
pub use removal::{departure, revocation};
pub use renewal::{renewal, renewed_twice};
pub use restore::restore;
pub use retries::{
    app_retries, append_retry, claim_and_read_retries, claim_retries, removal_retries,
    signer_retries,
};
pub use revocations::{departure_time, revocation_cleanup, revocation_times, revocation_unread};
pub use upload::{
    recovery_upload_claim, recovery_upload_deny_only, recovery_upload_records,
    recovery_upload_refused, recovery_upload_slots_before_the_loss,
};
pub use waiting::{
    waiting_read, waiting_read_erased, waiting_read_recovered, waiting_read_revoked,
};
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
    ("removal retries", |world| Box::pin(removal_retries(world))),
    ("claim and read retries", |world| {
        Box::pin(claim_and_read_retries(world))
    }),
    ("claim retries", |world| Box::pin(claim_retries(world))),
    ("hand-over", |world| Box::pin(hand_over(world))),
    ("hand-over aborted", |world| {
        Box::pin(hand_over_aborted(world))
    }),
    (
        "hand-over, the abort arrives after the take-over",
        |world| Box::pin(hand_over_abort_late(world)),
    ),
    (
        "hand-over, the take-over arrives after the abort",
        |world| Box::pin(hand_over_take_over_late(world)),
    ),
    ("signer, two new installs restored at once", |world| {
        Box::pin(signer_two_installs_race(world))
    }),
    ("records", |world| Box::pin(records(world))),
    ("erasure", |world| Box::pin(erasure(world))),
    ("erasure, answer lost", |world| {
        Box::pin(erasure_answer_lost(world))
    }),
    ("erasure, enrolled again", |world| {
        Box::pin(erasure_enrolled_again(world))
    }),
    ("pages", |world| Box::pin(pages(world))),
    ("invite code", |world| Box::pin(invite_code(world))),
    ("deny list", |world| Box::pin(deny_list(world))),
    ("renewal, a scope dropped", |world| {
        Box::pin(renewal_drops_scope(world))
    }),
    ("renewal, a reduction unpublished", |world| {
        Box::pin(reduction_unpublished(world))
    }),
    ("renewed twice", |world| Box::pin(renewed_twice(world))),
    ("own record", |world| Box::pin(own_record(world))),
    ("third epoch", |world| Box::pin(third_epoch(world))),
    ("awaiting a key", |world| Box::pin(awaiting_key(world))),
    ("third epoch, three readers", |world| {
        Box::pin(epochs_three_readers(world))
    }),
    ("rotation given up, its epoch completed", |world| {
        Box::pin(rotation_given_up(world))
    }),
    ("two collections", |world| Box::pin(two_collections(world))),
    ("waiting read", |world| Box::pin(waiting_read(world))),
    ("lagging app", |world| Box::pin(lagging_app(world))),
    ("missed item", |world| Box::pin(missed_item(world))),
    ("unreadable after a revoke", |world| {
        Box::pin(unreadable_after_revoke(world))
    }),
    ("waiting read, the account erased", |world| {
        Box::pin(waiting_read_erased(world))
    }),
    ("waiting read, the reader revoked", |world| {
        Box::pin(waiting_read_revoked(world))
    }),
    ("waiting read, a recovery in place", |world| {
        Box::pin(waiting_read_recovered(world))
    }),
    ("connect request", |world| Box::pin(connect_request(world))),
    ("connect request, the list full", |world| {
        Box::pin(connect_request_full(world))
    }),
    ("connect request, turned off", |world| {
        Box::pin(connect_request_turned_off(world))
    }),
    ("connect request, across a provider loss", |world| {
        Box::pin(connect_request_recovered(world))
    }),
    ("connect request, a recovery in place", |world| {
        Box::pin(connect_request_recovered_in_place(world))
    }),
    ("approval, grant paths declined", |world| {
        Box::pin(grant_paths_declined(world))
    }),
    ("approval, a decline the protocol refuses", |world| {
        Box::pin(grant_paths_decline_refused(world))
    }),
    ("provider loss", |world| Box::pin(provider_loss(world))),
    ("provider loss, a sender admitted", |world| {
        Box::pin(provider_loss_sender_admitted(world))
    }),
    ("provider loss, in place", |world| {
        Box::pin(provider_loss_in_place(world))
    }),
    ("provider loss in place, a sender while staged", |world| {
        Box::pin(provider_loss_in_place_sender(world))
    }),
    ("provider loss, refused", |world| {
        Box::pin(provider_loss_refused(world))
    }),
    ("provider loss, refusals not the switch's", |world| {
        Box::pin(provider_loss_refusals_in_transit(world))
    }),
    ("provider loss, restored", |world| {
        Box::pin(provider_loss_restored(world))
    }),
    ("provider loss in place, restored", |world| {
        Box::pin(provider_loss_in_place_restored(world))
    }),
    ("provider loss, refused at the same origin", |world| {
        Box::pin(provider_loss_same_origin_refused(world))
    }),
    ("provider loss, a revocation asked meanwhile", |world| {
        Box::pin(provider_loss_revocation_meanwhile(world))
    }),
    ("revocation, the time it counts from", |world| {
        Box::pin(revocation_times(world))
    }),
    ("departure, a version delivered meanwhile", |world| {
        Box::pin(departure_time(world))
    }),
    ("revocation, cleanup and purge", |world| {
        Box::pin(revocation_cleanup(world))
    }),
    ("revocation, the switch unread", |world| {
        Box::pin(revocation_unread(world))
    }),
    ("publication, the Homeserver's copy put right", |world| {
        Box::pin(publication_repaired(world))
    }),
    ("publication, another document at the version", |world| {
        Box::pin(publication_other_document(world))
    }),
    ("signer, a new install takes over", |world| {
        Box::pin(signer_new_install(world))
    }),
    ("signer, records behind and restored in place", |world| {
        Box::pin(signer_records_behind(world))
    }),
    ("signer restore, a version never delivered", |world| {
        Box::pin(signer_restore_undelivered(world))
    }),
    (
        "signer restore, a revocation only the switch holds",
        |world| Box::pin(signer_restore_revocation(world)),
    ),
    ("recovery upload, a claim rebuilt", |world| {
        Box::pin(recovery_upload_claim(world))
    }),
    ("recovery upload, records", |world| {
        Box::pin(recovery_upload_records(world))
    }),
    ("recovery upload, a deny list alone", |world| {
        Box::pin(recovery_upload_deny_only(world))
    }),
    ("recovery upload, refused", |world| {
        Box::pin(recovery_upload_refused(world))
    }),
    (
        "recovery upload, the hour's slots used before the loss",
        |world| Box::pin(recovery_upload_slots_before_the_loss(world)),
    ),
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
        Call::PutHandover | Call::GetHandover => Some("hand-over"),
        Call::GetRecord(_) | Call::ListRecords => Some("records"),
        Call::Erase => Some("erasure"),
        Call::RecoveryAdmission => Some("provider loss"),
        Call::RecoveryUpload => Some("provider loss, a sender admitted"),
        // A restored app lacks the keys of a part it passed before its loss, which went.
        Call::RequestKeys(_) => Some("restore"),
        Call::PostConnect | Call::GetConnect | Call::DeleteConnect(_) => Some("connect request"),
        // Not served yet.
        Call::PutPush
        | Call::Freeze
        | Call::Unfreeze
        | Call::Export
        | Call::ExportChunk(_)
        | Call::Import
        | Call::ImportChunk(_)
        | Call::ImportActivate => None,
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
