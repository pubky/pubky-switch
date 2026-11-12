//! The futures of the signer's entry points a host may spawn are `Send`: a host runs them on
//! a multi-threaded runtime, and a future that holds a non-`Send` value, such as a borrowed
//! iterator, across an await can't be spawned. The checks are at compile time: the function
//! below is never called, and building the tests fails if one of them isn't.

use pubky_switch_core::records::ConnectRequests;

use crate::{AppReview, CertChange, IdentityKeyring, Signer, SignerEnv, UserConfirmed};

fn is_send<T: Send>(_: T) {}

/// Every call below is a future the host may spawn; none is awaited.
#[allow(dead_code)]
fn signer_futures_are_send(
    signer: &mut Signer,
    env: SignerEnv,
    keyring: IdentityKeyring,
    other_keyring: IdentityKeyring,
    review: AppReview,
    change: CertChange,
    settings: ConnectRequests,
) {
    is_send(Signer::create(
        env.clone(),
        keyring,
        "https://switch.example",
    ));
    is_send(Signer::open(env, other_keyring));
    is_send(signer.approve(review));
    is_send(signer.revoke([0; 16], None, UserConfirmed::shown_and_confirmed()));
    is_send(signer.renew([0; 16], change));
    is_send(signer.renew_expiring());
    is_send(signer.run_due());
    is_send(signer.resume());
    is_send(signer.declare_provider_loss(
        "https://switch.example",
        UserConfirmed::shown_and_confirmed(),
    ));
    is_send(signer.end_staged_admission());
    is_send(signer.set_connect_requests(settings));
}
