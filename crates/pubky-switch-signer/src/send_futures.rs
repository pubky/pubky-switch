//! The futures of the signer's entry points a host may spawn are `Send`: a host runs them on
//! a multi-threaded runtime, and a future that holds a non-`Send` value, such as a borrowed
//! iterator, across an await can't be spawned. The checks are at compile time: the function
//! below is never called, and building the tests fails if one of them isn't. It names every
//! public async function of the signer.

use std::sync::Arc;

use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::ConnectRequests;

use crate::{
    Alert, AppReview, CertChange, IdentityKeyring, ReceivingApp, SecretVault, Signer, SignerEnv,
    UserConfirmed,
};

fn is_send<T: Send>(_: T) {}

/// Every call below is a future the host may spawn; none is awaited.
#[allow(dead_code, clippy::too_many_arguments)]
fn signer_futures_are_send(
    signer: &mut Signer,
    env: SignerEnv,
    keyring: IdentityKeyring,
    other_keyring: IdentityKeyring,
    restored_keyring: IdentityKeyring,
    review: AppReview,
    change: CertChange,
    settings: ConnectRequests,
    alert: &Alert,
    receiving: &ReceivingApp,
    keys: &AppKeys,
    vault: Arc<dyn SecretVault>,
) {
    let confirmed = UserConfirmed::shown_and_confirmed;
    // Constructors.
    is_send(Signer::create(
        env.clone(),
        keyring,
        "https://switch.example",
    ));
    is_send(Signer::open(env.clone(), other_keyring));
    is_send(Signer::restore_new(
        env.clone(),
        restored_keyring,
        confirmed(),
    ));
    is_send(Signer::receive_hand_over(
        env.clone(),
        receiving,
        vault.clone(),
    ));
    is_send(Signer::resume_take_over(env, [0; 32], keys, vault));
    // Calls on a signer, one at a time, as `&mut self` allows.
    is_send(signer.resume());
    is_send(signer.clear_alert(alert));
    is_send(signer.set_record_max_age(None));
    is_send(signer.set_connect_requests(settings));
    is_send(signer.renew([0; 16], change));
    is_send(signer.complete_renewals());
    is_send(signer.run_due());
    is_send(signer.renew_expiring());
    is_send(signer.declare_provider_loss("https://switch.example", confirmed()));
    is_send(signer.declare_provider_loss_confirming_records("https://switch.example", confirmed()));
    is_send(signer.end_staged_admission());
    is_send(signer.restore(confirmed()));
    is_send(signer.approve(review));
    is_send(signer.claim_delivered(&[0; 32]));
    is_send(signer.hand_over_to([0; 16], confirmed()));
    is_send(signer.abort_hand_over(confirmed()));
    is_send(signer.take_back(confirmed()));
    is_send(signer.close_account(confirmed()));
    is_send(signer.abort_erasure());
    is_send(signer.revoke([0; 16], None, confirmed()));
    is_send(signer.complete_removals());
    is_send(signer.open_attempts([0; 16]));
    is_send(signer.purge_removed([0; 16]));
    is_send(signer.serve_full_bundles());
}
