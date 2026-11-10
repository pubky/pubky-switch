//! The signing gate: the one way to the identity key for anything that signs (Switch spec 4.3).
//!
//! Every signed document, certificate, approval, claim, key bundle and operation is made with
//! a [`SigningKey`], and only [`signing_key`] hands one out, once its checks pass: this install
//! is the one named, its records aren't behind its own newer version, and no rollback or
//! equivocation alarm is latched or held. Clients of the switch get a request-only key
//! ([`crate::key::IdentityKeyring::request_signer`]) for their `Switch-Signature`, so they
//! read, and deliver what was signed already, but sign nothing new.
//!
//! Outside the gate, with the records' own key, are only the steps that sign nothing new:
//! the backup of a version that passed the gate (sealed once in its flow), opening a backup,
//! request signatures, and the delivery and publication of signed versions, the re-delivery
//! that clears an alarm included.

use crate::alert::Alert;
use crate::error::{Refusal, Result, SignerError};
use crate::key::{IdentityKeyring, SigningKey};
use crate::state::SignerState;

/// That the gate's checks passed for one call: only [`signing_key`] makes one.
pub(crate) struct GatePassed(());

/// Why the records `state` sign nothing now, if they don't: another install is the signer
/// ([`SignerError::NotNamed`]), the records are behind this install's own newer version
/// ([`Refusal::RecordsBehind`]), or an alarm is latched or held: the switch hasn't confirmed
/// the mark since a rollback or an equivocation, or the user hasn't cleared its alert
/// ([`SignerError::Alarm`], or [`Refusal::SwitchUnconfirmed`] once the alert is cleared and
/// the re-delivery that confirms the switch is still owed).
pub(crate) fn refusal(state: &SignerState) -> Option<SignerError> {
    if let Some(install) = state.managed_by {
        return Some(SignerError::NotNamed { install });
    }
    if let Some(version) = state.records_behind {
        return Some(Refusal::RecordsBehind { version }.into());
    }
    if let Some(alarm) = held_alarm(state) {
        return Some(SignerError::Alarm(alarm.clone()));
    }
    if state.switch_unconfirmed {
        return Some(Refusal::SwitchUnconfirmed.into());
    }
    None
}

/// The rollback or equivocation alert the user hasn't cleared, if any.
pub(crate) fn held_alarm(state: &SignerState) -> Option<&Alert> {
    state
        .alerts
        .iter()
        .find(|a| matches!(a, Alert::Rollback { .. } | Alert::Equivocation { .. }))
}

/// The identity key for the records `state` to sign with, once the gate's checks pass.
///
/// # Errors
///
/// The refusal of [`refusal`], or the key's error.
pub(crate) fn signing_key(keyring: &IdentityKeyring, state: &SignerState) -> Result<SigningKey> {
    if let Some(refused) = refusal(state) {
        return Err(refused);
    }
    Ok(keyring.signing_key(GatePassed(()))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::Source;
    use crate::key::tests::MemoryVault;

    #[test]
    fn test_gate_hands_out_the_key_only_when_nothing_holds_signing_back() {
        let keyring = IdentityKeyring::open(MemoryVault::holding([7; 32])).unwrap();
        let fresh = SignerState::new(keyring.public_key(), [1; 16]);
        assert!(signing_key(&keyring, &fresh).is_ok());
        let alarm = Alert::Equivocation {
            source: Source::Homeserver,
            version: 2,
        };
        let held = |change: &dyn Fn(&mut SignerState)| {
            let mut state = fresh.clone();
            change(&mut state);
            signing_key(&keyring, &state).err()
        };
        assert_eq!(
            held(&|s| s.managed_by = Some([7; 16])),
            Some(SignerError::NotNamed { install: [7; 16] })
        );
        assert_eq!(
            held(&|s| s.records_behind = Some(9)),
            Some(Refusal::RecordsBehind { version: 9 }.into())
        );
        assert_eq!(
            held(&|s| s.alert(alarm.clone())),
            Some(SignerError::Alarm(alarm.clone()))
        );
        assert_eq!(
            held(&|s| s.switch_unconfirmed = true),
            Some(Refusal::SwitchUnconfirmed.into())
        );
        // Other alerts don't hold signing back.
        assert!(held(&|s| s.alert(Alert::BackupMissing)).is_none());
    }
}
