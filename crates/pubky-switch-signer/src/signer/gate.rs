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
///
/// While this install hands the identity over, or takes it over, the gate also refuses every
/// routine step ([`Refusal::HandingOver`], [`Refusal::TakingOver`]): only
/// [`hand_over_key`] and [`taking_over_key`] serve those flows' own steps.
pub(crate) fn refusal(state: &SignerState) -> Option<SignerError> {
    base_refusal(state).or_else(|| {
        if let Some(handing) = &state.handing_over {
            Some(
                Refusal::HandingOver {
                    to_app: handing.to_app,
                }
                .into(),
            )
        } else if state.taking_over {
            Some(Refusal::TakingOver.into())
        } else {
            None
        }
    })
}

/// The checks every signing step passes, a hand-over's or a take-over's included.
fn base_refusal(state: &SignerState) -> Option<SignerError> {
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
    // A received key serves only the take-over's own steps.
    if keyring.is_received() {
        return Err(Refusal::TakingOver.into());
    }
    Ok(keyring.signing_key(GatePassed(()))?)
}

/// The identity key for a hand-over's own steps, while this install hands the identity over
/// (Switch wire 3.12): storing it at the switch, and the abort. The base checks still apply.
///
/// # Errors
///
/// [`Refusal::NotHandingOver`] when it isn't handing over; otherwise as [`signing_key`].
pub(crate) fn hand_over_key(keyring: &IdentityKeyring, state: &SignerState) -> Result<SigningKey> {
    if let Some(refused) = base_refusal(state) {
        return Err(refused);
    }
    if state.handing_over.is_none() || keyring.is_received() {
        return Err(Refusal::NotHandingOver.into());
    }
    Ok(keyring.signing_key(GatePassed(()))?)
}

/// The identity key for a take-over's own step, the new signer's first delivery, signed with
/// the received key (Switch wire 3.12). The base checks still apply.
///
/// # Errors
///
/// [`Refusal::TakingOver`] when it isn't taking over; otherwise as [`signing_key`].
pub(crate) fn taking_over_key(
    keyring: &IdentityKeyring,
    state: &SignerState,
) -> Result<SigningKey> {
    if let Some(refused) = base_refusal(state) {
        return Err(refused);
    }
    if !state.taking_over {
        return Err(Refusal::TakingOver.into());
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

    fn handing_over() -> crate::state::HandingOver {
        crate::state::HandingOver {
            to_app: [4; 16],
            doc: pubky_switch_core::sig::SignedDoc {
                body: String::new(),
                sig: String::new(),
            },
            handover: pubky_switch_core::records::SignerHandover::from_parts(
                vec![vec![0]],
                [0; 64],
            ),
            sent: crate::state::HandOverSent::Stored,
            abort: None,
            take_back: None,
        }
    }

    #[test]
    fn test_gate_lets_a_hand_over_sign_only_its_own_steps() {
        let keyring = IdentityKeyring::open(MemoryVault::holding([7; 32])).unwrap();
        let fresh = SignerState::new(keyring.public_key(), [1; 16]);
        assert_eq!(
            hand_over_key(&keyring, &fresh).err(),
            Some(Refusal::NotHandingOver.into())
        );
        let mut state = fresh.clone();
        state.handing_over = Some(handing_over());
        assert_eq!(
            signing_key(&keyring, &state).err(),
            Some(Refusal::HandingOver { to_app: [4; 16] }.into())
        );
        assert!(hand_over_key(&keyring, &state).is_ok());
        assert!(taking_over_key(&keyring, &state).is_err());
        // The base checks still hold a hand-over's own steps back.
        state.switch_unconfirmed = true;
        assert_eq!(
            hand_over_key(&keyring, &state).err(),
            Some(Refusal::SwitchUnconfirmed.into())
        );
    }

    #[test]
    fn test_gate_lets_a_received_key_sign_only_the_take_over() {
        let keyring = crate::key::tests::received_keyring([7; 32]);
        let mut state = SignerState::new(keyring.public_key(), [1; 16]);
        // Not taking over: a received key signs nothing.
        assert_eq!(
            signing_key(&keyring, &state).err(),
            Some(Refusal::TakingOver.into())
        );
        assert!(taking_over_key(&keyring, &state).is_err());
        state.taking_over = true;
        assert_eq!(
            signing_key(&keyring, &state).err(),
            Some(Refusal::TakingOver.into())
        );
        assert!(hand_over_key(&keyring, &state).is_err());
        assert!(taking_over_key(&keyring, &state).is_ok());
        state.managed_by = Some([9; 16]);
        assert_eq!(
            taking_over_key(&keyring, &state).err(),
            Some(SignerError::NotNamed { install: [9; 16] })
        );
    }
}
