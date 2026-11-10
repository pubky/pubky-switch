//! `invite_code.delete`'s rule beside the operation checks (Switch wire 6.2).

use crate::chain::ProofState;
use crate::http::ErrorCode;

use super::Refusal;

/// `invite_code.delete` (Switch wire 6.2): withdraws a code the switch holds; an unknown
/// code is `404 not_found`.
///
/// # Errors
///
/// The `404` refusal when the code isn't held.
pub fn invite_code_delete(held: bool) -> Result<ProofState, Refusal> {
    if held {
        Ok(ProofState::InviteCodeDelete)
    } else {
        Err(Refusal::new(
            ErrorCode::NotFound,
            "Switch wire 6.2: an unknown invite code",
        ))
    }
}
