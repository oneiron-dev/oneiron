//! Turn programs between a vault's machines (FIX 5266, untangle 6.9a): plant
//! an arming and the wake a landed turn owes it, name this machine for the
//! home election, and read what a machine owes and decided.

use crate::authority::{InvocationSlipBinding, VerifiedSlip};
use crate::error::Result;
use crate::{EntityId, Vault};

/// This machine's node id for the MACRO home election: its client id,
/// minted on first use.
///
/// # Errors
///
/// A store failure.
pub fn node_id(vault: &Vault) -> Result<u64> {
    crate::store::install_identity::load_or_mint_client_id(vault)
}

/// Arms a program for the agent `actor` in `conversation` at `armed_at`,
/// sealed by the verified slip `proof` and its instrument `binding`, and
/// records the wake TURN `turn`, landed at `landed_at`, owes it, as the
/// arm door and the turn's writer leave them (no SKILL is pinned). Answers
/// the registration.
///
/// # Errors
///
/// A slip that seals no turn program authority; a store failure.
#[allow(clippy::too_many_arguments)]
pub fn plant_slip_wake(
    vault: &Vault,
    actor: EntityId,
    proof: &VerifiedSlip,
    binding: &InvocationSlipBinding,
    conversation: EntityId,
    turn: EntityId,
    armed_at: u64,
    landed_at: u64,
) -> Result<EntityId> {
    crate::dreamer_runner::turn_program_test_hooks::plant_slip_wake(
        vault,
        actor,
        proof,
        binding,
        conversation,
        turn,
        armed_at,
        landed_at,
    )
}

/// Whether this machine owes the wake TURN `turn` owes `registration`.
///
/// # Errors
///
/// A store failure.
pub fn wake_owed_here(vault: &Vault, turn: EntityId, registration: EntityId) -> Result<bool> {
    crate::dreamer_runner::turn_program_test_hooks::wake_owed_here(vault, turn, registration)
}

/// How many decisions (admitted or refused) this machine holds for the wake
/// TURN `turn` owes `registration`.
///
/// # Errors
///
/// A store failure.
pub fn wake_decisions_here(vault: &Vault, turn: EntityId, registration: EntityId) -> Result<usize> {
    crate::dreamer_runner::turn_program_test_hooks::wake_decisions_here(vault, turn, registration)
}

/// Holds the wake TURN `turn` owes `registration` on its lapsed slip, as the
/// home's admission holds one whose slip lapsed: owed until its rebind or
/// its expiry. Answers whether there was a wake to hold.
///
/// # Errors
///
/// A store failure.
pub fn hold_wake_on_lapsed_slip(
    vault: &Vault,
    turn: EntityId,
    registration: EntityId,
    held_at: u64,
) -> Result<bool> {
    crate::dreamer_runner::turn_program_test_hooks::hold_wake_on_lapsed_slip(
        vault,
        turn,
        registration,
        held_at,
    )
}
