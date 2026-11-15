//! Door for `tests/fingerprint_keep_hook_digests.rs` (PLAN-UC-04 stage 6.3d): the input
//! hashes of the hook fact sources, a hook run's params digest and its run key, which the
//! engine computes in private code.

use crate::runtime_hooks::{FactPosition, SettledOutcome, SettlementKind};
use crate::skill_hub::pack_catalog::PackHookBinding;
use crate::{EntityId, Result};

/// The input hash of a tick of `task` due at `due_at`.
#[must_use]
pub fn tick_input_hash(task: EntityId, due_at: u64) -> [u8; 32] {
    crate::runtime_hooks::tick_input_hash_for_test(task, due_at)
}

/// The input hash of `proposal`'s settlement.
#[must_use]
pub fn settlement_input_hash(
    proposal: EntityId,
    outcome: SettledOutcome,
    settled_by: EntityId,
    kind: SettlementKind,
    body_hash: Option<[u8; 32]>,
) -> [u8; 32] {
    crate::runtime_hooks::settlement_input_hash_for_test(
        proposal, outcome, settled_by, kind, body_hash,
    )
}

/// The input hash of an inbound event: its attempt, its connector, channel and action (in
/// that order), the identity it addressed, its actor and its receive time.
#[must_use]
pub fn surface_inbound_input_hash(
    attempt: [u8; 16],
    tokens: [&str; 3],
    receiving_identity: EntityId,
    actor: EntityId,
    received_at: u64,
) -> [u8; 32] {
    crate::runtime_hooks::surface_inbound_input_hash_for_test(
        attempt,
        tokens,
        receiving_identity,
        actor,
        received_at,
    )
}

/// The params digest of `binding`, as a run's memo stores it.
///
/// # Errors
/// When the binding's selector does not encode.
pub fn selector_params_hash(binding_id: EntityId, binding: &PackHookBinding) -> Result<String> {
    crate::runtime_hooks::selector_params_hash_for_test(binding_id, binding)
}

/// The run key for `binding` on the fact at `position` whose input hash is `input_hash`.
///
/// # Errors
/// When the binding's selector or the run's envelope does not encode.
pub fn run_key(
    binding_id: EntityId,
    binding: &PackHookBinding,
    input_hash: [u8; 32],
    position: FactPosition,
) -> Result<[u8; 32]> {
    crate::runtime_hooks::run_key_for_test(binding_id, binding, input_hash, position)
}
