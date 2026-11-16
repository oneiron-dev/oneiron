//! Door for `tests/actor_binding_liveness.rs` (round-1 P1 of #7900): a delete
//! with a caller-run step in the gap between the guard phase's dropped read
//! snapshot and the plan's first write, so the test commits a binding change
//! there deterministically instead of racing threads.

use crate::{EntityId, Result, Vault};

/// [`Vault::delete_entity`] with `between` run after the guard phase's read
/// snapshot and before the plan's first write. No writer is held at the gap,
/// so `between` may commit (the test's signed `RebindActor`); the delete's
/// write transactions then run against the changed bindings.
///
/// # Errors
///
/// The delete's, including the last-bound-owner refusal when `between` left
/// the target holding the vault's last owner binding.
pub fn delete_entity_across(vault: &Vault, id: &EntityId, between: impl FnOnce()) -> Result<bool> {
    vault.delete_entity_across(id, between)
}
