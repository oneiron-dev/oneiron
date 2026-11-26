//! Door for `tests/task_types_promote.rs` (lead COORD-E2E-TREE-PIN = A,
//! 24 Nov 2026 22:45): the Coach tree gate's last step, which an admitting
//! ruling reaches after its held-out replay, on one revision and the head it
//! revises, without the scorer.

use crate::dreamer_runner::maintenance::type_tree_upkeep::TreeGateOutcome;
use crate::error::Result;
use crate::skill_optimize::SkillEditDisposition;
use crate::{EntityId, Vault};

/// What the gate's last step does with `proposal` over `predecessor` under
/// the ruling `disposition`: [`TreeGateOutcome::Ruled`] when the owner pinned
/// `predecessor` (nothing is put in force), else optimizer admission and
/// supersession as the gate runs them.
///
/// # Errors
///
/// As the gate's write: storage errors and the supersession door's refusals.
pub fn coach_tree_gate_last_step(
    vault: &Vault,
    proposal: &EntityId,
    predecessor: &EntityId,
    disposition: SkillEditDisposition,
    now: u64,
) -> Result<TreeGateOutcome> {
    crate::dreamer_runner::maintenance::put_revision_in_force_for_test(
        vault,
        proposal,
        predecessor,
        disposition,
        now,
    )
}
