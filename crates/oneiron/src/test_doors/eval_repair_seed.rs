//! The sealed eval case a confirmed repair seed recorded (census L1-20,
//! `tests/eval_repair_seed_gate.rs`): a sealed case is served only through
//! its cohort, so its ledger row has no other read.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::skill_optimize::EvalCase;

/// The ledger row of eval case `id`, if one is stored.
///
/// # Errors
///
/// An unreadable row, or storage errors.
pub fn eval_case(vault: &Vault, id: &EntityId) -> Result<Option<EvalCase>> {
    vault.eval_case_for_test_doors(id)
}
