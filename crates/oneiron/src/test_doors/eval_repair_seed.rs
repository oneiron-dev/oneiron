//! The sealed eval case a confirmed repair seed recorded (census L1-20,
//! `tests/eval_repair_seed_gate.rs`): a sealed case is served only through
//! its cohort, so its ledger row has no other read. And the seed doors'
//! writes alone, for a task compiled before them, as a compile that an erase
//! overtakes reaches them.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::skill_optimize::{
    EvalCase, EvalRepairLegAnswer, EvalRepairSeed, EvalRepairSeedLegs, EvalRepairSeedRequest,
    EvalRepairTask,
};

/// The ledger row of eval case `id`, if one is stored.
///
/// # Errors
///
/// An unreadable row, or storage errors.
pub fn eval_case(vault: &Vault, id: &EntityId) -> Result<Option<EvalCase>> {
    vault.eval_case_for_test_doors(id)
}

/// The write of `Memory::propose_eval_repair_seed` for `task` compiled
/// earlier, as a proposal that compiled before an erase reaches it.
///
/// # Errors
///
/// As the proposal's write: an erased capture, a held family, or storage
/// errors.
pub fn commit_proposal(
    vault: &Vault,
    task: &EvalRepairTask,
    request: &EvalRepairSeedRequest,
    at: u64,
) -> Result<EvalRepairSeed> {
    vault.commit_eval_repair_proposal_for_test_doors(task, request, at)
}

/// The write of `Memory::settle_eval_repair_seed` for `stored` read and
/// `task` compiled earlier, grading the `(old, candidate)` answers, as a
/// settle that read before an erase and a new proposal reaches it.
///
/// # Errors
///
/// As the gate's write: no seed, a seed that changed since `stored`, a
/// capture deleted since, or storage errors.
pub fn commit_settlement(
    vault: &Vault,
    stored: &EvalRepairSeed,
    task: &EvalRepairTask,
    answers: (&EvalRepairLegAnswer, &EvalRepairLegAnswer),
    legs: &EvalRepairSeedLegs,
    at: u64,
) -> Result<EvalRepairSeed> {
    vault.commit_eval_repair_settlement_for_test_doors(stored, task, answers, legs, at)
}
