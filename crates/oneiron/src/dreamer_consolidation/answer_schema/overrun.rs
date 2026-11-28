//! The answer-schema check's over-budget latch (HOUSE-SCHEMA-CHECK): one row per night whose
//! extraction ran past its budget, so the check skips the night with its reason instead of
//! scoring a cut-short sample.
//!
//! An extraction child of a night latches its night when it settles with a budget stop: a
//! [`Budget`](crate::dreamer_runner::DreamerParkWait::Budget) or
//! [`PassBudget`](crate::dreamer_runner::DreamerParkWait::PassBudget) wait on its parked row, a
//! hard-cut park, or a failed try with a budget refusal. The settle path writes the latch
//! beside the settlement; the first stop wins.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_runner::{DreamerAttemptStatus, DreamerConsolidationScope};
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// The over-budget latch, keyed by night.
const OVERRUN: SideTable<AttemptId, AnswerSchemaOverrun, Named> =
    SideTable::new(&side_table::DREAMER_ANSWER_SCHEMA_OVERRUN);

/// How deep a parent walk climbs looking for the night. Nights hang every child directly off
/// the recipe receipt; the bound only stops a corrupt cycle.
const PARENT_WALK_LIMIT: usize = 32;

/// The budget stop that latched a night over budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AnswerSchemaOverrun {
    /// The pass's guard refused the step's reservation with a budget wait.
    Budget,
    /// The pass's guard refused the step's reservation with a pass-budget wait.
    PassBudget,
    /// The try ended failed with a budget refusal.
    BudgetRefusal,
    /// The wake pass hit its deadline and the attempt kept its progress.
    DeadlineHardCut,
}

/// Whether `settled` is a consolidation partition attempt, the attempts that run TURN
/// extraction: the scope's own kind and attempt type, as the consolidation enqueue names
/// them (as `branch_scope` reads a partition attempt).
fn is_extraction_attempt(settled: &DreamerAttemptStatus) -> bool {
    [
        DreamerConsolidationScope::Micro,
        DreamerConsolidationScope::Meso,
        DreamerConsolidationScope::Macro,
    ]
    .into_iter()
    .any(|scope| {
        settled.attempt.kind == scope.attempt_kind()
            && settled.payload.attempt_type == scope.as_str()
    })
}

/// The night `settled` descends from, if any: the ancestor that is a nightly recipe receipt.
/// Walks `parent_attempt` up; a row or payload that does not read ends the walk with no night.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn night_of_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    settled: AttemptId,
) -> Result<Option<AttemptId>> {
    let queue = AttemptQueue::new(vault);
    let mut at = settled;
    for _ in 0..PARENT_WALK_LIMIT {
        let Some(record) = queue.get_in_txn(txn, at)? else {
            return Ok(None);
        };
        let Ok(payload) = crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload)
        else {
            return Ok(None);
        };
        if record.kind == crate::dreamer_runner::DREAMER_RECIPE_WAKE_ATTEMPT_KIND
            && payload.attempt_type == crate::dreamer_runner::DREAMER_RECIPE_WAKE_ATTEMPT_KIND
        {
            let nightly = payload
                .input
                .as_str()
                .and_then(|input| {
                    serde_json::from_str::<crate::dreamer_wake::WakePolicyTrigger>(input).ok()
                })
                .is_some_and(|trigger| trigger.recipe == crate::dreamer_wake::WakeRecipe::Nightly);
            if nightly {
                return Ok(Some(at));
            }
            return Ok(None);
        }
        let Some(parent) = payload.parent_attempt else {
            return Ok(None);
        };
        at = parent;
    }
    Ok(None)
}

/// Latches `night` over budget with `stop`, unless latched already: the first stop wins.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn latch_overrun_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    night: AttemptId,
    stop: AnswerSchemaOverrun,
) -> Result<()> {
    if OVERRUN.contains(&vault.store, &*txn, &night)? {
        return Ok(());
    }
    OVERRUN.put(&vault.store, txn, &night, &stop)
}

/// Whether `night` latched over budget.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn overrun_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    night: AttemptId,
) -> Result<Option<AnswerSchemaOverrun>> {
    OVERRUN.get(&vault.store, txn, &night)
}

/// Latches the night `settled` descends from when `settled` is an extraction child of a night:
/// the settle path calls this beside a budget-stop settlement with the stop it saw. A settled
/// attempt that is no extraction attempt, or descends from no night, latches nothing.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn latch_for_settled_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    settled: &DreamerAttemptStatus,
    stop: AnswerSchemaOverrun,
) -> Result<()> {
    if !is_extraction_attempt(settled) {
        return Ok(());
    }
    let Some(night) = night_of_in_txn(vault, &*txn, settled.attempt.id)? else {
        return Ok(());
    };
    latch_overrun_in_txn(vault, txn, night, stop)
}
