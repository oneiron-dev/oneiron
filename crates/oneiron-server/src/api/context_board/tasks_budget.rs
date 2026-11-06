//! Post-hook TASKS-row allocation metadata, before whole-frame shedding.

use serde::Serialize;
use utoipa::ToSchema;

/// Concrete TASK-row projection budget for this explicit render, when the
/// caller asked for one. Covers concrete rows only, including their `fits:`
/// rows and the overflow footer; project/fanout lead rows ride outside it.
///
/// `projected_tok` is the pre-frame projection cost after hook pins and tags,
/// before the whole-frame shed and row-byte fence, so it is NOT the final
/// delivered board cost. `exceeds_budget` is simply whether that projection
/// exceeds the request; hook pins and the footer may exceed and are reported,
/// never withheld. `Some(0)` is a literal zero; `None` keeps 100-row behavior.
/// No stored setting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct TasksRowBudget {
    /// The requested concrete-row allotment.
    budget_tok: usize,
    /// Pre-frame projection cost after pins/tags, before frame shed/fence.
    projected_tok: usize,
    /// True when the projection exceeds the request.
    exceeds_budget: bool,
}

impl TasksRowBudget {
    pub(super) fn of(tasks: &oneiron::context_board::TasksSection, budget_tok: usize) -> Self {
        let projected_tok = tasks.projected_tokens();
        Self {
            budget_tok,
            projected_tok,
            exceeds_budget: projected_tok > budget_tok,
        }
    }
}
