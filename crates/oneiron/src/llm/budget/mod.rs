mod guard;
mod ladders;
mod ledger;
mod policy;
mod state;
mod templates;
mod types;

mod settlement;

pub use self::guard::BudgetGuard;
pub(crate) use self::policy::{BudgetPolicyRow, BudgetPolicySelector, BudgetPolicyTable};
pub use self::templates::{
    BUDGET_LAND_PROMPT_TEMPLATE, BUDGET_LAND_PROMPT_TEMPLATE_ID,
    BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE, BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE_ID,
    BUDGET_PLAN_PROMPT_TEMPLATE, BUDGET_PLAN_PROMPT_TEMPLATE_ID, BUDGET_PROMPT_TEMPLATES,
    BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE, BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE_ID,
    BudgetPromptTemplate,
};
pub use self::types::{
    BudgetAdmission, BudgetExhaustionPolicy, BudgetLadderEvent, BudgetRead, BudgetSettlement,
    BudgetSignalDeliveryChannel, BudgetSteeringSignal, BudgetThreshold,
    DEFAULT_BUDGET_RESERVE_UNITS,
};

// settlement.rs resolves its `use super::{...}` through these bindings.
use self::ledger::{LeaseState, apply_usage_for_lease, release_reservations_for_lease};
use super::{BudgetDenied, BudgetLease};

#[cfg(test)]
mod tests;

// The flat budget.rs module used to provide these names to the sibling test
// module through `use super::*`: every budget-internal item the tests name
// bare, plus the module's own llm/crate import header. After the directory
// split the seam re-imports both so `tests.rs` resolves exactly as it did
// before.
#[cfg(test)]
use self::ladders::*;
#[cfg(test)]
use super::{LlmRequest, LlmUsage, ModelLocality};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::write_envelope::WriteActor;
