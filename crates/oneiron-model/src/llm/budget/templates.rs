//! Budget ladder prompt templates and their registry.

use serde::Serialize;

pub const BUDGET_PLAN_PROMPT_TEMPLATE_ID: &str = "budget.plan.80";

pub const BUDGET_LAND_PROMPT_TEMPLATE_ID: &str = "budget.land.95";

pub const BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE_ID: &str = "budget.owner_digest";

pub const BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE_ID: &str = "budget.resume_preamble";

pub const BUDGET_PLAN_PROMPT_TEMPLATE: &str = "\
Budget is at or above 80%. Re-rank the remaining work by value, keep quality \
honest, and make a compact PLAN for what still deserves compute.";

pub const BUDGET_LAND_PROMPT_TEMPLATE: &str = "\
Budget is at or above 95%. Enter LAND: start no new work, write durable \
checkpoints, and list unfinished work as cold-resumable TODOs. An \
incomplete-but-honest checkpoint is a successful landing.";

pub const BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE: &str = "\
Explain the budget stop clearly, summarize what landed, name unfinished work, \
and offer explicit choices: suspend, continue locally, or approve overdraft \
where policy allows.";

pub const BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE: &str = "\
Resume from the last budget landing checkpoint. Treat already-completed steps \
as done, preserve the user's quality bar, and spend only against a fresh lease.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct BudgetPromptTemplate {
    pub id: &'static str,
    pub text: &'static str,
}

pub const BUDGET_PROMPT_TEMPLATES: &[BudgetPromptTemplate] = &[
    BudgetPromptTemplate {
        id: BUDGET_PLAN_PROMPT_TEMPLATE_ID,
        text: BUDGET_PLAN_PROMPT_TEMPLATE,
    },
    BudgetPromptTemplate {
        id: BUDGET_LAND_PROMPT_TEMPLATE_ID,
        text: BUDGET_LAND_PROMPT_TEMPLATE,
    },
    BudgetPromptTemplate {
        id: BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE_ID,
        text: BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE,
    },
    BudgetPromptTemplate {
        id: BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE_ID,
        text: BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE,
    },
];
