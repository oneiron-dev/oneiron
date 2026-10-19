//! The host's loan to the Dreamer's check of a self-written compaction (FIX
//! 4465 B): the weaver's narrative route, on the pass's own line, and the
//! rubric this host ships as prompt data. The check reads the agent's
//! summary against its run's retained span and records a verdict; it never
//! writes a word of the agent's summary, which stays the agent's own.

use std::collections::BTreeSet;

use oneiron::dreamer_consolidation::{DREAMER_NARRATIVE_ROLE, RoleBackend};
use oneiron::dreamer_runner::maintenance::compaction_check::{
    CompactionCheckModel, run_compaction_check,
};
use oneiron::llm::HostInferenceContext;
use oneiron::{DreamerAdmittedAttempt, DreamerAttemptExecution, WakeAttemptContext};

use super::extraction_egress;

/// The rubric the judge reads the summary against its span by. Prompt data
/// beside this host, never engine prose; the policy call names it.
const COMPACTION_CHECK_RUBRIC: &str = include_str!("compaction_check_rubric.md");

/// What one pass lends its compaction checks: the judge is the weaver, on
/// its route and the pass's line, as the weaver's own work is metered.
#[derive(Clone, Copy)]
pub(super) struct CheckLend<'p> {
    pub(super) weaver: &'p RoleBackend,
    pub(super) guard: &'p oneiron::BudgetGuard,
    pub(super) egress: bool,
}

impl CheckLend<'_> {
    pub(super) async fn check(
        self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let egress = self
            .egress
            .then(|| extraction_egress(BTreeSet::from([self.weaver.model.clone()])));
        run_compaction_check(
            attempt,
            ctx,
            CompactionCheckModel {
                backend: self.weaver.backend.as_ref(),
                guard: self.guard,
                model: self.weaver.model.clone(),
                inference: HostInferenceContext {
                    binding: self.weaver.binding.clone(),
                    extraction_egress: egress.as_deref(),
                },
                role: DREAMER_NARRATIVE_ROLE,
                rubric: COMPACTION_CHECK_RUBRIC,
            },
        )
        .await
    }
}
