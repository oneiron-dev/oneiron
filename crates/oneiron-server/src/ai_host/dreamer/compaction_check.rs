//! The host's loan to the Dreamer's check of a self-written compaction (FIX
//! 4465 B): the weaver's narrative route, on the pass's own line, and the
//! rubric this host ships as prompt data. The check reads the agent's
//! summary against its run's retained span and records a verdict; it never
//! writes a word of the agent's summary, which stays the agent's own.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use oneiron::dreamer_consolidation::{DREAMER_NARRATIVE_ROLE, RoleBackend};
use oneiron::dreamer_runner::maintenance::compaction_check::{
    CompactionCheckDecisions, CompactionCheckModel, run_compaction_check,
};
use oneiron::llm::HostInferenceContext;
use oneiron::llm::decision::{DecisionBand, DecisionDial, DecisionRung};
use oneiron::{DreamerAdmittedAttempt, DreamerAttemptExecution, WakeAttemptContext};

use super::extraction_egress;
use crate::decision_host::DecisionHost;

/// The rubric the judge reads the summary against its span by. Prompt data
/// beside this host, never engine prose; the policy call names it.
const COMPACTION_CHECK_RUBRIC: &str = include_str!("compaction_check_rubric.md");

/// The typed support question's wording (FIX 8713): prompt data beside this
/// host, never engine prose.
const COMPACTION_SUPPORT_WORDING: &str = "Does the retained span support everything the \
summary says? Answer supported when every assertion in the summary is supported by the span, \
mismatch when any assertion is unsupported by the span or contradicts it.";

/// What one pass lends its compaction checks: the judge is the weaver, on
/// its route and the pass's line, as the weaver's own work is metered.
#[derive(Clone, Copy)]
pub(super) struct CheckLend<'p> {
    pub(super) weaver: &'p RoleBackend,
    pub(super) guard: &'p oneiron::BudgetGuard,
    pub(super) egress: bool,
}

impl CheckLend<'_> {
    /// Runs one check. With the server's decision host staffed, the shared
    /// ladder decides support, up to its Big rung so no person is asked
    /// (FIX 8713); before it is, the judge's own verdict stands, recorded as
    /// untyped.
    pub(super) async fn check(
        self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
        decisions: &OnceLock<DecisionHost>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let egress = self
            .egress
            .then(|| extraction_egress(BTreeSet::from([self.weaver.model.clone()])));
        let decisions = decisions.get().map(|host| CompactionCheckDecisions {
            ladder: host.ladder().ladder(),
            dial: DecisionDial {
                first: DecisionRung::Local,
                ceiling: DecisionRung::Big,
                band: DecisionBand::default(),
            },
            bands: host.bands(),
            wording: COMPACTION_SUPPORT_WORDING.to_owned(),
        });
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
                decisions,
            },
        )
        .await
    }
}
