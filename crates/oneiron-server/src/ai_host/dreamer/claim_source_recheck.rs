//! The host's loan to the Dreamer's re-check of the claims drawn from a
//! message deleted at the provider and kept (FIX 15414): the weaver's
//! narrative route, on the pass's own line, as a compaction's check borrows
//! it, and the rubric this host ships as prompt data. The re-check judges
//! each claim against its current supports and changes belief only through
//! the demotion ladder or the owner's review.

use std::collections::BTreeSet;

use oneiron::dreamer_consolidation::DREAMER_NARRATIVE_ROLE;
use oneiron::dreamer_runner::maintenance::claim_source_recheck::{
    ClaimSourceRecheckModel, run_claim_source_recheck,
};
use oneiron::llm::HostInferenceContext;
use oneiron::{DreamerAdmittedAttempt, DreamerAttemptExecution, WakeAttemptContext};

use super::compaction_check::CheckLend;
use super::extraction_egress;

/// The rubric the judge reads a claim against its supports by. Prompt data
/// beside this host, never engine prose.
const CLAIM_SOURCE_RECHECK_RUBRIC: &str = include_str!("claim_source_recheck_rubric.md");

impl CheckLend<'_> {
    /// Runs one re-check on the weaver's route.
    pub(super) async fn recheck_claim_sources(
        self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let egress = self
            .egress
            .then(|| extraction_egress(BTreeSet::from([self.weaver.model.clone()])));
        run_claim_source_recheck(
            attempt,
            ctx,
            ClaimSourceRecheckModel {
                backend: self.weaver.backend.as_ref(),
                guard: self.guard,
                model: self.weaver.model.clone(),
                inference: HostInferenceContext {
                    binding: self.weaver.binding.clone(),
                    extraction_egress: egress.as_deref(),
                },
                role: DREAMER_NARRATIVE_ROLE,
                rubric: CLAIM_SOURCE_RECHECK_RUBRIC,
            },
        )
        .await
    }
}
