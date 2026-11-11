//! The host's loan to the Dreamer's re-check of the claims drawn from a
//! message deleted at the provider and kept (FIX 15414): the weaver's
//! narrative route, on the pass's own line, as a compaction's check borrows
//! it, the rubric this host ships as prompt data, and the server's decision
//! ladder, which asks each claim's question (DECIDE-BYPASS-1). The re-check
//! judges each claim against its current supports and changes belief only
//! through the demotion ladder or the owner's review.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use oneiron::dreamer_consolidation::DREAMER_NARRATIVE_ROLE;
use oneiron::dreamer_runner::maintenance::claim_source_recheck::{
    ClaimSourceRecheckDecisions, ClaimSourceRecheckModel, run_claim_source_recheck, unlent,
};
use oneiron::llm::HostInferenceContext;
use oneiron::{DreamerAdmittedAttempt, DreamerAttemptExecution, WakeAttemptContext};

use super::compaction_check::CheckLend;
use super::extraction_egress;
use crate::decision_host::DecisionHost;

/// The rubric the judge reads a claim against its supports by. Prompt data
/// beside this host, never engine prose.
const CLAIM_SOURCE_RECHECK_RUBRIC: &str = include_str!("claim_source_recheck_rubric.md");

/// The typed support question's wording: prompt data beside this host,
/// never engine prose.
const CLAIM_SOURCE_SUPPORT_WORDING: &str = "Do the claim's supports, as they stand now, still \
carry the claim? Answer supported when they carry it as it stands, weakened when they still \
carry it but less firmly than its confidence says, unsupported when nothing left carries it.";

impl CheckLend<'_> {
    /// Runs one re-check on the weaver's route, each claim's verdict asked
    /// on the server's decision ladder. Before the decision host is
    /// staffed, the re-check waits its retry delay, never judged outside
    /// the ladder.
    pub(super) async fn recheck_claim_sources(
        self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
        decisions: &OnceLock<DecisionHost>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let Some(host) = decisions.get() else {
            return Ok(unlent());
        };
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
                decisions: ClaimSourceRecheckDecisions {
                    ladder: host.ladder().ladder(),
                    bands: host.bands(),
                    wording: CLAIM_SOURCE_SUPPORT_WORDING.to_owned(),
                },
            },
        )
        .await
    }
}
