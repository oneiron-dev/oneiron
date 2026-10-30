//! After an approval commits: the curator rungs it landed apply now.

use super::*;

impl Memory<'_> {
    /// Applies the curator rung of every claim this approval landed.
    pub(super) fn apply_landed_curators(
        &self,
        input: &RunSettleRequest,
        settlement: &RunSettlement,
        now: u64,
    ) {
        crate::dreamer_runner::maintenance::apply_curator_after_consent(
            self.vault(),
            input
                .review
                .changes
                .iter()
                .zip(&settlement.changes)
                .filter(|(_, outcome)| outcome.verdict == RunChangeVerdict::Landed)
                .filter_map(|(member, _)| match member {
                    RunReviewChange::Claim { claim_ref } => EntityId::from_hex(claim_ref).ok(),
                    _ => None,
                }),
            now,
        );
    }
}
