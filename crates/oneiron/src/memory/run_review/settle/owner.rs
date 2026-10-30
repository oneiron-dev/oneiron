//! The owner's answer to a run review: approve or reject, in one atomic transaction.
//! `Memory::settle_run_as_owner` is its call surface.
//! `memory::run_review` defines the review, settlement and decision records it writes.

use super::*;

mod admission;
mod curators;
mod members;
mod record;
mod settlement;

impl Memory<'_> {
    /// Both answers use the existing per-kind admission and one atomic
    /// transaction. No stale review can settle a newly changed member.
    pub fn settle_run_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &RunSettleRequest,
    ) -> MemoryResult<RunSettlement> {
        let run = run_key(&input.review.run_id)?;
        let approve = input.decision == RunSettleDecision::Approve;
        let now = self.vault().store.clock.now_recorded_at();
        let (settlement, metrics, vad) = self.with_verified_actor_write_txn(|txn| {
            self.settle_reviewed_run_in_txn(txn, owner, input, &run, approve, now)
        })?;
        // A curator rung this approval landed applies now, not at the next
        // nightly pass (FIX 470); one that cannot waits for that pass.
        if approve {
            self.apply_landed_curators(input, &settlement, now);
        }
        for decision in metrics {
            decision.record_metrics(&self.vault().store.diagnostics.gate);
        }
        for claim in vad {
            self.vault().consolidate_claim_vad_now(&claim, now)?;
        }
        self.produced_from(
            input
                .review
                .changes
                .iter()
                .map(RunReviewChange::rows)
                .collect::<MemoryResult<Vec<_>>>()?
                .into_iter()
                .flatten(),
        );
        Ok(settlement)
    }
}