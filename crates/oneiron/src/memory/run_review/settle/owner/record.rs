//! The owner's answer as a gate decision, appended and anchored to the reviewed run.

use super::*;
use crate::task_verb::settlement_anchor::anchor_reviewed_run_in_txn;

impl Memory<'_> {
    /// Appends the owner's decision on the reviewed run and anchors the run
    /// to it.
    pub(super) fn record_settlement_decision_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: WriteActor,
        review: &RunReview,
        run: &str,
        approve: bool,
        now: u64,
        members: &[EntityId],
    ) -> MemoryResult<crate::store::GateDecisionRecord> {
        let mut record = crate::memory::authorship::decision(
            actor,
            "proposal_outcome",
            if approve { "approved" } else { "rejected" },
            if approve {
                "gate.run.settle.approved"
            } else {
                "gate.run.settle.rejected"
            },
            None,
            review.review_id.as_bytes().to_vec(),
            now,
        );
        // FIX 11002: the outcome answers every Claim/Edge member with its
        // newest kept read context; the member refs couple their erases here.
        crate::gate::append_reviewed_run_decision_in_txn(
            self.vault(),
            txn,
            &mut record,
            run,
            members,
        )?;
        anchor_reviewed_run_in_txn(self.vault(), txn, run, &record)?;
        Ok(record)
    }
}
