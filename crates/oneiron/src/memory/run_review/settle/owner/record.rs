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
        // FIX 7500: the answer to the reviewed run. Its members are not
        // bound to this receipt, so no member's read context is kept.
        record.context = crate::store::GateDecisionContext::linked(
            crate::store::GateLoopLink::action(
                crate::store::GateLoopSource::Runner,
                Some(run.to_owned()),
                None,
                crate::store::GateLoopOrigin::Unresolved,
            ),
            None,
        );
        self.vault()
            .store
            .append_gate_decision_in_txn(txn, &record)?;
        anchor_reviewed_run_in_txn(self.vault(), txn, run, &record)?;
        Ok(record)
    }
}
