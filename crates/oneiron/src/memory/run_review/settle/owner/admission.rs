//! Who answers a run review, and against which review: the owner, once, on the review shown.

use super::*;

impl Memory<'_> {
    /// The owner's write actor and the review as it stands now; refused when
    /// the run already settled or its review changed since it was shown.
    pub(super) fn admit_run_settlement_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
        input: &RunSettleRequest,
        run: &String,
    ) -> MemoryResult<(WriteActor, RunReview)> {
        let actor = require_owner(self, txn, owner)?;
        if SETTLEMENTS.get(&self.vault().store, txn, run)?.is_some() {
            return Err(MemoryError::bad_request("this run review already settled"));
        }
        let review = snapshot::review_in_txn(self, txn, &input.review)?;
        if review.review_id != input.review_id {
            return Err(MemoryError::new(
                crate::memory::MEMORY_CODE_INVALID_STATE,
                "the review changed; review the complete set again",
                &[],
            ));
        }
        Ok((actor, review))
    }
}
