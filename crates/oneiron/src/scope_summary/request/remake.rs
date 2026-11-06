//! Fresh source-only rebuilds after an off-record save cuts deleted content.

use super::{
    ScopeSummaryQueued, ScopeSummaryRequest, derivation, enqueue_with_lineage_in_txn, plan_in_txn,
    requester_lane,
};
use crate::{Result, Vault};

impl Vault {
    /// Rebuilds from the admitted sources without an earlier summary as editor input.
    /// Queues in the caller's transaction; the caller notifies after commit.
    pub(crate) fn request_scope_summary_remake_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        request: &ScopeSummaryRequest,
        now: u64,
    ) -> Result<ScopeSummaryQueued> {
        let purpose = requester_lane::default_purpose(&request.target);
        let input = derivation::declaration(request, purpose, None);
        plan_in_txn(self, txn, &input)?;
        let queued = enqueue_with_lineage_in_txn(self, txn, input, None, None, now)?;
        // FIX 3103: the asking run, as its request is queued.
        crate::skill_attribution::note_summary_request_in_txn(&self.store, txn, queued.attempt);
        Ok(queued)
    }
}
