//! Recorded claim decisions retained until transaction commit or selective denial rollback.

use crate::gate::{GateDecision, GateMetrics};
use crate::store::{GateDecisionId, GateDecisionRecord};

pub(crate) struct RecordedClaimGateDecision {
    pub(super) record: GateDecisionRecord,
    pub(super) decision: GateDecision,
}

impl RecordedClaimGateDecision {
    pub(crate) fn decision_id(&self) -> GateDecisionId {
        self.record.decision_id
    }

    pub(crate) fn outcome(&self) -> &str {
        &self.record.outcome
    }

    pub(crate) fn record_metrics(&self, metrics: &GateMetrics) {
        metrics.record_decision(&self.decision);
    }

    pub(crate) fn into_record(self) -> GateDecisionRecord {
        self.record
    }

    /// Appends this decision again in `wtxn`, under its own id: the one
    /// denial a rolled-back savepoint judged, kept by the parent that
    /// refuses the write (OF-063, FIX 1223). It records no metric; the
    /// caller records it once the refusal commits.
    pub(crate) fn append_in_txn(
        &self,
        store: &crate::store::Store,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> crate::error::Result<()> {
        store.append_gate_decision_in_txn(wtxn, &self.record)
    }
}
