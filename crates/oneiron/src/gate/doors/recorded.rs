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
}
