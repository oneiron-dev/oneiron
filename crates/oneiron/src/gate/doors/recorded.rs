//! Recorded claim decisions retained until transaction commit or selective denial rollback.

use crate::gate::{GateDecision, GateMetrics, GateReasonCode};
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

    /// The actor and delegation-chain ceiling codes this decision held on:
    /// a hold that changes only with the actor's policy or Grant, never with
    /// an approval (as an effect's approval leaves them, gate/effect/
    /// preflight.rs).
    pub(crate) fn ceiling_reason_codes(&self) -> Vec<&'static str> {
        self.decision
            .reason_codes()
            .iter()
            .filter(|code| {
                matches!(
                    code,
                    GateReasonCode::PendingActorCeiling
                        | GateReasonCode::PendingDelegationChainCeiling
                )
            })
            .map(|code| code.as_str())
            .collect()
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
