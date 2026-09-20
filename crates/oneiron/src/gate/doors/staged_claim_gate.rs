//! Materialize the preflight decision from the same write transaction, exactly once.
use super::*;
use crate::batch::StagedClaimGateOutcome;
use crate::gate::GateMetrics;

#[expect(
    clippy::too_many_arguments,
    reason = "the staged seam mirrors the landed claim door's explicit axis tuple"
)]
pub(crate) fn apply_staged_claim_gate_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    envelope: Option<&WriteEnvelope>,
    policy: &PolicyManifestResolution,
    staged: &StagedClaimGateOutcome,
    mode: GateWriteMode,
) -> Result<()> {
    let decision = match staged.outcome {
        GateOutcome::Allow => GateDecision::allow(),
        GateOutcome::Pending => GateDecision::pending(staged.reason_codes.clone()),
        // A preflight denial returns to `BatchBuilder::commit`, which commits
        // exactly that denial receipt and aborts the batch, so no denied claim
        // can reach materialization. Refuse rather than assume.
        GateOutcome::Deny => {
            return Err(Error::InvariantViolation(
                "staged gate denial reached materialization",
            ));
        }
    };
    let effective_approval = body.approval;
    // The preflight computed this binding from the same body and the same
    // resolved manifest; materialization cannot recompute or substitute it.
    let binding = GateConsentBinding {
        diff_handle: staged.diff_handle.clone(),
        read_frontier_hash: staged.read_frontier_hash,
    };

    if mode.persist_pending_consent
        && staged.outcome == GateOutcome::Pending
        && effective_approval == ClaimApprovalStatus::Proposed
    {
        let pending = PendingGateConsentRecord {
            version: crate::store::PENDING_GATE_CONSENT_VERSION,
            claim_id: *id.as_bytes(),
            decision_id: staged.decision_id,
            created_at: staged.created_at,
            diff_handle: staged.diff_handle.clone(),
            read_frontier_hash: staged.read_frontier_hash,
            reason_codes: staged
                .reason_codes
                .iter()
                .map(|code| code.as_str().to_owned())
                .collect(),
            dreamer_run_id: pending_consent_dreamer_run_id(envelope, body),
        };
        store.put_pending_gate_consent_in_txn(wtxn, &pending)?;
    }

    enforce_claim_gate_decision_with_consent(
        store,
        wtxn,
        id,
        &decision,
        effective_approval,
        &binding,
        mode,
    )?;

    let actor_ref = write_envelope_actor_ref(envelope);
    check_claim_source_trust(
        body,
        actor_ref.as_deref(),
        policy,
        envelope.map(WriteEnvelope::lineage),
    )
}

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

    pub(crate) fn record(&self) -> &GateDecisionRecord {
        &self.record
    }

    pub(crate) fn decision(&self) -> &GateDecision {
        &self.decision
    }

    pub(crate) fn record_metrics(&self, metrics: &GateMetrics) {
        metrics.record_decision(&self.decision);
    }

    pub(crate) fn into_record(self) -> GateDecisionRecord {
        self.record
    }
}
