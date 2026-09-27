//! Verify tier-1 source provenance against the actual base ledgers, never a
//! caller-supplied reference's mere existence in the entity table.

use super::{
    ConsentDeniedDetector, DeterministicDetector, DiagnosticEvent, DiagnosticObservation,
    DiagnosticSourceKind, DiagnosticWorkingSet,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::{GateDecisionId, RetrievalRunId, Store};

fn ineligible() -> Error {
    Error::InvalidConfig("failure signal lacks a verified on-record source".into())
}

/// Both families resolve their own typed ledger and re-run the compiled
/// detector against the projection that exact base record yields. A nested
/// DIAGNOSTIC or a TURN is never a Gate decision or a published retrieval run.
/// Unknown detector/source pairs stay closed until they have a positive base
/// ledger resolver; no source-kind spelling is authority by itself.
pub(crate) fn verify(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    event: &DiagnosticEvent,
    model_step: Option<EntityId>,
) -> Result<()> {
    let mut projected = event.clone();
    if let Some(step) = model_step {
        if projected.replay.checkpoint_ref.as_deref() != Some(step.to_hex().as_str()) {
            return Err(ineligible());
        }
        let Some(index) = projected.evidence_refs.iter().position(|id| *id == step) else {
            return Err(ineligible());
        };
        projected.evidence_refs.remove(index);
        projected.replay.checkpoint_ref = None;
    }
    let [source] = projected.evidence_refs.as_slice() else {
        return Err(ineligible());
    };
    if store.off_record_sessions.contains_entity(source)? {
        return Err(ineligible());
    }
    let observation = match (event.detector_id.as_str(), event.source) {
        ("consent.denied.v1", DiagnosticSourceKind::Receipt) => {
            let id = GateDecisionId::from_bytes(*source.as_bytes());
            let decision = store
                .gate_decision_in_txn(txn, id)?
                .ok_or_else(ineligible)?;
            if decision.version != 0
                || decision.redacted_at.is_some()
                || decision.actor_class != "human"
                || decision.claim_id.is_some()
                || !decision.receipt_reasons.is_empty()
                || !decision.system_notices.is_empty()
            {
                return Err(ineligible());
            }
            crate::self_heal::DiagnosticObservation::from_consent_receipt(
                &crate::receipt::gate_decision_receipt(&decision),
            )?
            .ok_or_else(ineligible)?
        }
        ("retrieval.miss.v1", DiagnosticSourceKind::RetrievalTelemetry) => {
            let id = RetrievalRunId::from_bytes(*source.as_bytes());
            let run = store
                .retrieval_run_in_txn(txn, id)?
                .ok_or_else(ineligible)?;
            DiagnosticObservation::from_retrieval_run(&run).ok_or_else(ineligible)?
        }
        _ => return Err(ineligible()),
    };
    if observation.source_ref != *source
        || observation.payload_digest != event.replay.content_hash
        || observation.observed_at != event.valid_from
        || event.actor_ref.is_some()
    {
        return Err(ineligible());
    }
    let scope_ref = event.replay.run_ref.as_deref().ok_or_else(ineligible)?;
    let observations = [observation];
    let input = DiagnosticWorkingSet {
        scope_ref,
        observations: &observations,
    };
    let expected = match event.detector_id.as_str() {
        "consent.denied.v1" => ConsentDeniedDetector.detect(&input),
        "retrieval.miss.v1" => super::tripwires::RetrievalMissDetector.detect(&input),
        _ => return Err(ineligible()),
    };
    if expected.as_slice() != std::slice::from_ref(&projected) {
        return Err(ineligible());
    }
    Ok(())
}
