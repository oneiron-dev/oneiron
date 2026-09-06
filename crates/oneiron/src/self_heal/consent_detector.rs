//! T1 projection of explicit consent refusals from the existing receipt family.

use super::{
    DeterministicDetector, DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass,
    DiagnosticObservation, DiagnosticReplayCoordinate, DiagnosticSourceKind, DiagnosticWorkingSet,
    MAX_EVENTS_PER_RUN, run_deterministic_detectors, validate_working_set,
};
use crate::Vault;
use crate::consent::{CONSENT_CONTENT_KIND, CONSENT_REASON_DENIED};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use rmpv::Value;

/// Records an explicit consent refusal, not a heuristic about whether a
/// refusal was justified. The system is the reporting actor; the owner and
/// refused effect remain in the cited receipt. No repair is proposed.
pub struct ConsentDeniedDetector;

impl DeterministicDetector for ConsentDeniedDetector {
    fn detector_id(&self) -> &'static str {
        "consent.denied.v1"
    }

    fn detect(&self, input: &DiagnosticWorkingSet<'_>) -> Vec<DiagnosticEvent> {
        input
            .observations
            .iter()
            .filter(|observation| observation.kind == CONSENT_REASON_DENIED)
            .map(|observation| DiagnosticEvent {
                event_class: DiagnosticEventClass::ConsentDenied,
                actor_class: "system".to_owned(),
                actor_ref: None,
                source: DiagnosticSourceKind::Receipt,
                criticality: DiagnosticCriticality::Normal,
                // Authorization indicator for the requested effect: required
                // (1), denied (0), delta -1. This is not a grant count and does
                // not assert that the owner's refusal was a malfunction.
                expected: Value::from(1_u64),
                actual: Value::from(0_u64),
                delta: Value::from(-1_i64),
                replay: DiagnosticReplayCoordinate {
                    content_hash: observation.payload_digest,
                    run_ref: Some(input.scope_ref.to_owned()),
                    checkpoint_ref: None,
                },
                evidence_refs: vec![observation.source_ref],
                untrusted_detail: None,
                valid_from: observation.observed_at,
                valid_to: None,
            })
            .collect()
    }
}

impl DiagnosticObservation {
    /// Projects a scoped receipt into a bounded fact. Only the exact consent
    /// content kind, denied outcome and engine reason code denote a refusal.
    /// Other Gate outcomes and other receipt families produce no finding.
    /// The digest addresses the named MessagePack encoding of the receipt
    /// projection (its fields are ordered), without retaining a second log.
    pub fn from_consent_receipt(receipt: &ReceiptRecord) -> Result<Option<Self>> {
        if receipt.receipt_kind != ReceiptKind::Gate
            || receipt.outcome != "denied"
            || receipt.fields.get("content_kind").map(String::as_str) != Some(CONSENT_CONTENT_KIND)
            || !receipt
                .policy_trace
                .iter()
                .any(|reason| reason == CONSENT_REASON_DENIED)
        {
            return Ok(None);
        }
        let source_ref = receipt
            .receipt_id
            .strip_prefix("gate:")
            .and_then(|id| EntityId::from_hex(id).ok())
            .ok_or(Error::InvariantViolation(
                "consent receipt has no decision ref",
            ))?;
        let bytes = rmp_serde::to_vec_named(receipt)
            .map_err(|_| Error::InvariantViolation("consent receipt encode failed"))?;
        Ok(Some(Self {
            source_ref,
            kind: CONSENT_REASON_DENIED,
            payload_digest: *blake3::hash(&bytes).as_bytes(),
            observed_at: receipt.occurred_at,
        }))
    }
}

impl Vault {
    /// Reads only the caller-selected receipt scope and records explicit
    /// consent refusals through the diagnostic maintenance door. The query's
    /// kinds, actor, outcome, job and time bounds are not widened. Selection
    /// orders the facts before the pure detector sees them.
    pub fn run_consent_denied_detector(
        &self,
        scope_ref: &str,
        query: ReceiptQuery,
    ) -> Result<Vec<EntityId>> {
        validate_working_set(&DiagnosticWorkingSet {
            scope_ref,
            observations: &[],
        })?;
        if query.limit == 0 || query.limit > MAX_EVENTS_PER_RUN {
            return Err(Error::InvariantViolation("diagnostic receipt query limit"));
        }
        let mut observations = Vec::new();
        for receipt in self.receipts(query)? {
            if let Some(observation) = DiagnosticObservation::from_consent_receipt(&receipt)? {
                observations.push(observation);
            }
        }
        observations.sort_by_key(DiagnosticObservation::order_key);
        let input = DiagnosticWorkingSet {
            scope_ref,
            observations: &observations,
        };
        run_deterministic_detectors(self, &input, &[&ConsentDeniedDetector])
    }
}
