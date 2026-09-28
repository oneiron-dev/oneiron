//! Producer-owned, vault-local source proofs over the existing base ledgers.
//! These values have no public constructor or wire decoder. Diagnostic bytes
//! alone can never mint one, and nothing here can grant repair authority.

use super::{
    ConsentDeniedDetector, DeterministicDetector, DiagnosticEvent, DiagnosticObservation,
    DiagnosticSourceKind, DiagnosticWorkingSet,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::ReceiptRecord;
use crate::store::{GateDecisionId, RetrievalRunId, RetrievalRunRecord, Store};

#[derive(Clone)]
enum SourceProof {
    Gate {
        id: GateDecisionId,
        digest: [u8; 32],
    },
    Retrieval {
        id: RetrievalRunId,
        digest: [u8; 32],
    },
    CentroidSnapshot {
        hash: [u8; 32],
    },
}

/// Capture eligibility established by a producer against base ledger rows.
/// Private fields keep a caller-built `DiagnosticEvent` or `ReceiptRecord`
/// from being interpreted as this authority.
#[derive(Clone)]
pub(crate) struct VerifiedSourceSet {
    proofs: Vec<SourceProof>,
}

fn ineligible() -> Error {
    Error::InvalidConfig("failure signal lacks a verified on-record source".into())
}

fn digest<T: serde::Serialize>(value: &T) -> Result<[u8; 32]> {
    let bytes = rmp_serde::to_vec_named(value)
        .map_err(|_| Error::InvariantViolation("tier-1 source encoding failed"))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

impl VerifiedSourceSet {
    /// Existing single-observation deterministic producers. This validation
    /// runs only in the producer after its own successful diagnostic emit, not
    /// on arbitrary stored diagnostics at the public count door.
    pub(crate) fn point_producer(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        event: &DiagnosticEvent,
    ) -> Result<Self> {
        let [source] = event.evidence_refs.as_slice() else {
            return Err(ineligible());
        };
        let (observation, proof) = match (event.detector_id.as_str(), event.source) {
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
                let receipt = crate::receipt::gate_decision_receipt_from_base(&decision);
                let observation = DiagnosticObservation::from_consent_receipt(&receipt)?
                    .ok_or_else(ineligible)?;
                (
                    observation,
                    SourceProof::Gate {
                        id,
                        digest: digest(&receipt)?,
                    },
                )
            }
            ("retrieval.miss.v1", DiagnosticSourceKind::RetrievalTelemetry) => {
                let id = RetrievalRunId::from_bytes(*source.as_bytes());
                let run = store
                    .retrieval_run_in_txn(txn, id)?
                    .ok_or_else(ineligible)?;
                let observation =
                    DiagnosticObservation::from_retrieval_run(&run).ok_or_else(ineligible)?;
                (
                    observation,
                    SourceProof::Retrieval {
                        id,
                        digest: digest(&run)?,
                    },
                )
            }
            _ => return Err(ineligible()),
        };
        if observation.source_ref != *source
            || observation.observed_at != event.valid_from
            || observation.payload_digest != event.replay.content_hash
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
        if expected.as_slice() != std::slice::from_ref(event) {
            return Err(ineligible());
        }
        Ok(Self {
            proofs: vec![proof],
        })
    }

    /// A producer-validated telemetry window. Every run is point-read from
    /// base again, including each member of a model-judged session window.
    pub(crate) fn retrieval_window(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        runs: &[RetrievalRunRecord],
    ) -> Result<Self> {
        if runs.is_empty() {
            return Err(ineligible());
        }
        let mut proofs = Vec::with_capacity(runs.len());
        for run in runs {
            let stored = store
                .retrieval_run_in_txn(txn, run.run_id)?
                .ok_or_else(ineligible)?;
            if stored != *run {
                return Err(ineligible());
            }
            proofs.push(SourceProof::Retrieval {
                id: run.run_id,
                digest: digest(&stored)?,
            });
        }
        Ok(Self { proofs })
    }

    pub(crate) fn with_centroid_snapshot(
        mut self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        hash: [u8; 32],
    ) -> Result<Self> {
        if !super::centroid_evidence::snapshot_live_in_txn(store, txn, &hash)? {
            return Err(ineligible());
        }
        self.proofs.push(SourceProof::CentroidSnapshot { hash });
        Ok(self)
    }

    /// A caller-supplied receipt slice only gains eligibility when every
    /// selected receipt is reprojected from its actual base Gate ledger row.
    pub(crate) fn receipt_window(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        receipts: &[ReceiptRecord],
        evidence: &[EntityId],
    ) -> Result<Self> {
        if evidence.is_empty() {
            return Err(ineligible());
        }
        let mut proofs = Vec::with_capacity(evidence.len());
        for source in evidence {
            let id = GateDecisionId::from_bytes(*source.as_bytes());
            let decision = store
                .gate_decision_in_txn(txn, id)?
                .ok_or_else(ineligible)?;
            if decision.redacted_at.is_some() {
                return Err(ineligible());
            }
            let actual = crate::receipt::gate_decision_receipt_from_base(&decision);
            // Every supplied copy must match: a forged duplicate after the
            // real row could otherwise have fed the detector.
            let mut claimed = receipts
                .iter()
                .filter(|receipt| receipt.receipt_id == actual.receipt_id)
                .peekable();
            if claimed.peek().is_none() || claimed.any(|receipt| *receipt != actual) {
                return Err(ineligible());
            }
            proofs.push(SourceProof::Gate {
                id,
                digest: digest(&actual)?,
            });
        }
        Ok(Self { proofs })
    }

    /// A retained witness must still name unchanged on-record rows. Deletion,
    /// redaction, provisional retrieval and changed rows revoke it at read.
    pub(crate) fn still_live(&self, store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
        for proof in &self.proofs {
            match *proof {
                SourceProof::Gate {
                    id,
                    digest: expected,
                } => {
                    let Some(row) = store.gate_decision_in_txn(txn, id)? else {
                        return Ok(false);
                    };
                    if row.redacted_at.is_some()
                        || digest(&crate::receipt::gate_decision_receipt_from_base(&row))?
                            != expected
                    {
                        return Ok(false);
                    }
                }
                SourceProof::Retrieval {
                    id,
                    digest: expected,
                } => {
                    let Some(row) = store.retrieval_run_in_txn(txn, id)? else {
                        return Ok(false);
                    };
                    if digest(&row)? != expected {
                        return Ok(false);
                    }
                }
                SourceProof::CentroidSnapshot { hash } => {
                    if !super::centroid_evidence::snapshot_live_in_txn(store, txn, &hash)? {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }
}
