//! Producer-owned, vault-local source proofs over the existing base ledgers.
//! These values have no public constructor or wire decoder. Diagnostic bytes
//! alone can never mint one, and nothing here can grant repair authority.

use super::tripwires::{McpActionRejectedDetector, RetrievalRegressionDetector, TripwireBounds};
use super::{
    ConsentDeniedDetector, DeterministicDetector, DiagnosticEvent, DiagnosticObservation,
    DiagnosticSourceKind, DiagnosticWorkingSet,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::{CALL_RECEIPT_REF_PREFIX, CallReceipt, ReceiptRecord};
use crate::side_table::{self, Named, SideTable};
use crate::store::{GateDecisionId, RetrievalRunId, RetrievalRunRecord, Store};

/// The call receipt ledger, read in place (FIX 2449): an MCP refusal's
/// witness is its stored receipt.
const CALL_RECEIPTS: SideTable<EntityId, CallReceipt, Named> =
    SideTable::new(&side_table::CALL_RECEIPT);

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
    /// A refused MCP call's stored receipt, by its id and its whole row's
    /// digest (FIX 2449).
    McpCall {
        id: EntityId,
        digest: [u8; 32],
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

/// The stored call receipt `id`, while its row still names itself.
fn call_receipt_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<CallReceipt>> {
    let receipt_ref = format!("{CALL_RECEIPT_REF_PREFIX}{}", id.to_hex());
    Ok(CALL_RECEIPTS
        .get(store, txn, &id)?
        .filter(|receipt| receipt.receipt_ref == receipt_ref))
}

impl VerifiedSourceSet {
    /// Existing single-observation deterministic producers, a served MCP
    /// refusal's among them (FIX 2449). This validation runs only in the
    /// producer after its own successful diagnostic emit, not on arbitrary
    /// stored diagnostics at the public count door.
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
            ("mcp.rejected.v1", DiagnosticSourceKind::Receipt) => {
                let receipt = call_receipt_in(store, txn, *source)?.ok_or_else(ineligible)?;
                let observation = DiagnosticObservation::from_mcp_call_receipt(*source, &receipt)
                    .ok_or_else(ineligible)?;
                (
                    observation,
                    SourceProof::McpCall {
                        id: *source,
                        digest: digest(&receipt)?,
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
            "mcp.rejected.v1" => McpActionRejectedDetector.detect(&input),
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

    /// A served regression window (FIX 2449): `runs`, `bounds` and
    /// `window_end` as the producer fired with them. The window is drawn
    /// from them again as the producer's run drew it, and the detector run
    /// again must yield `event` whole; then every run in the window, not
    /// only the last, is point-read from base again.
    pub(crate) fn retrieval_regression(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        event: &DiagnosticEvent,
        runs: &[RetrievalRunRecord],
        bounds: TripwireBounds,
        window_end: u64,
    ) -> Result<Self> {
        let mut degraded: Vec<(DiagnosticObservation, &RetrievalRunRecord)> = runs
            .iter()
            .filter_map(|run| Some((DiagnosticObservation::from_retrieval_degradation(run)?, run)))
            .collect();
        degraded.sort_by_key(|(observation, _)| observation.order_key());
        degraded.dedup_by(|a, b| a.0 == b.0);
        let observations: Vec<DiagnosticObservation> = degraded
            .iter()
            .map(|(observation, _)| *observation)
            .collect();
        let input = DiagnosticWorkingSet {
            scope_ref: super::served_signals::SERVED_RETRIEVAL_SCOPE,
            observations: &observations,
        };
        let detector = RetrievalRegressionDetector { bounds, window_end };
        if detector.detect(&input).as_slice() != std::slice::from_ref(event) {
            return Err(ineligible());
        }
        let start = window_end.saturating_sub(bounds.window_secs);
        let members: Vec<RetrievalRunRecord> = degraded
            .into_iter()
            .filter(|(observation, _)| {
                observation.observed_at > start && observation.observed_at <= window_end
            })
            .map(|(_, run)| run.clone())
            .collect();
        Self::retrieval_window(store, txn, &members)
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
                SourceProof::McpCall {
                    id,
                    digest: expected,
                } => {
                    // An erase rewrites the row, and the witness goes with it.
                    let Some(receipt) = call_receipt_in(store, txn, id)? else {
                        return Ok(false);
                    };
                    if digest(&receipt)? != expected {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }
}
