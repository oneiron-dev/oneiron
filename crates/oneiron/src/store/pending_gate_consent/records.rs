//! Core half of `store::pending_gate_consent::records`: its store-layer items live in `oneiron_store::pending_gate_consent::records` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::pending_gate_consent::records::*;

use super::GateDecisionId;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub(in crate::store) use oneiron_records::store::pending_gate_consent::records::decode_pending_gate_consent;
#[doc(hidden)]
pub(super) use oneiron_records::store::pending_gate_consent::records::vet_pending_gate_consent_record;
#[doc(hidden)]
pub use oneiron_records::store::pending_gate_consent::records::{
    PendingGateConsentGroup, PendingGateConsentRecord,
};

/// Internal RCPT-1 deletion state for one run-scoped pending-consent row.
///
/// The primary pending row deliberately keeps its receipt-facing shape.  The
/// sidecar records the derived lookup keys so a later close/delete removes
/// exactly the index entries minted for the original pending body, even if a
/// stale proposal's claim has changed since it was queued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PendingGateConsentIndexState {
    pub(super) version: u8,
    pub(super) run_id: String,
    pub(super) group_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) semantic_claim_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OwnerAnswerObligationRecord {
    pub(super) version: u8,
    pub(super) claim_id: [u8; 16],
    /// The decision whose critical confirm opened the obligation. The field
    /// keeps the name of the invalidation row this record grew from, so a
    /// vault's earlier rows read as open obligations.
    #[serde(rename = "invalidated_decision_id")]
    pub(crate) opened_by: GateDecisionId,
    /// The hash of the content binding of the item the owner answers now
    /// ([`super::owner_answer_item_hash`]). An earlier invalidation row holds
    /// a body hash that names no item, so the first door to meet it shows the
    /// owner a fresh one.
    #[serde(rename = "replacement_body_hash")]
    pub(crate) item: [u8; 32],
}

pub(super) fn encode_pending_gate_consent_index_state(
    state: &PendingGateConsentIndexState,
) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(state)
        .map_err(|_| Error::InvariantViolation("pending gate consent index state encode failed"))
}

pub(super) fn decode_pending_gate_consent_index_state(
    raw: &[u8],
) -> Result<PendingGateConsentIndexState> {
    let state: PendingGateConsentIndexState = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("pending gate consent index state"))?;
    if state.version != PENDING_GATE_CONSENT_INDEX_STATE_VERSION
        || state.run_id.trim().is_empty()
        || state.group_key.trim().is_empty()
    {
        return Err(Error::CorruptedIndex("pending gate consent index state"));
    }
    Ok(state)
}

pub(super) fn encode_owner_answer_obligation(
    record: &OwnerAnswerObligationRecord,
) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("owner answer obligation encode failed"))
}

pub(super) fn decode_owner_answer_obligation(raw: &[u8]) -> Result<OwnerAnswerObligationRecord> {
    let record: OwnerAnswerObligationRecord =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("owner answer obligation"))?;
    if record.version != OWNER_ANSWER_OBLIGATION_VERSION || record.claim_id == [0; 16] {
        return Err(Error::CorruptedIndex("owner answer obligation"));
    }
    Ok(record)
}

pub(super) fn sort_pending_gate_consents(records: &mut [PendingGateConsentRecord]) {
    records.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| {
                left.decision_id
                    .as_bytes()
                    .cmp(&right.decision_id.as_bytes())
            })
            .then_with(|| left.claim_id.cmp(&right.claim_id))
    });
}
