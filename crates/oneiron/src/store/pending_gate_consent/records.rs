//! Pending gate-consent record and index-state types, ABI-pinned versions, msgpack codecs, and validation.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::{GATE_DIFF_HANDLE_MAX_LEN, GateDecisionId};

/// Body version of one pending gate-consent tray row.
///
/// Pinned to the same numeric value the decision ledger happens to carry
/// today, because that is the value already on disk — this names it rather
/// than changing it. The two families are stored, indexed and swept
/// separately, so borrowing [`GATE_DECISION_LEDGER_VERSION`] here would make
/// the NEXT decision-ledger bump decode every stored pending row as corrupt.
///
/// Receipt-family ABI-pin rule: changing this requires a
/// [`STORAGE_ABI_VERSION`] bump.
pub(crate) const PENDING_GATE_CONSENT_VERSION: u8 = 0;

/// Receipt-family ABI-pin rule: changing this requires a
/// [`STORAGE_ABI_VERSION`] bump.
pub(in crate::store) const PENDING_GATE_CONSENT_INDEX_STATE_VERSION: u8 = 1;

const PENDING_GATE_CONSENT_DREAMER_RUN_ID_MAX_LEN: usize = 128;

pub(super) const OWNER_ANSWER_OBLIGATION_VERSION: u8 = 0;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingGateConsentRecord {
    pub version: u8,
    pub claim_id: [u8; 16],
    pub decision_id: GateDecisionId,
    pub created_at: u64,
    pub diff_handle: Vec<u8>,
    pub read_frontier_hash: [u8; 32],
    pub reason_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dreamer_run_id: Option<String>,
    /// The predicate of the claim the row parks, stamped when the row is
    /// written, so a reader whose claim body is gone still names it. `None`
    /// where the writer had no claim body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,
}

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
pub struct PendingGateConsentGroup {
    pub dreamer_run_id: Option<String>,
    pub records: Vec<PendingGateConsentRecord>,
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
    /// Whether a peer revision that lands over this claim lands demoted: set
    /// when a peer overwrote a confirm this device attached, cleared by a
    /// fresh local one. An earlier invalidation row has no field and reads
    /// as set.
    #[serde(default = "peer_revisions_demoted_by_default")]
    pub(crate) demotes_peer_revisions: bool,
}

const fn peer_revisions_demoted_by_default() -> bool {
    true
}

pub(super) fn encode_pending_gate_consent(record: &PendingGateConsentRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("pending gate consent encode failed"))
}

pub(in crate::store) fn decode_pending_gate_consent(
    raw: &[u8],
) -> Result<PendingGateConsentRecord> {
    let record: PendingGateConsentRecord =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
    vet_pending_gate_consent_record(&record)?;
    Ok(record)
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

pub(super) fn vet_pending_gate_consent_record(record: &PendingGateConsentRecord) -> Result<()> {
    if record.version != PENDING_GATE_CONSENT_VERSION
        || record.diff_handle.is_empty()
        || record.diff_handle.len() > GATE_DIFF_HANDLE_MAX_LEN
        || record.reason_codes.is_empty()
        || !record
            .reason_codes
            .iter()
            .all(|reason| reason.starts_with("gate.pending."))
    {
        return Err(Error::CorruptedIndex("pending gate consent"));
    }
    if let Some(dreamer_run_id) = record.dreamer_run_id.as_deref()
        && (dreamer_run_id.trim().is_empty()
            || dreamer_run_id.len() > PENDING_GATE_CONSENT_DREAMER_RUN_ID_MAX_LEN)
    {
        return Err(Error::CorruptedIndex("pending gate consent"));
    }
    Ok(())
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
