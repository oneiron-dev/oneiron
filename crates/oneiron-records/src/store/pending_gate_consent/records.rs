//! Moved from `crates/oneiron/src/store/pending_gate_consent/records.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_store::gate_decision::types::GATE_DIFF_HANDLE_MAX_LEN;
use oneiron_store::gate_decision::types::GateDecisionId;
pub(crate) use oneiron_store::pending_gate_consent::records::*;
use serde::Deserialize;
use serde::Serialize;

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
    /// The deadline a locally attached critical confirm froze when the gate
    /// attached it (FIX 8760): its creation time plus the policy's
    /// `critical_confirm_lifetime_seconds` then. The binding, its signed
    /// action, the listing, the sweep and an answer read it, so a later
    /// policy edit never moves it. `None` on every other row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingGateConsentGroup {
    pub dreamer_run_id: Option<String>,
    pub records: Vec<PendingGateConsentRecord>,
}

pub fn encode_pending_gate_consent(record: &PendingGateConsentRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("pending gate consent encode failed"))
}

pub fn decode_pending_gate_consent(raw: &[u8]) -> Result<PendingGateConsentRecord> {
    let record: PendingGateConsentRecord =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("pending gate consent"))?;
    vet_pending_gate_consent_record(&record)?;
    Ok(record)
}

pub fn vet_pending_gate_consent_record(record: &PendingGateConsentRecord) -> Result<()> {
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
        && dreamer_run_id.trim().is_empty()
    {
        return Err(Error::CorruptedIndex("pending gate consent"));
    }
    // A frozen deadline comes after its row's creation: the lifetime is
    // positive.
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.created_at)
    {
        return Err(Error::CorruptedIndex("pending gate consent"));
    }
    Ok(())
}
