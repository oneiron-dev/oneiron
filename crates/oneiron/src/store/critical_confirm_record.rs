//! Core half of `store::critical_confirm_record`: its store-layer items live in `oneiron_store::critical_confirm_record` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::critical_confirm_record::*;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::{GateDecisionId, PendingGateConsentRecord};
use oneiron_authority::authority::CRITICAL_WRITE_CONFIRM_DOMAIN;
use sha2::{Digest, Sha256};

/// Whether `row` is a critical confirm's item: attached here or on sync,
/// timed out, or shown for an open obligation. Each one opens its claim's
/// owner-answer obligation, which is the hold readers ask.
pub(crate) fn pending_row_holds_critical_confirm(row: &PendingGateConsentRecord) -> bool {
    row.reason_codes
        .iter()
        .any(|reason| reason.contains("critical_confirm"))
}

/// The deterministic authority-log binding for a critical claim attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalWriteConfirmBinding {
    pub confirm_id: [u8; 32],
    pub gate_decision_id: GateDecisionId,
    pub claim_id: EntityId,
    pub effect_digest: [u8; 32],
    pub read_frontier_hash: [u8; 32],
    pub nonce: [u8; 16],
    pub expires_at: u64,
}

pub(crate) fn critical_write_confirm_binding(
    pending: &PendingGateConsentRecord,
) -> Result<CriticalWriteConfirmBinding> {
    if !matches!(
        pending.reason_codes.as_slice(),
        [reason]
            if reason.as_str() == GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED
                || reason.as_str() == GATE_REASON_PENDING_REPLICATED_CRITICAL_CONFIRM
                || reason.as_str() == GATE_REASON_PENDING_CRITICAL_CONFIRM_REOPENED
                || reason.as_str() == GATE_REASON_CRITICAL_CONFIRM_TIMEOUT
    ) {
        return Err(Error::InvalidClaimBody("not a critical-confirm attachment"));
    }
    let claim_id = EntityId::from_bytes(pending.claim_id)
        .map_err(|_| Error::InvalidClaimBody("pending critical-confirm claim id"))?;
    let mut digest = blake3::Hasher::new();
    digest.update(b"oneiron:critical-confirm:v1");
    digest.update(claim_id.as_bytes());
    digest.update(&pending.decision_id.as_bytes());
    digest.update(&pending.diff_handle);
    digest.update(&pending.read_frontier_hash);
    let effect_digest = *digest.finalize().as_bytes();
    let nonce = pending.decision_id.as_bytes();
    // The deadline the gate froze when it attached the confirm (FIX 8760);
    // a hold with none of its own, attached on sync or reopened for an open
    // obligation, never times out here and signs the shipped lifetime.
    let expires_at = pending.expires_at.unwrap_or_else(|| {
        pending
            .created_at
            .saturating_add(CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS)
    });
    let mut confirm = Sha256::new();
    confirm.update(CRITICAL_WRITE_CONFIRM_DOMAIN);
    confirm.update(pending.decision_id.as_bytes());
    confirm.update(claim_id.as_bytes());
    confirm.update(effect_digest);
    confirm.update(pending.read_frontier_hash);
    confirm.update(nonce);
    confirm.update(expires_at.to_be_bytes());
    Ok(CriticalWriteConfirmBinding {
        confirm_id: confirm.finalize().into(),
        gate_decision_id: pending.decision_id,
        claim_id,
        effect_digest,
        read_frontier_hash: pending.read_frontier_hash,
        nonce,
        expires_at,
    })
}
