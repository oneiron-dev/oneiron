//! Core half of `store::critical_confirm_record`: its store-layer items live in `oneiron_store::critical_confirm_record` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::critical_confirm_record::*;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::{GateDecisionId, PendingGateConsentRecord};
use oneiron_contracts::fingerprint::{LegacyDigest, purposes};

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
    let effect_digest = confirm_effect_digest(
        &claim_id,
        &pending.decision_id.as_bytes(),
        &pending.diff_handle,
        &pending.read_frontier_hash,
    );
    let nonce = pending.decision_id.as_bytes();
    // The deadline the gate froze when it attached the confirm (FIX 8760);
    // a hold with none of its own, attached on sync or reopened for an open
    // obligation, never times out here and signs the shipped lifetime.
    let expires_at = pending.expires_at.unwrap_or_else(|| {
        pending
            .created_at
            .saturating_add(CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS)
    });
    let confirm_id = write_confirm_id(
        &pending.decision_id.as_bytes(),
        &claim_id,
        &effect_digest,
        &pending.read_frontier_hash,
        &nonce,
        expires_at,
    );
    Ok(CriticalWriteConfirmBinding {
        confirm_id,
        gate_decision_id: pending.decision_id,
        claim_id,
        effect_digest,
        read_frontier_hash: pending.read_frontier_hash,
        nonce,
        expires_at,
    })
}

/// The effect a critical confirm binds (`purposes::store::CRITICAL_CONFIRM_EFFECT`):
/// the claim, the gate decision, the diff handle and the read frontier.
fn confirm_effect_digest(
    claim_id: &EntityId,
    decision_id: &[u8; 16],
    diff_handle: &[u8],
    read_frontier_hash: &[u8; 32],
) -> [u8; 32] {
    LegacyDigest::new(purposes::store::CRITICAL_CONFIRM_EFFECT)
        .raw(claim_id.as_bytes())
        .raw(decision_id)
        .raw(diff_handle)
        .raw(read_frontier_hash)
        .finish()
}

/// A critical write confirm's id (`purposes::store::CRITICAL_WRITE_CONFIRM`,
/// whose tag is `CRITICAL_WRITE_CONFIRM_DOMAIN`).
fn write_confirm_id(
    decision_id: &[u8; 16],
    claim_id: &EntityId,
    effect_digest: &[u8; 32],
    read_frontier_hash: &[u8; 32],
    nonce: &[u8; 16],
    expires_at: u64,
) -> [u8; 32] {
    LegacyDigest::new(purposes::store::CRITICAL_WRITE_CONFIRM)
        .raw(decision_id)
        .raw(claim_id.as_bytes())
        .raw(effect_digest)
        .raw(read_frontier_hash)
        .raw(nonce)
        .raw(&expires_at.to_be_bytes())
        .finish()
}

/// [`confirm_effect_digest`] for the K door
/// (`test_doors::fingerprint_keep_store_digests`). Not API.
#[cfg(oneiron_test_support)]
pub(crate) fn confirm_effect_digest_for_test(
    claim_id: &EntityId,
    decision_id: &[u8; 16],
    diff_handle: &[u8],
    read_frontier_hash: &[u8; 32],
) -> [u8; 32] {
    confirm_effect_digest(claim_id, decision_id, diff_handle, read_frontier_hash)
}

/// [`write_confirm_id`] for the K door
/// (`test_doors::fingerprint_keep_store_digests`). Not API.
#[cfg(oneiron_test_support)]
pub(crate) fn write_confirm_id_for_test(
    decision_id: &[u8; 16],
    claim_id: &EntityId,
    effect_digest: &[u8; 32],
    read_frontier_hash: &[u8; 32],
    nonce: &[u8; 16],
    expires_at: u64,
) -> [u8; 32] {
    write_confirm_id(
        decision_id,
        claim_id,
        effect_digest,
        read_frontier_hash,
        nonce,
        expires_at,
    )
}
