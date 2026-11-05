//! The critical-confirm pending record: its reason codes, its deadline, and
//! the deterministic binding the authority log keys a confirm by.

use sha2::{Digest, Sha256};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::{GateDecisionId, PendingGateConsentRecord};
use oneiron_authority::authority::CRITICAL_WRITE_CONFIRM_DOMAIN;

/// How long a critical write's confirm waits before a timeout demotes it.
pub const CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS: u64 = 300;
// The decision receipt uses the allow namespace; the durable pending row must
// remain in store.rs's existing pending namespace.
pub(crate) const GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED: &str =
    "gate.pending.critical_confirm_attached";
/// The pending reason of a critical confirm that timed out.
pub const GATE_REASON_CRITICAL_CONFIRM_TIMEOUT: &str = "gate.pending.critical_confirm_timeout";
/// The pending reason of the confirm this device attaches to a critical claim
/// that reached it by sync. The peer's Auto stamp is not this device's Clear.
/// The hold has no deadline here, since a timeout's demotion would rewrite the
/// peer's bytes on this device.
pub(crate) const GATE_REASON_PENDING_REPLICATED_CRITICAL_CONFIRM: &str =
    "gate.pending.critical_confirm_replicated";
/// The pending reason of the item a claim's open owner-answer obligation
/// shows its owner after a door removed the one it had without an answer, or a
/// later revision outdated it (the gate's owner-answer doors). Like a replicated
/// hold, it has no deadline.
pub(crate) const GATE_REASON_PENDING_CRITICAL_CONFIRM_REOPENED: &str =
    "gate.pending.critical_confirm_reopened";

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
    let expires_at = pending
        .created_at
        .saturating_add(CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS);
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
