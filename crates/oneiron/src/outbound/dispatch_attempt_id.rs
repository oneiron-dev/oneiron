//! Logical-send and attempt identity derivation.
//! Entry: `outbound_dispatch_attempt_id`.
//! Defines its own items.

use super::dispatch_types::OutboundDispatchError;
use crate::entity_id::EntityId;

pub(crate) fn outbound_dispatch_attempt_id(
    intent_ref: &str,
) -> std::result::Result<crate::attempt_queue::AttemptId, OutboundDispatchError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.outbound.dispatch_attempt.v1");
    hasher.update(&(intent_ref.len() as u64).to_le_bytes());
    hasher.update(intent_ref.as_bytes());
    let bytes: [u8; 16] = hasher.finalize().as_bytes()[..16]
        .try_into()
        .expect("BLAKE3 prefix length is fixed");
    crate::attempt_queue::AttemptId::from_bytes(&bytes).map_err(OutboundDispatchError::Engine)
}

/// The logical send one scheduled connector TASK is: its actor and its
/// idempotency key, or its TASK when it names none. The executor's every
/// attempt runs under it as its ledger identity, and the schedule's ask
/// names it as the send a press releases (FIX 6424), so both derive it here.
pub(crate) fn connector_logical_send_ref(
    actor_ref: EntityId,
    idempotency_key: Option<&str>,
    task_ref: EntityId,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.connector.logical_send.v1");
    hasher.update(actor_ref.as_bytes());
    if let Some(idempotency_key) = idempotency_key {
        hasher.update(b"idempotency_key");
        hasher.update(&(idempotency_key.len() as u64).to_le_bytes());
        hasher.update(idempotency_key.as_bytes());
    } else {
        hasher.update(b"task_ref");
        hasher.update(task_ref.as_bytes());
    }
    format!(
        "intent:logical-send:{}",
        crate::entity_id::bytes_to_hex_lower(hasher.finalize().as_bytes())
    )
}
