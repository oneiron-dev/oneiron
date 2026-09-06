use super::dispatch_types::OutboundDispatchError;

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
