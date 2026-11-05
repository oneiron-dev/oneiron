//! Content-derived diagnostic event addresses.

use crate::diagnostic_record::event::DIAGNOSTIC_EVENT_ID_DOMAIN;
use oneiron_contracts::entity_id::EntityId;

/// Derives the stable event id for `(detector_id, canonical_body)`.
///
/// Admission requires `detector_id` to equal the identity persisted in the
/// canonical body. Every local and replicated put checks this binding.
///
/// 16 raw domain-separated BLAKE3 bytes, so the id is reproducible from the
/// detector identity and the canonical body alone. The detector id is
/// length-prefixed so no two `(id, body)` pairs can concatenate to the same
/// transcript. A prefix landing on a reserved sentinel (~2^-120) is perturbed
/// rather than randomized, which keeps the derivation total without making it
/// unreproducible.
#[must_use]
pub fn diagnostic_event_id(detector_id: &str, canonical_body: &[u8]) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIAGNOSTIC_EVENT_ID_DOMAIN);
    hasher.update(&(detector_id.len() as u64).to_be_bytes());
    hasher.update(detector_id.as_bytes());
    hasher.update(canonical_body);
    let mut raw = [0_u8; 16];
    raw.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    EntityId::from_bytes(raw).unwrap_or_else(|_| {
        raw[0] ^= 0x01;
        raw[15] ^= 0x01;
        EntityId::from_bytes(raw).expect("perturbed diagnostic id is non-reserved")
    })
}
