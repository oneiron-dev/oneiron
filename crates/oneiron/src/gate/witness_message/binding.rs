//! Whole-envelope witness binding.
use super::{EntityId, WriteActor, edge_actor_class_str};
use oneiron_contracts::fingerprint::{LegacyDigest, purposes};

/// The content-addressed binding for one authorized MESSAGE write: the actor
/// that presented it and the canonical body bytes that carry every envelope
/// axis. Deterministic across processes and stable as an ABI
/// ([`purposes::gate::WITNESS_MESSAGE`]: a changed tuple takes a new purpose).
pub(super) fn witness_message_binding(actor: WriteActor, body: &[u8]) -> [u8; 32] {
    let entity_ref: EntityId = actor.entity_ref();
    LegacyDigest::new(purposes::gate::WITNESS_MESSAGE)
        .raw(edge_actor_class_str(actor.actor_class()).as_bytes())
        .raw(entity_ref.as_bytes())
        .len_u64_le(body.len())
        .raw(body)
        .finish()
}

/// The binding of the MESSAGE write `actor` presents with `body`.
#[cfg(oneiron_test_support)]
pub(crate) fn witness_message_binding_for_test(actor: WriteActor, body: &[u8]) -> [u8; 32] {
    witness_message_binding(actor, body)
}
