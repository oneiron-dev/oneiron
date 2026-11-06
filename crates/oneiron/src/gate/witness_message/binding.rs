//! Whole-envelope witness binding.
use super::{EntityId, WriteActor, edge_actor_class_str};
use sha2::{Digest, Sha256};

/// The domain tag for the witness-message binding hash. Bump the suffix if the
/// hashed tuple below ever changes; the value is an ABI.
const WITNESS_MESSAGE_BINDING_DOMAIN: &[u8] = b"oneiron.gate.witness_message.v1";

/// The content-addressed binding for one authorized MESSAGE write: the actor
/// that presented it and the canonical body bytes that carry every envelope
/// axis. Deterministic across processes and stable as an ABI.
pub(super) fn witness_message_binding(actor: WriteActor, body: &[u8]) -> [u8; 32] {
    let entity_ref: EntityId = actor.entity_ref();
    let mut hasher = Sha256::new();
    hasher.update(WITNESS_MESSAGE_BINDING_DOMAIN);
    hasher.update(edge_actor_class_str(actor.actor_class()).as_bytes());
    hasher.update(entity_ref.as_bytes());
    hasher.update((body.len() as u64).to_le_bytes());
    hasher.update(body);
    hasher.finalize().into()
}
