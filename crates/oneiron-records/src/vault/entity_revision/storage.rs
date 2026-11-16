//! Moved from `crates/oneiron/src/vault/entity_revision/storage.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::vault::entity_revision::storage::redact::ClaimValueRedactionBinding;
pub use crate::vault::entity_revision::storage::redact::LocalClaimValueRedaction;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::revision_ref::RevisionRef;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize)]
pub struct RevisionState {
    pub live: RevisionRef,
    pub indexed: RevisionRef,
    pub changed_at_ms: u64,
    pub has_doc: bool,
}

pub fn reference(id: &EntityId, raw: &[u8]) -> RevisionRef {
    let mut hash = blake3::Hasher::new();
    hash.update(id.as_bytes());
    hash.update(raw);
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    RevisionRef(bytes)
}
pub mod redact;
