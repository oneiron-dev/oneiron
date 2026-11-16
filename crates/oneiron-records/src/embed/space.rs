//! Moved from `crates/oneiron/src/embed/space.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::embedding::EMBEDDING_SETUP_LEARNED_AT;
pub use oneiron_store::embedding::EMBEDDING_SPACE_ID_MAX_LEN;
pub use oneiron_store::embedding::EMBEDDING_SPACE_MAX_DIMENSIONS;
pub use oneiron_store::embedding::EmbeddingSpace;
pub use oneiron_store::embedding::KindSlotBindings;
pub use oneiron_store::embedding_vocabulary::InputKind;
use serde::Serialize;

/// The id of declared space `id`'s EMBEDDING_SETUP row: the entity that names the space, as the
/// scorer of its retests does (FIX 1638).
pub fn space_setup_id(id: &str) -> Result<EntityId> {
    let domain = oneiron_contracts::entity_id::derived_domains::EMBEDDING_SETUP;
    EntityId::derive(domain, &[b"space".as_slice(), id.as_bytes()])
}

/// The id of `kind`'s slot EMBEDDING_SETUP row.
pub fn slot_setup_id(kind: InputKind) -> Result<EntityId> {
    let domain = oneiron_contracts::entity_id::derived_domains::EMBEDDING_SETUP;
    EntityId::derive(domain, &[b"slot".as_slice(), &[kind.byte()]])
}

pub fn refused_setup(reason: String) -> Error {
    Error::Artifact(ArtifactError::InvalidEmbeddingSetupBody(reason))
}

/// One document a space's model refused, as the owner sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MediaRefused {
    pub id: EntityId,
    pub reason: String,
    /// Vault seconds.
    pub at: u64,
}
