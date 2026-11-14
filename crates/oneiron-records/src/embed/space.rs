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
use serde::Deserialize;
use serde::Serialize;

/// Who wrote an EMBEDDING_SETUP retirement or slot row (FIX 6697): the owner through a door, or a
/// system move. Startup seeding honours only the owner's retirements and returns to a default;
/// a system move's re-seed from the config as they did before #3485.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupActor {
    /// The owner, through a door: retiring a space, unbinding or binding a slot, declaring a
    /// space, abandoning a move, saying yes to one.
    Owner,
    /// The engine: a timed-out or worse move's dropped candidate, an undo back to the vault's
    /// own text index, a swap's backfill retiring the incumbent, and any other engine-driven
    /// write. A row that names no actor is one of these.
    #[default]
    System,
}

impl SetupActor {
    fn is_system(&self) -> bool {
        *self == Self::System
    }
}

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
