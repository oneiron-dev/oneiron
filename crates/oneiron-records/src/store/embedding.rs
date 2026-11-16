//! Moved from `crates/oneiron/src/store/embedding.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::embedding::*;
pub use oneiron_store::embedding_vocabulary::EmbeddingDevice;
pub use oneiron_store::embedding_vocabulary::EmbeddingProvenance;
pub use oneiron_store::embedding_vocabulary::InputKind;
use serde::Deserialize;
use serde::Serialize;

/// Where an embedder runs relative to the vault owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EmbedderLocality {
    /// Runs on the same device as the vault.
    OnDevice,
    /// Runs on infrastructure controlled by the vault owner.
    OwnerServer,
    /// Runs on a third-party service.
    ThirdParty,
}
