//! Moved from `crates/oneiron/src/authority/export_secret_work.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub(crate) use oneiron_store::batch::export::secret_supplement_record::HolderExportNeed;
pub use oneiron_store::batch::export::secret_supplement_record::OpenedSecretSupplement;
pub use oneiron_store::batch::export::secret_supplement_record::SecretSupplementImport;
pub use oneiron_verb_wire::authority::export_secret_work::HolderExportState;
pub use oneiron_verb_wire::authority::export_secret_work::HolderExportUnassigned;
use oneiron_verb_wire::world_keys::owner_work::OwnerWorkStatus;
use serde::Deserialize;
use serde::Serialize;

/// One export secret request as its owner reads it (FIX 4624(b)): where it
/// stands and, once its holder sealed it and this install keeps the copy,
/// the sealed copy itself. Ids, digests and ciphertext only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportSecretSupplement {
    /// The request's signed authority-log entry, as hex.
    pub request: String,
    pub secret: EntityId,
    pub generation: u32,
    /// The export it supplements, as its audit row names it.
    pub export: EntityId,
    /// The install that holds the secret and seals it.
    pub holder: EntityId,
    /// The machine the copy is sealed to: only it opens the copy.
    pub recipient: EntityId,
    pub status: OwnerWorkStatus,
    /// Whether an admitted import mark is present in the authority fold.
    /// This is not the local custody import's outcome.
    pub marked_imported: bool,
    /// BLAKE3 of the sealed copy, lowercase hex, as its signed result names
    /// it; `None` before the holder sealed it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// The sealed copy, standard base64, when this install keeps it; `None`
    /// before it is sealed, or when only its holder keeps it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed: Option<String>,
}
