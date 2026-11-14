//! Read-facing views and per-verb inputs for structural puts.

pub use crate::vault::entity_view::EntityView;
#[doc(hidden)]
pub use oneiron_verb_wire::memory::structural::types::{
    AdmitImportedClaimInput, BlobArtifactInput, HabitCheckinInput, StructuralEdgeSpec,
    StructuralPutInput, TextIndexField,
};
use serde::{Deserialize, Serialize};

/// Receipt for a structural write (put/checkin/companion/blob artifact).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EntityRefReceipt {
    /// Short-id ref of the written entity (hex fallback).
    pub entity_ref: String,
    /// 32-hex id of the written entity.
    pub id_hex: String,
    /// Facade write marker (`put:<hex>`); structural puts produce no gate
    /// decision at base.
    pub receipt_ref: String,
    /// The written entity as a typed record ref (OF-063), built from the id
    /// and kind the writing door holds, with no read; `None` from a door that
    /// does not name the kind it wrote.
    #[serde(default)]
    pub record: Option<crate::lens::RecordRef>,
    /// For an agent's AGENT_DEF put, what its author writer made of it
    /// (ARCH-0053:20): active, or a proposal no dispatch runs; absent for
    /// every other write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_definition: Option<crate::core_write::AgentDefinitionWriteReceipt>,
}
/// View of one appended blob artifact version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BlobVersionView {
    /// 32-hex artifact id.
    pub artifact_ref: String,
    /// Version number (1-based, append-only).
    pub version: u64,
    /// blake3 content hash, lowercase hex.
    pub content_hash_hex: String,
    /// 32-hex id of the `blob.version` LEDGER claim.
    pub claim_ref: String,
    /// Unix seconds.
    pub created_at: u64,
    /// The BLOB_ARTIFACT as a typed record ref (OF-063), with no read.
    #[serde(default)]
    pub artifact: Option<crate::lens::RecordRef>,
    /// The version's LEDGER claim as a typed record ref, with no read.
    #[serde(default)]
    pub claim: Option<crate::lens::RecordRef>,
}

/// A checked append's actual result: a version on the chain, or an output
/// retained beside the live artifact until an authorized Keep settles it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlobVersionAppendOutcome {
    Landed(BlobVersionView),
    Proposed(crate::edit_settle::PendingProposalView),
}
