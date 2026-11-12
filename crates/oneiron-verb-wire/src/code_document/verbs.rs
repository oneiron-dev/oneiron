//! Moved from `crates/oneiron/src/code_document/verbs.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::code_document_values::CodeDocumentFrontier;
use oneiron_store::code_snapshot::ids::codebase_asset_entity_id as snapshot_asset_entity_id;
use oneiron_store::file_secret_marks::SecretSight;
use oneiron_store::receipt_identity::ERASED_CALL_IDENTITY;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// One tested state of a file: as the code revision `revision_ref` tested
/// it, or, with no revision, the document's live head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeStateRequest {
    /// The repository's code-document identity (FIX 12761):
    /// `portable:<hex>` while a portable id stands for it, else
    /// `local:<path>` or `github:<owner>/<repo>`. A frontier's `repo` spells
    /// it.
    pub repo: String,
    pub path: String,
    #[serde(default)]
    pub revision_ref: Option<String>,
}

/// Two tested states of one document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeDiffRequest {
    pub before: CodeStateRequest,
    pub after: CodeStateRequest,
}
