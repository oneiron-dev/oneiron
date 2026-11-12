//! Moved from `crates/oneiron/src/code_revision/import_types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::claim::ClaimApprovalStatus;
use oneiron_contracts::claim::ClaimLifecycleStatus;
use oneiron_contracts::claim::ClaimSource;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use oneiron_store::code_document_values::CodeDocumentFrontier;
pub use oneiron_store::code_import_manifest::CodeImportAnchor;
pub(crate) use oneiron_store::code_import_manifest::CodeImportManifest;
pub(crate) use oneiron_store::code_import_manifest::IMPORT_MANIFEST_PREDICATE;
use oneiron_store::code_import_manifest::claim_body;
use oneiron_store::code_import_manifest::from_claim;
pub(crate) use oneiron_store::code_import_manifest::manifest_digest;
pub(crate) use oneiron_store::code_import_manifest::manifest_id;
pub use oneiron_store::code_revision_record::CodePathRetirement;
use oneiron_store::code_snapshot::ids::entity_id_from_hash_material;
use oneiron_store::code_tree_blob::CodeTreeBlob;
use oneiron_store::critic_lens::LensCatalog;
use oneiron_store::write_envelope::claim_body::ClaimBody;
use oneiron_store::write_envelope::claim_body::ClaimSubject;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// The owner's explicit promotion request over one exact manifest: its
/// digest, the exact checked Baseline revision, the review catalog the
/// owner selects for this import and, when that catalog has lenses, the
/// saved review verdict. An empty lens list is quorum 0 on this import
/// alone: the owner's acceptance of the digest is the review (CALL F).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeImportAcceptance {
    /// The manifest digest the owner accepts, 64 lower-hex.
    pub manifest_digest: String,
    /// The checked Baseline revision whose untouched bytes it admits.
    pub baseline_revision: EntityId,
    /// The manifest-review catalog the owner selects for this import.
    pub catalog: LensCatalog,
    /// The persisted `vault.critic.review` verdict over the manifest;
    /// required when the catalog has lenses, unused when it has none.
    pub review_verdict: Option<EntityId>,
}
