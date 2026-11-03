//! The reviewed import's records (FIX 6869, G4 PR1): the anchor an import
//! binds, the owner's acceptance of one exact manifest, a retired path's
//! proof, and the two engine-owned claims, `repo.import_manifest` and
//! `repo.import_approval`.
//!
//! A manifest is compact: the anchor, the complete inventory's digest and
//! its own digest. The immutable snapshot and the pinned Git tree hold the
//! enumerated files; no blob content or file list is copied here. Both
//! claims have deterministic ids, so a repeat finds the same row and a
//! different body under that id is corruption, never an overwrite.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::CodeTreeBlob;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::code_document::CodeDocumentFrontier;
use crate::codebase::entity_id_from_hash_material;
use crate::critic::LensCatalog;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{ArtifactError, Error, Result};

/// The engine-owned predicate of an import manifest.
pub(crate) use crate::store::code_import_manifest::IMPORT_MANIFEST_PREDICATE;
/// The engine-owned predicate of an untouched-byte import approval.
pub(crate) const IMPORT_APPROVAL_PREDICATE: &str = "repo.import_approval";

const APPROVAL_DOMAIN: &[u8] = b"oneiron:code-import-approval:v1";

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(reason))
}

pub use crate::store::code_import_manifest::CodeImportAnchor;

pub use crate::store::code_revision_record::CodePathRetirement;

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

pub(crate) use crate::store::code_import_manifest::CodeImportManifest;

/// The `repo.import_approval` claim's value: the exact manifest, Baseline,
/// evidence and review an owner's promotion stood on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CodeImportApproval {
    pub(crate) schema_version: u8,
    pub(crate) manifest: EntityId,
    pub(crate) manifest_digest: String,
    pub(crate) baseline_revision: EntityId,
    /// The Baseline's revision fold, 64 lower-hex.
    pub(crate) baseline_fold: String,
    pub(crate) inventory_digest: String,
    pub(crate) plan_digest: String,
    /// The Baseline's fast and slow receipt input digests, in that order.
    pub(crate) evidence: Vec<String>,
    /// The owner-selected catalog, as its canonical JSON.
    pub(crate) catalog: String,
    pub(crate) catalog_digest: String,
    /// The saved review, or `None` for a catalog with no lenses.
    pub(crate) review: Option<EntityId>,
    pub(crate) approver: EntityId,
}

pub(crate) use crate::store::code_import_manifest::{manifest_digest, manifest_id};

/// An approval's deterministic claim id: the manifest, the Baseline fold,
/// the selected catalog, the effective review and the approving owner.
///
/// # Errors
/// An id derivation failure.
pub(crate) fn approval_id(approval: &CodeImportApproval) -> Result<EntityId> {
    let review = approval
        .review
        .map(|review| review.to_hex())
        .unwrap_or_default();
    entity_id_from_hash_material(
        APPROVAL_DOMAIN,
        &[
            approval.manifest.as_bytes(),
            approval.baseline_fold.as_bytes(),
            approval.catalog_digest.as_bytes(),
            review.as_bytes(),
            approval.approver.as_bytes(),
        ],
    )
}

/// The selected catalog's canonical JSON and its digest.
///
/// # Errors
/// An encoding failure.
pub(crate) fn catalog_digest(catalog: &LensCatalog) -> Result<(String, String)> {
    let json =
        serde_json::to_string(catalog).map_err(|_| invalid("import review catalog encode"))?;
    let digest = bytes_to_hex_lower(blake3::hash(json.as_bytes()).as_bytes());
    Ok((json, digest))
}

use crate::store::code_import_manifest::{claim_body, from_claim};

impl CodeImportApproval {
    /// Its claim, about the manifest it approves.
    ///
    /// # Errors
    /// An encoding failure.
    pub(crate) fn claim_body(&self) -> Result<ClaimBody> {
        claim_body(IMPORT_APPROVAL_PREDICATE, self.manifest, self)
    }

    /// The approval a claim holds.
    ///
    /// # Errors
    /// Another predicate, an inactive claim or a body that does not decode.
    pub(crate) fn from_claim(body: &ClaimBody) -> Result<Self> {
        let approval: Self = from_claim(body, IMPORT_APPROVAL_PREDICATE)?;
        if approval.schema_version != 1 || body.subject != ClaimSubject::Entity(approval.manifest) {
            return Err(Error::CorruptedIndex("an import approval's claim moved"));
        }
        Ok(approval)
    }
}
