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
pub(crate) const IMPORT_MANIFEST_PREDICATE: &str = "repo.import_manifest";
/// The engine-owned predicate of an untouched-byte import approval.
pub(crate) const IMPORT_APPROVAL_PREDICATE: &str = "repo.import_approval";

const MANIFEST_DOMAIN: &[u8] = b"oneiron:code-import-manifest:v1";
const APPROVAL_DOMAIN: &[u8] = b"oneiron:code-import-approval:v1";

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(reason))
}

/// What one import binds: the served repo's CODE anchor, its PROJECT, the
/// served name and object store, the admitted ref and exact chosen commit
/// with its tree, the receive-pack publication and provenance that admitted
/// it, and the distinct snapshot artifact the import wrote. Three
/// identities stay apart: `repo` (the served anchor), `snapshot` (the
/// imported snapshot) and the object store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeImportAnchor {
    pub repo: EntityId,
    pub project: EntityId,
    /// The served name, with no `.git` suffix.
    pub served_repo: String,
    /// The served object store's hex identity.
    pub object_store: String,
    /// The full admitted ref.
    pub source_ref: String,
    /// The chosen commit, 40 lower-hex.
    pub source_commit: String,
    /// Its root tree, 40 lower-hex.
    pub source_tree: String,
    /// The Published receive-pack publication that admitted the source.
    pub admission_receipt: EntityId,
    /// That publication's receive-pack provenance.
    pub receive_provenance: EntityId,
    /// The imported snapshot's CODE_ARTIFACT.
    pub snapshot: EntityId,
    /// Its fork hash, 64 lower-hex.
    pub snapshot_fork_hash: String,
}

/// One retired path of a tested queue revision: the exact predecessor it
/// removed, its document if it had one, and the reviewed operation and
/// review that retired it. No producer is admitted before G4 PR2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodePathRetirement {
    pub previous: CodeTreeBlob,
    pub document: Option<CodeDocumentFrontier>,
    pub operation_receipt: EntityId,
    pub review_ref: EntityId,
}

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

/// The `repo.import_manifest` claim's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CodeImportManifest {
    pub(crate) schema_version: u8,
    pub(crate) anchor: CodeImportAnchor,
    /// The complete all-blob inventory digest, the same algorithm a tested
    /// revision's `inventory_digest` uses, 64 lower-hex.
    pub(crate) inventory_digest: String,
    /// The manifest digest, 64 lower-hex.
    pub(crate) digest: String,
}

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

/// The digest of one manifest: every anchor field and the complete sorted
/// inventory, each path's Git object, BLAKE3 hash, size and mode. The
/// claim's own id, this digest and any time are not in it.
pub(crate) fn manifest_digest(
    anchor: &CodeImportAnchor,
    blobs: &BTreeMap<String, CodeTreeBlob>,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MANIFEST_DOMAIN);
    let ids = [
        anchor.repo,
        anchor.project,
        anchor.admission_receipt,
        anchor.receive_provenance,
        anchor.snapshot,
    ];
    for id in &ids {
        hasher.update(id.as_bytes());
    }
    for part in [
        &anchor.served_repo,
        &anchor.object_store,
        &anchor.source_ref,
        &anchor.source_commit,
        &anchor.source_tree,
        &anchor.snapshot_fork_hash,
    ] {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.update(&(blobs.len() as u64).to_be_bytes());
    for (path, blob) in blobs {
        for part in [path.as_bytes(), blob.git_oid.as_bytes()] {
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        hasher.update(&blob.content_hash);
        hasher.update(&blob.size_bytes.to_be_bytes());
        hasher.update(&blob.mode.to_be_bytes());
    }
    bytes_to_hex_lower(hasher.finalize().as_bytes())
}

/// A manifest's deterministic claim id, from its digest.
///
/// # Errors
/// An id derivation failure.
pub(crate) fn manifest_id(digest: &str) -> Result<EntityId> {
    entity_id_from_hash_material(MANIFEST_DOMAIN, &[digest.as_bytes()])
}

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

/// An engine-owned, observed, active claim about `subject` holding `record`.
fn claim_body<T: Serialize>(predicate: &str, subject: EntityId, record: &T) -> Result<ClaimBody> {
    let value = rmpv::ext::to_value(record).map_err(|_| invalid("import record encode"))?;
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    // Engine bookkeeping of what was imported and approved, never a
    // generic claim a caller could write.
    body.source = Some(ClaimSource::Observed);
    Ok(body)
}

/// `body`'s record, when it is an active claim of `predicate`; any other
/// shape is corruption.
fn from_claim<T: for<'de> Deserialize<'de>>(body: &ClaimBody, predicate: &str) -> Result<T> {
    if body.predicate != predicate || body.lifecycle != ClaimLifecycleStatus::Active {
        return Err(Error::CorruptedIndex("an import record's claim moved"));
    }
    rmpv::ext::from_value(body.value.clone()).map_err(|_| invalid("import record decode"))
}

impl CodeImportManifest {
    /// Its claim, about the served anchor.
    ///
    /// # Errors
    /// An encoding failure.
    pub(crate) fn claim_body(&self) -> Result<ClaimBody> {
        claim_body(IMPORT_MANIFEST_PREDICATE, self.anchor.repo, self)
    }

    /// The manifest a claim holds.
    ///
    /// # Errors
    /// Another predicate, an inactive claim or a body that does not decode.
    pub(crate) fn from_claim(body: &ClaimBody) -> Result<Self> {
        let manifest: Self = from_claim(body, IMPORT_MANIFEST_PREDICATE)?;
        if manifest.schema_version != 1
            || body.subject != ClaimSubject::Entity(manifest.anchor.repo)
        {
            return Err(Error::CorruptedIndex("an import manifest's claim moved"));
        }
        Ok(manifest)
    }
}

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
