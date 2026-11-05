//! Reviewed repository import anchors, manifest digests and raw claim codecs.

use crate::code_snapshot::ids::entity_id_from_hash_material;
use crate::code_tree_blob::CodeTreeBlob;
use crate::write_envelope::claim_body::ClaimBody;
use crate::write_envelope::claim_body::ClaimSubject;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The engine-owned predicate of an import manifest.
pub const IMPORT_MANIFEST_PREDICATE: &str = "repo.import_manifest";

const MANIFEST_DOMAIN: &[u8] = b"oneiron:code-import-manifest:v1";
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

/// The `repo.import_manifest` claim's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeImportManifest {
    pub schema_version: u8,
    pub anchor: CodeImportAnchor,
    /// The complete all-blob inventory digest, the same algorithm a tested
    /// revision's `inventory_digest` uses, 64 lower-hex.
    pub inventory_digest: String,
    /// The manifest digest, 64 lower-hex.
    pub digest: String,
}

/// The digest of one manifest: every anchor field and the complete sorted
/// inventory, each path's Git object, BLAKE3 hash, size and mode. The
/// claim's own id, this digest and any time are not in it.
pub fn manifest_digest(
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
pub fn manifest_id(digest: &str) -> Result<EntityId> {
    entity_id_from_hash_material(MANIFEST_DOMAIN, &[digest.as_bytes()])
}

/// An engine-owned, observed, active claim about `subject` holding `record`.
pub fn claim_body<T: Serialize>(
    predicate: &str,
    subject: EntityId,
    record: &T,
) -> Result<ClaimBody> {
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
pub fn from_claim<T: for<'de> Deserialize<'de>>(body: &ClaimBody, predicate: &str) -> Result<T> {
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
    pub fn claim_body(&self) -> Result<ClaimBody> {
        claim_body(IMPORT_MANIFEST_PREDICATE, self.anchor.repo, self)
    }

    /// The manifest a claim holds.
    ///
    /// # Errors
    /// Another predicate, an inactive claim or a body that does not decode.
    pub fn from_claim(body: &ClaimBody) -> Result<Self> {
        let manifest: Self = from_claim(body, IMPORT_MANIFEST_PREDICATE)?;
        if manifest.schema_version != 1
            || body.subject != ClaimSubject::Entity(manifest.anchor.repo)
        {
            return Err(Error::CorruptedIndex("an import manifest's claim moved"));
        }
        Ok(manifest)
    }
}
