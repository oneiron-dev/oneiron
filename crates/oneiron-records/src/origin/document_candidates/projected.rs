//! Moved from `crates/oneiron/src/origin/document_candidates/projected.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::origin::secret_projection::clearance::RepoProjectionHoldCause;
use oneiron_contracts::entity_id::EntityId;
pub(crate) use oneiron_store::origin::document_candidates::projected::*;
use serde::Deserialize;
use serde::Serialize;

/// One file of a projected candidate, by its path: the ORIGINAL blob its
/// copy stood for, the copy blob the agent was given, the blob it
/// submitted, the canonical blob its translation resolved and the typed
/// cause that holds it, if any. Git ids, lower hex; no content.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RepoProjectedCandidateFilePin {
    pub path: String,
    pub original_blob: Option<String>,
    pub copy_blob: Option<String>,
    pub submitted_blob: Option<String>,
    pub canonical_blob: Option<String>,
    pub cause: Option<RepoProjectionHoldCause>,
}

/// The immutable projection pins of a candidate received from a masked
/// copy: kept apart from the submitted COPY tips, so the canonical target
/// is never the submitted tree.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RepoProjectedCandidatePins {
    /// The masked copy's graph claim.
    pub graph: EntityId,
    /// The ingress proof's record id.
    pub ingress: EntityId,
    /// The submitted COPY old tip; none for a new branch.
    pub submitted_old: Option<String>,
    /// The submitted COPY new tip.
    pub submitted_new: String,
    /// The ORIGINAL commit the copy's old tip stood for.
    pub canonical_base: Option<String>,
    /// The canonical tree the translation resolved; none while a file has
    /// no unique translation.
    pub canonical_target_tree: Option<String>,
    /// Each changed file, in path order.
    pub files: Vec<RepoProjectedCandidateFilePin>,
}

impl RepoProjectedCandidatePins {
    /// The digest these pins enter a candidate's digest as: every pin,
    /// length-prefixed, under its own domain.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.repo_projection.candidate_pins.v1");
        let mut part = |field: &[u8]| {
            hasher.update(&(field.len() as u64).to_be_bytes());
            hasher.update(field);
        };
        let text = |field: Option<&String>| field.map_or("", String::as_str).to_owned();
        part(self.graph.as_bytes());
        part(self.ingress.as_bytes());
        part(text(self.submitted_old.as_ref()).as_bytes());
        part(self.submitted_new.as_bytes());
        part(text(self.canonical_base.as_ref()).as_bytes());
        part(text(self.canonical_target_tree.as_ref()).as_bytes());
        for file in &self.files {
            part(file.path.as_bytes());
            part(text(file.original_blob.as_ref()).as_bytes());
            part(text(file.copy_blob.as_ref()).as_bytes());
            part(text(file.submitted_blob.as_ref()).as_bytes());
            part(text(file.canonical_blob.as_ref()).as_bytes());
            part(
                file.cause
                    .map_or("", RepoProjectionHoldCause::as_str)
                    .as_bytes(),
            );
        }
        *hasher.finalize().as_bytes()
    }

    /// The cause the candidate holds on before any clearance: a file's
    /// (sealed-file edits first), or a conflict when no canonical target
    /// resolved.
    pub fn hold_cause(&self) -> Option<RepoProjectionHoldCause> {
        self.files
            .iter()
            .filter_map(|file| file.cause)
            .min()
            .or_else(|| {
                self.canonical_target_tree
                    .is_none()
                    .then_some(RepoProjectionHoldCause::ProjectionEditConflict)
            })
    }
}
