//! Core half of `origin::document_candidates::projected_files`: its store-layer items live in `oneiron_store::origin::document_candidates::projected_files` and are
//! re-exported here; the items below stay in the engine.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: the candidate intake calls it in 2b-ii-B"
)]

pub(crate) use oneiron_store::origin::document_candidates::projected_files::*;

use super::projected::RepoProjectedCandidateFilePin;
use crate::error::{Error, Result};
use crate::git_wire::GitOid;
use crate::origin::secret_projection::clearance::RepoProjectionHoldCause;
use crate::origin::secret_projection::edit::{
    RepoProjectedFileCopy, RepoProjectionDiffResult, apply_repo_projection_diff,
};

/// What one file's canonical after-state is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProjectedCanonicalAfter {
    /// These bytes, the translated edit or the agent's own.
    Bytes(Vec<u8>),
    /// The file is deleted, as authored.
    Delete,
    /// The original stays as stored.
    KeepOriginal,
    /// No executable translation: the typed cause holds it.
    Held(RepoProjectionHoldCause),
}

/// One translated file: its pin and its canonical after-state. The pin's
/// canonical blob is filled once the after-state's bytes are written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectedCandidateFile {
    pub(crate) pin: RepoProjectedCandidateFilePin,
    pub(crate) after: ProjectedCanonicalAfter,
}

/// Each of `files` translated onto its ORIGINAL, in path order.
///
/// # Errors
/// A masked copy with no original behind it, or a container reader's
/// engine failure.
pub(crate) fn prepare_projected_candidate_files(
    mut files: Vec<ProjectedFileInput<'_>>,
) -> Result<Vec<ProjectedCandidateFile>> {
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files.into_iter().map(translate_file).collect()
}

fn translate_file(file: ProjectedFileInput<'_>) -> Result<ProjectedCandidateFile> {
    let after = match (&file.copy, &file.original, &file.submitted) {
        // Got as stored: the agent's edit as authored.
        (None, _, Some((_, bytes))) => ProjectedCanonicalAfter::Bytes(bytes.to_vec()),
        (None, _, None) => ProjectedCanonicalAfter::Delete,
        (Some(_), None, _) => {
            return Err(Error::InvariantViolation(
                "a masked copy file has no original behind it",
            ));
        }
        (Some((_, RepoProjectedFileCopy::Opaque)), Some(_), None) => {
            ProjectedCanonicalAfter::Held(RepoProjectionHoldCause::SealedFileEdited)
        }
        (Some((_, RepoProjectedFileCopy::Masked { .. })), Some(_), None) => {
            ProjectedCanonicalAfter::Delete
        }
        (Some((_, copy)), Some((_, original)), Some((_, submitted))) => {
            match apply_repo_projection_diff(original, *copy, submitted)? {
                RepoProjectionDiffResult::Unchanged => ProjectedCanonicalAfter::KeepOriginal,
                RepoProjectionDiffResult::Applied(bytes) => ProjectedCanonicalAfter::Bytes(bytes),
                RepoProjectionDiffResult::SealedFileEdited => {
                    ProjectedCanonicalAfter::Held(RepoProjectionHoldCause::SealedFileEdited)
                }
                RepoProjectionDiffResult::ProjectionEditConflict => {
                    ProjectedCanonicalAfter::Held(RepoProjectionHoldCause::ProjectionEditConflict)
                }
            }
        }
    };
    let blob = |oid: Option<&GitOid>| oid.map(|oid| oid.as_str().to_owned());
    let pin = RepoProjectedCandidateFilePin {
        path: file.path,
        original_blob: blob(file.original.as_ref().map(|(oid, _)| oid)),
        copy_blob: blob(file.copy.as_ref().map(|(oid, _)| oid)),
        submitted_blob: blob(file.submitted.as_ref().map(|(oid, _)| oid)),
        canonical_blob: match &after {
            ProjectedCanonicalAfter::KeepOriginal => {
                blob(file.original.as_ref().map(|(oid, _)| oid))
            }
            _ => None,
        },
        cause: match &after {
            ProjectedCanonicalAfter::Held(cause) => Some(*cause),
            _ => None,
        },
    };
    Ok(ProjectedCandidateFile { pin, after })
}
