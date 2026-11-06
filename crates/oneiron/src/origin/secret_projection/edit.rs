//! Core half of `origin::secret_projection::edit`: its store-layer items live in `oneiron_store::origin::secret_projection::edit` and are
//! re-exported here; the items below stay in the engine.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: the projected candidate translation calls it in 2b-ii-B"
)]

pub(crate) use oneiron_store::origin::secret_projection::edit::*;

use super::REPO_OPAQUE_FILE_BYTES;
use crate::batch::secret_scan::{
    RetainedProjectionEdit, apply_retained_repo_projection_diff, is_container,
};
use crate::error::Result;
use crate::file_secret_marks::KeyPlaces;

/// The agent's `submitted` file mapped onto `original`, of which it was
/// given `copy`.
///
/// # Errors
/// An engine failure in a container reader.
pub(crate) fn apply_repo_projection_diff(
    original: &[u8],
    copy: RepoProjectedFileCopy<'_>,
    submitted: &[u8],
) -> Result<RepoProjectionDiffResult> {
    let (copy, places) = match copy {
        RepoProjectedFileCopy::Opaque if submitted == REPO_OPAQUE_FILE_BYTES => {
            return Ok(RepoProjectionDiffResult::Unchanged);
        }
        RepoProjectedFileCopy::Opaque => return Ok(RepoProjectionDiffResult::SealedFileEdited),
        RepoProjectedFileCopy::Masked { copy, places } => (copy, places),
    };
    if submitted == copy {
        return Ok(RepoProjectionDiffResult::Unchanged);
    }
    let members = places.iter().any(|(at, _)| !at.is_empty());
    if !members || !is_container(original) {
        let spans = places
            .iter()
            .filter(|(at, _)| at.is_empty())
            .flat_map(|(_, spans)| spans.iter().copied())
            .collect::<Vec<_>>();
        return Ok(visible_diff(original, copy, &spans, submitted).map_or(
            RepoProjectionDiffResult::ProjectionEditConflict,
            RepoProjectionDiffResult::Applied,
        ));
    }
    let mut leaf = |original: &[u8], copy: &[u8], submitted: &[u8], spans: &[(u64, u64)]| {
        visible_diff(original, copy, spans, submitted)
    };
    Ok(
        match apply_retained_repo_projection_diff(original, copy, submitted, places, &mut leaf)? {
            RetainedProjectionEdit::Rebuilt(bytes) => RepoProjectionDiffResult::Applied(bytes),
            RetainedProjectionEdit::Unmapped => RepoProjectionDiffResult::ProjectionEditConflict,
        },
    )
}
