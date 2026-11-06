//! A projected candidate's files translated onto the ORIGINAL (FIX 7608
//! slice 2b-ii-A, ASK E VisibleDiff, CALL H).
//!
//! Each file the agent changed in its masked copy is mapped onto the
//! ORIGINAL it stood for. A file the agent got as stored (no mark) takes
//! the submitted bytes and mode as authored. A masked file takes its
//! uniquely mapped edit, every protected span the agent did not touch kept
//! as stored; an unchanged one keeps the original. A sealed-file
//! placeholder changed, replaced or deleted holds with
//! `sealed_file_edited`; an edit with no unique mapping holds with
//! `projection_edit_conflict`. Untouched files never enter: they stay the
//! original inventory's. The submitted change is recorded beside the
//! canonical one, never in its place.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: the candidate intake calls it in 2b-ii-B"
)]

use crate::git_wire::ids::GitOid;
use crate::origin::secret_projection::edit::RepoProjectedFileCopy;
use crate::origin::secret_projection::edit::RepoProjectionDiffResult;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// One changed file of a projected push, as its preparation read it: the
/// ORIGINAL blob and bytes at the base, the copy the agent was given when
/// it differed from the original, and the blob and bytes it submitted
/// (none for a deletion).
pub struct ProjectedFileInput<'f> {
    pub path: String,
    pub original: Option<(GitOid, &'f [u8])>,
    pub copy: Option<(GitOid, RepoProjectedFileCopy<'f>)>,
    pub submitted: Option<(GitOid, &'f [u8])>,
}
