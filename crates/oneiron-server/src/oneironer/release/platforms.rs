//! The platform half of a fetch (FIX 6755): which archives a fetch places,
//! their extraction in staging, and the check that a placed bundle holds
//! each platform row whole or not at all.

use std::path::Path;

use super::{OneironerFetchError, OneironerRelease, ReleaseFile, catalogue, io_error};
use crate::oneironer::bundle::archive::{self, ArchiveError};
use crate::oneironer::bundle::{Manifest, Platform};

/// The platform archives a fetch places beside the common files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Platforms {
    /// The rows whose OS and architecture this build targets.
    Host,
    /// Every row: a supervisor placing a root other machines read.
    All,
    /// No row: the common files alone.
    None,
}

impl Platforms {
    pub(super) fn selects(self, row: &Platform) -> bool {
        match self {
            Self::Host => row.on_host(),
            Self::All => true,
            Self::None => false,
        }
    }
}

/// The platform rows a placed bundle holds, and those it does not.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Placement {
    pub(crate) installed: Vec<&'static str>,
    pub(crate) skipped: Vec<&'static str>,
}

/// Drops what an earlier run staged for a platform this one leaves out: it
/// is this staging's own, and a fetch places only what it selects.
pub(super) fn clear(
    staging: &Path,
    file: &ReleaseFile,
    row: &Platform,
) -> Result<(), OneironerFetchError> {
    let name: &str = &file.artifact.file;
    for path in [staging.join(name), staging.join(format!("{name}.partial"))] {
        if path.symlink_metadata().is_ok() {
            std::fs::remove_file(&path).map_err(io_error("removing", &path))?;
        }
    }
    archive::remove_extraction(staging, row.artifact()).map_err(archive_error(name))
}

/// Extracts a staged archive beside itself, keeping an earlier run's
/// extraction only while it still verifies against the archive.
pub(super) fn install(
    staging: &Path,
    file: &ReleaseFile,
    row: &Platform,
) -> Result<(), OneironerFetchError> {
    let name: &str = &file.artifact.file;
    let (tar, artifact) = (staging.join(name), row.artifact());
    let extracted = archive::extraction_dir(staging, artifact).map_err(archive_error(name))?;
    if extracted.symlink_metadata().is_ok()
        && archive::verify_extraction(&tar, artifact, &extracted).is_ok()
    {
        return Ok(());
    }
    archive::remove_extraction(staging, artifact).map_err(archive_error(name))?;
    archive::extract_verified(&tar, artifact, staging).map_err(archive_error(name))?;
    Ok(())
}

/// The platform rows of a placed bundle whose common files verified: each
/// is absent, or its pinned archive beside an extraction that verifies
/// against it; anything between is invalid. A row `selected` takes must be
/// there, since a placed bundle is never added to.
pub(super) fn verify(
    release: &OneironerRelease,
    dir: &Path,
    manifest: &Manifest,
    selected: Platforms,
) -> Result<Placement, OneironerFetchError> {
    let invalid = |reason: String| OneironerFetchError::ExistingInvalid {
        dir: dir.display().to_string(),
        reason,
    };
    let (mut placement, mut missing) = (Placement::default(), None);
    for (name, file, row) in catalogue::platform_rows(release, manifest)? {
        let archived: &str = &file.artifact.file;
        let tar = dir.join(archived);
        let extracted = archive::extraction_dir(dir, row.artifact())
            .map_err(|error| invalid(error.to_string()))?;
        let tar_placed = tar.symlink_metadata().is_ok();
        let tree_placed = extracted.symlink_metadata().is_ok();
        match (tar_placed, tree_placed) {
            (false, false) => {
                if selected.selects(row) {
                    missing.get_or_insert(name);
                }
                placement.skipped.push(name);
            }
            (true, true) => {
                archive::verify_extraction(&tar, row.artifact(), &extracted)
                    .map_err(|error| invalid(format!("{archived}: {error}")))?;
                placement.installed.push(name);
            }
            _ => {
                return Err(invalid(format!(
                    "{archived} is placed without its extraction"
                )));
            }
        }
    }
    if let Some(row) = missing {
        return Err(OneironerFetchError::PlatformNotPlaced {
            dir: dir.display().to_string(),
            row,
        });
    }
    Ok(placement)
}

fn archive_error(file: &str) -> impl FnOnce(ArchiveError) -> OneironerFetchError {
    let file = file.to_owned();
    move |error| OneironerFetchError::Archive { file, error }
}
