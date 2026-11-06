//! Retaining a mismatched installed model before its replacement is fetched.

use std::path::Path;

use super::{ArtifactError, ArtifactManifest, io_error, sync_dir};

/// Moves only the installed path into a unique sibling container. Once it
/// contains the old bytes, the container must outlive every later error.
pub(super) fn quarantine_installation(
    manifest: &ArtifactManifest,
    parent: &Path,
    dir: &Path,
    reason: &ArtifactError,
) -> Result<(), ArtifactError> {
    let container = tempfile::Builder::new()
        .prefix(&format!(".quarantine-{}-", manifest.revision))
        .tempdir_in(parent)
        .map_err(io_error(manifest, "creating quarantine in", parent))?;
    let retained = container.path().join("installed");
    std::fs::rename(dir, &retained).map_err(io_error(manifest, "quarantining", dir))?;
    let container = container.keep();
    sync_dir(manifest, &container)?;
    sync_dir(manifest, parent)?;
    tracing::warn!(
        model = %manifest.id,
        dir = %dir.display(),
        quarantine = %retained.display(),
        %reason,
        "model artifact quarantined; reinstalling"
    );
    Ok(())
}
