//! Pruning the result bodies beside checkpoint images.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::files::{body_entries, remove_unnamed, sync_dir};
use crate::recovery::checkpoint::{checkpoint_bodies_path, checkpoint_image_bodies};
use crate::store::BodyDir;
use crate::{Error, Result};

/// What one checkpoint body prune did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckpointBodyPruneReport {
    /// Body files no retained image names, each removed with its line
    /// index, and line indexes whose body is gone.
    pub removed: usize,
    /// Body files no retained image names, left for now: written within the
    /// last hour, or no regular file.
    pub kept: usize,
}

/// Removes from the `bodies/` directory beside the checkpoint images in
/// `dir` each body file, with its line index, that none of
/// `retained_images` names (OF-597). Every image in one directory shares
/// it, so `retained_images` is every image that stays in `dir`, of every
/// vault backed up there. A body written within the last hour stays, for a
/// snapshot still writing its bodies there; the caller keeps a prune from
/// overlapping a snapshot into `dir` otherwise.
///
/// # Errors
///
/// Refuses, removing nothing, when a retained image does not read whole or
/// keeps its bodies outside `dir`; filesystem errors as they occur.
pub fn prune_checkpoint_bodies(
    dir: &Path,
    retained_images: &[PathBuf],
) -> Result<CheckpointBodyPruneReport> {
    // An image's bodies sit beside it, so any name in `dir` finds the
    // directory its images share.
    let shared = checkpoint_bodies_path(&dir.join("image"));
    let mut named = HashSet::new();
    for image in retained_images {
        if checkpoint_bodies_path(image) != shared {
            return Err(Error::InvalidConfig(format!(
                "checkpoint image {} keeps its bodies outside {}",
                image.display(),
                dir.display()
            )));
        }
        named.extend(
            checkpoint_image_bodies(image)?
                .into_iter()
                .map(|(digest, _)| digest),
        );
    }
    let mut report = CheckpointBodyPruneReport::default();
    let Some(bodies) = BodyDir::at_path(&shared, false)? else {
        return Ok(report);
    };
    let now = SystemTime::now();
    for entry in body_entries(&bodies)? {
        let entry = entry?;
        if named.contains(&entry.digest) {
            continue;
        }
        if remove_unnamed(&bodies, &entry, now, None)? {
            report.removed += 1;
        } else if !entry.index {
            report.kept += 1;
        }
    }
    if report.removed > 0 {
        sync_dir(&bodies)?;
    }
    Ok(report)
}
