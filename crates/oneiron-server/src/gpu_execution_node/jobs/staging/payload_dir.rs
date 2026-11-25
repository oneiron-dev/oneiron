//! The payload directory's ownership check (row R3c): the work directory's
//! path walked from `/`, each directory and symbolic link on it the engine's
//! or root's in a directory no other account renames in, before anything is
//! made, written or removed beneath it.

use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::StagingRefusal;

/// The mode bits that let the group or other accounts write in a directory.
const GROUP_OTHER_WRITE: u32 = 0o022;

/// The sticky bit: in such a directory only an entry's owner renames it.
const STICKY: u32 = 0o1000;

/// The most symbolic links the work directory's path may pass through.
const WORK_PATH_LINKS_MAX: usize = 40;

/// Whether the key's payload directory exists and is the engine's alone:
/// its work directory passes [`trusted_work_dir`], and it is a directory
/// (not a symbolic link) owned by the engine's account. With `make`, the
/// work directory's missing components and then the payload directory are
/// made (0755), each only once its parent passed. Path-based writes and
/// removals beneath it are then safe: no other account can change what the
/// path names.
pub(super) fn payload_dir_owned(payload_dir: &Path, make: bool) -> Result<bool, StagingRefusal> {
    let not_owned = |path: &Path, why: &str| {
        tracing::warn!(path = %path.display(), why, "job staging: the payload directory is not the engine's alone");
        StagingRefusal::WorkDirUnsafe
    };
    let (Some(work_dir), Some(name)) = (payload_dir.parent(), payload_dir.file_name()) else {
        return Err(not_owned(payload_dir, "it has no work directory"));
    };
    let Some(work_dir) = trusted_work_dir(work_dir, make)? else {
        return Ok(false);
    };
    let payload = work_dir.join(name);
    if make {
        match std::fs::DirBuilder::new().mode(0o755).create(&payload) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                tracing::warn!(payload_dir = %payload.display(), %error, "job staging: the payload directory was not made");
                return Err(StagingRefusal::CheckoutFailed);
            }
        }
    }
    let engine = rustix::process::geteuid().as_raw();
    match std::fs::symlink_metadata(&payload) {
        Ok(found) if found.is_dir() && found.uid() == engine => {}
        Ok(_) => {
            return Err(not_owned(
                &payload,
                "the payload directory is a link, not a directory, or not the engine's",
            ));
        }
        Err(error) if !make && error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(not_owned(&payload, &error.to_string())),
    }
    if make {
        // The job account passes through and reads; only the engine writes.
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o755)).map_err(
            |error| {
                tracing::warn!(payload_dir = %payload.display(), %error, "job staging: the payload directory's mode was not set");
                StagingRefusal::CheckoutFailed
            },
        )?;
    }
    Ok(true)
}

/// Walks `work_dir` from `/` one component at a time and answers the
/// directory it names, or `None` when a component is missing and `make` is
/// false. Each directory on the way is owned by root or the engine's account
/// and no other account renames in it (it is not writable by them, or it is
/// sticky). Each symbolic link on the way is owned by root or the engine's
/// account, and is followed from the directory that holds it, which passed
/// first. No other account can then change what the path names. With
/// `make`, a missing component is made (0755) once its parent passed. The
/// work directory itself is owned by the engine's account, and no other
/// account writes in it.
pub(in crate::gpu_execution_node::jobs) fn trusted_work_dir(
    work_dir: &Path,
    make: bool,
) -> Result<Option<PathBuf>, StagingRefusal> {
    let not_owned = |path: &Path, why: &str| {
        tracing::warn!(path = %path.display(), why, "job staging: the work directory is not the engine's alone");
        StagingRefusal::WorkDirUnsafe
    };
    if !work_dir.is_absolute() {
        return Err(not_owned(work_dir, "the path is not absolute"));
    }
    let engine = rustix::process::geteuid().as_raw();
    let owner_trusted = |found: &std::fs::Metadata| found.uid() == 0 || found.uid() == engine;
    let passes = |found: &std::fs::Metadata| {
        found.is_dir()
            && owner_trusted(found)
            && (found.mode() & GROUP_OTHER_WRITE == 0 || found.mode() & STICKY != 0)
    };
    let mut current = PathBuf::from("/");
    let root = std::fs::symlink_metadata(&current)
        .map_err(|error| not_owned(&current, &error.to_string()))?;
    if !passes(&root) {
        return Err(not_owned(&current, "another account may rename in it"));
    }
    // The components still to walk, the next one last.
    let mut pending = Vec::new();
    push_components(&mut pending, work_dir);
    let mut links = 0;
    while let Some(name) = pending.pop() {
        let Some(name) = name else {
            // `current` was walked with no link in it, so its parent passed.
            current.pop();
            continue;
        };
        let next = current.join(&name);
        let found = match std::fs::symlink_metadata(&next) {
            Ok(found) => found,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !make {
                    return Ok(None);
                }
                match std::fs::DirBuilder::new().mode(0o755).create(&next) {
                    // What another account made first is read below.
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        tracing::warn!(path = %next.display(), %error, "job staging: the work directory was not made");
                        return Err(StagingRefusal::CheckoutFailed);
                    }
                }
                std::fs::symlink_metadata(&next)
                    .map_err(|error| not_owned(&next, &error.to_string()))?
            }
            Err(error) => return Err(not_owned(&next, &error.to_string())),
        };
        if found.file_type().is_symlink() {
            links += 1;
            if !owner_trusted(&found) || links > WORK_PATH_LINKS_MAX {
                return Err(not_owned(
                    &next,
                    "a symbolic link another account owns, or too many links",
                ));
            }
            let target =
                std::fs::read_link(&next).map_err(|error| not_owned(&next, &error.to_string()))?;
            if target.is_absolute() {
                current = PathBuf::from("/");
            }
            push_components(&mut pending, &target);
            continue;
        }
        if !passes(&found) {
            return Err(not_owned(
                &next,
                "not a directory, or one another account owns or may rename in",
            ));
        }
        current = next;
    }
    let work = std::fs::symlink_metadata(&current)
        .map_err(|error| not_owned(&current, &error.to_string()))?;
    if work.uid() != engine || work.mode() & GROUP_OTHER_WRITE != 0 {
        return Err(not_owned(
            &current,
            "the work directory is not the engine's, or others may write in it",
        ));
    }
    Ok(Some(current))
}

/// Puts `path`'s components on `pending` so that its first is popped first:
/// a name, or `None` for `..`.
fn push_components(pending: &mut Vec<Option<std::ffi::OsString>>, path: &Path) {
    use std::path::Component;

    for component in path.components().rev() {
        match component {
            Component::Normal(name) => pending.push(Some(name.to_owned())),
            Component::ParentDir => pending.push(None),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
}
