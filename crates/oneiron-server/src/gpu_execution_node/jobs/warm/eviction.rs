//! The cache pass's file work (row P2): what a cache path holds, and its removal. A path is
//! removed only when it is an entry directly in the box's cache directory, that directory is the
//! engine's alone (walked from `/` as the work directory is: [`trusted_work_dir`]), and the
//! engine's account owns the entry. It is first renamed to a name beginning
//! [`EVICTED_PREFIX`] in the same directory, under the admission lock, so no launch finds it half
//! removed; the files go after the lock is dropped, and a pass that did not complete is finished
//! by the next.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::gpu_execution_node::jobs::staging::trusted_work_dir;
use crate::gpu_execution_node::node_settings::EVICTED_PREFIX;

/// The most entries one measurement reads beneath a cache path; past it the count stops there,
/// and the figure is a lower bound.
const MEASURE_ENTRIES_MAX: u64 = 4_000_000;

/// The cache directory as the walk resolves it, when it is the engine's alone.
pub(super) fn trusted_cache_dir(cache_dir: &Path) -> Option<PathBuf> {
    match trusted_work_dir(cache_dir, false) {
        Ok(Some(resolved)) => Some(resolved),
        Ok(None) => None,
        Err(refusal) => {
            tracing::warn!(cache_dir = %cache_dir.display(), %refusal, "warm keys: the cache directory is not the engine's alone; nothing is removed");
            None
        }
    }
}

/// The disk `path` uses, its own entry and everything beneath it on the same file system, with
/// no symbolic link followed. `None` when the path does not exist.
pub(super) fn measure(path: &Path) -> Option<u64> {
    let top = std::fs::symlink_metadata(path).ok()?;
    let device = top.dev();
    let mut bytes = top.blocks().saturating_mul(512);
    let mut seen = 1_u64;
    let mut pending = if top.is_dir() {
        vec![path.to_path_buf()]
    } else {
        Vec::new()
    };
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > MEASURE_ENTRIES_MAX {
                tracing::warn!(path = %path.display(), "warm keys: a cache path holds more entries than one measurement reads; its figure is a lower bound");
                return Some(bytes);
            }
            let Ok(found) = entry.metadata() else {
                continue;
            };
            bytes = bytes.saturating_add(found.blocks().saturating_mul(512));
            if found.is_dir() && found.dev() == device {
                pending.push(entry.path());
            }
        }
    }
    Some(bytes)
}

/// Renames the cache path `path` out of use, inside `cache_dir`, and answers the new path.
///
/// # Errors
///
/// Why it was left: it is not an entry directly in the cache directory, the engine's account
/// does not own it, or the rename failed.
pub(super) fn take_out_of_use(
    cache_dir: &Path,
    path: &Path,
    now_ms: u64,
) -> Result<PathBuf, String> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err("the path has no directory".to_owned());
    };
    let in_cache_dir = trusted_work_dir(parent, false)
        .ok()
        .flatten()
        .is_some_and(|resolved| resolved == cache_dir);
    if !in_cache_dir {
        return Err("the path is not an entry directly in the cache directory".to_owned());
    }
    let entry = cache_dir.join(name);
    let found = std::fs::symlink_metadata(&entry).map_err(|error| error.to_string())?;
    if found.uid() != rustix::process::geteuid().as_raw() {
        return Err("the engine's account does not own it".to_owned());
    }
    let taken = cache_dir.join(format!(
        "{EVICTED_PREFIX}{}-{now_ms}",
        name.to_string_lossy()
    ));
    std::fs::rename(&entry, &taken).map_err(|error| error.to_string())?;
    Ok(taken)
}

/// Removes a path [`take_out_of_use`] renamed: a directory with what it holds, or the entry
/// itself (a symbolic link is removed, never followed).
pub(super) fn remove_taken(taken: &Path) {
    let removed = match std::fs::symlink_metadata(taken) {
        Ok(found) if found.is_dir() => std::fs::remove_dir_all(taken),
        Ok(_) => std::fs::remove_file(taken),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    };
    if let Err(error) = removed {
        tracing::warn!(path = %taken.display(), %error, "warm keys: a removed cache path was not deleted; the next pass tries again");
    }
}

/// Removes what an earlier pass renamed out of use and did not delete.
pub(super) fn remove_evicted(cache_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(cache_dir) else {
        return;
    };
    let engine = rustix::process::geteuid().as_raw();
    for entry in entries.flatten() {
        let taken = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(EVICTED_PREFIX));
        let owned = entry.metadata().is_ok_and(|found| found.uid() == engine);
        if taken && owned {
            remove_taken(&entry.path());
        }
    }
}
