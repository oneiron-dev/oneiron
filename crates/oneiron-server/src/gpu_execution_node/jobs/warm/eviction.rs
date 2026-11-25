//! The cache pass's file work (row P2): what a cache path holds, and its removal. A path is
//! removed only when it is a directory directly in the box's cache directory, that directory is
//! the engine's alone (walked from `/` as the work directory is: [`trusted_work_dir`]), the
//! engine's or the job account owns the entry, and no mount lies at it or beneath it.
//!
//! It is first moved into [`EVICTED_DIR_NAME`] inside the cache directory, under the admission
//! lock, so no launch finds it half removed. The file's check lets no warm path lie in that
//! directory, so all it holds is what passes moved there. The files go after the lock is
//! dropped, by a walk from open directories that follows no symbolic link and never leaves the
//! entry's file system; a pass that did not complete is finished by the next.

use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Dev, FileType, Mode, OFlags};

use crate::gpu_execution_node::jobs::staging::trusted_work_dir;
use crate::gpu_execution_node::node_settings::EVICTED_DIR_NAME;

/// The most entries one measurement reads beneath a cache path; past it the count stops there,
/// and the figure is a lower bound.
const MEASURE_ENTRIES_MAX: u64 = 4_000_000;

/// The deepest directory a removal descends to; a deeper tree is left, with a warning.
const REMOVE_DEPTH_MAX: usize = 256;

/// Where Linux lists the mounts this process sees.
const MOUNT_INFO_PATH: &str = "/proc/self/mountinfo";

/// Where the system names its accounts.
const ACCOUNTS_PATH: &str = "/etc/passwd";

/// The accounts whose cache entries a pass may remove: the engine's, and the job unit's when the
/// system's account file names it.
#[derive(Debug, Clone, Copy)]
pub(super) struct EntryOwners {
    engine: u32,
    job: Option<u32>,
}

impl EntryOwners {
    /// The engine's account and `job_account`'s.
    pub(super) fn of(job_account: &str) -> Self {
        Self {
            engine: rustix::process::geteuid().as_raw(),
            job: account_uid(job_account),
        }
    }

    fn admit(self, uid: u32) -> bool {
        uid == self.engine || Some(uid) == self.job
    }
}

/// The id of the account `name`, as the system's account file names it.
fn account_uid(name: &str) -> Option<u32> {
    let accounts = std::fs::read_to_string(ACCOUNTS_PATH).ok()?;
    accounts.lines().find_map(|line| {
        let mut fields = line.split(':');
        if fields.next()? != name {
            return None;
        }
        fields.nth(1)?.parse().ok()
    })
}

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

/// Whether a mount lies at `path` or beneath it. Where the system does not list its mounts
/// (not Linux), the removal's own walk still stops at another file system.
fn mount_at_or_beneath(path: &Path) -> bool {
    let mounts = match std::fs::read_to_string(MOUNT_INFO_PATH) {
        Ok(mounts) => mounts,
        // The list cannot be read on Linux: take a mount to be there.
        Err(_) => return cfg!(target_os = "linux"),
    };
    mounts
        .lines()
        .filter_map(|line| line.split(' ').nth(4))
        .any(|point| {
            Path::new(std::ffi::OsStr::from_bytes(&unescape_mount_point(point))).starts_with(path)
        })
}

/// A mount point as the mount list writes it: a space, a tab, a newline and a backslash as
/// `\` and three octal digits.
fn unescape_mount_point(point: &str) -> Vec<u8> {
    let bytes = point.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let octal = bytes.get(index + 1..index + 4).and_then(|digits| {
            let text = std::str::from_utf8(digits).ok()?;
            u8::from_str_radix(text, 8).ok()
        });
        match (bytes[index], octal) {
            (b'\\', Some(byte)) => {
                out.push(byte);
                index += 4;
            }
            (byte, _) => {
                out.push(byte);
                index += 1;
            }
        }
    }
    out
}

/// The directory the cache pass moves removed caches into, inside `cache_dir`: made with mode
/// 0700 when `create` and it is absent. `None` when it is absent and not made.
///
/// # Errors
///
/// It is not a directory the engine's account owns and only it may write in.
fn evicted_dir(cache_dir: &Path, create: bool) -> Result<Option<PathBuf>, String> {
    let evicted = cache_dir.join(EVICTED_DIR_NAME);
    match std::fs::symlink_metadata(&evicted) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !create {
                return Ok(None);
            }
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&evicted)
                .map_err(|error| error.to_string())?;
        }
        Err(error) => return Err(error.to_string()),
    }
    let found = std::fs::symlink_metadata(&evicted).map_err(|error| error.to_string())?;
    let own = found.file_type().is_dir()
        && found.uid() == rustix::process::geteuid().as_raw()
        && found.mode() & 0o022 == 0;
    if !own {
        return Err(format!(
            "{} is not a directory the engine's account alone writes in",
            evicted.display()
        ));
    }
    Ok(Some(evicted))
}

/// Moves the cache path `path` out of use, into the removed caches' directory inside
/// `cache_dir`, and answers the new path.
///
/// # Errors
///
/// Why it was left: it is not a directory directly in the cache directory, neither the engine's
/// nor the job account owns it, a mount lies at it or beneath it, or the move failed.
pub(super) fn take_out_of_use(
    cache_dir: &Path,
    path: &Path,
    owners: EntryOwners,
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
    if !found.file_type().is_dir() {
        return Err("it is not a directory".to_owned());
    }
    if !owners.admit(found.uid()) {
        return Err("neither the engine's nor the job account owns it".to_owned());
    }
    if mount_at_or_beneath(&entry) {
        return Err("a mount lies at it or beneath it".to_owned());
    }
    let evicted = evicted_dir(cache_dir, true)?
        .ok_or_else(|| "the removed caches' directory was not made".to_owned())?;
    let taken = evicted.join(format!("{}-{now_ms}", name.to_string_lossy()));
    std::fs::rename(&entry, &taken).map_err(|error| error.to_string())?;
    Ok(taken)
}

/// Removes a path [`take_out_of_use`] moved: a directory with what it holds, walked from open
/// directories with no symbolic link followed and no other file system entered, or the entry
/// itself.
pub(super) fn remove_taken(taken: &Path) {
    if let Err(error) = remove_tree(taken) {
        tracing::warn!(path = %taken.display(), %error, "warm keys: a removed cache path was not deleted; the next pass tries again");
    }
}

fn remove_tree(taken: &Path) -> std::io::Result<()> {
    let (Some(parent), Some(name)) = (taken.parent(), taken.file_name()) else {
        return Ok(());
    };
    if mount_at_or_beneath(taken) {
        return Err(std::io::Error::other("a mount lies at it or beneath it"));
    }
    let parent = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let device = rustix::fs::fstat(&parent)?.st_dev;
    let name = CString::new(name.as_bytes()).map_err(std::io::Error::other)?;
    match remove_at(parent.as_fd(), &name, device, 0) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        done => done,
    }
}

/// Removes `name` in the open directory `dir`: a directory only on the file system `device`,
/// what it holds first.
fn remove_at(dir: BorrowedFd<'_>, name: &CStr, device: Dev, depth: usize) -> std::io::Result<()> {
    let found = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if FileType::from_raw_mode(found.st_mode) != FileType::Directory {
        rustix::fs::unlinkat(dir, name, AtFlags::empty())?;
        return Ok(());
    }
    if found.st_dev != device {
        return Err(std::io::Error::other(
            "another file system is mounted beneath it",
        ));
    }
    if depth >= REMOVE_DEPTH_MAX {
        return Err(std::io::Error::other(format!(
            "it nests deeper than {REMOVE_DEPTH_MAX} directories"
        )));
    }
    let inner = rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let opened = rustix::fs::fstat(&inner)?;
    if opened.st_dev != found.st_dev || opened.st_ino != found.st_ino {
        return Err(std::io::Error::other("it changed while it was removed"));
    }
    // Every name is read before any is removed: removing while reading may skip entries.
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(&inner)? {
        let entry = entry?;
        let child = entry.file_name();
        if child != c"." && child != c".." {
            names.push(child.to_owned());
        }
    }
    for child in &names {
        remove_at(inner.as_fd(), child, device, depth + 1)?;
    }
    rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR)?;
    Ok(())
}

/// Removes what an earlier pass moved out of use and did not delete.
pub(super) fn remove_evicted(cache_dir: &Path) {
    let evicted = match evicted_dir(cache_dir, false) {
        Ok(Some(evicted)) => evicted,
        Ok(None) => return,
        Err(why) => {
            tracing::warn!(cache_dir = %cache_dir.display(), %why, "warm keys: the removed caches' directory is left as it is");
            return;
        }
    };
    let Ok(entries) = std::fs::read_dir(&evicted) else {
        return;
    };
    for entry in entries.flatten() {
        remove_taken(&entry.path());
    }
}
