//! The cache pass's file work (row P2): what a cache path holds, and its removal. A path is
//! removed only when it is a directory directly in the box's cache directory, that directory is
//! the engine's alone (walked from `/` as the work directory is: [`trusted_work_dir`]), the
//! engine's or the job account owns the entry, the engine's account can empty it, no mount lies
//! at it or beneath it, and no other warm key's path lies in it where the file system resolves
//! that path.
//!
//! It is first moved into [`EVICTED_DIR_NAME`] inside the cache directory ([`Trash`]), under the
//! admission lock, so no launch finds it half removed, and the warm-key table records what was
//! moved (its name there and its inode). Only a recorded entry is ever deleted from that
//! directory: anything else found there is left. The files go after the lock is dropped, by a
//! walk from open directories that follows no symbolic link and crosses no mount (Linux's
//! `openat2` with `RESOLVE_NO_XDEV`, so a bind mount made during the walk stops it too; where
//! that open does not exist, nothing is deleted). A deletion that did not complete is tried
//! again by the next pass.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Dev, FileType, Mode, OFlags};

use super::table::EvictedRecord;
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

/// How a removal opens each directory: no symbolic link followed.
const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

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

/// What a cache path holds, as [`measure`] reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Measured {
    /// The disk it uses: its own entry and everything beneath it on the same file system.
    pub(super) bytes: u64,
    /// The engine's account can empty every directory in it: the engine runs as root, or its
    /// account owns each of them with write and search permission, and every one was read.
    pub(super) emptiable: bool,
}

/// What `path` holds, with no symbolic link followed. `None` when the path does not exist.
pub(super) fn measure(path: &Path) -> Option<Measured> {
    let top = std::fs::symlink_metadata(path).ok()?;
    let device = top.dev();
    let engine = rustix::process::geteuid().as_raw();
    let can_empty = |found: &std::fs::Metadata| {
        engine == 0 || (found.uid() == engine && found.mode() & 0o300 == 0o300)
    };
    let mut measured = Measured {
        bytes: top.blocks().saturating_mul(512),
        emptiable: !top.is_dir() || can_empty(&top),
    };
    let mut seen = 1_u64;
    let mut pending = if top.is_dir() {
        vec![path.to_path_buf()]
    } else {
        Vec::new()
    };
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            measured.emptiable = false;
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > MEASURE_ENTRIES_MAX {
                tracing::warn!(path = %path.display(), "warm keys: a cache path holds more entries than one measurement reads; its figure is a lower bound");
                measured.emptiable = false;
                return Some(measured);
            }
            let Ok(found) = entry.metadata() else {
                continue;
            };
            measured.bytes = measured
                .bytes
                .saturating_add(found.blocks().saturating_mul(512));
            if found.is_dir() {
                measured.emptiable &= can_empty(&found);
                if found.dev() == device {
                    pending.push(entry.path());
                }
            }
        }
    }
    Some(measured)
}

/// Whether a mount lies at `path` or beneath it. Where the system does not list its mounts
/// (not Linux), nothing is deleted anyway ([`open_beneath`]).
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

/// The directory the cache pass moves removed caches into, [`EVICTED_DIR_NAME`] inside the cache
/// directory, held open beside the cache directory.
#[derive(Debug)]
pub(super) struct Trash {
    cache: OwnedFd,
    dir: OwnedFd,
    /// The file system the cache directory and this directory lie on.
    device: Dev,
    /// The cache directory where the file system resolves it.
    cache_real: PathBuf,
    path: PathBuf,
}

impl Trash {
    /// Opens the removed caches' directory inside `cache_dir` (as [`trusted_cache_dir`] resolved
    /// it), made with mode 0700 when it is absent.
    ///
    /// # Errors
    ///
    /// It is not a directory the engine's account owns and only it may enter, it lies on another
    /// file system than the cache directory, or a mount lies at it or beneath it.
    pub(super) fn open(cache_dir: &Path) -> Result<Self, String> {
        let cache = rustix::fs::open(cache_dir, DIR_FLAGS, Mode::empty())
            .map_err(|error| error.to_string())?;
        match rustix::fs::mkdirat(&cache, EVICTED_DIR_NAME, Mode::RWXU) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(error.to_string()),
        }
        let dir = rustix::fs::openat(&cache, EVICTED_DIR_NAME, DIR_FLAGS, Mode::empty())
            .map_err(|error| error.to_string())?;
        let path = cache_dir.join(EVICTED_DIR_NAME);
        let found = rustix::fs::fstat(&dir).map_err(|error| error.to_string())?;
        let device = rustix::fs::fstat(&cache)
            .map_err(|error| error.to_string())?
            .st_dev;
        if found.st_uid != rustix::process::geteuid().as_raw() || found.st_mode & 0o077 != 0 {
            return Err(format!(
                "{} is not a directory the engine's account alone may enter",
                path.display()
            ));
        }
        if found.st_dev != device || mount_at_or_beneath(&path) {
            return Err(format!("a mount lies at {} or beneath it", path.display()));
        }
        let cache_real = std::fs::canonicalize(cache_dir).map_err(|error| error.to_string())?;
        Ok(Self {
            cache,
            dir,
            device,
            cache_real,
            path,
        })
    }

    /// This directory where the file system resolves it: no warm path may lie in it.
    pub(super) fn real_path(&self) -> PathBuf {
        self.cache_real.join(EVICTED_DIR_NAME)
    }

    /// Moves the cache path `path` out of use, into this directory, and answers what to record.
    ///
    /// # Errors
    ///
    /// Why it was left: it is not a directory directly in the cache directory, neither the
    /// engine's nor the job account owns it, a mount lies at it or beneath it, a path of
    /// `protected` (other warm keys' paths, resolved) lies in it, or the move failed.
    pub(super) fn take(
        &self,
        cache_dir: &Path,
        path: &Path,
        owners: EntryOwners,
        protected: &[PathBuf],
        now_ms: u64,
    ) -> Result<EvictedRecord, String> {
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
        let found = rustix::fs::statat(&self.cache, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| error.to_string())?;
        if FileType::from_raw_mode(found.st_mode) != FileType::Directory {
            return Err("it is not a directory".to_owned());
        }
        if !owners.admit(found.st_uid) {
            return Err("neither the engine's nor the job account owns it".to_owned());
        }
        if mount_at_or_beneath(&cache_dir.join(name)) {
            return Err("a mount lies at it or beneath it".to_owned());
        }
        let real = self.cache_real.join(name);
        if protected.iter().any(|other| other.starts_with(&real)) {
            return Err("another warm key's path lies in it".to_owned());
        }
        let taken = format!("{}-{now_ms}", name.to_string_lossy());
        rustix::fs::renameat(&self.cache, name, &self.dir, taken.as_str())
            .map_err(|error| error.to_string())?;
        let moved = rustix::fs::statat(&self.dir, taken.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| error.to_string())?;
        Ok(EvictedRecord {
            name: taken,
            ino: moved.st_ino,
        })
    }

    /// Deletes the entry `record` names when the entry there is the one the pass moved: a
    /// directory with what it holds, walked from open directories with no symbolic link
    /// followed and no mount crossed. An entry already gone counts as deleted.
    ///
    /// # Errors
    ///
    /// Why it was left: another entry is there now, a mount lies at it or beneath it, or the
    /// walk failed.
    pub(super) fn delete(&self, record: &EvictedRecord) -> Result<(), String> {
        let name = CString::new(record.name.as_bytes()).map_err(|error| error.to_string())?;
        let found = match rustix::fs::statat(&self.dir, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
        {
            Ok(found) => found,
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(error) => return Err(error.to_string()),
        };
        if found.st_ino != record.ino || found.st_dev != self.device {
            return Err("the entry there is not the one the pass moved".to_owned());
        }
        if mount_at_or_beneath(&self.path.join(&record.name)) {
            return Err("a mount lies at it or beneath it".to_owned());
        }
        match remove_at(self.dir.as_fd(), &name, self.device, 0) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            done => done.map_err(|error| error.to_string()),
        }
    }

    /// How many entries of this directory no record names: they are left as they are.
    pub(super) fn unrecorded(&self, records: &BTreeMap<String, EvictedRecord>) -> usize {
        let Ok(entries) = rustix::fs::Dir::read_from(&self.dir) else {
            return 0;
        };
        entries
            .flatten()
            .filter(|entry| {
                let name = entry.file_name();
                name != c"."
                    && name != c".."
                    && name
                        .to_str()
                        .map_or(true, |name| !records.contains_key(name))
            })
            .count()
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
    let inner = open_beneath(dir, name)?;
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

/// Opens the directory `name` in `dir` with no symbolic link followed and no mount crossed:
/// the open fails at a mount there, a bind mount of the same file system included.
#[cfg(target_os = "linux")]
fn open_beneath(dir: BorrowedFd<'_>, name: &CStr) -> std::io::Result<OwnedFd> {
    use rustix::fs::ResolveFlags;
    Ok(rustix::fs::openat2(
        dir,
        name,
        DIR_FLAGS,
        Mode::empty(),
        ResolveFlags::NO_XDEV | ResolveFlags::NO_SYMLINKS,
    )?)
}

/// Where no open refuses a mount of the same file system, no directory is opened for removal,
/// so nothing is deleted.
#[cfg(not(target_os = "linux"))]
fn open_beneath(_dir: BorrowedFd<'_>, _name: &CStr) -> std::io::Result<OwnedFd> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "a removal that crosses no mount needs Linux's openat2",
    ))
}
