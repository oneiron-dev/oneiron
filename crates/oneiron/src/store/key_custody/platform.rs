//! The one platform seam of key custody's files (KS-2A, Engine 10-20
//! 04:1x): every open, directory sync, lock and ownership check the backend
//! makes goes through here, so both backends keep one layout, one
//! publish/retire order and one fsync discipline: temp write, file flush,
//! no-clobber publication or atomic replacement, temp removal, directory
//! durability; a retirement's marker flush, directory durability, unlink,
//! directory durability.
//!
//! On Unix the boundary is the effective uid: every file and directory is
//! the owner's, owner-only (0700/0600), opened without following a link,
//! and an entry has one link. On Windows the boundary is the user's
//! profile ACL, which every directory custody makes inherits: no uid or
//! mode is checked there (CALLS CUSTODY_NON_UNIX_BOUNDARY). A reparse point
//! is opened as itself and refused, never followed. No platform and no
//! location is refused.

use std::fs::{DirBuilder, File, Metadata, OpenOptions};
use std::path::Path;

use crate::error::Result;

/// Opens without following a link and without leaking the descriptor to a
/// child; a file it creates is owner-only.
pub(super) fn secure(options: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows::OPEN_REPARSE_POINT | windows::BACKUP_SEMANTICS);
    }
    options
}

/// A builder for one owner-only directory.
pub(super) fn dir_builder() -> DirBuilder {
    #[allow(unused_mut)]
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
}

/// Whether what `meta` describes is custody's own: a directory or a file
/// as `is_directory` says, never a link; on Unix also the effective uid's,
/// owner-only, and a file of one link (`single_link`).
pub(super) fn owned(meta: &Metadata, is_directory: bool, single_link: bool) -> bool {
    let shaped = if is_directory {
        meta.is_dir()
    } else {
        meta.is_file()
    };
    shaped && !meta.file_type().is_symlink() && unix_owned(meta, is_directory, single_link)
}

#[cfg(unix)]
fn unix_owned(meta: &Metadata, is_directory: bool, single_link: bool) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no arguments or pointers and only reads the
    // caller's effective uid; the result rejects another owner's file.
    meta.uid() == unsafe { libc::geteuid() }
        && meta.mode() & 0o077 == 0
        && (is_directory || !single_link || meta.nlink() == 1)
}

#[cfg(not(unix))]
fn unix_owned(_: &Metadata, _: bool, _: bool) -> bool {
    // The profile ACL is the boundary off Unix: nothing more to check.
    true
}

/// Syncs directory `path`, so an entry made, renamed or unlinked in it is
/// durable. Windows opens the directory for writing with backup semantics,
/// as a flush of its entries requires; an error is never swallowed.
pub fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(windows::BACKUP_SEMANTICS)
            .open(path)?
            .sync_all()?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        File::open(path)?.sync_all()?;
    }
    Ok(())
}

/// Syncs the directory held open as `directory` at `path`: through the
/// held descriptor on Unix, by its path elsewhere, where a flush needs a
/// handle opened for writing.
pub(super) fn sync_held(directory: &File, path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let _ = path;
        directory.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        sync_dir(path)?;
    }
    Ok(())
}

/// Holds an exclusive lock on `file` until it closes: one process at a time
/// reads, compares and replaces what the lock guards.
pub(super) fn lock_exclusive(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        rustix::fs::flock(file, rustix::fs::FlockOperation::LockExclusive)
            .map_err(std::io::Error::from)?;
    }
    #[cfg(not(unix))]
    {
        file.lock()?;
    }
    Ok(())
}

/// Opens the lock file at `path`, made owner-only when missing, and holds
/// an exclusive lock on it until the returned file closes. Two opens
/// exclude each other within one process as across processes.
pub(super) fn lock_at(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    let lock = secure(&mut options).open(path)?;
    lock_exclusive(&lock)?;
    Ok(lock)
}

/// The identity of a directory custody made, so its cleanup never removes
/// one that replaced it: device and inode on Unix; off Unix, its creation
/// time, as no stable call reads a file index there.
pub(super) fn directory_identity(meta: &Metadata) -> Option<(u64, u64)> {
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some((meta.dev(), meta.ino()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        Some((0, meta.creation_time()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = meta;
        None
    }
}

#[cfg(windows)]
mod windows {
    /// `FILE_FLAG_OPEN_REPARSE_POINT`: a link opens as itself.
    pub(super) const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    /// `FILE_FLAG_BACKUP_SEMANTICS`: a directory opens as a handle.
    pub(super) const BACKUP_SEMANTICS: u32 = 0x0200_0000;
}
