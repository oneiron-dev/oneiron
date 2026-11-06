//! Core half of `store::root_directory`: its store-layer items live in `oneiron_store::root_directory` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::root_directory::*;

use super::writer_lease::VAULT_WRITER_LOCK_FILE;
use crate::{Error, Result};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, openat, statat, unlinkat};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Removes the directory `path` names, with everything in it, only while
/// that name holds the very directory `held` has open. A name that holds
/// another directory, a link or nothing is refused, and both are left as
/// they are.
///
/// Everything inside goes through `held`, each entry relative to the
/// directory holding it, so no name moved meanwhile leads the removal out of
/// the tree. Only the emptied directory itself goes by name, checked again
/// first.
///
/// A vault's writer lock goes last: while it is linked, an owner that opens
/// the vault meets the lock whoever removes it holds, never a fresh one
/// beside data still being removed (C8 residual, review r2).
pub fn remove_held_directory(path: &Path, held: &File) -> Result<()> {
    let identity = file_identity(&held.metadata()?);
    let still_named = || -> Result<()> {
        if named_directory_identity(path)?.as_ref() == Some(&identity) {
            Ok(())
        } else {
            Err(Error::InvalidConfig(
                "the directory to remove no longer sits at its path".to_owned(),
            ))
        }
    };
    still_named()?;
    empty_directory(held.as_fd(), true)?;
    still_named()?;
    std::fs::remove_dir(path)?;
    Ok(())
}

/// Removes every entry of `dir`, depth first. A link is removed, never
/// followed.
pub(super) fn empty_directory(dir: BorrowedFd<'_>, root: bool) -> std::io::Result<()> {
    let mut entries = Vec::new();
    for entry in Dir::read_from(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name != c"." && name != c".." {
            entries.push((name.to_owned(), entry.file_type()));
        }
    }
    if root {
        // The writer lock last, after everything it guards.
        entries.sort_by_key(|(name, _)| name.as_bytes() == VAULT_WRITER_LOCK_FILE.as_bytes());
    }
    for (name, kind) in entries {
        let kind = match kind {
            FileType::Unknown => FileType::from_raw_mode(
                statat(dir, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)?.st_mode,
            ),
            kind => kind,
        };
        if kind == FileType::Directory {
            let child = openat(
                dir,
                name.as_c_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            empty_directory(child.as_fd(), false)?;
            unlinkat(dir, name.as_c_str(), AtFlags::REMOVEDIR)?;
        } else {
            unlinkat(dir, name.as_c_str(), AtFlags::empty())?;
        }
        #[cfg(test)]
        if root {
            AFTER_ROOT_ENTRY_REMOVED.with(|slot| {
                if let Some(callback) = slot.borrow_mut().as_mut() {
                    callback(name.as_c_str());
                }
            });
        }
    }
    #[cfg(test)]
    if root {
        AFTER_ROOT_ENTRY_REMOVED.with(|slot| slot.borrow_mut().take());
    }
    Ok(())
}
