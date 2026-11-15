//! Core half of `store::root_directory`: its store-layer items live in `oneiron_store::root_directory` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::root_directory::*;

use super::writer_lease::VAULT_WRITER_LOCK_FILE;
use crate::{Error, Result};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, fstat, openat, statat, unlinkat};
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
/// the tree. Each directory inside is emptied through its own descriptor,
/// and just before its unlink its name must still hold that directory;
/// another found there refuses the removal and is left as it is. Only the
/// held directory itself goes by `path`, checked again first.
///
/// POSIX has no rmdir bound to a descriptor, so each check and its unlink
/// are two calls. A directory moved to the name between them is unlinked
/// only if it is empty: one with anything in it makes the unlink fail and
/// the removal refuse. Whoever moves it there needs write access to its
/// parent, and with that access can remove an empty directory anyway.
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
            let emptied = fstat(&child)?;
            empty_directory(child.as_fd(), false)?;
            #[cfg(test)]
            BEFORE_CHILD_DIRECTORY_UNLINK.with(|slot| {
                if let Some(callback) = slot.borrow_mut().as_mut() {
                    callback(name.as_c_str());
                }
            });
            // The name must still hold the directory just emptied: one moved
            // there meanwhile is not this tree's to remove, and the whole
            // removal refuses, as a top no longer at its path does. One moved
            // there after this check is unlinked only if empty (see
            // `remove_held_directory`).
            let named = statat(dir, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)?;
            if (named.st_dev, named.st_ino) != (emptied.st_dev, emptied.st_ino) {
                return Err(std::io::Error::other(
                    "a directory inside the one to remove no longer sits at its name",
                ));
            }
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
        BEFORE_CHILD_DIRECTORY_UNLINK.with(|slot| slot.borrow_mut().take());
    }
    Ok(())
}

#[cfg(test)]
type ChildDirectoryCallback = Box<dyn FnMut(&std::ffi::CStr)>;

#[cfg(test)]
thread_local! {
    static BEFORE_CHILD_DIRECTORY_UNLINK: std::cell::RefCell<Option<ChildDirectoryCallback>> =
        std::cell::RefCell::new(None);
}

/// Runs `callback` with each directory's name inside the next removal on
/// this thread, once that directory is emptied and before it is unlinked.
#[cfg(test)]
pub(crate) fn arm_before_child_directory_unlink(callback: impl FnMut(&std::ffi::CStr) + 'static) {
    BEFORE_CHILD_DIRECTORY_UNLINK.with(|slot| *slot.borrow_mut() = Some(Box::new(callback)));
}

#[cfg(test)]
mod tests;
