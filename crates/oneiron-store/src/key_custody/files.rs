//! The local exterior backend: one owner-only directory tree beside the vault
//! root, never inside it, so restoring the vault's image cannot bring back an
//! entry destroyed here. A host must exclude it from every restorable
//! snapshot.
//!
//! `.<vault dir name>.key-custody/<namespace hex>.<vault hex>/<tag hex>.<item hex>/`
//! holds a subject's `g<generation hex16>` entries, its
//! `.retired-g<generation hex16>` markers and its
//! `.g<generation hex16>-<random hex16>.pending` temporaries; a world pad's
//! also holds the `.carried-<key id hex>` compartments a restore left
//! unopened ([`super::carried_pads`], PAD-3). Every directory
//! and file is opened without following a link. On Unix each is the
//! effective uid's, owner-only (0700/0600), and an entry has exactly one
//! link; on Windows the user's profile ACL, which custody's directories
//! inherit, is the boundary ([`super::platform`]).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rand::RngCore;
use zeroize::Zeroizing;

use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::key_custody::identity::CustodyBinding;
use crate::key_custody::identity::CustodyId;
use crate::key_custody::identity::CustodyKind;
use crate::key_custody::identity::CustodySecret;
use crate::key_custody::identity::CustodySubject;
use crate::key_custody::identity::custody_corrupt;
use crate::key_custody::platform;

/// What custody holds for one id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryState {
    /// Its entry is published and no marker retires it.
    Live,
    /// A retirement marker names it: it was destroyed, or is being.
    Retired,
    /// Neither: never published here, or lost.
    Missing,
}

/// The custody directory beside the vault at `root`.
pub fn container(root: &Path) -> Result<PathBuf> {
    let mut name = std::ffi::OsString::from(".");
    name.push(root.file_name().ok_or_else(custody_corrupt)?);
    name.push(".key-custody");
    Ok(root.with_file_name(name))
}

/// The key custody directory the engine keeps beside the vault whose data
/// directory is `data_dir` (`.<data directory>.key-custody`), for a host
/// that must keep the name free or move it with the vault (FIX 6582).
///
/// # Errors
/// A `data_dir` with no final component.
pub fn custody_container_path(data_dir: &Path) -> Result<PathBuf> {
    container(data_dir)
}

/// Whether a custody directory exists beside the vault at `root`. A binding
/// another platform wrote names no root here, so none exists for it.
pub fn custody_present(root: &Path) -> Result<bool> {
    if root.as_os_str().is_empty() {
        return Ok(false);
    }
    exists(&container(root)?)
}

pub fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

pub fn entry_name(generation: u64) -> String {
    format!("g{generation:016x}")
}

pub fn marker_name(generation: u64) -> String {
    format!(".retired-g{generation:016x}")
}

/// The name of the mark that `generation`'s Mint frame is synced (FIX
/// 5798): no census, generation scan or pending sweep reads it as an entry.
pub fn journaled_name(generation: u64) -> String {
    format!(".journaled-g{generation:016x}")
}

/// The error a fault reads as: the kind's own, or custody's.
fn damaged(kind: Option<CustodyKind>) -> Error {
    kind.map_or_else(custody_corrupt, CustodyKind::corrupt)
}

fn verify_permissions(file: &File, is_directory: bool, kind: Option<CustodyKind>) -> Result<()> {
    if !platform::owned(&file.metadata()?, is_directory, true) {
        return Err(damaged(kind));
    }
    Ok(())
}

pub fn safe_open(
    path: &Path,
    write_new: bool,
    directory: bool,
    kind: Option<CustodyKind>,
) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    if write_new {
        options.write(true).create_new(true);
    }
    let file = platform::secure(&mut options).open(path)?;
    verify_permissions(&file, directory, kind)?;
    Ok(file)
}

/// Makes directory `path`, which must not exist yet, owner-only, and syncs
/// its parent before anything is written inside it: without that, a synced
/// entry in a new directory can still disappear after power loss while LMDB
/// keeps what it decrypts.
pub fn make_new_dir(path: &Path, kind: Option<CustodyKind>) -> Result<File> {
    platform::dir_builder().create(path)?;
    platform::sync_dir(path.parent().ok_or_else(|| damaged(kind))?)?;
    safe_open(path, false, true, kind)
}

/// Opens directory `path`, checked owner-only, making it first when absent
/// and `create`.
pub fn open_dir(path: &Path, create: bool, kind: Option<CustodyKind>) -> Result<File> {
    if create {
        match make_new_dir(path, kind) {
            Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            made => return made,
        }
    }
    safe_open(path, false, true, kind)
}

/// Writes `bytes` at `path` through a synced temporary hard link, so a crash
/// never leaves a short entry. False when `path` already exists. The
/// temporary is removed whatever happened, failure before publication
/// included.
pub fn write_entry(
    dir: &Path,
    path: &Path,
    generation: u64,
    bytes: &[u8],
    kind: CustodyKind,
) -> Result<bool> {
    let suffix = rand::rngs::OsRng.next_u64();
    let temp = dir.join(format!(".g{generation:016x}-{suffix:016x}.pending"));
    let published = (|| -> Result<bool> {
        let mut file = safe_open(&temp, true, false, Some(kind))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        match fs::hard_link(&temp, path) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(err) => Err(err.into()),
        }
    })();
    fs::remove_file(&temp)?;
    published
}

/// Publishes `bytes` once as `name` in the custody directory `dir` (a
/// journal's, KS-4), through a synced temporary hard link as an entry is:
/// false when `name` already exists, whose bytes the caller then reads. The
/// temporary is removed whatever happened.
pub fn write_once(dir: &Path, name: &str, bytes: &[u8]) -> Result<bool> {
    let suffix = rand::rngs::OsRng.next_u64();
    let temp = dir.join(format!(".t{suffix:016x}.pending"));
    let published = (|| -> Result<bool> {
        let mut file = safe_open(&temp, true, false, None)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        match fs::hard_link(&temp, dir.join(name)) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(err) => Err(err.into()),
        }
    })();
    fs::remove_file(&temp)?;
    platform::sync_dir(dir)?;
    published
}

/// Replaces `name` in the custody directory `dir` with `bytes` in one
/// rename, synced, the directory synced after: a reader sees the old file or
/// the new one, never part of either.
pub fn replace_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let suffix = rand::rngs::OsRng.next_u64();
    let temp = dir.join(format!(".t{suffix:016x}.pending"));
    let written = (|| -> Result<()> {
        let mut file = safe_open(&temp, true, false, None)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, dir.join(name))?;
        Ok(())
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written?;
    platform::sync_dir(dir)?;
    Ok(())
}

/// The whole of the custody file at `path`, owner-only and opened without
/// following a link; `None` when there is none. A second link is allowed:
/// [`write_once`] holds one for an instant while it publishes.
pub fn read_whole(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut options = OpenOptions::new();
    options.read(true);
    let mut file = match platform::secure(&mut options).open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    if !platform::owned(&file.metadata()?, false, false) {
        return Err(custody_corrupt());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

/// Removes a subject's interrupted, unpublished temporaries. A crash after
/// the hard link but before the unlink leaves a complete entry with two
/// links; removing its temporary makes it readable again.
pub fn clean_pending(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(".g") && name.ends_with(".pending"))
        {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

/// Whether a marker in the subject directory `dir` retires `generation`.
pub fn retired_in(dir: &Path, generation: u64, kind: CustodyKind) -> Result<bool> {
    let path = dir.join(marker_name(generation));
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            safe_open(&path, false, false, Some(kind))?;
            Ok(true)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Exactly `kind`'s width: a short or long entry is damaged, never absent.
pub fn strict_read(file: &mut File, kind: CustodyKind) -> Result<CustodySecret> {
    let mut secret = Zeroizing::new(vec![0; kind.secret_len()]);
    file.read_exact(&mut secret).map_err(|_| kind.corrupt())?;
    let mut extra = [0];
    if file.read(&mut extra)? != 0 {
        return Err(kind.corrupt());
    }
    Ok(CustodySecret::from_bytes(secret))
}

/// Which missing directories an open makes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Create {
    /// None: a read needs all of them.
    Nothing,
    /// The subject's own, in an existing compartment: a retirement.
    Subject,
    /// All of them: a publication.
    All,
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    pub static AFTER_KEY_MARKER_CHECK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

/// Runs `callback` once, on this thread, between a read's marker check and
/// its entry open.
#[cfg(any(test, feature = "test-support"))]
pub fn arm_after_key_marker_check(callback: impl FnOnce() + 'static) {
    AFTER_KEY_MARKER_CHECK.with(|slot| *slot.borrow_mut() = Some(Box::new(callback)));
}

