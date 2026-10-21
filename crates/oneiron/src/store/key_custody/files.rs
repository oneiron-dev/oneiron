//! The local exterior backend: one owner-only directory tree beside the vault
//! root, never inside it, so restoring the vault's image cannot bring back an
//! entry destroyed here. A host must exclude it from every restorable
//! snapshot.
//!
//! `.<vault dir name>.key-custody/<namespace hex>.<vault hex>/<tag hex>.<item hex>/`
//! holds a subject's `g<generation hex16>` entries, its
//! `.retired-g<generation hex16>` markers and its
//! `.g<generation hex16>-<random hex16>.pending` temporaries. Every directory
//! and file is opened without following a link. On Unix each is the
//! effective uid's, owner-only (0700/0600), and an entry has exactly one
//! link; on Windows the user's profile ACL, which custody's directories
//! inherit, is the boundary ([`super::platform`]).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

use super::identity::{
    CustodyBinding, CustodyId, CustodyKind, CustodySecret, CustodySubject, custody_corrupt,
};
use super::platform;

/// What custody holds for one id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EntryState {
    /// Its entry is published and no marker retires it.
    Live,
    /// A retirement marker names it: it was destroyed, or is being.
    Retired,
    /// Neither: never published here, or lost.
    Missing,
}

/// The custody directory beside the vault at `root`.
pub(super) fn container(root: &Path) -> Result<PathBuf> {
    let mut name = std::ffi::OsString::from(".");
    name.push(root.file_name().ok_or_else(custody_corrupt)?);
    name.push(".key-custody");
    Ok(root.with_file_name(name))
}

/// Whether a custody directory exists beside the vault at `root`. A binding
/// another platform wrote names no root here, so none exists for it.
pub(crate) fn custody_present(root: &Path) -> Result<bool> {
    if root.as_os_str().is_empty() {
        return Ok(false);
    }
    exists(&container(root)?)
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

pub(super) fn entry_name(generation: u64) -> String {
    format!("g{generation:016x}")
}

pub(super) fn marker_name(generation: u64) -> String {
    format!(".retired-g{generation:016x}")
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

pub(super) fn safe_open(
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
pub(super) fn make_new_dir(path: &Path, kind: Option<CustodyKind>) -> Result<File> {
    platform::dir_builder().create(path)?;
    platform::sync_dir(path.parent().ok_or_else(|| damaged(kind))?)?;
    safe_open(path, false, true, kind)
}

/// Opens directory `path`, checked owner-only, making it first when absent
/// and `create`.
pub(super) fn open_dir(path: &Path, create: bool, kind: Option<CustodyKind>) -> Result<File> {
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
fn write_entry(
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
pub(super) fn write_once(dir: &Path, name: &str, bytes: &[u8]) -> Result<bool> {
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
pub(super) fn replace_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
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
pub(super) fn read_whole(path: &Path) -> Result<Option<Vec<u8>>> {
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
fn clean_pending(dir: &Path) -> Result<()> {
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
fn retired_in(dir: &Path, generation: u64, kind: CustodyKind) -> Result<bool> {
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
fn strict_read(file: &mut File, kind: CustodyKind) -> Result<CustodySecret> {
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
enum Create {
    /// None: a read needs all of them.
    Nothing,
    /// The subject's own, in an existing compartment: a retirement.
    Subject,
    /// All of them: a publication.
    All,
}

#[cfg(test)]
thread_local! {
    static AFTER_KEY_MARKER_CHECK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

/// Runs `callback` once, on this thread, between a read's marker check and
/// its entry open.
#[cfg(test)]
pub(in crate::store) fn arm_after_key_marker_check(callback: impl FnOnce() + 'static) {
    AFTER_KEY_MARKER_CHECK.with(|slot| *slot.borrow_mut() = Some(Box::new(callback)));
}

/// One binding's custody on this host's filesystem. It owns storage and
/// lifecycle only: whether a subject may be read, published or retired is
/// its client's policy.
#[derive(Clone, Copy)]
pub(crate) struct LocalCustody<'a> {
    binding: &'a CustodyBinding,
}

impl<'a> LocalCustody<'a> {
    pub(crate) fn at(binding: &'a CustodyBinding) -> Self {
        Self { binding }
    }

    pub(crate) fn binding(&self) -> &'a CustodyBinding {
        self.binding
    }
}

impl LocalCustody<'_> {
    /// This binding's compartment in its container.
    pub(super) fn compartment(&self) -> Result<PathBuf> {
        Ok(container(self.binding.root())?.join(self.binding.compartment_name()))
    }

    /// Opens this binding's compartment, making it and its container when
    /// absent.
    pub(super) fn open_compartment(&self) -> Result<()> {
        open_dir(&container(self.binding.root())?, true, None)?;
        open_dir(&self.compartment()?, true, None)?;
        Ok(())
    }

    /// `subject`'s directory; refused for another vault's subject.
    fn subject_dir(&self, subject: &CustodySubject) -> Result<PathBuf> {
        if subject.vault() != self.binding.vault() {
            return Err(subject.kind().corrupt());
        }
        Ok(self.compartment()?.join(subject.dir_name()))
    }

    /// Opens the directories down to `subject`'s, each checked on the way,
    /// making the missing ones `create` names.
    fn open_subject(&self, subject: &CustodySubject, create: Create) -> Result<(PathBuf, File)> {
        let kind = Some(subject.kind());
        let dir = self.subject_dir(subject)?;
        open_dir(
            &container(self.binding.root())?,
            create == Create::All,
            kind,
        )?;
        open_dir(&self.compartment()?, create == Create::All, kind)?;
        let file = open_dir(&dir, create != Create::Nothing, kind)?;
        Ok((dir, file))
    }

    pub(crate) fn retired(&self, id: &CustodyId) -> Result<bool> {
        retired_in(&self.subject_dir(id.subject())?, id.generation(), id.kind())
    }

    /// Whether an entry was published for `id` and is still there. No
    /// custody directory means no entry at all.
    pub(crate) fn published(&self, id: &CustodyId) -> Result<bool> {
        exists(
            &self
                .subject_dir(id.subject())?
                .join(entry_name(id.generation())),
        )
    }

    /// Retired dominates: a crash between a marker and its unlink leaves an
    /// entry no one may read.
    pub(crate) fn state(&self, id: &CustodyId) -> Result<EntryState> {
        Ok(if self.retired(id)? {
            EntryState::Retired
        } else if self.published(id)? {
            EntryState::Live
        } else {
            EntryState::Missing
        })
    }

    /// The first generation of `subject` no marker retires.
    pub(crate) fn first_unretired(&self, subject: &CustodySubject) -> Result<u64> {
        let mut generation = 0_u64;
        while self.retired(&subject.at(generation))? {
            generation = generation
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("key custody generation"))?;
        }
        Ok(generation)
    }

    /// Reads a live entry, strictly: a retired, short or long one is damaged,
    /// and a missing one fails.
    pub(crate) fn read(&self, id: &CustodyId) -> Result<CustodySecret> {
        let kind = id.kind();
        let (dir, _directory) = self.open_subject(id.subject(), Create::Nothing)?;
        if retired_in(&dir, id.generation(), kind)? {
            return Err(kind.corrupt());
        }
        #[cfg(test)]
        AFTER_KEY_MARKER_CHECK.with(|slot| {
            if let Some(callback) = slot.borrow_mut().take() {
                callback();
            }
        });
        let mut file = safe_open(
            &dir.join(entry_name(id.generation())),
            false,
            false,
            Some(kind),
        )?;
        strict_read(&mut file, kind)
    }

    /// Opens `id`'s subject directory for a publication, making what is
    /// missing, with interrupted temporaries removed and the directory
    /// synced. A retired id is refused.
    fn prepare(&self, id: &CustodyId) -> Result<(PathBuf, File)> {
        let (dir, directory) = self.open_subject(id.subject(), Create::All)?;
        clean_pending(&dir)?;
        platform::sync_held(&directory, &dir)?;
        if retired_in(&dir, id.generation(), id.kind())? {
            return Err(id.kind().corrupt());
        }
        Ok((dir, directory))
    }

    /// Publishes `secret` as `id`'s entry, synced before this returns, so
    /// before any reference to it commits. The same bytes already there are
    /// accepted; other bytes, a retired id, or a secret not the kind's width
    /// are refused.
    pub(crate) fn publish(&self, id: &CustodyId, secret: &CustodySecret) -> Result<()> {
        let kind = id.kind();
        if secret.expose().len() != kind.secret_len() {
            return Err(kind.corrupt());
        }
        let (dir, directory) = self.prepare(id)?;
        let path = dir.join(entry_name(id.generation()));
        let published =
            !exists(&path)? && write_entry(&dir, &path, id.generation(), secret.expose(), kind)?;
        platform::sync_held(&directory, &dir)?;
        if !published && self.read(id)?.expose() != secret.expose() {
            return Err(kind.corrupt());
        }
        Ok(())
    }

    /// Publishes `secret`, bytes its client computed, as the new entry `id`
    /// and journals its Mint (KS-3): the entry synced, then the frame synced,
    /// both before this returns, so before any reference to it commits. The
    /// client takes `id` past every generation its subject holds, so an
    /// interrupted call's entry is never published again: it is debris an
    /// erase of the subject still retires.
    pub(crate) fn publish_minted(&self, id: &CustodyId, secret: &CustodySecret) -> Result<()> {
        self.publish(id, secret)?;
        self.journal_entry(&super::log::LogEntry::Mint(id.clone()))?;
        Ok(())
    }

    /// The newest generation `subject` holds an entry or a retirement marker
    /// for, an unpublished temporary aside; `None` when it holds neither, or
    /// has no directory yet.
    pub(crate) fn newest_generation(&self, subject: &CustodySubject) -> Result<Option<u64>> {
        let names = match fs::read_dir(self.subject_dir(subject)?) {
            Ok(names) => names,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let mut newest = None;
        for name in names {
            let name = name?.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let generation = name
                .strip_prefix(".retired-g")
                .or_else(|| name.strip_prefix('g'))
                .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                .filter(|&generation| {
                    name == entry_name(generation) || name == marker_name(generation)
                });
            newest = newest.max(generation);
        }
        Ok(newest)
    }

    /// Every subject of `kind` whose item begins with `prefix` that has a
    /// directory in this compartment, read from the directory names alone,
    /// in id order: every pad instance of one world (KS-5). No compartment
    /// holds none.
    pub(crate) fn subjects_with_prefix(
        &self,
        kind: CustodyKind,
        prefix: &[u8],
    ) -> Result<Vec<CustodySubject>> {
        let names = match fs::read_dir(self.compartment()?) {
            Ok(names) => names,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err.into()),
        };
        let lead = format!(
            "{:02x}.{}",
            kind.tag(),
            crate::entity_id::bytes_to_hex_lower(prefix)
        );
        let mut subjects = Vec::new();
        for name in names {
            let name = name?.file_name();
            let Some(name) = name.to_str().filter(|name| name.starts_with(&lead)) else {
                continue;
            };
            if let Some(subject) = CustodySubject::from_dir_name(self.binding.vault(), name)
                && subject.kind() == kind
            {
                subjects.push(subject);
            }
        }
        subjects.sort();
        Ok(subjects)
    }

    /// `id`'s entry, minting it only while unpublished. A damaged entry is
    /// never treated as absent; only an unpublished temporary is discarded.
    pub(crate) fn get_or_create(&self, id: &CustodyId) -> Result<CustodySecret> {
        self.get_or_mint(id).map(|(secret, _)| secret)
    }

    /// [`Self::get_or_create`], its Mint journaled whether it minted the
    /// entry or found it (KS-6): an entry an earlier call published before
    /// its Mint failed to append, or its writer aborted, is journaled here,
    /// before any row sealed under it commits. Every reader of the log takes
    /// a Mint as a set member, so one journaled again only moves the log on.
    /// A retired id is refused, never minted again; a found key is kept.
    pub(crate) fn get_or_create_journaled(&self, id: &CustodyId) -> Result<CustodySecret> {
        let (secret, minted) = self.get_or_mint(id)?;
        if !minted {
            self.journal_entry(&super::log::LogEntry::Mint(id.clone()))?;
        }
        Ok(secret)
    }

    /// `id`'s entry and whether this call minted and journaled it.
    fn get_or_mint(&self, id: &CustodyId) -> Result<(CustodySecret, bool)> {
        let kind = id.kind();
        let (dir, directory) = self.prepare(id)?;
        let path = dir.join(entry_name(id.generation()));
        if exists(&path)? {
            return Ok((self.read(id)?, false));
        }
        let secret = CustodySecret::random(kind.secret_len());
        let published = write_entry(&dir, &path, id.generation(), secret.expose(), kind)?;
        platform::sync_held(&directory, &dir)?;
        if !published {
            return Ok((self.read(id)?, false));
        }
        // KS-4: the mint is journaled, synced, before a row sealed under it
        // may commit.
        self.journal_entry(&super::log::LogEntry::Mint(id.clone()))?;
        Ok((secret, true))
    }

    /// Destroys precisely `id`: its marker is synced, then its entry is
    /// unlinked and the directory synced. Neither an old snapshot nor a
    /// delayed retirement can revive or destroy another generation. Ordering
    /// against readers and the durable intent is the caller's
    /// ([`crate::store::Store::finish_custody_retirements`]).
    pub(crate) fn retire_local(&self, id: &CustodyId) -> Result<()> {
        let kind = id.kind();
        let (dir, directory) = self.open_subject(id.subject(), Create::Subject)?;
        match safe_open(
            &dir.join(marker_name(id.generation())),
            true,
            false,
            Some(kind),
        ) {
            Ok(file) => file.sync_all()?,
            Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if !retired_in(&dir, id.generation(), kind)? {
                    return Err(kind.corrupt());
                }
            }
            Err(err) => return Err(err),
        }
        platform::sync_held(&directory, &dir)?;
        match fs::remove_file(dir.join(entry_name(id.generation()))) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        platform::sync_held(&directory, &dir)?;
        Ok(())
    }
}
