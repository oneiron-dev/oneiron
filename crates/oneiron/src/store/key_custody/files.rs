//! The local exterior backend: one owner-only directory tree beside the vault
//! root, never inside it, so restoring the vault's image cannot bring back an
//! entry destroyed here. A host must exclude it from every restorable
//! snapshot.
//!
//! `.<vault dir name>.key-custody/<namespace hex>.<vault hex>/<tag hex>.<item hex>/`
//! holds a subject's `g<generation hex16>` entries, its
//! `.retired-g<generation hex16>` markers and its
//! `.g<generation hex16>-<random hex16>.pending` temporaries. Every directory
//! and file is the effective uid's, owner-only (0700/0600), opened without
//! following a link; an entry has exactly one link.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

use super::identity::{
    CustodyBinding, CustodyId, CustodyKind, CustodySecret, CustodySubject, custody_corrupt,
};

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
    #[cfg(unix)]
    {
        let mut name = std::ffi::OsString::from(".");
        name.push(root.file_name().ok_or_else(custody_corrupt)?);
        name.push(".key-custody");
        Ok(root.with_file_name(name))
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(Error::InvalidConfig(
            "key custody requires a supported Unix filesystem".into(),
        ))
    }
}

/// Whether a custody directory exists beside the vault at `root`.
pub(crate) fn custody_present(root: &Path) -> Result<bool> {
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

#[cfg(unix)]
fn verify_permissions(file: &File, is_directory: bool, kind: Option<CustodyKind>) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    // SAFETY: geteuid has no arguments or pointers and only reads the caller's
    // effective uid; the result is used to reject another owner's key file.
    if meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || (!is_directory && meta.nlink() != 1)
        || (is_directory && !meta.is_dir())
        || (!is_directory && !meta.is_file())
    {
        return Err(damaged(kind));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_permissions(file: &File, is_directory: bool, kind: Option<CustodyKind>) -> Result<()> {
    let meta = file.metadata()?;
    if (is_directory && !meta.is_dir()) || (!is_directory && !meta.is_file()) {
        return Err(damaged(kind));
    }
    Ok(())
}

fn safe_open(
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        options.mode(0o600);
    }
    let file = options.open(path)?;
    verify_permissions(&file, directory, kind)?;
    Ok(file)
}

/// Makes directory `path`, which must not exist yet, owner-only, and syncs
/// its parent before anything is written inside it: without that, a synced
/// entry in a new directory can still disappear after power loss while LMDB
/// keeps what it decrypts.
pub(super) fn make_new_dir(path: &Path, kind: Option<CustodyKind>) -> Result<File> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    File::open(path.parent().ok_or_else(|| damaged(kind))?)?.sync_all()?;
    safe_open(path, false, true, kind)
}

/// Opens directory `path`, checked owner-only, making it first when absent
/// and `create`.
fn open_dir(path: &Path, create: bool, kind: Option<CustodyKind>) -> Result<File> {
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
        directory.sync_all()?;
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
        directory.sync_all()?;
        if !published && self.read(id)?.expose() != secret.expose() {
            return Err(kind.corrupt());
        }
        Ok(())
    }

    /// `id`'s entry, minting it only while unpublished. A damaged entry is
    /// never treated as absent; only an unpublished temporary is discarded.
    pub(crate) fn get_or_create(&self, id: &CustodyId) -> Result<CustodySecret> {
        let kind = id.kind();
        let (dir, directory) = self.prepare(id)?;
        let path = dir.join(entry_name(id.generation()));
        if exists(&path)? {
            return self.read(id);
        }
        let secret = CustodySecret::random(kind.secret_len());
        let published = write_entry(&dir, &path, id.generation(), secret.expose(), kind)?;
        directory.sync_all()?;
        if published { Ok(secret) } else { self.read(id) }
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
        directory.sync_all()?;
        match fs::remove_file(dir.join(entry_name(id.generation()))) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        directory.sync_all()?;
        Ok(())
    }
}
