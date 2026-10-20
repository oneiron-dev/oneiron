//! One end's own outbox tree, as the carrier reads and writes it: through
//! held directories, each part opened without following a link, and only
//! regular files. On the guest these calls run as root, so a file the engine
//! made is read only when the vault's UID owns it, and everything written
//! is given its owner and mode before it is synced and renamed into place:
//! the vault UID's 0600, or root:UID 0640 for a protected public key. This is
//! the write-back installer; the engine never holds key-write authority.

use super::store::Version;
use oneiron_vault_contract::vm_outbox::{VmOutboxKind, vm_outbox_member};
use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, Metadata, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, fchown};
use std::path::Path;

/// The deepest member name walked: a custody log frame's five parts.
const MAX_DEPTH: usize = 5;
/// A training outbox's lock, which its producer and its shipper each take
/// for a coherent local snapshot or commit.
const TRAINING_LOCK: &str = ".lock";

/// A local file's identity and size, as a scan compares it to skip a digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct FileStamp {
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl FileStamp {
    fn of(metadata: &Metadata) -> Self {
        Self {
            ino: metadata.ino(),
            len: metadata.size(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

/// Whose tree an end writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Owner {
    /// The guest companion, as root, for the vault's UID (and GID).
    Guest { uid: u32 },
    /// The host attachment, as the supervisor's own user.
    Host,
}

impl Owner {
    /// Whether this end sends a file it found: on the guest, only one the
    /// vault's UID owns, so no link or name the engine planted makes root
    /// read a file of root's.
    fn sends(self, metadata: &Metadata) -> bool {
        match self {
            Self::Guest { uid } => metadata.is_file() && metadata.uid() == uid,
            Self::Host => metadata.is_file(),
        }
    }

    /// Gives a directory this end made its owner and mode 0700.
    fn own_dir(self, dir: &File) -> std::io::Result<()> {
        if let Self::Guest { uid } = self {
            fchown(dir, Some(uid), Some(uid))?;
        }
        dir.set_permissions(Permissions::from_mode(0o700))
    }

    /// Gives a file this end is about to publish its owner and mode.
    fn own_file(self, file: &File, protected: bool) -> std::io::Result<()> {
        let mode = match self {
            Self::Guest { uid } if protected => {
                fchown(file, Some(0), Some(uid))?;
                0o640
            }
            Self::Guest { uid } => {
                fchown(file, Some(uid), Some(uid))?;
                0o600
            }
            Self::Host => 0o600,
        };
        file.set_permissions(Permissions::from_mode(mode))
    }
}

/// The directory `name` in `parent`, opened without following a link.
pub(super) fn open_dir_at(parent: &File, name: &str) -> std::io::Result<File> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    Ok(File::from(rustix::fs::openat(
        parent,
        name,
        flags,
        Mode::empty(),
    )?))
}

/// The directory at `path`, its last part not followed through a link.
pub(super) fn open_dir_path(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

/// The directory `name` in `parent`, made for `owner` when missing.
pub(super) fn make_dir_at(parent: &File, name: &str, owner: Owner) -> std::io::Result<File> {
    match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) => {
            let dir = open_dir_at(parent, name)?;
            owner.own_dir(&dir)?;
            parent.sync_all()?;
            Ok(dir)
        }
        Err(Errno::EXIST) => open_dir_at(parent, name),
        Err(error) => Err(error.into()),
    }
}

/// The directory holding `member`'s leaf, and the leaf, walked from `root`;
/// missing directories are made for `make`, or are `NotFound` without it.
fn parent_of(root: &File, member: &str, make: Option<Owner>) -> std::io::Result<(File, String)> {
    let mut parts: Vec<&str> = member.split('/').collect();
    let leaf = parts.pop().unwrap_or_default().to_owned();
    let mut dir = root.try_clone()?;
    for part in parts {
        dir = match make {
            Some(owner) => make_dir_at(&dir, part, owner)?,
            None => open_dir_at(&dir, part)?,
        };
    }
    Ok((dir, leaf))
}

/// Every member of `kind` under `root` this end sends or keeps, by name,
/// with its stamp: protocol names only, regular files only, hidden names
/// (temporaries, locks) skipped and no link followed.
pub(super) fn list(
    root: &File,
    kind: VmOutboxKind,
    owner: Owner,
    takes: &dyn Fn(&str) -> bool,
) -> std::io::Result<BTreeMap<String, FileStamp>> {
    let mut found = BTreeMap::new();
    walk(root, "", 1, &mut |member: &str, dir: &File, name: &str| {
        if vm_outbox_member(kind, member).is_none() || !takes(member) {
            return Ok(());
        }
        let file = match open_file_at(dir, name) {
            Ok(file) => file,
            Err(error) if is_gone(&error) => return Ok(()),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if owner.sends(&metadata) {
            found.insert(member.to_owned(), FileStamp::of(&metadata));
        }
        Ok(())
    })?;
    Ok(found)
}

/// Calls `visit` with each file-like entry's member name, directory and leaf
/// under `dir`, descending into directories up to [`MAX_DEPTH`].
fn walk(
    dir: &File,
    prefix: &str,
    depth: usize,
    visit: &mut dyn FnMut(&str, &File, &str) -> std::io::Result<()>,
) -> std::io::Result<()> {
    for entry in rustix::fs::Dir::read_from(dir)? {
        let entry = entry?;
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let member = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        match entry.file_type() {
            FileType::Directory if depth < MAX_DEPTH => match open_dir_at(dir, name) {
                Ok(child) => walk(&child, &member, depth + 1, visit)?,
                Err(error) if is_gone(&error) => {}
                Err(error) => return Err(error),
            },
            FileType::RegularFile | FileType::Unknown => visit(&member, dir, name)?,
            _ => {}
        }
    }
    Ok(())
}

/// A name that went away, or turned out to be a link or a directory, between
/// listing and opening it.
fn is_gone(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOENT | libc::ELOOP | libc::ENOTDIR | libc::EISDIR)
    )
}

fn open_file_at(dir: &File, name: &str) -> std::io::Result<File> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    Ok(File::from(rustix::fs::openat(
        dir,
        name,
        flags,
        Mode::empty(),
    )?))
}

/// `member`'s file under `root`, held, with its stamp; `None` when it is not
/// there, or, with `sending`, when it is not one that end may send.
pub(super) fn open_member(
    root: &File,
    member: &str,
    sending: Option<Owner>,
) -> std::io::Result<Option<(File, FileStamp)>> {
    let opened = parent_of(root, member, None).and_then(|(dir, leaf)| open_file_at(&dir, &leaf));
    let file = match opened {
        Ok(file) => file,
        Err(error) if is_gone(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    let sendable = match sending {
        Some(owner) => owner.sends(&metadata),
        None => metadata.is_file(),
    };
    Ok(sendable.then(|| (file, FileStamp::of(&metadata))))
}

/// The digest and length of everything `file` holds, read from its start.
pub(super) fn digest(mut file: &File) -> std::io::Result<Version> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut length = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        length = length.saturating_add(read as u64);
    }
    Ok(Version {
        blake3: hasher.finalize().to_hex().to_string(),
        length,
    })
}

/// Takes `root`'s training lock for the life of the returned file, when the
/// outbox has one; it is held only for a local snapshot or commit.
pub(super) fn lock_training(root: &File) -> std::io::Result<Option<File>> {
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let lock = match rustix::fs::openat(root, TRAINING_LOCK, flags, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    rustix::fs::flock(&lock, FlockOperation::LockExclusive)?;
    Ok(Some(lock))
}

/// A member's incoming bytes, in a temporary sibling of its final name. One
/// dropped before it is published, a set abandoned midway among them, takes
/// its temporary with it.
pub(super) struct Staged {
    dir: File,
    leaf: String,
    temporary: String,
    file: File,
    hasher: blake3::Hasher,
    length: u64,
    published: bool,
}

impl Staged {
    /// A fresh temporary for `member` under `root`, its directories made for
    /// `owner` where missing. The name is hidden, so no scan or producer
    /// takes it for a member.
    pub(super) fn new(
        root: &File,
        member: &str,
        owner: Owner,
        transfer_id: u64,
    ) -> std::io::Result<Self> {
        let (dir, leaf) = parent_of(root, member, Some(owner))?;
        let temporary = format!(".{leaf}.vm-outbox-{transfer_id}.tmp");
        match rustix::fs::unlinkat(&dir, temporary.as_str(), AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(error) => return Err(error.into()),
        }
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let file = File::from(rustix::fs::openat(
            &dir,
            temporary.as_str(),
            flags,
            Mode::from_raw_mode(0o600),
        )?);
        Ok(Self {
            dir,
            leaf,
            temporary,
            file,
            hasher: blake3::Hasher::new(),
            length: 0,
            published: false,
        })
    }

    pub(super) fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.file.write_all(bytes)?;
        self.hasher.update(bytes);
        self.length = self.length.saturating_add(bytes.len() as u64);
        Ok(())
    }

    /// The digest and length of what was written.
    pub(super) fn version(&self) -> Version {
        Version {
            blake3: self.hasher.finalize().to_hex().to_string(),
            length: self.length,
        }
    }

    /// Gives the file its owner and mode, syncs it, renames it over the
    /// member's name and syncs the directory; returns the published stamp.
    pub(super) fn publish(mut self, owner: Owner, protected: bool) -> std::io::Result<FileStamp> {
        owner.own_file(&self.file, protected)?;
        self.file.sync_all()?;
        rustix::fs::renameat(
            &self.dir,
            self.temporary.as_str(),
            &self.dir,
            self.leaf.as_str(),
        )?;
        self.published = true;
        self.dir.sync_all()?;
        Ok(FileStamp::of(&self.file.metadata()?))
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.published {
            let _ = rustix::fs::unlinkat(&self.dir, self.temporary.as_str(), AtFlags::empty());
        }
    }
}

/// Removes `member` under `root`, when it is there, and syncs its directory;
/// for custody, a batch directory it leaves empty goes too.
pub(super) fn remove(root: &File, kind: VmOutboxKind, member: &str) -> std::io::Result<()> {
    let (dir, leaf) = match parent_of(root, member, None) {
        Ok(found) => found,
        Err(error) if is_gone(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    match rustix::fs::unlinkat(&dir, leaf.as_str(), AtFlags::empty()) {
        Ok(()) => dir.sync_all()?,
        Err(Errno::NOENT) => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    if kind != VmOutboxKind::Custody {
        return Ok(());
    }
    // `<slot>/<target>` stay: only the batch and its `log` may empty.
    let parts: Vec<&str> = member.split('/').collect();
    for keep in (3..parts.len()).rev() {
        let parent = parent_of(root, &parts[..keep].join("/"), None).map(|(dir, _)| dir);
        let Ok(parent) = parent else {
            break;
        };
        match rustix::fs::unlinkat(&parent, parts[keep - 1], AtFlags::REMOVEDIR) {
            Ok(()) => parent.sync_all()?,
            Err(_) => break,
        }
    }
    Ok(())
}
