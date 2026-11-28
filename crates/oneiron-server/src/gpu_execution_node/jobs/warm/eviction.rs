//! The cache pass's file work (row P2): what a cache path holds, and its removal. A path is
//! removed only when it is a directory directly in the box's cache directory, that directory is
//! the engine's alone (walked from `/` as the work directory is: [`trusted_work_dir`]), the
//! engine's or the job account owns the entry, the engine's account can empty it, no mount lies
//! at it or beneath it, no other warm key's path lies in it where the file system resolves that
//! path, by name or by what each directory is (its file system and inode), nothing in it is an
//! entry another warm key's path reaches by another name (a bind mount of a directory in it, or
//! a second name of a file in it), and neither of the node's own directories (its state and
//! work directories) lies in it.
//!
//! It is first moved into [`EVICTED_DIR_NAME`] inside the cache directory ([`Trash`]), under the
//! admission lock, so no launch finds it half removed, to a name nothing holds there and no
//! record names (the move never replaces an entry), and the warm-key table records what was
//! moved (its name there, its inode, and that directory's file system and inode). Only a
//! recorded entry is ever deleted from that directory, and only once the table that records it
//! is on disk: anything else found there is left. The files go after the lock is dropped, by a
//! walk from open directories that follows no symbolic link and crosses no mount (Linux's
//! `openat2` with `RESOLVE_NO_XDEV`, so a bind mount made during the walk stops it too; the
//! removed caches' directory itself is opened that way). Where that open does not exist (not
//! Linux, or a kernel or filter that refuses it), the pass moves nothing. A deletion that did not
//! complete is tried again by the next pass.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{AtFlags, Dev, FileType, Mode, OFlags};

use super::table::EvictedRecord;
use crate::gpu_execution_node::jobs::staging::trusted_work_dir;
use crate::gpu_execution_node::node_settings::EVICTED_DIR_NAME;

/// The most entries one measurement reads beneath a cache path; past it the count stops there,
/// and the figure is a lower bound.
const MEASURE_ENTRIES_MAX: u64 = 4_000_000;

/// The deepest directory a removal descends to; a deeper tree is left, with a warning.
const REMOVE_DEPTH_MAX: usize = 256;

/// The most symbolic links one lookup follows, as Linux's own lookup.
const LOOKUP_LINKS_MAX: usize = 40;

/// The most names a move tries in the removed caches' directory before it gives up.
const MOVE_NAMES_MAX: u32 = 16;

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

/// What an entry is, whatever its name: its file system and its inode.
pub(super) type Identity = (u64, u64);

/// The identity of the entry `found` describes.
fn identity(found: &std::fs::Metadata) -> Identity {
    (found.dev(), found.ino())
}

/// Where the file system resolves a warm path, and every real path its lookup passes through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Lookup {
    /// The path as the file system resolves it, with a missing tail as written.
    real: PathBuf,
    /// Each directory the lookup enters and each symbolic link it reads, where it lies.
    through: Vec<PathBuf>,
    /// The identity of each entry the lookup finds that is not a symbolic link: each directory
    /// it enters, and what it ends at.
    entered: Vec<Identity>,
    /// The identity of what the path names, when that exists.
    end: Option<Identity>,
}

impl Lookup {
    /// Whether removing the directory `dir` (where the file system resolves it; `own` its
    /// identity, `above` that of each directory above it) would change what this path names:
    /// the path lies in it or its lookup passes through it, or it lies in the path. Each is
    /// checked by name and by identity, so another name for the same directory (a bind mount, or
    /// a name that differs in case alone where the file system folds case) overlaps too. What
    /// lies beneath `dir` under another name is [`Measured::aliased`]'s part.
    pub(super) fn overlaps(&self, dir: &Path, own: Identity, above: &[Identity]) -> bool {
        self.lies_in(dir, own)
            || dir.starts_with(&self.real)
            || self.end.is_some_and(|end| above.contains(&end))
    }

    /// Whether moving the directory `dir` (where the file system resolves it, `own` its
    /// identity) would move what this path names or where its lookup goes: the path lies in it
    /// or its lookup passes through it, by name or by identity. A directory of the node's own
    /// is checked this way only, as the default cache directory lies in its work directory.
    pub(super) fn lies_in(&self, dir: &Path, own: Identity) -> bool {
        self.real.starts_with(dir)
            || self.through.iter().any(|passed| passed.starts_with(dir))
            || self.entered.contains(&own)
    }
}

/// Every identity `lookups` enter or end at. An entry beneath a cache path with one of them is
/// what another path reaches by another name (a bind mount of a directory in the cache, or a
/// second name of a file in it): removing the cache would change what that path names.
pub(super) fn guarded<'a>(lookups: impl IntoIterator<Item = &'a Lookup>) -> BTreeSet<Identity> {
    lookups
        .into_iter()
        .flat_map(|lookup| lookup.entered.iter().copied().chain(lookup.end))
        .collect()
}

/// One step of a lookup still to take.
enum Step {
    Up,
    Name(OsString),
}

/// The steps of `path`, after its root.
fn steps(path: &Path) -> impl Iterator<Item = Step> + '_ {
    path.components().filter_map(|component| match component {
        Component::Normal(name) => Some(Step::Name(name.to_owned())),
        Component::ParentDir => Some(Step::Up),
        Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
    })
}

/// Looks `path` (absolute) up as the file system does, one name at a time, following each
/// symbolic link (a dangling one to where its target would be), and records each directory it
/// enters and each link it reads, by name and by identity. Past the first name that does not
/// exist, the rest is kept as written.
///
/// # Errors
///
/// A name does not read for another reason than its absence, or the lookup follows more than
/// [`LOOKUP_LINKS_MAX`] links.
pub(super) fn lookup(path: &Path) -> std::io::Result<Lookup> {
    let mut pending: VecDeque<Step> = steps(path).collect();
    let mut at = PathBuf::from("/");
    let mut through = Vec::new();
    let mut entered = Vec::new();
    let mut links = 0;
    let mut missing = false;
    while let Some(step) = pending.pop_front() {
        let name = match step {
            Step::Up => {
                at.pop();
                continue;
            }
            Step::Name(name) => name,
        };
        let next = at.join(&name);
        if missing {
            at = next;
            continue;
        }
        match std::fs::symlink_metadata(&next) {
            Ok(found) if found.file_type().is_symlink() => {
                links += 1;
                if links > LOOKUP_LINKS_MAX {
                    return Err(std::io::Error::other(format!(
                        "{} follows more than {LOOKUP_LINKS_MAX} symbolic links",
                        path.display()
                    )));
                }
                let target = std::fs::read_link(&next)?;
                through.push(next);
                if target.is_absolute() {
                    at = PathBuf::from("/");
                }
                for step in steps(&target).collect::<Vec<_>>().into_iter().rev() {
                    pending.push_front(step);
                }
            }
            Ok(found) => {
                entered.push(identity(&found));
                through.push(next.clone());
                at = next;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing = true;
                at = next;
            }
            Err(error) => return Err(error),
        }
    }
    // Every name in `at` is an entry found, none a link: what it names is read once more, as a
    // `..` may have taken the lookup up from the last entry it found.
    let end = if missing {
        None
    } else {
        Some(identity(&std::fs::symlink_metadata(&at)?))
    };
    Ok(Lookup {
        real: at,
        through,
        entered,
        end,
    })
}

/// What a cache path holds, as [`measure`] reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Measured {
    /// The disk it uses: its own entry and everything beneath it on the same file system, a
    /// mount's tree left out (it is not the cache's; 0 for a mount at the path itself), and a
    /// file with several names in it counted once.
    pub(super) bytes: u64,
    /// The engine's account could empty every directory in it when it was read: the engine runs
    /// as root, or its account owns each of them with write and search permission; every entry
    /// read; no mount beneath it; and none deeper than a removal descends. A check before the
    /// move, not a promise: a removal that fails later is reported and tried again.
    pub(super) emptiable: bool,
    /// An entry read in it (itself included) has an identity of the `guarded` set: another
    /// warm key's path, or a directory of the node's own, reaches into it by another name, so
    /// it is not the cache's alone.
    pub(super) aliased: bool,
}

/// What `path` holds, with no symbolic link followed and no mount read into, and whether an
/// entry in it is one `guarded` ([`guarded`]) names. `None` when the path does not exist.
pub(super) fn measure(path: &Path, guarded: &BTreeSet<Identity>) -> Option<Measured> {
    let top = std::fs::symlink_metadata(path).ok()?;
    let device = top.dev();
    let engine = rustix::process::geteuid().as_raw();
    let can_empty = |found: &std::fs::Metadata| {
        engine == 0 || (found.uid() == engine && found.mode() & 0o300 == 0o300)
    };
    let mut measured = Measured {
        bytes: top.blocks().saturating_mul(512),
        emptiable: !top.is_dir() || can_empty(&top),
        aliased: guarded.contains(&identity(&top)),
    };
    if !top.is_dir() {
        return Some(measured);
    }
    // The walk goes where the file system resolves the path, as the mount list names mounts.
    let (Ok(real), Some(mounts)) = (std::fs::canonicalize(path), mount_points()) else {
        measured.emptiable = false;
        return Some(measured);
    };
    if mounts.contains(&real) {
        return Some(Measured {
            bytes: 0,
            emptiable: false,
            aliased: measured.aliased,
        });
    }
    // Each file with more than one name, by identity: its blocks count once.
    let mut linked: BTreeSet<Identity> = BTreeSet::new();
    let beneath: BTreeSet<&PathBuf> = mounts
        .iter()
        .filter(|point| point.starts_with(&real))
        .collect();
    let mut seen = 1_u64;
    // Each directory with its depth, the cache path's own at 0, as a removal counts it.
    let mut pending = vec![(real, 0_usize)];
    while let Some((dir, depth)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            measured.emptiable = false;
            continue;
        };
        for entry in entries {
            seen += 1;
            if seen > MEASURE_ENTRIES_MAX {
                tracing::warn!(path = %path.display(), "warm keys: a cache path holds more entries than one measurement reads; its figure is a lower bound");
                measured.emptiable = false;
                return Some(measured);
            }
            let Ok((inner, found)) = entry.and_then(|entry| Ok((entry.path(), entry.metadata()?)))
            else {
                measured.emptiable = false;
                continue;
            };
            // A mount beneath it: neither read into nor counted.
            if beneath.contains(&inner) {
                measured.emptiable = false;
                continue;
            }
            measured.aliased |= guarded.contains(&identity(&found));
            let first_name =
                found.is_dir() || found.nlink() <= 1 || linked.insert(identity(&found));
            if first_name {
                measured.bytes = measured
                    .bytes
                    .saturating_add(found.blocks().saturating_mul(512));
            }
            if found.is_dir() {
                measured.emptiable &= can_empty(&found);
                if found.dev() != device || depth + 1 >= REMOVE_DEPTH_MAX {
                    measured.emptiable = false;
                } else {
                    pending.push((inner, depth + 1));
                }
            }
        }
    }
    Some(measured)
}

/// The mount points this process sees; `None` when the list does not read on Linux. Where the
/// system does not list its mounts (not Linux), none: nothing is moved there anyway
/// ([`open_beneath`]).
fn mount_points() -> Option<BTreeSet<PathBuf>> {
    match std::fs::read_to_string(MOUNT_INFO_PATH) {
        Ok(mounts) => Some(
            mounts
                .lines()
                .filter_map(|line| line.split(' ').nth(4))
                .map(|point| PathBuf::from(OsStr::from_bytes(&unescape_mount_point(point))))
                .collect(),
        ),
        Err(_) if cfg!(target_os = "linux") => None,
        Err(_) => Some(BTreeSet::new()),
    }
}

/// Whether a mount lies at `path` or beneath it; on Linux, also when the mount list does not
/// read.
fn mount_at_or_beneath(path: &Path) -> bool {
    mount_points().is_none_or(|points| points.iter().any(|point| point.starts_with(path)))
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
    /// This directory's identity: a record made in another one is never acted on here.
    identity: Identity,
    /// The identity of the cache directory and of each directory above it.
    above_entries: Vec<Identity>,
    /// The cache directory where the file system resolves it.
    cache_real: PathBuf,
    path: PathBuf,
}

impl Trash {
    /// Opens the removed caches' directory inside `cache_dir` (as [`trusted_cache_dir`] resolved
    /// it), made with mode 0700 when it is absent, from the open cache directory with no
    /// symbolic link followed and no mount crossed.
    ///
    /// # Errors
    ///
    /// That open does not exist here ([`open_beneath`]), it is not a directory the engine's
    /// account owns and only it may enter, it lies on another file system than the cache
    /// directory, or a mount lies at it or beneath it.
    pub(super) fn open(cache_dir: &Path) -> Result<Self, String> {
        let cache = rustix::fs::open(cache_dir, DIR_FLAGS, Mode::empty())
            .map_err(|error| error.to_string())?;
        match rustix::fs::mkdirat(&cache, EVICTED_DIR_NAME, Mode::RWXU) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(error.to_string()),
        }
        let name = CString::new(EVICTED_DIR_NAME).map_err(|error| error.to_string())?;
        let dir = open_beneath(cache.as_fd(), &name).map_err(|error| error.to_string())?;
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
        let opened = std::fs::File::from(dir.try_clone().map_err(|error| error.to_string())?)
            .metadata()
            .map_err(|error| error.to_string())?;
        let cache_real = std::fs::canonicalize(cache_dir).map_err(|error| error.to_string())?;
        let above_entries = cache_real
            .ancestors()
            .map(|above| std::fs::symlink_metadata(above).map(|found| identity(&found)))
            .collect::<std::io::Result<Vec<Identity>>>()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            cache,
            dir,
            device,
            identity: identity(&opened),
            above_entries,
            cache_real,
            path,
        })
    }

    /// Whether `record` names an entry of this directory, not of one another cache directory
    /// had (on this file system or another).
    pub(super) fn holds(&self, record: &EvictedRecord) -> bool {
        (record.trash_dev, record.trash_ino) == self.identity
    }

    /// Whether removing what this directory holds would change what `lookup` names: no warm
    /// path may lie in it.
    pub(super) fn overlapped_by(&self, lookup: &Lookup) -> bool {
        lookup.overlaps(
            &self.cache_real.join(EVICTED_DIR_NAME),
            self.identity,
            &self.above_entries,
        )
    }

    /// Moves the cache path `path` out of use, into this directory, and answers what to record.
    ///
    /// # Errors
    ///
    /// Why it was left: it is not a directory directly in the cache directory, neither the
    /// engine's nor the job account owns it, a mount lies at it or beneath it, a path of
    /// `protected` (other warm keys' lookups) overlaps it, a directory of `service` (the node's
    /// own) lies in it, or the move failed. The move takes no name `recorded` (the moves not
    /// deleted yet) holds.
    pub(super) fn take(
        &self,
        cache_dir: &Path,
        path: &Path,
        owners: EntryOwners,
        (protected, service): (&[&Lookup], &[Lookup]),
        recorded: &BTreeMap<String, EvictedRecord>,
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
        if found.st_dev != self.device || mount_at_or_beneath(&cache_dir.join(name)) {
            return Err("a mount lies at it or beneath it".to_owned());
        }
        // On the cache directory's file system (checked above): its identity is that file
        // system's and its inode.
        let own = (self.identity.0, found.st_ino);
        let real = self.cache_real.join(name);
        if protected
            .iter()
            .any(|other| other.overlaps(&real, own, &self.above_entries))
        {
            return Err("another warm key's path lies in it or passes through it".to_owned());
        }
        if service.iter().any(|dir| dir.lies_in(&real, own)) {
            return Err("one of the node's directories (state or work) lies in it".to_owned());
        }
        let base = name.to_string_lossy();
        let mut attempt = 0;
        let taken = loop {
            let taken = match attempt {
                0 => format!("{base}-{now_ms}"),
                _ => format!("{base}-{now_ms}-{attempt}"),
            };
            let moved = if recorded.contains_key(&taken) {
                Err(rustix::io::Errno::EXIST)
            } else {
                rename_no_replace(self.cache.as_fd(), name, self.dir.as_fd(), &taken)
            };
            match moved {
                Ok(()) => break taken,
                Err(rustix::io::Errno::EXIST) if attempt < MOVE_NAMES_MAX => attempt += 1,
                Err(error) => return Err(error.to_string()),
            }
        };
        let moved = rustix::fs::statat(&self.dir, taken.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| error.to_string())?;
        Ok(EvictedRecord {
            name: taken,
            ino: moved.st_ino,
            trash_dev: self.identity.0,
            trash_ino: self.identity.1,
        })
    }

    /// Deletes the entry `record` names when the entry there is the one the pass moved: a
    /// directory with what it holds, walked from open directories with no symbolic link
    /// followed and no mount crossed, then this directory synced. An entry already gone counts
    /// as deleted once this directory is synced (an earlier pass may have unlinked it and failed
    /// that sync). The walk stops when `stop` answers true; the next pass goes on.
    ///
    /// # Errors
    ///
    /// Why it was left: the record names no single entry of this directory, another entry or
    /// no directory is there now, a mount lies at it or beneath it, the walk failed or stopped,
    /// or the sync failed.
    pub(super) fn delete(
        &self,
        record: &EvictedRecord,
        stop: &dyn Fn() -> bool,
    ) -> Result<(), String> {
        // The name exactly as recorded is one entry's: no `/`, no `.` or `..`, nothing a path's
        // reading would tidy away.
        let single = !matches!(record.name.as_str(), "" | "." | "..") && !record.name.contains('/');
        if !self.holds(record) || !single {
            return Err("the record names no single entry of this directory".to_owned());
        }
        let name = CString::new(record.name.as_bytes()).map_err(|error| error.to_string())?;
        match rustix::fs::statat(&self.dir, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(found) => {
                if found.st_ino != record.ino
                    || found.st_dev != self.device
                    || FileType::from_raw_mode(found.st_mode) != FileType::Directory
                {
                    return Err("the entry there is not the directory the pass moved".to_owned());
                }
                if mount_at_or_beneath(&self.path.join(&record.name)) {
                    return Err("a mount lies at it or beneath it".to_owned());
                }
                match remove_at(
                    self.dir.as_fd(),
                    &name,
                    self.device,
                    0,
                    Some(record.ino),
                    stop,
                ) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    done => done.map_err(|error| error.to_string())?,
                }
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(error.to_string()),
        }
        rustix::fs::fsync(&self.dir).map_err(|error| error.to_string())
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
/// what it holds first, and only with the inode `expect_ino` when it is given. An entry that
/// went while it was walked is passed over; a `NotFound` error means `name` itself went.
fn remove_at(
    dir: BorrowedFd<'_>,
    name: &CStr,
    device: Dev,
    depth: usize,
    expect_ino: Option<u64>,
    stop: &dyn Fn() -> bool,
) -> std::io::Result<()> {
    if stop() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "the service closed",
        ));
    }
    let found = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if expect_ino.is_some_and(|ino| ino != found.st_ino) {
        return Err(std::io::Error::other("it changed while it was removed"));
    }
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
        match remove_at(inner.as_fd(), child, device, depth + 1, None, stop) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            done => done?,
        }
    }
    rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR)?;
    Ok(())
}

/// Removes the directory `name` in `dir` with what it holds, by the walk the pass deletes with
/// (no symbolic link followed, no mount crossed): root's sweep of the job cache data a job
/// account wrote (FLEET-TOOL-PARITY row 5).
///
/// # Errors
///
/// Why the walk stopped.
#[cfg(target_os = "linux")]
pub(crate) fn remove_tree(dir: BorrowedFd<'_>, name: &CStr) -> std::io::Result<()> {
    let device = rustix::fs::fstat(dir)?.st_dev;
    remove_at(dir, name, device, 0, None, &|| false)
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

/// Where no open refuses a mount of the same file system, the removed caches' directory does
/// not open, so nothing is moved or deleted.
#[cfg(not(target_os = "linux"))]
fn open_beneath(_dir: BorrowedFd<'_>, _name: &CStr) -> std::io::Result<OwnedFd> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "a removal that crosses no mount needs Linux's openat2",
    ))
}

/// Renames `from` in `from_dir` to `to` in `to_dir`, never over an entry already there.
#[cfg(target_os = "linux")]
fn rename_no_replace(
    from_dir: BorrowedFd<'_>,
    from: &OsStr,
    to_dir: BorrowedFd<'_>,
    to: &str,
) -> rustix::io::Result<()> {
    rustix::fs::renameat_with(
        from_dir,
        from,
        to_dir,
        to,
        rustix::fs::RenameFlags::NOREPLACE,
    )
}

/// Off Linux the removed caches' directory never opens ([`open_beneath`]), so nothing moves.
#[cfg(not(target_os = "linux"))]
fn rename_no_replace(
    _from_dir: BorrowedFd<'_>,
    _from: &OsStr,
    _to_dir: BorrowedFd<'_>,
    _to: &str,
) -> rustix::io::Result<()> {
    Err(rustix::io::Errno::NOSYS)
}
