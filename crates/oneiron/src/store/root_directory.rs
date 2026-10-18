//! Descriptor-bound directory identity shared by store opens and writer leases.

use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, openat, statat, unlinkat};

use super::writer_lease::VAULT_WRITER_LOCK_FILE;
use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FileIdentity {
    dev: u64,
    ino: u64,
}

pub(super) fn open_root_directory(root: &Path) -> Result<File> {
    let path = CString::new(root.as_os_str().as_bytes())
        .map_err(|_| Error::InvalidConfig("vault root path contains a NUL byte".to_owned()))?;
    // SAFETY: `path` is a live NUL-terminated C string for the whole call, and
    // `libc::open` returns either a fresh descriptor owned by nobody else or a
    // negative error code; `adopt_descriptor` checks the code before taking
    // ownership, so the descriptor is closed exactly once.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_DIRECTORY | libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    Ok(adopt_descriptor(fd)?)
}

/// Open a spool under the retained vault root, never through its old pathname.
/// The staging directory itself is opened no-follow and kept pinned until the
/// anonymous tempfile has been created through that descriptor.
pub(super) fn lfs_staging_file(root: &File) -> Result<File> {
    let staging = lfs_staging_dir(root)?;
    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/self/fd/{}", staging.as_raw_fd());
        Ok(tempfile::tempfile_in(path)?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Other Unix hosts have no guaranteed /proc/self/fd directory walk.
        // Create exclusively relative to the held directory, then unlink the
        // name immediately so the returned file is just as anonymous.
        let name = CString::new(format!(".lfs-spool-{}", uuid::Uuid::now_v7()))
            .map_err(|_| Error::InvariantViolation("lfs spool name"))?;
        // SAFETY: the held directory and NUL-terminated name live through
        // openat; adopt_descriptor owns only a successfully opened new fd.
        let fd = unsafe {
            libc::openat(
                staging.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        let spool = adopt_descriptor(fd)?;
        // SAFETY: staging still holds the directory fd, name is unchanged,
        // and unlinkat transfers no descriptor ownership.
        if unsafe { libc::unlinkat(staging.as_raw_fd(), name.as_ptr(), 0) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(spool)
    }
}

/// The staging directory under the retained vault root, made 0700 when
/// absent and opened no-follow: the directory an anonymous spool or the
/// import's scratch row index (FIX 3678) is made in.
pub(super) fn lfs_staging_dir(root: &File) -> Result<File> {
    let name = c"lfs-staging";
    // SAFETY: `root` holds a live directory descriptor and `name` is a static
    // NUL-terminated single component. mkdirat does not transfer ownership.
    let created = unsafe { libc::mkdirat(root.as_raw_fd(), name.as_ptr(), 0o700) };
    if created < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
    }
    // SAFETY: the descriptor is owned by `root` for this call; the static
    // component remains live. adopt_descriptor takes ownership only on success.
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_DIRECTORY | libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    let staging = adopt_descriptor(fd)?;
    if root.metadata()?.dev() != staging.metadata()?.dev() {
        return Err(Error::InvalidConfig(
            "lfs staging crosses the vault filesystem".to_owned(),
        ));
    }
    Ok(staging)
}

/// Identity of the directory the caller's path names RIGHT NOW, without
/// following a final symlink. `None` means the path no longer names a
/// directory at all.
pub(super) fn named_directory_identity(root: &Path) -> Result<Option<FileIdentity>> {
    match std::fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(Some(file_identity(&metadata))),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// A directory on a path that another user could change: move entries in
/// it, or, for a vault's own directory, change entries in it. Its `Display`
/// names the directory and the `chmod` that fixes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedPath {
    /// The directory.
    pub directory: PathBuf,
    /// Whether it is the vault's own directory, writable by a group or other.
    pub vault_root: bool,
}

impl std::fmt::Display for SharedPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.vault_root {
            write!(
                f,
                "another user could change entries in the vault {}; chmod go-w it",
                self.directory.display()
            )
        } else {
            write!(
                f,
                "another user could move entries in {}; make it and the directories above it \
                 yours or root's with no group or other write (chmod go-w), or sticky (chmod +t)",
                self.directory.display()
            )
        }
    }
}

fn refused(shared: &SharedPath) -> Error {
    Error::InvalidConfig(format!("restore refused: {shared}"))
}

/// Refuses unless no other user can move an entry anywhere on the way to
/// `dir` ([`shared_path`]). On such a path every name a restore makes, opens
/// or exchanges stays the one it checked.
pub fn refuse_shared_path(dir: &Path) -> Result<()> {
    shared_path(dir)?.map_or(Ok(()), |shared| Err(refused(&shared)))
}

/// The first directory on the way to `dir` in which another user could move
/// an entry, if any. The path is resolved here one name at a time from `/`,
/// as the kernel resolves it, through every link and `..`: each directory
/// passed must be this user's or root's, with no group or other write unless
/// its sticky bit keeps others to their own entries, and each link followed
/// must be this user's or root's. Mode bits only: an access-control list
/// granting another user more is not read.
pub fn shared_path(dir: &Path) -> Result<Option<SharedPath>> {
    use std::ffi::OsString;
    use std::path::Component;
    let euid = rustix::process::geteuid().as_raw();
    let ours = |metadata: &std::fs::Metadata| metadata.uid() == euid || metadata.uid() == 0;
    let shared = |at: &Path| {
        Ok(Some(SharedPath {
            directory: at.to_path_buf(),
            vault_root: false,
        }))
    };
    // Names still to resolve, the next one last; `None` is the root.
    let mut names: Vec<Option<OsString>> = Vec::new();
    let push = |names: &mut Vec<Option<OsString>>, path: &Path| {
        for component in path.components().rev() {
            names.push(match component {
                Component::RootDir | Component::Prefix(_) => None,
                Component::CurDir => continue,
                Component::ParentDir => Some(OsString::from("..")),
                Component::Normal(name) => Some(name.to_owned()),
            });
        }
    };
    push(&mut names, &std::path::absolute(dir)?);
    let mut at = PathBuf::from("/");
    let mut links = 0;
    while let Some(name) = names.pop() {
        let next = match name {
            None => PathBuf::from("/"),
            Some(name) if name == ".." => {
                at.pop();
                continue;
            }
            Some(name) => at.join(name),
        };
        let metadata = std::fs::symlink_metadata(&next)?;
        if metadata.file_type().is_symlink() {
            links += 1;
            if links > 40 || !ours(&metadata) {
                return shared(&next);
            }
            push(&mut names, &std::fs::read_link(&next)?);
            continue;
        }
        let shielded = metadata.mode() & 0o022 == 0 || metadata.mode() & 0o1000 != 0;
        if !(metadata.is_dir() && ours(&metadata) && shielded) {
            return shared(&next);
        }
        at = next;
    }
    Ok(None)
}

/// [`refuse_shared_path`] for a vault's own directory ([`shared_vault_root`]).
pub fn refuse_shared_vault_root(root: &Path) -> Result<()> {
    shared_vault_root(root)?.map_or(Ok(()), |shared| Err(refused(&shared)))
}

/// [`shared_path`] for a vault's own directory, which must also be writable
/// by no group or other, sticky or not: the vault open makes and opens names
/// inside it.
pub fn shared_vault_root(root: &Path) -> Result<Option<SharedPath>> {
    if let Some(shared) = shared_path(root)? {
        return Ok(Some(shared));
    }
    Ok(
        (std::fs::metadata(root)?.mode() & 0o022 != 0).then(|| SharedPath {
            directory: root.to_path_buf(),
            vault_root: true,
        }),
    )
}

/// Makes the directory `path` names, owner-only whatever the umask, through
/// a descriptor of the directory holding it, and returns the one made,
/// opened through that same descriptor.
pub(super) fn make_directory(path: &Path) -> Result<File> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(Error::InvalidConfig(
            "a directory to make needs a parent and a name".to_owned(),
        ));
    };
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let parent = File::from(
        rustix::fs::open(parent_or_here(parent), flags, Mode::empty())
            .map_err(std::io::Error::from)?,
    );
    rustix::fs::mkdirat(&parent, name, Mode::from_raw_mode(0o700)).map_err(std::io::Error::from)?;
    let made = openat(&parent, name, flags | OFlags::NOFOLLOW, Mode::empty())
        .map_err(std::io::Error::from)?;
    Ok(File::from(made))
}

/// `parent`, or the working directory when a relative path has none.
pub(super) fn parent_or_here(parent: &Path) -> &Path {
    if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    }
}

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

#[cfg(test)]
type RootEntryCallback = Box<dyn FnMut(&std::ffi::CStr)>;

#[cfg(test)]
thread_local! {
    static AFTER_ROOT_ENTRY_REMOVED: std::cell::RefCell<Option<RootEntryCallback>> =
        std::cell::RefCell::new(None);
}

/// Runs `callback` with each entry's name as this thread removes it from the
/// root of a held directory, until the removal ends.
#[cfg(test)]
pub(crate) fn arm_after_root_entry_removed(callback: impl FnMut(&std::ffi::CStr) + 'static) {
    AFTER_ROOT_ENTRY_REMOVED.with(|slot| *slot.borrow_mut() = Some(Box::new(callback)));
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

pub(super) fn adopt_descriptor(fd: libc::c_int) -> std::io::Result<File> {
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a non-negative descriptor just returned by `open`/
    // `openat` and held by no other owner, so this `File` becomes its sole
    // owner and closes it exactly once.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    }
}
