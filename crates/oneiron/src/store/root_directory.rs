//! Descriptor-bound directory identity shared by store opens and writer leases.

use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, openat, statat, unlinkat};

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

/// Makes the directory `path` names, through a descriptor of the directory
/// holding it, and returns the identity of the one made, read through that
/// same descriptor. With `private`, that parent must be this user's and
/// writable by no group or other, so no one else can move an entry in or out
/// of it: the identity returned stays the one its name there holds.
pub(super) fn make_directory(path: &Path, private: bool) -> Result<FileIdentity> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(Error::InvalidConfig(
            "a directory to make needs a parent and a name".to_owned(),
        ));
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let parent =
        File::from(rustix::fs::open(parent, flags, Mode::empty()).map_err(std::io::Error::from)?);
    if private {
        let metadata = parent.metadata()?;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o022 != 0 {
            return Err(Error::InvalidConfig(
                "a replacing restore is built only where no one else may write".to_owned(),
            ));
        }
    }
    rustix::fs::mkdirat(&parent, name, Mode::from_raw_mode(0o777)).map_err(std::io::Error::from)?;
    let made = openat(&parent, name, flags | OFlags::NOFOLLOW, Mode::empty())
        .map_err(std::io::Error::from)?;
    Ok(file_identity(&File::from(made).metadata()?))
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
    empty_directory(held.as_fd())?;
    still_named()?;
    std::fs::remove_dir(path)?;
    Ok(())
}

/// Removes every entry of `dir`, depth first. A link is removed, never
/// followed.
fn empty_directory(dir: BorrowedFd<'_>) -> std::io::Result<()> {
    let mut entries = Vec::new();
    for entry in Dir::read_from(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name != c"." && name != c".." {
            entries.push((name.to_owned(), entry.file_type()));
        }
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
            empty_directory(child.as_fd())?;
            unlinkat(dir, name.as_c_str(), AtFlags::REMOVEDIR)?;
        } else {
            unlinkat(dir, name.as_c_str(), AtFlags::empty())?;
        }
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
