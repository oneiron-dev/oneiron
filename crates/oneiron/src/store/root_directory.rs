//! Descriptor-bound directory identity shared by store opens and writer leases.

use std::ffi::CString;
use std::fs::File;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

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
