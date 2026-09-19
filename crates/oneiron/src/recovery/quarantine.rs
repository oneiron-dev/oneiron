//! Atomic no-clobber quarantine renames. Never copy then unlink a live pathname.

use super::invalid_artifact_path;
use crate::error::{ArtifactError, Error, Result};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub(super) fn quarantine_invalid_artifact(path: &Path, expected: &[u8]) -> Result<PathBuf> {
    // A changed source is not the artifact we validated. Leave it alone.
    if !fs::symlink_metadata(path)?.file_type().is_file() || fs::read(path)? != expected {
        return Err(Error::ConcurrentWrite(
            "recovery artifact changed before quarantine",
        ));
    }
    for suffix in 1..=u16::MAX {
        let candidate = invalid_artifact_path(path, suffix);
        match rename_no_replace(path, &candidate) {
            Ok(()) => {
                // Rename consumes exactly one directory entry, not a later
                // replacement. If a writer raced between read and rename,
                // preserve the moved bytes, stop recovery and never delete them.
                if fs::read(&candidate)? != expected {
                    let _ = rename_no_replace(&candidate, path);
                    return Err(Error::ConcurrentWrite(
                        "recovery artifact changed during quarantine",
                    ));
                }
                sync_parent(path)?;
                return Ok(candidate);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(ArtifactError::RecoveryArtifactQuarantineExhausted {
        path: path.to_path_buf(),
    }
    .into())
}

#[cfg(unix)]
pub(super) fn sync_parent(path: &Path) -> io::Result<()> {
    fs::File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()
}
#[cfg(not(unix))]
pub(super) fn sync_parent(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
pub(super) fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let from = CString::new(from.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let to = CString::new(to.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: both C strings remain live through the call. No descriptor or
    // pointer escapes. EXCL/NOREPLACE prevents overwriting even a symlink.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    // SAFETY: CString checked both paths for interior NULs; their allocations live
    // through the call. RENAME_EXCL forbids replacing an existing destination.
    let rc = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
#[cfg(windows)]
pub(super) fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: NUL-terminated arrays remain live; flags deliberately omit REPLACE_EXISTING.
    let rc = unsafe {
        windows_sys::Win32::Storage::FileSystem::MoveFileExW(from.as_ptr(), to.as_ptr(), 0)
    };
    if rc != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    windows
)))]
pub(super) fn rename_no_replace(_from: &Path, _to: &Path) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}
