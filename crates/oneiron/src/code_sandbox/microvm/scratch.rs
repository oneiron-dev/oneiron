//! Private, clone-safe per-VM scratch custody and crash-leftover reclamation.

#[cfg(unix)]
use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};

use super::backend::backend_error;
use crate::Result;

/// Each prepared handle and backend state shares one custody owner. The last
/// clone removes only its own VM directory; a crash releases the kernel lock.
pub type ScratchHandle = Arc<ScratchCustody>;

pub struct ScratchCustody {
    pub path: PathBuf,
    #[cfg(unix)]
    pub root: PathBuf,
    #[cfg(unix)]
    pub backend: &'static str,
    #[cfg(unix)]
    pub _lock: fs::File,
}

impl Drop for ScratchCustody {
    fn drop(&mut self) {
        // Serialize deletion with every scan of the same scratch root. If
        // locking fails, leave an orphan for the next successful startup reap.
        #[cfg(unix)]
        let Ok(Some(_root_lock)) =
            locked_file(&self.root.join(".owner.lock"), true, true, self.backend)
        else {
            return;
        };
        // The root is host-owned and private. Never follow a replaced VM root.
        if fs::symlink_metadata(&self.path).is_ok_and(|m| m.is_dir() && !m.is_symlink()) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(unix)]
pub fn locked_file(
    path: &Path,
    existing: bool,
    blocking: bool,
    backend: &'static str,
) -> Result<Option<fs::File>> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    if !existing {
        options.create(true).mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|e| backend_error(backend, format!("scratch lock open failed: {}", e.kind())))?;
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Err(backend_error(backend, "scratch lock is not a regular file"));
    }
    let flags = libc::LOCK_EX | if blocking { 0 } else { libc::LOCK_NB };
    // SAFETY: fd is an owned live file, flock has no pointer arguments.
    if unsafe { libc::flock(file.as_raw_fd(), flags) } != 0 {
        let error = io::Error::last_os_error();
        if !blocking && error.kind() == io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(backend_error(
            backend,
            format!("scratch lock failed: {}", error.kind()),
        ));
    }
    Ok(Some(file))
}

