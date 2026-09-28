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
pub(super) type ScratchHandle = Arc<ScratchCustody>;

pub(super) struct ScratchCustody {
    path: PathBuf,
    #[cfg(unix)]
    root: PathBuf,
    #[cfg(unix)]
    backend: &'static str,
    #[cfg(unix)]
    _lock: fs::File,
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

pub(super) fn provision(
    root: &Path,
    vm_id: &str,
    backend: &'static str,
) -> Result<(PathBuf, ScratchHandle)> {
    #[cfg(unix)]
    {
        let _root_lock = locked_file(&root.join(".owner.lock"), false, true, backend)?
            .ok_or_else(|| backend_error(backend, "scratch root lock busy"))?;
        reap_locked(root, backend)?;
        let vm_root = root.join(vm_id);
        fs::create_dir(&vm_root).map_err(|e| {
            backend_error(backend, format!("VM scratch creation failed: {}", e.kind()))
        })?;
        let lock = match locked_file(&vm_root.join(".lock"), false, false, backend) {
            Ok(Some(file)) => file,
            Ok(None) => return Err(backend_error(backend, "new VM lock busy")),
            Err(error) => {
                let _ = fs::remove_dir_all(&vm_root);
                return Err(error);
            }
        };
        let custody = Arc::new(ScratchCustody {
            path: vm_root.clone(),
            root: root.to_path_buf(),
            backend,
            _lock: lock,
        });
        Ok((vm_root, custody))
    }
    #[cfg(not(unix))]
    {
        let vm_root = root.join(vm_id);
        fs::create_dir(&vm_root).map_err(|e| {
            backend_error(backend, format!("VM scratch creation failed: {}", e.kind()))
        })?;
        let custody = Arc::new(ScratchCustody {
            path: vm_root.clone(),
        });
        Ok((vm_root, custody))
    }
}

/// Reap only completed orphan VM roots, never a live handle in another process.
/// Must hold the root lock during both reaping and VM creation.
#[cfg(unix)]
fn reap_locked(root: &Path, backend: &'static str) -> Result<()> {
    for entry in fs::read_dir(root)
        .map_err(|e| backend_error(backend, format!("scratch scan failed: {}", e.kind())))?
    {
        let entry = entry
            .map_err(|e| backend_error(backend, format!("scratch entry failed: {}", e.kind())))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // Never remove unrelated contents (including an old application's scratch).
        if name.len() != 32 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|e| {
            backend_error(backend, format!("scratch metadata failed: {}", e.kind()))
        })?;
        if !metadata.is_dir() || metadata.is_symlink() {
            continue;
        }
        let lock_path = path.join(".lock");
        let lock = match fs::symlink_metadata(&lock_path) {
            Ok(metadata) if metadata.is_file() && !metadata.is_symlink() => {
                match locked_file(&lock_path, true, false, backend) {
                    Ok(Some(file)) => Some(file),
                    Ok(None) => continue, // live process owns this VM
                    Err(error) => return Err(error),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            _ => continue, // suspicious entry: fail closed, never traverse it
        };
        fs::remove_dir_all(&path).map_err(|e| {
            backend_error(
                backend,
                format!("orphan scratch cleanup failed: {}", e.kind()),
            )
        })?;
        drop(lock);
    }
    Ok(())
}

#[cfg(unix)]
fn locked_file(
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

/// At backend startup, reclaim crash leftovers without creating a new VM.
#[cfg(all(unix, any(test, feature = "microvm-firecracker")))]
pub(super) fn reap(root: &Path, backend: &'static str) -> Result<()> {
    let _root_lock = locked_file(&root.join(".owner.lock"), false, true, backend)?
        .ok_or_else(|| backend_error(backend, "scratch root lock busy"))?;
    reap_locked(root, backend)
}
