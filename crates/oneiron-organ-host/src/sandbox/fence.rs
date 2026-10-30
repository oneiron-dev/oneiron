//! The descendant fence (FIX 7887): a cgroup of its own for each organ
//! process, made under the engine's own cgroup where that one is the
//! engine's to divide (Linux cgroup v2 with `cgroup.kill`, Linux 5.14 and
//! later, delegated to the engine's user). The child joins its cell between
//! fork and exec, before it can start anything, so every process it starts
//! is in the cell however it leaves its process group; ending the organ
//! writes `cgroup.kill`, which kills them all at once. No PID is polled and
//! nothing is counted. An empty cell is removed as soon as it can be; one
//! whose last processes are still being reaped is removed at the next
//! start or end. At its first organ start the engine also ends and removes
//! the cells of engines that are gone, which a crash leaves behind; a live
//! engine's cells are left alone (FIX 10579).
//!
//! Where the engine's cgroup is not delegated to it, or on a platform with
//! no cgroups, no cell is made and the organ runs on its process group: its
//! isolation fact names why. That is the host's capability to grant (the
//! engine's service unit with `Delegate=yes`), not a refusal here.

use std::ffi::{CStr, CString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

/// Where this engine makes its organs' cells, as it found its own cgroup.
struct Fence {
    dir: Result<PathBuf, String>,
    next: AtomicU64,
    /// Cells ended while their last processes were still being reaped.
    stale: Mutex<Vec<PathBuf>>,
}

fn here() -> &'static Fence {
    static FENCE: OnceLock<Fence> = OnceLock::new();
    FENCE.get_or_init(|| {
        let dir = own_cgroup();
        let stale = match &dir {
            Ok(dir) => sweep(dir),
            Err(_) => Vec::new(),
        };
        Fence {
            dir,
            next: AtomicU64::new(0),
            stale: Mutex::new(stale),
        }
    })
}

/// Ends the cells under `parent` that engines now gone left behind, named
/// for a pid that is neither this process nor alive, and removes them: the
/// ones whose processes are still being reaped come back, to be removed at
/// the next start or end. No failure here refuses or stops anything.
fn sweep(parent: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    let own = std::process::id();
    let mut stale = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|name| name.strip_prefix("oneiron-organ-"))
            .and_then(|rest| rest.split_once('-'))
            .filter(|(_, n)| n.parse::<u64>().is_ok())
            .and_then(|(pid, _)| pid.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == own || alive(pid) {
            continue;
        }
        let dir = entry.path();
        let _ = std::fs::write(dir.join("cgroup.kill"), b"1");
        if !removed(&dir) {
            stale.push(dir);
        }
    }
    stale
}

/// Whether `pid` may name a live process: only `ESRCH` says it does not.
fn alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return true;
    };
    // SAFETY: kill(2) with signal 0 sends nothing; it only looks the pid up.
    let looked = unsafe { libc::kill(pid, 0) };
    looked == 0 || errno() != libc::ESRCH
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Removes a cell's directory: `false` while processes are still in it.
fn removed(dir: &Path) -> bool {
    match std::fs::remove_dir(dir) {
        Ok(()) => true,
        Err(err) => err.kind() == io::ErrorKind::NotFound,
    }
}

/// The engine's own cgroup directory, when it may make cells in it.
#[cfg(target_os = "linux")]
fn own_cgroup() -> Result<PathBuf, String> {
    let own = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|err| format!("the engine's cgroup could not be read: {err}"))?;
    let path = own
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| "the engine is in no cgroup v2 hierarchy".to_owned())?;
    let dir = Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/'));
    if !dir.join("cgroup.kill").exists() {
        return Err(format!(
            "the engine's cgroup {} has no cgroup.kill (cgroup v2 on Linux 5.14 or later)",
            dir.display()
        ));
    }
    for at in [dir.clone(), dir.join("cgroup.procs")] {
        if !writable(&at) {
            return Err(format!(
                "the engine's cgroup {} is not delegated to it",
                dir.display()
            ));
        }
    }
    Ok(dir)
}

#[cfg(not(target_os = "linux"))]
fn own_cgroup() -> Result<PathBuf, String> {
    Err("this platform has no cgroups to fence an organ's descendants in".to_owned())
}

/// Whether this process may write `path`.
#[cfg(target_os = "linux")]
fn writable(path: &Path) -> bool {
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: access(2) reads a NUL-terminated path this function owns.
    unsafe { libc::access(path.as_ptr(), libc::W_OK) == 0 }
}

/// A new cell for one organ process, or why there is none.
pub(super) fn cell() -> Result<Cell, String> {
    let fence = here();
    lock(&fence.stale).retain(|dir| !removed(dir));
    let parent = fence.dir.as_ref().map_err(Clone::clone)?;
    let n = fence.next.fetch_add(1, Ordering::Relaxed);
    let dir = parent.join(format!("oneiron-organ-{}-{n}", std::process::id()));
    std::fs::create_dir(&dir).map_err(|err| format!("the organ's cgroup was not made: {err}"))?;
    match CString::new(dir.join("cgroup.procs").as_os_str().as_bytes()) {
        Ok(procs) => Ok(Cell { dir, procs }),
        Err(_) => {
            let _ = std::fs::remove_dir(&dir);
            Err("the organ's cgroup path holds a NUL".to_owned())
        }
    }
}

/// Joins the cell whose `cgroup.procs` is `procs`, from the child between
/// fork and exec: 0, or the errno that stopped it. It allocates nothing.
pub(super) fn join(procs: &CStr) -> i32 {
    // SAFETY: open(2), write(2) and close(2) on a path made before the fork
    // and a buffer in static memory: async-signal-safe, and no allocation.
    unsafe {
        let fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return errno();
        }
        // "0" moves the writing process.
        let written = libc::write(fd, b"0".as_ptr().cast(), 1);
        let joined = if written == 1 { 0 } else { errno() };
        libc::close(fd);
        joined
    }
}

fn errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// One organ process's cgroup.
#[derive(Debug)]
pub(crate) struct Cell {
    dir: PathBuf,
    procs: CString,
}

impl Cell {
    /// The `cgroup.procs` the child joins.
    pub(super) fn procs(&self) -> &CStr {
        &self.procs
    }

    /// Kills every process in the cell, wherever in the process tree it
    /// went: the organ and all it started.
    pub(crate) fn kill(&self) {
        let _ = std::fs::write(self.dir.join("cgroup.kill"), b"1");
    }
}

impl Drop for Cell {
    /// Removes the cell once its processes are gone; one still being
    /// reaped is removed at the next start or end.
    fn drop(&mut self) {
        let fence = here();
        let mut stale = lock(&fence.stale);
        stale.retain(|dir| !removed(dir));
        if !removed(&self.dir) {
            stale.push(std::mem::take(&mut self.dir));
        }
    }
}
