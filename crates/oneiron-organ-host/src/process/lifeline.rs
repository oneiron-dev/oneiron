//! One organ process's life: the child, the cell its descendants are fenced
//! in (FIX 7887), the kernel limits that grow with what its own buffers are
//! granted (FIX 6194), and the way to end it all.

use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::{OrganProcess, lock};
use crate::budget::NativeLimits;
use crate::sandbox::Cell;

/// The child and the way to end it, shared with the reader thread so
/// either side can end and reap it.
#[derive(Debug)]
pub(super) struct Lifeline {
    pub(super) pid: u32,
    child: Mutex<Option<Child>>,
    /// Set once `end` has reaped the child; read without waiting for an
    /// `end` in progress.
    pub(super) reaped: AtomicBool,
    /// A handle on the host's end of the socket, kept to shut it down.
    socket: UnixStream,
    /// The cgroup every process the organ starts is in, when this host
    /// could make one.
    cell: Mutex<Option<Cell>>,
    /// The kernel's data and file-size limits, when the host keeps them in
    /// step with what the organ's own buffers are granted.
    limits: Option<Limits>,
}

/// A first-party organ's soft data and file-size limits: its memory grant,
/// and what its own buffers have been granted on top (Linux).
#[derive(Debug)]
struct Limits {
    base: u64,
    granted: Mutex<u64>,
}

impl Lifeline {
    /// `limits` is the memory grant whose soft limits move as the organ's
    /// buffers are granted; `None` keeps them where the start set them.
    pub(super) fn new(
        child: Child,
        socket: UnixStream,
        cell: Option<Cell>,
        limits: Option<u64>,
    ) -> Arc<Self> {
        Arc::new(Self {
            pid: child.id(),
            child: Mutex::new(Some(child)),
            reaped: AtomicBool::new(false),
            socket,
            cell: Mutex::new(cell),
            limits: limits.map(|base| Limits {
                base,
                granted: Mutex::new(0),
            }),
        })
    }

    /// Kills the organ and everything it started: its cell, when it has
    /// one, then its process group. Shuts the socket down and reaps the
    /// child. Safe to call twice; once the reap is done it returns without
    /// waiting, so dropping an ended process never waits on the thread that
    /// reaped it.
    pub(super) fn end(&self) {
        if self.reaped.load(Ordering::SeqCst) {
            return;
        }
        let _ = self.socket.shutdown(Shutdown::Both);
        // Held through the reap, so whoever calls second returns only once
        // the process is gone.
        let mut slot = lock(&self.child);
        let Some(child) = slot.as_mut() else {
            return;
        };
        // The cell first: it reaches a descendant that left the group.
        if let Some(cell) = lock(&self.cell).as_ref() {
            cell.kill();
        }
        if let Ok(group) = i32::try_from(self.pid) {
            // SAFETY: kill(2) with a negative pid signals the process group
            // the organ leads (the sandbox's setpgid). Only this call reaps
            // the child (`exited` looks without reaping), so its pid, and
            // with it the group id, cannot have been reused.
            unsafe {
                libc::kill(-group, libc::SIGKILL);
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        *slot = None;
        // Removed now if it is empty, else at the next start or end.
        drop(lock(&self.cell).take());
        self.reaped.store(true, Ordering::SeqCst);
    }

    /// Whether the organ has exited. It looks without reaping: a reaped
    /// pid could be reused before `end` signals its group.
    pub(super) fn exited(&self) -> bool {
        let child = lock(&self.child);
        if child.is_none() {
            return true;
        }
        // SAFETY: an all-zero siginfo_t is a valid value of this plain C
        // struct; waitid(2) only writes into it.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: as above; WNOWAIT leaves the child waitable for `end`.
        let found = unsafe {
            libc::waitid(
                libc::P_PID,
                self.pid,
                &raw mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        // With WNOHANG, a child still running leaves si_pid zero.
        // SAFETY: waitid filled `info` (or left it zeroed).
        found == 0 && unsafe { info.si_pid() } != 0
    }

    /// Whether `end` has run: the process and its group are gone.
    pub(super) fn ended(&self) -> bool {
        lock(&self.child).is_none()
    }

    /// Moves the organ's soft limits to its grant plus `granted` more, or
    /// less. The child's slot is held meanwhile, so its pid is still its
    /// own: a reaped child is never touched.
    fn regrant(&self, more: bool, bytes: u64) {
        let Some(limits) = &self.limits else {
            return;
        };
        let child = lock(&self.child);
        if child.is_none() {
            return;
        }
        let mut granted = lock(&limits.granted);
        *granted = if more {
            granted.saturating_add(bytes)
        } else {
            granted.saturating_sub(bytes)
        };
        soften(self.pid, limits.base.saturating_add(*granted));
    }
}

/// Sets the soft data and file-size limits of `pid`, under no hard one.
#[cfg(target_os = "linux")]
fn soften(pid: u32, soft: u64) {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return;
    };
    let limit = libc::rlimit {
        rlim_cur: libc::rlim_t::try_from(soft).unwrap_or(libc::RLIM_INFINITY),
        rlim_max: libc::RLIM_INFINITY,
    };
    for resource in [libc::RLIMIT_DATA, libc::RLIMIT_FSIZE] {
        // SAFETY: prlimit(2) on the organ's own pid, its child unreaped (the
        // caller holds its slot), so the pid is not another process's; it
        // reads a fully initialized struct and writes nothing back.
        unsafe {
            libc::prlimit(pid, resource, &limit, std::ptr::null_mut());
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn soften(_: u32, _: u64) {}

impl NativeLimits for OrganProcess {
    fn grant(&self, bytes: u64) {
        self.lifeline.regrant(true, bytes);
    }

    fn give_back(&self, bytes: u64) {
        self.lifeline.regrant(false, bytes);
    }
}

/// Ends a just-spawned child unless the start completes.
pub(super) struct EndOnDrop(pub(super) Option<Arc<Lifeline>>);

impl Drop for EndOnDrop {
    fn drop(&mut self) {
        if let Some(lifeline) = self.0.take() {
            lifeline.end();
        }
    }
}
