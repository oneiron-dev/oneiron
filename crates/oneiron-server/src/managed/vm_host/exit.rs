//! A watch on one VMM generation's exit (FIX 7047): a pidfd taken as the
//! VMM spawns, which any number of tasks await at once while others use the
//! VM. A watch never reaps: it reads the exit status the kernel keeps for
//! the exited child, and the driver keeps owning its kill-on-drop child and
//! reaping it on a stop or a kill, as before. Every reap reads the status
//! through the watch first (FIX 7126, [`super::reaper`]): a stop, a kill, a
//! sleep's snapshot, and a dropped driver's reaper thread alike, so a waiter
//! gets the real one. Only a read of the status that failed leaves a waiter
//! an error instead.

use rustix::io::Errno;
use rustix::process::{Pid, PidfdFlags, WaitId, WaitIdOptions, WaitIdStatus, pidfd_open, waitid};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::{Arc, OnceLock};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// What a waiter on a VMM already reaped, its status unread, is told.
const REAPED: &str = "the driver reaped the VMM before its exit status was read";

/// One VMM generation's exit. Every clone watches the same process; a VMM
/// started again needs a new watch.
#[derive(Debug, Clone)]
pub struct VmExitWatch(Arc<Exit>);

#[derive(Debug)]
struct Exit {
    pidfd: AsyncFd<OwnedFd>,
    /// The status once any waiter read it, for waiters after the reap.
    status: OnceLock<ExitStatus>,
}

impl VmExitWatch {
    /// The watch on `child`, taken right after its spawn: nothing has reaped
    /// it, so its pid names it alone.
    pub(super) fn of(child: &tokio::process::Child) -> std::io::Result<Self> {
        // No `PIDFD_NONBLOCK`: `wait_blocking` blocks on it.
        let pidfd = pidfd_open(child_pid(child)?, PidfdFlags::empty())?;
        Ok(Self(Arc::new(Exit {
            pidfd: AsyncFd::with_interest(pidfd, Interest::READABLE)?,
            status: OnceLock::new(),
        })))
    }

    /// Waits for the VMM to exit and returns its status, without reaping
    /// it. Cancel-safe, and any number of tasks may wait at once. A VMM
    /// reaped while no read of its status succeeded is an error.
    pub async fn wait(&self) -> std::io::Result<ExitStatus> {
        let exit = &self.0;
        loop {
            if let Some(status) = exit.status.get() {
                return Ok(*status);
            }
            let mut ready = exit.pidfd.readable().await?;
            let options = WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG;
            match waitid(WaitId::PidFd(exit.pidfd.get_ref().as_fd()), options) {
                Ok(Some(status)) => {
                    let status = exit_status(&status)?;
                    return Ok(*exit.status.get_or_init(|| status));
                }
                // Readiness the process has not exited behind.
                Ok(None) => ready.clear_ready(),
                Err(Errno::CHILD) => {
                    let status = exit.status.get().copied();
                    return status.ok_or_else(|| std::io::Error::other(REAPED));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// [`Self::wait`] on this thread, blocking it until the VMM exits, and
    /// caching its status the same way, without reaping it. A dropped
    /// driver's reaper thread reads the status so before it reaps
    /// ([`super::reaper`]).
    pub(super) fn wait_blocking(&self) -> std::io::Result<ExitStatus> {
        let exit = &self.0;
        loop {
            if let Some(status) = exit.status.get() {
                return Ok(*status);
            }
            // No `NOHANG`, on a blocking pidfd: this waits for the exit.
            let options = WaitIdOptions::EXITED | WaitIdOptions::NOWAIT;
            match waitid(WaitId::PidFd(exit.pidfd.get_ref().as_fd()), options) {
                Ok(Some(status)) => {
                    let status = exit_status(&status)?;
                    return Ok(*exit.status.get_or_init(|| status));
                }
                Ok(None) => return Err(std::io::Error::other("waitid reported no exit")),
                Err(Errno::INTR) => {}
                Err(Errno::CHILD) => {
                    let status = exit.status.get().copied();
                    return status.ok_or_else(|| std::io::Error::other(REAPED));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

/// `child`'s pid, while nothing has reaped it, so that it names it alone.
pub(super) fn child_pid(child: &tokio::process::Child) -> std::io::Result<Pid> {
    child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw)
        .ok_or_else(|| std::io::Error::other("the VMM has no process id"))
}

/// `waitid`'s report of an exit as the status a reap gives: the exit code,
/// or the terminating signal and whether it dumped core.
fn exit_status(status: &WaitIdStatus) -> std::io::Result<ExitStatus> {
    if let Some(code) = status.exit_status() {
        return Ok(ExitStatus::from_raw((code & 0xff) << 8));
    }
    match status.terminating_signal() {
        Some(signal) if status.dumped() => Ok(ExitStatus::from_raw(signal | 0x80)),
        Some(signal) => Ok(ExitStatus::from_raw(signal)),
        None => Err(std::io::Error::other(
            "the VMM changed state without exiting",
        )),
    }
}
