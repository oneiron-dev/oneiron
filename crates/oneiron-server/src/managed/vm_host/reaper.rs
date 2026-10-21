//! Every end of a VMM generation the driver holds (FIX 7126), in the one
//! order that keeps its exit status for the exit watch's waiters: the kill
//! asked for, the exit read through the watch, which keeps the status, and
//! only then the reap. A stop, a kill and a sleep's snapshot end it through
//! [`VaultVm::end_vmm`], which holds the child and its watch until the reap,
//! so a call cancelled on the way leaves them to the next call or to the
//! driver's drop. A drop cannot await: it kills the child and hands it and
//! its watch to a thread of their own, which reads the exit and then reaps,
//! with nothing a runtime's shutdown cancels between the two.

use super::exit::child_pid;
use super::{VaultVm, VmExitWatch};
use rustix::io::Errno;
use rustix::process::{WaitId, WaitIdOptions, waitid};

impl VaultVm {
    /// Ends the VMM generation the driver holds: kills it when `kill`, reads
    /// its exit through the watch, then reaps it, and lets go of the child
    /// and its watch only once it is reaped. A reap that fails keeps them,
    /// so the VM still counts as running and the driver's drop reaps it.
    pub(super) async fn end_vmm(&mut self, kill: bool) {
        let vault = &self.vault;
        let Some(child) = self.child.as_mut() else {
            return;
        };
        // A child the stop's grace already reaped has nothing left to kill.
        if kill
            && child.id().is_some()
            && let Err(error) = child.start_kill()
        {
            tracing::warn!(
                reason = "vm_kill_failed",
                vault = %vault,
                %error,
                "the vault VM's VMM could not be killed; its exit is awaited all the same"
            );
        }
        if let Some(exit) = &self.exit
            && let Err(error) = exit.wait().await
        {
            tracing::warn!(
                reason = "vm_exit_unread",
                vault = %vault,
                %error,
                "the vault VM's VMM exit status could not be read before its reap"
            );
        }
        let reaped = child.wait().await;
        match reaped {
            Ok(_) => {
                self.child = None;
                self.exit = None;
            }
            Err(error) => tracing::warn!(
                reason = "vm_reap_failed",
                vault = %vault,
                %error,
                "the vault VM's VMM was not reaped; the driver keeps it until its drop"
            ),
        }
    }
}

impl Drop for VaultVm {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            reap_dropped(child, self.exit.take(), &self.vault);
        }
    }
}

/// Kills `child`, a dropped driver's VMM, and hands it with `exit`, its
/// watch, to a thread that reaps it once its exit is read.
fn reap_dropped(mut child: tokio::process::Child, exit: Option<VmExitWatch>, vault: &str) {
    // A child already reaped has no exit left to read.
    if child.id().is_none() {
        return;
    }
    if let Err(error) = child.start_kill() {
        tracing::warn!(
            reason = "vm_kill_failed",
            vault,
            %error,
            "a dropped vault VM driver could not kill its VMM; its exit is awaited all the same"
        );
    }
    let owner = vault.to_owned();
    let spawned = std::thread::Builder::new()
        .name("vm-reaper".into())
        .spawn(move || reap(child, exit, &owner));
    if let Err(error) = spawned {
        tracing::warn!(
            reason = "vm_reaper_unavailable",
            vault,
            %error,
            "no thread could reap a dropped vault VM driver's VMM; the runtime reaps it, and its exit watch's waiters may get an error"
        );
    }
}

/// The reaper thread's work: blocks until `child` exits and its status is
/// read, through `exit` when it watches it, then reaps it.
fn reap(mut child: tokio::process::Child, exit: Option<VmExitWatch>, vault: &str) {
    let observed = match &exit {
        Some(exit) => exit.wait_blocking().map(|_| ()),
        None => exited(&child),
    };
    if let Err(error) = observed {
        tracing::warn!(
            reason = "vm_exit_unread",
            vault,
            %error,
            "a dropped vault VM driver's VMM exit status could not be read before its reap"
        );
    }
    match child.try_wait() {
        Ok(Some(_)) => {}
        Ok(None) => tracing::warn!(
            reason = "vm_reap_failed",
            vault,
            "a dropped vault VM driver's VMM had not exited at its reap; the runtime reaps it"
        ),
        Err(error) => tracing::warn!(
            reason = "vm_reap_failed",
            vault,
            %error,
            "a dropped vault VM driver's VMM could not be reaped"
        ),
    }
}

/// Blocks until `child`, which has no exit watch, exits, without reaping
/// it: nothing reaped it yet, so its pid names it alone.
fn exited(child: &tokio::process::Child) -> std::io::Result<()> {
    let pid = child_pid(child)?;
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOWAIT;
    loop {
        match waitid(WaitId::Pid(pid), options) {
            Ok(_) => return Ok(()),
            Err(Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
}
