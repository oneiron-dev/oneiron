//! What an earlier VMM generation left queued on the boot port's and the
//! restore channel's host sockets (FIX 7077). Both listeners live as long as
//! the driver, across every generation it runs, so a connection a dead
//! guest made and nobody accepted would be the next boot's first accept,
//! and its hello or frame taken for the new guest's. Each spawn drops them
//! first, once the generation before it is reaped and before the new VMM
//! exists: no connection the new guest makes can be among them. The custody
//! anchor's exchange socket is a third such listener (FIX 7480).

use super::VaultVm;
use oneiron_vault_contract::vm::{VM_ANCHOR_PORT, VM_BOOT_PORT, VM_RESTORE_PORT};
use std::io::ErrorKind;
use std::os::fd::AsFd as _;
use tokio::net::UnixListener;

impl VaultVm {
    /// Drops every connection queued on the boot port's, the restore
    /// channel's and the anchor exchange's sockets, before a spawn. Only
    /// with no VMM held: one held may still run, and what it queued is its
    /// own. The driver lets go of a VMM only once it is reaped
    /// ([`VaultVm::end_vmm`]).
    pub(super) fn drop_stale_connections(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.is_running(),
            "the vault VM's previous VMM is not reaped yet"
        );
        for (port, listener) in [
            (VM_BOOT_PORT, &self.boot),
            (VM_RESTORE_PORT, &self.restore),
            (VM_ANCHOR_PORT, &self.anchor.exchange),
        ] {
            let dropped = drop_queued(listener)?;
            if dropped > 0 {
                tracing::info!(
                    reason = "vm_stale_connections_dropped",
                    vault = %self.vault,
                    port,
                    dropped,
                    "dropped connections an earlier generation of the vault VM left queued"
                );
            }
        }
        Ok(())
    }
}

/// Accepts and closes every connection queued on `listener` until none is
/// left, and counts them. The accepts are the socket's own, nonblocking,
/// through a second descriptor of it, so a connection the runtime has not
/// yet seen is taken all the same.
fn drop_queued(listener: &UnixListener) -> std::io::Result<usize> {
    let queue = std::os::unix::net::UnixListener::from(listener.as_fd().try_clone_to_owned()?);
    // The runtime's own mode for the socket, made sure of: an empty queue
    // answers at once.
    queue.set_nonblocking(true)?;
    let mut dropped = 0;
    loop {
        match queue.accept() {
            Ok(_) => dropped += 1,
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(dropped),
            // A queued connection its peer gave up on, or a signal.
            Err(error) if error.kind() == ErrorKind::ConnectionAborted => {}
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}
