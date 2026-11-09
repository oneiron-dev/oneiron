//! Lifted half of `oneiron::code_sandbox::egress::floor` (core split, `oneiron-agent-runtime`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

pub use oneiron::code_sandbox::egress::floor::*;
#[allow(unused_imports)]
use crate::ext::*;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::PoisonError;
use oneiron_container::HostNetFloor;
use oneiron_container::HostNetPermit;
use crate::Vault;
use crate::work_line::LinePermit;

/// How many of the process's descriptor permits guests' network work holds
/// now: one for each descriptor and each worker thread (FIX 6304).
pub fn guest_network_permits() -> u64 {
    GUEST_PERMITS.load(Ordering::Relaxed)
}

/// Methods of [`GuestPermits`] that moved out of `oneiron` with `code_sandbox::egress::floor` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxEgressFloorGuestPermitsExt {
    fn counted(permits: Vec<LinePermit>) -> Self;
}

impl CodeSandboxEgressFloorGuestPermitsExt for GuestPermits {
    fn counted(permits: Vec<LinePermit>) -> Self {
            GUEST_PERMITS.fetch_add(permits.len() as u64, Ordering::Relaxed);
            Self(permits)
        }
}

/// Methods of [`Vault`] that moved out of `oneiron` with `code_sandbox::egress::floor` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxEgressFloorVaultExt {
    /// Attaches the floor `attach` builds as this vault's host floor
    /// (FIX 6299): every relay a run on this vault opens charges it from
    /// then on. The floor a previous host attached goes first, and its hold
    /// on the descriptor line's policy with it, so the vault's host served
    /// again takes the policy back. Permits held keep their owners.
    fn attach_host_net_floor(&self, attach: impl FnOnce() -> Arc<dyn HostNetFloor>);
    /// This vault's host floor ([`VaultHostFloor`]), for a relay that owns
    /// its handle: a short session's own relay among them (FIX 6300).
    fn host_net_floor(&self) -> Arc<dyn HostNetFloor>;
    /// Takes `fds` descriptors and `workers` threads of this vault's host
    /// floor, looked up now, as a run's relay charges it. For a host relay
    /// that serves no run (FIX 7333).
    ///
    /// # Errors
    /// Returns the floor's `WouldBlock` back-pressure when it is full.
    fn acquire_host_net_floor(&self, fds: usize, workers: usize) -> io::Result<HostNetPermit>;
    /// Takes `bytes` of this vault's host floor, looked up now, as a run's
    /// relay charges its paused request and answer bodies; a vault no host
    /// attached a floor to charges no bytes.
    ///
    /// # Errors
    /// Returns the floor's `WouldBlock` back-pressure when it is full.
    fn acquire_host_net_bytes(&self, bytes: u64) -> io::Result<HostNetPermit>;
}

impl CodeSandboxEgressFloorVaultExt for Vault {
    /// Attaches the floor `attach` builds as this vault's host floor
    /// (FIX 6299): every relay a run on this vault opens charges it from
    /// then on. The floor a previous host attached goes first, and its hold
    /// on the descriptor line's policy with it, so the vault's host served
    /// again takes the policy back. Permits held keep their owners.
    fn attach_host_net_floor(&self, attach: impl FnOnce() -> Arc<dyn HostNetFloor>) {
            let mut attached = self
                .host_net_floor
                .attached
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            drop(attached.take());
            *attached = Some(attach());
        }

    /// This vault's host floor ([`VaultHostFloor`]), for a relay that owns
    /// its handle: a short session's own relay among them (FIX 6300).
    fn host_net_floor(&self) -> Arc<dyn HostNetFloor> {
            Arc::clone(&self.host_net_floor) as Arc<dyn HostNetFloor>
        }

    /// Takes `fds` descriptors and `workers` threads of this vault's host
    /// floor, looked up now, as a run's relay charges it. For a host relay
    /// that serves no run (FIX 7333).
    ///
    /// # Errors
    /// Returns the floor's `WouldBlock` back-pressure when it is full.
    fn acquire_host_net_floor(&self, fds: usize, workers: usize) -> io::Result<HostNetPermit> {
            self.host_net_floor.acquire(fds, workers)
        }

    /// Takes `bytes` of this vault's host floor, looked up now, as a run's
    /// relay charges its paused request and answer bodies; a vault no host
    /// attached a floor to charges no bytes.
    ///
    /// # Errors
    /// Returns the floor's `WouldBlock` back-pressure when it is full.
    fn acquire_host_net_bytes(&self, bytes: u64) -> io::Result<HostNetPermit> {
            self.host_net_floor.acquire_bytes(bytes)
        }
}
