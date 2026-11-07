//! The host floor guests' network work charges (FIX 5978, FIX 5979,
//! FIX 6299, FIX 6304).
//!
//! Each descriptor and worker thread a guest's socket entries and relays
//! hold takes one permit of the process's descriptor line
//! ([`crate::host_descriptors`]), the same line a serving host's own sockets
//! take theirs from. A vault no host attached a floor to charges that line
//! all the same: an embedded engine, a CLI run and a test meter their
//! guests' sockets as a served vault does. A host's attached floor adds its
//! byte line for paused bodies; it never brings a second descriptor budget.
//!
//! A bundle takes free permits only, all or none, so a socket waiting in the
//! line gets the next permit that comes free. A bundle that finds too little
//! room crosses the line: a serving host asks its Connections question and
//! raises its live pool check once for that crossing, not once per retry.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use oneiron_container::{
    HOST_NET_FD_FLOOR, HOST_NET_WORKER_FLOOR, HostNetFloor, HostNetPermit, floor_saturated,
};

use crate::Vault;
use crate::host_descriptors::descriptor_line;
use crate::work_line::{LinePermit, LineShortage};

/// Permits of the descriptor line guests' network work holds now.
static GUEST_PERMITS: AtomicU64 = AtomicU64::new(0);

/// How many of the process's descriptor permits guests' network work holds
/// now: one for each descriptor and each worker thread (FIX 6304).
pub fn guest_network_permits() -> u64 {
    GUEST_PERMITS.load(Ordering::Relaxed)
}

/// The process's descriptor line, as guests' network work takes it: a
/// permit for each descriptor and each worker thread. It charges no bytes.
pub struct ProcessDescriptorFloor;

impl HostNetFloor for ProcessDescriptorFloor {
    fn acquire(&self, fds: usize, workers: usize) -> io::Result<HostNetPermit> {
        match descriptor_line().try_admit_background_bundle(fds.saturating_add(workers)) {
            Ok(permits) => Ok(HostNetPermit::new(GuestPermits::counted(permits))),
            // The descriptors are counted before the workers, so the floor
            // named is the first one the free permits could not cover.
            Err(LineShortage { free }) if free < fds => Err(floor_saturated(HOST_NET_FD_FLOOR)),
            Err(LineShortage { .. }) => Err(floor_saturated(HOST_NET_WORKER_FLOOR)),
        }
    }
}

/// One bundle's permits, counted in [`guest_network_permits`] until they go.
struct GuestPermits(Vec<LinePermit>);

impl GuestPermits {
    fn counted(permits: Vec<LinePermit>) -> Self {
        GUEST_PERMITS.fetch_add(permits.len() as u64, Ordering::Relaxed);
        Self(permits)
    }
}

impl Drop for GuestPermits {
    fn drop(&mut self) {
        GUEST_PERMITS.fetch_sub(self.0.len() as u64, Ordering::Relaxed);
    }
}

/// A vault's host floor: the floor its serving host attached
/// ([`Vault::attach_host_net_floor`]), looked up at each charge, else the
/// process's descriptor line ([`ProcessDescriptorFloor`]). A relay opened
/// before an attachment charges the attached floor from then on.
#[derive(Default)]
pub struct VaultHostFloor {
    attached: RwLock<Option<Arc<dyn HostNetFloor>>>,
}

impl HostNetFloor for VaultHostFloor {
    fn acquire(&self, fds: usize, workers: usize) -> io::Result<HostNetPermit> {
        let attached = self.attached.read().unwrap_or_else(PoisonError::into_inner);
        match &*attached {
            Some(floor) => floor.acquire(fds, workers),
            None => ProcessDescriptorFloor.acquire(fds, workers),
        }
    }

    fn acquire_bytes(&self, bytes: u64) -> io::Result<HostNetPermit> {
        let attached = self.attached.read().unwrap_or_else(PoisonError::into_inner);
        match &*attached {
            Some(floor) => floor.acquire_bytes(bytes),
            None => ProcessDescriptorFloor.acquire_bytes(bytes),
        }
    }
}

impl Vault {
    /// Attaches the floor `attach` builds as this vault's host floor
    /// (FIX 6299): every relay a run on this vault opens charges it from
    /// then on. The floor a previous host attached goes first, and its hold
    /// on the descriptor line's policy with it, so the vault's host served
    /// again takes the policy back. Permits held keep their owners.
    pub fn attach_host_net_floor(&self, attach: impl FnOnce() -> Arc<dyn HostNetFloor>) {
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
    pub fn host_net_floor(&self) -> Arc<dyn HostNetFloor> {
        Arc::clone(&self.host_net_floor) as Arc<dyn HostNetFloor>
    }

    /// Takes `fds` descriptors and `workers` threads of this vault's host
    /// floor, looked up now, as a run's relay charges it. For a host relay
    /// that serves no run (FIX 7333).
    ///
    /// # Errors
    /// Returns the floor's `WouldBlock` back-pressure when it is full.
    pub fn acquire_host_net_floor(&self, fds: usize, workers: usize) -> io::Result<HostNetPermit> {
        self.host_net_floor.acquire(fds, workers)
    }

    /// Takes `bytes` of this vault's host floor, looked up now, as a run's
    /// relay charges its paused request and answer bodies; a vault no host
    /// attached a floor to charges no bytes.
    ///
    /// # Errors
    /// Returns the floor's `WouldBlock` back-pressure when it is full.
    pub fn acquire_host_net_bytes(&self, bytes: u64) -> io::Result<HostNetPermit> {
        self.host_net_floor.acquire_bytes(bytes)
    }
}
