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
pub static GUEST_PERMITS: AtomicU64 = AtomicU64::new(0);

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
pub struct GuestPermits(Vec<LinePermit>);

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
    pub attached: RwLock<Option<Arc<dyn HostNetFloor>>>,
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

