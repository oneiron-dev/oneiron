//! Organ-host machine-floor leases.

use std::time::Instant;

use super::{MachineMemory, MemoryLease, MemoryRefusal};

#[cfg(unix)]
struct OrganLease(MemoryLease);

#[cfg(unix)]
impl oneiron_organ_host::FloorLease for OrganLease {
    fn grow(
        &mut self,
        more: u64,
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), oneiron_organ_host::FloorRefusal> {
        MemoryLease::grow_pending(&mut self.0, more, deadline, stopped).map_err(organ_refusal)
    }

    fn materialized(&mut self, reserved: u64, actual: u64) {
        MemoryLease::materialized(&mut self.0, reserved, actual);
    }

    fn shrink(&mut self, bytes: u64) {
        MemoryLease::shrink(&mut self.0, bytes);
    }

    fn grow_untimed(
        &mut self,
        more: u64,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), oneiron_organ_host::FloorRefusal> {
        MemoryLease::grow_untimed(&mut self.0, more, stopped).map_err(organ_refusal)
    }
}

/// The machine's memory as the organ host's floor (FIX 7654): an organ's
/// own buffers lease from the same line as every other lease here, within
/// their call's deadline, and leave it when their call is revoked. Each
/// lease is held by the call's room until the call ends. A frame's lease
/// waits on the same line with no deadline, until it is stopped.
#[cfg(unix)]
pub(crate) struct OrganFloor(pub(crate) MachineMemory);

#[cfg(unix)]
impl oneiron_organ_host::MachineFloor for OrganFloor {
    fn check_irreducible_peak(
        &self,
        pinned: u64,
        bytes: u64,
    ) -> Result<(), oneiron_organ_host::FloorRefusal> {
        self.0
            .empty_lease()
            .check_irreducible_peak(pinned, bytes)
            .map_err(organ_refusal)
    }

    fn try_lease(
        &self,
        bytes: u64,
    ) -> Result<Option<Box<dyn oneiron_organ_host::FloorLease>>, oneiron_organ_host::FloorRefusal>
    {
        self.0
            .try_lease(bytes)
            .map(|lease| {
                lease.map(|lease| {
                    Box::new(OrganLease(lease)) as Box<dyn oneiron_organ_host::FloorLease>
                })
            })
            .map_err(organ_refusal)
    }

    fn track_allocated(&self, bytes: u64) -> Box<dyn oneiron_organ_host::FloorLease> {
        let mut lease = self.0.empty_lease();
        lease.materialized(0, bytes);
        Box::new(OrganLease(lease))
    }

    fn lease(
        &self,
        bytes: u64,
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<Box<dyn oneiron_organ_host::FloorLease>, oneiron_organ_host::FloorRefusal> {
        organ_lease(self.0.lease_until(bytes, deadline, stopped))
    }

    fn lease_untimed(
        &self,
        bytes: u64,
        stopped: &dyn Fn() -> bool,
    ) -> Result<Box<dyn oneiron_organ_host::FloorLease>, oneiron_organ_host::FloorRefusal> {
        organ_lease(self.0.lease_untimed(bytes, stopped))
    }
}

/// A machine lease as the organ host's floor answers it.
#[cfg(unix)]
fn organ_lease(
    leased: Result<MemoryLease, MemoryRefusal>,
) -> Result<Box<dyn oneiron_organ_host::FloorLease>, oneiron_organ_host::FloorRefusal> {
    leased
        .map(|lease| Box::new(OrganLease(lease)) as Box<dyn oneiron_organ_host::FloorLease>)
        .map_err(organ_refusal)
}

#[cfg(unix)]
fn organ_refusal(refused: MemoryRefusal) -> oneiron_organ_host::FloorRefusal {
    match refused {
        MemoryRefusal::Floor { needed, available } => {
            oneiron_organ_host::FloorRefusal::Floor { needed, available }
        }
        MemoryRefusal::WaitedOut { .. } => oneiron_organ_host::FloorRefusal::Deadline,
    }
}
