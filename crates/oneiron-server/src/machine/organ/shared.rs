//! The held job's one machine-memory lease, shared with retained native pages.

use std::sync::Arc;

use oneiron::host_memory::SharedMemoryLease;
use oneiron_organ_host::{FloorRefusal, SharedFloorLease};

use super::{MemoryLease, organ_refusal};

pub(super) fn share(lease: MemoryLease) -> Arc<dyn SharedFloorLease> {
    Arc::new(OrganSharedLease(lease.into_shared()))
}

struct OrganSharedLease(SharedMemoryLease);

impl SharedFloorLease for OrganSharedLease {
    fn grow_pending_untimed(
        &self,
        more: u64,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), FloorRefusal> {
        self.0
            .grow_pending_untimed(more, stopped)
            .map_err(organ_refusal)
    }

    fn reserve_pending_untimed(
        &self,
        bytes: u64,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), FloorRefusal> {
        self.0
            .reserve_pending_untimed(bytes, stopped)
            .map_err(organ_refusal)
    }

    fn try_reserve_pending(&self, bytes: u64) -> bool {
        self.0.try_reserve_pending(bytes)
    }

    fn materialized_reserved(&self, bytes: u64) {
        self.0.materialized_reserved(bytes);
    }

    fn cancel_reserved(&self, bytes: u64) {
        self.0.cancel_reserved(bytes);
    }

    fn materialized(&self, reserved: u64, actual: u64) {
        self.0.materialized(reserved, actual);
    }

    fn shrink(&self, bytes: u64) {
        self.0.shrink(bytes);
    }

    fn reclaimed(&self, bytes: u64) {
        self.0.reclaimed(bytes);
    }

    fn release_allocated(&self, bytes: u64) {
        self.0.release_allocated(bytes);
    }

    fn finish(&self) {
        self.0.finish();
    }
}
