//! Native page admission for a held call, outside its complete write door.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use oneiron::Vault;
use oneiron::edit_settle::{OrganWait, OrganWaitView};
use oneiron::store::native_write::{NativeWriteAccount, NativeWriteAttempt};

use crate::error::HostError;
use crate::shutdown;
use crate::resource_memory::{FloorRefusal, SharedFloorLease};

struct WaitPages {
    room: Arc<dyn SharedFloorLease>,
    denied: AtomicUsize,
}

impl NativeWriteAccount for WaitPages {
    fn reserve(&self, bytes: usize) -> bool {
        if self.room.try_reserve_pending(bytes as u64) {
            true
        } else {
            self.denied.fetch_max(bytes, Ordering::Relaxed);
            false
        }
    }

    fn materialized(&self, bytes: usize) {
        self.room.materialized_reserved(bytes as u64);
    }

    fn release(&self, bytes: usize, allocated: bool) {
        if allocated {
            self.room.reclaimed(bytes as u64);
        } else {
            self.room.cancel_reserved(bytes as u64);
        }
    }
}

struct NativeScope(Arc<WaitPages>);

impl Drop for NativeScope {
    fn drop(&mut self) {
        // No writer or growth wait remains. Cached native buffers keep their
        // actual charge; their later physical frees no longer retain credit.
        self.0.room.finish();
    }
}

pub(super) fn hold(
    vault: &Vault,
    wait: &OrganWait,
    reason: &str,
    room: Option<Arc<dyn SharedFloorLease>>,
) -> Result<OrganWaitView, HostError> {
    let Some(room) = room else {
        return vault.hold_organ_wait(wait, reason).map_err(HostError::from);
    };
    let pages = Arc::new(WaitPages {
        room,
        denied: AtomicUsize::new(0),
    });
    let _scope = NativeScope(Arc::clone(&pages));
    // Capture the real mesh cancel before any queue handoff. No execution
    // deadline is invented for a call which is merely being held offline.
    let cancel = shutdown::current();
    loop {
        let attempt = NativeWriteAttempt::new(pages.clone());
        let result = vault.hold_organ_wait_accounted(wait, reason, &attempt);
        let denied = pages.denied.swap(0, Ordering::Relaxed);
        if result.is_err() && denied > 0 && !attempt.own_rows_committed() {
            // The entire door has returned, with its writer and read loans
            // gone. Reuse this same lease's cumulative/reclaimed room; the
            // next attempt repeats every current-row and deletion check.
            pages
                .room
                .reserve_pending_untimed(denied as u64, &|| {
                    cancel.as_ref().is_some_and(|cancel| cancel.is_stopping())
                })
                .map_err(refused)?;
            continue;
        }
        return result.map_err(HostError::from);
    }
}

fn refused(refusal: FloorRefusal) -> HostError {
    match refusal {
        FloorRefusal::Floor { needed, available } => HostError::Io(std::io::Error::new(
            std::io::ErrorKind::OutOfMemory,
            format!("held-call persistence needs {needed} bytes, {available} available"),
        )),
        FloorRefusal::Deadline => HostError::Interrupted,
    }
}
