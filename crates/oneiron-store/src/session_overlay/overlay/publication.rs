//! Visibility of a segment whose base writer has already committed.

use std::sync::Arc;

use super::ACTIVE_SEGMENT;
use super::lifecycle::{OverlayLifecycleState, SessionOverlay};
use oneiron_contracts::error::{Error, Result};

impl SessionOverlay {
    /// Waits for an earlier base writer's segment to publish before a caller
    /// holding the next base writer inspects its rows. This thread's own
    /// segment is already visible through `write_snapshot` and never waits.
    /// No writer is acquired here: the order remains base -> segment.
    pub fn synchronize_publication(self: &Arc<Self>) -> Result<()> {
        let own_segment = ACTIVE_SEGMENT.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|segment| Arc::ptr_eq(&segment.overlay, self))
        });
        if own_segment {
            return Ok(());
        }
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        while lifecycle.segment_active && lifecycle.state != OverlayLifecycleState::Gone {
            lifecycle = self.segment_available.wait(lifecycle).map_err(|_| {
                Error::InvariantViolation("session overlay lifecycle mutex poisoned")
            })?;
        }
        Ok(())
    }
}
