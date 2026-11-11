//! Canonical reader-ledger writes that supersede rows in a sealed overlay.

use super::*;
use crate::session_overlay::keyspace::{OverlayKeyspace, retire_snapshot_row};

/// The same publication permit as an overlay segment, held by a base writer
/// until its durable ledger changes stop being shadowed by the sealed room.
pub struct BaseRowRetirementGuard {
    segment: TxnSegmentGuard,
    mode_generation: u64,
}

impl BaseRowRetirementGuard {
    /// Retires only these full VaultMeta keys after their base write commits.
    /// A flip-back leaves the new mode's overlay untouched, even if a row has
    /// the same bytes as the old one. An aborted write drops the guard instead.
    pub fn commit(mut self, keys: impl IntoIterator<Item = Vec<u8>>) -> Result<()> {
        let segment = ACTIVE_SEGMENT.with(|slot| slot.borrow_mut().take());
        let Some(segment) = segment else {
            return Err(Error::InvariantViolation(
                "session txn segment disappeared before retirement",
            ));
        };
        let overlay = &self.segment.overlay;
        if !Arc::ptr_eq(&segment.overlay, overlay) {
            return Err(Error::InvariantViolation(
                "another session txn segment replaced the retirement segment",
            ));
        }
        {
            let lifecycle = overlay.lifecycle.lock().map_err(|_| {
                Error::InvariantViolation("session overlay lifecycle mutex poisoned")
            })?;
            if lifecycle.generation == segment.generation
                && lifecycle.sealed_mode_is(self.mode_generation)
            {
                let mut next = overlay.state.load_full().as_ref().clone();
                for key in keys {
                    retire_snapshot_row(
                        &mut next,
                        &segment.preview,
                        OverlayKeyspace::VaultMeta,
                        &key,
                    );
                }
                next.recalculate_bytes();
                overlay.state.store(Arc::new(next));
            }
        }
        drop(segment);
        self.segment.finished = true;
        overlay.charge_now();
        Ok(())
    }
}

impl SessionOverlay {
    pub(in crate::session_overlay) fn install_base_row_retirement(
        self: &Arc<Self>,
        mode_generation: u64,
    ) -> Result<BaseRowRetirementGuard> {
        Ok(BaseRowRetirementGuard {
            segment: self.install_segment(Some(mode_generation))?,
            mode_generation,
        })
    }

    pub(super) fn acquire_base_retirement_lease(
        self: &Arc<Self>,
        mode_generation: u64,
    ) -> Result<Lease> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        loop {
            if !lifecycle.sealed_mode_is(mode_generation) {
                return Err(Error::OffRecord(
                    OffRecordError::OffRecordOverlayLeaseClosed {
                        generation: mode_generation,
                    },
                ));
            }
            if !lifecycle.segment_active {
                break;
            }
            // Acquired inside the base writer, as for an ordinary segment.
            // Publication releases this permit without acquiring a writer.
            lifecycle = self.segment_available.wait(lifecycle).map_err(|_| {
                Error::InvariantViolation("session overlay lifecycle mutex poisoned")
            })?;
        }
        lifecycle.leases = lifecycle
            .leases
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session overlay lease count"))?;
        lifecycle.segment_active = true;
        Ok(Lease {
            overlay: self.clone(),
            generation: lifecycle.generation,
            snapshot_state: None,
        })
    }
}
