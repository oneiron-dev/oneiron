//! Overlay lifecycle state machine, leases, seal/rearm/close.
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};

use arc_swap::ArcSwap;

use crate::error::{Error, Result};

use super::super::keyspace::OverlayState;
use super::ACTIVE_SEGMENT;
use super::segment::NEXT_OVERLAY_GENERATION;

/// Write-transaction entry points that a session write path must wrap.
///
/// ONE-1726 supplies the segment mechanism only. Future session paths must
/// install it around `Vault::try_with_write_txn`/`with_write_txn`,
/// `BatchBuilder::commit`, facade `with_verified_actor_write_txn`/`witness`,
/// and the direct `env.write_txn()` clusters in `dreamer_runner`,
/// `attempt_queue`, `claim`, `deletion`, `connector_key`, `companion`,
/// `code_run`, and the remaining store/vault feature modules.
pub(crate) const SESSION_WRITE_TXN_ENTRY_POINTS: &[&str] = &[
    "Vault::try_with_write_txn / Vault::with_write_txn",
    "BatchBuilder::commit",
    "Memory::with_verified_actor_write_txn / Memory::witness",
    "direct env.write_txn(): dreamer_runner, attempt_queue, claim, deletion, connector_key, companion, code_run, and remaining feature modules",
];

const _: () = assert!(!SESSION_WRITE_TXN_ENTRY_POINTS.is_empty());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::session_overlay) enum OverlayLifecycleState {
    Live,
    Sealing,
    Sealed,
    Closing,
    Gone,
}

pub(in crate::session_overlay) struct Lifecycle {
    pub(in crate::session_overlay) state: OverlayLifecycleState,
    pub(super) generation: u64,
    /// Monotonic counter bumped by every MODE publication — `seal_writes`
    /// (Live -> Sealed, the flip on-record) and `rearm` (Sealed -> Live, the
    /// K10 flip-back). A [`SessionWriteRoute`] records the value it was minted
    /// under and [`SessionWriteRoute::revalidate`] refuses a mismatch, so a
    /// route minted before the most recent flip can never stage or commit.
    /// Distinct from `generation`, which stamps LEASES and bumps at close.
    mode_generation: u64,
    pub(super) leases: usize,
    pub(super) segment_active: bool,
}

pub(in crate::session_overlay) struct Lease {
    pub(super) overlay: Arc<SessionOverlay>,
    #[allow(
        dead_code,
        reason = "segment generation is consumed once ONE-1728 installs production session writes"
    )]
    pub(super) generation: u64,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut lifecycle) = self.overlay.lifecycle.lock() {
            lifecycle.leases = lifecycle.leases.saturating_sub(1);
            if lifecycle.leases == 0 {
                self.overlay.lease_drained.notify_all();
            }
        }
    }
}

/// Persistent-COW in-memory overlay shared by one live session.
pub(crate) struct SessionOverlay {
    pub(in crate::session_overlay) state: ArcSwap<OverlayState>,
    pub(in crate::session_overlay) lifecycle: Mutex<Lifecycle>,
    lease_drained: Condvar,
    pub(super) segment_available: Condvar,
    pub(super) budget_bytes: usize,
}

impl SessionOverlay {
    // Budget failures belong exclusively to preflight, before the base commit.
    // This apply helper deliberately has no budget input or budget-error branch.
    pub(crate) fn new(budget_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            state: ArcSwap::from_pointee(OverlayState::empty()),
            lifecycle: Mutex::new(Lifecycle {
                state: OverlayLifecycleState::Live,
                generation: NEXT_OVERLAY_GENERATION.fetch_add(1, Ordering::Relaxed),
                mode_generation: 0,
                leases: 0,
                segment_active: false,
            }),
            lease_drained: Condvar::new(),
            segment_available: Condvar::new(),
            budget_bytes,
        })
    }

    /// The currently published mode generation, read under the state lock.
    /// [`SessionWriteRoute`] is the only consumer.
    pub(crate) fn mode_generation(&self) -> Result<u64> {
        Ok(self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?
            .mode_generation)
    }

    /// Seals the overlay write path while leaving composed reads available.
    /// The transition first blocks new segment installers, then drains the one
    /// permitted active writer before publishing `Sealed`.
    ///
    /// The seal is permanent EXCEPT for the K10 flip-back: [`Self::rearm`]
    /// transitions `Sealed` -> `Live` when a session flips back to
    /// `OffRecord`. Every other state stays terminal.
    pub(crate) fn seal_writes(self: &Arc<Self>) -> Result<()> {
        let holds_active_segment = ACTIVE_SEGMENT.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|segment| Arc::ptr_eq(&segment.overlay, self))
        });
        if holds_active_segment {
            return Err(Error::InvariantViolation(
                "session overlay seal called while this thread holds an active txn segment",
            ));
        }

        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        match lifecycle.state {
            OverlayLifecycleState::Live => {
                lifecycle.state = OverlayLifecycleState::Sealing;
                self.segment_available.notify_all();
            }
            OverlayLifecycleState::Sealed => return Ok(()),
            OverlayLifecycleState::Sealing
            | OverlayLifecycleState::Closing
            | OverlayLifecycleState::Gone => {
                return Err(Error::OffRecordOverlayLeaseClosed {
                    generation: lifecycle.generation,
                });
            }
        }
        while lifecycle.segment_active {
            lifecycle = self.segment_available.wait(lifecycle).map_err(|_| {
                Error::InvariantViolation("session overlay lifecycle mutex poisoned")
            })?;
        }
        lifecycle.state = OverlayLifecycleState::Sealed;
        lifecycle.mode_generation = next_mode_generation(lifecycle.mode_generation)?;
        Ok(())
    }

    /// K10 flip-back: re-enables overlay writes when a session returns to
    /// `OffRecord` mode. The ONLY legal transition is `Sealed` -> `Live`
    /// (`Live` IS the landed write-enabled state — no `Armed` variant exists;
    /// K10's "armed" prose names `Live`). Every other state — including a
    /// `Live` overlay that was never sealed — is refused, so rearm can never
    /// resurrect a closing or closed overlay.
    ///
    /// Publishing bumps the mode generation, so any [`SessionWriteRoute`]
    /// minted before the flip-back is refused by [`SessionWriteRoute::revalidate`]
    /// before it can stage. The room's earlier turns stay visible in-session
    /// and unextractable through base: rearm reopens the write door only, and
    /// touches no row.
    pub(crate) fn rearm(self: &Arc<Self>) -> Result<()> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if lifecycle.state != OverlayLifecycleState::Sealed {
            return Err(Error::OffRecordOverlayLeaseClosed {
                generation: lifecycle.generation,
            });
        }
        lifecycle.state = OverlayLifecycleState::Live;
        lifecycle.mode_generation = next_mode_generation(lifecycle.mode_generation)?;
        Ok(())
    }

    pub(crate) fn close(self: &Arc<Self>) -> Result<()> {
        // A close nested inside this thread's own active segment would wait on a lease
        // that only this stack can release (the guard drops when it unwinds past here).
        // Fail fast — in the single-writer model close is a session-lifecycle op, never
        // nested inside an active write segment — leaving the overlay Live and usable.
        let holds_active_segment = ACTIVE_SEGMENT.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|segment| Arc::ptr_eq(&segment.overlay, self))
        });
        if holds_active_segment {
            return Err(Error::InvariantViolation(
                "session overlay close called while this thread holds an active txn segment",
            ));
        }

        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        match lifecycle.state {
            OverlayLifecycleState::Live | OverlayLifecycleState::Sealed => {
                lifecycle.state = OverlayLifecycleState::Closing;
                // Wake every installer parked on the segment permit so each re-checks the
                // terminal lifecycle state and returns the closed error instead of sleeping;
                // release_segment_writer's notify_one only ever wakes a single waiter.
                self.segment_available.notify_all();
            }
            OverlayLifecycleState::Sealing
            | OverlayLifecycleState::Closing
            | OverlayLifecycleState::Gone => {
                return Err(Error::OffRecordOverlayLeaseClosed {
                    generation: lifecycle.generation,
                });
            }
        }
        while lifecycle.leases != 0 {
            lifecycle = self.lease_drained.wait(lifecycle).map_err(|_| {
                Error::InvariantViolation("session overlay lifecycle mutex poisoned")
            })?;
        }
        // Retain the immutable state as the registry's fail-closed membership
        // snapshot until the entry itself is unpublished. No read lease can
        // observe it after the lifecycle reaches Gone.
        lifecycle.generation = lifecycle
            .generation
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session overlay generation"))?;
        lifecycle.state = OverlayLifecycleState::Gone;
        Ok(())
    }

    pub(super) fn acquire_read_lease(self: &Arc<Self>) -> Result<Lease> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if !matches!(
            lifecycle.state,
            OverlayLifecycleState::Live | OverlayLifecycleState::Sealed
        ) {
            return Err(Error::OffRecordOverlayLeaseClosed {
                generation: lifecycle.generation,
            });
        }
        lifecycle.leases = lifecycle
            .leases
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session overlay lease count"))?;
        Ok(Lease {
            overlay: self.clone(),
            generation: lifecycle.generation,
        })
    }

    pub(super) fn acquire_existing_lease(self: &Arc<Self>, generation: u64) -> Result<Lease> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if lifecycle.state == OverlayLifecycleState::Gone || lifecycle.generation != generation {
            return Err(Error::OffRecordOverlayLeaseClosed { generation });
        }
        lifecycle.leases = lifecycle
            .leases
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session overlay lease count"))?;
        Ok(Lease {
            overlay: self.clone(),
            generation,
        })
    }
}

/// Advances the mode-publication counter. Overflow is a hard error rather than
/// a wrap: a wrapped counter could make a stale route revalidate.
fn next_mode_generation(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("session overlay mode generation"))
}
