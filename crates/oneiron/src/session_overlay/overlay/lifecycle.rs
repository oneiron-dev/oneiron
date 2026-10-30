//! Overlay lifecycle state machine, leases, seal/rearm/close.
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use arc_swap::ArcSwap;

use crate::error::{Error, Result};

use super::super::keyspace::{KeyspaceState, OverlayKeyspace, OverlayState, OverlayValue};
use super::ACTIVE_SEGMENT;
use super::held::Held;
use super::retained::Retained;
use super::segment::{NEXT_OVERLAY_GENERATION, TxnSegment};
use crate::error::OffRecordError;

/// Write-transaction entry points that a session write path must wrap.
///
/// ONE-1726 supplies the segment mechanism only. Future session paths must
/// install it around `Vault::try_with_write_txn`/`with_write_txn` (and their
/// `_grouped` engine doors), `BatchBuilder::commit`, facade
/// `with_verified_actor_write_txn`/`witness`, and the direct `env.write_txn()`
/// clusters in `dreamer_runner`, `attempt_queue`, `claim`, `deletion`,
/// `connector_key`, `companion`, `code_run`, and the remaining store/vault
/// feature modules.
const SESSION_WRITE_TXN_ENTRY_POINTS: &[&str] = &[
    "Vault::try_with_write_txn / Vault::with_write_txn (and their _grouped engine doors)",
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
    /// The state a snapshot reads under this lease, counted in what the
    /// overlay retains until the lease drops. A segment's lease reads none.
    pub(super) snapshot_state: Option<Arc<OverlayState>>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        // Released before the lease count drains, so a close waiting on it
        // charges without the state.
        if let Some(state) = self.snapshot_state.take() {
            self.overlay.release_snapshot_state(state);
        }
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
    /// A room stretch's charge on its host's retained-memory line, bound
    /// once at entry (FIX 5991): moved to what the overlay retains as it
    /// changes (FIX 10104), and taken and dropped once the closed overlay
    /// is unpublished, or with the overlay.
    charge: Mutex<Option<OverlayCharge>>,
    /// What live snapshots and promotion plans hold beyond the published
    /// state, counted in what the overlay retains.
    pub(super) held: Mutex<Held>,
}

/// The host's charge beside the bytes its stretch holds before any row.
struct OverlayCharge {
    charge: Box<dyn crate::off_record::RetainedCharge>,
    entered: usize,
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
            charge: Mutex::new(None),
            held: Mutex::new(Held::default()),
        })
    }

    /// The bytes an overlay holds before any row: itself and its empty
    /// state.
    pub(crate) fn empty_bytes() -> usize {
        std::mem::size_of::<Self>().saturating_add(std::mem::size_of::<OverlayState>())
    }

    /// Binds a room stretch's charge, reserved for the `entered` bytes it
    /// holds before any row, and moves it to what the overlay holds now
    /// (FIX 5991). A second charge is dropped unbound.
    pub(crate) fn bind_charge(
        &self,
        charge: Box<dyn crate::off_record::RetainedCharge>,
        entered: usize,
    ) {
        let bound = match self.charge.lock() {
            Ok(mut slot) if slot.is_none() => {
                *slot = Some(OverlayCharge { charge, entered });
                true
            }
            _ => false,
        };
        if bound {
            self.charge_now();
        }
    }

    /// Moves a bound charge to the overlay's retained `bytes` beside its
    /// entry's. It never waits and never refuses; an unbound overlay, or
    /// one whose charge was released, charges nothing.
    pub(super) fn charge_to(&self, bytes: usize) {
        if let Ok(slot) = self.charge.lock()
            && let Some(bound) = slot.as_ref()
        {
            bound.charge.charge(bound.entered.saturating_add(bytes));
        }
    }

    /// The bytes the overlay retains now (FIX 10104): its published state,
    /// `segment`, a write's live segment, the states live snapshots read and
    /// the copies live promotion plans hold, each shared allocation once,
    /// with `incoming`, the heap a copy about to be made will hold.
    pub(super) fn retained_with(&self, segment: Option<&TxnSegment>, incoming: usize) -> usize {
        let mut retained = Retained::default();
        retained.state(&self.state.load_full());
        if let Some(segment) = segment {
            retained.segment(segment);
        }
        retained.held(&self.held.lock().unwrap_or_else(PoisonError::into_inner));
        retained.bytes().saturating_add(incoming)
    }

    /// Moves a bound charge to what the overlay retains now: its published
    /// state and this thread's segment of it, if any. A snapshot or plan
    /// that drops while this thread's segment is borrowed mutably, or while
    /// the thread's locals are torn down, moves nothing: the next charge
    /// catches up.
    pub(super) fn charge_now(&self) {
        let bytes = ACTIVE_SEGMENT.try_with(|slot| {
            let slot = slot.try_borrow().ok()?;
            let segment = slot
                .as_ref()
                .filter(|segment| std::ptr::eq(segment.overlay.as_ref(), self));
            Some(self.retained_with(segment, 0))
        });
        if let Ok(Some(bytes)) = bytes {
            self.charge_to(bytes);
        }
    }

    /// Releases a closed overlay once its registry entry is unpublished
    /// (FIX 10103): the membership kept for the registry's classification
    /// goes, and the host's charge is taken and dropped, so a stale handle
    /// still bound to it holds no transcript, journal or charge. An overlay
    /// that is not closed is left as it is.
    pub(crate) fn release_closed_state(&self) -> Result<()> {
        let lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if lifecycle.state != OverlayLifecycleState::Gone {
            return Ok(());
        }
        self.state.store(Arc::new(OverlayState::empty()));
        drop(lifecycle);
        let released = self
            .charge
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay charge mutex poisoned"))?
            .take();
        drop(released);
        Ok(())
    }

    /// The currently published mode generation, read under the state lock.
    /// [`SessionWriteRoute`] is the only consumer.
    pub(in crate::session_overlay) fn mode_generation(&self) -> Result<u64> {
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
                return Err(Error::OffRecord(
                    OffRecordError::OffRecordOverlayLeaseClosed {
                        generation: lifecycle.generation,
                    },
                ));
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
            return Err(Error::OffRecord(
                OffRecordError::OffRecordOverlayLeaseClosed {
                    generation: lifecycle.generation,
                },
            ));
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
                // Every route minted before the close is stale from here: a
                // base write holding one lands nothing once the room closes.
                lifecycle.mode_generation = next_mode_generation(lifecycle.mode_generation)?;
                // Wake every installer parked on the segment permit so each re-checks the
                // terminal lifecycle state and returns the closed error instead of sleeping;
                // release_segment_writer's notify_one only ever wakes a single waiter.
                self.segment_available.notify_all();
            }
            OverlayLifecycleState::Sealing
            | OverlayLifecycleState::Closing
            | OverlayLifecycleState::Gone => {
                return Err(Error::OffRecord(
                    OffRecordError::OffRecordOverlayLeaseClosed {
                        generation: lifecycle.generation,
                    },
                ));
            }
        }
        while lifecycle.leases != 0 {
            lifecycle = self.lease_drained.wait(lifecycle).map_err(|_| {
                Error::InvariantViolation("session overlay lifecycle mutex poisoned")
            })?;
        }
        // Retain only the membership the registry's fail-closed
        // classification reads until the entry itself is unpublished
        // ([`Self::release_closed_state`]): the transcript, its indexes and
        // its journal go now (FIX 10103). No read lease can observe the state
        // after the lifecycle reaches Gone.
        lifecycle.generation = lifecycle
            .generation
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session overlay generation"))?;
        lifecycle.state = OverlayLifecycleState::Gone;
        let membership = membership_only(&self.state.load_full());
        self.state.store(Arc::new(membership));
        drop(lifecycle);
        self.charge_now();
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
            return Err(Error::OffRecord(
                OffRecordError::OffRecordOverlayLeaseClosed {
                    generation: lifecycle.generation,
                },
            ));
        }
        lifecycle.leases = lifecycle
            .leases
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session overlay lease count"))?;
        Ok(Lease {
            overlay: self.clone(),
            generation: lifecycle.generation,
            snapshot_state: None,
        })
    }

    pub(super) fn acquire_existing_lease(self: &Arc<Self>, generation: u64) -> Result<Lease> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if lifecycle.state == OverlayLifecycleState::Gone || lifecycle.generation != generation {
            return Err(Error::OffRecord(
                OffRecordError::OffRecordOverlayLeaseClosed { generation },
            ));
        }
        lifecycle.leases = lifecycle
            .leases
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session overlay lease count"))?;
        Ok(Lease {
            overlay: self.clone(),
            generation,
            snapshot_state: None,
        })
    }
}

/// The entity ids `state` holds as rows, each with no body: the membership
/// [`SessionOverlay::contains_entity`] answers from, and nothing else.
fn membership_only(state: &OverlayState) -> OverlayState {
    let mut kept = OverlayState::empty();
    let slot = OverlayKeyspace::Entities.slot();
    if let KeyspaceState::Single { rows, .. } = state.keyspaces[slot].as_ref() {
        let rows = rows
            .iter()
            .filter(|(_, value)| matches!(value, OverlayValue::Present(_)))
            .map(|(id, _)| (id.clone(), OverlayValue::Present(Vec::new())))
            .collect();
        kept.keyspaces[slot] = Arc::new(KeyspaceState::Single {
            clear_base: false,
            rows,
        });
    }
    kept
}

/// Advances the mode-publication counter. Overflow is a hard error rather than
/// a wrap: a wrapped counter could make a stale route revalidate.
fn next_mode_generation(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("session overlay mode generation"))
}
