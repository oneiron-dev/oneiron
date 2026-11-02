//! What the overlay's readers hold beyond its published state, counted in
//! what the overlay retains (FIX 11083): the state each live snapshot reads,
//! so a state a publish replaced stays counted until its last snapshot
//! drops, and the heap each live promotion plan copied out of the journal,
//! until the plan drops. Holding never refuses, waits or delays: it moves
//! the charge, and the host reports a budget it exceeds as it does for any
//! other bytes.

use std::collections::BTreeSet;
use std::sync::{Arc, PoisonError};

use super::super::journal::PromotePlan;
use super::super::keyspace::OverlayState;
use super::lifecycle::{Lease, SessionOverlay};
use super::retained::plan_heap;

/// The states live snapshots read, one entry per snapshot, and the heap
/// of each live promotion plan.
#[derive(Default)]
pub(super) struct Held {
    pub(super) states: Vec<Arc<OverlayState>>,
    pub(super) plans: Vec<Arc<PlanHeap>>,
}

/// The heap one promotion plan copied: its own bytes, and the run tokens
/// its ops name, each `(address, bytes)` once, which share the journal's
/// allocations and count once beside them.
pub(super) struct PlanHeap {
    pub(super) bytes: usize,
    pub(super) tokens: BTreeSet<(usize, usize)>,
}

/// A promotion plan's hold on what its overlay retains: the plan's copies
/// stay counted until it drops.
pub(in crate::session_overlay) struct PlanCharge {
    overlay: Arc<SessionOverlay>,
    heap: Arc<PlanHeap>,
}

impl Drop for PlanCharge {
    fn drop(&mut self) {
        self.overlay
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .plans
            .retain(|plan| !Arc::ptr_eq(plan, &self.heap));
        self.overlay.charge_now();
    }
}

impl Lease {
    /// Holds the overlay's published state as the state this snapshot
    /// lease reads, loaded under the hold so a publish either counts it or
    /// replaced it before the load.
    pub(super) fn hold_published(&mut self) -> Arc<OverlayState> {
        let mut held = self
            .overlay
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let state = self.overlay.state.load_full();
        held.states.push(Arc::clone(&state));
        drop(held);
        self.snapshot_state = Some(Arc::clone(&state));
        state
    }

    /// Holds `preview`, a write's previewed state, as the state this
    /// snapshot lease reads.
    pub(super) fn hold_preview(&mut self, preview: Arc<OverlayState>) -> Arc<OverlayState> {
        self.overlay
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .states
            .push(Arc::clone(&preview));
        self.snapshot_state = Some(Arc::clone(&preview));
        preview
    }

    /// Charges the heap `plan` copied out of the journal to the overlay
    /// this lease reads, until the returned charge drops.
    pub(in crate::session_overlay) fn charge_plan(&self, plan: &PromotePlan) -> PlanCharge {
        let heap = Arc::new(PlanHeap {
            bytes: plan_heap(plan),
            tokens: plan
                .source_runs
                .iter()
                .flatten()
                .map(crate::skill_attribution::RunWriteToken::heap_allocation)
                .collect(),
        });
        self.overlay
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .plans
            .push(Arc::clone(&heap));
        self.overlay.charge_now();
        PlanCharge {
            overlay: Arc::clone(&self.overlay),
            heap,
        }
    }
}

impl SessionOverlay {
    /// Lets go of the state a dropped snapshot read. A state a publish
    /// replaced leaves what the overlay retains once no live snapshot reads
    /// it, and the charge moves down to what is left; the published state
    /// stays counted, so its last reader moves nothing.
    pub(super) fn release_snapshot_state(&self, state: Arc<OverlayState>) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let released = held
            .states
            .iter()
            .position(|kept| Arc::ptr_eq(kept, &state))
            .map(|at| held.states.swap_remove(at));
        let still_read = held.states.iter().any(|kept| Arc::ptr_eq(kept, &state));
        drop(held);
        drop(released);
        let replaced = !still_read && !Arc::ptr_eq(&self.state.load_full(), &state);
        drop(state);
        if replaced {
            self.charge_now();
        }
    }
}
