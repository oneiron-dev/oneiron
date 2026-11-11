//! Moved from `crates/oneiron/src/dreamer_wake/observation/live.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_wake::deadline::WakePassDeadline;
use crate::memory::wake_observation::WakeRef;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::BudgetGuard;
use oneiron_model::llm::BudgetLease;
use oneiron_store::attempt_id::AttemptId;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::sync::Weak;

/// One running pass: the clock it runs on, and its admitted calls.
pub struct ActiveWake {
    pub clock: WakePassDeadline,
    pub calls: Mutex<BTreeMap<EntityId, Weak<ActiveCall>>>,
    pub attempt_lines: Mutex<BTreeMap<AttemptId, String>>,
}

impl ActiveWake {
    /// Records the runner line `attempt` reserved on: the line an owed wake
    /// call of that attempt charges (FIX 11450).
    pub fn record_attempt_line(&self, attempt: AttemptId, line: &str) {
        self.attempt_lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(attempt, line.to_owned());
    }

    /// The runner line `attempt` reserved on, while this pass runs it.
    pub fn attempt_line(&self, attempt: AttemptId) -> Option<String> {
        self.attempt_lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&attempt)
            .cloned()
    }

    /// Registers one admitted call before its row is visible. Calls no
    /// observer holds any more leave here.
    pub fn register_call(
        &self,
        call: EntityId,
        guard: &BudgetGuard,
        lease: &BudgetLease,
    ) -> Arc<ActiveCall> {
        let live = Arc::new(ActiveCall {
            call,
            guard: guard.clone(),
            lease_id: lease.id().to_owned(),
        });
        let mut calls = self.calls.lock().unwrap_or_else(PoisonError::into_inner);
        calls.retain(|_, held| held.strong_count() > 0);
        calls.insert(call, Arc::downgrade(&live));
        drop(calls);
        live
    }
}

/// One admitted call: the guard that issued its lease, and the lease's id.
pub struct ActiveCall {
    pub call: EntityId,
    pub guard: BudgetGuard,
    pub lease_id: String,
}

/// What a bound deadline carries to its clones: the committed wake, and the
/// hold that keeps the pass live while any clone runs.
#[derive(Clone)]
pub struct WakeBinding {
    pub wake: WakeRef,
    pub live: Arc<ActiveWake>,
}

impl WakeBinding {
    pub const fn wake(&self) -> WakeRef {
        self.wake
    }
}
