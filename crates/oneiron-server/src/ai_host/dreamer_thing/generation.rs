//! The served agent's generation count (FIX 7508, 9015, 11449): what its
//! calls spent on its parent's guard, handed to the parent once, at its
//! close. A call admitted before the close that settles after it is neither
//! lost nor cancelled: the close marks it owed on the attempt's line, and
//! its terminal usage is charged there when it settles. One that never
//! settles stays owed. A session dropped without its close charges what its
//! count still holds there at once.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron::attempt_queue::AttemptId;
use oneiron::dreamer_runner::DreamerRunnerStore;
use oneiron::{EntityId, Vault};

/// One child's generation count, shared by its backend and its session.
pub(super) struct GenerationCount {
    vault: Arc<Vault>,
    /// The attempt's own line: a late call is owed and charged there.
    budget_id: String,
    attempt: AttemptId,
    /// The parent run, as the count's log lines name it.
    parent_run: EntityId,
    state: Mutex<CountState>,
}

#[derive(Default)]
struct CountState {
    /// What calls that settled before the close spent.
    units: u64,
    /// Calls admitted and not yet settled.
    in_flight: u64,
    closed: bool,
}

impl GenerationCount {
    pub(super) fn new(
        vault: Arc<Vault>,
        budget_id: String,
        attempt: AttemptId,
        parent_run: EntityId,
    ) -> Self {
        Self {
            vault,
            budget_id,
            attempt,
            parent_run,
            state: Mutex::new(CountState::default()),
        }
    }

    /// Admits one call, unless the count is closed.
    pub(super) fn admit(&self) -> bool {
        let mut state = self.lock();
        if state.closed {
            return false;
        }
        state.in_flight = state.in_flight.saturating_add(1);
        true
    }

    /// Settles one admitted call that spent `units` (0 for a call that
    /// failed). Before the close they join the count; after it they are
    /// charged to the attempt's line at once, under the count's lock, so
    /// the charge always lands after the close marked the call owed.
    pub(super) fn settle(&self, units: u64) {
        let mut state = self.lock();
        state.in_flight = state.in_flight.saturating_sub(1);
        if !state.closed {
            state.units = state.units.saturating_add(units);
            return;
        }
        let charged = DreamerRunnerStore::new(&self.vault).charge_late_usage(
            &self.budget_id,
            self.attempt,
            units,
        );
        if let Err(error) = charged {
            tracing::warn!(
                kind = ?error.kind(),
                parent_run = %self.parent_run.to_hex(),
                units,
                "a thing child's late call was not charged; it stays owed on its line"
            );
        }
    }

    /// Closes the count and returns what it holds, once: a later close
    /// returns 0. The calls still in flight are marked owed on the
    /// attempt's line in the same step.
    pub(super) fn close(&self) -> u64 {
        let mut state = self.lock();
        if state.closed {
            return 0;
        }
        state.closed = true;
        if state.in_flight > 0
            && let Err(error) = DreamerRunnerStore::new(&self.vault)
                .owe_late_calls(&self.budget_id, state.in_flight)
        {
            tracing::warn!(
                kind = ?error.kind(),
                parent_run = %self.parent_run.to_hex(),
                calls = state.in_flight,
                "a thing child's calls in flight were not marked owed"
            );
        }
        std::mem::take(&mut state.units)
    }

    /// Closes a count whose session dropped without its close (FIX 11449):
    /// what the close holds is charged to the attempt's own line at once,
    /// never handed to a parent. A count closed normally charges nothing
    /// more: the second close returns 0.
    pub(super) fn close_dropped(&self) {
        let units = self.close();
        if units == 0 {
            return;
        }
        if let Err(error) = DreamerRunnerStore::new(&self.vault).charge_dropped_usage(
            &self.budget_id,
            self.attempt,
            units,
        ) {
            tracing::warn!(
                kind = ?error.kind(),
                parent_run = %self.parent_run.to_hex(),
                units,
                "a thing child's dropped count was not charged; its units are lost"
            );
        }
    }

    fn lock(&self) -> MutexGuard<'_, CountState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
