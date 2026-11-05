//! Native task-decline outcomes captured by a code run.

use super::{CodeRunReplayRecord, SelfDispatchOutcome, SelfEffect};
use crate::EntityId;

impl CodeRunReplayRecord {
    /// Counts this record's native, successful declines of `task`.
    /// Failed calls, waits and non-terminal reader reports do not settle it.
    #[must_use]
    pub fn task_decline_count(&self, task: EntityId) -> usize {
        self.bridge_calls
            .iter()
            .filter(|call| {
                call.effect == SelfEffect::TasksRefuse
                    && matches!(
                        super::payload::decode_self_dispatch_outcome(&call.outcome),
                        Ok(SelfDispatchOutcome::TaskRefusal(refusal))
                            if refusal.task_ref == task && refusal.declined()
                    )
            })
            .count()
    }
}
