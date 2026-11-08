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

impl CodeRunReplayRecord {
    /// The retained output of the latest fresh native decline of this TASK.
    pub(crate) fn task_decline_output(&self, task: EntityId) -> Option<&super::CodeRunRawOutput> {
        for call in self.bridge_calls.iter().rev() {
            if call.effect != SelfEffect::TasksRefuse {
                continue;
            }
            if !matches!(
                super::payload::decode_self_dispatch_outcome(&call.outcome),
                Ok(SelfDispatchOutcome::TaskRefusal(refusal))
                    if refusal.task_ref == task && refusal.declined() && !refusal.replay
            ) {
                continue;
            }
            let path = crate::engine_executor::bridge_result_output_path(call.seq);
            return self
                .outputs
                .iter()
                .rev()
                .find(|output| output.complete && output.path == path);
        }
        None
    }
}
