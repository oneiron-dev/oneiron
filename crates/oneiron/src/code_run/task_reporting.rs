//! Native terminal TASK reports captured by a code run.

use super::{CodeRunBridgeCall, CodeRunReplayRecord, SelfDispatchOutcome, SelfEffect};
use crate::EntityId;
use crate::task_verb::sdk::AgentVerb;
use crate::task_verb::{TaskHandle, TaskOutcome, TaskPhase, TaskUpdateReceipt};

impl CodeRunReplayRecord {
    /// Counts fresh native terminal reports of `task`, not acknowledgements,
    /// non-terminal reports or replays of an earlier settlement.
    #[must_use]
    pub fn task_terminal_report_count(&self, task: EntityId) -> usize {
        self.bridge_calls
            .iter()
            .filter(|call| terminal_task_report(call, task))
            .count()
    }
}

fn terminal_task_report(call: &CodeRunBridgeCall, task: EntityId) -> bool {
    if call.effect != SelfEffect::AgentVerb {
        return false;
    }
    let effective = call.rewritten_request.as_ref().unwrap_or(&call.request);
    let Some(fields) = effective.as_map() else {
        return false;
    };
    let verb = fields.iter().find_map(|(key, value)| {
        (key.as_str() == Some("verb"))
            .then(|| value.as_str())
            .flatten()
    });
    if verb.and_then(AgentVerb::from_name) != Some(AgentVerb::TasksUpdate) {
        return false;
    }
    let Ok(SelfDispatchOutcome::AgentVerb(answer)) =
        super::payload::decode_self_dispatch_outcome(&call.outcome)
    else {
        return false;
    };
    let Ok(TaskUpdateReceipt {
        task_ref,
        report: Some(report),
        ..
    }) = serde_json::from_value(answer.output)
    else {
        return false;
    };
    if task_ref != task
        || report.idempotent_replay
        || !matches!(
            report.outcome,
            TaskOutcome::Reported {
                phase: TaskPhase::Terminal { .. }
            }
        )
    {
        return false;
    }
    let reported_task = match report.handle {
        TaskHandle::Task { task_ref } => task_ref,
        TaskHandle::Attempt(attempt) => attempt.task_ref,
        _ => return false,
    };
    let Some(lifecycle) = report.lifecycle else {
        return false;
    };
    // An Ack can return the TASK's existing terminal phase without settling it.
    reported_task == task
        && lifecycle.call == "report"
        && matches!(
            lifecycle.fields.get("body").map(String::as_str),
            Some("done" | "failed")
        )
}
