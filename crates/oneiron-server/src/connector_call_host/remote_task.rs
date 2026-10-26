//! A connector's answer that takes a `tools/call` as a remote task (FIX
//! 7960): the MCP task envelope, `result.task.taskId`, with its polling
//! hint. Only that one wire shape is read; no content string is scanned for
//! an id.

use super::*;

/// MCP states a task's polling hint in milliseconds.
const POLL_INTERVAL_MILLIS_PER_SEC: u64 = 1_000;

/// The remote task a `tools/call` answer names, when it is the task
/// envelope with a non-empty task id. Any other answer is the tool's own.
pub(super) fn remote_task_from_result(message: &Value) -> Option<RemoteTaskHandle> {
    let task = message.get("result")?.get("task")?;
    let id = task.get("taskId")?.as_str()?;
    if id.is_empty() {
        return None;
    }
    let poll_after_secs = task
        .get("pollInterval")
        .and_then(Value::as_u64)
        .map(|millis| millis.div_ceil(POLL_INTERVAL_MILLIS_PER_SEC));
    Some(RemoteTaskHandle {
        id: id.to_owned(),
        poll_after_secs,
    })
}
