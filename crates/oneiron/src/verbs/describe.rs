//! `describe`'s typed input and the checks every door runs over it: one
//! target per call (FIX 3256), and whether the call takes the highway
//! status branch, a task-work producer (Rule 5).
use crate::memory::{Memory, MemoryError, MemoryResult};
use serde::Deserialize;

use crate::memory::AFTER_NEEDS_HANDLE;
pub use crate::memory::DescribeRequest;

/// `describe({handle, after})` (OF-220): the status of one highway handle,
/// or a poll when `after` names the last observation, as the highway answers
/// it. A handle names the described thing whole, so a task ref beside it, or
/// an `after` with no handle, is refused ([`DescribeRequest::validate`]).
pub fn describe_handle_status(
    memory: &Memory<'_>,
    input: &DescribeRequest,
) -> MemoryResult<crate::task_verb::TaskDescription> {
    input.validate()?;
    let Some(handle) = input.handle else {
        return Err(MemoryError::bad_request(AFTER_NEEDS_HANDLE));
    };
    let receipt = memory.tasks_status(crate::task_verb::TaskStatusQuery {
        handle,
        after: input.after,
    })?;
    Ok(crate::task_verb::TaskDescription::Status { receipt })
}

/// Whether `describe` over the raw request `input` reaches
/// [`describe_handle_status`] (Rule 5, FIX 2166): the highway's status is a
/// task-work producer, so the served doors await a task-work turn for this
/// branch and bind it, and the engine never waits for one on the server's
/// runtime. The served doors ask it of the args the pre hooks left (FIX
/// 4445). A request that does not decode, or names more than one target,
/// takes no turn; the dispatch refuses it.
#[must_use]
pub fn describe_takes_task_work_turn(input: &serde_json::Value) -> bool {
    DescribeRequest::deserialize(input)
        .is_ok_and(|request| request.validate().is_ok() && request.handle.is_some())
}

/// The rows one describe names by id: its task, else its handle's truth
/// row (the tray row, the TASK or the ask group). A continuation of its
/// answer is released only while they may leave.
#[must_use]
pub fn describe_named_rows(input: &DescribeRequest) -> Vec<crate::EntityId> {
    let task = input
        .task_ref
        .as_deref()
        .and_then(|id| crate::EntityId::from_hex(id).ok());
    let handle = input.handle.map(|handle| match handle {
        crate::task_verb::TaskHandle::Proposed { proposal_ref } => proposal_ref,
        crate::task_verb::TaskHandle::Task { task_ref }
        | crate::task_verb::TaskHandle::Attempt(crate::task_verb::AttemptHandle {
            task_ref, ..
        }) => task_ref,
        crate::task_verb::TaskHandle::Ask { group_ref } => group_ref,
    });
    task.into_iter().chain(handle).collect()
}
