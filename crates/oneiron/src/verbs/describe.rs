//! `describe`'s typed input and the checks every door runs over it: one
//! target per call (FIX 3256), and whether the call takes the highway
//! status branch, a task-work producer (Rule 5).
use crate::memory::{Memory, MemoryError, MemoryResult};
use serde::{Deserialize, Serialize};

/// `describe`'s one input: the task to describe, a board card's key, the
/// vault for its shape card, or none for the whole TASKS section.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescribeRequest {
    #[serde(default)]
    pub task_ref: Option<String>,
    #[serde(default, rename = "self")]
    pub self_target: bool,
    /// `describe(vault)`: the vault's shape card (ARCH-0070), what its
    /// arrangement amounts to and what its actors can send. Names nothing
    /// else.
    #[serde(default)]
    pub vault: bool,
    #[serde(default)]
    pub session_id: Option<String>,
    /// A board card's key: describe expands that card, under the board's
    /// scope and frame-epoch checks.
    #[serde(default)]
    pub key: Option<String>,
    /// The board frame the card key was read from; a stale one is refused.
    #[serde(default)]
    pub frame_epoch: Option<u64>,
    /// A fold of the run's own log (`f1`): its span, its stub and the ids it
    /// holds. Only the run that folded it answers this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fold: Option<String>,
    /// A task highway handle (OF-220): describe answers its status, the
    /// highway's own `TaskCallReceipt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<super::TaskHandle>,
    /// The digest of the last status observed for `handle`: describe then
    /// polls, and an unchanged answer is `unchanged`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "super::brief::hex32::option"
    )]
    #[schemars(with = "Option<String>")]
    pub after: Option<[u8; 32]>,
}

/// The refusal of an `after` that names no handle to poll.
const AFTER_NEEDS_HANDLE: &str = "describe(after) polls a handle: name the handle it observed";

impl DescribeRequest {
    /// The one describe selector check (FIX 3256), which every door runs
    /// before any lookup and again on the args a pre hook left: naming none
    /// of `self`, `vault`, `task_ref`, `key`, `fold` and `handle` describes
    /// the TASKS section, and naming more than one is refused, never answered
    /// first-wins. `after` polls a handle, so it needs one; `session_id` and
    /// `frame_epoch` are context for the target, not targets of their own.
    pub fn validate(&self) -> MemoryResult<()> {
        let targets = self.targets();
        if targets.len() > 1 {
            return Err(MemoryError::bad_request(format!(
                "describe names one target, not {}",
                targets.join(" and ")
            )));
        }
        if self.after.is_some() && self.handle.is_none() {
            return Err(MemoryError::bad_request(AFTER_NEEDS_HANDLE));
        }
        Ok(())
    }

    /// The targets this request names, in the row's field order.
    fn targets(&self) -> Vec<&'static str> {
        [
            ("self", self.self_target),
            ("vault", self.vault),
            ("task_ref", self.task_ref.is_some()),
            ("key", self.key.is_some()),
            ("fold", self.fold.is_some()),
            ("handle", self.handle.is_some()),
        ]
        .into_iter()
        .filter_map(|(target, named)| named.then_some(target))
        .collect()
    }
}

/// `describe({handle, after})` (OF-220): the status of one highway handle,
/// or a poll when `after` names the last observation, as the highway answers
/// it. A handle names the described thing whole, so a task ref beside it, or
/// an `after` with no handle, is refused ([`DescribeRequest::validate`]).
pub fn describe_handle_status(
    memory: &Memory<'_>,
    input: &DescribeRequest,
) -> MemoryResult<super::TaskDescription> {
    input.validate()?;
    let Some(handle) = input.handle else {
        return Err(MemoryError::bad_request(AFTER_NEEDS_HANDLE));
    };
    let receipt = memory.tasks_status(super::TaskStatusQuery {
        handle,
        after: input.after,
    })?;
    Ok(super::TaskDescription::Status { receipt })
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
        super::TaskHandle::Proposed { proposal_ref } => proposal_ref,
        super::TaskHandle::Task { task_ref }
        | super::TaskHandle::Attempt(super::AttemptHandle { task_ref, .. }) => task_ref,
        super::TaskHandle::Ask { group_ref } => group_ref,
    });
    task.into_iter().chain(handle).collect()
}
