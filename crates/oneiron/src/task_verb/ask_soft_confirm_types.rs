//! Revision-bound soft-confirm reply, notice, and delivery state.
use super::TaskAskOptionId;
use crate::EntityId;
use serde::{Deserialize, Serialize};

/// One durable, idempotent approve-or-no delivery instruction. A notice is
/// an ask revision fact, not permission to book or commit anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAskSoftConfirmNotice {
    pub group_ref: EntityId,
    pub revision: u64,
    pub person_ref: EntityId,
    pub companion_answer_ref: EntityId,
    pub option: Option<TaskAskOptionId>,
    pub task_ref: EntityId,
    pub deadline: u64,
}

/// Delivery is separate from approval; a pending state never authorizes an effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskSoftConfirmDelivery {
    PendingRoute,
    PendingGate,
    Failed,
    Scheduled,
    Closed,
}

/// A response to the notice, distinct from the original question's option ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskConfirmationDecision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAskConfirmation {
    pub revision: u64,
    pub companion_answer_ref: EntityId,
    pub decision: TaskAskConfirmationDecision,
}

impl super::TaskAskWord {
    /// One human's approve-or-reject reply through normal answer intake.
    /// Approval selects the proposed option; rejection is a typed response,
    /// never a fabricated option id in the original question.
    pub fn confirm(
        result_ref: EntityId,
        notice: &super::TaskAskSoftConfirmNotice,
        decision: super::TaskAskConfirmationDecision,
    ) -> Self {
        Self {
            option: (decision == super::TaskAskConfirmationDecision::Approve)
                .then(|| notice.option.clone())
                .flatten(),
            confirmation: Some(super::TaskAskConfirmation {
                revision: notice.revision,
                companion_answer_ref: notice.companion_answer_ref,
                decision,
            }),
            ..Self::new(result_ref)
        }
    }
}
