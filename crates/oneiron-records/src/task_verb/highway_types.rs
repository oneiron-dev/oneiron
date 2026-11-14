//! Moved from `crates/oneiron/src/task_verb/highway_types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::task_verb::brief::BriefStamp;
use crate::task_verb::task_actor::TaskActor;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use oneiron_verb_wire::failure_ladder::task_terminal::TaskTerminalDisposition;
pub use oneiron_verb_wire::task_verb::highway_types::TaskAccept;
pub use oneiron_verb_wire::task_verb::highway_types::TaskRedo;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Serde for an attempt id as 32 hex characters.
mod attempt_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    use oneiron_store::attempt_id::AttemptId;

    pub(super) fn serialize<S: Serializer>(
        id: &AttemptId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&oneiron_contracts::entity_id::bytes_to_hex_lower(
            id.as_bytes(),
        ))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<AttemptId, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = super::super::brief::decode_hex::<16>(&text)
            .ok_or_else(|| serde::de::Error::custom("expected a 32-character hex attempt id"))?;
        AttemptId::from_bytes(&bytes)
            .map_err(|_| serde::de::Error::custom("expected a 16-byte attempt id"))
    }
}

/// A durable locator. It is not a capability: every use re-proves the actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaskHandle {
    /// Truth: the Proposed CLAIM and its tray row, keyed by claim id. Stays
    /// valid after landing; Status resolves it to the TASK.
    Proposed { proposal_ref: EntityId },
    /// Truth: the synced TASK row.
    Task { task_ref: EntityId },
    /// Truth: the node-local ATTEMPT row.
    Attempt(AttemptHandle),
    /// Truth: the ask group; the same handle `tasks.wait` takes.
    Ask { group_ref: EntityId },
}

/// One try on one seat, on the node that leased it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttemptHandle {
    pub task_ref: EntityId,
    #[serde(with = "attempt_hex")]
    #[schemars(with = "String")]
    pub attempt_ref: AttemptId,
    pub attempt_count: u32,
    /// The machine holding the attempt row, when this install has one.
    #[serde(default)]
    pub node_ref: Option<EntityId>,
}

/// Where one handle's work stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum TaskPhase {
    Proposed {
        pending: bool,
    },
    Rejected,
    Queued,
    Working {
        started_at: u64,
    },
    Blocked {
        since: u64,
        on: Vec<EntityId>,
    },
    Interrupted,
    Terminal {
        disposition: TaskTerminalDisposition,
    },
    /// An ask handle's group: waiting, or settled.
    Asked {
        settled: bool,
    },
}

/// The live try a status read sees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptView {
    pub attempt_ref: String,
    pub state: String,
    pub attempt_count: u32,
    pub yours: bool,
    pub claimed_at: Option<u64>,
    pub backoff_until: Option<u64>,
}

/// One bound try's library program (CUA E4): the record its TASK named, the
/// one its first lease resolved that to, the brief it was leased under, and
/// what its strict run came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskWorkflowStatus {
    pub attempt_ref: String,
    /// The record the TASK's handle named.
    pub requested: EntityId,
    /// The live program the try pinned; `None` when the handle led to none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved: Option<EntityId>,
    pub brief: BriefStamp,
    pub outcome: TaskWorkflowOutcome,
}

/// What a bound try's strict library run came to (CUA E4). Each settled
/// outcome names the receipt NOTE that holds its whole evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskWorkflowOutcome {
    /// Not run yet.
    Pending,
    /// The strict program was started at `at`, under the try's lease, and
    /// its end is not recorded yet (FIX 8104). An entry that finds it hands
    /// the run off as [`TaskWorkflowHandoff::Interrupted`]; it never runs
    /// the program again.
    Started { at: u64 },
    /// The program met its postcondition and every TASK check held, with no
    /// model answering (FIX 8072): a met run that was not model-free hands
    /// off instead.
    Done { receipt_ref: EntityId },
    /// The try went on to its planner, for `cause`.
    Handoff {
        cause: TaskWorkflowHandoff,
        receipt_ref: EntityId,
    },
}

/// Why a bound try went on to its planner (CUA E4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskWorkflowHandoff {
    /// The strict program stopped short, for its own `stop_cause` (E2).
    Program {
        stop_cause: oneiron_browser::BatchStopCause,
    },
    /// The program met its postcondition and a TASK check did not hold
    /// (`task_goal_unmet`).
    GoalUnmet,
    /// The handle's lineage ends at `id`, retired with no successor.
    Retired {
        id: EntityId,
        reason: Option<String>,
    },
    /// No program was ever filed under `id`.
    Missing { id: EntityId },
    /// The library could not be read for `id` at the try's first lease; the
    /// error is in the receipt.
    Unreadable { id: EntityId },
    /// The strict program was started at an earlier entry and its end was
    /// never recorded (FIX 8104): what it did on the page is unknown.
    Interrupted,
    /// The strict program met its postcondition with every TASK check
    /// holding, but its run was not model-free (FIX 8072): a verb hook
    /// dispatched a model, or a decision's record proves no rung
    /// (`model_free_unproven`), so the try settles no zero-model Done.
    NotModelFree,
}

impl TaskWorkflowHandoff {
    /// The stable code a planner reads the handoff by.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Program { .. } => "workflow_stopped",
            Self::GoalUnmet => "task_goal_unmet",
            Self::Retired { .. } => "workflow_retired",
            Self::Missing { .. } => "workflow_missing",
            Self::Unreadable { .. } => "workflow_unreadable",
            Self::Interrupted => "workflow_interrupted",
            Self::NotModelFree => "workflow_not_model_free",
        }
    }
}

/// The body of the `TaskLifecycle` receipt one mutating call owes: the call,
/// what was asked, what resolved, and why (ARCH-0079).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskLifecycleRecord {
    pub call: String,
    pub outcome: String,
    pub occurred_at: u64,
    /// No one once the actor was erased (FIX 3520).
    pub actor: TaskActor,
    /// The parent attempt of a host-bound call.
    pub on_behalf_of: Option<String>,
    /// The attempt, in hex.
    pub job_ref: Option<String>,
    /// The TASK, in hex.
    pub trigger_ref: Option<String>,
    pub fields: BTreeMap<String, String>,
}
