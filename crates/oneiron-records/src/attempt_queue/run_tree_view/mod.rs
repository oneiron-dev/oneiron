//! Moved from `crates/oneiron/src/attempt_queue/run_tree_view/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::attempt_inputs::AttemptInterventionKind;
use oneiron_store::attempt_state::AttemptState;
use oneiron_store::model_step_submission::StepBudgetRefusal;
use serde::Deserialize;
use serde::Serialize;

/// One real archived-attempt deletion, not a synthetic attempt node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTreeDeletion {
    pub attempt_id: String,
    /// Absent only after this actor's erase scrub.
    pub deleted_by: Option<String>,
    pub deleted_at: u64,
}

/// One [`RunTreeNode`]'s own fields in its tree's [`RunTreeWire`] table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTreeWireNode {
    #[serde(rename = "job_id")] // wire key pinned pre-rename (ONE-1714)
    pub attempt_id: String,
    pub run_id: Option<String>,
    pub parent_id: Option<String>,
    pub worker_kind: String,
    /// Operator-selected worker, if this attempt has been redirected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker: Option<String>,
    /// The dispatched agent's label for `agent.dispatch` attempts; elided
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    pub status: RunTreeStatus,
    /// The artifact version this attempt's durable output lives in; elided
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_ref: Option<String>,
    pub timestamps: RunTreeTimestamps,
    pub failure: Option<RunTreeFailure>,
    pub events: Vec<RunTreeEvent>,
    /// The node's children, as indexes into the table's `nodes`, in order.
    pub children: Vec<u64>,
}

/// Surface lifecycle status.
///
/// A waiting [`AttemptState::Scheduled`] try maps onto the existing `Paused`
/// token — deferred, not eligible to run now — which the Context Board already
/// projects as `TaskBoardStatus::Scheduled`. No readiness field or new variant
/// is added here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunTreeStatus {
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
    /// The executor stopped without delivering and without being stopped. Its
    /// own token because the two neighbouring ones are both claims about a
    /// cause: `Failed` asserts an observed fault, `Cancelled` asserts an
    /// operator's intent, and an abandonment has neither.
    Abandoned,
}

/// Node timestamps copied from the backing queue row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTreeTimestamps {
    pub created_at: u64,
    pub updated_at: u64,
}

/// Summarized failure state for display and API reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTreeFailure {
    pub reason: String,
    /// The typed refusal of a try a spend scope refused for good
    /// (BUDGET-TRAP-UNTYPED-NO-SENDER), copied from the failed row beside
    /// `reason`; `None` for every other failure and on a tree kept before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_refusal: Option<StepBudgetRefusal>,
}

/// Lifecycle/operator event for display and API reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTreeEvent {
    pub sequence: u64,
    pub at: u64,
    pub actor: String,
    pub kind: RunTreeEventKind,
    pub note: Option<String>,
}

/// Surface lifecycle/operator event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunTreeEventKind {
    Created,
    Claimed,
    Paused,
    Resumed,
    Completed,
    Failed,
    Cancelled,
    Interrupted,
    Redirected,
    /// The attempt reached [`RunTreeStatus::Abandoned`].
    Abandoned,
    /// The attempt named the artifact version carrying its durable output.
    /// Emitted for every executor kind that attaches one, whether or not the
    /// row settled normally.
    ResultAttached,
}

/// Non-mutating repairs applied while rendering a tree from rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunTreeRepair {
    MissingParent {
        #[serde(rename = "job_id")] // wire key pinned pre-rename (ONE-1714)
        attempt_id: String,
        missing_parent_id: String,
    },
    ParentCycle {
        #[serde(rename = "job_id")] // wire key pinned pre-rename (ONE-1714)
        attempt_id: String,
        parent_id: String,
    },
}

/// Why one rendered node is marked.
///
/// ONE-1887 overlay vocabulary, deliberately NOT a [`RunTreeStatus`] variant
/// and not a second readiness axis: marking a failure is a view concern, so
/// the shared attempt-lifecycle projection stays exactly as ONE-1795 left it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunTreeNodeMarkerKind {
    Failing,
}

/// One typed marker naming a rendered node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTreeNodeMarker {
    /// The same lowercase-hex spelling [`RunTreeNode::attempt_id`] carries.
    pub attempt_id: String,
    pub kind: RunTreeNodeMarkerKind,
}

impl From<AttemptState> for RunTreeStatus {
    fn from(state: AttemptState) -> Self {
        match state {
            AttemptState::Queued => Self::Queued,
            // A landing attempt is STILL RUNNING: it holds its lease and is
            // doing bounded finishing work. It is emphatically not `Completed`
            // — nothing was delivered — and not `Cancelled` — nothing was
            // killed. The trigger provenance rides
            // [`project_attempt_to_a2a`] and the durable receipts rather than a
            // seventh status token, so no read surface has to learn a new axis
            // to keep telling live work from settled work.
            AttemptState::Leased | AttemptState::Landing => Self::Running,
            // Deferred until its scheduled instant: the same "not eligible to
            // run now" axis the board already renders as Scheduled.
            AttemptState::Paused | AttemptState::Scheduled => Self::Paused,
            AttemptState::Completed => Self::Completed,
            AttemptState::Failed => Self::Failed,
            AttemptState::Cancelled => Self::Cancelled,
            AttemptState::Abandoned => Self::Abandoned,
        }
    }
}

impl From<AttemptInterventionKind> for RunTreeEventKind {
    fn from(kind: AttemptInterventionKind) -> Self {
        match kind {
            AttemptInterventionKind::Interrupt => Self::Interrupted,
            AttemptInterventionKind::Pause => Self::Paused,
            AttemptInterventionKind::Resume => Self::Resumed,
            AttemptInterventionKind::Cancel => Self::Cancelled,
            AttemptInterventionKind::Redirect => Self::Redirected,
        }
    }
}
