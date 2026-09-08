//! Run-tree view types: nodes, status/event vocab, repairs, and markers.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptInterventionKind, AttemptState};

/// Renderable run tree for dashboard/read APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTree {
    pub roots: Vec<RunTreeNode>,
    pub repairs: Vec<RunTreeRepair>,
}

/// One renderable attempt node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTreeNode {
    #[serde(rename = "job_id")] // wire key pinned pre-rename (ONE-1714)
    pub attempt_id: String,
    pub run_id: Option<String>,
    pub parent_id: Option<String>,
    pub worker_kind: String,
    /// The dispatched agent's label for `agent.dispatch` attempts (decoded from
    /// the payload snapshot; tolerant — a malformed inner input renders as
    /// `None`). Additive and elided when absent, so serialized trees stay
    /// wire-compatible in both directions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    pub status: RunTreeStatus,
    /// The artifact version this attempt's durable output lives in, copied
    /// from the backing queue row. Cross-executor: any executor kind that
    /// named a result projects it here, not only foreign ones.
    ///
    /// Additive and elided when absent — the same shape as `agent_id` — so
    /// serialized trees stay wire-compatible in both directions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_ref: Option<String>,
    pub timestamps: RunTreeTimestamps,
    pub failure: Option<RunTreeFailure>,
    pub events: Vec<RunTreeEvent>,
    pub children: Vec<RunTreeNode>,
    /// ONE-1453 presentation marker: this run is durably paused by the
    /// per-actor burst breaker.
    ///
    /// PRESENTATION ONLY, and additive: it never mutates [`RunTreeStatus`],
    /// [`RunTreeEventKind`], attempt rows, or
    /// [`crate::attempt_queue::AttemptState`]. A breaker pause is not
    /// terminal and synthesizes no attempt event. Breaker truth lives in
    /// `gate`; the read adapter obtains that projection without storing it. Elided
    /// when false, so serialized trees stay wire-compatible in both
    /// directions.
    #[serde(default, skip_serializing_if = "is_false")]
    pub gate_breaker_paused: bool,
}

/// Serializer predicate that elides the additive `false` marker.
fn is_false(value: &bool) -> bool {
    !*value
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

/// An unchanged run tree plus the marker naming its failing node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTreeFailureDiagram {
    pub tree: RunTree,
    pub marker: RunTreeNodeMarker,
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
        }
    }
}
