//! The checker doors' wire types (FIX 6868). A request names no argv, plan
//! body, output, actor, green, pass or receipt; the answer names no host
//! path, plan command body or command exhaust.
use serde::{Deserialize, Serialize};

use super::MergeQueuePointersView;
use crate::EntityId;
use crate::merge_queue::{CheckPhase, Quarantine, QueueCheckHoldReason};

/// Checked initialization of one repository's queue.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeQueueInitializeRequest {
    /// An existing CODE_ARTIFACT whose stored pointer is a local folder.
    pub repo: EntityId,
    /// The repository's current clean HEAD Git commit, 40 hex characters.
    /// Its `.oneiron/checks.json` is the plan the queue freezes.
    pub baseline_commit: String,
    /// An existing contract baseline the init cross-checks; its contracts
    /// must be the plan's. None records a new one.
    #[serde(default)]
    pub contract_baseline_ref: Option<String>,
}

/// A check phase on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueueCheckPhase {
    Fast,
    Slow,
}

impl From<QueueCheckPhase> for CheckPhase {
    fn from(phase: QueueCheckPhase) -> Self {
        match phase {
            QueueCheckPhase::Fast => Self::Fast,
            QueueCheckPhase::Slow => Self::Slow,
        }
    }
}

/// One fast or slow check of one staged path, on the frozen plan.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeQueueCheckRequest {
    /// An existing CODE_ARTIFACT whose stored pointer is a local folder.
    pub repo: EntityId,
    /// The batch digest an enqueue returned, 64 hex characters.
    pub batch_ref: String,
    /// The staged path's bitset of included proposals. A slow check names
    /// the landed path.
    pub mask: u64,
    pub phase: QueueCheckPhase,
    /// Run again even when a passing receipt of the same inputs exists.
    #[serde(default)]
    pub force_refresh: bool,
}

/// The diagnosis of one red batch.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeQueueDiagnoseRequest {
    /// An existing CODE_ARTIFACT whose stored pointer is a local folder.
    pub repo: EntityId,
    /// The batch digest an enqueue returned, 64 hex characters.
    pub batch_ref: String,
}

/// One checker work row to read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeQueueCheckStatusRequest {
    /// An existing CODE_ARTIFACT whose stored pointer is a local folder.
    pub repo: EntityId,
    /// The work reference a checker door returned, 64 hex characters.
    pub work_ref: String,
}

/// What a checker work row asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeQueueCheckWorkKind {
    Init,
    Check,
    Diagnose,
}

/// Where a checker work row stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeQueueCheckState {
    Queued,
    Running,
    /// Kept; nothing goes green until the named configuration exists.
    NeedsConfiguration,
    /// Kept with no verdict: an interrupted or unavailable executor, a
    /// missing offline input or a lapsed approval.
    Held,
    Passed,
    Failed,
    /// The path already held a verdict when the check ran.
    Settled,
}

/// One checker work row as the wire carries it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeQueueCheckWorkView {
    pub repo: EntityId,
    pub work_ref: String,
    pub kind: MergeQueueCheckWorkKind,
    pub status: MergeQueueCheckState,
    /// The setting keys a needs-configuration status names.
    pub configuration_keys: Vec<String>,
    /// Why the work needs configuration or is held.
    pub reason: Option<String>,
    pub hold: Option<QueueCheckHoldReason>,
    /// How many times the request was queued.
    pub generation: u32,
    pub baseline_commit: Option<String>,
    pub plan_digest: Option<String>,
    /// Each generation's receipt, by its bound inputs digest, oldest first.
    pub receipt_refs: Vec<String>,
    /// The stored contract verdicts the work recorded or found.
    pub verdict_refs: Vec<String>,
    /// The queue pointers a completed init produced.
    pub pointers: Option<MergeQueuePointersView>,
    /// The minimal failing group a completed diagnosis kept.
    pub quarantine: Option<Quarantine>,
}
