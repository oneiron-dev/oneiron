//! Moved from `crates/oneiron/src/memory/merge_queue_doors/checker_types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

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
