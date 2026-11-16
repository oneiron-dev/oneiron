//! Moved from `crates/oneiron/src/memory/merge_queue_doors/checker_types.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::merge_queue_doors::types::MergeQueuePointersView;
use crate::merge_queue::check_inputs::QueueCheckHoldReason;
use crate::merge_queue::types::CheckPhase;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::merge_queue::types::Quarantine;
pub use oneiron_verb_wire::memory::merge_queue_doors::checker_types::MergeQueueCheckRequest;
pub use oneiron_verb_wire::memory::merge_queue_doors::checker_types::MergeQueueCheckStatusRequest;
pub use oneiron_verb_wire::memory::merge_queue_doors::checker_types::MergeQueueDiagnoseRequest;
pub use oneiron_verb_wire::memory::merge_queue_doors::checker_types::MergeQueueInitializeRequest;
pub use oneiron_verb_wire::memory::merge_queue_doors::checker_types::QueueCheckPhase;
use serde::Deserialize;
use serde::Serialize;

impl From<QueueCheckPhase> for CheckPhase {
    fn from(phase: QueueCheckPhase) -> Self {
        match phase {
            QueueCheckPhase::Fast => Self::Fast,
            QueueCheckPhase::Slow => Self::Slow,
        }
    }
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
