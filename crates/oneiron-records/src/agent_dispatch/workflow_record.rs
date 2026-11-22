//! Moved from `crates/oneiron/src/agent_dispatch/workflow_record.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;

/// A completed step's stable provenance, independent of queue dedupe retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowStepResult {
    pub ordinal: usize,
    pub requested_agent: String,
    pub dispatched_agent: String,
    pub attempt_id: AttemptId,
    pub result_ref: String,
}
