//! Moved from `crates/oneiron/src/engine_executor/checkpoint_read.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One page of one code run's checkpoints.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckpointReadRequest {
    /// 32-hex code-run id (the executor run, not an attempt's run
    /// correlation id).
    pub run_ref: String,
    /// First checkpointed step to read, inclusive.
    #[serde(default)]
    pub from_step: u64,
    /// Steps in this page; [`CHECKPOINT_READ_DEFAULT_LIMIT`] when absent,
    /// at most [`CHECKPOINT_READ_MAX_LIMIT`]. Must be positive.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// A page of committed checkpoints and the stored replies resumed at them.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckpointView {
    pub run_ref: String,
    /// Count of checkpointed steps, not an in-flight step.
    pub completed_steps: u64,
    pub steps: Vec<CheckpointStepView>,
    /// The replies parked calls of this page's steps resumed with, in the
    /// order the run recorded them.
    pub resumed: Vec<CheckpointResumeView>,
    /// Where the next page starts; none past the last checkpoint.
    pub next_step: Option<u64>,
}

/// One committed step checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckpointStepView {
    pub step: u64,
    pub label: String,
    /// 64-hex chained state hash the checkpoint committed.
    pub state_hash: String,
    pub created_at_ms: u64,
}

/// One stored reply a parked call resumed with.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckpointResumeView {
    /// The step whose call parked.
    pub step: u64,
    /// 32-hex id of the wait the call parked on.
    pub wait_ref: String,
    /// The parked call's effect.
    pub effect: String,
    /// The run's handle on the stored reply (bound as `wait<step>`).
    pub output_handle: String,
    /// The reply itself, exactly when the injector carries it inline: small
    /// enough and clean of secret or taint for this run. Otherwise absent,
    /// and the reply is read by its handle.
    pub reply: Option<serde_json::Value>,
}
