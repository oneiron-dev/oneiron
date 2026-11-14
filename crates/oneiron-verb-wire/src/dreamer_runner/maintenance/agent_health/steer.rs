//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/agent_health/steer.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::attempt_run_signal::RunSignalState;
use serde::Deserialize;
use serde::Serialize;

/// `steer`'s input: the child TASK, the nudge, and the caller's retry key.
/// A resend with the same key and instruction answers the first receipt.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SteerRequest {
    pub task_ref: String,
    pub instruction: String,
    pub key: String,
}

/// `steer`'s answer: the live attempt whose inbox holds the signal, and the
/// signal's state (pending until the child's breakpoint takes it).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SteerReceipt {
    pub task_ref: String,
    pub branch: String,
    pub run_id: String,
    pub key: String,
    pub state: RunSignalState,
}
