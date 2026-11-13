//! Moved from `crates/oneiron/src/task_verb/fanout_batch.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One child. No child maximum is copied from the parent: the route reserves
/// its calibrated hold from the one existing parent spend tree.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FanoutChildInput {
    pub agent_ref: EntityId,
    pub label: String,
    pub prompt: String,
}

/// The caller supplies work and a retry key, never an actor, attempt or lease.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FanoutBatchInput {
    pub intent_key: String,
    pub children: Vec<FanoutChildInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FanoutSlotState {
    Held,
    Pending,
    Completed,
    Error,
}

/// The TASK's real terminal result, not an ask answer or an inferred success.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FanoutSlotTerminal {
    pub disposition: TaskTerminalDisposition,
    pub result_ref: Option<EntityId>,
    pub finished_at: u64,
}

/// `vault.fanout.launch`'s input: the launch to read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FanoutLaunchRequest {
    pub launch_ref: EntityId,
}

/// The durable hold of a launch that waits.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FanoutLaunchHold {
    pub surface_ref: String,
    pub denied: bool,
}
