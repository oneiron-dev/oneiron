//! Moved from `crates/oneiron/src/verbs/fanout_launch.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::task_verb::fanout_batch::FanoutLaunchHold;
pub use crate::task_verb::fanout_batch::FanoutLaunchRequest;
use crate::task_verb::fanout_launch::FanoutCheckChoice;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The owner's ruling on a held launch. A denial keeps the hold, visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FanoutLaunchRuling {
    ApproveOnce,
    ApproveAndRemember,
    Deny,
}

/// `vault.fanout.resume`'s input: the held launch, the digest the owner
/// saw, the ruling, and the standing cap an approve-and-remember keeps.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FanoutResumeRequest {
    pub launch_ref: EntityId,
    pub plan_digest: String,
    pub ruling: FanoutLaunchRuling,
    #[serde(default)]
    pub remembered_cap: Option<u64>,
}

/// `vault.fanout.ack`'s input: the launch whose width check is answered,
/// the digest the owner saw, the answer, and the standing cap an
/// ack-and-remember keeps.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FanoutAckRequest {
    pub launch_ref: EntityId,
    pub plan_digest: String,
    pub answer: FanoutCheckChoice,
    #[serde(default)]
    pub remembered_cap: Option<u64>,
}
