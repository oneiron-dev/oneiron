//! Moved from `crates/oneiron/src/dreamer_wake/policy.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::dreamer_wake::policy::observation::*;
use crate::dreamer_wake::policy::*;
use oneiron_base::error::Error;
pub use oneiron_store::dreamer_wake_policy::AgentWakeRole;
pub use oneiron_store::dreamer_wake_policy::AgentWakeSignals;
pub use oneiron_store::dreamer_wake_policy::AgentWakeTriggers;
pub use oneiron_store::dreamer_wake_policy::CadencePrecedence;
pub use oneiron_store::dreamer_wake_policy::WeaveRecipePriority;
use serde::Deserialize;
use serde::Serialize;

pub fn invalid() -> Error {
    Error::InvalidConfig("invalid dreamer wake policy row".into())
}

/// Liveness is sampled by the host at the same instant as the policy check.
/// `last_inbound_at` is seconds on the vault clock. A running turn or live
/// background job cancels the quiet timer rather than merely postponing work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeIdleState {
    pub running_turns: bool,
    pub live_background_work: bool,
    /// False when the vault has no usable compute lease; idle must suspend.
    pub compute_available: bool,
    pub last_inbound_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum WakePolicyDecision {
    Silent,
    ArmIdle { due_at: u64 },
    Enqueue { recipe: WakeRecipe },
}

/// Which workflow recipe receives the durable wake signal. This is not a
/// consolidation scope: a policy trigger alone has no partition payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WakeRecipe {
    Continuous,
    Nightly,
    Weave,
}

impl WakeRecipe {
    const fn key(self) -> u8 {
        match self {
            Self::Continuous => 0,
            Self::Nightly => 1,
            Self::Weave => 2,
        }
    }
}
pub mod observation;
