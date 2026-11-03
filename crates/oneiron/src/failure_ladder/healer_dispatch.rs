//! Failure-ladder healer routing contract.

use crate::failure_ladder::HealerCase;
use serde::{Deserialize, Serialize};

/// Which healer a failure scope routes its cases to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealerSlot {
    /// No healer: the case goes only to the human surface. It is an explicit
    /// typed outcome, never a silently dropped case.
    Reserved,
    /// The Coach, the second base agent (ARCH-0066 #coach): the default slot.
    /// The case also wakes one Coach heal attempt on the Dreamer's runner.
    Coach,
    /// Lowercase-hex EntityId spelling.
    AgentDef { agent_def_ref: String },
}

/// Caller input for [`AgentDispatcher::dispatch_healer_slot`](crate::agent_dispatch::AgentDispatcher::dispatch_healer_slot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchHealer {
    pub slot: HealerSlot,
    pub case: HealerCase,
    pub run_id: Option<String>,
    pub now: u64,
}
