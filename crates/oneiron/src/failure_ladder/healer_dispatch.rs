//! Failure-ladder healer routing contract.

use crate::failure_ladder::HealerCase;
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_records::failure_ladder::healer_dispatch::HealerSlot;

/// Caller input for [`AgentDispatcher::dispatch_healer_slot`](crate::agent_dispatch::AgentDispatcher::dispatch_healer_slot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchHealer {
    pub slot: HealerSlot,
    pub case: HealerCase,
    pub run_id: Option<String>,
    pub now: u64,
}
