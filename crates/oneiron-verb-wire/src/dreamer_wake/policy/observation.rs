//! Moved from `crates/oneiron/src/dreamer_wake/policy/observation.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_wake::policy::*;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::sync::atomic::Ordering;

/// One real scheduler check. Reads of this receipt never run the scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeCadenceReceipt {
    pub sequence: u64,
    pub observed_at: u64,
    /// The deadline the preceding check armed, if any.
    pub previous_due_at: Option<u64>,
    pub boundary_reached: bool,
    /// Sticky across later checks, so child completions cannot hide a boundary.
    pub last_boundary_at: Option<u64>,
    pub idle: WakeIdleState,
    pub decision: WakePolicyDecision,
    pub wake: Option<EntityId>,
    pub processed_change_id: Option<[u8; 16]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WakeCadenceRequest {}
