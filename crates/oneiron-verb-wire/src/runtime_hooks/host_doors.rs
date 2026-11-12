//! Moved from `crates/oneiron/src/runtime_hooks/host_doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::compaction::host_request::HostCompactRequest;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::BudgetExhaustionPolicy;
pub use oneiron_store::compaction::host_request::HostCompactResult;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostWakeKind {
    Compaction,
    SessionEnd,
    Event,
    Timer,
}

impl HostWakeKind {
    fn trigger(self) -> oneiron_wake_contract::dreamer_wake::types::WakeTrigger {
        use oneiron_wake_contract::dreamer_wake::types::WakeTrigger;
        match self {
            Self::Compaction => WakeTrigger::Compaction,
            Self::SessionEnd => WakeTrigger::SessionEnd,
            Self::Event => WakeTrigger::Event,
            Self::Timer => WakeTrigger::Timer,
        }
    }
}

/// The trigger is nominal: Timer schedules its maintenance lanes in the
/// same write as consolidation, rather than becoming a generic enqueue.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostWakeRequest {
    pub wake_kind: HostWakeKind,
    /// The host's queue snapshot, carried to the hooks and the queued wake.
    pub queue_head: Vec<EntityId>,
}

/// Names an existing durable spend scope. Its cap's policy is Suspend;
/// neither the policy nor accounting can be changed by this notification.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostBudgetHitRequest {
    pub seat: String,
    pub policy: BudgetExhaustionPolicy,
}
