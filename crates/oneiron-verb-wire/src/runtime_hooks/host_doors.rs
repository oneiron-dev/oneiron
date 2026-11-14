//! Moved from `crates/oneiron/src/runtime_hooks/host_doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::compaction::host_request::HostCompactRequest;
use oneiron_model::llm::BudgetExhaustionPolicy;
pub use oneiron_store::compaction::host_request::HostCompactResult;
use serde::Deserialize;
use serde::Serialize;

/// Names an existing durable spend scope. Its cap's policy is Suspend;
/// neither the policy nor accounting can be changed by this notification.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostBudgetHitRequest {
    pub seat: String,
    pub policy: BudgetExhaustionPolicy,
}
