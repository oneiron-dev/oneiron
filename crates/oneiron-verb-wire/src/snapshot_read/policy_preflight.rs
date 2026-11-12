//! Moved from `crates/oneiron/src/snapshot_read/policy_preflight.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::claim_history_handoff::ClaimReadStatus;
use oneiron_authority::claim_history_handoff::PointRead;
use oneiron_authority::claim_history_handoff::ScopedReadResult;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;

/// The act a preflight asks about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPreflightAct {
    /// Reading each ref through the caller's own scoped read.
    Read,
}

/// One `vault.policy.preflight` request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyPreflightRequest {
    /// The refs, at most [`POLICY_PREFLIGHT_MAX_REFS`]; each is answered in
    /// this order.
    pub refs: Vec<EntityId>,
    /// The act the caller means to take on them.
    pub act: PolicyPreflightAct,
}
