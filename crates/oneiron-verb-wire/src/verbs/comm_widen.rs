//! Moved from `crates/oneiron/src/verbs/comm_widen.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.tasks.comm_widen.revoke`'s input: the run whose widen ask recorded
/// the stop-asking choice.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommWidenRevokeRequest {
    /// The asking run's attempt, 32 hex: the receipt's `attempt`.
    pub attempt: EntityId,
}
