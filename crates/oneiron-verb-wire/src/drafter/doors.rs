//! Moved from `crates/oneiron/src/drafter/doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The status read: events after `events_after` only, when given.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterStatusRequest {
    #[serde(default)]
    pub events_after: Option<EntityId>,
}

/// A revert of `version`'s target to `version`, at the binding generation
/// the caller read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterRevertRequest {
    pub version: EntityId,
    pub expected_binding_generation: u64,
}
