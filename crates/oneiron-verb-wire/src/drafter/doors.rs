//! Moved from `crates/oneiron/src/drafter/doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::drafter::types::DrafterActor;
use crate::drafter::types::DrafterServing;
use crate::drafter::types::DrafterVersionState;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MEMORY_CODE_FORBIDDEN;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

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
