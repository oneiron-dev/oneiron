//! Moved from `crates/oneiron/src/dreamer_runner/authority.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub(crate) use oneiron_store::base_agent::coach_actor_id;
pub(crate) use oneiron_store::base_agent::dreamer_actor_id;
pub(crate) use oneiron_store::base_agent::guard_actor_delete;
pub(crate) use oneiron_store::base_agent::guard_actor_put;
pub(crate) use oneiron_store::base_agent::is_base_agent_actor;
use serde::Deserialize;
use serde::Serialize;

/// A resident's stamp on one of its own dreaming attempts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidentAuthorityStamp {
    pub attempt_id: [u8; 16],
    pub resident: EntityId,
    pub receipt_id: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamerAuthorityStamp {
    pub attempt_id: [u8; 16],
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    pub actor: EntityId,
    pub facet: String,
    pub receipt_id: [u8; 16],
}
