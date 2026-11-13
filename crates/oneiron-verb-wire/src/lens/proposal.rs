//! Moved from `crates/oneiron/src/lens/proposal.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;
use std::ops::Bound;

/// One pack lens slot: an installed pack and one of its skills.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LensSlot {
    pub pack_name: String,
    /// The SKILL's 32-hex entity id.
    pub skill_id: String,
}

impl LensSlot {
    pub fn skill(&self) -> MemoryResult<EntityId> {
        EntityId::from_hex(&self.skill_id)
            .map_err(|_| MemoryError::bad_request("slot.skill_id is a 32-hex SKILL id"))
    }
}

/// `vault.lenses.list`'s input: one page of proposals in lens-id order.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LensListRequest {
    /// Only this pack's proposals.
    #[serde(default)]
    pub pack_name: Option<String>,
    /// The `next_after` of the page before.
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    /// Carry each proposal's frozen tree. A reader narrowed to some worlds
    /// or facets gets the trees of the proposals whose scope its read
    /// admits, each whole and only while it reads every row the tree names
    /// (FIX 2136).
    #[serde(default)]
    pub with_compiled: bool,
}
