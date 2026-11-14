//! Moved from `crates/oneiron/src/skill_attribution/late_credit.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::receipt::pack_attribution::UsedProvenanceEdge;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One fractional share, with its complete eligible used chain. An erase
/// redacts only the ids it names (FIX 8988): the share keeps its decay and
/// weight.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LateCreditShare {
    /// The credited skill; `None` once that skill is erased.
    pub subject: Option<EntityId>,
    /// The contributing skill the chain starts from; `None` for the run's
    /// output root, and once that skill is erased, which clears the chain too.
    pub origin_skill: Option<EntityId>,
    /// The used chain; `None` once an erased entity is one of its ends.
    pub chain: Option<Vec<UsedProvenanceEdge>>,
    pub decay: f64,
    pub weight: f64,
}
