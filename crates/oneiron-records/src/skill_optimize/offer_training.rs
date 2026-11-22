//! Moved from `crates/oneiron/src/skill_optimize/offer_training.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_verb_wire::skill_optimize::offer_switch::SwitchOwner;
use serde::Deserialize;
use serde::Serialize;

/// The prepared run an approved Train offer handed off, at the exact spec
/// the owner authorized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferTrainingHandoff {
    pub offer: EntityId,
    pub offer_digest: String,
    pub run: EntityId,
    pub spec_blake3: [u8; 32],
    /// Who authorized the run, or no one once that actor was erased
    /// (FIX 20774).
    pub owner: SwitchOwner,
    pub at: u64,
}
