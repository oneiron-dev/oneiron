//! Moved from `crates/oneiron/src/skill_optimize/offer_switch.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::skill_optimize::offer_switch::SwitchOwner;
use serde::Deserialize;
use serde::Serialize;

/// The owner's undo of a switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferSwitchUndo {
    pub owner: SwitchOwner,
    pub at: u64,
}
