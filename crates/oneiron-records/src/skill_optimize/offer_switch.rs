//! Moved from `crates/oneiron/src/skill_optimize/offer_switch.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_verb_wire::embed::binding_move::BindingMoveState;
use oneiron_verb_wire::embed::binding_move::BindingNotApplied;
pub use oneiron_verb_wire::skill_optimize::offer_switch::SwitchOwner;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Where a switch's binding stands: bound with the approval, or, for the
/// embedder seat, staged through a space move and applied at its swap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SwitchApplication {
    /// Bound in the approval's own write.
    Bound,
    /// Staged: the old binding and index serve while its candidate space
    /// fills, or until a declared space pins the model.
    Staged,
    /// The staged binding applied as its move swapped in.
    Applied { at: u64 },
    /// The staged binding never applied.
    NotApplied { at: u64, why: BindingNotApplied },
}

impl SwitchApplication {
    /// What a staged binding's `state` reads as here; `None` for an undo,
    /// which the receipt's own `undone` records.
    fn staged(state: &BindingMoveState) -> Option<Self> {
        match state {
            BindingMoveState::Waiting | BindingMoveState::Filling => Some(Self::Staged),
            BindingMoveState::Applied { at, .. } => Some(Self::Applied { at: *at }),
            BindingMoveState::NotApplied { at, why } => Some(Self::NotApplied {
                at: *at,
                why: why.clone(),
            }),
            BindingMoveState::Undone { .. } => None,
        }
    }
}

/// The owner's undo of a switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferSwitchUndo {
    pub owner: SwitchOwner,
    pub at: u64,
}
