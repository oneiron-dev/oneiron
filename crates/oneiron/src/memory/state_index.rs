//! Composite-state projection records and owner-authored window targets.

use crate::EntityId;

/// Input claims use unit-interval values. Producers own measurement, not this projection.
pub const GOAL_VELOCITY: &str = "state.goal_velocity";
pub const ENGAGEMENT: &str = "state.engagement";
pub const COMPOSITE_INDEX: &str = "state.composite_index";

/// The composite index's evidence key. The evidence counts the annotated
/// turns the index read and names no turn: each turn sits in its room's
/// facet and the composite in the subject's substrate facet, so a reader of
/// the composite may not read those turns (Engine ANSWER
/// AFFECT-SIGNAL-COUNT-NOT-LIST = A). It names neither signal claim either:
/// a reader the composite admits may be refused a signal row by a check of
/// its own (REVIEW-9905 P1 round 2).
pub const COMPOSITE_EVIDENCE_ANNOTATED_TURNS: &str = "annotated_turns";

/// Evidence selected by a derived/Dreamer pass. Each reference must resolve in the vault.
#[derive(Debug, Clone)]
pub struct StateIndexEvidence {
    pub vad_turns: Vec<EntityId>,
    pub goal_velocity: EntityId,
    pub engagement: EntityId,
}

#[doc(hidden)]
pub use oneiron_verb_wire::memory::state_index::{ModeGateInputs, StateIndex, StateWindow};
