//! Composite-state projection records and owner-authored window targets.

use crate::{EntityId, Error, Result};
use serde::{Deserialize, Serialize};

/// Input claims use unit-interval values. Producers own measurement, not this projection.
pub const GOAL_VELOCITY: &str = "state.goal_velocity";
pub const ENGAGEMENT: &str = "state.engagement";
pub const COMPOSITE_INDEX: &str = "state.composite_index";

/// Evidence selected by a derived/Dreamer pass. Each reference must resolve in the vault.
#[derive(Debug, Clone)]
pub struct StateIndexEvidence {
    pub vad_turns: Vec<EntityId>,
    pub goal_velocity: EntityId,
    pub engagement: EntityId,
}

#[doc(hidden)]
use oneiron_verb_wire::memory::state_index::invalid;
#[doc(hidden)]
pub use oneiron_verb_wire::memory::state_index::{ModeGateInputs, StateIndex, StateWindow};
