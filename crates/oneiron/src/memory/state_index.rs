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

/// Numerical inputs retained so an agent can make its own mode decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModeGateInputs {
    pub affect: f32,
    pub goal_velocity: f32,
    pub engagement: f32,
}

/// Unknown subjects return a neutral 0.5 with no inputs or claim. Absence is not evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StateIndex {
    pub value: f32,
    pub inputs: Option<ModeGateInputs>,
    pub claim: Option<String>,
    pub observed_at: Option<u64>,
}
impl Default for StateIndex {
    fn default() -> Self {
        Self {
            value: 0.5,
            inputs: None,
            claim: None,
            observed_at: None,
        }
    }
}

/// The owner's targets for one window. They describe this person's own
/// pace, not a clinical or population norm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StateWindow {
    pub window_secs: u64,
    pub expected_goal_completions: u32,
    pub expected_engaged_days: u32,
}

impl StateWindow {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.window_secs == 0
            || self.expected_goal_completions == 0
            || self.expected_engaged_days == 0
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn invalid() -> Error {
    Error::InvalidClaimBody("invalid state index window")
}
