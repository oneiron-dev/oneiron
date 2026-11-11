//! Escalation mode, failure scope, and per-scope consecutive-transient policy.

use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};

use crate::failure_ladder::healer_dispatch::HealerSlot;

use super::classify::DEFAULT_MAX_CONSECUTIVE_TRANSIENTS;

/// What the Nth consecutive transient failure selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureEscalationMode {
    /// Route to the healer slot; the default slot wakes the Coach.
    Auto,
    Human,
}

/// The agent-side scope a policy binds to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureScope {
    /// Lowercase-hex EntityId spelling.
    pub agent_ref: String,
    #[serde(default)]
    pub skill_ref: Option<String>,
}

/// Caller-supplied policy. Persistence and lookup are not in this ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureScopePolicy {
    pub scope: FailureScope,
    pub max_consecutive_transients: NonZeroU16,
    pub escalation_mode: FailureEscalationMode,
    pub healer_slot: HealerSlot,
}

impl FailureScopePolicy {
    /// Selects the configured healer without changing the scope's retry cap.
    /// A reserved slot stays human-only; an explicit healer selects auto escalation.
    #[must_use]
    pub fn for_healer(
        scope: FailureScope,
        max_consecutive_transients: NonZeroU16,
        healer_slot: HealerSlot,
    ) -> Self {
        let escalation_mode = match &healer_slot {
            HealerSlot::Reserved => FailureEscalationMode::Human,
            HealerSlot::Coach | HealerSlot::AgentDef { .. } => FailureEscalationMode::Auto,
        };
        Self {
            scope,
            max_consecutive_transients,
            escalation_mode,
            healer_slot,
        }
    }

    /// The default policy: N=3, Auto escalation that wakes the Coach.
    #[must_use]
    pub const fn auto(scope: FailureScope) -> Self {
        Self {
            scope,
            max_consecutive_transients: DEFAULT_MAX_CONSECUTIVE_TRANSIENTS,
            escalation_mode: FailureEscalationMode::Auto,
            healer_slot: HealerSlot::Coach,
        }
    }
}
