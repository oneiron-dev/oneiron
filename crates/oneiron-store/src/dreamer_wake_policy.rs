//! The owner-editable dreamer wake-policy row (`DREAMER_WAKE_POLICY`) and
//! its parts: the recipe dials, the resident role table with each role's
//! trigger classes and the cadence precedence, and the trigger facts the
//! scheduler supplies. The dreamer wake (`dreamer_wake::policy`) validates
//! and applies them; agent definitions take them to decide a resident's
//! wake.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WeaveRecipePriority {
    BeforeConnectorEvent,
    AfterConnectorEvent,
}

/// Which role a definition without an explicit cadence dial receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentWakeRole {
    Companion,
    Leader,
    Worker,
}

/// The owner-selected cadence precedence. The shipped default lets an
/// agent's explicit interval override the vault grain (FIX 8727); an owner
/// who wants no agent woken more often than the vault picks the vault floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CadencePrecedence {
    VaultFloor,
    AgentOverride,
}

/// Which signal classes admit a wake for one role. Each bit is policy data,
/// not a hardcoded role switch in the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentWakeTriggers {
    pub cadence: bool,
    pub surprise: bool,
    pub agency: bool,
    pub event: bool,
}

/// Trigger facts supplied to the engine scheduler; the policy selects which
/// facts a resident role may use. Cadence is derived, never caller asserted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AgentWakeSignals {
    pub surprise: bool,
    pub agency: bool,
    pub event: bool,
}
