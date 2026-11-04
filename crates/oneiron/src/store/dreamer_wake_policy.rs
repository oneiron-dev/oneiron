//! The owner-editable dreamer wake-policy row (`DREAMER_WAKE_POLICY`) and
//! its parts: the recipe dials, the resident role table with each role's
//! trigger classes and the cadence precedence, and the trigger facts the
//! scheduler supplies. The dreamer wake (`dreamer_wake::policy`) validates
//! and applies them; agent definitions take them to decide a resident's
//! wake.
use serde::{Deserialize, Serialize};

/// Per-vault recipe dials. An owner may write a different v1 row; these are
/// data, not compiled thresholds. `new_records` excludes Generated claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamerWakePolicy {
    pub wake_grain_turns: u64,
    /// Resident trigger table, missing-role rule and nested rate precedence.
    pub agent_cadence: AgentWakePolicy,
    /// New explicit CLAIMs plus user TURNs since the last weave.
    pub new_records: u64,
    pub longest_wait_secs: u64,
    pub nightly_secs: u64,
    /// Minimum inbound silence for any idle recipe to run.
    pub idle_secs: u64,
    /// Independent quiet-window trigger for Weave, even below accumulation.
    pub quiet_weave_secs: u64,
    /// Where the per-vault workflow skill competes with connector events.
    /// Cleanup and maintenance retain their protected priority; consolidation
    /// stays after these two lanes so its home-node stop cannot starve them.
    pub weave_recipe_priority: WeaveRecipePriority,
    /// The surprise floor, in thousandths (OF-138, ARCH-0036): a turn whose
    /// re-tag moved at least this far beside the set it replaced is a
    /// surprise signal for a resident's wake. The tagger measures the delta;
    /// a role's trigger table decides whether surprise may wake it.
    pub surprise_permille: u16,
}

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

/// Role table on the owner-editable wake-policy row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentWakePolicy {
    pub absent_role: AgentWakeRole,
    pub precedence: CadencePrecedence,
    pub companion: AgentWakeTriggers,
    pub leader: AgentWakeTriggers,
    pub worker: AgentWakeTriggers,
}

/// Trigger facts supplied to the engine scheduler; the policy selects which
/// facts a resident role may use. Cadence is derived, never caller asserted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AgentWakeSignals {
    pub surprise: bool,
    pub agency: bool,
    pub event: bool,
}
