//! Moved from `crates/oneiron/src/verbs/engine_controls.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_runner::free_time::policy::FreeTimeSchedule;
use serde::Deserialize;
use serde::Serialize;

/// `vault.stewardship.rules.period.set`'s input: how often the standing
/// rule `rule` falls due, in seconds. The rule's person, draft route and
/// `since` stay as the owner set them.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StewardshipRulePeriodSetRequest {
    /// The rule's id, as the rule set names it.
    pub rule: String,
    pub every_secs: u64,
}

/// `vault.free_time.schedule.set`'s input: the agent (32 hex) whose standing
/// free-time policy moves, the revision the caller read, and the new
/// schedule. The policy's units, split and shown cap stay the owner's.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeScheduleSetRequest {
    pub agent: String,
    pub expected_revision: u64,
    pub schedule: FreeTimeSchedule,
}
