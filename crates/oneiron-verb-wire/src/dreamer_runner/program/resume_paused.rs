//! The wire shapes of the owner's resume of paused turn programs
//! (`vault.turn_programs.resume`, FIX
//! TURNPROGRAM-OCCURRENCE-ARMINGS-LIVE-ON-A-VAULT-COPY).

use crate::dreamer_runner::program::read::views::PausedTurnProgramItem;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The owner's resume of some of the programs a vault copy holds paused.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResumePausedTurnProgramsRequest {
    /// The registrations to resume, as `vault.turn_programs.paused` lists
    /// them: at least one and at most 64, none twice. Each must be a paused
    /// program of this store; the ones it does not name stay paused.
    pub registrations: Vec<EntityId>,
    /// The confirm `vault.owner_confirm.preview` returned for this call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<String>,
}

/// What the owner's sheet shows of one resume, and what its confirm binds:
/// the chosen programs as they stand, in actor order, then registration
/// order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResumePausedTurnProgramsPreview {
    pub programs: Vec<ResumePausedTurnProgramItem>,
}

/// One chosen program as the sheet shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResumePausedTurnProgramItem {
    /// The program as the paused list shows it to the owner.
    pub program: PausedTurnProgramItem,
    /// Whether resuming wakes it at once: it is a timer whose next due time
    /// has passed. It then wakes once, late, and goes on from its next due
    /// time. An idle or a feed program is never marked: it wakes when the
    /// host next turns idle, or when its feed next shows it an entry.
    pub fires_at_once: bool,
}

/// What one resume did.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResumedTurnPrograms {
    /// The programs resumed, as the sheet showed them.
    pub resumed: Vec<ResumePausedTurnProgramItem>,
    /// How many programs the store still holds paused.
    pub still_paused: u64,
}
