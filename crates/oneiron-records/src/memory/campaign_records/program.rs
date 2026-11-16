//! Moved from `crates/oneiron/src/memory/campaign_records/program.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::memory::campaign_records::program::ArchiveCampaignProgramRequest;
pub use oneiron_verb_wire::memory::campaign_records::program::CampaignProgramAudienceSpec;
pub use oneiron_verb_wire::memory::campaign_records::program::CampaignProgramReadRequest;
use serde::Deserialize;
use serde::Serialize;

/// A program's lifecycle on the wire. Draft and Paused are the FIX 12542
/// lifecycle states; neither is ever presented as Active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignProgramLifecycle {
    /// Authored but not launched: editable, automatic_intake=false.
    Draft,
    /// Enrolls from its audience.
    Active,
    /// Held by a campaign pause: editable, automatic_intake=false.
    Paused,
    /// Retired: readable, enrolls no one, never re-opened.
    Archived,
}
