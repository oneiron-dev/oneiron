//! Moved from `crates/oneiron/src/lens/proposal.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_lens_wire::lens::generated_ui::GeneratedLens;
pub use oneiron_verb_wire::lens::proposal::LensListRequest;
pub use oneiron_verb_wire::lens::proposal::LensSlot;
use serde::Deserialize;
use serde::Serialize;
use std::ops::Bound;

/// Where a proposal stands in its slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensProposalState {
    /// Waiting for the owner, or cleared from its slot.
    Proposed,
    /// The owner's current selection for its slot.
    Active,
}

/// One proposal: neutral ids, its binding, its state and whether it mounts
/// now. Never a screen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LensListRow {
    pub lens_ref: String,
    pub pack_name: String,
    pub skill_id: String,
    pub pack_content_hash: String,
    pub compiled_hash: String,
    pub kit_version: u16,
    pub apps_contract_version: u16,
    pub proposed_by: String,
    pub proposed_at: u64,
    pub state: LensProposalState,
    /// Active, and its pack is still installed Active at the content it was
    /// proposed against, with the skill still loading.
    pub mounted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiled: Option<GeneratedLens>,
}

/// One page of `vault.lenses.list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LensListPage {
    pub rows: Vec<LensListRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after: Option<String>,
}
