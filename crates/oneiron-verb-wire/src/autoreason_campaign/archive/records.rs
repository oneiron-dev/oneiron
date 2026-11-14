//! Moved from `crates/oneiron/src/autoreason_campaign/archive/records.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::autoreason_campaign::archive::ArchiveCell;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignArchiveRequest {
    pub root: EntityId,
}

/// Admission to the coverage floor only; other promotion gates still apply.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignArchiveAdmission {
    pub descriptor_revision: String,
    pub candidate: EntityId,
    pub required_cells: Vec<ArchiveCell>,
    pub covered_cells: Vec<ArchiveCell>,
    pub admitted: bool,
}
