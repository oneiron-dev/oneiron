//! Moved from `crates/oneiron/src/autoreason_campaign/archive.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::autoreason_campaign::archive::axes::ArchiveAxis;
pub use crate::autoreason_campaign::archive::records::CampaignArchiveAdmission;
pub use crate::autoreason_campaign::archive::records::CampaignArchiveRequest;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Coordinates use the axis order in the pinned definition. Cluster cells are
/// deliberately unnamed and cannot mix with categorical cells.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchiveCell {
    Axes { bins: Vec<String> },
    Cluster { index: usize },
}

/// The scoring definition shared by every output in this campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveQualityMetric {
    pub metric_id: String,
    pub revision: String,
}
pub mod axes;
pub mod records;
