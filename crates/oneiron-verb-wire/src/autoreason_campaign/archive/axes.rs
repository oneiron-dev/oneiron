//! Moved from `crates/oneiron/src/autoreason_campaign/archive/axes.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::autoreason_campaign::archive::ArchiveCell;
use crate::autoreason_campaign::archive::ArchiveQualityMetric;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// One categorical dimension proposed from this task's goal and samples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveAxis {
    pub name: String,
    pub bins: Vec<String>,
}
