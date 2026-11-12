//! Moved from `crates/oneiron/src/ingest/ag_ui/file.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::ingest::ag_ui::observations::AgUiCustomMapping;
use rmpv::Value as Msgpack;
use serde::Deserialize;
use serde::Serialize;

/// Registration is snapshotted with this file. It grants no app or training authority.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgUiFileImport {
    pub claim_ref: Option<String>,
    pub project_ref: String,
    pub app_id: String,
    pub custom_mappings: Vec<AgUiCustomMapping>,
    pub jsonl: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgUiFileReadInput {
    pub claim_ref: String,
    pub source_hash: String,
}
