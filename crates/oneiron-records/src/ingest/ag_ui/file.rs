//! Moved from `crates/oneiron/src/ingest/ag_ui/file.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::ingest::ag_ui::observations::AgUiAppObservation;
use crate::ingest::ag_ui::observations::AgUiRepairLink;
use oneiron_contracts::claim::ScopedReadReceipt;
pub use oneiron_verb_wire::ingest::ag_ui::file::AgUiFileImport;
pub use oneiron_verb_wire::ingest::ag_ui::file::AgUiFileReadInput;
use oneiron_verb_wire::ingest::ag_ui::observations::AgUiCustomMapping;
use rmpv::Value as Msgpack;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgUiFileReceipt {
    pub claim_ref: String,
    pub source_hash: String,
    pub event_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgUiFileView {
    pub claim_ref: String,
    pub source_hash: String,
    pub capture_actor_ref: String,
    pub project_ref: String,
    pub app_id: String,
    pub custom_mappings: Vec<AgUiCustomMapping>,
    pub jsonl: String,
    pub event_count: usize,
    pub observations: Vec<AgUiAppObservation>,
    pub repair_links: Vec<AgUiRepairLink>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgUiFileRead {
    pub source: Option<AgUiFileView>,
    pub receipt: ScopedReadReceipt,
}
