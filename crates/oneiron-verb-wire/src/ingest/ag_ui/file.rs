//! Moved from `crates/oneiron/src/ingest/ag_ui/file.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::ingest::ag_ui::observations::AgUiCustomMapping;
use oneiron_authority::claim_history_handoff::ClaimReadStatus;
use oneiron_authority::claim_history_handoff::ScopedReadReceipt;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::claim::ClaimSource;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryResult;
use oneiron_contracts::temporal::TimeRange;
use oneiron_store::write_envelope::WriteActor;
use oneiron_store::write_envelope::claim_body::ClaimSubject;
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
