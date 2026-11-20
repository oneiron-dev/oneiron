//! Moved from `crates/oneiron/src/share_travel/agent_pack_export.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::share_travel::agent_pack_export::AgentPackExportRequest;
use serde::Deserialize;
use serde::Serialize;

/// One file of the folder, its bytes base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPackExportFile {
    pub path: String,
    pub content_base64: String,
}
