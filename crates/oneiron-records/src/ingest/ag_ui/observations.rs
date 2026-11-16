//! Moved from `crates/oneiron/src/ingest/ag_ui/observations.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::ingest::ag_ui::observations::AgUiCustomMapping;
pub use oneiron_verb_wire::ingest::ag_ui::observations::AgUiObservationKind;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgUiAppObservation {
    pub ordinal: usize,
    pub name: String,
    pub kind: AgUiObservationKind,
    pub id: Option<String>,
    pub thread_id: Option<String>,
    pub run_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub failure_id: Option<String>,
    pub repair_id: Option<String>,
    pub outcome: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgUiRepairLinkStatus {
    Linked,
    MissingLink,
    AmbiguousLink,
    NamespaceMismatch,
    MissingOutcome,
}

/// Ordinals address occurrences in this source only. Repeated IDs stay ambiguous.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgUiRepairLink {
    pub outcome_ordinal: usize,
    pub repair_ordinal: Option<usize>,
    pub failure_ordinal: Option<usize>,
    pub status: AgUiRepairLinkStatus,
}
