//! Moved from `crates/oneiron/src/ingest/ag_ui/observations.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgUiObservationKind {
    Action,
    Failure,
    Repair,
    Outcome,
}

/// JSON pointers address the whole CUSTOM event, not an assumed payload schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgUiCustomMapping {
    pub name: String,
    pub kind: AgUiObservationKind,
    pub id: Option<String>,
    pub thread_id: Option<String>,
    pub run_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub failure_id: Option<String>,
    pub repair_id: Option<String>,
    pub outcome: Option<String>,
}
