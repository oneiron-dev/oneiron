//! Moved from `crates/oneiron/src/note/reads.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::note::documents::invalid;
use oneiron_authority::claim_history_handoff::ClaimReadStatus;
use oneiron_authority::claim_history_handoff::PointRead;
use oneiron_authority::claim_history_handoff::ReadRow;
use oneiron_authority::claim_history_handoff::ScopedReadResult;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::scan_checks::PendingScanChecks;
use serde::Deserialize;
use serde::Serialize;

/// One explicit NOTE read. Private notes require the caller's stated reason.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteAccessRequest {
    pub note_ref: String,
    #[serde(default)]
    pub reason: Option<String>,
}

/// A half-open span in the selected text, measured in Unicode scalar indices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteReadSpan {
    pub start: usize,
    pub end: usize,
}

/// Reads the independently published NOTE frontier, not the live editor head.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteIndexedReadRequest {
    pub note_ref: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub spans: Vec<NoteReadSpan>,
}

/// Where this read obtained the body. A local read never silently fetches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NoteReadSource {
    Local,
    Home,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteEditorCloseRequest {
    pub binding: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NoteEditorClosed {
    pub closed: bool,
}
