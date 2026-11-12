//! Moved from `crates/oneiron/src/note/proposal_doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::note::documents::invalid;
use crate::note::proposals::NoteVerdict;
use crate::note::reads::NoteAccessRequest;
use oneiron_authority::claim_history_handoff::ScopedReadResult;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteForkReadRequest {
    pub note_ref: String,
    pub fork_ref: String,
    #[serde(default)]
    pub reason: Option<String>,
}

/// A fork identity is not an entity ref or an authority credential.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteProposalForkRef {
    pub note_ref: String,
    pub fork_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteProposalOpenRequest {
    pub forks: Vec<NoteProposalForkRef>,
    pub explainer: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteProposalRequest {
    pub proposal_ref: String,
    #[serde(default)]
    pub reason: Option<String>,
}
