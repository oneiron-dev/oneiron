//! Moved from `crates/oneiron/src/llm/defaults/submit.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_model::llm::PurposeDefaultTable;
use serde::Deserialize;
use serde::Serialize;

/// Where a kept proposal stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurposeDefaultProposalStatus {
    /// No holder has answered it; it changes nothing.
    Pending,
    /// A holder approved it, and its table became the active defaults.
    Approved { holder: String, at: u64 },
    /// A holder declined it; the active defaults stayed as they were.
    Declined { holder: String, at: u64 },
}

/// A replacement table kept for a holder's say. It changes nothing unless a
/// holder approves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurposeDefaultProposal {
    /// The proposal's id, as hex.
    pub proposal_id: String,
    /// Who submitted it, as hex.
    pub author: String,
    /// The validated table it proposes.
    pub table: PurposeDefaultTable,
    /// Vault clock seconds.
    pub at: u64,
    /// Whether a holder has answered it, and how.
    pub status: PurposeDefaultProposalStatus,
}
