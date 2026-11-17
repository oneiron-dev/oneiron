//! Moved from `crates/oneiron/src/edit_settle/pending/view.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What kind of proposal is waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PendingProposalKind {
    /// Paid decisions are retained; no proposed workbook bytes exist yet.
    NeedsStaging,
    Edit,
    Output,
}
