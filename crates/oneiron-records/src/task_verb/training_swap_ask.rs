//! Moved from `crates/oneiron/src/task_verb/training_swap_ask.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Where one owner's question about one result stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapAskState {
    /// Reserved or asked, with no answer yet.
    Open,
    /// This owner's `approve_swap` bound the checkpoint.
    Swapped,
    /// This owner's `keep` kept the current model.
    Kept,
    /// The owner's swap word reached a setup refusal; nothing bound.
    NeedsSetup { reason: String },
    /// Another answer, the owner's direct swap or a newer result closed it.
    Closed,
}
