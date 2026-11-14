//! Moved from `crates/oneiron/src/llm/decision/asks/grant_draft.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The standing grant an owner's reason drafted from an ask about one consent effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AskGrantDraft {
    /// Drafted from the reason, by the bound's digest: it grants nothing until the owner
    /// confirms it.
    Proposed { grant_ref: String },
    /// The owner confirmed it: the standing grant is live, under the rule row the reason
    /// landed as.
    Confirmed {
        grant_ref: String,
        /// The confirm's consent receipt, by decision id hex.
        receipt: String,
        /// The reason's rule row, by decision id hex: the one-tap undo names it.
        rule: String,
    },
}
