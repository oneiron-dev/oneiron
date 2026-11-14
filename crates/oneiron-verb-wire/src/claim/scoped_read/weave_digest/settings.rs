//! Moved from `crates/oneiron/src/claim/scoped_read/weave_digest/settings.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Where a Coach change to the owner's digest settings stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WeaveDigestSettingChangeStatus {
    /// Proposed: it waits for the owner's answer, and silence changes nothing.
    Pending,
    /// The Coach applied it under a Grant that names digest settings.
    Applied,
    /// The owner accepted the proposal, as his own act.
    Accepted,
    /// The owner declined the proposal.
    Declined,
    /// The owner's own edit came first; nothing applied.
    Superseded,
    /// The owner's one tap restored the settings before it.
    Undone,
}

/// The owner's answer to one proposed change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveDigestSettingAnswer {
    /// The change, as 32 hex.
    pub change_ref: String,
    /// `true` accepts it as the owner's own act; `false` declines it.
    pub accept: bool,
}

/// The owner's one-tap undo of an applied or accepted change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveDigestSettingUndo {
    /// The change, as 32 hex.
    pub change_ref: String,
}
