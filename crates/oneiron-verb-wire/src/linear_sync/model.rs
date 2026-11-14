//! Moved from `crates/oneiron/src/linear_sync/model.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// The tracker-side identity of a mirrored issue.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct LinearIssueRef {
    /// Opaque tracker id; the join key of the link row.
    pub issue_id: String,
    /// Owning team id.
    pub team_id: String,
    /// Human-facing identifier (e.g. `ENG-123`).
    pub identifier: String,
}

/// One field both sides edited since the common base.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct LinearFieldConflict {
    /// The bidirectional field name.
    pub field: String,
    /// Engine-side value that was NOT overwritten.
    pub task_value: Option<String>,
    /// Tracker-side value that was NOT applied.
    pub issue_value: Option<String>,
}
