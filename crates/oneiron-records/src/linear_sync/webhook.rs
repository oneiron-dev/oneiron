//! Moved from `crates/oneiron/src/linear_sync/webhook.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::linear_sync::mirror_event::LinearMirrorRecord;
use oneiron_verb_wire::linear_sync::model::LinearFieldConflict;
use oneiron_verb_wire::linear_sync::model::LinearIssueRef;
pub use oneiron_verb_wire::linear_sync::webhook::LinearExternalActor;
use serde::Deserialize;
use serde::Serialize;

/// What one delivery did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinearWebhookStatus {
    /// Issue-owned fields applied to the linked TASK.
    Applied,
    /// A field both sides moved was left untouched and pinned.
    Conflict,
    /// Nothing to apply: unchanged, an echo or an already-seen event.
    Noop,
    /// Not an update of a linked issue.
    Ignored,
}

impl LinearWebhookStatus {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Conflict => "conflict",
            Self::Noop => "noop",
            Self::Ignored => "ignored",
        }
    }
}

/// The receipt one delivery answers, and a replay of it answers again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinearWebhookReceipt {
    /// The delivery.
    pub delivery_id: String,
    /// What it did.
    pub status: LinearWebhookStatus,
    /// The linked TASK it changed or found unchanged.
    pub task_ref: Option<String>,
    /// The issue it named.
    pub issue: Option<LinearIssueRef>,
    /// The fields both sides moved.
    pub conflicts: Vec<LinearFieldConflict>,
    /// The mirror operation it ran, for a linked issue.
    pub mirror: Option<LinearMirrorRecord>,
    /// The event row it is recorded under, in hex.
    pub event_ref: String,
    /// Whether this answers an already-recorded delivery.
    pub replayed: bool,
    /// The vault clock when the delivery was recorded.
    pub recorded_at: u64,
}
