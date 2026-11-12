//! Moved from `crates/oneiron/src/scope_summary/status.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Atomic durable landing result, retained across worker replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeSummaryResult {
    pub summary: String,
    pub claim: Option<String>,
    pub record: Option<String>,
}

/// The declaration's public state; parked and failed attempts name their reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScopeSummaryStatus {
    pub attempt: String,
    pub requester: String,
    pub current_attempt: String,
    pub state: String,
    pub result: Option<ScopeSummaryResult>,
    pub failure: Option<String>,
    pub retry_at: Option<u64>,
    pub updated_at: u64,
    /// Why an Arc declaration's row is still owed, typed (FIX 8060, 8291);
    /// `None` for every other summary, and for an Arc that owes nothing.
    pub arc_pending: Option<ArcPendingStatus>,
    /// Why the landed summary no longer reads as it was composed while it
    /// still serves (FIX 6321); `None` while it reads as composed.
    pub stale: Option<SummaryStale>,
}

/// Why an Arc is still owed (FIX 8060, 8291), as its row records it: the
/// cause's code is its `cause` tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "cause", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArcPendingStatus {
    /// A closed sitting below the Arc has no summary yet.
    ArcLowerPending { session: String },
    /// A TURN the Arc must read did not read for the Dreamer, by its id.
    ArcSourceUnavailable { handle: String },
    /// The Arc composes in parts: its work generation, the parts done and
    /// the parts still owed. Its queued attempt goes on at its next wake.
    ArcCompositionPending {
        work_id: String,
        parts_done: u64,
        parts_owed: u64,
    },
    /// The model's window holds the call's frame and not one character of
    /// a source beside it.
    ArcWindowTooSmall { window: u64, frame_tokens: u64 },
}

/// Why a landed summary is stale while it still serves (FIX 6321): its
/// re-derivation is queued by the change that made it so.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub enum SummaryStale {
    /// NOTEs it covers were edited since it was composed, by id.
    NoteSourceEdited { notes: Vec<String> },
}
