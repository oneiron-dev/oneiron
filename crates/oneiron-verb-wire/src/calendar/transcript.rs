//! Moved from `crates/oneiron/src/calendar/transcript.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::calendar::transcript::door::TranscriptFileDropInput;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TranscriptIngestOutcome {
    Session {
        session_ref: oneiron_contracts::entity_id::EntityId,
        turn_refs: Vec<oneiron_contracts::entity_id::EntityId>,
        /// IDs carried by the same in-transaction SessionEnd wake plan.
        wake_turn_refs: Vec<oneiron_contracts::entity_id::EntityId>,
        extraction_enqueued: bool,
    },
    RetryOpenSession {
        open_session_ref: oneiron_contracts::entity_id::EntityId,
    },
    /// The original session-open hook has asked; no SESSION was minted.
    HookPending {
        session_ref: oneiron_contracts::entity_id::EntityId,
        ask: oneiron_contracts::entity_id::EntityId,
    },
    /// The same upload is already retained under its native lease or due instant.
    Queued { attempt_ref: String },
    /// A nonempty file with no usable turns remains explicit caller-owned NOTE input.
    NoteFallback {
        note_ref: oneiron_contracts::entity_id::EntityId,
    },
}
pub mod door;
