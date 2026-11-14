//! Moved from `crates/oneiron/src/verbs/note_history.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteHistoryPurgeRequest {
    pub note_ref: String,
    /// The confirm `vault.owner_confirm.preview` returned for this call.
    /// It is needed only where the purge erases at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<String>,
}

/// The shared-vault act returned by an owner's explicit history purge.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteHistoryPurgeExecuteRequest {
    pub act_id: String,
    /// The confirm `vault.owner_confirm.preview` returned for this call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<String>,
}

/// The engine's durable receipt, with encoded causal frontiers rather than
/// a scalar floor. `applied` identifies the boundary the engine retained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteHistoryPurgeReceipt {
    pub receipt: String,
    pub entity: String,
    pub document: String,
    /// No actor identity remains after that actor is erased.
    pub actor: Option<String>,
    pub requested: Vec<u8>,
    pub applied: Vec<u8>,
    pub at: u64,
    /// The engine's BLAKE3 hash, not a citation quote's SHA-256.
    pub live_text_hash: [u8; 32],
}

/// A waiting act has erased nothing. Its starter executes it after the
/// shared-vault veto window closes without an objection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum NoteHistoryPurgeOutcome {
    Erased { receipt: NoteHistoryPurgeReceipt },
    Waiting { note_ref: String, act_id: String },
}
