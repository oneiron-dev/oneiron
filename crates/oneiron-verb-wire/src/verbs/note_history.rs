//! Moved from `crates/oneiron/src/verbs/note_history.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `vault.notes.history_purge`'s input: the NOTE whose history the owner
/// erases.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteHistoryPurgeRequest {
    pub note_ref: String,
    /// An asker's approved check-in for this erase, 32 hex
    /// (`text_history_erase_effect_digest` over the note, with no frontier):
    /// the Owner applies it on their own proof, and the outcome names its
    /// asker.
    #[serde(default)]
    pub check_in_ref: Option<String>,
}

/// The shared-vault act returned by an owner's explicit history purge.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteHistoryPurgeExecuteRequest {
    pub act_id: String,
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
/// shared-vault veto window closes without an objection. Each names the
/// check-in decision the erase runs on (2k2): the Owner on their own proof,
/// and the approved check-in of another asker it applied, with its
/// requester; a waiting act records it too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum NoteHistoryPurgeOutcome {
    Erased {
        receipt: NoteHistoryPurgeReceipt,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        check_in: Option<crate::check_in::CheckInDecision>,
    },
    Waiting {
        note_ref: String,
        act_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        check_in: Option<crate::check_in::CheckInDecision>,
    },
}
