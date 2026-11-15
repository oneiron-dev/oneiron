//! Moved from `crates/oneiron/src/compaction/conversation.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::compaction::check_material::CompactionCheckMaterialRef;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One retained turn of a conversation's window, by revision: the turn, who
/// it speaks for, the MESSAGEs its reader read in order, and the hex of its
/// projection's fingerprint, which pins its words, rows and authors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationTurnSpan {
    pub turn: EntityId,
    /// `user` or `companion`.
    pub role: String,
    pub messages: Vec<EntityId>,
    pub fingerprint: String,
}

impl ConversationTurnSpan {
    /// The fingerprint its landing pinned, as bytes: 64 lowercase hex
    /// digits, as the landing wrote it.
    pub fn pinned_fingerprint(&self) -> Option<[u8; 32]> {
        oneiron_hex::decode(&self.fingerprint)
    }
}

/// The retained evidence a conversation's self-written summary was cut
/// from: the SESSION its turns were witnessed into, the conversation and the
/// branch it read (a DAG conversation's HEAD), and the window's turns in
/// order. The chat generation that sealed it is the paid calls' job, never
/// evidence. A landed summary's evidence also names its check material,
/// the gate input of its accepted try (FIX 5040).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationEvidence {
    pub session: EntityId,
    pub conversation: EntityId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<EntityId>,
    pub turns: Vec<ConversationTurnSpan>,
    /// The check material's ref: `None` until its pass is accepted. Its
    /// landing sets it, so each landed receipt names it.
    pub check_material: Option<CompactionCheckMaterialRef>,
}
