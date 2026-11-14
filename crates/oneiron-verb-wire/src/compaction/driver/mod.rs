//! Moved from `crates/oneiron/src/compaction/driver/mod.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;

/// One message-log row the host hands the backend.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct CompactionWindowMessage {
    /// The MESSAGE whose words `content` renders: a `DerivedFrom` target
    /// when the vault stores it.
    pub message_id: EntityId,
    /// The covered TURN entity — a `DerivedFrom` target and the H-S3 probe
    /// subject.
    pub turn_id: EntityId,
    /// Rendered MESSAGE content: the material the backend summarizes.
    pub content: String,
    /// The turn NUMBER this row belongs to, in its lineage's own ordering:
    /// the session's, or a chat window's conversation within the session.
    pub turn: u64,
    pub tokens: u64,
}
