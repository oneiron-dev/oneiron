//! Moved from `crates/oneiron/src/sync/chunks/read.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;

/// What a reader asks of a lift-marked object's read, in its request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ChunkRead {
    /// A granted read's first request: why the agent needs the real bytes.
    Ask {
        /// The agent's why, one line.
        why: String,
    },
    /// A later request of the read the host granted: the reference its
    /// reply named.
    Held {
        /// The read's reference.
        read: EntityId,
    },
}

/// The lift sweep's mark on an object as it travels with its real bytes: the
/// detector's reason and when it was made, never a value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChunkMark {
    /// The detector's reason for the first hit.
    pub reason: String,
    /// When the mark was made.
    pub marked_at: u64,
}
