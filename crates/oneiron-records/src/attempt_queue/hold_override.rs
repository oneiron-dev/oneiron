//! Moved from `crates/oneiron/src/attempt_queue/hold_override.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The hold an override released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverriddenHold {
    /// OF-368: the comment thread and the drift of it the release covers.
    Annotation {
        artifact_id: EntityId,
        thread_id: EntityId,
        /// The artifact version the thread had drifted at; `None` when the
        /// thread read as not drifted (a store-only handle reads no thread).
        drifted_at_version: Option<u64>,
    },
}
