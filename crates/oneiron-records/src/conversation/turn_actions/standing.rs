//! Moved from `crates/oneiron/src/conversation/turn_actions/standing.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::memory::MemoryError;

/// The slip a turn action was asked with no longer stands for its requester.
pub fn standing_lost() -> MemoryError {
    MemoryError::new(
        oneiron_contracts::memory::MEMORY_CODE_FORBIDDEN,
        "the slip this turn action was asked with no longer stands for its requester",
        &["Ask for the action again with a live credential."],
    )
}
