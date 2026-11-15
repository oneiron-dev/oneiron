//! Moved from `crates/oneiron/src/task_verb/highway_block.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// What a blocked TASK waits on its owner for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockPurpose {
    /// A result whose done-means is the owner's call, under the brief
    /// revision it was judged against.
    Done {
        result_ref: EntityId,
        brief_rev: u32,
    },
    /// Work its taker cannot go on with without the owner.
    Blocked,
}
