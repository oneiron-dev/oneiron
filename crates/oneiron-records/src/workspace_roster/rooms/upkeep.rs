//! Moved from `crates/oneiron/src/workspace_roster/rooms/upkeep.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::rooms::*;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One room as its upkeep reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomUpkeepInput {
    pub room: EntityId,
    /// Every turn the reader reads, oldest first: what a summary cites.
    pub source_refs: Vec<EntityId>,
    /// When the newest of them was spoken; `None` for a room with none.
    pub last_activity: Option<u64>,
    /// Each thread the reader reads, by its root turn.
    pub threads: Vec<RoomUpkeepThread>,
}

/// One thread's liveness facts, as the room's liveness fold reads them before
/// any policy ranks, caps or lanes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomUpkeepThread {
    /// The thread's root turn.
    pub handle: EntityId,
    /// The trunk turn it hangs under.
    pub trunk: EntityId,
    /// Its root's time, or its newest reply's, of those the reader reads; 0
    /// when it reads none of them (FIX 5545).
    pub last_message_at: u64,
    /// The open TASKs bound to it that the reader reads.
    pub open_tasks: Vec<EntityId>,
    /// What those TASKs wait on, where the one waited on is a live PERSON
    /// the reader reads: a follow-up's next notice, an ask's due notice and
    /// the TASK's cutoff (OF-417).
    pub waits: Vec<RoomThreadWait>,
}

impl RoomUpkeepThread {
    /// Whether a person's own schedule still holds the thread at `now`
    /// (Unix seconds): some wait's next notice or cutoff is still ahead. A
    /// wait with neither time holds nothing.
    #[must_use]
    pub fn waiting_for_person(&self, now: u64) -> bool {
        self.waits.iter().any(|wait| {
            wait.next_nudge
                .into_iter()
                .chain(wait.until)
                .any(|at| now < at)
        })
    }
}
