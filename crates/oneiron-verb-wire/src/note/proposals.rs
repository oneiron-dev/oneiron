//! Moved from `crates/oneiron/src/note/proposals.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::note::documents::invalid;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::side_table::key::HexId;
use oneiron_store::write_envelope::WriteActor;
use serde::Deserialize;
use serde::Serialize;

/// What an actor's erase does with a fork it opened that no one decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingNoteForkErase {
    /// The fork goes, with its snapshot and its place in a bundle.
    Delete,
    /// The fork stays and names no one, as a decided fork does.
    Keep,
}

/// A fork no one decided is still review work a reviewer could land, so an
/// erase of the actor who opened it deletes it (FIX 3520).
pub const ACTOR_ERASE_PENDING_NOTE_FORK: PendingNoteForkErase = PendingNoteForkErase::Delete;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum NoteVerdict {
    Merge,
    Switch,
    Reject,
}
