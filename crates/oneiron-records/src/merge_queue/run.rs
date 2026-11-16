//! Moved from `crates/oneiron/src/merge_queue/run.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// A run's accepted queue entry: whose it is, the exact proposals accepted,
/// the declaration it was accepted under and the predecessors it waits
/// behind, as its batch writer read them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoQueueOrder {
    /// The run's work the proposals were made in.
    pub work: EntityId,
    /// The TASK the run realized.
    pub task: EntityId,
    /// The actor that submitted them.
    pub holder: EntityId,
    /// The exact stored proposals accepted, in batch order.
    pub proposals: Vec<EntityId>,
    /// The run's own declaration the entry was accepted under, if it had one.
    pub declaration: Option<EntityId>,
    /// The symbols the entry touches (CALL "FIX 6867 run-only overlap
    /// granularity").
    pub symbols: BTreeSet<String>,
    /// The live declarations of other TASKs that overlapped it when it was
    /// accepted.
    pub predecessors: Vec<RepoQueuePredecessor>,
    /// The queue sequence that accepted it: an entry accepted later never
    /// holds this one.
    pub sequence: u64,
}

/// One declaration a run's entry waits behind: the TASK and the id of the
/// declaration that held it at acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoQueuePredecessor {
    pub task: EntityId,
    pub declaration: EntityId,
}
