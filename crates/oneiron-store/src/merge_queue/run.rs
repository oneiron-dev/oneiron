//! A leased run's entries in the merge queue (FIX 6867, G1 PR2b): the
//! queue's one batch formation takes the run's exact stored proposals under
//! the admission its final writer judges, and keeps beside the batch the
//! declarations of other TASKs that overlapped it then. Symbol leases order
//! work and veto none: an entry whose predecessors still hold waits Queued
//! and is never refused. A predecessor stops holding it once its
//! declaration is released, expires or is replaced, or once a run batch
//! accepted under that declaration reaches the queue's head; one accepted
//! after this entry never holds it. Acceptance hands the exact candidate to
//! the queue: staging and landing never ask whether the worker that
//! submitted it still runs, and every existing check, review and recovery
//! still applies.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::contract_oracle::invalid;
use crate::merge_queue::batch_index::BatchIndexKind;
use crate::merge_queue::types::BatchState;
use crate::merge_queue::types::MergeProposal;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

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
