//! Moved from `crates/oneiron/src/merge_queue/types.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::contract_oracle::graph::AffectedTests;
pub use oneiron_store::merge_queue::types::*;
use oneiron_store::repo_fork::RepoForkHash;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckPhase {
    Fast,
    Slow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeBatch {
    pub schema_version: u8,
    pub id: String,
    pub expected_head: String,
    pub base_green: String,
    pub baseline_id: String,
    pub proposals: Vec<MergeProposal>,
    pub state: BatchState,
    pub paths: Vec<SpeculativePath>,
    pub pre_snapshot: Option<RepoForkHash>,
    pub landed_head: Option<String>,
    pub slow_verdict: Option<String>,
    pub quarantine: Option<Quarantine>,
    pub selected_tests: AffectedTests,
    /// A leased run's accepted entry and the declarations it waits behind
    /// (FIX 6867); `None` for an owner or trusted batch, which waits on none.
    pub run_order: Option<super::RepoQueueOrder>,
    /// What was decided for it (FIX 6868, G2 PR2): the automatic driver's
    /// record, and the survivor links and diagnosis trace an owner's call
    /// also writes (FIX 4362). `None` until one is written.
    pub drive: Option<super::QueueBatchDrive>,
    /// The batch of the same enqueue this one stages on once that one has
    /// landed: an enqueue of more than one batch's proposals forms
    /// consecutive batches ([MERGE-QUEUE-ENQUEUE-SPLITS-LARGE-BATCH]).
    /// `None` for an enqueue's first batch; never written then, so every
    /// row without it encodes as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follows: Option<String>,
    /// The batch of the same enqueue that stages on this one once it has
    /// landed; `None` for an enqueue's last batch, never written then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub followed_by: Option<String>,
}
