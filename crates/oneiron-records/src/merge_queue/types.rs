//! Moved from `crates/oneiron/src/merge_queue/types.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::contract_oracle::graph::AffectedTests;
pub use oneiron_store::merge_queue::types::*;
use oneiron_store::repo_fork::RepoForkHash;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

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
}
