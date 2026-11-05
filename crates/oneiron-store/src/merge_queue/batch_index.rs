//! Keyed reads of one queue's batches (FIX 7067): a run's enqueue, stage
//! and observe read the batches that name a proposal, a work or a
//! declaration through one index row each, never every batch the queue
//! ever kept. The rows are written in the writer that saves the batch; a
//! reader reads each named batch whole and judges what it holds.
//!
//! These writers add index rows and retain them with their batch.
//! Survivor requeues create a new batch rather than removing the old one.
//! Readers re-judge the stored batch; a missing batch is index corruption.
//! A writer that later removes a batch or changes its indexed membership
//! must remove the old index rows in that same transaction.
use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// What an index row files a batch under.
#[derive(Debug, Clone, Copy)]
pub enum BatchIndexKind {
    /// A proposal the batch holds, by its id.
    Proposal,
    /// A run entry's work, by hex id.
    Work,
    /// A run entry's own declaration, by hex id.
    Declaration,
}

impl BatchIndexKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Proposal => "proposal",
            Self::Work => "work",
            Self::Declaration => "declaration",
        }
    }
}

pub fn index_prefix(repo_hex: &str, kind: BatchIndexKind, id: &str) -> String {
    format!("{repo_hex}:{}:{id}:", kind.tag())
}

