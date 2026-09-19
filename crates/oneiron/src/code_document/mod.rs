//! Base-mode live code files: actor-stamped Loro operations and verified tested frontiers.
//!
//! This is the approved-write primitive below the gate. It changes documents,
//! never repository refs. Each session edits its own observed state; persistence
//! merges those operations, not a replacement file body.

mod codec;
mod session;
mod storage;
mod types;

pub use session::CodeDocumentSession;
pub(crate) use storage::{CodeFileIngress, verify_frontier_in_txn};
pub use types::{
    CodeDocumentFrontier, CodeEditReceipt, CodeFileEdit, CodeSpanAnchor, CodeSpanResolution,
};

#[cfg(test)]
mod tests;
