//! Base-mode live code files: actor-stamped Loro operations and verified tested frontiers.
//!
//! This is the approved-write primitive below the gate. It changes documents,
//! never repository refs. Each session edits its own observed state; persistence
//! merges those operations, not a replacement file body.

mod blame;
mod codec;
mod session;
mod storage;
mod types;
mod verbs;

pub use blame::CodeRangePair;
pub use session::CodeDocumentSession;
pub(crate) use storage::{CodeFileIngress, verify_frontier_in_txn};
pub use types::{
    CodeDocumentFrontier, CodeEditReceipt, CodeFileEdit, CodeOpAttribution, CodeOpProvenance,
    CodeRangeChange, CodeSpanAnchor, CodeSpanBlame, CodeSpanResolution,
};
pub use verbs::{
    CodeBlameView, CodeChangeView, CodeDiffRequest, CodeDiffView, CodeOperationView, CodeSpanView,
    CodeStateRequest, CodeStateView, CodeUnitBlameView, CodeUnitVersionView,
};

#[cfg(test)]
mod tests;
