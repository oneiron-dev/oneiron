//! Solved browser capture receipts and claim predicates.
use crate::entity_id::EntityId;

/// The predicate of a solved run's evidence claim (CUA E8a).
pub const SOLVED_RUN_PREDICATE: &str = "browser.solved_run";

/// The predicate of a filed program's anchor claim (FIX 10513): the
/// scoped filing evidence through which a reader is granted the
/// program's coverage of its group.
pub const WORKFLOW_FILING_PREDICATE: &str = "browser.workflow.filing";

/// What a capture came to (CUA E8a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolvedCaptureReceipt {
    /// The evidence claim `id` stands in `group`; `fresh` is false when the
    /// same capture had landed before, which moves no generation.
    Captured {
        id: EntityId,
        group: [u8; 32],
        fresh: bool,
    },
    /// Nothing was captured, for this cause.
    Unavailable(SolvedCaptureGap),
}

/// Why a capture kept nothing (CUA E8a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolvedCaptureGap {
    /// The caller's call is off the record: its session's writer keeps its
    /// lifecycle, and the base vault keeps no evidence of it.
    OffRecord,
}
