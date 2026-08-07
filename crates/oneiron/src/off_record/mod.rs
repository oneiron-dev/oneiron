//! Off-record session lifecycle and promotion surfaces.

mod lifecycle;
mod promote;

pub use lifecycle::{
    ExecutorUtterance, OffRecordBackendClass, OffRecordCloseOutcome, OffRecordMode,
    OffRecordSession, OffRecordSessionRecord, OffRecordSessionVault,
};
pub use promote::{OffRecordPromoteReceipt, PromoteOutcome};

pub(crate) use lifecycle::{
    OffRecordSessionRegistry, guard_off_record_entity_put, off_record_fence_active,
    off_record_fences_present,
};
/// `FloorWrites` lives in `promote.rs` from ONE-1728 on; this re-export keeps
/// the `crate::off_record::FloorWrites` path stable, so the `gate.rs` and
/// `deletion.rs` call sites are diff-quiet across the move.
pub(crate) use promote::FloorWrites;
/// The promote-replay capability `batch.rs` matches on. Only `promote.rs` can
/// MINT one (private field, private constructor); this path just lets the two
/// membership doors ask a grant they were handed what it exempts.
pub(crate) use promote::PromoteReplayGrant;

/// ONE-1728 (K2) / ONE-1729: downstream cites resolve through `off_record`.
/// `OverlaySnapshot` is promote's input; `SessionWriteRoute` is captured by
/// ONE-1729's executor run entry.
#[allow(
    unused_imports,
    reason = "ONE-1729 is the first lib-target consumer of SessionWriteRoute through this path"
)]
pub(crate) use crate::session_overlay::{OverlaySnapshot, SessionWriteRoute};
