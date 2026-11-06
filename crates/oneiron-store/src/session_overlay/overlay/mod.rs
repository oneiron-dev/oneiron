//! Ephemeral in-memory write overlay for one live session (ARCH-0052, D1).
//!
//! The children own the lifecycle state machine, txn segments, row staging,
//! and promoted-closure retirement; this module only declares them and
//! re-exports the names the rest of `session_overlay` uses.

use std::cell::RefCell;

use self::segment::TxnSegment;

pub mod held;
pub mod lifecycle;
mod publication;
pub mod repo_projection;
pub mod retained;
pub mod retire;
pub mod retire_selected;
pub mod rows;
pub mod segment;

thread_local! {
    pub(super) static ACTIVE_SEGMENT: RefCell<Option<TxnSegment>> = const { RefCell::new(None) };
}

/// Whether this thread holds an installed txn segment, which keeps its overlay
/// segment permit until the owner commits it after the base commit. The group
/// commit closes a group after such a write, so no later member of the same
/// group waits on that permit.
pub fn txn_segment_installed() -> bool {
    ACTIVE_SEGMENT.with(|slot| slot.borrow().is_some())
}

pub(super) use self::held::PlanCharge;
pub(super) use self::lifecycle::Lease;
pub use self::lifecycle::SessionOverlay;
pub use self::segment::TxnSegmentGuard;

#[cfg(test)]
pub(super) use self::lifecycle::OverlayLifecycleState;
