//! Ephemeral in-memory write overlay for one live session (ARCH-0052, D1).
//!
//! The children own the lifecycle state machine, txn segments, row staging,
//! and promoted-closure retirement; this module only declares them and
//! re-exports the names the rest of `session_overlay` uses.

use std::cell::RefCell;

use self::segment::TxnSegment;

mod lifecycle;
mod retire;
mod rows;
mod segment;

thread_local! {
    pub(super) static ACTIVE_SEGMENT: RefCell<Option<TxnSegment>> = const { RefCell::new(None) };
}

pub(super) use self::lifecycle::Lease;
pub(crate) use self::lifecycle::SessionOverlay;
pub(crate) use self::segment::TxnSegmentGuard;

#[cfg(test)]
pub(super) use self::lifecycle::OverlayLifecycleState;
