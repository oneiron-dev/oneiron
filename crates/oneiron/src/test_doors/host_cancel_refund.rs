//! Door for `tests/booking_deposit_settlement.rs` (BK-DEPOSITS; Astra money
//! review F3, Sol money review M2): a host cancel is two commits, its
//! deposit refund and its calendar status. Calendar ingest asks
//! [`take_stop_before_refund`] right before the refund step: armed, the poll
//! ends there with an error, as a process stopped there would, and the next
//! poll of the same feed must repair the refund. It calls
//! [`run_between_commits`] between the two commits: an armed action (a
//! visitor's cancel) runs there once.

use std::cell::{Cell, RefCell};

/// An action a test runs between a host cancel's two commits.
pub type BetweenCommitsAction = Box<dyn FnOnce()>;

thread_local! {
    static STOP_BEFORE_REFUND: Cell<bool> = const { Cell::new(false) };
    static BETWEEN_COMMITS: RefCell<Option<BetweenCommitsAction>> = const { RefCell::new(None) };
}

/// Arms one stop: the next host-cancel refund step on this thread ends its
/// poll before the refund commits.
pub fn stop_before_next_host_cancel_refund() {
    STOP_BEFORE_REFUND.with(|stop| stop.set(true));
}

/// Whether a stop is armed on this thread; disarms it.
pub(crate) fn take_stop_before_refund() -> bool {
    STOP_BEFORE_REFUND.with(Cell::take)
}

/// Arms `action` to run once, on this thread, between the next host
/// cancel's two commits.
pub fn between_next_host_cancel_commits(action: BetweenCommitsAction) {
    BETWEEN_COMMITS.with(|slot| *slot.borrow_mut() = Some(action));
}

/// Runs and disarms the armed action, if any.
pub(crate) fn run_between_commits() {
    if let Some(action) = BETWEEN_COMMITS.with(|slot| slot.borrow_mut().take()) {
        action();
    }
}
