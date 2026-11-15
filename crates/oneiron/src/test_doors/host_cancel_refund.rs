//! Door for `tests/booking_deposit_settlement.rs` (BK-DEPOSITS, Astra money
//! review F3): a stop between the host cancel's status commit and its deposit
//! refund commit. Calendar ingest asks [`take_stop_before_refund`] right
//! before the refund step; armed, the poll ends there with an error, as a
//! process stopped between the two commits would, and the next poll of the
//! same feed must repair the refund.

use std::cell::Cell;

thread_local! {
    static STOP_BEFORE_REFUND: Cell<bool> = const { Cell::new(false) };
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
