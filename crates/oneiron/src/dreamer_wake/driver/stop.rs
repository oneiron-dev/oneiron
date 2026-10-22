//! Where a wake pass stops between attempts: at the attempt boundary
//! (a cancellation, the hard deadline, or the graceful finalize window), and
//! after an attempt settles (a cancellation, or backlog left for later).

use super::*;

/// The stop the attempt boundary calls, if any; the caller records it and
/// ends the pass.
pub(super) fn boundary_stop(
    driver: &mut DreamerWakeDriver<'_>,
    cancel: &WakeCancellation,
) -> Option<WakePassStop> {
    if cancel.is_cancelled() {
        // Cooperative-preemption boundary (H-S5/R2): between attempts
        // the driver holds no admitted attempt and no in-flight gated
        // write, so stopping here can never truncate a gated write
        // or an off-record close.
        return Some(WakePassStop::Cancelled);
    }
    driver.maybe_fire_wrap_notice();
    if driver.deadline.expired() {
        // Hard cut at the attempt boundary: any admitted LLM call has
        // settled before the sequential driver reaches this check.
        return Some(WakePassStop::DeadlineHardCut);
    }
    if driver.enter_finalize_if_due() {
        // Graceful wrap: admit NO new attempts and NO new step leases;
        // the pass ends under deadline/budget pressure.
        return Some(if driver.counter_exhausted() {
            WakePassStop::BudgetExhausted
        } else {
            WakePassStop::DeadlineHardCut
        });
    }
    None
}

/// The stop a settled attempt calls, if any; the caller records it and ends
/// the pass.
pub(super) fn attempt_stop(cancel_requested: bool, backlog_left: bool) -> Option<WakePassStop> {
    if cancel_requested {
        // The admitted attempt was parked and its reservation refunded
        // through the Park arm above — the pass may now stop at this
        // attempt boundary (H-S5/R2).
        return Some(WakePassStop::Cancelled);
    }
    if backlog_left {
        return Some(WakePassStop::BacklogLeft);
    }
    None
}
