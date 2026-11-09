//! Monotonic wake-pass clock and cooperative cancellation flag.

use oneiron_model::llm::WorkCancel;

use crate::dreamer_runner::DreamerAdmittedAttempt;

/// Wake-pass wall-clock ceiling: the REAL ceiling (1184-D4-C), monotonic.
pub const DREAMER_WAKE_PASS_WALL_CLOCK_CEILING_MS: u64 = 180_000;

#[doc(hidden)]
pub use oneiron_wake_contract::dreamer_wake::deadline::{
    DREAMER_GRACEFUL_WRAP_WINDOW_MS, WakeCancellation, WakePassDeadline,
};
#[doc(hidden)]

pub(super) fn wake_pass_deadline_for_admitted(
    wake_pass_deadline: &WakePassDeadline,
    admitted: &DreamerAdmittedAttempt,
) -> WakePassDeadline {
    let mut deadline = wake_pass_deadline.clone();
    deadline.admitted_budget_line = Some(admitted.admitted_budget_line().clone());
    deadline
}

/// Wrap-up-soon notice threshold (1184-D4-D): counter OR clock percent.
pub const DREAMER_WRAP_UP_NOTICE_PERCENT: u64 = 80;

/// Trips the device-work cancellation once the wake pass asked for one
/// (FIX 11963): the pass polls the wake flag at its checkpoints, and
/// device work admitted under the pass's cancellation stops admitting once
/// tripped. Idempotent on both sides; returns whether it tripped now.
pub fn sync_wake_cancel(wake: &WakeCancellation, device: &WorkCancel) -> bool {
    if wake.is_cancelled() {
        device.cancel();
        true
    } else {
        false
    }
}
