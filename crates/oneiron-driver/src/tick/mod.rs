//! Tick sources: what wakes the supervisor (ONE-1684).
//!
//! The driver is a pure EVENT CONSUMER (ARCH-0026 / CROSS-ARCH-0022 /
//! ARCH-0046): there is no periodic heartbeat or poll timer anywhere in
//! this module. Every wakeup traces to exactly one of two causes —
//!
//! * a **commitment deadline read from the attempt queue** ([`TimerTick`]
//!   sleeps until the concrete next deadline, re-read once per cycle), or
//! * an **authenticated push** ([`PushTick`], a bounded coalescing mailbox
//!   whose producer handles are TYPED by role: a [`HintPusher`] is
//!   structurally unable to inject a wake-class tick — H-S4).
//!
//! [`HybridTick`] selects over both with deadline priority: when a deadline
//! and a push are ready in the same poll, the deadline wins. Push bursts
//! coalesce (capacity 1 per wake lane and plain-hint slot; session hints
//! ride a bounded ORDERED queue that coalesces only adjacent Activity hints
//! arriving within the configured idle floor — lifecycle causality is never
//! reordered) into follow-up passes,
//! while a missed deadline can never be dropped — deadlines are never
//! buffered here, they are re-read from the attempt queue on every cycle, so
//! a deadline that lost one race simply re-surfaces on the next call.

use std::sync::Arc;

mod hybrid;
mod model;
mod push;
mod timer;

pub use self::hybrid::HybridTick;
pub use self::model::{
    CommitmentDeadline, DeadlineSource, HintSignal, Tick, TickSource, WakeSignal,
};
pub(crate) use self::model::{SessionHintCarrier, SessionHintStamp};
pub use self::push::{HintPusher, PushTick, TickPushError, WakePusher};
pub(crate) use self::timer::sleep_until_due;
pub use self::timer::{AttemptQueueDeadlines, CommitmentDueDeadlines, TimerTick};

/// Millisecond wall-clock read, injectable for tests.
pub type NowMillis = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests;
