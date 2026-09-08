//! Hybrid tick: biased deadline-versus-push select with deadline priority and session-hint sidecar delegation.

use std::sync::Arc;

use super::{
    DeadlineSource, PushTick, SessionHintCarrier, Tick, TickSource, TimerTick, sleep_until_due,
};
use crate::session::SessionHint;

// ---------------------------------------------------------------------------
// HybridTick — biased select over timer + push, deadline priority
// ---------------------------------------------------------------------------

/// Selects over a [`TimerTick`] and a [`PushTick`] with deadline priority:
/// an already-due deadline short-circuits before the push lane is even
/// looked at, and when both lanes become ready in the same poll the biased
/// select picks the deadline branch. Nothing is buffered on the timer side
/// — the next deadline is re-read from the attempt queue on every cycle, so a
/// deadline that lost one race re-surfaces on the next call and can never
/// be dropped by push coalescing (H-S4).
pub struct HybridTick<D> {
    timer: TimerTick<D>,
    push: PushTick,
}

impl<D: DeadlineSource> HybridTick<D> {
    #[must_use]
    pub fn new(timer: TimerTick<D>, push: PushTick) -> Self {
        Self { timer, push }
    }
}

impl<D: DeadlineSource> TickSource for HybridTick<D> {
    async fn next_tick(&mut self) -> Option<Tick> {
        match self.timer.read_deadline() {
            // A deadline that is already due beats any pending push.
            Some(deadline) if deadline.due_at_ms <= self.timer.now() => {
                Some(Tick::Deadline(deadline))
            }
            Some(deadline) => {
                let clock = Arc::clone(&self.timer.now_ms);
                let winner = tokio::select! {
                    biased;
                    () = sleep_until_due(&clock, deadline.due_at_ms) => None,
                    push = self.push.recv() => Some(push),
                };
                match winner {
                    // The deadline came due first.
                    None => Some(Tick::Deadline(deadline)),
                    // A push won; the un-consumed deadline re-surfaces on
                    // the next cycle's fresh read.
                    Some(Some(tick)) => Some(tick),
                    // Push lane closed while a deadline is armed: wait the
                    // deadline out on the timer lane alone.
                    Some(None) => {
                        sleep_until_due(&clock, deadline.due_at_ms).await;
                        Some(Tick::Deadline(deadline))
                    }
                }
            }
            // No timed work: only a push can wake us. `None` from the push
            // lane means no producers remain either — the source is
            // exhausted.
            None => self.push.recv().await,
        }
    }

    fn take_buffered_session_hint(&mut self) -> Option<(SessionHint, Option<u64>, u64)> {
        self.push.take_buffered_session_hint()
    }

    fn take_buffered_session_hint_carrier(&mut self) -> Option<SessionHintCarrier> {
        self.push.take_buffered_session_hint_carrier()
    }

    fn take_delivered_session_hint_carrier(&mut self) -> Option<SessionHintCarrier> {
        self.push.take_delivered_session_hint_carrier()
    }
}
