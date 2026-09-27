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
    changes: Option<tokio::sync::watch::Receiver<u64>>,
    push_open: bool,
}

impl<D: DeadlineSource> HybridTick<D> {
    #[must_use]
    pub fn new(timer: TimerTick<D>, push: PushTick) -> Self {
        let changes = timer.subscribe_changes();
        Self {
            timer,
            push,
            changes,
            push_open: true,
        }
    }
}

async fn wait_for_change(changes: &mut Option<tokio::sync::watch::Receiver<u64>>) {
    if let Some(receiver) = changes {
        if receiver.changed().await.is_err() {
            *changes = None;
        }
    } else {
        std::future::pending::<()>().await;
    }
}

impl<D: DeadlineSource> TickSource for HybridTick<D> {
    async fn next_tick(&mut self) -> Option<Tick> {
        loop {
            match self.timer.read_deadline() {
                // A due deadline beats buffered push, even after invalidation.
                Some(deadline) if deadline.due_at_ms <= self.timer.now() => {
                    return Some(Tick::Deadline(deadline));
                }
                Some(deadline) => {
                    let clock = Arc::clone(&self.timer.now_ms);
                    // A closed push lane must not discard an already-read
                    // deadline from a one-shot source. Keep the ORIGINAL sleep
                    // (not a restarted duration) until it fires or changes.
                    let sleep = sleep_until_due(&clock, deadline.due_at_ms);
                    tokio::pin!(sleep);
                    loop {
                        tokio::select! {
                            biased;
                            () = &mut sleep => {
                                return Some(Tick::Deadline(deadline));
                            }
                            () = wait_for_change(&mut self.changes) => break,
                            push = self.push.recv(), if self.push_open => match push {
                                Some(tick) => return Some(tick),
                                None => self.push_open = false,
                            },
                        }
                    }
                }
                None => {
                    if !self.push_open {
                        return None;
                    }
                    tokio::select! {
                        biased;
                        () = wait_for_change(&mut self.changes) => continue,
                        push = self.push.recv() => match push {
                            Some(tick) => return Some(tick),
                            None => self.push_open = false,
                        },
                    }
                }
            }
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
