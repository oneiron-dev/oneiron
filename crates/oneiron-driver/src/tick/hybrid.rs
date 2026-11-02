//! Hybrid tick: deadline and push lanes taking turns, a deadline rest that leaves pushes flowing, and session-hint sidecar delegation.

use std::sync::Arc;

use tokio::time::Instant;

use super::{
    ArmedLane, CommitmentDeadline, DeadlineSource, PushTick, SessionHintCarrier, Tick, TickSource,
    TimerTick, sleep_until_due,
};

// ---------------------------------------------------------------------------
// HybridTick — timer + push lanes taking turns
// ---------------------------------------------------------------------------

/// Selects over a [`TimerTick`] and a [`PushTick`], the two lanes taking
/// turns (FIX 11403): a push already buffered runs before a due deadline,
/// and after a push a due deadline goes first, so neither lane starves the
/// other. Nothing is buffered on the timer side — the next deadline is
/// re-read from the attempt queue on every cycle, so a deadline that lost
/// one turn re-surfaces on the next call and can never be dropped by push
/// coalescing (H-S4). While the supervisor rests the deadline lane behind an
/// owed retry ([`TickSource::rest_deadlines`]), only deadline re-reads wait:
/// pushes keep flowing, and the rest's end reads the deadline again.
pub struct HybridTick<D> {
    timer: TimerTick<D>,
    push: PushTick,
    changes: Option<tokio::sync::watch::Receiver<u64>>,
    push_open: bool,
    /// The last tick came from the push lane: a due deadline goes next.
    deadline_next: bool,
    /// No deadline is re-read before this instant; pushes are served.
    deadline_rest: Option<Instant>,
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
            deadline_next: false,
            deadline_rest: None,
        }
    }

    /// One deadline read, recorded as the queue lane's armed instant.
    fn read_armed_deadline(&mut self) -> Option<CommitmentDeadline> {
        let deadline = self.timer.read_deadline();
        self.push.record_armed(
            ArmedLane::Queue,
            deadline.map(|deadline| deadline.due_at_ms),
        );
        deadline
    }

    /// `tick`, served from the push lane: a due deadline goes next.
    fn served_push(&mut self, tick: Tick) -> Tick {
        self.deadline_next = true;
        tick
    }

    /// `deadline`, served from the timer lane: a buffered push goes next.
    fn served_deadline(&mut self, deadline: CommitmentDeadline) -> Tick {
        self.deadline_next = false;
        Tick::Deadline(deadline)
    }

    /// The instant the deadline lane's rest ends, while it lasts.
    fn resting_until(&mut self) -> Option<Instant> {
        self.deadline_rest = self.deadline_rest.filter(|until| *until > Instant::now());
        self.deadline_rest
    }

    /// Serves the push lane while the deadline lane rests until `until`:
    /// the first push is the tick; `None` once the rest is over.
    async fn push_during_rest(&mut self, until: Instant) -> Option<Tick> {
        if self.push_open {
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(until) => return None,
                push = self.push.recv() => match push {
                    Some(tick) => return Some(self.served_push(tick)),
                    None => self.push_open = false,
                },
            }
        }
        // A closed push lane must not end a source whose deadline only
        // rests: the rest is waited out and the deadline read again.
        tokio::time::sleep_until(until).await;
        None
    }
}

/// Waits for the next post-commit invalidation `changes` carries; pends
/// forever once there is none or its sender is gone.
pub(crate) async fn wait_for_change(changes: &mut Option<tokio::sync::watch::Receiver<u64>>) {
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
            // A push already buffered runs before a due deadline, unless the
            // last tick was a push: then a due deadline goes first.
            if !self.deadline_next
                && let Some(tick) = self.push.take_pending()
            {
                return Some(self.served_push(tick));
            }
            if let Some(until) = self.resting_until() {
                if let Some(tick) = self.push_during_rest(until).await {
                    return Some(tick);
                }
                continue;
            }
            match self.read_armed_deadline() {
                Some(deadline) if deadline.due_at_ms <= self.timer.now() => {
                    return Some(self.served_deadline(deadline));
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
                                return Some(self.served_deadline(deadline));
                            }
                            () = wait_for_change(&mut self.changes) => break,
                            push = self.push.recv(), if self.push_open => match push {
                                Some(tick) => return Some(self.served_push(tick)),
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
                            Some(tick) => return Some(self.served_push(tick)),
                            None => self.push_open = false,
                        },
                    }
                }
            }
        }
    }

    fn take_buffered_session_hint(
        &mut self,
    ) -> Option<(
        oneiron::session_lifecycle::SessionKey,
        crate::SessionHint,
        Option<u64>,
        u64,
    )> {
        self.push.take_buffered_session_hint()
    }

    fn take_buffered_session_hint_carrier(&mut self) -> Option<SessionHintCarrier> {
        self.push.take_buffered_session_hint_carrier()
    }

    fn take_delivered_session_hint_carrier(&mut self) -> Option<SessionHintCarrier> {
        self.push.take_delivered_session_hint_carrier()
    }

    fn note_armed(&mut self, lane: ArmedLane, at_ms: Option<u64>) {
        self.push.record_armed(lane, at_ms);
    }

    fn rest_deadlines(&mut self, until: Option<Instant>) -> bool {
        self.deadline_rest = until;
        true
    }
}
