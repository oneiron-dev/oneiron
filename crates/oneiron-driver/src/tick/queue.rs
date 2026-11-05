//! The ordered SESSION-hint queue (FIX 8602): every lifecycle fact a
//! producer handed in, in arrival order, until the session decorator applies
//! it.
//!
//! Nothing here counts, caps or evicts. Arrival order IS lifecycle causality
//! (end-then-open is a reopen; open-end-open is two sittings), so facts are
//! never reordered; only ADJACENT Activity hints for one key whose arrivals
//! fall within the channel's coalescing floor roll up, into one period that
//! keeps both endpoint stamps and its count. A boundary hint never coalesces.
//!
//! The one limit is real memory: a fact the allocator cannot find room for
//! is not queued. Its producer then waits in a line, and every producer
//! arriving after it queues behind, so a later fact never passes an earlier
//! one and each keeps the arrival stamp it came with. The line moves as the
//! receiver drains; a producer leaves it when its fact is kept, when the
//! receiver is gone, or at its own deadline.

use std::collections::{BTreeSet, VecDeque};

use super::{QueuedSessionHint, SessionHintCarrier};
use crate::session::{SessionHint, SessionHintEffect};

#[derive(Debug, Default)]
pub(super) struct SessionHintQueue {
    hints: VecDeque<QueuedSessionHint>,
    /// The ticket the next producer that has to wait takes.
    next_ticket: u64,
    /// The waiting ticket whose turn it is; `next_ticket` while none waits.
    serving: u64,
    /// Tickets whose producer left the line before its turn came.
    left_early: BTreeSet<u64>,
}

impl SessionHintQueue {
    /// Keeps `carrier` at the back, rolled into the last entry when both are
    /// Activity for one key arriving within `coalesce_floor_ms`. `false` when
    /// the allocator has no room for a new entry; the queue is then as it was.
    pub(super) fn keep(&mut self, carrier: SessionHintCarrier, coalesce_floor_ms: u64) -> bool {
        self.keep_with_completion(carrier, &mut None, coalesce_floor_ms)
    }

    /// [`Self::keep`] with the tracked completion the kept envelope owns
    /// afterwards. A `false` return leaves `completion` intact — a tracked
    /// waiter keeps its sender across failed keeps and retries with it.
    pub(super) fn keep_with_completion(
        &mut self,
        carrier: SessionHintCarrier,
        completion: &mut Option<std::sync::mpsc::Sender<SessionHintEffect>>,
        coalesce_floor_ms: u64,
    ) -> bool {
        if carrier.hint == SessionHint::Activity
            && let Some(last) = self.hints.back_mut()
            && last.carrier.hint == SessionHint::Activity
            && last.carrier.key == carrier.key
            && carrier
                .first
                .arrival_ms
                .saturating_sub(last.carrier.last.arrival_ms)
                < coalesce_floor_ms
        {
            last.carrier
                .aggregate_activity(carrier.first.claimed_ms, carrier.first.arrival_ms);
            return true;
        }
        if self.hints.try_reserve(1).is_err() {
            return false;
        }
        let envelope = match completion.take() {
            Some(sender) => QueuedSessionHint::tracked(carrier, sender),
            None => QueuedSessionHint::untracked(carrier),
        };
        self.hints.push_back(envelope);
        true
    }

    pub(super) fn pop_front(&mut self) -> Option<QueuedSessionHint> {
        self.hints.pop_front()
    }

    /// Drops every queued envelope WITHOUT touching the waiter line: tracked
    /// waiters read the dropped senders as closed, while producers still in
    /// line leave through their own receiver-gone check.
    pub(super) fn clear(&mut self) {
        self.hints.clear();
    }

    /// Whether no producer waits for room.
    pub(super) fn line_empty(&self) -> bool {
        self.serving == self.next_ticket
    }

    /// A place at the back of the line.
    pub(super) fn join_line(&mut self) -> u64 {
        let ticket = self.next_ticket;
        self.next_ticket = self.next_ticket.saturating_add(1);
        ticket
    }

    pub(super) fn is_turn(&self, ticket: u64) -> bool {
        self.serving == ticket
    }

    /// Ends `ticket`'s place in the line, its fact kept or not: the turn
    /// passes to the next producer still waiting.
    pub(super) fn leave_line(&mut self, ticket: u64) {
        if self.serving != ticket {
            self.left_early.insert(ticket);
            return;
        }
        self.serving = self.serving.saturating_add(1);
        while self.left_early.remove(&self.serving) {
            self.serving = self.serving.saturating_add(1);
        }
    }
}
