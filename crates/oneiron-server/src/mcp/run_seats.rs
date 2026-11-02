//! Each durable run's compaction seat, kept by the host across `execute_code`
//! calls: a pass in flight, its margin law and the last report outlive one
//! call (agent-runtime-v1 §d7).
use std::collections::{HashMap, VecDeque};

use oneiron::EntityId;
use oneiron::engine_executor::RunCompaction;

/// Seats held at once before an idle one is reclaimed. Past it the least
/// recently used seat with no pass pending or uncollected is dropped; its
/// run builds a fresh seat at its next call, and its swapped epochs stay
/// durable. A seat whose pass is in flight is never dropped, so a resumed
/// run joins its own pass (FIX 9508); when every seat holds one, they all
/// stay.
const MAX_HELD_SEATS: usize = 256;

#[derive(Default)]
pub(super) struct RunSeats {
    seats: HashMap<EntityId, RunCompaction>,
    /// Least recently used first.
    order: VecDeque<EntityId>,
}

impl RunSeats {
    /// The run's seat, out of the map for the length of one call.
    pub(super) fn take(&mut self, run_id: EntityId) -> Option<RunCompaction> {
        self.order.retain(|held| *held != run_id);
        self.seats.remove(&run_id)
    }

    /// Puts a seat back after a call; a run that ended drops its seat.
    pub(super) fn put(&mut self, run_id: EntityId, seat: RunCompaction, ended: bool) {
        if ended {
            return;
        }
        while self.seats.len() >= MAX_HELD_SEATS {
            // Only an idle seat, which a later call builds again, is
            // reclaimed; a seat whose pass is pending or uncollected keeps
            // its receiver for the run to join.
            let idle = self.order.iter().position(|held| {
                self.seats
                    .get(held)
                    .is_none_or(|seat| !seat.report().in_flight)
            });
            let Some(oldest) = idle.and_then(|at| self.order.remove(at)) else {
                break;
            };
            self.seats.remove(&oldest);
        }
        self.order.push_back(run_id);
        self.seats.insert(run_id, seat);
    }
}
