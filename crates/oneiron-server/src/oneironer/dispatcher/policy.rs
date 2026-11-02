//! The dispatcher's policy (Engine 10-21, FIX 6755 rulings 3 and 4): the one
//! definition of each hold, batch cap and pending cap, and the rules that
//! route a live call and name why a worker ran a call.
//!
//! The pending caps bound in-memory dispatch only. The durable marker is
//! written at its commit whatever the dispatcher holds, and a commit never
//! waits on it; past a cap the caller's claim waits for room, and work the
//! dispatcher has not claimed stays in the store for a later pass. Nothing
//! here refuses a call for a backlog.

use std::time::Duration;

use oneiron::memory::extraction::ExecutionPick;

/// How long a live call waits for company before its worker runs it: never.
pub(crate) const LIVE_HOLD: Duration = Duration::ZERO;
/// Live calls one worker runs as one unit: one turn, no live micro-batch.
pub(crate) const LIVE_BATCH_CAP: usize = 1;
/// Bulk calls one worker takes from the shared queue as one unit, at most.
/// A worker that runs inputs one at a time takes one, so waiting live work
/// goes first at every unit.
pub(crate) const BULK_BATCH_CAP: usize = 8;
/// Live calls claimed and not yet answered, queued or running.
pub(crate) const LIVE_PENDING_CAP: usize = 64;
/// Bulk calls claimed and not yet answered, queued or running.
pub(crate) const BULK_PENDING_CAP: usize = 64;

// The workers run a live unit the moment they take it; a hold would need a
// worker that waits for company, which none does.
const _: () = assert!(
    LIVE_HOLD.is_zero(),
    "a nonzero LIVE_HOLD needs a holding worker"
);

/// One ready worker as live routing sees it.
pub(super) struct Candidate {
    pub(super) index: usize,
    /// Its place in the calibrated rank: 0 is preferred.
    pub(super) rank: usize,
    /// Neither running a unit nor holding a waiting live call.
    pub(super) free: bool,
    /// Live calls waiting in its queue.
    pub(super) waiting: usize,
}

/// The ready worker a live call goes to, and the rule that chose it: a free
/// worker first, by the calibrated rank when several are free; with none
/// free, the shorter waiting live queue, counted in calls, with ties taken in
/// turn from the scheduler's one `cursor`, which moves past the worker it
/// gives. `None` when no worker is ready.
pub(super) fn route_live(
    candidates: &[Candidate],
    cursor: &mut usize,
) -> Option<(usize, ExecutionPick)> {
    let free = candidates.iter().filter(|candidate| candidate.free);
    if let Some(best) = free.clone().min_by_key(|candidate| candidate.rank) {
        let rule = if free.count() > 1 {
            ExecutionPick::Calibrated
        } else {
            ExecutionPick::Free
        };
        return Some((best.index, rule));
    }
    let shortest = candidates.iter().map(|candidate| candidate.waiting).min()?;
    let tied = move || {
        candidates
            .iter()
            .filter(move |candidate| candidate.waiting == shortest)
            .map(|candidate| candidate.index)
    };
    let chosen = tied()
        .find(|index| *index >= *cursor)
        .or_else(|| tied().next())?;
    *cursor = chosen + 1;
    Some((chosen, ExecutionPick::ShorterQueue))
}

/// Why a worker runs a call a routing `rule` gave it: `pinned` when the slot
/// serves one configured worker; `fallback` when a worker ranked above it is
/// not ready; `free` when it is the one ready worker the call could run on
/// and the rule names a queue choice none was made from; else the rule
/// itself.
pub(super) fn reason(
    pinned: bool,
    preferred_away: bool,
    single: bool,
    rule: ExecutionPick,
) -> ExecutionPick {
    if pinned {
        ExecutionPick::Pinned
    } else if preferred_away {
        ExecutionPick::Fallback
    } else if single && rule == ExecutionPick::ShorterQueue {
        ExecutionPick::Free
    } else {
        rule
    }
}
