//! The try an office fork originates from (FIX 3551, OF-505): the exact
//! running attempt a host sealed into this surface (`HostBinding`), proved
//! live in the fork's own transaction. It is never a run root, TASK, actor,
//! run tag or any other field a caller writes.

use crate::attempt_queue::AttemptId;
use crate::memory::{Memory, MemoryResult};

use super::create_origin::{BoundRunWords, bound_dispatch_in_txn};

const OFFICE_FORK_WORDS: BoundRunWords = BoundRunWords {
    gone: (
        "the forking run is no longer a live agent run",
        "Open the fork from the agent run the host bound.",
    ),
    lapsed: (
        "the forking run's lease is no longer current",
        "Open the fork while the agent's try is leased.",
    ),
    foreign: (
        "a bound fork opens as its run's agent",
        "Open the fork from the agent run the host bound.",
    ),
};

/// The attempt an office fork opened on `memory` originates from, read only
/// through `txn`, the fork's committing transaction: the try a host bound,
/// still an agent dispatch, running, leased by the binding's owner at its
/// generation, and run by this surface's actor. A surface no host bound (an
/// owner's or a direct call) opens a fork with no originating try:
/// `Ok(None)`.
///
/// # Errors
///
/// A stale or foreign binding refuses, and never reads as unbound; storage
/// errors.
pub(crate) fn office_fork_origin_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
) -> MemoryResult<Option<AttemptId>> {
    Ok(bound_dispatch_in_txn(memory, txn, &OFFICE_FORK_WORDS)?.map(|(record, _)| record.id))
}
