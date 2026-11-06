//! A leased agent run's write identity, as the engine's run-write envelope
//! carries it with each write.

use std::sync::Arc;

use crate::attempt_id::AttemptId;

/// A leased run's write identity: its attempt, its lease's owner and the
/// lease's generation, as the host holds them. Only a host lease makes one,
/// never an actor. A write whose token is absent, or whose lease no longer
/// holds, records no use of the run and lands as it would (FIX 3103).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunWriteToken(Arc<RunLease>);

#[derive(Debug, PartialEq, Eq)]
struct RunLease {
    attempt: AttemptId,
    owner: String,
    generation: u32,
}

impl RunWriteToken {
    /// The token of `attempt`'s lease held by `owner` at `generation`. A
    /// token proves nothing alone: a write records a use of the run only
    /// while the engine reads the lease as still held.
    pub fn of(attempt: AttemptId, owner: String, generation: u32) -> Self {
        Self(Arc::new(RunLease {
            attempt,
            owner,
            generation,
        }))
    }

    /// The shared allocation this token names and the heap bytes it holds:
    /// the lease's counts and fields, and its owner at capacity. Tokens that
    /// share one lease name one allocation, so a holder that keeps many
    /// counts it once.
    pub fn heap_allocation(&self) -> (usize, usize) {
        let bytes = (2 * std::mem::size_of::<usize>())
            .saturating_add(std::mem::size_of::<RunLease>())
            .saturating_add(self.0.owner.capacity());
        (Arc::as_ptr(&self.0) as usize, bytes)
    }

    /// The leased attempt.
    pub fn attempt(&self) -> AttemptId {
        self.0.attempt
    }

    /// The lease's owner.
    pub fn owner(&self) -> &str {
        &self.0.owner
    }

    /// The lease's generation.
    pub fn generation(&self) -> u32 {
        self.0.generation
    }
}
