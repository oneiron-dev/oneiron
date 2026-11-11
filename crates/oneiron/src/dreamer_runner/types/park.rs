//! Parking a Dreamer attempt in local runner state.

use crate::attempt_queue::AttemptId;
use crate::workspace_roster::spend_scope::SpendScopeId;

use super::DreamerParkCause;
use super::DreamerParkWaitClass;

/// Input for parking a Dreamer attempt in local runner state.
///
/// `park_owner` is the parker's ownership token: only the owner recorded on
/// the row may overwrite it or resume the attempt (fail-closed on mismatch).
/// `carried_spend` is what the step spent so far, for a payer park's resume;
/// `None` where the parker spent nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParkDreamerAttempt {
    pub attempt_id: AttemptId,
    pub reason: String,
    pub cause: DreamerParkCause,
    pub park_owner: String,
    pub carried_spend: Option<u64>,
    pub now: u64,
}

/// What a parked attempt waits on: the typed refill that resumes it. A typed wait exists only on a
/// trap park (the writer refuses it elsewhere): one resume route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DreamerParkWait {
    /// The hard cap of exactly this open spend scope refused the step's reservation of
    /// `asked_units`; a top-up of this scope that leaves room for them wakes the step's trap.
    Budget {
        /// The open hard spend scope whose own cap refused the reservation.
        scope: SpendScopeId,
        /// The units the step tried to reserve under that scope.
        asked_units: u64,
    },
}

impl DreamerParkWait {
    /// The wait's class, as the park resume table reads it.
    #[must_use]
    pub fn class(&self) -> DreamerParkWaitClass {
        match self {
            Self::Budget { .. } => DreamerParkWaitClass::Budget,
        }
    }
}

/// A parked attempt's typed wait with its lease fence: the queue row's `attempt_count` the writer
/// read in the park's own transaction. A resumer wakes the wait only while the row still carries
/// this generation, so a retry's park never answers its source's refill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerParkedWait {
    /// The condition that wakes the parked attempt's trap.
    pub wait: DreamerParkWait,
    /// The queue row's attempt count when this wait was parked.
    pub lease_generation: u32,
}
