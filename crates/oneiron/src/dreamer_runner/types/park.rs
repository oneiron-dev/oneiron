//! Parking a Dreamer attempt in local runner state.

use crate::attempt_queue::AttemptId;

use super::DreamerParkCause;

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
