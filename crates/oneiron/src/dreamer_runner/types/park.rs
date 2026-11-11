//! Parking a Dreamer attempt in local runner state.

use crate::attempt_queue::AttemptId;
use crate::code_run::WaitKey;
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

/// Exactly what wakes a parked attempt's trap. A typed wait exists only on a trap park.
/// For Consent, Peer and Human, the code-run wait's delivery wakes the trap through the `TRAPS`
/// binding written beside the park.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DreamerParkWait {
    /// The hard cap of exactly this open spend scope refused the step's reservation, which asked
    /// it for `asked_units`; a top-up of this scope that leaves room for them wakes the trap.
    Budget {
        /// The open hard spend scope whose own cap refused the reservation.
        scope: SpendScopeId,
        /// The units the reservation asked of that scope: the reservation less what the open
        /// scopes below it could still cover when the step parked.
        asked_units: u64,
    },
    /// A held effect's consent answer or an outbound call's settled reply delivered on the wait.
    Consent {
        /// The exact code-run wait whose delivery wakes the bound trap.
        key: WaitKey,
    },
    /// A peer's or child's result delivered on the wait.
    Peer {
        /// The exact code-run wait whose delivery wakes the bound trap.
        key: WaitKey,
    },
    /// A person's answer delivered on the wait.
    Human {
        /// The exact code-run wait whose delivery wakes the bound trap.
        key: WaitKey,
    },
}

impl DreamerParkWait {
    /// The wait's class, as the park resume table reads it.
    #[must_use]
    pub fn class(&self) -> DreamerParkWaitClass {
        match self {
            Self::Budget { .. } => DreamerParkWaitClass::Budget,
            Self::Consent { .. } => DreamerParkWaitClass::Consent,
            Self::Peer { .. } => DreamerParkWaitClass::Peer,
            Self::Human { .. } => DreamerParkWaitClass::Human,
        }
    }
}

/// A parked attempt's typed wait with its lease fence: the queue row's `attempt_count` the writer
/// read in the park's own transaction. Budget top-ups check this generation before waking the trap;
/// answer deliveries use the trap's private attempt and lineage binding and the exact wait key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerParkedWait {
    /// The condition that wakes the parked attempt's trap.
    pub wait: DreamerParkWait,
    /// The queue row's attempt count stamped by the writer for every class; Consent, Peer and Human
    /// resumers do not read it here because the trap binding and exact wait key fence their delivery.
    pub lease_generation: u32,
}
