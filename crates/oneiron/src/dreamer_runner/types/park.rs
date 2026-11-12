//! Parking a Dreamer attempt in local runner state.

use crate::attempt_queue::AttemptId;
use crate::code_run::WaitKey;
use crate::entity_id::EntityId;
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

/// A model seat's durable identity: one login or subscription.
pub type ModelSeatId = EntityId;

/// Exactly what wakes a parked attempt. A Budget, PassBudget, ResidentShare, Consent, Peer or Human
/// wait exists only on a trap park: for Consent, Peer and Human, the code-run wait's delivery wakes the trap through
/// the `TRAPS` binding written beside the park. A Seat wait exists only on the driver's own park.
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
    /// The guard of the wake pass the step ran in refused the step's reservation, which asked it
    /// for `asked_units`; that guard is rebuilt each pass, so a later pass whose guard has room
    /// for them wakes the trap at its start. A step also bound to a spend scope (a free-time
    /// item's) names the scope's nearest open hard scope, whose top-up that leaves room for them
    /// wakes the trap too: the scope's own room is stale until the pass settles the step's spend.
    PassBudget {
        /// The units the refused reservation asked of the pass's guard.
        asked_units: u64,
        /// The nearest open hard scope above the step's spend scope, when the step has one: the
        /// scope a top-up raises to give the step room.
        scope: Option<SpendScopeId>,
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
    /// A spent model seat refused the try; the seat's available write wakes it.
    Seat {
        /// The spent seat.
        seat: ModelSeatId,
        /// The seat row's generation this park names; the available write answers it.
        generation: u64,
        /// The vendor-reported reset in seconds, when the refusal named one.
        reset_at_s: Option<u64>,
    },
    /// The owner pinned this resident's share of the host's allocation, and the step's call did
    /// not fit it; the owner's share write that frees the call wakes the trap (D3).
    ResidentShare {
        /// The resident whose share refused the call.
        resident: EntityId,
        /// The share, in the allocation's unit, the call needed: what the resident had used and
        /// held, plus the call's reservation.
        needed_units: u64,
    },
}

impl DreamerParkWait {
    /// The wait's class, as the park resume table reads it.
    #[must_use]
    pub fn class(&self) -> DreamerParkWaitClass {
        match self {
            Self::Budget { .. } => DreamerParkWaitClass::Budget,
            Self::PassBudget { .. } => DreamerParkWaitClass::PassBudget,
            Self::Consent { .. } => DreamerParkWaitClass::Consent,
            Self::Peer { .. } => DreamerParkWaitClass::Peer,
            Self::Human { .. } => DreamerParkWaitClass::Human,
            Self::Seat { .. } => DreamerParkWaitClass::Seat,
            Self::ResidentShare { .. } => DreamerParkWaitClass::ResidentShare,
        }
    }
}

/// A parked attempt's typed wait with its lease fence: the queue row's `attempt_count` the writer
/// read in the park's own transaction. Budget top-ups and seat-available writes check this
/// generation before waking a park; answer deliveries use the trap's private attempt and lineage
/// binding and the exact wait key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerParkedWait {
    /// The condition that wakes the parked attempt.
    pub wait: DreamerParkWait,
    /// The queue row's attempt count stamped by the writer for every class; Consent, Peer and Human
    /// resumers do not read it here because the trap binding and exact wait key fence their delivery.
    pub lease_generation: u32,
}
