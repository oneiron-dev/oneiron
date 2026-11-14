//! Durable and live wake-observation read vocabulary.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use oneiron_model::llm::BudgetLeaseState;

#[doc(hidden)]
pub use oneiron_wake_contract::memory::wake_observation::{ClaimAuthoringFallback, WakeRef};

#[doc(hidden)]
pub use oneiron_records::memory::wake_observation::{
    WakeCallState, WakeObservedAttempt, WakeObservedCall, WakeObservedCallEnd,
    WakeObservedCheckpoint, WakeObservedEnd, WakeObservedHeader, WakeObservedResume,
};

/// Rows one page carries when the request names no limit.
pub const WAKE_OBSERVATION_PAGE_DEFAULT: usize = 50;

/// The most rows one page carries; the cursor reads on past it.
pub const WAKE_OBSERVATION_PAGE_MAX: usize = 500;

/// What a wake observation read addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeObservationSelector {
    /// One attempt: its latest recorded generation, or the latest one `wake`
    /// admitted. Its page lists its calls in that pass, each with the
    /// generation it was admitted under.
    Attempt {
        attempt: AttemptId,
        wake: Option<WakeRef>,
    },
    /// One pass. Its page lists the attempt generations it admitted.
    Wake { wake: WakeRef },
}

/// Where the previous page of a wake observation stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeObservationCursor {
    /// After this call, on an attempt's page.
    Call(EntityId),
    /// After this attempt generation, on a pass's page.
    Member {
        attempt: AttemptId,
        attempt_count: u32,
    },
}

/// One wake observation read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeObservationRequest {
    pub selector: WakeObservationSelector,
    /// Rows on this page: `None` reads [`WAKE_OBSERVATION_PAGE_DEFAULT`], and
    /// a limit past [`WAKE_OBSERVATION_PAGE_MAX`] reads the max. A page is
    /// never a cap: [`WakeObservation::next`] reads on.
    pub limit: Option<usize>,
    pub cursor: Option<WakeObservationCursor>,
}

/// One attempt generation as its pass observed it, with the Checkpoint park
/// that pass cut, once it parked, and the earlier pass's cut it continues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeObservedGeneration {
    pub attempt: WakeObservedAttempt,
    pub checkpoint: Option<WakeObservedCheckpoint>,
    pub after_cut: Option<WakeObservedCheckpoint>,
}

/// What one pass recorded, read on one snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeObservation {
    pub wake: WakeRef,
    pub header: WakeObservedHeader,
    /// The addressed generation, on an attempt's read.
    pub generation: Option<WakeObservedGeneration>,
    /// A pass's page: the generations it admitted, in attempt order.
    pub members: Vec<WakeObservedGeneration>,
    /// An attempt's page: its calls in that pass, in call order.
    pub calls: Vec<WakeObservedCall>,
    /// Where the next page starts; `None` once this page reached the end.
    pub next: Option<WakeObservationCursor>,
    /// The live pass, sampled after the snapshot and never atomically with
    /// it; `None` when no root on this handle runs it now.
    pub live: Option<WakeLiveState>,
}

/// A running pass as its clock and its calls' guards read now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeLiveState {
    pub elapsed_ms: u64,
    pub remaining_ms: u64,
    /// Its calls still running.
    pub calls: Vec<WakeLiveCall>,
}

/// One running call, with its lease as the guard that issued it holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeLiveCall {
    pub call: EntityId,
    pub lease_id: String,
    /// `None` once that guard holds no lease by this id.
    pub lease: Option<BudgetLeaseState>,
}
