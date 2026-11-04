//! Durable and live wake-observation read vocabulary.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use oneiron_model::llm::BudgetLeaseState;

/// One wake pass's observation handle: the store-issued id its rows are
/// keyed by. A pass, never a recipe, attempt or budget id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WakeRef(pub(crate) EntityId);

impl WakeRef {
    /// The pass a stored id names.
    #[must_use]
    pub const fn from_entity_id(id: EntityId) -> Self {
        Self(id)
    }

    /// The id the pass's rows are keyed by.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        self.0
    }
}

/// The `w` row: one pass's clock and where it ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeObservedHeader {
    /// What woke the pass.
    pub trigger: String,
    pub scope: String,
    /// The worker label the pass leases its attempts under.
    pub worker: String,
    pub node_id: u64,
    /// The pass's wake-budget line, a diagnostic name.
    pub budget_id: String,
    /// Unix ms the wall clock read at the deadline's origin, before the pass
    /// assembled its guard and executors; `None` under an injected clock.
    pub origin_unix_ms: Option<u64>,
    pub ceiling_ms: u64,
    /// When its hooks allowed the pass: wall Unix ms, and ms on its clock.
    pub entered_unix_ms: u64,
    pub entered_elapsed_ms: u64,
    /// Set once every worker settled; `None` while it runs, and for good
    /// when its process died first.
    pub ended: Option<WakeObservedEnd>,
}

impl WakeObservedHeader {
    /// The ceiling anchored to the wall origin.
    #[must_use]
    pub fn ceiling_unix_ms(&self) -> Option<u64> {
        self.origin_unix_ms?.checked_add(self.ceiling_ms)
    }
}

/// How a pass ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeObservedEnd {
    pub unix_ms: u64,
    pub elapsed_ms: u64,
    /// Why it stopped; `None` when it returned an error.
    pub stop: Option<String>,
    /// Why its claims were authored single-pass under a promoted default
    /// (FIX 897), when they were.
    pub claim_authoring_fallback: Option<ClaimAuthoringFallback>,
}

/// The `a` row: one attempt generation a pass admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeObservedAttempt {
    pub attempt: AttemptId,
    /// The queue generation (`attempt_count`) its admission leased.
    pub attempt_count: u32,
    pub wake: WakeRef,
    /// The worker label holding its lease.
    pub worker: String,
    /// The run correlation its queue row carried.
    pub run_id: Option<String>,
    /// Ms on the pass's clock when its admission was observed.
    pub admitted_elapsed_ms: u64,
    /// The Checkpoint park this generation's pass cut, once it parked.
    pub park: Option<EntityId>,
    /// The cut of the attempt's previous observed generation, which this one
    /// continues from as the same try.
    pub after_cut: Option<EntityId>,
}

/// The `c` row: one model call a pass admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeObservedCall {
    pub call: EntityId,
    pub attempt: AttemptId,
    pub attempt_count: u32,
    /// The logical step's canonical request hash.
    pub step_hash: [u8; 32],
    /// 0 for the step's own call, n for its nth schema correction.
    pub ordinal: u32,
    /// The id of the lease its guard issued: a diagnostic, not a capability.
    pub lease_id: String,
    /// Ms on the pass's clock just after its guard admitted it: an upper
    /// bound on the allocation, never a time inside the guard.
    pub admitted_elapsed_ms: u64,
    pub end: Option<WakeObservedCallEnd>,
}

/// How one call closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeObservedCallEnd {
    pub state: WakeCallState,
    pub at_unix_ms: u64,
    /// Units its lease charged; on a claimed step's own call, the usage the
    /// step's response reports, its corrections' included.
    pub used_units: Option<u64>,
    /// The terminal `dreamer.step` claim that recorded its step.
    pub claim: Option<EntityId>,
    /// When the provider limit that refused it says it resets, in Unix
    /// seconds (FIX 11226); none for any other end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stated_reset: Option<u64>,
}

/// A call's last recorded state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeCallState {
    /// Its step's terminal claim recorded the response.
    Claimed,
    /// Its lease settled the units it charged; no claim recorded a response.
    Settled,
    /// Its lease was released untouched.
    Aborted,
    /// It closed with its lease still open, or one its guard no longer knows.
    Unsettled,
}

/// The `p` row: one Checkpoint park a pass cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeObservedCheckpoint {
    pub attempt: AttemptId,
    pub attempt_count: u32,
    /// The pass that cut it.
    pub wake: WakeRef,
    /// Unix seconds, as the park row records them.
    pub parked_at: u64,
    /// The steps whose terminal claims the cutting pass recorded: what the
    /// same try replays from its memo once resumed.
    pub saved_steps: Vec<[u8; 32]>,
    pub resumed: Option<WakeObservedResume>,
    /// A Retry park's due instant, in Unix seconds: the latest reset a
    /// provider limit that refused one of its try's calls stated (FIX
    /// 11226). No later pass resumes it before then, and one may at it.
    /// None keeps the vault's Retry pause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<u64>,
}

/// The later pass that resumed a Checkpoint park, as the same try.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeObservedResume {
    pub wake: WakeRef,
    /// Unix seconds.
    pub at: u64,
    pub worker: String,
}

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

/// Why a pass authored its claims single-pass under a promoted
/// claim-authoring default (FIX 897). Never a refusal: the pass ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimAuthoringFallback {
    /// Several bound campaigns carry the default, in root order; none is
    /// chosen for the host (Engine 10-18).
    AmbiguousCampaigns { roots: Vec<AttemptId> },
}
