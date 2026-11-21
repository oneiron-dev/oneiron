//! Moved from `crates/oneiron/src/memory/wake_observation.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
pub use oneiron_wake_contract::memory::wake_observation::ClaimAuthoringFallback;
pub use oneiron_wake_contract::memory::wake_observation::WakeRef;
use serde::Deserialize;
use serde::Serialize;

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
