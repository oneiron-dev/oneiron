//! Moved from `crates/oneiron/src/memory/dreamer_wake_read.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The input: an attempt's observation (`job_ref`, with `wake_ref` naming
/// the pass whose generation to read, else its latest), or one pass's
/// (`wake_ref` alone). A page carries 50 rows unless `limit` names others,
/// and never more than 500; `cursor` is the previous page's `next_cursor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationWakeStatusRequest {
    /// The attempt, as 32 hex (`vault.consolidation.enqueue`'s `job_ref`).
    #[serde(default)]
    pub job_ref: Option<String>,
    /// The wake pass, as 32 hex.
    #[serde(default)]
    pub wake_ref: Option<String>,
    /// Rows on this page: 50 when absent, at most 500.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Where the previous page stopped: its `next_cursor`.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// One page of what one wake pass recorded, read on one snapshot, and the
/// pass as it runs now, sampled after.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeView {
    /// The pass, as 32 hex.
    pub wake_ref: String,
    pub header: DreamerWakeHeaderView,
    /// On an attempt's read: the addressed generation.
    #[serde(default)]
    pub generation: Option<DreamerWakeGenerationView>,
    /// On a pass's read: the attempt generations it admitted, in attempt
    /// order.
    #[serde(default)]
    pub members: Vec<DreamerWakeGenerationView>,
    /// On an attempt's read: its model calls in that pass, in call order.
    #[serde(default)]
    pub calls: Vec<DreamerWakeCallView>,
    /// The next page's `cursor`; absent once this page reached the end.
    #[serde(default)]
    pub next_cursor: Option<String>,
    /// The pass as this host runs it now, sampled after the page and never
    /// atomically with it; absent when nothing here runs it.
    #[serde(default)]
    pub live: Option<DreamerWakeLiveView>,
}

/// One pass's clock and where it ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeHeaderView {
    /// What woke the pass.
    pub trigger: String,
    pub scope: String,
    /// The worker label the pass leases its attempts under.
    pub worker: String,
    /// The node that ran it, as a decimal string.
    pub node_id: String,
    /// The pass's wake-budget line, a diagnostic name.
    pub budget_id: String,
    /// Unix ms at the deadline's origin; absent under an injected clock.
    pub origin_unix_ms: Option<u64>,
    /// The pass's wall-clock ceiling, ms on its own clock.
    pub ceiling_ms: u64,
    /// The ceiling anchored to the wall origin, Unix ms.
    pub ceiling_unix_ms: Option<u64>,
    /// When its hooks allowed the pass: Unix ms, and ms on its clock.
    pub entered_unix_ms: u64,
    pub entered_elapsed_ms: u64,
    /// How it ended; absent while it runs, and for good when its process
    /// died first.
    pub ended: Option<DreamerWakeEndView>,
}

/// How a pass ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeEndView {
    pub unix_ms: u64,
    pub elapsed_ms: u64,
    /// Why it stopped; absent when it returned an error.
    pub stop: Option<String>,
    /// Why its claims were authored single-pass under a promoted default,
    /// when they were.
    pub claim_authoring_fallback: Option<DreamerWakeClaimAuthoringFallbackView>,
}

/// Why a pass authored its claims single-pass under a promoted default, in
/// wire shapes: campaign roots as 32 hex, in root order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DreamerWakeClaimAuthoringFallbackView {
    /// Several bound campaigns carry the default; none is chosen for the host.
    AmbiguousCampaigns { roots: Vec<String> },
}

/// One attempt generation a pass admitted, with the Checkpoint park that
/// pass cut, once it parked, and the earlier cut it continues as the same
/// try.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeGenerationView {
    /// The attempt, as 32 hex.
    pub job_ref: String,
    /// The queue generation its admission leased.
    pub attempt_count: u32,
    /// The pass that admitted it, as 32 hex.
    pub wake_ref: String,
    pub worker: String,
    pub run_id: Option<String>,
    /// Ms on the pass's clock when its admission was observed.
    pub admitted_elapsed_ms: u64,
    pub checkpoint: Option<DreamerWakeCheckpointView>,
    pub after_cut: Option<DreamerWakeCheckpointView>,
}

/// One Checkpoint park a pass cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeCheckpointView {
    /// The park, as 32 hex.
    pub park_ref: String,
    pub job_ref: String,
    pub attempt_count: u32,
    /// The pass that cut it, as 32 hex.
    pub wake_ref: String,
    /// Unix seconds.
    pub parked_at: u64,
    /// The steps the cutting pass recorded, each as its 64-hex request hash:
    /// what the same try replays from its memo once resumed.
    pub saved_steps: Vec<String>,
    /// The later pass that resumed it.
    pub resumed: Option<DreamerWakeResumeView>,
}

/// The later pass that resumed a Checkpoint park.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeResumeView {
    pub wake_ref: String,
    /// Unix seconds.
    pub at: u64,
    pub worker: String,
}

/// One model call a pass admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeCallView {
    /// The call, as 32 hex.
    pub call_ref: String,
    pub job_ref: String,
    pub attempt_count: u32,
    /// The logical step's canonical request hash, as 64 hex.
    pub step_hash: String,
    /// 0 for the step's own call, n for its nth schema correction.
    pub ordinal: u32,
    /// The lease its guard issued: a diagnostic, not a capability.
    pub lease_id: String,
    /// Ms on the pass's clock just after its guard admitted it.
    pub admitted_elapsed_ms: u64,
    pub end: Option<DreamerWakeCallEndView>,
}

/// How one call closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeCallEndView {
    pub state: DreamerWakeCallStateView,
    pub at_unix_ms: u64,
    pub used_units: Option<u64>,
    /// The terminal step claim that recorded its step, as 32 hex.
    pub claim_ref: Option<String>,
}

/// A call's last recorded state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DreamerWakeCallStateView {
    /// Its step's terminal claim recorded the response.
    Claimed,
    /// Its lease settled the units it charged; no claim recorded a response.
    Settled,
    /// Its lease was released untouched.
    Aborted,
    /// It closed with its lease still open, or one its guard no longer knows.
    Unsettled,
}

/// A running pass as its clock and its calls' guards read now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeLiveView {
    pub elapsed_ms: u64,
    pub remaining_ms: u64,
    /// Its calls still running.
    pub calls: Vec<DreamerWakeLiveCallView>,
}

/// One running call and its lease as the guard that issued it holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeLiveCallView {
    pub call_ref: String,
    pub lease_id: String,
    /// Absent once that guard holds no lease by this id.
    pub lease: Option<DreamerWakeLeaseView>,
}

/// A live lease's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DreamerWakeLeaseView {
    /// Admitted and not yet closed; `dispatched` once bytes may have left.
    Open {
        reserve_units: u64,
        dispatched: bool,
    },
    /// Closed with the units it charged.
    Settled { used_units: u64 },
    /// Released untouched.
    Aborted,
}
