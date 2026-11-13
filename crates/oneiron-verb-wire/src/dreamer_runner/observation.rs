//! Moved from `crates/oneiron/src/dreamer_runner/observation.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::dreamer::DreamerParkCauseView;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_state::AttemptState;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WakeSettlementsRequest {
    pub after: Option<EntityId>,
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WakeSettlementRequest {
    pub wake: EntityId,
}

/// What a root's jobs came to, reduced in the read that lists them. Each
/// list names jobs of `jobs` by `attempt`; a try a retry superseded is in
/// none of them.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeOutcomeView {
    pub state: WakeOutcomeState,
    /// Queued, leased, landing or scheduled: work not yet done.
    pub waiting_on: Vec<EntityId>,
    /// Parked, or paused by an operator.
    pub parked: Vec<WakeParkedJob>,
    /// Failed, and no retry took its place.
    pub failed: Vec<EntityId>,
    /// Cancelled or abandoned.
    pub stopped: Vec<EntityId>,
    /// The nightly remainder, left for a later interval and not waited for.
    pub deferred: Vec<WakeDeferredJob>,
    /// The completed jobs' result references, once each, in job order.
    pub result_refs: Vec<String>,
    /// The completed jobs' conclusions, once each, in job order.
    pub conclusions: Vec<EntityId>,
}

/// `awaiting_host` when every waiting job is queued or scheduled for a
/// host Coach consumer; otherwise `running` while any job still waits.
/// Then `failed` for any failure no retry recovered; then `partial` for
/// any parked, paused, stopped or deferred job; else `succeeded`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WakeOutcomeState {
    Running,
    /// Queued for a host consumer, not a claim the host is absent or the work ended.
    AwaitingHost,
    Succeeded,
    Partial,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeParkedJob {
    pub attempt: EntityId,
    /// `None` for an operator's pause, which writes no park row.
    pub cause: Option<DreamerParkCauseView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeDeferredJob {
    pub attempt: EntityId,
    /// When it is due, in Unix seconds: its retry's scheduled instant, else
    /// the due its payload names.
    pub due: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeRecipeJobView {
    pub attempt: EntityId,
    pub parent: Option<EntityId>,
    /// The try this job retries, when a retry minted it.
    pub retry_of: Option<EntityId>,
    pub kind: String,
    pub state: AttemptState,
    pub created_at: u64,
    pub updated_at: u64,
    /// The actual Dreamer, Coach or resident principal, never inferred from a name.
    pub actor: Option<EntityId>,
    pub facet: Option<String>,
    pub authority_receipt: Option<[u8; 16]>,
    pub park_cause: Option<DreamerParkCauseView>,
    pub parked_at: Option<u64>,
    pub result_ref: Option<String>,
    /// Exact claim identities retained by the promotion/merge output ledgers.
    pub conclusions: Vec<EntityId>,
}
