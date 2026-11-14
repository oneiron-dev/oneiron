//! Moved from `crates/oneiron/src/memory/dreamer.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::model_step_submission::StepBudgetRefusal;
use oneiron_wake_contract::dreamer_runner::types::DreamerParkCause;
use serde::Deserialize;
use serde::Serialize;

/// Reference to one queued Dreamer attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerAttemptRef {
    /// 32-hex attempt id (poll via [`Memory::dreamer_attempt_status`]).
    pub job_ref: String,
    /// Queue state at enqueue time.
    pub state: String,
    /// True when the advisory dedupe key coalesced onto an existing attempt.
    pub existing: bool,
}

/// Poll-model view of one Dreamer attempt (W2: long work returns attempt ids).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerAttemptView {
    /// 32-hex attempt id.
    pub job_ref: String,
    /// `queued` | `leased` | `paused` | `completed` | `failed` | `cancelled`.
    pub state: String,
    /// Queue attempt kind.
    pub kind: String,
    /// Worker label holding the lease, if leased.
    pub lease_owner: Option<String>,
    /// Admission attempts so far.
    pub attempt_count: u32,
    /// Run correlation id, if any.
    pub run_id: Option<String>,
    /// Last failure message, if any.
    pub last_error: Option<String>,
    /// The typed refusal of a try a spend scope refused for good, kept on
    /// the failed row beside `last_error`; `None` for every other row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_refusal: Option<StepBudgetRefusal>,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    pub updated_at: u64,
    /// The attempt's park, when the runner parked it (DOOR-144 A): the
    /// durable fact that its work remains for a later resume. Absent when
    /// the attempt holds no park row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parked: Option<DreamerParkedAttemptView>,
}

/// The public face of one parked Dreamer attempt: which attempt, why, and
/// when. The park-owner token and the free-text reason stay private; this
/// names no wake, continuation object or lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerParkedAttemptView {
    /// 32-hex attempt id.
    pub job_ref: String,
    /// What code reads of the park: why it parked.
    pub cause: DreamerParkCauseView,
    /// Unix seconds.
    pub parked_at: u64,
}

/// Why a Dreamer attempt parked, as [`DreamerParkCause`] spells it in its
/// private row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DreamerParkCauseView {
    /// Its model call failed because the provider is down.
    ProviderUnavailable,
    /// Its executor returned an error or panicked.
    ExecutorError,
    /// The wake pass hit its deadline and the attempt kept its progress.
    Checkpoint,
    /// A refusal or error park, resumed as the same try once its retry
    /// delay has passed.
    Retry,
    /// The host's pause stopped the pass before the attempt dispatched;
    /// resumed as the same try by a later pass.
    Paused,
    /// The pass was cancelled.
    Cancelled,
    /// It waits on a signal: a budget approval, a seat login, a peer.
    Signal,
    /// Anything else.
    Other,
}

impl From<DreamerParkCause> for DreamerParkCauseView {
    fn from(cause: DreamerParkCause) -> Self {
        match cause {
            DreamerParkCause::ProviderUnavailable => Self::ProviderUnavailable,
            DreamerParkCause::ExecutorError => Self::ExecutorError,
            DreamerParkCause::Checkpoint => Self::Checkpoint,
            DreamerParkCause::Retry => Self::Retry,
            DreamerParkCause::Paused => Self::Paused,
            DreamerParkCause::Cancelled => Self::Cancelled,
            DreamerParkCause::Signal => Self::Signal,
            DreamerParkCause::Other => Self::Other,
        }
    }
}
