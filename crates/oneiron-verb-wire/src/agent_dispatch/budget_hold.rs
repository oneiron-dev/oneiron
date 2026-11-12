//! Moved from `crates/oneiron/src/agent_dispatch/budget_hold.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::agent_dispatch::spend_record::SpendSignal;
use oneiron_base::error::Result;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::attempt_inputs::AttemptInterventionKind;
use oneiron_store::attempt_state::AttemptState;
use oneiron_wake_contract::store::attempt_cancel::AttemptResumePoint;
use serde::Deserialize;
use serde::Serialize;

/// Where a run's budget hold stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BudgetHoldState {
    /// The wrap-up warning went out; nothing is parked yet.
    Warned,
    /// At least one attempt is parked at the cap.
    Held,
    /// The owner resumed the run.
    Resumed,
}

/// One attempt the hold parked, with the checkpoint it resumes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HeldAttempt {
    pub attempt: AttemptId,
    pub resume_point: AttemptResumePoint,
}

/// The owner's notice of a held run, and whether the host delivered it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BudgetHoldNotice {
    pub text: String,
    /// Unix seconds the host delivered it; `None` while it is still owed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<u64>,
}
