//! Moved from `crates/oneiron/src/self_heal/audit/doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::self_heal::audit::SealCheckKind;
use crate::self_heal::audit::SealCheckOutcome;
use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealAttemptRequest {
    pub attempt: AttemptId,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealPendingRequest {
    #[serde(default)]
    pub attempt: Option<AttemptId>,
}

/// Completion names a persisted request, never a caller-selected audit rate.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealCompleteRequest {
    pub attempt: AttemptId,
    pub kind: SealCheckKind,
    pub outcome: SealCheckOutcome,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealRunRequest {}

/// A normal Coach job; its existing leased runner performs the checks.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SealRunReceipt {
    pub job: AttemptId,
}
