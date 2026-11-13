//! Moved from `crates/oneiron/src/self_heal/audit/doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::learning::honesty::SealAssessment;
use crate::learning::honesty::seal_assessment;
use crate::self_heal::audit::SealCheckKind;
use crate::self_heal::audit::SealCheckOutcome;
use crate::self_heal::audit::SealedAttemptReceipt;
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

/// Findings move task quality; the confession reward remains separate.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SealReceiptView {
    pub receipt: SealedAttemptReceipt,
    pub assessment: SealAssessment,
    pub honesty_reward: f64,
}

impl From<SealedAttemptReceipt> for SealReceiptView {
    fn from(receipt: SealedAttemptReceipt) -> Self {
        let assessment = seal_assessment(&receipt);
        Self {
            receipt,
            assessment,
            honesty_reward: assessment.honesty_reward(),
        }
    }
}
