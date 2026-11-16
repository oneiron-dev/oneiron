//! Moved from `crates/oneiron/src/memory/run_review/mod.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunChangeVerdict {
    Landed,
    Rejected,
    Waiting,
    LetGo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunChangeOutcome {
    pub change: String,
    pub verdict: RunChangeVerdict,
    pub receipt: Option<String>,
}

/// Derived text with its source refs. It is never persisted as a memory row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunReviewExplainer {
    pub text: String,
    pub read_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunReview {
    pub run_id: String,
    pub review_id: String,
    pub changes: Vec<RunChangeOutcome>,
    pub explainer: RunReviewExplainer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunSettleDecision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum RunAnsweredBy {
    Word { word_ref: String },
    Row { row: String },
    Grant { grant: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum RunSettlementKind {
    ProposalOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunSettlementReason {
    OwnerApproved,
    OwnerRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunSettlement {
    pub kind: RunSettlementKind,
    pub run_id: String,
    pub receipt: String,
    pub changes: Vec<RunChangeOutcome>,
    pub verdict: RunChangeVerdict,
    pub answered_by: RunAnsweredBy,
    pub reason: RunSettlementReason,
    pub summary: String,
    pub revert_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunSettlementRequest {
    pub run_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevertRunRequest {
    /// The job id or the settlement's run: handle.
    pub run_id: String,
    /// Absent means all; a present list selects exact change refs, even one.
    #[serde(default)]
    pub changes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunCompensation {
    pub change: String,
    pub receipt: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunNotUndoneReason {
    OneWay,
    BackupOnly,
    Dependent,
    NotSelected,
    NotLanded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunNotUndone {
    pub change: String,
    pub reason: RunNotUndoneReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RevertRunOutcome {
    pub run_id: String,
    pub compensated: Vec<RunCompensation>,
    pub not_undone: Vec<RunNotUndone>,
}
