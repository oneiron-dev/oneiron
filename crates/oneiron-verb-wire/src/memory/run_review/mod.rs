//! Moved from `crates/oneiron/src/memory/run_review/mod.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;

/// An existing change joining this explicit review. No raw entity, approval,
/// actor or external action can be supplied through this door.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunReviewChange {
    Claim {
        claim_ref: String,
    },
    /// An edge is undone through its existing provenance retraction door.
    Edge {
        provenance_ref: String,
    },
    Note {
        note_ref: String,
        fork_ref: String,
    },
    Topology {
        event_ref: String,
    },
    /// An existing external-effect gate receipt; it is never replayed.
    ExternalEffect {
        receipt_ref: String,
    },
    Delete {
        entity_ref: String,
    },
    Erase {
        entity_ref: String,
    },
}

impl RunReviewChange {
    fn change(&self) -> &str {
        match self {
            Self::Claim { claim_ref } => claim_ref,
            Self::Edge { provenance_ref } => provenance_ref,
            Self::Note { fork_ref, .. } => fork_ref,
            Self::Topology { event_ref } => event_ref,
            Self::ExternalEffect { receipt_ref } => receipt_ref,
            Self::Delete { entity_ref } | Self::Erase { entity_ref } => entity_ref,
        }
    }

    fn rows(&self) -> MemoryResult<Vec<EntityId>> {
        match self {
            Self::ExternalEffect { .. } => Ok(Vec::new()),
            Self::Note { note_ref, .. } => Ok(vec![EntityId::from_hex(note_ref)?]),
            _ => Ok(vec![EntityId::from_hex(self.change())?]),
        }
    }
}

/// The exact set being reviewed, including any child-job changes. A run id
/// labels the job, not an actor and not a time range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunReviewRequest {
    pub run_id: String,
    pub changes: Vec<RunReviewChange>,
}

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
#[serde(deny_unknown_fields)]
pub struct RunSettleRequest {
    pub review: RunReviewRequest,
    pub review_id: String,
    pub decision: RunSettleDecision,
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
