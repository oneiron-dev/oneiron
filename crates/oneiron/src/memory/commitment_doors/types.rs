//! Public commitment shapes. IDs are caller references, never raw storage keys.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentObligorKind {
    Owner,
    Agent,
    ThirdParty,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitmentObligor {
    pub kind: CommitmentObligorKind,
    pub entity_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitmentContent {
    pub text: String,
    #[serde(default)]
    pub payload_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStrength {
    StatedIntention,
    Decision,
    Commitment,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Open,
    Fulfilled,
    Released,
    Lapsed,
    Superseded,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentBirthKind {
    RunTreeNode,
    Brief,
    SurfaceAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitmentBirthProvenance {
    pub kind: CommitmentBirthKind,
    pub reference: String,
}

/// The engine's shared recurrence vocabulary, projected without a second evaluator.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommitmentSchedule {
    Once {
        due: u64,
    },
    Interval {
        period: u64,
        anchor: u64,
    },
    Quota {
        count: u32,
        window: CommitmentQuotaWindow,
    },
    Rrule {
        rrule_string: String,
        tz: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommitmentQuotaWindow {
    IsoWeek { tz: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitmentCreateRequest {
    #[serde(default)]
    pub id: Option<String>,
    pub obligor: CommitmentObligor,
    pub beneficiary: String,
    pub content: CommitmentContent,
    pub schedule: CommitmentSchedule,
    #[serde(default)]
    pub lead_seconds: Option<u64>,
    pub strength: CommitmentStrength,
    pub birth_provenance: CommitmentBirthProvenance,
    /// When the promise was made, independently of when it was learned.
    pub occurred_at: u64,
    #[serde(default)]
    pub learned_at: Option<u64>,
    pub evidence_turn_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitmentRefRequest {
    pub commitment_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitmentCloseRequest {
    pub commitment_ref: String,
    /// Readable witness TURNs supporting this explicit lifecycle decision.
    pub evidence_turn_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommitmentFulfillmentSource {
    UserDone,
    BriefCompletion { brief_ref: String },
    ChecklistTick,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitmentFulfillRequest {
    pub commitment_ref: String,
    pub source: CommitmentFulfillmentSource,
    pub evidence_turn_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CommitmentOccurrence {
    pub due_at: u64,
    pub window_start: u64,
    pub window_end: u64,
    pub ordinal: u32,
}

/// Projected from the committed row, not from the current request or retry clock.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CommitmentLifecycleReceipt {
    pub fulfillment_source: Option<CommitmentFulfillmentSource>,
    pub commitment_ref: String,
    pub status: CommitmentStatus,
    pub learned_at: u64,
    pub evidence_turn_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CommitmentView {
    pub commitment_ref: String,
    pub obligor: CommitmentObligor,
    pub beneficiary: String,
    pub content: CommitmentContent,
    pub schedule: CommitmentSchedule,
    pub lead_seconds: Option<u64>,
    pub strength: CommitmentStrength,
    pub status: CommitmentStatus,
    pub birth_provenance: CommitmentBirthProvenance,
    pub series_ref: Option<String>,
    pub occurrence: Option<CommitmentOccurrence>,
    pub occurred_at: u64,
    pub learned_at: u64,
    pub evidence_turn_refs: Vec<String>,
    pub receipt: CommitmentLifecycleReceipt,
}

/// `stored_awaiting_approval`: a Proposed or stale series is stored with no
/// due row until it is approved (FIX 5993).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CommitmentIndexOutcome {
    Indexed { project_at: u64, next_due: u64 },
    StoredRrule { route: String },
    StoredAwaitingApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CommitmentCreateReceipt {
    pub commitment: CommitmentView,
    pub index: CommitmentIndexOutcome,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentWakePhase {
    Lead,
    Due,
}

/// Observation only. Approval remains the owner's existing run-approval door.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CommitmentWakeProposal {
    pub proposal_ref: String,
    pub instance_ref: String,
    pub phase: CommitmentWakePhase,
    pub fire_at: u64,
    pub due_at: u64,
    pub occurred_at: u64,
    pub idempotency_key: String,
    pub trigger_ref: String,
    pub verb: String,
    pub channel: String,
    pub target: String,
    pub on_behalf_of: Option<String>,
    pub content_ref: Option<String>,
    pub dedupe_key: Option<String>,
    pub approval: String,
}
