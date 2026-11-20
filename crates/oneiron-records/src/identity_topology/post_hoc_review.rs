//! Moved from `crates/oneiron/src/identity_topology/post_hoc_review.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The domain a selection's digest derives under.
pub const SELECTION_DIGEST_DOMAIN: &[u8] = b"oneiron/identity-topology/post-hoc-audit-selection/v1";

/// The ramp-shaped scope of the reviewed decision: its op kind, the registry
/// class of its primary target, and the opaque handle of its deciding actor
/// (the proposer-scope handle; unattributed when no actor was bound).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyAuditScope {
    pub op_kind: String,
    pub target_class: String,
    pub actor: String,
}

/// Who decided the reviewed decision, as its seal names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyAuditDecider {
    /// The owner, by proof or by an answer the engine sealed for him.
    Owner,
    /// An agent within its Grant.
    Agent,
    /// The engine's own inference under a named cause.
    Engine,
}

/// One eligible decision's durable review candidate, written in the
/// decision's own writer. Ids and digests only, never claim or evidence text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyAuditIntent {
    pub schema_version: u16,
    /// `H(domain, event, core_digest)`: the idempotency key, no authority.
    pub audit_id: [u8; 32],
    /// The reviewed decision's type-76 record.
    pub event: EntityId,
    /// The core digest its seal binds.
    pub core_digest: [u8; 32],
    /// Its signed admission disposition.
    pub disposition: EntityId,
    pub scope: TopologyAuditScope,
    pub decided_by: TopologyAuditDecider,
    /// Every record the decision names, each once (`decision_records`):
    /// its participants, the claims and edge endpoints its reassignment map
    /// routes, a facet's forks, then its evidence refs. The review reads every
    /// one, and an erase of any of them drops the candidate.
    pub subjects: Vec<EntityId>,
    /// The agent-dispatch attempt whose run made the decision, when its
    /// writer was bound to one.
    pub origin_attempt: Option<[u8; 16]>,
    pub created_at: u64,
}

/// What an answer is (L08-A 20:15): a recipe's declared model judgment, its
/// scorer in the decision receipt and its prompt in the recipe revision, or
/// an outcome the engine settled with no judgment (its own reads, a refused
/// question, a moved revision). Neither is an owner decision, a human
/// acceptance or a verified success or failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyAuditEvidence {
    ModelJudgment,
    EngineSettled,
}

impl TopologyAuditEvidence {
    /// The stable name a receipt carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModelJudgment => "model_judgment",
            Self::EngineSettled => "engine_settled",
        }
    }
}

/// What one review found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyAuditOutcome {
    /// The recipe found the evidence supports the decision. Model opinion,
    /// never ground truth and never an owner's approval.
    Pass,
    /// The recipe found the evidence does not support it.
    Concern,
    /// No judgment: the recipe abstained, refused the case, or the decision
    /// could not be read as declared.
    Unknown,
    /// The decision was undone or superseded before its review.
    Obsolete,
}

impl TopologyAuditOutcome {
    /// The stable name a receipt carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Concern => "concern",
            Self::Unknown => "unknown",
            Self::Obsolete => "obsolete",
        }
    }
}

/// What a concern did to the reviewed decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TopologyAuditCorrection {
    /// The Coach's undo landed: its counter-event.
    Undone { event: EntityId },
    /// The undo door refused it, or the decision was the owner's own: an
    /// engine code.
    Refused { reason: String },
}

/// The one result of one reviewed candidate, append-only: the leased Coach
/// job writes it, with its correction, in one writer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyAuditResult {
    pub audit_id: [u8; 32],
    /// [`TopologyAuditSelection::digest`] of the selection it reviewed.
    pub selection_digest: [u8; 32],
    /// The Coach attempt that reviewed.
    pub review_attempt: [u8; 16],
    /// The reviewing actor; none for a result no recipe judged.
    pub reviewer: Option<EntityId>,
    /// The ladder's decision receipt, as JSON.
    pub decision_receipt: Option<String>,
    /// The core digest the review read.
    pub reviewed_core: [u8; 32],
    /// The seal revision of the decision the review read: the `seen` a
    /// correction's undo is checked against.
    pub reviewed_revision: [u8; 32],
    /// The records the review read.
    pub evidence_refs: Vec<EntityId>,
    pub outcome: TopologyAuditOutcome,
    pub evidence: TopologyAuditEvidence,
    /// An engine code, never model text.
    pub reason: String,
    pub correction: Option<TopologyAuditCorrection>,
    pub completed_at: u64,
}
#[cfg(feature = "sync")]
pub mod home;
