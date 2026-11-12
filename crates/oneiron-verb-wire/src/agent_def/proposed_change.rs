//! Moved from `crates/oneiron/src/agent_def/proposed_change.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron_contracts::claim::ClaimApprovalStatus;
use oneiron_contracts::claim::ClaimLifecycleStatus;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;
use oneiron_store::batch::builder::ops::BatchOp;
use oneiron_store::gate_decision::types::GateDecisionId;
use oneiron_store::gate_decision::types::GateSystemNoticeRecord;
use oneiron_store::scan_kind::EngineScan;
use oneiron_store::write_envelope::WriteActor;

/// How the owner answered a proposed change to a stored definition.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProposedAgentDefinitionChangeDecision {
    /// The proposal became the stored definition's next version.
    Approved,
    /// The stored definition stayed as it was.
    Rejected,
}
