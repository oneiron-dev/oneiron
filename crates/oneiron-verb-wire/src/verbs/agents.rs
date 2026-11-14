//! Moved from `crates/oneiron/src/verbs/agents.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::agent_def::made_by::AgentMadeBy;
pub use crate::agent_def::proposed_change::ProposedAgentDefinitionChangeDecision;
pub use crate::code_run::dispatcher::workflow_dispatch::operations::agent_definition::AgentCeilingInput;
pub use crate::code_run::dispatcher::workflow_dispatch::operations::agent_definition::AgentMcpInput;
pub use crate::code_run::dispatcher::workflow_dispatch::operations::agent_definition::AgentScopeInput;
pub use crate::code_run::dispatcher::workflow_dispatch::operations::agent_definition::AgentSkillInput;
use oneiron_contracts::claim::ClaimLifecycleStatus;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentDefinitionRequest {
    pub agent_def_ref: EntityId,
}

/// The persisted currentness axis, using its canonical wire spellings.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentDefinitionLifecycle {
    Active,
    Superseded,
    Retracted,
}

impl From<ClaimLifecycleStatus> for AgentDefinitionLifecycle {
    fn from(status: ClaimLifecycleStatus) -> Self {
        match status {
            ClaimLifecycleStatus::Active => Self::Active,
            ClaimLifecycleStatus::Superseded => Self::Superseded,
            ClaimLifecycleStatus::Retracted => Self::Retracted,
        }
    }
}

/// The owner's approval of one proposed change to a stored definition.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposedAgentDefinitionChangeApproveRequest {
    /// The proposal row, as `vault.agents.proposed_changes.list` names it.
    pub proposal_ref: EntityId,
    /// The stored definition's version the owner read beside the proposal.
    /// The approval is refused once the stored definition has moved on.
    pub expected_target_version: String,
}

/// The owner's rejection of one proposed change to a stored definition.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposedAgentDefinitionChangeRejectRequest {
    /// The proposal row, as `vault.agents.proposed_changes.list` names it.
    pub proposal_ref: EntityId,
}

/// Which proposed changes the owner lists.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposedAgentDefinitionChangesRequest {
    /// Only the changes proposed to this stored definition; every waiting
    /// change when absent.
    #[serde(default)]
    pub target_ref: Option<EntityId>,
}
