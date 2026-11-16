//! Typed custom AGENT_DEF authoring. Authorship is the caller's, never input.
use serde::{Deserialize, Serialize};

use crate::agent_def::{AgentDefinition, switches_off_or_narrows};
use crate::claim::ClaimApprovalStatus;
use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult};
use crate::{EntityId, TimeRange, Vault};

pub use crate::agent_def::ProposedAgentDefinitionChangeDecision;
pub use crate::agent_def::{
    AgentMadeBy, AgentMadeByRequest, AgentTreePauseReceipt, AgentTreePauseRequest,
    AgentTreeResumeReceipt, AgentTreeResumeRequest,
};
pub use crate::code_run::workflow_operations::{
    AgentCeilingInput, AgentDefinitionSpec, AgentMcpInput, AgentScopeInput, AgentSkillInput,
};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentDefinitionCreateRequest {
    pub agent_def_ref: EntityId,
    pub definition: AgentDefinitionSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentDefinitionUpdateRequest {
    pub agent_def_ref: EntityId,
    pub expected_version: String,
    pub definition: AgentDefinitionSpec,
}

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::agents::{
    AgentDefinitionLifecycle, AgentDefinitionRequest, ProposedAgentDefinitionChangeApproveRequest,
    ProposedAgentDefinitionChangeRejectRequest, ProposedAgentDefinitionChangesRequest,
};

/// The saved revision; its ceiling is a self-limit, never a dispatch grant.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentDefinitionView {
    pub agent_def_ref: EntityId,
    pub definition: AgentDefinitionSpec,
    pub approval_status: ClaimApprovalStatus,
    pub lifecycle_status: AgentDefinitionLifecycle,
    /// What the agent made, transitively, on the answer to the owner's edit
    /// that switched it off or narrowed it: switching off does not cascade,
    /// so these keep running (ARCH-0053 #author-off-no-cascade). Absent on
    /// every other answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub made_by: Option<AgentMadeBy>,
}

fn view(agent_def_ref: EntityId, definition: &AgentDefinition) -> AgentDefinitionView {
    AgentDefinitionView {
        agent_def_ref,
        definition: definition.into(),
        approval_status: definition.approval_status,
        lifecycle_status: definition.lifecycle_status.into(),
        made_by: None,
    }
}

fn load(vault: &Vault, id: EntityId) -> MemoryResult<AgentDefinition> {
    vault.get_agent_definition(&id)?.ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "agent definition not found",
            &["Name an existing AGENT_DEF."],
        )
    })
}

pub fn create_agent_definition_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AgentDefinitionCreateRequest,
) -> MemoryResult<AgentDefinitionView> {
    let definition = input.definition.definition(owner.revalidate(vault)?);
    let now = crate::unix_seconds_now();
    vault.create_agent_definition_as(
        owner,
        &input.agent_def_ref,
        &definition,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(view(input.agent_def_ref, &definition))
}

pub fn update_agent_definition_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AgentDefinitionUpdateRequest,
) -> MemoryResult<AgentDefinitionView> {
    owner.revalidate(vault)?;
    let prior = load(vault, input.agent_def_ref)?;
    let mut definition = prior.clone();
    input.definition.apply(&mut definition);
    let now = crate::unix_seconds_now();
    vault.update_agent_definition_at_version_as(
        owner,
        &input.agent_def_ref,
        &input.expected_version,
        &definition,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    let mut answer = view(input.agent_def_ref, &definition);
    if switches_off_or_narrows(&prior, &definition) {
        answer.made_by = Some(vault.agent_made_by_as(owner, &input.agent_def_ref)?);
    }
    Ok(answer)
}

/// `vault.agents.made_by.get`: what one agent made, transitively, and what
/// each is doing now (ARCH-0053 #author-off-no-cascade).
pub fn read_agent_made_by_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AgentMadeByRequest,
) -> MemoryResult<AgentMadeBy> {
    vault
        .agent_made_by_as(owner, &input.agent_def_ref)
        .map_err(MemoryError::from)
}

/// `vault.agents.pause_tree`: the owner pauses what one agent made that
/// waits, in one act with one receipt (ARCH-0053 #author-off-no-cascade).
pub fn pause_agent_tree_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AgentTreePauseRequest,
) -> MemoryResult<AgentTreePauseReceipt> {
    vault
        .pause_agent_tree_as(owner, &input.agent_def_ref)
        .map_err(MemoryError::from)
}

/// `vault.agents.resume_tree`: the owner undoes one tree pause.
pub fn resume_agent_tree_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AgentTreeResumeRequest,
) -> MemoryResult<AgentTreeResumeReceipt> {
    vault
        .resume_agent_tree_as(owner, &input.pause_ref)
        .map_err(MemoryError::from)
}

pub fn read_agent_definition_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AgentDefinitionRequest,
) -> MemoryResult<AgentDefinitionView> {
    owner.revalidate(vault)?;
    Ok(view(
        input.agent_def_ref,
        &load(vault, input.agent_def_ref)?,
    ))
}

/// One proposed change waiting for the owner, beside the stored definition
/// it would replace.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProposedAgentDefinitionChangeView {
    /// The proposal row and the definition it holds.
    pub proposal: AgentDefinitionView,
    /// The stored definition it would replace.
    pub target_ref: EntityId,
    /// That definition as it stands now; `None` when no row stands there.
    pub target: Option<AgentDefinitionView>,
    /// The agent that put the proposal.
    pub proposed_by: Option<EntityId>,
    /// The door the proposal was put through.
    pub proposed_through: Option<String>,
}

/// The proposed changes waiting for the owner.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProposedAgentDefinitionChanges {
    pub changes: Vec<ProposedAgentDefinitionChangeView>,
}

/// What the owner's answer to a proposed change wrote. The proposal row is
/// deleted; the gate decision at `receipt_ref` records the answer.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProposedAgentDefinitionChangeSettlementView {
    pub proposal_ref: EntityId,
    pub target_ref: EntityId,
    pub decision: ProposedAgentDefinitionChangeDecision,
    pub proposal_version: String,
    /// The stored definition's version before the answer; `None` when a
    /// rejected proposal named a row that no longer stands.
    pub target_version_before: Option<String>,
    /// The stored definition as the answer left it; `None` as above.
    pub target: Option<AgentDefinitionView>,
    /// The agent that put the proposal.
    pub proposed_by: Option<EntityId>,
    /// The door the proposal was put through.
    pub proposed_through: Option<String>,
    /// The gate decision that records the answer, as `gate:<id hex>`.
    pub receipt_ref: String,
}

fn settlement_view(
    settlement: crate::agent_def::ProposedAgentDefinitionChangeSettlement,
) -> ProposedAgentDefinitionChangeSettlementView {
    let change = settlement.change;
    ProposedAgentDefinitionChangeSettlementView {
        proposal_ref: change.proposal,
        target_ref: change.target,
        decision: settlement.decision,
        proposal_version: change.definition.version,
        target_version_before: settlement.target_version_before,
        target: settlement
            .target_after
            .as_ref()
            .map(|after| view(change.target, after)),
        proposed_by: change.proposed_by,
        proposed_through: change.proposed_through,
        receipt_ref: settlement.receipt_ref,
    }
}

/// `vault.agents.proposed_changes.list`: the proposed changes to stored
/// definitions waiting for the owner.
///
/// # Errors
///
/// The owner proof's refusal, and a stored definition that does not decode.
pub fn list_proposed_agent_definition_changes_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ProposedAgentDefinitionChangesRequest,
) -> MemoryResult<ProposedAgentDefinitionChanges> {
    let changes = vault
        .proposed_agent_definition_changes_as(owner, input.target_ref.as_ref())?
        .into_iter()
        .map(|(change, current)| ProposedAgentDefinitionChangeView {
            proposal: view(change.proposal, &change.definition),
            target_ref: change.target,
            target: current.as_ref().map(|current| view(change.target, current)),
            proposed_by: change.proposed_by,
            proposed_through: change.proposed_through,
        })
        .collect();
    Ok(ProposedAgentDefinitionChanges { changes })
}

/// `vault.agents.proposed_changes.approve`: the stored definition takes the
/// proposal as its next version, and the proposal row is deleted.
///
/// # Errors
///
/// The owner proof's refusal; no proposal waiting at `proposal_ref`; a
/// stored definition no longer at `expected_target_version`; the refusals
/// the owner's own update of the stored definition meets.
pub fn approve_proposed_agent_definition_change_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ProposedAgentDefinitionChangeApproveRequest,
) -> MemoryResult<ProposedAgentDefinitionChangeSettlementView> {
    Ok(settlement_view(
        vault.approve_proposed_agent_definition_change_as(
            owner,
            &input.proposal_ref,
            &input.expected_target_version,
        )?,
    ))
}

/// `vault.agents.proposed_changes.reject`: the stored definition stays as it
/// is, and the proposal row is deleted.
///
/// # Errors
///
/// The owner proof's refusal; no proposal waiting at `proposal_ref`.
pub fn reject_proposed_agent_definition_change_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ProposedAgentDefinitionChangeRejectRequest,
) -> MemoryResult<ProposedAgentDefinitionChangeSettlementView> {
    Ok(settlement_view(
        vault.reject_proposed_agent_definition_change_as(owner, &input.proposal_ref)?,
    ))
}
