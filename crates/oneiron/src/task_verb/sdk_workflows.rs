//! Typed saved workflows: ordered AGENT_DEF compositions the owner keeps.
use serde::{Deserialize, Serialize};

use crate::agent_def::workflow::WorkflowDefinition;
use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult};
use crate::{EntityId, Vault};

/// A new composition at a new WORKFLOW id. Each step names a live AGENT_DEF;
/// an occupied id is refused, never edited.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSaveRequest {
    pub workflow_ref: EntityId,
    pub name: String,
    pub steps: Vec<EntityId>,
}

/// An edit of exactly the revision the caller read; the door assigns the next.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowUpdateRequest {
    pub workflow_ref: EntityId,
    pub expected_revision: u64,
    pub name: String,
    pub steps: Vec<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRequest {
    pub workflow_ref: EntityId,
}

/// The saved revision. Steps are definition refs; a dispatch captures each
/// step's definition revision when it admits the run.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkflowView {
    pub workflow_ref: EntityId,
    pub name: String,
    pub steps: Vec<EntityId>,
    pub revision: u64,
    pub forked_from: Option<EntityId>,
}

fn view(workflow_ref: EntityId, definition: WorkflowDefinition) -> WorkflowView {
    WorkflowView {
        workflow_ref,
        name: definition.name,
        steps: definition.steps,
        revision: definition.revision,
        forked_from: definition.forked_from,
    }
}

pub fn save_workflow_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: WorkflowSaveRequest,
) -> MemoryResult<WorkflowView> {
    let definition = WorkflowDefinition::new(input.name, input.steps)?;
    vault.create_workflow_as(
        owner,
        &input.workflow_ref,
        &definition,
        crate::unix_seconds_now(),
    )?;
    Ok(view(input.workflow_ref, definition))
}

pub fn update_workflow_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: WorkflowUpdateRequest,
) -> MemoryResult<WorkflowView> {
    let definition = vault.update_workflow_as(
        owner,
        &input.workflow_ref,
        input.expected_revision,
        &input.name,
        input.steps,
        crate::unix_seconds_now(),
    )?;
    Ok(view(input.workflow_ref, definition))
}

pub fn read_workflow_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: WorkflowRequest,
) -> MemoryResult<WorkflowView> {
    owner.revalidate(vault)?;
    let definition = vault.get_workflow(&input.workflow_ref)?.ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "workflow not found",
            &["Name an existing WORKFLOW."],
        )
    })?;
    Ok(view(input.workflow_ref, definition))
}
