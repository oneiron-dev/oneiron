//! Typed saved workflows: ordered AGENT_DEF compositions the owner keeps.
use serde::{Deserialize, Serialize};

use super::sdk_agents::AgentDefinitionSpec;
use crate::agent_def::workflow::WorkflowDefinition;
use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
    WorkflowDispatchStatus,
};
use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::context_projection::ContextSpec;
use crate::error::{ArtifactError, Error};
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

/// Starts one run of a saved workflow as the owner: a root with no parent,
/// through the ordinary dispatch admission for every step. The briefing is
/// the work each step reads and grants no read scope; `context_spec` is a
/// request, resolved against each step's own scope. A retry with the same
/// intent key returns the same run; another request under it is refused.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDispatchRequest {
    pub workflow_ref: EntityId,
    pub intent_key: String,
    pub briefing: String,
    #[serde(default)]
    pub context_spec: Option<ContextSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRunRequest {
    pub root_attempt_ref: EntityId,
}

/// One step as the run captured it at admission. `agent_def_ref` is the
/// definition dispatched, which an attenuated fork can make differ from
/// the requested one; `definition` holds its captured version, scope and
/// ceiling, never a later edit.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkflowStepCapture {
    pub requested_agent_ref: EntityId,
    pub agent_def_ref: EntityId,
    pub definition: AgentDefinitionSpec,
}

/// A settled step's attempt and the result it pinned.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkflowStepRun {
    pub ordinal: usize,
    pub requested_agent_ref: EntityId,
    pub dispatched_agent_ref: EntityId,
    pub attempt_ref: EntityId,
    pub result_ref: String,
}

/// A run of a saved workflow: its inert root attempt, the step attempt
/// active now, every step's captured definition and the steps settled so far.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkflowRunView {
    pub workflow_ref: EntityId,
    pub workflow_revision: u64,
    pub root_attempt_ref: EntityId,
    pub active_attempt_ref: EntityId,
    pub steps: Vec<WorkflowStepCapture>,
    pub results: Vec<WorkflowStepRun>,
}

fn attempt_ref(id: AttemptId) -> MemoryResult<EntityId> {
    Ok(EntityId::from_bytes(*id.as_bytes())?)
}

fn run_view(status: &WorkflowDispatchStatus) -> MemoryResult<WorkflowRunView> {
    let steps = status
        .definition
        .steps
        .iter()
        .zip(&status.captured_steps)
        .map(|(requested, frozen)| {
            Ok(WorkflowStepCapture {
                requested_agent_ref: *requested,
                agent_def_ref: frozen.target.agent_definition_ref()?,
                definition: (&frozen.definition).into(),
            })
        })
        .collect::<MemoryResult<_>>()?;
    let results = status
        .results
        .iter()
        .map(|result| {
            Ok(WorkflowStepRun {
                ordinal: result.ordinal,
                requested_agent_ref: EntityId::from_hex(&result.requested_agent)?,
                dispatched_agent_ref: EntityId::from_hex(&result.dispatched_agent)?,
                attempt_ref: attempt_ref(result.attempt_id)?,
                result_ref: result.result_ref.clone(),
            })
        })
        .collect::<MemoryResult<_>>()?;
    Ok(WorkflowRunView {
        workflow_ref: status.workflow_ref,
        workflow_revision: status.definition.revision,
        root_attempt_ref: attempt_ref(status.attempt.id)?,
        active_attempt_ref: attempt_ref(status.active_step)?,
        steps,
        results,
    })
}

pub fn dispatch_workflow_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: WorkflowDispatchRequest,
) -> MemoryResult<WorkflowRunView> {
    owner.revalidate(vault)?;
    let outcome = AgentDispatcher::new(vault).dispatch_with_context(
        DispatchAgent {
            target: AgentDispatchTarget::Workflow(input.workflow_ref),
            parent_attempt: None,
            dedupe_key: Some(format!(
                "vault.workflows.dispatch:{}:{}",
                input.workflow_ref.to_hex(),
                input.intent_key
            )),
            run_id: None,
            now: vault.now_recorded_at(),
        },
        AgentSpawnContext::default().with_context_spec(
            input
                .context_spec
                .unwrap_or_default()
                .with_briefing(input.briefing),
        ),
    )?;
    match outcome {
        AgentDispatchOutcome::WorkflowDispatched(status)
        | AgentDispatchOutcome::WorkflowExisting(status) => run_view(&status),
        _ => Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "a saved workflow dispatch did not start a workflow run",
        ))
        .into()),
    }
}

pub fn read_workflow_run_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: WorkflowRunRequest,
) -> MemoryResult<WorkflowRunView> {
    owner.revalidate(vault)?;
    let root = AttemptId::from_bytes(input.root_attempt_ref.as_bytes())?;
    run_view(&AgentDispatcher::new(vault).workflow_status(root)?)
}
