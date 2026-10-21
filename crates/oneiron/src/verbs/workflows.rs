//! Typed saved workflows: ordered AGENT_DEF compositions the owner keeps.
use serde::{Deserialize, Serialize};

use super::agents::AgentDefinitionSpec;
use crate::agent_def::workflow::WorkflowDefinition;
use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
    SpawnSpend, SpendScopeId, WorkflowDispatchStatus,
};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::consent::AuthenticatedOwner;
use crate::context_projection::ContextSpec;
use crate::edge::EdgeActorClass;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{ArtifactError, Error};
use crate::federation::{ScopeAxis, ScopeId};
use crate::llm::run_admission::{DeclaredMaximum, LeaseUnit};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND, Memory, MemoryError,
    MemoryResult,
};
use crate::store::GateDecisionId;
use crate::task_verb::HostBinding;
use crate::task_verb::highway_runner::workflow_try::{
    WorkflowBinder, WorkflowFunding, dispatch_bound,
};
use crate::write_envelope::WriteActor;
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
    /// A TASK this run realizes: an idle standard task the owner owns, on
    /// the engine's runner lane, that no try realizes now. The run's root is
    /// its try and settles it when the run ends; the steps stay TASK-less.
    /// Absent, the run realizes no TASK.
    #[serde(default)]
    pub task_ref: Option<EntityId>,
}

/// Starts one run of a saved workflow that realizes a TASK, from a leased
/// agent run and as that agent (FIX 5316). The TASK is an idle standard
/// task the agent owns, on the engine's runner lane, that no try realizes
/// now; the run's root is its try and settles it when the run ends, and
/// the steps stay TASK-less. The try the run's lease holds is its real
/// parent: every step inherits that try's run, project, scope, context and
/// depth bounds, and the run spends under its lease tree. The briefing and
/// `context_spec` are as an owner's dispatch takes them. A retry with the
/// same intent key and request returns the same run; another request under
/// it is refused.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowBoundDispatchRequest {
    pub workflow_ref: EntityId,
    pub intent_key: String,
    pub briefing: String,
    #[serde(default)]
    pub context_spec: Option<ContextSpec>,
    pub task_ref: EntityId,
}

/// Starts one run of a saved workflow that realizes a TASK, as the member
/// whose own verified credential calls (FIX 5316). The TASK is an idle
/// standard task the member owns, on the engine's runner lane, that no try
/// realizes now; the run's root is its try and settles it when the run
/// ends, and the steps stay TASK-less. The member pays: the run is a root
/// whose spend scope opens under the cap they set and were shown, with them
/// as its payer, and a step this host cannot bill them for holds on the
/// owners' payer-needed ask, never on the owner's account. The TASK, the
/// workflow and each step's definition are read on the member's own lane.
/// Each step's context is what the member's own grants read of what
/// `context_spec` asks for: a row they do not read is left out, never
/// refused, and the step is told how many were. A retry with the same
/// intent key, request and terms returns the same run; another under it is
/// refused.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPersonDispatchRequest {
    pub workflow_ref: EntityId,
    pub intent_key: String,
    pub briefing: String,
    #[serde(default)]
    pub context_spec: Option<ContextSpec>,
    pub task_ref: EntityId,
    /// The most the run may spend, as the member set it: more than zero.
    pub cap_units: u64,
    /// The engine's named lease unit; a monetary line names its money unit.
    pub unit: String,
    /// When the member was shown `cap_units`, in host milliseconds.
    pub shown_at_ms: u64,
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
    /// The TASK a bound run realizes: its root is that TASK's try and
    /// settles it when the run ends. `None` for a TASK-less run (FIX 5295).
    #[serde(default)]
    pub task_ref: Option<EntityId>,
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
        task_ref: status
            .attempt
            .task_ref
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?,
    })
}

pub fn dispatch_workflow_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: WorkflowDispatchRequest,
) -> MemoryResult<WorkflowRunView> {
    owner.revalidate(vault)?;
    let request = DispatchAgent {
        target: AgentDispatchTarget::Workflow(input.workflow_ref),
        parent_attempt: None,
        dedupe_key: Some(format!(
            "vault.workflows.dispatch:{}:{}",
            input.workflow_ref.to_hex(),
            input.intent_key
        )),
        run_id: None,
        now: vault.now_recorded_at(),
    };
    let spawn = AgentSpawnContext::default().with_context_spec(
        input
            .context_spec
            .unwrap_or_default()
            .with_briefing(input.briefing),
    );
    // FIX 4391: a run that realizes a TASK has its own admission; without
    // one the dispatch is the one it always was.
    let outcome = match input.task_ref {
        None => AgentDispatcher::new(vault).dispatch_with_context(request, spawn)?,
        Some(task_ref) => dispatch_bound(
            vault,
            &WorkflowBinder::Owner(owner),
            request,
            spawn,
            task_ref,
        )?,
    };
    started_run(outcome)
}

/// The run a saved workflow's dispatch started or found. An agent's bound
/// run whose context widens its parent's slice started nothing: it waits on
/// the widen proposal it filed, and takes its TASK only once the board above
/// approves it (FIX 5350).
fn started_run(outcome: AgentDispatchOutcome) -> MemoryResult<WorkflowRunView> {
    match outcome {
        AgentDispatchOutcome::WorkflowDispatched(status)
        | AgentDispatchOutcome::WorkflowExisting(status) => run_view(&status),
        AgentDispatchOutcome::ProposedWiden(proposal) => Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            format!(
                "the run's context widens its parent's slice, so it waits on widen proposal {} \
                 for the board above; it starts and takes its TASK once the board approves",
                proposal.proposal_id
            ),
            &[
                "Ask the board above to approve the proposal, then repeat this request under \
                 the same intent key to read the run.",
            ],
        )),
        _ => Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "a saved workflow dispatch did not start a workflow run",
        ))
        .into()),
    }
}

/// `self.workflows.dispatch_bound` (FIX 5316): `agent` binds one run of a
/// saved workflow to a TASK under `lease`, the live lease its host proved on
/// the try it runs as. That try is the run's real parent and its run is the
/// run's; nothing of either comes from the request. The intent key is
/// qualified by the agent, its try, the TASK and the workflow, so no other
/// caller's or try's retry names this run. The binder rechecks the lease in
/// the admitting writer.
pub(crate) fn dispatch_workflow_bound_as(
    vault: &Vault,
    agent: WriteActor,
    lease: &HostBinding,
    input: WorkflowBoundDispatchRequest,
) -> MemoryResult<WorkflowRunView> {
    let parent = lease.parent();
    let run_id = AttemptQueue::new(vault)
        .get(parent)?
        .and_then(|record| record.run_id);
    let request = DispatchAgent {
        target: AgentDispatchTarget::Workflow(input.workflow_ref),
        parent_attempt: Some(parent),
        dedupe_key: Some(format!(
            "self.workflows.dispatch_bound:{}:{}:{}:{}:{}",
            agent.entity_ref().to_hex(),
            bytes_to_hex_lower(parent.as_bytes()),
            input.task_ref.to_hex(),
            input.workflow_ref.to_hex(),
            input.intent_key
        )),
        run_id,
        now: vault.now_recorded_at(),
    };
    let spawn = AgentSpawnContext::default().with_context_spec(
        input
            .context_spec
            .unwrap_or_default()
            .with_briefing(input.briefing),
    );
    let binder = WorkflowBinder::Agent {
        actor: agent,
        lease,
    };
    started_run(dispatch_bound(
        vault,
        &binder,
        request,
        spawn,
        input.task_ref,
    )?)
}

/// Domain of a member-funded run's root spend scope id.
const MEMBER_FUNDING_DOMAIN: &[u8] = b"oneiron.workflow.member_funding.v1";

/// `vault.workflows.dispatch_bound` (FIX 5316): `person`, a member by the
/// proof their door bound to their own slip, binds one run of a saved
/// workflow to a TASK as themselves. `memory` is the handle their credential
/// reads through: once no run an earlier request started answers this one,
/// the TASK, the workflow and each step's definition are read on its lane
/// in the admitting writer, never the owner's (FIX 5415). The context the
/// run asks for is never refused: each step reads what the member's own
/// grants read of it, and the rest is left out (FIX 5416). The run is a
/// root the member funds: its spend scope opens in the admitting writer
/// under their terms, with them as payer. The intent key is qualified by
/// the member, the TASK and the workflow, and the terms name the root, so
/// another member's retry never names this run and other terms under the
/// same key are another request. The binder rechecks the member's proof in
/// that writer.
pub fn dispatch_workflow_bound_as_person(
    memory: &Memory<'_>,
    person: &AuthenticatedOwner,
    input: WorkflowPersonDispatchRequest,
) -> MemoryResult<WorkflowRunView> {
    let vault = memory.vault();
    let actor = person.revalidate_person(vault)?;
    if memory.actor() != actor || memory.actor_class() != EdgeActorClass::Human {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "vault.workflows.dispatch_bound binds as the person whose credential calls",
            &["Call it on your own verified human credential."],
        ));
    }
    let funding = member_funding(actor, &input)?;
    let request = DispatchAgent {
        target: AgentDispatchTarget::Workflow(input.workflow_ref),
        parent_attempt: None,
        dedupe_key: Some(format!(
            "vault.workflows.dispatch_bound:{}:{}:{}:{}",
            actor.to_hex(),
            input.task_ref.to_hex(),
            input.workflow_ref.to_hex(),
            input.intent_key
        )),
        run_id: None,
        now: vault.now_recorded_at(),
    };
    let spawn = AgentSpawnContext::default()
        .with_context_spec(
            input
                .context_spec
                .unwrap_or_default()
                .with_briefing(input.briefing),
        )
        .with_spend(SpawnSpend {
            scope: funding.scope.clone(),
        });
    let lane = || memory.read_key();
    let binder = WorkflowBinder::Person {
        person,
        lane: &lane,
        funding: &funding,
        slip: memory
            .presented_credential()
            .map(|slip| slip.claims().slip_id),
        landing: member_landing(vault, memory)?,
    };
    started_run(dispatch_bound(
        vault,
        &binder,
        request,
        spawn,
        input.task_ref,
    )?)
}

/// `vault.workflows.dispatch_bound` on an embedded handle: its own actor
/// binds as the person it is, never as the embedded owner. A handle bound
/// to the slip its caller presented binds on that slip, bound to their
/// proof; any other handle a transport reached is refused, as is an actor
/// that is not a live person.
pub fn dispatch_workflow_bound_as_member(
    memory: &Memory<'_>,
    input: WorkflowPersonDispatchRequest,
) -> MemoryResult<WorkflowRunView> {
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "vault.workflows.dispatch_bound is a live person's own act",
            &["Call it as that person, on their own verified human credential."],
        )
    };
    if memory.actor_class() != EdgeActorClass::Human {
        return Err(refused());
    }
    let vault = memory.vault();
    let actor = memory.actor();
    let person = vault.authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())?;
    let person = match memory.presented_credential() {
        Some(slip) => vault.bind_person_credential(person, slip.clone())?,
        None if memory.native_invocation() => person,
        None => return Err(refused()),
    };
    dispatch_workflow_bound_as_person(memory, &person, input)
}

/// The facet a member's writes land in, for a credential whose facet
/// caveats narrow it (FIX 5421, owner ruling FACET-READ = A), as the one
/// facet a bind may take: the write facet its pairing picked while the
/// credential carries it, else the smallest it carries, else none. `None`
/// for a handle no facet caveat narrows. This door names no session, so
/// none places the write.
fn member_landing(vault: &Vault, memory: &Memory<'_>) -> MemoryResult<Option<ScopeAxis<ScopeId>>> {
    let Some(slip) = memory.presented_credential() else {
        return Ok(None);
    };
    let facets = match &slip.scope().facets {
        ScopeAxis::All => return Ok(None),
        ScopeAxis::Some(facets) => facets.clone(),
        ScopeAxis::Bottom => std::collections::BTreeSet::new(),
    };
    let paired = vault.paired_write_facet(&slip.claims().slip_id)?;
    let landing = paired
        .map(ScopeId)
        .filter(|facet| facets.contains(facet))
        .or_else(|| facets.first().copied());
    Ok(Some(ScopeAxis::Some(landing.into_iter().collect())))
}

/// The terms a member accepted, as the root they fund: a cap of more than
/// zero in a named unit, when they saw it, and the root spend scope this
/// binding and those terms name. The same request and terms reopen the same
/// root; other terms name another.
fn member_funding(
    person: EntityId,
    input: &WorkflowPersonDispatchRequest,
) -> MemoryResult<WorkflowFunding> {
    if input.cap_units == 0 {
        return Err(MemoryError::bad_request(
            "cap_units must be more than zero: set the most this run may spend, as you were shown it",
        ));
    }
    let unit = LeaseUnit::new(input.unit.as_str()).map_err(|_| {
        MemoryError::bad_request(
            "unit must name a lease unit: lowercase ASCII letters, digits, `_` and `-`",
        )
    })?;
    let cap = input.cap_units.to_be_bytes();
    let shown = input.shown_at_ms.to_be_bytes();
    let root = EntityId::derive(
        MEMBER_FUNDING_DOMAIN,
        &[
            person.as_bytes().as_slice(),
            input.task_ref.as_bytes().as_slice(),
            input.workflow_ref.as_bytes().as_slice(),
            input.intent_key.as_bytes(),
            cap.as_slice(),
            unit.as_str().as_bytes(),
            shown.as_slice(),
        ],
    )?;
    Ok(WorkflowFunding {
        scope: SpendScopeId::launch(format!("workflow-member:{}", root.to_hex()))?,
        maximum: DeclaredMaximum {
            units: input.cap_units,
            unit,
        },
        shown_at_ms: input.shown_at_ms,
    })
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
