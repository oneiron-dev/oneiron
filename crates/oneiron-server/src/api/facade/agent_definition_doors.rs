//! Custom definitions, saved workflows and workspace onboarding, with the
//! caller's own proof.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::{
    self, AgentDefinitionCreateRequest, AgentDefinitionRequest, AgentDefinitionUpdateRequest,
    AgentDefinitionView, WorkflowDispatchRequest, WorkflowPersonDispatchRequest, WorkflowRequest,
    WorkflowRunRequest, WorkflowRunView, WorkflowSaveRequest, WorkflowUpdateRequest, WorkflowView,
    WorkspaceMemberOnboardRequest, WorkspacePresetReceipt, WorkspacePresetRequest,
    WorkspaceRosterRequest,
};
use oneiron::workspace_roster::{MemberOnboardingOutcome, WorkspaceRosterEntry};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{MaybeListed, owner_proof};
use super::shared_act_doors::{as_person_naming, person};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_agents_create(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AgentDefinitionCreateRequest,
) -> MaybeListed<AgentDefinitionView> {
    const VERB: &str = "vault.agents.create";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::create_agent_definition_as(server.vault(), &owner, input),
        |saved| Some(vec![saved.agent_def_ref]),
    )
    .await
}

pub(crate) async fn vault_agents_update(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AgentDefinitionUpdateRequest,
) -> MaybeListed<AgentDefinitionView> {
    const VERB: &str = "vault.agents.update";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::update_agent_definition_as(server.vault(), &owner, input),
        |saved| Some(vec![saved.agent_def_ref]),
    )
    .await
}

pub(crate) async fn vault_agents_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AgentDefinitionRequest,
) -> MaybeListed<AgentDefinitionView> {
    const VERB: &str = "vault.agents.get";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::read_agent_definition_as(server.vault(), &owner, input),
        |saved| Some(vec![saved.agent_def_ref]),
    )
    .await
}

/// A saved workflow names itself and the definitions its steps compose.
fn workflow_rows(saved: &WorkflowView) -> Option<Vec<oneiron::EntityId>> {
    Some(
        std::iter::once(saved.workflow_ref)
            .chain(saved.steps.iter().copied())
            .collect(),
    )
}

pub(crate) async fn vault_workflows_save(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkflowSaveRequest,
) -> MaybeListed<WorkflowView> {
    const VERB: &str = "vault.workflows.save";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::save_workflow_as(server.vault(), &owner, input),
        workflow_rows,
    )
    .await
}

pub(crate) async fn vault_workflows_update(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkflowUpdateRequest,
) -> MaybeListed<WorkflowView> {
    const VERB: &str = "vault.workflows.update";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::update_workflow_as(server.vault(), &owner, input),
        workflow_rows,
    )
    .await
}

pub(crate) async fn vault_workflows_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkflowRequest,
) -> MaybeListed<WorkflowView> {
    const VERB: &str = "vault.workflows.get";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::read_workflow_as(server.vault(), &owner, input),
        workflow_rows,
    )
    .await
}

/// A run names its workflow, every step attempt it has started and the
/// definitions those steps captured.
fn workflow_run_rows(run: &WorkflowRunView) -> Option<Vec<oneiron::EntityId>> {
    let mut rows = vec![
        run.workflow_ref,
        run.root_attempt_ref,
        run.active_attempt_ref,
    ];
    for step in &run.steps {
        rows.extend([step.requested_agent_ref, step.agent_def_ref]);
    }
    for result in &run.results {
        rows.extend([result.dispatched_agent_ref, result.attempt_ref]);
    }
    rows.sort_unstable();
    rows.dedup();
    Some(rows)
}

pub(crate) async fn vault_workflows_dispatch(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkflowDispatchRequest,
) -> MaybeListed<WorkflowRunView> {
    const VERB: &str = "vault.workflows.dispatch";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::dispatch_workflow_as(server.vault(), &owner, input),
        workflow_run_rows,
    )
    .await
}

/// The proof of a member acting on their own behalf at a door that binds it
/// (FIX 5316): the vault owner as the owner door admits him, or any other
/// live person on their own verified human slip, bound to it so the engine
/// rechecks that slip in the acting writer, as the world-settings door binds
/// a holder's. The proof lends a member no owner authority. A managed vault
/// admits only its attested owner, a host action only the owner it acts as,
/// and an invitee's slip is no member's.
pub(super) fn member_proof(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<AuthenticatedOwner> {
    super::owner_binding::host_preflight(server, auth)?;
    if let Ok(owner) = crate::api::owner_routes::owner(auth, server) {
        return Ok(owner);
    }
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is a live person's own act"),
            &["Present your own verified human credential."],
        )
    };
    if server.managed_issuer.is_some()
        || auth.managed_owner().is_some()
        || crate::api::host_action::host_action_of(server.vault(), auth).is_some()
    {
        return Err(refused());
    }
    let slip = auth
        .verified_slip()
        .filter(|_| auth.actor_class() == Some("human"))
        .ok_or_else(refused)?;
    let principal = auth.principal_ref().ok_or_else(refused)?;
    let actor = EntityId::from_hex(principal).map_err(|_| refused())?;
    if slip.claims().holder_ref != actor.to_hex() || slip.claims().invitation_ref.is_some() {
        return Err(refused());
    }
    let person = server
        .vault()
        .authenticate_owner(actor, principal, true, GateDecisionId::now())
        .map_err(|_| refused())?;
    server
        .vault()
        .bind_person_credential(person, slip.clone())
        .map_err(|_| refused())
}

/// `vault.workflows.dispatch_bound` (FIX 5316): a member binds one run of a
/// saved workflow to a TASK they own, as themselves, under the funding terms
/// they accepted. The engine reads on the member's own credential handle
/// (`caller`'s), rechecks their bound proof in the admitting writer and
/// opens the run's root spend scope with them as payer. The answer lists
/// the TASK beside the run's rows.
pub(crate) async fn vault_workflows_dispatch_bound(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: WorkflowPersonDispatchRequest,
) -> MaybeListed<WorkflowRunView> {
    const VERB: &str = "vault.workflows.dispatch_bound";
    let task = input.task_ref;
    let lane = auth.clone();
    as_person_naming(
        server,
        VERB,
        member_proof(server, auth, VERB),
        move |server, member| {
            let memory =
                crate::api::credential_memory(server.vault(), Some(&lane), caller.0, caller.1)
                    .at(lane.locality());
            sdk::dispatch_workflow_bound_as_person(&memory, &member, input)
        },
        move |run| {
            let mut rows = workflow_run_rows(run)?;
            rows.push(task);
            rows.sort_unstable();
            rows.dedup();
            Some(rows)
        },
    )
    .await
}

pub(crate) async fn vault_workflows_status(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkflowRunRequest,
) -> MaybeListed<WorkflowRunView> {
    const VERB: &str = "vault.workflows.status";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::read_workflow_run_as(server.vault(), &owner, input),
        workflow_run_rows,
    )
    .await
}

pub(crate) async fn vault_workspace_establish(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkspacePresetRequest,
) -> MaybeListed<WorkspacePresetReceipt> {
    const VERB: &str = "vault.workspace.establish";
    let mut rows = vec![input.preset.org_ref, input.preset.house_actor_ref];
    rows.extend(input.preset.house_identity_ref);
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, holder| sdk::establish_workspace_as(server.vault(), &holder, input),
        |_| Some(rows),
    )
    .await
}

pub(crate) async fn vault_workspace_members_onboard(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkspaceMemberOnboardRequest,
) -> MaybeListed<MemberOnboardingOutcome> {
    const VERB: &str = "vault.workspace.members.onboard";
    let mut rows = vec![
        input.workspace.org_ref,
        input.workspace.house_actor_ref,
        input.work_facet_ref,
    ];
    rows.extend(input.workspace.house_identity_ref);
    match &input.companion {
        sdk::WorkspaceCompanionInput::Work {
            work_facet_ref,
            profile_grant_ref,
            ..
        } => {
            rows.extend([*work_facet_ref, *profile_grant_ref]);
        }
        sdk::WorkspaceCompanionInput::Bring { work_facet_ref, .. } => rows.push(*work_facet_ref),
    }
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, holder| sdk::onboard_workspace_member_as(server.vault(), &holder, input),
        |outcome| {
            rows.extend([
                outcome.person_ref,
                outcome.actor_ref,
                outcome.federation_grant_ref,
            ]);
            rows.extend(outcome.companion_person_ref);
            rows.extend(outcome.companion_actor_ref);
            Some(rows)
        },
    )
    .await
}

pub(crate) async fn vault_workspace_roster(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkspaceRosterRequest,
) -> MaybeListed<Vec<WorkspaceRosterEntry>> {
    const VERB: &str = "vault.workspace.roster";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::read_workspace_roster_as(server.vault(), &owner, input),
        |roster| {
            Some(
                roster
                    .iter()
                    .flat_map(|entry| {
                        [
                            Some(entry.actor_ref),
                            Some(entry.subject_ref),
                            entry.principal_ref,
                            entry.facet_ref,
                            entry.identity_ref,
                        ]
                        .into_iter()
                        .flatten()
                    })
                    .collect(),
            )
        },
    )
    .await
}
