//! Custom definitions, saved workflows and workspace onboarding, with the
//! caller's own proof.
use std::sync::Arc;

use oneiron::task_verb::sdk::{
    self, AgentDefinitionCreateRequest, AgentDefinitionRequest, AgentDefinitionUpdateRequest,
    AgentDefinitionView, WorkflowRequest, WorkflowSaveRequest, WorkflowUpdateRequest, WorkflowView,
    WorkspaceMemberOnboardRequest, WorkspacePresetReceipt, WorkspacePresetRequest,
    WorkspaceRosterRequest,
};
use oneiron::workspace_roster::{MemberOnboardingOutcome, WorkspaceRosterEntry};

use super::host_doors::{MaybeListed, owner_proof};
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
