//! Workspace roster and companion onboarding through the existing runner.
//! Mailbox enrollment is not part of this door. Bring consent is the caller's
//! authenticated proof, never a field deserialized from the request.
use serde::{Deserialize, Serialize};

use super::sdk::AgentDefinitionSpec;
use crate::consent::AuthenticatedOwner;
use crate::federation::{FederationGrantPreset, FederationGrantRole};
use crate::memory::MemoryResult;
use crate::workspace_roster::{
    CompanionBirthIntent, CompanionChoice, MemberGrantBundle, MemberOnboardingIntent,
    MemberOnboardingOutcome, WorkCompanionPolicy, WorkspaceRosterEntry, WorkspaceRosterPreset,
};
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspacePresetRequest {
    pub preset: WorkspaceRosterPreset,
    #[serde(default)]
    pub work_companion: WorkCompanionPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkspacePresetReceipt {
    pub workspace_ref: String,
    pub work_companion: WorkCompanionPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkspaceCompanionInput {
    Work {
        person_ref: EntityId,
        actor_ref: EntityId,
        work_facet_ref: EntityId,
        profile_grant_ref: EntityId,
        actor_definition: AgentDefinitionSpec,
        display_name: String,
    },
    Bring {
        person_ref: EntityId,
        actor_ref: EntityId,
        work_facet_ref: EntityId,
    },
}

/// Public input to the resumable member-onboarding runner. PERSON, FACET,
/// ORG and the seeded house definition must already exist. The runner owns
/// subject anchors, the exact Member grant and companion-profile grant.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceMemberOnboardRequest {
    pub onboarding_id: String,
    pub workspace: WorkspaceRosterPreset,
    pub person_ref: EntityId,
    pub actor_ref: EntityId,
    pub actor_definition: AgentDefinitionSpec,
    pub work_facet_ref: EntityId,
    pub federation_grant_ref: EntityId,
    pub companion: WorkspaceCompanionInput,
    pub occurred_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRosterRequest {
    pub workspace_ref: String,
}

pub fn establish_workspace_as(
    vault: &Vault,
    holder: &AuthenticatedOwner,
    input: WorkspacePresetRequest,
) -> MemoryResult<WorkspacePresetReceipt> {
    vault.establish_workspace_preset(&input.preset, input.work_companion, holder)?;
    Ok(WorkspacePresetReceipt {
        workspace_ref: input.preset.workspace_ref,
        work_companion: input.work_companion,
    })
}

pub fn onboard_workspace_member_as(
    vault: &Vault,
    holder: &AuthenticatedOwner,
    input: WorkspaceMemberOnboardRequest,
) -> MemoryResult<MemberOnboardingOutcome> {
    let author = holder.revalidate_person(vault)?;
    let companion = match input.companion {
        WorkspaceCompanionInput::Work {
            person_ref,
            actor_ref,
            work_facet_ref,
            profile_grant_ref,
            actor_definition,
            display_name,
        } => CompanionChoice::Work(CompanionBirthIntent {
            person_ref,
            actor_ref,
            work_facet_ref,
            profile_grant_ref,
            actor_definition: actor_definition.definition(author),
            display_name,
        }),
        WorkspaceCompanionInput::Bring {
            person_ref,
            actor_ref,
            work_facet_ref,
        } => CompanionChoice::Bring {
            person: person_ref,
            actor: actor_ref,
            work_facet: work_facet_ref,
            proof: holder.clone(),
        },
    };
    let profile_grant_ref = companion.birth().map(|birth| birth.profile_grant_ref);
    let intent = MemberOnboardingIntent {
        onboarding_id: input.onboarding_id,
        workspace: input.workspace,
        person_ref: input.person_ref,
        actor_ref: input.actor_ref,
        actor_definition: input.actor_definition.definition(author),
        work_facet_ref: input.work_facet_ref,
        grant_bundle: MemberGrantBundle {
            federation_grant_ref: input.federation_grant_ref,
            role: FederationGrantRole::Member,
            preset: FederationGrantPreset::Member,
            companion_profile_grant_ref: profile_grant_ref,
        },
        companion,
        delegated_mailbox: None,
        occurred_at: input.occurred_at,
    };
    Ok(vault.onboard_workspace_member(
        intent,
        &WriteActor::new(author, EdgeActorClass::Human),
        None,
    )?)
}

/// The unfiltered roster is the owner's read. Onboarding itself still needs
/// the runner's live AddMember power, including when the caller is an owner.
pub fn read_workspace_roster_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: WorkspaceRosterRequest,
) -> MemoryResult<Vec<WorkspaceRosterEntry>> {
    owner.revalidate(vault)?;
    Ok(vault.workspace_roster(&input.workspace_ref, crate::unix_seconds_now())?)
}
