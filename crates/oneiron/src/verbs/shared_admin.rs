//! Named organization administration, one-hop Delegate grants and scoped member projections.
use serde::{Deserialize, Serialize};

use crate::claim::{ClaimReadStatus, PointRead};
use crate::consent::AuthenticatedOwner;
use crate::federation::{
    FederationGrant, FederationGrantRole, FederationGrantScope, MemberRelationship, OrgAdminError,
    OrgAdminPolicy, OrgAdminPower, Scope,
};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
};
use crate::ports::EntityStoreRead;
use crate::{EntityId, Vault};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrgAdminConfigureRequest {
    pub policy: OrgAdminPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrgAdminConfigured {
    pub org_ref: EntityId,
    pub configured: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrgAdminPowersRequest {
    pub org_ref: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrgAdminPowers {
    pub powers: Vec<OrgAdminPower>,
}

/// One explicit six-axis narrowing; the host, not the caller, supplies mint time.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationDelegateRequest {
    pub parent_grant: EntityId,
    pub member_ref: EntityId,
    pub authority_scope: Scope,
    pub expires_at: u64,
}

/// Stored grant facts, not a role label that grants additional powers.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FederationMemberGrant {
    pub grant_ref: EntityId,
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    pub member_ref: EntityId,
    pub role: FederationGrantRole,
    pub authority_scope: Scope,
    pub delegated_by: Option<EntityId>,
    pub expires_at: Option<u64>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MemberProjection {
    pub member_ref: EntityId,
    pub grants: Vec<FederationMemberGrant>,
    pub relationship: MemberRelationship,
}

/// The existing signed roster shape, with the shared vault whose Admin power acts.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedProjectAccessResetRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    pub roster: crate::workspace_roster::ProjectRosterWriteRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SharedProjectAccessReset {
    pub project: EntityId,
    pub installed: bool,
    pub invitations: Vec<String>,
}

fn org_error(error: OrgAdminError) -> MemoryError {
    match error {
        OrgAdminError::AlreadyConfigured => MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "organization administration is already configured",
            &["Organization administration is fixed at setup."],
        ),
        OrgAdminError::Denied => MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "organization administration power denied",
            &["Use the organization's named power grant."],
        ),
        OrgAdminError::Engine(error) => error.into(),
    }
}

pub fn configure_org_admin_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OrgAdminConfigureRequest,
) -> MemoryResult<OrgAdminConfigured> {
    vault
        .configure_org_admin_as_owner(owner, &input.policy)
        .map_err(org_error)?;
    Ok(OrgAdminConfigured {
        org_ref: input.policy.org_ref(),
        configured: true,
    })
}

pub fn read_org_admin_powers(
    memory: &Memory<'_>,
    input: OrgAdminPowersRequest,
) -> MemoryResult<OrgAdminPowers> {
    let _key = memory.read_key()?;
    let policy = memory
        .vault()
        .org_admin_policy(input.org_ref)
        .map_err(org_error)?;
    Ok(OrgAdminPowers {
        powers: policy.visible_powers(memory.actor()),
    })
}

fn member_grant(
    id: EntityId,
    grant: FederationGrant,
    now: u64,
    activated: bool,
) -> MemoryResult<FederationMemberGrant> {
    let FederationGrantScope::Vault { vault_id } = grant.scope else {
        return Err(MemoryError::bad_request(
            "expected a shared-vault member grant",
        ));
    };
    let active = activated && grant.confers_at(now);
    Ok(FederationMemberGrant {
        grant_ref: id,
        vault_id,
        member_ref: grant.member_ref,
        role: grant.role,
        authority_scope: grant.authority_scope,
        delegated_by: grant.delegated_by,
        expires_at: grant.expires_at,
        active,
    })
}

pub fn create_federation_delegate_as(
    vault: &Vault,
    holder: &AuthenticatedOwner,
    input: FederationDelegateRequest,
) -> MemoryResult<FederationMemberGrant> {
    let (id, grant) = vault.create_scoped_federation_delegate(
        holder,
        input.parent_grant,
        input.member_ref,
        &input.authority_scope,
        input.expires_at,
    )?;
    member_grant(id, grant, vault.store.clock.now_recorded_at(), true)
}

pub fn reset_shared_project_access(
    memory: &Memory<'_>,
    input: SharedProjectAccessResetRequest,
) -> MemoryResult<SharedProjectAccessReset> {
    let result =
        memory.projects_reset_access(input.vault_id, input.roster.project, &input.roster.record)?;
    Ok(SharedProjectAccessReset {
        project: input.roster.project,
        installed: result.installed,
        invitations: result
            .invitations
            .into_iter()
            .map(|join| join.join_ref)
            .collect(),
    })
}

/// Every grant and relationship claim passes the caller's own scoped read.
/// The relationship resolver is the same one all engine contexts use.
pub fn read_member_projection(
    memory: &Memory<'_>,
    input: super::SharedMemberRequest,
) -> MemoryResult<MemberProjection> {
    let member = EntityId::from_hex(&input.member)
        .map_err(|_| MemoryError::bad_request("member is not an entity id"))?;
    let vault = memory.vault();
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    let ids = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let ids = vault
            .store
            .port_entity_ids_by_type(&txn, crate::registry::ENTITY_TYPE_FEDERATION_GRANT, None)?
            .collect::<crate::Result<Vec<_>>>()?;
        ids
    };
    let mut grants = Vec::new();
    for id in ids {
        let mut rows = lane.read(&[PointRead::id(id)], None)?.value;
        let Some(row) = rows.pop().flatten() else {
            continue;
        };
        let Some(body) = row.body else { continue };
        let grant = crate::federation::decode_federation_grant_body(&body)?;
        if grant.member_ref != member || grant.scope != FederationGrantScope::vault(input.vault_id)
        {
            continue;
        }
        let activated = {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            let fold = vault.authority_fold_readonly_in_txn(&txn)?;
            !fold.vault_root_is_conflicted()
                && vault.shared_vault_deletion_in_txn(&txn)?.is_none()
                && crate::federation::pact_admits_grant(&fold, &id, &grant)
        };
        memory.produced_from([id]);
        grants.push(member_grant(
            id,
            grant,
            vault.store.clock.now_recorded_at(),
            activated,
        )?);
    }
    let relationship =
        crate::federation::resolve_member_relationship_filtered(vault, member, |id| {
            let readable = lane
                .read(&[PointRead::id(id)], None)?
                .value
                .into_iter()
                .flatten()
                .any(|row| row.body.is_some());
            if readable {
                memory.produced_from([id]);
            }
            Ok(readable)
        })?;
    Ok(MemberProjection {
        member_ref: member,
        grants,
        relationship,
    })
}
