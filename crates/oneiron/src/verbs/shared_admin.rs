//! Named organization administration, one-hop Delegate grants and scoped member projections.
use serde::{Deserialize, Serialize};

use crate::check_in::{AppliedCheckIn, CheckInDecision};
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
    /// Another asker's approved check-in for this exact configuration, 32
    /// hex: the owner applies it on their own proof, and the configuring
    /// writer spends it (ROLES-CHECKIN 2k8). Omitted: the owner's own act.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrgAdminConfigured {
    pub org_ref: EntityId,
    pub configured: bool,
    /// The decision the configuration ran on: the owner's own proof, naming
    /// the asker's approved check-in it applied (ROLES-CHECKIN 2k8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<CheckInDecision>,
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
    /// The role in one plain sentence, beside its name, for a role whose
    /// reach a reader cannot guess from the name (the Steward's: ARCH-0043).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_note: Option<String>,
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

/// `vault.org_admin.configure` under the owner's proof. Naming an org's
/// admins and their powers widens their grants (ARCH-0082 #act-table "Widen
/// another's grant"): the owner's own act goes on their own proof, never
/// gated, and the answer records that decision (`check_in`). With
/// `check_in_ref` the owner applies another asker's approved check-in for
/// this exact configuration, spent in the configuring writer after every
/// check (ROLES-CHECKIN 2k8; Engine RULING P25-SHAPE Q1 = A).
///
/// # Errors
///
/// `BAD_REQUEST` for a malformed `check_in_ref`; the configuration's
/// refusals; a check-in that is not an approved ask for it.
pub fn configure_org_admin_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OrgAdminConfigureRequest,
) -> MemoryResult<OrgAdminConfigured> {
    let applied = match super::shared::check_in_ref(input.check_in_ref.as_deref())? {
        Some(id) => Some(AppliedCheckIn {
            id,
            verb: "vault.org_admin.configure",
            effect_digest: org_admin_configure_effect_digest(&input)?,
        }),
        None => None,
    };
    let decision = vault
        .configure_org_admin_with_check_in(owner, &input.policy, applied.as_ref())
        .map_err(org_error)?;
    Ok(OrgAdminConfigured {
        org_ref: input.policy.org_ref(),
        configured: true,
        check_in: Some(decision),
    })
}

/// The digest of the owner's org admin configuration `request`: the effect
/// an asker's `vault.check_in.open` names for `vault.org_admin.configure`,
/// and the one the owner's act spends (2k8; P25-SHAPE Q1 = A). BLAKE3, key
/// derived from `oneiron check_in org admin configure v1`, over the
/// request's MessagePack encoding with field names, without its
/// `check_in_ref`: the org, its admins and their powers.
///
/// # Errors
///
/// The request does not encode.
pub fn org_admin_configure_effect_digest(
    request: &OrgAdminConfigureRequest,
) -> MemoryResult<[u8; 32]> {
    let configure = OrgAdminConfigureRequest {
        check_in_ref: None,
        ..request.clone()
    };
    let encoded = rmp_serde::to_vec_named(&configure)
        .map_err(|_| crate::error::Error::InvariantViolation("org admin configure encode"))?;
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in org admin configure v1");
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
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
        role_note: (grant.role == FederationGrantRole::Steward)
            .then(|| crate::federation::STEWARD_ROLE_NOTE.to_owned()),
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
