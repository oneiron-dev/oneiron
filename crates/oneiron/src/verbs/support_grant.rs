//! The inputs and answers of the owner's support grant rows (OF-606):
//! `vault.support_grants.mint`, `.list` and `.revoke`, host doors. A server
//! runs each under the vault owner's proof, as `/v1/owner/support-grants/*`
//! takes it, and hands mint and revoke its own slip issuer, which signs the
//! slip and its revoke only after the engine revalidated that proof. The
//! customer's support person or agent never passes these doors, its own
//! grant included. An embedded handle holds no host signing key, so it
//! refuses mint and revoke after the owner check; its owner may list.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::{
    CommReach, HostSlipIssuer, SUPPORT_GRANT_REVOKE_COMMAND, SupportGrantQuery,
    SupportGrantRequest, SupportGrantRow, SupportGrantStatus, SupportHolderClass, SupportRepair,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::federation::Scope;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};

/// The longest support grant list one call answers.
const SUPPORT_GRANT_LIST_MAX: usize = 500;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::support_grant::{
    SupportGrantList, SupportGrantListRequest, SupportGrantMintAnswer, SupportGrantMintRequest,
    SupportGrantRevokeAnswer, SupportGrantRevokeRequest, SupportGrantView,
};

/// `vault.support_grants.mint` on a server: [`Vault::mint_support_grant`]
/// under the owner's proof and the host's own `issuer`.
pub fn mint_support_grant_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    issuer: &HostSlipIssuer,
    input: SupportGrantMintRequest,
) -> MemoryResult<SupportGrantMintAnswer> {
    let holder_key = super::shared_members::holder_key(&input.holder_key)?;
    let minted = vault.mint_support_grant(
        owner,
        issuer,
        SupportGrantRequest {
            holder: input.holder,
            holder_class: input.holder_class,
            holder_key,
            scope: input.scope,
            records: input.records.into_iter().collect(),
            ttl_secs: input.ttl_secs,
            purpose: input.purpose,
            ticket_ref: input.ticket_ref,
            comm: input.comm,
            repairs: input.repairs,
        },
    )?;
    Ok(SupportGrantMintAnswer {
        slip: minted.slip.to_token()?,
        grant: support_grant_view(&minted.grant),
        decision_ref: minted.decision_id.to_hex(),
    })
}

/// `vault.support_grants.list` under the owner's proof: active grants, or
/// every one with `include_inactive`.
pub fn list_support_grants_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SupportGrantListRequest,
) -> MemoryResult<SupportGrantList> {
    let limit = input
        .limit
        .map_or(SUPPORT_GRANT_LIST_MAX, |limit| limit as usize)
        .min(SUPPORT_GRANT_LIST_MAX);
    let rows = vault.list_support_grants(
        owner,
        SupportGrantQuery {
            limit,
            include_inactive: input.include_inactive,
        },
    )?;
    Ok(SupportGrantList {
        grants: rows.iter().map(support_grant_view).collect(),
    })
}

/// `vault.support_grants.revoke` on a server: [`Vault::revoke_support_grant`]
/// under the owner's proof and the host's own `issuer`. A repeat answers
/// `changed: false`; an id that names no support grant is not found.
pub fn revoke_support_grant_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    issuer: &HostSlipIssuer,
    input: SupportGrantRevokeRequest,
) -> MemoryResult<SupportGrantRevokeAnswer> {
    let slip_id = grant_ref(&input.grant_ref)?;
    let revoked = vault.revoke_support_grant(owner, issuer, slip_id)?;
    Ok(SupportGrantRevokeAnswer {
        grant_ref: input.grant_ref,
        holder: revoked.holder,
        changed: revoked.changed,
        revoked_at: revoked.revoked_at,
        decision_ref: revoked
            .decision_id
            .map(crate::store::GateDecisionId::to_hex),
        delivered_recallable: false,
    })
}

/// `vault.support_grants.mint` on an embedded handle: the owner's call,
/// refused, because the slip is signed with a host key no embedded vault
/// holds.
pub fn mint_support_grant_embedded(
    memory: &Memory<'_>,
    _input: SupportGrantMintRequest,
) -> MemoryResult<SupportGrantMintAnswer> {
    host_signs(memory, "vault.support_grants.mint")
}

/// `vault.support_grants.list` on an embedded handle: the embedded owner's
/// own read.
pub fn list_support_grants_embedded(
    memory: &Memory<'_>,
    input: SupportGrantListRequest,
) -> MemoryResult<SupportGrantList> {
    let owner = memory.embedded_owner("vault.support_grants.list")?;
    list_support_grants_as(memory.vault(), &owner, input)
}

/// `vault.support_grants.revoke` on an embedded handle: refused after the
/// owner check, as mint is.
pub fn revoke_support_grant_embedded(
    memory: &Memory<'_>,
    _input: SupportGrantRevokeRequest,
) -> MemoryResult<SupportGrantRevokeAnswer> {
    host_signs(memory, "vault.support_grants.revoke")
}

fn host_signs<T>(memory: &Memory<'_>, verb: &str) -> MemoryResult<T> {
    let _owner = memory.embedded_owner(verb)?;
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{verb} is signed with the host's own key; an embedded vault holds none"),
        &[super::host::SERVED_CLIENT_HINT],
    ))
}

fn support_grant_view(row: &SupportGrantRow) -> SupportGrantView {
    SupportGrantView {
        grant_ref: crate::entity_id::bytes_to_hex_lower(&row.slip_id),
        holder: row.holder,
        holder_class: row.holder_class.clone(),
        scope: row.scope.clone(),
        records: row.records.iter().cloned().collect(),
        purpose: row.delegation.purpose.clone(),
        ticket_ref: row.delegation.ticket_ref.clone(),
        approved_by: row.delegation.owner_ref.clone(),
        approved_at: row.delegation.approved_at,
        wall_expires_at: row.delegation.wall_expires_at,
        status: row.status,
        comm: row.comm,
        revoke_command: SUPPORT_GRANT_REVOKE_COMMAND.to_owned(),
        repairs: row.delegation.repairs.clone(),
    }
}

fn grant_ref(hex: &str) -> MemoryResult<[u8; 32]> {
    let refused = || MemoryError::bad_request("grant_ref is not 32 bytes of hex");
    if hex.len() != 64 {
        return Err(refused());
    }
    let mut id = [0; 32];
    for (byte, pair) in id.iter_mut().zip(hex.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| refused())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| refused())?;
    }
    Ok(id)
}
