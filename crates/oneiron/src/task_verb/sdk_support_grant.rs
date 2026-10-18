//! The inputs and answers of the owner's support grant rows (OF-606):
//! `vault.support_grants.mint`, `.list` and `.revoke`, host doors. A server
//! runs each under the vault owner's proof, as `/v1/owner/support-grants/*`
//! takes it, and hands mint and revoke its own slip issuer, which signs the
//! slip and its revoke only after the engine revalidated that proof. The
//! customer's support person or agent never passes these doors, its own
//! grant included. An embedded handle holds no host signing key, so it
//! refuses mint and revoke after the owner check; its owner may list.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::{
    HostSlipIssuer, SUPPORT_GRANT_REVOKE_COMMAND, SupportGrantQuery, SupportGrantRequest,
    SupportGrantRow, SupportGrantStatus, SupportHolderClass,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::federation::Scope;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};

/// The longest support grant list one call answers.
const SUPPORT_GRANT_LIST_MAX: usize = 500;

/// `vault.support_grants.mint`'s input: the support PERSON, its class and
/// own public key, the exact bounds, and why.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportGrantMintRequest {
    /// The support PERSON: a live person of this vault, no owner of it,
    /// that the owner selected or authored the ordinary way.
    pub holder: EntityId,
    /// `human` for a named support person, `agent` for a support agent.
    pub holder_class: SupportHolderClass,
    /// The support party's own Ed25519 public key, 64 hex. It keeps the
    /// private key; nothing delivers one.
    pub holder_key: String,
    /// The exact bounds: named worlds, no empty axis, a sensitivity ceiling.
    /// Its verbs axis names `propose` or `write` only when the owner
    /// selects them; bottom or `read` alone is read-only.
    pub scope: Scope,
    /// Exact records the grant reads; a relationship's rows open to support
    /// only when named here. Empty: every record inside `scope`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<EntityId>,
    /// Lifetime in seconds, 1..=86400; one hour when omitted. More time is
    /// a fresh mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Why the owner lets support in, 1..=256 bytes.
    pub purpose: String,
    /// The support ticket the visit serves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_ref: Option<String>,
}

/// One support grant as the owner reviews it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportGrantView {
    /// The grant's id: its slip id, 64 hex.
    pub grant_ref: String,
    pub holder: EntityId,
    pub holder_class: String,
    pub scope: Scope,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<String>,
    pub purpose: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_ref: Option<String>,
    /// The owner PERSON who approved it (hex).
    pub approved_by: String,
    /// Recording time of the owner's mint (Unix seconds).
    pub approved_at: u64,
    /// The wall deadline (Unix seconds); the grant ends at it.
    pub wall_expires_at: u64,
    pub status: SupportGrantStatus,
    /// The one-tap revoke command: `vault.support_grants.revoke`.
    pub revoke_command: String,
}

/// `vault.support_grants.mint`'s answer: the credential for the support
/// party, who proves each request with their own key, and the grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportGrantMintAnswer {
    /// The `v2.slip.` credential. It carries no private key.
    pub slip: String,
    pub grant: SupportGrantView,
    /// The Gate receipt of the owner's mint (hex).
    pub decision_ref: String,
}

/// `vault.support_grants.list`'s input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportGrantListRequest {
    /// Also list expired, revoked and ended grants.
    #[serde(default)]
    pub include_inactive: bool,
    /// At most this many, newest first; 500 when omitted, and never more.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// `vault.support_grants.list`'s answer, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportGrantList {
    pub grants: Vec<SupportGrantView>,
}

/// `vault.support_grants.revoke`'s input: the grant, by its id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportGrantRevokeRequest {
    /// The grant's id (its slip id), 64 hex.
    pub grant_ref: String,
}

/// `vault.support_grants.revoke`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportGrantRevokeAnswer {
    pub grant_ref: String,
    pub holder: EntityId,
    /// False when the grant was already revoked and this call changed
    /// nothing.
    pub changed: bool,
    /// Recording time of this revoke; absent when it changed nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
    /// The Gate receipt of this revoke (hex); absent when it changed nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_ref: Option<String>,
    /// Always false: what support already read, and outside effects already
    /// completed, are not recalled by a revoke.
    pub delivered_recallable: bool,
}

/// `vault.support_grants.mint` on a server: [`Vault::mint_support_grant`]
/// under the owner's proof and the host's own `issuer`.
pub fn mint_support_grant_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    issuer: &HostSlipIssuer,
    input: SupportGrantMintRequest,
) -> MemoryResult<SupportGrantMintAnswer> {
    let holder_key = super::sdk_shared_members::holder_key(&input.holder_key)?;
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
        &[super::sdk_host::SERVED_CLIENT_HINT],
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
        revoke_command: SUPPORT_GRANT_REVOKE_COMMAND.to_owned(),
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
