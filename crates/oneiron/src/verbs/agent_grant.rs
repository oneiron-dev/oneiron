//! The inputs and answers of the owner's agent grant rows (FIX 5628):
//! `vault.agents.grants.mint` and `.revoke`, host doors. A server runs each
//! under the vault owner's proof, as `/v1/owner/agent-grants/*` takes it,
//! with where his say-so reached it; an embedded handle runs them as its
//! embedded owner, on this install. An agent never reaches these doors for
//! its own grant: no agent widens its own authority.
//!
//! A grant names one live agent principal and the owner's complete six-axis
//! scope, stored exactly as given; its verbs axis is the explicit verb list
//! (`{"kind":"some","values":["read","weave_digest_settings"]}` lets the
//! Coach apply the digest settings it is granted). `vault.agents.base` names
//! the base agents' principal ids (the Coach's among them) for the owner. It stands until revoked,
//! or until the expiry the owner set. Each grant shows in
//! `vault.consent.registry` with its own one-tap revoke.
//!
//! A mint may also give the agent repo bounds (FIX 6867): one CODE anchor
//! (a CODE_ARTIFACT) in the PROJECT it belongs to, full Git ref names or
//! ref prefix rules (`refs/heads/run/*`, FIX 6895), and separate readable
//! and editable globs (`*` and `?` inside one path component, `**` across
//! components). Omitted, the grant delegates no repo access of its own and
//! behaves exactly as before; with no editable globs it edits nothing, and
//! reading a path never lets the agent edit it.
use serde::{Deserialize, Serialize};

use super::revision_shape;
use crate::Vault;
use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::federation::{AGENT_GRANT_REVOKE_COMMAND, AgentGrantStanding, RepoAccessBounds, Scope};
use crate::memory::MemoryResult;

/// `vault.agents.grants.mint`'s input: the agent, the owner's exact scope
/// and an optional expiry. The host chooses the grant's vault scope, its
/// mint time and its delegator (the owner), never the input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentGrantMintRequest {
    /// The agent principal granted (32 hex): a live agent definition, or a
    /// base agent such as the Coach. Never a person or a device.
    pub agent: EntityId,
    /// The owner's complete six-axis scope, stored exactly as given. Its
    /// verbs axis is the explicit verb list, a nonempty `some` set; the
    /// grant confers only with `read` among them.
    pub authority_scope: Scope,
    /// When the grant stops conferring (Unix seconds, later than now).
    /// Omitted: it stands until revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// The one repo the agent may reach, its refs and its read and edit
    /// globs. The scope must list `read` and name the bounds' PROJECT in its
    /// audience; edits also need `write`. Omitted: no repo-specific
    /// delegation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_bounds: Option<RepoAccessBounds>,
}

/// One owner's agent grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentGrantView {
    /// The grant's FEDERATION_GRANT row.
    pub grant_ref: EntityId,
    /// The agent principal granted.
    pub agent: EntityId,
    /// The owner's exact scope; its verbs are the explicit verb list.
    pub authority_scope: Scope,
    /// The owner PERSON who granted it.
    pub delegated_by: EntityId,
    /// When it stops conferring (Unix seconds); absent: until revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// The repo bounds the owner gave; absent on a general grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_bounds: Option<RepoAccessBounds>,
    /// Whether it confers now: unexpired, with `read` among its verbs and no
    /// empty world, band, audience or sensitivity axis.
    pub confers: bool,
    /// The one-tap revoke command: `vault.agents.grants.revoke`.
    pub revoke_command: String,
}

/// `vault.agents.grants.mint`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentGrantMinted {
    pub grant: AgentGrantView,
    /// The signed authority entry that records the owner's mint (64 hex).
    pub act_ref: String,
}

/// `vault.agents.grants.revoke`'s input: the grant, by its id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentGrantRevokeRequest {
    /// The grant's FEDERATION_GRANT row (32 hex).
    pub grant_ref: EntityId,
    /// The revision the surface showed (64 lower-case hex), checked for its
    /// shape only: the owner's revoke always lands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen: Option<String>,
}

/// `vault.agents.grants.revoke`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentGrantRevoked {
    pub grant_ref: EntityId,
    /// False when the grant was already revoked and this call changed
    /// nothing.
    pub changed: bool,
    /// The agent the revoked grant named; absent when it changed nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<EntityId>,
    /// The signed authority entry that records this revoke (64 hex); absent
    /// when it changed nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act_ref: Option<String>,
}

/// One base agent's principal, as `vault.agents.grants.mint` names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BaseAgentPrincipal {
    /// `coach` or `dreamer`.
    pub name: String,
    /// Its MACHINE principal (32 hex): a grant's `agent`.
    pub id: EntityId,
}

/// `vault.agents.base`'s answer: the base agents, the Coach first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BaseAgentList {
    pub agents: Vec<BaseAgentPrincipal>,
}

/// `vault.agents.base` under the owner's proof: the Coach's and the
/// Dreamer's principal ids, so a surface can name one in a grant.
pub fn read_base_agents_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> MemoryResult<BaseAgentList> {
    Ok(BaseAgentList {
        agents: vault
            .base_agent_principals(owner)?
            .into_iter()
            .map(|(name, id)| BaseAgentPrincipal {
                name: name.to_owned(),
                id,
            })
            .collect(),
    })
}

/// `vault.agents.grants.mint` under the owner's proof, his act recording
/// `surface`.
pub fn mint_agent_grant_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: AgentGrantMintRequest,
) -> MemoryResult<AgentGrantMinted> {
    let minted = vault.mint_agent_grant(
        owner,
        surface,
        input.agent,
        input.authority_scope,
        input.expires_at,
        input.repo_bounds,
    )?;
    Ok(AgentGrantMinted {
        grant: agent_grant_view(&minted.standing, minted.standing.created_at),
        act_ref: minted.act.to_hex(),
    })
}

/// `vault.agents.grants.revoke` under the owner's proof, his act recording
/// `surface`. A repeat answers `changed: false`; an id that names no agent
/// grant is not found.
pub fn revoke_agent_grant_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: AgentGrantRevokeRequest,
) -> MemoryResult<AgentGrantRevoked> {
    if let Some(seen) = &input.seen {
        revision_shape(seen)?;
    }
    let revoked = vault.revoke_agent_grant(owner, surface, input.grant_ref)?;
    Ok(AgentGrantRevoked {
        grant_ref: input.grant_ref,
        changed: revoked.act.is_some(),
        agent: revoked.agent,
        act_ref: revoked.act.map(|act| act.to_hex()),
    })
}

fn agent_grant_view(standing: &AgentGrantStanding, now: u64) -> AgentGrantView {
    AgentGrantView {
        grant_ref: standing.id,
        agent: standing.grant.member_ref,
        authority_scope: standing.grant.authority_scope.clone(),
        delegated_by: standing.delegated_by,
        expires_at: standing.grant.expires_at,
        repo_bounds: standing.grant.repo_bounds.clone(),
        confers: standing.grant.confers_at(now),
        revoke_command: AGENT_GRANT_REVOKE_COMMAND.to_owned(),
    }
}
