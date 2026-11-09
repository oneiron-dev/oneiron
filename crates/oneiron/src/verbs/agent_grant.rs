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
//!
//! A mint may also name verb classes beside the exact verbs (FIX 8735):
//! `verb_classes: ["send"]` lets the agent do each verb the class admits,
//! by the class's own spelling, the built-in outbound classes, or the
//! owner's verb-class row for it (`vault.agents.verb_classes.configure`),
//! resolved each time a door judges a verb. The verbs axis may then be
//! empty (`{"kind":"bottom"}`); it is never every verb. A grant without
//! classes behaves exactly as before.
//!
//! A mint may also name the host wallet the work the grant funds draws on
//! (FIX 7766): `wallet_ref: {"issuer": "...", "id": "..."}`, an opaque host
//! reference, signed in the owner's act. A spend lease the owner opens with
//! the grant as its `funding_grant_ref` freezes it, and every call that
//! lease's tree admits draws on that wallet's allocation or is refused. A
//! grant without one behaves exactly as before.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::revision_shape;
use crate::Vault;
use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::federation::{
    AGENT_GRANT_REVOKE_COMMAND, AgentGrantStanding, EngineControlChange, RepoAccessBounds, Scope,
    SystemAgentGrantNarrowing, SystemFunction, WalletRef,
};
use crate::memory::MemoryResult;

/// `vault.agents.grants.mint`'s input: the agent, the owner's exact scope
/// and an optional expiry. The host chooses the grant's vault scope, its
/// mint time and its delegator (the owner), never the input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentGrantMintRequest {
    /// The agent principal granted (32 hex): a live agent definition, a base
    /// agent such as the Coach, or a named agent's principal. Never another
    /// person or a device.
    pub agent: EntityId,
    /// The owner's complete six-axis scope, stored exactly as given. Its
    /// verbs axis is the explicit verb list, a nonempty `some` set, or
    /// empty beside a nonempty `verb_classes`; the grant confers only with
    /// `read` among them or admitted by a class it names.
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
    /// The verb classes the agent may act under beside the exact verbs, by
    /// class name: each admits its own spelling, its built-in outbound
    /// members, and the owner's verb-class row for it. Never `git_push`.
    /// Omitted: none.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub verb_classes: BTreeSet<String>,
    /// The host wallet the work this grant funds draws on: the host's
    /// issuer namespace and the wallet's id there, both nonempty. Omitted:
    /// none, and the grant funds no launch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_ref: Option<WalletRef>,
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
    /// The verb classes the owner named beside the exact verbs; absent
    /// when it names none.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub verb_classes: BTreeSet<String>,
    /// The host wallet the owner named for the work it funds; absent when
    /// it names none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_ref: Option<WalletRef>,
    /// Whether it confers now: unexpired, with `read` among its verbs (or
    /// admitted by a class it names) and no empty world, band, audience or
    /// sensitivity axis.
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
        input.verb_classes,
        input.wallet_ref,
    )?;
    Ok(AgentGrantMinted {
        grant: agent_grant_view(&minted.standing, minted.confers),
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

/// The view of `standing` as minted; `confers` was judged in the minting
/// writer, the grant's classes resolved there.
fn agent_grant_view(standing: &AgentGrantStanding, confers: bool) -> AgentGrantView {
    AgentGrantView {
        grant_ref: standing.id,
        agent: standing.grant.member_ref,
        authority_scope: standing.grant.authority_scope.clone(),
        delegated_by: standing.delegated_by,
        expires_at: standing.grant.expires_at,
        repo_bounds: standing.grant.repo_bounds.clone(),
        verb_classes: standing.grant.verb_classes.clone(),
        wallet_ref: standing.grant.wallet_ref.clone(),
        confers,
        revoke_command: AGENT_GRANT_REVOKE_COMMAND.to_owned(),
    }
}

/// `vault.agents.grants.narrow`'s input: a base agent (the Dreamer or the
/// Coach) and the Steward verbs its grant keeps.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SystemAgentGrantNarrowRequest {
    /// The base agent's principal (32 hex), as `vault.agents.base` names it.
    pub agent: EntityId,
    /// The verbs the grant keeps; an empty list revokes it whole.
    pub keep: BTreeSet<String>,
    /// The confirm token an earlier answer gave for this same narrowing (64
    /// hex); omitted, nothing changes and the answer says what breaks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<String>,
}

/// What a narrowing did (untangle 6.3c; S6-4 amended).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SystemAgentGrantNarrowed {
    /// Nothing to narrow: the grant already holds no more than asked, or no
    /// grant stands.
    Unchanged,
    /// Nothing changed: the narrowing breaks `breaks`. Ask again with
    /// `confirm` to apply it.
    ConfirmRequired {
        warning: String,
        breaks: Vec<SystemFunction>,
        /// 64 hex.
        confirm: String,
    },
    /// Applied: `grant` is the narrower grant (32 hex), none when the grant
    /// was revoked whole; `breaks` is what the owner confirmed.
    Narrowed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant: Option<EntityId>,
        breaks: Vec<SystemFunction>,
    },
}

/// `vault.agents.grants.narrow`: the owner narrows or revokes a base agent's
/// Steward grant. A narrowing that breaks a vault function answers with the
/// list and a confirm token and changes nothing until the owner sends that
/// token back; the record keeps that the owner chose it. It never widens.
pub fn narrow_system_agent_grant_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SystemAgentGrantNarrowRequest,
) -> MemoryResult<SystemAgentGrantNarrowed> {
    let confirm = input
        .confirm
        .as_deref()
        .map(|hex| {
            hex32(hex).ok_or_else(|| crate::memory::MemoryError::bad_request("confirm is 64 hex"))
        })
        .transpose()?;
    Ok(
        match vault.narrow_system_agent_grant(owner, input.agent, &input.keep, confirm)? {
            SystemAgentGrantNarrowing::Unchanged => SystemAgentGrantNarrowed::Unchanged,
            SystemAgentGrantNarrowing::ConfirmRequired {
                warning,
                breaks,
                confirm,
            } => SystemAgentGrantNarrowed::ConfirmRequired {
                warning: warning.to_owned(),
                breaks,
                confirm: crate::entity_id::bytes_to_hex_lower(&confirm),
            },
            SystemAgentGrantNarrowing::Narrowed { grant, breaks } => {
                SystemAgentGrantNarrowed::Narrowed { grant, breaks }
            }
        },
    )
}

/// 32 bytes from 64 ASCII hex digits of either case.
fn hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0; 32];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// `vault.engine.controls.changes`'s answer row: one change made through
/// the engine-control door, by its receipt id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineControlChangeEntry {
    /// The receipt (32 hex).
    pub id: EntityId,
    pub change: EngineControlChange,
}

/// `vault.engine.controls.changes`: every change the owner or a holder of
/// `engine.controls` made to the engine's stored knobs, oldest first, for
/// the owner to read (untangle 6.6).
pub fn engine_control_changes_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: super::EmptyRequest,
) -> MemoryResult<Vec<EngineControlChangeEntry>> {
    Ok(vault
        .engine_control_changes(owner)?
        .into_iter()
        .map(|(id, change)| EngineControlChangeEntry { id, change })
        .collect())
}
