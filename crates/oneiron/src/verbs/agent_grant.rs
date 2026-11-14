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
//! `vault.agents.grants.from_slip` converts one live slip of a named agent
//! that no Grant has ever named, as the owner's registry lists it, into its
//! holder's default read Grants (FIX AGENT-GRANTLESS-VISIBLE; Engine RULING
//! GRANTLESS-SHAPE Q9 = A). It takes no Scope: each Grant is the slip's
//! logged Scope with verbs `read`.
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
    AGENT_GRANT_REVOKE_COMMAND, AgentGrantStanding, EngineControlChange, EngineControlClass,
    GrantlessAgentConversion, SystemAgent, SystemAgentGrantNarrowing, SystemFunction,
};
use crate::memory::{MemoryError, MemoryResult};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::agent_grant::{
    AgentGrantFromSlipOutcome, AgentGrantFromSlipRequest, AgentGrantMintRequest, AgentGrantMinted,
    AgentGrantRevokeRequest, AgentGrantRevoked, AgentGrantView, BaseAgentList, BaseAgentPrincipal,
    SystemAgentGrantNarrowRequest,
};

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
        input.working_view_bounds,
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

/// `vault.agents.grants.from_slip` under the owner's proof, his acts
/// recording `surface` (Engine RULING GRANTLESS-SHAPE Q9 = A): converts one
/// live slip of a named agent that no Grant has ever named into its holder's
/// default read Grants, verbs `read` and each Scope's other axes, with no
/// expiry, wallet, repo bounds or classes. A slip that no longer qualifies
/// answers unchanged with its reason, so a repeat never mints twice; an id
/// that names no slip is not found.
pub fn mint_agent_grants_from_slip_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: AgentGrantFromSlipRequest,
) -> MemoryResult<AgentGrantFromSlipOutcome> {
    let slip_id = hex32(&input.slip_ref)
        .ok_or_else(|| crate::memory::MemoryError::bad_request("slip_ref is 64 hex"))?;
    Ok(
        match vault.mint_default_agent_grants_from_slip(owner, surface, slip_id)? {
            GrantlessAgentConversion::Minted(minted) => AgentGrantFromSlipOutcome::Minted {
                grants: minted
                    .iter()
                    .map(|minted| AgentGrantMinted {
                        grant: agent_grant_view(&minted.standing, minted.confers),
                        act_ref: minted.act.to_hex(),
                    })
                    .collect(),
            },
            GrantlessAgentConversion::Unchanged(reason) => {
                AgentGrantFromSlipOutcome::Unchanged { reason }
            }
        },
    )
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
        working_view_bounds: standing.grant.working_view_bounds,
        confers,
        revoke_command: AGENT_GRANT_REVOKE_COMMAND.to_owned(),
    }
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

/// `vault.agents.grants.restore`'s input: the base agent (the Dreamer or the
/// Coach) whose default grant the owner gives back.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SystemAgentGrantRestoreRequest {
    /// The base agent's principal (32 hex), as `vault.agents.base` names it.
    pub agent: EntityId,
}

/// What a grant back did (FABLE-6917-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemAgentGrantRestored {
    /// True when the door gave the default grant back; false when it
    /// already stood whole, and nothing changed.
    pub restored: bool,
    /// The Dreamer's live reach, read after the grant (Engine RULING
    /// ROW4-WEAVE-GRANT-REACH = A): the default grant can stand whole while
    /// the owner's policy rows still keep the Dreamer from landing what it
    /// derives. Absent for the Coach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reach: Option<DreamerGrantReach>,
}

/// What the live policy lets the Dreamer do, as
/// [`Vault::dreamer_weave_reach`] reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamerGrantReach {
    /// A receipt-free read grant covering every record names the Dreamer.
    pub reads: bool,
    /// An Auto actor ceiling and the Dreamer-bound `Generated` permit: what
    /// it derives lands.
    pub lands_auto: bool,
}

/// `vault.agents.grants.restore`: the owner gives a base agent its default
/// grant back after a narrowing or a revoke, the inverse of
/// `vault.agents.grants.narrow` (Engine RULING ROW3-GRANT-VERBS = A). The
/// Dreamer's runs through [`Vault::grant_dreamer_weave`], as `oneiron
/// dreamer grant` does, and the Coach's through [`Vault::grant_coach_steward`].
/// The Dreamer's answer carries its reach, read after the grant, as `oneiron
/// dreamer grant` reads it before it reports success. A second call changes
/// nothing. Any other principal is refused: its grants are minted and
/// revoked by their ids.
pub fn restore_system_agent_grant_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SystemAgentGrantRestoreRequest,
) -> MemoryResult<SystemAgentGrantRestored> {
    let (restored, reach) = match SystemAgent::of(input.agent) {
        Some(SystemAgent::Dreamer) => {
            let restored = vault.grant_dreamer_weave(owner, vault.now_recorded_at())?;
            let reach = vault.dreamer_weave_reach()?;
            let reach = DreamerGrantReach {
                reads: reach.reads,
                lands_auto: reach.lands_auto,
            };
            (restored, Some(reach))
        }
        Some(SystemAgent::Coach) => (vault.grant_coach_steward(owner)?, None),
        None => {
            return Err(MemoryError::bad_request(
                "vault.agents.grants.restore gives back a base agent's default grant: \
                 name the Dreamer or the Coach as vault.agents.base lists them",
            ));
        }
    };
    Ok(SystemAgentGrantRestored { restored, reach })
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

/// `vault.engine.defaults`'s answer row: one grant the engine stood by
/// default, by its grant id, with its receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineDefaultGrantEntry {
    /// The grant (32 hex).
    pub grant: EntityId,
    pub receipt: crate::federation::EngineDefaultGrant,
}

/// `vault.engine.defaults`: every grant the engine stood by default, oldest
/// first, for the owner to read on first open (lead 10 Nov 06:5x). Each is
/// the engine's act, never the owner's; the owner narrows or revokes it at
/// `vault.agents.grants.narrow`.
pub fn engine_default_grants_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: super::EmptyRequest,
) -> MemoryResult<Vec<EngineDefaultGrantEntry>> {
    Ok(vault
        .engine_default_grants(owner)?
        .into_iter()
        .map(|(grant, receipt)| EngineDefaultGrantEntry { grant, receipt })
        .collect())
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
/// an `engine.controls` class made to the engine's stored knobs, oldest first, for
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

/// `vault.engine.controls.grant`'s input: an agent principal that is no
/// base agent, and the classes of the engine's knobs it may tune.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EngineControlsGrantRequest {
    /// The agent's principal (32 hex).
    pub agent: EntityId,
    /// At least one class.
    pub classes: BTreeSet<EngineControlClass>,
}

/// `vault.engine.controls.grant`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineControlsGranted {
    /// The grant the owner minted (32 hex).
    pub grant: EntityId,
}

/// `vault.engine.controls.grant`: the owner lets an agent tune the engine's
/// knobs of the named classes (S66-1; Engine RULING ROW3-GRANT-VERBS = A),
/// through [`Vault::grant_engine_controls`]: a grant naming those classes'
/// verbs alone, as the owner's signed act. A base agent's grant is its
/// default grant, given back at `vault.agents.grants.restore`.
pub fn grant_engine_controls_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EngineControlsGrantRequest,
) -> MemoryResult<EngineControlsGranted> {
    Ok(EngineControlsGranted {
        grant: vault.grant_engine_controls(owner, input.agent, &input.classes)?,
    })
}

/// `vault.engine.controls.revoke`'s input: the agent whose engine.controls
/// grants the owner takes back.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EngineControlsRevokeRequest {
    /// The agent's principal (32 hex).
    pub agent: EntityId,
}

/// `vault.engine.controls.revoke`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineControlsRevoked {
    /// The grants revoked (32 hex each); empty when none stood.
    pub revoked: Vec<EntityId>,
}

/// `vault.engine.controls.revoke`: the owner takes back every
/// engine.controls grant given to an agent that is no base agent, through
/// [`Vault::revoke_engine_controls`], by a signed revoke of each. A base
/// agent's grant is narrowed at `vault.agents.grants.narrow`.
pub fn revoke_engine_controls_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EngineControlsRevokeRequest,
) -> MemoryResult<EngineControlsRevoked> {
    Ok(EngineControlsRevoked {
        revoked: vault.revoke_engine_controls(owner, input.agent)?,
    })
}
