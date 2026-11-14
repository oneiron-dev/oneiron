//! Moved from `crates/oneiron/src/verbs/agent_grant.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::federation::agent_grant::grantless::AgentGrantFromSlipUnchangedReason;
use oneiron_authority::federation::RepoAccessBounds;
use oneiron_authority::federation::Scope;
use oneiron_authority::federation::WalletRef;
use oneiron_authority::federation::WorkingViewEditBounds;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

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
    /// The one owner working view of the `repo_bounds` repo the agent may
    /// edit, and the owner account it lives in: the grant then edits that
    /// view's files under the editable globs through
    /// `vault.code.views.edit`, and every other repo door refuses it. It
    /// needs `repo_bounds` and a view the owner made of their repo.
    /// Omitted: no view bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_view_bounds: Option<WorkingViewEditBounds>,
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
    /// The one owner working view, and its account, the grant edits alone;
    /// absent on a grant bound to none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_view_bounds: Option<WorkingViewEditBounds>,
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

/// `vault.agents.grants.from_slip`'s input: one slip the owner's registry
/// lists among its `grantless_agents` (FIX AGENT-GRANTLESS-VISIBLE).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentGrantFromSlipRequest {
    /// The slip's id (64 hex), as the registry row's `slip_ref` names it.
    pub slip_ref: String,
}

/// `vault.agents.grants.from_slip`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AgentGrantFromSlipOutcome {
    /// The holder's default read Grants as minted: the named slip's Scope
    /// first, then one for each other distinct Scope of its live slips.
    Minted { grants: Vec<AgentGrantMinted> },
    /// Nothing was minted, for `reason`.
    Unchanged {
        reason: AgentGrantFromSlipUnchangedReason,
    },
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
