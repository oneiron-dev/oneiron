//! Moved from `crates/oneiron/src/verbs/oauth_authorization.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::agent_tier::AgentTier;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.oauth.authorization.answer`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OAuthAuthorizationAnswer {
    /// The sign-in request the owner's ask names (32 hex).
    pub request_ref: EntityId,
    /// Whether the owner lets the app in.
    pub allow: bool,
    /// The tier an allow gives: `read`, `propose` or `full`. Omitted: the tier the app asked
    /// for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<AgentTier>,
    /// The one world an allow binds the app's grant to (32 hex). Omitted: every world the owner
    /// reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world_ref: Option<EntityId>,
}

/// `vault.oauth.authorization.answer`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OAuthAuthorizationAnswered {
    pub request_ref: EntityId,
    /// Whether the owner let the app in.
    pub allowed: bool,
    /// The agent principal the app acts as; absent on a deny.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<EntityId>,
    /// The owner agent grant the app's tokens stand on, which the consent registry revokes;
    /// absent on a deny.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ref: Option<EntityId>,
    /// The tier the app got; absent on a deny.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<AgentTier>,
    /// The world the grant is bound to; absent on a deny and on a grant over every world.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world_ref: Option<EntityId>,
}
