//! The input and answer of `vault.oauth.authorization.answer` (FIX 4902), a host door: the
//! vault owner's answer to an outside app's OAuth sign-in request for this vault's `/mcp`, the
//! one-tap actions of the inbox ask the request sent him. A server runs it under the vault
//! owner's proof, with where his say-so reached it; an embedded handle runs it as its embedded
//! owner, on this install. An agent never answers a sign-in: no agent admits another.
//!
//! An allow admits the app as the owner's agent at the tier he gives (the one it asked for when
//! he names none), bound to one world when he names one: its own agent principal, its ceiling,
//! and an owner agent grant that `vault.consent.registry` lists with its one-tap revoke. The
//! authorize page then collects the code. A deny sends the app `access_denied`.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::{ActSurface, AgentTier};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::MemoryResult;

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

/// `vault.oauth.authorization.answer` under the owner's proof, his acts recording `surface`.
pub fn answer_oauth_authorization_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: OAuthAuthorizationAnswer,
) -> MemoryResult<OAuthAuthorizationAnswered> {
    let allowed = vault.answer_oauth_authorization(
        owner,
        surface,
        input.request_ref,
        input.allow,
        input.tier,
        input.world_ref,
        crate::unix_seconds_now(),
    )?;
    Ok(OAuthAuthorizationAnswered {
        request_ref: input.request_ref,
        allowed: allowed.is_some(),
        agent: allowed.map(|allowed| allowed.agent),
        grant_ref: allowed.map(|allowed| allowed.grant_ref),
        tier: allowed.map(|allowed| allowed.tier),
        world_ref: allowed.and_then(|allowed| allowed.world),
    })
}
